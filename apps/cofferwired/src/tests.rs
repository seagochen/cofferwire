use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::{to_bytes, Body};
use axum::http::{header, Request as HttpRequest, StatusCode as HttpStatus};
use axum::Router;
use axum_server::accept::Accept;
use cofferwire_client::{
    CommitOutcome, InboxStore, PollOutcome, Recipient, RequestIdSource, SendCompletion, Sender,
    StoreError, Transport, TransportError,
};
use cofferwire_codec::{
    decode_response, encode_authenticated_request, encode_request, RequestFrame,
};
use cofferwire_crypto::{EncryptionSecretKey, RelaySigningKey};
use cofferwire_types::{
    CreateQueueRequest, MessageId, QueueId, QueueLimits, Request, RequestId, ResponseBody, Ttl,
    MAX_FRAME_BYTES,
};
use futures_util::{SinkExt, StreamExt};
use rand_core::OsRng;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as ClientMessage;
use tower::ServiceExt;

use super::*;

const QUEUE: QueueId = QueueId::from_bytes([1; 32]);

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cofferwired-{}-{sequence}.sqlite",
            std::process::id()
        ));
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("sqlite-journal"));
    }
}

struct HttpTransport {
    application: Router,
    runtime: tokio::runtime::Runtime,
}

impl HttpTransport {
    fn new(service: RelayService) -> Self {
        Self {
            application: router(service),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime builds"),
        }
    }
}

impl Transport for HttpTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let application = self.application.clone();
        let request = HttpRequest::post("/v1/frame")
            .header(header::CONTENT_TYPE, FRAME_MEDIA_TYPE)
            .body(Body::from(request.to_vec()))
            .map_err(|_| TransportError)?;
        self.runtime.block_on(async move {
            let response = application
                .oneshot(request)
                .await
                .map_err(|_| TransportError)?;
            if response.status() != HttpStatus::OK
                || response.headers().get(header::CONTENT_TYPE)
                    != Some(&header::HeaderValue::from_static(FRAME_MEDIA_TYPE))
            {
                return Err(TransportError);
            }
            to_bytes(response.into_body(), MAX_FRAME_BYTES)
                .await
                .map(|bytes| bytes.to_vec())
                .map_err(|_| TransportError)
        })
    }
}

struct LoseFirstResponse<T> {
    inner: T,
    lose: bool,
}

impl<T: Transport> Transport for LoseFirstResponse<T> {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let response = self.inner.exchange(request)?;
        if self.lose {
            self.lose = false;
            Err(TransportError)
        } else {
            Ok(response)
        }
    }
}

struct RequestIds(u128);

impl RequestIdSource for RequestIds {
    fn next_request_id(&mut self) -> RequestId {
        self.0 += 1;
        RequestId::from_bytes(self.0.to_be_bytes())
    }
}

#[derive(Default)]
struct Inbox(HashMap<MessageId, Vec<u8>>);

impl InboxStore for Inbox {
    fn commit(
        &mut self,
        message_id: MessageId,
        plaintext: &[u8],
    ) -> Result<CommitOutcome, StoreError> {
        match self.0.get(&message_id) {
            Some(existing) if existing == plaintext => Ok(CommitOutcome::AlreadyCommitted),
            Some(_) => Err(StoreError),
            None => {
                self.0.insert(message_id, plaintext.to_vec());
                Ok(CommitOutcome::Applied)
            }
        }
    }
}

fn signed_frame(key: &RelaySigningKey, request_id: RequestId, request: Request) -> Vec<u8> {
    let authenticated = encode_authenticated_request(request_id, &request);
    let auth = key.sign_request(&authenticated);
    encode_request(&RequestFrame::new(request_id, request, auth))
}

#[test]
fn https_binding_preserves_frames_and_rejects_oversized_bodies() {
    let database = TestDatabase::new();
    let service = RelayService::open(database.path()).expect("relay opens");
    let sender_key = RelaySigningKey::from_seed([2; 32]);
    let recipient_key = RelaySigningKey::from_seed([3; 32]);
    let create = Request::CreateQueue(CreateQueueRequest::new(
        QUEUE,
        sender_key.principal(),
        recipient_key.principal(),
        QueueLimits::new(4, 1024).expect("valid limits"),
    ));
    let request_id = RequestId::from_bytes([9; 16]);
    let request = signed_frame(&sender_key, request_id, create);
    let mut transport = HttpTransport::new(service.clone());
    let response = transport
        .exchange(&request)
        .expect("HTTPS exchange succeeds");
    let response = decode_response(&response).expect("exact response frame decodes");
    assert_eq!(response.request_id(), request_id);
    assert!(matches!(
        response.response(),
        Response::Success(ResponseBody::CreateQueue(
            cofferwire_types::CreateQueueOutcome::Created
        ))
    ));

    let oversized = HttpRequest::post("/v1/frame")
        .header(header::CONTENT_TYPE, FRAME_MEDIA_TYPE)
        .body(Body::from(vec![0_u8; MAX_FRAME_BYTES + 1]))
        .expect("request builds");
    let status = transport.runtime.block_on(async {
        router(service)
            .oneshot(oversized)
            .await
            .expect("router responds")
            .status()
    });
    assert_eq!(status, HttpStatus::PAYLOAD_TOO_LARGE);
}

#[test]
fn authenticated_request_replay_is_consistent_and_conflicts_fail() {
    let database = TestDatabase::new();
    let service = RelayService::open(database.path()).expect("relay opens");
    let sender_key = RelaySigningKey::from_seed([2; 32]);
    let recipient_key = RelaySigningKey::from_seed([3; 32]);
    let request_id = RequestId::from_bytes([0x44; 16]);
    let create = |max_messages| {
        Request::CreateQueue(CreateQueueRequest::new(
            QUEUE,
            sender_key.principal(),
            recipient_key.principal(),
            QueueLimits::new(max_messages, 1024).expect("valid limits"),
        ))
    };
    let request = signed_frame(&sender_key, request_id, create(4));
    let first = service
        .exchange_frame_at(&request, 1_000)
        .expect("first exchange");
    let retry = service
        .exchange_frame_at(&request, 1_001)
        .expect("retry exchange");
    assert_eq!(retry, first);

    let conflict = signed_frame(&sender_key, request_id, create(5));
    let response = service
        .exchange_frame_at(&conflict, 1_002)
        .expect("conflicting exchange");
    assert!(matches!(
        decode_response(&response).expect("response decodes").response(),
        Response::Error(error) if error.status() == Status::AuthReplay
    ));
}

#[test]
fn invalid_authentication_never_reaches_storage() {
    let database = TestDatabase::new();
    let service = RelayService::open(database.path()).expect("relay opens");
    let sender_key = RelaySigningKey::from_seed([2; 32]);
    let recipient_key = RelaySigningKey::from_seed([3; 32]);
    let create = Request::CreateQueue(CreateQueueRequest::new(
        QUEUE,
        sender_key.principal(),
        recipient_key.principal(),
        QueueLimits::new(4, 1024).expect("valid limits"),
    ));
    let mut request = signed_frame(&sender_key, RequestId::from_bytes([8; 16]), create);
    *request.last_mut().expect("auth byte exists") ^= 1;
    let mut transport = HttpTransport::new(service);
    let response = transport
        .exchange(&request)
        .expect("protocol response returned");
    assert_eq!(
        decode_response(&response)
            .expect("response decodes")
            .response()
            .status(),
        Status::AuthInvalid
    );
}

#[tokio::test]
async fn connection_limiter_rejects_excess_until_connection_drops() {
    let limiter = ConnectionLimit::for_test(1);
    let ((), connection) = limiter
        .accept((), ())
        .await
        .expect("first connection is admitted");
    assert!(limiter.accept((), ()).await.is_err());
    drop(connection);
    assert!(limiter.accept((), ()).await.is_ok());
}

#[tokio::test]
async fn queue_rate_limit_returns_service_unavailable_once_exceeded() {
    let database = TestDatabase::new();
    let service = RelayService::open(database.path()).expect("relay opens");
    let sender_key = RelaySigningKey::from_seed([2; 32]);
    let recipient_key = RelaySigningKey::from_seed([3; 32]);
    let create = Request::CreateQueue(CreateQueueRequest::new(
        QUEUE,
        sender_key.principal(),
        recipient_key.principal(),
        QueueLimits::new(4, 1024).expect("valid limits"),
    ));
    let request_id = RequestId::from_bytes([0x55; 16]);
    // The same signed frame is replayed by request-id after the first
    // call; each replay still passes through the rate limiter before the
    // replay cache is consulted (`exchange_at`), so repeating one frame
    // exercises the budget without needing a distinct request per call.
    let frame = signed_frame(&sender_key, request_id, create);
    let application = router(service);

    for attempt in 0..QUEUE_RATE_LIMIT_MAX_REQUESTS {
        let request = HttpRequest::post("/v1/frame")
            .header(header::CONTENT_TYPE, FRAME_MEDIA_TYPE)
            .body(Body::from(frame.clone()))
            .expect("request builds");
        let status = application
            .clone()
            .oneshot(request)
            .await
            .expect("router responds")
            .status();
        assert_eq!(status, HttpStatus::OK, "request {attempt} is within budget");
    }

    let over_budget = HttpRequest::post("/v1/frame")
        .header(header::CONTENT_TYPE, FRAME_MEDIA_TYPE)
        .body(Body::from(frame))
        .expect("request builds");
    let status = application
        .oneshot(over_budget)
        .await
        .expect("router responds")
        .status();
    assert_eq!(status, HttpStatus::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn websocket_binding_carries_one_exact_binary_frame() {
    let database = TestDatabase::new();
    let service = RelayService::open(database.path()).expect("relay opens");
    let sender_key = RelaySigningKey::from_seed([2; 32]);
    let recipient_key = RelaySigningKey::from_seed([3; 32]);
    let create = Request::CreateQueue(CreateQueueRequest::new(
        QUEUE,
        sender_key.principal(),
        recipient_key.principal(),
        QueueLimits::new(4, 1024).expect("valid limits"),
    ));
    let request_id = RequestId::from_bytes([10; 16]);
    let frame = signed_frame(&sender_key, request_id, create);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let address = listener.local_addr().expect("listener has address");
    let server = tokio::spawn(async move {
        axum::serve(listener, router(service))
            .await
            .expect("test server runs");
    });
    let mut request = format!("ws://{address}/v1/ws")
        .into_client_request()
        .expect("WebSocket request builds");
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        header::HeaderValue::from_static(WEBSOCKET_PROTOCOL),
    );
    let (mut websocket, response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("WebSocket connects");
    assert_eq!(
        response.headers().get(header::SEC_WEBSOCKET_PROTOCOL),
        Some(&header::HeaderValue::from_static(WEBSOCKET_PROTOCOL))
    );
    websocket
        .send(ClientMessage::Binary(frame.into()))
        .await
        .expect("binary request sends");
    let response = websocket
        .next()
        .await
        .expect("response exists")
        .expect("response is valid");
    let ClientMessage::Binary(response) = response else {
        panic!("expected binary response");
    };
    let response = decode_response(&response).expect("exact response frame decodes");
    assert_eq!(response.request_id(), request_id);
    assert!(response.response().status().is_ok());
    server.abort();
}

#[test]
fn disconnected_clients_exchange_encrypted_message_via_durable_http_binding() {
    let database = TestDatabase::new();
    let service = RelayService::open(database.path()).expect("relay opens");
    let sender_signing = RelaySigningKey::from_seed([2; 32]);
    let recipient_signing = RelaySigningKey::from_seed([3; 32]);
    let sender_encryption = EncryptionSecretKey::derive(&[4; 32]);
    let recipient_encryption = EncryptionSecretKey::derive(&[5; 32]);
    let sender_principal = sender_signing.principal();
    let recipient_principal = recipient_signing.principal();

    let create = Request::CreateQueue(CreateQueueRequest::new(
        QUEUE,
        sender_principal,
        recipient_principal,
        QueueLimits::new(4, 1024).expect("valid limits"),
    ));
    let mut setup_transport = HttpTransport::new(service.clone());
    let response = setup_transport
        .exchange(&signed_frame(
            &sender_signing,
            RequestId::from_bytes([6; 16]),
            create,
        ))
        .expect("queue creation succeeds");
    assert!(decode_response(&response)
        .expect("create response decodes")
        .response()
        .status()
        .is_ok());
    drop(setup_transport);

    let sender = Sender::new(
        QUEUE,
        sender_principal,
        recipient_principal,
        sender_signing,
        sender_encryption.clone(),
        recipient_encryption.public_key(),
    )
    .expect("sender config is valid");
    let message_id = MessageId::from_bytes([7; 32]);
    let prepared = sender
        .prepare(
            RequestId::from_bytes([7; 16]),
            message_id,
            b"offline secret",
            Ttl::from_secs(300),
            &mut OsRng,
        )
        .expect("message encrypts");
    let mut lossy = LoseFirstResponse {
        inner: HttpTransport::new(service.clone()),
        lose: true,
    };
    assert!(sender.send(&prepared, &mut lossy).is_err());
    drop(lossy);
    let mut reconnected = HttpTransport::new(service.clone());
    assert_eq!(
        sender
            .send(&prepared, &mut reconnected)
            .expect("exact retry succeeds"),
        SendCompletion::Accepted
    );
    drop(reconnected);
    drop(sender);

    let recipient = Recipient::new(
        QUEUE,
        sender_principal,
        recipient_principal,
        recipient_signing,
        recipient_encryption,
        sender_encryption.public_key(),
    )
    .expect("recipient config is valid");
    let mut recipient_transport = HttpTransport::new(service);
    let mut inbox = Inbox::default();
    let mut request_ids = RequestIds(100);
    assert_eq!(
        recipient
            .poll(&mut recipient_transport, &mut inbox, &mut request_ids)
            .expect("recipient fetches, decrypts, commits and acknowledges"),
        PollOutcome::Applied(message_id)
    );
    assert_eq!(inbox.0.get(&message_id), Some(&b"offline secret".to_vec()));
}
