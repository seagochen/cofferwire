//! HTTPS and WebSocket bindings for the durable Cofferwire relay.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode as HttpStatus};
use axum::response::{IntoResponse, Response as HttpResponse};
use axum::routing::{get, post};
use axum::Router;
use cofferwire_codec::{decode_request, encode_response, DecodeError, ResponseFrame};
use cofferwire_crypto::verify_request;
use cofferwire_relay as relay;
use cofferwire_types::{
    Command, Delivery, ErrorResponse, Principal, Request, RequestId, Response, ResponseBody,
    Status, Timestamp, MAX_FRAME_BYTES,
};
use futures_util::StreamExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_service::Service;

/// Media type for an exact Cofferwire protocol frame.
pub const FRAME_MEDIA_TYPE: &str = "application/cofferwire";
/// WebSocket subprotocol for exact v1 frames.
pub const WEBSOCKET_PROTOCOL: &str = "cofferwire.v1";
/// Maximum concurrent commands across both bindings.
pub const MAX_CONCURRENT_COMMANDS: usize = 64;
/// Maximum accepted TLS connections, including HTTP keep-alive and WebSocket.
pub const MAX_CONNECTIONS: usize = 256;
/// Maximum live WebSocket sessions.
pub const MAX_WEBSOCKET_CONNECTIONS: usize = 128;
/// Hard deadline for one HTTPS request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle deadline while waiting for the next WebSocket frame.
pub const WEBSOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Acceptor layer that rejects TLS connections above a process-wide bound.
#[derive(Clone, Debug)]
pub struct ConnectionLimit {
    permits: Arc<Semaphore>,
}

impl ConnectionLimit {
    /// Creates the reference daemon's connection limiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }
}

impl Default for ConnectionLimit {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S> axum_server::accept::Accept<I, S> for ConnectionLimit {
    type Stream = I;
    type Service = ConnectionService<S>;
    type Future = std::future::Ready<std::io::Result<(I, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let result = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map(|permit| {
                (
                    stream,
                    ConnectionService {
                        inner: service,
                        permit: ConnectionPermit {
                            _permit: Arc::new(permit),
                        },
                    },
                )
            })
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "connection limit reached",
                )
            });
        std::future::ready(result)
    }
}

/// Service wrapper that retains one connection permit until Hyper drops it.
#[derive(Clone, Debug)]
pub struct ConnectionService<S> {
    inner: S,
    permit: ConnectionPermit,
}

#[derive(Clone, Debug)]
struct ConnectionPermit {
    _permit: Arc<OwnedSemaphorePermit>,
}

struct OptionalConnectionPermit(Option<ConnectionPermit>);

impl<S> FromRequestParts<S> for OptionalConnectionPermit
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.extensions.get::<ConnectionPermit>().cloned()))
    }
}

impl<S, B> Service<axum::http::Request<B>> for ConnectionService<S>
where
    S: Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: axum::http::Request<B>) -> Self::Future {
        request.extensions_mut().insert(self.permit.clone());
        self.inner.call(request)
    }
}

/// Shared durable relay state used by both transport bindings.
#[derive(Clone, Debug)]
pub struct RelayService {
    relay: Arc<Mutex<relay::DurableRelay>>,
    replays: Arc<Mutex<HashMap<(Principal, RequestId), ReplayEntry>>>,
    commands: Arc<Semaphore>,
    websocket_connections: Arc<Semaphore>,
}

impl RelayService {
    /// Opens the durable relay database.
    ///
    /// # Errors
    ///
    /// Returns a durable storage error if the database cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, relay::DurableRelayError> {
        Ok(Self::new(relay::DurableRelay::open(path)?))
    }

    /// Wraps an already-open durable relay.
    #[must_use]
    pub fn new(relay: relay::DurableRelay) -> Self {
        Self {
            relay: Arc::new(Mutex::new(relay)),
            replays: Arc::new(Mutex::new(HashMap::new())),
            commands: Arc::new(Semaphore::new(MAX_CONCURRENT_COMMANDS)),
            websocket_connections: Arc::new(Semaphore::new(MAX_WEBSOCKET_CONNECTIONS)),
        }
    }

    /// Exchanges one frame at a caller-supplied relay time.
    ///
    /// This deterministic entry point exists for transport-neutral conformance
    /// and cross-implementation runners. Production transports sample their own
    /// clock through the private asynchronous exchange path.
    ///
    /// # Errors
    ///
    /// Returns [`FrameExchangeError`] when durable storage cannot complete the
    /// command.
    pub fn exchange_frame_at(
        &self,
        bytes: &[u8],
        now_seconds: u64,
    ) -> Result<Vec<u8>, FrameExchangeError> {
        self.exchange_at(bytes, relay::Timestamp::from_secs(now_seconds))
            .map_err(|_| FrameExchangeError)
    }

    async fn exchange(&self, bytes: Vec<u8>) -> Result<Vec<u8>, ExchangeError> {
        let permit = Arc::clone(&self.commands)
            .try_acquire_owned()
            .map_err(|_| ExchangeError::Overloaded)?;
        let service = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            service.exchange_at(&bytes, relay_time())
        })
        .await
        .map_err(|_| ExchangeError::Internal)?
    }

    fn exchange_at(&self, bytes: &[u8], now: relay::Timestamp) -> Result<Vec<u8>, ExchangeError> {
        let decoded = match decode_request(bytes) {
            Ok(decoded) => decoded,
            Err(error) => return Ok(decode_error_response(bytes, &error)),
        };
        let request_id = decoded.frame().request_id();
        let request = decoded.frame().request();
        let command = request.command();
        let principal = request_principal(request);
        if verify_request(
            principal,
            decoded.authenticated_bytes(),
            decoded.frame().auth(),
        )
        .is_err()
        {
            return Ok(error_response(
                request_id,
                Some(command),
                Status::AuthInvalid,
            ));
        }

        let replay_key = (principal, request_id);
        let mut replays = self.replays.lock().map_err(|_| ExchangeError::Storage)?;
        if let Some(existing) = replays.get(&replay_key) {
            return if existing.request == bytes {
                Ok(existing.response.clone())
            } else {
                Ok(error_response(
                    request_id,
                    Some(command),
                    Status::AuthReplay,
                ))
            };
        }

        let response = match self.execute(request, now) {
            Ok(response) => response,
            Err(ExecuteError::Protocol(status)) => Response::Error(
                ErrorResponse::new(Some(command), status).expect("status is always an error"),
            ),
            Err(ExecuteError::Storage) => return Err(ExchangeError::Storage),
        };
        let response = encode_response(&ResponseFrame::new(request_id, response));
        replays.insert(
            replay_key,
            ReplayEntry {
                request: bytes.to_vec(),
                response: response.clone(),
            },
        );
        Ok(response)
    }

    fn execute(&self, request: &Request, now: relay::Timestamp) -> Result<Response, ExecuteError> {
        let mut durable = self.relay.lock().map_err(|_| ExecuteError::Storage)?;
        let result = match request {
            Request::CreateQueue(create) => {
                let limits = relay::QueueLimits::new(
                    usize::try_from(create.limits().max_messages())
                        .map_err(|_| ExecuteError::Protocol(Status::LimitOutOfRange))?,
                    usize::try_from(create.limits().max_message_bytes())
                        .map_err(|_| ExecuteError::Protocol(Status::LimitOutOfRange))?,
                )
                .ok_or(ExecuteError::Protocol(Status::LimitOutOfRange))?;
                durable
                    .create_queue(
                        relay_queue(create.queue_id()),
                        relay::QueueConfig::new(
                            relay_principal(create.sender()),
                            relay_principal(create.recipient()),
                            limits,
                        ),
                    )
                    .map(|outcome| {
                        ResponseBody::CreateQueue(match outcome {
                            relay::CreateQueueOutcome::Created => {
                                cofferwire_types::CreateQueueOutcome::Created
                            }
                            relay::CreateQueueOutcome::AlreadyExists => {
                                cofferwire_types::CreateQueueOutcome::AlreadyExists
                            }
                        })
                    })
            }
            Request::Send(send) => {
                let ttl = relay::Ttl::from_secs(send.ttl().as_secs())
                    .ok_or(ExecuteError::Protocol(Status::LimitOutOfRange))?;
                durable
                    .send(
                        relay_queue(send.queue_id()),
                        relay_principal(send.sender()),
                        relay::MessageId::from_bytes(*send.message_id().as_bytes()),
                        send.payload().as_bytes(),
                        now,
                        ttl,
                    )
                    .map(|outcome| {
                        ResponseBody::Send(match outcome {
                            relay::SendOutcome::Accepted => cofferwire_types::SendOutcome::Accepted,
                            relay::SendOutcome::Duplicate => {
                                cofferwire_types::SendOutcome::Duplicate
                            }
                        })
                    })
            }
            Request::Fetch(fetch) => durable
                .fetch(
                    relay_queue(fetch.queue_id()),
                    relay_principal(fetch.recipient()),
                    now,
                )
                .and_then(|delivery| delivery.as_ref().map_or(Ok(None), wire_delivery))
                .map(ResponseBody::Fetch),
            Request::Ack(ack) => durable
                .acknowledge(
                    relay_queue(ack.queue_id()),
                    relay_principal(ack.recipient()),
                    relay::MessageId::from_bytes(*ack.message_id().as_bytes()),
                    now,
                )
                .map(|()| ResponseBody::Ack),
            Request::DeleteQueue(delete) => durable
                .delete_queue(
                    relay_queue(delete.queue_id()),
                    relay_principal(delete.recipient()),
                )
                .map(|()| ResponseBody::DeleteQueue),
        };
        result.map(Response::Success).map_err(ExecuteError::from)
    }
}

#[derive(Clone, Debug)]
struct ReplayEntry {
    request: Vec<u8>,
    response: Vec<u8>,
}

/// Builds the bounded HTTPS/WebSocket application router.
pub fn router(service: RelayService) -> Router {
    Router::new()
        .route("/healthz", get(|| async { HttpStatus::NO_CONTENT }))
        .route("/v1/frame", post(post_frame))
        .route("/v1/ws", get(upgrade_websocket))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(MAX_FRAME_BYTES))
        .layer(TimeoutLayer::new(REQUEST_TIMEOUT))
        .with_state(service)
}

async fn post_frame(
    State(service): State<RelayService>,
    headers: HeaderMap,
    body: Bytes,
) -> HttpResponse {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(FRAME_MEDIA_TYPE)
    {
        return HttpStatus::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    match service.exchange(body.to_vec()).await {
        Ok(response) => ([(header::CONTENT_TYPE, FRAME_MEDIA_TYPE)], response).into_response(),
        Err(_) => HttpStatus::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn upgrade_websocket(
    State(service): State<RelayService>,
    OptionalConnectionPermit(connection_permit): OptionalConnectionPermit,
    upgrade: WebSocketUpgrade,
) -> HttpResponse {
    let Ok(permit) = Arc::clone(&service.websocket_connections).try_acquire_owned() else {
        return HttpStatus::SERVICE_UNAVAILABLE.into_response();
    };
    upgrade
        .protocols([WEBSOCKET_PROTOCOL])
        .max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| websocket_session(socket, service, permit, connection_permit))
        .into_response()
}

async fn websocket_session(
    mut socket: WebSocket,
    service: RelayService,
    _permit: OwnedSemaphorePermit,
    _connection_permit: Option<ConnectionPermit>,
) {
    loop {
        let Ok(Some(Ok(message))) =
            tokio::time::timeout(WEBSOCKET_IDLE_TIMEOUT, socket.next()).await
        else {
            break;
        };
        match message {
            Message::Binary(bytes) => {
                let Ok(response) = service.exchange(bytes.to_vec()).await else {
                    break;
                };
                if socket.send(Message::Binary(response.into())).await.is_err() {
                    break;
                }
            }
            Message::Close(_) | Message::Text(_) => break,
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }
}

#[derive(Debug)]
enum ExchangeError {
    Overloaded,
    Storage,
    Internal,
}

/// A storage failure at the deterministic conformance exchange boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameExchangeError;

impl std::fmt::Display for FrameExchangeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("relay frame exchange failed")
    }
}

impl std::error::Error for FrameExchangeError {}

#[derive(Debug)]
enum ExecuteError {
    Protocol(Status),
    Storage,
}

impl From<relay::DurableRelayError> for ExecuteError {
    fn from(error: relay::DurableRelayError) -> Self {
        match error {
            relay::DurableRelayError::Relay(error) => Self::Protocol(relay_status(error)),
            relay::DurableRelayError::Storage { .. }
            | relay::DurableRelayError::UnsupportedSchemaVersion { .. } => Self::Storage,
        }
    }
}

fn decode_error_response(bytes: &[u8], error: &DecodeError) -> Vec<u8> {
    let request_id = match error {
        DecodeError::UnsupportedVersion { request_id, .. } => *request_id,
        _ => request_id_from_prefix(bytes),
    };
    let status = match error {
        DecodeError::UnsupportedVersion { .. } => Status::UnsupportedVersion,
        DecodeError::FrameTooLarge { .. } => Status::FrameTooLarge,
        _ => Status::MalformedFrame,
    };
    error_response(request_id, None, status)
}

fn request_id_from_prefix(bytes: &[u8]) -> RequestId {
    let mut id = [0_u8; 16];
    if let Some(source) = bytes.get(1..17) {
        id.copy_from_slice(source);
    }
    RequestId::from_bytes(id)
}

fn error_response(request_id: RequestId, command: Option<Command>, status: Status) -> Vec<u8> {
    let response = Response::Error(
        ErrorResponse::new(command, status).expect("callers pass only non-success status"),
    );
    encode_response(&ResponseFrame::new(request_id, response))
}

fn request_principal(request: &Request) -> Principal {
    match request {
        Request::CreateQueue(create) => create.sender(),
        Request::Send(send) => send.sender(),
        Request::Fetch(fetch) => fetch.recipient(),
        Request::Ack(ack) => ack.recipient(),
        Request::DeleteQueue(delete) => delete.recipient(),
    }
}

fn relay_queue(queue: cofferwire_types::QueueId) -> relay::QueueId {
    relay::QueueId::from_bytes(*queue.as_bytes())
}

fn relay_principal(principal: Principal) -> relay::Principal {
    relay::Principal::from_bytes(*principal.as_bytes())
}

fn wire_delivery(delivery: &relay::Delivery) -> Result<Option<Delivery>, relay::DurableRelayError> {
    let payload = cofferwire_types::Payload::new(delivery.payload().to_vec())
        .map_err(|_| relay::DurableRelayError::Relay(relay::RelayError::MessageTooLarge))?;
    Ok(Some(Delivery::new(
        cofferwire_types::MessageId::from_bytes(*delivery.id().as_bytes()),
        payload,
        Timestamp::from_secs(delivery.expires_at().as_secs()),
    )))
}

const fn relay_status(error: relay::RelayError) -> Status {
    match error {
        relay::RelayError::QueueNotFound => Status::QueueNotFound,
        relay::RelayError::Unauthorized => Status::Unauthorized,
        relay::RelayError::QueueIdConflict => Status::QueueIdConflict,
        relay::RelayError::MessageIdConflict => Status::MessageIdConflict,
        relay::RelayError::MessageTooLarge => Status::MessageTooLarge,
        relay::RelayError::QueueFull => Status::QueueFull,
        relay::RelayError::ExpiryOverflow => Status::ExpiryOverflow,
        relay::RelayError::AckMismatch => Status::AckMismatch,
        relay::RelayError::NotDelivered => Status::NotDelivered,
    }
}

fn relay_time() -> relay::Timestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    relay::Timestamp::from_secs(seconds)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::body::{to_bytes, Body};
    use axum::http::Request as HttpRequest;
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
    };
    use futures_util::SinkExt;
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
        let limiter = ConnectionLimit {
            permits: Arc::new(Semaphore::new(1)),
        };
        let ((), connection) = limiter
            .accept((), ())
            .await
            .expect("first connection is admitted");
        assert!(limiter.accept((), ()).await.is_err());
        drop(connection);
        assert!(limiter.accept((), ()).await.is_ok());
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
}
