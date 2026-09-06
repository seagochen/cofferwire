use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command as ProcessCommand, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use cofferwire_client::{
    CommitOutcome, InboxStore, Recipient, RequestIdSource, Sender, StoreError, Transport,
    TransportError,
};
use cofferwire_codec::{
    decode_response, encode_authenticated_request, encode_request, RequestFrame,
};
use cofferwire_crypto::{EncryptionSecretKey, RelaySigningKey};
use cofferwire_types::{
    CreateQueueRequest, DeleteQueueRequest, FetchRequest, MessageId, QueueId, QueueLimits, Request,
    RequestId, Response, ResponseBody, Status, Ttl,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);
const TRACE_CATALOG: &str = include_str!("../../../vectors/queue-v1-traces.json");

struct PythonTransport {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<BufReader<ChildStdout>>,
    database: PathBuf,
    now: u64,
    lose_next_response: bool,
}

impl PythonTransport {
    fn start() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .to_path_buf();
        let database = std::env::temp_dir().join(format!(
            "cofferwire-python-interop-{}-{}.sqlite",
            std::process::id(),
            NEXT_DATABASE.fetch_add(1, Ordering::Relaxed)
        ));
        let (child, input, output) = Self::spawn(&root, &database);
        Self {
            child: Some(child),
            input: Some(input),
            output: Some(output),
            database,
            now: 1_000,
            lose_next_response: false,
        }
    }

    fn spawn(
        root: &std::path::Path,
        database: &std::path::Path,
    ) -> (Child, ChildStdin, BufReader<ChildStdout>) {
        let mut child = ProcessCommand::new("python3")
            .arg(root.join("independent/python/cofferwire_v1.py"))
            .arg("line-relay")
            .arg(database)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("independent Python relay starts");
        let input = child.stdin.take().expect("child stdin");
        let output = BufReader::new(child.stdout.take().expect("child stdout"));
        (child, input, output)
    }

    fn restart(&mut self) {
        drop(self.input.take());
        self.child
            .as_mut()
            .expect("running child")
            .wait()
            .expect("relay stops cleanly");
        self.output.take();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root")
            .to_path_buf();
        let (child, input, output) = Self::spawn(&root, &self.database);
        self.child = Some(child);
        self.input = Some(input);
        self.output = Some(output);
    }
}

impl Transport for PythonTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let input = self.input.as_mut().ok_or(TransportError)?;
        writeln!(input, "{} {}", self.now, encode_hex(request)).map_err(|_| TransportError)?;
        input.flush().map_err(|_| TransportError)?;
        let mut line = String::new();
        self.output
            .as_mut()
            .ok_or(TransportError)?
            .read_line(&mut line)
            .map_err(|_| TransportError)?;
        if self.lose_next_response {
            self.lose_next_response = false;
            return Err(TransportError);
        }
        decode_hex(line.trim()).ok_or(TransportError)
    }
}

impl Drop for PythonTransport {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        for suffix in ["", "-journal", "-shm", "-wal"] {
            let _ = fs::remove_file(format!("{}{suffix}", self.database.display()));
        }
    }
}

struct RequestIds(u128);

impl RequestIdSource for RequestIds {
    fn next_request_id(&mut self) -> RequestId {
        let result = RequestId::from_bytes(self.0.to_be_bytes());
        self.0 += 1;
        result
    }
}

#[derive(Default)]
struct Inbox(Vec<(MessageId, Vec<u8>)>);

impl InboxStore for Inbox {
    fn commit(
        &mut self,
        message_id: MessageId,
        plaintext: &[u8],
    ) -> Result<CommitOutcome, StoreError> {
        if self.0.iter().any(|(existing, _)| *existing == message_id) {
            return Ok(CommitOutcome::AlreadyCommitted);
        }
        self.0.push((message_id, plaintext.to_vec()));
        Ok(CommitOutcome::Applied)
    }
}

struct VectorRng(u8);

impl RngCore for VectorRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for VectorRng {}

fn signed_frame(key: &RelaySigningKey, request_id: RequestId, request: Request) -> Vec<u8> {
    let authenticated = encode_authenticated_request(request_id, &request);
    let auth = key.sign_request(&authenticated);
    encode_request(&RequestFrame::new(request_id, request, auth))
}

fn assert_trace_catalog() {
    for number in 1..=8 {
        assert!(TRACE_CATALOG.contains(&format!("QV1-TRACE-{number:03}")));
    }
}

fn assert_negative_paths(
    transport: &mut PythonTransport,
    queue: QueueId,
    recipient: cofferwire_types::Principal,
    recipient_signing: &RelaySigningKey,
) {
    let fetch = Request::Fetch(FetchRequest::new(queue, recipient));
    let mut invalid = signed_frame(
        recipient_signing,
        RequestId::from_bytes(4_u128.to_be_bytes()),
        fetch.clone(),
    );
    *invalid.last_mut().expect("auth byte") ^= 1;
    let response = transport.exchange(&invalid).expect("invalid auth response");
    assert!(matches!(
        decode_response(&response).expect("auth response decodes").response(),
        Response::Error(error) if error.status() == Status::AuthInvalid
    ));

    let response = transport
        .exchange(&signed_frame(
            recipient_signing,
            RequestId::from_bytes(5_u128.to_be_bytes()),
            fetch,
        ))
        .expect("first fetch exchange");
    assert!(matches!(
        decode_response(&response)
            .expect("fetch response")
            .response(),
        Response::Success(ResponseBody::Fetch(Some(_)))
    ));
}

fn assert_terminal_paths(
    transport: &mut PythonTransport,
    queue: QueueId,
    recipient: cofferwire_types::Principal,
    recipient_signing: &RelaySigningKey,
) {
    let malformed = [vec![1], vec![0; 16], vec![0xff]].concat();
    let response = transport.exchange(&malformed).expect("malformed response");
    assert!(matches!(
        decode_response(&response).expect("malformed response decodes").response(),
        Response::Error(error) if error.status() == Status::MalformedFrame
    ));

    let delete_id = RequestId::from_bytes(10_u128.to_be_bytes());
    let delete = Request::DeleteQueue(DeleteQueueRequest::new(queue, recipient));
    let response = transport
        .exchange(&signed_frame(recipient_signing, delete_id, delete))
        .expect("delete exchange");
    assert!(matches!(
        decode_response(&response)
            .expect("delete response")
            .response(),
        Response::Success(ResponseBody::DeleteQueue)
    ));

    let mut unsupported = vec![2];
    unsupported.extend([0xAA; 16]);
    unsupported.extend(b"future");
    let response = transport.exchange(&unsupported).expect("version response");
    assert!(matches!(
        decode_response(&response).expect("version response decodes").response(),
        Response::Error(error) if error.status() == Status::UnsupportedVersion
    ));
}

#[test]
fn rust_client_interoperates_with_independent_python_relay() {
    if std::env::var_os("COFFERWIRE_MATRIX").is_none() {
        return;
    }
    assert_trace_catalog();
    let queue = QueueId::from_bytes([0x41; 32]);
    let message = MessageId::from_bytes([0x51; 32]);
    let sender_signing = RelaySigningKey::from_seed([0x31; 32]);
    let recipient_signing = RelaySigningKey::from_seed([0x32; 32]);
    let sender = sender_signing.principal();
    let recipient = recipient_signing.principal();
    let sender_encryption = EncryptionSecretKey::derive(&[0x55; 32]);
    let recipient_encryption = EncryptionSecretKey::derive(&[0x66; 32]);
    let mut transport = PythonTransport::start();

    let create_id = RequestId::from_bytes(1_u128.to_be_bytes());
    let create = Request::CreateQueue(CreateQueueRequest::new(
        queue,
        sender,
        recipient,
        QueueLimits::new(2, 1024).expect("valid limits"),
    ));
    let response = transport
        .exchange(&signed_frame(&sender_signing, create_id, create))
        .expect("create exchange");
    assert!(matches!(
        decode_response(&response)
            .expect("create response")
            .response(),
        Response::Success(ResponseBody::CreateQueue(_))
    ));

    let sender_client = Sender::new(
        queue,
        sender,
        recipient,
        sender_signing,
        sender_encryption,
        recipient_encryption.public_key(),
    )
    .expect("sender configuration");
    let prepared = sender_client
        .prepare(
            RequestId::from_bytes(2_u128.to_be_bytes()),
            message,
            b"cross implementation",
            Ttl::from_secs(60),
            &mut VectorRng(0),
        )
        .expect("prepare message");
    transport.lose_next_response = true;
    assert!(sender_client.send(&prepared, &mut transport).is_err());
    sender_client
        .send(&prepared, &mut transport)
        .expect("exact retry succeeds");
    let second_message = MessageId::from_bytes([0x52; 32]);
    let second = sender_client
        .prepare(
            RequestId::from_bytes(3_u128.to_be_bytes()),
            second_message,
            b"second cross implementation message",
            Ttl::from_secs(60),
            &mut VectorRng(64),
        )
        .expect("prepare second message");
    sender_client
        .send(&second, &mut transport)
        .expect("second send succeeds");
    transport.restart();

    assert_negative_paths(&mut transport, queue, recipient, &recipient_signing);

    let recipient_client = Recipient::new(
        queue,
        sender,
        recipient,
        recipient_signing.clone(),
        recipient_encryption,
        sender_client_encryption_public(),
    )
    .expect("recipient configuration");
    let mut inbox = Inbox::default();
    let mut request_ids = RequestIds(6);
    recipient_client
        .poll(&mut transport, &mut inbox, &mut request_ids)
        .expect("fetch, decrypt, commit and ack succeed");
    assert_eq!(inbox.0, vec![(message, b"cross implementation".to_vec())]);
    recipient_client
        .poll(&mut transport, &mut inbox, &mut request_ids)
        .expect("second message follows the first");
    assert_eq!(
        inbox.0,
        vec![
            (message, b"cross implementation".to_vec()),
            (
                second_message,
                b"second cross implementation message".to_vec()
            ),
        ]
    );

    assert_terminal_paths(&mut transport, queue, recipient, &recipient_signing);
}

fn sender_client_encryption_public() -> cofferwire_crypto::EncryptionPublicKey {
    EncryptionSecretKey::derive(&[0x55; 32]).public_key()
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("String writes cannot fail");
        output
    })
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
        })
        .collect()
}
