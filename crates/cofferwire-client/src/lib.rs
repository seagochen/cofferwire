//! Durable, transport-independent Cofferwire client state machines.

#![forbid(unsafe_code)]

pub mod blob;
pub mod offline;
pub mod receipt;

use cofferwire_codec::{
    decode_request, decode_response, encode_authenticated_request, encode_request, DecodeError,
    RequestFrame,
};
use cofferwire_crypto::{
    open_message, seal_message, verify_request, CryptoError, EncryptionPublicKey,
    EncryptionSecretKey, MessageContext, RelaySigningKey,
};
use cofferwire_types::{
    AckRequest, Command, FetchRequest, MessageId, Principal, QueueId, Request, RequestId, Response,
    ResponseBody, SendOutcome, SendRequest, Status, Ttl,
};
use rand_core::{CryptoRng, RngCore};

/// A transport failure with no secret-bearing diagnostic payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportError;

/// A local durable-store failure with no plaintext-bearing diagnostic payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreError;

/// Moves exactly one already-delimited protocol frame.
///
/// Implementations may use HTTPS, WebSocket, files, tests, or another binding;
/// the client state machine never depends on connection identity or ordering.
pub trait Transport {
    /// Sends one request frame and returns its complete response frame.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] when no complete response frame is available.
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError>;
}

/// Supplies fresh request identifiers independently of any transport.
pub trait RequestIdSource {
    /// Returns the next identifier. Implementations must not repeat an ID for a
    /// different authenticated request under the same principal and queue.
    fn next_request_id(&mut self) -> RequestId;
}

/// Result of an idempotent local inbox commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// The message was durably stored and applied for the first time.
    Applied,
    /// The same message was already durably stored and must not be applied again.
    AlreadyCommitted,
}

/// The recipient's atomic local durability and deduplication boundary.
pub trait InboxStore {
    /// Durably stores and applies a plaintext exactly once by `message_id`.
    ///
    /// Returning [`CommitOutcome::Applied`] promises the commit survives a
    /// process crash. Returning [`CommitOutcome::AlreadyCommitted`] promises no
    /// second application occurred. An error must mean neither promise was made.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] unless the durable success contract above holds.
    fn commit(
        &mut self,
        message_id: MessageId,
        plaintext: &[u8],
    ) -> Result<CommitOutcome, StoreError>;
}

/// A state-machine failure. No variant contains keys, plaintext or ciphertext.
#[derive(Debug)]
pub enum ClientError {
    /// A configured signing key does not match its queue principal.
    PrincipalKeyMismatch,
    /// The replaceable transport failed before a valid response arrived.
    Transport(TransportError),
    /// The response frame was malformed or non-canonical.
    Decode(DecodeError),
    /// A cryptographic operation failed.
    Crypto(CryptoError),
    /// The response request ID did not match the outstanding request.
    ResponseRequestIdMismatch,
    /// The response command did not match the outstanding request.
    ResponseCommandMismatch,
    /// The relay returned a non-success protocol status.
    Relay(Status),
    /// The relay returned a valid success body not allowed at this transition.
    UnexpectedResponse,
    /// The local durable commit failed, so ACK was not attempted.
    Store(StoreError),
    /// Persisted sender state was not a valid authenticated SEND request.
    InvalidPreparedSend,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrincipalKeyMismatch => {
                formatter.write_str("principal does not match signing key")
            }
            Self::Transport(_) => formatter.write_str("transport exchange failed"),
            Self::Decode(error) => write!(formatter, "invalid response frame: {error}"),
            Self::Crypto(error) => write!(formatter, "cryptographic operation failed: {error}"),
            Self::ResponseRequestIdMismatch => formatter.write_str("response request ID mismatch"),
            Self::ResponseCommandMismatch => formatter.write_str("response command mismatch"),
            Self::Relay(status) => write!(formatter, "relay returned status {status:?}"),
            Self::UnexpectedResponse => formatter.write_str("unexpected successful response body"),
            Self::Store(_) => formatter.write_str("durable inbox commit failed"),
            Self::InvalidPreparedSend => formatter.write_str("invalid persisted SEND state"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<TransportError> for ClientError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<DecodeError> for ClientError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<CryptoError> for ClientError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

/// Immutable, persistable state for one SEND operation.
///
/// Retrying this value reuses the exact request ID, message ID, ciphertext and
/// signature bytes. Debug output deliberately reveals only identifiers and size.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedSend {
    request_id: RequestId,
    message_id: MessageId,
    frame: Vec<u8>,
}

impl PreparedSend {
    /// Returns the stable message identifier.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// Returns the stable request identifier used by exact retries.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the exact bytes an outbox must durably persist before sending.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.frame
    }
}

impl std::fmt::Debug for PreparedSend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSend")
            .field("request_id", &self.request_id)
            .field("message_id", &self.message_id)
            .field("frame_len", &self.frame.len())
            .finish()
    }
}

/// Successful completion of an idempotent SEND.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendCompletion {
    /// The relay accepted a new message.
    Accepted,
    /// The relay had already accepted the exact same message.
    Duplicate,
}

/// Sender state machine bound to one device queue and recipient device.
pub struct Sender {
    queue_id: QueueId,
    sender: Principal,
    recipient: Principal,
    signing_key: RelaySigningKey,
    encryption_key: EncryptionSecretKey,
    recipient_encryption_key: EncryptionPublicKey,
}

impl Sender {
    /// Constructs a sender and verifies that its signing key owns `sender`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::PrincipalKeyMismatch`] for inconsistent config.
    pub fn new(
        queue_id: QueueId,
        sender: Principal,
        recipient: Principal,
        signing_key: RelaySigningKey,
        encryption_key: EncryptionSecretKey,
        recipient_encryption_key: EncryptionPublicKey,
    ) -> Result<Self, ClientError> {
        if signing_key.principal() != sender {
            return Err(ClientError::PrincipalKeyMismatch);
        }
        Ok(Self {
            queue_id,
            sender,
            recipient,
            signing_key,
            encryption_key,
            recipient_encryption_key,
        })
    }

    /// Encrypts once and returns exact bytes that must be durably persisted.
    ///
    /// # Errors
    ///
    /// Returns a cryptographic or size error without constructing partial state.
    pub fn prepare<R: CryptoRng + RngCore>(
        &self,
        request_id: RequestId,
        message_id: MessageId,
        plaintext: &[u8],
        ttl: Ttl,
        rng: &mut R,
    ) -> Result<PreparedSend, ClientError> {
        let context = MessageContext {
            queue_id: self.queue_id,
            sender: self.sender,
            recipient: self.recipient,
            message_id,
        };
        let ciphertext = seal_message(
            &self.encryption_key,
            self.recipient_encryption_key,
            context,
            plaintext,
            rng,
        )?;
        let request = Request::Send(SendRequest::new(
            self.queue_id,
            self.sender,
            message_id,
            ciphertext,
            ttl,
        ));
        let frame = signed_frame(&self.signing_key, request_id, request);
        Ok(PreparedSend {
            request_id,
            message_id,
            frame,
        })
    }

    /// Restores and authenticates exact persisted SEND bytes after a restart.
    ///
    /// # Errors
    ///
    /// Rejects malformed, differently signed, or non-SEND state.
    pub fn restore(&self, bytes: Vec<u8>) -> Result<PreparedSend, ClientError> {
        let decoded = decode_request(&bytes).map_err(|_| ClientError::InvalidPreparedSend)?;
        verify_request(
            self.sender,
            decoded.authenticated_bytes(),
            decoded.frame().auth(),
        )
        .map_err(|_| ClientError::InvalidPreparedSend)?;
        let (request_id, message_id) = match decoded.frame().request() {
            Request::Send(send)
                if send.queue_id() == self.queue_id && send.sender() == self.sender =>
            {
                (decoded.frame().request_id(), send.message_id())
            }
            _ => return Err(ClientError::InvalidPreparedSend),
        };
        drop(decoded);
        Ok(PreparedSend {
            request_id,
            message_id,
            frame: bytes,
        })
    }

    /// Attempts an exact SEND. Calling it again with the same prepared state is
    /// the retry transition and emits byte-for-byte identical ciphertext.
    ///
    /// # Errors
    ///
    /// Transport, decode, correlation, status and response-shape failures are
    /// returned without mutating the prepared state.
    pub fn send<T: Transport>(
        &self,
        prepared: &PreparedSend,
        transport: &mut T,
    ) -> Result<SendCompletion, ClientError> {
        let response = transport.exchange(prepared.as_bytes())?;
        let response = checked_response(&response, prepared.request_id, Command::Send)?;
        match response {
            Response::Success(ResponseBody::Send(SendOutcome::Accepted)) => {
                Ok(SendCompletion::Accepted)
            }
            Response::Success(ResponseBody::Send(SendOutcome::Duplicate)) => {
                Ok(SendCompletion::Duplicate)
            }
            Response::Error(error) => Err(ClientError::Relay(error.status())),
            Response::Success(_) => Err(ClientError::UnexpectedResponse),
        }
    }
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sender")
            .field("queue_id", &self.queue_id)
            .field("sender", &self.sender)
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

/// Result of one recipient polling transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollOutcome {
    /// The relay had no current unexpired message.
    Empty,
    /// A new application message was durably committed and relay-acknowledged.
    Applied(MessageId),
    /// A redelivered message was already committed and was relay-acknowledged.
    RedeliveryAcknowledged(MessageId),
}

/// Recipient state machine bound to one independent device queue.
pub struct Recipient {
    queue_id: QueueId,
    sender: Principal,
    recipient: Principal,
    signing_key: RelaySigningKey,
    encryption_key: EncryptionSecretKey,
    sender_encryption_key: EncryptionPublicKey,
}

impl Recipient {
    /// Constructs a recipient and verifies that its signing key owns `recipient`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::PrincipalKeyMismatch`] for inconsistent config.
    pub fn new(
        queue_id: QueueId,
        sender: Principal,
        recipient: Principal,
        signing_key: RelaySigningKey,
        encryption_key: EncryptionSecretKey,
        sender_encryption_key: EncryptionPublicKey,
    ) -> Result<Self, ClientError> {
        if signing_key.principal() != recipient {
            return Err(ClientError::PrincipalKeyMismatch);
        }
        Ok(Self {
            queue_id,
            sender,
            recipient,
            signing_key,
            encryption_key,
            sender_encryption_key,
        })
    }

    /// Executes `FETCH -> authenticate/decrypt -> durable commit -> ACK` once.
    ///
    /// # Errors
    ///
    /// Any failure before durable commit returns without sending ACK. A failure
    /// while sending ACK leaves the committed message for safe redelivery.
    pub fn poll<T: Transport, S: InboxStore, I: RequestIdSource>(
        &self,
        transport: &mut T,
        store: &mut S,
        request_ids: &mut I,
    ) -> Result<PollOutcome, ClientError> {
        let fetch_id = request_ids.next_request_id();
        let fetch = Request::Fetch(FetchRequest::new(self.queue_id, self.recipient));
        let fetch_bytes = signed_frame(&self.signing_key, fetch_id, fetch);
        let response = transport.exchange(&fetch_bytes)?;
        let response = checked_response(&response, fetch_id, Command::Fetch)?;
        let delivery = match response {
            Response::Success(ResponseBody::Fetch(None)) => return Ok(PollOutcome::Empty),
            Response::Success(ResponseBody::Fetch(Some(delivery))) => delivery,
            Response::Error(error) => return Err(ClientError::Relay(error.status())),
            Response::Success(_) => return Err(ClientError::UnexpectedResponse),
        };

        let message_id = delivery.message_id();
        let context = MessageContext {
            queue_id: self.queue_id,
            sender: self.sender,
            recipient: self.recipient,
            message_id,
        };
        let plaintext = open_message(
            &self.encryption_key,
            self.sender_encryption_key,
            context,
            delivery.payload(),
        )?;
        let commit = store
            .commit(message_id, &plaintext)
            .map_err(ClientError::Store)?;

        let ack_id = request_ids.next_request_id();
        let ack = Request::Ack(AckRequest::new(self.queue_id, self.recipient, message_id));
        let ack_bytes = signed_frame(&self.signing_key, ack_id, ack);
        let response = transport.exchange(&ack_bytes)?;
        match checked_response(&response, ack_id, Command::Ack)? {
            Response::Success(ResponseBody::Ack) => match commit {
                CommitOutcome::Applied => Ok(PollOutcome::Applied(message_id)),
                CommitOutcome::AlreadyCommitted => {
                    Ok(PollOutcome::RedeliveryAcknowledged(message_id))
                }
            },
            Response::Error(error) => Err(ClientError::Relay(error.status())),
            Response::Success(_) => Err(ClientError::UnexpectedResponse),
        }
    }
}

impl std::fmt::Debug for Recipient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Recipient")
            .field("queue_id", &self.queue_id)
            .field("sender", &self.sender)
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

fn signed_frame(key: &RelaySigningKey, request_id: RequestId, request: Request) -> Vec<u8> {
    let authenticated = encode_authenticated_request(request_id, &request);
    let auth = key.sign_request(&authenticated);
    encode_request(&RequestFrame::new(request_id, request, auth))
}

fn checked_response(
    bytes: &[u8],
    request_id: RequestId,
    command: Command,
) -> Result<Response, ClientError> {
    let frame = decode_response(bytes)?;
    if frame.request_id() != request_id {
        return Err(ClientError::ResponseRequestIdMismatch);
    }
    if frame.response().command() != Some(command) {
        return Err(ClientError::ResponseCommandMismatch);
    }
    Ok(frame.response().clone())
}
