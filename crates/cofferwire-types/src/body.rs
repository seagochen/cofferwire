use crate::error::TypeError;
use crate::ids::{MessageId, Principal, QueueId};
use crate::limits::QueueLimits;
use crate::payload::Payload;
use crate::time::{Timestamp, Ttl};
use crate::Command;

/// `CREATE_QUEUE` (1) request body: `[queue-id, sender, recipient,
/// max-messages, max-message-bytes]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateQueueRequest {
    queue_id: QueueId,
    sender: Principal,
    recipient: Principal,
    limits: QueueLimits,
}

impl CreateQueueRequest {
    /// Constructs a `CREATE_QUEUE` request body.
    #[must_use]
    pub const fn new(
        queue_id: QueueId,
        sender: Principal,
        recipient: Principal,
        limits: QueueLimits,
    ) -> Self {
        Self {
            queue_id,
            sender,
            recipient,
            limits,
        }
    }

    /// Returns the queue identifier.
    #[must_use]
    pub const fn queue_id(&self) -> QueueId {
        self.queue_id
    }

    /// Returns the principal authorized to send.
    #[must_use]
    pub const fn sender(&self) -> Principal {
        self.sender
    }

    /// Returns the principal authorized to fetch, acknowledge and delete.
    #[must_use]
    pub const fn recipient(&self) -> Principal {
        self.recipient
    }

    /// Returns the requested queue resource limits.
    #[must_use]
    pub const fn limits(&self) -> QueueLimits {
        self.limits
    }
}

/// `CREATE_QUEUE` (1) response body: `[outcome]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateQueueOutcome {
    /// `outcome = 0`: a new queue was created.
    Created,
    /// `outcome = 1`: the same identifier and configuration already existed.
    AlreadyExists,
}

impl CreateQueueOutcome {
    /// Returns the wire outcome code.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Created => 0,
            Self::AlreadyExists => 1,
        }
    }
}

impl TryFrom<u8> for CreateQueueOutcome {
    type Error = TypeError;

    /// # Errors
    ///
    /// Returns [`TypeError::UnknownDiscriminant`] when `value` is neither
    /// `0` nor `1`.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Created),
            1 => Ok(Self::AlreadyExists),
            other => Err(TypeError::UnknownDiscriminant {
                type_name: "CreateQueueOutcome",
                value: other,
            }),
        }
    }
}

/// `SEND` (2) request body: `[queue-id, sender, message-id, payload, ttl]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendRequest {
    queue_id: QueueId,
    sender: Principal,
    message_id: MessageId,
    payload: Payload,
    ttl: Ttl,
}

impl SendRequest {
    /// Constructs a `SEND` request body.
    #[must_use]
    pub const fn new(
        queue_id: QueueId,
        sender: Principal,
        message_id: MessageId,
        payload: Payload,
        ttl: Ttl,
    ) -> Self {
        Self {
            queue_id,
            sender,
            message_id,
            payload,
            ttl,
        }
    }

    /// Returns the queue identifier.
    #[must_use]
    pub const fn queue_id(&self) -> QueueId {
        self.queue_id
    }

    /// Returns the sending principal.
    #[must_use]
    pub const fn sender(&self) -> Principal {
        self.sender
    }

    /// Returns the sender-chosen idempotency identifier.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// Returns the opaque message payload.
    #[must_use]
    pub const fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Consumes the request, returning its opaque message payload.
    #[must_use]
    pub fn into_payload(self) -> Payload {
        self.payload
    }

    /// Returns the requested message lifetime.
    #[must_use]
    pub const fn ttl(&self) -> Ttl {
        self.ttl
    }
}

/// `SEND` (2) response body: `[outcome]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// `outcome = 0`: a new message was accepted.
    Accepted,
    /// `outcome = 1`: the same message identifier and payload were already accepted.
    Duplicate,
}

impl SendOutcome {
    /// Returns the wire outcome code.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Accepted => 0,
            Self::Duplicate => 1,
        }
    }
}

impl TryFrom<u8> for SendOutcome {
    type Error = TypeError;

    /// # Errors
    ///
    /// Returns [`TypeError::UnknownDiscriminant`] when `value` is neither
    /// `0` nor `1`.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Duplicate),
            other => Err(TypeError::UnknownDiscriminant {
                type_name: "SendOutcome",
                value: other,
            }),
        }
    }
}

/// `FETCH` (3) request body: `[queue-id, recipient]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchRequest {
    queue_id: QueueId,
    recipient: Principal,
}

impl FetchRequest {
    /// Constructs a `FETCH` request body.
    #[must_use]
    pub const fn new(queue_id: QueueId, recipient: Principal) -> Self {
        Self {
            queue_id,
            recipient,
        }
    }

    /// Returns the queue identifier.
    #[must_use]
    pub const fn queue_id(&self) -> QueueId {
        self.queue_id
    }

    /// Returns the fetching principal.
    #[must_use]
    pub const fn recipient(&self) -> Principal {
        self.recipient
    }
}

/// The `[1, message-id, payload, expires-at]` shape of a `FETCH` (3)
/// response body when a message is available (`CW-WIRE-026`). The `[0]`
/// shape ("no message available") is represented as `None` wherever this
/// type is used, matching the executable relay model's `Option<Delivery>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    message_id: MessageId,
    payload: Payload,
    expires_at: Timestamp,
}

impl Delivery {
    /// Constructs a delivered message.
    #[must_use]
    pub const fn new(message_id: MessageId, payload: Payload, expires_at: Timestamp) -> Self {
        Self {
            message_id,
            payload,
            expires_at,
        }
    }

    /// Returns the sender-chosen message identifier.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// Returns the opaque message payload.
    #[must_use]
    pub const fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Returns the relay expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

/// `ACK` (4) request body: `[queue-id, recipient, message-id]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRequest {
    queue_id: QueueId,
    recipient: Principal,
    message_id: MessageId,
}

impl AckRequest {
    /// Constructs an `ACK` request body.
    #[must_use]
    pub const fn new(queue_id: QueueId, recipient: Principal, message_id: MessageId) -> Self {
        Self {
            queue_id,
            recipient,
            message_id,
        }
    }

    /// Returns the queue identifier.
    #[must_use]
    pub const fn queue_id(&self) -> QueueId {
        self.queue_id
    }

    /// Returns the acknowledging principal.
    #[must_use]
    pub const fn recipient(&self) -> Principal {
        self.recipient
    }

    /// Returns the acknowledged message identifier.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }
}

/// `DELETE_QUEUE` (5) request body: `[queue-id, recipient]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteQueueRequest {
    queue_id: QueueId,
    recipient: Principal,
}

impl DeleteQueueRequest {
    /// Constructs a `DELETE_QUEUE` request body.
    #[must_use]
    pub const fn new(queue_id: QueueId, recipient: Principal) -> Self {
        Self {
            queue_id,
            recipient,
        }
    }

    /// Returns the queue identifier.
    #[must_use]
    pub const fn queue_id(&self) -> QueueId {
        self.queue_id
    }

    /// Returns the deleting principal.
    #[must_use]
    pub const fn recipient(&self) -> Principal {
        self.recipient
    }
}

/// A v1 request body, tagged by the command it belongs to.
///
/// This covers every command defined by `05-wire-format.md` "Commands";
/// [`Request::command`] gives the corresponding [`Command`] without
/// duplicating that mapping at every call site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// `CREATE_QUEUE` (1).
    CreateQueue(CreateQueueRequest),
    /// `SEND` (2).
    Send(SendRequest),
    /// `FETCH` (3).
    Fetch(FetchRequest),
    /// `ACK` (4).
    Ack(AckRequest),
    /// `DELETE_QUEUE` (5).
    DeleteQueue(DeleteQueueRequest),
}

impl Request {
    /// Returns the command this request body belongs to.
    #[must_use]
    pub const fn command(&self) -> Command {
        match self {
            Self::CreateQueue(_) => Command::CreateQueue,
            Self::Send(_) => Command::Send,
            Self::Fetch(_) => Command::Fetch,
            Self::Ack(_) => Command::Ack,
            Self::DeleteQueue(_) => Command::DeleteQueue,
        }
    }
}

/// A v1 success (`status = OK`) response body, tagged by the command it
/// answers. A nonzero status always carries an empty body (`CW-WIRE-027`)
/// and is represented by [`ErrorResponse`], not by this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseBody {
    /// `CREATE_QUEUE` (1).
    CreateQueue(CreateQueueOutcome),
    /// `SEND` (2).
    Send(SendOutcome),
    /// `FETCH` (3): `None` for the `[0]` "no message" shape.
    Fetch(Option<Delivery>),
    /// `ACK` (4): the body is empty.
    Ack,
    /// `DELETE_QUEUE` (5): the body is empty.
    DeleteQueue,
}

/// A v1 error response, whose body is always empty (`CW-WIRE-027`).
///
/// `command = None` represents wire command code `0`, used when no
/// supported request command was decoded (`CW-WIRE-013`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorResponse {
    command: Option<Command>,
    status: crate::Status,
}

impl ErrorResponse {
    /// Constructs an error response for a decoded command or command `0`.
    ///
    /// # Errors
    ///
    /// Returns [`TypeError::SuccessStatusForErrorResponse`] when `status`
    /// is [`crate::Status::Ok`].
    pub const fn new(command: Option<Command>, status: crate::Status) -> Result<Self, TypeError> {
        if status.is_ok() {
            return Err(TypeError::SuccessStatusForErrorResponse);
        }
        Ok(Self { command, status })
    }

    /// Returns the decoded command, or `None` for wire command code `0`.
    #[must_use]
    pub const fn command(self) -> Option<Command> {
        self.command
    }

    /// Returns the nonzero error status.
    #[must_use]
    pub const fn status(self) -> crate::Status {
        self.status
    }
}

/// A complete v1 response payload semantic value.
///
/// This enum makes the `status`/`body` invariant structural: success
/// always has the body matching its command, while every error has an
/// empty body and a nonzero status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    /// `status = OK` with the command-specific success body.
    Success(ResponseBody),
    /// A nonzero status with an empty body.
    Error(ErrorResponse),
}

impl Response {
    /// Returns the response command, or `None` for wire command code `0`.
    #[must_use]
    pub const fn command(&self) -> Option<Command> {
        match self {
            Self::Success(body) => Some(body.command()),
            Self::Error(error) => error.command(),
        }
    }

    /// Returns the wire response status.
    #[must_use]
    pub const fn status(&self) -> crate::Status {
        match self {
            Self::Success(_) => crate::Status::Ok,
            Self::Error(error) => error.status(),
        }
    }
}

impl ResponseBody {
    /// Returns the command this response body answers.
    #[must_use]
    pub const fn command(&self) -> Command {
        match self {
            Self::CreateQueue(_) => Command::CreateQueue,
            Self::Send(_) => Command::Send,
            Self::Fetch(_) => Command::Fetch,
            Self::Ack => Command::Ack,
            Self::DeleteQueue => Command::DeleteQueue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUEUE: QueueId = QueueId::from_bytes([1; 32]);
    const SENDER: Principal = Principal::from_bytes([2; 32]);
    const RECIPIENT: Principal = Principal::from_bytes([3; 32]);
    const MESSAGE: MessageId = MessageId::from_bytes([4; 32]);

    fn limits() -> QueueLimits {
        QueueLimits::new(4, 1024).expect("valid limits")
    }

    #[test]
    fn create_queue_outcome_round_trips() {
        assert_eq!(
            CreateQueueOutcome::try_from(0),
            Ok(CreateQueueOutcome::Created)
        );
        assert_eq!(
            CreateQueueOutcome::try_from(1),
            Ok(CreateQueueOutcome::AlreadyExists)
        );
        assert_eq!(CreateQueueOutcome::Created.as_u8(), 0);
        assert_eq!(CreateQueueOutcome::AlreadyExists.as_u8(), 1);
        assert_eq!(
            CreateQueueOutcome::try_from(2),
            Err(TypeError::UnknownDiscriminant {
                type_name: "CreateQueueOutcome",
                value: 2,
            })
        );
    }

    #[test]
    fn send_outcome_round_trips() {
        assert_eq!(SendOutcome::try_from(0), Ok(SendOutcome::Accepted));
        assert_eq!(SendOutcome::try_from(1), Ok(SendOutcome::Duplicate));
        assert_eq!(SendOutcome::Accepted.as_u8(), 0);
        assert_eq!(SendOutcome::Duplicate.as_u8(), 1);
        assert_eq!(
            SendOutcome::try_from(2),
            Err(TypeError::UnknownDiscriminant {
                type_name: "SendOutcome",
                value: 2,
            })
        );
    }

    #[test]
    fn request_reports_its_command() {
        let create =
            Request::CreateQueue(CreateQueueRequest::new(QUEUE, SENDER, RECIPIENT, limits()));
        assert_eq!(create.command(), Command::CreateQueue);

        let send = Request::Send(SendRequest::new(
            QUEUE,
            SENDER,
            MESSAGE,
            Payload::new(b"hi".to_vec()).expect("valid payload"),
            Ttl::from_secs(60),
        ));
        assert_eq!(send.command(), Command::Send);

        let fetch = Request::Fetch(FetchRequest::new(QUEUE, RECIPIENT));
        assert_eq!(fetch.command(), Command::Fetch);

        let ack = Request::Ack(AckRequest::new(QUEUE, RECIPIENT, MESSAGE));
        assert_eq!(ack.command(), Command::Ack);

        let delete = Request::DeleteQueue(DeleteQueueRequest::new(QUEUE, RECIPIENT));
        assert_eq!(delete.command(), Command::DeleteQueue);
    }

    #[test]
    fn response_body_reports_its_command() {
        assert_eq!(
            ResponseBody::CreateQueue(CreateQueueOutcome::Created).command(),
            Command::CreateQueue
        );
        assert_eq!(
            ResponseBody::Send(SendOutcome::Accepted).command(),
            Command::Send
        );
        assert_eq!(ResponseBody::Fetch(None).command(), Command::Fetch);
        assert_eq!(ResponseBody::Ack.command(), Command::Ack);
        assert_eq!(ResponseBody::DeleteQueue.command(), Command::DeleteQueue);
    }

    #[test]
    fn fetch_response_carries_a_delivery() {
        let delivery = Delivery::new(
            MESSAGE,
            Payload::new(b"hi".to_vec()).expect("valid payload"),
            Timestamp::from_secs(60),
        );
        assert_eq!(delivery.message_id(), MESSAGE);
        assert_eq!(delivery.payload().as_bytes(), b"hi");
        assert_eq!(delivery.expires_at(), Timestamp::from_secs(60));
    }

    #[test]
    fn success_response_derives_command_and_ok_status_from_its_body() {
        let response = Response::Success(ResponseBody::Send(SendOutcome::Accepted));
        assert_eq!(response.command(), Some(Command::Send));
        assert_eq!(response.status(), crate::Status::Ok);
    }

    #[test]
    fn error_response_supports_a_recognized_command_and_empty_command_code() {
        let recognized = ErrorResponse::new(Some(Command::Send), crate::Status::QueueFull)
            .expect("nonzero status is valid");
        assert_eq!(recognized.command(), Some(Command::Send));
        assert_eq!(recognized.status(), crate::Status::QueueFull);

        let unavailable = ErrorResponse::new(None, crate::Status::UnsupportedVersion)
            .expect("command zero is valid when no command was decoded");
        let response = Response::Error(unavailable);
        assert_eq!(response.command(), None);
        assert_eq!(response.status(), crate::Status::UnsupportedVersion);
    }

    #[test]
    fn error_response_rejects_ok_status() {
        assert_eq!(
            ErrorResponse::new(Some(Command::Fetch), crate::Status::Ok),
            Err(TypeError::SuccessStatusForErrorResponse)
        );
    }
}
