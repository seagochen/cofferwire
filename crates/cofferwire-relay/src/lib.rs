//! Transport-independent queue semantics for a Cofferwire relay.
//!
//! This crate intentionally operates on authenticated principals and opaque
//! payloads. Networking and cryptographic verification are separate layers.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

mod durable;
mod durable_blob;

pub use durable::{DurableRelay, DurableRelayError, StorageErrorKind, DEFAULT_BUSY_TIMEOUT};
pub use durable_blob::{BlobRelayError, BlobRelayResult};

macro_rules! opaque_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Constructs an identifier from its exact byte representation.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the exact byte representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

opaque_id!(QueueId, "An opaque identifier for one relay-local queue.");
opaque_id!(
    MessageId,
    "A sender-chosen idempotency identifier for one message."
);
opaque_id!(
    Principal,
    "A queue-scoped authenticated actor, not a global user identity."
);

/// Relay time in whole seconds from an implementation-defined epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Constructs a timestamp from seconds.
    #[must_use]
    pub const fn from_secs(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the timestamp as seconds.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    const fn checked_add(self, ttl: Ttl) -> Option<Self> {
        match self.0.checked_add(ttl.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// A message lifetime in seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ttl(u64);

impl Ttl {
    /// Constructs a non-zero lifetime.
    #[must_use]
    pub const fn from_secs(seconds: u64) -> Option<Self> {
        if seconds == 0 {
            None
        } else {
            Some(Self(seconds))
        }
    }

    /// Returns the lifetime as seconds.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

/// Per-queue resource limits enforced before accepting new messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueLimits {
    max_messages: NonZeroUsize,
    max_message_bytes: NonZeroUsize,
}

impl QueueLimits {
    /// Creates non-zero queue limits.
    #[must_use]
    pub const fn new(max_messages: usize, max_message_bytes: usize) -> Option<Self> {
        let Some(max_messages) = NonZeroUsize::new(max_messages) else {
            return None;
        };
        let Some(max_message_bytes) = NonZeroUsize::new(max_message_bytes) else {
            return None;
        };
        Some(Self {
            max_messages,
            max_message_bytes,
        })
    }

    /// Returns the maximum number of queued messages.
    #[must_use]
    pub const fn max_messages(self) -> usize {
        self.max_messages.get()
    }

    /// Returns the maximum opaque payload size.
    #[must_use]
    pub const fn max_message_bytes(self) -> usize {
        self.max_message_bytes.get()
    }
}

/// Queue-scoped authorization and resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueConfig {
    sender: Principal,
    recipient: Principal,
    limits: QueueLimits,
}

impl QueueConfig {
    /// Constructs a queue configuration.
    #[must_use]
    pub const fn new(sender: Principal, recipient: Principal, limits: QueueLimits) -> Self {
        Self {
            sender,
            recipient,
            limits,
        }
    }

    /// Returns the principal allowed to send.
    #[must_use]
    pub const fn sender(self) -> Principal {
        self.sender
    }

    /// Returns the principal allowed to fetch, acknowledge and delete.
    #[must_use]
    pub const fn recipient(self) -> Principal {
        self.recipient
    }

    /// Returns the queue resource limits.
    #[must_use]
    pub const fn limits(self) -> QueueLimits {
        self.limits
    }
}

/// Result of an idempotent queue-creation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateQueueOutcome {
    /// A new queue was created.
    Created,
    /// The same identifier and configuration already existed.
    AlreadyExists,
}

/// Result of an idempotent send request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// A new message was accepted.
    Accepted,
    /// The same message identifier and payload were already accepted.
    Duplicate,
}

/// An opaque message returned to the authenticated recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    id: MessageId,
    payload: Vec<u8>,
    expires_at: Timestamp,
}

impl Delivery {
    /// Returns the sender-chosen message identifier.
    #[must_use]
    pub const fn id(&self) -> MessageId {
        self.id
    }

    /// Returns the opaque payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the relay expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

/// Queue state-machine errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayError {
    /// No queue exists with the supplied identifier.
    QueueNotFound,
    /// The authenticated principal cannot perform the command.
    Unauthorized,
    /// An existing queue identifier was reused with a different configuration.
    QueueIdConflict,
    /// A message identifier was reused with a different payload.
    MessageIdConflict,
    /// The payload exceeds the queue's configured byte limit.
    MessageTooLarge,
    /// The queue is at its configured message-count limit.
    QueueFull,
    /// Adding the requested TTL would overflow the timestamp representation.
    ExpiryOverflow,
    /// The acknowledged identifier is not the queue's current message.
    AckMismatch,
    /// The current message has not been fetched and cannot be acknowledged.
    NotDelivered,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::QueueNotFound => "queue not found",
            Self::Unauthorized => "principal is not authorized",
            Self::QueueIdConflict => "queue identifier conflicts with existing configuration",
            Self::MessageIdConflict => "message identifier conflicts with existing payload",
            Self::MessageTooLarge => "message exceeds queue byte limit",
            Self::QueueFull => "queue is full",
            Self::ExpiryOverflow => "message expiry overflows timestamp representation",
            Self::AckMismatch => "acknowledgement does not match current message",
            Self::NotDelivered => "message has not been delivered",
        })
    }
}

impl std::error::Error for RelayError {}

#[derive(Debug)]
struct QueuedMessage {
    id: MessageId,
    payload: Vec<u8>,
    expires_at: Timestamp,
    delivered: bool,
}

#[derive(Debug)]
struct Queue {
    config: QueueConfig,
    messages: VecDeque<QueuedMessage>,
}

impl Queue {
    fn discard_expired(&mut self, now: Timestamp) {
        self.messages.retain(|message| message.expires_at > now);
    }
}

/// In-memory reference state machine for relay queues.
///
/// Production durability requires placing each mutating operation inside an
/// atomic storage transaction. This type defines behavior, not persistence.
#[derive(Debug, Default)]
pub struct Relay {
    queues: HashMap<QueueId, Queue>,
}

impl Relay {
    /// Creates an empty relay state machine.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a queue, or confirms an exact idempotent retry.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::QueueIdConflict`] when the identifier already
    /// exists with a different configuration.
    pub fn create_queue(
        &mut self,
        id: QueueId,
        config: QueueConfig,
    ) -> Result<CreateQueueOutcome, RelayError> {
        match self.queues.get(&id) {
            Some(existing) if existing.config == config => Ok(CreateQueueOutcome::AlreadyExists),
            Some(_) => Err(RelayError::QueueIdConflict),
            None => {
                self.queues.insert(
                    id,
                    Queue {
                        config,
                        messages: VecDeque::new(),
                    },
                );
                Ok(CreateQueueOutcome::Created)
            }
        }
    }

    /// Accepts an opaque message for asynchronous delivery.
    ///
    /// An idempotent retry with the same message identifier and payload does
    /// not extend the original expiry time.
    ///
    /// # Errors
    ///
    /// Returns an authorization, size, capacity, identifier-conflict or
    /// timestamp-overflow error when the message cannot be accepted.
    pub fn send(
        &mut self,
        queue_id: QueueId,
        sender: Principal,
        message_id: MessageId,
        payload: Vec<u8>,
        now: Timestamp,
        ttl: Ttl,
    ) -> Result<SendOutcome, RelayError> {
        let queue = self
            .queues
            .get_mut(&queue_id)
            .ok_or(RelayError::QueueNotFound)?;
        if queue.config.sender != sender {
            return Err(RelayError::Unauthorized);
        }

        queue.discard_expired(now);

        if let Some(existing) = queue
            .messages
            .iter()
            .find(|message| message.id == message_id)
        {
            return if existing.payload == payload {
                Ok(SendOutcome::Duplicate)
            } else {
                Err(RelayError::MessageIdConflict)
            };
        }

        if payload.len() > queue.config.limits.max_message_bytes() {
            return Err(RelayError::MessageTooLarge);
        }
        if queue.messages.len() >= queue.config.limits.max_messages() {
            return Err(RelayError::QueueFull);
        }

        let expires_at = now.checked_add(ttl).ok_or(RelayError::ExpiryOverflow)?;
        queue.messages.push_back(QueuedMessage {
            id: message_id,
            payload,
            expires_at,
            delivered: false,
        });
        Ok(SendOutcome::Accepted)
    }

    /// Fetches the current message, redelivering it until it is acknowledged.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::QueueNotFound`] or [`RelayError::Unauthorized`]
    /// when the recipient cannot access the queue.
    pub fn fetch(
        &mut self,
        queue_id: QueueId,
        recipient: Principal,
        now: Timestamp,
    ) -> Result<Option<Delivery>, RelayError> {
        let queue = self.recipient_queue_mut(queue_id, recipient)?;
        queue.discard_expired(now);
        let Some(message) = queue.messages.front_mut() else {
            return Ok(None);
        };
        message.delivered = true;
        Ok(Some(Delivery {
            id: message.id,
            payload: message.payload.clone(),
            expires_at: message.expires_at,
        }))
    }

    /// Deletes the current message after the recipient has durably stored it.
    ///
    /// # Errors
    ///
    /// Returns an authorization error, [`RelayError::AckMismatch`] when the
    /// identifier is not current, or [`RelayError::NotDelivered`] when ACK
    /// arrives before a successful fetch.
    pub fn acknowledge(
        &mut self,
        queue_id: QueueId,
        recipient: Principal,
        message_id: MessageId,
        now: Timestamp,
    ) -> Result<(), RelayError> {
        let queue = self.recipient_queue_mut(queue_id, recipient)?;
        queue.discard_expired(now);
        let message = queue.messages.front().ok_or(RelayError::AckMismatch)?;
        if message.id != message_id {
            return Err(RelayError::AckMismatch);
        }
        if !message.delivered {
            return Err(RelayError::NotDelivered);
        }
        queue.messages.pop_front();
        Ok(())
    }

    /// Deletes a queue and all queued messages.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::QueueNotFound`] or [`RelayError::Unauthorized`]
    /// when the recipient cannot delete the queue.
    pub fn delete_queue(
        &mut self,
        queue_id: QueueId,
        recipient: Principal,
    ) -> Result<(), RelayError> {
        let queue = self
            .queues
            .get(&queue_id)
            .ok_or(RelayError::QueueNotFound)?;
        if queue.config.recipient != recipient {
            return Err(RelayError::Unauthorized);
        }
        self.queues.remove(&queue_id);
        Ok(())
    }

    fn recipient_queue_mut(
        &mut self,
        queue_id: QueueId,
        recipient: Principal,
    ) -> Result<&mut Queue, RelayError> {
        let queue = self
            .queues
            .get_mut(&queue_id)
            .ok_or(RelayError::QueueNotFound)?;
        if queue.config.recipient != recipient {
            return Err(RelayError::Unauthorized);
        }
        Ok(queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUEUE: QueueId = QueueId::from_bytes([1; 32]);
    const SENDER: Principal = Principal::from_bytes([2; 32]);
    const RECIPIENT: Principal = Principal::from_bytes([3; 32]);
    const OTHER: Principal = Principal::from_bytes([4; 32]);
    const MESSAGE_A: MessageId = MessageId::from_bytes([5; 32]);
    const MESSAGE_B: MessageId = MessageId::from_bytes([6; 32]);
    const NOW: Timestamp = Timestamp::from_secs(1_000);
    const TTL: Ttl = match Ttl::from_secs(60) {
        Some(ttl) => ttl,
        None => panic!("test TTL must be non-zero"),
    };

    fn relay_with_limits(max_messages: usize, max_message_bytes: usize) -> Relay {
        let limits = QueueLimits::new(max_messages, max_message_bytes).expect("valid limits");
        let mut relay = Relay::new();
        relay
            .create_queue(QUEUE, QueueConfig::new(SENDER, RECIPIENT, limits))
            .expect("queue creation succeeds");
        relay
    }

    #[test]
    fn cw_queue_001_delivers_offline_until_acknowledged() {
        let mut relay = relay_with_limits(4, 1024);
        assert_eq!(
            relay.send(QUEUE, SENDER, MESSAGE_A, b"ciphertext".to_vec(), NOW, TTL),
            Ok(SendOutcome::Accepted)
        );

        let first = relay
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .expect("message exists");
        let redelivery = relay
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .expect("message is redelivered");
        assert_eq!(first, redelivery);

        relay
            .acknowledge(QUEUE, RECIPIENT, MESSAGE_A, NOW)
            .expect("ack succeeds after delivery");
        assert_eq!(relay.fetch(QUEUE, RECIPIENT, NOW), Ok(None));
    }

    #[test]
    fn cw_queue_002_send_retry_is_idempotent() {
        let mut relay = relay_with_limits(1, 1024);
        let payload = b"same ciphertext".to_vec();
        assert_eq!(
            relay.send(QUEUE, SENDER, MESSAGE_A, payload.clone(), NOW, TTL),
            Ok(SendOutcome::Accepted)
        );
        assert_eq!(
            relay.send(
                QUEUE,
                SENDER,
                MESSAGE_A,
                payload,
                Timestamp::from_secs(1_010),
                TTL
            ),
            Ok(SendOutcome::Duplicate)
        );
    }

    #[test]
    fn cw_queue_003_rejects_message_id_reuse_with_different_payload() {
        let mut relay = relay_with_limits(2, 1024);
        relay
            .send(QUEUE, SENDER, MESSAGE_A, b"one".to_vec(), NOW, TTL)
            .expect("first send succeeds");
        assert_eq!(
            relay.send(QUEUE, SENDER, MESSAGE_A, b"two".to_vec(), NOW, TTL),
            Err(RelayError::MessageIdConflict)
        );
    }

    #[test]
    fn cw_queue_004_ack_cannot_delete_unfetched_or_different_message() {
        let mut relay = relay_with_limits(2, 1024);
        relay
            .send(QUEUE, SENDER, MESSAGE_A, b"one".to_vec(), NOW, TTL)
            .expect("send succeeds");
        assert_eq!(
            relay.acknowledge(QUEUE, RECIPIENT, MESSAGE_A, NOW),
            Err(RelayError::NotDelivered)
        );
        relay.fetch(QUEUE, RECIPIENT, NOW).expect("fetch succeeds");
        assert_eq!(
            relay.acknowledge(QUEUE, RECIPIENT, MESSAGE_B, NOW),
            Err(RelayError::AckMismatch)
        );
        assert!(relay
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .is_some());
    }

    #[test]
    fn cw_queue_005_expired_messages_are_not_delivered_and_release_capacity() {
        let mut relay = relay_with_limits(1, 1024);
        relay
            .send(QUEUE, SENDER, MESSAGE_A, b"old".to_vec(), NOW, TTL)
            .expect("send succeeds");
        let expiry = Timestamp::from_secs(NOW.as_secs() + TTL.as_secs());
        assert_eq!(relay.fetch(QUEUE, RECIPIENT, expiry), Ok(None));
        assert_eq!(
            relay.send(QUEUE, SENDER, MESSAGE_B, b"new".to_vec(), expiry, TTL),
            Ok(SendOutcome::Accepted)
        );
    }

    #[test]
    fn cw_queue_006_enforces_scoped_authorization() {
        let mut relay = relay_with_limits(2, 1024);
        assert_eq!(
            relay.send(QUEUE, OTHER, MESSAGE_A, Vec::new(), NOW, TTL),
            Err(RelayError::Unauthorized)
        );
        assert_eq!(
            relay.fetch(QUEUE, OTHER, NOW),
            Err(RelayError::Unauthorized)
        );
        assert_eq!(
            relay.delete_queue(QUEUE, OTHER),
            Err(RelayError::Unauthorized)
        );
    }

    #[test]
    fn cw_queue_007_enforces_size_and_depth_limits() {
        let mut relay = relay_with_limits(1, 3);
        assert_eq!(
            relay.send(QUEUE, SENDER, MESSAGE_A, vec![0; 4], NOW, TTL),
            Err(RelayError::MessageTooLarge)
        );
        relay
            .send(QUEUE, SENDER, MESSAGE_A, vec![0; 3], NOW, TTL)
            .expect("message at size limit succeeds");
        assert_eq!(
            relay.send(QUEUE, SENDER, MESSAGE_B, vec![0], NOW, TTL),
            Err(RelayError::QueueFull)
        );
    }

    #[test]
    fn cw_queue_008_queue_creation_is_idempotent_but_not_ambiguous() {
        let limits = QueueLimits::new(1, 10).expect("valid limits");
        let config = QueueConfig::new(SENDER, RECIPIENT, limits);
        let mut relay = Relay::new();
        assert_eq!(
            relay.create_queue(QUEUE, config),
            Ok(CreateQueueOutcome::Created)
        );
        assert_eq!(
            relay.create_queue(QUEUE, config),
            Ok(CreateQueueOutcome::AlreadyExists)
        );
        let conflicting = QueueConfig::new(OTHER, RECIPIENT, limits);
        assert_eq!(
            relay.create_queue(QUEUE, conflicting),
            Err(RelayError::QueueIdConflict)
        );
    }
}
