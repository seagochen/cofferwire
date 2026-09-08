//! SQLite-backed transactional queue storage.

use std::path::Path;
use std::time::Duration;

use cofferwire_types::{
    Delivery as WireDelivery, Payload, Principal as AuthenticatedPrincipal, Request as WireRequest,
    RequestId, ResponseBody as WireResponseBody,
};
use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::replay::{self, EffectError, Namespace};
use crate::{
    CreateQueueOutcome, Delivery, MessageId, Principal, QueueConfig, QueueId, QueueLimits,
    RelayError, SendOutcome, Timestamp, Ttl,
};

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS queues (
    queue_id         BLOB PRIMARY KEY CHECK (length(queue_id) = 32),
    sender           BLOB NOT NULL CHECK (length(sender) = 32),
    recipient        BLOB NOT NULL CHECK (length(recipient) = 32),
    max_messages     BLOB NOT NULL CHECK (length(max_messages) = 8),
    max_message_bytes BLOB NOT NULL CHECK (length(max_message_bytes) = 8)
) STRICT;

CREATE TABLE IF NOT EXISTS messages (
    sequence   INTEGER PRIMARY KEY,
    queue_id   BLOB NOT NULL REFERENCES queues(queue_id) ON DELETE CASCADE,
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    payload    BLOB NOT NULL,
    expires_at BLOB NOT NULL CHECK (length(expires_at) = 8),
    delivered  INTEGER NOT NULL DEFAULT 0 CHECK (delivered IN (0, 1)),
    UNIQUE (queue_id, message_id)
) STRICT;

CREATE INDEX IF NOT EXISTS messages_queue_order
    ON messages(queue_id, sequence);
CREATE INDEX IF NOT EXISTS messages_expiry
    ON messages(queue_id, expires_at);

CREATE TABLE IF NOT EXISTS blob_uploads (
    upload_id BLOB PRIMARY KEY CHECK (length(upload_id) = 32),
    upload_cap BLOB NOT NULL CHECK (length(upload_cap) = 32),
    download_cap BLOB NOT NULL CHECK (length(download_cap) = 32),
    renew_cap BLOB NOT NULL CHECK (length(renew_cap) = 32),
    delete_cap BLOB NOT NULL CHECK (length(delete_cap) = 32),
    manifest BLOB NOT NULL,
    expires_at BLOB NOT NULL CHECK (length(expires_at) = 8),
    committed_blob BLOB CHECK (committed_blob IS NULL OR length(committed_blob) = 32)
) STRICT;
CREATE TABLE IF NOT EXISTS blob_upload_chunks (
    upload_id BLOB NOT NULL REFERENCES blob_uploads(upload_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (upload_id, chunk_index)
) STRICT;
CREATE TABLE IF NOT EXISTS blob_objects (
    blob_id BLOB PRIMARY KEY CHECK (length(blob_id) = 32),
    manifest BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS blob_chunks (
    blob_id BLOB NOT NULL REFERENCES blob_objects(blob_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    PRIMARY KEY (blob_id, chunk_index)
) STRICT;
CREATE TABLE IF NOT EXISTS blob_grants (
    grant_id BLOB PRIMARY KEY CHECK (length(grant_id) = 32),
    blob_id BLOB NOT NULL REFERENCES blob_objects(blob_id),
    download_cap BLOB NOT NULL CHECK (length(download_cap) = 32),
    renew_cap BLOB NOT NULL CHECK (length(renew_cap) = 32),
    delete_cap BLOB NOT NULL CHECK (length(delete_cap) = 32),
    expires_at BLOB NOT NULL CHECK (length(expires_at) = 8),
    deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1))
) STRICT;
CREATE INDEX IF NOT EXISTS blob_grants_download ON blob_grants(blob_id, download_cap);
CREATE INDEX IF NOT EXISTS blob_grants_renew ON blob_grants(blob_id, renew_cap);
CREATE INDEX IF NOT EXISTS blob_grants_delete ON blob_grants(blob_id, delete_cap);
CREATE TABLE IF NOT EXISTS blob_replays (
    capability_id BLOB NOT NULL CHECK (length(capability_id) = 32),
    request_id BLOB NOT NULL CHECK (length(request_id) = 16),
    request BLOB NOT NULL,
    response BLOB NOT NULL,
    PRIMARY KEY (capability_id, request_id)
) STRICT;
CREATE TABLE IF NOT EXISTS queue_replays (
    principal  BLOB NOT NULL CHECK (length(principal) = 32),
    request_id BLOB NOT NULL CHECK (length(request_id) = 16),
    request    BLOB NOT NULL,
    response   BLOB NOT NULL,
    PRIMARY KEY (principal, request_id)
) STRICT;
";
const SCHEMA_VERSION: i64 = 3;

/// Maximum time a command waits to acquire `SQLite`'s writer lock.
pub const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_millis(250);

/// Stable classification for storage failures exposed above `SQLite`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageErrorKind {
    /// The bounded writer-lock wait expired.
    Busy,
    /// `SQLite` rejected a write to read-only storage.
    ReadOnly,
    /// The database or filesystem reached its configured capacity.
    Full,
    /// The storage system reported an I/O failure.
    Io,
    /// `SQLite` reported a malformed database image.
    Corrupt,
    /// Another storage failure occurred.
    Other,
}

/// An error from the durable queue layer.
#[derive(Debug)]
pub enum DurableRelayError {
    /// The command was rejected by queue semantics.
    Relay(RelayError),
    /// The storage engine could not complete the transaction.
    Storage {
        /// Stable category suitable for retry and operator policy.
        kind: StorageErrorKind,
        /// Original `SQLite` error retained for diagnostics.
        source: rusqlite::Error,
    },
    /// The database was written by an unsupported schema version.
    UnsupportedSchemaVersion {
        /// Version found in the database.
        found: i64,
        /// Newest version understood by this build.
        supported: i64,
    },
}

impl std::fmt::Display for DurableRelayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relay(error) => error.fmt(formatter),
            Self::Storage { kind, source } => {
                write!(
                    formatter,
                    "durable queue storage failed ({kind:?}): {source}"
                )
            }
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                formatter,
                "unsupported durable queue schema version {found}; this build supports {supported}"
            ),
        }
    }
}

impl std::error::Error for DurableRelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Relay(error) => Some(error),
            Self::Storage { source, .. } => Some(source),
            Self::UnsupportedSchemaVersion { .. } => None,
        }
    }
}

impl From<RelayError> for DurableRelayError {
    fn from(error: RelayError) -> Self {
        Self::Relay(error)
    }
}

impl From<rusqlite::Error> for DurableRelayError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage {
            kind: classify_storage_error(&error),
            source: error,
        }
    }
}

impl DurableRelayError {
    /// Returns the stable storage category, when this is a storage failure.
    #[must_use]
    pub const fn storage_kind(&self) -> Option<StorageErrorKind> {
        match self {
            Self::Storage { kind, .. } => Some(*kind),
            Self::Relay(_) | Self::UnsupportedSchemaVersion { .. } => None,
        }
    }
}

/// A relay whose mutating commands commit atomically to `SQLite`.
///
/// The connection uses `SQLite`'s rollback journal with `synchronous=FULL`.
/// Consequently, a successful method return occurs only after the commit's
/// durability barrier succeeds. A process exit before commit leaves either
/// the complete previous state or the complete new state, never a partial
/// queue operation.
#[derive(Debug)]
pub struct DurableRelay {
    pub(crate) connection: Connection,
}

impl DurableRelay {
    /// Opens or creates a durable relay database.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the database cannot be opened, configured,
    /// or migrated to the current schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DurableRelayError> {
        let connection = Connection::open(path)?;
        Self::initialize(connection)
    }

    fn initialize(mut connection: Connection) -> Result<Self, DurableRelayError> {
        connection.busy_timeout(DEFAULT_BUSY_TIMEOUT)?;
        let version =
            connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?;
        if version > SCHEMA_VERSION {
            return Err(DurableRelayError::UnsupportedSchemaVersion {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = DELETE;
             PRAGMA synchronous = FULL;",
        )?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        if version != SCHEMA_VERSION {
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        commit(transaction)?;
        Ok(Self { connection })
    }

    /// Creates a queue, or confirms an exact idempotent retry.
    ///
    /// # Errors
    ///
    /// Returns a semantic conflict or storage error.
    pub fn create_queue(
        &mut self,
        id: QueueId,
        config: QueueConfig,
    ) -> Result<CreateQueueOutcome, DurableRelayError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = Self::create_queue_tx(&transaction, id, config)?;
        #[cfg(test)]
        crash_point("create_queue_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crash_point("create_queue_after_commit");
        Ok(outcome)
    }

    /// Transaction-scoped variant of [`Self::create_queue`].
    ///
    /// # Errors
    ///
    /// Returns a semantic conflict or storage error.
    pub fn create_queue_tx(
        transaction: &Transaction<'_>,
        id: QueueId,
        config: QueueConfig,
    ) -> Result<CreateQueueOutcome, DurableRelayError> {
        let existing = transaction
            .query_row(
                "SELECT sender, recipient, max_messages, max_message_bytes
                 FROM queues WHERE queue_id = ?1",
                [id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        blob_32(row.get_ref(0)?.as_blob()?)?,
                        blob_32(row.get_ref(1)?.as_blob()?)?,
                        blob_u64(row.get_ref(2)?.as_blob()?)?,
                        blob_u64(row.get_ref(3)?.as_blob()?)?,
                    ))
                },
            )
            .optional()?;

        if let Some((sender, recipient, max_messages, max_message_bytes)) = existing {
            let same = sender == *config.sender().as_bytes()
                && recipient == *config.recipient().as_bytes()
                && max_messages == usize_to_u64(config.limits().max_messages())
                && max_message_bytes == usize_to_u64(config.limits().max_message_bytes());
            return if same {
                Ok(CreateQueueOutcome::AlreadyExists)
            } else {
                Err(RelayError::QueueIdConflict.into())
            };
        }

        transaction.execute(
            "INSERT INTO queues
             (queue_id, sender, recipient, max_messages, max_message_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id.as_bytes().as_slice(),
                config.sender().as_bytes().as_slice(),
                config.recipient().as_bytes().as_slice(),
                usize_to_u64(config.limits().max_messages())
                    .to_be_bytes()
                    .as_slice(),
                usize_to_u64(config.limits().max_message_bytes())
                    .to_be_bytes()
                    .as_slice(),
            ],
        )?;
        Ok(CreateQueueOutcome::Created)
    }

    /// Atomically accepts and durably commits an opaque message.
    ///
    /// An idempotent retry does not extend the original expiry.
    ///
    /// # Errors
    ///
    /// Returns an authorization, limit, conflict, expiry, or storage error.
    pub fn send(
        &mut self,
        queue_id: QueueId,
        sender: Principal,
        message_id: MessageId,
        payload: &[u8],
        now: Timestamp,
        ttl: Ttl,
    ) -> Result<SendOutcome, DurableRelayError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = Self::send_tx(
            &transaction,
            queue_id,
            sender,
            message_id,
            payload,
            now,
            ttl,
        )?;
        #[cfg(test)]
        crash_point("send_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crash_point("send_after_commit");
        Ok(outcome)
    }

    /// Transaction-scoped variant of [`Self::send`].
    ///
    /// # Errors
    ///
    /// Returns an authorization, limit, conflict, expiry, or storage error.
    pub fn send_tx(
        transaction: &Transaction<'_>,
        queue_id: QueueId,
        sender: Principal,
        message_id: MessageId,
        payload: &[u8],
        now: Timestamp,
        ttl: Ttl,
    ) -> Result<SendOutcome, DurableRelayError> {
        let config = read_queue(transaction, queue_id)?.ok_or(RelayError::QueueNotFound)?;
        if config.sender() != sender {
            return Err(RelayError::Unauthorized.into());
        }
        discard_expired(transaction, queue_id, now)?;

        let existing = transaction
            .query_row(
                "SELECT payload FROM messages WHERE queue_id = ?1 AND message_id = ?2",
                params![
                    queue_id.as_bytes().as_slice(),
                    message_id.as_bytes().as_slice()
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing == payload {
                Ok(SendOutcome::Duplicate)
            } else {
                Err(RelayError::MessageIdConflict.into())
            };
        }
        if payload.len() > config.limits().max_message_bytes() {
            return Err(RelayError::MessageTooLarge.into());
        }
        let count: u64 = transaction.query_row(
            "SELECT count(*) FROM messages WHERE queue_id = ?1",
            [queue_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if count >= usize_to_u64(config.limits().max_messages()) {
            return Err(RelayError::QueueFull.into());
        }
        let expires_at = now
            .as_secs()
            .checked_add(ttl.as_secs())
            .map(Timestamp::from_secs)
            .ok_or(RelayError::ExpiryOverflow)?;
        transaction.execute(
            "INSERT INTO messages (queue_id, message_id, payload, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                queue_id.as_bytes().as_slice(),
                message_id.as_bytes().as_slice(),
                payload,
                expires_at.as_secs().to_be_bytes().as_slice(),
            ],
        )?;
        Ok(SendOutcome::Accepted)
    }

    /// Fetches and atomically marks the current message as delivered.
    ///
    /// # Errors
    ///
    /// Returns an authorization or storage error.
    pub fn fetch(
        &mut self,
        queue_id: QueueId,
        recipient: Principal,
        now: Timestamp,
    ) -> Result<Option<Delivery>, DurableRelayError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let delivery = Self::fetch_tx(&transaction, queue_id, recipient, now)?;
        if delivery.is_some() {
            #[cfg(test)]
            crash_point("fetch_before_commit");
        }
        commit(transaction)?;
        if delivery.is_some() {
            #[cfg(test)]
            crash_point("fetch_after_commit");
        }
        Ok(delivery)
    }

    /// Transaction-scoped variant of [`Self::fetch`].
    ///
    /// # Errors
    ///
    /// Returns an authorization or storage error.
    pub fn fetch_tx(
        transaction: &Transaction<'_>,
        queue_id: QueueId,
        recipient: Principal,
        now: Timestamp,
    ) -> Result<Option<Delivery>, DurableRelayError> {
        authorize_recipient(transaction, queue_id, recipient)?;
        discard_expired(transaction, queue_id, now)?;
        let message = transaction
            .query_row(
                "SELECT sequence, message_id, payload, expires_at
                 FROM messages WHERE queue_id = ?1 ORDER BY sequence LIMIT 1",
                [queue_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        blob_32(row.get_ref(1)?.as_blob()?)?,
                        row.get::<_, Vec<u8>>(2)?,
                        blob_u64(row.get_ref(3)?.as_blob()?)?,
                    ))
                },
            )
            .optional()?;
        let Some((sequence, message_id, payload, expires_at)) = message else {
            return Ok(None);
        };
        transaction.execute(
            "UPDATE messages SET delivered = 1 WHERE sequence = ?1",
            [sequence],
        )?;
        Ok(Some(Delivery {
            id: MessageId::from_bytes(message_id),
            payload,
            expires_at: Timestamp::from_secs(expires_at),
        }))
    }

    /// Atomically validates and deletes the current delivered message.
    ///
    /// # Errors
    ///
    /// Returns an authorization, mismatch, delivery-state, or storage error.
    pub fn acknowledge(
        &mut self,
        queue_id: QueueId,
        recipient: Principal,
        message_id: MessageId,
        now: Timestamp,
    ) -> Result<(), DurableRelayError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::acknowledge_tx(&transaction, queue_id, recipient, message_id, now)?;
        #[cfg(test)]
        crash_point("ack_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crash_point("ack_after_commit");
        Ok(())
    }

    /// Transaction-scoped variant of [`Self::acknowledge`].
    ///
    /// # Errors
    ///
    /// Returns an authorization, mismatch, delivery-state, or storage error.
    pub fn acknowledge_tx(
        transaction: &Transaction<'_>,
        queue_id: QueueId,
        recipient: Principal,
        message_id: MessageId,
        now: Timestamp,
    ) -> Result<(), DurableRelayError> {
        authorize_recipient(transaction, queue_id, recipient)?;
        discard_expired(transaction, queue_id, now)?;
        let current = transaction
            .query_row(
                "SELECT sequence, message_id, delivered
                 FROM messages WHERE queue_id = ?1 ORDER BY sequence LIMIT 1",
                [queue_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        blob_32(row.get_ref(1)?.as_blob()?)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(RelayError::AckMismatch)?;
        if current.1 != *message_id.as_bytes() {
            return Err(RelayError::AckMismatch.into());
        }
        if !current.2 {
            return Err(RelayError::NotDelivered.into());
        }
        transaction.execute("DELETE FROM messages WHERE sequence = ?1", [current.0])?;
        Ok(())
    }

    /// Atomically deletes a queue and all of its messages.
    ///
    /// # Errors
    ///
    /// Returns an authorization or storage error.
    pub fn delete_queue(
        &mut self,
        queue_id: QueueId,
        recipient: Principal,
    ) -> Result<(), DurableRelayError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::delete_queue_tx(&transaction, queue_id, recipient)?;
        #[cfg(test)]
        crash_point("delete_queue_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crash_point("delete_queue_after_commit");
        Ok(())
    }

    /// Transaction-scoped variant of [`Self::delete_queue`].
    ///
    /// # Errors
    ///
    /// Returns an authorization or storage error.
    pub fn delete_queue_tx(
        transaction: &Transaction<'_>,
        queue_id: QueueId,
        recipient: Principal,
    ) -> Result<(), DurableRelayError> {
        authorize_recipient(transaction, queue_id, recipient)?;
        transaction.execute(
            "DELETE FROM queues WHERE queue_id = ?1",
            [queue_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Returns the stored replay record for `(principal, request_id)`.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the lookup cannot be completed.
    pub fn queue_replay(
        &self,
        principal: AuthenticatedPrincipal,
        request_id: RequestId,
    ) -> Result<Option<QueueReplayRecord>, DurableRelayError> {
        replay::lookup(
            &self.connection,
            Namespace::Queue,
            principal.as_bytes(),
            request_id,
        )
    }

    /// Executes one decoded queue request and records its exact replay response.
    ///
    /// This is the storage boundary used by network adapters: callers provide
    /// protocol values and response encoding, but never receive a `SQLite`
    /// transaction or depend on the storage engine.
    ///
    /// # Errors
    ///
    /// Returns a storage error; protocol rejections are encoded responses.
    pub fn queue_request_exchange(
        &mut self,
        principal: AuthenticatedPrincipal,
        request_id: RequestId,
        request_bytes: &[u8],
        request: &WireRequest,
        now: Timestamp,
        encode: impl FnOnce(Result<WireResponseBody, RelayError>) -> Vec<u8>,
    ) -> Result<QueueExchange, DurableRelayError> {
        self.queue_exchange(
            principal,
            request_id,
            request_bytes,
            |transaction| execute_queue_request(transaction, request, now),
            encode,
        )
    }

    /// Runs a queue command and records its replay entry in one transaction.
    ///
    /// `effect` executes the command inside the supplied transaction and
    /// `encode` renders the final response bytes from its outcome. On success
    /// the command effect and the `(principal, request_id)` replay record
    /// commit atomically; on a protocol rejection the effect rolls back and
    /// only the replay record commits. A concurrent duplicate that commits
    /// first resolves to the stored response for an exact retry, or to
    /// [`QueueExchange::Conflict`] for differing request bytes.
    ///
    /// # Errors
    ///
    /// Returns a storage error; protocol rejections are encoded responses.
    pub fn queue_exchange<T>(
        &mut self,
        principal: AuthenticatedPrincipal,
        request_id: RequestId,
        request: &[u8],
        effect: impl FnOnce(&Transaction<'_>) -> Result<T, DurableRelayError>,
        encode: impl FnOnce(Result<T, RelayError>) -> Vec<u8>,
    ) -> Result<QueueExchange, DurableRelayError> {
        replay::exchange(
            &mut self.connection,
            Namespace::Queue,
            principal.as_bytes(),
            request_id,
            request,
            |transaction| match effect(transaction) {
                Ok(value) => Ok(value),
                Err(DurableRelayError::Relay(error)) => Err(EffectError::Protocol(error)),
                Err(error) => Err(EffectError::Storage(error)),
            },
            encode,
        )
    }
}

fn execute_queue_request(
    transaction: &Transaction<'_>,
    request: &WireRequest,
    now: Timestamp,
) -> Result<WireResponseBody, DurableRelayError> {
    match request {
        WireRequest::CreateQueue(create) => {
            let limits = QueueLimits::new(
                usize::try_from(create.limits().max_messages())
                    .map_err(|_| RelayError::LimitOutOfRange)?,
                usize::try_from(create.limits().max_message_bytes())
                    .map_err(|_| RelayError::LimitOutOfRange)?,
            )
            .ok_or(RelayError::LimitOutOfRange)?;
            DurableRelay::create_queue_tx(
                transaction,
                create.queue_id(),
                QueueConfig::new(create.sender(), create.recipient(), limits),
            )
            .map(WireResponseBody::CreateQueue)
        }
        WireRequest::Send(send) => {
            let ttl = Ttl::from_secs(send.ttl().as_secs()).ok_or(RelayError::LimitOutOfRange)?;
            DurableRelay::send_tx(
                transaction,
                send.queue_id(),
                send.sender(),
                send.message_id(),
                send.payload().as_bytes(),
                now,
                ttl,
            )
            .map(WireResponseBody::Send)
        }
        WireRequest::Fetch(fetch) => {
            DurableRelay::fetch_tx(transaction, fetch.queue_id(), fetch.recipient(), now).and_then(
                |delivery| {
                    let delivery = if let Some(delivery) = delivery {
                        let payload = Payload::new(delivery.payload)
                            .map_err(|_| DurableRelayError::from(RelayError::MessageTooLarge))?;
                        Some(WireDelivery::new(
                            delivery.id,
                            payload,
                            cofferwire_types::Timestamp::from_secs(delivery.expires_at.as_secs()),
                        ))
                    } else {
                        None
                    };
                    Ok(WireResponseBody::Fetch(delivery))
                },
            )
        }
        WireRequest::Ack(ack) => DurableRelay::acknowledge_tx(
            transaction,
            ack.queue_id(),
            ack.recipient(),
            ack.message_id(),
            now,
        )
        .map(|()| WireResponseBody::Ack),
        WireRequest::DeleteQueue(delete) => {
            DurableRelay::delete_queue_tx(transaction, delete.queue_id(), delete.recipient())
                .map(|()| WireResponseBody::DeleteQueue)
        }
    }
}

/// Stored replay record: exact request bytes and the recorded response bytes.
pub type QueueReplayRecord = crate::ReplayRecord;

/// Queue-profile name for the shared replay outcome.
pub type QueueExchange = crate::ReplayExchange;

fn read_queue(
    transaction: &Transaction<'_>,
    queue_id: QueueId,
) -> rusqlite::Result<Option<QueueConfig>> {
    transaction
        .query_row(
            "SELECT sender, recipient, max_messages, max_message_bytes
             FROM queues WHERE queue_id = ?1",
            [queue_id.as_bytes().as_slice()],
            |row| {
                let max_messages = u64_to_usize(blob_u64(row.get_ref(2)?.as_blob()?)?)?;
                let max_message_bytes = u64_to_usize(blob_u64(row.get_ref(3)?.as_blob()?)?)?;
                let limits = QueueLimits::new(max_messages, max_message_bytes)
                    .ok_or_else(|| invalid_data("queue limits must be non-zero"))?;
                Ok(QueueConfig::new(
                    Principal::from_bytes(blob_32(row.get_ref(0)?.as_blob()?)?),
                    Principal::from_bytes(blob_32(row.get_ref(1)?.as_blob()?)?),
                    limits,
                ))
            },
        )
        .optional()
}

fn authorize_recipient(
    transaction: &Transaction<'_>,
    queue_id: QueueId,
    recipient: Principal,
) -> Result<(), DurableRelayError> {
    let config = read_queue(transaction, queue_id)?.ok_or(RelayError::QueueNotFound)?;
    if config.recipient() != recipient {
        return Err(RelayError::Unauthorized.into());
    }
    Ok(())
}

fn discard_expired(
    transaction: &Transaction<'_>,
    queue_id: QueueId,
    now: Timestamp,
) -> rusqlite::Result<()> {
    transaction.execute(
        "DELETE FROM messages WHERE queue_id = ?1 AND expires_at <= ?2",
        params![
            queue_id.as_bytes().as_slice(),
            now.as_secs().to_be_bytes().as_slice()
        ],
    )?;
    Ok(())
}

fn blob_32(value: &[u8]) -> rusqlite::Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| invalid_data("identifier must contain exactly 32 bytes"))
}

fn blob_u64(value: &[u8]) -> rusqlite::Result<u64> {
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| invalid_data("integer must contain exactly 8 bytes"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).expect("usize always fits in u64 on supported Rust targets")
}

fn u64_to_usize(value: u64) -> rusqlite::Result<usize> {
    usize::try_from(value).map_err(|_| invalid_data("stored limit does not fit usize"))
}

fn invalid_data(message: &'static str) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(message.to_owned())
}

fn classify_storage_error(error: &rusqlite::Error) -> StorageErrorKind {
    let rusqlite::Error::SqliteFailure(failure, _) = error else {
        return StorageErrorKind::Other;
    };
    match failure.code {
        ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => StorageErrorKind::Busy,
        ErrorCode::ReadOnly | ErrorCode::PermissionDenied => StorageErrorKind::ReadOnly,
        ErrorCode::DiskFull => StorageErrorKind::Full,
        ErrorCode::SystemIoFailure | ErrorCode::CannotOpen => StorageErrorKind::Io,
        ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => StorageErrorKind::Corrupt,
        _ => StorageErrorKind::Other,
    }
}

pub(crate) fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_COMMIT.with(std::cell::Cell::take) {
        drop(transaction);
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
            Some("injected commit failure".to_owned()),
        ));
    }
    transaction.commit()
}

#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_NEXT_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn crash_point(point: &str) {
    if std::env::var("COFFERWIRE_TEST_CRASH_POINT").as_deref() == Ok(point) {
        std::process::abort();
    }
}

#[cfg(test)]
mod tests;
