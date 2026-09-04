//! SQLite-backed transactional queue storage.

use std::path::Path;
use std::time::Duration;

use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior,
};

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
";
const SCHEMA_VERSION: i64 = 1;

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
    connection: Connection,
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
        if version != 0 && version != SCHEMA_VERSION {
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
        if version == 0 {
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
        commit(transaction)?;
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
        let config = read_queue(&transaction, queue_id)?.ok_or(RelayError::QueueNotFound)?;
        if config.sender() != sender {
            return Err(RelayError::Unauthorized.into());
        }
        discard_expired(&transaction, queue_id, now)?;

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
        let expires_at = now.checked_add(ttl).ok_or(RelayError::ExpiryOverflow)?;
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
        #[cfg(test)]
        crash_point("send_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crash_point("send_after_commit");
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
        authorize_recipient(&transaction, queue_id, recipient)?;
        discard_expired(&transaction, queue_id, now)?;
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
            commit(transaction)?;
            return Ok(None);
        };
        transaction.execute(
            "UPDATE messages SET delivered = 1 WHERE sequence = ?1",
            [sequence],
        )?;
        #[cfg(test)]
        crash_point("fetch_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crash_point("fetch_after_commit");
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
        authorize_recipient(&transaction, queue_id, recipient)?;
        discard_expired(&transaction, queue_id, now)?;
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
        #[cfg(test)]
        crash_point("ack_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crash_point("ack_after_commit");
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
        authorize_recipient(&transaction, queue_id, recipient)?;
        transaction.execute(
            "DELETE FROM queues WHERE queue_id = ?1",
            [queue_id.as_bytes().as_slice()],
        )?;
        commit(transaction)?;
        Ok(())
    }
}

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

fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
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
    static FAIL_NEXT_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn crash_point(point: &str) {
    if std::env::var("COFFERWIRE_TEST_CRASH_POINT").as_deref() == Ok(point) {
        std::process::abort();
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    const QUEUE: QueueId = QueueId::from_bytes([1; 32]);
    const SENDER: Principal = Principal::from_bytes([2; 32]);
    const RECIPIENT: Principal = Principal::from_bytes([3; 32]);
    const MESSAGE: MessageId = MessageId::from_bytes([4; 32]);
    const OTHER: Principal = Principal::from_bytes([5; 32]);
    const MESSAGE_B: MessageId = MessageId::from_bytes([6; 32]);
    const NOW: Timestamp = Timestamp::from_secs(10_000);
    const TTL: Ttl = match Ttl::from_secs(300) {
        Some(ttl) => ttl,
        None => panic!("test TTL must be non-zero"),
    };

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);
    const CRASH_DATABASE_ENV: &str = "COFFERWIRE_TEST_CRASH_DATABASE";
    const CRASH_ACTION_ENV: &str = "COFFERWIRE_TEST_CRASH_ACTION";
    const CRASH_POINT_ENV: &str = "COFFERWIRE_TEST_CRASH_POINT";

    struct TestDatabase(PathBuf);

    impl TestDatabase {
        fn new() -> Self {
            let serial = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cofferwire-relay-{}-{serial}.sqlite3",
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
            for suffix in ["", "-journal", "-shm", "-wal"] {
                let candidate = PathBuf::from(format!("{}{suffix}", self.0.display()));
                match fs::remove_file(candidate) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("failed to remove test database: {error}"),
                }
            }
        }
    }

    fn open_with_queue(database: &TestDatabase) -> DurableRelay {
        let mut relay = DurableRelay::open(database.path()).expect("database opens");
        let limits = QueueLimits::new(2, 1024).expect("valid limits");
        relay
            .create_queue(QUEUE, QueueConfig::new(SENDER, RECIPIENT, limits))
            .expect("queue creation commits");
        relay
    }

    fn run_crashing_child(database: &TestDatabase, action: &str, point: &str) {
        let output = Command::new(std::env::current_exe().expect("test executable is available"))
            .args([
                "--exact",
                "durable::tests::crash_worker",
                "--test-threads=1",
            ])
            .env(CRASH_DATABASE_ENV, database.path())
            .env(CRASH_ACTION_ENV, action)
            .env(CRASH_POINT_ENV, point)
            .output()
            .expect("crash worker starts");
        assert!(
            !output.status.success(),
            "crash worker unexpectedly returned normally:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn assert_database_integrity(relay: &DurableRelay) {
        let result: String = relay
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("integrity check executes");
        assert_eq!(result, "ok");
    }

    fn storage_kind(error: &DurableRelayError) -> StorageErrorKind {
        error.storage_kind().expect("expected storage failure")
    }

    fn prepare_delivered_message(database: &TestDatabase) {
        let mut relay = open_with_queue(database);
        relay
            .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
            .expect("send commits");
        relay
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch commits delivery state");
    }

    #[test]
    fn crash_worker() {
        let Some(path) = std::env::var_os(CRASH_DATABASE_ENV) else {
            return;
        };
        let action = std::env::var(CRASH_ACTION_ENV).expect("crash action is supplied");
        let mut relay = DurableRelay::open(path).expect("crash worker opens database");
        match action.as_str() {
            "send" => {
                relay
                    .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
                    .expect("configured crash point must terminate send");
            }
            "fetch" => {
                relay
                    .fetch(QUEUE, RECIPIENT, NOW)
                    .expect("configured crash point must terminate fetch");
            }
            "ack" => {
                relay
                    .acknowledge(QUEUE, RECIPIENT, MESSAGE, NOW)
                    .expect("configured crash point must terminate ack");
            }
            other => panic!("unknown crash action: {other}"),
        }
        panic!("crash worker passed its configured crash point");
    }

    #[test]
    fn hard_process_crashes_recover_at_every_command_commit_boundary() {
        let send_before = TestDatabase::new();
        drop(open_with_queue(&send_before));
        run_crashing_child(&send_before, "send", "send_before_commit");
        let mut recovered = DurableRelay::open(send_before.path()).expect("database recovers");
        assert_database_integrity(&recovered);
        assert!(recovered
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .is_none());

        let send_after = TestDatabase::new();
        drop(open_with_queue(&send_after));
        run_crashing_child(&send_after, "send", "send_after_commit");
        let mut recovered = DurableRelay::open(send_after.path()).expect("database recovers");
        assert_database_integrity(&recovered);
        assert!(recovered
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .is_some());

        let fetch_before = TestDatabase::new();
        {
            let mut relay = open_with_queue(&fetch_before);
            relay
                .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
                .expect("send commits");
        }
        run_crashing_child(&fetch_before, "fetch", "fetch_before_commit");
        let mut recovered = DurableRelay::open(fetch_before.path()).expect("database recovers");
        assert_database_integrity(&recovered);
        assert!(matches!(
            recovered.acknowledge(QUEUE, RECIPIENT, MESSAGE, NOW),
            Err(DurableRelayError::Relay(RelayError::NotDelivered))
        ));

        let fetch_after = TestDatabase::new();
        {
            let mut relay = open_with_queue(&fetch_after);
            relay
                .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
                .expect("send commits");
        }
        run_crashing_child(&fetch_after, "fetch", "fetch_after_commit");
        let mut recovered = DurableRelay::open(fetch_after.path()).expect("database recovers");
        assert_database_integrity(&recovered);
        recovered
            .acknowledge(QUEUE, RECIPIENT, MESSAGE, NOW)
            .expect("committed delivery state survives");

        let ack_before = TestDatabase::new();
        prepare_delivered_message(&ack_before);
        run_crashing_child(&ack_before, "ack", "ack_before_commit");
        let mut recovered = DurableRelay::open(ack_before.path()).expect("database recovers");
        assert_database_integrity(&recovered);
        assert!(recovered
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .is_some());

        let ack_after = TestDatabase::new();
        prepare_delivered_message(&ack_after);
        run_crashing_child(&ack_after, "ack", "ack_after_commit");
        let mut recovered = DurableRelay::open(ack_after.path()).expect("database recovers");
        assert_database_integrity(&recovered);
        assert!(recovered
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .is_none());
    }

    #[test]
    fn cw_store_005_unknown_schema_version_is_rejected_without_mutation() {
        let database = TestDatabase::new();
        let connection = Connection::open(database.path()).expect("database opens");
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("future version is written");
        drop(connection);

        assert!(matches!(
            DurableRelay::open(database.path()),
            Err(DurableRelayError::UnsupportedSchemaVersion {
                found: 2,
                supported: 1
            })
        ));
        let connection = Connection::open(database.path()).expect("database still opens directly");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("schema version remains readable");
        assert_eq!(version, SCHEMA_VERSION + 1);
    }

    #[test]
    fn cw_store_001_send_is_visible_after_successful_commit_and_restart() {
        let database = TestDatabase::new();
        {
            let mut relay = open_with_queue(&database);
            assert!(matches!(
                relay.send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL),
                Ok(SendOutcome::Accepted)
            ));
        }

        let mut recovered = DurableRelay::open(database.path()).expect("database reopens");
        let delivery = recovered
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds after restart")
            .expect("committed message survives restart");
        assert_eq!(delivery.id(), MESSAGE);
        assert_eq!(delivery.payload(), b"ciphertext");
    }

    #[test]
    fn cw_store_002_uncommitted_send_is_absent_after_restart() {
        let database = TestDatabase::new();
        let mut relay = open_with_queue(&database);
        {
            let transaction = relay.connection.transaction().expect("transaction begins");
            transaction
                .execute(
                    "INSERT INTO messages (queue_id, message_id, payload, expires_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        QUEUE.as_bytes().as_slice(),
                        MESSAGE.as_bytes().as_slice(),
                        b"not committed".as_slice(),
                        (NOW.as_secs() + TTL.as_secs()).to_be_bytes().as_slice(),
                    ],
                )
                .expect("mutation reaches the journal");
            // Dropping models termination before the commit durability boundary.
        }
        drop(relay);

        let mut recovered = DurableRelay::open(database.path()).expect("database reopens");
        assert!(recovered
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .is_none());
    }

    #[test]
    fn cw_store_003_ack_delete_is_atomic_across_restart() {
        let database = TestDatabase::new();
        let mut relay = open_with_queue(&database);
        relay
            .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
            .expect("send commits");
        relay
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch commits delivery state");
        {
            let transaction = relay.connection.transaction().expect("transaction begins");
            transaction
                .execute(
                    "DELETE FROM messages WHERE queue_id = ?1 AND message_id = ?2",
                    params![QUEUE.as_bytes().as_slice(), MESSAGE.as_bytes().as_slice()],
                )
                .expect("delete occurs inside transaction");
            // Termination before commit must restore the acknowledged message.
        }
        drop(relay);

        let mut recovered = DurableRelay::open(database.path()).expect("database reopens");
        assert!(recovered
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("rolled-back message can be redelivered")
            .is_some());
        recovered
            .acknowledge(QUEUE, RECIPIENT, MESSAGE, NOW)
            .expect("ack deletion commits");
        drop(recovered);

        let mut recovered = DurableRelay::open(database.path()).expect("database reopens");
        assert!(recovered
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .is_none());
    }

    #[test]
    fn cw_store_004_delivery_state_survives_restart_until_ack() {
        let database = TestDatabase::new();
        {
            let mut relay = open_with_queue(&database);
            relay
                .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
                .expect("send commits");
            relay
                .fetch(QUEUE, RECIPIENT, NOW)
                .expect("fetch commits delivery state");
        }

        let mut recovered = DurableRelay::open(database.path()).expect("database reopens");
        recovered
            .acknowledge(QUEUE, RECIPIENT, MESSAGE, NOW)
            .expect("ack remains authorized after restart");
        assert!(recovered
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .is_none());
    }

    #[test]
    fn durable_backend_preserves_the_queue_contract() {
        let database = TestDatabase::new();
        let limits = QueueLimits::new(1, 10).expect("valid limits");
        let config = QueueConfig::new(SENDER, RECIPIENT, limits);
        let mut relay = DurableRelay::open(database.path()).expect("database opens");
        assert!(matches!(
            relay.create_queue(QUEUE, config),
            Ok(CreateQueueOutcome::Created)
        ));
        assert!(matches!(
            relay.create_queue(QUEUE, config),
            Ok(CreateQueueOutcome::AlreadyExists)
        ));
        assert!(matches!(
            relay.create_queue(QUEUE, QueueConfig::new(OTHER, RECIPIENT, limits)),
            Err(DurableRelayError::Relay(RelayError::QueueIdConflict))
        ));
        assert!(matches!(
            relay.send(QUEUE, OTHER, MESSAGE, b"one", NOW, TTL),
            Err(DurableRelayError::Relay(RelayError::Unauthorized))
        ));
        assert!(matches!(
            relay.send(QUEUE, SENDER, MESSAGE, &[0; 11], NOW, TTL),
            Err(DurableRelayError::Relay(RelayError::MessageTooLarge))
        ));
        assert!(matches!(
            relay.send(QUEUE, SENDER, MESSAGE, b"one", NOW, TTL),
            Ok(SendOutcome::Accepted)
        ));
        assert!(matches!(
            relay.send(QUEUE, SENDER, MESSAGE, b"one", NOW, TTL),
            Ok(SendOutcome::Duplicate)
        ));
        assert!(matches!(
            relay.send(QUEUE, SENDER, MESSAGE, b"changed", NOW, TTL),
            Err(DurableRelayError::Relay(RelayError::MessageIdConflict))
        ));
        assert!(matches!(
            relay.send(QUEUE, SENDER, MESSAGE_B, b"two", NOW, TTL),
            Err(DurableRelayError::Relay(RelayError::QueueFull))
        ));
        assert!(matches!(
            relay.fetch(QUEUE, OTHER, NOW),
            Err(DurableRelayError::Relay(RelayError::Unauthorized))
        ));
        assert!(matches!(
            relay.acknowledge(QUEUE, RECIPIENT, MESSAGE, NOW),
            Err(DurableRelayError::Relay(RelayError::NotDelivered))
        ));
        assert!(relay
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .is_some());
        assert!(matches!(
            relay.acknowledge(QUEUE, RECIPIENT, MESSAGE_B, NOW),
            Err(DurableRelayError::Relay(RelayError::AckMismatch))
        ));

        let expiry = Timestamp::from_secs(NOW.as_secs() + TTL.as_secs());
        assert!(relay
            .fetch(QUEUE, RECIPIENT, expiry)
            .expect("expiry cleanup commits")
            .is_none());
        assert!(matches!(
            relay.send(QUEUE, SENDER, MESSAGE_B, b"two", expiry, TTL),
            Ok(SendOutcome::Accepted)
        ));
        assert!(matches!(
            relay.delete_queue(QUEUE, OTHER),
            Err(DurableRelayError::Relay(RelayError::Unauthorized))
        ));
    }

    #[test]
    fn concurrent_sends_serialize_capacity_and_message_id_conflicts() {
        let capacity_database = TestDatabase::new();
        {
            let mut relay = DurableRelay::open(capacity_database.path()).expect("database opens");
            relay
                .create_queue(
                    QUEUE,
                    QueueConfig::new(
                        SENDER,
                        RECIPIENT,
                        QueueLimits::new(1, 1024).expect("valid limits"),
                    ),
                )
                .expect("queue creation commits");
        }
        let results = concurrent_sends(
            capacity_database.path(),
            [(MESSAGE, b"one".as_slice()), (MESSAGE_B, b"two".as_slice())],
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(SendOutcome::Accepted)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(result, Err(DurableRelayError::Relay(RelayError::QueueFull)))
                })
                .count(),
            1
        );
        let recovered = DurableRelay::open(capacity_database.path()).expect("database reopens");
        assert_database_integrity(&recovered);

        let conflict_database = TestDatabase::new();
        drop(open_with_queue(&conflict_database));
        let results = concurrent_sends(
            conflict_database.path(),
            [(MESSAGE, b"one".as_slice()), (MESSAGE, b"two".as_slice())],
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(SendOutcome::Accepted)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| {
                    matches!(
                        result,
                        Err(DurableRelayError::Relay(RelayError::MessageIdConflict))
                    )
                })
                .count(),
            1
        );
        let recovered = DurableRelay::open(conflict_database.path()).expect("database reopens");
        assert_database_integrity(&recovered);
    }

    fn concurrent_sends(
        path: &Path,
        operations: [(MessageId, &[u8]); 2],
    ) -> Vec<Result<SendOutcome, DurableRelayError>> {
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for (message_id, payload) in operations {
            let path = path.to_owned();
            let barrier = Arc::clone(&barrier);
            let payload = payload.to_vec();
            workers.push(thread::spawn(move || {
                let mut relay = DurableRelay::open(path).expect("worker opens database");
                barrier.wait();
                relay.send(QUEUE, SENDER, message_id, &payload, NOW, TTL)
            }));
        }
        barrier.wait();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker does not panic"))
            .collect()
    }

    #[test]
    fn busy_timeout_is_bounded_and_classified() {
        let database = TestDatabase::new();
        let mut relay = open_with_queue(&database);
        let blocker = Connection::open(database.path()).expect("second connection opens");
        blocker
            .execute_batch("BEGIN IMMEDIATE")
            .expect("writer lock acquired");

        let start = Instant::now();
        let error = relay
            .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
            .expect_err("bounded lock wait must fail");
        let elapsed = start.elapsed();
        assert_eq!(storage_kind(&error), StorageErrorKind::Busy);
        assert!(
            elapsed >= Duration::from_millis(200),
            "elapsed: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(2), "elapsed: {elapsed:?}");

        blocker
            .execute_batch("ROLLBACK")
            .expect("writer lock released");
        assert_database_integrity(&relay);
    }

    #[test]
    fn readonly_full_and_commit_failures_rollback_without_false_success() {
        let readonly_database = TestDatabase::new();
        let mut readonly = open_with_queue(&readonly_database);
        readonly
            .connection
            .pragma_update(None, "query_only", true)
            .expect("query-only mode enabled");
        let error = readonly
            .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
            .expect_err("read-only write fails");
        assert_eq!(storage_kind(&error), StorageErrorKind::ReadOnly);
        readonly
            .connection
            .pragma_update(None, "query_only", false)
            .expect("query-only mode disabled");
        assert!(readonly
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch after failure")
            .is_none());
        assert_database_integrity(&readonly);

        let full_database = TestDatabase::new();
        let mut full = DurableRelay::open(full_database.path()).expect("database opens");
        full.create_queue(
            QUEUE,
            QueueConfig::new(
                SENDER,
                RECIPIENT,
                QueueLimits::new(2, 128 * 1024).expect("valid limits"),
            ),
        )
        .expect("queue creation commits");
        let page_count: i64 = full
            .connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .expect("page count reads");
        full.connection
            .pragma_update(None, "max_page_count", page_count)
            .expect("page limit fixed at current size");
        let error = full
            .send(QUEUE, SENDER, MESSAGE, &vec![0x5a; 128 * 1024], NOW, TTL)
            .expect_err("page limit makes insertion fail");
        assert_eq!(storage_kind(&error), StorageErrorKind::Full);
        assert!(full
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch after failure")
            .is_none());
        assert_database_integrity(&full);

        let commit_database = TestDatabase::new();
        let mut commit_failure = open_with_queue(&commit_database);
        FAIL_NEXT_COMMIT.with(|flag| flag.set(true));
        let error = commit_failure
            .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
            .expect_err("injected commit failure is returned");
        assert_eq!(storage_kind(&error), StorageErrorKind::Io);
        assert!(commit_failure
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch after rollback")
            .is_none());
        assert_database_integrity(&commit_failure);
    }

    #[test]
    fn long_generated_sequence_matches_in_memory_reference_model() {
        let database = TestDatabase::new();
        let mut durable = DurableRelay::open(database.path()).expect("database opens");
        let mut reference = crate::Relay::new();
        let limits = QueueLimits::new(4, 32).expect("valid limits");
        let config = QueueConfig::new(SENDER, RECIPIENT, limits);
        let mut random = 0x4d59_5df4_d0f3_3173_u64;

        for step in 0..2_000_u64 {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let now = Timestamp::from_secs(NOW.as_secs() + step / 7);
            let message = MessageId::from_bytes([random.to_be_bytes()[6]; 32]);
            let payload =
                vec![random.to_be_bytes()[5]; usize::try_from(random % 40).expect("small")];
            let ttl = Ttl::from_secs(random % 11 + 1).expect("nonzero TTL");
            match random % 6 {
                0 => assert_eq!(
                    reference.create_queue(QUEUE, config),
                    durable_relay_result(durable.create_queue(QUEUE, config))
                ),
                1 => assert_eq!(
                    reference.send(QUEUE, SENDER, message, payload.clone(), now, ttl),
                    durable_relay_result(durable.send(QUEUE, SENDER, message, &payload, now, ttl))
                ),
                2 => assert_eq!(
                    reference.fetch(QUEUE, RECIPIENT, now),
                    durable_relay_result(durable.fetch(QUEUE, RECIPIENT, now))
                ),
                3 => assert_eq!(
                    reference.acknowledge(QUEUE, RECIPIENT, message, now),
                    durable_relay_result(durable.acknowledge(QUEUE, RECIPIENT, message, now))
                ),
                4 => assert_eq!(
                    reference.delete_queue(QUEUE, RECIPIENT),
                    durable_relay_result(durable.delete_queue(QUEUE, RECIPIENT))
                ),
                _ => {
                    let expiry_time = Timestamp::from_secs(now.as_secs() + 20);
                    assert_eq!(
                        reference.fetch(QUEUE, RECIPIENT, expiry_time),
                        durable_relay_result(durable.fetch(QUEUE, RECIPIENT, expiry_time))
                    );
                }
            }
        }
        assert_database_integrity(&durable);
    }

    fn durable_relay_result<T>(result: Result<T, DurableRelayError>) -> Result<T, RelayError> {
        result.map_err(|error| match error {
            DurableRelayError::Relay(error) => error,
            other => panic!("unexpected durable storage failure: {other}"),
        })
    }
}
