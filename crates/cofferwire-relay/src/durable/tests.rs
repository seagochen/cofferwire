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
        "create_queue" => {
            let limits = QueueLimits::new(2, 1024).expect("valid limits");
            relay
                .create_queue(QUEUE, QueueConfig::new(SENDER, RECIPIENT, limits))
                .expect("configured crash point must terminate create_queue");
        }
        "delete_queue" => {
            relay
                .delete_queue(QUEUE, RECIPIENT)
                .expect("configured crash point must terminate delete_queue");
        }
        other => panic!("unknown crash action: {other}"),
    }
    panic!("crash worker passed its configured crash point");
}

#[test]
#[allow(clippy::too_many_lines)]
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

    let create_before = TestDatabase::new();
    run_crashing_child(&create_before, "create_queue", "create_queue_before_commit");
    let mut recovered = DurableRelay::open(create_before.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let limits = QueueLimits::new(2, 1024).expect("valid limits");
    assert!(
        matches!(
            recovered.create_queue(QUEUE, QueueConfig::new(SENDER, RECIPIENT, limits)),
            Ok(CreateQueueOutcome::Created)
        ),
        "crash before commit leaves no queue behind"
    );

    let create_after = TestDatabase::new();
    run_crashing_child(&create_after, "create_queue", "create_queue_after_commit");
    let mut recovered = DurableRelay::open(create_after.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let limits = QueueLimits::new(2, 1024).expect("valid limits");
    assert!(
        matches!(
            recovered.create_queue(QUEUE, QueueConfig::new(SENDER, RECIPIENT, limits)),
            Ok(CreateQueueOutcome::AlreadyExists)
        ),
        "crash after commit durably records the queue"
    );

    let delete_before = TestDatabase::new();
    drop(open_with_queue(&delete_before));
    run_crashing_child(&delete_before, "delete_queue", "delete_queue_before_commit");
    let recovered = DurableRelay::open(delete_before.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    assert_eq!(
        recovered
            .connection
            .query_row("SELECT count(*) FROM queues", [], |row| row
                .get::<_, i64>(0))
            .expect("count reads"),
        1,
        "crash before commit leaves the queue behind"
    );

    let delete_after = TestDatabase::new();
    drop(open_with_queue(&delete_after));
    run_crashing_child(&delete_after, "delete_queue", "delete_queue_after_commit");
    let recovered = DurableRelay::open(delete_after.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    assert_eq!(
        recovered
            .connection
            .query_row("SELECT count(*) FROM queues", [], |row| row
                .get::<_, i64>(0))
            .expect("count reads"),
        0,
        "crash after commit durably records the deletion"
    );
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
        Err(DurableRelayError::UnsupportedSchemaVersion { found, supported })
            if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
    ));
    let connection = Connection::open(database.path()).expect("database still opens directly");
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("schema version remains readable");
    assert_eq!(version, SCHEMA_VERSION + 1);
}

#[test]
fn v2_databases_migrate_to_version_3_adding_queue_replays() {
    let database = TestDatabase::new();
    {
        let mut relay = open_with_queue(&database);
        relay
            .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
            .expect("send commits");
    }
    // Downgrade to the version 2 layout: no queue_replays table, stamp 2.
    let connection = Connection::open(database.path()).expect("database opens directly");
    connection
        .execute_batch("DROP TABLE queue_replays;")
        .expect("queue replay table drops");
    connection
        .pragma_update(None, "user_version", 2)
        .expect("version downgrades");
    drop(connection);

    let mut relay = DurableRelay::open(database.path()).expect("v2 database migrates");
    let version: i64 = relay
        .connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("version reads");
    assert_eq!(version, 3);
    let delivery = relay
        .fetch(QUEUE, RECIPIENT, NOW)
        .expect("fetch succeeds after migration")
        .expect("pre-existing message survives migration");
    assert_eq!(delivery.payload(), b"ciphertext");
    assert_eq!(
        relay
            .queue_replay(
                AuthenticatedPrincipal::from_bytes([0; 32]),
                RequestId::from_bytes([0; 16])
            )
            .expect("lookup succeeds on the newly created table"),
        None
    );
    assert_database_integrity(&relay);
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
fn concurrent_fetch_and_acknowledge_never_apply_twice_or_lose_the_message() {
    let database = TestDatabase::new();
    {
        let mut relay = open_with_queue(&database);
        relay
            .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
            .expect("send commits");
    }
    let barrier = Arc::new(Barrier::new(3));
    let path = database.path().to_owned();
    let mut workers = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            let mut relay = DurableRelay::open(path).expect("worker opens database");
            barrier.wait();
            let fetched = relay.fetch(QUEUE, RECIPIENT, NOW).expect("fetch succeeds");
            fetched.map(|delivery| relay.acknowledge(QUEUE, RECIPIENT, delivery.id(), NOW))
        }));
    }
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker does not panic"))
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Some(Ok(()))))
            .count(),
        1,
        "exactly one concurrent ack applies the deletion: {results:?}"
    );
    // The other worker either lost the fetch race entirely (the first
    // worker's fetch-then-ack pair both completed before this worker's
    // fetch ran, so it saw an empty queue) or fetched the same message
    // and then lost the ack race with AckMismatch. Both are correct,
    // consistent outcomes; anything else indicates corruption.
    for result in &results {
        match result {
            Some(Ok(()) | Err(DurableRelayError::Relay(RelayError::AckMismatch))) | None => {}
            other => panic!("unexpected concurrent fetch/ack outcome: {other:?}"),
        }
    }

    let mut recovered = DurableRelay::open(database.path()).expect("database reopens");
    assert!(
        recovered
            .fetch(QUEUE, RECIPIENT, NOW)
            .expect("fetch succeeds")
            .is_none(),
        "the message is gone exactly once, never duplicated or stuck"
    );
    assert_database_integrity(&recovered);
}

#[test]
fn concurrent_delete_queue_applies_exactly_once() {
    let database = TestDatabase::new();
    drop(open_with_queue(&database));
    let barrier = Arc::new(Barrier::new(3));
    let path = database.path().to_owned();
    let mut workers = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            let mut relay = DurableRelay::open(path).expect("worker opens database");
            barrier.wait();
            relay.delete_queue(QUEUE, RECIPIENT)
        }));
    }
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker does not panic"))
        .collect();
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one concurrent delete succeeds: {results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(DurableRelayError::Relay(RelayError::QueueNotFound))
            ))
            .count(),
        1,
        "the losing delete observes the queue is already gone, not partial state: {results:?}"
    );
    let recovered = DurableRelay::open(database.path()).expect("database reopens");
    assert_database_integrity(&recovered);
}

#[test]
fn concurrent_fetch_across_the_expiry_boundary_never_yields_an_expired_message() {
    let database = TestDatabase::new();
    {
        let mut relay = open_with_queue(&database);
        relay
            .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
            .expect("send commits");
    }
    let expiry = Timestamp::from_secs(NOW.as_secs() + TTL.as_secs());
    let barrier = Arc::new(Barrier::new(3));
    let path = database.path().to_owned();
    let before_worker = {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut relay = DurableRelay::open(path).expect("worker opens database");
            barrier.wait();
            relay.fetch(QUEUE, RECIPIENT, NOW)
        })
    };
    let after_worker = {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            let mut relay = DurableRelay::open(path).expect("worker opens database");
            barrier.wait();
            relay.fetch(QUEUE, RECIPIENT, expiry)
        })
    };
    barrier.wait();
    let before_result = before_worker.join().expect("worker does not panic");
    let after_result = after_worker.join().expect("worker does not panic");
    // Whichever transaction commits first, an expiry-time fetch never
    // observes the message: either it purges the not-yet-delivered
    // message itself, or the pre-expiry racer already committed first
    // and the message is simply gone by the time expiry-time cleanup
    // runs. A pre-expiry fetch may or may not still see it, but the
    // expiry-time fetch's result is deterministic regardless of
    // interleaving.
    assert!(
        after_result.expect("fetch succeeds").is_none(),
        "an expiry-time fetch never returns an expired message under a race"
    );
    let _ = before_result.expect("fetch succeeds");

    let mut recovered = DurableRelay::open(database.path()).expect("database reopens");
    assert!(recovered
        .fetch(QUEUE, RECIPIENT, expiry)
        .expect("fetch succeeds")
        .is_none());
    assert_database_integrity(&recovered);
}

#[test]
fn file_copy_backup_restores_correctly_in_a_fresh_process() {
    let source = TestDatabase::new();
    {
        let mut relay = open_with_queue(&source);
        relay
            .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
            .expect("send commits");
    }
    // This schema uses SQLite's rollback journal (not WAL), so a plain
    // file copy taken after every writer has closed is a valid backup:
    // there is no separate WAL/shm file holding uncommitted data.
    let backup = TestDatabase::new();
    fs::copy(source.path(), backup.path()).expect("file-level backup copies committed state");
    drop(source);

    let mut restored = DurableRelay::open(backup.path()).expect("backup opens in a fresh process");
    assert_database_integrity(&restored);
    let delivery = restored
        .fetch(QUEUE, RECIPIENT, NOW)
        .expect("fetch succeeds")
        .expect("backed-up message survives restore");
    assert_eq!(delivery.payload(), b"ciphertext");
    restored
        .acknowledge(QUEUE, RECIPIENT, delivery.id(), NOW)
        .expect("restored database accepts further commands");
}

#[test]
fn clock_jumps_never_fabricate_or_silently_lose_an_accepted_message() {
    let database = TestDatabase::new();
    let mut relay = open_with_queue(&database);
    relay
        .send(QUEUE, SENDER, MESSAGE, b"ciphertext", NOW, TTL)
        .expect("send commits");

    // A large backward jump must not treat the unexpired message as
    // already gone, nor let a conflicting resend through as if it were
    // a fresh, never-seen message identifier.
    let far_past = Timestamp::from_secs(0);
    assert!(
        relay
            .fetch(QUEUE, RECIPIENT, far_past)
            .expect("fetch succeeds")
            .is_some(),
        "a backward clock jump must not fabricate an expiry for an unexpired message"
    );
    assert!(matches!(
        relay.send(QUEUE, SENDER, MESSAGE, b"changed", far_past, TTL),
        Err(DurableRelayError::Relay(RelayError::MessageIdConflict))
    ));

    // A large forward jump must discard the now-ancient message and
    // release its capacity, without corrupting unrelated state.
    let far_future = Timestamp::from_secs(NOW.as_secs() + TTL.as_secs() + 1_000_000);
    assert!(
        relay
            .fetch(QUEUE, RECIPIENT, far_future)
            .expect("fetch succeeds")
            .is_none(),
        "a forward clock jump discards the expired message rather than fabricating a delivery"
    );
    assert!(
        matches!(
            relay.send(QUEUE, SENDER, MESSAGE_B, b"new", far_future, TTL),
            Ok(SendOutcome::Accepted)
        ),
        "capacity is correctly released after the forward jump"
    );
    assert_database_integrity(&relay);

    // Jumping back again must not resurrect the message already purged
    // at a later time, nor duplicate the newly accepted one.
    let delivery = relay
        .fetch(QUEUE, RECIPIENT, NOW)
        .expect("fetch succeeds")
        .expect("the newly accepted message is still deliverable");
    assert_eq!(
        delivery.id(),
        MESSAGE_B,
        "a further backward jump does not resurrect the message purged earlier"
    );
    assert_database_integrity(&relay);
}

#[test]
fn durable_relay_error_debug_never_contains_opaque_payload_bytes() {
    const SECRET: &[u8] = b"top-secret-ciphertext-marker";
    let database = TestDatabase::new();
    let mut relay = open_with_queue(&database);
    relay
        .send(QUEUE, SENDER, MESSAGE, SECRET, NOW, TTL)
        .expect("send commits");

    // A relay-semantics error: retrying the same message ID with a
    // different payload. The rejection carries no request data at all
    // (RelayError variants are all unit variants), but this proves it
    // for the exact type surfaced to callers.
    let conflict = relay
        .send(QUEUE, SENDER, MESSAGE, b"different payload", NOW, TTL)
        .expect_err("conflicting resend is rejected");
    let rendered = format!("{conflict:?} {conflict}");
    assert!(!rendered.contains("top-secret"));
    assert!(!rendered.contains("different payload"));

    // A storage-layer error: injected commit failure while a secret
    // payload is in flight. `DurableRelayError::Storage` wraps
    // `rusqlite::Error`, which reports constraint/IO failures, not bound
    // parameter values; this proves the wrapped Debug/Display honor
    // that.
    FAIL_NEXT_COMMIT.with(|flag| flag.set(true));
    let storage_error = relay
        .send(QUEUE, SENDER, MESSAGE_B, SECRET, NOW, TTL)
        .expect_err("injected commit failure is returned");
    let rendered = format!("{storage_error:?} {storage_error}");
    assert!(!rendered.contains("top-secret"));
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
        let payload = vec![random.to_be_bytes()[5]; usize::try_from(random % 40).expect("small")];
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
