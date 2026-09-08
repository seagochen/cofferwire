use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::Connection;

use super::*;
use crate::durable::FAIL_NEXT_COMMIT;

const NOW: Timestamp = Timestamp::from_secs(1_000);
const CAP: CapabilityId = CapabilityId::from_bytes([7; 32]);
const REQUEST_ID: RequestId = RequestId::from_bytes([9; 16]);
const CRASH_DATABASE_ENV: &str = "COFFERWIRE_TEST_BLOB_CRASH_DATABASE";
const CRASH_ACTION_ENV: &str = "COFFERWIRE_TEST_BLOB_CRASH_ACTION";
const CRASH_POINT_ENV: &str = "COFFERWIRE_TEST_CRASH_POINT";

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "cofferwire-blob-relay-{}-{serial}.sqlite3",
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

fn fixture() -> (
    UploadId,
    BlobCapabilities,
    BlobManifest,
    Vec<Vec<u8>>,
    BlobId,
) {
    let chunks = vec![vec![0xAB; 48], vec![0xCD; 48]];
    let mut manifest = b"CWB1".to_vec();
    manifest.extend_from_slice(&1_u16.to_be_bytes());
    manifest.extend_from_slice(&1_u16.to_be_bytes());
    manifest.extend_from_slice(&[0x55; 16]);
    manifest.extend_from_slice(&64_u64.to_be_bytes());
    manifest.extend_from_slice(&32_u32.to_be_bytes());
    manifest.extend_from_slice(&2_u32.to_be_bytes());
    for chunk in &chunks {
        manifest.extend_from_slice(&Sha256::digest(chunk));
    }
    let manifest = BlobManifest::parse(manifest).expect("fixture manifest is valid");
    let caps = BlobCapabilities {
        upload: CapabilityId::from_bytes([1; 32]),
        download: CapabilityId::from_bytes([2; 32]),
        renew: CapabilityId::from_bytes([3; 32]),
        delete: CapabilityId::from_bytes([4; 32]),
    };
    let upload_id = UploadId::from_bytes([42; 32]);
    let blob_id = identify(&manifest);
    (upload_id, caps, manifest, chunks, blob_id)
}

/// A single-chunk fixture whose ciphertext is large enough to force real
/// page growth, for tests that need a write too big to fit in whatever
/// free-space slack a fresh database happens to have.
fn large_chunk_fixture() -> (UploadId, BlobCapabilities, BlobManifest, Vec<u8>, BlobId) {
    let chunk_size: u32 = 128 * 1024;
    let ciphertext = vec![0x5A_u8; chunk_size as usize + 16];
    let mut manifest = b"CWB1".to_vec();
    manifest.extend_from_slice(&1_u16.to_be_bytes());
    manifest.extend_from_slice(&1_u16.to_be_bytes());
    manifest.extend_from_slice(&[0x77; 16]);
    manifest.extend_from_slice(&u64::from(chunk_size).to_be_bytes());
    manifest.extend_from_slice(&chunk_size.to_be_bytes());
    manifest.extend_from_slice(&1_u32.to_be_bytes());
    manifest.extend_from_slice(&Sha256::digest(&ciphertext));
    let manifest = BlobManifest::parse(manifest).expect("large fixture manifest is valid");
    let caps = BlobCapabilities {
        upload: CapabilityId::from_bytes([11; 32]),
        download: CapabilityId::from_bytes([12; 32]),
        renew: CapabilityId::from_bytes([13; 32]),
        delete: CapabilityId::from_bytes([14; 32]),
    };
    let upload_id = UploadId::from_bytes([43; 32]);
    let blob_id = identify(&manifest);
    (upload_id, caps, manifest, ciphertext, blob_id)
}

fn replay_response(result: Result<BlobWriteOutcome, BlobRelayError>) -> Vec<u8> {
    match result {
        Ok(outcome) => vec![0xA0, outcome.as_u8()],
        Err(error) => vec![0xE0, error as u8],
    }
}

fn begin_exchange(
    relay: &mut DurableRelay,
    request: &[u8],
    ttl: u64,
) -> Result<BlobExchange, DurableRelayError> {
    let (upload_id, caps, manifest, ..) = fixture();
    relay.blob_exchange(
        CAP,
        REQUEST_ID,
        request,
        |transaction| {
            DurableRelay::begin_blob_upload_tx(transaction, upload_id, caps, &manifest, NOW, ttl)
        },
        replay_response,
    )
}

#[test]
fn blob_replay_record_survives_restart_and_returns_stored_response() {
    let database = TestDatabase::new();
    {
        let mut relay = DurableRelay::open(database.path()).expect("database opens");
        assert_eq!(
            begin_exchange(&mut relay, b"request-bytes", 100).expect("exchange commits"),
            BlobExchange::Respond(vec![0xA0, 0])
        );
    }

    let mut relay = DurableRelay::open(database.path()).expect("database reopens");
    assert_eq!(
        relay
            .blob_replay(CAP, REQUEST_ID)
            .expect("replay lookup succeeds"),
        Some((b"request-bytes".to_vec(), vec![0xA0, 0]))
    );
    // A duplicate delivery after restart resolves through the insert race
    // path and returns the stored response rather than re-executing.
    assert_eq!(
        begin_exchange(&mut relay, b"request-bytes", 100).expect("exchange commits"),
        BlobExchange::Respond(vec![0xA0, 0])
    );
}

#[test]
fn conflicting_request_id_reuse_is_rejected_after_restart() {
    let database = TestDatabase::new();
    {
        let mut relay = DurableRelay::open(database.path()).expect("database opens");
        begin_exchange(&mut relay, b"request-bytes", 100).expect("exchange commits");
    }

    let mut relay = DurableRelay::open(database.path()).expect("database reopens");
    assert_eq!(
        begin_exchange(&mut relay, b"other-request-bytes", 100).expect("exchange resolves"),
        BlobExchange::Conflict
    );
}

#[test]
fn protocol_rejections_are_recorded_without_committing_effects() {
    let database = TestDatabase::new();
    let mut relay = DurableRelay::open(database.path()).expect("database opens");
    let (upload_id, caps, ..) = fixture();
    let outcome = relay
        .blob_exchange(
            CAP,
            REQUEST_ID,
            b"renew-unknown",
            |transaction| {
                DurableRelay::renew_blob_tx(
                    transaction,
                    BlobId::from_bytes([3; 32]),
                    caps.renew,
                    NOW,
                    50,
                )
            },
            |result: Result<u64, BlobRelayError>| match result {
                Ok(_) => vec![0xA0],
                Err(error) => vec![0xE0, error as u8],
            },
        )
        .expect("protocol rejection is still recorded");
    assert_eq!(
        outcome,
        BlobExchange::Respond(vec![0xE0, BlobRelayError::NotFound as u8])
    );
    drop(relay);

    let mut relay = DurableRelay::open(database.path()).expect("database reopens");
    assert_eq!(
        relay
            .blob_replay(CAP, REQUEST_ID)
            .expect("replay lookup succeeds"),
        Some((
            b"renew-unknown".to_vec(),
            vec![0xE0, BlobRelayError::NotFound as u8]
        ))
    );
    // The rejected command left no staging or grant state behind.
    assert!(matches!(
        relay.begin_blob_upload(upload_id, caps, &fixture().2, NOW, 100),
        Ok(BlobWriteOutcome::Stored)
    ));
}

#[test]
fn replay_record_and_effect_commit_atomically() {
    let database = TestDatabase::new();
    let mut relay = DurableRelay::open(database.path()).expect("database opens");
    FAIL_NEXT_COMMIT.with(|flag| flag.set(true));
    let error = begin_exchange(&mut relay, b"request-bytes", 100)
        .expect_err("injected commit failure is returned");
    assert!(error.storage_kind().is_some());
    drop(relay);

    let mut relay = DurableRelay::open(database.path()).expect("database reopens");
    assert_eq!(
        relay.blob_replay(CAP, REQUEST_ID).expect("lookup succeeds"),
        None
    );
    let (upload_id, caps, manifest, ..) = fixture();
    assert!(
        matches!(
            relay.begin_blob_upload(upload_id, caps, &manifest, NOW, 100),
            Ok(BlobWriteOutcome::Stored)
        ),
        "effect rolled back with the replay record"
    );
}

fn assert_database_integrity(relay: &DurableRelay) {
    let result: String = relay
        .connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity check executes");
    assert_eq!(result, "ok");
}

fn run_crashing_child(database: &TestDatabase, action: &str, point: &str) {
    let output = Command::new(std::env::current_exe().expect("test executable is available"))
        .args([
            "--exact",
            "durable_blob::tests::crash_worker",
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

#[test]
fn crash_worker() {
    let Some(path) = std::env::var_os(CRASH_DATABASE_ENV) else {
        return;
    };
    let action = std::env::var(CRASH_ACTION_ENV).expect("crash action is supplied");
    let mut relay = DurableRelay::open(path).expect("crash worker opens database");
    let (upload_id, caps, manifest, ..) = fixture();
    match action.as_str() {
        "begin" => {
            relay
                .begin_blob_upload(upload_id, caps, &manifest, NOW, 100)
                .expect("configured crash point must terminate begin");
        }
        "publish" => {
            let (upload_id, caps, manifest, chunks, blob_id) = fixture();
            relay
                .begin_blob_upload(upload_id, caps, &manifest, NOW, 100)
                .expect("begin commits before the targeted crash point");
            for (index, chunk) in chunks.iter().enumerate() {
                relay
                    .put_blob_chunk(
                        upload_id,
                        caps.upload,
                        u32::try_from(index).expect("index fits"),
                        chunk,
                        NOW,
                    )
                    .expect("chunk commits before the targeted crash point");
            }
            relay
                .commit_blob(upload_id, caps.upload, blob_id, NOW)
                .expect("configured crash point must terminate commit");
        }
        "put" => {
            let (upload_id, caps, manifest, chunks, _) = fixture();
            relay
                .begin_blob_upload(upload_id, caps, &manifest, NOW, 100)
                .expect("begin commits before the targeted crash point");
            relay
                .put_blob_chunk(upload_id, caps.upload, 0, &chunks[0], NOW)
                .expect("configured crash point must terminate put");
        }
        "renew" => {
            let (upload_id, caps, manifest, chunks, blob_id) = fixture();
            relay
                .begin_blob_upload(upload_id, caps, &manifest, NOW, 100)
                .expect("begin commits before the targeted crash point");
            for (index, chunk) in chunks.iter().enumerate() {
                relay
                    .put_blob_chunk(
                        upload_id,
                        caps.upload,
                        u32::try_from(index).expect("index fits"),
                        chunk,
                        NOW,
                    )
                    .expect("chunk commits before the targeted crash point");
            }
            relay
                .commit_blob(upload_id, caps.upload, blob_id, NOW)
                .expect("commit commits before the targeted crash point");
            relay
                .renew_blob(blob_id, caps.renew, NOW, 500)
                .expect("configured crash point must terminate renew");
        }
        "delete" => {
            let (upload_id, caps, manifest, chunks, blob_id) = fixture();
            relay
                .begin_blob_upload(upload_id, caps, &manifest, NOW, 100)
                .expect("begin commits before the targeted crash point");
            for (index, chunk) in chunks.iter().enumerate() {
                relay
                    .put_blob_chunk(
                        upload_id,
                        caps.upload,
                        u32::try_from(index).expect("index fits"),
                        chunk,
                        NOW,
                    )
                    .expect("chunk commits before the targeted crash point");
            }
            relay
                .commit_blob(upload_id, caps.upload, blob_id, NOW)
                .expect("commit commits before the targeted crash point");
            relay
                .delete_blob(blob_id, caps.delete, NOW)
                .expect("configured crash point must terminate delete");
        }
        other => panic!("unknown crash action: {other}"),
    }
    panic!("crash worker passed its configured crash point");
}

#[test]
#[allow(clippy::too_many_lines)]
fn hard_process_crashes_recover_at_every_blob_command_boundary() {
    let begin_before = TestDatabase::new();
    run_crashing_child(&begin_before, "begin", "begin_before_commit");
    let mut recovered = DurableRelay::open(begin_before.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let (upload_id, caps, manifest, ..) = fixture();
    assert!(
        matches!(
            recovered.begin_blob_upload(upload_id, caps, &manifest, NOW, 100),
            Ok(BlobWriteOutcome::Stored)
        ),
        "crash before commit leaves no staged upload behind"
    );

    let begin_after = TestDatabase::new();
    run_crashing_child(&begin_after, "begin", "begin_after_commit");
    let mut recovered = DurableRelay::open(begin_after.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let (upload_id, caps, manifest, ..) = fixture();
    assert!(
        matches!(
            recovered.begin_blob_upload(upload_id, caps, &manifest, NOW, 100),
            Ok(BlobWriteOutcome::Duplicate)
        ),
        "crash after commit durably records the staged upload"
    );

    let publish_before = TestDatabase::new();
    run_crashing_child(&publish_before, "publish", "publish_before_commit");
    let mut recovered = DurableRelay::open(publish_before.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let (_, caps, _, _, blob_id) = fixture();
    assert!(
        matches!(
            recovered.get_blob_manifest(blob_id, caps.download, NOW),
            Err(BlobDurableError::Protocol(BlobRelayError::NotFound))
        ),
        "crash before the publish commit leaves the object unavailable"
    );

    let publish_after = TestDatabase::new();
    run_crashing_child(&publish_after, "publish", "publish_after_commit");
    let mut recovered = DurableRelay::open(publish_after.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let (_, caps, manifest, _, blob_id) = fixture();
    let (stored, _expiry) = recovered
        .get_blob_manifest(blob_id, caps.download, NOW)
        .expect("crash after the publish commit leaves the object available");
    assert_eq!(stored, manifest);

    let put_before = TestDatabase::new();
    run_crashing_child(&put_before, "put", "put_before_commit");
    let mut recovered = DurableRelay::open(put_before.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let (upload_id, caps, _, chunks, _) = fixture();
    assert!(
        matches!(
            recovered.put_blob_chunk(upload_id, caps.upload, 0, &chunks[0], NOW),
            Ok(BlobWriteOutcome::Stored)
        ),
        "crash before commit leaves no stored chunk behind"
    );

    let put_after = TestDatabase::new();
    run_crashing_child(&put_after, "put", "put_after_commit");
    let mut recovered = DurableRelay::open(put_after.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let (upload_id, caps, _, chunks, _) = fixture();
    assert!(
        matches!(
            recovered.put_blob_chunk(upload_id, caps.upload, 0, &chunks[0], NOW),
            Ok(BlobWriteOutcome::Duplicate)
        ),
        "crash after commit durably records the chunk"
    );

    let renew_before = TestDatabase::new();
    run_crashing_child(&renew_before, "renew", "renew_before_commit");
    let mut recovered = DurableRelay::open(renew_before.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let (_, caps, _, _, blob_id) = fixture();
    let (_, expiry) = recovered
        .get_blob_manifest(blob_id, caps.download, NOW)
        .expect("committed object remains available");
    assert_eq!(
        expiry,
        NOW.as_secs() + 100,
        "crash before commit leaves the original expiry untouched"
    );

    let renew_after = TestDatabase::new();
    run_crashing_child(&renew_after, "renew", "renew_after_commit");
    let mut recovered = DurableRelay::open(renew_after.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let (_, caps, _, _, blob_id) = fixture();
    let (_, expiry) = recovered
        .get_blob_manifest(blob_id, caps.download, NOW)
        .expect("committed object remains available");
    assert_eq!(
        expiry,
        NOW.as_secs() + 500,
        "crash after commit durably records the extended expiry"
    );

    let delete_before = TestDatabase::new();
    run_crashing_child(&delete_before, "delete", "delete_before_commit");
    let mut recovered = DurableRelay::open(delete_before.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let (_, caps, _, _, blob_id) = fixture();
    assert!(
        recovered
            .get_blob_manifest(blob_id, caps.download, NOW)
            .is_ok(),
        "crash before commit leaves the grant undeleted"
    );

    let delete_after = TestDatabase::new();
    run_crashing_child(&delete_after, "delete", "delete_after_commit");
    let mut recovered = DurableRelay::open(delete_after.path()).expect("database recovers");
    assert_database_integrity(&recovered);
    let (_, caps, _, _, blob_id) = fixture();
    assert!(
        matches!(
            recovered.get_blob_manifest(blob_id, caps.download, NOW),
            Err(BlobDurableError::Protocol(BlobRelayError::NotFound))
        ),
        "crash after commit durably records the deletion"
    );
}

#[test]
fn blob_storage_faults_roll_back_without_false_success_or_partial_state() {
    let readonly_database = TestDatabase::new();
    let (upload_id, caps, manifest, ..) = fixture();
    let mut readonly = DurableRelay::open(readonly_database.path()).expect("database opens");
    readonly
        .connection
        .pragma_update(None, "query_only", true)
        .expect("query-only mode enabled");
    let error = readonly
        .begin_blob_upload(upload_id, caps, &manifest, NOW, 100)
        .expect_err("read-only write fails");
    assert!(matches!(error, BlobDurableError::Storage(_)));
    readonly
        .connection
        .pragma_update(None, "query_only", false)
        .expect("query-only mode disabled");
    assert_database_integrity(&readonly);
    assert!(matches!(
        readonly.begin_blob_upload(upload_id, caps, &manifest, NOW, 100),
        Ok(BlobWriteOutcome::Stored)
    ));

    let full_database = TestDatabase::new();
    let mut full = DurableRelay::open(full_database.path()).expect("database opens");
    let (upload_id, caps, manifest, ciphertext, _) = large_chunk_fixture();
    full.begin_blob_upload(upload_id, caps, &manifest, NOW, 100)
        .expect("begin commits before the page limit is fixed");
    let page_count: i64 = full
        .connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .expect("page count reads");
    full.connection
        .pragma_update(None, "max_page_count", page_count)
        .expect("page limit fixed at current size");
    let error = full
        .put_blob_chunk(upload_id, caps.upload, 0, &ciphertext, NOW)
        .expect_err("page limit makes the oversized chunk insert fail");
    assert!(matches!(error, BlobDurableError::Storage(_)));
    assert_database_integrity(&full);
    assert!(
        full.put_blob_chunk(upload_id, caps.upload, 0, &ciphertext, NOW)
            .is_err(),
        "still fails consistently rather than leaving partial chunk state"
    );

    let commit_database = TestDatabase::new();
    let mut commit_failure = DurableRelay::open(commit_database.path()).expect("database opens");
    let (upload_id, caps, manifest, ..) = fixture();
    FAIL_NEXT_COMMIT.with(|flag| flag.set(true));
    let error = commit_failure
        .begin_blob_upload(upload_id, caps, &manifest, NOW, 100)
        .expect_err("injected commit failure is returned");
    assert!(matches!(error, BlobDurableError::Storage(_)));
    assert_database_integrity(&commit_failure);
    assert!(
        matches!(
            commit_failure.begin_blob_upload(upload_id, caps, &manifest, NOW, 100),
            Ok(BlobWriteOutcome::Stored)
        ),
        "rolled-back commit leaves no staged upload behind"
    );
}

#[test]
fn v1_databases_migrate_to_the_latest_schema_preserving_blob_state() {
    let database = TestDatabase::new();
    let (upload_id, caps, manifest, chunks, blob_id) = fixture();
    {
        let mut relay = DurableRelay::open(database.path()).expect("database opens");
        assert_eq!(
            relay
                .begin_blob_upload(upload_id, caps, &manifest, NOW, 100)
                .expect("begin commits"),
            BlobWriteOutcome::Stored
        );
        for (index, chunk) in chunks.iter().enumerate() {
            relay
                .put_blob_chunk(
                    upload_id,
                    caps.upload,
                    u32::try_from(index).expect("index fits"),
                    chunk,
                    NOW,
                )
                .expect("chunk commits");
        }
        relay
            .commit_blob(upload_id, caps.upload, blob_id, NOW)
            .expect("commit publishes the object");
    }
    // Downgrade to the version 1 layout: no replay tables, version stamp 1.
    let connection = Connection::open(database.path()).expect("database opens directly");
    connection
        .execute_batch("DROP TABLE blob_replays; DROP TABLE queue_replays;")
        .expect("replay tables drop");
    connection
        .pragma_update(None, "user_version", 1)
        .expect("version downgrades");
    drop(connection);

    // A v1 database jumps straight to the latest schema in one migration,
    // not through each intermediate version.
    let mut relay = DurableRelay::open(database.path()).expect("v1 database migrates");
    let version: i64 = relay
        .connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("version reads");
    assert_eq!(version, 3);
    let (stored, expiry) = relay
        .get_blob_manifest(blob_id, caps.download, NOW)
        .expect("pre-existing blob state survives migration");
    assert_eq!(stored, manifest);
    assert_eq!(expiry, NOW.as_secs() + 100);
    assert_eq!(
        relay.blob_replay(CAP, REQUEST_ID).expect("lookup succeeds"),
        None
    );
}
