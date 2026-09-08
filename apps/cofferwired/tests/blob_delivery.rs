use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cofferwire_client::blob::{
    download_blob, BlobUploadIdentity, BlobUploadStore, BlobUploader, PreparedBlob, UploadProgress,
};
use cofferwire_client::{RequestIdSource, StoreError, Transport, TransportError};
use cofferwire_types::RequestId;
use cofferwired::RelayService;
use rand_core::OsRng;

static NEXT_DB: AtomicU64 = AtomicU64::new(0);

struct Database(PathBuf);
impl Database {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "cofferwire-blob-e2e-{}-{}.sqlite3",
            std::process::id(),
            NEXT_DB.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

struct Ids(u128);
impl RequestIdSource for Ids {
    fn next_request_id(&mut self) -> RequestId {
        self.0 += 1;
        RequestId::from_bytes(self.0.to_be_bytes())
    }
}

#[derive(Default)]
struct UploadStore(Vec<u8>);

impl BlobUploadStore for UploadStore {
    fn commit(&mut self, state: &[u8]) -> Result<(), StoreError> {
        self.0 = state.to_vec();
        Ok(())
    }
}

struct FailingStore;

impl BlobUploadStore for FailingStore {
    fn commit(&mut self, _state: &[u8]) -> Result<(), StoreError> {
        Err(StoreError)
    }
}

struct RejectUnexpectedTransport;

impl Transport for RejectUnexpectedTransport {
    fn exchange(&mut self, _request: &[u8]) -> Result<Vec<u8>, TransportError> {
        panic!("transport must not run before durable upload-state commit")
    }
}

#[test]
fn upload_state_is_validated_and_committed_before_transport() {
    let prepared = PreparedBlob::new(b"snapshot", 64, &mut OsRng).expect("blob is prepared");
    let identity = prepared.upload_identity();
    assert_eq!(
        BlobUploadIdentity::from_bytes(identity.to_bytes()),
        identity,
        "non-secret identity survives independent persistence"
    );
    let mut uploader = prepared.uploader(3_600);
    let snapshot = uploader.to_bytes();
    BlobUploader::restore(&snapshot, identity).expect("valid state restores");

    let mut tampered = snapshot.clone();
    // The object key starts after magic, version, and upload ID. Changing it
    // makes authenticated chunk opening fail without exposing key bytes.
    tampered[37] ^= 1;
    assert_eq!(
        BlobUploader::restore(&tampered, identity).err(),
        Some(cofferwire_client::blob::BlobClientError::InvalidPersistedState)
    );
    assert_eq!(
        BlobUploader::restore(&snapshot[..snapshot.len() - 1], identity).err(),
        Some(cofferwire_client::blob::BlobClientError::InvalidPersistedState)
    );
    let other_identity = PreparedBlob::new(b"other", 64, &mut OsRng)
        .expect("second blob is prepared")
        .upload_identity();
    assert_eq!(
        BlobUploader::restore(&snapshot, other_identity).err(),
        Some(cofferwire_client::blob::BlobClientError::InvalidPersistedState)
    );
    let mut unsupported = snapshot.clone();
    unsupported[4] = unsupported[4].wrapping_add(1);
    assert_eq!(
        BlobUploader::restore(&unsupported, identity).err(),
        Some(cofferwire_client::blob::BlobClientError::InvalidPersistedState)
    );

    let mut ids = Ids(0);
    let mut transport = RejectUnexpectedTransport;
    assert_eq!(
        uploader.advance(&mut transport, &mut ids, &mut FailingStore),
        Err(cofferwire_client::blob::BlobClientError::Store)
    );
}

#[test]
fn every_ambiguous_upload_stage_survives_a_client_restart() {
    let database = Database::new();
    let prepared = PreparedBlob::new(b"one chunk", 64, &mut OsRng).expect("blob is prepared");
    let identity = prepared.upload_identity();
    let mut uploader = prepared.uploader(3_600);
    let mut store = UploadStore::default();
    let mut ids = Ids(0);
    let mut transport = RestartingTransport {
        path: database.path(),
        now: 10_000,
        lose_response_once: false,
    };

    for expected in [
        UploadProgress::Begun,
        UploadProgress::ChunkStored(0),
        UploadProgress::Committed(13_600),
    ] {
        transport.lose_response_once = true;
        assert_eq!(
            uploader.advance(&mut transport, &mut ids, &mut store),
            Err(cofferwire_client::blob::BlobClientError::Transport)
        );
        uploader = BlobUploader::restore(&store.0, identity).expect("upload state restores");
        assert_eq!(
            uploader.advance(&mut transport, &mut ids, &mut store),
            Ok(expected)
        );
    }
    assert_eq!(
        uploader.advance(&mut transport, &mut ids, &mut store),
        Ok(UploadProgress::Complete)
    );
}

struct RestartingTransport<'a> {
    path: &'a Path,
    now: u64,
    lose_response_once: bool,
}
impl Transport for RestartingTransport<'_> {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        // Every exchange opens a new daemon/service instance, exercising process-level
        // SQLite recovery rather than relying on in-memory state.
        let service = RelayService::open(self.path).map_err(|_| TransportError)?;
        let response = service
            .exchange_blob_frame_at(request, self.now)
            .map_err(|_| TransportError)?;
        if self.lose_response_once {
            self.lose_response_once = false;
            return Err(TransportError);
        }
        Ok(response)
    }
}

#[test]
fn large_blob_resumes_after_ambiguous_chunk_and_process_restarts() {
    let database = Database::new();
    let plaintext: Vec<u8> = (0_u32..2_500_000)
        .map(|index| u8::try_from(index % 251).expect("modulo fits u8"))
        .collect();
    let prepared =
        PreparedBlob::new(&plaintext, 65_536, &mut OsRng).expect("large blob is prepared");
    let identity = prepared.upload_identity();
    let mut uploader = prepared.uploader(3_600);
    let mut store = UploadStore::default();
    let mut ids = Ids(0);
    let mut transport = RestartingTransport {
        path: database.path(),
        now: 10_000,
        lose_response_once: false,
    };

    assert_eq!(
        uploader.advance(&mut transport, &mut ids, &mut store),
        Ok(UploadProgress::Begun)
    );
    assert_eq!(
        uploader.advance(&mut transport, &mut ids, &mut store),
        Ok(UploadProgress::ChunkStored(0))
    );
    transport.lose_response_once = true;
    assert_eq!(
        uploader.advance(&mut transport, &mut ids, &mut store),
        Err(cofferwire_client::blob::BlobClientError::Transport)
    );
    // Simulate a client process restart. The recovered state retains the
    // ambiguous request byte-for-byte rather than merely the chunk index.
    let mut uploader = BlobUploader::restore(&store.0, identity).expect("upload state restores");
    assert_eq!(
        uploader.advance(&mut transport, &mut ids, &mut store),
        Ok(UploadProgress::ChunkStored(1))
    );
    loop {
        if matches!(
            uploader
                .advance(&mut transport, &mut ids, &mut store)
                .expect("upload resumes"),
            UploadProgress::Committed(_)
        ) {
            break;
        }
    }
    let restored =
        download_blob(&prepared, &mut transport, &mut ids).expect("complete object verifies");
    assert_eq!(restored, plaintext);
}
