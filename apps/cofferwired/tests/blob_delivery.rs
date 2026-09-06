use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cofferwire_client::blob::{download_blob, PreparedBlob, UploadProgress};
use cofferwire_client::{RequestIdSource, Transport, TransportError};
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
    let mut uploader = prepared.uploader(3_600);
    let mut ids = Ids(0);
    let mut transport = RestartingTransport {
        path: database.path(),
        now: 10_000,
        lose_response_once: false,
    };

    assert_eq!(
        uploader.advance(&mut transport, &mut ids),
        Ok(UploadProgress::Begun)
    );
    assert_eq!(
        uploader.advance(&mut transport, &mut ids),
        Ok(UploadProgress::ChunkStored(0))
    );
    transport.lose_response_once = true;
    assert_eq!(
        uploader.advance(&mut transport, &mut ids),
        Err(cofferwire_client::blob::BlobClientError::Transport)
    );
    // The retry uses the state machine's retained byte-for-byte request.
    assert_eq!(
        uploader.advance(&mut transport, &mut ids),
        Ok(UploadProgress::ChunkStored(1))
    );
    loop {
        if matches!(
            uploader
                .advance(&mut transport, &mut ids)
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
