//! `SQLite` transactions implementing the blob/1 availability state machine.

use cofferwire_types::blob::{BlobCapabilities, BlobId, BlobManifest, CapabilityId, UploadId};
use cofferwire_types::RequestId;
use rusqlite::{params, ErrorCode, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::durable::commit;
use crate::{DurableRelay, DurableRelayError, Timestamp};

const IDENTITY_DOMAIN: &[u8] = b"cofferwire blob identity v1\0";
type BeginRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type CommitRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
);
type UploadRow = (Vec<u8>, Vec<u8>, u64);

/// Stable protocol failure from durable blob storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobRelayError {
    NotFound,
    Unauthorized,
    IdConflict,
    LimitOutOfRange,
    ChunkConflict,
    Incomplete,
    IdentityMismatch,
    Expired,
}

impl std::fmt::Display for BlobRelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blob relay rejected command: {self:?}")
    }
}
impl std::error::Error for BlobRelayError {}

/// Blob semantics or the underlying durable-storage error.
#[derive(Debug)]
pub enum BlobRelayResult {
    Protocol(BlobRelayError),
    Storage(DurableRelayError),
}
impl From<rusqlite::Error> for BlobRelayResult {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value.into())
    }
}
impl From<BlobRelayError> for BlobRelayResult {
    fn from(value: BlobRelayError) -> Self {
        Self::Protocol(value)
    }
}

/// Outcome of a replay-checked durable blob command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobExchange {
    /// Response bytes to return to the caller, freshly produced or replayed.
    Respond(Vec<u8>),
    /// The request identifier was reused with different request bytes.
    Conflict,
}

/// Stored replay record: exact request bytes and the recorded response bytes.
pub type BlobReplayRecord = (Vec<u8>, Vec<u8>);

impl DurableRelay {
    /// Returns the stored replay record for `(capability, request_id)`.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the lookup cannot be completed.
    pub fn blob_replay(
        &self,
        capability: CapabilityId,
        request_id: RequestId,
    ) -> Result<Option<BlobReplayRecord>, DurableRelayError> {
        self.connection
            .query_row(
                "SELECT request, response FROM blob_replays
                 WHERE capability_id=?1 AND request_id=?2",
                params![
                    capability.as_bytes().as_slice(),
                    request_id.as_bytes().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(DurableRelayError::from)
    }

    /// Runs a blob command and records its replay entry in one transaction.
    ///
    /// `effect` executes the command inside the supplied transaction and
    /// `encode` renders the final response bytes from its outcome. On success
    /// the command effect and the `(capability, request_id)` replay record
    /// commit atomically; on a protocol rejection the effect rolls back and
    /// only the replay record commits. A concurrent duplicate that commits
    /// first resolves to the stored response for an exact retry, or to
    /// [`BlobExchange::Conflict`] for differing request bytes.
    ///
    /// # Errors
    ///
    /// Returns a storage error; protocol rejections are encoded responses.
    pub fn blob_exchange<T>(
        &mut self,
        capability: CapabilityId,
        request_id: RequestId,
        request: &[u8],
        effect: impl FnOnce(&Transaction<'_>) -> Result<T, BlobRelayResult>,
        encode: impl FnOnce(Result<T, BlobRelayError>) -> Vec<u8>,
    ) -> Result<BlobExchange, DurableRelayError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (response, committed_effect) = match effect(&transaction) {
            Ok(value) => (encode(Ok(value)), true),
            Err(BlobRelayResult::Protocol(error)) => (encode(Err(error)), false),
            Err(BlobRelayResult::Storage(error)) => return Err(error),
        };
        // A rejected command rolls back with its transaction; only the replay
        // record for the encoded rejection commits in a fresh transaction.
        let transaction = if committed_effect {
            transaction
        } else {
            drop(transaction);
            self.connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?
        };
        if insert_replay(&transaction, capability, request_id, request, &response)? {
            commit(transaction)?;
            return Ok(BlobExchange::Respond(response));
        }
        drop(transaction);
        match self.blob_replay(capability, request_id)? {
            Some((stored_request, stored_response)) if stored_request == request => {
                Ok(BlobExchange::Respond(stored_response))
            }
            Some(_) => Ok(BlobExchange::Conflict),
            None => Err(DurableRelayError::Storage {
                kind: crate::StorageErrorKind::Other,
                source: rusqlite::Error::InvalidParameterName(
                    "replay insert conflicted without a stored record".to_owned(),
                ),
            }),
        }
    }

    /// Creates staging state or confirms an exact idempotent retry.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for invalid/conflicting state or a storage error.
    pub fn begin_blob_upload(
        &mut self,
        upload_id: UploadId,
        caps: BlobCapabilities,
        manifest: &BlobManifest,
        now: Timestamp,
        ttl: u64,
    ) -> Result<u8, BlobRelayResult> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome =
            Self::begin_blob_upload_tx(&transaction, upload_id, caps, manifest, now, ttl)?;
        commit(transaction)?;
        Ok(outcome)
    }

    /// Transaction-scoped variant of [`Self::begin_blob_upload`].
    ///
    /// # Errors
    ///
    /// Returns a protocol error for invalid/conflicting state or a storage error.
    pub fn begin_blob_upload_tx(
        transaction: &Transaction<'_>,
        upload_id: UploadId,
        caps: BlobCapabilities,
        manifest: &BlobManifest,
        now: Timestamp,
        ttl: u64,
    ) -> Result<u8, BlobRelayResult> {
        let expiry = now
            .as_secs()
            .checked_add(ttl)
            .filter(|_| ttl > 0)
            .ok_or(BlobRelayError::LimitOutOfRange)?;
        let existing: Option<BeginRow> = transaction.query_row(
            "SELECT upload_cap, download_cap, renew_cap, delete_cap, manifest, expires_at FROM blob_uploads WHERE upload_id=?1",
            [upload_id.as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))).optional()?;
        if let Some(existing) = existing {
            let same = existing.0 == caps.upload.as_bytes()
                && existing.1 == caps.download.as_bytes()
                && existing.2 == caps.renew.as_bytes()
                && existing.3 == caps.delete.as_bytes()
                && existing.4 == manifest.as_bytes()
                && existing.5 == expiry.to_be_bytes();
            return if same {
                Ok(1)
            } else {
                Err(BlobRelayError::IdConflict.into())
            };
        }
        transaction.execute("INSERT INTO blob_uploads(upload_id,upload_cap,download_cap,renew_cap,delete_cap,manifest,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![upload_id.as_bytes().as_slice(), caps.upload.as_bytes().as_slice(), caps.download.as_bytes().as_slice(), caps.renew.as_bytes().as_slice(), caps.delete.as_bytes().as_slice(), manifest.as_bytes(), expiry.to_be_bytes().as_slice()])?;
        Ok(0)
    }

    /// Stores one verified chunk and returns 1 for an identical retry.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for authorization, expiry, limit, or digest failures.
    pub fn put_blob_chunk(
        &mut self,
        upload_id: UploadId,
        cap: CapabilityId,
        index: u32,
        ciphertext: &[u8],
        now: Timestamp,
    ) -> Result<u8, BlobRelayResult> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome =
            Self::put_blob_chunk_tx(&transaction, upload_id, cap, index, ciphertext, now)?;
        commit(transaction)?;
        Ok(outcome)
    }

    /// Transaction-scoped variant of [`Self::put_blob_chunk`].
    ///
    /// # Errors
    ///
    /// Returns a protocol error for authorization, expiry, limit, or digest failures.
    pub fn put_blob_chunk_tx(
        transaction: &Transaction<'_>,
        upload_id: UploadId,
        cap: CapabilityId,
        index: u32,
        ciphertext: &[u8],
        now: Timestamp,
    ) -> Result<u8, BlobRelayResult> {
        let (stored_cap, manifest, expiry) =
            upload(transaction, upload_id)?.ok_or(BlobRelayError::NotFound)?;
        if stored_cap != cap.as_bytes() {
            return Err(BlobRelayError::Unauthorized.into());
        }
        if now.as_secs() >= expiry {
            return Err(BlobRelayError::Expired.into());
        }
        let manifest = BlobManifest::parse(manifest).map_err(|_| BlobRelayError::IdConflict)?;
        let digest = manifest
            .digest(index as usize)
            .ok_or(BlobRelayError::LimitOutOfRange)?;
        if ciphertext.len() != manifest.chunk_size() as usize + 16
            || <Sha256 as Digest>::digest(ciphertext).as_slice() != digest
        {
            return Err(BlobRelayError::ChunkConflict.into());
        }
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT ciphertext FROM blob_upload_chunks WHERE upload_id=?1 AND chunk_index=?2",
                params![upload_id.as_bytes().as_slice(), index],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing == ciphertext {
                Ok(1)
            } else {
                Err(BlobRelayError::ChunkConflict.into())
            };
        }
        transaction.execute(
            "INSERT INTO blob_upload_chunks(upload_id,chunk_index,ciphertext) VALUES(?1,?2,?3)",
            params![upload_id.as_bytes().as_slice(), index, ciphertext],
        )?;
        Ok(0)
    }

    /// Atomically publishes a complete immutable object and availability grant.
    ///
    /// # Errors
    ///
    /// Returns a protocol error unless the live upload is complete and identity-valid.
    pub fn commit_blob(
        &mut self,
        upload_id: UploadId,
        cap: CapabilityId,
        requested: BlobId,
        now: Timestamp,
    ) -> Result<u64, BlobRelayResult> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = Self::commit_blob_tx(&transaction, upload_id, cap, requested, now)?;
        commit(transaction)?;
        Ok(outcome)
    }

    /// Transaction-scoped variant of [`Self::commit_blob`].
    ///
    /// # Errors
    ///
    /// Returns a protocol error unless the live upload is complete and identity-valid.
    pub fn commit_blob_tx(
        transaction: &Transaction<'_>,
        upload_id: UploadId,
        cap: CapabilityId,
        requested: BlobId,
        now: Timestamp,
    ) -> Result<u64, BlobRelayResult> {
        let row: Option<CommitRow> = transaction.query_row("SELECT upload_cap,download_cap,renew_cap,delete_cap,manifest,expires_at,committed_blob FROM blob_uploads WHERE upload_id=?1", [upload_id.as_bytes().as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
        let (
            upload_cap,
            download_cap,
            renew_cap,
            delete_cap,
            manifest_bytes,
            expiry_bytes,
            committed,
        ) = row.ok_or(BlobRelayError::NotFound)?;
        if upload_cap != cap.as_bytes() {
            return Err(BlobRelayError::Unauthorized.into());
        }
        let expiry = be_u64(&expiry_bytes)?;
        if now.as_secs() >= expiry {
            return Err(BlobRelayError::Expired.into());
        }
        if let Some(committed) = committed {
            return if committed == requested.as_bytes() {
                Ok(expiry)
            } else {
                Err(BlobRelayError::IdConflict.into())
            };
        }
        let manifest =
            BlobManifest::parse(manifest_bytes).map_err(|_| BlobRelayError::IdConflict)?;
        if identify(&manifest) != requested {
            return Err(BlobRelayError::IdentityMismatch.into());
        }
        let count: u64 = transaction.query_row(
            "SELECT count(*) FROM blob_upload_chunks WHERE upload_id=?1",
            [upload_id.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        if count != manifest.chunk_count() as u64 {
            return Err(BlobRelayError::Incomplete.into());
        }
        for index in 0..manifest.chunk_count() {
            let wire_index = u32::try_from(index).map_err(|_| BlobRelayError::LimitOutOfRange)?;
            let chunk: Vec<u8> = transaction.query_row("SELECT ciphertext FROM blob_upload_chunks WHERE upload_id=?1 AND chunk_index=?2", params![upload_id.as_bytes().as_slice(), wire_index], |r| r.get(0)).map_err(|_| BlobRelayError::Incomplete)?;
            let digest: [u8; 32] = Sha256::digest(&chunk).into();
            if manifest.digest(index) != Some(&digest) {
                return Err(BlobRelayError::ChunkConflict.into());
            }
        }
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT manifest FROM blob_objects WHERE blob_id=?1",
                [requested.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if existing
            .as_deref()
            .is_some_and(|bytes| bytes != manifest.as_bytes())
        {
            return Err(BlobRelayError::IdConflict.into());
        }
        transaction.execute(
            "INSERT OR IGNORE INTO blob_objects(blob_id,manifest) VALUES(?1,?2)",
            params![requested.as_bytes().as_slice(), manifest.as_bytes()],
        )?;
        transaction.execute("INSERT OR IGNORE INTO blob_chunks(blob_id,chunk_index,ciphertext) SELECT ?1,chunk_index,ciphertext FROM blob_upload_chunks WHERE upload_id=?2", params![requested.as_bytes().as_slice(), upload_id.as_bytes().as_slice()])?;
        transaction.execute("INSERT INTO blob_grants(grant_id,blob_id,download_cap,renew_cap,delete_cap,expires_at) VALUES(?1,?2,?3,?4,?5,?6)", params![upload_id.as_bytes().as_slice(), requested.as_bytes().as_slice(), download_cap, renew_cap, delete_cap, expiry_bytes])?;
        transaction.execute(
            "UPDATE blob_uploads SET committed_blob=?1 WHERE upload_id=?2",
            params![
                requested.as_bytes().as_slice(),
                upload_id.as_bytes().as_slice()
            ],
        )?;
        Ok(expiry)
    }

    /// Returns a committed manifest only for a live matching grant.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for unavailable, unauthorized, expired, or corrupt state.
    pub fn get_blob_manifest(
        &mut self,
        id: BlobId,
        cap: CapabilityId,
        now: Timestamp,
    ) -> Result<(BlobManifest, u64), BlobRelayResult> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let outcome = Self::get_blob_manifest_tx(&transaction, id, cap, now)?;
        commit(transaction)?;
        Ok(outcome)
    }

    /// Transaction-scoped variant of [`Self::get_blob_manifest`].
    ///
    /// # Errors
    ///
    /// Returns a protocol error for unavailable, unauthorized, expired, or corrupt state.
    pub fn get_blob_manifest_tx(
        transaction: &Transaction<'_>,
        id: BlobId,
        cap: CapabilityId,
        now: Timestamp,
    ) -> Result<(BlobManifest, u64), BlobRelayResult> {
        let expiry = authorize_grant(transaction, id, "download_cap", cap, now)?;
        let bytes: Vec<u8> = transaction.query_row(
            "SELECT manifest FROM blob_objects WHERE blob_id=?1",
            [id.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        let manifest = BlobManifest::parse(bytes).map_err(|_| BlobRelayError::IdConflict)?;
        if identify(&manifest) != id {
            return Err(BlobRelayError::IdentityMismatch.into());
        }
        Ok((manifest, expiry))
    }

    /// Returns one committed digest-verified ciphertext chunk.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for unavailable, unauthorized, expired, or corrupt state.
    pub fn get_blob_chunk(
        &mut self,
        id: BlobId,
        cap: CapabilityId,
        index: u32,
        now: Timestamp,
    ) -> Result<(Vec<u8>, u64), BlobRelayResult> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let outcome = Self::get_blob_chunk_tx(&transaction, id, cap, index, now)?;
        commit(transaction)?;
        Ok(outcome)
    }

    /// Transaction-scoped variant of [`Self::get_blob_chunk`].
    ///
    /// # Errors
    ///
    /// Returns a protocol error for unavailable, unauthorized, expired, or corrupt state.
    pub fn get_blob_chunk_tx(
        transaction: &Transaction<'_>,
        id: BlobId,
        cap: CapabilityId,
        index: u32,
        now: Timestamp,
    ) -> Result<(Vec<u8>, u64), BlobRelayResult> {
        let expiry = authorize_grant(transaction, id, "download_cap", cap, now)?;
        let manifest_bytes: Vec<u8> = transaction.query_row(
            "SELECT manifest FROM blob_objects WHERE blob_id=?1",
            [id.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        let manifest =
            BlobManifest::parse(manifest_bytes).map_err(|_| BlobRelayError::IdConflict)?;
        let expected = manifest
            .digest(index as usize)
            .ok_or(BlobRelayError::LimitOutOfRange)?;
        let chunk: Vec<u8> = transaction
            .query_row(
                "SELECT ciphertext FROM blob_chunks WHERE blob_id=?1 AND chunk_index=?2",
                params![id.as_bytes().as_slice(), index],
                |r| r.get(0),
            )
            .map_err(|_| BlobRelayError::NotFound)?;
        let digest: [u8; 32] = Sha256::digest(&chunk).into();
        if &digest != expected {
            return Err(BlobRelayError::ChunkConflict.into());
        }
        Ok((chunk, expiry))
    }

    /// Extends but never shortens a live grant.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for invalid TTL, authorization, or expiry.
    pub fn renew_blob(
        &mut self,
        id: BlobId,
        cap: CapabilityId,
        now: Timestamp,
        ttl: u64,
    ) -> Result<u64, BlobRelayResult> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = Self::renew_blob_tx(&transaction, id, cap, now, ttl)?;
        commit(transaction)?;
        Ok(outcome)
    }

    /// Transaction-scoped variant of [`Self::renew_blob`].
    ///
    /// # Errors
    ///
    /// Returns a protocol error for invalid TTL, authorization, or expiry.
    pub fn renew_blob_tx(
        transaction: &Transaction<'_>,
        id: BlobId,
        cap: CapabilityId,
        now: Timestamp,
        ttl: u64,
    ) -> Result<u64, BlobRelayResult> {
        let requested = now
            .as_secs()
            .checked_add(ttl)
            .filter(|_| ttl > 0)
            .ok_or(BlobRelayError::LimitOutOfRange)?;
        let current = authorize_grant(transaction, id, "renew_cap", cap, now)?;
        let expiry = current.max(requested);
        transaction.execute(
            "UPDATE blob_grants SET expires_at=?1 WHERE blob_id=?2 AND renew_cap=?3 AND deleted=0",
            params![
                expiry.to_be_bytes().as_slice(),
                id.as_bytes().as_slice(),
                cap.as_bytes().as_slice()
            ],
        )?;
        Ok(expiry)
    }

    /// Atomically marks exactly one matching grant unavailable.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for unavailable, unauthorized, or expired state.
    pub fn delete_blob(
        &mut self,
        id: BlobId,
        cap: CapabilityId,
        now: Timestamp,
    ) -> Result<(), BlobRelayResult> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::delete_blob_tx(&transaction, id, cap, now)?;
        commit(transaction)?;
        Ok(())
    }

    /// Transaction-scoped variant of [`Self::delete_blob`].
    ///
    /// # Errors
    ///
    /// Returns a protocol error for unavailable, unauthorized, or expired state.
    pub fn delete_blob_tx(
        transaction: &Transaction<'_>,
        id: BlobId,
        cap: CapabilityId,
        now: Timestamp,
    ) -> Result<(), BlobRelayResult> {
        authorize_grant(transaction, id, "delete_cap", cap, now)?;
        transaction.execute(
            "UPDATE blob_grants SET deleted=1 WHERE blob_id=?1 AND delete_cap=?2",
            params![id.as_bytes().as_slice(), cap.as_bytes().as_slice()],
        )?;
        Ok(())
    }
}

/// Inserts the replay record, returning `false` when the primary key already
/// exists (a concurrent duplicate committed first).
fn insert_replay(
    transaction: &Transaction<'_>,
    capability: CapabilityId,
    request_id: RequestId,
    request: &[u8],
    response: &[u8],
) -> Result<bool, DurableRelayError> {
    match transaction.execute(
        "INSERT INTO blob_replays(capability_id,request_id,request,response) VALUES(?1,?2,?3,?4)",
        params![
            capability.as_bytes().as_slice(),
            request_id.as_bytes().as_slice(),
            request,
            response
        ],
    ) {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::SqliteFailure(failure, _))
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

fn upload(tx: &Transaction<'_>, id: UploadId) -> Result<Option<UploadRow>, BlobRelayResult> {
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT upload_cap,manifest,expires_at FROM blob_uploads WHERE upload_id=?1",
            [id.as_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    row.map(|(cap, manifest, expiry)| Ok((cap, manifest, be_u64(&expiry)?)))
        .transpose()
}

fn authorize_grant(
    tx: &Transaction<'_>,
    id: BlobId,
    column: &str,
    cap: CapabilityId,
    now: Timestamp,
) -> Result<u64, BlobRelayResult> {
    let query =
        format!("SELECT expires_at,deleted FROM blob_grants WHERE blob_id=?1 AND {column}=?2");
    let exact: Option<(Vec<u8>, bool)> = tx
        .query_row(
            &query,
            params![id.as_bytes().as_slice(), cap.as_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((expiry, deleted)) = exact else {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM blob_grants WHERE blob_id=?1)",
            [id.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        return Err(if exists {
            BlobRelayError::Unauthorized
        } else {
            BlobRelayError::NotFound
        }
        .into());
    };
    if deleted {
        return Err(BlobRelayError::NotFound.into());
    }
    let expiry = be_u64(&expiry)?;
    if now.as_secs() >= expiry {
        return Err(BlobRelayError::Expired.into());
    }
    Ok(expiry)
}

fn be_u64(bytes: &[u8]) -> Result<u64, BlobRelayResult> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| BlobRelayError::IdConflict)?;
    Ok(u64::from_be_bytes(bytes))
}
fn identify(manifest: &BlobManifest) -> BlobId {
    let mut hash = Sha256::new();
    hash.update(IDENTITY_DOMAIN);
    hash.update(manifest.as_bytes());
    BlobId::from_bytes(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rusqlite::Connection;

    use super::*;
    use crate::durable::FAIL_NEXT_COMMIT;

    const NOW: Timestamp = Timestamp::from_secs(1_000);
    const CAP: CapabilityId = CapabilityId::from_bytes([7; 32]);
    const REQUEST_ID: RequestId = RequestId::from_bytes([9; 16]);

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

    fn replay_response(result: Result<u8, BlobRelayError>) -> Vec<u8> {
        match result {
            Ok(outcome) => vec![0xA0, outcome],
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
                DurableRelay::begin_blob_upload_tx(
                    transaction,
                    upload_id,
                    caps,
                    &manifest,
                    NOW,
                    ttl,
                )
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
            Ok(0)
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
                Ok(0)
            ),
            "effect rolled back with the replay record"
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
                0
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
}
