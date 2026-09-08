//! `SQLite` transactions implementing the blob/1 availability state machine.

use cofferwire_types::blob::{
    BlobCapabilities, BlobId, BlobManifest, BlobRequest, BlobResponseBody, BlobWriteOutcome,
    CapabilityId, UploadId,
};
use cofferwire_types::RequestId;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::durable::commit;
use crate::replay::{self, EffectError, Namespace};
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
pub enum BlobDurableError {
    Protocol(BlobRelayError),
    Storage(DurableRelayError),
}
impl std::fmt::Display for BlobDurableError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(formatter),
            Self::Storage(error) => error.fmt(formatter),
        }
    }
}
impl std::error::Error for BlobDurableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Storage(error) => Some(error),
        }
    }
}
impl From<rusqlite::Error> for BlobDurableError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value.into())
    }
}
impl From<BlobRelayError> for BlobDurableError {
    fn from(value: BlobRelayError) -> Self {
        Self::Protocol(value)
    }
}

/// Blob-profile name for the shared replay outcome.
pub type BlobExchange = crate::ReplayExchange;

/// Stored replay record: exact request bytes and the recorded response bytes.
pub type BlobReplayRecord = crate::ReplayRecord;

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
        replay::lookup(
            &self.connection,
            Namespace::Blob,
            capability.as_bytes(),
            request_id,
        )
    }

    /// Executes one decoded blob request and records its exact replay response.
    ///
    /// Network adapters provide semantic protocol values and response encoding
    /// without receiving a `SQLite` transaction.
    ///
    /// # Errors
    ///
    /// Returns a storage error; protocol rejections are encoded responses.
    pub fn blob_request_exchange(
        &mut self,
        capability: CapabilityId,
        request_id: RequestId,
        request_bytes: &[u8],
        request: &BlobRequest,
        now: Timestamp,
        encode: impl FnOnce(Result<BlobResponseBody, BlobRelayError>) -> Vec<u8>,
    ) -> Result<BlobExchange, DurableRelayError> {
        self.blob_exchange(
            capability,
            request_id,
            request_bytes,
            |transaction| execute_blob_request(transaction, request, now),
            encode,
        )
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
        effect: impl FnOnce(&Transaction<'_>) -> Result<T, BlobDurableError>,
        encode: impl FnOnce(Result<T, BlobRelayError>) -> Vec<u8>,
    ) -> Result<BlobExchange, DurableRelayError> {
        replay::exchange(
            &mut self.connection,
            Namespace::Blob,
            capability.as_bytes(),
            request_id,
            request,
            |transaction| match effect(transaction) {
                Ok(value) => Ok(value),
                Err(BlobDurableError::Protocol(error)) => Err(EffectError::Protocol(error)),
                Err(BlobDurableError::Storage(error)) => Err(EffectError::Storage(error)),
            },
            encode,
        )
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
    ) -> Result<BlobWriteOutcome, BlobDurableError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome =
            Self::begin_blob_upload_tx(&transaction, upload_id, caps, manifest, now, ttl)?;
        #[cfg(test)]
        crate::durable::crash_point("begin_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crate::durable::crash_point("begin_after_commit");
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
    ) -> Result<BlobWriteOutcome, BlobDurableError> {
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
                Ok(BlobWriteOutcome::Duplicate)
            } else {
                Err(BlobRelayError::IdConflict.into())
            };
        }
        transaction.execute("INSERT INTO blob_uploads(upload_id,upload_cap,download_cap,renew_cap,delete_cap,manifest,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![upload_id.as_bytes().as_slice(), caps.upload.as_bytes().as_slice(), caps.download.as_bytes().as_slice(), caps.renew.as_bytes().as_slice(), caps.delete.as_bytes().as_slice(), manifest.as_bytes(), expiry.to_be_bytes().as_slice()])?;
        Ok(BlobWriteOutcome::Stored)
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
    ) -> Result<BlobWriteOutcome, BlobDurableError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome =
            Self::put_blob_chunk_tx(&transaction, upload_id, cap, index, ciphertext, now)?;
        #[cfg(test)]
        crate::durable::crash_point("put_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crate::durable::crash_point("put_after_commit");
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
    ) -> Result<BlobWriteOutcome, BlobDurableError> {
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
                Ok(BlobWriteOutcome::Duplicate)
            } else {
                Err(BlobRelayError::ChunkConflict.into())
            };
        }
        transaction.execute(
            "INSERT INTO blob_upload_chunks(upload_id,chunk_index,ciphertext) VALUES(?1,?2,?3)",
            params![upload_id.as_bytes().as_slice(), index, ciphertext],
        )?;
        Ok(BlobWriteOutcome::Stored)
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
    ) -> Result<u64, BlobDurableError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = Self::commit_blob_tx(&transaction, upload_id, cap, requested, now)?;
        #[cfg(test)]
        crate::durable::crash_point("publish_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crate::durable::crash_point("publish_after_commit");
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
    ) -> Result<u64, BlobDurableError> {
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
    ) -> Result<(BlobManifest, u64), BlobDurableError> {
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
    ) -> Result<(BlobManifest, u64), BlobDurableError> {
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
    ) -> Result<(Vec<u8>, u64), BlobDurableError> {
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
    ) -> Result<(Vec<u8>, u64), BlobDurableError> {
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
    ) -> Result<u64, BlobDurableError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = Self::renew_blob_tx(&transaction, id, cap, now, ttl)?;
        #[cfg(test)]
        crate::durable::crash_point("renew_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crate::durable::crash_point("renew_after_commit");
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
    ) -> Result<u64, BlobDurableError> {
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
    ) -> Result<(), BlobDurableError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::delete_blob_tx(&transaction, id, cap, now)?;
        #[cfg(test)]
        crate::durable::crash_point("delete_before_commit");
        commit(transaction)?;
        #[cfg(test)]
        crate::durable::crash_point("delete_after_commit");
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
    ) -> Result<(), BlobDurableError> {
        authorize_grant(transaction, id, "delete_cap", cap, now)?;
        transaction.execute(
            "UPDATE blob_grants SET deleted=1 WHERE blob_id=?1 AND delete_cap=?2",
            params![id.as_bytes().as_slice(), cap.as_bytes().as_slice()],
        )?;
        Ok(())
    }
}

fn execute_blob_request(
    transaction: &Transaction<'_>,
    request: &BlobRequest,
    now: Timestamp,
) -> Result<BlobResponseBody, BlobDurableError> {
    match request {
        BlobRequest::BeginUpload {
            upload_id,
            capabilities,
            manifest,
            ttl,
        } => DurableRelay::begin_blob_upload_tx(
            transaction,
            *upload_id,
            *capabilities,
            manifest,
            now,
            *ttl,
        )
        .map(BlobResponseBody::BeginUpload),
        BlobRequest::PutChunk {
            upload_id,
            upload_cap,
            index,
            ciphertext,
        } => DurableRelay::put_blob_chunk_tx(
            transaction,
            *upload_id,
            *upload_cap,
            *index,
            ciphertext,
            now,
        )
        .map(BlobResponseBody::PutChunk),
        BlobRequest::Commit {
            upload_id,
            upload_cap,
            blob_id,
        } => DurableRelay::commit_blob_tx(transaction, *upload_id, *upload_cap, *blob_id, now)
            .map(BlobResponseBody::Commit),
        BlobRequest::GetManifest {
            blob_id,
            download_cap,
        } => DurableRelay::get_blob_manifest_tx(transaction, *blob_id, *download_cap, now)
            .map(|(manifest, expiry)| BlobResponseBody::GetManifest(manifest, expiry)),
        BlobRequest::GetChunk {
            blob_id,
            download_cap,
            index,
        } => DurableRelay::get_blob_chunk_tx(transaction, *blob_id, *download_cap, *index, now)
            .map(|(chunk, expiry)| BlobResponseBody::GetChunk(chunk, expiry)),
        BlobRequest::Renew {
            blob_id,
            renew_cap,
            ttl,
        } => DurableRelay::renew_blob_tx(transaction, *blob_id, *renew_cap, now, *ttl)
            .map(BlobResponseBody::Renew),
        BlobRequest::Delete {
            blob_id,
            delete_cap,
        } => DurableRelay::delete_blob_tx(transaction, *blob_id, *delete_cap, now)
            .map(|()| BlobResponseBody::Delete),
    }
}

fn upload(tx: &Transaction<'_>, id: UploadId) -> Result<Option<UploadRow>, BlobDurableError> {
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
) -> Result<u64, BlobDurableError> {
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

fn be_u64(bytes: &[u8]) -> Result<u64, BlobDurableError> {
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
mod tests;
