//! Transport-independent resumable blob upload and fail-closed download.

use cofferwire_codec::blob::{
    decode_blob_request, decode_blob_response, encode_blob_authenticated_request,
    encode_blob_request,
};
use cofferwire_crypto::blob::{
    identify, open_blob, seal_blob, verify_blob_request, BlobCryptoError, BlobSigningKey,
    EncryptedBlob, ObjectKey,
};
use cofferwire_types::blob::{
    BlobCapabilities, BlobCommand, BlobId, BlobManifest, BlobRequest, BlobRequestFrame,
    BlobResponseBody, BlobStatus, CapabilityId, UploadId, MAX_BLOB_FRAME_BYTES, MAX_CHUNKS,
};
use cofferwire_types::RequestId;
use rand_core::{CryptoRng, RngCore};

use crate::{RequestIdSource, Transport, TransportError};

const UPLOAD_STATE_MAGIC: [u8; 4] = *b"CWBU";
const UPLOAD_STATE_VERSION: u8 = 1;

/// Blob client failure without secret-bearing diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobClientError {
    Transport,
    Store,
    Crypto,
    InvalidResponse,
    InvalidPersistedState,
    Relay(BlobStatus),
}
impl From<TransportError> for BlobClientError {
    fn from(_: TransportError) -> Self {
        Self::Transport
    }
}
impl From<BlobCryptoError> for BlobClientError {
    fn from(_: BlobCryptoError) -> Self {
        Self::Crypto
    }
}

/// Durable boundary for secret-bearing blob upload state.
///
/// The supplied bytes contain object and capability key material. Store
/// implementations must protect them as secrets and return success only after
/// the exact state survives a process crash.
pub trait BlobUploadStore {
    /// Atomically replaces the previously stored state.
    ///
    /// # Errors
    ///
    /// Returns an error unless the bytes are durably committed.
    fn commit(&mut self, state: &[u8]) -> Result<(), crate::StoreError>;
}

/// Non-secret identity used to reject replacement of persisted upload state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobUploadIdentity {
    upload_id: UploadId,
    blob_id: BlobId,
    capabilities: BlobCapabilities,
}

impl BlobUploadIdentity {
    /// Fixed size of the canonical identity encoding.
    pub const ENCODED_LEN: usize = 32 * 6;

    /// Returns the upload identifier.
    #[must_use]
    pub const fn upload_id(&self) -> UploadId {
        self.upload_id
    }

    /// Returns the immutable ciphertext identity.
    #[must_use]
    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    /// Returns the four public operation capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> BlobCapabilities {
        self.capabilities
    }

    /// Encodes this non-secret identity for independent persistence.
    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0; Self::ENCODED_LEN];
        for (index, value) in [
            self.upload_id.as_bytes(),
            self.blob_id.as_bytes(),
            self.capabilities.upload.as_bytes(),
            self.capabilities.download.as_bytes(),
            self.capabilities.renew.as_bytes(),
            self.capabilities.delete.as_bytes(),
        ]
        .into_iter()
        .enumerate()
        {
            let offset = index * 32;
            bytes[offset..offset + 32].copy_from_slice(value);
        }
        bytes
    }

    /// Restores the canonical non-secret identity encoding.
    #[must_use]
    pub fn from_bytes(bytes: [u8; Self::ENCODED_LEN]) -> Self {
        let field = |index: usize| {
            let mut value = [0; 32];
            let offset = index * 32;
            value.copy_from_slice(&bytes[offset..offset + 32]);
            value
        };
        Self {
            upload_id: UploadId::from_bytes(field(0)),
            blob_id: BlobId::from_bytes(field(1)),
            capabilities: BlobCapabilities {
                upload: CapabilityId::from_bytes(field(2)),
                download: CapabilityId::from_bytes(field(3)),
                renew: CapabilityId::from_bytes(field(4)),
                delete: CapabilityId::from_bytes(field(5)),
            },
        }
    }
}

/// All private material needed to upload and later retrieve one encrypted object.
#[derive(Clone)]
pub struct PreparedBlob {
    upload_id: UploadId,
    encrypted: EncryptedBlob,
    upload_key: BlobSigningKey,
    download_key: BlobSigningKey,
    renew_key: BlobSigningKey,
    delete_key: BlobSigningKey,
}

impl PreparedBlob {
    /// Produces a new independently keyed, padded encrypted blob.
    ///
    /// # Errors
    ///
    /// Rejects invalid chunk sizing or plaintext beyond the profile maximum.
    pub fn new<R: CryptoRng + RngCore>(
        plaintext: &[u8],
        chunk_size: u32,
        rng: &mut R,
    ) -> Result<Self, BlobClientError> {
        let encrypted = seal_blob(plaintext, chunk_size, rng)?;
        let mut upload_id = [0; 32];
        rng.fill_bytes(&mut upload_id);
        Ok(Self {
            upload_id: UploadId::from_bytes(upload_id),
            encrypted,
            upload_key: BlobSigningKey::generate(rng),
            download_key: BlobSigningKey::generate(rng),
            renew_key: BlobSigningKey::generate(rng),
            delete_key: BlobSigningKey::generate(rng),
        })
    }
    /// Blob identity safe to place in an end-to-end protected descriptor.
    #[must_use]
    pub const fn blob_id(&self) -> BlobId {
        self.encrypted.blob_id
    }
    /// Download capability safe to share only with intended consumers.
    #[must_use]
    pub fn download_capability(&self) -> CapabilityId {
        self.download_key.capability()
    }
    /// Returns the non-secret identity that must be retained independently
    /// when restoring secret-bearing upload state.
    #[must_use]
    pub fn upload_identity(&self) -> BlobUploadIdentity {
        BlobUploadIdentity {
            upload_id: self.upload_id,
            blob_id: self.encrypted.blob_id,
            capabilities: BlobCapabilities {
                upload: self.upload_key.capability(),
                download: self.download_key.capability(),
                renew: self.renew_key.capability(),
                delete: self.delete_key.capability(),
            },
        }
    }
    /// Constructs a resumable state machine. Persist this value before sending.
    #[must_use]
    pub fn uploader(&self, ttl: u64) -> BlobUploader {
        BlobUploader {
            blob: self.clone(),
            ttl,
            stage: UploadStage::Begin,
            pending: None,
        }
    }
}

impl std::fmt::Debug for PreparedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedBlob")
            .field("upload_id", &self.upload_id)
            .field("blob_id", &self.encrypted.blob_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UploadStage {
    Begin,
    Chunk(usize),
    Commit,
    Complete,
}

#[derive(Debug)]
struct Pending {
    request_id: RequestId,
    command: BlobCommand,
    bytes: Vec<u8>,
}

/// Result of one upload transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadProgress {
    Begun,
    ChunkStored(usize),
    Committed(u64),
    Complete,
}

/// Upload state that retains an ambiguous frame byte-for-byte for exact retry.
pub struct BlobUploader {
    blob: PreparedBlob,
    ttl: u64,
    stage: UploadStage,
    pending: Option<Pending>,
}

impl BlobUploader {
    /// Returns a complete secret-bearing snapshot for protected persistence.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_upload_state(self)
    }

    /// Restores and validates a persisted upload state.
    ///
    /// # Errors
    ///
    /// Rejects malformed state, inconsistent identifiers, corrupt encrypted
    /// object material, and pending frames not signed by the stored capability.
    pub fn restore(bytes: &[u8], expected: BlobUploadIdentity) -> Result<Self, BlobClientError> {
        let uploader = decode_upload_state(bytes)?;
        if uploader.blob.upload_identity() != expected {
            return Err(BlobClientError::InvalidPersistedState);
        }
        Ok(uploader)
    }

    /// Returns the immutable prepared object associated with this upload.
    #[must_use]
    pub const fn prepared_blob(&self) -> &PreparedBlob {
        &self.blob
    }

    /// Advances one durably recorded operation.
    ///
    /// # Errors
    ///
    /// Returns store, transport, codec, correlation, relay-status, or
    /// response-shape failures.
    pub fn advance<T: Transport, I: RequestIdSource, S: BlobUploadStore>(
        &mut self,
        transport: &mut T,
        ids: &mut I,
        store: &mut S,
    ) -> Result<UploadProgress, BlobClientError> {
        if self.stage == UploadStage::Complete {
            return Ok(UploadProgress::Complete);
        }
        if self.pending.is_none() {
            let (request, key) = match self.stage {
                UploadStage::Begin => (
                    BlobRequest::BeginUpload {
                        upload_id: self.blob.upload_id,
                        capabilities: BlobCapabilities {
                            upload: self.blob.upload_key.capability(),
                            download: self.blob.download_key.capability(),
                            renew: self.blob.renew_key.capability(),
                            delete: self.blob.delete_key.capability(),
                        },
                        manifest: self.blob.encrypted.manifest.clone(),
                        ttl: self.ttl,
                    },
                    &self.blob.upload_key,
                ),
                UploadStage::Chunk(index) => (
                    BlobRequest::PutChunk {
                        upload_id: self.blob.upload_id,
                        upload_cap: self.blob.upload_key.capability(),
                        index: u32::try_from(index)
                            .map_err(|_| BlobClientError::InvalidResponse)?,
                        ciphertext: self.blob.encrypted.chunks[index].clone(),
                    },
                    &self.blob.upload_key,
                ),
                UploadStage::Commit => (
                    BlobRequest::Commit {
                        upload_id: self.blob.upload_id,
                        upload_cap: self.blob.upload_key.capability(),
                        blob_id: self.blob.encrypted.blob_id,
                    },
                    &self.blob.upload_key,
                ),
                UploadStage::Complete => unreachable!(),
            };
            let request_id = ids.next_request_id();
            let command = request.command();
            self.pending = Some(Pending {
                request_id,
                command,
                bytes: signed(key, request_id, request),
            });
        }
        store
            .commit(&self.to_bytes())
            .map_err(|_| BlobClientError::Store)?;
        let pending = self
            .pending
            .as_ref()
            .ok_or(BlobClientError::InvalidResponse)?;
        let response_bytes = transport.exchange(&pending.bytes)?;
        let response =
            decode_blob_response(&response_bytes).map_err(|_| BlobClientError::InvalidResponse)?;
        if response.request_id != pending.request_id
            || response.response.command != Some(pending.command)
        {
            return Err(BlobClientError::InvalidResponse);
        }
        if !response.response.status.is_ok() {
            return Err(BlobClientError::Relay(response.response.status));
        }
        let (next_stage, progress) = match (&self.stage, response.response.body) {
            (UploadStage::Begin, Some(BlobResponseBody::BeginUpload(_))) => {
                (UploadStage::Chunk(0), UploadProgress::Begun)
            }
            (UploadStage::Chunk(index), Some(BlobResponseBody::PutChunk(_))) => {
                let completed = *index;
                let next = if completed + 1 == self.blob.encrypted.chunks.len() {
                    UploadStage::Commit
                } else {
                    UploadStage::Chunk(completed + 1)
                };
                (next, UploadProgress::ChunkStored(completed))
            }
            (UploadStage::Commit, Some(BlobResponseBody::Commit(expiry))) => {
                (UploadStage::Complete, UploadProgress::Committed(expiry))
            }
            _ => return Err(BlobClientError::InvalidResponse),
        };
        let previous_stage = self.stage;
        self.stage = next_stage;
        let previous_pending = self.pending.take();
        if store.commit(&self.to_bytes()).is_err() {
            self.stage = previous_stage;
            self.pending = previous_pending;
            return Err(BlobClientError::Store);
        }
        Ok(progress)
    }
}

fn encode_upload_state(uploader: &BlobUploader) -> Vec<u8> {
    let manifest = uploader.blob.encrypted.manifest.as_bytes();
    let pending = uploader
        .pending
        .as_ref()
        .map_or(&[][..], |pending| pending.bytes.as_slice());
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&UPLOAD_STATE_MAGIC);
    bytes.push(UPLOAD_STATE_VERSION);
    bytes.extend_from_slice(uploader.blob.upload_id.as_bytes());
    bytes.extend_from_slice(&uploader.blob.encrypted.key.to_bytes());
    for seed in [
        uploader.blob.upload_key.to_seed(),
        uploader.blob.download_key.to_seed(),
        uploader.blob.renew_key.to_seed(),
        uploader.blob.delete_key.to_seed(),
    ] {
        bytes.extend_from_slice(&seed);
    }
    bytes.extend_from_slice(&uploader.ttl.to_be_bytes());
    let (stage, index) = match uploader.stage {
        UploadStage::Begin => (0, 0),
        UploadStage::Chunk(index) => (
            1,
            u32::try_from(index).expect("validated manifest chunk count fits u32"),
        ),
        UploadStage::Commit => (2, 0),
        UploadStage::Complete => (3, 0),
    };
    bytes.push(stage);
    bytes.extend_from_slice(&index.to_be_bytes());
    push_sized(&mut bytes, manifest);
    bytes.extend_from_slice(
        &u32::try_from(uploader.blob.encrypted.chunks.len())
            .expect("validated manifest chunk count fits u32")
            .to_be_bytes(),
    );
    for chunk in &uploader.blob.encrypted.chunks {
        push_sized(&mut bytes, chunk);
    }
    push_sized(&mut bytes, pending);
    bytes
}

fn push_sized(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .expect("blob profile values fit the snapshot length field")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}

fn decode_upload_state(bytes: &[u8]) -> Result<BlobUploader, BlobClientError> {
    let mut cursor = StateCursor(bytes);
    if cursor.array::<4>()? != UPLOAD_STATE_MAGIC {
        return Err(BlobClientError::InvalidPersistedState);
    }
    if cursor.byte()? != UPLOAD_STATE_VERSION {
        return Err(BlobClientError::InvalidPersistedState);
    }
    let upload_id = UploadId::from_bytes(cursor.array::<32>()?);
    let object_key = ObjectKey::from_bytes(cursor.array::<32>()?);
    let upload_key = BlobSigningKey::from_seed(cursor.array::<32>()?);
    let download_key = BlobSigningKey::from_seed(cursor.array::<32>()?);
    let renew_key = BlobSigningKey::from_seed(cursor.array::<32>()?);
    let delete_key = BlobSigningKey::from_seed(cursor.array::<32>()?);
    let ttl = u64::from_be_bytes(cursor.array::<8>()?);
    if ttl == 0 {
        return Err(BlobClientError::InvalidPersistedState);
    }
    let stage_tag = cursor.byte()?;
    let stage_index = u32::from_be_bytes(cursor.array::<4>()?) as usize;
    let manifest = BlobManifest::parse(cursor.sized(MAX_BLOB_FRAME_BYTES)?.to_vec())
        .map_err(|_| BlobClientError::InvalidPersistedState)?;
    let chunk_count = u32::from_be_bytes(cursor.array::<4>()?) as usize;
    if chunk_count != manifest.chunk_count() || chunk_count > MAX_CHUNKS {
        return Err(BlobClientError::InvalidPersistedState);
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    for _ in 0..chunk_count {
        let maximum = usize::try_from(manifest.chunk_size())
            .ok()
            .and_then(|size| size.checked_add(16))
            .ok_or(BlobClientError::InvalidPersistedState)?;
        chunks.push(cursor.sized(maximum)?.to_vec());
    }
    let pending_bytes = cursor.sized(MAX_BLOB_FRAME_BYTES)?.to_vec();
    cursor.finish()?;

    let blob_id = identify(&manifest);
    let encrypted = EncryptedBlob {
        key: object_key,
        manifest,
        blob_id,
        chunks,
    };
    open_blob(
        &encrypted.key,
        encrypted.blob_id,
        &encrypted.manifest,
        &encrypted.chunks,
    )
    .map_err(|_| BlobClientError::InvalidPersistedState)?;
    let stage = match stage_tag {
        0 if stage_index == 0 => UploadStage::Begin,
        1 if stage_index < encrypted.chunks.len() => UploadStage::Chunk(stage_index),
        2 if stage_index == 0 => UploadStage::Commit,
        3 if stage_index == 0 => UploadStage::Complete,
        _ => return Err(BlobClientError::InvalidPersistedState),
    };
    let blob = PreparedBlob {
        upload_id,
        encrypted,
        upload_key,
        download_key,
        renew_key,
        delete_key,
    };
    let pending = if pending_bytes.is_empty() {
        None
    } else {
        Some(validate_pending(&blob, ttl, stage, pending_bytes)?)
    };
    if stage == UploadStage::Complete && pending.is_some() {
        return Err(BlobClientError::InvalidPersistedState);
    }
    Ok(BlobUploader {
        blob,
        ttl,
        stage,
        pending,
    })
}

fn validate_pending(
    blob: &PreparedBlob,
    ttl: u64,
    stage: UploadStage,
    bytes: Vec<u8>,
) -> Result<Pending, BlobClientError> {
    let decoded =
        decode_blob_request(&bytes).map_err(|_| BlobClientError::InvalidPersistedState)?;
    let request = &decoded.frame.request;
    verify_blob_request(
        request.capability(),
        decoded.authenticated_bytes,
        &decoded.frame.auth,
    )
    .map_err(|_| BlobClientError::InvalidPersistedState)?;
    let matches = match (stage, request) {
        (
            UploadStage::Begin,
            BlobRequest::BeginUpload {
                upload_id,
                capabilities,
                manifest,
                ttl: request_ttl,
            },
        ) => {
            *upload_id == blob.upload_id
                && *request_ttl == ttl
                && manifest == &blob.encrypted.manifest
                && capabilities.upload == blob.upload_key.capability()
                && capabilities.download == blob.download_key.capability()
                && capabilities.renew == blob.renew_key.capability()
                && capabilities.delete == blob.delete_key.capability()
        }
        (
            UploadStage::Chunk(expected),
            BlobRequest::PutChunk {
                upload_id,
                upload_cap,
                index,
                ciphertext,
            },
        ) => {
            *upload_id == blob.upload_id
                && *upload_cap == blob.upload_key.capability()
                && usize::try_from(*index) == Ok(expected)
                && blob.encrypted.chunks.get(expected) == Some(ciphertext)
        }
        (
            UploadStage::Commit,
            BlobRequest::Commit {
                upload_id,
                upload_cap,
                blob_id,
            },
        ) => {
            *upload_id == blob.upload_id
                && *upload_cap == blob.upload_key.capability()
                && *blob_id == blob.encrypted.blob_id
        }
        _ => false,
    };
    if !matches {
        return Err(BlobClientError::InvalidPersistedState);
    }
    Ok(Pending {
        request_id: decoded.frame.request_id,
        command: request.command(),
        bytes,
    })
}

struct StateCursor<'a>(&'a [u8]);

impl<'a> StateCursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], BlobClientError> {
        if self.0.len() < length {
            return Err(BlobClientError::InvalidPersistedState);
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, BlobClientError> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BlobClientError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BlobClientError::InvalidPersistedState)
    }

    fn sized(&mut self, maximum: usize) -> Result<&'a [u8], BlobClientError> {
        let length = u32::from_be_bytes(self.array::<4>()?) as usize;
        if length > maximum {
            return Err(BlobClientError::InvalidPersistedState);
        }
        self.take(length)
    }

    fn finish(self) -> Result<(), BlobClientError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(BlobClientError::InvalidPersistedState)
        }
    }
}

/// Downloads and verifies a complete object before returning plaintext.
///
/// # Errors
///
/// Fails without returning partial plaintext on transport, relay, digest, identity, or AEAD errors.
pub fn download_blob<T: Transport, I: RequestIdSource>(
    prepared: &PreparedBlob,
    transport: &mut T,
    ids: &mut I,
) -> Result<Vec<u8>, BlobClientError> {
    let manifest_body = exchange(
        transport,
        ids,
        &prepared.download_key,
        BlobRequest::GetManifest {
            blob_id: prepared.encrypted.blob_id,
            download_cap: prepared.download_key.capability(),
        },
    )?;
    let BlobResponseBody::GetManifest(manifest, _) = manifest_body else {
        return Err(BlobClientError::InvalidResponse);
    };
    let mut chunks = Vec::with_capacity(manifest.chunk_count());
    for index in 0..manifest.chunk_count() {
        let body = exchange(
            transport,
            ids,
            &prepared.download_key,
            BlobRequest::GetChunk {
                blob_id: prepared.encrypted.blob_id,
                download_cap: prepared.download_key.capability(),
                index: u32::try_from(index).map_err(|_| BlobClientError::InvalidResponse)?,
            },
        )?;
        let BlobResponseBody::GetChunk(chunk, _) = body else {
            return Err(BlobClientError::InvalidResponse);
        };
        chunks.push(chunk);
    }
    open_blob(
        &prepared.encrypted.key,
        prepared.encrypted.blob_id,
        &manifest,
        &chunks,
    )
    .map_err(Into::into)
}

fn exchange<T: Transport, I: RequestIdSource>(
    transport: &mut T,
    ids: &mut I,
    key: &BlobSigningKey,
    request: BlobRequest,
) -> Result<BlobResponseBody, BlobClientError> {
    let request_id = ids.next_request_id();
    let command = request.command();
    let bytes = signed(key, request_id, request);
    let response = decode_blob_response(&transport.exchange(&bytes)?)
        .map_err(|_| BlobClientError::InvalidResponse)?;
    if response.request_id != request_id || response.response.command != Some(command) {
        return Err(BlobClientError::InvalidResponse);
    }
    if !response.response.status.is_ok() {
        return Err(BlobClientError::Relay(response.response.status));
    }
    response
        .response
        .body
        .ok_or(BlobClientError::InvalidResponse)
}

fn signed(key: &BlobSigningKey, request_id: RequestId, request: BlobRequest) -> Vec<u8> {
    let authenticated = encode_blob_authenticated_request(request_id, &request);
    let auth = key.sign_request(&authenticated);
    encode_blob_request(&BlobRequestFrame {
        request_id,
        request,
        auth,
    })
}
