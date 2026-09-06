//! Transport-independent resumable blob upload and fail-closed download.

use cofferwire_codec::blob::{
    decode_blob_response, encode_blob_authenticated_request, encode_blob_request,
};
use cofferwire_crypto::blob::{
    open_blob, seal_blob, BlobCryptoError, BlobSigningKey, EncryptedBlob,
};
use cofferwire_types::blob::{
    BlobCapabilities, BlobCommand, BlobId, BlobRequest, BlobRequestFrame, BlobResponseBody,
    BlobStatus, CapabilityId, UploadId,
};
use cofferwire_types::RequestId;
use rand_core::{CryptoRng, RngCore};

use crate::{RequestIdSource, Transport, TransportError};

/// Blob client failure without secret-bearing diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobClientError {
    Transport,
    Crypto,
    InvalidResponse,
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

/// All private material needed to upload and later retrieve one encrypted object.
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
    /// Constructs a resumable state machine. Persist this value before sending.
    #[must_use]
    pub const fn uploader(&self, ttl: u64) -> BlobUploader<'_> {
        BlobUploader {
            blob: self,
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
pub struct BlobUploader<'a> {
    blob: &'a PreparedBlob,
    ttl: u64,
    stage: UploadStage,
    pending: Option<Pending>,
}

impl BlobUploader<'_> {
    /// Advances one durable operation. A transport failure preserves the exact pending frame.
    ///
    /// # Errors
    ///
    /// Returns transport, codec, correlation, relay-status, or response-shape failures.
    pub fn advance<T: Transport, I: RequestIdSource>(
        &mut self,
        transport: &mut T,
        ids: &mut I,
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
        let progress = match (&self.stage, response.response.body) {
            (UploadStage::Begin, Some(BlobResponseBody::BeginUpload(0 | 1))) => {
                self.stage = UploadStage::Chunk(0);
                UploadProgress::Begun
            }
            (UploadStage::Chunk(index), Some(BlobResponseBody::PutChunk(0 | 1))) => {
                let completed = *index;
                self.stage = if completed + 1 == self.blob.encrypted.chunks.len() {
                    UploadStage::Commit
                } else {
                    UploadStage::Chunk(completed + 1)
                };
                UploadProgress::ChunkStored(completed)
            }
            (UploadStage::Commit, Some(BlobResponseBody::Commit(expiry))) => {
                self.stage = UploadStage::Complete;
                UploadProgress::Committed(expiry)
            }
            _ => return Err(BlobClientError::InvalidResponse),
        };
        self.pending = None;
        Ok(progress)
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
