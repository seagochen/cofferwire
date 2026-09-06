//! Cryptographic construction for immutable encrypted blob/1 objects.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use cofferwire_types::blob::{
    BlobId, BlobManifest, CapabilityId, MAX_PADDED_BYTES, MIN_PADDED_BYTES,
};
use cofferwire_types::Auth;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

const KEY_INFO: &[u8] = b"cofferwire blob key v1\0";
const CHUNK_DOMAIN: &[u8] = b"cofferwire blob chunk v1\0";
const IDENTITY_DOMAIN: &[u8] = b"cofferwire blob identity v1\0";
const REQUEST_DOMAIN: &[u8] = b"cofferwire blob request v1\0";

/// Failure to construct or authenticate an encrypted object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobCryptoError {
    PlaintextTooLarge,
    InvalidChunkSize,
    AuthenticationFailed,
    InvalidObject,
}

impl std::fmt::Display for BlobCryptoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::PlaintextTooLarge => "blob plaintext too large",
            Self::InvalidChunkSize => "invalid blob chunk size",
            Self::AuthenticationFailed => "blob authentication failed",
            Self::InvalidObject => "invalid encrypted blob object",
        })
    }
}
impl std::error::Error for BlobCryptoError {}

/// Secret content key. Debug intentionally omits its bytes.
#[derive(Clone)]
pub struct ObjectKey([u8; 32]);

impl ObjectKey {
    /// Loads a fixed key (for secure persistence and vectors).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Generates an independent key.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}
impl std::fmt::Debug for ObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ObjectKey([REDACTED])")
    }
}

/// Ed25519 key for one blob capability role.
#[derive(Clone)]
pub struct BlobSigningKey(SigningKey);
impl BlobSigningKey {
    /// Loads a fixed seed (for secure persistence and vectors).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }
    /// Generates an independent capability.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(SigningKey::generate(rng))
    }
    /// Returns the public capability identifier.
    #[must_use]
    pub fn capability(&self) -> CapabilityId {
        CapabilityId::from_bytes(self.0.verifying_key().to_bytes())
    }
    /// Signs exact codec-provided request bytes under the blob domain.
    ///
    /// # Panics
    ///
    /// The fixed 68-byte proof is always below the protocol auth bound.
    #[must_use]
    pub fn sign_request(&self, authenticated: &[u8]) -> Auth {
        let mut input = Vec::with_capacity(REQUEST_DOMAIN.len() + authenticated.len());
        input.extend_from_slice(REQUEST_DOMAIN);
        input.extend_from_slice(authenticated);
        let signature = self.0.sign(&input);
        let mut proof = Vec::with_capacity(68);
        proof.extend_from_slice(&1_u16.to_be_bytes());
        proof.extend_from_slice(&1_u16.to_be_bytes());
        proof.extend_from_slice(&signature.to_bytes());
        Auth::new(proof).expect("fixed blob proof")
    }
}
impl std::fmt::Debug for BlobSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobSigningKey")
            .field("capability", &self.capability())
            .finish_non_exhaustive()
    }
}

/// Verifies a blob request proof without emitting key or request material.
///
/// # Errors
///
/// Returns one indistinguishable error for malformed and invalid proofs.
pub fn verify_blob_request(
    capability: CapabilityId,
    authenticated: &[u8],
    auth: &Auth,
) -> Result<(), BlobCryptoError> {
    let proof = auth.as_bytes();
    if proof.len() != 68 || proof[..2] != 1_u16.to_be_bytes() || proof[2..4] != 1_u16.to_be_bytes()
    {
        return Err(BlobCryptoError::AuthenticationFailed);
    }
    let key = VerifyingKey::from_bytes(capability.as_bytes())
        .map_err(|_| BlobCryptoError::AuthenticationFailed)?;
    let signature =
        Signature::from_slice(&proof[4..]).map_err(|_| BlobCryptoError::AuthenticationFailed)?;
    let mut input = Vec::with_capacity(REQUEST_DOMAIN.len() + authenticated.len());
    input.extend_from_slice(REQUEST_DOMAIN);
    input.extend_from_slice(authenticated);
    key.verify_strict(&input, &signature)
        .map_err(|_| BlobCryptoError::AuthenticationFailed)
}

/// A complete immutable encrypted object ready for resumable upload.
#[derive(Clone, Debug)]
pub struct EncryptedBlob {
    pub key: ObjectKey,
    pub manifest: BlobManifest,
    pub blob_id: BlobId,
    pub chunks: Vec<Vec<u8>>,
}

/// Encrypts, pads, chunks, and identifies an object.
///
/// # Errors
///
/// Rejects unsupported chunk sizes and plaintexts beyond the profile maximum.
pub fn seal_blob<R: CryptoRng + RngCore>(
    plaintext: &[u8],
    chunk_size: u32,
    rng: &mut R,
) -> Result<EncryptedBlob, BlobCryptoError> {
    if !(32..=1_048_576).contains(&chunk_size) || !chunk_size.is_power_of_two() {
        return Err(BlobCryptoError::InvalidChunkSize);
    }
    let stream_len = plaintext
        .len()
        .checked_add(8)
        .ok_or(BlobCryptoError::PlaintextTooLarge)?;
    let max_padded =
        usize::try_from(MAX_PADDED_BYTES).map_err(|_| BlobCryptoError::PlaintextTooLarge)?;
    let min_padded =
        usize::try_from(MIN_PADDED_BYTES).map_err(|_| BlobCryptoError::PlaintextTooLarge)?;
    if stream_len > max_padded {
        return Err(BlobCryptoError::PlaintextTooLarge);
    }
    let mut padded_size = stream_len.max(min_padded).next_power_of_two();
    padded_size = padded_size.max(chunk_size as usize);
    if padded_size > max_padded
        || padded_size % chunk_size as usize != 0
        || padded_size / chunk_size as usize > 32_768
    {
        return Err(BlobCryptoError::InvalidChunkSize);
    }
    let key = ObjectKey::generate(rng);
    let mut salt = [0; 16];
    rng.fill_bytes(&mut salt);
    let mut stream = vec![0; padded_size];
    stream[..8].copy_from_slice(&(plaintext.len() as u64).to_be_bytes());
    stream[8..8 + plaintext.len()].copy_from_slice(plaintext);
    rng.fill_bytes(&mut stream[8 + plaintext.len()..]);
    let aead_key = derive_key(&key, &salt);
    let cipher = ChaCha20Poly1305::new((&aead_key).into());
    let count = padded_size / chunk_size as usize;
    let count_u32 = u32::try_from(count).map_err(|_| BlobCryptoError::InvalidChunkSize)?;
    let mut chunks = Vec::with_capacity(count);
    let mut digests = Vec::with_capacity(count);
    for (index, plain) in stream.chunks_exact(chunk_size as usize).enumerate() {
        let nonce = nonce(index)?;
        let aad = aad(
            &salt,
            padded_size as u64,
            chunk_size,
            count_u32,
            u32::try_from(index).map_err(|_| BlobCryptoError::InvalidObject)?,
        );
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .map_err(|_| BlobCryptoError::AuthenticationFailed)?;
        digests.push(Sha256::digest(&ciphertext).into());
        chunks.push(ciphertext);
    }
    let manifest = make_manifest(salt, padded_size as u64, chunk_size, &digests)?;
    let blob_id = identify(&manifest);
    Ok(EncryptedBlob {
        key,
        manifest,
        blob_id,
        chunks,
    })
}

/// Authenticates a complete object before returning any plaintext.
///
/// # Errors
///
/// Fails closed on identity, count, order, digest, AEAD, or padding-length errors.
pub fn open_blob(
    key: &ObjectKey,
    expected_id: BlobId,
    manifest: &BlobManifest,
    chunks: &[Vec<u8>],
) -> Result<Vec<u8>, BlobCryptoError> {
    if identify(manifest) != expected_id || chunks.len() != manifest.chunk_count() {
        return Err(BlobCryptoError::InvalidObject);
    }
    let aead_key = derive_key(key, manifest.object_salt());
    let cipher = ChaCha20Poly1305::new((&aead_key).into());
    let padded_size =
        usize::try_from(manifest.padded_size()).map_err(|_| BlobCryptoError::InvalidObject)?;
    let count =
        u32::try_from(manifest.chunk_count()).map_err(|_| BlobCryptoError::InvalidObject)?;
    let mut stream = Vec::with_capacity(padded_size);
    for (index, chunk) in chunks.iter().enumerate() {
        let digest: [u8; 32] = Sha256::digest(chunk).into();
        if manifest.digest(index) != Some(&digest) {
            return Err(BlobCryptoError::InvalidObject);
        }
        let aad = aad(
            manifest.object_salt(),
            manifest.padded_size(),
            manifest.chunk_size(),
            count,
            u32::try_from(index).map_err(|_| BlobCryptoError::InvalidObject)?,
        );
        let plaintext = cipher
            .decrypt(
                &nonce(index)?,
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .map_err(|_| BlobCryptoError::AuthenticationFailed)?;
        if plaintext.len() != manifest.chunk_size() as usize {
            return Err(BlobCryptoError::InvalidObject);
        }
        stream.extend_from_slice(&plaintext);
    }
    if stream.len() != padded_size {
        return Err(BlobCryptoError::InvalidObject);
    }
    let length = u64::from_be_bytes(
        stream
            .get(..8)
            .and_then(|value| value.try_into().ok())
            .ok_or(BlobCryptoError::InvalidObject)?,
    );
    let length = usize::try_from(length).map_err(|_| BlobCryptoError::InvalidObject)?;
    if length > stream.len() - 8 {
        return Err(BlobCryptoError::InvalidObject);
    }
    Ok(stream[8..8 + length].to_vec())
}

/// Computes the immutable manifest identity.
#[must_use]
pub fn identify(manifest: &BlobManifest) -> BlobId {
    let mut hash = Sha256::new();
    hash.update(IDENTITY_DOMAIN);
    hash.update(manifest.as_bytes());
    BlobId::from_bytes(hash.finalize().into())
}

fn derive_key(key: &ObjectKey, salt: &[u8; 16]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &key.0);
    let mut output = [0; 32];
    hkdf.expand(KEY_INFO, &mut output)
        .expect("fixed HKDF output");
    output
}
fn nonce(index: usize) -> Result<Nonce, BlobCryptoError> {
    let index = u64::try_from(index).map_err(|_| BlobCryptoError::InvalidObject)?;
    let mut bytes = [0; 12];
    bytes[4..].copy_from_slice(&index.to_be_bytes());
    Ok(bytes.into())
}
fn aad(salt: &[u8; 16], padded_size: u64, chunk_size: u32, count: u32, index: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(66);
    out.extend_from_slice(CHUNK_DOMAIN);
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(&padded_size.to_be_bytes());
    out.extend_from_slice(&chunk_size.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&index.to_be_bytes());
    out
}
fn make_manifest(
    salt: [u8; 16],
    padded_size: u64,
    chunk_size: u32,
    digests: &[[u8; 32]],
) -> Result<BlobManifest, BlobCryptoError> {
    let mut bytes = Vec::with_capacity(40 + 32 * digests.len());
    bytes.extend_from_slice(b"CWB1");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&padded_size.to_be_bytes());
    bytes.extend_from_slice(&chunk_size.to_be_bytes());
    let count = u32::try_from(digests.len()).map_err(|_| BlobCryptoError::InvalidObject)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for digest in digests {
        bytes.extend_from_slice(digest);
    }
    BlobManifest::parse(bytes).map_err(|_| BlobCryptoError::InvalidObject)
}
