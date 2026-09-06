//! Cofferwire v1's fixed cryptographic profile.
//!
//! Relay commands use Ed25519 signatures over the exact codec-provided bytes.
//! Application messages use RFC 9180 authenticated HPKE with
//! DHKEM(X25519, HKDF-SHA-256), HKDF-SHA-256 and ChaCha20-Poly1305.

#![forbid(unsafe_code)]

pub mod blob;
mod error;
pub mod receipt;

use cofferwire_types::{Auth, MessageId, Payload, Principal, QueueId, MAX_MESSAGE_BYTES};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
pub use error::CryptoError;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, Kem as _, OpModeR, OpModeS, Serializable,
};
use rand_core::{CryptoRng, RngCore};

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

const PROFILE_ID: [u8; 2] = 1_u16.to_be_bytes();
const ED25519_ID: [u8; 2] = 1_u16.to_be_bytes();
const KEM_ID: [u8; 2] = 0x0020_u16.to_be_bytes();
const KDF_ID: [u8; 2] = 0x0001_u16.to_be_bytes();
const AEAD_ID: [u8; 2] = 0x0003_u16.to_be_bytes();
const RELAY_AUTH_DOMAIN: &[u8] = b"cofferwire relay request v1\0";
const HPKE_INFO_DOMAIN: &[u8] = b"cofferwire hpke info v1\0";
const HPKE_AAD_DOMAIN: &[u8] = b"cofferwire hpke aad v1\0";
const AUTH_HEADER_BYTES: usize = 4;
const SIGNATURE_BYTES: usize = 64;
const ENVELOPE_HEADER_BYTES: usize = 8;
const ENCAPSULATED_KEY_BYTES: usize = 32;
const AEAD_TAG_BYTES: usize = 16;

/// Maximum plaintext accepted by [`seal_message`].
pub const MAX_PLAINTEXT_BYTES: usize =
    MAX_MESSAGE_BYTES - ENVELOPE_HEADER_BYTES - ENCAPSULATED_KEY_BYTES - AEAD_TAG_BYTES;

/// An Ed25519 command-signing key whose debug representation excludes secret bytes.
#[derive(Clone)]
pub struct RelaySigningKey(SigningKey);

impl RelaySigningKey {
    /// Constructs a deterministic signing key from a 32-byte secret seed.
    ///
    /// This constructor exists for secure key loading and public test vectors;
    /// callers must not use low-entropy or reused seeds in production.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// Generates a new signing key from a cryptographically secure RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(SigningKey::generate(rng))
    }

    /// Returns the queue-scoped principal corresponding to this key.
    #[must_use]
    pub fn principal(&self) -> Principal {
        Principal::from_bytes(self.0.verifying_key().to_bytes())
    }

    /// Signs the exact `preamble || payload` supplied by the codec.
    ///
    /// # Panics
    ///
    /// The fixed 68-byte proof is always below the protocol's auth bound.
    #[must_use]
    pub fn sign_request(&self, authenticated_bytes: &[u8]) -> Auth {
        let mut message = Vec::with_capacity(RELAY_AUTH_DOMAIN.len() + authenticated_bytes.len());
        message.extend_from_slice(RELAY_AUTH_DOMAIN);
        message.extend_from_slice(authenticated_bytes);
        let signature = self.0.sign(&message);

        let mut proof = Vec::with_capacity(AUTH_HEADER_BYTES + SIGNATURE_BYTES);
        proof.extend_from_slice(&PROFILE_ID);
        proof.extend_from_slice(&ED25519_ID);
        proof.extend_from_slice(&signature.to_bytes());
        Auth::new(proof).expect("fixed command proof fits MAX_AUTH_BYTES")
    }
}

impl std::fmt::Debug for RelaySigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelaySigningKey")
            .field("principal", &self.principal())
            .finish_non_exhaustive()
    }
}

/// Verifies an Ed25519 relay-command proof with strict anti-malleability checks.
///
/// # Errors
///
/// Returns one indistinguishable authentication error for malformed keys, profile
/// downgrade attempts, malformed signatures and invalid signatures.
pub fn verify_request(
    principal: Principal,
    authenticated_bytes: &[u8],
    auth: &Auth,
) -> Result<(), CryptoError> {
    let bytes = auth.as_bytes();
    if bytes.len() != AUTH_HEADER_BYTES + SIGNATURE_BYTES
        || bytes[..2] != PROFILE_ID
        || bytes[2..4] != ED25519_ID
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    let verifying_key = VerifyingKey::from_bytes(principal.as_bytes())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let signature = Signature::from_slice(&bytes[AUTH_HEADER_BYTES..])
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let mut message = Vec::with_capacity(RELAY_AUTH_DOMAIN.len() + authenticated_bytes.len());
    message.extend_from_slice(RELAY_AUTH_DOMAIN);
    message.extend_from_slice(authenticated_bytes);
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Public half of a device's authenticated HPKE identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptionPublicKey([u8; 32]);

impl EncryptionPublicKey {
    /// Parses and validates a canonical X25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] for an invalid encoding.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        <Kem as hpke::Kem>::PublicKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(bytes))
    }

    /// Returns the exact 32-byte public-key encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn parse(&self) -> Result<<Kem as hpke::Kem>::PublicKey, CryptoError> {
        <Kem as hpke::Kem>::PublicKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidKey)
    }
}

/// Private half of a device's authenticated HPKE identity.
#[derive(Clone)]
pub struct EncryptionSecretKey(<Kem as hpke::Kem>::PrivateKey);

impl EncryptionSecretKey {
    /// Generates a new key from a cryptographically secure RNG.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let (secret, _) = Kem::gen_keypair(rng);
        Self(secret)
    }

    /// Deterministically derives a key from 32 bytes of input keying material.
    ///
    /// This is intended for secure key loading and public vectors. Production
    /// input keying material must contain 256 bits of entropy and be unique.
    #[must_use]
    pub fn derive(ikm: &[u8; 32]) -> Self {
        let (secret, _) = Kem::derive_keypair(ikm);
        Self(secret)
    }

    /// Returns the corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> EncryptionPublicKey {
        let bytes = Kem::sk_to_pk(&self.0).to_bytes();
        let mut output = [0_u8; 32];
        output.copy_from_slice(&bytes);
        EncryptionPublicKey(output)
    }
}

impl std::fmt::Debug for EncryptionSecretKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptionSecretKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// Stable context bound into HPKE key derivation and associated data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageContext {
    /// Queue on which the ciphertext is delivered.
    pub queue_id: QueueId,
    /// Queue-scoped signing principal expected to have authored the message.
    pub sender: Principal,
    /// Queue-scoped recipient principal.
    pub recipient: Principal,
    /// Sender-chosen idempotency identifier.
    pub message_id: MessageId,
}

/// Encrypts and authenticates one application plaintext using a fresh HPKE encapsulation.
///
/// # Errors
///
/// Rejects plaintext that cannot fit the wire payload or invalid keys. The RNG
/// must be a CSPRNG and must never repeat its state across calls.
pub fn seal_message<R: CryptoRng + RngCore>(
    sender_secret: &EncryptionSecretKey,
    recipient_public: EncryptionPublicKey,
    context: MessageContext,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Payload, CryptoError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(CryptoError::PlaintextTooLarge {
            max: MAX_PLAINTEXT_BYTES,
            actual: plaintext.len(),
        });
    }
    let sender_public = Kem::sk_to_pk(&sender_secret.0);
    let recipient_public = recipient_public.parse()?;
    let info = context_bytes(HPKE_INFO_DOMAIN, context);
    let aad = context_bytes(HPKE_AAD_DOMAIN, context);
    let mode = OpModeS::Auth((sender_secret.0.clone(), sender_public));
    let (encapped, mut encryption) =
        setup_sender::<Aead, Kdf, Kem, _>(&mode, &recipient_public, &info, rng)
            .map_err(|_| CryptoError::EncryptionFailed)?;
    let ciphertext = encryption
        .seal(plaintext, &aad)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut envelope =
        Vec::with_capacity(ENVELOPE_HEADER_BYTES + ENCAPSULATED_KEY_BYTES + ciphertext.len());
    envelope.extend_from_slice(&PROFILE_ID);
    envelope.extend_from_slice(&KEM_ID);
    envelope.extend_from_slice(&KDF_ID);
    envelope.extend_from_slice(&AEAD_ID);
    envelope.extend_from_slice(&encapped.to_bytes());
    envelope.extend_from_slice(&ciphertext);
    Payload::new(envelope).map_err(|_| CryptoError::EncryptionFailed)
}

/// Authenticates and decrypts one application payload.
///
/// # Errors
///
/// Profile mismatch is reported separately from a uniform decryption failure;
/// neither error includes ciphertext, key, or plaintext material.
pub fn open_message(
    recipient_secret: &EncryptionSecretKey,
    sender_public: EncryptionPublicKey,
    context: MessageContext,
    payload: &Payload,
) -> Result<Vec<u8>, CryptoError> {
    let envelope = payload.as_bytes();
    let prefix = envelope
        .get(..ENVELOPE_HEADER_BYTES)
        .ok_or(CryptoError::InvalidEnvelope)?;
    if prefix[..2] != PROFILE_ID
        || prefix[2..4] != KEM_ID
        || prefix[4..6] != KDF_ID
        || prefix[6..8] != AEAD_ID
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    let encapped_end = ENVELOPE_HEADER_BYTES + ENCAPSULATED_KEY_BYTES;
    let encapped = envelope
        .get(ENVELOPE_HEADER_BYTES..encapped_end)
        .ok_or(CryptoError::InvalidEnvelope)?;
    let ciphertext = envelope
        .get(encapped_end..)
        .filter(|value| value.len() >= AEAD_TAG_BYTES)
        .ok_or(CryptoError::InvalidEnvelope)?;
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(encapped)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let sender_public = sender_public.parse()?;
    let info = context_bytes(HPKE_INFO_DOMAIN, context);
    let aad = context_bytes(HPKE_AAD_DOMAIN, context);
    let mut decryption = setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Auth(sender_public),
        &recipient_secret.0,
        &encapped,
        &info,
    )
    .map_err(|_| CryptoError::DecryptionFailed)?;
    decryption
        .open(ciphertext, &aad)
        .map_err(|_| CryptoError::DecryptionFailed)
}

fn context_bytes(domain: &[u8], context: MessageContext) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len() + 128);
    output.extend_from_slice(domain);
    output.extend_from_slice(&PROFILE_ID);
    output.extend_from_slice(&KEM_ID);
    output.extend_from_slice(&KDF_ID);
    output.extend_from_slice(&AEAD_ID);
    output.extend_from_slice(context.queue_id.as_bytes());
    output.extend_from_slice(context.sender.as_bytes());
    output.extend_from_slice(context.recipient.as_bytes());
    output.extend_from_slice(context.message_id.as_bytes());
    output
}
