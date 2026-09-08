//! Offline bootstrap and recovery bundles (`cofferwire-offline/1`).
//!
//! See `docs/spec/13-offline-bundles.md`. A bundle is never sent to a relay; it is
//! a local export/import artifact. Its secret-bearing plaintext is sealed
//! with the exact authenticated-HPKE construction already used for
//! application messages (`seal_message`/`open_message`) -- no new
//! cryptographic primitive is defined here.

use cofferwire_crypto::{
    open_message, seal_message, CryptoError, EncryptionPublicKey, EncryptionSecretKey,
    MessageContext, RelaySigningKey,
};
use cofferwire_types::{MessageId, Payload, Principal, QueueId};
use rand_core::{CryptoRng, RngCore};

use crate::StoreError;

/// Maximum relay hints one bundle may carry (`CW-OFFLINE-002`).
pub const MAX_RELAY_HINTS: usize = 8;
/// Maximum bytes of one relay hint (`CW-OFFLINE-002`).
pub const MAX_RELAY_HINT_BYTES: usize = 256;

const MAGIC: [u8; 4] = *b"CWOB";
const VERSION: u8 = 1;
const ENVELOPE_HEADER_LEN: usize = MAGIC.len() + 1 + 32 + 32;
const INVITATION_TYPE: u8 = 1;
const RECOVERY_TYPE: u8 = 2;

/// The role the importing device will hold on the confirmed queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Sender,
    Recipient,
}

/// The importing device's own secret material, present only in a recovery
/// bundle. Reconstructed with the same deterministic constructions already
/// defined for secure key loading (`CW-OFFLINE-006`).
#[derive(Clone, Copy)]
pub struct OwnIdentitySeed {
    pub signing_seed: [u8; 32],
    pub encryption_ikm: [u8; 32],
}

impl std::fmt::Debug for OwnIdentitySeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnIdentitySeed")
            .finish_non_exhaustive()
    }
}

impl OwnIdentitySeed {
    /// Reconstructs the importing device's own keys.
    #[must_use]
    pub fn reconstruct(&self) -> (RelaySigningKey, EncryptionSecretKey) {
        (
            RelaySigningKey::from_seed(self.signing_seed),
            EncryptionSecretKey::derive(&self.encryption_ikm),
        )
    }
}

/// The fields carried by a bundle's inner plaintext, exclusive of the queue
/// and bundle identifiers (which are bound through `MessageContext`, not
/// repeated inside the encrypted content).
#[derive(Clone, Debug)]
pub struct BundleFields {
    pub role: Role,
    pub peer_principal: Principal,
    pub peer_encryption_public_key: EncryptionPublicKey,
    pub created_at_secs: u64,
    pub own_identity: Option<OwnIdentitySeed>,
    pub relay_hints: Vec<Vec<u8>>,
}

/// A rejected bundle. No variant reveals key, plaintext, or ciphertext
/// material.
#[derive(Debug)]
pub enum BundleError {
    /// Too many relay hints, or one exceeding `MAX_RELAY_HINT_BYTES`.
    RelayHints,
    /// The plaintext is not a validly structured bundle for its declared
    /// type (`CW-OFFLINE-005`).
    Malformed,
    /// The envelope declares an unrecognized `cofferwire-offline` version
    /// (`CW-OFFLINE-010`).
    UnsupportedVersion,
    /// Sealing or opening failed -- includes tampering, an unintended
    /// recipient, or a wrong expected exporter (`CW-OFFLINE-007`).
    Crypto(CryptoError),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RelayHints => formatter.write_str("relay hint count or size out of bounds"),
            Self::Malformed => formatter.write_str("malformed offline bundle plaintext"),
            Self::UnsupportedVersion => formatter.write_str("unsupported offline bundle version"),
            Self::Crypto(error) => {
                write!(formatter, "offline bundle authentication failed: {error}")
            }
        }
    }
}
impl std::error::Error for BundleError {}

fn encode_fields(fields: &BundleFields) -> Result<Vec<u8>, BundleError> {
    if fields.relay_hints.len() > MAX_RELAY_HINTS {
        return Err(BundleError::RelayHints);
    }
    for hint in &fields.relay_hints {
        if hint.len() > MAX_RELAY_HINT_BYTES {
            return Err(BundleError::RelayHints);
        }
    }
    let mut out = Vec::new();
    out.push(if fields.own_identity.is_some() {
        RECOVERY_TYPE
    } else {
        INVITATION_TYPE
    });
    out.push(match fields.role {
        Role::Sender => 0,
        Role::Recipient => 1,
    });
    out.extend_from_slice(fields.peer_principal.as_bytes());
    out.extend_from_slice(fields.peer_encryption_public_key.as_bytes());
    out.extend_from_slice(&fields.created_at_secs.to_be_bytes());
    if let Some(identity) = &fields.own_identity {
        out.extend_from_slice(&identity.signing_seed);
        out.extend_from_slice(&identity.encryption_ikm);
    }
    out.push(u8::try_from(fields.relay_hints.len()).expect("bounded above"));
    for hint in &fields.relay_hints {
        let length = u16::try_from(hint.len()).expect("bounded above");
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(hint);
    }
    Ok(out)
}

fn decode_fields(plaintext: &[u8]) -> Result<BundleFields, BundleError> {
    let mut cursor = Cursor(plaintext);
    let bundle_type = cursor.byte()?;
    if bundle_type != INVITATION_TYPE && bundle_type != RECOVERY_TYPE {
        return Err(BundleError::Malformed);
    }
    let role = match cursor.byte()? {
        0 => Role::Sender,
        1 => Role::Recipient,
        _ => return Err(BundleError::Malformed),
    };
    let peer_principal = Principal::from_bytes(cursor.array32()?);
    let peer_encryption_public_key =
        EncryptionPublicKey::from_bytes(cursor.array32()?).map_err(|_| BundleError::Malformed)?;
    let created_at_secs = u64::from_be_bytes(cursor.array8()?);
    let own_identity = if bundle_type == RECOVERY_TYPE {
        let signing_seed = cursor.array32()?;
        let encryption_ikm = cursor.array32()?;
        Some(OwnIdentitySeed {
            signing_seed,
            encryption_ikm,
        })
    } else {
        None
    };
    let hint_count = usize::from(cursor.byte()?);
    if hint_count > MAX_RELAY_HINTS {
        return Err(BundleError::Malformed);
    }
    let mut relay_hints = Vec::with_capacity(hint_count);
    for _ in 0..hint_count {
        let length = usize::from(u16::from_be_bytes(cursor.array2()?));
        if length > MAX_RELAY_HINT_BYTES {
            return Err(BundleError::Malformed);
        }
        relay_hints.push(cursor.bytes(length)?.to_vec());
    }
    cursor.finish()?;
    Ok(BundleFields {
        role,
        peer_principal,
        peer_encryption_public_key,
        created_at_secs,
        own_identity,
        relay_hints,
    })
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn bytes(&mut self, length: usize) -> Result<&'a [u8], BundleError> {
        if self.0.len() < length {
            return Err(BundleError::Malformed);
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8, BundleError> {
        Ok(self.bytes(1)?[0])
    }
    fn array2(&mut self) -> Result<[u8; 2], BundleError> {
        self.bytes(2)?
            .try_into()
            .map_err(|_| BundleError::Malformed)
    }
    fn array8(&mut self) -> Result<[u8; 8], BundleError> {
        self.bytes(8)?
            .try_into()
            .map_err(|_| BundleError::Malformed)
    }
    fn array32(&mut self) -> Result<[u8; 32], BundleError> {
        self.bytes(32)?
            .try_into()
            .map_err(|_| BundleError::Malformed)
    }
    fn finish(self) -> Result<(), BundleError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(BundleError::Malformed)
        }
    }
}

/// Seals one offline bundle for `importing_principal`.
///
/// `context.queue_id` and `context.message_id` (the bundle identifier, a
/// fresh value the caller MUST generate with a CSPRNG) are bound into the
/// seal and also carried in the envelope's cleartext header, exactly as
/// queue-v1 already exposes these identifiers outside the
/// end-to-end-protected payload. `context.sender` MUST be the exporting
/// device's own principal and `context.recipient` the importing device's.
///
/// # Errors
///
/// Returns [`BundleError::RelayHints`] for an out-of-bounds relay hint list,
/// or [`BundleError::Crypto`] if sealing fails.
pub fn seal_bundle<R: CryptoRng + RngCore>(
    context: MessageContext,
    exporting_encryption_key: &EncryptionSecretKey,
    importing_encryption_public_key: EncryptionPublicKey,
    fields: &BundleFields,
    rng: &mut R,
) -> Result<Vec<u8>, BundleError> {
    let plaintext = encode_fields(fields)?;
    let sealed = seal_message(
        exporting_encryption_key,
        importing_encryption_public_key,
        context,
        &plaintext,
        rng,
    )
    .map_err(BundleError::Crypto)?;
    let mut envelope = Vec::with_capacity(ENVELOPE_HEADER_LEN + sealed.as_bytes().len());
    envelope.extend_from_slice(&MAGIC);
    envelope.push(VERSION);
    envelope.extend_from_slice(context.queue_id.as_bytes());
    envelope.extend_from_slice(context.message_id.as_bytes());
    envelope.extend_from_slice(sealed.as_bytes());
    Ok(envelope)
}

/// Opens one offline bundle envelope against a caller-supplied expected
/// exporter -- never an identity read from the envelope itself
/// (`CW-OFFLINE-007`).
///
/// # Errors
///
/// Returns [`BundleError::UnsupportedVersion`] for an unrecognized version,
/// [`BundleError::Malformed`] for a structurally invalid envelope or
/// plaintext, and [`BundleError::Crypto`] for a decryption/authentication
/// failure (wrong recipient, tampering, or wrong expected exporter).
pub fn open_bundle(
    importing_encryption_key: &EncryptionSecretKey,
    importing_principal: Principal,
    expected_exporter: Principal,
    expected_exporter_encryption_key: EncryptionPublicKey,
    envelope: &[u8],
) -> Result<(QueueId, MessageId, BundleFields), BundleError> {
    if envelope.len() < ENVELOPE_HEADER_LEN || envelope[..MAGIC.len()] != MAGIC {
        return Err(BundleError::Malformed);
    }
    if envelope[MAGIC.len()] != VERSION {
        return Err(BundleError::UnsupportedVersion);
    }
    let mut cursor = Cursor(&envelope[MAGIC.len() + 1..]);
    let queue_id = QueueId::from_bytes(cursor.array32().map_err(|_| BundleError::Malformed)?);
    let bundle_id = MessageId::from_bytes(cursor.array32().map_err(|_| BundleError::Malformed)?);
    let sealed = Payload::new(cursor.0.to_vec()).map_err(|_| BundleError::Malformed)?;
    let context = MessageContext {
        queue_id,
        sender: expected_exporter,
        recipient: importing_principal,
        message_id: bundle_id,
    };
    let plaintext = open_message(
        importing_encryption_key,
        expected_exporter_encryption_key,
        context,
        &sealed,
    )
    .map_err(BundleError::Crypto)?;
    let fields = decode_fields(&plaintext)?;
    Ok((queue_id, bundle_id, fields))
}

/// Result of recording one opened bundle (`CW-OFFLINE-008`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportOutcome {
    /// This `(queue-id, role, peer-principal, bundle-id)` had not been
    /// imported before.
    Imported,
    /// This exact `bundle-id` was already recorded; a no-op duplicate.
    AlreadyImported,
}

/// A rejected durable record of an otherwise-valid bundle.
#[derive(Debug)]
pub enum BundleStoreError {
    /// An import already exists for this `(queue-id, role)` under a
    /// different `peer-principal` (`CW-OFFLINE-009`).
    ConflictingIdentity,
    /// The durable record itself failed.
    Failure(StoreError),
}

/// The importer's durable deduplication boundary for accepted bundles.
///
/// Implementations key deduplication by `bundle_id` and MUST reject a
/// differing `peer_principal` for an already-recorded `(queue_id, role)`
/// pair as [`BundleStoreError::ConflictingIdentity`] rather than silently
/// replacing the stored identity (`CW-OFFLINE-009`).
pub trait BundleStore {
    /// Durably records one opened bundle.
    ///
    /// # Errors
    ///
    /// Returns [`BundleStoreError`] for a conflicting identity or a failed
    /// durable record.
    fn record(
        &mut self,
        queue_id: QueueId,
        role: Role,
        peer_principal: Principal,
        bundle_id: MessageId,
    ) -> Result<ImportOutcome, BundleStoreError>;
}

/// A rejected bundle import, from either verification or durable recording.
#[derive(Debug)]
pub enum ImportError {
    /// Opening the bundle failed; see [`BundleError`].
    Bundle(BundleError),
    /// An import already exists for this queue and role under a different
    /// peer (`CW-OFFLINE-009`).
    ConflictingIdentity,
    /// The durable record failed.
    Store(StoreError),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bundle(error) => write!(formatter, "{error}"),
            Self::ConflictingIdentity => {
                formatter.write_str("bundle confirms a conflicting peer identity")
            }
            Self::Store(_) => formatter.write_str("durable bundle import record failed"),
        }
    }
}
impl std::error::Error for ImportError {}

/// Opens and durably records one offline bundle in a single call.
///
/// # Errors
///
/// See [`ImportError`].
pub fn open_and_record_bundle<S: BundleStore>(
    store: &mut S,
    importing_encryption_key: &EncryptionSecretKey,
    importing_principal: Principal,
    expected_exporter: Principal,
    expected_exporter_encryption_key: EncryptionPublicKey,
    envelope: &[u8],
) -> Result<(QueueId, BundleFields, ImportOutcome), ImportError> {
    let (queue_id, bundle_id, fields) = open_bundle(
        importing_encryption_key,
        importing_principal,
        expected_exporter,
        expected_exporter_encryption_key,
        envelope,
    )
    .map_err(ImportError::Bundle)?;
    let outcome = store
        .record(queue_id, fields.role, fields.peer_principal, bundle_id)
        .map_err(|error| match error {
            BundleStoreError::ConflictingIdentity => ImportError::ConflictingIdentity,
            BundleStoreError::Failure(error) => ImportError::Store(error),
        })?;
    Ok((queue_id, fields, outcome))
}

#[cfg(test)]
mod tests;
