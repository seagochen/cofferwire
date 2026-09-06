//! Signed end-to-end `receipt.applied` application receipts.
//!
//! See `docs/spec/08-receipts.md`. A receipt is ordinary opaque application
//! content: it travels inside a normal queue-v1 `SEND` payload and a relay
//! never parses it. This module only builds and verifies the fixed 237-byte
//! plaintext structure; delivering it is an ordinary `seal_message`/
//! `open_message` exchange like any other application message.

use ed25519_dalek::{Signature, Signer as _, VerifyingKey};
use sha2::{Digest, Sha256};

use cofferwire_types::{MessageId, Principal, QueueId};

use crate::RelaySigningKey;

const RECEIPT_DOMAIN: &[u8] = b"cofferwire receipt v1\0";
const MAGIC: [u8; 4] = *b"CWR1";
const APPLIED_TYPE: u8 = 1;
const DIGEST_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const SIGNED_LEN: usize = MAGIC.len() + 1 + 32 * 4 + DIGEST_BYTES + 8;
const RECEIPT_LEN: usize = SIGNED_LEN + SIGNATURE_BYTES;

/// A rejected `receipt.applied` candidate. No variant reveals key, plaintext,
/// or ciphertext material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptError {
    /// The plaintext is not exactly 237 bytes, or its magic/type is wrong.
    Malformed,
    /// The Ed25519 signature does not verify under the expected principal.
    AuthenticationFailed,
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed receipt.applied plaintext",
            Self::AuthenticationFailed => "receipt.applied authentication failed",
        })
    }
}
impl std::error::Error for ReceiptError {}

/// Identifies the application object one `receipt.applied` message confirms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmedObject {
    /// The original message's queue.
    pub queue_id: QueueId,
    /// The original message's sender principal.
    pub sender: Principal,
    /// The original message's recipient principal; also the confirming
    /// device's own signing identity.
    pub recipient: Principal,
    /// The original message's sender-chosen identifier.
    pub message_id: MessageId,
}

/// A `receipt.applied` message whose signature has been verified against a
/// caller-supplied expected principal.
///
/// A valid signature only proves authenticity and integrity under that
/// principal. Callers MUST separately compare `confirmed` (and, when they
/// hold the original plaintext, `applied_content_digest`) against the
/// specific object they expect confirmed before treating this as evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppliedReceipt {
    /// The confirmed application object.
    pub confirmed: ConfirmedObject,
    /// `SHA-256` of the exact plaintext the confirming device applied.
    pub applied_content_digest: [u8; 32],
    /// Device-local clock seconds at the time of the local durable commit.
    /// Informational only; never a freshness or ordering gate.
    pub applied_at_secs: u64,
}

/// Builds one signed `receipt.applied` plaintext.
///
/// `applied_plaintext` MUST be the exact bytes the confirming device durably
/// applied; `signing_key` MUST be the confirming device's own signing key
/// (`signing_key.principal() == confirmed.recipient`), which the caller is
/// responsible for ensuring.
#[must_use]
pub fn build_applied_receipt(
    signing_key: &RelaySigningKey,
    confirmed: ConfirmedObject,
    applied_plaintext: &[u8],
    applied_at_secs: u64,
) -> Vec<u8> {
    let digest: [u8; 32] = Sha256::digest(applied_plaintext).into();
    let mut message = Vec::with_capacity(RECEIPT_LEN);
    message.extend_from_slice(&MAGIC);
    message.push(APPLIED_TYPE);
    message.extend_from_slice(confirmed.queue_id.as_bytes());
    message.extend_from_slice(confirmed.sender.as_bytes());
    message.extend_from_slice(confirmed.recipient.as_bytes());
    message.extend_from_slice(confirmed.message_id.as_bytes());
    message.extend_from_slice(&digest);
    message.extend_from_slice(&applied_at_secs.to_be_bytes());
    debug_assert_eq!(message.len(), SIGNED_LEN);
    let signature = sign(signing_key, &message);
    message.extend_from_slice(&signature);
    message
}

/// Parses and verifies one `receipt.applied` plaintext against
/// `expected_signer` -- the confirming device's principal the verifier
/// already expects for this object, not a principal read from the receipt.
///
/// # Errors
///
/// Returns [`ReceiptError::Malformed`] for a wrong-length or wrong-magic/type
/// plaintext, and [`ReceiptError::AuthenticationFailed`] for a signature that
/// does not verify under `expected_signer`.
///
/// # Panics
///
/// The fixed-length check above guarantees every subsequent slice index is
/// in bounds.
pub fn verify_applied_receipt(
    expected_signer: Principal,
    plaintext: &[u8],
) -> Result<AppliedReceipt, ReceiptError> {
    if plaintext.len() != RECEIPT_LEN {
        return Err(ReceiptError::Malformed);
    }
    if plaintext[..MAGIC.len()] != MAGIC || plaintext[MAGIC.len()] != APPLIED_TYPE {
        return Err(ReceiptError::Malformed);
    }
    let signed = &plaintext[..SIGNED_LEN];
    let signature_bytes = &plaintext[SIGNED_LEN..];
    let verifying_key = VerifyingKey::from_bytes(expected_signer.as_bytes())
        .map_err(|_| ReceiptError::AuthenticationFailed)?;
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| ReceiptError::AuthenticationFailed)?;
    let mut message = Vec::with_capacity(RECEIPT_DOMAIN.len() + signed.len());
    message.extend_from_slice(RECEIPT_DOMAIN);
    message.extend_from_slice(signed);
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| ReceiptError::AuthenticationFailed)?;

    let mut offset = MAGIC.len() + 1;
    let queue_id = QueueId::from_bytes(read32(plaintext, &mut offset));
    let sender = Principal::from_bytes(read32(plaintext, &mut offset));
    let recipient = Principal::from_bytes(read32(plaintext, &mut offset));
    let message_id = MessageId::from_bytes(read32(plaintext, &mut offset));
    let applied_content_digest = read32(plaintext, &mut offset);
    let applied_at_secs = u64::from_be_bytes(
        plaintext[offset..offset + 8]
            .try_into()
            .expect("fixed 8-byte slice"),
    );
    offset += 8;
    debug_assert_eq!(offset, SIGNED_LEN);

    Ok(AppliedReceipt {
        confirmed: ConfirmedObject {
            queue_id,
            sender,
            recipient,
            message_id,
        },
        applied_content_digest,
        applied_at_secs,
    })
}

/// Computes the exact digest a receipt binds to for `plaintext`.
///
/// Exposed so a verifier holding the original plaintext can compare it
/// against [`AppliedReceipt::applied_content_digest`] (`CW-RECEIPT-007`).
#[must_use]
pub fn content_digest(plaintext: &[u8]) -> [u8; 32] {
    Sha256::digest(plaintext).into()
}

fn sign(signing_key: &RelaySigningKey, signed_fields: &[u8]) -> [u8; SIGNATURE_BYTES] {
    let mut message = Vec::with_capacity(RECEIPT_DOMAIN.len() + signed_fields.len());
    message.extend_from_slice(RECEIPT_DOMAIN);
    message.extend_from_slice(signed_fields);
    // RelaySigningKey's inner SigningKey is a private field of the crate
    // root; `receipt` is a descendant module of that root, so it may access
    // it directly rather than widening RelaySigningKey's public API with a
    // raw-key accessor.
    signing_key.0.sign(&message).to_bytes()
}

fn read32(bytes: &[u8], offset: &mut usize) -> [u8; 32] {
    let mut value = [0_u8; 32];
    value.copy_from_slice(&bytes[*offset..*offset + 32]);
    *offset += 32;
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUEUE: QueueId = QueueId::from_bytes([1; 32]);
    const SENDER_SEED: [u8; 32] = [2; 32];
    const RECIPIENT_SEED: [u8; 32] = [3; 32];
    const OTHER_SEED: [u8; 32] = [4; 32];
    const MESSAGE: MessageId = MessageId::from_bytes([5; 32]);

    fn confirmed(sender: Principal, recipient: Principal) -> ConfirmedObject {
        ConfirmedObject {
            queue_id: QUEUE,
            sender,
            recipient,
            message_id: MESSAGE,
        }
    }

    #[test]
    fn round_trips_and_binds_exact_content() {
        let sender = RelaySigningKey::from_seed(SENDER_SEED).principal();
        let recipient_key = RelaySigningKey::from_seed(RECIPIENT_SEED);
        let object = confirmed(sender, recipient_key.principal());
        let plaintext = b"family update applied";
        let receipt = build_applied_receipt(&recipient_key, object, plaintext, 1_700_000_000);

        let verified =
            verify_applied_receipt(recipient_key.principal(), &receipt).expect("verifies");
        assert_eq!(verified.confirmed, object);
        assert_eq!(verified.applied_content_digest, content_digest(plaintext));
        assert_eq!(verified.applied_at_secs, 1_700_000_000);
    }

    #[test]
    fn rejects_wrong_signer_as_authentication_failure() {
        let sender = RelaySigningKey::from_seed(SENDER_SEED).principal();
        let recipient_key = RelaySigningKey::from_seed(RECIPIENT_SEED);
        let object = confirmed(sender, recipient_key.principal());
        let receipt = build_applied_receipt(&recipient_key, object, b"content", 1);

        let wrong_signer = RelaySigningKey::from_seed(OTHER_SEED).principal();
        assert_eq!(
            verify_applied_receipt(wrong_signer, &receipt),
            Err(ReceiptError::AuthenticationFailed)
        );
    }

    #[test]
    fn every_byte_tamper_is_rejected() {
        let sender = RelaySigningKey::from_seed(SENDER_SEED).principal();
        let recipient_key = RelaySigningKey::from_seed(RECIPIENT_SEED);
        let object = confirmed(sender, recipient_key.principal());
        let receipt = build_applied_receipt(&recipient_key, object, b"content", 1);
        assert_eq!(receipt.len(), RECEIPT_LEN);

        for index in 0..receipt.len() {
            let mut tampered = receipt.clone();
            tampered[index] ^= 0x01;
            assert!(
                verify_applied_receipt(recipient_key.principal(), &tampered).is_err(),
                "byte {index} tamper was not rejected"
            );
        }
    }

    #[test]
    fn rejects_truncated_and_oversized_plaintext() {
        let sender = RelaySigningKey::from_seed(SENDER_SEED).principal();
        let recipient_key = RelaySigningKey::from_seed(RECIPIENT_SEED);
        let object = confirmed(sender, recipient_key.principal());
        let receipt = build_applied_receipt(&recipient_key, object, b"content", 1);

        let mut truncated = receipt.clone();
        truncated.pop();
        assert_eq!(
            verify_applied_receipt(recipient_key.principal(), &truncated),
            Err(ReceiptError::Malformed)
        );

        let mut oversized = receipt.clone();
        oversized.push(0);
        assert_eq!(
            verify_applied_receipt(recipient_key.principal(), &oversized),
            Err(ReceiptError::Malformed)
        );
    }

    #[test]
    fn rejects_wrong_magic_and_type() {
        let sender = RelaySigningKey::from_seed(SENDER_SEED).principal();
        let recipient_key = RelaySigningKey::from_seed(RECIPIENT_SEED);
        let object = confirmed(sender, recipient_key.principal());
        let mut receipt = build_applied_receipt(&recipient_key, object, b"content", 1);
        receipt[4] = 0xFF;
        assert_eq!(
            verify_applied_receipt(recipient_key.principal(), &receipt),
            Err(ReceiptError::Malformed)
        );
    }

    #[test]
    fn signing_domain_is_separate_from_relay_request_signing() {
        let recipient_key = RelaySigningKey::from_seed(RECIPIENT_SEED);
        let object = confirmed(
            RelaySigningKey::from_seed(SENDER_SEED).principal(),
            recipient_key.principal(),
        );
        let receipt = build_applied_receipt(&recipient_key, object, b"content", 1);
        let signed_fields = &receipt[..SIGNED_LEN];
        // A relay-request signature over the same bytes must not verify as a
        // receipt signature, proving the two domains never collide.
        let relay_auth = recipient_key.sign_request(signed_fields);
        assert_ne!(relay_auth.as_bytes()[4..], receipt[SIGNED_LEN..]);
    }
}
