//! Client-side generation, verification, and deduplication of
//! `receipt.applied` application receipts. See `spec/08-receipts.md`.
//!
//! Generation and low-level verification are plain functions from
//! `cofferwire_crypto::receipt`, re-exported here for convenience. This
//! module adds the durability/deduplication boundary a reference client
//! needs: recording an accepted receipt by the confirmed object's identity,
//! independent of the transport-level message the receipt itself arrived on.

use cofferwire_crypto::receipt::verify_applied_receipt as verify_receipt_signature;
pub use cofferwire_crypto::receipt::{
    build_applied_receipt, content_digest, AppliedReceipt, ConfirmedObject, ReceiptError,
};
use cofferwire_types::Principal;

use crate::StoreError;

/// Result of recording one verified `receipt.applied` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptOutcome {
    /// The confirmed object had not been recorded before.
    Recorded,
    /// The confirmed object was already recorded; this is a no-op duplicate.
    AlreadyRecorded,
}

/// The verifier's durable deduplication boundary for accepted receipts.
///
/// Implementations key their storage by the confirmed object identity
/// (`CW-RECEIPT-008`), not by the receipt's own transport-level message
/// identifier, so a second valid receipt for an already-recorded object is a
/// no-op rather than a second application-level effect.
pub trait ReceiptStore {
    /// Durably records that `confirmed` has an accepted `receipt.applied`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] unless the durable record succeeded.
    fn record(&mut self, confirmed: ConfirmedObject) -> Result<ReceiptOutcome, StoreError>;
}

/// A rejected receipt-verification attempt. No variant reveals key,
/// plaintext, or ciphertext material.
#[derive(Debug)]
pub enum ReceiptVerificationError {
    /// The receipt is malformed or its signature is invalid (`CW-RECEIPT-005`).
    Crypto(ReceiptError),
    /// The receipt is authentic but confirms a different object than
    /// expected (`CW-RECEIPT-006`).
    ObjectMismatch,
    /// The receipt is authentic and confirms the expected object, but its
    /// content digest does not match the plaintext the caller originally
    /// sent (`CW-RECEIPT-007`).
    ContentMismatch,
    /// The durable record of the confirmed object failed.
    Store(StoreError),
}

impl std::fmt::Display for ReceiptVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto(error) => write!(formatter, "receipt verification failed: {error}"),
            Self::ObjectMismatch => formatter.write_str("receipt confirms an unexpected object"),
            Self::ContentMismatch => {
                formatter.write_str("receipt confirms unexpected applied content")
            }
            Self::Store(_) => formatter.write_str("durable receipt record failed"),
        }
    }
}
impl std::error::Error for ReceiptVerificationError {}

/// Verifies one `receipt.applied` plaintext against `expected_signer` and
/// `expected`, then records it exactly once.
///
/// `expected_signer` MUST be the confirming device's principal the caller
/// already expects for this object (never a principal read from the
/// receipt). When `expected_content` is supplied, its digest MUST match the
/// receipt's bound digest.
///
/// # Errors
///
/// Returns [`ReceiptVerificationError::Crypto`] for a malformed or
/// signature-invalid receipt, [`ReceiptVerificationError::ObjectMismatch`]
/// for a valid receipt confirming a different object,
/// [`ReceiptVerificationError::ContentMismatch`] for a content digest
/// mismatch, and [`ReceiptVerificationError::Store`] if the durable record
/// fails.
pub fn verify_and_record_applied_receipt<S: ReceiptStore>(
    store: &mut S,
    expected_signer: Principal,
    expected: ConfirmedObject,
    expected_content: Option<&[u8]>,
    plaintext: &[u8],
) -> Result<(AppliedReceipt, ReceiptOutcome), ReceiptVerificationError> {
    let receipt = verify_receipt_signature(expected_signer, plaintext)
        .map_err(ReceiptVerificationError::Crypto)?;
    if receipt.confirmed != expected {
        return Err(ReceiptVerificationError::ObjectMismatch);
    }
    if let Some(content) = expected_content {
        if receipt.applied_content_digest != content_digest(content) {
            return Err(ReceiptVerificationError::ContentMismatch);
        }
    }
    let outcome = store
        .record(expected)
        .map_err(ReceiptVerificationError::Store)?;
    Ok((receipt, outcome))
}
