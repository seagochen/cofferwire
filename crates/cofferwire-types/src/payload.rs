use crate::error::TypeError;
use crate::MAX_MESSAGE_BYTES;

/// The opaque message byte string carried by `SEND`/`FETCH` (`CW-WIRE-024`).
///
/// This document does not constrain its contents; the relay does not parse
/// or validate it and this crate treats it as expected end-to-end
/// ciphertext. Its length is bounded by the protocol-wide
/// [`MAX_MESSAGE_BYTES`] regardless of any smaller per-queue limit a relay
/// configures.
///
/// `Payload` may carry authenticated ciphertext, so its `Debug`
/// implementation prints only its length, never its bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct Payload(Vec<u8>);

impl Payload {
    /// Constructs a payload from opaque bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TypeError::TooLarge`] when `bytes` exceeds
    /// [`MAX_MESSAGE_BYTES`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, TypeError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(TypeError::TooLarge {
                field: "payload",
                max: MAX_MESSAGE_BYTES as u64,
                actual: bytes.len() as u64,
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the opaque bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the payload, returning its opaque bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the payload length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Payload")
            .field("len", &self.0.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_empty_payload() {
        let payload = Payload::new(Vec::new()).expect("empty payload is valid");
        assert!(payload.is_empty());
    }

    #[test]
    fn accepts_maximum_size_payload() {
        let payload = Payload::new(vec![0; MAX_MESSAGE_BYTES]).expect("max-size payload is valid");
        assert_eq!(payload.len(), MAX_MESSAGE_BYTES);
    }

    #[test]
    fn rejects_oversized_payload() {
        assert_eq!(
            Payload::new(vec![0; MAX_MESSAGE_BYTES + 1]),
            Err(TypeError::TooLarge {
                field: "payload",
                max: MAX_MESSAGE_BYTES as u64,
                actual: (MAX_MESSAGE_BYTES + 1) as u64,
            })
        );
    }

    #[test]
    fn debug_does_not_print_contents() {
        let payload = Payload::new(b"secret ciphertext".to_vec()).expect("payload is valid");
        let rendered = format!("{payload:?}");
        assert!(!rendered.contains("secret"));
        assert!(rendered.contains("17"));
    }
}
