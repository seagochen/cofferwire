use crate::error::TypeError;
use crate::MAX_AUTH_BYTES;

/// The `auth` byte string carried by every request frame (`CW-WIRE-014`).
///
/// Zero length remains representable at the structural wire-codec layer for
/// negative tests and profile-independent parsing. The adopted v1
/// cryptographic profile requires exactly 68 bytes and rejects empty auth.
/// This type fixes only the wire-level bound, not verification.
///
/// `Auth` may carry a signature, MAC or capability token, so its `Debug`
/// implementation prints only its length, never its bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct Auth(Vec<u8>);

impl Auth {
    /// Constructs an `auth` value from its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TypeError::TooLarge`] when `bytes` exceeds
    /// [`MAX_AUTH_BYTES`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, TypeError> {
        if bytes.len() > MAX_AUTH_BYTES {
            return Err(TypeError::TooLarge {
                field: "auth",
                max: MAX_AUTH_BYTES as u64,
                actual: bytes.len() as u64,
            });
        }
        Ok(Self(bytes))
    }

    /// Constructs an empty structural `auth` value for codec and negative tests.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Returns the `auth` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the value, returning its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the `auth` length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when `auth` is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Auth")
            .field("len", &self.0.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_auth_is_valid() {
        assert!(Auth::empty().is_empty());
        assert!(Auth::new(Vec::new())
            .expect("empty auth is valid")
            .is_empty());
    }

    #[test]
    fn accepts_maximum_size_auth() {
        let auth = Auth::new(vec![0; MAX_AUTH_BYTES]).expect("max-size auth is valid");
        assert_eq!(auth.len(), MAX_AUTH_BYTES);
    }

    #[test]
    fn rejects_oversized_auth() {
        assert_eq!(
            Auth::new(vec![0; MAX_AUTH_BYTES + 1]),
            Err(TypeError::TooLarge {
                field: "auth",
                max: MAX_AUTH_BYTES as u64,
                actual: (MAX_AUTH_BYTES + 1) as u64,
            })
        );
    }

    #[test]
    fn debug_does_not_print_contents() {
        let auth = Auth::new(b"signature-bytes".to_vec()).expect("auth is valid");
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("signature"));
        assert!(rendered.contains("15"));
    }
}
