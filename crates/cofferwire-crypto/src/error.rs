/// A cryptographic profile failure that never contains key or plaintext bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// A key did not have a valid canonical encoding.
    InvalidKey,
    /// The authentication proof had the wrong length, profile, algorithm, or signature.
    AuthenticationFailed,
    /// The ciphertext envelope selected a different or malformed profile.
    InvalidEnvelope,
    /// The authenticated ciphertext could not be opened.
    DecryptionFailed,
    /// The plaintext is too large to fit inside a v1 message payload.
    PlaintextTooLarge { max: usize, actual: usize },
    /// The underlying standard construction rejected an otherwise bounded operation.
    EncryptionFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => formatter.write_str("invalid public or private key"),
            Self::AuthenticationFailed => formatter.write_str("request authentication failed"),
            Self::InvalidEnvelope => formatter.write_str("invalid ciphertext envelope"),
            Self::DecryptionFailed => formatter.write_str("ciphertext authentication failed"),
            Self::PlaintextTooLarge { max, actual } => {
                write!(formatter, "plaintext has {actual} bytes; maximum is {max}")
            }
            Self::EncryptionFailed => formatter.write_str("message encryption failed"),
        }
    }
}

impl std::error::Error for CryptoError {}
