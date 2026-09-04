use cofferwire_types::{RequestId, TypeError, MAX_FRAME_BYTES};

/// A deterministic frame-decoding failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The delimited frame exceeds the protocol-wide bound.
    FrameTooLarge { actual: usize },
    /// The input ended before the current item was complete.
    Truncated { offset: usize },
    /// Protocol version zero is reserved.
    ReservedVersion,
    /// The fixed preamble was readable, but this codec does not implement the version.
    UnsupportedVersion { version: u8, request_id: RequestId },
    /// A CBOR argument used a wider representation than its value requires.
    NonCanonicalArgument { offset: usize },
    /// A forbidden major type or additional-information value was encountered.
    UnexpectedType {
        offset: usize,
        expected: &'static str,
    },
    /// An array did not have the exact required number of elements.
    WrongArrayLength {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    /// A byte string did not have the required fixed length.
    WrongByteStringLength {
        field: &'static str,
        expected: usize,
        actual: u64,
    },
    /// A byte string exceeded its field-specific bound.
    ByteStringTooLarge {
        field: &'static str,
        max: usize,
        actual: u64,
    },
    /// A scalar or discriminator was outside the v1 data model.
    InvalidValue { field: &'static str, value: u64 },
    /// Bytes remained after the one complete frame.
    TrailingBytes { offset: usize },
    /// The decoded values violate a protocol type invariant.
    InvalidProtocolValue(TypeError),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooLarge { actual } => write!(
                formatter,
                "frame of {actual} bytes exceeds the maximum of {MAX_FRAME_BYTES} bytes"
            ),
            Self::Truncated { offset } => write!(formatter, "truncated item at byte {offset}"),
            Self::ReservedVersion => formatter.write_str("protocol version 0 is reserved"),
            Self::UnsupportedVersion { version, .. } => {
                write!(formatter, "unsupported protocol version {version}")
            }
            Self::NonCanonicalArgument { offset } => {
                write!(formatter, "non-canonical CBOR argument at byte {offset}")
            }
            Self::UnexpectedType { offset, expected } => {
                write!(formatter, "expected {expected} at byte {offset}")
            }
            Self::WrongArrayLength {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "{field} array has {actual} elements; expected {expected}"
            ),
            Self::WrongByteStringLength {
                field,
                expected,
                actual,
            } => write!(formatter, "{field} has {actual} bytes; expected {expected}"),
            Self::ByteStringTooLarge { field, max, actual } => {
                write!(formatter, "{field} has {actual} bytes; maximum is {max}")
            }
            Self::InvalidValue { field, value } => {
                write!(formatter, "invalid {field} value {value}")
            }
            Self::TrailingBytes { offset } => {
                write!(
                    formatter,
                    "unexpected trailing bytes starting at byte {offset}"
                )
            }
            Self::InvalidProtocolValue(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<TypeError> for DecodeError {
    fn from(value: TypeError) -> Self {
        Self::InvalidProtocolValue(value)
    }
}
