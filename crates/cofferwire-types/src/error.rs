/// A construction-time protocol invariant violation.
///
/// Every fallible constructor in this crate returns this single error type
/// so that a caller can match on one shared vocabulary instead of a
/// different error enum per bounded field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypeError {
    /// Protocol version `0` was supplied; it is reserved and MUST be
    /// rejected by both roles (`CW-WIRE-008`).
    ReservedVersion,
    /// A field that MUST be nonzero was constructed with `0`.
    ZeroValue {
        /// The name of the rejected field.
        field: &'static str,
    },
    /// A bounded field exceeded its maximum permitted size.
    TooLarge {
        /// The name of the rejected field.
        field: &'static str,
        /// The maximum permitted value, inclusive.
        max: u64,
        /// The value that was rejected.
        actual: u64,
    },
    /// [`crate::Status::Ok`] was used to construct an error response.
    SuccessStatusForErrorResponse,
    /// A wire-level discriminant (a command, status or outcome code) did
    /// not match any value defined for its type.
    UnknownDiscriminant {
        /// The Rust type name the discriminant was decoded against.
        type_name: &'static str,
        /// The rejected discriminant byte.
        value: u8,
    },
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReservedVersion => {
                write!(formatter, "protocol version 0 is reserved")
            }
            Self::ZeroValue { field } => {
                write!(formatter, "{field} must not be zero")
            }
            Self::TooLarge { field, max, actual } => {
                write!(
                    formatter,
                    "{field} of {actual} bytes exceeds the maximum of {max} bytes"
                )
            }
            Self::SuccessStatusForErrorResponse => {
                formatter.write_str("an error response must have a nonzero status")
            }
            Self::UnknownDiscriminant { type_name, value } => {
                write!(formatter, "{value} is not a valid {type_name} discriminant")
            }
        }
    }
}

impl std::error::Error for TypeError {}
