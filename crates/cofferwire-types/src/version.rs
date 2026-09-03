use crate::error::TypeError;

/// The wire protocol version carried by a frame's `preamble` (`CW-WIRE-004`).
///
/// `0` is reserved and MUST be rejected by both roles (`CW-WIRE-008`), so
/// it is rejected here at construction rather than left for every caller
/// to check independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Version(u8);

impl Version {
    /// The only protocol version this crate defines commands for.
    pub const CURRENT: Self = Self(1);

    /// Constructs a version from its wire byte.
    ///
    /// # Errors
    ///
    /// Returns [`TypeError::ReservedVersion`] when `value` is `0`.
    pub const fn new(value: u8) -> Result<Self, TypeError> {
        if value == 0 {
            Err(TypeError::ReservedVersion)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_current_version() {
        assert_eq!(Version::new(1), Ok(Version::CURRENT));
        assert_eq!(Version::CURRENT.as_u8(), 1);
    }

    #[test]
    fn accepts_a_future_version_byte() {
        assert_eq!(Version::new(2).map(Version::as_u8), Ok(2));
    }

    #[test]
    fn rejects_reserved_zero() {
        assert_eq!(Version::new(0), Err(TypeError::ReservedVersion));
    }
}
