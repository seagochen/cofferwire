/// Relay time in whole seconds, per `CW-WIRE-023`.
///
/// Clock source and permitted skew are open decisions (`01-terminology.md`
/// "Relay time"); this type only fixes the wire representation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Constructs a timestamp from seconds.
    #[must_use]
    pub const fn from_secs(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the timestamp as seconds.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Adds a TTL, returning `None` on overflow (`status = EXPIRY_OVERFLOW`).
    #[must_use]
    pub const fn checked_add(self, ttl: Ttl) -> Option<Self> {
        match self.0.checked_add(ttl.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// A message lifetime in whole seconds, per `CW-WIRE-023`.
///
/// The wire representation is a full `u64`: `CW-WIRE-029`'s worked
/// `SEND` size calculation reserves a maximum-width `ttl` of
/// `2^64 - 1`, and version 1 defines no minimum. A relay or application
/// policy MAY impose a narrower bound (for example, rejecting `0`); that
/// policy decision belongs to the layer enforcing it, not to this wire
/// type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ttl(u64);

impl Ttl {
    /// Constructs a lifetime from seconds.
    #[must_use]
    pub const fn from_secs(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the lifetime as seconds.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_seconds() {
        assert_eq!(Timestamp::from_secs(42).as_secs(), 42);
        assert_eq!(Ttl::from_secs(42).as_secs(), 42);
    }

    #[test]
    fn checked_add_computes_expiry() {
        let now = Timestamp::from_secs(1_000);
        let ttl = Ttl::from_secs(60);
        assert_eq!(now.checked_add(ttl), Some(Timestamp::from_secs(1_060)));
    }

    #[test]
    fn checked_add_reports_overflow() {
        let now = Timestamp::from_secs(u64::MAX);
        let ttl = Ttl::from_secs(1);
        assert_eq!(now.checked_add(ttl), None);
    }

    #[test]
    fn maximum_width_ttl_is_representable() {
        assert_eq!(Ttl::from_secs(u64::MAX).as_secs(), u64::MAX);
    }
}
