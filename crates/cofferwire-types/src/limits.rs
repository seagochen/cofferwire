use crate::error::TypeError;
use crate::MAX_MESSAGE_BYTES;

/// Per-queue resource limits carried by `CREATE_QUEUE`.
///
/// `max-messages` and `max-message-bytes` are nonzero unsigned integers
/// (`05-wire-format.md` "`CREATE_QUEUE`"); `max-message-bytes` additionally
/// MUST NOT exceed [`MAX_MESSAGE_BYTES`], or `CREATE_QUEUE` fails with
/// `status = LIMIT_OUT_OF_RANGE` (`CW-WIRE-030`). Both bounds are enforced
/// here so every accepted `QueueLimits` can back a `SEND` of exactly its
/// declared `max-message-bytes`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueLimits {
    max_messages: u64,
    max_message_bytes: u64,
}

impl QueueLimits {
    /// Constructs validated queue limits.
    ///
    /// # Errors
    ///
    /// Returns [`TypeError::ZeroValue`] when either argument is `0`, or
    /// [`TypeError::TooLarge`] when `max_message_bytes` exceeds
    /// [`MAX_MESSAGE_BYTES`].
    pub const fn new(max_messages: u64, max_message_bytes: u64) -> Result<Self, TypeError> {
        if max_messages == 0 {
            return Err(TypeError::ZeroValue {
                field: "max_messages",
            });
        }
        if max_message_bytes == 0 {
            return Err(TypeError::ZeroValue {
                field: "max_message_bytes",
            });
        }
        if max_message_bytes > MAX_MESSAGE_BYTES as u64 {
            return Err(TypeError::TooLarge {
                field: "max_message_bytes",
                max: MAX_MESSAGE_BYTES as u64,
                actual: max_message_bytes,
            });
        }
        Ok(Self {
            max_messages,
            max_message_bytes,
        })
    }

    /// Returns the maximum number of queued messages.
    #[must_use]
    pub const fn max_messages(self) -> u64 {
        self.max_messages
    }

    /// Returns the maximum opaque payload size in bytes.
    #[must_use]
    pub const fn max_message_bytes(self) -> u64 {
        self.max_message_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_limits() {
        let limits = QueueLimits::new(4, 1024).expect("valid limits");
        assert_eq!(limits.max_messages(), 4);
        assert_eq!(limits.max_message_bytes(), 1024);
    }

    #[test]
    fn accepts_maximum_message_bytes() {
        let limits = QueueLimits::new(1, MAX_MESSAGE_BYTES as u64).expect("max bound is valid");
        assert_eq!(limits.max_message_bytes(), MAX_MESSAGE_BYTES as u64);
    }

    #[test]
    fn accepts_full_wire_range_for_max_messages() {
        let limits = QueueLimits::new(u64::MAX, 1).expect("full count range is valid");
        assert_eq!(limits.max_messages(), u64::MAX);
    }

    #[test]
    fn rejects_zero_max_messages() {
        assert_eq!(
            QueueLimits::new(0, 1024),
            Err(TypeError::ZeroValue {
                field: "max_messages"
            })
        );
    }

    #[test]
    fn rejects_zero_max_message_bytes() {
        assert_eq!(
            QueueLimits::new(1, 0),
            Err(TypeError::ZeroValue {
                field: "max_message_bytes"
            })
        );
    }

    #[test]
    fn rejects_max_message_bytes_over_bound() {
        assert_eq!(
            QueueLimits::new(1, MAX_MESSAGE_BYTES as u64 + 1),
            Err(TypeError::TooLarge {
                field: "max_message_bytes",
                max: MAX_MESSAGE_BYTES as u64,
                actual: MAX_MESSAGE_BYTES as u64 + 1,
            })
        );
    }
}
