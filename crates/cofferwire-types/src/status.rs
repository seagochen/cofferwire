use crate::error::TypeError;

/// A v1 response status code, per `05-wire-format.md` "Status codes".
///
/// Codes 5-13 correspond 1:1 to the executable relay model's queue-state
/// errors (`CW-WIRE-028`); the remaining codes are wire- or
/// authentication-level and have no relay-state equivalent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Status {
    /// `OK` (0): success.
    Ok = 0,
    /// `UNSUPPORTED_VERSION` (1): see `CW-WIRE-009`.
    UnsupportedVersion = 1,
    /// `MALFORMED_FRAME` (2): violates `CW-WIRE-001`-`007`, `-012`-`014`, `-026`.
    MalformedFrame = 2,
    /// `FRAME_TOO_LARGE` (3): exceeds `CW-WIRE-020`.
    FrameTooLarge = 3,
    /// `UNKNOWN_COMMAND` (4): see `CW-WIRE-025`.
    UnknownCommand = 4,
    /// `QUEUE_NOT_FOUND` (5): no queue with `queue-id`.
    QueueNotFound = 5,
    /// `UNAUTHORIZED` (6): authenticated principal not authorized for the role.
    Unauthorized = 6,
    /// `QUEUE_ID_CONFLICT` (7): `queue-id` reused with a different configuration.
    QueueIdConflict = 7,
    /// `MESSAGE_ID_CONFLICT` (8): `message-id` reused with a different payload.
    MessageIdConflict = 8,
    /// `MESSAGE_TOO_LARGE` (9): payload exceeds the queue's `max-message-bytes`.
    MessageTooLarge = 9,
    /// `QUEUE_FULL` (10): queue at its `max-messages` limit.
    QueueFull = 10,
    /// `EXPIRY_OVERFLOW` (11): `now + ttl` overflows the timestamp representation.
    ExpiryOverflow = 11,
    /// `ACK_MISMATCH` (12): acknowledged `message-id` is not the current message.
    AckMismatch = 12,
    /// `NOT_DELIVERED` (13): current message has not been fetched.
    NotDelivered = 13,
    /// `AUTH_INVALID` (14): `auth` missing, malformed, or fails verification.
    AuthInvalid = 14,
    /// `LIMIT_OUT_OF_RANGE` (15): queue limit is zero or exceeds a v1 protocol bound.
    LimitOutOfRange = 15,
    /// `AUTH_REPLAY` (16): conflicting or stale authenticated request.
    AuthReplay = 16,
}

impl Status {
    /// Returns the wire status code.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns `true` for [`Status::Ok`].
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl TryFrom<u8> for Status {
    type Error = TypeError;

    /// # Errors
    ///
    /// Returns [`TypeError::UnknownDiscriminant`] when `value` is not a
    /// status code defined by the "Status codes" table (`CW-WIRE-028`).
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::MalformedFrame),
            3 => Ok(Self::FrameTooLarge),
            4 => Ok(Self::UnknownCommand),
            5 => Ok(Self::QueueNotFound),
            6 => Ok(Self::Unauthorized),
            7 => Ok(Self::QueueIdConflict),
            8 => Ok(Self::MessageIdConflict),
            9 => Ok(Self::MessageTooLarge),
            10 => Ok(Self::QueueFull),
            11 => Ok(Self::ExpiryOverflow),
            12 => Ok(Self::AckMismatch),
            13 => Ok(Self::NotDelivered),
            14 => Ok(Self::AuthInvalid),
            15 => Ok(Self::LimitOutOfRange),
            16 => Ok(Self::AuthReplay),
            other => Err(TypeError::UnknownDiscriminant {
                type_name: "Status",
                value: other,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: [(u8, Status); 17] = [
        (0, Status::Ok),
        (1, Status::UnsupportedVersion),
        (2, Status::MalformedFrame),
        (3, Status::FrameTooLarge),
        (4, Status::UnknownCommand),
        (5, Status::QueueNotFound),
        (6, Status::Unauthorized),
        (7, Status::QueueIdConflict),
        (8, Status::MessageIdConflict),
        (9, Status::MessageTooLarge),
        (10, Status::QueueFull),
        (11, Status::ExpiryOverflow),
        (12, Status::AckMismatch),
        (13, Status::NotDelivered),
        (14, Status::AuthInvalid),
        (15, Status::LimitOutOfRange),
        (16, Status::AuthReplay),
    ];

    #[test]
    fn round_trips_every_defined_status() {
        for (code, status) in TABLE {
            assert_eq!(Status::try_from(code), Ok(status));
            assert_eq!(status.as_u8(), code);
        }
    }

    #[test]
    fn only_ok_reports_success() {
        for (code, status) in TABLE {
            assert_eq!(status.is_ok(), code == 0);
        }
    }

    #[test]
    fn rejects_status_past_the_last_defined_code() {
        assert_eq!(
            Status::try_from(17),
            Err(TypeError::UnknownDiscriminant {
                type_name: "Status",
                value: 17,
            })
        );
    }
}
