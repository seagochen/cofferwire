use crate::error::TypeError;

/// A v1 request command code, per `05-wire-format.md` "Commands".
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum Command {
    /// `CREATE_QUEUE` (1): `CW-QUEUE-008`.
    CreateQueue = 1,
    /// `SEND` (2): `CW-QUEUE-002`, `CW-QUEUE-003`, `CW-QUEUE-007`.
    Send = 2,
    /// `FETCH` (3): `CW-QUEUE-001`, `CW-QUEUE-005`.
    Fetch = 3,
    /// `ACK` (4): `CW-QUEUE-004`.
    Ack = 4,
    /// `DELETE_QUEUE` (5): queue lifecycle (`03-architecture.md`).
    DeleteQueue = 5,
}

impl Command {
    /// Returns the wire command code.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for Command {
    type Error = TypeError;

    /// # Errors
    ///
    /// Returns [`TypeError::UnknownDiscriminant`] when `value` is not a
    /// command code defined by the "Commands" table (`CW-WIRE-025`).
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::CreateQueue),
            2 => Ok(Self::Send),
            3 => Ok(Self::Fetch),
            4 => Ok(Self::Ack),
            5 => Ok(Self::DeleteQueue),
            other => Err(TypeError::UnknownDiscriminant {
                type_name: "Command",
                value: other,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_defined_command() {
        for (code, command) in [
            (1, Command::CreateQueue),
            (2, Command::Send),
            (3, Command::Fetch),
            (4, Command::Ack),
            (5, Command::DeleteQueue),
        ] {
            assert_eq!(Command::try_from(code), Ok(command));
            assert_eq!(command.as_u8(), code);
        }
    }

    #[test]
    fn rejects_command_zero() {
        assert_eq!(
            Command::try_from(0),
            Err(TypeError::UnknownDiscriminant {
                type_name: "Command",
                value: 0,
            })
        );
    }

    #[test]
    fn rejects_command_past_the_last_defined_code() {
        assert_eq!(
            Command::try_from(6),
            Err(TypeError::UnknownDiscriminant {
                type_name: "Command",
                value: 6,
            })
        );
    }
}
