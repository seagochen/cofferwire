macro_rules! bounded_id {
    ($name:ident, $len:literal, $description:literal) => {
        #[doc = $description]
        ///
        /// The wire representation has a fixed byte width; using an array makes
        /// a shorter-or-longer value unrepresentable rather than a runtime check.
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Constructs an identifier from its exact byte representation.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Returns the exact byte representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }
    };
}

bounded_id!(
    RequestId,
    16,
    "A client-chosen response-correlation identifier, unrelated to a message identifier."
);
bounded_id!(
    QueueId,
    32,
    "An opaque identifier for one relay-local queue."
);
bounded_id!(
    MessageId,
    32,
    "A sender-chosen idempotency identifier for one message, scoped to one queue."
);
bounded_id!(
    Principal,
    32,
    "A queue-scoped authenticated actor, not a global user identity."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_exact_bytes() {
        let bytes = [7; 32];
        let request_bytes = [8; 16];
        assert_eq!(
            RequestId::from_bytes(request_bytes).as_bytes(),
            &request_bytes
        );
        assert_eq!(QueueId::from_bytes(bytes).as_bytes(), &bytes);
        assert_eq!(MessageId::from_bytes(bytes).as_bytes(), &bytes);
        assert_eq!(Principal::from_bytes(bytes).as_bytes(), &bytes);
    }

    #[test]
    fn distinct_ids_are_not_equal() {
        assert_ne!(QueueId::from_bytes([1; 32]), QueueId::from_bytes([2; 32]));
    }
}
