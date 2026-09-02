# cofferwire-relay

This crate contains Cofferwire's transport-independent queue state machine. It deliberately does not implement networking, persistent storage or cryptography yet.

Callers must authenticate commands before passing the resulting queue-scoped principal to the state machine. Message payloads are opaque bytes and are expected to be encrypted by a higher layer.

The first implementation exists to make delivery, retry, expiry and ACK behavior executable while the wire and cryptographic profiles are still being specified.

