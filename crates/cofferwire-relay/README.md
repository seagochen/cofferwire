# cofferwire-relay

This crate contains Cofferwire's transport-independent queue state machine and a SQLite-backed durable implementation. It deliberately does not implement networking or cryptography yet.

Callers must authenticate commands before passing the resulting queue-scoped principal to the state machine. Message payloads are opaque bytes and are expected to be encrypted by a higher layer.

`Relay` is the in-memory semantic reference. `DurableRelay` executes each command in a SQLite rollback-journal transaction with full synchronous durability. A successful send is returned only after commit, ACK validation and deletion share one transaction, and uncommitted changes are discarded by recovery. The database carries schema version 1 and is refused without modification when its version is newer than this build understands.

The test suite terminates child processes immediately before and after the `SEND`, `FETCH` and ACK commit boundaries, then reopens the same database and runs SQLite integrity and queue-state checks.
