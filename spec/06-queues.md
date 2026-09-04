# Queue Semantics (Draft)

This document records the behavior implemented by the executable queue state
model. The wire format and authentication proof are defined separately by
`05-wire-format.md` and `04-cryptographic-profile.md`; this document does not
define their byte representation or a persistent-storage schema.

## Scope

A queue is a relay-local, unidirectional mailbox with one queue-scoped sender principal and one queue-scoped recipient principal. Principals are not global user identities. Payloads are opaque to the queue layer and are expected to be encrypted and authenticated by a higher layer.

## Initial requirements

- **CW-QUEUE-001:** After accepting a message, a relay MUST make it available to the authorized recipient until the message is acknowledged or expires. Fetching without ACK MUST permit redelivery.
- **CW-QUEUE-002:** Repeating `SEND` with the same queue, message identifier and payload MUST be idempotent and MUST NOT extend the original expiry.
- **CW-QUEUE-003:** Reusing a live message identifier with a different payload MUST fail.
- **CW-QUEUE-004:** An ACK MUST identify the current delivered message. It MUST NOT delete an unfetched message or a different message.
- **CW-QUEUE-005:** A message whose expiry is less than or equal to relay time MUST NOT be delivered and MUST no longer consume queue depth.
- **CW-QUEUE-006:** Only the queue-scoped sender may send. Only the queue-scoped recipient may fetch, acknowledge or delete the queue.
- **CW-QUEUE-007:** A relay MUST enforce its declared per-message byte limit and per-queue message-count limit before accepting a new message.
- **CW-QUEUE-008:** Repeating queue creation with the same identifier and configuration MUST be idempotent. Reusing the identifier with a different configuration MUST fail.

## ACK boundary

The recipient sends a relay ACK only after the ciphertext has been authenticated and the application message has been durably stored locally:

```text
fetch -> authenticate -> durable local commit -> relay ACK
```

Relay ACK authorizes deletion of the queued transport message. It does not prove to the sender that the application accepted or applied the message. An application receipt is a separate end-to-end message.

## Persistence requirement

The in-memory Rust state model defines observable semantics. A durable relay implementation must additionally satisfy:

- **CW-STORE-001:** A successful `SEND` result MUST NOT be returned until the complete message insertion has crossed the storage engine's documented durability boundary. The message MUST be recoverable after restart.
- **CW-STORE-002:** A `SEND` interrupted before that durability boundary MUST NOT expose a partial message after recovery.
- **CW-STORE-003:** ACK validation and deletion MUST be one atomic transaction. After a successful ACK and restart, the acknowledged message MUST remain absent.
- **CW-STORE-004:** Delivery state MUST survive restart so a message fetched before a crash can subsequently be acknowledged. Until ACK commits, the message itself MUST remain recoverable for redelivery.
- **CW-STORE-005:** A persistent database MUST carry an explicit schema version. An implementation MUST reject a newer unknown version without modifying it.
- **CW-STORE-006:** Every command that can change queue state MUST reserve the SQLite writer before reading semantic state or capacity. Concurrent writers therefore observe a serial command order; a capacity race cannot overfill a queue, and reuse of a message identifier resolves deterministically to an idempotent retry or a conflict.
- **CW-STORE-007:** Waiting for another SQLite writer MUST be bounded. The baseline implementation waits at most 250 milliseconds and reports a stable `Busy` storage category when the lock remains unavailable. A caller MAY retry the same authenticated request after backoff.
- **CW-STORE-008:** Expiry cleanup, command validation and the command's state change MUST occur in one transaction using one caller-supplied relay timestamp. Messages whose expiry is less than or equal to that timestamp are removed before capacity or delivery decisions.
- **CW-STORE-009:** Read-only media, exhausted storage, I/O errors and commit failures MUST NOT produce a successful command response. Transaction rollback MUST leave no partially visible queue operation, and a recovered database MUST pass SQLite integrity checking.

The current durable Rust implementation uses an immediate SQLite rollback-journal transaction per command with `synchronous=FULL` and a 250 millisecond busy timeout. Method success is the response boundary: no successful `SEND`, `FETCH`, ACK or queue mutation result is produced before its transaction commits. SQLite recovery supplies the all-before or all-after state when execution stops during a transaction. Storage failures are classified as busy, read-only, full, I/O, corrupt or other while retaining their original SQLite error for diagnostics. Schema version 1 is stored in SQLite's `user_version`; newer values are rejected before connection settings or schema statements are applied.

## Open decisions

- integration of cryptographic verification into a deployable relay service;
- whether delivery remains strictly one-at-a-time on the final wire protocol;
- maximum and minimum TTL values;
- queue rotation and suspension states;
- error-code privacy and authorization-oracle behavior;
- schema migration and long-term database compatibility policy.
