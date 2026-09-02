# Queue Semantics (Draft)

This document records the behavior implemented by the first executable queue state model. It is a draft and does not yet define a wire format, authentication proof or persistent-storage schema.

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

The in-memory Rust state model defines observable semantics only. A durable relay implementation must make message acceptance and ACK deletion atomic across crashes. A successful acceptance response must not be emitted before the relay reaches its documented durability boundary.

## Open decisions

- cryptographic representation and verification of queue-scoped principals;
- whether delivery remains strictly one-at-a-time on the final wire protocol;
- maximum and minimum TTL values;
- queue rotation and suspension states;
- error-code privacy and authorization-oracle behavior;
- persistent transaction and recovery format.

