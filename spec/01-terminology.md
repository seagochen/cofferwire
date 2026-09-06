# Terminology (Draft)

This document defines the terms used by the Cofferwire queue-only protocol core. These definitions describe protocol roles and objects, not Rust APIs, network endpoints or a global account system.

Normative terms such as **MUST**, **MUST NOT**, **SHOULD** and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## Initial scope

The initial interoperable queue-v1 profile carries small asynchronous application messages. Each receiving device has its own independent receive queue. Blob transfer is defined by the separately negotiated `cofferwire-blob/1` profile; account discovery, device enrollment and application-specific synchronization remain outside queue v1. Its frozen scope revision is `CW-SCOPE-QUEUE-V1-2026-09-06`.

- **CW-TERM-001:** A protocol role or identifier defined here MUST NOT be interpreted as a global user identity unless a later application profile explicitly defines that mapping.
- **CW-TERM-002:** Each receiving device MUST use an independent receive queue. A relay MUST NOT infer that separate queues belong to the same user or application identity.

## Participants

### Device

A device is one client installation with its own local state and cryptographic material. Multiple devices controlled by one person are distinct protocol participants.

### Sender

The sender is the queue-scoped principal authorized to submit opaque messages to one queue. It is not necessarily the human or application author represented inside the end-to-end message.

### Recipient

The recipient is the queue-scoped principal authorized to fetch, acknowledge and delete one queue. In the initial profile, the recipient represents one receiving device.

### Relay

A relay is an availability service that stores and forwards opaque messages. It is not trusted to establish application authorship, plaintext integrity or correct delivery history.

## Queue objects

### Queue

A queue is a relay-local, unidirectional mailbox with one sender principal, one recipient principal and explicit resource limits. Queues are independently replaceable and do not form an account directory.

### Queue identifier

A queue identifier selects one relay-local queue. It is opaque to protocol layers that do not operate the queue and does not reveal an application or user identity by definition.

### Queue-scoped principal

A queue-scoped principal is an authenticated actor authorized for a specific
queue role. Version 1 represents it as an Ed25519 public key and proves control
according to `04-cryptographic-profile.md`.

### Message identifier

A message identifier is a sender-chosen idempotency identifier scoped to one queue. Reuse rules are defined in `06-queues.md`.

### Opaque message

An opaque message is the exact byte string accepted by the relay queue layer. The initial profile expects it to contain authenticated end-to-end ciphertext, but the relay does not parse or validate its plaintext semantics.

### Delivery

A delivery is a relay response containing the current queued message. Delivery does not mean that the recipient authenticated, persisted or applied the application message. A message can be delivered more than once until relay ACK or expiry.

## Acknowledgements and receipts

### Relay ACK

A relay ACK is authorization from the queue recipient to delete the current delivered transport message. It is sent only after the recipient has authenticated the ciphertext and durably stored the resulting application message.

### Application receipt

An application receipt is a separate end-to-end message describing application state, such as successful application of an update. It is not a relay ACK and is not interpreted by the relay.

- **CW-TERM-003:** A relay ACK MUST NOT be represented or described as proof that the application accepted or applied a message.
- **CW-TERM-004:** An application receipt MUST travel as an end-to-end authenticated application message and MUST NOT authorize relay deletion implicitly.

## Time and persistence

### Relay time

Relay time is the relay's time value used to evaluate message expiry. Clock source, permitted skew and protocol representation remain open decisions.

### TTL and expiry

TTL is the requested lifetime of a queued message. Expiry is the relay-computed boundary after which the message is unavailable and no longer consumes queue depth.

### Durability boundary

A durability boundary is the storage-engine point after which a successful state change is guaranteed to survive the documented crash model. The relay's successful `SEND` response occurs after this boundary.

### Local durable commit

A local durable commit is the recipient device's persistence boundary for an authenticated application message. It precedes relay ACK:

```text
fetch -> authenticate -> local durable commit -> relay ACK
```

- **CW-TERM-005:** Implementations MUST distinguish the relay durability boundary from the recipient device's local durable commit.

## Open decisions

- wire representations for identifiers, principals, time and errors;
- authentication proof and capability representation;
- clock source, skew policy and TTL bounds;
- device enrollment and queue rotation terminology beyond one existing
  relationship's bootstrap and recovery (`13-offline-bundles.md`);
- application message schema.
