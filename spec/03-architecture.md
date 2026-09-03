# Architecture (Draft)

This document defines the component boundaries and message flow of the initial Cofferwire queue-only profile. It does not define encoded bytes, cryptographic algorithms or a network binding.

## Profile boundary

The initial profile supports small asynchronous messages. Each receiving device owns an independent unidirectional receive queue. Blob transfer is deferred to a separate profile rather than emulated by exceeding this profile's message limits.

- **CW-ARCH-001:** A relay MUST model each receive queue independently and MUST NOT require a global user account to route queue commands.
- **CW-ARCH-002:** Multi-device fan-out MUST occur above the relay queue layer. The relay MUST NOT infer device grouping or duplicate a message across queues on behalf of an account.

## Components

### Application profile

The application profile defines plaintext message schemas, application authorization, conflict handling and application receipts. Family-tree or messaging semantics do not belong to the core queue protocol.

### Client state machine

The client state machine coordinates identifiers, end-to-end protection, retries, authentication, local persistence and relay ACK. Its semantic state does not depend on a permanent connection.

### Cryptographic profile

The cryptographic profile has two distinct jobs. It authenticates relay
commands against the exact wire bytes exposed by the codec, and it
transforms application messages into end-to-end authenticated opaque
payloads. These operations use separate keys, algorithms, domain
separation and associated data; successful relay-command authentication
does not authenticate or decrypt an application message.

- **CW-ARCH-012:** A transport MUST pass the complete frame to the codec,
  and the codec MUST expose the exact authenticated request bytes and
  opaque `auth` value to the relay-command authenticator. The relay queue
  service MUST receive a queue-scoped principal only after that
  authenticator succeeds. Transport identity, headers or connection state
  MUST NOT substitute for this boundary.

### Codec

The codec maps protocol commands and responses to deterministic bytes and rejects non-canonical or hostile input. It does not perform queue storage or application processing.

### Transport binding

A transport binding carries codec frames over HTTPS, WebSocket, local files or another medium. Replacing the binding does not change identifiers, queue semantics or cryptographic verification.

### Relay queue service

The relay authenticates queue-scoped commands, enforces resource policy and durably stores opaque payloads. It does not decrypt application messages, decide their authorship or generate application receipts.

- **CW-ARCH-003:** Networking, codec, cryptographic, client-state and relay-storage layers MUST expose failures without converting an uncommitted state change into success.
- **CW-ARCH-004:** Transport reconnection or replacement MUST NOT change the meaning of a queue command or create a new application message implicitly.

## Queue provisioning

A receiving device obtains an independent queue identifier and recipient authority. It conveys the corresponding sender authority to an intended sender through invitation or bootstrap material. The representation, authentication and rotation of that material remain open decisions.

The relay stores only queue-scoped authorization and resource policy. It does not need an application account or contact graph.

## Send flow

```text
application message
  -> end-to-end protect for target device
  -> deterministic protocol encoding
  -> transport SEND
  -> verify relay-command authentication and replay state
  -> relay authorization and limits
  -> relay durable commit
  -> successful SEND response
```

- **CW-ARCH-005:** A sender retry for an ambiguous `SEND` outcome MUST reuse the same queue-scoped message identifier and exact opaque payload.
- **CW-ARCH-006:** A successful `SEND` response MUST occur after relay durable commit, regardless of transport binding.

Sending to multiple devices produces one independently protected queue message per target device. The application or client layer performs this fan-out and tracks outcomes independently.

## Receive flow

```text
transport FETCH
  -> verify relay-command authentication and replay state
  -> relay delivery of opaque payload
  -> strict protocol decode
  -> end-to-end authenticate and decrypt
  -> validate application message
  -> local durable commit
  -> relay ACK
  -> relay atomic deletion
```

- **CW-ARCH-007:** A client MUST NOT expose unauthenticated plaintext to the application.
- **CW-ARCH-008:** A client MUST NOT send relay ACK before local durable commit succeeds.
- **CW-ARCH-009:** Failure before relay ACK commits MUST leave the relay message eligible for redelivery until expiry.
- **CW-ARCH-010:** Duplicate delivery MUST NOT imply duplicate application of the same authenticated application message.

Application receipts, when defined, travel through the same end-to-end message path in the reverse logical direction. They do not replace relay ACK.

## State ownership

The sender owns application message construction, target-device selection and retry state. The relay owns only queue availability state. The recipient device owns verification, application deduplication and local durable state.

Queue deletion removes relay availability but cannot prove that a malicious relay erased retained ciphertext. Device removal or user-level revocation requires a later application or recovery profile.

## Failure behavior

- A lost successful `SEND` response produces an idempotent retry, not a second accepted message.
- A crash before recipient local commit produces redelivery and no relay ACK.
- A crash after local commit but before ACK produces redelivery that local deduplication can recognize.
- A crash after ACK commit leaves the transport message absent; application recovery uses local durable state.
- Relay omission or permanent failure requires another relay or transport and cannot be repaired by cryptography alone.

- **CW-ARCH-011:** Each layer MUST preserve enough stable identifiers for the client to distinguish retry or redelivery from a new application event.

## Initial crate boundaries

The planned Rust implementation separates these responsibilities:

- `cofferwire-types`: protocol values and invariants;
- `cofferwire-codec`: deterministic wire encoding and strict parsing;
- `cofferwire-crypto`: end-to-end protection and verification;
- `cofferwire-client`: sender and recipient state machines;
- `cofferwire-relay`: durable opaque queue semantics;
- `cofferwire-test`: public vectors and conformance traces;
- `cofferwired`: reference network relay daemon.

Public Rust APIs are implementation details. Normative behavior is defined by specification text, encoded bytes and conformance vectors.

## Open decisions

- queue invitation and concrete authentication/key-rotation suite;
- canonical wire encoding, framing and version negotiation;
- cryptographic profile and key lifecycle;
- application-message identity and local deduplication representation;
- exact message, TTL and queue limits;
- baseline transport binding and authentication;
- relay replacement and offline bootstrap flows.
