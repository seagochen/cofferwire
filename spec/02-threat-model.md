# Threat Model (Draft)

This document defines the initial security assumptions for the Cofferwire queue-only profile. It describes what the protocol must tolerate and what it does not promise. Concrete algorithms remain the responsibility of the cryptographic profile.

## Protected assets

The protocol aims to protect:

- application message confidentiality and integrity;
- application authorship evidence as defined by the v1 cryptographic profile;
- queue authorization credentials and device private key material;
- accepted-message availability until relay ACK or expiry;
- consistent interpretation of protocol bytes across implementations.

## Trust boundaries

Recipient devices trust their own cryptographic implementation and durable local storage while those components remain uncompromised. Senders trust their own corresponding components. A relay is outside the end-to-end trust boundary.

- **CW-THREAT-001:** Clients MUST treat all relay-provided payloads, metadata, ordering and error responses as attacker-controlled input.
- **CW-THREAT-002:** End-to-end authenticity and confidentiality MUST NOT depend on relay honesty or transport-channel encryption alone.

## Relay adversary

A malicious or compromised relay can:

- observe queue access time, source network information, message length, TTL, frequency and connection lifetime;
- delay, drop, replay, reorder, duplicate or selectively deliver messages;
- return stale, fabricated or inconsistent queue responses;
- correlate operations that use the same queue or connection;
- retain ciphertext after ACK or expiry despite the protocol's availability semantics;
- deny service, lie about capacity or stop operating.

The cryptographic profile prevents a relay without the required end-to-end key
material from learning plaintext or forging an authenticated application
message, subject to its documented endpoint-compromise and metadata limits.

- **CW-THREAT-003:** A recipient MUST authenticate an end-to-end message before making its contents available to the application.
- **CW-THREAT-004:** A recipient MUST NOT send relay ACK for a message that failed end-to-end authentication.
- **CW-THREAT-005:** Clients MUST tolerate replay, duplication and reordering without treating relay behavior as proof of a new application event.

## Network adversary

An active network adversary can observe, block, replay, inject and modify traffic and can impersonate a network endpoint when transport authentication fails. Transport security reduces exposure on a connection but does not replace end-to-end message protection.

- **CW-THREAT-006:** Every network-facing parser MUST reject malformed, non-canonical and over-limit input before performing unbounded allocation or expensive unauthenticated work.
- **CW-THREAT-007:** Failure of transport authentication MUST NOT expose queue credentials or cause plaintext processing.

## Endpoint compromise

Compromise of a sender can expose messages and credentials available to that sender and can create valid malicious messages within its authority. Compromise of one recipient device can expose that device's queued and locally stored messages and its queue credentials.

Independent per-device queues limit operational coupling, but they do not by themselves provide post-compromise security, key recovery or revocation.

- **CW-THREAT-008:** Compromise of one device credential MUST NOT automatically authorize access to another device's independent queue.
- **CW-THREAT-009:** Implementations MUST NOT claim recovery from endpoint compromise unless a later ratchet, rotation or recovery profile defines and tests that property.

## Crash and storage adversary

Processes can stop at any instruction boundary. Storage can report I/O errors, become read-only or run out of capacity. Power loss can occur around a commit boundary.

- **CW-THREAT-010:** A relay MUST NOT report successful `SEND` before the accepted message crosses its documented durability boundary.
- **CW-THREAT-011:** A recipient MUST NOT issue relay ACK before the authenticated application message crosses its local durable commit boundary.
- **CW-THREAT-012:** Storage failure MUST produce failure or an unambiguous retry outcome, never a false success with partial committed state.

## Metadata and privacy limits

The initial profile does not hide IP addresses, queue access, timing, message length, TTL or traffic volume from the relay. Independent opaque queues reduce explicit global identity, but repeated access can still be correlated.

- **CW-THREAT-013:** Documentation and user-facing claims MUST distinguish payload confidentiality from metadata privacy and anonymity.
- **CW-THREAT-014:** Implementations MUST NOT claim sender anonymity, relationship anonymity or traffic-analysis resistance solely because payloads and queue identifiers are opaque.

## Availability limits

No protocol can force a malicious relay or network to deliver data. Cofferwire can detect invalid authenticated content and make retries safe, but omission and permanent denial of service require relay replacement or another transport.

## Out of scope for the initial queue profile

- blob confidentiality, chunk integrity and partial-upload visibility, which
  are defined separately by `cofferwire-blob/1` in `07-blobs.md`;
- global account discovery or contact directories;
- traffic padding, mixing, cover traffic or anonymous network routing;
- recovery from a fully compromised endpoint;
- prevention of ciphertext retention by a malicious relay;
- application authorization and conflict-resolution semantics;
- protection against denial of service by every authorized principal.

## Open decisions

- a future post-quantum or post-compromise-secure profile and recovery mechanism;
- padding buckets and metadata-reduction targets;
- rate limits and proof-of-work or other abuse controls;
- transport authentication and credential presentation;
- clock-skew and expiry-race policy.
