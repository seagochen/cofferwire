# Cofferwire Project Plan

## Mission

Define a small, open protocol and build an interoperable Rust implementation for private asynchronous messages and encrypted objects. Relays provide availability, not trust. Correctness must come from cryptographic verification and explicit protocol state machines.

## Design principles

1. **Specify before optimizing.** Wire behavior, failure behavior and security assumptions are normative.
2. **Do not invent cryptography.** Use reviewed standards and publish algorithm identifiers and test vectors.
3. **Assume relay compromise.** A relay may inspect, replay, reorder, omit, retain or corrupt traffic.
4. **Avoid global identifiers.** Queue and capability credentials are scoped and replaceable.
5. **Make retries safe.** Commands and application objects are idempotent or explicitly deduplicated.
6. **Separate acknowledgements.** Transport deletion ACKs and signed application receipts have different meanings.
7. **Keep transports replaceable.** Message semantics cannot depend on WebSocket ordering, latency or permanent connectivity.
8. **Prove interoperability.** A second independent implementation is required before version 1.0.
9. **State privacy limits honestly.** Encryption does not by itself hide IP addresses, timing, size or access correlation.

## Planned components

```text
spec/                   normative protocol specification
crates/cofferwire-types protocol types and invariants
crates/cofferwire-codec deterministic encoding and framing
crates/cofferwire-crypto cryptographic profile and key handling
crates/cofferwire-client queue and blob client state machines
crates/cofferwire-relay  untrusted queue/blob relay library
crates/cofferwire-test   conformance runner and public vectors
apps/cofferwired         reference relay daemon
apps/cofferwire-cli      diagnostic and interoperability CLI
```

Names may change before the first wire-format freeze. Public Rust APIs are not the protocol; encoded bytes and normative behavior are.

## Milestones

### M0 — Project and governance foundation

- publish scope, terminology, contribution rules and license;
- define specification change and versioning processes;
- create an architectural decision record template;
- decide protocol identifiers, URI form and WebSocket subprotocol name;
- document compatibility boundaries with SimpleX SMP/XFTP and other prior art.

**Exit:** reviewers can tell what Cofferwire is, what it is not and how a normative change is accepted.

### M1 — Threat model and protocol core

- enumerate relay, network, sender, recipient and device-compromise threats;
- define identities, queue-scoped keys, capabilities and object identifiers;
- select the cryptographic profile from established standards;
- define canonical encoding, framing, size limits and version negotiation;
- publish initial positive and negative cryptographic vectors.

**Exit:** independent code can encode, decode, sign, encrypt and reject the same vectors byte-for-byte.

### M2 — Asynchronous queue MVP

- specify queue creation, securing, sending, fetching, ACK, rotation and deletion;
- define idempotency, duplicate delivery, expiry, quotas and error codes;
- implement the Rust codec, client state machine and durable relay;
- make ACK deletion crash-safe and atomic;
- support a WebSocket/HTTPS baseline binding.

**Exit:** two clients exchange encrypted messages while never online together; retries, crashes and duplicate delivery do not lose accepted messages.

### M3 — Encrypted blob delivery

- separate ciphertext identity from access capability;
- specify chunking, padding buckets, upload commit, download, renewal and deletion;
- define leases/TTL as availability policy rather than ownership;
- implement resumable upload and integrity-checked download;
- prevent partial uploads from becoming visible.

**Exit:** large objects survive interrupted transfers and are accepted only when every committed chunk and manifest verifies.

### M4 — Receipts, relay replacement and recovery

- define signed application receipts such as `receipt.applied`;
- define invitation/bootstrap material and multiple relay hints;
- specify relay rotation without changing application identity;
- add local export/import as a complete offline transport;
- document recovery when notifications or relays disappear.

**Exit:** a client can recover missed updates through another relay or an offline bundle without changing application semantics.

### M5 — Conformance and independent interoperability

- map every normative requirement to conformance test IDs;
- publish language-neutral vectors and state-machine traces;
- run Rust client ↔ Rust relay tests;
- build or commission a minimal independent implementation in another language;
- run the full cross-implementation matrix.

**Exit:** the independent client and relay interoperate in both directions, including failures and version negotiation.

### M6 — Family-tree application profile

- define how family-tree bundles and signed receipts use Cofferwire;
- integrate the family-tree project without adding family semantics to the core protocol;
- validate long-offline members, history recovery and relay replacement;
- collect operational metrics that do not expose application content.

**Exit:** real family-tree updates synchronize across at least three devices and two independently operated relays.

### M7 — Security review and version 1.0

- complete parser fuzzing, state-model checking and adversarial network tests;
- commission external cryptography/protocol review;
- resolve all critical/high findings and publish the review and response;
- freeze version 1 wire identifiers and compatibility rules;
- publish reproducible release artifacts and a security support policy.

**Exit:** all release gates in `TESTING.md` pass and no unresolved critical/high security issue remains.

### M8 — Optional encrypted-storage profile

- define durable signed manifests, version graphs and multi-device conflicts;
- define replication targets, lease renewal and garbage collection;
- define sharing, future-access revocation and key rotation;
- keep durable storage separate from temporary message delivery.

**Exit:** storage behavior is independently specified and does not change the version 1 messaging wire contract.

## Decisions required before coding the wire protocol

- exact attacker capabilities and metadata privacy target;
- exact cryptographic suites and algorithm-agility limits;
- deterministic encoding rules and extension mechanism;
- per-recipient queue model and multi-device behavior;
- relay persistence, quota and abuse-control contract;
- backward-compatibility window and deprecation process;
- whether the first release includes blobs or queues only.

## Definition of done

Cofferwire is not complete merely because the reference implementation works. Version 1 is complete only when:

- the normative specification is self-contained;
- each `MUST` has at least one conformance test;
- public positive and negative vectors are stable;
- independent implementations interoperate in both client and relay roles;
- crash recovery, expiry, duplicates, reordering and partitions are tested;
- security and metadata limitations are documented;
- an external security review has no unresolved critical/high findings;
- upgrade and version-negotiation behavior is demonstrated;
- the family-tree application completes an end-to-end pilot without protocol-specific exceptions.

