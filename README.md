# Cofferwire

Cofferwire is an open, transport-independent protocol family for private
asynchronous messaging and encrypted object delivery through replaceable,
untrusted relays. The frozen queue protocol version 1 carries small messages;
encrypted objects use the separately negotiated draft `cofferwire-blob/1`
profile.

> **Project status:** design phase with executable in-memory and transactional queue models. No implementation is production-ready, and no security guarantees should be inferred yet.

## Goals

- asynchronous delivery without requiring peers to be online together;
- end-to-end confidentiality and authenticated application data;
- capability-based, unlinkable queues instead of global user identifiers;
- replaceable relays that are not trusted with plaintext or authorship decisions;
- deterministic wire formats and public conformance vectors;
- encrypted blob delivery for larger immutable objects;
- transport independence, including WebSocket, HTTPS and offline files;
- independent, interoperable implementations.

## Non-goals

- a global peer-discovery network or DHT;
- a cryptocurrency, consensus network or globally authoritative ledger;
- defining application semantics such as family-tree permissions;
- claiming that encryption eliminates IP, timing or traffic-analysis metadata;
- making a relay the permanent owner of user data.

## Planned architecture

```text
Application profiles      family sync, messaging, backup
Object layer              signed manifests, versions, receipts
Messaging layer           anonymous queues, retry, deduplication
Blob layer                encrypted chunks, leases, capabilities
Transport bindings        WebSocket/HTTPS, files, local transports
```

The specification lives in `spec/`. The Rust workspace keeps protocol types,
canonical framing, cryptography, client transitions and relay durability in
separate transport-independent crates.

## Current implementation

- [`crates/cofferwire-types`](crates/cofferwire-types) — transport-independent v1 protocol types (bounded identifiers, ciphertext, TTL, version, commands, responses and errors) fixed by [`spec/05-wire-format.md`](spec/05-wire-format.md);
- [`crates/cofferwire-codec`](crates/cofferwire-codec) — deterministic v1 framing and strict, bounded canonical-CBOR decoding;
- [`crates/cofferwire-crypto`](crates/cofferwire-crypto) — the fixed Ed25519 and authenticated RFC 9180 HPKE profile with public vectors;
- [`crates/cofferwire-client`](crates/cofferwire-client) — sender retry and recipient durable-commit-before-ACK state machines over a replaceable transport trait;
- [`crates/cofferwire-relay`](crates/cofferwire-relay) — transport-independent in-memory reference state machine and SQLite transactional store;
- [`crates/cofferwire-test`](crates/cofferwire-test) — structural conformance tests and public-vector harnesses.
- [`apps/cofferwired`](apps/cofferwired) — bounded reference HTTPS/WebSocket
  daemon backed by the SQLite relay.
- [`independent/python`](independent/python) — clean-room Python queue-v1 client
  and durable relay built only from the public specification and vectors.

The network daemon and client crates are reference implementations pending
independent interoperability testing and external security review; they are
not production-ready security claims.

## Documents

- [PLAN.md](PLAN.md) — milestones and project decisions
- [TESTING.md](TESTING.md) — conformance, interoperability and security validation
- [SECURITY.md](SECURITY.md) — vulnerability reporting and security status
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution rules
- [spec/README.md](spec/README.md) — specification structure
- [spec/01-terminology.md](spec/01-terminology.md) — protocol roles and objects
- [spec/02-threat-model.md](spec/02-threat-model.md) — attackers, trust boundaries and security limits
- [spec/03-architecture.md](spec/03-architecture.md) — component responsibilities and message flows
- [spec/04-cryptographic-profile.md](spec/04-cryptographic-profile.md) — fixed relay-authentication and end-to-end encryption profile
- [spec/05-wire-format.md](spec/05-wire-format.md) — canonical envelope, framing and version negotiation
- [spec/09-transport-bindings.md](spec/09-transport-bindings.md) — baseline
  HTTPS/WebSocket mappings and resource bounds
- [spec/10-versioning.md](spec/10-versioning.md) — profile scopes, identifier
  registry and compatibility policy
- [spec/07-blobs.md](spec/07-blobs.md) — independent encrypted blob/1 profile
- [docs/adr/0001-version-1-scope.md](docs/adr/0001-version-1-scope.md) — accepted
  queue-v1 scope decision (`CW-SCOPE-QUEUE-V1-2026-09-06`)

## License

Copyright and contributions are licensed under the [Apache License 2.0](LICENSE).
