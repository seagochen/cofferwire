# Cofferwire

Cofferwire is an open, transport-independent protocol for private asynchronous messaging and encrypted object delivery through replaceable, untrusted relays.

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

The specification lives in `spec/`. The first Rust crate, `cofferwire-relay`, makes queue delivery, retry, expiry and ACK behavior executable without prematurely choosing a network binding or cryptographic representation.

## Current implementation

- [`crates/cofferwire-relay`](crates/cofferwire-relay) — transport-independent in-memory reference state machine and SQLite transactional store;
- [`spec/06-queues.md`](spec/06-queues.md) — the draft requirements exercised by its tests.

Networking and cryptographic authentication are intentionally not implemented yet. The durable queue layer is local-only and is not yet a complete relay service.

## Documents

- [PLAN.md](PLAN.md) — milestones and project decisions
- [TESTING.md](TESTING.md) — conformance, interoperability and security validation
- [SECURITY.md](SECURITY.md) — vulnerability reporting and security status
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution rules
- [spec/README.md](spec/README.md) — specification structure
- [spec/01-terminology.md](spec/01-terminology.md) — protocol roles and objects
- [spec/02-threat-model.md](spec/02-threat-model.md) — attackers, trust boundaries and security limits
- [spec/03-architecture.md](spec/03-architecture.md) — component responsibilities and message flows

## License

Copyright and contributions are licensed under the [Apache License 2.0](LICENSE).
