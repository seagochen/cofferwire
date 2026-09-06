# ADR 0001: Freeze version 1 as the queue-only profile

- Status: accepted
- Date: 2026-09-06
- Scope revision: `CW-SCOPE-QUEUE-V1-2026-09-06`
- Issues: #14, #15

## Context

The repository already uses protocol version `1` for the queue frame, five
queue commands, seventeen response statuses, the Ed25519/HPKE cryptographic
profile, and the HTTPS/WebSocket bindings. Adding blob transfer, application
receipts, or offline bundles to that namespace would give existing v1 decoders
two incompatible meanings for the same version.

## Decision

Cofferwire protocol version 1 is the small-message, queue-only profile defined
by the normative set recorded in `spec/10-versioning.md`. It does not include
blob transfer, application receipts, or offline bundles.

Encrypted blob delivery is developed as the independently negotiated
`cofferwire-blob/1` profile. Its version, commands, statuses, media type, and
transport identifiers do not allocate or reinterpret queue-v1 values. An
application may use both profiles, but support for either never implies support
for the other.

Application receipts remain ordinary end-to-end queue messages until a later
application-receipt profile is standardized. Offline bundles remain a future
transport/profile and are not a queue-v1 transport binding.

## Rationale

The queue implementation and public vectors already exercise a complete,
bounded 64 KiB contract. Freezing that smaller surface preserves byte-level
interoperability and lets blob availability, resumability, padding, and
capability lifecycles evolve without weakening queue decoders. Separate profile
negotiation also permits deployments to offer queues without large-object
storage.

## Consequences

- Queue-v1 identifiers are governed by `spec/10-versioning.md`; incompatible
  changes require a new queue protocol version.
- Blob/1 can reach conformance independently and is not a version-1.0 release
  gate unless a release explicitly advertises that optional profile.
- M3 depends on this decision and `spec/07-blobs.md`. M4 receipts and offline
  bundles must allocate their own application/profile or transport version.
- M5 interoperability matrices state the profile and scope revision being
  tested. M7 freezes the selected release's registered identifiers; it does not
  silently expand queue v1.
