# Cofferwire Specification

This directory contains the normative, implementation-independent protocol
specification. Queue protocol version 1 is frozen as a small-message-only
profile at scope revision `CW-SCOPE-QUEUE-V1-2026-09-06`. Encrypted blobs use
the independently negotiated draft `cofferwire-blob/1` profile; receipts and
offline bundles are not part of queue v1.

Specification documents:

```text
00-overview.md
01-terminology.md          protocol roles and objects
02-threat-model.md         attackers, trust boundaries and security limits
03-architecture.md         component responsibilities and message flows
04-cryptographic-profile.md fixed relay-command and authenticated HPKE profile
05-wire-format.md          canonical envelope, framing and version negotiation
06-queues.md               executable queue and persistence semantics
07-blobs.md               independent encrypted blob/1 profile
07-blobs.cddl             blob/1 structural frame schema
08-receipts.md
09-transport-bindings.md
10-versioning.md          scope, allocation registry and compatibility rules
11-security-considerations.md
12-privacy-considerations.md
```

Normative terms such as **MUST**, **MUST NOT**, **SHOULD** and **MAY** will be used consistently with RFC 2119/RFC 8174 conventions. Every normative requirement will receive a stable conformance ID and a corresponding entry in the test suite.

`10-versioning.md` is the single registry for versions, commands, statuses,
algorithms and transport identifiers. The queue-v1 normative set listed there
is frozen: incompatible changes require a new queue version. Blob/1 remains a
draft until separately frozen and does not allocate queue-v1 identifiers.
