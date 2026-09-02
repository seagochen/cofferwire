# Cofferwire Specification

This directory will contain the normative, implementation-independent protocol specification.

Specification documents:

```text
00-overview.md
01-terminology.md          protocol roles and objects
02-threat-model.md         attackers, trust boundaries and security limits
03-architecture.md         component responsibilities and message flows
04-cryptographic-profile.md
05-wire-format.md
06-queues.md               executable queue and persistence semantics
07-blobs.md
08-receipts.md
09-transport-bindings.md
10-versioning.md
11-security-considerations.md
12-privacy-considerations.md
```

Normative terms such as **MUST**, **MUST NOT**, **SHOULD** and **MAY** will be used consistently with RFC 2119/RFC 8174 conventions. Every normative requirement will receive a stable conformance ID and a corresponding entry in the test suite.

Until the first wire-format freeze, all documents are drafts and may change incompatibly.
