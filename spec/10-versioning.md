# Versioning and Identifier Registry

This document is the single allocation registry and compatibility policy for
Cofferwire protocol profiles. The immutable queue-v1 scope revision is
`CW-SCOPE-QUEUE-V1-2026-09-06`, accepted by
`docs/adr/0001-version-1-scope.md`.

Normative terms are interpreted as described by RFC 2119 and RFC 8174.

## Registered profiles and normative sets

| profile | version | revision | status | normative documents and artifacts |
|---|---:|---|---|---|
| queue | 1 | `CW-SCOPE-QUEUE-V1-2026-09-06` | scope and allocations frozen; pre-1.0 | `01-terminology.md`, `02-threat-model.md`, `03-architecture.md`, `04-cryptographic-profile.md`, `05-wire-format.md`, `05-wire-format.cddl`, `06-queues.md`, `09-transport-bindings.md`, `vectors/codec-v1.json`, `vectors/crypto-v1.json` |
| blob | 1 | `CW-BLOB-1-DRAFT-2026-09-06` | draft, independent | `07-blobs.md`, `07-blobs.cddl`, `vectors/blob-v1.json` |
| receipts | 1 | `CW-RECEIPT-1-DRAFT-2026-09-06` | draft, independent | `08-receipts.md`, `vectors/receipts-v1.json` |
| offline | 1 | `CW-OFFLINE-1-DRAFT-2026-09-06` | draft, independent | `13-offline-bundles.md`, `vectors/offline-v1.json` |

Queue v1 carries small asynchronous messages only. Blob delivery, application
receipts, and offline bundles are outside its scope. Blob/1 is independently
negotiated and does not extend the queue-v1 frame.

- **CW-VERSION-001:** An implementation claiming queue-v1 conformance MUST
  implement the complete queue-v1 normative set at scope revision
  `CW-SCOPE-QUEUE-V1-2026-09-06` and MUST NOT advertise blob, receipt, or
  offline-bundle behavior as part of that conformance claim.
- **CW-VERSION-002:** A conformance report, interoperability result, or security
  audit MUST identify every profile/version under test and the queue-v1 scope
  revision when queue v1 is included.

## Queue-v1 allocations

| registry | allocated values |
|---|---|
| frame version | `0` reserved; `1` queue v1 |
| direction | `0` request; `1` response |
| command | `1 CREATE_QUEUE`; `2 SEND`; `3 FETCH`; `4 ACK`; `5 DELETE_QUEUE` |
| status | `0 OK`; `1 UNSUPPORTED_VERSION`; `2 MALFORMED_FRAME`; `3 FRAME_TOO_LARGE`; `4 UNKNOWN_COMMAND`; `5 QUEUE_NOT_FOUND`; `6 UNAUTHORIZED`; `7 QUEUE_ID_CONFLICT`; `8 MESSAGE_ID_CONFLICT`; `9 MESSAGE_TOO_LARGE`; `10 QUEUE_FULL`; `11 EXPIRY_OVERFLOW`; `12 ACK_MISMATCH`; `13 NOT_DELIVERED`; `14 AUTH_INVALID`; `15 LIMIT_OUT_OF_RANGE`; `16 AUTH_REPLAY` |
| crypto profile | `0x0001` Cofferwire queue-v1 |
| relay signature | `0x0001` Ed25519 |
| HPKE KEM | `0x0020` DHKEM(X25519, HKDF-SHA-256) |
| HPKE KDF | `0x0001` HKDF-SHA-256 |
| HPKE AEAD | `0x0003` ChaCha20-Poly1305 |
| HTTPS | `POST /v1/frame`; media type `application/cofferwire` |
| WebSocket | `GET /v1/ws`; subprotocol `cofferwire.v1` |

The detailed encoding and semantics remain in the registered normative
documents; this table is the authoritative allocation index.

- **CW-VERSION-003:** An allocated numeric value or transport identifier MUST
  NOT be assigned a different meaning within the same profile version.
- **CW-VERSION-004:** Unallocated queue-v1 commands, statuses, algorithms,
  fields, or trailing array elements MUST be rejected as specified by
  `05-wire-format.md`; their presence is not an ignorable extension.

## Blob/1 allocations

| registry | allocated values |
|---|---|
| profile name/version | `cofferwire-blob/1` |
| frame version | `1` in the blob endpoint namespace |
| command | `1 BEGIN_UPLOAD`; `2 PUT_CHUNK`; `3 COMMIT`; `4 GET_MANIFEST`; `5 GET_CHUNK`; `6 RENEW`; `7 DELETE` |
| status | `0 OK`; `1 UNSUPPORTED_VERSION`; `2 MALFORMED_FRAME`; `3 FRAME_TOO_LARGE`; `4 UNKNOWN_COMMAND`; `5 NOT_FOUND`; `6 UNAUTHORIZED`; `7 ID_CONFLICT`; `8 LIMIT_OUT_OF_RANGE`; `9 CHUNK_CONFLICT`; `10 INCOMPLETE`; `11 IDENTITY_MISMATCH`; `12 EXPIRED`; `13 AUTH_INVALID`; `14 AUTH_REPLAY` |
| content suite | `0x0001` HKDF-SHA-256 / ChaCha20-Poly1305 / SHA-256 |
| capability signature | `0x0001` Ed25519 |
| HTTPS | `POST /blob/v1/frame`; media type `application/cofferwire-blob` |
| WebSocket | `GET /blob/v1/ws`; subprotocol `cofferwire.blob.v1` |

Queue and blob values are different registries. Equal integers across the two
tables do not identify the same command or status.

## Compatibility and change policy

- **CW-VERSION-005:** A peer MUST negotiate and validate the profile name and
  version before decoding profile-specific payload bytes. Support for queue v1
  MUST NOT imply support for blob/1, or vice versa.
- **CW-VERSION-006:** Additive behavior within a frozen version is permitted
  only through an extension point already specified to ignore an unknown value.
  Neither queue v1 nor blob/1 currently defines such an extension point.
- **CW-VERSION-007:** Any change to canonical bytes, authentication coverage,
  field meaning, required behavior, or an existing failure result is breaking
  and MUST allocate a new profile version and new public vectors.
- **CW-VERSION-008:** A deprecated version MUST remain documented and testable
  for at least twelve months after its successor's stable release. A server MAY
  stop enabling it after that window, but MUST NOT reinterpret its identifiers.
- **CW-VERSION-009:** During the compatibility window, a release advertising an
  old version MUST pass that version's frozen vectors and interoperability
  suite. Implementations MAY support multiple versions concurrently through
  explicit negotiation.
- **CW-VERSION-010:** Unknown profiles, versions, commands, algorithms, and
  capabilities MUST fail closed without state mutation. An unsupported version
  response follows that profile's fixed preamble rule when one exists; a peer
  MUST NOT guess another version's payload layout.
- **CW-VERSION-011:** Removing a security-broken version before twelve months
  requires a published security advisory identifying the affected versions,
  reason, replacement, and cutoff date.
