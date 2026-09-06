# Encrypted Blob Delivery Profile (Draft)

This document defines the implementation-independent `cofferwire-blob/1`
profile for immutable encrypted objects larger than a queue-v1 message. It is a
separate version space from the queue protocol. A relay is an untrusted
availability service: it sees ciphertext sizes and access patterns, cannot
decrypt content, and cannot prove physical erasure.

Normative terms are interpreted as described by RFC 2119 and RFC 8174. All
integers in fixed binary structures are unsigned big-endian integers.

## Limits and terms

`object key` is a fresh 32-byte content secret. `object salt` is a fresh
16-byte public random value. Neither is an access capability. `blob-id` is the
SHA-256 identity of a committed ciphertext manifest. An `upload-id` is a fresh
32-byte staging identifier. Upload, download, renew, and delete capabilities
are four independent Ed25519 key pairs; the 32-byte public key is the wire
capability identifier and possession of the private seed authorizes only its
named operation. A committed availability grant is the four capability public
keys plus one lease attached to immutable bytes. Multiple grants may reference
the same blob ID without changing its ciphertext identity.

```text
MIN_PADDED_BYTES = 64
MAX_PADDED_BYTES = 1073741824       ; 2^30
MIN_CHUNK_BYTES  = 32
MAX_CHUNK_BYTES  = 1048576          ; 2^20
MAX_CHUNKS       = 32768             ; 2^15; keeps the manifest frame bounded
MAX_BLOB_FRAME_BYTES = 1049600
```

- **CW-BLOB-001:** An object key, object salt, upload ID, and all four
  capability key pairs MUST be generated independently with a CSPRNG. An
  implementation MUST NOT derive a relay capability from the object key or
  include the object key in a relay request.
- **CW-BLOB-002:** A chunk size MUST be a power of two in the inclusive range
  `MIN_CHUNK_BYTES..MAX_CHUNK_BYTES`. The padded size MUST be a power of two in
  `MIN_PADDED_BYTES..MAX_PADDED_BYTES`, MUST be divisible by the chunk size, and
  `chunk-count = padded-size / chunk-size` MUST NOT exceed `MAX_CHUNKS`.

## Content protection, padding, and identity

Let `N` be the plaintext byte length. The producer forms this padded plaintext
stream:

```text
uint64be(N) || plaintext || random-padding
```

The stream length is the smallest permitted power-of-two padded size that is
at least `N + 8`. Padding bytes come from a CSPRNG and have no semantic value.

- **CW-BLOB-023:** A producer MUST reject `N > MAX_PADDED_BYTES - 8`, MUST
  encode the exact stream above, and MUST fill every padding byte from a CSPRNG.

The content suite identifier is `0x0001`. Its 32-byte AEAD key is:

```text
HKDF-SHA-256(
  salt = object-salt,
  IKM  = object-key,
  info = ASCII("cofferwire blob key v1") || 0x00,
  L    = 32)
```

Split the padded stream into equal `chunk-size` plaintext chunks. Chunk `i`
uses RFC 8439 ChaCha20-Poly1305 with nonce `uint32be(0) || uint64be(i)` and:

```text
AAD = ASCII("cofferwire blob chunk v1") || 0x00
   || uint16be(profile=1) || uint16be(suite=1) || object-salt
   || uint64be(padded-size) || uint32be(chunk-size)
   || uint32be(chunk-count) || uint32be(i)
```

Each ciphertext chunk is exactly `chunk-size + 16` bytes. Its digest is
`SHA-256(ciphertext-chunk)`.

- **CW-BLOB-003:** Producers MUST use a new object key and salt for every
  object, MUST use each chunk index exactly once, and MUST authenticate the
  exact AAD above. Consumers MUST authenticate every chunk before releasing any
  plaintext and MUST reject a repeated, missing, reordered, or out-of-range
  chunk.
- **CW-BLOB-004:** After all chunks authenticate, a consumer MUST concatenate
  their plaintext, parse `N`, require `N <= padded-size - 8`, return exactly the
  following `N` bytes, and discard all remaining padding. It MUST NOT expose
  partial plaintext on any failure.

The canonical manifest is this fixed binary structure; hashes occur in index
order and no trailing bytes are allowed:

```text
magic             4 bytes = ASCII("CWB1")
profile           uint16 = 1
content-suite     uint16 = 1
object-salt       16 bytes
padded-size       uint64
chunk-size        uint32
chunk-count       uint32
chunk-digests     chunk-count * 32 bytes
```

The committed identity is:

```text
blob-id = SHA-256(ASCII("cofferwire blob identity v1") || 0x00 || manifest)
```

- **CW-BLOB-005:** A manifest MUST satisfy all limit equations, contain exactly
  `40 + 32 * chunk-count` bytes, and select only registered profile and suite
  values. Unknown values or trailing bytes MUST be rejected.
- **CW-BLOB-006:** A relay and consumer MUST recompute every ciphertext digest
  and the blob ID. A mismatch MUST fail closed. Blob identity covers ciphertext
  and public layout metadata, not the access capabilities or lease.
- **CW-BLOB-007:** Once committed, the manifest and chunks for a blob ID MUST be
  immutable. Reusing a blob ID for different bytes MUST fail with
  `ID_CONFLICT`. A relay MAY deduplicate the immutable bytes for identical blob
  IDs, but MUST keep each committed grant's capabilities and lease independent.

The object key and blob ID may be carried in an end-to-end protected queue
message or offline application material. Relay capabilities are conveyed only
to principals that need their specific operation. The blob profile does not
standardize that end-to-end descriptor.

## Frame and authorization

A blob frame uses the immutable 17-byte preamble from queue v1 (`version` byte
then 16-byte request ID), but it is carried only on a registered blob transport
identifier. The remaining request frame is canonical CBOR:

```text
[0, command, body] || auth
auth = bstr .size 68
auth-content = uint16be(profile=1) || uint16be(signature=1)
             || Ed25519-signature
```

The signature input is
`ASCII("cofferwire blob request v1") || 0x00 || preamble || payload`, where
`payload` is the exact received CBOR request array and excludes `auth`.
Responses are `[1, command, status, body]` and carry no `auth`.

- **CW-BLOB-024:** A blob frame MUST use only canonical unsigned integers,
  definite byte strings and definite arrays under CW-WIRE-001–003, MUST match
  `07-blobs.cddl`, and MUST NOT exceed `MAX_BLOB_FRAME_BYTES`. Unknown commands,
  statuses, extra fields, trailing bytes and non-canonical encodings MUST be
  rejected without state mutation.

- **CW-BLOB-008:** A relay MUST verify the signature against the capability
  public key in the command body before lookup, resource work, or mutation. A
  malformed or invalid proof returns `AUTH_INVALID`; a valid proof for the
  wrong capability role returns `UNAUTHORIZED`.
- **CW-BLOB-009:** The relay MUST durably reserve `(capability-id, request-id)`
  and atomically record the response with any command effect. An exact retry
  returns that response; conflicting reuse returns `AUTH_REPLAY` with no state
  mutation.

## Commands and bodies

| code | command | request body | successful response body |
|---:|---|---|---|
| 1 | `BEGIN_UPLOAD` | `[upload-id, upload-cap, download-cap, renew-cap, delete-cap, manifest, ttl]` | `[outcome]` (`0` created, `1` identical retry) |
| 2 | `PUT_CHUNK` | `[upload-id, upload-cap, index, ciphertext-chunk]` | `[outcome]` (`0` stored, `1` identical retry) |
| 3 | `COMMIT` | `[upload-id, upload-cap, blob-id]` | `[expires-at]` |
| 4 | `GET_MANIFEST` | `[blob-id, download-cap]` | `[manifest, expires-at]` |
| 5 | `GET_CHUNK` | `[blob-id, download-cap, index]` | `[ciphertext-chunk, expires-at]` |
| 6 | `RENEW` | `[blob-id, renew-cap, ttl]` | `[expires-at]` |
| 7 | `DELETE` | `[blob-id, delete-cap]` | `[]` |

All IDs and capability public keys are 32-byte byte strings. `ttl` and
`expires-at` are seconds represented as CBOR unsigned integers. `index` is
zero-based and less than the manifest's chunk count. `BEGIN_UPLOAD` uses relay
time plus TTL for both staging and initial committed expiry.

- **CW-BLOB-010:** `BEGIN_UPLOAD` MUST validate the complete manifest and all
  limits before creating staging state. Reuse of an upload ID is idempotent
  only when the manifest, four capability IDs, and original expiry are
  identical; otherwise it returns `ID_CONFLICT`.
- **CW-BLOB-011:** `PUT_CHUNK` MUST require the upload capability, a live
  staging lease, an in-range index, the exact ciphertext length, and the
  manifest digest at that index. An identical retry is idempotent; different
  bytes at a stored index return `CHUNK_CONFLICT`.
- **CW-BLOB-012:** `COMMIT` MUST return `INCOMPLETE` unless every indexed chunk
  exists and verifies. It MUST recompute the requested blob ID, then atomically
  publish the immutable manifest/chunk set and a grant containing the four
  capabilities and initial expiry. A commit response MUST NOT be successful
  before that state crosses the relay's durable boundary.
- **CW-BLOB-013:** `GET_MANIFEST` and `GET_CHUNK` MUST return `NOT_FOUND` for an
  uncommitted upload. Missing or corrupt committed data MUST fail and MUST NOT
  return partial object bytes.
- **CW-BLOB-014:** `RENEW` MUST require the renew capability and a live committed
  lease. It sets expiry to `max(current-expiry, now + ttl)` after overflow and
  policy validation; it MUST NOT shorten a lease.
- **CW-BLOB-015:** `DELETE` MUST require the delete capability and atomically
  make its matching grant unavailable to all four capabilities in that grant.
  Other independent grants for identical ciphertext remain unchanged. Success
  means the honest relay crossed its documented logical-deletion boundary; it
  does not prove a malicious relay erased retained ciphertext.

## Status codes and lease failure

The blob/1 status registry is in `10-versioning.md`.

- **CW-BLOB-025:** Every nonzero status MUST have an empty response body. A
  relay MUST NOT return an unregistered status.

- **CW-BLOB-016:** Upload, download, renew, and delete capability IDs authorize
  only their named command group and identify their matching upload or committed
  grant. A capability MUST NOT substitute for another role or grant, even when
  controlled by the same holder.
- **CW-BLOB-017:** At `now >= expires-at`, staging or committed state is expired.
  An operation naming state that expired returns `EXPIRED` when the relay still
  retains an expiry tombstone, otherwise `NOT_FOUND`; both outcomes expose no
  content and cause no state revival. Only `RENEW` before expiry extends a
  committed lease.
- **CW-BLOB-018:** A relay MAY garbage-collect expired staging, expired grants,
  deletion tombstones, and immutable bytes referenced by no live grant. Expiry
  and deletion are availability promises, not cryptographic erasure or proof of
  ownership.

## Transport bindings

The baseline HTTPS endpoint is `POST /blob/v1/frame` with
`Content-Type: application/cofferwire-blob`. The WebSocket endpoint is
`GET /blob/v1/ws` with subprotocol `cofferwire.blob.v1`. One request or binary
message contains exactly one frame. TLS is required but is not capability
authentication. Oversized bodies are rejected before complete buffering.

- **CW-BLOB-019:** A blob transport MUST select the blob profile before parsing
  its payload and MUST NOT send a blob frame to a queue endpoint or reinterpret
  a queue response as blob/1.
- **CW-BLOB-020:** Disconnect after an ambiguous outcome MUST be handled by
  retrying the exact persisted authenticated frame; connection identity or
  ordering MUST NOT alter command semantics.

## Public vectors and conformance

`vectors/blob-v1.json` contains fixed test-only keys, padding, ciphertext
chunks, manifest, identity, capabilities, and negative operations.

- **CW-BLOB-021:** A conforming producer and consumer MUST reproduce every
  positive field byte-for-byte and reject each negative vector with the named
  stable conformance ID. Fixed vector secrets MUST NOT be accepted by production
  provisioning policy.
- **CW-BLOB-022:** Conformance tests MUST cover interrupted upload, invisible
  partial state, missing/corrupt chunks, commit immutability, each capability
  boundary, expiry, renewal, deletion, retry replay, and restart at every
  durability boundary.
