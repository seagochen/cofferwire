# Wire Format (Draft)

This document defines the canonical byte-level envelope, framing and
version-negotiation rules for the queue-only profile described by
`06-queues.md`. It restates no new queue behavior; where a command's effect
is normative, this document cross-references the existing `CW-QUEUE-*` and
`CW-STORE-*` requirements rather than duplicating them.

Normative terms such as **MUST**, **MUST NOT**, **SHOULD** and **MAY** are
interpreted as described by RFC 2119 and RFC 8174. Terms such as *device*,
*sender*, *recipient*, *relay*, *queue*, *queue-scoped principal*, *message
identifier*, *opaque message*, *delivery*, *relay ACK* and *durability
boundary* have the meanings defined in `01-terminology.md`.

This document does not define a cryptographic profile, a transport binding
or a signature/MAC algorithm. It fixes the exact bytes exchanged once a
transport connection carries one frame, the byte representation of the
identifiers already used by `06-queues.md`, and — because a wire contract
that leaves no room for authentication cannot be implemented safely — the
position and byte range that a future cryptographic profile authenticates.

A frame has three parts, concatenated with no separator:

```text
frame        = preamble payload auth?     ; auth present only in a request frame
preamble     = version request-id         ; exactly 17 raw bytes, not CBOR
version      = 1 byte                     ; 0-255
request-id   = 16 bytes
payload      = one canonical CBOR array   ; see "Frame structure"
auth         = one canonical CBOR byte string, request frames only
```

## Canonical encoding

`payload` and, when present, `auth` are encoded as CBOR (RFC 8949),
restricted for version 1 to a small canonical subset so that an independent
implementation can be written against a minimal encoder/decoder rather than
a general-purpose CBOR library. `preamble` is raw fixed-width bytes, not
CBOR, and CW-WIRE-001–003 do not apply to it — see "Frame structure" for
why.

- **CW-WIRE-001:** `payload` and `auth` MUST use only the unsigned-integer
  major type (0), the definite-length byte-string major type (2) and the
  definite-length array major type (4). Negative integers, text strings,
  maps, tags, floating-point/simple values and indefinite-length items
  MUST NOT appear.
- **CW-WIRE-002:** Every CBOR item's *argument* — the value that follows an
  item's initial byte, per RFC 8949 §3 — MUST use the shortest of the five
  argument encodings RFC 8949 defines. This applies uniformly to an
  unsigned integer's value (major type 0) and to the length of a byte
  string or array (major types 2 and 4); a length is an argument like any
  other and has the same canonical-shortest requirement. For example, the
  32-byte `queue-id` in the worked example below MUST be encoded with
  initial byte `0x58` followed by length byte `0x20` (1-byte length
  argument, the shortest form for values 24–255). The alternative
  `0x59 0x00 0x20` (2-byte length argument, also representing 32) encodes
  the same value non-canonically and MUST be rejected.
  Likewise, a 16-byte byte string uses `0x50` directly; the alternative
  `0x59 0x00 0x10` length form is non-canonical and MUST be rejected.
- **CW-WIRE-003:** A relay or client MUST decode `payload` as exactly one
  canonical CBOR array immediately following `preamble`, and — for a
  request — MUST decode `auth` as exactly one canonical CBOR byte string
  immediately following `payload`. No bytes may remain after `auth`
  (requests) or after `payload` (responses, which carry no `auth` in v1).
  A relay or client MUST reject the frame if any item uses a major type
  excluded by CW-WIRE-001, if any argument violates CW-WIRE-002, or if
  bytes remain where none are permitted — even when a lenient
  general-purpose CBOR decoder would accept the input.

CW-WIRE-001 through CW-WIRE-003 together define what "canonical" and
"non-canonical" mean for this protocol: canonical is exactly the subset
above, in shortest form, with no trailing bytes; anything else is
non-canonical and MUST be rejected, not repaired or reinterpreted.

## Frame structure

- **CW-WIRE-004:** `preamble` MUST be exactly 17 raw bytes: 1 byte
  `version` (an unsigned octet, not a CBOR-encoded integer) followed by 16
  raw bytes `request-id`. Neither field is CBOR-encoded.
- **CW-WIRE-005:** `preamble`'s layout, byte width and raw (non-CBOR)
  encoding are not subject to version negotiation and MUST NOT change in
  any future protocol version. A future version MAY change how `payload`
  and `auth` are encoded; it MUST NOT change how `preamble` is read. This
  is what lets a relay or client that supports only a subset of versions
  always read `version` and `request-id` — see "Version negotiation".
- **CW-WIRE-006:** `request-id` is chosen by the client and correlates a
  response to its request; it is not a message identifier and has no
  relation to the queue-scoped `message-id` defined in `01-terminology.md`.
  A relay MUST copy it unmodified into the corresponding response's
  `preamble`. It exists so a transport binding MAY pipeline multiple
  outstanding requests over one connection without depending on response
  ordering, consistent with the project's transport-independence
  principle.
- **CW-WIRE-007:** Within a request or response `payload`, the `body`
  element MUST be an array containing exactly the number of elements
  defined for the request command or the response's command/status pair in
  "Commands" below. A `body` with extra, missing or reordered elements
  MUST be rejected as malformed. Version 1 has no mechanism for a decoder
  to skip an unknown trailing field. ("Authenticated command envelope"
  below fixes the array `payload` itself carries: `[0, command, body]` for a request,
  `[1, command, status, body]` for a response.)

If the received bytes are fewer than 17, no `request-id` can be extracted
and no response frame can be constructed; signaling this case (for example,
closing the transport connection) is a transport binding's responsibility
and is out of scope for this document.

## Version negotiation

- **CW-WIRE-008:** The current protocol version is `1`. `version = 0` is
  reserved and MUST be rejected by both roles.
- **CW-WIRE-009:** If a relay does not support the request's `version`, it
  MUST respond using its own highest supported version's `payload` and
  `auth` encoding — for a relay that speaks only v1, this means a v1
  response payload `[1, 0, status, body]` with
  `status = UNSUPPORTED_VERSION` and `body = []`; command `0` means the
  request command was not decoded. The response uses a `preamble` whose
  `version` is the relay's highest supported version and whose
  `request-id` is copied from the request per
  CW-WIRE-006. Because CW-WIRE-005 guarantees `preamble` is readable
  regardless of the request's version, the relay reaches this response
  without decoding anything past byte 17 of an unsupported request — it
  MUST NOT attempt to interpret that request's `payload` or `auth`.
- **CW-WIRE-010:** A client that receives a response whose `preamble`
  `version` differs from its request's `version` MUST treat it as a
  version rejection at the reported version and MUST decode that
  response's `payload` using that reported version's layout, not its own.
- **CW-WIRE-011:** Extending the protocol (new fields, new semantics for an
  existing command) requires either a new protocol version or a new
  command code. Version 1 defines no in-band unknown-field tolerance; this
  keeps canonical-encoding verification (CW-WIRE-003) decidable without a
  version-specific exception list.

See "Worked examples" below for a concrete case: a v1-only relay receiving
a frame whose `version` is a hypothetical future value with an unrelated
`payload` encoding, and the response it produces without parsing that
payload.

## Authenticated command envelope

A wire contract that has no place for authentication cannot be implemented
safely: a relay that authorizes `SEND`, `FETCH`, `ACK` and `DELETE_QUEUE`
by `principal` alone (per `03-architecture.md`, `CW-ARCH-003`, and
`CW-THREAT-001`) needs somewhere to put the proof, and that place has to
exist in v1 or adding it later breaks v1 decoders. This section fixes the
authenticated envelope's shape, position and byte range now; it does not
define the signature, MAC or capability scheme that fills it — that is
`04-cryptographic-profile.md`'s responsibility.

- **CW-WIRE-012:** For protocol version 1, a request's `payload` MUST be
  the canonical CBOR array `[0, command, body]` (exactly 3 elements). The
  leading `0` is the request direction discriminator.
- **CW-WIRE-013:** For protocol version 1, a response's `payload` MUST be
  the canonical CBOR array `[1, command, status, body]` (exactly 4
  elements). The leading `1` is the response direction discriminator.
  For a recognized command, `command` MUST echo the request command; it is
  `0` only when no supported command is available, such as an unknown
  version, an unknown command or a structurally malformed payload. A
  decoder MUST reject any other discriminator and MUST NOT reinterpret a
  payload in the opposite direction. The echoed command also makes every
  success response body machine-checkable without out-of-band request context.
- **CW-WIRE-014:** Every request frame MUST carry `auth` as the canonical
  CBOR byte string immediately following `payload` (CW-WIRE-003,
  CW-WIRE-012). The byte string's content length MUST be between 0 and
  `MAX_AUTH_BYTES` (1024) inclusive; zero length is permitted because no
  cryptographic profile has yet been adopted. A response frame carries no
  `auth` in version 1. `auth` is part of the frame itself, not a
  transport-level header, cookie or connection property: verifying it
  MUST NOT depend on HTTPS, a WebSocket handshake or any other
  transport's authentication or connection state, consistent with this
  project's transport-independence principle (`PLAN.md`) and with queue
  commands remaining meaningful over a replaceable or offline transport.
- **CW-WIRE-015:** This document defines only the on-the-wire *byte
  representation* of a queue-scoped `principal` (CW-WIRE-022); it does not
  by itself define how a principal proves authorization to act, and
  `auth`'s mere presence does not either until a cryptographic profile
  defines its verification (CW-WIRE-018). **A relay or client MUST NOT
  treat presentation of a correct `principal` value, by itself, as proof
  of authorization.** Per `CW-THREAT-001`, a relay treats all
  relay-provided input as attacker-controlled, and symmetrically a network
  attacker who observes a `principal` value in transit MUST NOT thereby
  gain the ability to act as that principal.
- **CW-WIRE-016:** The authenticated byte range for a request is the exact
  concatenation `preamble || payload` as received on the wire — the 17
  raw preamble bytes followed by the canonical CBOR encoding of
  `[0, command, body]`, verbatim, excluding `auth` itself. A cryptographic
  profile that defines how to verify `auth` MUST verify it against exactly
  this byte range without using a derived or reserialized form. A profile
  MAY also bind fixed domain-separation and authenticated profile metadata
  as specified by CW-CRYPTO-002, but those additions never replace or
  transform `preamble || payload`.
- **CW-WIRE-017:** Because `command` and `body` are themselves inside the
  authenticated byte range, they cannot be altered independently of
  `auth` once a profile defines verification: a signature or MAC computed
  for one `command`, `queue-id`, `principal`, `message-id` or `payload`
  MUST NOT verify against a request that changes any of those values, and
  a signature or MAC computed under one `request-id` MUST NOT verify under
  a different one. This is a structural consequence of authenticating
  `preamble || payload` verbatim, not a separate mechanism to implement.
- **CW-WIRE-018:** No cryptographic profile exists yet. Until one is
  adopted, `auth` carries no verifiable meaning: a relay or client MUST
  NOT treat a nonempty `auth`, or the wire-level acceptance of a request,
  as evidence that any principal was authenticated. This matches the
  project's current status (see the repository `README.md`) that no
  security guarantees should be inferred from the executable relay model
  yet. Once a profile defining `auth` verification is adopted, a relay
  operating under it MUST reject a request whose `auth` is missing,
  malformed or fails verification with `status = AUTH_INVALID` (see
  "Status codes"), distinct from `UNAUTHORIZED`, which remains for a
  request that authenticates correctly but names a principal the queue
  does not authorize for that role.
- **CW-WIRE-019:** Replay handling is part of command authentication, not
  transport state. It MUST follow CW-CRYPTO-007: an exact authenticated
  retry returns the durably recorded response without applying the command
  again, while conflicting reuse or a profile-rejected stale request fails
  with `AUTH_REPLAY`. Queue-command idempotency remains an independent
  safeguard and does not replace replay verification.

## Framing and size limits

- **CW-WIRE-020:** The maximum encoded size of one frame — `preamble`
  plus `payload` plus, for a request, `auth` — is 65536 bytes (64 KiB) in
  either direction. An implementation MUST determine a frame's exact
  encoded length from the transport binding before allocating a decode
  buffer for it, and MUST reject a frame exceeding this bound without
  allocating a buffer sized to the oversized claim or attempting to decode
  any element inside it. A relay rejects an oversized request with
  `status = FRAME_TOO_LARGE`; where the transport cannot associate a
  response with an unparsed oversized input, it MAY instead terminate the
  transport connection.
- **CW-WIRE-021:** This 64 KiB bound is independent of, and MUST be
  enforced before, the per-queue `max_message_bytes` limit defined by
  `CW-QUEUE-007` in `06-queues.md`. The frame bound protects parsing
  itself and applies before any queue is identified; the per-queue limit
  is a relay-operator policy applied afterward, once the queue is known,
  and MAY be tighter but MUST NOT exceed `MAX_MESSAGE_BYTES` (64374).
- **CW-WIRE-029:** Version 1 defines the following protocol constants and
  exact worst-case `SEND` calculation. The calculation reserves the
  largest permitted `auth`, a maximum-width `ttl`, all three identifiers,
  and every CBOR argument byte, including the opaque payload's own length
  argument:

  ```text
  MAX_FRAME_BYTES   = 65536
  MAX_AUTH_BYTES    = 1024
  MAX_MESSAGE_BYTES = 64374

  send-frame-bytes =
      17                    preamble
    + 1                     payload array(3)
    + 1                     request direction discriminator
    + 1                     SEND command
    + 1                     send-req body array(5)
    + 3 * (2 + 32)          queue-id, sender, message-id
    + 3 + message-bytes     opaque payload header and content
    + 9                     maximum-width ttl
    + 3 + 1024              maximum auth header and content
    = 1162 + message-bytes

  MAX_MESSAGE_BYTES = MAX_FRAME_BYTES - 1162 = 64374
  ```

  The 3-byte byte-string headers are the canonical `0x59` plus a 2-byte
  argument; both 1024 and 64374 are in the 256–65535 range. Consequently a
  64374-byte opaque payload produces a frame of exactly 65536 bytes even
  with `ttl = 2^64 - 1` and a 1024-byte `auth`; adding one payload byte
  produces 65537 bytes and MUST fail with `FRAME_TOO_LARGE`.
- **CW-WIRE-030:** `CREATE_QUEUE` MUST reject
  `max-message-bytes = 0` or a value greater than
  `MAX_MESSAGE_BYTES` with `status = LIMIT_OUT_OF_RANGE`. Thus every
  accepted queue configuration can carry a `SEND` whose opaque payload is
  exactly its declared `max-message-bytes`, for every valid v1 `ttl` and
  `auth`. This validation occurs before queue creation or idempotency
  comparison. A queue MAY advertise a smaller operator-selected limit.

How a transport binding delimits one frame within a connection or request
(one WebSocket message, a length-prefixed HTTP body, or another mechanism)
is defined by the transport-binding document, not here. This document only
constrains the bytes once a frame boundary is known.

## Identifiers and scalars

- **CW-WIRE-022:** `queue-id`, `principal` and `message-id` are each a
  fixed 32-byte string, matching the identifiers already produced by the
  executable relay model. A relay or client MUST reject an occurrence of
  any of these fields whose byte-string length is not exactly 32.
  The wire representation alone never proves authorization; see
  "Authenticated command envelope" above (CW-WIRE-015) for what this
  document fixes now and defers to the cryptographic profile.
- **CW-WIRE-023:** `timestamp` and `ttl` fields are unsigned integers of
  whole seconds, consistent with "Relay time" and "TTL and expiry" in
  `01-terminology.md`. Clock source and permitted skew remain open per that
  document.
- **CW-WIRE-024:** `payload` (the opaque message byte string carried by
  `SEND`/`FETCH`, distinct from the frame's `payload` array) is an opaque
  byte string. This document does not constrain its contents;
  `06-queues.md` and a later cryptographic profile define what it is
  expected to contain.

## Commands

| code | name           | implements (see `06-queues.md`)          |
|-----:|----------------|-------------------------------------------|
|    1 | `CREATE_QUEUE` | `CW-QUEUE-008`                             |
|    2 | `SEND`         | `CW-QUEUE-002`, `CW-QUEUE-003`, `CW-QUEUE-007` |
|    3 | `FETCH`        | `CW-QUEUE-001`, `CW-QUEUE-005`             |
|    4 | `ACK`          | `CW-QUEUE-004`                             |
|    5 | `DELETE_QUEUE` | queue lifecycle (see `03-architecture.md`) |

- **CW-WIRE-025:** A relay MUST reject a request whose `command` is not in
  this table with `status = UNKNOWN_COMMAND`, without attempting to decode
  `body`.

Each `body` below is the third element of `[0, command, body]` or the
fourth element of `[1, command, status, body]` (CW-WIRE-012,
CW-WIRE-013); it is unchanged by, and does not itself carry, `auth`.

### `CREATE_QUEUE` (1)

```text
request  body = [queue-id, sender, recipient, max-messages, max-message-bytes]
response body = [outcome]              ; 0 = created, 1 = already-exists
```

`max-messages` and `max-message-bytes` are nonzero unsigned integers
corresponding to `QueueLimits` in `06-queues.md`. `outcome` corresponds to
`CreateQueueOutcome`.

### `SEND` (2)

```text
request  body = [queue-id, sender, message-id, payload, ttl]
response body = [outcome]              ; 0 = accepted, 1 = duplicate
```

`outcome` corresponds to `SendOutcome`.

### `FETCH` (3)

```text
request  body = [queue-id, recipient]
response body = [0]
         body = [1, message-id, payload, expires-at]
```

- **CW-WIRE-026:** `fetch-resp` MUST be the 1-element array `[0]` when no
  message is available, or the 4-element array
  `[1, message-id, payload, expires-at]` when a `Delivery` exists. A
  `fetch-resp` of any other length, or whose first element is neither `0`
  nor `1`, MUST be rejected as malformed.

### `ACK` (4)

```text
request  body = [queue-id, recipient, message-id]
response body = []
```

### `DELETE_QUEUE` (5)

```text
request  body = [queue-id, recipient]
response body = []
```

## Status codes

- **CW-WIRE-027:** `status = 0` means success; the response `command` MUST
  be in the Commands table and `body` has the shape defined for that
  command above. A nonzero `status` MUST carry
  `body = []` — version 1 carries no structured error detail beyond the
  status code and, for `UNSUPPORTED_VERSION`, the response `preamble`'s
  `version` field.
- **CW-WIRE-028:** A relay MUST NOT return a status value outside this
  table. Codes 5–13 correspond 1:1 to `RelayError` as defined by the
  executable relay model.

| status | name                  | meaning                                            |
|-------:|-----------------------|-----------------------------------------------------|
|      0 | `OK`                  | success                                              |
|      1 | `UNSUPPORTED_VERSION` | see CW-WIRE-009                                      |
|      2 | `MALFORMED_FRAME`     | violates CW-WIRE-001–007, -012–014, -026             |
|      3 | `FRAME_TOO_LARGE`     | exceeds CW-WIRE-020                                  |
|      4 | `UNKNOWN_COMMAND`     | see CW-WIRE-025                                      |
|      5 | `QUEUE_NOT_FOUND`     | no queue with `queue-id`                             |
|      6 | `UNAUTHORIZED`        | authenticated principal not authorized for the role  |
|      7 | `QUEUE_ID_CONFLICT`   | `queue-id` reused with a different configuration      |
|      8 | `MESSAGE_ID_CONFLICT` | `message-id` reused with a different payload          |
|      9 | `MESSAGE_TOO_LARGE`   | payload exceeds the queue's `max-message-bytes`       |
|     10 | `QUEUE_FULL`          | queue at its `max-messages` limit                     |
|     11 | `EXPIRY_OVERFLOW`     | `now + ttl` overflows the timestamp representation    |
|     12 | `ACK_MISMATCH`        | acknowledged `message-id` is not the current message  |
|     13 | `NOT_DELIVERED`       | current message has not been fetched                  |
|     14 | `AUTH_INVALID`        | `auth` missing, malformed, or fails verification (see CW-WIRE-018) |
|     15 | `LIMIT_OUT_OF_RANGE`  | queue limit is zero or exceeds a v1 protocol bound (see CW-WIRE-030) |
|     16 | `AUTH_REPLAY`         | conflicting or stale authenticated request (see CW-CRYPTO-007) |

## Worked examples

All four examples below were produced and round-trip verified against a
minimal reference encoder/decoder implementing exactly the rules above.

### (a) A `SEND` request

`version = 1`, `request-id = 0xAA * 16`, `queue-id = 0x11 * 32`,
`sender = 0x22 * 32`, `message-id = 0x33 * 32`, opaque `payload = "hi"`,
`ttl = 60` seconds, and an empty `auth` (no cryptographic profile is
adopted yet — see CW-WIRE-018) encode to exactly these 129 bytes:

```text
01                                                                # preamble: version = 1
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa                                  # preamble: request-id (16 bytes)
83                                                                 # payload: array(3) [direction, command, body]
  00                                                               # direction = request
  02                                                               # command = SEND
  85                                                                # body: array(5)
    58 20 1111111111111111111111111111111111111111111111111111111111111111  # queue-id (32 bytes)
    58 20 2222222222222222222222222222222222222222222222222222222222222222  # sender (32 bytes)
    58 20 3333333333333333333333333333333333333333333333333333333333333333  # message-id (32 bytes)
    42 6869                                                        # opaque payload = "hi"
    18 3c                                                          # ttl = 60
40                                                                  # auth: bstr, length 0
```

### (b) The matching success response

Accepting that message (`status = OK`, `outcome = 0`) is 23 bytes. No
`auth` follows the payload in a response.

```text
01                                    # preamble: version = 1
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa      # preamble: request-id (echoed)
84                                    # payload: array(4) [direction, command, status, body]
  01                                  # direction = response
  02                                  # command = SEND (echoed)
  00                                  # status = OK
  81                                  # body: array(1)
    00                                # outcome = 0 (accepted)
```

### (c) A non-canonical encoding that MUST be rejected

The same `queue-id` from (a), encoded with a longer-than-necessary length
argument (CW-WIRE-002): initial byte `0x59` (major type 2, 2-byte length
argument) instead of `0x58` (1-byte length argument).

```text
59 0020 1111111111111111111111111111111111111111111111111111111111111111
```

This decodes to the identical 32-byte value as `58 20 ...` in (a). A
decoder that accepts both would allow two distinct byte sequences for the
same logical `SEND` request, breaking the byte-for-byte determinism this
document requires; CW-WIRE-002/003 require rejecting the `0x59` form.

The same requirement applies to array-length arguments, not just
byte-string lengths. The 5-element `send-req` body in (a) MUST use initial
byte `0x85` (major type 4, direct length 5). The alternative
`0x98 0x05` (major type 4, 1-byte length argument, also representing 5)
encodes the same array length non-canonically and MUST equally be
rejected.

### (d) A hypothetical future version, handled without understanding it

A v1-only relay receives a frame claiming `version = 2` with an
unspecified, unrelated 10-byte payload it does not understand:

```text
02                                    # preamble: version = 2 (unsupported)
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa      # preamble: request-id
ffffffffffffffffffff                  # opaque to this relay — never decoded
```

Per CW-WIRE-005 the relay still reads `version` and `request-id` from the
fixed preamble. It ignores the remaining 10 bytes entirely (CW-WIRE-009)
and replies in its own highest supported version, 1, echoing the
`request-id` and reporting `UNSUPPORTED_VERSION`:

```text
01                                    # preamble: version = 1 (relay's max)
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa      # preamble: request-id (echoed)
84                                    # payload: array(4) [direction, command, status, body]
  01                                  # direction = response
  00                                  # command unavailable (not decoded)
  01                                  # status = UNSUPPORTED_VERSION
  80                                  # body: array(0)
```

This holds regardless of what the unsupported version's payload actually
contained, and regardless of whether that version even uses CBOR for it.

## Structural schema

[`05-wire-format.cddl`](05-wire-format.cddl) is the RFC 8610 structural
schema for the CBOR `payload` following the raw 17-byte `preamble`. Its
root rule, `frame-payload`, is an explicit choice over complete request and
response payloads. Each request alternative fixes the command literal and
corresponding body; response alternatives distinguish `OK` bodies from
the empty body required by every error status. The schema therefore does
not use `any` and rejects command/body mismatches, unknown commands,
invalid outcomes, nonempty error bodies, wrong identifier sizes, and data
model types excluded by CW-WIRE-001.

`request-auth` is a separate rule because `auth` is a second CBOR data item
after a request payload rather than part of the payload tree. The raw
`preamble`, shortest-argument encoding, item ordering and absence of
trailing bytes are byte-level constraints that RFC 8610 CDDL cannot
express; CW-WIRE-002–005 remain normative and a conforming codec MUST
check them in addition to validating the structural schema.

## Open decisions

- how a transport binding delimits one frame (length prefix, one WebSocket
  message, or another mechanism) — deferred to a transport-bindings
  document;
- the algorithm carried by `auth` (signature, MAC, or capability token),
  its agility/versioning within that opaque byte string, and whether it
  becomes mandatory-nonempty once a cryptographic profile is adopted —
  deferred to `04-cryptographic-profile.md`;
- concrete freshness windows beyond CW-CRYPTO-007's mandatory replay
  record;
- whether a relay should collapse `QUEUE_NOT_FOUND` and `UNAUTHORIZED`
  (and now `AUTH_INVALID`) into fewer distinguishable statuses for a
  hostile caller to avoid an existence oracle, as already flagged as open
  in `06-queues.md`;
- whether a future version introduces structured error detail beyond a
  status code;
- exact numeric values for `max-messages` and TTL bounds remain a
  relay/application configuration choice within the v1 scalar domain;
- whether version 1's fixed-length, no-unknown-field arrays remain the
  long-term extension strategy or a later major version adopts a
  self-describing structure for `payload`.
