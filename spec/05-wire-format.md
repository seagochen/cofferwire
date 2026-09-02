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
or an authentication mechanism. It defines only the bytes exchanged once a
transport connection carries one frame, and the byte representation of the
identifiers already used by `06-queues.md`.

## Canonical encoding

Frames are encoded as CBOR (RFC 8949), restricted for version 1 to a small
canonical subset so that an independent implementation can be written
against a minimal encoder/decoder rather than a general-purpose CBOR
library.

- **CW-WIRE-001:** A version 1 frame MUST use only the unsigned-integer
  major type (0), the definite-length byte-string major type (2) and the
  definite-length array major type (4). Negative integers, text strings,
  maps, tags, floating-point/simple values and indefinite-length items
  MUST NOT appear in a version 1 frame.
- **CW-WIRE-002:** Every integer MUST use the shortest encoding able to
  represent its value, per RFC 8949 §4.2's core deterministic encoding
  requirements. A relay or client MUST reject a longer-than-necessary
  encoding of the same value.
- **CW-WIRE-003:** A relay or client MUST decode exactly one top-level CBOR
  item per frame and MUST reject the frame if any trailing bytes remain, if
  any element uses a major type excluded by CW-WIRE-001, or if any integer
  violates CW-WIRE-002 — even when a lenient general-purpose CBOR decoder
  would accept the input. This applies uniformly whether the frame is a
  request or a response.

`CW-WIRE-001` through `CW-WIRE-003` together define what "canonical" and
"non-canonical" mean for this protocol: canonical is exactly the subset
above in shortest form with no trailing bytes; anything else is
non-canonical and MUST be rejected, not repaired or reinterpreted.

## Envelope

- **CW-WIRE-004:** A request frame MUST be the array
  `[version, request-id, command, body]` (exactly 4 elements).
- **CW-WIRE-005:** A response frame MUST be the array
  `[version, request-id, status, body]` (exactly 4 elements).
- **CW-WIRE-006:** `request-id` MUST be a 16-byte byte string chosen by the
  client. A relay MUST copy it unmodified into the corresponding response.
  `request-id` correlates a response to its request; it is not a message
  identifier and has no relation to the queue-scoped `message-id` defined
  in `01-terminology.md`. It exists so a transport binding MAY pipeline
  multiple outstanding requests over one connection without depending on
  response ordering, consistent with the project's transport-independence
  principle.
- **CW-WIRE-007:** `body` MUST be an array containing exactly the number of
  elements defined for the command (request) or status (response) below. A
  `body` with extra, missing or reordered elements MUST be rejected as
  malformed. Version 1 has no mechanism for a decoder to skip an unknown
  trailing field.

`request-id` and `version` occupy the same two leading positions in both
directions so a relay can extract them, and therefore respond, even when
the remainder of the frame is malformed or uses an unsupported version.

## Version negotiation

- **CW-WIRE-008:** The current protocol version is `1`. `version = 0` is
  reserved and MUST be rejected by both roles.
- **CW-WIRE-009:** If a relay does not support the request's `version`, it
  MUST respond with `status = UNSUPPORTED_VERSION`, `body = []`, and a
  `version` field set to the highest version the relay supports. It MUST
  NOT attempt to decode `command` or `body` under an unsupported version,
  since their shape is not defined for that version.
- **CW-WIRE-010:** A client that receives a response whose `version` differs
  from the request's `version` MUST treat it as a version rejection at the
  reported version and MUST NOT interpret the accompanying `body` using its
  own version's command layout.
- **CW-WIRE-011:** Extending the protocol (new fields, new semantics for an
  existing command) requires either a new protocol version or a new command
  code. Version 1 defines no in-band unknown-field tolerance; this keeps
  canonical-encoding verification (CW-WIRE-003) decidable without a
  version-specific exception list.

If the bytes are not even a well-formed array (for example, the leading
byte is not an array-major-type byte, or the array has fewer than 2
elements), no `request-id` can be safely extracted and no response frame
can be constructed. Signaling this case is a transport binding's
responsibility (for example, closing the connection) and is out of scope
for this document.

## Framing and size limits

- **CW-WIRE-012:** The maximum encoded size of one frame is 65536 bytes
  (64 KiB) in either direction. An implementation MUST determine a frame's
  exact encoded length from the transport binding before allocating a
  decode buffer for it, and MUST reject a frame exceeding this bound
  without allocating a buffer sized to the oversized claim or attempting to
  decode any element inside it. A relay rejects an oversized request with
  `status = FRAME_TOO_LARGE`; where the transport cannot associate a
  response with an unparsed oversized input, it MAY instead terminate the
  transport connection.
- **CW-WIRE-013:** This 64 KiB bound is independent of, and MUST be
  enforced before, the per-queue `max_message_bytes` limit defined by
  `CW-QUEUE-007` in `06-queues.md`. The frame bound protects parsing itself
  and applies before any queue is identified; the per-queue limit is a
  relay-operator policy applied afterward, once the queue is known, and MAY
  be tighter but MUST NOT exceed the frame bound minus the other fixed
  fields in `send-req`.

How a transport binding delimits one frame within a connection or request
(one WebSocket message, a length-prefixed HTTP body, or another mechanism)
is defined by the transport-binding document, not here. This document only
constrains the bytes once a frame boundary is known.

## Identifiers and scalars

- **CW-WIRE-014:** `queue-id`, `principal` and `message-id` are each a
  fixed 32-byte string, matching the identifiers already produced by the
  executable relay model. A relay or client MUST reject an occurrence of
  any of these fields whose byte-string length is not exactly 32.
- **CW-WIRE-015:** This document defines only the on-the-wire *byte
  representation* of a queue-scoped `principal`. It does not define how a
  principal proves authorization to act. **A relay or client MUST NOT
  treat presentation of a correct `principal` value, by itself, as proof
  of authorization.** Per `CW-THREAT-001`, a relay treats all
  relay-provided input as attacker-controlled, and symmetrically a network
  attacker who observes a `principal` value in transit MUST NOT thereby
  gain the ability to act as that principal. The binding authentication
  mechanism (signature, MAC, or capability token) is defined by the
  cryptographic profile (`04-cryptographic-profile.md`, not yet written)
  and by a future revision of this document once that profile exists.
- **CW-WIRE-016:** `timestamp` and `ttl` fields are unsigned integers of
  whole seconds, consistent with "Relay time" and "TTL and expiry" in
  `01-terminology.md`. Clock source and permitted skew remain open per that
  document.
- **CW-WIRE-017:** `payload` is an opaque byte string. This document does
  not constrain its contents; `06-queues.md` and a later cryptographic
  profile define what it is expected to contain.

## Commands

| code | name           | implements (see `06-queues.md`)          |
|-----:|----------------|-------------------------------------------|
|    1 | `CREATE_QUEUE` | `CW-QUEUE-008`                             |
|    2 | `SEND`         | `CW-QUEUE-002`, `CW-QUEUE-003`, `CW-QUEUE-007` |
|    3 | `FETCH`        | `CW-QUEUE-001`, `CW-QUEUE-005`             |
|    4 | `ACK`          | `CW-QUEUE-004`                             |
|    5 | `DELETE_QUEUE` | queue lifecycle (see `03-architecture.md`) |

- **CW-WIRE-018:** A relay MUST reject a request whose `command` is not in
  this table with `status = UNKNOWN_COMMAND`, without attempting to decode
  `body`.

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

- **CW-WIRE-019:** `fetch-resp` MUST be the 1-element array `[0]` when no
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

- **CW-WIRE-020:** `status = 0` means success; `body` has the shape defined
  for the request's command above. A nonzero `status` MUST carry
  `body = []` — version 1 carries no structured error detail beyond the
  status code and, for `UNSUPPORTED_VERSION`, the response's `version`
  field.
- **CW-WIRE-021:** A relay MUST NOT return a status value outside this
  table. Codes 5-13 correspond 1:1 to `RelayError` as defined by the
  executable relay model.

| status | name                  | meaning                                            |
|-------:|-----------------------|-----------------------------------------------------|
|      0 | `OK`                  | success                                              |
|      1 | `UNSUPPORTED_VERSION` | see CW-WIRE-009                                      |
|      2 | `MALFORMED_FRAME`     | violates CW-WIRE-001–007, -012, -014 or -019         |
|      3 | `FRAME_TOO_LARGE`     | exceeds CW-WIRE-012                                  |
|      4 | `UNKNOWN_COMMAND`     | see CW-WIRE-018                                      |
|      5 | `QUEUE_NOT_FOUND`     | no queue with `queue-id`                             |
|      6 | `UNAUTHORIZED`        | principal not authorized for the queue role          |
|      7 | `QUEUE_ID_CONFLICT`   | `queue-id` reused with a different configuration      |
|      8 | `MESSAGE_ID_CONFLICT` | `message-id` reused with a different payload          |
|      9 | `MESSAGE_TOO_LARGE`   | payload exceeds the queue's `max-message-bytes`       |
|     10 | `QUEUE_FULL`          | queue at its `max-messages` limit                     |
|     11 | `EXPIRY_OVERFLOW`     | `now + ttl` overflows the timestamp representation    |
|     12 | `ACK_MISMATCH`        | acknowledged `message-id` is not the current message  |
|     13 | `NOT_DELIVERED`       | current message has not been fetched                  |

## Worked example

A `SEND` request with `version = 1`, `request-id = 0xAA * 16`,
`queue-id = 0x11 * 32`, `sender = 0x22 * 32`, `message-id = 0x33 * 32`,
`payload = "hi"`, `ttl = 60` seconds, encodes to exactly these 128 bytes
(verified by round-trip decoding a minimal reference encoder/decoder
against this document):

```text
84                                                                # array(4): request
  01                                                              # version = 1
  50 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa                             # request-id (16 bytes)
  02                                                               # command = SEND
  85                                                               # array(5): send-req body
    58 20 1111111111111111111111111111111111111111111111111111111111111111  # queue-id (32 bytes)
    58 20 2222222222222222222222222222222222222222222222222222222222222222  # sender (32 bytes)
    58 20 3333333333333333333333333333333333333333333333333333333333333333  # message-id (32 bytes)
    42 6869                                                        # payload = "hi"
    18 3c                                                          # ttl = 60
```

A successful response accepting that message (`status = 0`,
`outcome = 0`) is 22 bytes:

```text
84                                    # array(4): response
  01                                  # version = 1
  50 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # request-id (echoed)
  00                                  # status = OK
  81                                  # array(1): send-resp body
    00                                # outcome = 0 (accepted)
```

## Structural schema

The following CDDL (RFC 8610) restates the envelope and command bodies
above in a language-neutral, tool-checkable form:

```cddl
request  = [version: uint, request-id: bstr .size 16, command: uint, body: any]
response = [version: uint, request-id: bstr .size 16, status: uint, body: any]

queue-id   = bstr .size 32
principal  = bstr .size 32
message-id = bstr .size 32
timestamp  = uint
ttl        = uint .ge 1

create-queue-req  = [queue-id, sender: principal, recipient: principal,
                      max-messages: uint .ge 1, max-message-bytes: uint .ge 1]
create-queue-resp = [outcome: 0..1]

send-req  = [queue-id, sender: principal, message-id, payload: bstr, ttl]
send-resp = [outcome: 0..1]

fetch-req  = [queue-id, recipient: principal]
fetch-resp = [0] / [1, message-id, payload: bstr, expires-at: timestamp]

ack-req  = [queue-id, recipient: principal, message-id]
ack-resp = []

delete-queue-req  = [queue-id, recipient: principal]
delete-queue-resp = []

error-resp = []
```

## Open decisions

- how a transport binding delimits one frame (length prefix, one WebSocket
  message, or another mechanism) — deferred to a transport-bindings
  document;
- the authentication mechanism binding a request to its claimed
  `principal` — deferred to the cryptographic profile (CW-WIRE-015);
- whether a relay should collapse `QUEUE_NOT_FOUND` and `UNAUTHORIZED`
  into one status for a hostile caller to avoid an existence oracle, as
  already flagged as open in `06-queues.md`;
- whether a future version introduces structured error detail beyond a
  status code;
- exact numeric values for `max-messages`, `max-message-bytes` and TTL
  bounds remain a relay/application configuration choice within the
  64 KiB frame bound, not a wire-format constant;
- whether version 1's fixed-length, no-unknown-field arrays remain the
  long-term extension strategy or a later major version adopts a
  self-describing structure.
