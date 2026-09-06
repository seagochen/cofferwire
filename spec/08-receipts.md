# Application Receipts (Draft)

This document defines `receipts/1`, the implementation-independent format for
a `receipt.applied` application receipt. A receipt is ordinary opaque
end-to-end message content: it travels inside a normal queue-v1 `SEND`
payload, exactly like any other application message, and a relay never
parses or interprets it. This is a separate draft revision from queue-v1 and
from `cofferwire-blob/1`; it allocates no queue-v1 identifier and requires no
change to the queue-v1 or blob/1 wire frames.

Normative terms are interpreted as described by RFC 2119 and RFC 8174. All
integers in fixed binary structures are unsigned big-endian integers. This
document builds on `01-terminology.md`'s relay-ACK/application-receipt
distinction (`CW-TERM-003`, `CW-TERM-004`) and local-durable-commit ordering
(`CW-TERM-005`); it does not restate them.

## Purpose and non-goals

A `receipt.applied` receipt lets the original sender of an application
message learn, with an end-to-end authenticated proof independent of the
relay, that a specific receiving device durably applied a specific piece of
content. It does not replace relay ACK, does not give a relay any new
authority, and does not define how an application discovers or provisions
the reverse queue a receipt travels on -- that remains an application
profile concern.

- **CW-RECEIPT-001:** A `receipt.applied` message MUST be carried only as the
  opaque plaintext of an ordinary queue-v1 application message (the payload
  produced by `open_message`/`seal_message` in `04-cryptographic-profile.md`).
  It MUST NOT be represented as a relay command, a relay response, or a field
  of either, and a relay MUST NOT be relied upon to parse, validate, or act
  on its content.

## Confirmed object and device binding

A receipt confirms one application object: the exact plaintext durably
applied by one receiving device for one queue-v1 message. The confirmed
object is identified by the same four values that identify the original
message: confirmed queue identifier, confirmed sender principal, confirmed
recipient principal, and confirmed message identifier. The confirmed
recipient principal is also the confirming device's own signing identity.

- **CW-RECEIPT-002:** A `receipt.applied` message MUST bind, by value inside
  its signed content, the confirmed queue identifier, confirmed sender
  principal, confirmed recipient principal, confirmed message identifier, and
  a SHA-256 digest of the exact plaintext bytes durably applied. It MUST NOT
  bind these values only through the enclosing transport context (queue,
  sender, recipient of the reverse message carrying the receipt), because
  that context describes the receipt's own delivery, not the object it
  confirms.
- **CW-RECEIPT-003:** A `receipt.applied` message MUST be signed with the
  confirming device's queue-scoped Ed25519 signing key -- the same key type
  used as a queue-v1 principal -- under a domain-separation prefix distinct
  from relay-command signing, so the same key can never produce a signature
  valid under the other purpose.

## Wire format

A `receipt.applied` plaintext is this fixed 237-byte binary structure, with
no variable-length or optional fields:

```text
RECEIPT-APPLIED-V1 = magic || type
                   || confirmed-queue-id || confirmed-sender
                   || confirmed-recipient || confirmed-message-id
                   || applied-content-digest || applied-at
                   || signature

magic                  = ASCII("CWR1")            ; 4 bytes
type                   = 0x01                     ; 1 byte, receipt.applied
confirmed-queue-id     = 32 bytes
confirmed-sender       = 32 bytes
confirmed-recipient    = 32 bytes
confirmed-message-id   = 32 bytes
applied-content-digest = SHA-256(applied plaintext) ; 32 bytes
applied-at             = uint64be                 ; seconds, device-local clock
signature              = Ed25519(SIGNED-FIELDS)   ; 64 bytes

SIGNED-FIELDS = everything above except `signature`
DOMAIN        = ASCII("cofferwire receipt v1") || 0x00
signature     = Ed25519-Sign(confirming device key, DOMAIN || SIGNED-FIELDS)
```

- **CW-RECEIPT-004:** A producer MUST encode exactly the 237-byte structure
  above with `type = 0x01` and MUST compute `applied-content-digest` over the
  exact plaintext bytes returned to the application, before any
  application-level reinterpretation. A consumer MUST reject a `receipt`
  candidate plaintext that is not exactly 237 bytes or whose first five bytes
  are not `magic || type` as a malformed receipt, distinct from a signature
  failure.

## Verification outcomes

Verification requires the confirmed object the verifier expects to be
confirmed (queue, sender, recipient, message identifier) and, when the
verifier wants a content guarantee and not only an identifier match, the
digest of the plaintext it originally sent.

- **CW-RECEIPT-005:** A verifier MUST verify the Ed25519 signature against
  the confirming device's principal that it already expects for this object
  (the original message's recipient), not against a principal read from the
  receipt itself. A receipt whose signature does not verify under that
  expected principal MUST be rejected and MUST NOT be treated as evidence
  about any object, device, or content.
- **CW-RECEIPT-006:** A signature-valid receipt whose confirmed queue
  identifier, confirmed sender, confirmed recipient, or confirmed message
  identifier does not exactly match the object the verifier is confirming
  MUST be rejected with an outcome distinguishable from a signature failure
  and MUST NOT be recorded against the object the verifier expected.
- **CW-RECEIPT-007:** A verifier that also holds the plaintext it originally
  sent MUST compare it against `applied-content-digest` and MUST treat a
  mismatch as rejection distinguishable from both a signature failure and an
  object mismatch.

## Idempotency and replay

- **CW-RECEIPT-008:** A verifier MUST deduplicate accepted receipts by the
  confirmed object identity (confirmed queue, sender, recipient, and message
  identifier), independent of the transport-level message identifier the
  receipt itself traveled under. A second valid receipt confirming an
  already-recorded object MUST be accepted as a no-op duplicate and MUST NOT
  be applied a second time.
- **CW-RECEIPT-009:** The `applied-at` field is informational only. A
  verifier MUST NOT use it as a freshness gate, MUST NOT reject an otherwise
  valid receipt for arriving out of order relative to other receipts, and
  MUST rely only on `CW-RECEIPT-008`'s object-identity deduplication for
  replay safety.

## Relation to relay ACK

- **CW-RECEIPT-010:** An implementation MUST keep the relay `Ack` command and
  response and the `receipt.applied` message in disjoint wire
  representations, disjoint state-machine transitions, and disjoint
  documentation sections, so that no code path can treat one as evidence of
  the other. A reference implementation MUST generate a `receipt.applied`
  message only after the confirming device's local durable commit
  (`CW-TERM-005`) has already succeeded for the confirmed object, never
  before it and never in place of relay ACK.

## Open decisions

- how an application provisions or discovers the reverse queue a receipt
  travels on;
- additional receipt types beyond `receipt.applied` (for example, an explicit
  application-level rejection receipt);
- whether a future application profile freezes `receipts/1` with its own
  scope revision, analogous to `cofferwire-blob/1`.
