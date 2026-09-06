# Family-Tree Application Profile (Draft)

This document defines `family-tree/1`, an application profile built entirely
on top of published Cofferwire primitives: queue-v1 application messages
(`04-cryptographic-profile.md`, `06-queues.md`), `cofferwire-blob/1`
(`07-blobs.md`), `receipts/1` (`08-receipts.md`), and `cofferwire-offline/1`
(`13-offline-bundles.md`). It is not part of the core protocol: it allocates
no queue-v1, blob/1, receipts/1, or offline/1 identifier, adds no relay
behavior, and is not validated by `scripts/check_conformance.py` or listed
in `conformance/registry.json` -- that registry governs the shared
core-protocol identifier space (`10-versioning.md`), and this profile's
`FT-` identifiers are a separate, independent namespace for exactly this
reason. A reader does not need the Rust reference implementation to
implement this profile from this document and `profiles/vectors/
family-tree-v1.json` alone.

Normative terms are interpreted as described by RFC 2119 and RFC 8174. All
integers in fixed binary structures are unsigned big-endian integers.

## Purpose and non-goals

This profile defines how a shared, multi-device, multi-relay family tree
synchronizes as ordinary Cofferwire application content: what a tree edit
looks like on the wire, how two independently-made edits are detected as
conflicting and how a resolution is recorded, how `receipt.applied` is used
to confirm an edit was durably merged (not merely decrypted), and what
operational metrics an implementation may collect. It does not define a user
interface, a storage engine, discovery of family members, or any relay
behavior beyond what queue-v1/blob/1/receipts/1/offline/1 already define.
Per `CW-ARCH-001`/`CW-ARCH-002`, per-device independent queues and
multi-device fan-out are already the relay's and core client's contract;
this profile adds no relay-visible behavior on top of them.

- **FT-SCOPE-001:** An implementation MUST treat every requirement in this
  document as an application-layer convention carried inside ordinary
  end-to-end message, blob, and receipt content. It MUST NOT require a relay
  to parse, validate, or act on family-tree content, and MUST NOT introduce
  a new relay command, status, or transport identifier for this profile.

## Object model and identity

A shared family tree is a set of **person** and **relationship** objects.
Each object has one **object identifier**: a fresh 32-byte value chosen by
CSPRNG when the object is first created, stable for the object's lifetime
regardless of later edits. A relationship object references exactly two
person object identifiers and a relationship type (for example parent-child
or spouse); this profile does not constrain which relationship types an
implementation defines.

- **FT-OBJECT-001:** An object identifier MUST be generated independently
  with a CSPRNG and MUST NOT be derived from, or reused as, any queue-v1
  `QueueId`, `MessageId`, blob/1 identifier, or Ed25519 public key. Object
  identity is a family-tree-profile concept with no core-protocol meaning
  (`CW-TERM-001`).

Every change to an object is one **update**: a self-contained, independently
authenticated record of one creation, amendment, or conflict-resolving
merge. Updates form a per-object directed acyclic graph analogous to a
version-control commit graph: each update names the revision(s) it was
based on, and two updates naming the same parent without one being a
descendant of the other are a detected conflict.

## Update wire format

```text
FT-UPDATE-V1 = magic || version || object-type || object-id
             || revision-id || parent-count || parent-revision-ids
             || author-key || created-at
             || field-count || fields
             || signature

magic               = ASCII("FTU1")                ; 4 bytes
version             = 0x01                          ; 1 byte
object-type         = 0x01 person | 0x02 relationship  ; 1 byte
object-id           = 32 bytes
revision-id         = 32 bytes    ; fresh per update, CSPRNG, never a counter
parent-count        = 1 byte, 0..=8
parent-revision-ids = parent-count * 32 bytes
                      ; 0 parents: this update creates the object.
                      ; 1 parent: an ordinary edit.
                      ; 2+ parents: a merge resolving a conflict among them.
author-key          = 32 bytes     ; Ed25519 public key identifying one
                                    ; contributing device (CW-TERM-001: not
                                    ; necessarily any queue's principal)
created-at          = uint64be     ; seconds, informational only
field-count         = 1 byte, 0..=32
fields              = field-count * (field-tag || uint16be length || value)
field-tag           = 1 byte, application-assigned per object-type
signature           = 64 bytes, Ed25519 over every preceding byte
```

- **FT-UPDATE-001:** A producer MUST sign every byte of an update preceding
  `signature` with the Ed25519 secret key corresponding to `author-key`,
  under the domain-separation prefix `ASCII("cofferwire family-tree update
  v1") || 0x00` prepended to the signed bytes. This signature is
  independent of, and in addition to, whatever end-to-end message or blob
  authentication carries the update; it is what lets a forwarding device
  (a history-recovery bundle, `## Bundles`) relay updates it did not author
  without being able to forge authorship.
- **FT-UPDATE-002:** A consumer MUST verify an update's signature against
  its own `author-key` before considering the update for merge, MUST reject
  a wrong-length or invalid signature, and MUST NOT treat a valid signature
  as asserting that `author-key` belongs to any particular queue's
  principal -- that association, if any, is a separate application
  decision this profile does not make.
- **FT-UPDATE-003:** An implementation MUST preserve every field it does not
  recognize by `field-tag` rather than discarding it, since family-tree
  schema evolution (new field tags) is expected over the object's lifetime.
  It MAY decline to display an unrecognized field. This is deliberately
  looser than a core-protocol closed field set (`CW-VERSION-004`): schema
  growth here is an ordinary application concern, not a security-relevant
  wire negotiation.

## Conflict detection and resolution

Each object's synchronization state is its current set of **leaf**
revisions: revisions with no known child update yet. A consumer applies
updates to this state as follows.

- **FT-CONFLICT-001:** Applying an update with `parent-count = 0` for an
  object with no existing revisions MUST make it the object's sole leaf.
  Applying it for an object that already has revisions MUST be rejected as
  a duplicate creation attempt, distinct from an ordinary conflict.
- **FT-CONFLICT-002:** Applying an update with exactly one parent that is
  currently the object's unique leaf MUST remove that parent from the leaf
  set and MUST make the new update the sole leaf (a fast-forward edit).
- **FT-CONFLICT-003:** Applying an update with exactly one parent that is
  NOT currently a leaf (already superseded, or the object has more than one
  current leaf) MUST add the new update to the leaf set alongside the
  existing leaves, without removing any of them, and MUST report this as a
  detected conflict requiring resolution.
- **FT-CONFLICT-004:** Applying an update with two or more parents MUST
  require every named parent to currently be a leaf; if so, all of them
  MUST be removed from the leaf set and replaced by the new update as the
  object's sole leaf (a merge resolving the conflict). If any named parent
  is not currently a leaf, the merge MUST be rejected rather than silently
  resolving only some branches.
- **FT-CONFLICT-005:** An object with more than one current leaf MUST be
  reported to the application as unresolved until a merge update
  (`FT-CONFLICT-004`) reduces it to one; an implementation MUST NOT pick a
  leaf automatically and discard the others.

This is a deterministic, library-independent algorithm: two implementations
that apply the same updates in any order converge on the same leaf set,
because leaf membership depends only on the parent-revision graph, not on
arrival order.

## Receipts

- **FT-RECEIPT-001:** A recipient MUST generate a `receipt.applied`
  (`08-receipts.md`) for an update only after `FT-CONFLICT-001`
  through `FT-CONFLICT-004` have durably applied it to local state --
  fast-forward, recorded conflict, or merge alike -- never merely after
  decrypting it. The receipt's confirmed content digest
  (`CW-RECEIPT-002`) MUST cover the exact `FT-UPDATE-V1` bytes applied.
- **FT-RECEIPT-002:** An update's original author MUST treat a missing or
  not-yet-received receipt as "durability unknown," not as rejection, and
  MAY retransmit the identical update; `FT-CONFLICT-001`'s duplicate-
  creation and the underlying transport's own replay handling
  (`CW-RECEIPT-008`, `CW-QUEUE-*`) make a retransmitted duplicate a no-op.

## Bundles

A **bundle** packages many updates for transfer as one unit -- a full-tree
snapshot for a newly joined device, or a backlog for a long-offline one.

```text
FT-BUNDLE-V1 = magic || version || update-count || updates

magic         = ASCII("FTB1")     ; 4 bytes
version       = 0x01              ; 1 byte
update-count  = uint32be
updates       = update-count * (uint32be length || FT-UPDATE-V1 bytes)
```

- **FT-BUNDLE-001:** A bundle MUST contain each update's exact
  `FT-UPDATE-V1` bytes unmodified; a consumer MUST verify each contained
  update exactly as if it had arrived individually (`FT-UPDATE-002`,
  `## Conflict detection and resolution`) and MUST apply them in an order
  consistent with each update's declared parents (an update MUST NOT be
  applied before every parent it names, when that parent is also present in
  the same bundle).
- **FT-BUNDLE-002:** A bundle exceeding queue-v1's message size MUST be
  transferred as one `cofferwire-blob/1` object (`07-blobs.md`), never by
  splitting `FT-UPDATE-V1` records across multiple queue-v1 messages. A
  bundle that fits within queue-v1's message size MAY instead travel as one
  ordinary application message.

## Example flows

These traces name devices by author-key label, not by queue; each pairwise
relationship between two devices already has its own independent queue-v1
queues and, where noted, a `cofferwire-offline/1` bootstrap between them, per
`13-offline-bundles.md`.

### Three devices, two relays

Alice-Phone (`A1`) and Alice-Laptop (`A2`) are Alice's two devices; Bob-Phone
(`B1`) is Bob's device. `A1`↔`B1` and `A2`↔`B1` are independent queue pairs,
possibly on different relays.

```text
A1 creates person P (update U1, 0 parents)
A1 sends U1 to B1 (ordinary queue-v1 SEND, independently)
A1 sends U1 to A2 (ordinary queue-v1 SEND, independently -- CW-ARCH-002:
  fan-out is an application-layer action, not a relay one)
B1 applies U1 (FT-CONFLICT-001), generates receipt.applied to A1
A2 applies U1 (FT-CONFLICT-001), generates receipt.applied to A1
B1 amends P (update U2, parent U1), sends to A1 and (if A1 relays it) A2
A1 applies U2 (FT-CONFLICT-002: fast-forward from U1 to U2)
```

### Long offline and history recovery

`B1` goes offline for an extended period while `A1` and `A2` continue
exchanging updates. On reconnecting, `B1` fetches its queue as usual
(queue-v1's existing durable, order-independent delivery already tolerates
an arbitrarily long gap); no family-tree-specific catch-up handshake is
needed for updates still queued. A device joining for the first time, or one
that has discarded local state, instead receives a bundle
(`## Bundles`) containing the full leaf-reachable update history over
`cofferwire-blob/1`, applies every update per `FT-BUNDLE-001`, and arrives
at the same leaf set as an existing member.

### Relay replacement and offline bundle

When a queue's relay becomes unavailable, `13-offline-bundles.md`'s
recovery or invitation bundle carries the affected queue's identity and
updated relay hints; per `CW-OFFLINE-011`, the queue identifier and both
principals are unchanged, so already-applied family-tree updates and their
recorded leaf state require no migration. A device resuming after a relay
replacement simply continues fetching the same queue through the new hint;
any update the old relay withheld is recovered only if its original sender
retransmits it (`13-offline-bundles.md`, `## Relay replacement`) or it is
included in a subsequent history-recovery bundle.

## Operational metrics

- **FT-METRIC-001:** An implementation MUST NOT collect, in any operational
  metric, an object identifier, revision identifier, queue identifier,
  author key, capability, key material, or any application field value
  (a name, date, note, or other person/relationship content).
  It MUST NOT collect a value that lets two metric events be correlated to
  the same object, queue, or author across sessions where that correlation
  is avoidable.
- **FT-METRIC-002:** An implementation MAY collect aggregate, bucketed
  counters with no attached identifier -- for example a count of updates
  applied, a count of conflicts detected versus merged, a bucketed
  sync-latency histogram, a bucketed bundle-transfer size, or a count of
  distinct relay hints used in a period -- provided `FT-METRIC-001` still
  holds for every such counter.

## Vectors

`profiles/vectors/family-tree-v1.json` provides a worked object history
(one creation, a fast-forward edit, a detected conflict, and a resolving
merge) with exact `FT-UPDATE-V1` bytes, so that an implementation can check
its own parsing, signature verification, and `## Conflict detection and
resolution` algorithm against a shared fixture without a Cofferwire relay,
matching this repository's `vectors/*.json` convention for the core
protocol.

## Open decisions

- whether `author-key` MAY or SHOULD equal one of the author's queue-v1
  principals, and how an application discovers that mapping if so;
- a canonical field-tag registry per object type (this document fixes the
  framing, not a specific person/relationship schema);
- whether a future revision adds an explicit tombstone/deletion update
  distinct from a field-level edit.
