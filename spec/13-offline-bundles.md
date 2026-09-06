# Offline Bootstrap and Recovery Bundles (Draft)

This document defines `cofferwire-offline/1`, the implementation-independent
format for an offline bundle: a single encrypted, self-contained artifact
that either introduces a new counterparty to an existing queue relationship
(an invitation) or lets one device resume its own identity and queue
relationships elsewhere (a recovery bundle). A bundle is never sent to a
relay and allocates no queue-v1 or blob/1 identifier; it is a local
export/import artifact -- a file, QR code, or other out-of-band transfer --
exactly as `PLAN.md`'s M4 milestone describes "local export/import as a
complete offline transport."

Normative terms are interpreted as described by RFC 2119 and RFC 8174. All
integers in fixed binary structures are unsigned big-endian integers. This
document reuses the authenticated HPKE construction from
`04-cryptographic-profile.md` (`seal_message`/`open_message`) unchanged; it
defines no new cryptographic primitive.

## Purpose and non-goals

An offline bundle answers two related questions without inventing new
cryptography or a new relay-visible wire format: how does an intended
counterparty learn where and how to reach an existing queue relationship
(bootstrap/invitation, `03-architecture.md`'s "Queue provisioning" section),
and how does a device recover its own complete identity and relay
reachability after data loss or after its relays become unavailable or
untrusted (recovery). It does not define account recovery across unrelated
identities, does not define a discovery service, and does not change how a
relay authenticates or stores queue commands.

- **CW-OFFLINE-001:** `cofferwire-offline/1` MUST NOT extend the frozen
  queue-v1 frame, command, or status namespace, and MUST NOT extend
  `cofferwire-blob/1`'s. A relay MUST NOT be relied upon to parse, validate,
  transport, or store an offline bundle.

## Relay hints

A relay hint is an opaque, application-interpreted byte string identifying
where one queue may currently be reached (for example an endpoint URL). The
core protocol assigns it no syntax, consistent with `03-architecture.md`'s
transport-independence: a transport binding already carries codec frames
over whatever medium an application chooses, and this profile only orders
and bounds the hints that name where to attempt that binding.

```text
MAX_RELAY_HINTS      = 8
MAX_RELAY_HINT_BYTES = 256
```

- **CW-OFFLINE-002:** A bundle producer MUST order relay hints by
  preference, most preferred first, and MUST NOT include more than
  `MAX_RELAY_HINTS` hints or a hint longer than `MAX_RELAY_HINT_BYTES`. A
  consumer MUST try hints in the given order and MUST treat hint content as
  opaque, attacker-controlled bytes below the transport-selection layer.

## Bundle types and confidentiality

A bundle is exactly one of two types. An **invitation** conveys a
counterparty's public queue identity and current relay hints to a device
that already holds its own signing and encryption keys; it carries no
secret. A **recovery** bundle additionally carries the exporting device's
own signing seed and encryption key material -- private material an
invitation never includes.

- **CW-OFFLINE-003:** An implementation MUST encrypt every recovery bundle,
  since it is secret-bearing, and MUST also encrypt every invitation
  bundle, since its relay hints and queue identifier are otherwise exposed
  to whatever channel carries it.
- **CW-OFFLINE-004:** A bundle's plaintext MUST be sealed with the exact
  authenticated-HPKE construction defined for application messages
  (`seal_message`/`open_message`, profile `0x0001`, KEM `0x0020`, KDF
  `0x0001`, AEAD `0x0003`), bound to a `MessageContext` whose `queue_id` is
  the bundle's confirmed queue, whose `sender` is the exporting device's
  principal, whose `recipient` is the importing device's principal, and
  whose `message_id` is the bundle's own `bundle-id`. No new key type,
  algorithm, or associated-data construction is defined by this profile.

Because sealing requires the importing device's encryption public key,
producing a bundle presupposes that the importing device already exists and
has shared that public key out of band; this profile defines the bundle
format and its handling, not that out-of-band key exchange.

## Wire format

The sealed plaintext is this structure. The common prefix is 143 bytes; a
recovery bundle appends 64 more bytes before the relay-hint list.

```text
OFFLINE-BUNDLE-V1 = magic || version || bundle-type
                  || bundle-id || queue-id || role
                  || peer-principal || peer-encryption-public-key
                  || created-at
                  || [ own-signing-seed || own-encryption-ikm ]   ; recovery only
                  || relay-hint-count || relay-hints

magic                      = ASCII("CWOB")        ; 4 bytes
version                    = 0x01                 ; 1 byte
bundle-type                = 0x01 invitation | 0x02 recovery   ; 1 byte
bundle-id                  = 32 bytes             ; fresh per bundle, CSPRNG
queue-id                   = 32 bytes
role                       = 0x00 sender | 0x01 recipient       ; 1 byte
                             ; the role the IMPORTING device will hold
peer-principal             = 32 bytes             ; the counterparty
peer-encryption-public-key = 32 bytes             ; the counterparty
created-at                 = uint64be              ; seconds, informational only
own-signing-seed           = 32 bytes             ; recovery only
own-encryption-ikm         = 32 bytes             ; recovery only
relay-hint-count           = 1 byte, 0..=MAX_RELAY_HINTS
relay-hints                = relay-hint-count * (uint16be length || bytes)
```

- **CW-OFFLINE-005:** A producer MUST set `bundle-type` to exactly one
  defined value and MUST include `own-signing-seed`/`own-encryption-ikm`
  if and only if `bundle-type` is recovery. A consumer MUST reject a
  plaintext that is not exactly this structure for its declared type
  (wrong magic, wrong version, unrecognized type, truncated, or with a
  relay-hint count or length outside `CW-OFFLINE-002`'s bounds) as
  malformed, distinct from an authentication failure.
- **CW-OFFLINE-006:** The importing device MUST reconstruct its own
  identity for a recovery bundle only via the same deterministic
  constructions already defined for secure key loading
  (`RelaySigningKey::from_seed`, `EncryptionSecretKey::derive`), and MUST
  treat `own-signing-seed`/`own-encryption-ikm` with the same
  confidentiality as any other private key material.

## Import outcomes

- **CW-OFFLINE-007:** An importer MUST attempt to open a bundle only with
  its own encryption secret key and MUST reject a bundle that does not
  authenticate under it -- whether from tampering, an unintended recipient,
  or a wrong expected exporter principal -- without exposing any partial
  plaintext, and MUST NOT distinguish in its externally observable behavior
  between these causes.
- **CW-OFFLINE-008:** An importer MUST deduplicate accepted bundles by
  `bundle-id`. Importing an already-recorded `bundle-id` again MUST be a
  no-op that reproduces the same outcome, not a second application-level
  effect.
- **CW-OFFLINE-009:** An importer that already holds an imported bundle for
  a given `(queue-id, role)` MUST reject a new bundle for the same pair
  whose `peer-principal` differs, as a conflicting identity change, unless
  the application explicitly confirms a deliberate counterparty
  replacement. A new bundle for the same `(queue-id, role, peer-principal)`
  differing only in relay hints or `created-at` MAY be accepted as a relay
  hint update without changing any stored identity.
- **CW-OFFLINE-010:** An implementation MUST reject an unrecognized
  `cofferwire-offline` version before attempting to decrypt or interpret
  its payload, and MUST NOT guess another version's layout
  (`CW-VERSION-010`).

## Relay replacement

Relay replacement means updating which relay hints a client attempts for an
existing `queue-id`; it does not change the queue's identifier, either
principal, or any application-level identifier.

- **CW-OFFLINE-011:** Replacing a queue's relay hints, by import or by any
  other means, MUST NOT change `queue-id`, `sender`, `recipient`, or any
  application message or receipt identifier, and MUST NOT be treated by any
  layer as producing a new application event (`CW-ARCH-004`,
  `CW-ARCH-010`). Local durable state keyed by these identifiers -- an
  `InboxStore` commit or a `ReceiptStore` record -- MUST remain valid and
  MUST NOT be invalidated, reset, or duplicated by a relay-hint change.

An old relay that is unavailable or malicious cannot be forced to release
messages it never delivers; this profile lets a device recover its own
already-durable state and resume receiving through a new relay, and cannot
by itself recover a message a withholding relay never serves. A sender that
learns of a relay replacement is expected to resend outstanding messages
through the replacement, exactly as an ordinary lost-response retry already
requires (`CW-ARCH-005`).

## Open decisions

- how an importing device's encryption public key reaches the exporting
  device before a bundle can be sealed to it;
- whether a future revision defines a bundle type that also carries
  received-but-unacknowledged ciphertext for a fully offline handoff;
- device enrollment and queue rotation terminology beyond one existing
  relationship's bootstrap and recovery.
