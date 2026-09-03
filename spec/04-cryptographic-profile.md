# Cryptographic Profile Boundary (Draft)

This document defines the mandatory boundary between the v1 wire codec and
a concrete cryptographic suite. It intentionally does not select a
signature, MAC, capability construction or end-to-end encryption
algorithm. Until such a suite and its public vectors are adopted, v1 is
structurally implementable but MUST NOT be represented as providing
authenticated relay access or end-to-end security.

Normative terms are interpreted as described by RFC 2119 and RFC 8174.
Wire fields and status values are defined in `05-wire-format.md`.

## Relay-command authentication

- **CW-CRYPTO-001:** Every v1 request command (`CREATE_QUEUE`, `SEND`,
  `FETCH`, `ACK` and `DELETE_QUEUE`) MUST pass through the same
  transport-independent authentication boundary. A concrete profile MUST
  define the syntax of the opaque `auth` byte string, verification key or
  capability material for each queue role, algorithm identifiers and
  algorithm-agility rules. Its encoded `auth` content MUST fit the
  0–1024-byte bound in CW-WIRE-014.
- **CW-CRYPTO-002:** The mandatory authenticated request bytes are the
  exact `preamble || payload` bytes defined by CW-WIRE-016. A profile MUST
  bind all of them without decoding and re-encoding. It MAY additionally
  bind a fixed domain-separation string and profile metadata carried
  inside `auth`, but it MUST specify those additional bytes exactly and
  authenticate them against modification.
- **CW-CRYPTO-003:** A relay MUST verify command authentication and replay
  state before queue authorization, resource-policy checks or any queue
  mutation. Missing, malformed or cryptographically invalid `auth` MUST
  produce `AUTH_INVALID` and no queue-visible effect.
- **CW-CRYPTO-004:** A 32-byte `principal` is an identifier or key
  reference, not a bearer credential. Knowledge or observation of its
  bytes alone MUST NOT permit construction of valid `auth`. A request
  whose proof verifies but whose authenticated principal lacks the named
  queue role MUST produce `UNAUTHORIZED` and no queue-visible effect.
- **CW-CRYPTO-005:** Authentication MUST have identical meaning over
  HTTPS, WebSocket, a local file or any later transport binding. TLS
  identity, cookies, headers, connection continuity and request ordering
  MAY provide defense in depth but MUST NOT replace `auth` verification.
- **CW-CRYPTO-006:** Because direction, version, request ID, command and
  every body field are inside the mandatory authenticated bytes, changing
  any of them — including substituting a queue, principal, message ID,
  opaque payload or TTL — MUST make verification fail with `AUTH_INVALID`.
  Proof generated for one command or queue MUST NOT authorize another.
- **CW-CRYPTO-007:** A relay MUST durably reserve an authenticated
  `(principal, request-id)` before applying its command, then commit the
  command effect and recorded response atomically. An exact retry of the
  same authenticated request MUST return that response without applying
  the command again. Reuse of the tuple with different
  `preamble`, `payload` or `auth`, and any replay rejected by a concrete
  profile's stricter freshness window, MUST produce `AUTH_REPLAY` without
  a queue-visible effect. Replay records are queue-scoped and MUST remain
  until that queue is deleted; a concrete profile MUST define equivalent
  durable handling for `CREATE_QUEUE` at the provisioning boundary.

These rules define failure semantics and byte binding, not a cryptographic
construction. A concrete profile is incomplete until independent test
vectors demonstrate valid proofs plus wrong-version, wrong-request-ID,
wrong-direction, wrong-command, wrong-queue, modified-body and replay
rejection cases.

## End-to-end payload protection

Relay-command authentication authorizes access to queue state. It does not
make the relay trustworthy and does not authenticate application
plaintext. A later concrete profile separately defines how clients
encrypt and authenticate the opaque message payload, including key
derivation, nonces, associated data, sender authentication and public
positive/negative vectors. The receive order remains the one required by
CW-ARCH-007 through CW-ARCH-010: verify and decrypt, validate, durably
commit locally, then issue relay ACK.

## Open decisions

- the reviewed standard signature, MAC or capability suite used by
  `auth`;
- provisioning and rotation of queue-scoped verification material;
- exact domain-separation and profile-metadata encoding;
- freshness windows stricter than the mandatory request-ID replay record;
- the end-to-end application-payload protection suite.
