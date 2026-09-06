# Cryptographic Profile

This document fixes the only cryptographic profile accepted by Cofferwire
protocol version 1. It composes reviewed public standards; it does not define a
new signature, key agreement, KDF, AEAD, or nonce construction.

Normative terms are interpreted as described by RFC 2119 and RFC 8174. Wire
fields and status values are defined in `05-wire-format.md`. The public known
answer data is in `vectors/crypto-v1.json` and is explicitly test-only.

## Algorithms and identifiers

Profile identifiers and algorithm identifiers are unsigned integers encoded in
network byte order at their fixed widths. Version 1 has one suite and no
negotiation:

| purpose | algorithm | standard ID | Cofferwire encoding |
|---|---|---:|---:|
| profile | Cofferwire v1 | n/a | `0x0001` |
| relay command signature | Ed25519 | RFC 8032 | `0x0001` |
| HPKE mode | Auth | RFC 9180 mode 2 | implicit |
| HPKE KEM | DHKEM(X25519, HKDF-SHA-256) | `0x0020` | `0x0020` |
| HPKE KDF | HKDF-SHA-256 | `0x0001` | `0x0001` |
| HPKE AEAD | ChaCha20-Poly1305 | `0x0003` | `0x0003` |

- **CW-CRYPTO-001:** Implementations MUST accept exactly the identifiers above
  for a v1 proof or ciphertext and MUST reject every other value. They MUST NOT
  silently substitute an algorithm, retry with another profile, or accept a
  partially recognized suite. Algorithm agility requires a new protocol or
  profile version with new vectors.
- **CW-CRYPTO-002:** Ed25519 is used because it has deterministic signatures,
  fixed 32-byte public keys matching the v1 principal width, and public RFC 8032
  vectors. Verification MUST reject non-canonical scalars and small-order public
  keys (the reference implementation uses strict verification).
- **CW-CRYPTO-003:** Authenticated HPKE is used because RFC 9180 specifies the
  KEM, labeled HKDF domain separation, AEAD nonce derivation, Auth mode, wire
  encodings and independent vectors as one construction. X25519, SHA-256 and
  ChaCha20-Poly1305 target the v1 128-bit classical security level and avoid
  platform-specific acceleration requirements.

The v1 profile does not provide post-quantum security, deniable sender
authentication, multi-recipient encryption, payload padding, traffic-analysis
resistance, or negotiation with other suites. HPKE Auth mode has the
key-compromise impersonation and recipient-key-compromise limitations described
by RFC 9180; in particular, later compromise of the recipient private key can
expose recorded v1 ciphertexts.

## Relay-command authentication

For v1, a queue-scoped `principal` is exactly an RFC 8032 Ed25519 public key.
Possession of the corresponding private key is proven by `auth`; presentation
of `principal` alone is never authorization.

The `auth` byte-string content is exactly 68 bytes:

```text
relay-auth = profile-id signature-id signature
profile-id = 2 bytes, 0x0001
signature-id = 2 bytes, 0x0001
signature = 64-byte Ed25519 signature
```

The signed message is the following concatenation, with no length prefix or
separator beyond the fixed domain's terminating zero byte:

```text
ASCII("cofferwire relay request v1") || 0x00 || preamble || payload
```

Here `preamble || payload` is the exact received range from CW-WIRE-016, not a
decoded or re-encoded value.

- **CW-CRYPTO-004:** Every `CREATE_QUEUE`, `SEND`, `FETCH`, `ACK`, and
  `DELETE_QUEUE` request MUST carry the 68-byte proof above. Missing, malformed,
  unknown-profile, unknown-algorithm, invalid-key, and invalid-signature cases
  MUST all produce `AUTH_INVALID` and no queue-visible effect.
- **CW-CRYPTO-005:** The relay MUST verify against the exact received
  authenticated bytes before queue authorization, policy checks, resource work,
  or mutation. Changing direction, version, request ID, command, queue,
  principal, message ID, opaque payload, TTL, or any other body byte MUST make
  verification fail.
- **CW-CRYPTO-006:** For commands with one acting principal, the signature MUST
  verify under that field. `CREATE_QUEUE` is signed by its `sender`; deployment
  admission policy MAY additionally require an out-of-band provisioning
  authorization. A valid signature from a principal lacking the required queue
  role produces `UNAUTHORIZED`, not `AUTH_INVALID`.
- **CW-CRYPTO-007:** Authentication is transport-independent. TLS identities,
  cookies, headers, connection continuity, and request ordering MAY add defense
  in depth but MUST NOT replace this proof.
- **CW-CRYPTO-008:** The relay MUST durably reserve `(principal, request-id)`
  before applying a command, then commit the command effect and recorded
  response atomically. An exact authenticated retry returns the recorded
  response. Reuse with different authenticated bytes or `auth` produces
  `AUTH_REPLAY` with no queue-visible effect. Queue-scoped replay records remain
  until queue deletion; the provisioning boundary MUST provide equivalent
  durable handling for `CREATE_QUEUE`.

## End-to-end application payload

Each device has a distinct long-term X25519 HPKE identity key pair in addition
to its relay-command Ed25519 key. CW-CRYPTO-010 requires the sender to know the
intended recipient device's HPKE public key and the recipient to know the
expected sender device's HPKE public key through an authenticated out-of-band
relationship.

One plaintext is protected using a new RFC 9180 Auth-mode setup and sequence
number zero. The opaque `SEND` payload has this exact form:

```text
e2e-payload = profile-id kem-id kdf-id aead-id enc ciphertext
profile-id = 2 bytes, 0x0001
kem-id     = 2 bytes, 0x0020
kdf-id     = 2 bytes, 0x0001
aead-id    = 2 bytes, 0x0003
enc        = 32-byte RFC 9180 X25519 encapsulated key
ciphertext = plaintext || 16-byte ChaCha20-Poly1305 tag
```

The HPKE `info` input is:

```text
ASCII("cofferwire hpke info v1") || 0x00 || profile-id || kem-id ||
kdf-id || aead-id || queue-id || sender || recipient || message-id
```

The HPKE AEAD associated data uses the identical fixed-width suffix but starts
with `ASCII("cofferwire hpke aad v1") || 0x00`. `sender` and `recipient` are
the queue-scoped Ed25519 principals, while HPKE Auth mode independently binds
the expected sender X25519 public key.

- **CW-CRYPTO-009:** A sender MUST generate a fresh HPKE ephemeral key with a
  cryptographically secure operating-system RNG for every encryption attempt.
  It MUST NOT reuse deterministic test RNG state, an encapsulation, or an HPKE
  context in production. RFC 9180 derives the ChaCha20-Poly1305 key and base
  nonce; the single v1 message uses sequence number zero, so callers do not
  construct or transmit a nonce.
- **CW-CRYPTO-010:** The four context identifiers above MUST be supplied from
  authenticated local queue configuration and the delivered message metadata.
  A recipient MUST reject a change to any identifier, algorithm field,
  encapsulated key, ciphertext byte, expected sender HPKE key, or recipient
  private key before exposing plaintext.
- **CW-CRYPTO-011:** A v1 encrypted payload has 40 bytes of header and
  encapsulated key plus a 16-byte AEAD tag. Therefore plaintext MUST be at most
  `MAX_MESSAGE_BYTES - 56 = 64318` bytes. Implementations MUST reject oversized
  plaintext before encryption.
- **CW-CRYPTO-012:** Decryption and authentication MUST precede application
  validation and durable local commit; relay ACK MUST follow that commit. HPKE
  failure MUST NOT produce partial plaintext, a relay ACK, or distinguishable
  errors for wrong sender key, wrong recipient key, context mismatch, or tag
  mismatch.

## Key generation and lifecycle

- **CW-CRYPTO-013:** Production Ed25519 seeds, X25519 input keying material and
  HPKE ephemeral material MUST contain at least 256 bits from a CSPRNG. Fixed
  keys and deterministic RNG streams in public vectors are test-only and MUST
  be rejected by production credential provisioning policy.
- **CW-CRYPTO-014:** Private keys MUST be stored using the platform's protected
  credential storage where available, MUST NOT be serialized through ordinary
  application state, and MUST be zeroized on drop by the cryptographic library.
  Private keys and plaintext MUST NOT appear in `Debug`, logs, metrics, error
  messages, panic text, or crash annotations.
- **CW-CRYPTO-015:** Key rotation creates a new device key identity and new
  device queue. V1 has no in-band key update, recovery, revocation, or downgrade
  mechanism. Old queues and private keys MUST remain only as long as required to
  drain already accepted messages, then be deleted according to local policy.
  An implementation MUST NOT reinterpret a new key under an old principal.

## Failure and vectors

`vectors/crypto-v1.json` records a fixed relay signature and a complete HPKE
envelope. The executable tests reproduce both, then mutate every authenticated
command byte, every envelope byte, every associated-data field, and both device
keys. These vectors complement the RFC 8032 and RFC 9180 vectors; they do not
replace them.

- **CW-CRYPTO-016:** Secret-bearing types MUST have redacted debug output.
  Errors MAY identify the failed operation or malformed public envelope, but
  MUST NOT contain key, proof, ciphertext, or plaintext bytes.
- **CW-CRYPTO-017:** Implementations claiming this profile MUST reproduce all
  positive vectors and reject every negative/tampered case. A round trip alone
  is insufficient evidence of interoperability.
