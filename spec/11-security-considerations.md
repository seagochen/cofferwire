# Security Considerations (Draft)

This document is the operational-limits and abuse-control counterpart to
`02-threat-model.md`. The threat model states what an adversary can do and
what the protocol promises; this document states what a conforming
implementation does concretely to stay inside those promises when it is
exposed to a hostile or merely overloaded network, and it names the
machine-readable catalog that keeps those concrete numbers honest.

It applies across every profile implemented in this repository (queue-v1,
`cofferwire-blob/1`, `receipts/1`, `cofferwire-offline/1`) and to any later
application profile built on top of them, unless a profile document states a
narrower or additional rule of its own.

## Bounded work before authentication

`09-transport-bindings.md`'s baseline resource policy already fixes the
reference daemon's connection, body-size and concurrency bounds. This section
makes explicit the order those bounds apply in relative to parsing and
authentication, refining `CW-THREAT-006` for the reference transport binding.

- **CW-SECURITY-001:** A relay-facing binding MUST apply its connection-count
  bound, request-body-size bound and concurrent-command bound before decoding
  a request frame or invoking a cryptographic verification routine on it, so
  that an unauthenticated flood of connections or oversized bodies cannot
  force unbounded parsing, allocation or cryptographic work. Rejection at
  this stage MUST NOT depend on the request's content being well-formed.

## Per-credential rate limiting

The threat model's open decisions previously left "rate limits and
proof-of-work or other abuse controls" unresolved. This section resolves the
rate-limiting half: the reference daemon bounds how often one already-
authenticated credential may invoke durable business logic, independent of
the connection- and body-level bounds above.

- **CW-SECURITY-002:** Once a request has passed frame decoding and relay-
  command authentication, an implementation MUST additionally bound the rate
  of accepted requests per credential (queue principal for queue-v1 commands,
  capability identifier for blob/1 commands) within a rolling time window
  before invoking durable business logic, and MUST reject a request under a
  credential that is over its budget rather than executing it.
- **CW-SECURITY-003:** A rate limiter MUST bound the number of distinct
  credentials it tracks at once and MUST fail closed -- reject rather than
  silently evict and re-admit -- for a new credential once that bound is
  reached, so that a flood of one-off credentials cannot grow the limiter's
  memory without bound.
- **CW-SECURITY-004:** The concrete window length, per-window request budget
  and tracked-credential capacity are deployment policy, not a wire-protocol
  requirement, and different values do not affect interoperability.

Proof-of-work and other non-rate-based abuse controls remain an open
decision; this document resolves only the rate-limiting half.

## Published, code-checked operational limits

- **CW-SECURITY-005:** The reference daemon's concrete operational limits
  (frame and body size, connection and concurrency bounds, timeouts, and the
  rate-limit window/budget/capacity from `CW-SECURITY-002`–`CW-SECURITY-004`)
  MUST be published in a machine-readable catalog, and an automated test MUST
  fail if that catalog and the compiled constants it describes ever diverge.
  See `docs/conformance/operational-limits-v1.json` and
  `apps/cofferwired/tests/operational_limits.rs`.

## Secret redaction in diagnostics

- **CW-SECURITY-006:** The `Debug` and `Display` representations of an error,
  log record or metric value produced by client or relay code on any of these
  profiles' code paths MUST NOT render plaintext, ciphertext, private
  signing or encryption key material, key-derivation seeds, capability
  tokens or other secret-bearing bytes. An error variant MAY name which
  check failed; it MUST NOT carry the bytes that failed it.

## Test mapping

`CW-SECURITY-001` is exercised by the reference daemon's oversized-body and
connection-limit tests. `CW-SECURITY-002`–`CW-SECURITY-004` are exercised by
`apps/cofferwired/src/rate_limit.rs`'s unit tests and by
`queue_rate_limit_returns_service_unavailable_once_exceeded`, which drives the
limiter through the real HTTP binding rather than only the standalone type.
`CW-SECURITY-005` is exercised by `operational_limits.rs`. `CW-SECURITY-006`
is exercised by one tamper-and-inspect test per profile: the durable relay's
`durable_relay_error_debug_never_contains_opaque_payload_bytes`, the client
state machine's `client_error_debug_never_contains_plaintext_or_ciphertext`,
the offline-bundle module's `bundle_error_debug_never_contains_relay_hints_or_key_material`
and `import_error_debug_never_contains_relay_hints_or_key_material`, and the
receipt module's `receipt_verification_error_debug_never_contains_plaintext_or_signature`.
