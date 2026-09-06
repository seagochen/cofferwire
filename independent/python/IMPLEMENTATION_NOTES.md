# Independence and implementation notes

- Scope: queue v1 at `CW-SCOPE-QUEUE-V1-2026-09-06`.
- Inputs used: public Markdown specifications, CDDL, JSON vectors, and
  conformance traces only.
- Excluded inputs: Rust source, Rust APIs, compiled Rust libraries, generated
  bindings, and copied Rust algorithms.
- Language/runtime: Python 3.11 or later with `cryptography==46.0.5`; canonical
  CBOR and protocol state machines are implemented locally.
- Roles: `Client` emits all five queue commands; `Relay` verifies authentication
  and persists queue, delivery, and replay state with SQLite.

No specification ambiguity was found while implementing the public vectors.
Cross-implementation testing did expose one reference behavior difference:
the Rust daemon returned an idempotent semantic result rather than the recorded
response for an exact authenticated retry. The #20 implementation work fixed
that observable result and added a regression test; no specification change was
required because `CW-CRYPTO-008` and `CW-WIRE-019` were already explicit.
