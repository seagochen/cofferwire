# Cofferwire Testing Strategy

Testing starts with the specification. It is not postponed until the product is feature-complete. Every normative statement must be observable, testable and assigned a stable conformance identifier.

## 1. Specification traceability

Each normative requirement receives an ID such as `CW-QUEUE-ACK-004` and records:

- the requirement text and specification version;
- applicable client, relay or both;
- positive tests;
- negative/adversarial tests;
- expected observable result;
- any security property it supports.

A generated coverage report must fail CI when a new `MUST` has no associated test. `SHOULD` requirements require a test or a documented implementation exception.

## 2. Canonical test vectors

Language-neutral vectors will cover:

- canonical encoding and byte-for-byte framing;
- key derivation, encryption, signatures and capability authentication;
- deterministic object and message identifiers;
- padding boundaries and maximum sizes;
- valid messages plus malformed, truncated and non-canonical variants;
- version negotiation and unknown extension handling.

`vectors/blob-v1.json` fixes the blob/1 content-protection, chunk digest,
manifest, ciphertext identity and independent capability fixtures. Its stable
negative IDs cover tampering, reordering, incomplete visibility, capability
cross-use, expiry and committed immutability. Run these executable vector checks
with `cargo test -p cofferwire-test`.

Vectors contain fixed test-only keys and must never be accepted as production credentials. Formats should be simple JSON metadata plus binary fixtures, even when the protocol itself uses a binary encoding.

## 3. Unit and component tests

Rust components test parsers, encoders, cryptographic wrappers, storage transactions and state transitions. Coverage targets are useful diagnostics, not proof of protocol correctness. Security-critical branches and every error code require explicit tests.

`cofferwire-test` validates the v1 structural CDDL against positive and
negative CBOR examples, including command/body discrimination, response
body selection, forbidden data-model types, authentication size and the
maximum message boundary. Run it with `cargo test -p cofferwire-test`.

`cofferwire-codec`, `cofferwire-crypto`, and `cofferwire-client` exercise strict
framing, public cryptographic vectors, tampering, retry, redelivery and durable
commit ordering. Run the complete suite with `cargo test --workspace`. The
parser fuzz target is buildable with `cargo check --manifest-path
fuzz/Cargo.toml` and runnable with `cargo fuzz run decode_frames`.

## 4. Reference-model and property testing

A small executable model defines queue and blob state independently from the production server. Property tests generate command sequences and compare the implementation with the model.

Required invariants include:

- an accepted message is delivered at least once until ACK or expiry;
- ACK never deletes a different or not-yet-persisted message;
- duplicate commands do not create divergent committed state;
- committed blobs are immutable and hash-valid;
- uncommitted or partial blobs are never downloadable;
- unauthorized credentials never gain send, receive, renew or delete authority;
- restart recovery preserves all acknowledged durability guarantees.

## 5. Interoperability matrix

The decisive protocol test is independent interoperability:

| Client | Relay | Required |
|---|---|---:|
| Rust reference | Rust reference | yes |
| Independent client | Rust reference | yes |
| Rust reference | Independent relay | yes |
| Independent client | Independent relay | yes |
| Previous supported version | Current version | during compatibility window |

Every matrix result identifies the profile/version under test. Queue-v1 results
also identify scope revision `CW-SCOPE-QUEUE-V1-2026-09-06`; blob/1 is tested in
a separate matrix and is never inferred from queue-v1 support.

The second implementation must be written from the public specification and vectors, preferably in another language and without importing reference implementation code. Any ambiguity it finds is a specification bug.

The independent Python client and SQLite relay live in `independent/python`.
Their local codec, Ed25519, HPKE-vector and queue tests run with
`python3 -m unittest discover -s independent/python/tests -v`; independence and
dependency boundaries are recorded in `independent/python/IMPLEMENTATION_NOTES.md`.

## 6. Parser fuzzing and hostile input

Continuous fuzz targets cover every unauthenticated parser and state transition. Corpora include valid vectors, boundary sizes and captured interoperability traces.

Tests must exercise:

- arbitrary and deeply nested input;
- length overflows and allocation bombs;
- invalid Unicode where text is allowed;
- duplicate/non-canonical fields;
- truncated frames and concatenated frames;
- invalid signatures, tags, nonces and capabilities;
- unsupported versions and extensions;
- request floods and quota exhaustion.

No network input may panic the process, trigger unbounded allocation or expose secrets in logs/errors.

## 7. Fault-injection and distributed behavior

A deterministic network harness introduces:

- dropped, delayed, duplicated and reordered messages;
- disconnects at every request/response boundary;
- relay restart before and after durable commit;
- disk-full, read-only disk and partial-write failures;
- clock jumps and expiry races;
- concurrent fetch/ACK/delete operations;
- unavailable, malicious and inconsistent relays.

Long-running randomized scenarios maintain a model of accepted messages and verify that the implementation neither loses them before its documented durability boundary nor invents messages.

## 8. Security validation

Automated negative tests verify authentication boundaries, replay handling, key separation, downgrade resistance and ciphertext/object integrity. Dependency scanning, secret scanning and reproducible-build checks run in CI.

Before version 1.0, an external review must cover:

- cryptographic construction and domain separation;
- capability lifecycle and revocation limits;
- queue/blob authorization state machines;
- replay, rollback and downgrade attacks;
- storage deletion/retention claims;
- metadata leakage and traffic correlation assumptions;
- denial-of-service and abuse controls.

Security testing must not claim anonymity solely because payloads are encrypted. Separate experiments should record what a relay can correlate through IP addresses, timing, sizes, queue access and blob access.

## 9. Durability and recovery

Crash tests terminate the relay/client at all persistence boundaries, reopen the same storage and verify invariants. Backups are restored into fresh processes. Migration tests upgrade real databases from every supported version.

Special attention is required for the receive path:

```text
download -> authenticate -> persist locally -> relay ACK
```

Tests must prove that crashes cannot move ACK before durable local persistence. Application receipts are tested separately and must not be confused with relay deletion ACKs.

## 10. Performance and resource limits

Benchmarks measure throughput and latency, but also memory, file descriptors, storage amplification and recovery time. Load tests include many mostly-idle queues, since that matches the family-sync workload better than chat-only message rates.

Published limits must be enforced consistently:

- maximum frame, message, object and chunk sizes;
- queue depth and per-capability rate limits;
- TTL/lease bounds;
- maximum concurrent streams and connections;
- bounded work before authentication.

## 11. Platform and transport tests

The same semantic traces run over every supported binding. At minimum:

- native Rust client over the baseline network transport;
- browser/WASM client where supported;
- offline file export/import;
- IPv4/IPv6 and common reverse-proxy deployments;
- suspend/resume and long-offline mobile behavior.

Transport substitution must not change message identifiers, verification results or application state.

## 12. Release gates

A release candidate cannot become version 1.0 unless:

1. every `MUST` is covered and all conformance tests pass;
2. all public positive and negative vectors pass in two independent implementations;
3. the full interoperability matrix passes;
4. fuzz targets complete the agreed continuous budget with no unresolved crash;
5. fault-injection and crash-recovery suites pass;
6. backward/forward version negotiation is demonstrated;
7. no unresolved critical/high security finding remains;
8. threat model, privacy limitations and operational limits are published;
9. a real family-tree pilot completes delayed delivery, relay replacement and offline recovery;
10. release artifacts and test results are reproducible and publicly archived.

These gates verify conformance to the documented protocol. They do not prove universal security; claims must remain limited to the threat model and evidence actually tested.
