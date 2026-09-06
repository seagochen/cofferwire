# External Cryptography and Protocol Review Scope

This is the required scope and hand-off procedure for issue #27 and release
gate 7. The reviewer must be independent of the Cofferwire design and
implementation work, and must have demonstrable experience reviewing applied
cryptography, binary protocols, or distributed authorization systems. A
self-review, automated scanner report, or review by an implementation
co-author does not satisfy this gate.

## Frozen input

The project coordinator selects one full Git commit and creates the review
archive directly from committed bytes:

```sh
python3 scripts/build_review_bundle.py --revision COMMIT --output cofferwire-review.tar
sha256sum cofferwire-review.tar
```

The archive contains `REVIEW-MANIFEST.json`, source, specifications, CDDL,
vectors, application profiles, independent implementation, tests, release
evidence, `TESTING.md`, and `SECURITY.md`. The manifest records the exact
commit and SHA-256 of every member. The reviewer must identify that commit and
archive digest in the final report. Any remediation after review creates a new
candidate revision; the project response must map each finding to its fix and
verification, and the reviewer must state whether re-review was performed.

## Required technical coverage

The report must explicitly address every topic below, even when the conclusion
is “no finding.”

1. `cryptographic_construction`: HPKE mode/suite use, Ed25519 use, randomness,
   canonical authenticated bytes, message/blob content protection, receipts,
   offline bundles, and domain separation.
2. `capability_lifecycle`: generation, role separation, expiry, renewal,
   revocation, deletion limits, leakage consequences, and post-compromise
   behavior.
3. `queue_blob_authorization`: CREATE/SEND/FETCH/ACK/DELETE and all blob command
   state transitions, principal/capability confusion, replay records, and
   transaction boundaries.
4. `replay_rollback_downgrade`: request-ID reuse, duplicate delivery, stale
   databases/backups, clock changes, unknown versions/algorithms, negotiation,
   and cross-profile substitution.
5. `storage_deletion_retention`: SQLite durability assumptions, backups,
   queue cascade deletion, blob grant revocation versus ciphertext retention,
   and operator claims.
6. `metadata_traffic_correlation`: relay-visible IP, timing, length, queue and
   blob access; padding limitations; receipts and offline behavior; any
   correlation experiment and the claims it does or does not support.
7. `dos_abuse_controls`: work before authentication, parser/allocation bounds,
   connection/stream/command bounds, rate limits, quota exhaustion, key-space
   pressure, and unauthenticated error behavior.
8. `client_relay_implementation`: all Rust crates and `apps/cofferwired`, with
   special attention to durable local commit before ACK, retries, secret
   redaction, concurrency, and error mapping.

The reviewer should also inspect the independent Python implementation and
public vectors for specification ambiguity, but it is not a substitute for
reviewing the Rust client and relay.

## Finding handling

- Potentially exploitable, unpatched findings are reported only through the
  private channels in `SECURITY.md`; neither titles nor reproduction details
  belong in public issues before coordinated disclosure.
- Every finding has a stable opaque identifier, severity, affected profiles,
  disposition, and remediation reference. Public reports may use a redacted
  description until disclosure is safe.
- `critical` and `high` findings must be fixed and independently verified.
  Risk acceptance does not satisfy the version 1 gate for these severities.
- `medium` and `low` findings require one explicit disposition: fixed,
  accepted with rationale, or a public follow-up issue once disclosure is
  safe.
- The public report and project response must not claim that scope coverage is
  equivalent to proof of security or anonymity.

## Deliverables

The reviewer provides a public report and a machine-readable result based on
`docs/security/external-review-result.example.json`. The project publishes a
point-by-point response, remediation evidence, and the validator result:

```sh
python3 scripts/validate_external_review.py path/to/external-review-result.json
```

Passing the validator checks completeness and release-blocking dispositions;
it cannot establish that a claimed reviewer identity, qualification, or
independence is genuine. The maintainer must verify those facts separately.
