# Family-Tree v1 Pilot Plan

This plan is the execution contract for release gate 9 and issue #25. The
pilot uses synthetic family-tree records only. It must not contain real names,
dates, relationships, credentials, private keys, capabilities, queue IDs, IP
addresses, or raw application/relay logs in the public result.

The checked-in validator is intentionally stricter than a demonstration: a
result is accepted only when three distinct physical devices and two relays
with distinct operators have exercised every required failure and recovery
path against one candidate revision.

## Participants and isolation

Before starting, assign opaque public labels to:

- three physical devices (`device-a`, `device-b`, and `device-c`), each with a
  separate durable client store and its own queue principal;
- two relay deployments (`relay-a` and `relay-b`) with different public
  endpoints, databases, credentials, configuration files, and operators;
- one coordinator who records only aggregate results and SHA-256 digests.

An operator is a person or organization able to change, stop, restore, and
inspect only its own relay. Two processes controlled by one operator do not
meet the independent-operation requirement. A device may use any supported
OS, but its public description must be no more identifying than OS family and
architecture.

## Candidate and data

1. Check out the same full 40-character Git commit on every participant.
2. Build with the Rust version declared by the repository and record the
   binary/configuration SHA-256 digests.
3. Create a new synthetic tree whose fields contain only the tokens
   `PERSON-A`, `PERSON-B`, `RELATIONSHIP-A-B`, and monotonically numbered test
   notes. Never reuse production identities or data.
4. Stop immediately if a secret enters a log/result, a participant cannot
   erase the synthetic data, a protocol-specific workaround is proposed, or
   any verification/authentication error is ignored.

## Execution sequence

Record UTC start/end times and a pass/fail observation for every scenario.
Raw logs may be retained privately for debugging, but the public evidence
contains only bounded counts, duration buckets, versions, digests, and the
observations below.

1. **Delayed convergence:** keep `device-c` offline. Create and fan out update
   U1 from `device-a`; apply it on `device-b`; reconnect `device-c` and verify
   all three devices report the same revision leaf set without having been
   simultaneously online.
2. **Duplicate delivery:** suppress one relay ACK response after its durable
   commit. Retry the identical request and verify the application applies U1
   once while the relay response is safely replayed.
3. **Long offline:** disconnect `device-b` for at least 24 hours of wall-clock
   time. Apply further synthetic updates on the other devices, then reconnect
   and verify convergence. Accelerating only a protocol timestamp is not a
   substitute for this observation.
4. **Suspend/resume and lost notification:** suspend the client process or
   operating system on `device-c`, discard all notification hints, resume it,
   poll explicitly, and verify no accepted update is silently lost or applied
   twice.
5. **Relay replacement:** make `relay-a` unavailable without copying its
   database. Recreate affected queues on `relay-b` from authenticated recovery
   material, retransmit outstanding application updates, and verify that the
   family-tree object and revision identifiers are unchanged.
6. **Offline-only history recovery:** erase the synthetic application state on
   `device-c` while preserving only its documented recovery prerequisite.
   Disable network access, export a complete signed `FT-BUNDLE-V1` history to
   removable/local media, import and verify it on `device-c`, and compare the
   resulting leaf set byte-for-byte with the other devices before restoring
   networking.
7. **Receipts:** for every applied update, verify any `receipt.applied` binds
   the exact update bytes and signer expected by the application. Relay ACKs
   must not be counted as application receipts.

## Public result

Copy `docs/pilot/family-tree-v1-result.example.json`, replace every placeholder,
and run:

```sh
python3 scripts/validate_family_tree_pilot.py path/to/result.json
```

The validator rejects missing scenarios, fewer than three physical devices,
shared relay operators, duplicate endpoints, non-passing observations,
protocol exceptions, secret-like fields, and results that are not bound to a
single commit. Publish the validated result next to the release gate manifest.

Passing this validator checks completeness and internal consistency; it does
not prove that the named people, hardware, elapsed time, or observations are
truthful. Those facts require participant attestations and public review.
