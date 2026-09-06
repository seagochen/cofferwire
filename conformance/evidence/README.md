# Queue-v1 interoperability evidence

验证体系的模块关系和统一入口见
[`../../docs/detailed_design/60_一致性验证与独立实现.md`](../../docs/detailed_design/60_一致性验证与独立实现.md)。

`interop-matrix-v1.json` is the machine-readable result of running
`scripts/run_interop_matrix.py` against the frozen
`CW-SCOPE-QUEUE-V1-2026-09-06` scope.

The runner builds the Rust line-transport relay, runs one common semantic trace
catalog across all four current-version client/relay combinations, runs public
codec and cryptographic vectors in both implementations, and records the exact
source revision, toolchain, commands, and SHA-256 artifact identities.

Run from a clean checkout with Python 3.11+, Rust 1.84, and the dependency in
`independent/python/pyproject.toml` installed:

```console
python3 scripts/run_interop_matrix.py --output conformance/evidence/interop-matrix-v1.json
```

Queue v1 is the first registered version, so there is no previous/current pair
inside the compatibility window. This is recorded as `not-applicable`, not as a
passing interoperability combination. Unknown-version and downgrade rejection
remain required and are exercised by both implementations.

## Continuous fuzzing evidence

`fuzz-evidence-v1.json` is the machine-readable result of a clean hostile-input
fuzzing run (see `fuzz/README.md`). It records the exact revision, nightly
rustc and cargo-fuzz versions, target list, per-target budget (the budget this
run actually used and the 900-second scheduled-CI budget it stands in for),
RSS/timeout/input limits, corpus provenance, and the unresolved crash count.

Regenerate after a passing run with:

```console
COFFERWIRE_FUZZ_SECONDS=10 scripts/fuzz_smoke.sh
python3 scripts/collect_fuzz_evidence.py
```

## System-level fault injection and model-checking evidence

`durability-evidence-v1.json` is the machine-readable result of the
system-level fault-injection and model-checking regression suite (see the
`hard_process_crashes_*`, `*_storage_faults_*`, `*_replay_*`,
`concurrent_*`, `clock_jumps_*`, `*_backup_*`, and
`long_generated_sequence_*` tests across `cofferwire-relay`,
`cofferwire-client`, and `cofferwired`). For each documented fault class it
records which named tests cover it, the fixed seed or budget that makes the
scenario deterministic and reviewable, and each test's pass/fail result from
an actual `cargo test --workspace` run.

Regenerate after a passing run with:

```console
python3 scripts/collect_durability_evidence.py
```
