# Queue-v1 interoperability evidence

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
python3 scripts/run_interop_matrix.py --output docs/conformance/interop-matrix-v1.json
```

Queue v1 is the first registered version, so there is no previous/current pair
inside the compatibility window. This is recorded as `not-applicable`, not as a
passing interoperability combination. Unknown-version and downgrade rejection
remain required and are exercised by both implementations.
