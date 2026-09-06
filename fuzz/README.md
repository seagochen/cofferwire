# Hostile-input fuzzing

This directory is the executable inventory for every unauthenticated parser
and attacker-controlled transition in v1.

| Surface | Target | Bound |
|---|---|---|
| queue request/response canonical CBOR | `decode-frames` | 65,536-byte protocol rejection |
| blob request/response canonical CBOR and manifest | `decode-blob-frames` | 1,049,600-byte protocol rejection |
| queue/blob Ed25519 proof parsing and verification | `verify-hostile-proofs` | fixed 1,049,601-byte fuzzer input cap |
| authenticated queue state transitions, quota and expiry | `relay-transitions` | 256 operations, 1,024-byte payload policy |

HTTP and WebSocket do not add another parser: Axum supplies one already
delimited binary body to the same codec functions. TLS is terminated by
Rustls. HPKE and blob AEAD inputs are fixed-layout byte strings parsed and
authenticated by `open_message`/`open_blob`; their mutation classes are
covered by deterministic crypto/vector tests and the proof target's decoded
payload mutations. SQLite parses no unauthenticated network bytes.

`python3 scripts/prepare_fuzz_corpus.py` derives disposable corpora under the
ignored `fuzz/target/generated-corpus/` directory from public codec/blob
vectors, interoperability traces, exact manifests/chunks, boundary lengths,
deep nesting, truncation and declared allocation bombs. Generated corpora and
crash artifacts are reproducible from tracked files.

Run `COFFERWIRE_FUZZ_SECONDS=10 scripts/fuzz_smoke.sh` locally. Each target has
a 1 GiB RSS limit, ten-second per-input timeout, bounded maximum input and a
hard wall-clock budget. Panic, sanitizer failure, OOM, timeout, or nonzero exit
fails the script. LeakSanitizer is disabled because it cannot operate under the
restricted `ptrace` policy used by CI and Codex; Rust panic, AddressSanitizer,
timeout and RSS checks remain active. Scheduled CI uses 900 seconds per target
and retains all artifacts for 30 days; ordinary push/PR CI only compiles every
target (`cargo check --manifest-path fuzz/Cargo.toml --bins`) without running
them. On a scheduled-run failure, `scripts/minimize_fuzz_crashes.sh` shrinks
every `crash-`/`timeout-`/`oom-` artifact with `cargo fuzz tmin` (an
`<artifact>.minimized` copy lands next to the original) before artifacts
upload, so triage starts from the smallest reproducer. A crash is still
promoted by hand: copy the (minimized) input into the relevant deterministic
test/corpus and track it with a security Issue before the gate may pass.

Diagnostics from these targets contain only stable error categories; protocol
keys, proofs, capabilities, plaintext and ciphertext bytes are never formatted.
