#!/usr/bin/env bash
set -euo pipefail

budget="${COFFERWIRE_FUZZ_SECONDS:-10}"
rss_mb="${COFFERWIRE_FUZZ_RSS_MB:-1024}"
timeout="${COFFERWIRE_FUZZ_TIMEOUT_SECONDS:-10}"
targets=(decode-frames decode-blob-frames verify-hostile-proofs relay-transitions)
export ASAN_OPTIONS="detect_leaks=0${ASAN_OPTIONS:+:${ASAN_OPTIONS}}"

python3 scripts/prepare_fuzz_corpus.py
mkdir -p fuzz/artifacts
for target in "${targets[@]}"; do
  mkdir -p "fuzz/artifacts/${target}"
  cargo +nightly fuzz run "${target}" "fuzz/target/generated-corpus/${target}" -- \
    "-max_total_time=${budget}" \
    "-rss_limit_mb=${rss_mb}" \
    "-timeout=${timeout}" \
    -detect_leaks=0 \
    -max_len=1049601 \
    "-artifact_prefix=fuzz/artifacts/${target}/"
done
