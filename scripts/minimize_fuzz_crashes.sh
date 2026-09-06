#!/usr/bin/env bash
# Shrinks any crash/timeout/OOM artifact left by scripts/fuzz_smoke.sh so a
# CI failure uploads a small, triageable reproducer next to the original.
# Intended to run after a fuzz run fails and before artifacts are uploaded;
# it never fails the job itself, since a minimization failure is not a reason
# to discard the original artifact.
set -uo pipefail

rss_mb="${COFFERWIRE_FUZZ_RSS_MB:-1024}"
timeout="${COFFERWIRE_FUZZ_TIMEOUT_SECONDS:-10}"
targets=(decode-frames decode-blob-frames verify-hostile-proofs relay-transitions)
export ASAN_OPTIONS="detect_leaks=0${ASAN_OPTIONS:+:${ASAN_OPTIONS}}"

found_any=0
for target in "${targets[@]}"; do
  directory="fuzz/artifacts/${target}"
  [ -d "${directory}" ] || continue
  shopt -s nullglob
  for artifact in "${directory}"/crash-* "${directory}"/timeout-* "${directory}"/oom-*; do
    [ -f "${artifact}" ] || continue
    case "${artifact}" in
      *.minimized) continue ;;
    esac
    found_any=1
    echo "Minimizing ${artifact} (target: ${target})"
    # -max_len is deliberately omitted: libFuzzer's internal minimizer derives
    # its own bound from the crashing input and asserts if one is also passed.
    output="$(cargo +nightly fuzz tmin "${target}" "${artifact}" -- \
      "-rss_limit_mb=${rss_mb}" "-timeout=${timeout}" -detect_leaks=0 \
      2>&1)"
    status=$?
    minimized_path="$(printf '%s\n' "${output}" | sed -n 's/^\s*Minimized artifact:\s*$/&/p' > /dev/null; \
      printf '%s\n' "${output}" | awk '/Minimized artifact:/{getline; getline; print; exit}' | tr -d '\t')"
    if [ "${status}" -eq 0 ] && [ -n "${minimized_path}" ] && [ -f "${minimized_path}" ]; then
      destination="${artifact}.minimized"
      cp "${minimized_path}" "${destination}"
      echo "  -> ${destination} ($(wc -c < "${destination}") bytes, was $(wc -c < "${artifact}") bytes)"
    else
      echo "  tmin did not produce a minimized artifact for ${artifact}; keeping original only" >&2
      printf '%s\n' "${output}" >&2
    fi
  done
  shopt -u nullglob
done

if [ "${found_any}" -eq 0 ]; then
  echo "No crash, timeout, or OOM artifacts found under fuzz/artifacts/; nothing to minimize."
fi
exit 0
