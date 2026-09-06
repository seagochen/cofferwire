#!/usr/bin/env python3
"""Collect release evidence for the continuous hostile-input fuzzing gate.

Run after `scripts/fuzz_smoke.sh` completes without a crash, timeout, OOM, or
sanitizer failure. Records the exact revision, toolchain, per-target budget,
resource limits, corpus provenance, and unresolved-crash count so the fuzzing
gate result can be reviewed without re-running it.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    "decode-frames",
    "decode-blob-frames",
    "verify-hostile-proofs",
    "relay-transitions",
]
SCHEDULED_CI_SECONDS_PER_TARGET = 900


def run(*args: str) -> str:
    return subprocess.run(
        args, cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def unresolved_crashes() -> dict[str, list[str]]:
    unresolved: dict[str, list[str]] = {}
    for target in TARGETS:
        directory = ROOT / "fuzz" / "artifacts" / target
        if not directory.is_dir():
            unresolved[target] = []
            continue
        unresolved[target] = sorted(
            entry.name
            for entry in directory.iterdir()
            if entry.is_file()
            and entry.name.startswith(("crash-", "timeout-", "oom-"))
            and not entry.name.endswith(".minimized")
        )
    return unresolved


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(ROOT / "conformance" / "evidence" / "fuzz-evidence-v1.json"),
    )
    parser.add_argument(
        "--this-run-seconds-per-target",
        type=int,
        default=int(os.environ.get("COFFERWIRE_FUZZ_SECONDS", "10")),
        help="Budget actually used for the run this evidence describes.",
    )
    args = parser.parse_args()

    unresolved = unresolved_crashes()
    evidence = {
        "format": "cofferwire-fuzz-evidence-v1",
        "revision": run("git", "rev-parse", "HEAD"),
        "toolchain": {
            "rustc_nightly": run("rustc", "+nightly", "--version"),
            "cargo_fuzz": run("cargo", "fuzz", "--version"),
        },
        "targets": TARGETS,
        "budget": {
            "this_run_seconds_per_target": args.this_run_seconds_per_target,
            "scheduled_ci_seconds_per_target": SCHEDULED_CI_SECONDS_PER_TARGET,
        },
        "limits": {
            "rss_limit_mb": int(os.environ.get("COFFERWIRE_FUZZ_RSS_MB", "1024")),
            "timeout_seconds": int(
                os.environ.get("COFFERWIRE_FUZZ_TIMEOUT_SECONDS", "10")
            ),
            "max_input_bytes": 1_049_601,
        },
        "corpus_source": (
            "scripts/prepare_fuzz_corpus.py derives seeds from the tracked "
            "vectors/codec-v1.json, vectors/blob-v1.json, and "
            "vectors/queue-v1-traces.json public/interop vectors, exact blob "
            "manifest/chunk vectors, and a fixed set of hostile-input byte "
            "classes (indefinite-length markers, truncation, declared "
            "allocation bombs) into the ignored "
            "fuzz/target/generated-corpus/ directory; it is fully "
            "reproducible from tracked files."
        ),
        "unresolved_crashes": {
            "count": sum(len(names) for names in unresolved.values()),
            "by_target": unresolved,
        },
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
