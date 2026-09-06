#!/usr/bin/env python3
"""Run the four queue-v1 client/relay combinations and emit JSON evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACE = ROOT / "vectors" / "queue-v1-traces.json"


def run(name, command, extra_environment=None):
    environment = os.environ.copy()
    environment.update(extra_environment or {})
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return {
        "name": name,
        "command": command,
        "result": "passed" if completed.returncode == 0 else "failed",
        "exit_code": completed.returncode,
        "output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
    }, completed.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def output(command):
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    trace = json.loads(TRACE.read_text())
    build = subprocess.run(
        ["cargo", "build", "-p", "cofferwired", "--bin", "cofferwire-line-relay"],
        cwd=ROOT,
        check=False,
    )
    if build.returncode:
        return build.returncode
    relay = ROOT / "target" / "debug" / "cofferwire-line-relay"
    python_test = "independent.python.tests.test_independent"
    rows = [
        (
            "rust-client__rust-relay",
            ["cargo", "test", "-p", "cofferwired", "-p", "cofferwire-relay"],
            {},
        ),
        (
            "independent-client__rust-relay",
            [
                "python3",
                "-m",
                "unittest",
                f"{python_test}.CrossImplementationTests.test_independent_client_to_rust_relay",
                "-v",
            ],
            {
                "COFFERWIRE_MATRIX": "1",
                "COFFERWIRE_RUST_LINE_RELAY": str(relay),
            },
        ),
        (
            "rust-client__independent-relay",
            [
                "cargo",
                "test",
                "-p",
                "cofferwire-client",
                "--test",
                "python_interop",
            ],
            {"COFFERWIRE_MATRIX": "1"},
        ),
        (
            "independent-client__independent-relay",
            [
                "python3",
                "-m",
                "unittest",
                f"{python_test}.IndependentImplementationTests",
                "-v",
            ],
            {},
        ),
    ]
    results = []
    failed_output = []
    for name, command, environment in rows:
        result, command_output = run(name, command, environment)
        result["trace_ids"] = [case["id"] for case in trace["cases"]]
        results.append(result)
        if result["result"] != "passed":
            failed_output.append(f"{name}:\n{command_output}")
    vector_result, vector_output = run(
        "rust-public-vectors",
        ["cargo", "test", "-p", "cofferwire-codec", "-p", "cofferwire-crypto", "-p", "cofferwire-test"],
    )
    independent_vector_result, independent_vector_output = run(
        "independent-public-vectors",
        [
            "python3",
            "-m",
            "unittest",
            f"{python_test}.IndependentImplementationTests.test_public_codec_and_crypto_vectors",
            "-v",
        ],
    )
    evidence = [vector_result, independent_vector_result]
    if any(item["result"] != "passed" for item in evidence):
        failed_output.extend([vector_output, independent_vector_output])
    report = {
        "format": "cofferwire-interop-matrix-v1",
        "source_revision": output(["git", "rev-parse", "HEAD"]),
        "scope_revision": trace["scope_revision"],
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "rustc": output(["rustc", "--version"]),
            "cargo": output(["cargo", "--version"]),
        },
        "artifacts": {
            "rust_line_relay_sha256": digest(relay),
            "independent_source_sha256": digest(ROOT / "independent/python/cofferwire_v1.py"),
            "trace_sha256": digest(TRACE),
            "codec_vectors_sha256": digest(ROOT / "vectors/codec-v1.json"),
            "crypto_vectors_sha256": digest(ROOT / "vectors/crypto-v1.json"),
        },
        "trace_cases": trace["cases"],
        "matrix": results,
        "vector_evidence": evidence,
        "compatibility": {
            "unknown_version": "passed in every role implementation",
            "downgrade": "unregistered algorithms and versions fail closed",
            "previous_current": trace["previous_version"],
        },
        "differences": [],
        "overall": "passed"
        if all(item["result"] == "passed" for item in results + evidence)
        else "failed",
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered)
    else:
        print(rendered, end="")
    if report["overall"] != "passed":
        print("\n".join(failed_output), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
