#!/usr/bin/env python3
"""Validate a complete, signed Cofferwire version 1 release candidate."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ARTIFACTS = {"source", "binaries", "spec", "vectors", "conformance", "sbom"}
GATES = set(range(1, 11))


class ReleaseError(ValueError):
    """The candidate does not satisfy the version 1 release contract."""


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise ReleaseError(f"cannot load {name}")
    spec.loader.exec_module(module)
    return module


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_checksums(directory: Path) -> set[str]:
    checksum_file = directory / "SHA256SUMS"
    require(checksum_file.is_file(), "SHA256SUMS is missing")
    seen = set()
    for line in checksum_file.read_text(encoding="ascii").splitlines():
        digest, separator, filename = line.partition("  ")
        require(separator == "  " and HEX64.fullmatch(digest) is not None, "malformed SHA256SUMS line")
        require(filename == Path(filename).name and filename not in seen, "unsafe or duplicate checksum filename")
        seen.add(filename)
        path = directory / filename
        require(path.is_file() and sha256(path) == digest, f"checksum mismatch for {filename}")
    return seen


def validate_gates(document: object, revision: str) -> None:
    require(isinstance(document, dict) and document.get("format") == "cofferwire-release-gates-v1", "invalid gate manifest")
    require(document.get("candidate_revision") == revision, "gate manifest revision mismatch")
    gates = document.get("gates")
    require(isinstance(gates, list), "gates must be an array")
    numbers = {gate.get("number") for gate in gates if isinstance(gate, dict)}
    require(numbers == GATES and len(gates) == 10, "exactly gates 1 through 10 are required")
    for gate in gates:
        require(gate.get("status") == "passed", f"gate {gate.get('number')} did not pass")
        require(isinstance(gate.get("evidence"), str) and gate["evidence"] not in {"", "REPLACE-ME"}, f"gate {gate.get('number')} lacks evidence")
        require(isinstance(gate.get("sha256"), str) and HEX64.fullmatch(gate["sha256"]) is not None and gate["sha256"] != "0" * 64, f"gate {gate.get('number')} has invalid evidence digest")


def validate(directory: Path, allowed_signers: Path, signer: str) -> None:
    manifest_path = directory / "release-manifest-v1.json"
    require(manifest_path.is_file(), "release manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("format") == "cofferwire-release-manifest-v1", "invalid release manifest")
    require(manifest.get("version") == "1.0.0", "release version is not 1.0.0")
    revision = manifest.get("candidate_revision")
    require(isinstance(revision, str) and HEX40.fullmatch(revision) is not None, "invalid candidate revision")
    require(manifest.get("queue_scope_revision") == "CW-SCOPE-QUEUE-V1-2026-09-06", "queue scope revision mismatch")
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, dict) and set(artifacts) == ARTIFACTS, "required artifact set is incomplete")
    for name, entry in artifacts.items():
        require(isinstance(entry, dict), f"artifact {name} is invalid")
        filename = entry.get("file", "")
        require(filename == Path(filename).name and filename not in {"", ".", ".."}, f"artifact {name} has an unsafe filename")
        path = directory / filename
        require(path.is_file() and sha256(path) == entry.get("sha256"), f"artifact {name} digest mismatch")

    evidence = manifest.get("evidence")
    require(isinstance(evidence, dict) and set(evidence) == {"gates", "pilot", "review"}, "gate, pilot, and review evidence are required")
    for name, filename in evidence.items():
        require(filename == Path(filename).name and filename not in {"", ".", ".."}, f"evidence {name} has an unsafe filename")
    gates = json.loads((directory / evidence["gates"]).read_text())
    pilot = json.loads((directory / evidence["pilot"]).read_text())
    review = json.loads((directory / evidence["review"]).read_text())
    validate_gates(gates, revision)
    require(pilot.get("candidate_revision") == revision, "pilot evidence revision mismatch")
    require(review.get("reviewed_revision") == revision, "external review revision mismatch")
    load_script("validate_family_tree_pilot").validate(pilot)
    load_script("validate_external_review").validate(review)
    checked = validate_checksums(directory)
    required_checksums = {
        "release-manifest-v1.json",
        *(entry["file"] for entry in artifacts.values()),
        *evidence.values(),
    }
    require(required_checksums <= checked, "SHA256SUMS does not cover every release artifact and evidence file")

    signature = directory / "SHA256SUMS.sig"
    require(signature.is_file(), "SHA256SUMS.sig is missing")
    verification = subprocess.run(
        ["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers), "-I", signer, "-n", "file", "-s", str(signature)],
        input=(directory / "SHA256SUMS").read_bytes(),
        capture_output=True,
    )
    require(verification.returncode == 0, "release signature verification failed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--allowed-signers", required=True, type=Path)
    parser.add_argument("--signer", required=True)
    args = parser.parse_args()
    try:
        validate(args.directory, args.allowed_signers, args.signer)
    except (OSError, json.JSONDecodeError, ReleaseError, ValueError) as error:
        parser.error(str(error))
    print(f"validated signed version 1 candidate in {args.directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
