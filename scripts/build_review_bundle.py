#!/usr/bin/env python3
"""Build a deterministic external-review archive from one committed revision."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIXES = (
    ".github/workflows/",
    "apps/",
    "conformance/",
    "crates/",
    "conformance/evidence/",
    "docs/detailed_design/",
    "fuzz/",
    "independent/",
    "profiles/",
    "scripts/",
    "docs/spec/",
    "vectors/",
)
ROOT_FILES = {
    "Cargo.lock",
    "Cargo.toml",
    "CONTRIBUTING.md",
    "LICENSE",
    "PLAN.md",
    "README.md",
    "SECURITY.md",
    "TESTING.md",
}


def git(*arguments: str) -> bytes:
    return subprocess.run(
        ["git", *arguments], cwd=ROOT, check=True, capture_output=True
    ).stdout


def resolve_revision(revision: str) -> str:
    return git("rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()


def selected_paths(revision: str) -> list[str]:
    paths = git("ls-tree", "-r", "-z", "--name-only", revision).decode().split("\0")
    return sorted(
        path
        for path in paths
        if path and (path in ROOT_FILES or path.startswith(PREFIXES))
    )


def file_mode(revision: str, path: str) -> int:
    mode = git("ls-tree", revision, "--", path).decode().split()[0]
    return 0o755 if mode == "100755" else 0o644


def add_bytes(archive: tarfile.TarFile, name: str, content: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info, io.BytesIO(content))


def build(revision: str, output: Path) -> dict[str, object]:
    commit = resolve_revision(revision)
    entries = []
    payloads = []
    for path in selected_paths(commit):
        content = git("show", f"{commit}:{path}")
        mode = file_mode(commit, path)
        payloads.append((path, content, mode))
        entries.append(
            {
                "path": path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    manifest = {
        "format": "cofferwire-review-bundle-v1",
        "revision": commit,
        "queue_scope_revision": "CW-SCOPE-QUEUE-V1-2026-09-06",
        "profiles": ["queue/1", "cofferwire-blob/1", "receipts/1", "cofferwire-offline/1", "family-tree/1"],
        "files": entries,
    }
    rendered = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
        add_bytes(archive, "REVIEW-MANIFEST.json", rendered, 0o644)
        for path, content, mode in payloads:
            add_bytes(archive, path, content, mode)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    manifest = build(args.revision, args.output)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(f"revision={manifest['revision']}")
    print(f"sha256={digest}")
    print(f"files={len(manifest['files'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
