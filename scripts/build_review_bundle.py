#!/usr/bin/env python3
"""Build a deterministic external-review archive from one committed revision."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from pathlib import Path

from cofferwire_tools.archive import (
    QUEUE_SCOPE_REVISION,
    add_bytes,
    git,
    git_mode,
    resolve_revision,
    tracked_paths,
)

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


def selected_paths(revision: str) -> list[str]:
    return sorted(
        path
        for path in tracked_paths(revision)
        if path and (path in ROOT_FILES or path.startswith(PREFIXES))
    )


def build(revision: str, output: Path) -> dict[str, object]:
    commit = resolve_revision(revision)
    entries = []
    payloads = []
    for path in selected_paths(commit):
        content = git("show", f"{commit}:{path}")
        mode = git_mode(commit, path)
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
        "queue_scope_revision": QUEUE_SCOPE_REVISION,
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
