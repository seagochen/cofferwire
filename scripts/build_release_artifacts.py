#!/usr/bin/env python3
"""Assemble deterministic version 1 release artifacts from a Git revision."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git(*arguments: str) -> bytes:
    return subprocess.run(["git", *arguments], cwd=ROOT, check=True, capture_output=True).stdout


def resolve_revision(revision: str) -> str:
    return git("rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()


def tracked_paths(revision: str) -> list[str]:
    return sorted(git("ls-tree", "-r", "--name-only", revision).decode().splitlines())


def selected(path: str, kind: str) -> bool:
    if kind == "source":
        return not path.startswith(("docs/conformance/", "profiles/vectors/", "vectors/"))
    if kind == "spec":
        return path.startswith(("spec/", "profiles/", "docs/adr/")) and "/vectors/" not in path
    if kind == "vectors":
        return path.startswith(("vectors/", "profiles/vectors/"))
    if kind == "conformance":
        return path.startswith("docs/conformance/") or path in {"conformance/coverage.json", "conformance/registry.json", "TESTING.md"}
    raise ValueError(f"unknown artifact kind {kind}")


def git_mode(revision: str, path: str) -> int:
    raw = git("ls-tree", revision, "--", path).decode().split()[0]
    return 0o755 if raw == "100755" else 0o644


def add_bytes(archive: tarfile.TarFile, name: str, content: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    archive.addfile(info, io.BytesIO(content))


def build_git_tar(revision: str, output: Path, kind: str) -> None:
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in tracked_paths(revision):
            if selected(path, kind):
                add_bytes(archive, path, git("show", f"{revision}:{path}"), git_mode(revision, path))


def build_binary_tar(output: Path, binaries: list[tuple[str, Path]]) -> None:
    names = [name for name, _ in binaries]
    if len(names) != len(set(names)):
        raise ValueError("binary names must be unique")
    with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
        for name, path in sorted(binaries):
            if "/" in name or name in {"", ".", ".."}:
                raise ValueError(f"invalid binary name {name!r}")
            add_bytes(archive, f"bin/{name}", path.read_bytes(), 0o755)


def build_sbom(revision: str, output: Path) -> None:
    lock = tomllib.loads(git("show", f"{revision}:Cargo.lock").decode())
    components = []
    for package in sorted(lock["package"], key=lambda item: (item["name"], item["version"], item.get("source", ""))):
        component = {"type": "library", "name": package["name"], "version": package["version"]}
        if "source" in package:
            component["externalReferences"] = [{"type": "distribution", "url": package["source"]}]
        if "checksum" in package:
            component["hashes"] = [{"alg": "SHA-256", "content": package["checksum"]}]
        components.append(component)
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "cofferwire", "version": "1.0.0", "properties": [{"name": "cofferwire:git-revision", "value": revision}]}},
        "components": components,
    }
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_binary(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError("binary must be NAME=PATH")
    path = Path(raw_path)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"binary does not exist: {path}")
    return name, path


def build(args: argparse.Namespace) -> dict[str, object]:
    revision = resolve_revision(args.revision)
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "source": output / "cofferwire-source-v1.tar",
        "spec": output / "cofferwire-spec-v1.tar",
        "vectors": output / "cofferwire-vectors-v1.tar",
        "conformance": output / "cofferwire-conformance-v1.tar",
        "binaries": output / "cofferwire-binaries-v1.tar",
        "sbom": output / "cofferwire-sbom-v1.cdx.json",
    }
    for kind in ("source", "spec", "vectors", "conformance"):
        build_git_tar(revision, artifacts[kind], kind)
    build_binary_tar(artifacts["binaries"], args.binary)
    build_sbom(revision, artifacts["sbom"])

    evidence = {}
    for name, source in (("gates", args.gate_manifest), ("pilot", args.pilot_evidence), ("review", args.review_evidence)):
        if source is not None:
            destination = output / f"{name}-evidence-v1.json"
            shutil.copyfile(source, destination)
            evidence[name] = destination.name
    manifest = {
        "format": "cofferwire-release-manifest-v1",
        "version": "1.0.0",
        "candidate_revision": revision,
        "queue_scope_revision": "CW-SCOPE-QUEUE-V1-2026-09-06",
        "artifacts": {name: {"file": path.name, "sha256": sha256(path)} for name, path in sorted(artifacts.items())},
        "evidence": evidence,
    }
    manifest_path = output / "release-manifest-v1.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum_paths = list(artifacts.values()) + [manifest_path] + [output / filename for filename in evidence.values()]
    checksums = "".join(f"{sha256(path)}  {path.name}\n" for path in sorted(checksum_paths, key=lambda item: item.name))
    (output / "SHA256SUMS").write_text(checksums, encoding="ascii")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--binary", required=True, action="append", type=parse_binary)
    parser.add_argument("--gate-manifest", type=Path)
    parser.add_argument("--pilot-evidence", type=Path)
    parser.add_argument("--review-evidence", type=Path)
    args = parser.parse_args()
    manifest = build(args)
    print(f"revision={manifest['candidate_revision']}")
    print(f"artifacts={len(manifest['artifacts'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
