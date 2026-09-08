"""Deterministic Git-tree and tar helpers shared by release tooling."""

from __future__ import annotations

import io
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QUEUE_SCOPE_REVISION = "CW-SCOPE-QUEUE-V1-2026-09-06"
RELEASE_VERSION = "1.0.0"


def git(*arguments: str) -> bytes:
    return subprocess.run(
        ["git", *arguments], cwd=ROOT, check=True, capture_output=True
    ).stdout


def resolve_revision(revision: str) -> str:
    return git("rev-parse", "--verify", f"{revision}^{{commit}}").decode().strip()


def tracked_paths(revision: str) -> list[str]:
    paths = git("ls-tree", "-r", "-z", "--name-only", revision).decode().split("\0")
    return sorted(path for path in paths if path)


def git_mode(revision: str, path: str) -> int:
    raw = git("ls-tree", revision, "--", path).decode().split()[0]
    return 0o755 if raw == "100755" else 0o644


def add_bytes(
    archive: tarfile.TarFile,
    name: str,
    content: bytes,
    mode: int = 0o644,
) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    archive.addfile(info, io.BytesIO(content))
