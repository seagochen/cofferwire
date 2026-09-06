#!/usr/bin/env python3
"""Build deterministic fuzz seeds from public vectors and interop traces."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "fuzz" / "target" / "generated-corpus"


def write(target: str, name: str, data: bytes) -> None:
    directory = CORPUS / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)


def main() -> None:
    blob = json.loads((ROOT / "vectors" / "blob-v1.json").read_text())
    interop = (ROOT / "vectors" / "queue-v1-traces.json").read_bytes()
    queue_vector = (ROOT / "vectors" / "codec-v1.json").read_bytes()
    blob_vector = (ROOT / "vectors" / "blob-v1.json").read_bytes()
    write("decode-frames", "public-codec-vector", queue_vector)
    write("decode-frames", "interop-traces", interop)
    write("decode-blob-frames", "public-blob-vector", blob_vector)
    write("verify-hostile-proofs", "queue-vector", queue_vector)
    write("verify-hostile-proofs", "blob-vector", blob_vector)
    write("relay-transitions", "interop-hash-seed", hashlib.sha256(interop).digest() * 8)
    positive = blob["positive"]
    write("decode-blob-frames", "manifest", bytes.fromhex(positive["manifest_hex"]))
    for index, chunk in enumerate(positive["ciphertext_chunks_hex"]):
        write("decode-blob-frames", f"chunk-{index}", bytes.fromhex(chunk))
    hostile = [b"\x9f", b"\x5b" + b"\xff" * 8, b"\x81" * 64, b"\x00" * 17, b"\xff" * 4096]
    for target in ("decode-frames", "decode-blob-frames", "verify-hostile-proofs"):
        for index, data in enumerate(hostile):
            write(target, f"hostile-{index}", data)


if __name__ == "__main__":
    main()
