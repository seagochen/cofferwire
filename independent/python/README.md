# Independent Python implementation

This directory is a clean-room implementation of the frozen Cofferwire
queue-v1 scope `CW-SCOPE-QUEUE-V1-2026-09-06`. It was written from the public
files under `spec/`, `vectors/`, and `conformance/`; it does not import, link,
generate code from, or copy the Rust reference implementation.

It contains a strict minimal CBOR codec, Ed25519 request authentication, a
client for every queue-v1 command, and a SQLite relay with durable command
transactions. The line relay is a test-harness transport: each input line is
`<unix-seconds> <frame-hex>` and each output line is one response frame in hex.
It deliberately adds no meaning to the protocol frame.

From the repository root:

```console
python3 -m pip wheel --no-build-isolation --no-deps \
  --wheel-dir /tmp/cofferwire-independent-dist independent/python
python3 -m unittest discover -s independent/python/tests -v
python3 independent/python/cofferwire_v1.py line-relay /tmp/cofferwire-python.sqlite
```

The only external dependency is `cryptography`, used for standards-based
Ed25519, X25519 and ChaCha20-Poly1305 primitives. Test-only fixed keys are never
production credentials.
