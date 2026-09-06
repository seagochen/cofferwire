# Version 1 Release Process

This procedure implements issue #28. It deliberately separates reproducible
artifact assembly from authorization to publish: artifacts can be rehearsed at
any commit, but the final validator refuses version 1 unless all ten release
gates, the real pilot, the external review, checksums, and a signature refer to
the same candidate revision.

## 1. Select one candidate

Use a full 40-character commit hash. The worktree used for compilation must be
clean and checked out at that commit. Queue v1 is the release's stable protocol
scope (`CW-SCOPE-QUEUE-V1-2026-09-06`); the blob, receipt, offline, and
family-tree documents remain separately named profiles and must not be
advertised as queue-v1 behavior.

Copy `docs/release/gate-manifest-v1.example.json` to a temporary location. For
each gate, record `passed`, the candidate revision, a public evidence path/URL,
and its SHA-256. A statement or checkbox without an evidence artifact is not a
passing gate.

## 2. Reproduce binaries in two clean environments

In two separately provisioned clean Linux environments, check out the exact
candidate and run:

```sh
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
export RUSTFLAGS="--remap-path-prefix=$(pwd)=/usr/src/cofferwire -C strip=symbols"
cargo build --release --locked --bin cofferwired --bin cofferwire-line-relay
sha256sum target/release/cofferwired target/release/cofferwire-line-relay
```

The Rust and Cargo versions, target triple, commands, and both digest sets must
be public gate-10 evidence. Both environments must produce identical bytes. If
they do not, stop; do not select one build as canonical without first defining
and machine-checking the permitted difference.

## 3. Assemble deterministic artifacts

Using either identical build output:

```sh
python3 scripts/build_release_artifacts.py \
  --revision COMMIT \
  --output-dir artifacts/cofferwire-1.0 \
  --binary cofferwired=target/release/cofferwired \
  --binary cofferwire-line-relay=target/release/cofferwire-line-relay \
  --gate-manifest /tmp/gate-manifest-v1.json \
  --pilot-evidence /tmp/family-tree-pilot-v1.json \
  --review-evidence /tmp/external-review-v1.json
```

The builder reads source/specification bytes from Git objects at `COMMIT`, not
from the worktree. All tar metadata is normalized. It creates:

- `cofferwire-source-v1.tar`;
- `cofferwire-spec-v1.tar`;
- `cofferwire-vectors-v1.tar`;
- `cofferwire-conformance-v1.tar`;
- `cofferwire-binaries-v1.tar`;
- `cofferwire-sbom-v1.cdx.json` (CycloneDX 1.5 from the locked dependency set);
- copied gate, pilot, and review evidence;
- `release-manifest-v1.json` and `SHA256SUMS`.

Run the builder twice in clean directories and compare every line of
`SHA256SUMS` before signing.

## 4. Sign and validate

Sign with a release-only OpenSSH Ed25519 key. Keep the private key outside the
repository and artifact directory:

```sh
ssh-keygen -Y sign -f /secure/path/release_ed25519 -n file \
  artifacts/cofferwire-1.0/SHA256SUMS
```

Publish an `allowed_signers` file through an independently authenticated
channel. Then validate the complete candidate:

```sh
python3 scripts/validate_release_candidate.py \
  artifacts/cofferwire-1.0 \
  --allowed-signers /path/to/allowed_signers \
  --signer cofferwire-release
```

The validator checks every digest, required artifact, signature, gate state,
evidence revision, pilot constraints, and external-review dispositions.

## 5. Publish and tag

Only after validation succeeds:

1. publish the directory without modifying any byte;
2. record its public URL and `SHA256SUMS` digest in release notes;
3. create annotated tag `v1.0.0` at the candidate commit, including that digest;
4. push the tag and independently download and revalidate the public archive;
5. update `README.md` and `SECURITY.md` in a subsequent commit to describe only
   the released and externally reviewed guarantees.

The tag is the final irreversible publication step. It must not be created for
an incomplete rehearsal or before issues #25 and #27 satisfy their external
acceptance criteria.
