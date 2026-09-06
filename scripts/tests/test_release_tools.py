import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


BUILDER = load("build_release_artifacts")
VALIDATOR = load("validate_release_candidate")


class ReleaseToolTests(unittest.TestCase):
    def test_tracked_paths_preserve_unicode_names(self):
        self.assertIn(
            "docs/detailed_design/00_概述.md", BUILDER.tracked_paths("HEAD")
        )

    def test_artifact_path_classification_tracks_published_evidence_and_decision(self):
        self.assertFalse(BUILDER.selected("conformance/evidence/fuzz-evidence-v1.json", "source"))
        self.assertTrue(BUILDER.selected("conformance/evidence/fuzz-evidence-v1.json", "conformance"))
        self.assertTrue(BUILDER.selected("docs/detailed_design/00_概述.md", "spec"))
        self.assertFalse(BUILDER.selected("docs/detailed_design/90_部署与运维.md", "spec"))

    def build(self, directory):
        binary = directory / "cofferwired"
        binary.write_bytes(b"deterministic-test-binary")
        args = argparse.Namespace(
            revision="HEAD",
            output_dir=directory / "release",
            binary=[("cofferwired", binary)],
            gate_manifest=None,
            pilot_evidence=None,
            review_evidence=None,
        )
        return BUILDER.build(args), args.output_dir

    def test_artifacts_are_byte_reproducible(self):
        with tempfile.TemporaryDirectory() as first_raw, tempfile.TemporaryDirectory() as second_raw:
            first_manifest, first = self.build(Path(first_raw))
            second_manifest, second = self.build(Path(second_raw))
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual((first / "SHA256SUMS").read_bytes(), (second / "SHA256SUMS").read_bytes())
            for line in (first / "SHA256SUMS").read_text().splitlines():
                _, _, filename = line.partition("  ")
                self.assertEqual((first / filename).read_bytes(), (second / filename).read_bytes())

    def test_sbom_is_cyclonedx_and_bound_to_revision(self):
        with tempfile.TemporaryDirectory() as raw:
            manifest, directory = self.build(Path(raw))
            sbom = json.loads((directory / "cofferwire-sbom-v1.cdx.json").read_text())
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertEqual(sbom["specVersion"], "1.5")
            properties = sbom["metadata"]["component"]["properties"]
            self.assertEqual(properties[0]["value"], manifest["candidate_revision"])
            self.assertGreater(len(sbom["components"]), 10)

    def test_checksum_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            _, directory = self.build(Path(raw))
            VALIDATOR.validate_checksums(directory)
            target = directory / "cofferwire-spec-v1.tar"
            target.write_bytes(target.read_bytes() + b"tampered")
            with self.assertRaisesRegex(VALIDATOR.ReleaseError, "checksum mismatch"):
                VALIDATOR.validate_checksums(directory)

    def test_gate_manifest_requires_all_passed_same_revision(self):
        value = json.loads((ROOT / "scripts/fixtures/gate-manifest-v1.example.json").read_text())
        value["candidate_revision"] = "a" * 40
        for gate in value["gates"]:
            gate["status"] = "passed"
            gate["evidence"] = f"gate-{gate['number']}.json"
            gate["sha256"] = format(gate["number"], "064x")
        VALIDATOR.validate_gates(value, "a" * 40)
        value["gates"][6]["status"] = "pending"
        with self.assertRaisesRegex(VALIDATOR.ReleaseError, "gate 7"):
            VALIDATOR.validate_gates(value, "a" * 40)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is required")
    def test_complete_candidate_signature_is_verified(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            revision = BUILDER.resolve_revision("HEAD")
            pilot = json.loads((ROOT / "scripts/fixtures/family-tree-v1-result.example.json").read_text())
            pilot.update(candidate_revision=revision, started_at_utc="2026-09-06T00:00:00Z", ended_at_utc="2026-09-08T00:00:01Z")
            for index, device in enumerate(pilot["devices"]):
                device["platform"] = f"test-os-{index}"
            for index, relay in enumerate(pilot["relays"]):
                relay.update(operator=f"operator-{index}", endpoint=f"https://relay-{index}.example.test", binary_sha256=format(index + 1, "064x"), config_sha256=format(index + 11, "064x"))
            for scenario in pilot["scenarios"].values():
                scenario.update(status="passed", observation="test fixture observation")
            pilot["scenarios"]["long_offline_24h"]["wall_clock_hours"] = 24
            pilot["scenarios"]["relay_replacement"]["application_identity_unchanged"] = True
            pilot["scenarios"]["offline_history_recovery"]["network_disabled"] = True
            pilot["aggregate_metrics"].update(updates_created=2, updates_applied=6)
            for index, attestation in enumerate(pilot["participant_attestations"]):
                attestation.update(name_or_org=f"participant-{index}", statement="test fixture attestation")

            review = json.loads((ROOT / "scripts/fixtures/external-review-result.example.json").read_text())
            review.update(reviewed_revision=revision, review_bundle_sha256="1" * 64, methodology="test fixture method")
            review["reviewer"].update(name_or_org="Test Reviewer", qualifications="test qualification", independent=True, conflicts_disclosed="none")
            for topic in review["scope"]:
                review["scope"][topic] = "addressed in test fixture"
            review["public_report"] = {"path_or_url": "report.pdf", "sha256": "2" * 64}
            review["project_response"] = {"path_or_url": "response.md", "sha256": "3" * 64}

            gates = json.loads((ROOT / "scripts/fixtures/gate-manifest-v1.example.json").read_text())
            gates["candidate_revision"] = revision
            for gate in gates["gates"]:
                gate.update(status="passed", evidence=f"gate-{gate['number']}.json", sha256=format(gate["number"], "064x"))
            paths = {}
            for name, value in (("pilot", pilot), ("review", review), ("gates", gates)):
                paths[name] = root / f"{name}.json"
                paths[name].write_text(json.dumps(value))
            binary = root / "cofferwired"
            binary.write_bytes(b"signed-test-binary")
            args = argparse.Namespace(revision=revision, output_dir=root / "release", binary=[("cofferwired", binary)], gate_manifest=paths["gates"], pilot_evidence=paths["pilot"], review_evidence=paths["review"])
            BUILDER.build(args)

            key = root / "release-key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "file", str(args.output_dir / "SHA256SUMS")], check=True, capture_output=True)
            allowed = root / "allowed_signers"
            allowed.write_text(f"cofferwire-release {key.with_suffix('.pub').read_text()}")
            VALIDATOR.validate(args.output_dir, allowed, "cofferwire-release")


if __name__ == "__main__":
    unittest.main()
