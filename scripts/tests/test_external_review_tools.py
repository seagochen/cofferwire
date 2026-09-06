import copy
import hashlib
import importlib.util
import json
import tarfile
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


BUNDLE = load("build_review_bundle")
VALIDATOR = load("validate_external_review")


def valid_review():
    value = json.loads(
        (ROOT / "docs/security/external-review-result.example.json").read_text()
    )
    value["reviewed_revision"] = "a" * 40
    value["review_bundle_sha256"] = "1" * 64
    value["reviewer"] = {
        "name_or_org": "Independent Review LLC",
        "qualifications": "Applied cryptography and protocol review experience",
        "independent": True,
        "conflicts_disclosed": "No implementation or design role",
    }
    value["methodology"] = "Manual design review plus executable negative tests"
    for topic in value["scope"]:
        value["scope"][topic] = "addressed in report section 3"
    value["public_report"] = {"path_or_url": "review.pdf", "sha256": "2" * 64}
    value["project_response"] = {"path_or_url": "response.md", "sha256": "3" * 64}
    return value


class ReviewToolTests(unittest.TestCase):
    def test_complete_no_finding_review_passes(self):
        VALIDATOR.validate(valid_review())

    def test_non_independent_review_is_rejected(self):
        value = valid_review()
        value["reviewer"]["independent"] = False
        with self.assertRaisesRegex(VALIDATOR.ReviewError, "not independent"):
            VALIDATOR.validate(value)

    def test_unfixed_high_finding_is_rejected(self):
        value = valid_review()
        value["findings"] = [{"id": "CW-REV-001", "severity": "high", "disposition": "accepted", "publicly_safe": True}]
        with self.assertRaisesRegex(VALIDATOR.ReviewError, "blocks release"):
            VALIDATOR.validate(value)

    def test_medium_finding_requires_rationale(self):
        value = valid_review()
        value["findings"] = [{"id": "CW-REV-002", "severity": "medium", "disposition": "follow_up", "publicly_safe": True}]
        with self.assertRaisesRegex(VALIDATOR.ReviewError, "rationale"):
            VALIDATOR.validate(value)

    def test_review_bundle_is_byte_reproducible_and_self_describing(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.tar"
            second = Path(directory) / "second.tar"
            manifest = BUNDLE.build("HEAD", first)
            BUNDLE.build("HEAD", second)
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())
            with tarfile.open(first) as archive:
                embedded = json.load(archive.extractfile("REVIEW-MANIFEST.json"))
            self.assertEqual(embedded, manifest)
            self.assertIn("spec/04-cryptographic-profile.md", {entry["path"] for entry in manifest["files"]})


if __name__ == "__main__":
    unittest.main()
