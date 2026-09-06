import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_conformance import (
    ConformanceError,
    build_report,
    load_registry,
    scan_specs,
)


class ConformanceCheckerTests(unittest.TestCase):
    def fixture(self, specification, registry):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        spec = root / "spec"
        spec.mkdir()
        (spec / "01.md").write_text(specification)
        registry_path = root / "registry.json"
        registry_path.write_text(json.dumps(registry))
        self.addCleanup(temporary.cleanup)
        return spec, registry_path

    @staticmethod
    def registry(tests=None, mappings=None, revisions=None):
        return {
            "format": "fixture",
            "revisions": revisions or {"v1": "revision-1"},
            "tests": tests or {
                "TEST-1": {"command": "true", "category": "codec", "roles": ["client"]}
            },
            "mappings": mappings or [
                {"prefix": "CW-TEST-", "revision": "v1", "tests": ["TEST-1"]}
            ],
            "should_exceptions": [],
        }

    def test_accepts_covered_must_and_builds_report(self):
        spec, path = self.fixture("- **CW-TEST-001:** A peer MUST stop.\n", self.registry())
        report = build_report(scan_specs(spec), load_registry(path))
        self.assertEqual(report["requirement_count"], 1)
        self.assertEqual(report["requirements"][0]["tests"], ["TEST-1"])

    def test_rejects_uncovered_must(self):
        registry = self.registry(mappings=[{"prefix": "CW-TEST-", "revision": "v1", "tests": []}])
        spec, path = self.fixture("- **CW-TEST-001:** A peer MUST stop.\n", registry)
        with self.assertRaisesRegex(ConformanceError, "no executable test"):
            build_report(scan_specs(spec), load_registry(path))

    def test_rejects_duplicate_normative_id(self):
        spec, _ = self.fixture(
            "- **CW-TEST-001:** A peer MUST stop.\n\n- **CW-TEST-001:** A peer MUST fail.\n",
            self.registry(),
        )
        with self.assertRaisesRegex(ConformanceError, "duplicate normative ID"):
            scan_specs(spec)

    def test_rejects_unknown_test_and_revision(self):
        spec, path = self.fixture(
            "- **CW-TEST-001:** A peer MUST stop.\n",
            self.registry(mappings=[{"prefix": "CW-TEST-", "revision": "missing", "tests": ["NOPE"]}]),
        )
        with self.assertRaisesRegex(ConformanceError, "unknown revision"):
            build_report(scan_specs(spec), load_registry(path))
        registry = self.registry(
            mappings=[{"prefix": "CW-TEST-", "revision": "v1", "tests": ["NOPE"]}]
        )
        spec, path = self.fixture("- **CW-TEST-001:** A peer MUST stop.\n", registry)
        with self.assertRaisesRegex(ConformanceError, "unknown tests"):
            build_report(scan_specs(spec), load_registry(path))

    def test_rejects_unscoped_normative_keyword(self):
        spec, _ = self.fixture("A peer MUST stop.\n", self.registry())
        with self.assertRaisesRegex(ConformanceError, "unscoped normative keyword"):
            scan_specs(spec)

    def test_rejects_duplicate_registry_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text('{"tests": {}, "tests": {}}')
            with self.assertRaisesRegex(ConformanceError, "duplicate JSON key"):
                load_registry(path)


if __name__ == "__main__":
    unittest.main()
