import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_family_tree_pilot", ROOT / "scripts/validate_family_tree_pilot.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def valid_evidence():
    document = json.loads(
        (ROOT / "docs/pilot/family-tree-v1-result.example.json").read_text()
    )
    document["candidate_revision"] = "a" * 40
    document["started_at_utc"] = "2026-09-06T00:00:00Z"
    document["ended_at_utc"] = "2026-09-08T00:00:01Z"
    for index, device in enumerate(document["devices"]):
        device["platform"] = f"test-os-{index}"
    for index, relay in enumerate(document["relays"]):
        relay["operator"] = f"operator-{index}"
        relay["endpoint"] = f"https://relay-{index}.example.test"
        relay["binary_sha256"] = format(index + 1, "064x")
        relay["config_sha256"] = format(index + 11, "064x")
    for scenario in document["scenarios"].values():
        scenario["status"] = "passed"
        scenario["observation"] = "verified synthetic state convergence"
    document["scenarios"]["long_offline_24h"]["wall_clock_hours"] = 24
    document["scenarios"]["relay_replacement"]["application_identity_unchanged"] = True
    document["scenarios"]["offline_history_recovery"]["network_disabled"] = True
    document["aggregate_metrics"]["updates_created"] = 2
    document["aggregate_metrics"]["updates_applied"] = 6
    for index, attestation in enumerate(document["participant_attestations"]):
        attestation["name_or_org"] = f"participant-{index}"
        attestation["statement"] = "I attest that I observed the stated scenario."
    return document


class PilotEvidenceTests(unittest.TestCase):
    def test_complete_evidence_passes(self):
        MODULE.validate(valid_evidence())

    def test_shared_operator_is_rejected(self):
        document = valid_evidence()
        document["relays"][1]["operator"] = document["relays"][0]["operator"]
        with self.assertRaisesRegex(MODULE.EvidenceError, "operators"):
            MODULE.validate(document)

    def test_nonphysical_device_is_rejected(self):
        document = valid_evidence()
        document["devices"][2]["physical"] = False
        with self.assertRaisesRegex(MODULE.EvidenceError, "physical"):
            MODULE.validate(document)

    def test_short_offline_interval_is_rejected(self):
        document = valid_evidence()
        document["scenarios"]["long_offline_24h"]["wall_clock_hours"] = 23.9
        with self.assertRaisesRegex(MODULE.EvidenceError, "24 wall-clock"):
            MODULE.validate(document)

    def test_protocol_exception_is_release_blocking(self):
        document = valid_evidence()
        document["protocol_exceptions"] = ["manual frame rewrite"]
        with self.assertRaisesRegex(MODULE.EvidenceError, "exceptions"):
            MODULE.validate(document)

    def test_secret_bearing_field_is_rejected_recursively(self):
        document = valid_evidence()
        document["relays"][0]["private_key"] = "do-not-publish"
        with self.assertRaisesRegex(MODULE.EvidenceError, "forbidden public field"):
            MODULE.validate(document)

    def test_placeholder_example_is_rejected(self):
        document = copy.deepcopy(valid_evidence())
        document["candidate_revision"] = "0" * 40
        with self.assertRaisesRegex(MODULE.EvidenceError, "placeholder"):
            MODULE.validate(document)


if __name__ == "__main__":
    unittest.main()
