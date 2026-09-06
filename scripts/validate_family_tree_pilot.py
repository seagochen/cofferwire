#!/usr/bin/env python3
"""Validate public evidence for the real family-tree interoperability pilot."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REQUIRED_SCENARIOS = {
    "delayed_convergence",
    "duplicate_delivery",
    "long_offline_24h",
    "suspend_resume",
    "lost_notification",
    "relay_replacement",
    "offline_history_recovery",
    "application_receipts",
}
FORBIDDEN_KEYS = {
    "private_key",
    "secret",
    "capability",
    "queue_id",
    "object_id",
    "revision_id",
    "ip_address",
    "raw_log",
}


class EvidenceError(ValueError):
    """Evidence is incomplete, internally inconsistent, or unsafe to publish."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def parse_utc(value: object, field: str) -> datetime:
    require(isinstance(value, str) and value.endswith("Z"), f"{field} must be UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise EvidenceError(f"{field} is not ISO-8601") from error


def reject_sensitive_keys(value: object, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            require(normalized not in FORBIDDEN_KEYS, f"forbidden public field {path}.{key}")
            reject_sensitive_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive_keys(child, f"{path}[{index}]")


def validate(document: object) -> None:
    require(isinstance(document, dict), "root must be an object")
    reject_sensitive_keys(document)
    require(document.get("format") == "cofferwire-family-tree-pilot-v1", "wrong format")
    revision = document.get("candidate_revision")
    require(isinstance(revision, str) and HEX40.fullmatch(revision) is not None, "candidate_revision must be 40 lowercase hex characters")
    require(revision != "0" * 40, "candidate_revision is still a placeholder")
    started = parse_utc(document.get("started_at_utc"), "started_at_utc")
    ended = parse_utc(document.get("ended_at_utc"), "ended_at_utc")
    require(ended > started, "ended_at_utc must be after started_at_utc")
    require(document.get("synthetic_data_only") is True, "pilot must use synthetic data only")

    devices = document.get("devices")
    require(isinstance(devices, list) and len(devices) >= 3, "at least three devices are required")
    labels = {item.get("label") for item in devices if isinstance(item, dict)}
    require(len(labels) == len(devices), "device labels must be distinct")
    for device in devices:
        require(isinstance(device, dict) and device.get("physical") is True, "every device must be physical")
        require(device.get("platform") not in (None, "", "REPLACE-ME"), "every device needs a platform description")

    relays = document.get("relays")
    require(isinstance(relays, list) and len(relays) >= 2, "at least two relays are required")
    operators = {item.get("operator") for item in relays if isinstance(item, dict)}
    endpoints = {item.get("endpoint") for item in relays if isinstance(item, dict)}
    require(len(operators) == len(relays), "relay operators must be distinct")
    require(len(endpoints) == len(relays), "relay endpoints must be distinct")
    for relay in relays:
        require(isinstance(relay, dict), "every relay must be an object")
        require(relay.get("operator") not in (None, "", "REPLACE-ME-A", "REPLACE-ME-B"), "relay operator is a placeholder")
        endpoint = relay.get("endpoint")
        require(isinstance(endpoint, str) and endpoint.startswith("https://"), "relay endpoint must use HTTPS")
        require(not endpoint.endswith(".invalid"), "relay endpoint is still a placeholder")
        for digest_name in ("binary_sha256", "config_sha256"):
            digest = relay.get(digest_name)
            require(isinstance(digest, str) and HEX64.fullmatch(digest) is not None and digest != "0" * 64, f"invalid {digest_name}")

    scenarios = document.get("scenarios")
    require(isinstance(scenarios, dict), "scenarios must be an object")
    require(REQUIRED_SCENARIOS <= scenarios.keys(), "one or more required scenarios are missing")
    for name in REQUIRED_SCENARIOS:
        scenario = scenarios[name]
        require(isinstance(scenario, dict) and scenario.get("status") == "passed", f"scenario {name} did not pass")
        require(scenario.get("observation") not in (None, "", "REPLACE-ME"), f"scenario {name} lacks an observation")
    require(scenarios["long_offline_24h"].get("wall_clock_hours", 0) >= 24, "long-offline observation must last at least 24 wall-clock hours")
    require(scenarios["relay_replacement"].get("application_identity_unchanged") is True, "relay replacement changed application identity")
    require(scenarios["offline_history_recovery"].get("network_disabled") is True, "offline history recovery was not network-isolated")

    metrics = document.get("aggregate_metrics")
    require(isinstance(metrics, dict), "aggregate_metrics must be an object")
    for name in ("updates_created", "updates_applied", "duplicate_applications", "silent_losses"):
        require(type(metrics.get(name)) is int and metrics[name] >= 0, f"metric {name} must be a non-negative integer")
    require(metrics["updates_created"] > 0 and metrics["updates_applied"] >= metrics["updates_created"] * 3, "every update must converge to all three devices")
    require(metrics["duplicate_applications"] == 0, "duplicate application was observed")
    require(metrics["silent_losses"] == 0, "silent loss was observed")
    require(document.get("protocol_exceptions") == [], "protocol exceptions block version 1")

    attestations = document.get("participant_attestations")
    require(isinstance(attestations, list) and len(attestations) >= 3, "three participant attestations are required")
    attestation_roles = {item.get("role") for item in attestations if isinstance(item, dict)}
    require({"device-and-coordinator", "relay-a-operator", "relay-b-operator"} <= attestation_roles, "required attestation roles are missing")
    for item in attestations:
        require(item.get("name_or_org") not in (None, "", "REPLACE-ME"), "attestation identity is a placeholder")
        require(item.get("statement") not in (None, "", "REPLACE-ME"), "attestation statement is a placeholder")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.evidence.read_text(encoding="utf-8"))
        validate(document)
    except (OSError, json.JSONDecodeError, EvidenceError) as error:
        parser.error(str(error))
    print(f"validated {args.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
