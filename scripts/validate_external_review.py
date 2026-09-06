#!/usr/bin/env python3
"""Validate release-gating external security review evidence."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SCOPE = {
    "cryptographic_construction",
    "capability_lifecycle",
    "queue_blob_authorization",
    "replay_rollback_downgrade",
    "storage_deletion_retention",
    "metadata_traffic_correlation",
    "dos_abuse_controls",
    "client_relay_implementation",
}
SEVERITIES = {"critical", "high", "medium", "low", "informational"}


class ReviewError(ValueError):
    """The external review evidence does not satisfy the release gate."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReviewError(message)


def real_text(value: object) -> bool:
    return isinstance(value, str) and value.strip() not in {"", "REPLACE-ME", "pending"}


def digest(value: object, field: str) -> None:
    require(isinstance(value, str) and HEX64.fullmatch(value) is not None and value != "0" * 64, f"invalid {field}")


def validate(document: object) -> None:
    require(isinstance(document, dict), "root must be an object")
    require(document.get("format") == "cofferwire-external-review-v1", "wrong format")
    revision = document.get("reviewed_revision")
    require(isinstance(revision, str) and HEX40.fullmatch(revision) is not None and revision != "0" * 40, "invalid reviewed_revision")
    digest(document.get("review_bundle_sha256"), "review_bundle_sha256")
    reviewer = document.get("reviewer")
    require(isinstance(reviewer, dict), "reviewer must be an object")
    require(real_text(reviewer.get("name_or_org")), "reviewer identity is missing")
    require(real_text(reviewer.get("qualifications")), "reviewer qualifications are missing")
    require(reviewer.get("independent") is True, "reviewer is not independent")
    require(real_text(reviewer.get("conflicts_disclosed")), "conflict disclosure is missing")
    require(real_text(document.get("methodology")), "methodology is missing")

    scope = document.get("scope")
    require(isinstance(scope, dict) and SCOPE <= scope.keys(), "required review scope is incomplete")
    for topic in SCOPE:
        require(real_text(scope[topic]), f"scope topic {topic} was not addressed")
    require(document.get("private_reporting_used_for_unpatched_findings") is True, "private reporting requirement was not confirmed")

    findings = document.get("findings")
    require(isinstance(findings, list), "findings must be an array")
    identifiers = set()
    for finding in findings:
        require(isinstance(finding, dict), "finding must be an object")
        identifier = finding.get("id")
        require(real_text(identifier) and identifier not in identifiers, "finding IDs must be present and unique")
        identifiers.add(identifier)
        severity = finding.get("severity")
        require(severity in SEVERITIES, f"finding {identifier} has invalid severity")
        disposition = finding.get("disposition")
        if severity in {"critical", "high"}:
            require(disposition == "fixed", f"finding {identifier} blocks release until fixed")
            require(real_text(finding.get("remediation")), f"finding {identifier} lacks remediation evidence")
            require(finding.get("verified") is True, f"finding {identifier} remediation is not verified")
        elif severity in {"medium", "low"}:
            require(disposition in {"fixed", "accepted", "follow_up"}, f"finding {identifier} lacks a valid disposition")
            require(real_text(finding.get("rationale_or_reference")), f"finding {identifier} lacks disposition rationale")
        require(finding.get("publicly_safe") is True, f"finding {identifier} is not safe for the public result")

    for section_name in ("public_report", "project_response"):
        section = document.get(section_name)
        require(isinstance(section, dict) and real_text(section.get("path_or_url")), f"{section_name} is missing")
        digest(section.get("sha256"), f"{section_name}.sha256")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        validate(json.loads(args.evidence.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ReviewError) as error:
        parser.error(str(error))
    print(f"validated {args.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
