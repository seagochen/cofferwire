#!/usr/bin/env python3
"""Validate normative requirement traceability and emit a stable report."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

REQUIREMENT = re.compile(r"^- \*\*(CW-[A-Z]+-[0-9]{3}):\*\*(.*)$")
NORMATIVE = re.compile(r"\b(MUST(?: NOT)?|SHOULD(?: NOT)?|MAY)\b")
REQUIRED_SCOPE = re.compile(r"\b(MUST(?: NOT)?|SHOULD(?: NOT)?)\b")


class ConformanceError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConformanceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_registry(path: Path):
    try:
        return json.loads(path.read_text(), object_pairs_hook=unique_object)
    except (json.JSONDecodeError, OSError) as error:
        raise ConformanceError(f"cannot read registry: {error}") from error


@dataclass(frozen=True)
class Requirement:
    identifier: str
    source: str
    line: int
    terms: tuple[str, ...]


def scan_specs(spec_dir: Path) -> list[Requirement]:
    requirements = []
    identifiers = set()
    for path in sorted(spec_dir.glob("*.md")):
        lines = path.read_text().splitlines()
        active_id = None
        active_line = 0
        active_text: list[str] = []

        def finish():
            if active_id is None:
                return
            terms = tuple(sorted(set(NORMATIVE.findall(" ".join(active_text)))))
            requirements.append(
                Requirement(active_id, f"docs/spec/{path.name}", active_line, terms)
            )

        in_code = False
        for line_number, line in enumerate(lines, 1):
            if line.startswith("```"):
                in_code = not in_code
                continue
            match = REQUIREMENT.match(line)
            if match:
                finish()
                active_id, active_line, active_text = match.group(1), line_number, [match.group(2)]
                if active_id in identifiers:
                    raise ConformanceError(f"duplicate normative ID: {active_id}")
                identifiers.add(active_id)
                continue
            if active_id is not None and (not line or line.startswith("  ")):
                active_text.append(line)
                continue
            finish()
            active_id, active_text = None, []
            if (
                not in_code
                and REQUIRED_SCOPE.search(line)
                and "Normative terms" not in line
                and "Normative terms such as" not in line
            ):
                raise ConformanceError(
                    f"unscoped normative keyword at docs/spec/{path.name}:{line_number}"
                )
        finish()
    return requirements


def build_report(requirements: list[Requirement], registry: dict) -> dict:
    revisions = registry.get("revisions", {})
    tests = registry.get("tests", {})
    mappings = registry.get("mappings", [])
    exceptions = {item["requirement"]: item for item in registry.get("should_exceptions", [])}
    expanded = []
    for requirement in requirements:
        matches = [item for item in mappings if requirement.identifier.startswith(item["prefix"])]
        if len(matches) != 1:
            raise ConformanceError(
                f"{requirement.identifier} has {len(matches)} mapping rules; expected exactly one"
            )
        mapping = matches[0]
        revision_name = mapping.get("revision")
        if revision_name not in revisions:
            raise ConformanceError(f"{requirement.identifier} names unknown revision {revision_name}")
        test_ids = mapping.get("tests", [])
        if not test_ids:
            raise ConformanceError(f"{requirement.identifier} has no executable test")
        unknown = sorted(set(test_ids) - set(tests))
        if unknown:
            raise ConformanceError(
                f"{requirement.identifier} names unknown tests: {', '.join(unknown)}"
            )
        if any(term.startswith("SHOULD") for term in requirement.terms):
            if not test_ids and requirement.identifier not in exceptions:
                raise ConformanceError(f"{requirement.identifier} SHOULD has no test or exception")
        expanded.append(
            {
                "id": requirement.identifier,
                "source": requirement.source,
                "line": requirement.line,
                "revision": revisions[revision_name],
                "terms": list(requirement.terms),
                "tests": test_ids,
            }
        )
    dangling = sorted(set(exceptions) - {item.identifier for item in requirements})
    if dangling:
        raise ConformanceError(f"exceptions name unknown requirements: {', '.join(dangling)}")
    category_counts = Counter()
    role_counts = Counter()
    for item in expanded:
        for test_id in item["tests"]:
            category_counts[tests[test_id]["category"]] += 1
            role_counts.update(tests[test_id]["roles"])
    return {
        "format": "cofferwire-conformance-coverage-v1",
        "registry_format": registry.get("format"),
        "requirement_count": len(expanded),
        "uncovered_must": [],
        "unresolved_should": [],
        "coverage_by_category": dict(sorted(category_counts.items())),
        "coverage_by_role": dict(sorted(role_counts.items())),
        "requirements": expanded,
    }


def encoded_report(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-dir", type=Path, default=Path("docs/spec"))
    parser.add_argument("--registry", type=Path, default=Path("conformance/registry.json"))
    parser.add_argument("--check-report", type=Path)
    parser.add_argument("--print-report", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        report = build_report(scan_specs(arguments.spec_dir), load_registry(arguments.registry))
        rendered = encoded_report(report)
        if arguments.check_report and arguments.check_report.read_text() != rendered:
            raise ConformanceError(f"stale coverage report: {arguments.check_report}")
    except (ConformanceError, OSError) as error:
        print(f"conformance check failed: {error}", file=sys.stderr)
        return 1
    if arguments.print_report:
        print(rendered, end="")
    else:
        print(f"covered {report['requirement_count']} normative requirements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
