#!/usr/bin/env python3
"""Collect release evidence for the system-level fault-injection and
model-checking gate (issue #23).

Runs `cargo test --workspace`, matches its output against the named
regression test for each documented fault class, and records the exact
revision, toolchain, fixed seeds/budgets, and pass/fail result for each.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Each fault class lists the exact `cargo test` result-line test names that
# provide its regression coverage, plus the fixed seed/budget that makes the
# scenario deterministic and reviewable without re-deriving it.
FAULT_CLASSES = {
    "restart_process_kill_at_every_durability_boundary": {
        "description": (
            "A real child process is aborted at a named point immediately "
            "before/after each command's SQLite commit; the parent reopens "
            "the database and verifies the recovered state."
        ),
        "seed_or_budget": "10 queue boundaries + 10 blob boundaries, deterministic (no randomness)",
        "tests": [
            "durable::tests::hard_process_crashes_recover_at_every_command_commit_boundary",
            "durable_blob::tests::hard_process_crashes_recover_at_every_blob_command_boundary",
            "crash_after_commit_redelivers_without_duplicate_application_then_acks",
        ],
    },
    "disk_full_read_only_busy_commit_failure": {
        "description": (
            "SQLite pragmas force read-only rejection and page-limited disk "
            "exhaustion; a thread-local flag injects one commit failure; "
            "a second connection holds the writer lock to bound busy-wait."
        ),
        "seed_or_budget": "deterministic fault injection, no randomness",
        "tests": [
            "durable::tests::readonly_full_and_commit_failures_rollback_without_false_success",
            "durable::tests::busy_timeout_is_bounded_and_classified",
            "durable_blob::tests::blob_storage_faults_roll_back_without_false_success_or_partial_state",
        ],
    },
    "duplicate_delivery_and_durable_replay": {
        "description": (
            "Exact request retries and daemon restarts must return the "
            "original response byte-for-byte; conflicting request-id reuse "
            "must return AUTH_REPLAY, never silently re-execute."
        ),
        "seed_or_budget": "deterministic fixed frames, no randomness",
        "tests": [
            "durable_blob::tests::blob_replay_record_survives_restart_and_returns_stored_response",
            "durable_blob::tests::conflicting_request_id_reuse_is_rejected_after_restart",
            "durable_blob::tests::replay_record_and_effect_commit_atomically",
            "queue_replays_survive_daemon_restart",
            "blob_replays_survive_daemon_restart",
            "tests::authenticated_request_replay_is_consistent_and_conflicts_fail",
        ],
    },
    "disconnect_and_dropped_response": {
        "description": (
            "A transport that fails exactly once after the relay has "
            "already durably accepted the command; the client's identical "
            "retry over a fresh connection must complete exactly once."
        ),
        "seed_or_budget": "deterministic scripted transport, no randomness",
        "tests": [
            "tests::disconnected_clients_exchange_encrypted_message_via_durable_http_binding",
            "empty_expired_disconnect_and_out_of_order_paths_are_deterministic",
        ],
    },
    "malicious_or_inconsistent_relay": {
        "description": (
            "A relay response with a mismatched request id, or a tampered "
            "ciphertext payload, must be rejected by the client without "
            "corrupting local state or sending a false ACK."
        ),
        "seed_or_budget": "deterministic scripted transport, no randomness",
        "tests": [
            "empty_expired_disconnect_and_out_of_order_paths_are_deterministic",
            "authentication_or_store_failure_never_sends_ack",
        ],
    },
    "concurrency_and_expiry_races": {
        "description": (
            "Two threads race SEND, FETCH+ACK, and DELETE against the same "
            "queue/message; a further pair races an expiry-time fetch "
            "against a pre-expiry fetch."
        ),
        "seed_or_budget": "SQLite IMMEDIATE-transaction serialization, no randomness",
        "tests": [
            "durable::tests::concurrent_sends_serialize_capacity_and_message_id_conflicts",
            "durable::tests::concurrent_fetch_and_acknowledge_never_apply_twice_or_lose_the_message",
            "durable::tests::concurrent_delete_queue_applies_exactly_once",
            "durable::tests::concurrent_fetch_across_the_expiry_boundary_never_yields_an_expired_message",
        ],
    },
    "clock_jump": {
        "description": (
            "A large backward jump must not fabricate an expiry or let a "
            "conflicting resend through; a large forward jump must discard "
            "the now-ancient message and release capacity; jumping back "
            "again must not resurrect it."
        ),
        "seed_or_budget": "fixed timestamps, no randomness",
        "tests": [
            "durable::tests::clock_jumps_never_fabricate_or_silently_lose_an_accepted_message",
        ],
    },
    "backup_restore_and_schema_upgrade": {
        "description": (
            "A rollback-journal-mode file copy must restore correctly in a "
            "fresh process; every historical schema version (v1, v2) must "
            "migrate to the latest version preserving existing state."
        ),
        "seed_or_budget": "deterministic fixture state, no randomness",
        "tests": [
            "durable::tests::file_copy_backup_restores_correctly_in_a_fresh_process",
            "durable::tests::v2_databases_migrate_to_version_3_adding_queue_replays",
            "durable_blob::tests::v1_databases_migrate_to_the_latest_schema_preserving_blob_state",
        ],
    },
    "long_sequence_model_check": {
        "description": (
            "A fixed-seed LCG drives 2000 random operations against both "
            "the SQLite-backed relay and an independent in-memory reference "
            "model, asserting an identical outcome after every step."
        ),
        "seed_or_budget": "LCG seed 0x4d595df4d0f33173, 2000 steps",
        "tests": [
            "durable::tests::long_generated_sequence_matches_in_memory_reference_model",
        ],
    },
}


def run(*args: str) -> str:
    return subprocess.run(
        args, cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(ROOT / "docs" / "conformance" / "durability-evidence-v1.json"),
    )
    args = parser.parse_args()

    test_run = subprocess.run(
        ["cargo", "test", "--workspace"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = test_run.stdout + test_run.stderr
    passed = set(re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE))

    classes = {}
    all_passed = True
    for name, spec in FAULT_CLASSES.items():
        results = {}
        for test_name in spec["tests"]:
            ok = test_name in passed
            results[test_name] = "passed" if ok else "not_found_or_failed"
            all_passed = all_passed and ok
        classes[name] = {
            "description": spec["description"],
            "seed_or_budget": spec["seed_or_budget"],
            "tests": results,
        }

    evidence = {
        "format": "cofferwire-durability-evidence-v1",
        "revision": run("git", "rev-parse", "HEAD"),
        "toolchain": {
            "rustc": run("rustc", "--version"),
            "cargo": run("cargo", "--version"),
        },
        "workspace_test_exit_code": test_run.returncode,
        "fault_classes": classes,
        "all_named_tests_passed": all_passed,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(f"wrote {output_path}")
    if not all_passed:
        raise SystemExit("one or more named durability regression tests did not pass")


if __name__ == "__main__":
    main()
