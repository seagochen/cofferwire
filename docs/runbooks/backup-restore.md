# Runbook: Backup and Restore

This runbook covers the reference relay daemon's single SQLite database
(`DATABASE_PATH`, opened by `cofferwire-relay::DurableRelay`). It documents
only the method this repository's fault-injection suite actually verifies;
see `TESTING.md` section 9 for the underlying tests.

## What is proven, and what is not

The schema uses SQLite's rollback journal (`PRAGMA journal_mode = DELETE`),
not WAL, so a database has no separate `-wal`/`-shm` file holding
uncommitted data. `cofferwire-relay`'s
`file_copy_backup_restores_correctly_in_a_fresh_process` test proves that a
plain file copy taken **after every writer connection to the database has
closed** restores correctly in a fresh process, including a follow-up fetch
and acknowledge against the restored copy.

This repository does not test taking a file copy while `cofferwired` is
still running and possibly mid-transaction. Do not treat a copy taken from a
live process as a verified backup; use the stop-copy-restart procedure
below, or evaluate SQLite's own online backup API (`sqlite3_backup_init`) and
validate it against this codebase's own crash/restore tests before relying
on it.

## Backup procedure (tested)

1. Stop `cofferwired` (or otherwise ensure the process holds no open
   connection to `DATABASE_PATH`). A SIGTERM followed by waiting for the
   process to exit is sufficient; there is no separate flush step because
   every accepted command already committed durably before its response was
   returned (`CW-THREAT-010`, `CW-THREAT-012`).
2. Copy `DATABASE_PATH` to the backup location. There is no companion
   journal file to copy in the steady state; if a `-journal` file happens to
   exist, the prior step did not fully stop the process -- wait for the
   process to exit and retry.
3. Restart `cofferwired` against the original `DATABASE_PATH`. The backup
   copy is now a point-in-time snapshot independent of the live database.

## Restore procedure (tested)

1. Stop `cofferwired` if it is running against the target path.
2. Copy the backup file to `DATABASE_PATH` (or point `DATABASE_PATH` at the
   backup file directly).
3. Start `cofferwired`. `DurableRelay::open` runs the schema migration path
   on first open, so a backup taken from an older schema version (see
   `PRAGMA user_version` in `crates/cofferwire-relay/src/durable.rs`)
   upgrades automatically; this is the same path exercised by
   `v2_databases_migrate_to_version_3_adding_queue_replays` and
   `v1_databases_migrate_to_the_latest_schema_preserving_blob_state`.
4. Verify with a read-only client request (for example `FETCH` against a
   known queue) before resuming normal traffic.

## What a restore does and does not preserve

A restored database preserves every durably committed queue and blob state,
including replay records (`queue_replays`, `blob_replays`), so a client
retrying a request it already sent before the backup was taken still
receives its original response rather than a fresh execution. A restore
naturally loses any command accepted by the live database strictly after
the backup was taken; this is an ordinary backup recency gap, not a
durability violation, since the daemon never reports success for a command
that has not yet committed.
