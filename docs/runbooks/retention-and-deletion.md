# Runbook: Retention and Deletion

This runbook states, precisely, what happens on disk when a queue expires,
is deleted, or a blob is deleted -- so an operator does not assume a
stronger deletion guarantee than the reference implementation currently
provides. `02-threat-model.md` already states that prevention of ciphertext
retention by a malicious relay is out of scope; this runbook is about the
weaker, more practical question of what a cooperating operator running the
unmodified reference daemon can rely on today.

## Queue messages: expiry and queue deletion

- An expired message is removed by an ordinary SQL `DELETE FROM messages
  WHERE ... expires_at <= now` the next time that queue is touched
  (`discard_expired` in `crates/cofferwire-relay/src/durable.rs`).
- Deleting a queue (`DeleteQueue`, authorized to the recipient) issues
  `DELETE FROM queues WHERE queue_id = ?1`; the `messages` table declares
  `queue_id ... REFERENCES queues(queue_id) ON DELETE CASCADE` and the
  connection runs with `PRAGMA foreign_keys = ON`, so every message row for
  that queue is deleted in the same transaction.

## Blobs: deletion does not remove stored ciphertext today

`DurableRelay::delete_blob_tx` (`crates/cofferwire-relay/src/durable_blob.rs`)
authorizes the caller's `delete_cap` and then runs `UPDATE blob_grants SET
deleted=1 WHERE ...`. It does not delete any row from `blob_chunks`,
`blob_objects`, or `blob_uploads`. There is currently no code path in this
repository that removes stored blob ciphertext after deletion, after a
grant's lease expires, or after an upload is abandoned before commit. An
operator who needs blob ciphertext to actually leave disk on deletion or
expiry cannot rely on the reference daemon to do this automatically today;
this is a real gap, not an intentionally undocumented feature, and is a
reasonable candidate for a follow-up issue rather than something this
runbook can instruct around.

## Logical deletion is not secure erasure

Both of the real `DELETE`/cascading-`DELETE` paths above remove rows from
SQLite's live b-tree, but the database runs `PRAGMA journal_mode = DELETE`
(rollback journal) without `PRAGMA secure_delete`. SQLite's default behavior
frees the deleted rows' pages for reuse; it does not overwrite their bytes
immediately, and a freed page's previous content can persist in the database
file until SQLite reuses or a `VACUUM` reclaims it. Practically:

- A logically deleted queue or message is no longer reachable through any
  relay command, but its ciphertext bytes may still be physically present in
  `DATABASE_PATH` until the file is vacuumed.
- If an operator needs freed pages actually overwritten, open the database
  with `PRAGMA secure_delete = ON` (accepting the extra write cost SQLite
  documents for that pragma) or run `VACUUM` after a bulk deletion. Neither
  is currently done automatically by `cofferwired`.
- A file-level backup taken before a deletion (see
  `docs/runbooks/backup-restore.md`) still contains the deleted data in full;
  deletion on the live database does not retroactively affect any backup
  already taken.

## What this means for a compliance or right-to-delete request

Treat "delete this queue/blob" as removing the data from active service
immediately (queues: yes, verified; blobs: not yet, see above), and treat
"purge the bytes from every copy of storage" as a separate, currently manual
operational step: apply `secure_delete`/`VACUUM` to the live database as
described above, and separately rotate or discard any older backups that
still contain the deleted data.
