# Backup and recovery

Kavrix now has an authenticated encrypted-backup format, a production
whole-vault MongoDB snapshot source, and a production MongoDB restore store. It
still does **not** expose `creds backup`, `creds verify`, or `creds restore`. Do
not advertise backup as an end-user CLI feature or invent command syntax around
the library.

The implemented library entry points are in the private workspace package
[`@kavrix/import-export`](../packages/import-export/src/index.ts). The MongoDB
adapter is
[`MongoBackupRestoreStore`](../packages/storage/src/mongo-backup-restore-store.ts).
The matching source adapter is
[`MongoBackupSource`](../packages/storage/src/mongo-backup-source.ts).
Neither package is currently public.

## Security boundary

An archive contains the canonical vault record and opaque encrypted group, item,
attachment, audit, and history records. Attachment stream headers and chunks
remain encrypted. Credential fields, notes, attachment plaintext, wrapped keys,
and unlock secrets are never backup metadata.

The archive is authenticated with a key derived from the already-unwrapped
32-byte Vault Root Key (VRK). Authentication detects corruption, truncation,
reordering, cross-vault substitution, and modification by a party without the
VRK. It does not hide visible format metadata. The header exposes the opaque
vault ID, schema version, creation time, format version, authentication
algorithm, and random salt. Entries expose the same opaque IDs, versions,
ciphertext sizes, and sync metadata already visible to encrypted storage. The
footer exposes the record count, transcript digest, and authentication tag.

An archive is not an unlock credential. It contains wrapped key slots, not a
portable key, recovery key, passphrase, device key, or plaintext VRK.

## Version 1 stream

Version 1 is strict UTF-8 JSON Lines with non-empty LF-terminated lines. CRLF,
empty lines, an unterminated final line, malformed JSON, extra schema fields,
data after the footer, and configured-limit violations fail closed.

The canonical order is:

1. one `header`;
2. one `vault` entry as the first record;
3. parent groups before items;
4. history after its item;
5. attachment metadata, then its one header, then contiguous zero-based chunks;
6. for each deleted entity, its exact active `tombstone-predecessor`, then its
   `tombstone`;
7. for each restored entity, the current active record followed by its restored
   tombstone, with no predecessor entry;
8. one footer.

Entry kinds are `vault`, `group`, `item`, `attachment`, `attachment-header`,
`attachment-chunk`, `audit`, `history`, `tombstone-predecessor`, and `tombstone`.
Only the last declared attachment chunk may carry the `final` tag.

The predecessor is not reconstructed or guessed. It is the exact prior active
opaque group, item, or attachment record. Its identity and revision must match
the tombstone, and `contentHashForRecord(predecessor)` must equal the
tombstone's authenticated `lastCiphertextHash`. This permits a new sync client
to apply an exact predecessor upsert followed by the deletion. A producer must
obtain the predecessor from retained immutable change data and fail backup
creation if it is unavailable. Older archives containing a deleted tombstone
without this predecessor are now rejected as incomplete.

The graph validator also rejects duplicate identities, missing parents,
cross-parent attachments, attachment schema/key/revision disagreement,
incomplete streams, cross-vault entries, and orphan tombstones.

## Authentication and errors

Creation generates a random 32-byte salt and derives a 32-byte authentication
key with HKDF-SHA-256 using `credvault/backup-authentication/v1`. The exact header
and entry lines are fed to SHA-256 and HMAC-SHA-256 as a four-byte big-endian
length followed by line bytes. Verification compares the resulting digest and
tag in constant time. Temporary authentication material is zeroized best effort.

A restore session ID is a domain-separated SHA-256 digest of the exact
authenticated header line. Replaying the same archive therefore reopens the
same durable session; creating another archive normally creates another session.

| Code                           | Meaning                                                                           |
| ------------------------------ | --------------------------------------------------------------------------------- |
| `BACKUP_INVALID`               | Framing, schema, transcript, ordering, identity, or graph is inconsistent.        |
| `BACKUP_TOO_LARGE`             | Aggregate bytes, line size, or record count exceeds the active bound.             |
| `BACKUP_WRONG_VAULT`           | Header or entry does not match the expected vault.                                |
| `BACKUP_AUTHENTICATION_FAILED` | Transcript authentication failed, including use of the wrong VRK.                 |
| `BACKUP_INCOMPLETE`            | Required header/footer, parent, predecessor, vault, or attachment data is absent. |
| `BACKUP_COMMIT_UNCERTAIN`      | Commit did not confirm and the exact restore remains staged for reconciliation.   |

Callers must not print nested parser, cryptographic, record, URI, or storage
causes to an operator-facing log.

## Implemented library operations

| API                                                                             | Current behavior                                                                                                               |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `createEncryptedBackup(input, vaultRootKey)`                                    | Streams the header, vault, ordered encrypted entries, and footer while enforcing bounds and the canonical graph.               |
| `verifyEncryptedBackup(source, vaultRootKey, expectedVaultId, limits?)`         | Authenticates and validates the complete stream without publishing records.                                                    |
| `restoreEncryptedBackup(source, vaultRootKey, expectedVaultId, store, limits?)` | Stages parsed opaque entries, authenticates the complete stream, then asks the durable store to publish that exact transcript. |
| `MongoBackupSource.open(vaultId, limits)`                                       | Opens a one-shot, transactionally consistent vault snapshot with a parsed `vault` and ordered non-vault `records` stream.      |
| `MongoBackupRestoreStore.open(sessionId, limits)`                               | Opens or resumes hidden, bounded MongoDB staging for an authenticated restore.                                                 |

These APIs require a caller that already owns an unlocked VRK. They do not
accept a portable key, passphrase, recovery key, filename, MongoDB URI, or CLI
runtime.

## MongoDB source semantics

`MongoBackupSource` starts a primary snapshot-read transaction before reading
the vault. It binds the vault record to the persisted revision/change counter,
then enumerates deterministic opaque-ID order: groups, their items, per-item
history, finalized attachments with their exact header and contiguous chunks,
tombstones, and audits. It imports no decryption or plaintext APIs.

Every vault-scoped group, item, attachment, history, and audit document must be
visited exactly once. Orphans, duplicate identities, cross-parent rows, unknown
tombstones, non-final attachment staging, missing/extra/foreign chunks, schema
or revision disagreement, and counter drift fail closed. A deleted tombstone is
emitted only after its exact active predecessor has been recovered from retained
immutable upsert/restore change data and authenticated with
`contentHashForRecord`. A restored tombstone is emitted immediately after the
active current record and never receives a predecessor entry.

The stream is one-shot. Full consumption, iterator return, explicit `close()`,
cancellation, or failure aborts the read transaction and ends its MongoDB
session. Callers that open but do not consume a snapshot must call `close()`.
Errors are generic and do not include record bodies, MongoDB causes, or URIs.

The transaction provides a consistent none-or-all view of concurrent commits.
It is still an online snapshot, not a database-wide writer fence: a sufficiently
long backup can be aborted by MongoDB transaction lifetime or operational
limits, and operators must retry from a new snapshot.

## MongoDB restore semantics

The Mongo adapter uses `backup_restore_sessions` and
`backup_restore_entries` for durable hidden staging. Hidden means normal
`MongoVaultStorage` reads and sync pulls cannot observe those entries; a MongoDB
administrator can still inspect the collections. Writes are strict-schema
parsed before sizing, bound to one session/vault/ordinal/hash, and repeated
prefix entries must match exactly. An abort deletes staged entries and leaves a
durable `aborted` session marker.

After archive authentication succeeds, one MongoDB transaction:

- verifies the exact transcript/session/count and canonical record graph;
- verifies that the target database has no normal records and no other restore
  session state;
- inserts the vault, groups, items, attachments, attachment streams, audits,
  histories, and tombstones without upsert or overwrite;
- creates a current-state sync feed, using exact predecessor upsert followed by
  tombstone for deleted records;
- stores the backup vault's exact revision as the counter rollback anchor;
- deletes staged entries and marks the session committed.

A retry after confirmed commit is idempotent only when the session, vault,
record count, and transcript digest match. A non-empty target fails closed and
is never merged or overwritten.

This is transaction atomic, but it is not protected by a database-wide writer
fence. A concurrent API or raw MongoDB writer targeting another document can
race the snapshot emptiness check. Restore therefore requires a brand-new,
exclusive database with the API stopped and no other writers connected. Do not
route the API to the database until restore and validation have completed. This
offline/exclusive requirement is operational, not automatically enforced by
the adapter.

## Operator drill for the current library

There is no supported executable command. A release/operator composition must
perform the following library-level sequence:

1. Stop the API and all database writers. Select a new MongoDB database on a
   transaction-capable replica set. Never point restore at an existing database.
2. To create an archive, open `MongoBackupSource`, pass its exact `vault` and
   `records` to `createEncryptedBackup`, and always close an unconsumed snapshot.
   Do not buffer or log the opaque record stream.
3. Obtain the archive and a valid unlock method through protected input. Unwrap
   the expected vault's VRK without placing it in argv, an environment variable,
   a URL, a filename, or a log.
4. Open the archive as a stream and call `verifyEncryptedBackup` with the
   expected opaque vault ID. Verification consumes the stream; reopen it for
   restore.
5. Create and initialize `MongoBackupRestoreStore`, then call
   `restoreEncryptedBackup` with explicit Mongo-compatible limits.
6. On `BACKUP_COMMIT_UNCERTAIN`, inspect the stager's durable `status()`. Retry
   only the identical archive/session when status is `staging`. Treat
   `committed` as success. Do not substitute a newly created archive.
7. Reopen the database through `MongoVaultStorage`. Verify the exact vault ID
   and revision, expected record counts, attachment header/chunk continuity,
   tombstones, audits, and item history before starting the API.
8. On at least one clean client, pull from cursor zero and apply the complete
   current-state feed. A deleted record must apply as predecessor upsert then
   tombstone and remain invisible.
9. Compare the restored revision with protected highest-seen local rollback
   anchors. The archive authentication proves integrity, not freshness.

The source exists, but protected unlock/file handling and an operator command do
not. Do not improvise those boundaries against production data.

## Bounds

The generic format defaults to 16 GiB aggregate input/output, 2,000,000 records,
and 32 MiB per JSON line. Callers may reduce aggregate and record limits. The
format's maximum configurable aggregate bound is 64 GiB.

The Mongo adapter is deliberately narrower:

- explicit aggregate limit at most 128 MiB;
- explicit record limit at most 10,000;
- each staged BSON document at most 15 MiB, below MongoDB's 16 MiB document cap.

The Mongo source independently enforces at most 128 MiB and 10,000 emitted
records, including the vault. Tombstones retained for ordering and all
vault-scoped collection counts are bounded before or during enumeration.

Because the generic defaults exceed the adapter caps, Mongo restore callers must
pass explicit lower limits. Large-vault and large-attachment restore is not yet
supported by this atomic implementation.

## Verified drill and supported record families

The repository's real integration drills use production crypto and the real
Mongo adapters against `mongodb://127.0.0.1:27029/?replicaSet=rs0`. They create
an authenticated archive containing:

- the exact vault and revision;
- a group, active item, deleted item, exact deletion predecessor, and tombstone;
- one attachment with its authenticated stream header and contiguous chunks;
- one encrypted audit record and one encrypted item-history record.

It verifies the archive, restores it, retries the committed session, reopens it
through `MongoVaultStorage`, compares every supported record, checks attachment
continuity, applies the pull feed to a clean `OpaqueVaultSnapshot`, and scans all
raw MongoDB documents for test plaintext canaries. It also proves staging is
invisible/abortable, divergent and cross-vault replay fails, and a non-empty
target is not overwritten.

The source drill restores the same families, opens a production snapshot,
creates and verifies a second authenticated archive from that stream, restores
that second archive into another fresh database, and compares every supported
family and tombstone semantic. It covers deleted and restored tombstones, exact
predecessor recovery, complete attachment streams, concurrent writes appearing
wholly before or after a snapshot, orphan/cross-identity corruption, missing
predecessor/chunk failure, and plaintext-canary absence from the archive, raw
restored BSON, inspection, and generic errors.

The recorded local run used Node.js 24.19.0 on Windows x64 and MongoDB 8.0.26
`rs0`. This evidence is platform-specific. It is not a claim about other MongoDB
versions, managed services, operating systems, very large archives, or
power-loss timing.

## What is not recovered

The current format and adapter do not recover:

- original server change-sequence history, idempotency commits, sync push
  checkpoints, attachment upload sessions, device sessions/tokens, API
  bootstrap state, or protected local rollback anchors;
- audit/history as sync protocol families (they are preserved in dedicated
  MongoDB collections and exposed through storage readers only);
- a vault tombstone (restore rejects it);
- original attachment upload-session timestamps or idempotency keys (the exact
  encrypted attachment records/header/chunks are preserved under a deterministic
  restore-owned finalized staging identity);
- schema migrations, cross-version transforms, partial restore, merge, overwrite,
  in-place rollback, or automatic post-restore unlock;
- executable backup/verify/restore commands, protected destination-file
  composition, scheduling, retention, or remote object-store upload.

The adapter synthesizes only a validated current-state sync feed. It does not
claim to reproduce historical server changes. The vault rollback revision is
preserved exactly; it is not incremented during restore.

## Portable key and recovery warnings

- Keep at least one verified unlock method separate from the archive. Losing
  every usable slot leaves the ciphertext unrecoverable.
- Portable and recovery keys are independent random values. Neither is
  regenerated or inferred from an archive.
- Do not store an unprotected key beside the archive or upload both to the same
  broadly accessible location.
- Preserve strict ownership/mode or ACL protection on dedicated key files. Do
  not copy them into application data, staging collections, or backup folders.
- Never put a portable key, recovery key, passphrase, VRK, or decrypted record in
  argv, environment variables, filenames, URLs, logs, manifests, checksum files,
  or backup metadata.
- Backup authentication does not prove freshness. Preserve protected highest-seen
  revision state separately and compare before accepting restored data.

See [Cryptography](./cryptography.md),
[Portable Key and Device Enrollment](./portable-key-and-device-enrollment.md),
and [Self-hosting](./self-hosting.md) for adjacent boundaries.
