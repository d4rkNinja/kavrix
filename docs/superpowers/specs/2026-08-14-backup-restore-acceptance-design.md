# Encrypted backup and isolated restore acceptance design (#48)

## Goal

Prove the complete backup/restore path against real MongoDB adapters: create an
authenticated archive from an opaque Mongo snapshot, verify it, restore it into
a different empty database, compare the restored vault revision and current
records with the source, and read the restored state through a fresh storage
and sync snapshot. The test must also prove that plaintext canaries do not
appear in the archive or durable Mongo documents.

## Architecture

The acceptance gate lives in the storage Mongo integration suite because the
packed CLI intentionally has no raw MongoDB target adapter. It uses the real
`MongoBackupSource`, `createEncryptedBackup`, `verifyEncryptedBackup`,
`MongoBackupRestoreStore`, `restoreEncryptedBackup`, `MongoVaultStorage`, and
`OpaqueVaultSnapshot` implementations. A canonical encrypted fixture first
seeds an isolated source database through the normal restore coordinator; the
archive under test is then created from that source database, so the backup
source and restore target are both real adapters.

The source and target use separate randomly named databases on the configured
transaction-capable replica set. The target is never reused or merged. The
restore verifier receives one protected fixture credential through a test-only
factory and retains the root key only for the bounded operation; no credential
or decrypted payload is written to MongoDB, the archive, logs, or process
arguments.

## Flow

1. Restore the canonical known-v1 fixture into a fresh source database.
2. Open `MongoBackupSource`, collect the opaque current records, create an
   authenticated archive, and authenticate the complete archive.
3. Restore that archive into a separate empty target database using the
   canonical semantic verifier and an equal highest-seen revision anchor.
4. Open the target with a fresh `MongoBackupSource`/`MongoVaultStorage`, assert
   exact vault and opaque record equality, and apply a fresh sync page to an
   `OpaqueVaultSnapshot` to read active, deleted, and restored records.
5. Assert the target revision and sync freshness equal the source revision,
   staging is empty, and both durable databases plus the archive are free of
   plaintext and credential canaries.

## Failure and security coverage

- A non-empty or reused target is not used; normal target state is inspected
  only after authenticated publication.
- The equal revision anchor proves the restored snapshot is not older than the
  client's known state. Lower-revision rejection remains covered by the focused
  rollback test in the same integration suite.
- Archive and BSON scans search for all canonical plaintext and credential
  canaries, including the protected fixture credential.
- Test cleanup drops only the randomly named databases it created and closes
  the client and fixture key material through existing helpers.

## Out of scope

This issue does not expose a packed `backup restore` command or add a MongoDB
URI/credential to the CLI. That adapter remains an explicit release/operator
composition boundary documented in `docs/backup-and-recovery.md`.

## Verification

Run the new focused integration test and the affected storage integration,
storage unit, import/export, client, and CLI backup suites when a local
transaction-capable Mongo replica set is available. On the managed workstation
without `KAVRIX_MONGODB_URI`, run all non-Mongo gates and record the integration
environment blocker rather than claiming a live Mongo result.
