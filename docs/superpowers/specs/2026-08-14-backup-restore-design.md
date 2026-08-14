# Protected isolated backup restore design

## Scope

Issue #43 composes protected archive I/O with the existing authenticated,
durable restore coordinator. The coordinator remains the owner of hidden
staging, sealed readback, receipt binding, publication, finalization, replay,
rollback checks, and commit-uncertain reconciliation.

The CLI layer does not import MongoDB or accept a MongoDB URI. An application
host supplies two explicit ports: a `BackupRestoreStore` for a newly isolated
target and a `RestoreVerificationSessionFactory` that owns one protected
portable-key, passphrase, or recovery-key credential. This keeps the storage
adapter and credential acquisition outside command parsing and prevents raw
unlock material from entering a CLI request or renderer.

## Command contract

The dependency-injected catalog supports:

```text
creds backup restore --file <existing-archive-path> [--vault <vault-id>] [--slot <slot-id>] [--json]
```

The archive path is validated as a protected regular source before it is read.
The optional vault and slot values are opaque selectors only; they are not
credentials. The configured restore port receives the validated request and
must bind the selectors to its target and one-shot verification factory.

The packed executable intentionally exposes only `backup create` and `backup
verify` for now. It has no safe, configured way to obtain an isolated MongoDB
target without adding a database credential/URI input channel to the CLI. The
restore descriptor is therefore not included in packed help and cannot be
mistaken for a released restore workflow.

## Protected composition

`executeProtectedEncryptedBackupRestore` performs the following bounded
sequence:

1. Validate the archive path, protected parent, regular-file identity, links,
   permissions, and maximum size before invoking either restore port.
2. Read the source through the protected-file bounded reader.
3. Pass one async archive chunk, the expected vault ID, explicit target store,
   verification factory, and resolved limits to `restoreEncryptedBackup`.
4. Map `verified-and-committed` to a redacted `restored` receipt and exact
   committed replay to `already-committed`. A replay never fabricates a slot
   receipt.
5. Map library backup codes to a generic CLI restore error. For
   `BACKUP_COMMIT_UNCERTAIN`, instruct the operator to preserve the exact
   archive and isolated target and retry only that same restore session.
6. Wipe the bounded archive buffer on every exit path.

The lower-level coordinator remains the authority for empty-target checks,
hidden durable staging, full authenticated framing, semantic readback to true
EOF, exact receipt publication, finalize, rollback freshness comparison, and
response-loss/replay recovery. No merge, overwrite, in-place restore, history,
or audit semantic claim is added here.

## Verification coverage

Focused CLI tests cover source preflight ordering, bounded reads, target/factory
port binding, committed receipts, committed replay, buffer wiping, generic
uncertain-commit preservation instructions, and path-redacted text/JSON output.
Existing `@kavrix/import-export` and storage suites remain authoritative for
the hidden staging, empty-target, semantic readback, receipt, rollback, replay,
and Mongo transaction behavior.
