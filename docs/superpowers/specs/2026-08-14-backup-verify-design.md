# Protected encrypted backup verify design

## Scope

Issue #42 adds `creds backup verify`. It reopens one existing protected archive,
authenticates the complete bounded framing and canonical graph with the active
remembered-device root key, and returns a safe summary. It does not create a
temporary archive, open a restore store, stage records, or publish anything.

The authenticated format remains owned by `@kavrix/import-export`. The CLI owns
source preflight, invocation-scoped unlock composition, bounded protected-file
read, error-code mapping, and redacted rendering. The command does not import
MongoDB or accept unlock material in argv, environment variables, filenames, or
output.

## Command contract

```text
creds backup verify --file <existing-archive-path> [--vault <vault-id>] [--json]
```

The source must already be one protected regular file in a protected directory.
The CLI validates that path and its size before entering the unlock runner. A
supplied vault ID must equal the active profile; the command never guesses
between enrolled vaults.

The successful receipt contains only:

- `action: "verified"`;
- the opaque vault ID;
- bounded record and byte counts;
- the archive schema version and creation timestamp; and
- the domain-separated restore-session digest.

It never prints the source path, record payloads, credential values, key slots,
or unlock material.

## Verification protocol

1. Validate the source path, parent directory, regular-file identity, protected
   permissions/ACL, link count, and maximum size before unlock.
2. Enter the existing invocation-scoped remembered-device unlock lifecycle and
   unwrap the root key for this bounded operation only.
3. Read the protected source with a maximum-size bounded read and retain no
   second public copy. Pass one async chunk to `verifyEncryptedBackup` with the
   active vault ID and CLI bounds.
4. Require the library verifier to consume the complete UTF-8 framed stream,
   authenticate the transcript, validate the vault and graph, and reject
   tampering, truncation, duplicates, missing parents, wrong vaults, and
   unsupported bounds according to its documented `BACKUP_*` code.
5. Return the schema-validated safe summary. Zeroize the root key and source
   buffer on both success and failure.

`verifyEncryptedBackup` validates the outer authenticated graph. It does not
prove semantic decryptability of history or audit payloads; that remains a
separate restore gate and is not silently treated as verified by this command.

## Error and failure behavior

Protected-file failures map to `BACKUP_INVALID`. Library `BackupError` codes are
preserved in `CliBackupVerificationError`, while the user-facing message stays
generic. No nested parser, cryptographic, storage, URI, or file path cause is
rendered. Source preflight failure never prompts for unlock input. Verification
does not mutate the source and has no publication or cleanup ambiguity.

## Verification coverage

Focused tests cover source preflight before unlock, bounded protected reads,
successful authenticated summaries, source/root-key wiping, tamper-to-code
mapping, stable text/JSON output, path redaction, missing options, and packed
help. Existing import/export tests remain the authority for truncation, wrong
vault/key, duplicate/missing parents, graph bounds, unsupported semantic
families, and replay-resistant authentication framing.
