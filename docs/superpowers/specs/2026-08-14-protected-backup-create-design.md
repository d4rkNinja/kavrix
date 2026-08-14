# Protected encrypted backup create design

## Scope

Issue #41 adds the first public backup operation: `creds backup create`. It
creates one authenticated, bounded JSON-lines archive from the already unlocked
opaque local vault state and publishes it only after the complete stream has
been written and synced to a restrictive hidden sibling temporary file.

The lower-level authenticated format remains owned by
`@kavrix/import-export`. The CLI owns command parsing, protected destination
validation, invocation lifecycle, and the redacted receipt. The CLI does not
implement cryptography or import MongoDB; a production snapshot adapter is
responsible for supplying canonical opaque records through the existing local
vault/store boundary. The global writer lease makes that local snapshot
consistent for the duration of the command. MongoDB snapshot composition stays
in the storage/operator boundary until a later issue supplies a supported
adapter.

## Command contract

```text
creds backup create --file <new-archive-path> [--vault <vault-id>] [--json]
```

The destination is required, must be a new regular file in a user-only
directory, and is validated before the command acquires unlock material. The
target is never replaced. `--vault`, when present, must identify the active
profile; the command never guesses between enrolled vaults.

The success receipt contains only the action, opaque vault ID, record count,
and archive byte count. It does not contain credentials, key material, record
payloads, Mongo details, or an unlock result.

## Write protocol

1. Validate the destination parent and absence of the final target without
   opening the vault or reading secret input.
2. Enter the existing invocation-scoped unlock lifecycle and obtain the
   process-local root key only for the duration of archive generation.
3. Enumerate canonical opaque vault, group, and item records in stable parent
   order under the writer lease. The authenticated format enforces schema,
   graph, record, line, and aggregate bounds.
4. Create a random hidden sibling file with exclusive create and user-only
   permissions. Stream each authenticated archive frame into it, fsync the
   file, and check the final byte count.
5. Publish with the existing create-only hard-link protocol, remove the hidden
   sibling, verify the published regular file, and fsync its directory. A
   pre-existing target, symlink, hard link, or publication race fails closed.
6. Always close the source and remove only the exact temporary path owned by
   this operation when publication has not succeeded. If cleanup or publication
   status is uncertain, return failure and never claim a successful receipt.

## Security properties

- The archive contains opaque encrypted records and wrapped slots only; no
  plaintext credential values or unlock material enters the stream or metadata.
- Chunks are bounded and zeroized after each successful write where ownership
  permits. The root key is owned and wiped by the caller's unlocked lifecycle.
- The final path is never opened with overwrite semantics. Temp cleanup is
  limited to the validated, exclusively-created sibling path.
- Renderer output is schema-validated, ANSI-free, and limited to safe summary
  fields.

## Verification

Focused tests cover destination validation before secret input, no overwrite or
link publication, restrictive streaming output, bounded generation, source
closure on success/failure, cleanup, canary absence, stable text/JSON receipts,
and packed help. Existing import/export tests remain the authority for archive
authentication, tampering, truncation, graph validation, and bounds.

Non-publishing archive verification and isolated restore remain strictly in
#42 and #43.
