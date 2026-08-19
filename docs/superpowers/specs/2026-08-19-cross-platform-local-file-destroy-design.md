# Cross-platform secret input, local file storage, and vault destruction design

## Goal

Make the shipped `kavrix` CLI reliable on supported Windows, macOS, and Linux
terminals; let an operator choose MongoDB or a local encrypted vault file; add
an authenticated, twice-confirmed whole-vault destruction command; and add a
packed-CLI acceptance gate that cleans every test-owned artifact on both success
and failure.

The change preserves the current zero-knowledge boundary and existing MongoDB
command behavior. MongoDB remains the default datastore so existing invocations
do not silently change targets.

## Confirmed terminal defect

`LocalSecretInput` currently extracts `stdin.setRawMode` and calls the detached
function. Node's TTY implementation requires the stream receiver, so the call
can throw before the first masked value is read. The CLI converts that exception
to `Secret input terminal preparation failed.` This is a cross-platform defect,
not a Windows-only policy limitation.

The fix will call raw-mode operations through their owning stream, attach error
listeners before the transition, and restore the original raw state on success,
validation failure, cancellation, stream failure, and setup failure. Listener
removal, raw-state restoration, pausing, and the prompt newline will be attempted
independently. Secret bytes remain masked, bounded, and zeroized where the
JavaScript runtime permits; no shell, `stty`, PowerShell, or new prompting
dependency will be introduced.

## Datastore contract and selection

`@kavrix/storage` will own a narrow `EncryptedVaultStore` interface used by the
CLI:

- `ping`
- `get`
- `listVaultIds`
- `create`
- revision-checked `update`
- revision-checked `delete`
- `close`

`MongoLocalVaultStore` will implement the interface without changing its URI,
TLS, timeout, schema, or conflict behavior. Its delete operation will remove only
the selected vault document using the expected revision. It will never drop a
database or collection.

A new `FileLocalVaultStore` will store one canonical `LocalVaultDocument` per
file. The document already places credential names and values inside an
authenticated encrypted payload and wraps the root key; the file still exposes
the same bounded metadata that MongoDB sees, including vault ID, versions,
revision, timestamps, envelope sizes, and key-slot metadata. Documentation will
say this precisely rather than claim that every byte of the container is opaque.

The file adapter will:

- parse every read and write with the canonical runtime schema;
- enforce a bounded file size;
- reject symlinks, non-regular files, multiple hard links, unsafe ownership,
  unsafe Unix modes, and unsafe Windows ACLs;
- use an exclusive sibling lock and expected-revision checks;
- publish updates through a same-directory restrictive temporary file, fsync,
  atomic rename, identity verification, and directory sync where supported;
- remove temporary files after failures while preserving an ambiguous lock for
  explicit recovery rather than guessing that no writer exists;
- never store a passphrase, portable key, recovery secret, decrypted payload, or
  MongoDB URI.

Commands that access vault data receive:

- `--datastore <mongodb|file>`, default `mongodb`;
- existing MongoDB options when `mongodb` is selected;
- `--data-file <path>` when `file` is selected.

Mixed-backend options are rejected before secret input. File-backed commands do
not request a database URL. `db ping` remains MongoDB-specific; the normal
file-store open and schema validation provide the local availability check.
Datastore choice is explicit on each invocation and is not persisted in a
plaintext settings file.

## Initialization and failure recovery

Initialization will validate every destination before reading passphrases. It
will create the protected key, encrypted datastore document, and authenticated
revision anchor through an initialization cleanup stack. If a later step fails,
Kavrix removes only artifacts proven to have been created by that invocation.
Cleanup failure is surfaced together with the original error and is never
silently ignored.

Existing MongoDB initialization cannot be made fully atomic with local protected
files. The implementation will therefore preserve resumable, fail-closed
behavior and test each interruption boundary. It will not delete a pre-existing
file or MongoDB document during rollback.

## `kavrix destroy`

`kavrix destroy` will destroy exactly one selected vault. It is not an alias for
credential removal and has no `--force`, `--yes`, or confirmation-in-argv bypass.

The command will:

1. Resolve and validate the selected datastore, vault ID, active key file, and
   revision anchor before prompting.
2. Read the datastore credential and key-file passphrase through the existing
   masked or explicit framed-stdin paths.
3. Authenticate the key binding, decrypt and validate the vault, and require the
   current authenticated revision anchor. Storage access alone is insufficient.
4. Display a sanitized plan containing the vault ID, datastore target, revision,
   encrypted record count, active key, anchor, and explicitly supplied additional
   protected artifacts.
5. Require the exact first confirmation `DESTROY <vault-id>`.
6. Re-read the datastore and fail on any revision or authenticated metadata
   change.
7. Require a second exact confirmation containing the current revision and a
   fresh displayed challenge.
8. Delete the datastore document using expected-revision compare-and-delete.
9. Guardedly unlink additional verified key/recovery artifacts, then the active
   anchor, then the active key last. Every artifact must be a strict Kavrix file
   bound to this vault; paths are never globbed.
10. Report datastore and local-artifact results separately. Partial cleanup is a
    failure and remains safe to resume.

Interactive confirmations use visible terminal input because they are not
secrets. `--confirmation-stdin` accepts exactly two bounded newline-delimited
frames for controlled automation. It cannot be mixed with interactive
confirmation and never accepts confirmation text in argv.

Kavrix cannot discover portable-key copies or recovery kits created outside the
current invocation history. The command will accept repeatable explicit protected
artifact paths, verify each binding before deletion, and warn that unknown
copies, MongoDB backups/oplogs/snapshots, filesystem snapshots, SSD remapping,
and provider retention are outside its erasure guarantee. The security claim is
guarded unlink plus cryptographic erasure only when every usable key and recovery
copy has actually been removed.

## Tests and pre-CI acceptance

Focused automated tests will cover:

- receiver-preserving masked input and original raw-state restoration;
- sequential prompts, Unicode, CR/LF, backspace, Ctrl-C, early EOF, stream error,
  raw-mode failure, cleanup failure, and absence of secret output;
- local-file creation, read, update, conflict, bounded parsing, tampering,
  symlink/hard-link/permission rejection, lock contention, atomic interruption,
  and plaintext canaries;
- MongoDB compare-and-delete behavior at the adapter boundary;
- datastore option validation before secret acquisition;
- both destroy confirmations, cancellation at each stage, stale revisions,
  wrong vault bindings, untrusted paths, partial cleanup, and successful rerun;
- initialization rollback without deleting pre-existing artifacts.

`acceptance/pre-ci/all-commands/` will own a packed-install lifecycle runner. A
root `pnpm acceptance:pre-ci` command will run it before release-oriented CI
steps. The always-available scenario uses a generated local encrypted data file
and executes help/version plus the complete applicable public command lifecycle,
including `init`, key operations, recovery operations, credential CRUD, views,
search/statistics, doctor commands, vault commands, and `destroy`.

An optional MongoDB scenario runs only when a URI is supplied through a protected
stdin/file-descriptor flow. It uses randomly generated database, collection, and
vault names, never caller-supplied deletion targets. A real MongoDB pass is not
claimed when that prerequisite is absent.

The acceptance runner registers each resource immediately with an idempotent
cleanup stack. Its outer `finally` handles success, assertion failure, child
failure, timeout, `SIGINT`, and `SIGTERM`; kills active children with a bounded
escalation; removes only test-owned temporary roots; and, for MongoDB, deletes
only a generated target carrying the current random ownership marker. Cleanup
errors are aggregated with test errors. `SIGKILL` and host crashes cannot run
process cleanup, so residue is timestamped and eligible only for a separately
bounded ownership-checked scavenger.

CI will run unit, format, lint, type, build, packed-package, and the local-file
acceptance gate on supported Windows, macOS, and Linux runners. The packed smoke
script will also remove its currently leaked pack directory and scan relevant
artifacts/output for plaintext canaries and private paths.

## Remote verification

The requested host is `ubuntu@80.225.195.189`. The initial read-only SSH probe to
port 22 timed out. No result from that host will be claimed until it becomes
reachable and authenticates using an approved key or agent. Once reachable, the
remote test will create one test-owned `kavrix` directory, run the packed local
file acceptance path, and remove that directory in `finally` regardless of pass
or failure.

## Documentation and compatibility

The README, CLI reference, architecture, datastore guide, data model, security
testing, release procedure, dependency policy, and implementation-status ledger
will be reconciled with the shipped behavior and observable gates. Existing
MongoDB invocations keep their default backend, option names, outputs, and exit
codes unless a new fail-closed validation rejects an ambiguous mixed-backend
invocation.

This change introduces no new cryptographic primitive, plaintext settings file,
browser surface, API server, sync daemon, external prompt program, or destructive
database-wide operation.
