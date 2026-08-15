# CLI reference

Kavrix is not published. The public-package build produces a `creds` executable
with the production-backed command surface below. The repository also retains a
larger dependency-injected catalog for protocol and adapter tests; commands marked
"catalog only" are not available in the packed executable.

This distinction is security-relevant: a command listed as "catalog only" below
is not usable from the current public executable.

## Public-package executable

The packed executable does not read MongoDB directly. Local generation uses the
production cryptographic RNG, TOTP consumes a locally supplied seed, and `key
create` writes one protected or unprotected portable-key file. `init` composes a
crash-safe initialization coordinator; `connect` and `recover` use the
authenticated HTTPS control/sync client without sending local unlock material;
`unlock`/`lock`
compose the invocation-scoped unlocked lifecycle; `status` reads a single
canonical local profile, the opaque SQLite queue, and protected rollback state
without unlocking or decrypting the vault; and `group`/`credential` compose local
encrypted mutation against the unlocked local store. Its current surface is:

| Command                                                                           | Status                         | Behavior                                                                                                                                                                                                                                                                            |
| --------------------------------------------------------------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `creds`                                                                           | Available in the built package | Prints help.                                                                                                                                                                                                                                                                        |
| `creds --help`                                                                    | Available in the built package | Prints static help.                                                                                                                                                                                                                                                                 |
| `creds --version`                                                                 | Available in the built package | Prints package version `0.1.0`.                                                                                                                                                                                                                                                     |
| `creds version`                                                                   | Available in the built package | Prints package version `0.1.0`.                                                                                                                                                                                                                                                     |
| `creds completion <shell>`                                                        | Available in the built package | Prints static top-level completion for `bash`, `zsh`, `fish`, or `powershell`.                                                                                                                                                                                                      |
| `creds generate password [options]`                                               | Available in the built package | Generates one policy-validated password with production randomness.                                                                                                                                                                                                                 |
| `creds generate passphrase [options]`                                             | Available in the built package | Generates one passphrase from the attributed EFF short word list.                                                                                                                                                                                                                   |
| `creds totp [options]`                                                            | Available in the built package | Reads a masked or explicit-stdin Base32 seed and emits one canonical TOTP code.                                                                                                                                                                                                     |
| `creds key create --file <path> [options]`                                        | Available in the built package | Creates one unbound v1 portable-key file, refuses overwrite, and never displays the portable key.                                                                                                                                                                                   |
| `creds key slot list [--json]`                                                    | Available in the built package | Lists only redacted slot ID/type/state/version/timestamps and public device IDs; derivation metadata and wrapped keys are excluded.                                                                                                                                                 |
| `creds key slot create <slot-type> [options]`                                     | Available in the built package | Adds a portable-key, passphrase, recovery-key, or device-key slot after explicit local reauthentication, remote readback, and encrypted audit publication.                                                                                                                          |
| `creds key slot disable <slot-id> [options]`                                      | Available in the built package | Removes only this device's protected device-slot secret; the remote vault record is unchanged and the remembered current slot requires a verified replacement.                                                                                                                      |
| `creds key slot revoke <slot-id> [options]`                                       | Available in the built package | Revokes one remote slot through the revision-bound control plane, with last-current-slot protection and encrypted audit publication.                                                                                                                                                |
| `creds key rotate [options]`                                                      | Available in the built package | Generates or imports a portable replacement file, durably publishes pending then active slot envelopes, confirms the replacement locally, and revokes the old slot only after confirmation.                                                                                         |
| `creds key rotate resume <operation-id> [options]`                                | Available in the built package | Replays the exact authenticated local checkpoint against the fetched vault and resumes only an identical pending rotation.                                                                                                                                                          |
| `creds key rotate list [--json]`                                                  | Available in the built package | Lists only operation IDs, public lifecycle states, slot IDs, and timestamps; replacement keys and wrapped-root data are excluded.                                                                                                                                                   |
| `creds init [options]`                                                            | Available in the built package | Creates one vault/profile/device/session with durable recovery material and a global writer lease; `--key-file` accepts a guarded unprotected or passphrase-protected unbound v1 file.                                                                                              |
| `creds init resume <operation-id>`                                                | Available in the built package | Resumes one durable initialization journal operation.                                                                                                                                                                                                                               |
| `creds init cancel <operation-id>`                                                | Available in the built package | Cancels one safely cancellable prepared initialization operation.                                                                                                                                                                                                                   |
| `creds connect --server <url> --vault <vault-id> --device <device-id>`            | Available in the built package | Attaches an empty local data home to an existing enrolled device using its protected session and device slot; it never accepts or transmits a portable key.                                                                                                                         |
| `creds recover --server <url> --vault <vault-id> [options]`                       | Available in the built package | Recovers an empty data home with an invite and local portable key, creates a fresh device slot only after local authentication, persists the profile, and performs the first opaque sync.                                                                                           |
| `creds recover resume <operation-id> --server <url> --vault <vault-id> [options]` | Available in the built package | Resumes a durable recovery journal and completes only the missing local slot/profile/sync work.                                                                                                                                                                                     |
| `creds recover cancel <operation-id> --server <url> --vault <vault-id>`           | Available in the built package | Cancels a prepared recovery journal locally before network use.                                                                                                                                                                                                                     |
| `creds device join --server <url> --vault <vault-id> [options]`                   | Available in the built package | Joins a vault with an invite and portable key through the durable successor-token, device-slot, profile, and first-sync coordinator.                                                                                                                                                |
| `creds device join resume <operation-id> [options]`                               | Available in the built package | Resumes the exact pending device-join operation without generating replacement identities.                                                                                                                                                                                          |
| `creds device join cancel <operation-id> [options]`                               | Available in the built package | Cancels only a prepared local device-join journal before network use.                                                                                                                                                                                                               |
| `creds device list --vault <vault-id> [options]`                                  | Available in the built package | Lists canonical public device metadata with bounded opaque pagination; bearer tokens and token hashes are never returned.                                                                                                                                                           |
| `creds device revoke <device-id> --vault <vault-id> --confirm`                    | Available in the built package | Revokes the current or another device after explicit confirmation; the server invalidates its sessions and denies revoking the last active device.                                                                                                                                  |
| `creds device remember [options]`                                                 | Available in the built package | Generates a device-key unlock slot locally and stores its secret only in the native keychain; the API session credential is separate and unchanged.                                                                                                                                 |
| `creds device forget <slot-id> [options]`                                         | Available in the built package | Removes only the exact local device-key entry after reauthentication; the remote slot and API session credential remain unchanged.                                                                                                                                                  |
| `creds device invite create --vault <vault-id> [options]`                         | Available in the built package | Issues one bounded, short-lived invite; the token is displayed once only on an interactive or explicitly acknowledged stdout.                                                                                                                                                       |
| `creds device invite list --vault <vault-id> [options]`                           | Available in the built package | Lists only canonical public invite metadata and never returns invite tokens or hashes.                                                                                                                                                                                              |
| `creds device invite revoke <invite-id> --vault <vault-id>`                       | Available in the built package | Revokes one unused invite by opaque ID through the authenticated control plane.                                                                                                                                                                                                     |
| `creds unlock --check [options]`                                                  | Available in the built package | Verifies unlock material and immediately relocks; no daemon persists.                                                                                                                                                                                                               |
| `creds lock [options]`                                                            | Available in the built package | Locks the active vault and clears use-case-managed secret state.                                                                                                                                                                                                                    |
| `creds status [options]`                                                          | Available in the built package | Reports redacted locked/offline state for exactly one enrolled local profile without networking.                                                                                                                                                                                    |
| `creds template list [--json]`                                                    | Available in the built package | Lists available built-in templates and group templates in the vault.                                                                                                                                                                                                                |
| `creds template inspect <query> [--json]`                                         | Available in the built package | Inspects a template schema definition (fields, stable keys, types, required/sensitive flags).                                                                                                                                                                                       |
| `creds template create <name> [options]`                                          | Available in the built package | Creates a reusable template / group container, optionally based on a built-in template (`--from`).                                                                                                                                                                                  |
| `creds template edit <group-query> [options]`                                     | Available in the built package | Updates template name or description metadata.                                                                                                                                                                                                                                      |
| `creds template archive <group-query>`                                            | Available in the built package | Archives a group template container as a tombstone.                                                                                                                                                                                                                                 |
| `creds template restore <group-id>`                                               | Available in the built package | Restores an archived group template container.                                                                                                                                                                                                                                      |
| `creds template delete <group-query> --force`                                     | Available in the built package | Permanently deletes a group template container with explicit `--force` authorization.                                                                                                                                                                                               |
| `creds group create <name> [options]`                                             | Available in the built package | Creates an encrypted local group container, optionally initialized with a built-in template (`--template`).                                                                                                                                                                         |
| `creds group list [--json]`                                                       | Available in the built package | Lists active groups with redacted names.                                                                                                                                                                                                                                            |
| `creds group rename <query> <new-name>`                                           | Available in the built package | Renames an active group by ID, name, or alias.                                                                                                                                                                                                                                      |
| `creds group archive <query>`                                                     | Available in the built package | Archives an active group as a tombstone.                                                                                                                                                                                                                                            |
| `creds group restore <group-id>`                                                  | Available in the built package | Restores an archived group by exact ID.                                                                                                                                                                                                                                             |
| `creds group delete <query> --force`                                              | Available in the built package | Permanently deletes a group with an explicit `--force` authorization.                                                                                                                                                                                                               |
| `creds credential create <group> <title>`                                         | Available in the built package | Creates an encrypted credential item inside a group.                                                                                                                                                                                                                                |
| `creds credential list <group> [--json]`                                          | Available in the built package | Lists active credentials in a group with redacted titles.                                                                                                                                                                                                                           |
| `creds credential rename <group> <credential> <new-title>`                        | Available in the built package | Renames an active credential.                                                                                                                                                                                                                                                       |
| `creds credential archive <group> <credential>`                                   | Available in the built package | Archives an active credential as a tombstone.                                                                                                                                                                                                                                       |
| `creds credential restore <group> <credential-id>`                                | Available in the built package | Restores an archived credential by exact ID.                                                                                                                                                                                                                                        |
| `creds credential delete <group> <credential> --force`                            | Available in the built package | Permanently deletes a credential with an explicit `--force` authorization.                                                                                                                                                                                                          |
| `creds field add <group> <credential> <field-key> [opts]`                         | Available in the built package | Adds a new dynamic field definition to a credential.                                                                                                                                                                                                                                |
| `creds field set <group> <credential> <field-key> [val]`                          | Available in the built package | Sets or updates a field value using positional text or `--value-stdin`.                                                                                                                                                                                                             |
| `creds field update <group> <credential> <field-key>`                             | Available in the built package | Updates dynamic field definition metadata (label, type, sensitive).                                                                                                                                                                                                                 |
| `creds field archive <group> <credential> <field-key>`                            | Available in the built package | Archives a field value into archivedFieldValues.                                                                                                                                                                                                                                    |
| `creds field restore <group> <credential> <field-key>`                            | Available in the built package | Restores an archived field value back to active field values.                                                                                                                                                                                                                       |
| `creds field remove <group> <credential> <key> --force`                           | Available in the built package | Permanently removes an item-specific field definition and value.                                                                                                                                                                                                                    |
| `creds note add <group> [cred] [title] [opts]`                                    | Available in the built package | Adds an encrypted note to a group or credential using positional text or `--content-stdin`.                                                                                                                                                                                         |
| `creds note update <group> [cred] <note> [opts]`                                  | Available in the built package | Updates note title, content, sensitivity, or pin state.                                                                                                                                                                                                                             |
| `creds note archive <group> [cred] <note>`                                        | Available in the built package | Sets archivedAt timestamp on a group or credential note.                                                                                                                                                                                                                            |
| `creds note restore <group> [cred] <note>`                                        | Available in the built package | Restores an archived note back to active notes.                                                                                                                                                                                                                                     |
| `creds note remove <group> [cred] <note> --force`                                 | Available in the built package | Permanently removes a note with an explicit `--force` authorization.                                                                                                                                                                                                                |
| `creds show <group> <credential> [--json]`                                        | Available in the built package | Inspects a credential with secret fields and sensitive note content redacted.                                                                                                                                                                                                       |
| `creds copy <group> <credential> <field> [--index <n>]`                           | Available in the built package | Copies an authorized field value to the guarded clipboard with auto-clear.                                                                                                                                                                                                          |
| `creds reveal <group> <credential> <field> [--stdout]`                            | Available in the built package | Reveals an authorized field value, denying non-interactive redirection unless `--stdout` is passed.                                                                                                                                                                                 |
| `creds get <group> <credential> <field> [--reveal]`                               | Available in the built package | Gets one field value with redacted default, optional `--reveal` and structured `--json` mode.                                                                                                                                                                                       |
| `creds sync [--json]`                                                             | Available in the built package | Synchronizes vault data with server and prints updated status.                                                                                                                                                                                                                      |
| `creds backup create --file <path> [--vault <vault-id>] [--json]`                 | Available in the built package | Creates one bounded authenticated archive from the enrolled local opaque cache; destination validation occurs before unlock, existing files/links are refused, and the receipt contains only vault ID, record count, and byte count. Unsupported local record families fail closed. |
| `creds backup verify --file <path> [--vault <vault-id>] [--json]`                 | Available in the built package | Opens an existing protected archive read-only, authenticates its complete bounded framing and graph with the active remembered device slot, and emits only a safe verification summary. It never stages or publishes.                                                               |

The generated completion is derived from the static public catalog. It never
loads runtime vault names, aliases, fields, IDs, or secrets. Inspect output
before installing it into a shell profile:

```text
creds completion bash
creds completion zsh
creds completion fish
creds completion powershell
```

Password policy options cover length 8-1024, per-character-class minima, visible
ASCII exclusions, and `--stdout`. Passphrase options cover 6-24 words, one
supported separator, optional random capitalization/digit, exact word
exclusions, and `--stdout`. TOTP supports `--secret-stdin`, SHA-1/SHA-256/SHA-512,
6-8 digits, periods from 5 through 3600 seconds, an optional bounded Unix time,
and `--stdout`. Secret output requires an interactive stdout unless `--stdout`
is explicit.

`key create` is unprotected by default. `--protect-with-passphrase` acquires two
matching masked entries of at least 12 UTF-8 bytes; `--passphrase-stdin` requires
exactly two bounded frames followed by EOF. Success emits only `Portable key file
created.` Existing targets are never replaced.

`backup create` requires `--file` and creates a new archive in a protected
user-only directory. It does not accept a key or passphrase in argv, and it
does not print archive contents or unlock material. The command currently
backs up the enrolled local opaque vault/group/item state; the Mongo snapshot
and protected restore composition own attachment/history/audit records, and
known-v1 restore semantically opens the documented history and audit payloads.

`backup verify` also requires `--file`, but the path must already name one
protected regular archive. It validates the source before unlock, then uses the
active remembered device slot to authenticate the complete bounded archive. It
does not create temporary staging, publish records, or print the archive path,
contents, or unlock material. Outer authentication of history and audit records
is supported, but the command fails with `BACKUP_DECRYPTABILITY_UNSUPPORTED`
instead of claiming those families are semantically verified.

The protected `backup restore` composition is available only to the
dependency-injected catalog with an explicit isolated-target restore port. The
packed executable omits that descriptor because no safe target/database adapter
is configured there; it must not be treated as a released restore command.

`key slot` commands require an explicit `--reauth` method. Portable, recovery,
and passphrase credentials are accepted through masked input, bounded stdin, or
guarded portable-key files; `device-key` reauthentication reads only the
protected local keychain. Slot creation and remote revocation publish an
encrypted audit sidecar containing metadata only. `disable` is local-only and
removes a same-device device-slot secret without changing the server record.
All rendered slot output is redacted and never includes derivation parameters,
wrapped-root envelopes, credentials, or device secrets.

`key rotate --generate-file <path>` writes a fresh bound replacement file, or
`key rotate --replacement-file <path>` imports an existing unbound file. A
protected generated/imported file uses the corresponding passphrase-stdin
option; secret stdin cannot be shared with reauthentication stdin in one
invocation. `key rotate resume` requires the same replacement file so its
possession can be confirmed again. The local journal stores only public slot
snapshots, revisions, and an HMAC-authenticated checkpoint. The vault key
version and encrypted payload bytes do not change.

`status` accepts `--json`, `--secret-backend <native|sealed-file>`, and
`--backend-passphrase-stdin`. The backend defaults to `native`; a missing native
adapter fails closed and never falls back to a file. Explicit `sealed-file` mode
uses one masked prompt unless its stdin flag is present. The stdin form reads
exactly one bounded UTF-8 passphrase followed by EOF. The stdin flag is invalid
with `native`, and neither backend policy nor its passphrase is read from an
environment variable. `CREDS_HOME` must be absolute when set.

Status resolves exactly one profile before loading protected state. It reports
only vault/device IDs, `locked`, `offline`, pending opaque mutation count, and an
optional protected-state timestamp. It holds the global writer lease, closes
the SQLite stores and protected backend before rendering, and never opens
initialization/join journals or a clipboard. A sealed backend authenticates and
unseals only the local protected rollback metadata needed for that timestamp;
status never obtains vault root/group/item keys or decrypts credential records.
Zero/multiple profiles, corruption, wrong passphrases, and lease contention fail
closed. This command is not an unlock, online-sync, credential-read, or
native-keychain portability claim.

`unlock --check` acquires unlock material through a masked prompt or explicit
stdin, opens one protected session and local store, derives the vault root key
only inside the locked lifecycle, and relocks immediately; no daemon persists.
`lock` releases owned buffers and clears use-case-managed secret state. Both hold
the global writer lease and close every opened resource, surfacing an aggregate
error when an operation and its cleanup both fail.

`init --key-file <path>` validates the guarded file before initialization. An
unprotected file needs no extra secret; a protected file prompts for its
passphrase, or accepts `--key-file-passphrase-stdin` as a leading bounded frame.
With `--confirmation-stdin`, that frame is followed by the portable and
recovery confirmation frames. Fresh initialization rejects bound files.

`recover` requires an empty local data home. The invite and portable key may be
entered through two masked prompts, or supplied as two exact stdin frames with
`--invite-stdin --portable-key-stdin`. `--key-file <path>` accepts the guarded
unprotected/protected portable-key format; filesystem safety is checked before
the protected backend or key-file passphrase is opened. A protected file may use
`--key-file-passphrase-stdin`; together with `--invite-stdin`, the exact stdin
frames are invite then file passphrase. Recovery output contains only the opaque
operation, vault, and device IDs.

`group` and `credential` mutate the encrypted local store through the same
invocation-scoped unlocked lifecycle. Secrets never enter argv, environment,
completion, or logs: titles and names are sanitized plain text, field values are
set only through protected stdin or a masked prompt in later commands, and
archive/restore operate on opaque tombstones. Permanent deletion requires the
explicit `--force` flag. Ambiguous or missing names fail closed, and list output
renders only sanitized titles and opaque IDs.

The deterministic package build emits one ESM executable entry and
content-hashed lazy chunks. Version, completion, public help, `status --help`,
and invalid commands do not evaluate the production-status chunk; version and
completion also avoid the cryptography/key-file chunk. The public JavaScript module contains only a
`CLI_VERSION` export; repository-only CLI factories and adapters are not
exported. The CycloneDX SBOM records an aggregate artifact-set hash, one hash for
every emitted JavaScript file, four bundled npm libraries, and the attributed
EFF word list as a separate CC-BY-4.0 data component. See the
[release process](./release.md) for the remaining publication gates.

## Additional dependency-injected catalog

[`CLI_COMMAND_CATALOG`](../apps/cli/src/catalog.ts) and
[`runCli`](../apps/cli/src/cli.ts) implement and test the following parser,
validation, rendering, and use-case boundaries. They require real
`CliUseCasePorts` and, where applicable, a `SecretInputPort`. Commands listed
here without production composition are exercised only through injected use-case
ports and never reach the packed executable.

| Syntax                                                                                                      | Status                         | Implemented boundary behavior                                                                                                                                                                                           |
| ----------------------------------------------------------------------------------------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `creds show <group-query> <credential-query> [--json]`                                                      | Catalog only                   | Calls one redacted, schema-validated show use case. See [Direct access CLI](./direct-access-cli.md).                                                                                                                    |
| `creds copy <group-query> <credential-query> <field-query> [--index <number>]`                              | Catalog only                   | Delegates authorized clipboard copy and returns only a safe label/deadline receipt, never the copied value.                                                                                                             |
| `creds device invite create --vault <vault-id> [options]`                                                   | Available in the built package | Issues a bounded invite with explicit or least-privilege default scopes; one-time token output requires an interactive terminal or `--stdout`.                                                                          |
| `creds device invite list --vault <vault-id> [--json]`                                                      | Available in the built package | Lists canonical public invite metadata, never invite tokens or hashes.                                                                                                                                                  |
| `creds device invite revoke <invite-id> --vault <vault-id>`                                                 | Available in the built package | Revokes one opaque invite ID through the authenticated production port.                                                                                                                                                 |
| `creds device list --vault <vault-id> [--limit <1..200>] [--cursor <opaque>] [--json]`                      | Available in the built package | Renders only public device records and forwards canonical bounded pagination through the authenticated production port.                                                                                                 |
| `creds device revoke <device-id> --vault <vault-id> --confirm`                                              | Available in the built package | Requires explicit confirmation; current-device revocation is allowed only when another active device remains, and the API atomically invalidates target sessions.                                                       |
| `creds device remember [options]`                                                                           | Available in the built package | Composes the existing device-key slot creator and native keychain readback; no plaintext fallback or session-locator reuse is possible.                                                                                 |
| `creds device forget <slot-id> [options]`                                                                   | Available in the built package | Composes the local slot-disable path for one exact slot ID and retains the remote encrypted slot and API session entry.                                                                                                 |
| `creds recover --server <url> --vault <vault-id> [--key-file <path>] [--invite-stdin --portable-key-stdin]` | Available in the built package | Uses the durable join coordinator, locally authenticates the portable slot, persists independent session/device successors through protected adapters, stores the profile, and initializes opaque sync.                 |
| `creds device join --server <url> --vault <vault-id> [options]`                                             | Available in the built package | Uses the durable join coordinator, protected portable-key authentication, device/session persistence, and first opaque sync; output contains only opaque operation/vault/device IDs.                                    |
| `creds backup restore --file <path> [--vault <vault-id>] [--slot <slot-id>] [--json]`                       | Catalog only                   | Validates and bounded-reads a protected archive, then delegates hidden isolated staging, semantic readback, receipt-bound publication, replay, and uncertain-commit handling to explicit target and verification ports. |

The lower-level `device invite join` catalog entry remains a protocol-test
contract. The public `device join` and `recover` commands supply the fresh-home
production composition with server selection, portable-key/key-file input,
durable enrollment replay state, profile/device-slot persistence, and first
sync. They are intentionally distinct from the later device-management
workflow that will list, revoke, and manage already-enrolled devices. Read
[Portable Key and Device Enrollment](./portable-key-and-device-enrollment.md)
for the protocol status.

The lower-level protocol now returns the canonical wrapped/encrypted vault record
with a successful invite redemption. The client validates its vault binding and
can locally authenticate an active current portable-key slot before it completes
device enrollment. `unlockRedeemedVaultWithPortableKey` returns an owned VRK that
the caller must clear. The portable key and VRK are never sent back to the API.
The catalog `joinInvite` adapter is responsible for preserving that ordering and
for durable, idempotent successor-token handling; `recover` uses that adapter
and never renders its protected session or successor material.

If a catalog command is constructed without its required injected adapter, it
fails with `CLI_UNAVAILABLE` and exit code `5`; it never falls back to fake data.
In the public executable the same unregistered command is invalid usage and
returns exit code `2`.

## Unavailable public command families

The following surfaces are not available from the packed executable and must not
be treated as released behavior, even where a tested injected descriptor or
lower-level use case exists:

- device-token lifecycle and remember/forget beyond the composed invite, join,
  `key slot`, and `key rotate` commands;
- backup restore, history, and attachment commands;
- `set`, `update`, `run`, and the TUI entrypoint.

Lower-level implementations exist for several of these concerns, but no
uncomposed operation is advertised as a working command. The factual feature
ledger is [Implementation Status](./implementation-status.md).

## Exit codes and errors

The CLI runtime defines stable numeric categories in
[`CLI_EXIT_CODES`](../apps/cli/src/errors.ts):

| Exit | Meaning                                                                    |
| ---: | -------------------------------------------------------------------------- |
|  `0` | Success, including help and version display.                               |
|  `1` | An unexpected failure or a domain failure without a more specific mapping. |
|  `2` | Invalid command usage or domain validation failure.                        |
|  `3` | No matching record.                                                        |
|  `4` | Ambiguous name or alias.                                                   |
|  `5` | Required production adapter or network service unavailable.                |

Usage errors produced by Commander are deliberately generic:

```text
Error [CLI_USAGE]: Invalid command usage. Run 'creds --help'.
```

Other errors use one sanitized line on standard error:

```text
Error [CODE]: Safe message.
```

Unexpected exceptions become `UNEXPECTED_FAILURE` without exception text.
Ambiguity errors do not print candidate IDs, and invalid usage does not reflect
hostile arguments. ANSI/OSC/C1 controls, terminal string commands, bidi controls,
and embedded line controls are neutralized by the terminal boundary. Errors are
text even when a command has `--json`.

## Secret input

[`NodeSecretInput`](../apps/cli/src/secret-input.ts) implements the current input
boundary. The public executable uses it for TOTP seeds, protected key-file
passphrases, and an explicitly selected sealed status backend; the injected
catalog also uses it for initialization and invite enrollment.

- Interactive input requires a real TTY, enters raw mode, does not echo the
  value, supports backspace, treats Ctrl+C as cancellation, and restores the
  prior raw-mode state.
- Redirected input is never consumed implicitly. The matching explicit stdin
  switch is required.
- `creds totp --secret-stdin` accepts exactly one bounded UTF-8 Base32 frame.
  `creds key create --protect-with-passphrase --passphrase-stdin` accepts exactly
  two matching bounded UTF-8 frames followed by EOF. Missing, extra, empty,
  malformed, control-bearing, or oversized input fails closed.
- `creds status --secret-backend sealed-file --backend-passphrase-stdin`
  accepts exactly one bounded UTF-8 passphrase followed by EOF. Without the
  stdin flag, sealed mode requires a masked TTY prompt; native mode never accepts
  this flag.
- `creds recover` accepts the invite and portable key through two masked prompts,
  two exact stdin frames, or a guarded portable-key file plus an invite prompt;
  protected files acquire their passphrase only after filesystem preflight.
- Injectable initialization has separately staged `--key-stdin` and
  `--confirmation-stdin` protocols; invite enrollment uses `--invite-stdin`.
  Those flags do not make the corresponding commands public.
- No secret-valued positional or normal option is defined. In particular, there
  is no `--invite <value>`, `--passphrase <value>`, `--portable-key <value>`, or
  TOTP seed option that carries the secret itself.

Do not put a portable key, recovery key, passphrase, invite, token, or credential
value in argv, a URL, an environment variable, a shell history entry, or a
command-substitution expression. Explicit stdin is an automation boundary, not
permission to source plaintext from an unprotected file or another logged
command.

## Text and structured output

Non-interactive output is normalized to LF and contains no intentional ANSI.
Every string crossing the renderer is sanitized for terminal control sequences.

The catalog `--json` outputs are canonical redacted projections, formatted with
two-space indentation and one trailing newline. They are not plaintext export:

- status contains only vault/device IDs and sync state metadata;
- show masks sensitive fields, secret scalar variants, secret environment
  entries, and every note body;
- invite list contains only the public invite schema;
- invite join returns only vault and device IDs.

There is no current flag that emits secret JSON or bypasses redaction. JSON
schemas are command-specific, and stderr remains the sanitized text error
channel.

Password/passphrase generation and TOTP are deliberate non-JSON secret-output
commands. They emit exactly one generated value or code plus a newline, only to
an interactive stdout or when `--stdout` explicitly authorizes redirection.
`key create` emits only its generic success line and never the portable key or
passphrase.

## Shell quoting

Group and credential names are not secrets, but quote them so whitespace,
wildcards, variables, and punctuation reach Commander as one argument. Never use
these patterns to pass an actual secret.

| Shell      | Literal-name example                       |
| ---------- | ------------------------------------------ |
| Bash       | `creds show 'Email Accounts' 'Gmail Work'` |
| Zsh        | `creds show 'Email Accounts' 'Gmail Work'` |
| Fish       | `creds show 'Email Accounts' 'Gmail Work'` |
| PowerShell | `creds show 'Email Accounts' 'Gmail Work'` |

Those `show` examples describe the catalog syntax; they currently fail as invalid
usage in the packed executable. For Bash and Zsh, an embedded apostrophe can be
represented by closing the literal, adding an escaped apostrophe, and reopening
it: `'Operations'\'' Mail'`. In PowerShell, double an apostrophe inside a
single-quoted string: `'Operations'' Mail'`. Fish users should use a quoted form
appropriate to the exact name or select by opaque ID when punctuation would be
unclear.

Use `--` before positional queries that begin with a hyphen, once the operational
catalog is composed. Do not rely on shell aliases, glob expansion, locale-specific
case conversion, or unquoted command substitution for record selection.

## Current verification limits

Parser, renderer, terminal sanitizer, masked/stdin input, local generators, RFC
TOTP behavior, key-file creation/ACLs, static completion, package contents, lazy
chunk loading, and packed-bin behavior have automated tests. The Scenario A
acceptance test exercises initialization, unlock, encrypted mutations, sync,
redacted reads, guarded copy, lock, and reopen through source-level production
composition with real SQLite/client adapters and an opaque HTTPS fixture. A
Windows packed fixture installs the npm archive, invokes the generated shim, and
reads real canonical SQLite/sealed status state; it does not prove native-keychain
behavior or the full online journey through the installed child. Interruption,
fresh-home recovery/device-B, backup/restore, and whole-system canary coverage
remain later acceptance gates. Cross-platform shell completion packaging is
prepared, but a published package and final target-platform release evidence do
not exist.
