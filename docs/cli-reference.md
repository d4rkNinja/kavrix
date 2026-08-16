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

| Command                                                                                                                               | Status                         | Behavior                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `creds`                                                                                                                               | Available in the built package | Prints help.                                                                                                                                                                                                                                                                                                                                                                                                   |
| `creds --help`                                                                                                                        | Available in the built package | Prints static help.                                                                                                                                                                                                                                                                                                                                                                                            |
| `creds --version`                                                                                                                     | Available in the built package | Prints package version `0.1.0`.                                                                                                                                                                                                                                                                                                                                                                                |
| `creds version`                                                                                                                       | Available in the built package | Prints package version `0.1.0`.                                                                                                                                                                                                                                                                                                                                                                                |
| `creds completion <shell>`                                                                                                            | Available in the built package | Prints static top-level completion for `bash`, `zsh`, `fish`, or `powershell`.                                                                                                                                                                                                                                                                                                                                 |
| `creds generate password [options]`                                                                                                   | Available in the built package | Generates one policy-validated password with production randomness.                                                                                                                                                                                                                                                                                                                                            |
| `creds generate passphrase [options]`                                                                                                 | Available in the built package | Generates one passphrase from the attributed EFF short word list.                                                                                                                                                                                                                                                                                                                                              |
| `creds totp [options]`                                                                                                                | Available in the built package | Reads a masked or explicit-stdin Base32 seed and emits one canonical TOTP code.                                                                                                                                                                                                                                                                                                                                |
| `creds totp code <group> <credential> [field] [options]`                                                                              | Available in the built package | Generates one code from a seed already stored in the local encrypted vault, without ever printing the seed. The seed is decrypted locally and its decoded bytes are wiped on every exit path; nothing is sent to the API. Redirection is denied unless `--stdout` is passed, the receipt goes to stderr so command substitution captures only the code, and a field whose reveal policy is `never` is refused. |
| `creds key create --file <path> [options]`                                                                                            | Available in the built package | Creates one unbound v1 portable-key file, refuses overwrite, and never displays the portable key.                                                                                                                                                                                                                                                                                                              |
| `creds key slot list [--json]`                                                                                                        | Available in the built package | Lists only redacted slot ID/type/state/version/timestamps and public device IDs; derivation metadata and wrapped keys are excluded.                                                                                                                                                                                                                                                                            |
| `creds key slot create <slot-type> [options]`                                                                                         | Available in the built package | Adds a portable-key, passphrase, recovery-key, or device-key slot after explicit local reauthentication, remote readback, and encrypted audit publication.                                                                                                                                                                                                                                                     |
| `creds key slot disable <slot-id> [options]`                                                                                          | Available in the built package | Removes only this device's protected device-slot secret; the remote vault record is unchanged and the remembered current slot requires a verified replacement.                                                                                                                                                                                                                                                 |
| `creds key slot revoke <slot-id> [options]`                                                                                           | Available in the built package | Revokes one remote slot through the revision-bound control plane, with last-current-slot protection and encrypted audit publication.                                                                                                                                                                                                                                                                           |
| `creds key rotate [options]`                                                                                                          | Available in the built package | Generates or imports a portable replacement file, durably publishes pending then active slot envelopes, confirms the replacement locally, and revokes the old slot only after confirmation.                                                                                                                                                                                                                    |
| `creds key rotate resume <operation-id> [options]`                                                                                    | Available in the built package | Replays the exact authenticated local checkpoint against the fetched vault and resumes only an identical pending rotation.                                                                                                                                                                                                                                                                                     |
| `creds key rotate list [--json]`                                                                                                      | Available in the built package | Lists only operation IDs, public lifecycle states, slot IDs, and timestamps; replacement keys and wrapped-root data are excluded.                                                                                                                                                                                                                                                                              |
| `creds init [options]`                                                                                                                | Available in the built package | Creates one vault/profile/device/session with durable recovery material and a global writer lease; `--key-file` accepts a guarded unprotected or passphrase-protected unbound v1 file.                                                                                                                                                                                                                         |
| `creds init resume <operation-id>`                                                                                                    | Available in the built package | Resumes one durable initialization journal operation.                                                                                                                                                                                                                                                                                                                                                          |
| `creds init cancel <operation-id>`                                                                                                    | Available in the built package | Cancels one safely cancellable prepared initialization operation.                                                                                                                                                                                                                                                                                                                                              |
| `creds connect --server <url> --vault <vault-id> --device <device-id>`                                                                | Available in the built package | Attaches an empty local data home to an existing enrolled device using its protected session and device slot; it never accepts or transmits a portable key.                                                                                                                                                                                                                                                    |
| `creds recover --server <url> --vault <vault-id> [options]`                                                                           | Available in the built package | Recovers an empty data home with an invite and local portable key, creates a fresh device slot only after local authentication, persists the profile, and performs the first opaque sync.                                                                                                                                                                                                                      |
| `creds recover resume <operation-id> --server <url> --vault <vault-id> [options]`                                                     | Available in the built package | Resumes a durable recovery journal and completes only the missing local slot/profile/sync work.                                                                                                                                                                                                                                                                                                                |
| `creds recover cancel <operation-id> --server <url> --vault <vault-id>`                                                               | Available in the built package | Cancels a prepared recovery journal locally before network use.                                                                                                                                                                                                                                                                                                                                                |
| `creds device join --server <url> --vault <vault-id> [options]`                                                                       | Available in the built package | Joins a vault with an invite and portable key through the durable successor-token, device-slot, profile, and first-sync coordinator.                                                                                                                                                                                                                                                                           |
| `creds device join resume <operation-id> [options]`                                                                                   | Available in the built package | Resumes the exact pending device-join operation without generating replacement identities.                                                                                                                                                                                                                                                                                                                     |
| `creds device join cancel <operation-id> [options]`                                                                                   | Available in the built package | Cancels only a prepared local device-join journal before network use.                                                                                                                                                                                                                                                                                                                                          |
| `creds device list --vault <vault-id> [options]`                                                                                      | Available in the built package | Lists canonical public device metadata with bounded opaque pagination; bearer tokens and token hashes are never returned.                                                                                                                                                                                                                                                                                      |
| `creds device revoke <device-id> --vault <vault-id> --confirm`                                                                        | Available in the built package | Revokes the current or another device after explicit confirmation; the server invalidates its sessions and denies revoking the last active device.                                                                                                                                                                                                                                                             |
| `creds device remember [options]`                                                                                                     | Available in the built package | Generates a device-key unlock slot locally and stores its secret only in the native keychain; the API session credential is separate and unchanged.                                                                                                                                                                                                                                                            |
| `creds device forget <slot-id> [options]`                                                                                             | Available in the built package | Removes only the exact local device-key entry after reauthentication; the remote slot and API session credential remain unchanged.                                                                                                                                                                                                                                                                             |
| `creds device invite create --vault <vault-id> [options]`                                                                             | Available in the built package | Issues one bounded, short-lived invite; the token is displayed once only on an interactive or explicitly acknowledged stdout.                                                                                                                                                                                                                                                                                  |
| `creds device invite list --vault <vault-id> [options]`                                                                               | Available in the built package | Lists only canonical public invite metadata and never returns invite tokens or hashes.                                                                                                                                                                                                                                                                                                                         |
| `creds device invite revoke <invite-id> --vault <vault-id>`                                                                           | Available in the built package | Revokes one unused invite by opaque ID through the authenticated control plane.                                                                                                                                                                                                                                                                                                                                |
| `creds unlock --check [options]`                                                                                                      | Available in the built package | Verifies unlock material and immediately relocks; no daemon persists.                                                                                                                                                                                                                                                                                                                                          |
| `creds lock [options]`                                                                                                                | Available in the built package | Locks the active vault and clears use-case-managed secret state.                                                                                                                                                                                                                                                                                                                                               |
| `creds status [options]`                                                                                                              | Available in the built package | Reports redacted locked/offline state for exactly one enrolled local profile without networking.                                                                                                                                                                                                                                                                                                               |
| `creds template list [--json]`                                                                                                        | Available in the built package | Lists available built-in templates and group templates in the vault.                                                                                                                                                                                                                                                                                                                                           |
| `creds template inspect <query> [--json]`                                                                                             | Available in the built package | Inspects a template schema definition (fields, stable keys, types, required/sensitive flags).                                                                                                                                                                                                                                                                                                                  |
| `creds template create <name> [options]`                                                                                              | Available in the built package | Creates a reusable template / group container, optionally based on a built-in template (`--from`).                                                                                                                                                                                                                                                                                                             |
| `creds template edit <group-query> [options]`                                                                                         | Available in the built package | Updates template name or description metadata.                                                                                                                                                                                                                                                                                                                                                                 |
| `creds template archive <group-query>`                                                                                                | Available in the built package | Archives a group template container as a tombstone.                                                                                                                                                                                                                                                                                                                                                            |
| `creds template restore <group-id>`                                                                                                   | Available in the built package | Restores an archived group template container.                                                                                                                                                                                                                                                                                                                                                                 |
| `creds template delete <group-query> --force`                                                                                         | Available in the built package | Permanently deletes a group template container with explicit `--force` authorization.                                                                                                                                                                                                                                                                                                                          |
| `creds template migrate plan <group> [options]`                                                                                       | Available in the built package | Previews a lossless schema migration plan, showing step kinds and affected item counts before applying.                                                                                                                                                                                                                                                                                                        |
| `creds template migrate apply <group> [options]`                                                                                      | Available in the built package | Applies an atomic template schema migration across group items, preserving unmapped fields as orphaned values; requires `--confirm-risky` if destructive steps exist.                                                                                                                                                                                                                                          |
| `creds template migrate status <group> [--json]`                                                                                      | Available in the built package | Displays current template schema version and active item count for a group container.                                                                                                                                                                                                                                                                                                                          |
| `creds group create <name> [options]`                                                                                                 | Available in the built package | Creates an encrypted local group container, optionally initialized with a built-in template (`--template`).                                                                                                                                                                                                                                                                                                    |
| `creds group list [--json]`                                                                                                           | Available in the built package | Lists active groups with redacted names.                                                                                                                                                                                                                                                                                                                                                                       |
| `creds group rename <query> <new-name>`                                                                                               | Available in the built package | Renames an active group by ID, name, or alias.                                                                                                                                                                                                                                                                                                                                                                 |
| `creds group archive <query>`                                                                                                         | Available in the built package | Archives an active group as a tombstone.                                                                                                                                                                                                                                                                                                                                                                       |
| `creds group restore <group-id>`                                                                                                      | Available in the built package | Restores an archived group by exact ID.                                                                                                                                                                                                                                                                                                                                                                        |
| `creds group delete <query> --force`                                                                                                  | Available in the built package | Permanently deletes a group with an explicit `--force` authorization.                                                                                                                                                                                                                                                                                                                                          |
| `creds credential create <group> <title>`                                                                                             | Available in the built package | Creates an encrypted credential item inside a group.                                                                                                                                                                                                                                                                                                                                                           |
| `creds credential list <group> [--json]`                                                                                              | Available in the built package | Lists active credentials in a group with redacted titles.                                                                                                                                                                                                                                                                                                                                                      |
| `creds credential rename <group> <credential> <new-title>`                                                                            | Available in the built package | Renames an active credential.                                                                                                                                                                                                                                                                                                                                                                                  |
| `creds credential archive <group> <credential>`                                                                                       | Available in the built package | Archives an active credential as a tombstone.                                                                                                                                                                                                                                                                                                                                                                  |
| `creds credential restore <group> <credential-id>`                                                                                    | Available in the built package | Restores an archived credential by exact ID.                                                                                                                                                                                                                                                                                                                                                                   |
| `creds credential delete <group> <credential> --force`                                                                                | Available in the built package | Permanently deletes a credential with an explicit `--force` authorization.                                                                                                                                                                                                                                                                                                                                     |
| `creds field add <group> <credential> <field-key> [opts]`                                                                             | Available in the built package | Adds a new dynamic field definition to a credential. An initial value arrives only through `--value-stdin`, never through an argument.                                                                                                                                                                                                                                                                         |
| `creds field set <group> <credential> <field> [opts]`                                                                                 | Available in the built package | Writes one field value read from `--value-stdin` or a masked prompt. Resolves the field by ID, key, label, or unique prefix; requires `--create` to define a missing field; accepts `--if-revision <n>`; refuses to overwrite a repeatable field.                                                                                                                                                              |
| `creds field generate <group> <credential> <field> [opts]`                                                                            | Available in the built package | Generates one password or passphrase with the production RNG and stores it in a credential field through a single atomic update. Defaults to a 24-character password; `--passphrase` selects the reviewed word list. Requires `--create` for a missing field, accepts `--if-revision <n>`, and emits the value only for an explicit `--reveal` or `--copy`, which re-read it under the guarded policies.       |
| `creds field update <group> <credential> <field>`                                                                                     | Available in the built package | Updates item-specific field definition metadata (label, type, sensitive). Accepts `--if-revision <n>` and refuses to redefine a shared group-template field.                                                                                                                                                                                                                                                   |
| `creds field archive <group> <credential> <field-key>`                                                                                | Available in the built package | Archives a field value into archivedFieldValues.                                                                                                                                                                                                                                                                                                                                                               |
| `creds field restore <group> <credential> <field-key>`                                                                                | Available in the built package | Restores an archived field value back to active field values.                                                                                                                                                                                                                                                                                                                                                  |
| `creds field remove <group> <credential> <key> --force`                                                                               | Available in the built package | Permanently removes an item-specific field definition and value.                                                                                                                                                                                                                                                                                                                                               |
| `creds note add <group> [cred] [title] [opts]`                                                                                        | Available in the built package | Adds an encrypted note to a group or credential using positional text or `--content-stdin`.                                                                                                                                                                                                                                                                                                                    |
| `creds note update <group> [cred] <note> [opts]`                                                                                      | Available in the built package | Updates note title, content, sensitivity, or pin state.                                                                                                                                                                                                                                                                                                                                                        |
| `creds note archive <group> [cred] <note>`                                                                                            | Available in the built package | Sets archivedAt timestamp on a group or credential note.                                                                                                                                                                                                                                                                                                                                                       |
| `creds note restore <group> [cred] <note>`                                                                                            | Available in the built package | Restores an archived note back to active notes.                                                                                                                                                                                                                                                                                                                                                                |
| `creds note remove <group> [cred] <note> --force`                                                                                     | Available in the built package | Permanently removes a note with an explicit `--force` authorization.                                                                                                                                                                                                                                                                                                                                           |
| `creds attachment list <group> <credential> [--json]`                                                                                 | Available in the built package | Lists encrypted attachments bound to a credential item.                                                                                                                                                                                                                                                                                                                                                        |
| `creds attachment upload <group> <credential> <file-path> [--json]`                                                                   | Available in the built package | Encrypts and uploads a local file as an attachment stream bound to a credential item.                                                                                                                                                                                                                                                                                                                          |
| `creds attachment download <group> <credential> <attachment-id> <dest> [--force]`                                                     | Available in the built package | Downloads and decrypts an attachment stream to a local path, requiring `--force` to overwrite existing files.                                                                                                                                                                                                                                                                                                  |
| `creds attachment delete <group> <credential> <attachment-id> --force`                                                                | Available in the built package | Permanently removes an attachment record and binding with explicit `--force` confirmation.                                                                                                                                                                                                                                                                                                                     |
| `creds history list <group> <credential> [--json]`                                                                                    | Available in the built package | Lists encrypted history revisions for a credential item.                                                                                                                                                                                                                                                                                                                                                       |
| `creds history show <group> <credential> <revision> [--json]`                                                                         | Available in the built package | Inspects an authorized historical revision projection with masked secret values.                                                                                                                                                                                                                                                                                                                               |
| `creds history diff <group> <credential> <revision> [compare-rev] [--json]`                                                           | Available in the built package | Compares field differences between historical revisions locally.                                                                                                                                                                                                                                                                                                                                               |
| `creds history restore <group> <credential> <revision> --force [--json]`                                                              | Available in the built package | Restores an exact historical revision as a new mutation with explicit `--force`.                                                                                                                                                                                                                                                                                                                               |
| `creds recovery list <group> <credential> <field> [--json]`                                                                           | Available in the built package | Lists recovery-code entries by stable identifier with lifecycle state and an available/used inventory. Code values are never printed in either output mode.                                                                                                                                                                                                                                                    |
| `creds recovery use <group> <credential> <field> --code <id> [--if-revision <n>] [--json]`                                            | Available in the built package | Marks exactly one recovery code used, selected by stable identifier or an unambiguous prefix and never by position. Refuses an already-used code, accepts `--if-revision <n>`, and prints only a masked receipt.                                                                                                                                                                                               |
| `creds recovery reveal <group> <credential> <field> --code <id> [--use] [--if-revision <n>] [--stdout]`                               | Available in the built package | Releases one unused code value, denying non-interactive redirection unless `--stdout` is passed. `--use` marks the code used before printing it and writes the receipt to stderr so command substitution captures only the code. A field whose reveal policy is `never` is refused.                                                                                                                            |
| `creds recovery copy <group> <credential> <field> --code <id>`                                                                        | Available in the built package | Copies one unused recovery code to the guarded clipboard by stable identifier with auto-clear. It never marks the code used, because a clipboard write can fail after the value leaves the vault.                                                                                                                                                                                                              |
| `creds audit list [--class <c>] [--limit <1..200>] [--cursor <id>] [--json]`                                                          | Available in the built package | Lists locally derived audit events newest first with bounded keyset pagination. Events are projected from unlock-slot lifecycle timestamps and queued mutations; the `backup` class has no local source yet and returns nothing.                                                                                                                                                                               |
| `creds audit show <event-id> [--json]`                                                                                                | Available in the built package | Inspects one locally derived audit event by the opaque identifier reported by `creds audit list`.                                                                                                                                                                                                                                                                                                              |
| `creds show <group> <credential> [--json]`                                                                                            | Available in the built package | Inspects a credential with secret fields and sensitive note content redacted.                                                                                                                                                                                                                                                                                                                                  |
| `creds copy <group> <credential> <field> [--index <n>]`                                                                               | Available in the built package | Copies an authorized field value to the guarded clipboard with auto-clear.                                                                                                                                                                                                                                                                                                                                     |
| `creds reveal <group> <credential> <field> [--stdout]`                                                                                | Available in the built package | Reveals an authorized field value, denying non-interactive redirection unless `--stdout` is passed.                                                                                                                                                                                                                                                                                                            |
| `creds search <term> [--group <q>] [--limit <1..200>] [--include-archived] [--include-secret-values] [--json]`                        | Available in the built package | Searches the unlocked vault on this device for a case-insensitive term across names, slugs, aliases, tags, subtitle, environment, owner, purpose, note titles, non-sensitive note content, and searchable fields. Nothing is indexed or sent anywhere, results are bounded, and a hit reports the matched property, never the matched text.                                                                    |
| `creds get <group> <credential> <field> [--reveal]`                                                                                   | Available in the built package | Gets one field value with redacted default, optional `--reveal` and structured `--json` mode. JSON reports `redacted` and the `revision` the value was read at, so a script can pair the read with `--if-revision`.                                                                                                                                                                                            |
| `creds set <group> <credential> <field> [opts]`                                                                                       | Available in the built package | Scriptable alias of `creds field set`, sharing its handler, value handling, and receipt.                                                                                                                                                                                                                                                                                                                       |
| `creds update <group> <credential> <field> [opts]`                                                                                    | Available in the built package | Scriptable alias of `creds field update`, sharing its handler and receipt.                                                                                                                                                                                                                                                                                                                                     |
| `creds run [options] <executable> [args...]`                                                                                          | Available in the built package | Releases authorized field values into one directly spawned child's environment, never into its argv, then reports its bounded, secret-redacted output.                                                                                                                                                                                                                                                         |
| `creds sync [--json]`                                                                                                                 | Available in the built package | Synchronizes vault data with server and prints updated status.                                                                                                                                                                                                                                                                                                                                                 |
| `creds backup create --file <path> [--vault <vault-id>] [--json]`                                                                     | Available in the built package | Creates one bounded authenticated archive from the enrolled local opaque cache; destination validation occurs before unlock, existing files/links are refused, and the receipt contains only vault ID, record count, and byte count. Unsupported local record families fail closed.                                                                                                                            |
| `creds backup verify --file <path> [--vault <vault-id>] [--json]`                                                                     | Available in the built package | Opens an existing protected archive read-only, authenticates its complete bounded framing and graph with the active remembered device slot, and emits only a safe verification summary. It never stages or publishes.                                                                                                                                                                                          |
| `creds transfer export --file <path> [--group <group>] [--vault <vault-id>] [--transfer-passphrase-stdin] [--json]`                   | Available in the built package | Writes one policy-filtered encrypted transfer under its own confirmed passphrase. Destination validation precedes unlock, existing files and links are refused, and the receipt reports only vault ID, group count, credential count, withheld-value count, and byte count.                                                                                                                                    |
| `creds transfer import --file <path> [--on-collision fail\|skip\|rename] [--vault <vault-id>] [--transfer-passphrase-stdin] [--json]` | Available in the built package | Authenticates one complete encrypted transfer and plans the whole application before the first mutation. Malformed, oversized, tampered, or unapplicable input leaves the destination vault untouched.                                                                                                                                                                                                         |

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
and `--stdout`. `creds totp code` accepts the same policy options against a stored
seed and validates them before the vault is opened, so an out-of-range request
never decrypts anything. Secret output requires an interactive stdout unless
`--stdout` is explicit.

`creds field generate` accepts the same password and passphrase policy options
against a credential field and validates them before the vault is opened, so an
out-of-range request never unlocks anything. Mixing the two policies is refused
rather than silently resolved: `--passphrase` rejects `--length`, the class
minima, and `--exclude`, and a password request rejects `--words`,
`--separator`, `--capitalize`, `--digit`, and `--exclude-word`. The generated
value is not printed by the write itself. `--copy` places it on the guarded
clipboard and `--reveal` prints it, each by re-reading the stored field through
the same reveal and copy policies `creds reveal` and `creds copy` enforce. With
`--reveal` the value is alone on stdout and the receipts move to stderr, so a
redirect captures only the secret.

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

`transfer` moves groups between vaults. A transfer is not a backup: it is
protected by its own passphrase, never by the vault's unlock material, so a
transfer file that leaks cannot be opened with vault credentials and vault
credentials are never written into a portable file. `transfer export` confirms
that passphrase twice, because a mistyped one would produce a file nobody can
ever open; `--transfer-passphrase-stdin` reads it from bounded stdin frames
instead of masked prompts. The passphrase is never accepted in argv.

Export applies field export policy before anything is written. A value whose
field declares `exportPolicy: never` is omitted entirely — not masked, not
re-encrypted — and every omission is declared in a per-item withholding manifest
carrying only a stable key, a scope, and a reason. Attachment content and
attachment identifiers are never carried, and item-to-item references are
withheld because the destination mints new identities. Export fails closed rather
than emitting a document that could never be imported: a _required_ field whose
value must be withheld aborts the export instead of producing a broken file.

`transfer import` authenticates the whole file, then plans the whole application
— group-name collisions and per-item template validity included — before the
first group is created. `--on-collision` selects how an existing group name is
treated: `fail` (the default) refuses the transfer, `skip` drops the colliding
group and its credentials, and `rename` creates it under the first free suffixed
name. Two identically named groups inside one transfer cannot collapse into one.
The receipt reports counts only; it never prints the transfer path, a group name,
a credential title, or any field value.

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

`run` releases authorized field values into one child process and never into a
command line. Each `--env NAME=group/credential/field` mapping names one
destination variable and one field address; append `#index` to select an entry of
a repeatable field. The flag is repeatable, every destination name must be unique
after upper-casing, and names the runner reserves for itself (including `PATH`,
`LD_PRELOAD`, and `NODE_OPTIONS`) are refused. Values are resolved through the
same authorization gate as `copy`, so a field whose policy requires confirmation
or reauthentication fails closed rather than being released silently.

The child is started with `spawn` and an argument array, never through a shell.
Its environment contains only the mapped destinations plus the parent variables
explicitly named by `--inherit`, which accepts a comma-separated subset of
`PATH`, `PATHEXT`, `SystemRoot`, `WINDIR`, `COMSPEC`, `TEMP`, `TMP`, `HOME`,
`USERPROFILE`, `LANG`, `LC_ALL`, `LC_CTYPE`, and `TZ`. `--cwd` selects the
working directory and defaults to the current one; it is resolved to an absolute
path before the child starts. `--timeout <milliseconds>` bounds wall-clock time
up to 24 hours, and `--max-output <bytes>` bounds each captured stream, defaulting
to 65536 bytes and accepting at most 16 MiB. Captured output is redacted before it
is rendered: every released value is replaced byte-for-byte with `*`, including a
value cut in half by the capture limit. The command refuses to start at all if a
released value appears in the executable path or any argument.

Every argument after `<executable>` is relayed to the program verbatim, so this
command's own options must be written before it: `creds run --env
API_TOKEN=Infra/Vendor/token deploy release --wait` sends `release --wait` to
`deploy`, while `creds run deploy --env ...` sends `--env ...` to `deploy`. A
single leading `--` is accepted and consumed, so `creds run node -- --version`
and `creds run node --version` are equivalent; any later `--` belongs to the
program. `--dry-run` validates the whole invocation, prints the planned
executable, argument count, destination names, inherited names, working
directory, timeout, and capture limit, and returns without unlocking the vault or
reading a field. It therefore confirms the shape of the invocation, not that
every address resolves or that every field is releasable.

The rendered result reports the executable, the child's exit code, its signal,
the termination reason (`exit`, `signal`, `timeout`, `aborted`, or
`output-limit`), which destinations carried a secret, whether output was
truncated, and the two redacted streams. A child that does not finish normally
exits the CLI with `RUN_CHILD_FAILED` and code `1` after that report, so a failed
child is never presented as a successful command. Two limits belong to the
operating system rather than to this command and are documented rather than
claimed away: Windows copies a fixed set of shell variables (including `PATH`,
`SYSTEMROOT`, `TEMP`, and the `USER*` family) into every child regardless of the
environment supplied here, so a child there observes more names than were mapped
or inherited, none of which carry a released value; and termination reaches only
the spawned process, so a child that has already forked keeps its descendants
running past a timeout, an abort, or an output-limit kill. This command is process
hygiene, not a sandbox — the program selected can read its own environment and
disclose it deliberately.

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
- backup restore;
- the TUI entrypoint.

Lower-level implementations exist for several of these concerns, but no
uncomposed operation is advertised as a working command. The factual feature
ledger is [Implementation Status](./implementation-status.md).

## Session lifetime

Every unlocked invocation runs inside one bounded session
([`InvocationSession`](../apps/cli/src/session.ts)). The session owns the
deadlines, the abort signal that cancellable work is threaded onto, and the
ordered release stack. Release steps run exactly once in reverse acquisition
order for every ending — normal completion, thrown error, deadline, inactivity,
or signal — so a decrypted root key never outlives the command that unwrapped
it.

- Expiry is measured on a monotonic clock, never wall-clock time, so changing the
  system clock cannot extend a session. A backward reading fails closed.
- An unlocked command is cancelled on `SIGINT`, `SIGTERM`, and `SIGHUP`; the
  environment, SQLite stores, protected backend, and clipboard are released
  before the process leaves.
- Work that has stopped making progress is abandoned rather than waited on, so a
  command blocked on a socket, pipe, or prompt cannot hold a session open past
  its deadline.
- A result produced after a deadline lapsed is never reported as success.
- Nothing about an unlocked session is written down: there is no daemon or agent,
  and a later process cannot resume it.

Deadlines default to a 15-minute invocation limit, a 2-minute inactivity limit,
and a 2-minute reauthentication window. Operators may override them; each value
is milliseconds as a plain unsigned decimal, must fall between `1000` and
`86400000`, and neither the inactivity limit nor the reauthentication window may
exceed the invocation limit.

| Variable                        | Bounds the                                     |
| ------------------------------- | ---------------------------------------------- |
| `CREDS_SESSION_TIMEOUT_MS`      | Total lifetime of one unlocked invocation.     |
| `CREDS_SESSION_IDLE_TIMEOUT_MS` | Time allowed between recorded progress.        |
| `CREDS_REAUTH_WINDOW_MS`        | Reuse window after a proven unlock credential. |

These are operator policy, not secrets; no passphrase, key, or token is ever
read from the environment. An unset or blank variable keeps the shipped default.
A malformed, out-of-bounds, or internally inconsistent value fails closed with a
usage error before any vault is opened, and the rejected value is not echoed
back.

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

A session that ends before its command finishes exits `1` and names the reason,
so an interrupted run is distinguishable from a failed one without adding a new
numeric category:

| Code                     | The session was locked because                      |
| ------------------------ | --------------------------------------------------- |
| `SESSION_TIMEOUT`        | The invocation limit was reached.                   |
| `SESSION_IDLE_TIMEOUT`   | The inactivity limit was reached.                   |
| `SESSION_INTERRUPTED`    | The invocation was cancelled (`SIGINT`).            |
| `SESSION_TERMINATED`     | The invocation was terminated (`SIGTERM`/`SIGHUP`). |
| `SESSION_CLOCK_UNUSABLE` | The monotonic clock moved backward.                 |

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
  TOTP seed option that carries the secret itself. `creds totp code` reads its
  seed from the unlocked vault, so it takes no seed input at all.

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
- invite join returns only vault and device IDs;
- recovery list contains element identifiers, lifecycle state, and inventory
  counts, and never a code value;
- search contains the matched property of each hit with a label locator, such as
  a field label, note title, or tag, and never a matched value or an excerpt.

One flag deliberately opts out: `creds get --reveal --json` reports the field
value with `"redacted": false`, because the same invocation already prints that
value in text mode. Every other `--json` projection is redacted, JSON schemas are
command-specific, and stderr remains the sanitized text error channel.

Password/passphrase generation and TOTP are deliberate non-JSON secret-output
commands. They emit exactly one generated value or code plus a newline, only to
an interactive stdout or when `--stdout` explicitly authorizes redirection.
`creds totp code` follows the same rule and additionally writes its field/policy
receipt to stderr, so a command substitution captures the code alone.
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
redacted reads, guarded copy, guarded run, lock, and reopen through source-level
production composition with real SQLite/client adapters and an opaque HTTPS
fixture. Its guarded-run step spawns this Node runtime as a real child and proves
from the child's own report that the released bytes arrived intact, that the
child's argv did not carry them, that an unmapped parent variable did not reach
it, and that the value it echoed came back fully redacted. A
Windows packed fixture installs the npm archive, invokes the generated shim, and
reads real canonical SQLite/sealed status state; it does not prove native-keychain
behavior or the full online journey through the installed child. Interruption,
fresh-home recovery/device-B, backup/restore, and whole-system canary coverage
remain later acceptance gates. Cross-platform shell completion packaging is
prepared, but a published package and final target-platform release evidence do
not exist.

`creds audit` reports a local projection, not a server-authenticated audit log.
The API and MongoDB hold audit sidecars as opaque ciphertext and expose no audit
read route, so the authorized device derives the feed from state it already
holds: unlock-slot lifecycle timestamps and queued opaque mutations. Two limits
follow and are covered by tests rather than hidden. The `backup` class has no
locally persisted source, so it is accepted as a filter and yields no events.
The creation event of a slot that was later superseded or revoked carries no
`state`, because the state at creation time is not retained locally and is never
inferred from the slot's current state.

`creds recovery` operates on recovery-code lists that already exist in the
encrypted record. The CLI has no command that mints one: multi-element field
values reach a vault through `creds transfer import`, sync, or a restore path the
packed executable does not yet expose, and `creds field add` only defines
single-value fields. The lifecycle commands are covered by unit tests over the
selection policy and by a production-composition test that seeds a list the way
those paths do, then proves the durable `available` to `used` transition, its
revision receipt, refusal of a second use, and the absence of code material in
both the stored record and the pending opaque mutation.

There is also no per-element archive. The canonical element lifecycle is closed
at `available` and `used`, so archiving one code is not representable without
changing the stored data model for every existing vault. Retiring a whole
recovery-code list uses the field-level `creds field archive` and
`creds field restore` commands, which move the entire value into and out of
`archivedFieldValues`.
