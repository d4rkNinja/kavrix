# Kavrix command guide

This guide follows the current public executable. `kavrix --help` and
`kavrix <command> --help` are authoritative for the installed version.
Database-container commands use `kavrix db ...`; stable version 2 compatibility
commands remain at the root.

## 1. Register a datastore profile

Profiles contain routing data, never connection credentials or unlock secrets.

```sh
kavrix db profile add work --datastore file \
  --data-file ./work.kavrix --key-file ./work.kavrix.key
kavrix db profile use work
kavrix db profile status
kavrix db profile list
```

File profiles store the profile ID, datastore type, data-file path, key-file
path, and the opaque database ID after initialization. MongoDB profiles store
the profile ID, datastore type, database name, database/vault collection names,
key path, and opaque database ID. They never store the MongoDB URI, username,
password, passphrase, database label, vault label, DRK, or VRK.

Use `--config-dir <path>` with `db profile` commands and
`--profile-config-dir <path>` with database/credential commands when the
registry is not in its platform default location.

### MongoDB profile

```sh
kavrix db profile add team-db --datastore mongodb \
  --database kavrix \
  --database-collection kavrix_databases \
  --vault-collection kavrix_vaults \
  --key-file ./team-db.kavrix.key
kavrix db ping --profile team-db
```

The URI is requested through a masked prompt. Controlled automation may use the
command's `--database-url-stdin` or `--secrets-stdin` option and an isolated pipe.
Never place a credential-bearing URI in argv, an environment variable, a profile,
or source control. Remote URIs require validated TLS. Database-container writes
require a replica set or sharded MongoDB topology with transaction support.

## 2. Initialize a database

```sh
kavrix db init --profile work
kavrix db status --profile work --json
kavrix db key status --profile work --json
```

Initialization asks for the private database label and a new key-file passphrase
with confirmation. It creates a random database ID, a random 256-bit database
root key (DRK), a DRK-wrapping portable slot, a protected database-owner key
file, an encrypted private catalog, and a DRK-authenticated revision anchor. The
profile is bound to the new database ID only after publication succeeds.

For controlled file-mode automation, `db init --secrets-stdin` expects exactly:

```text
<database label>
<new key-file passphrase>
<same passphrase>
```

MongoDB mode prepends one `<MongoDB URI>\n` frame. Passphrases must be at least
16 UTF-8 bytes. Do not construct these frames in a shell command line.

## 3. Create and select vaults

```sh
kavrix db vault create --profile work
kavrix db vault list --profile work --json
kavrix db vault status <vault-id> --profile work
kavrix db vault rename <vault-id> --profile work
```

Each vault gets an independent random vault root key (VRK), wrapped to the DRK
with exact database/vault binding. Database and vault labels are stored only in
the encrypted catalog. Ordinary list/status output returns opaque IDs and
`[REDACTED]`, not labels. `db vault create --secrets-stdin` expects the database
key passphrase followed by the private vault label; MongoDB mode prepends its URI.

The current database container keeps the existing flat credential payload. Pass
the returned opaque vault ID explicitly to every credential command:

```sh
kavrix put production/api-token --profile work --vault <vault-id>
kavrix get production/api-token --profile work --vault <vault-id>
kavrix list --profile work --vault <vault-id>
```

If a database contains more than one vault and `--vault` is omitted, the CLI
fails before requesting the passphrase rather than guessing.

## 4. Store and read credentials

`put` prompts for the key-file passphrase and credential value without echoing.
Replacement requires `--overwrite`. For controlled automation, combine
`--passphrase-stdin` and `--value-stdin`; the exact frames are passphrase then
value.

Default `get` output is masked. Plaintext is written only with `--reveal`:

```sh
kavrix get production/api-token --profile work --vault <vault-id> --reveal
```

Use reveal only in a trusted terminal. Do not redirect it to logs, files, shell
history, or untrusted child processes.

| Need                           | Command                     |
| ------------------------------ | --------------------------- |
| List names                     | `kavrix list`               |
| Dashboard                      | `kavrix view`               |
| One credential card            | `kavrix view <name>`        |
| Search names                   | `kavrix search <pattern>`   |
| Counts and revision statistics | `kavrix stats`              |
| Existence check                | `kavrix has <name>`         |
| Rename                         | `kavrix rename <from> <to>` |
| Remove                         | `kavrix remove <name>`      |

Names are decrypted locally for these operations. Values remain masked unless a
separate reveal option is explicit.

## 5. Database recovery

```sh
kavrix db recovery create --profile work \
  --recovery-file ./work.database.recovery
kavrix db recovery verify --profile work \
  --recovery-file ./work.database.recovery
kavrix db recovery status --profile work
```

A database recovery kit protects recovery material that unwraps the same DRK.
It therefore recovers owner access to every vault in the database. Store its
passphrase separately from the owner-key passphrase and keep the kit on a
separate protected medium.

| Goal                          | Command                              |
| ----------------------------- | ------------------------------------ |
| Create a kit                  | `kavrix db recovery create`          |
| Verify a kit                  | `kavrix db recovery verify`          |
| Inspect slot counts           | `kavrix db recovery status`          |
| Revoke a non-final slot       | `kavrix db recovery revoke <slotId>` |
| Create a fresh owner key file | `kavrix db recovery use`             |

Recovery use validates the kit, database binding, current datastore state, and
trusted database anchor before writing a fresh owner key and anchor. It does not
guess a passphrase, bypass rollback checks, recreate missing ciphertext, or
erase old snapshots. Database recovery kits and legacy vault recovery kits are
different formats and reject cross-use.

## 6. Switch databases safely

```sh
kavrix db profile use personal
kavrix db status
kavrix db profile use work
kavrix db status
```

Selection changes only the non-secret route. Every unlock verifies the profile's
expected database ID against the protected owner key and observed database. A key
from another database fails even if the selected files or collection names look
similar. Explicit routing overrides preserve this binding and cannot rebind a
profile silently.

For local-file sharing, securely transfer exactly the encrypted database file
and its matching owner key file, then send the passphrase separately. Anyone who
can unlock those two files has full access to every vault. Local profiles do not
provide reader/editor roles or per-vault revocation.

## 7. Migrate a version 2 vault

Migration is explicit and copy-first. Register the source legacy file and the
destination database as different profiles:

```sh
kavrix db profile add legacy --datastore file \
  --data-file ./legacy.vault --key-file ./legacy.key
kavrix db profile add destination --datastore file \
  --data-file ./new.database --key-file ./new.database.key

kavrix migrate database \
  --source-profile legacy \
  --destination-profile destination \
  --source-vault default \
  --initialize
```

For an unbound local destination, `--initialize --secrets-stdin` expects exactly
the source passphrase, destination passphrase, destination confirmation, private
database label, and private migrated-vault label. A MongoDB source URI frame,
when applicable, comes first. The reader has a strict maximum of seven frames,
matching the widest migration secret construction.

Kavrix authenticates the version 2 source key, anchor, metadata, and payload;
creates a new VRK-bound destination vault; reopens the destination; and compares
the complete canonical payload before success. Source data/key/anchor files stay
unchanged. A failed or ambiguous publication is never reported as migrated.

## 8. Legacy compatibility commands

The root `init`, `vault`, `key`, `recovery`, and `doctor` groups operate on the
stable version 2 single-vault format. They remain available for compatibility
and migration; they are not aliases for database-owner operations.

```sh
kavrix init --datastore file --data-file ./legacy.vault \
  --key-file ./legacy.key --vault default
kavrix doctor --datastore file --data-file ./legacy.vault \
  --key-file ./legacy.key --vault default
```

Legacy recovery use may rotate a version 2 vault root. Database recovery keeps
the database DRK and independently wrapped VRKs. Read the command path carefully
before operating on recovery material.

## 9. Security and platform behavior

- Secret input is accepted only through masked prompts or explicit bounded stdin
  frames. Secrets are not normal flags, positional arguments, profiles, or
  environment variables.
- On Windows, masked prompting preserves the terminal receiver, restores the
  prior raw-mode state on success/error/cancel, handles carriage return and
  backspace, and reports preparation/cleanup failures without echoing input.
- Protected files require owner-only POSIX modes or verified Windows user-only
  ACLs. Symlinks, hard links, replacement races, oversized files, trailing data,
  and unsafe parent directories fail closed.
- Terminal-rendered labels and names are treated as hostile and control sequences
  are sanitized. Non-interactive output is ANSI-free.
- Kavrix uses versioned XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, and SHA-256;
  it does not claim encryption is permanently unbreakable.

## 10. Current limits

The database container currently supports encrypted database/vault labels and
the flat credential record payload. Environments, groups/services, structured
items, and typed fields are deferred.

User identity files, public enrollment, recipient discovery, vault grants,
reader/editor/owner roles, signed writer revisions, revocation by VRK rotation,
and ownership transfer are not implemented. Do not use design examples for those
future commands as if they were installed. MongoDB currently uses owner access;
local mode is intentionally full-database sharing.

MongoDB can observe opaque routing metadata, sizes, timing, and access patterns,
and can delete or withhold ciphertext. Kavrix cannot protect an unlocked host
from administrators, same-user malware, keyloggers, terminal/clipboard capture,
process-memory inspection, swap, or crash dumps. Losing all matching owner keys
and database recovery kits is unrecoverable.

## Advanced destructive operation

The whole-vault destruction command is intentionally absent from normal help,
command listings, completion suggestions, the README, and routine workflow
sections. It applies only to legacy version 2 single-vault storage and is not a
database-container vault deletion command. Use it only after independently
verifying the exact datastore, vault, key file, recovery copies, and backup
retention:

```sh
kavrix destroy \
  --datastore file \
  --data-file ./legacy.vault \
  --key-file ./legacy.key \
  --artifact ./copied.key \
  --artifact ./offline.recovery \
  --vault default
```

The command first authenticates and decrypts the selected vault. It then shows a
sanitized deletion plan and requires two exact confirmations: one naming the
vault and one containing the current revision plus a fresh challenge. There is
no `--force` or `--yes` bypass. Controlled automation may use
`--confirmation-stdin` only with every matching secret-stdin flag and the exact
bounded input frames shown by the live challenge.

Successful destruction removes only the selected MongoDB document or local vault
file, followed by the active revision anchor, active protected key file, and
every validated same-vault file supplied with repeatable `--artifact <path>`
options. When an artifact is a portable key, its adjacent `.anchor` file is
included automatically when present. All artifact paths are validated before
the first confirmation; an unsafe, malformed, missing, or differently bound file
stops destruction before anything is deleted.

The command never drops a MongoDB database or collection. Kavrix cannot discover
or erase undeclared or unavailable key copies, recovery kits, MongoDB oplogs or
backups, provider snapshots, filesystem snapshots, SSD-remapped blocks, or
offline copies. Supply every known local artifact explicitly and remove
remaining copies separately under their owning retention policies.
