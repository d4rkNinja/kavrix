# Kavrix command guide

This guide explains the commands in the order a user normally needs them.
`kavrix --help` and `kavrix <command> --help` remain the
authoritative option lists for the installed version.

## 1. Select a datastore

MongoDB remains the default for compatibility. To keep the encrypted document
in a local file instead, repeat these options on every vault command:

```sh
kavrix init --datastore file --data-file ./kavrix.vault
```

The local file contains authenticated metadata and an encrypted payload. It does
not contain plaintext credential names, values, passphrases, or unwrapped keys.
Kavrix does not write a settings file that silently remembers the selection.

### Connect to MongoDB

Kavrix talks to MongoDB directly. It does not start a server and does not write
a settings file containing your database URI or unlock material.

```sh
kavrix db ping --database kavrix_local
```

The URI is requested through protected input. For controlled automation, use
`--database-url-stdin` and provide stdin through a channel that is
protected by your process supervisor. Do not put a URI containing credentials
in shell history or command arguments.

Common database options:

| Option                 | Meaning                                        |
| ---------------------- | ---------------------------------------------- |
| `--database-url-stdin` | Read the MongoDB URI from stdin                |
| `--database <name>`    | Database name when the URI does not select one |
| `--collection <name>`  | Vault collection name                          |
| `--vault <id>`         | Opaque vault identifier                        |

Common datastore options:

| Option                        | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| `--datastore <mongodb\|file>` | Select MongoDB or a local encrypted file |
| `--data-file <path>`          | Local encrypted vault file               |

Use TLS with certificate and hostname verification for remote MongoDB
deployments. Encryption at rest does not replace transport security.

## 2. Create a vault

```sh
kavrix init --datastore file --data-file ./kavrix.vault --key-file ./kavrix.key
```

Initialization creates the encrypted vault, a protected portable key file, and
the initial unlock slot. The key-file passphrase is requested through a masked
prompt or `--passphrase-stdin`. Passphrases must contain at least 16
UTF-8 bytes.

The key file is the first unlock method. Do not store it in source control,
inside a public cloud-sync folder, or beside every database backup.

## 3. Store and read credentials

### Add or replace a value

```sh
kavrix put production/api-token \
  --database kavrix_local \
  --key-file ./kavrix.key
```

Kavrix prompts for the value without echoing it. Existing names are protected
from accidental replacement; add `--overwrite` only when replacement
is intentional. `--value-stdin` is available for controlled
automation.

### Read a value

```sh
kavrix get production/api-token \
  --database kavrix_local \
  --key-file ./kavrix.key
```

The default output is masked. `--reveal` explicitly writes plaintext
to stdout:

```sh
kavrix get production/api-token --reveal
```

Use `--reveal` only in a trusted terminal. Do not redirect it to a
file, log, shell history, or an untrusted child process.

### Browse without revealing values

| Need                                | Command                   |
| ----------------------------------- | ------------------------- |
| List names                          | `kavrix list`             |
| Dashboard                           | `kavrix view`             |
| One credential card                 | `kavrix view <name>`      |
| Search names                        | `kavrix search <pattern>` |
| Counts and size/revision statistics | `kavrix stats`            |
| Existence check                     | `kavrix has <name>`       |

`view`, `search`, and `stats` never need to print
credential values. `view` supports `--json` for masked
machine-readable output; `search` and `stats` also support
`--json`.

### Change or remove a record

```sh
kavrix rename production/api-token production/service-token
kavrix remove production/service-token
```

Renaming keeps the encrypted value and changes only the record name. Removal
deletes the selected credential through the vault mutation path. Read the
confirmation prompt and stop if the selected name is not the one you intended.

## 4. Inspect vaults

```sh
kavrix vault list
kavrix vault status --vault default
```

These commands show identifiers and non-secret metadata. They do not unlock or
print credential values.

## 5. Key-file lifecycle

All key-file commands accept `--key-file`; copy operations also
accept `--output-key-file` or `--destination`.

| Goal                         | Command                                      |
| ---------------------------- | -------------------------------------------- |
| Show safe metadata           | `kavrix key status`                          |
| Verify cryptographic binding | `kavrix key verify`                          |
| Create a protected copy      | `kavrix key copy`                            |
| Explicit copy aliases        | `kavrix key replicate` / `kavrix key assign` |
| Replace the file passphrase  | `kavrix key rewrap`                          |

Copy, replicate, and assign create another protected file for the same vault.
They do not create independently revocable identities. Protect each copy with a
different physical or administrative location. Existing destination files are
not replaced unless `--overwrite` is explicit.

## 6. Recovery-kit lifecycle

### Create and verify

```sh
kavrix recovery create \
  --vault default \
  --key-file ./kavrix.key \
  --recovery-file ./kavrix.recovery.kit

kavrix recovery verify \
  --vault default \
  --key-file ./kavrix.key \
  --recovery-file ./kavrix.recovery.kit
```

The recovery kit is a protected encrypted file. Its passphrase is separate from
the portable key-file passphrase. Store the kit separately and verify it before
an outage.

### Inspect, revoke, and use

| Goal                                  | Command                           |
| ------------------------------------- | --------------------------------- |
| Show non-secret slot counts and state | `kavrix recovery status`          |
| Revoke one slot                       | `kavrix recovery revoke <slotId>` |
| Create replacement key material       | `kavrix recovery use`             |

Recovery use requires the current trusted local revision anchor. It verifies
the recovery kit and current snapshot before creating a new protected key file.
It does not guess a missing key, overwrite an existing destination by default,
or bypass rollback checks.

## 7. Validate the vault

### Normal validation

```sh
kavrix doctor
```

`doctor` unlocks and validates the local vault without printing
credential values.

### Health and safe repair

```sh
kavrix doctor health
```

Health checks cover:

| Check                 | What it protects                                  |
| --------------------- | ------------------------------------------------- |
| Encrypted datastore   | Availability and one bounded transient retry      |
| Vault schema          | Canonical shape and supported versions            |
| Key file              | File safety, binding, and cryptographic integrity |
| Encrypted payload     | AEAD authentication and associated data           |
| Recovery slots        | Valid lifecycle state and metadata integrity      |
| Local revision anchor | Detection of rollback and same-revision forks     |

The command may retry a transient datastore operation and report that safe
transient action as `autoHealed`. It never regenerates a key, rewrites
ciphertext, disables authentication, or silently accepts a lower revision.

`manualRecoveryRequired` means an operator must investigate. Confirm
the URI, vault, key file, and database snapshot; compare with a known-good
backup; then use a verified recovery kit if appropriate.
`--accept-current` is only for initializing a missing local anchor
after independent verification of the current database snapshot.

## 8. Shared safety options

| Option                 | Where it applies                            | Safety purpose                         |
| ---------------------- | ------------------------------------------- | -------------------------------------- |
| `--key-file <path>`    | Vault commands                              | Select the protected portable key file |
| `--datastore <type>`   | Vault commands                              | Select `mongodb` or `file`             |
| `--data-file <path>`   | File-backed vault commands                  | Select the encrypted local vault file  |
| `--passphrase-stdin`   | Key-file commands                           | Read a passphrase without an argument  |
| `--database-url-stdin` | Database commands                           | Read a URI without shell history       |
| `--value-stdin`        | `put`                                       | Read a value without an argument       |
| `--overwrite`          | Put, copy, recovery output                  | Opt into replacing an existing object  |
| `--json`               | View, search, stats, recovery verify/status | Masked machine-readable output         |
| `--reveal`             | Get and named view                          | Explicit plaintext output guard        |

Kavrix rejects ordinary secret-bearing arguments and does not store secrets in
environment variables or a default settings file.

## 9. Security model in user terms

- Credential values are authenticated-encrypted before datastore writes.
- Both datastore adapters store encrypted envelopes and wrapped key-slot metadata, not
  plaintext credentials or unlock material.
- The key hierarchy lets unlock methods change without re-encrypting every credential.
- Protected files are checked for canonical format, vault binding, integrity,
  and user-only filesystem permissions.
- Tampering, malformed input, wrong bindings, missing keys, and unsafe replay
  fail closed rather than returning partial plaintext.
- The local unlocked process remains trusted. A compromised user account,
  terminal, clipboard, backup, swap, crash dump, or host can still expose data.
- MongoDB can observe operational metadata such as opaque relationships,
  ciphertext sizes, versions, timestamps, and traffic patterns.
- Losing all authorized key files and recovery kits is permanent by design.

The implementation uses versioned authenticated encryption with libsodium
XChaCha20-Poly1305 and Argon2id-based passphrase derivation. See
[cryptography.md](cryptography.md) for the technical contract and its stated
limitations.

## 10. Support checklist

When a command fails:

1. Run the same command with `--help` and confirm the selected paths and vault.
2. For MongoDB, run `kavrix db ping` to separate availability from unlock problems.
3. Run `kavrix key verify` for the selected key file.
4. Run `kavrix doctor health` and follow `manualRecoveryRequired` guidance.
5. Do not delete the only key file, revoke the last unlock method, or accept a
   current snapshot without an independent backup comparison.

## Advanced destructive operation

The whole-vault destruction command is intentionally absent from normal help,
command listings, completion suggestions, the README, and routine workflow
sections. Use it only after independently verifying the exact datastore, vault,
key file, recovery copies, and backup retention:

```sh
kavrix destroy \
  --datastore file \
  --data-file ./kavrix.vault \
  --key-file ./kavrix.key \
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
the first confirmation; an unsafe, malformed, missing, or differently bound
file stops destruction before anything is deleted. The public vault binding is
structurally checked, but copied key and recovery contents cannot be
cryptographically authenticated without each copy's own passphrase.

The command never drops a MongoDB database or collection. Kavrix cannot discover
or erase undeclared or unavailable key copies, recovery kits, MongoDB
oplogs/backups, provider snapshots, filesystem snapshots, SSD-remapped blocks,
or offline copies. Supply every known local artifact explicitly and destroy
remaining copies separately under their owning retention policies.
