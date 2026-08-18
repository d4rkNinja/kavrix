# Kavrix CLI

Kavrix is a local encrypted credential vault for MongoDB. It encrypts values
before they leave your computer and connects directly to MongoDB. You do not
run a Kavrix server, HTTP API, sync daemon, or self-hosting process.

## Install

```sh
npm install --global kavrix
```

Supported Node.js versions:

```
>=24.12.0 <25 || >=25.1.0
```

## First vault

Run these commands in order:

```sh
kavrix db ping --database kavrix_local
kavrix init --database kavrix_local --key-file ./kavrix.key
kavrix put production/api-token --database kavrix_local --key-file ./kavrix.key
kavrix list --database kavrix_local --key-file ./kavrix.key
kavrix get production/api-token --database kavrix_local --key-file ./kavrix.key
```

Kavrix asks for the MongoDB URI, key-file passphrase, and credential value
through protected input. It never accepts those secrets as ordinary command
arguments. `get` stays masked unless you explicitly add
`--reveal`.

Create and verify a recovery kit immediately after initialization:

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

Store the key file and recovery kit separately. They are protected files, not
plain text codes. Losing every authorized unlock method is unrecoverable by
design.

## Commands people use most

| Task                                  | Command                                     |
| ------------------------------------- | ------------------------------------------- |
| Readable dashboard                    | `kavrix view`                               |
| One credential card                   | `kavrix view <name>`                        |
| Search names only                     | `kavrix search <pattern>`                   |
| Counts and safe statistics            | `kavrix stats`                              |
| Add or replace a value                | `kavrix put <name> [--overwrite]`           |
| Read a value                          | `kavrix get <name> [--reveal]`              |
| Rename a record                       | `kavrix rename <from> <to>`                 |
| Delete a record                       | `kavrix remove <name>`                      |
| Validate encrypted data               | `kavrix doctor`                             |
| Check and repair safe transient state | `kavrix doctor health`                      |
| Inspect vaults                        | `kavrix vault list` / `kavrix vault status` |

## Key and recovery lifecycle

| Task                                  | Command                                      |
| ------------------------------------- | -------------------------------------------- |
| Inspect a key file                    | `kavrix key status`                          |
| Verify a key file                     | `kavrix key verify`                          |
| Create another key-file copy          | `kavrix key copy`                            |
| Same copy operation, explicit aliases | `kavrix key replicate` / `kavrix key assign` |
| Change a key-file passphrase          | `kavrix key rewrap`                          |
| Create a recovery kit                 | `kavrix recovery create`                     |
| Verify a recovery kit                 | `kavrix recovery verify`                     |
| List recovery-slot state              | `kavrix recovery status`                     |
| Revoke a recovery slot                | `kavrix recovery revoke <slotId>`            |
| Replace a lost key with recovery      | `kavrix recovery use`                        |

Key-file copies share the same vault binding and are not independently
revocable. Recovery use requires the trusted local revision anchor and creates
a new protected destination; it does not silently overwrite an existing file.

## Security boundary

MongoDB receives encrypted envelopes, wrapped key-slot metadata, and unavoidable
operational metadata. It does not receive plaintext credential values,
passphrases, portable keys, recovery keys, or decrypted records.

Kavrix uses versioned authenticated encryption, independent key slots, strict
input schemas, protected key-file permissions, and fail-closed validation.
Tampering, wrong bindings, malformed data, missing keys, and unsafe rollback
states do not produce plaintext.

The local process and host remain part of the trust boundary. A process running
as the already-unlocked user can read plaintext in memory, and terminal
software, clipboard managers, swap, backups, or crash dumps may retain data.
Kavrix protects the database boundary; it cannot protect a compromised computer.

## Safe input and output

- Use masked prompts, protected files, or explicit stdin for secrets.
- Use `--database-url-stdin`, `--passphrase-stdin`, and `--value-stdin` for controlled automation.
- Never put secrets in command arguments, URLs, environment files, or logs.
- Plaintext is masked unless `--reveal` is explicitly requested.
- Keep key files and recovery kits outside the database backup path when possible.
- Use TLS with certificate and hostname verification for remote MongoDB.

Run the full command help whenever you need option details:

```sh
kavrix --help
kavrix <command> --help
```

For the complete practical guide, see
[../../docs/cli-reference.md](../../docs/cli-reference.md) in the source
repository. For the public product guide, see the repository
[README](../../README.md).

## License and attribution

Kavrix is released under the MIT license. The package includes attribution for
the [EFF Short Wordlist for Passphrases #1](https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt)
under [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).

## Zero-knowledge boundary

Kavrix uses a zero-knowledge storage boundary: MongoDB receives encrypted
credential envelopes and wrapped key metadata, but not plaintext values,
passphrases, portable keys, or recovery keys.
