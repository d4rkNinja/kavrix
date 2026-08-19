# Kavrix

Kavrix is a local, zero-knowledge credential vault for the terminal. It encrypts
credential values and private labels on your machine and stores authenticated
ciphertext in a hardened local database file or MongoDB. One database can hold
multiple independently encrypted vaults. Kavrix does not start an API server,
sync daemon, or web service.

## What you control

- **Datastore:** a protected local database file or supported MongoDB deployment.
- **Routing:** protected profiles containing only non-secret paths, names, and opaque IDs.
- **Unlock material:** a passphrase-protected database-owner key file.
- **Recovery:** separately protected database recovery kits that can replace a lost owner key.
- **Trust:** plaintext and root keys stay in the local Kavrix process.

If every valid database-owner key file and database recovery kit is lost, every
vault in that database is intentionally unrecoverable.

## Install

Kavrix requires Node.js `>=24.12.0 <25` or `>=25.1.0`. MongoDB is required only
when that datastore is selected.

```sh
npm install --global kavrix
kavrix --version
kavrix --help
```

## First database and vault

```sh
# 1. Register and select a non-secret local route.
kavrix db profile add work --datastore file \
  --data-file ./work.kavrix --key-file ./work.kavrix.key
kavrix db profile use work

# 2. Initialize the database, then create a vault. Labels stay encrypted.
kavrix db init --profile work
kavrix db vault create --profile work

# 3. Copy the returned opaque vault ID into the flat credential commands.
kavrix put github/token --profile work --vault <vault-id>
kavrix list --profile work --vault <vault-id>

# 4. Reveal plaintext only when explicitly required.
kavrix get github/token --reveal --profile work --vault <vault-id>
```

Do not place passwords, portable keys, recovery secrets, or database credentials
in shell history. Prefer masked prompts, protected files, or the explicit stdin
flows shown by `kavrix <command> --help`.

## Everyday commands

| Command                     | Purpose                                                     |
| --------------------------- | ----------------------------------------------------------- |
| `kavrix db profile ...`     | Add, select, inspect, or remove non-secret routes.          |
| `kavrix db init`            | Create an encrypted database and protected owner key.       |
| `kavrix db vault ...`       | Create, list, inspect, or rename database vaults.           |
| `kavrix db recovery ...`    | Manage database-root recovery kits.                         |
| `kavrix migrate database`   | Copy one legacy version 2 vault into a database.            |
| `kavrix db ping`            | Test a direct MongoDB connection.                           |
| `kavrix init`               | Create a legacy-compatible version 2 single vault.          |
| `kavrix put <name>`         | Add a value; replacement requires explicit override.        |
| `kavrix get <name>`         | Read metadata; `--reveal` is required for plaintext.        |
| `kavrix list`               | List names without values.                                  |
| `kavrix view [name]`        | Show a sanitized vault dashboard or credential card.        |
| `kavrix search <pattern>`   | Search credential names only.                               |
| `kavrix stats`              | Show non-secret vault statistics.                           |
| `kavrix has <name>`         | Check for a name without revealing its value.               |
| `kavrix rename <from> <to>` | Rename a record.                                            |
| `kavrix remove <name>`      | Delete a record.                                            |
| `kavrix vault list`         | List vault identifiers in the selected collection.          |
| `kavrix vault status`       | Inspect non-secret vault metadata.                          |
| `kavrix key ...`            | Verify, copy, replicate, assign, or rewrap key files.       |
| `kavrix recovery ...`       | Create, verify, inspect, revoke, or use recovery kits.      |
| `kavrix doctor`             | Authenticate and validate a vault without revealing values. |
| `kavrix doctor health`      | Diagnose and safely repair bounded transient state.         |

Run `kavrix <command> --help` for the authoritative options installed with your
version.

## Security model

Kavrix uses versioned authenticated encryption, not "unbreakable encryption."
Vault payloads, the private database catalog, and wrapped keys use
XChaCha20-Poly1305. Passphrase-protected files use Argon2id-derived keys and
XChaCha20-Poly1305. HKDF-SHA-256 derives purpose-specific keys. Associated data
binds ciphertext to the database, vault, purpose, key version, revision, and a
digest of security-relevant metadata.

A database-root-key-authenticated revision anchor is stored beside each active
database key file. Kavrix rejects lower database revisions,
same-revision forks, and inconsistent catalog/vault heads before returning
plaintext. A missing or invalid owner anchor fails closed. A freshly generated
local-share key contains an encrypted, authenticated one-use anchor for the exact
share-time snapshot; first use publishes its companion anchor and consumes that
bootstrap authority. It never accepts a newer, older, or forked first-use file.

Remote MongoDB connections must explicitly enable validated TLS. Multi-document
database/vault changes require a MongoDB replica set or sharded topology with
transactions. MongoDB stores database documents and vault documents in two
collections and can observe opaque IDs, revisions, timestamps, ciphertext
sizes, and access patterns. It cannot read database, vault, or credential labels.

Kavrix cannot protect an unlocked host from administrator access, same-user
malware, keyloggers, terminal capture, process-memory inspection, or a user who
reveals or copies plaintext. JavaScript runtimes also cannot guarantee that all
secret copies are erased from memory.

See [the threat model](docs/threat-model.md), [cryptographic design](docs/cryptography.md),
and [data model](docs/data-model.md).

## Recovery and backups

Keep at least one database recovery kit on a separate protected medium from the
active owner key. Back up datastore ciphertext and protected recovery material
separately. For local-file sharing, generate a fresh protected share key with
`kavrix db key create`, then transfer that key and the exact matching database
file. Together they grant full access to every vault once the share-key
passphrase is known; there is no vault-scoped local sharing or revocation.

Database recovery recreates owner access to the same database root key; each
vault still has an independent vault root key wrapped to that database root.
Recovery cannot erase ciphertext or keys from old snapshots, so backup access
controls and retention remain important.

## Documentation

Start with the [documentation index](docs/README.md). The most useful pages are:

- [Command guide](docs/cli-reference.md)
- [Datastore policy](docs/local-database.md)
- [Recovery kits](docs/backup-and-recovery.md)
- [Architecture](docs/architecture.md)
- [Security testing](docs/security-testing.md)
- [Release procedure](docs/release.md)

## Contributing and release checks

```sh
pnpm install --frozen-lockfile
pnpm verify
pnpm acceptance:database-container
pnpm --filter kavrix package:smoke
pnpm --filter kavrix pack:check
pnpm audit --audit-level high
```

Security reports should follow [SECURITY.md](SECURITY.md). The public npm package
is built and published through GitHub Actions with npm trusted publishing and
provenance; long-lived npm publication tokens are not part of the release path.

## Word-list attribution

Generated passphrases use **EFF Short Wordlist for Passphrases #1**, from
https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt, licensed under
CC BY 4.0: https://creativecommons.org/licenses/by/4.0/.

## License

[MIT](LICENSE)
