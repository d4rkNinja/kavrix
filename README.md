# Kavrix

Kavrix is a local, zero-knowledge credential vault for the terminal. It encrypts
credential values on your machine and stores only authenticated ciphertext in a
hardened local vault file or your MongoDB database. Kavrix does not start an API
server, sync daemon, or web service.

## What you control

- **Datastore:** a protected local file or supported local/remote MongoDB deployment.
- **Unlock material:** a passphrase-protected portable key file.
- **Recovery:** separately protected recovery kits that can replace a lost key.
- **Trust:** plaintext and root keys stay in the local Kavrix process.

If every valid key file and recovery kit is lost, the vault is intentionally
unrecoverable.

## Install

Kavrix requires Node.js `>=24.12.0 <25` or `>=25.1.0`. MongoDB is required only
when that datastore is selected.

```sh
npm install --global kavrix
kavrix --version
kavrix --help
```

## First vault

```sh
# 1. Create a local encrypted vault file and protected key file.
kavrix init --datastore file --data-file ./kavrix.vault

# 2. Add a credential value through the masked prompt.
kavrix put github/token --datastore file --data-file ./kavrix.vault

# 3. Browse names without revealing values.
kavrix list --datastore file --data-file ./kavrix.vault
kavrix view --datastore file --data-file ./kavrix.vault

# 4. Reveal plaintext only when explicitly required.
kavrix get github/token --reveal --datastore file --data-file ./kavrix.vault
```

Do not place passwords, portable keys, recovery secrets, or database credentials
in shell history. Prefer masked prompts, protected files, or the explicit stdin
flows shown by `kavrix <command> --help`.

## Everyday commands

| Command                     | Purpose                                                     |
| --------------------------- | ----------------------------------------------------------- |
| `kavrix db ping`            | Test a direct MongoDB connection.                           |
| `kavrix init`               | Create a vault and protected key file.                      |
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

Kavrix uses versioned authenticated encryption. Vault payload encryption uses
XChaCha20-Poly1305; passphrase-protected files use Argon2id-derived keys and
XChaCha20-Poly1305. Associated data binds ciphertext to vault identity, format,
key version, revision, and a digest of security-relevant metadata.

A root-key-authenticated revision anchor is stored beside the active key file.
Kavrix rejects older database revisions and same-revision metadata forks before
returning plaintext. If the anchor is missing, normal unlock fails closed;
`kavrix doctor health --accept-current` is an explicit trust decision and should
only be used after independently verifying the database snapshot.

Remote MongoDB connections must explicitly enable validated TLS. Kavrix rejects
TLS-disablement and insecure certificate or hostname options. MongoDB can still
observe vault identifiers, revisions, timestamps, ciphertext sizes, and access
patterns. A process able to read the local vault file can observe the same
authenticated metadata, but not credential names or values without unlocking.

Kavrix cannot protect an unlocked host from administrator access, same-user
malware, keyloggers, terminal capture, process-memory inspection, or a user who
reveals or copies plaintext. JavaScript runtimes also cannot guarantee that all
secret copies are erased from memory.

See [the threat model](docs/threat-model.md), [cryptographic design](docs/cryptography.md),
and [data model](docs/data-model.md).

## Recovery and backups

Keep at least one recovery kit on a separate protected medium from the active
key file. Back up datastore ciphertext and protected recovery material
separately. A vault backup without a valid key or recovery kit is unusable; a
key without the datastore does not contain the credentials.

Recovery-kit use rotates the vault root key for the current document. It cannot
erase ciphertext from old database snapshots, so backup access controls and
retention remain important.

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
