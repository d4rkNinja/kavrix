# Kavrix

Kavrix is a zero-knowledge credential vault and credential firewall for the
terminal. It encrypts credentials and their labels on your machine and stores
authenticated ciphertext in a hardened local database file or in your own
MongoDB deployment. One database holds multiple independently encrypted vaults,
and tools consume credentials through tightly scoped execution instead of
plaintext files:

- `kavrix run` injects only the requested credentials into a child process
  environment.
- Permission policies and temporary grants decide which executables may use a
  credential, for how long, and how many times.
- `kavrix agent run` lets AI coding agents request credentials through a local
  broker that enforces those policies on every request.

Plaintext secrets never need to land in `.env` files, shell history, logs, or
unrelated processes. Kavrix does not start an API server, sync daemon, or web
service, and it never sends your unlock material anywhere.

## Requirements

- Node.js `>=24.12.0 <25` or `>=25.1.0`
- MongoDB only if you select that datastore; database writes require a
  transaction-capable replica set or sharded topology

## Installation

```sh
npm install --global kavrix
kavrix --version
kavrix --help
```

## Quick start

The canonical first-run path is a non-secret datastore profile, followed by
database initialization and vault creation. A bare `kavrix init` is retained
only for legacy version 2 single-vault compatibility: on a first TTY run with
no routing or secret flags it creates `~/.kavrix/config.toml`
(`%USERPROFILE%\\.kavrix\\config.toml` on Windows) and does not initialize a
vault. The protected file is a non-secret onboarding reference; current
commands do not load it automatically. Copy the profile examples you need and
use an explicit protected prompt or stdin flow for secrets.

```sh
# 1. Register and select a non-secret route to your datastore.
kavrix db profile add work --datastore file \
  --data-file ./work.kavrix --key-file ./work.kavrix.key
kavrix db profile use work

# 2. Initialize the database and create a vault. Labels stay encrypted.
kavrix db init --profile work
kavrix db vault create --profile work

# 3. Copy the returned opaque vault ID into the flat commands.
kavrix put github/token --profile work --vault <vault-id>
kavrix list --profile work --vault <vault-id>

# 4. Reveal plaintext only when you explicitly ask for it.
kavrix get github/token --reveal --profile work --vault <vault-id>
```

Sensitive input is always prompted for or read from stdin. Never place
passwords, keys, recovery secrets, or database URIs in shell arguments or shell
history.

## Everyday commands

| Command                     | Purpose                                              |
| --------------------------- | ---------------------------------------------------- |
| `kavrix put <name>`         | Add a value; replacing one requires `--overwrite`.   |
| `kavrix get <name>`         | Read metadata; `--reveal` is required for plaintext. |
| `kavrix list`               | List names without values.                           |
| `kavrix view [name]`        | Show a sanitized dashboard or one credential card.   |
| `kavrix search <pattern>`   | Search credential names only.                        |
| `kavrix stats`              | Non-secret counts, sizes, and revisions.             |
| `kavrix has <name>`         | Check whether a name exists.                         |
| `kavrix rename <from> <to>` | Rename a record while keeping its encrypted value.   |
| `kavrix remove <name>`      | Delete a record.                                     |

### Databases, profiles, and vaults

| Command                   | Purpose                                                   |
| ------------------------- | --------------------------------------------------------- |
| `kavrix db profile ...`   | Add, select, inspect, or remove non-secret routes.        |
| `kavrix db init`          | Create an encrypted database and protected owner key.     |
| `kavrix db status`        | Authenticate and inspect the selected database.           |
| `kavrix db vault ...`     | Create, list, inspect, or rename database vaults.         |
| `kavrix db key create`    | Create an exact-snapshot key for full local-file sharing. |
| `kavrix db recovery ...`  | Manage database-root recovery kits.                       |
| `kavrix migrate database` | Copy one legacy version 2 vault into a database.          |
| `kavrix db ping`          | Test a direct MongoDB connection.                         |

### Keys, recovery, and health

| Command                | Purpose                                                     |
| ---------------------- | ----------------------------------------------------------- |
| `kavrix key ...`       | Verify, copy, replicate, assign, or rewrap key files.       |
| `kavrix recovery ...`  | Create, verify, inspect, revoke, or use recovery kits.      |
| `kavrix doctor`        | Authenticate and validate a vault without revealing values. |
| `kavrix doctor health` | Diagnose and safely repair bounded transient state.         |
| `kavrix init`          | Legacy version 2 single-vault compatibility path.           |

## Running tools without pasting secrets

```sh
# Inject selected credentials as environment variables only.
kavrix run --secret AWS_KEY=aws/deploy-key -- terraform plan

# Bound what a credential may do before anything spawns.
kavrix policy create deploy --secret aws/deploy-key \
  --command terraform --hash terraform=<sha256> --ttl 30m --require-confirmation

# Simulate and explain without reading the credential.
kavrix policy check deploy -- terraform plan
kavrix policy explain deploy -- terraform plan
kavrix policy lint
kavrix policy diff deploy --secret aws/deploy-key --command terraform --ttl 15m
kavrix policy suggest

# Hand out access that expires and can be revoked.
kavrix grant create aws/deploy-key --ttl 15m --max-uses 3
kavrix grant list
kavrix grant show <grant-id>
kavrix grant revoke <grant-id>

# Review what happened, without secret material.
kavrix audit
```

Policies support command allowlists, SHA-256 executable pins, execution-window
TTLs, working-directory restrictions, deny rules, reveal gating, and
confirmation requirements. Every decision is evaluated fail-closed before a
child process spawns. Policy simulation, explanation, linting, diffing, and
suggestions authenticate authorization metadata without decrypting credential
payloads or mutating the audit/state sidecar.

## AI coding agents

```sh
kavrix agent run --agent bot --config kavrix.yaml \
  --profile work --vault <vault-id> -- <agent-executable>
```

An agent started this way holds no credential material. When it needs one, it
asks a local broker over a per-session authenticated channel; the broker checks
your stored policies for that request and injects the value directly into one
authorized child process. Denials are distinguishable from broken connections,
and `kavrix audit` records the events.

## Options worth knowing

| Flag                                | What it does                                                               |
| ----------------------------------- | -------------------------------------------------------------------------- |
| `--profile`, `--profile-config-dir` | Select a datastore profile without storing secrets.                        |
| `--vault <id>`                      | Select one opaque vault explicitly.                                        |
| `--passphrase-stdin`                | Read the key passphrase from stdin.                                        |
| `--database-url-stdin`              | Read the MongoDB URI from stdin.                                           |
| `--value-stdin`                     | Read a credential value from stdin.                                        |
| `--secrets-stdin`                   | Read every unlock secret from exact stdin frames.                          |
| `--reveal`                          | The explicit guard that prints plaintext.                                  |
| `--json`                            | Masked machine-readable output.                                            |
| `--overwrite`                       | Opt in to replacing something that already exists.                         |
| `--allow-insecure-transport`        | Explicit opt-in to unencrypted MongoDB transport (isolated networks only). |

`kavrix <command> --help` is authoritative for your installed version.

## Security model

Kavrix uses versioned authenticated encryption, not "unbreakable encryption."
Vault payloads, the private database catalog, and wrapped keys use
XChaCha20-Poly1305. Passphrase-protected files derive keys with Argon2id.
HKDF-SHA-256 separates key purposes, and associated data binds every ciphertext
to the exact database, vault, purpose, key version, revision, and metadata
digest.

A revision anchor authenticated by the database root key is stored beside each
active owner key file. Rollback attempts, same-revision forks, and inconsistent
catalog/vault heads are rejected before plaintext is returned, and a missing or
invalid anchor fails closed.

MongoDB stores ciphertext plus opaque routing metadata in two collections. It
can observe the MongoDB database and collection namespaces, opaque IDs,
revisions, timestamps, ciphertext sizes, and access patterns. Human-readable
Kavrix database labels, vault labels, credential labels, and values remain
encrypted. Remote connections must explicitly enable validated TLS.

Details: [threat model](docs/threat-model.md),
[cryptography](docs/cryptography.md), [data model](docs/data-model.md).

## Backups and recovery

Keep at least one database recovery kit on separate protected media from the
active owner key, and verify it with
`kavrix db recovery verify --profile work --recovery-file <path>` before you
rely on it. Back up datastore ciphertext and protected recovery material
separately.

For local-file sharing, generate a fresh share key with `kavrix db key create`
and transfer it together with the exact matching database file. That pair grants
full access to every vault once its passphrase is known; there is no
vault-scoped local sharing or revocation.

If every valid owner key file and every recovery kit is lost, the database is
permanently unrecoverable by design. There is no vendor reset or escrow, because
no one else ever held the required material.

## Limitations

- Kavrix cannot protect an unlocked host from administrators, same-user malware,
  keyloggers, terminal capture, clipboard capture, process-memory inspection, or
  swap and crash dumps. Secret buffers are cleared best effort; JavaScript
  cannot guarantee complete erasure.
- An authorized program can read its own environment. Execution controls add
  authorization and process hygiene; they do not constrain what a legitimate
  program does with values it was given.
- User identities, public enrollment, recipient discovery, per-vault grants and
  roles, revocation with rotation, and ownership transfer are not implemented.
- Windows command scripts (`.bat`, `.cmd`, `.com`) are refused for execution
  because launching them requires shell argument re-parsing; invoke real
  executables.

See [implementation status](docs/implementation-status.md) for the full factual
ledger of what is implemented and verified.

## Documentation

Start with the [documentation index](docs/README.md):

- [Command guide](docs/cli-reference.md)
- [Threat model](docs/threat-model.md)
- [Recovery guide](docs/backup-and-recovery.md)
- [Datastore policy](docs/local-database.md)
- [Architecture](docs/architecture.md)

## Support

Security issues follow [SECURITY.md](SECURITY.md); please do not open public
issues for them. Bug reports and feature requests go to the
[issue tracker](https://github.com/d4rkNinja/kavrix/issues). Contributions are
described in [CONTRIBUTING.md](CONTRIBUTING.md). The published npm package is
built through GitHub Actions with trusted publishing and provenance.

## License

[MIT](LICENSE)
