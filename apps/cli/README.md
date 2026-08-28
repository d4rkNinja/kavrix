# kavrix

Kavrix is a zero-knowledge credential vault for the terminal. It encrypts
credential names and values on your machine and stores authenticated ciphertext
in a protected local database file or in your own MongoDB deployment. One
database holds multiple independently encrypted vaults, and no Kavrix server,
account, or telemetry exists anywhere in the path.

Tools consume credentials through tightly scoped execution: `kavrix run`
injects only the requested values into a child process environment, permission
policies and temporary grants bound what each executable may do, and
`kavrix agent run` brokers every request from AI coding agents against those
policies.

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

```sh
# 1. Register and select a non-secret route to your datastore.
kavrix db profile add work --datastore file \
  --data-file ./work.kavrix --key-file ./work.kavrix.key
kavrix db profile use work

# 2. Initialize the database and create a vault.
kavrix db init --profile work
kavrix db vault create --profile work

# 3. Copy the returned opaque vault ID into the flat commands.
kavrix put github/token --profile work --vault <vault-id>
kavrix get github/token --reveal --profile work --vault <vault-id>
```

Sensitive input is prompted for or read from stdin; it is never accepted as a
normal argument. Use `kavrix <command> --help` for the exact protected-input
options in your installed version.

## Command overview

| Group                                                                      | Purpose                                                                               |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `db profile ...`                                                           | Manage non-secret datastore routes.                                                   |
| `db init`, `db status`                                                     | Initialize or authenticate a multi-vault database.                                    |
| `db vault ...`                                                             | Create, list, inspect, or rename encrypted vaults.                                    |
| `db key create`                                                            | Create an exact-snapshot key for full local-file sharing.                             |
| `db recovery ...`                                                          | Manage database-root recovery kits.                                                   |
| `migrate database`                                                         | Copy one legacy version 2 vault into a database.                                      |
| `put`, `get`, `list`, `view`, `search`, `stats`, `has`, `rename`, `remove` | Store, read, and organize credentials.                                                |
| `key status/verify/copy/replicate/assign/rewrap`                           | Manage protected key files.                                                           |
| `recovery create/verify/status/revoke/use`                                 | Manage recovery kits.                                                                 |
| `doctor`, `doctor health`                                                  | Validate a vault; repair bounded transient state safely.                              |
| `init`, `vault`, `legacy v2 commands`                                      | Version 2 compatibility surface.                                                      |
| `run`                                                                      | Execute one command with selected credentials injected as environment variables only. |
| `policy create/list/show/remove/check/explain/lint/diff/suggest`           | Stored rules plus read-only simulation, diagnostics, previews, and narrowing advice.  |
| `grant create/list/show/revoke`                                            | Temporary consumable authorizations with live expiry, restrictions, and use caps.     |
| `audit`                                                                    | Plaintext-free security audit trail.                                                  |
| `agent run`, `agent exec`                                                  | Credential firewall that brokers AI coding agents.                                    |

Plaintext output is always opt-in through `--reveal`; listing and dashboard
commands never display credential values.

## Running tools without pasting secrets

```sh
kavrix run --secret AWS_KEY=aws/deploy-key -- terraform plan

kavrix policy create deploy --secret aws/deploy-key \
  --command terraform --hash terraform=<sha256> --ttl 30m
kavrix policy check deploy -- terraform plan
kavrix policy explain deploy -- terraform plan
kavrix policy lint
kavrix policy suggest

kavrix grant create aws/deploy-key --ttl 15m --max-uses 3
kavrix grant show <grant-id>

kavrix agent run
```

Policies are evaluated fail-closed before any child process spawns, grants are
consumed atomically and can be revoked immediately, and `kavrix audit` records
policy, grant, authorization, and completion events without secret material.
The policy developer tools and grant inspection authenticate metadata without
decrypting credential payloads, modifying audit state, or creating a missing
authorization sidecar.

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

## Security model

Vault payloads, the private database catalog, and wrapped keys use
XChaCha20-Poly1305 authenticated encryption. Protected key and recovery files
derive keys with Argon2id; HKDF-SHA-256 separates key purposes. Ciphertext is
bound to exact database/vault identity, purpose, versions, revision, and a
metadata digest, and a root-key-authenticated local revision anchor rejects
rollback, forks, and inconsistent heads before plaintext is returned.

MongoDB stores ciphertext plus opaque routing metadata in two collections; it
never receives passphrases, root keys, labels, or decrypted values. Remote URIs
must explicitly enable validated TLS.

## Limitations

- Kavrix cannot protect an unlocked machine from administrators, same-user
  malware, keyloggers, terminal capture, or process-memory inspection, and an
  authorized program can always read its own environment.
- Losing all valid owner keys and all database recovery kits makes the database
  permanently unrecoverable by design; there is no reset or escrow.
- User identities, public enrollment, per-vault grants and roles, revocation
  with rotation, ownership transfer, groups, structured items, and typed fields
  are not yet implemented.
- Windows command scripts (`.bat`, `.cmd`, `.com`) are refused for execution;
  invoke real executables.

For local sharing, create a fresh share key with `kavrix db key create` and
transfer it with its exact matching encrypted database file; deliver the
passphrase separately. The pair grants access to all vaults once unlocked.

## Documentation and support

- [Full README](https://github.com/d4rkNinja/kavrix#readme)
- [Command guide](https://github.com/d4rkNinja/kavrix/blob/main/docs/cli-reference.md)
- [Threat model](https://github.com/d4rkNinja/kavrix/blob/main/docs/threat-model.md)
- [Implementation status](https://github.com/d4rkNinja/kavrix/blob/main/docs/implementation-status.md)
- [Security reports](https://github.com/d4rkNinja/kavrix/blob/main/SECURITY.md)
- [Issue tracker](https://github.com/d4rkNinja/kavrix/issues)

## Word-list attribution

Generated passphrases use **EFF Short Wordlist for Passphrases #1**, from
https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt, licensed under
CC BY 4.0: https://creativecommons.org/licenses/by/4.0/.

## License

MIT
