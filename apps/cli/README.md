# kavrix

**Secrets stay in Kavrix. Applications get access. Agents get permission.**

A local-first secrets firewall for developers, applications, and AI agents.
Kavrix uses zero-knowledge storage: adapters receive encrypted vault records; the local CLI decrypts
authorized values in memory. There is no Kavrix server, account, or telemetry.

Give applications and AI agents access to credentials without handing over your
`.env`. `kavrix run` injects only the values a process needs; policies and
temporary grants bound what each executable may do; `kavrix agent run` brokers
every credential request from AI coding agents. Encrypted storage stays on your
machine (a protected local file or your own MongoDB).

## Installation

```sh
npm install --global kavrix
kavrix --version
kavrix --help
```

Requires Node.js `>=24.12.0 <25` or `>=25.1.0`. MongoDB is needed only if you
select that datastore; database writes require a transaction-capable replica
set or sharded topology.

Keep current with `kavrix update --check` (report only) or `kavrix update`
(upgrades a global npm install; Homebrew, pnpm, yarn, npx, and workspace
checkouts are refused with the exact manual command).

## Quick start

```sh
kavrix init          # one-time setup: creates your encrypted vault (interactive)
kavrix add github/token    # store a secret (value read from a masked prompt)
kavrix ls            # list credential names — values stay masked
kavrix get github/token --reveal   # print one secret, explicitly
kavrix run --secret TOKEN=github/token -- printenv TOKEN
```

`kavrix init` works interactively on a TTY (Ink onboarding by default,
`--no-tui` for classic prompts) and non-interactively for scripts:

```sh
PASS='MyPassphrase16chars!'
printf '%s\n%s\n' "$PASS" "$PASS" \
  | kavrix init --json --passphrase-stdin --data-file ./work.kavrix \
      --key-file ./work.key
printf '%s\n%s\n' "$PASS" 'secret-value' \
  | kavrix add github/token --profile default \
      --passphrase-stdin --value-stdin
printf '%s\n' "$PASS" | kavrix ls --profile default --passphrase-stdin
```

Scripted init creates a bound profile so `add`, `get`, and `run` work
immediately. Secret values are never accepted as arguments: they come from a
masked prompt, stdin frames, a protected key file, or the OS keychain.

## Run tools without pasting secrets

```sh
kavrix run --secret AWS_KEY=aws/deploy-key -- terraform plan
```

`kavrix run` decrypts only the credentials you name and injects them as
environment variables into exactly one child process — never through command
arguments, temp files, or your shell history.

## AI agents

```sh
kavrix agent run --agent bot --config kavrix.yaml --profile work -- codex
```

The agent process receives no credential material — only a local broker
endpoint and a one-session token. Every operation the agent requests is
authorized per request against the agent's permission entries (allowed
commands, SHA-256 executable pins, TTL windows, confirmations), the secret is
injected into the authorized child only, denials never start a child, and both
outcomes are recorded in the sealed audit trail.

## Policies, grants, audit

```sh
kavrix policy create deploy --secret aws/deploy-key \
  --command terraform --hash terraform=<sha256> --ttl 30m --require-confirmation
kavrix policy check deploy -- terraform plan   # simulate without reading the secret
kavrix policy lint
kavrix grant create aws/deploy-key --ttl 15m --max-uses 3
kavrix grant revoke <grant-id>
kavrix audit
```

Policies are evaluated fail-closed before any child process spawns; grants are
consumed atomically and can be revoked immediately; the audit trail records
policy, grant, authorization, and completion events without secret material.

## Interactive TUI

```sh
kavrix        # interactive TTY: onboarding on first run, then the TUI
kavrix tui    # full interactive app (profiles, vaults, credentials, doctor, ...)
```

Secrets stay masked until an explicit, confirmed reveal. Press `:` or `Ctrl+K`
for the command palette. Use `kavrix init --no-tui` for classic line prompts;
scripts keep the numbered commands.

## Command overview

| Group                                                                     | Purpose                                                                           |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `init`                                                                    | Set up your first encrypted vault.                                                |
| `add <name>`, `get <name>`, `ls [pattern]`, `rm <name>`, `mv <from> <to>` | Store, read, find, delete, and rename credentials.                                |
| `generate [name]`                                                         | Generate a random secret locally and store it without display.                    |
| `run`                                                                     | Execute one command with selected credentials injected into its environment only. |
| `agent run`, `agent exec`                                                 | Credential firewall that brokers AI coding agents.                                |
| `policy ...`, `grant ...`, `audit`                                        | Rules, temporary authorizations, and the audit trail.                             |
| `context`, `service`, `item`, `field`, `note`                             | Structured project credentials with typed fields and notes.                       |
| `import`, `export`                                                        | Guarded `.env` / archive import and passphrase-sealed export.                     |
| `backup`                                                                  | Passphrase-sealed backup of one local-file database.                              |
| `session`                                                                 | Keychain-gated convenience unlock for the selected profile.                       |
| `status`, `doctor`                                                        | Routing overview and vault validation (`--heal` for safe repairs).                |
| `tui`                                                                     | The interactive app (TTY required).                                               |
| `update`                                                                  | Upgrade a global npm install.                                                     |
| `db ...`                                                                  | Advanced: profiles, multi-vault databases, owner keys, recovery kits, migration.  |

## Options worth knowing

| Flag                                            | What it does                                          |
| ----------------------------------------------- | ----------------------------------------------------- |
| `--profile <id>`, `--profile-config-dir <path>` | Select a datastore profile (non-secret routing only). |
| `--vault <id>`                                  | Override the profile's default vault for one command. |
| `--passphrase-stdin`, `--value-stdin`           | Read secrets from stdin, never from arguments.        |
| `--reveal`                                      | The explicit guard that prints plaintext.             |
| `--json`                                        | Masked machine-readable output.                       |
| `--overwrite`                                   | Opt in to replacing something that already exists.    |

For exact stdin frame orders, run `kavrix frames <command>`.

## Security honesty

Kavrix controls which process receives a credential. Once an authorized process
receives it, Kavrix cannot control what that program does.

Vault payloads, the private database catalog, and wrapped keys use
XChaCha20-Poly1305 authenticated encryption. Protected key and recovery files
derive keys with Argon2id; HKDF-SHA-256 separates key purposes. Ciphertext is
bound to exact database/vault identity, and a root-key-authenticated local
revision anchor rejects rollback and forks before plaintext is returned.
MongoDB stores only ciphertext and opaque routing metadata.

## Limitations

- Kavrix cannot protect an unlocked machine from administrators, same-user
  malware, keyloggers, terminal capture, or process-memory inspection.
- Losing all valid owner keys and all recovery kits makes the database
  permanently unrecoverable by design; there is no reset or escrow.
- Team sharing (user identities, per-vault roles) is not implemented yet.
- Windows command scripts (`.bat`, `.cmd`, `.com`) are refused for execution.

## Documentation and support

- [Full README](https://github.com/d4rkNinja/kavrix#readme)
- [Command guide](https://github.com/d4rkNinja/kavrix/blob/main/docs/cli-reference.md)
- [Getting started](https://github.com/d4rkNinja/kavrix/blob/main/docs/getting-started.md)
- [Agent guide](https://github.com/d4rkNinja/kavrix/blob/main/docs/agent-guide.md)
- [Security reports](https://github.com/d4rkNinja/kavrix/blob/main/SECURITY.md)
- [Issue tracker](https://github.com/d4rkNinja/kavrix/issues)

## Word-list attribution

Generated passphrases use **EFF Short Wordlist for Passphrases #1**, from
https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt, licensed under
CC BY 4.0: https://creativecommons.org/licenses/by/4.0/.

## License

MIT

## Structured firewall workflows in 0.3.4

Run typed fields with canonical `field:context/service/item/stable-key` references.
`policy mode required` requires a selected policy or grant for every injected
secret. Complete operation rules restrict exact argument vectors. Item edits
retain authenticated snapshots for `item history restore`. Structured export
transfers fields, notes, metadata and snapshots, with optional inert policy
candidates. `backup create --include-firewall` retains sealed firewall state;
`backup restore-firewall` requires owner authentication and discards old grants.

See the [workflow guide](https://github.com/d4rkNinja/kavrix/blob/main/docs/firewall-workflows.md)
for commands, retention, compatibility and transfer limits.
