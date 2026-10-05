# Getting started

Task-based walkthroughs for the most common workflows. Full options live in
the [command guide](cli-reference.md); terms are defined in the
[glossary](glossary.md).

You need Node.js `>=24.12.0 <25` or `>=25.1.0`. MongoDB is only needed if you
choose that datastore.

```sh
npm install --global kavrix
kavrix --version
```

## 1. Create your first vault (interactive)

Just run:

```sh
kavrix
```

On a fresh machine this starts the onboarding wizard. It creates an encrypted
local database, a protected owner key file, a default vault, and a verified
recovery kit, then opens the terminal UI. Passphrases are asked through
masked prompts and must be at least 16 bytes. At the end you can optionally
enable OS session unlock.

The wizard fills the terminal. Click storage choices and the bottom controls, or
use arrows and Enter. `Ctrl+G` opens paged Help with complete repair instructions;
Escape closes it without submitting your input. Taps work when your terminal
translates them into mouse clicks. `kavrix init --no-mouse` keeps keyboard setup
and native terminal selection.

- Prefer classic line-by-line prompts? `kavrix init --no-tui`
- Want the UI without onboarding? `kavrix tui`
- After onboarding, bare `kavrix` opens the TUI directly.

Everything below also works from the TUI — each screen shows its keys in the
footer.

## 2. Store and read a secret

Interactively, `put` prompts for the passphrase and value without echoing:

```sh
kavrix put github/token
kavrix list                        # names only, never values
kavrix get github/token            # masked metadata
kavrix get github/token --reveal   # the guarded plaintext output
```

For scripts, read both from stdin frames (passphrase, then value):

```sh
printf '%s\n' 'my-passphrase-16b' 'secret-value' \
  | kavrix put github/token --passphrase-stdin --value-stdin
```

`kavrix frames put` prints the exact frame order for any command. Replacing
an existing credential requires `--overwrite`.

## 3. Migrate an existing `.env`

Already keep secrets in a `.env` file? Import it in one guarded command:

```sh
kavrix import env --file ./.env --prefix prod/
```

Every variable becomes a credential (`prod/AWS_KEY`, `prod/DATABASE_URL`,
...). The file is parsed strictly before anything is unlocked, values are
never echoed, existing credentials fail the import unless `--overwrite` is
explicit, and on a TTY the command offers to shred and delete the source
file afterward (`--delete-source` skips the question).

## 4. Run a program with secrets

Inject only what one command needs:

```sh
kavrix run --secret GITHUB_TOKEN=github/token -- gh repo list
```

The secret enters the child's environment only — never argv, never a file —
and the child's exit code is preserved. For repeatable setups, use a project
file:

```yaml
# kavrix.yaml
version: 1
project: my-project
environments:
  development:
    secrets:
      GITHUB_TOKEN: github/token
      DATABASE_URL: database/development
```

```sh
kavrix run --environment development -- npm test
```

`--no-config` ignores any `kavrix.yaml` (including a broken one), and
`--json` captures bounded child output with secrets redacted.

## 5. Guard what a credential may do (policy)

```sh
kavrix policy create github-development \
  --secret github/token --command git --command gh --ttl 30m

kavrix policy check github-development -- gh pr view 42
kavrix policy lint
```

`policy check` exits `0` for allow, `12` for deny, and `17` when a real run
would ask for confirmation — without ever decrypting the credential. Once a
policy covers a credential, `get --reveal` is denied unless the policy
explicitly allows reveal, and deny entries block every path.

## 6. Give temporary access (grant)

```sh
kavrix grant create production/database --command psql --ttl 15m --max-uses 2
kavrix grant list
kavrix run --grant production/database -- psql -c 'select 1'
kavrix grant revoke <grant-id>
```

A grant expires on its own, stops after its maximum uses, and can be revoked
at any time. `grant show` reports remaining uses and restrictions without
reading the credential.

## 7. Let an AI agent work without handing it secrets

Declare the agent's permissions in `kavrix.yaml`:

```yaml
version: 1
project: my-project
agents:
  bot:
    permissions:
      gh-issue-list:
        secret: github/token
        commands: [gh]
        env: GITHUB_TOKEN
```

Start the agent with zero credential material — it receives only a local
broker endpoint and a one-session token:

```sh
kavrix agent run --agent bot --config kavrix.yaml -- codex
```

Commands without `--profile` use the profile you selected during onboarding
and its default vault; pass `--profile work --vault <vault-id>` to target a
specific one.

Inside that session, children request secrets per operation:

```sh
kavrix agent exec gh -- gh issue list
```

Every request is authorized before any child starts; the secret is injected
into the authorized child only; and both allow and deny decisions appear in
`kavrix audit`.

## 8. Stop typing the passphrase

```sh
kavrix session enable     # seals unlock material via the OS credential store
kavrix list --session     # unlock without the passphrase
kavrix session status
kavrix session revoke     # remove it; the passphrase always still works
```

Sessions expire automatically (default 12 hours). Either half alone — sealed
file or OS keychain entry — is useless.

## 9. Back up before you need it

```sh
kavrix db recovery create --profile work --recovery-file ./work.database.recovery
kavrix db recovery verify --profile work --recovery-file ./work.database.recovery
kavrix db recovery status --profile work
```

A recovery kit restores owner access to every vault in the database. Keep it
on separate protected media from the owner key, with a different passphrase.
If every owner key and every recovery kit is lost, the database is
permanently unrecoverable by design — there is no vendor reset.

For a copy of the data itself, seal the whole database file:

```sh
kavrix backup create --file ./work.backup.json --profile work
kavrix backup verify --file ./work.backup.json
kavrix backup restore --file ./work.backup.json --data-file ./restored.kavrix
```

The archive is one passphrase-protected file — keep it (and its passphrase,
different again) on separate protected media. `verify` proves the archive is
intact before you rely on it; `restore` writes the database file back, and
the original owner key still unlocks it.

## 10. When something looks wrong

```sh
kavrix doctor                 # validate the vault, no values revealed
kavrix doctor health          # structured report, changes nothing
kavrix doctor health --heal --dry-run   # preview safe repairs
kavrix doctor health --heal   # apply safe repairs
```

Heal fixes specific local problems — incomplete profiles, dangling
selection, owner-only permission drift — and never invents passphrase
recovery or deletes data.

Exit codes are stable for automation: `0` success, `2` usage, `10`
authentication, `11` missing credential, `12` denied, `13` grant
invalid/expired/exhausted, `14` invalid configuration, `15` datastore
failure, `16` security-integrity failure, `17` confirmation required or
declined, `18` execution/spawn failure.

## Where next

- [Features](features.md) — what Kavrix does, in plain language
- [Command guide](cli-reference.md) — every command and option
- [TUI guide](tui-guide.md) — the interactive app
- [Recovery guide](backup-and-recovery.md) — recovery kits in depth
- [Threat model](threat-model.md) — what Kavrix protects, and what it cannot
- [Glossary](glossary.md) — every term, defined
