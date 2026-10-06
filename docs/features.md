# Features

Kavrix is a local-first secrets firewall. Your secrets live in encrypted
vaults on your machine, and nothing reads one — an app, a script, or an AI
agent — until Kavrix's rules allow it. Every allowed use is recorded.

This page explains what Kavrix can do in plain language. For exact commands
and options see the [command guide](cli-reference.md); for a step-by-step
walkthrough see [getting started](getting-started.md). Unfamiliar terms are
defined in the [glossary](glossary.md).

## Encrypted storage you control

- All secrets live in one encrypted database: either a hardened local file or
  your own MongoDB deployment. There is no Kavrix server, account, or
  telemetry in the path.
- One database holds multiple vaults, each independently encrypted. Opening
  one vault never decrypts another.
- With MongoDB, the server stores only unreadable ciphertext and routing
  metadata — it is structurally unable to decrypt anything. Remote
  connections require validated TLS.
- Named profiles let you keep separate databases (for example `work` and
  `personal`) and switch between them; each profile remembers its own default
  vault.

## Credentials with structure, not just name/value

- A credential can carry typed fields — username, password, API key, URL,
  certificate, TOTP seed, recovery codes, JSON, environment maps — plus
  notes and expiry/rotation metadata.
- Project contexts and groups/services organize credentials the way your
  infrastructure is organized.
- Everything non-secret stays encrypted too: labels and metadata live inside
  the encrypted payload, never in the clear in the database.
- Older flat `name → value` records keep working through the same commands.
- Migrating is one command: `kavrix import env --file ./.env` turns a
  `.env` file into credentials (guarded parsing, values never echoed, and
  an offer to shred the source file afterward).

## Run programs without pasting secrets

`kavrix run` decrypts only the credentials you name and injects them as
environment variables into exactly one child process:

```sh
kavrix run --secret DATABASE_URL=production/database -- node server.js
```

- Secrets travel through the child's environment only — never through
  command arguments, temp files, or your shell history.
- Child exit codes and signal deaths are preserved, so `run` is safe to use
  in scripts and CI.
- Project files (`kavrix.yaml`) map many environment variables at once and
  define reusable policies — see [getting started](getting-started.md).

## Policies: decide what a credential may do

Stored policies are fail-closed rules evaluated before any program starts:

- command allowlists and SHA-256 executable pins,
- per-execution time windows (TTL),
- working-directory restrictions,
- reveal gating — reading the plaintext is denied unless a policy allows it,
- confirmation prompts for dangerous commands,
- explicit deny entries that block every path.

You can rehearse safely: `policy check` and `policy explain` simulate a
decision without decrypting the credential, and `policy lint`, `policy diff`,
and `policy suggest` help you keep rules tight over time.

## Temporary grants

Hand out access that expires and can be revoked:

```sh
kavrix grant create production/database --command psql --ttl 15m --max-uses 2
```

A grant is consumable: its TTL, remaining uses, command restrictions, and
live status are inspectable without ever reading the credential, and
consumption is atomic, so two simultaneous runs cannot both claim the last
use.

## AI agent firewall

Start an agent — Codex, Claude Code, your own bot — with **zero credential
material**:

```sh
kavrix agent run --agent bot --config kavrix.yaml -- codex
```

- The agent process receives only a local broker endpoint and a one-session
  token. Its environment and arguments contain no secrets.
- Every operation the agent requests is authorized per request; the secret is
  injected directly into the one authorized child, and each allow or deny is
  recorded in the audit trail.
- Request queues, frame sizes, and rates are bounded; abusive connections are
  torn down.

## Audit trail

Every security-relevant event — policy decisions, grant use, reveals,
confirmations, completions — is recorded with sanitized metadata only, never
secret values. `kavrix audit` shows what happened and `kavrix audit --json`
feeds it to automation.

## Keys, recovery, and health

- A protected owner key file unlocks the database. Recovery kits are an
  independently protected way back in — create, verify, and revoke them, and
  keep one off-machine.
- `doctor` validates a vault without revealing values. `doctor health --heal`
  repairs specific, safe classes of local problems (permission drift,
  incomplete profiles, dangling selection) and never invents passphrase
  recovery or deletes data.
- Key files can be verified, copied, replicated, assigned, and rewrapped;
  every operation checks file permissions (owner-only on Unix and Windows).
- `kavrix backup create` seals the whole database file into one
  passphrase-protected archive; `backup verify` authenticates it, and
  `backup restore` writes it back — see [backups](#keys-recovery-and-health).

## Stop typing your passphrase

Optional OS session unlock: `kavrix session enable` seals your unlock
material and puts the wrapping key in your operating system credential store
(Windows PasswordVault, macOS Keychain, Linux Secret Service). Then commands
accept `--session` and the TUI unlocks without the passphrase until the
session expires. Either half alone is useless, revocation removes both, and
the passphrase always still works — nothing about it is weakened.

## Terminal UI

`kavrix` (or `kavrix tui`) opens a full interactive app: profiles, vaults,
credentials, policies, grants, recovery, doctor, and session unlock, with
secrets masked by default and reveal explicitly guarded (`r` then `y`, with a
visible countdown). Screens are reachable by number or Tab, long lists have
`/` search, and motion respects your reduced-motion setting. Press `t` to
switch between five color themes (Gold, Ocean, Magma, Forest, Violet) with
a live preview — your choice is saved, or set it per launch with
`kavrix tui --theme`.

Common database TUI actions reuse authenticated keys, with fresh protected-file,
datastore, and rollback-anchor checks per operation. Storage closes between
actions. Two idle minutes or fifteen minutes since unlock locks the TUI; navigation
alone does not renew it. Browse and policy/grant/audit views load one snapshot
each. Agent brokers can execute up to four requests concurrently; confirmations
and audit writes remain serialized.

## Housekeeping

- `kavrix status` shows the resolved routing; `kavrix frames <command>`
  prints the exact stdin frame order for scripting.
- Stable exit codes (documented in the [command guide](cli-reference.md)) and
  `--json` envelopes make automation reliable.
- `kavrix update --check` reports newer npm releases for global installs.

## What Kavrix deliberately does not do

Honest boundaries — the [threat model](threat-model.md) records them in full:

- No Kavrix server, cloud, or sync daemon. Kavrix is one local CLI.
- No team collaboration yet: no user identities, roles, per-vault sharing, or
  revocation-with-rotation commands. That protocol exists internally but is
  not shipped.
- Local-file sharing is all-or-nothing: a share key plus the database file
  grants full access to every vault.
- Once an authorized program has received a secret, Kavrix cannot control
  what it does with it. Execution scoping is authorization, not a sandbox.
