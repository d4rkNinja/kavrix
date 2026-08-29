# Kavrix command guide

This guide follows the current public executable. `kavrix --help` and
`kavrix <command> --help` are authoritative for the installed version.
Database-container commands use `kavrix db ...`; stable version 2 compatibility
commands remain at the root. `kavrix frames [command]` prints the exact stdin
frame contract for every secret-reading command, and `kavrix status` shows the
selected profile and active routing mode.

The canonical first-run path is `db profile`, then `db init`, then `db vault
create`. A bare root `kavrix init` is retained for legacy version 2
single-vault compatibility. On a first TTY invocation with no routing or secret
flags it creates the non-secret `~/.kavrix/config.toml` template and does not
initialize a vault. The protected file is an onboarding reference and is not
loaded automatically; copy the profile examples you need, then use explicit
protected prompts or stdin flows for secrets.

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

### Share a complete local database

```sh
kavrix db key create --profile work \
  --output-key-file ./work.shared.database.key
```

After the command succeeds, copy exactly the generated share key and the
matching encrypted database file. The new key contains an encrypted,
authenticated one-use anchor for that exact snapshot. On first open in a clean
location, Kavrix authenticates the catalog and every vault, requires exact
equality with the share-time anchor, creates the companion `.database-anchor`,
and consumes bootstrap authority in the copied key. A missing owner anchor, a
consumed share key without its anchor, or any older, newer, or forked database
snapshot fails closed. Because the DRK opens every wrapped VRK, local sharing is
whole-database access and has no vault-scoped revocation.

For `--secrets-stdin`, `db key create` expects the current owner-key passphrase,
the new share-key passphrase, and confirmation. This command is file-datastore
only; MongoDB vault-scoped grants remain deferred.

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

New database vaults keep a versioned structured payload. The existing root
commands remain a compatibility projection over the default project context,
default service/group, and each item's canonical `value` password field. Pass
the returned opaque vault ID explicitly to every credential command:

```sh
kavrix put production/api-token --profile work --vault <vault-id>
kavrix get production/api-token --profile work --vault <vault-id>
kavrix list --profile work --vault <vault-id>
```

If a database contains more than one vault and `--vault` is omitted, the CLI
fails before requesting the passphrase rather than guessing.

### Structured project credentials

Structured commands require a database-container profile and an explicit vault.
They resolve names exactly and fail on missing or ambiguous parents:

```sh
kavrix context create payments --environment production \
  --profile work --vault <vault-id>
kavrix service create postgres --context payments \
  --profile work --vault <vault-id>
kavrix item create primary --context payments --service postgres \
  --profile work --vault <vault-id>
kavrix field set password --type password \
  --context payments --service postgres --item primary \
  --profile work --vault <vault-id>
```

`context` is also available as `environment`, `service` as `group`, and `item`
as `credential`. Each family provides create/list/rename/remove operations;
parents can be removed only when empty. `item show` reports metadata and field
states without values. Removing an item also removes its owned encrypted
attachment and history records from the aggregate.

`field set` reads the value only through a masked prompt or protected stdin; a
value is never accepted in argv. For controlled automation, provide both
`--passphrase-stdin` and `--value-stdin` (or `--value-stdin-base64`) so the exact
frames are database-key passphrase followed by field value. Supported types
include `username`, `password`, `api-key`, `url`, `certificate`, `totp-secret`
(`totp-seed` alias), `recovery-code-list` (`recovery-code` alias), `json`, and
`environment-map`. Environment maps use one `KEY=VALUE` entry per line.

`field list` exposes the schema policies but not field values. `field get`
returns ordinary non-sensitive values as escaped JSON and returns `[REDACTED]`
for a present sensitive value unless `--reveal` is explicit, the field's
reveal policy permits it, and the outer stored reveal policy also allows it.
Use `--reveal-base64` instead for an authorized byte-preserving transport of a
multiline sensitive value. The default context, service, and canonical `value`
field cannot be renamed or removed because they anchor flat-command
compatibility. Other field removal archives the definition/value inside the
item rather than silently discarding its schema history.

Notes, expiry/rotation metadata, attachment ownership, and encrypted history
are part of the structured payload and survive these operations. Version 0.2.6
does not add attachment transfer or history-restore commands.

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

| Goal                           | Command                              |
| ------------------------------ | ------------------------------------ |
| Create a kit                   | `kavrix db recovery create`          |
| Verify a kit                   | `kavrix db recovery verify`          |
| Inspect slot counts            | `kavrix db recovery status`          |
| Revoke a non-final slot        | `kavrix db recovery revoke <slotId>` |
| Create a fresh owner key file  | `kavrix db recovery use`             |
| Diagnose container trust state | `kavrix db doctor health`            |

`kavrix db doctor health [--accept-current]` verifies the database binding,
every encrypted document, and the trusted local anchor, and reports structured
findings. With `--accept-current`, and only after the entire observed snapshot
authenticates with the database root key, it rewrites the local rollback anchor
to match; datastore content is never modified. See the troubleshooting section
of `docs/local-database.md` before using it.

Recovery use validates the kit, database binding, current datastore state, and
trusted database anchor before writing a fresh owner key and anchor. Recovery
companion anchors may advance only through the authenticated recovery workflow
after an owner mutation; ordinary owner opens never auto-advance an anchor. It does not
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

For local-file sharing, run `kavrix db key create`, then securely transfer
exactly the encrypted database file and the freshly generated matching share key.
Send the share-key passphrase separately. Anyone who can unlock those two files
has full access to every vault. Local profiles do not provide reader/editor roles
or per-vault revocation.

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
the source passphrase, expected source-vault label, destination passphrase,
destination confirmation, private database label, and private migrated-vault
label. A MongoDB source URI frame, when applicable, comes first, making the
supported MongoDB-source-to-local initialization flow exactly seven frames. The
expected source label is checked only after the legacy vault authenticates and a
mismatch returns a generic migration-input error. The reader accepts at most
seven frames and rejects requests for eight or more.

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

## 9. Execute credentials without copying them

`kavrix run` decrypts only the credentials you name and injects them into the
environment of exactly one child process:

```sh
kavrix run \
  --profile work --vault <vault-id> \
  --secret DATABASE_URL=production/database \
  -- node server.js
```

Project files keep mappings and policy definitions out of the shell. A project
file contains references only, never plaintext values, and strict parsing
fails closed on unknown keys. Top-level `policies:` are reusable by
`run --policy`; per-environment `policies:` are additional definitions scoped
under `environments.<name>.policies`. The exact accepted shape is
`environments.<name>.secrets.<ENV>` plus permission entries (each with
`secret`, `commands`, and optional `hashes`, `env`, `reveal`, `ttl`,
`maxUses`, `requireConfirmation`, `workingDirectory`, or `deny`):

```yaml
# kavrix.yaml
version: 1
project: backend-api
environments:
  development:
    secrets:
      DATABASE_URL: database/development
      REDIS_URL: redis/development
    policies:
      github-development:
        secret: github/development-token
        commands: [git, gh]
        reveal: false
        ttl: 30m
        # Optional: bind use to one directory subtree (canonical real path).
        workingDirectory: /srv/work/backend-api

policies:
  npm-publish:
    secret: npm/publish-token
    commands: [npm]
    reveal: false
    requireConfirmation: [publish]
    maxUses: 1
```

`snake_case` aliases (`require_confirmation`, `max_uses`) are accepted on
permission entries and normalized to camelCase.

Agent firewall permissions live under top-level `agents.<name>.permissions`
with the same permission-entry shape, and each entry used by
`kavrix agent exec` must declare `env` (the destination variable for the
injected secret) or the request is denied as `no-injection-mapping`:

```yaml
agents:
  bot:
    permissions:
      gh-issue-list:
        secret: github/development-token
        commands: [gh]
        env: GITHUB_TOKEN
```

```sh
kavrix run ... --config kavrix.yaml --environment development -- npm test
kavrix run ... --policy npm-publish -- npm publish
```

Behavior guarantees and limits (see the threat model for the full list): values
are injected only into the child environment and never placed in arguments;
child exit codes propagate, signal death maps to conventional `128+n` codes;
`--json` captures bounded child output (64 KiB per stream) with injected
secrets redacted; a child that exceeds the bound is terminated with an
output-limit kill (exit `143`, `termination: "output-limit"`); no plaintext
temporary files are written. The child can always read its own environment.
This is process scoping, not a sandbox.

## 10. Policies and temporary grants

Stored policies live in a sealed sidecar beside the owner key, authenticated
with a key derived from the database root key and a monotonic sequence.
Permission to use a credential is distinct from permission to reveal it:
`get <name> --reveal` is denied while any covering policy does not explicitly
set `reveal: true`, and deny entries block every path.

```sh
kavrix policy create github-development \
  --secret github/development-token \
  --command git --command gh \
  [--hash node=<sha256hex>] [--env GITHUB_TOKEN] \
  [--ttl 30m] [--max-uses 3] [--workdir <path>] \
  [--require-confirmation|--require-confirmation publish] \
  [--deny] [--reveal] [--json]
```

`--workdir` canonicalizes the given directory through realpath at creation and
restricts every later use to invocations launched inside that subtree
(fail-closed when the invocation directory cannot be resolved).

Policy development and review are available without decrypting a credential
payload:

```sh
kavrix policy check github-development -- gh pr view 42
kavrix policy explain github-development -- gh pr view 42
kavrix policy lint
kavrix policy diff github-development \
  --secret github/development-token --command git --command gh --ttl 15m
kavrix policy suggest --limit 100
```

`policy check` resolves and hashes the proposed executable, evaluates the stored
deny, command, hash, working-directory, execution-window TTL, and confirmation
rules, and reports `credentialRead: false`. It exits `0` for allow, `12` for
deny, and `17` when the real run would require confirmation. `policy explain`
returns the same result plus the ordered rule trace and is informational (exit
`0` even when the simulated result is deny or confirm). Neither command checks
that the named credential currently exists, reads its ciphertext, prompts for
confirmation, consumes a grant, or appends an audit event.

`policy lint` reports shadowed allow rules, ineffective or impossible settings,
heuristically broad policies, and retained expired grants. Errors exit `14` for
CI; warnings alone exit `0`. A policy `--ttl` is a per-execution time cap, not a
policy expiration date. `policy diff` accepts the same definition flags as
`policy create` and classifies each semantic change as tightening, widening, or
changing without applying it. `policy suggest` considers only positive,
sanitized authorization events from the bounded audit ring and can only propose
narrowing an existing command allowlist. Suggestions are low-confidence,
review-only output: absence from the retained audit ring is not proof that a
command is unused, and nothing is applied automatically.

These read-only commands authenticate the key binding and the current database
metadata against the exact local revision anchor, then open only the sealed
authorization sidecar. They do not create a missing sidecar or rewrite its
bytes. Consequently they deliberately do not verify credential ciphertext
integrity; a later command that actually reads a credential still performs the
full authenticated catalog and vault open and fails closed on corruption.

When `kavrix run` includes one or more `--policy` options, every credential
provided through an explicit `--secret` mapping must be covered by at least one
selected policy. A policy for one credential cannot be presented while a
different explicit credential is injected. Selected policy credentials also
participate in stored-deny evaluation even when the policy is used only as a
process gate, keeping real execution aligned with `policy check`.

Temporary grants are consumable authorizations evaluated against wall-clock
TTL, use counts, command allowlists, and pins at consumption time under an
exclusive lock, so concurrent invocations cannot both claim the last use:

```sh
kavrix grant production/database --command psql --ttl 15m   # documented bare form
kavrix grant create production/database --command psql --ttl 15m --max-uses 2
kavrix grant list
kavrix grant show grant_<uuid>
kavrix grant revoke grant_<uuid>
kavrix run --grant production/database -- psql ...
```

`run --grant <ref>` accepts either a grant id or its credential name. The
referenced credential is resolved in-session and verified to exist **before**
any use is consumed, so a missing or unmappable credential never burns a use.
A grant that declares `--env VARIABLE` injects the credential under that
variable; a grant without `env` injects under a derived name (credential
reference uppercased with non-alphanumeric runs collapsed to `_`, e.g.
`production/database` → `PRODUCTION_DATABASE`). When no portable derived name
exists, the run fails closed with exit 14 and asks for an explicit mapping.
`grant list` and `grant show` report the live status (including a fail-closed
`clock-invalid` state), remaining uses, expiry and time remaining, actor,
command/hash restrictions, injection variable, and provenance without reading
the credential.

Stable exit codes carry the outcome to automation: success `0`, generic `1`,
usage `2`, authentication `10`, credential missing `11`, authorization denied
`12`, grant invalid/expired/exhausted `13`, invalid configuration `14`,
datastore failure `15`, security-integrity failure `16`, confirmation required
or declined `17`. Commands accepting `--json` emit machine-readable envelopes;
failures print one sanitized line to stderr.

Every security-relevant action appends to an audit ring inside the sealed state;
`kavrix audit [--json] [--limit N]` renders bounded metadata only, never
credential plaintext.

## 11. AI agent credential firewall

`kavrix agent run` starts an agent process with no credential material: it
receives only a local broker endpoint and a per-session token. Every
credential-backed operation must be requested through `kavrix agent exec`,
which asks the broker to evaluate the configured permission and inject the
secret directly into the authorized child:

```sh
# agents.bot permissions come from the project file's `agents:` section.
kavrix agent run --agent bot --config kavrix.yaml \
  --profile work --vault <vault-id> \
  -- codex

# Inside the agent session (its children inherit KAVRIX_AGENT_BROKER/TOKEN):
kavrix agent exec gh -- gh issue list
```

Each request is authorized per operation (`git fetch` allow, `npm publish`
ask when configured, `reveal` denied), prompts on the controlling terminal for
confirmations when one is attached, and otherwise fails closed. Agent
descendants inherit broker access; policy still gates every request. Windows
command scripts are refused as run targets because launching them requires
shell re-parsing.

## 12. Security and platform behavior

- Secret input is accepted only through masked prompts or explicit bounded stdin
  frames. Secrets are not normal flags, positional arguments, profiles, or
  environment variables.
- Every stdin frame contract is machine-referenceable: `kavrix frames` lists
  the exact frames for every secret-reading command, and `kavrix frames <command>`
  prints one contract. Values that contain line breaks or are empty use the
  dedicated base64 frame (`put --value-stdin-base64`, one base64 line).
- On Windows, masked prompting preserves the terminal receiver, restores the
  prior raw-mode state on success/error/cancel, handles carriage return and
  backspace, and reports preparation/cleanup failures without echoing input.
- Protected files require owner-only POSIX modes or verified Windows user-only
  ACLs. Symlinks, hard links, replacement races, oversized files, trailing data,
  and unsafe parent directories fail closed.
- Terminal-rendered labels and names are treated as hostile and control sequences
  are sanitized. Non-interactive output is ANSI-free.
- Credential names reject whitespace, control characters, leading/trailing or
  doubled slashes, and dot segments; vault identifiers reject reserved words
  (`__proto__`, `constructor`, `prototype`) and malformed shapes with explicit
  messages.
- Kavrix uses versioned XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, and SHA-256;
  it does not claim encryption is permanently unbreakable.

## 13. Current limits

The database container supports encrypted database/vault labels and structured
project contexts, groups/services, credential items, and typed fields. Its root
credential commands remain the default-context/service compatibility
projection described above. Notes, expiry/rotation metadata, attachment
ownership, and encrypted history records are modeled and preserved, but 0.2.6
does not add attachment transfer or history-restore commands. Project-file
environments cover execution mappings only; they are not a second vault
hierarchy. Structured commands, policies, grants, audit, run, and agent commands
require a database-container profile. Legacy version 2 vaults keep their
existing compatibility commands and can migrate with the copy-first flow in
section 7.

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
