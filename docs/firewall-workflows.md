# Structured firewall workflows in 0.3.4

These commands are implemented in the 0.3.4 source. Release availability and
cross-platform evidence are reported separately in the release notes.

## Execute a structured field

```sh
kavrix context create payments
kavrix service create github --context payments
kavrix item create deploy --context payments --service github
kavrix field set token --type api-key --context payments --service github --item deploy
kavrix run --secret GITHUB_TOKEN=field:payments/github/deploy/token -- gh issue list --repo example/project
```

The field value comes from a masked prompt, never an argument. The reference
syntax is `field:<context>/<service>/<item>/<stable-field-key>`. Percent-encode
each component independently when it contains `/`, spaces, or other reserved
characters. Encodings must be canonical (`production%2Fwest`, not extra path
segments). The complete reference is bounded to 256 characters. `field:` is a
reserved execution-reference prefix: a collision with an existing flat name is
refused rather than guessed. Existing flat names such as `github/token` keep
their literal meaning. Field labels and IDs cannot substitute for stable keys.

The same reference works in project environment mappings, policies, grants and
agent permission entries. Only the named fields are resolved. Injection does
not grant plaintext reveal permission; field reads continue to enforce both
schema reveal rules and stored policies. Legacy structured deny/reveal policy
references remain restrictive during migration to canonical references.

## Require authorization for every injected secret

```sh
kavrix policy create read-issues --secret field:payments/github/deploy/token \
  --command gh \
  --operation '{"command":"gh","args":["issue","list","--repo","example/project"]}'
kavrix policy mode required
kavrix run --policy read-issues --secret GITHUB_TOKEN=field:payments/github/deploy/token \
  -- gh issue list --repo example/project
kavrix policy mode
```

Mode is stored inside the selected encrypted vault. In required mode every
injected secret must be covered by an explicitly selected policy or a valid
grant. `--no-config` cannot disable this requirement. An owner's explicit
`kavrix policy mode optional` restores optional policy selection. Agent requests
always require their configured permission; stored deny rules additionally
take precedence on every request, including a running session.

An operation matches the executable and **the complete argument vector**.
Additional arguments, reordered flags, different targets, and arbitrary trailing
arguments are denied. Repeat `--operation` to approve alternative complete
invocations. Operation arguments must be non-secret. The equivalent YAML is:

```yaml
version: 1
agents:
  reviewer:
    permissions:
      list-issues:
        secret: field:payments/github/deploy/token
        env: GITHUB_TOKEN
        commands: [gh]
        operations:
          - command: gh
            args: [issue, list, --repo, example/project]
        maxUses: 3
```

`maxUses` on an agent permission is a per-broker-session limit, reserved before
spawn, including concurrent requests. Failed spawn attempts are not refunded.
Restarting a broker starts a fresh session budget. Temporary grant use counts
remain persisted, atomic and independent of these session budgets. Exact
operation rules are also supported by grants, `policy check`, `explain`, `diff`
and imported policy candidates. A permitted program can still misuse a supplied
credential; these rules do not sandbox its code, configuration or network access.

## Restore an earlier item revision

```sh
kavrix item history list deploy --context payments --service github --limit 100
kavrix item history show deploy <version-id> --context payments --service github
kavrix item history restore deploy <version-id> --context payments --service github
```

Edits capture the previous item in the same authenticated, optimistic vault
mutation as the new content. New snapshots are readable for restoration because
they live inside the vault's existing authenticated encryption envelope; they
do not depend on the incomplete wrapped-key representation of legacy history.
List/show print metadata only. Restore copies content into a fresh revision,
preserves the current item name, and snapshots the displaced content. It refuses
missing or mismatched identities, templates and attachment relationships.

Retention is at most 100 snapshots per item and 10,000 per vault, subject to
the existing vault-size bound. Oldest snapshots leave the retained set first.
Permanent item removal also removes its retained snapshots; this command is
not an undelete mechanism. Legacy isolated history ciphertext remains visible
as metadata and cannot be restored. Existing backup copies remain independent.

Structured payload version 1 remains readable. Edits that create snapshots, or
new policy-mode/import settings, write version 2. Older CLIs reject version 2;
keep an independently verified backup before upgrading or attempting a downgrade.

## Transfer structured data without activating foreign policies

```sh
kavrix export --structured --include-policies --file ./transfer.kavrix-export
kavrix import archive --file ./transfer.kavrix-export --profile destination
kavrix policy candidates --profile destination
kavrix policy import read-issues --profile destination
```

Version 2 exports carry complete structured fields, item/group notes, private
metadata, organization, and new restorable snapshots. Identities are rebound to
the destination vault without rewriting secret strings. Structured import
requires an empty vault; explicit `--overwrite` replaces the complete selected
vault. A required destination policy mode is preserved. Prefix filtering applies
only to flat exports/imports. Existing version 1 flat archives remain readable.

`--include-policies` carries stored definitions as encrypted, inert review
candidates. `policy candidates` displays them; `policy import <id>` explicitly
activates one and refuses an existing policy ID. Grants, audit and owner keys
are not transferred by this export. Attachments and legacy isolated history
ciphertext cannot be rebound; a structured export containing either is refused
instead of silently dropping records. Use a whole-database backup for those.

## Recover the firewall as well as database ciphertext

```sh
kavrix backup create --include-firewall --file ./complete.kavrix-backup
kavrix backup verify --file ./complete.kavrix-backup
kavrix backup restore --file ./complete.kavrix-backup --data-file ./restored.kavrix
# Bind and authenticate the restored database with your owner key or recovery kit.
kavrix backup restore-firewall --file ./complete.kavrix-backup --profile restored
```

The optional full bundle contains the exact database bytes and the sealed
authorization sidecar, under the existing passphrase-authenticated backup
envelope. Owner/recovery keys remain separate. Source changes during copying
are refused. Verify authenticates the outer backup and validates its database
and sidecar scope; it does not unlock the archived vault or validate the inner
sidecar's MAC without an owner key.

Recovery is deliberately two-stage. Database restore reports `firewallPending`
for full bundles. After the database is bound and authenticated, restore-firewall
requires owner unlock and the archive passphrase, verifies the sidecar against
the same database root and identity, then restores policies and bounded audit
history. **All archived grants are discarded**; reissue any needed access.
Existing policies/grants require explicit `--overwrite`, which also discards
current grants. Recovery records a `firewall-restored` audit event. Rollback
anchors are never silently re-accepted; follow the existing manual recovery
procedure when restoring an older database snapshot.

Existing ciphertext-only backups and their stdin contracts are unchanged.
Use `kavrix frames "backup restore-firewall"` for its owner-passphrase then
archive-passphrase input order (with MongoDB routing input when applicable).

Full firewall backups use archive version 2 so older CLIs reject the new bundle
semantics. Ciphertext-only backups retain archive version 1. The authenticated
header binds the version, and relabeling an archive fails authentication.

Stored deny and reveal rules recognize the flat default credential name and its
structured value-field reference as the same credential, using authenticated
default context and service identities.
