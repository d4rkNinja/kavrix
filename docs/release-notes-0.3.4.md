# Kavrix 0.3.4

This release connects structured credentials to execution, policy enforcement,
history, transfer and firewall recovery. See the
[workflow guide](firewall-workflows.md) for complete commands.

## Execution and authorization

- `run`, project environment mappings, grants and agents accept canonical
  `field:context/service/item/stable-key` references. Names containing path
  separators use independently percent-encoded components. Ambiguity fails closed.
- `policy mode required` stores the authorization requirement inside the
  encrypted vault. Every injected secret needs an explicitly selected policy or
  valid grant; `--no-config` cannot bypass it.
- Policies and grants support repeated `--operation <json>` rules. Both the
  executable and complete argument vector must match; extra flags and different
  targets are denied. Policy check/explain/diff use the same operation contract.
- Agent permissions enforce `maxUses` atomically within a broker session,
  including concurrent requests. Stored denies apply to every agent request,
  including policy edits made during a running session. Budgets restart with a
  new broker; validated attempts are charged before spawn and are not refunded.
- Structured field reveal remains separately gated. Legacy structured reveal
  and deny references remain restrictive during canonical-reference migration.

## Restorable history

- Item edits atomically retain prior snapshots inside the existing vault AEAD.
  `item history list/show` expose metadata only; `item history restore` restores
  content as a fresh revision while preserving the current item name.
- Retention is bounded to 100 snapshots per item and 10,000 per vault, within the
  existing payload-size limit. Permanent removal deletes the live item's copies.
- Unknown identities, inconsistent vault/group bindings, missing relationships
  and incompatible templates fail closed. Legacy isolated history remains
  metadata-only because it lacks reachable wrapped keys.

## Transfer and recovery

- `export --structured` carries fields, item/group notes, private metadata,
  organization and new snapshots. Import rebinds identities without modifying
  secret strings; an existing vault requires explicit whole-vault `--overwrite`.
- `--include-policies` transfers inert definitions. Review them with
  `policy candidates`, then approve one with `policy import <id>`. Import refuses
  an existing policy ID. Grants and audit do not cross this transfer boundary.
- `backup create --include-firewall` preserves the database bytes and sealed
  authorization sidecar. Database restore reports pending firewall recovery;
  `backup restore-firewall` authenticates the owner and archive before restoring
  rules and bounded audit history. Archived grants are always discarded.
- Existing ciphertext-only backups and version 1 flat export archives remain
  supported. Full recovery never silently accepts a rollback anchor. Owner and
  recovery keys remain separate from backup media.

## Compatibility and verification scope

Structured version 1 remains readable. Snapshot writes and new vault settings
activate structured version 2, which older CLIs reject. Keep a verified backup
before upgrading or attempting a downgrade. Structured transfer refuses
nonportable attachments and legacy isolated history ciphertext; whole-database
backup preserves those bytes. Operation rules authorize invocations, not the
permitted program's subsequent behavior or network access.

The release gates are the complete [local preflight](release.md), packed CLI
acceptance, exact-commit CI and CodeQL, and trusted publication with registry
integrity reconciliation. New regression suites cover the structured CLI
journey, snapshot binding/retention, encrypted canaries, version/AAD tampering,
concurrent broker limits, stored denies, inert policy import and recovery without
grant resurrection. Native Windows evidence does not substitute for native
Linux/macOS checks or live transactional MongoDB integration.

Full firewall backups use archive version 2 so older CLIs reject the new bundle
semantics. Ciphertext-only backups retain archive version 1. The authenticated
header binds the version, and relabeling an archive fails authentication.
