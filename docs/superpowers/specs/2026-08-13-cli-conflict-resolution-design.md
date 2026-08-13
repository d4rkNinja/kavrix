# CLI conflict listing and resolution design

## Scope

Issue #32 adds durable, explicit conflict handling to the command-only CLI. A
conflict is a server rejection of an opaque mutation because the server's
current revision no longer matches the mutation's expected revision.

The implementation must preserve the zero-knowledge boundary: the local client
may retain encrypted records and public synchronization metadata, but it must
not decrypt or print credential payloads while listing or resolving conflicts.

## Chosen architecture

The SQLite local-sync format advances from v3 to v4 with a `sync_conflicts`
ledger. Each row stores the canonical opaque mutation, the canonical opaque
server-current record (or null), the server current revision, and optional
canonical resolution metadata. The row is inserted in the same transaction as
outbound reconciliation, so a successful conflict response cannot be lost
between sync completion and a later CLI invocation.

Unresolved rows are exposed through a sync-local-store conflict port. Resolved
rows remain bounded local audit history; their retained mutation/current data is
still opaque encrypted data, while resolution metadata contains only strategy,
revision, idempotency, and timestamp fields. Canonical-row validation, bounds,
v3-to-v4 migration, and restart tests protect this ledger.

## CLI and session flow

The public commands are:

- `creds sync conflicts list [--json]`
- `creds sync conflicts resolve <conflict-id> --strategy <keep-local|accept-remote> --revision <current-revision> [--json]`

The conflict ID is the existing mutation idempotency key. The required revision
binds resolution to the exact current revision shown by `list`; if the local
base has moved or the stored conflict has changed, resolution fails closed.
The list projection includes only the conflict ID, entity type/id, expected and
current revisions, and current state (`present`, `deleted`, or `missing`).

`accept-remote` deletes the unresolved pending mutation and its deletion
predecessor. `keep-local` updates the pending mutation to the exact current
revision, increments the opaque record revision, preserves the encrypted
payload, and assigns a fresh locally generated idempotency key. Delete
predecessors are rebound to the current opaque predecessor transactionally.
Both paths write resolution metadata and are idempotent when retried with the
same conflict and strategy.

Production commands use the existing invocation-scoped unlock runner and
always relock/close resources. A persistent unresolved ledger row forces the
redacted status projection to report an error state; resolution itself does
not claim that synchronization succeeded. The user must run `creds sync` after
resolution.

## Merge boundary

The current canonical mutation schema contains complete encrypted group/item
records and exposes no decrypting merge port. Therefore no field-level merge
policy can be implemented safely in this issue. The CLI exposes only the two
schema-valid opaque policies above and rejects attempts to invent a plaintext
or fabricated merge. A future decrypting use case may add an explicit merge
policy without changing this ledger's revision and retry invariants.

## Verification

Focused coverage will prove: conflict persistence during reconciliation,
redacted listings, v3 migration, malformed/tampered rows, revision-bound
resolution, keep-local rebase, accept-remote removal, delete predecessor
handling, exact retry idempotency, restart durability, plaintext-canary
absence, and CLI JSON rendering. Affected package tests plus format, lint,
typecheck, build, and audit gates will run before the issue commit.
