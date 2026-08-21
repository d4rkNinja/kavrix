# Implementation status

## Supported product

The supported product is the `kavrix` CLI in `apps/cli`. It persists one
authenticated encrypted database with multiple independently encrypted vaults
in a hardened local container or two MongoDB collections. Version 2 single-vault
documents remain supported through stable compatibility commands and explicit
copy-first migration. No Kavrix API server, sync daemon, SQLite cache, or
interactive Ink TUI is required or shipped.

Active release workspaces:

- `@kavrix/schemas`: canonical database-container, vault, legacy, and envelope schemas.
- `@kavrix/crypto`: DRK/VRK hierarchy, key derivation, wrapping, authenticated encryption, and secure-byte helpers.
- `@kavrix/key-files`: protected database-owner key, recovery-kit, legacy key, and revision-anchor files.
- `@kavrix/storage`: database-scoped local/MongoDB adapters and fail-closed URI/TLS policy.
- `kavrix`: CLI composition, masked input, sanitized rendering, and npm package.

The active-versus-parked source boundary and its verification commands are
recorded in [Active release boundary](active-release-boundary.md). The source
trees for the parked packages remain in the repository for incubation, but they
are not workspace members, release artifacts, or evidence for the active release.

## Implemented command surface

- guided interactive root `init` onboarding with arrow-key local-file or MongoDB
  selection, destination-local validation retries, protected user-data defaults,
  masked secret handoff, back/cancel navigation, and static recovery next steps;
  explicit and non-interactive init invocations retain their flag-driven behavior;
- protected non-secret datastore profile add/list/use/status/remove;
- file/MongoDB database initialization, authenticated status, and MongoDB ping;
- encrypted database vault create/list/status/rename;
- database-owner key status, whole-local-database share-key creation, and database recovery create/verify/status/revoke/use;
- explicit legacy version 2 migration into an existing or explicitly initialized local database;
- encrypted put/get/list/view/search/stats operations;
- explicit override and reveal controls;
- has, rename, remove, vault list, and vault status;
- protected key-file status, verify, copy, replicate, assign, and rewrap;
- recovery-kit create, verify, status, revoke, and use;
- authenticated `doctor` validation and fail-closed `doctor health` repair.

Run `kavrix <command> --help` for exact options. Planned or retired commands must
not be documented as available.

## Security properties

- plaintext labels, values, DRKs, VRKs, and unlock keys do not cross the storage boundary;
- database/catalog/wrapped-key AAD binds database and vault identity, purpose,
  versions, revision, and authenticated metadata digests;
- a DRK-authenticated local anchor rejects rollback, same-revision forks, and
  inconsistent catalog/vault heads before plaintext is returned;
- fresh local-share keys carry a protected one-use exact-snapshot bootstrap;
  owner anchors remain mandatory and recovery anchors advance only inside the
  authenticated recovery workflow;
- local publication is atomic and MongoDB multi-document publication requires transactions;
- remote MongoDB requires explicit validated TLS and insecure TLS flags are rejected;
- protected files use bounded formats, atomic creation, and permission checks;
- terminal output is sanitized and values are masked unless reveal is explicit.

## Verification boundary

The active release gate covers only the five workspaces listed above. Root
Vitest includes the active CLI, schema, crypto, key-file, and storage suites,
including the portable-key and revision-anchor security tests; its coverage
scope is restricted to those same five source trees. Parked package sources are
not counted as active release coverage and are not represented as shipped
features in this ledger.

The current verification commands and their platform limits are maintained in
[`docs/security-testing.md`](security-testing.md). A feature is not marked
verified here merely because source or tests exist in a parked package.

## Release gates

A release requires formatting, lint, strict typecheck, unit tests, build,
packed-install smoke, packed database-container acceptance on Windows/macOS/Linux,
package allowlist inspection, SBOM verification, dependency audit, exact-SHA CI
and CodeQL, and npm OIDC provenance. The repository's live MongoDB integration
test runs only when `KAVRIX_MONGODB_URI` points to a disposable transaction-capable
replica set. CI does not download or claim an unpinned MongoDB service. Windows
ACL evidence depends on the actual runner account and filesystem.

The verification result for a release belongs in its CI logs and GitHub release,
not as a permanently stale test count in this document.

## Known limits

MongoDB can observe opaque database/vault IDs, revisions, timestamps, ciphertext
sizes, and access patterns. A database operator can delete or withhold data. The
local revision anchor is fail-closed but is not remote tamper-proof storage. A
fresh local-share key trusts only the exact authenticated snapshot captured when
the key was created; after first use its companion anchor is mandatory.

User identities, public enrollment, recipient discovery, vault grants, reader/
editor/owner roles, revocation with VRK rotation, and ownership transfer are not
implemented. Environments, groups/services, structured items, and typed fields
are also deferred. Local-file mode has no fine-grained sharing: sharing its data
file and a freshly generated matching share key grants full database access once
unlocked.

Kavrix does not protect an unlocked host from administrators, same-user malware,
keyloggers, screen/terminal/clipboard capture, process-memory inspection, swap, or
crash dumps. JavaScript cannot guarantee complete zeroization. Losing all valid
key files and recovery kits is unrecoverable by design.
