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

## Implemented command surface

- protected non-secret datastore profile add/list/use/status/remove;
- file/MongoDB database initialization, authenticated status, and MongoDB ping;
- encrypted database vault create/list/status/rename;
- database-owner key status and database recovery create/verify/status/revoke/use;
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
- local publication is atomic and MongoDB multi-document publication requires transactions;
- remote MongoDB requires explicit validated TLS and insecure TLS flags are rejected;
- protected files use bounded formats, atomic creation, and permission checks;
- terminal output is sanitized and values are masked unless reveal is explicit.

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
local revision anchor is fail-closed but is not remote tamper-proof storage.

User identities, public enrollment, recipient discovery, vault grants, reader/
editor/owner roles, revocation with VRK rotation, and ownership transfer are not
implemented. Environments, groups/services, structured items, and typed fields
are also deferred. Local-file mode has no fine-grained sharing: sharing its data
file and matching owner key grants full database access once unlocked.

Kavrix does not protect an unlocked host from administrators, same-user malware,
keyloggers, screen/terminal/clipboard capture, process-memory inspection, swap, or
crash dumps. JavaScript cannot guarantee complete zeroization. Losing all valid
key files and recovery kits is unrecoverable by design.
