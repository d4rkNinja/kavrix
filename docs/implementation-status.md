# Implementation status

## Supported product

The supported product is the `kavrix` CLI in `apps/cli`. It connects directly to
MongoDB and persists one authenticated encrypted local-vault version 2 document
per vault. No Kavrix API server, sync daemon, SQLite cache, or interactive Ink
TUI is required or shipped.

Active release workspaces:

- `@kavrix/schemas`: canonical local-vault and envelope schemas.
- `@kavrix/crypto`: key derivation, wrapping, authenticated encryption, and secure-byte helpers.
- `@kavrix/key-files`: protected portable-key, recovery-kit, and revision-anchor files.
- `@kavrix/storage`: direct MongoDB adapter and fail-closed URI/TLS policy.
- `kavrix`: CLI composition, masked input, sanitized rendering, and npm package.

## Implemented command surface

- database ping and vault initialization;
- encrypted put/get/list/view/search/stats operations;
- explicit override and reveal controls;
- has, rename, remove, vault list, and vault status;
- protected key-file status, verify, copy, replicate, assign, and rewrap;
- recovery-kit create, verify, status, revoke, and use;
- authenticated `doctor` validation and fail-closed `doctor health` repair.

Run `kavrix <command> --help` for exact options. Planned or retired commands must
not be documented as available.

## Security properties

- plaintext values and unlock keys do not cross the MongoDB storage boundary;
- payload AAD binds vault identity, versions, revision, and a recomputed digest of
  portable/recovery-slot metadata;
- a root-key-authenticated local anchor rejects lower revisions and same-revision
  forks before plaintext is returned;
- remote MongoDB requires explicit validated TLS and insecure TLS flags are rejected;
- protected files use bounded formats, atomic creation, and permission checks;
- terminal output is sanitized and values are masked unless reveal is explicit.

## Release gates

A release requires formatting, lint, strict typecheck, unit tests, build,
packed-install smoke, package allowlist inspection, SBOM verification, dependency
audit, exact-SHA CI and CodeQL, and npm OIDC provenance. A real MongoDB integration
run requires a disposable replica-set URI. Windows ACL evidence depends on the
actual runner account and filesystem.

The verification result for a release belongs in its CI logs and GitHub release,
not as a permanently stale test count in this document.

## Known limits

MongoDB can observe vault IDs, revisions, timestamps, ciphertext sizes, and access
patterns. A database operator can delete or withhold data. The local revision
anchor is fail-closed but is not remote tamper-proof storage; accepting a missing
anchor is an explicit operator trust decision.

Kavrix does not protect an unlocked host from administrators, same-user malware,
keyloggers, screen/terminal/clipboard capture, process-memory inspection, swap, or
crash dumps. JavaScript cannot guarantee complete zeroization. Losing all valid
key files and recovery kits is unrecoverable by design.
