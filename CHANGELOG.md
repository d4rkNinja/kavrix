# Changelog

All notable user-facing and security changes to Kavrix are recorded here.

## 0.1.3 - 2026-08-20

### Added

- Added encrypted multi-vault database containers backed by either a protected
  local file or MongoDB, while preserving the zero-knowledge boundary.
- Added bound datastore profiles with explicit per-command routing overrides and
  database-identity verification.
- Added database owner commands for initialization, status, vault creation,
  inspection and rename, local share keys, recovery kits, and recovery-based
  owner-key replacement.
- Added authenticated revision anchors that detect stale, rolled-back, or
  mismatched database state.
- Added copy-first migration from legacy local vaults into a database container,
  including post-copy verification and guarded rollback ownership.

### Security and reliability

- Made protected-file replacement more reliable on Windows while preserving
  strict user-only access controls.
- Retained exact file-object handles for owned key, recovery-kit, revision-anchor,
  and initialization rollback operations so pathname replacement or inode reuse
  cannot redirect cleanup into a foreign file.
- Treat datastore errors after a mutation begins as an ambiguous commit unless
  the adapter proves rejection, poisoning stale sessions and retaining recovery
  artifacts needed to reconcile the result.
- Sanitized database command output paths before terminal rendering.
- Restored Windows user-only ACL application and added protected Windows test
  fixtures without weakening production permission checks.
- Preserved explicit flat-command datastore, database, collection, data-file,
  and key-file overrides when a bound profile is selected.

### Verification

- Expanded release coverage for the encrypted database-container lifecycle,
  cross-platform filesystem races, Windows ACL behavior, packed-package smoke
  tests, and the supported Node.js runtime range.
