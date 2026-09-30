# Release notes — 0.2.21 Windows heal / doctor guard

Fixes the 0.2.20 Windows live-QA failure where `kavrix init` (TUI, step 12)
failed with "The portable key file or its parent directory is not safe to
use; harden parent permissions to mode 700 (or run
`kavrix doctor health --heal`)" and the documented remedy
`kavrix doctor health --heal` itself crashed with "The local vault file is
invalid or unsafe." (exit 15) instead of producing its JSON report.

Root cause: an existing `~/.kavrix` created before strict ACLs kept the ACEs
inherited from the Windows profile directory (a write-granting ACE for an
orphan/unresolvable SID is common on real machines), so strict parent
verification failed for portable-key writes and `FileLocalVaultStore` target
validation. Nothing in init or doctor repaired that state: heal only hardened
parents of existing key/data artifacts, and the doctor's legacy path called
`FileLocalVaultStore.validatePath` unguarded before its guarded section.

Changes, all fail-closed (the ACL verifier itself is unchanged):

- `doctor health --heal` (and `db doctor health --heal`) hardens the
  kavrix-owned artifact home (`~/.kavrix`) and its existing `config.toml`
  (action ids `kavrix-dir-acl`, `kavrix-config-file-acl`) even when no
  key/data artifact exists yet; report/dry-run list them as manual/planned
  without changes. Directories Kavrix does not own (the home directory
  itself, filesystem roots) are still refused by the existing broad-root
  guard.
- TUI `create-file-profile` / `create-mongodb-profile` hardens an existing
  kavrix artifact home before artifact writes (idempotent when already
  strict); operator-chosen non-Kavrix parents keep the old behavior.
- `ensureKavrixConfig` (classic init) hardens and re-verifies an unsafe
  existing Kavrix home or `config.toml` once; foreign-owned targets still
  fail closed.
- `doctor health` guards the legacy file-datastore validation: an
  unopenable/unvalidatable datastore becomes a `database` manual-recovery
  check inside the JSON report (exit 16) instead of an uncaught
  `FileLocalVaultError` (exit 15). The report still records what heal
  repaired.

Verified by `apps/cli/test/doctor-heal.test.ts` (new: kavrix-home heal,
report-mode no-op, unopenable-legacy-store guard with fake-HOME
isolation) and `apps/cli/test/tui-session.test.ts` (new: existing unsafe
kavrix home is hardened before `create-file-profile` writes; win32 runs
the real ACL path).
