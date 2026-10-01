# Release notes — 0.2.31 one brand: Kavrix

A truth release: the product is Kavrix and everything that ships says so.
This release removes the last traces of the pre-rename product identity
("CredVault" / `creds`) from every user-visible surface, aligns the
engineering guides with the workspace that actually exists, and deletes
dead legacy trees from the repository. No cryptographic, storage, policy,
or authorization behavior changed.

## What ships

- The interactive TUI now renders `kavrix` as the product label everywhere:
  the header screen model, the home "product" status pill, and the
  onboarding "product" row previously fell back to the retired
  "CredVault" label because no caller ever overrode the default. The
  unused product-identity override machinery is gone; the labels are
  single constants (`PRODUCT_LABEL`, `EXECUTABLE_NAME`).
- TUI copy that used `creds` as shorthand now says "credentials" (run
  preview title, home credential-count pill, run-screen footer hint).
- The root, `apps/`, and `packages/` engineering guides (AGENTS.md) now
  describe the real eight-package workspace, name `kavrix` as the product
  and executable, mark the legacy unworked directories as pending removal,
  and state plainly that there is no `apps/api` and no hosted service.
- Repository truth reset:
  - Deleted the six legacy directories that were never part of the pnpm
    workspace and are imported by nothing that ships: `packages/client`,
    `packages/sync`, `packages/keychain`, `packages/clipboard`,
    `packages/import-export`, `packages/local-store` (~43k lines). Git
    history preserves them.
  - Deleted the never-wired platform test lane
    (`vitest.platform.config.ts`, `scripts/platform-acceptance.*`) whose
    subjects no longer exist.
  - Deleted the collaboration-era planning documents
    (`docs/superpowers/`) and the four stale root session reports
    (`FIX-SUMMARY.md`, `TUI-RELEASE-GATE.md`, `TUI-TEST-REPORT.md`,
    `UI-ENHANCEMENT.md`).
  - `CHANGELOG.md` now points at the per-release notes instead of a
    ledger that had been frozen since 0.2.9.
  - Test wiring no longer enumerates CLI suites by hand: `apps/cli/test`
    runs as a glob, a dead entry for a deleted debug suite is gone, and
    lint ignores no longer list files deleted in August.

## Deliberately unchanged

- The versioned portable-key format prefix (`cvk1_`,
  `packages/crypto/src/keys.ts`) is a serialized format identifier, not a
  display string. Renaming it would strand every existing portable key
  file; it changes only through a real format migration.
- The demo recording assets under `docs/assets/` predate the rename and
  show a `creds:` status pill from the old build; the recording itself is
  historical footage. They will be refreshed in a future documentation
  pass.

## Verification

The full TUI suite passes with label assertions updated to `kavrix`
(including a new guard that the product constants are `kavrix`), the root
`pnpm verify` gate passes on the slimmed workspace, and no tracked file
outside `docs/assets/` and the `cvk1_` format prefix contains the retired
brand.
