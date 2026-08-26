# Changelog

All notable user-facing and security changes to Kavrix are recorded here.

## 0.2.2 - 2026-08-26

### Added

- The guided `init` storage selection is now an interactive Ink showcase:
  animated color-cycling brandmark and accents, a live spinner, highlighted
  option rows with descriptions, and the same key bindings as before
  (Up/Down or j/k to choose, Enter to confirm, Esc to go back, Ctrl+C to
  cancel). Terminals without a TTY keep the exact numbered line fallback, and
  non-color environments (NO_COLOR, dumb TERM) render without styling. The
  showcase ships as a lazily loaded bundle chunk, so non-interactive commands
  never pay for the Ink/React graph.

### Fixed

- The Windows-only database-container acceptance suite expected the retired
  generic "Database authentication failed." stderr for stale or tampered
  local snapshots; it now pins the shipped rollback classification
  ("The database snapshot was rejected as stale or forked.", exit 16) for an
  authentic stale anchor, a stale database document, and a tampered anchor,
  matching the error-mapping contract introduced in 0.2.1.
- Interactive init no longer loses keystrokes typed during showcase startup;
  terminal listeners attach before mounting and buffered input is replayed in
  order.

### Security and reliability

- The packed package allowlist now covers every bundled dependency of the
  showcase (Ink, React, and their reviewed runtime closure) with license
  inventory and SBOM components; the portable-key crypto graph must remain
  contiguous in exactly one compiled artifact.

## 0.2.1 - 2026-08-26

### Improved

- Minor performance improvements and a better CLI user experience: commands now
  explain their exact stdin frame contracts in `--help` (plus the new
  `kavrix frames <command>` reference), errors name their true cause instead of
  generic authentication or failure messages, and `kavrix status` reports the
  active datastore universe and selected profile.

### Added

- `kavrix db doctor health`: verifies the binding, every encrypted document,
  and the rollback anchor; `--accept-current` performs the only bounded repair
  for containers by fully authenticating the observed snapshot before
  re-anchoring local rollback protection. Datastore content is never modified,
  and unhealthy results exit nonzero.
- Multi-line and empty credential values through `put --value-stdin-base64`
  with byte-exact round trips.
- Owner-visible vault labels via an explicit `--show-labels` opt-in on
  `db vault list` and `db vault status`, redacted by default everywhere else.
- Glob-or-substring search matching with explicit case handling
  (`--case-sensitive`; insensitive by default).
- A share-key snapshot notice at `db key create` so recipients are warned that
  later database writes are invisible to previously distributed copies.

### Security and reliability

- Lock files record their owning process ID. After a hard kill, the next
  invocation detects a dead owner and removes its lock automatically while
  keeping live owners, foreign shapes, and replaced files fail-closed busy;
  removal re-verifies file identity immediately before unlinking.
- `run --grant` resolves grants in-session: bare grants inject under a derived
  environment variable, declared `env` mappings are honored, referenced
  credentials are verified before any use is consumed, and unmappable names
  fail closed without burning a use.
- Documented exit codes are honored globally (wrong passphrase `10`, missing
  credential or vault `11`, usage and frame mistakes `2`, invalid
  configuration `14`); duplicate, rename, remove, unknown-vault, and
  recovery-frame failures now report their real cause instead of
  "Database authentication failed."
- Vault and credential identifiers reject reserved prototype-polluting names
  consistently, and credential names refuse whitespace, control characters,
  slash abuse, and dot segments.
- Corrected project YAML documentation (policy placement under
  `environments.<name>.policies`), documented mandatory agent `env`
  permissions, TLS versus `--allow-insecure-transport` semantics, and the
  Windows `icacls /inheritance:r` sharing recipe.

### Verification

- Added end-to-end regression suites covering the external test report's
  findings: grant execution and consumption guarantees, exit-code mapping,
  multi-line base64 values, name validation, search semantics, reserved
  identifiers, owner labels, stale-lock recovery, and anchor repair.
- Format, lint, typecheck, build, unit/integration tests, and package-content
  checks pass on the release commit.

## 0.2.0

### Added

- Credential execution runtime (`kavrix run`): selected credentials are
  injected into a child process environment only, never into argv or shell
  history, with project-file environment mappings, exit-code and signal
  propagation, and redacted JSON output capture.
- Stored permission policies (`kavrix policy`) sealed in an
  AEAD-authenticated sidecar: command allowlists, SHA-256 executable pins,
  execution-window TTLs, working-directory restrictions, deny entries,
  reveal gating, and confirmation requirements evaluated fail-closed before a
  child spawns.
- Temporary consumable grants (`kavrix grant`) with TTL, maximum uses, atomic
  consumption under the protected-file lock, revocation, and distinct stable
  exit codes for expired, exhausted, revoked, and unknown references.
- Plaintext-free audit trail (`kavrix audit`) recording policy, grant,
  authorization, confirmation, and completion events.
- AI-agent credential firewall (`kavrix agent run` / `kavrix agent exec`):
  agents start with no credential material and request each operation through
  a per-session broker that enforces stored policies before injecting values.
- Guided interactive `init` onboarding with datastore selection, destination
  validation, masked secret handoff, and back/cancel navigation.

### Fixed

- Explicit standalone routing (`--datastore` without `--profile`) always uses
  the legacy single-vault path; an ambient current datastore profile no longer
  adopts such invocations into database-container mode.
- MongoDB connections materialize both collections eagerly so first-use
  transactions are race-free on empty deployments.

### Verification

- The test suite runs hermetically against isolated per-worker home
  directories, packed-CLI acceptance passes end to end on Windows, and the
  database-container acceptance continues to run in CI on Linux.

## 0.1.5 - 2026-08-21

### Fixed

- Kept guided initialization at the destination step after an invalid or unsafe
  vault/key path instead of restarting the entire onboarding flow.
- Reported why Kavrix could not establish the protected default key directory
  on Windows and distinguished that failure from an unsafe custom key path.
- Validated destination paths before beginning masked MongoDB URL and
  passphrase entry, so configuration errors are corrected beside the affected
  fields.

### Improved

- Replaced typed storage numbers with an interactive Up/Down and Enter selector,
  while retaining a line-input fallback for terminals without raw-mode support.
- Clarified that MongoDB URLs are entered through a masked prompt and that
  Atlas, replica-set, sharded-cluster, TLS, and `replicaSet` URL options are
  accepted without exposing connection credentials.
- Reduced repeated onboarding work after validation failures by preserving the
  selected datastore and returning directly to its destination fields.

### Verification

- Added regression coverage for destination-local retries, actionable Windows
  permission errors, terminal cleanup, and secret-safe onboarding output.
- Revalidated MongoDB URI policy, CLI coverage, strict type checking, linting,
  builds, and the installed packed-package allowlist.

## 0.1.4 - 2026-08-20

### Added

- Added a guided, step-by-step `kavrix init` experience for new users with a
  clear choice between an encrypted local file and MongoDB, protected local
  defaults, masked secret entry, recovery guidance, back/cancel controls, and
  actionable completion steps.
- Added secure one-directory provisioning for the default local vault and key
  files without mutating an existing parent directory's permissions.

### Security and reliability

- Hardened Windows initialization by inspecting inherited parent-directory
  permissions without rewriting them and by applying strict access controls only
  to Kavrix-owned files and directories.
- Made local-share replacement compare the exact encrypted key-file version
  under an exclusive lock using a one-shot transition token, preventing a stale
  session from overwriting a newer share.
- Bound encrypted vault-preference records to the canonical authenticated-data
  context instead of accepting record-supplied context values.
- Preserved protected files after ambiguous datastore, anchor, or publication
  failures so pathname replacement cannot redirect cleanup into an unrelated
  file.
- Tracked destructive datastore mutations and delayed success output until the
  datastore closes successfully.
- Enforced UTF-8 byte limits at schema boundaries and sanitized recursive JSON
  keys and values, failing closed when sanitized keys collide.

### Verification

- Expanded onboarding, publication-transition, filesystem-race, Windows ACL,
  schema-boundary, and storage-adapter regression coverage.
- Added active-release CI and package-hygiene checks, and removed stale
  changesets for features that are not part of the published CLI.

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
