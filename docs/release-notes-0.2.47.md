# Release notes — 0.2.47

This patch increments the checkout's 0.2.46 version by 0.0.1. Publication
requires exact-commit CI and CodeQL followed by trusted publishing, as
described in [the release procedure](release.md).

## New commands

- `kavrix export --file <path>` seals the flat credentials of the selected
  database vault into a passphrase-protected archive
  (XChaCha20-Poly1305, Argon2id, authenticated header). `--prefix` limits the
  selection. Values are never printed. See the
  [command guide](cli-reference.md#17-encrypted-export-and-archive-import).
- `kavrix import archive --file <path>` authenticates an export archive and
  imports it in one atomic vault update, optionally under `--prefix`.
  Existing names require `--overwrite`.
- `kavrix generate [name]` creates a random password, hex, or base64url secret
  with rejection sampling and a per-class guarantee. With a name it is stored
  without display; without a name `--reveal` prints it. See the
  [command guide](cli-reference.md#18-generate-a-secret).

Exports cover the root compatibility credentials only. Structured fields,
notes, policies, grants, and audit records are not exported.

## Fixes and hardening

- The `SessionUnlockError`, `PortableKeyFileError`, `DatabaseMigrationError`,
  and Commander usage exit-code mappings now derive from the canonical
  `CLI_EXIT_CODES` table instead of repeating literal numbers. Exit codes are
  unchanged.
- Backup and export files larger than one secure-stream chunk are now written
  in bounded chunks. Previously, a protected file above 32 MiB could fail to
  publish.
- The secretstream state cleanup validates the shape of libsodium's runtime
  heap before wiping. A new contract test pins `libsodium-wrappers` 0.8.4 and
  fails loudly if the private WASM API that cleanup relies on changes.
- The unused second copy of the collaboration policy in `@kavrix/core` was
  removed. `@kavrix/core` now hosts the secret generator used by
  `kavrix generate`.
- The unused HTTP API wire schemas were removed from `@kavrix/schemas`. The
  remaining sync contracts are marked reserved; only the tombstone record is
  used (by backups).
- Root test discovery now uses globs for the key-file and storage suites, so a
  new test file there can no longer be silently excluded. A dead test that
  imported the retired keychain package was removed.
- Property-based tests (fast-check) now cover canonical AAD injectivity, the
  export envelope, `.env` parsing, and the generator.
- A pnpm override pins the development-only `vite` (via vitest) at 8.2.4 or
  newer, resolving GHSA-587h-7wmj-h5pm. No shipped dependency changed.
- `.gitignore` excludes `*.kavrix-export` archives and a stray `Microsoft/`
  PowerShell cache folder.

## Verification status

Windows local verification passed build, formatting, lint, type checking, CLI
source inclusion, the full unit/integration suite with coverage, packed
all-command local-file acceptance, and the note/history executable smoke.
Coverage includes 2,202 passing tests and 25 skipped tests: 86.86% statements,
80.09% branches, 91.11% functions, and 88.43% lines. The skipped count rose
from 21 because the environment-gated MongoDB integration suites are now
discovered by the default run; they still skip without a live replica set.
Skipped tests are not verification evidence. No gate or coverage threshold was
reduced. Database-container acceptance, the dependency audit, and packed
allowlist/SBOM inspection were not rerun for this change set.

No existing encryption format, authorization policy, or reveal requirement
changes. The export archive is a new, versioned format
(`kavrix-vault-export` version 1). Local Windows evidence does not establish
Linux, macOS, or live MongoDB verification; the release CI must supply its own
platform evidence.
