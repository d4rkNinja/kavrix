# Reliability audit: 2026-10-25

Status: local validation and native OS test suites passed. Final CI acceptance
status is tracked in [PR #173](https://github.com/d4rkNinja/kavrix/pull/173/checks).
This audit is not a release or a guarantee about every terminal environment.

## Implemented fixes

- TUI credential and action searches retain typed `j` and `k`. Arrow keys move
  through search results; ordinary list navigation retains `j/k` shortcuts.
- The action palette accepts bracketed paste. Highlighting and mouse activation
  use the same filtered row indexes as keyboard activation. Nested action chips
  activate their displayed command instead of inserting its shortcut into the
  search. Reveal still requires confirmation.
- Native clipboard helpers handle stdin errors and stop after five seconds per
  backend. Errors exclude copied values. Windows PowerShell reads the UTF-8 stdin
  bytes using an explicit UTF-8 decoder. Helpers receive values through stdin,
  with shell execution disabled and Windows helper windows hidden.
- Executable lookup resolves relative PATH entries against the requested child
  working directory and checks POSIX execute permission. Canonical Windows script
  targets remain refused when reached through a symlink.
- The runner checks cancellation immediately before spawning. Lifecycle listeners
  are installed before invoking `onSpawn`; a throwing callback causes immediate
  child termination and a generic error after child closure.
- Local `.tmp` artifacts are excluded from lint and formatting, consistently with
  the existing Git exclusion. Product source remains covered by both checks.
- Full and acceptance-only verification always run packed database-container
  acceptance. Its file-datastore journey needs no Docker service; the former
  Docker availability check incorrectly skipped this gate on Docker-free hosts.
- Zod is pinned to 4.6.6 for the bounded-collection validation fix
  ([GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5)).
  The canonical vault-list regression rejects an oversized list with one size
  issue instead of accumulating an issue for every invalid element.
- Vitest and its coverage provider are pinned to 4.1.12, covering the development
  mocker advisories
  [GHSA-qxg6-89mg-rqv8](https://github.com/advisories/GHSA-qxg6-89mg-rqv8) and
  [GHSA-xp26-3454-mjgp](https://github.com/advisories/GHSA-xp26-3454-mjgp).
  Lockfile integrity pins and dependency-age restrictions remain enforced; these
  versions are old enough to satisfy the existing seven-day minimum.

## Verification

Regression tests live beside the affected code:

- `packages/runner/test/runner.test.ts`
- `apps/cli/test/execution-executable.test.ts`
- `apps/cli/test/tui-clipboard.test.ts`
- `packages/tui/test/app/credential-filter.test.ts`
- `packages/tui/test/command-palette.test.ts`
- `packages/tui/test/app/interaction-regressions.test.ts`
- `packages/schemas/test/collection-bounds.test.ts`

The mounted Ink regression exercises bracketed paste and a mouse click on a
filtered Reveal action, checking that confirmation opens without dispatching a
secret release. This uses synthetic terminal streams, not a physical terminal.

On Windows with Node 26.10.0, the complete test/coverage run passed: 2,239 tests
passed and 27 were skipped across 184 files. Coverage passed the unchanged
thresholds: statements 86.84%, branches 80.09%, functions 91.09%, lines 88.41%.
The native CLI-backed TUI CRUD and legacy-vault upgrade journeys passed, including
preservation of the existing encrypted vault and key bytes during unlock.

An additional Windows Node 24.12.0 run covered all TUI tests, the runner,
clipboard, package checks, and real CLI-backed TUI CRUD/upgrade journeys:
568 tests passed and one service-dependent test was skipped across 42 files.

The workspace build, type checks, lint, formatting, installed packed CLI smoke
check, and packed all-command local-file acceptance passed. Production and full
dependency audits report no known vulnerabilities. A frozen-lockfile policy check
also passed without new dependency-age exceptions.

A Windows storage retry test failed once in the initial exploratory run. Its
isolated test, complete file, and final full-suite run passed without changing
the implementation or weakening its assertions. The original intermittent
failure was not reproduced; no storage fix is claimed for that observation.

After merging the current base, commit `f057a81` passed 575 focused local tests
and the native Linux x64 and macOS arm64 full suites (2,252 passed and 16
service/platform-gated skips each). All four Windows x64 test shards passed.
CodeQL, dependency review/audit, package contents, active-source coverage, static
checks, Linux packed-CLI runtime checks, and the real MongoDB setup probe passed.
The PR checks link records the remaining packed Windows acceptance result.

The database-container acceptance command also passed directly on the local
Docker-free Windows host. The corrected verifier's `--acceptance-only` flow
then passed database-container acceptance, all-command acceptance, and package
smoke without a Docker installation. A native PowerShell probe confirmed the production
UTF-8 stdin decoder preserves Japanese text, Greek characters, and emoji, using
an output sink without accessing the clipboard.

## Outstanding platform evidence and limits

- Native macOS/Linux execution is unavailable on this Windows host. CI supplied
  the native Linux/macOS evidence above, including the POSIX permission and
  symlink regressions; it does not prove every OS version or architecture.
- Clipboard backend selection and failure handling have unit coverage for all
  three OS families. This is not evidence of native clipboard interoperability on
  each OS or terminal support for OSC 52. OSC 52 clearing remains best effort;
  native clipboard automatic clearing remains unavailable.
- File-based and MongoDB journeys require their respective integration evidence.
  Simulated adapters do not establish real MongoDB interoperability.
- Existing process-boundary limits remain: the runner is not a sandbox, child
  descendants can outlive the direct child, and executable hashing cannot close
  the platform race between validation and execution.
