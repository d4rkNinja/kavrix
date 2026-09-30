# Release notes — 0.2.20 QA / TUI / CLI

Branch `fix/0.2.20-qa-and-tui-release` records 0.2.20 live-QA outcomes that
have fixture or filtered CLI evidence. Cited suites verify only the rows
that name them. This record does not claim live-desktop Jr/Mid/Senior
verified.

CLI P1/P2 evidence:
`apps/cli/test/live-qa-p1-0.2.20.test.ts`,
`apps/cli/test/launch-routing-guards.test.ts` (filtered `--no-config` help
case; full-file hang is recorded below),
`apps/cli/test/execution-render.test.ts` (`reportJsonFailure` envelope),
`apps/cli/test/doctor-heal.test.ts` (7 passed, 16 skipped, 96.65s on
win32; `os.tmpdir` + `realpath`; no chmod 0555 on Windows; POSIX 755/777
branches live in the same file but were not executed here), and
`apps/cli/test/report-regressions.test.ts` (27 passed, 2 files);
`apps/cli/test/local-secrets.test.ts` (38 passed);
`packages/schemas/test/policy.test.ts` plus `local-secrets.test.ts`
(89 passed together; focused P2 subset 8 passed);
`apps/cli/test/execution-exit-codes.test.ts` (2 passed);
`packages/runner/test/runner.test.ts` (51 passed). Filtered pass covering
`--no-config` help (`Skip project configuration:`), spawn-miss
`EXECUTION_FAILED` / exit 18 via a portable `os.tmpdir()` path,
unresolvable executable, and protected `USER` destination.

Limitation: full-file runs of `launch-routing-guards.test.ts`,
`execution-guards.test.ts`, and `execution-run.test.ts` hang because
in-process `runCli` never returns. Those hangs are not assertion failures.
The MongoDB ambient-profile guard is untested end-to-end.

Remaining hole: broker `agent exec` child-start still maps spawn failure to
`deny('invalid-request')`. That is not the public `run --json`
`EXECUTION_FAILED` path.

Onboarding fixture evidence:
`packages/tui/test/app/onboarding-router.test.ts` and
`packages/tui/test/app/onboarding-paint.test.ts` (20 passed, 2 files;
`onboarding-app.tsx`, `onboarding-router.ts`). Onboarding cases were
dropped from `first-paint.test.ts`.

Vault-shell fixture evidence:
`packages/tui/test/app/first-paint.test.ts` and
`packages/tui/test/app/router.test.ts` (58 passed).

CI hygiene only (not live-desktop): `packages/tui/test/motion.test.ts`
(8 passed; `motion.ts` 100% branches).

## P0

- Init onboarding blank/stuck: **verified** by the onboarding-router and
  onboarding-paint suites. Content-sized chrome, first-paint kick, hydrate
  Loading/timeout, and redraw after step/input; no stale Storage/Key-file
  frames; passphrase/recovery finish. Live-desktop Jr/Mid/Senior proof is
  not recorded.
- Mid TUI blank: **verified** by the first-paint and router suites.
  `ensureTtySize` uses 80×24 on a 0×0 TTY and paints Loading / home /
  Hydrate failed, never a blank frame. Live Mid-class desktop remains
  unproven.

## P1

- `run --json` with a wrong passphrase: **verified** by
  `live-qa-p1-0.2.20.test.ts` and `report-regressions.test.ts`. JSON
  `AUTHENTICATION_FAILED` envelope on stdout, exit 10 (not empty stdout).
- Vault-read `--json` (`list` / `get` / `has` / `search`) with a wrong
  passphrase: **verified** by `live-qa-p1-0.2.20.test.ts`,
  `launch-routing-guards.test.ts`, and `execution-render.test.ts`. Same
  `AUTHENTICATION_FAILED` envelope as `run --json` on stdout, exit 10, no
  passphrase leak, no human stderr duplicate.
- `--environment` without a project file: **verified** by
  `live-qa-p1-0.2.20.test.ts`; fail-closed (not silently ignored).
- `--no-config` combined with `--environment` fail-closes (exit 14 /
  `INVALID_CONFIGURATION` JSON when `--json`). Help description starts with
  `Skip project configuration:`. **Verified** by `live-qa-p1-0.2.20.test.ts`,
  `launch-routing-guards.test.ts`, and `execution-render.test.ts`.
- Pure `--secret` runs ignore a broken cwd `kavrix.yaml`; `--no-config` is
  documented to force that. **Verified** by `live-qa-p1-0.2.20.test.ts`.
- `put` with only `--passphrase-stdin` names `Missing --value-stdin`.
  **Verified** by `live-qa-p1-0.2.20.test.ts`.
- Onboarding focus: **verified** by the onboarding-router and
  onboarding-paint suites (`ACTIVE n/m` banner). Live-desktop is not
  verified.
- Recovery kit labeled separately from Doctor/heal: **verified** by the
  first-paint and router suites.
- Credentials Enter opens masked `credential-detail`; footer advertises
  Enter/open and Enter/detail. REVEAL is `r` then `y`; copy never paints
  plaintext; tick expiry remasks. **Verified** by the first-paint and
  router suites. Live-desktop Jr/Mid/Senior re-verify is not claimed.
- `doctor --heal` hardens only existing key/data parents via key-files
  `hardenExistingSecureDirectory` / `hardenExistingSecureFile` (Windows
  DACL + Unix 700/600). A project-root `--config-dir` is left alone;
  owned secret parents still repair; an unsafe project-root registry
  fail-closes without rewriting that directory. **Windows-verified** by
  `apps/cli/test/doctor-heal.test.ts` (7 passed, 16 skipped, 96.65s on
  win32; `os.tmpdir()` + `realpath`; no chmod 0555 on Windows). POSIX
  755/777 branches in that file were not run on this machine; darwin/linux
  CI must cover them. A stale `@kavrix/key-files` dist was rebuilt so the
  helper is exported. Not live-desktop verified.

## P2

- `run` documents `--` as recommended, not required, when the child has no
  option-like arguments. **Verified** by `live-qa-p1-0.2.20.test.ts`.
- `--json` failures keep the machine envelope on stdout only (no duplicate
  human stderr). **Verified** by `live-qa-p1-0.2.20.test.ts`.
- Missing child executable: `EXECUTION_FAILED` / exit 18 (not authorization
  denied). Spawn-miss uses a portable `os.tmpdir()` path, not a host
  `/tmp` hardcode. **Verified** by `live-qa-p1-0.2.20.test.ts`,
  `execution-exit-codes.test.ts`, and `packages/runner/test/runner.test.ts`
  (filtered spawn / unresolvable-exe pass).
- `status` reports `unconfigured` plus the resolved config directory instead
  of a silent `legacy-v2` when no registry exists. **Verified** by
  `report-regressions.test.ts`.
- Short wrong unlock/run passphrase: authentication failure (exit 10), not
  length usage (exit 2). **Verified** by `live-qa-p1-0.2.20.test.ts` and
  `local-secrets.test.ts` (short unlock reaches authentication).
- `--secret` destinations `USER`, `USERNAME`, and `LOGNAME` fail closed as
  reserved inherited names. **Verified** by `live-qa-p1-0.2.20.test.ts`
  (filtered protected `USER` dest).
- Narrow-terminal footer prioritizes Enter/detail, Esc, and quit, with a
  `+N more` overflow: **verified** by the first-paint and router suites.
- Large credential lists use a bounded window plus `/` search (400-row
  filter fixture): **verified** by the first-paint and router suites.
  Live-desktop scroll/search measurement is not recorded.
- Reveal Escape remasks, then a later Escape returns home: **verified** by
  the first-paint and router suites. Live-desktop Mid-class proof is not
  claimed.
- Vault context/environment naming is distinct from CLI `run --environment`:
  **verified** by the first-paint and router suites.
- Opaque `kavrix.yaml` with a flat environment object (no `secrets` map):
  missing-`secrets`-map message, exit 14 `INVALID_CONFIGURATION`, values
  not echoed, same on win32/darwin/linux. LF and CRLF fixtures under
  `os.tmpdir()`. **Verified** by `packages/schemas/test/policy.test.ts`
  and `apps/cli/test/execution-project-config.test.ts`.
- Swapped `put --passphrase-stdin --value-stdin` frames (value then
  passphrase): `Secret input frames are in the wrong order.`, exit 2;
  not a 16-byte passphrase check. Create pairs still require 16 bytes.
  LF and CRLF frames. Same message/exit on win32/darwin/linux.
  **Verified** by `apps/cli/test/local-secrets.test.ts`.
- Optional `/` and emoji credential names: no schema change; the existing
  policy already allows them (slash-separated references asserted;
  control characters still rejected). **Verified** unchanged by
  `packages/schemas/test/policy.test.ts`.

## CI / release blockers — remaining

- Live-desktop Jr/Mid/Senior TUI proof is not recorded. Fixture suites
  cited above are not a live-desktop close.
- Full-file hangs remain for `launch-routing-guards.test.ts`,
  `execution-guards.test.ts`, and `execution-run.test.ts` (in-process
  `runCli` never returns). Those hangs are not assertion failures.
- Broker `agent exec` child-start still maps spawn failure to
  `deny('invalid-request')`. That is not the public `run --json`
  `EXECUTION_FAILED` path.
- Heal POSIX 755/777 branches were not run on this Windows machine;
  darwin/linux CI must cover them.
- `#162` and `#156` remain unmerged on purpose.
- 0.2.20 is not on npm until an authorized publish. This ledger does not
  claim an npm 0.2.20 release.
- Publish integrity-wait flake after a package is already on npm is process
  debt, not a product-gate pass. This branch hardens the wait against
  transient `npm view` failures; it is not an npm publication.
- `packages/tui/test/motion.test.ts` (8 passed) is CI branch-coverage
  hygiene only, not live-desktop evidence.
