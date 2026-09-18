# Kavrix TUI Test Report

Date: 2026-09-18 (Asia/Calcutta)
Branch: `feature/full-interactive-tui`
Scope: Full interactive Ink app in `@kavrix/tui` + `kavrix tui|ui` CLI wiring,
including in-TUI credential mutations and **create-file-profile** from the Profiles screen.

## Build / automation

| Check | Result |
| --- | --- |
| `pnpm --filter @kavrix/tui build` | PASS |
| `pnpm --filter @kavrix/tui test` | PASS (66 tests) |
| `pnpm --filter kavrix build` | PASS |
| `vitest` `apps/cli/test/tui-session.test.ts` | PASS (2 tests, mocked spawn frames) |
| `kavrix tui --help` | PASS |
| `kavrix ui --help` (alias) | PASS |
| `kavrix tui` on non-TTY | PASS (clear error, exit 1) |
| `node scripts/tui-smoke.mjs` | PASS (12 screens) |
| `node scripts/tui-vault-smoke.mjs` | PASS (temp HOME vault mutations via CliTuiSession) |

## Screens

| Screen | Linux TTY color | ASCII mode | NO_COLOR | Windows path assumptions | Notes |
| --- | --- | --- | --- | --- | --- |
| Home / dashboard | PASS | PASS | PASS | PASS | Colorful banner + menu; `BrandBanner` shared |
| Profiles | PASS | PASS | PASS | PASS | Enter = use-profile; `n` = create-file-profile |
| Vaults | PASS | PASS | PASS | PASS | Selection + status from session |
| Credentials (masked) | PASS | PASS | PASS | PASS | Masked by default |
| Credentials (REVEAL) | PASS | PASS | PASS | PASS | Confirm overlay required; 15s clear |
| Credentials (put/rename/remove) | PASS | PASS | PASS | PASS | `n` put, `m` rename, `x` confirm-remove; stdin frames only |
| Doctor | PASS | PASS | PASS | PASS | `d` refreshes; unlock gated |
| Recovery | PASS | PASS | PASS | PASS | Loads `db recovery status` / legacy `recovery status` into snapshot.recovery |
| Run | PASS | PASS | PASS | PASS | Dry preview only; no argv secrets |
| Policy / Grant / Audit | PASS | PASS | PASS | PASS | List + refresh; mutations CLI-gated |
| Agent | PASS | PASS | PASS | PASS | Dry-run status only |
| Context / Service / Item | PASS | PASS | PASS | PASS | Browse rows from session metadata |
| Help / keymap | PASS | PASS | PASS | PASS | Includes Profiles `n` create + put/rename/remove keys |
| Storage showcase dest. | PASS | PASS | PASS | PASS | Existing presentational showcase retained |

Legend: render + router navigation covered by vitest (`packages/tui/test/app/router.test.ts`). ASCII / NO_COLOR / win32 defaults covered by `resolveAppPresentation` tests and home/credentials/profiles ASCII snapshots.

## win32 presentation assumptions

| Assumption | Behavior | Covered by |
| --- | --- | --- |
| `process.platform === 'win32'` | ASCII borders/glyphs default on (same as `--ascii`) | `resolveAppPresentation({ platform: 'win32' })` |
| Explicit `--ascii` | Forces ASCII even on UTF-capable Unix terminals | `resolveAppPresentation({ ascii: true })` |
| `NO_COLOR` / `noColor: true` / `TERM=dumb` | Color disabled | presentation unit tests |
| Path construction | Defaults use `node:path.join` / `path.sep` (no bashisms) | `defaultFileProfilePaths` + `pathSeparator()` tests |
| Default file profile paths | `~/.local/share/kavrix/<id>/db.kavrix` and `owner.key` via `join(homedir(), …)` | router create-profile overlay + paths helper |

On Windows hosts, `path.sep` is `\\`; the TUI never concatenates paths with `/` literals for profile files.

## Security checks exercised

- Secrets never rendered unless REVEAL confirm (`y`) succeeds.
- Passphrase and put-value entry use masked overlays (`****`); not written into `AppSnapshot`.
- Create-file-profile holds passphrase only in ephemeral router state across confirm, then clears it.
- Put/rename/remove and create-file-profile spawn CLI with secrets on stdin frames only; never argv.
- `sanitizeTerminalText` used for all user-facing strings.
- CLI host avoids static Ink import (lazy `import('@kavrix/tui')`).

## Frames contracts verified

```text
kavrix put     → [mongodb-url,] passphrase, value   (--passphrase-stdin --value-stdin)
kavrix rename  → [mongodb-url,] passphrase          (--passphrase-stdin)
kavrix remove  → [mongodb-url,] passphrase          (--passphrase-stdin)
kavrix recovery status     → (none)
kavrix db recovery status  → [mongodb-url,] passphrase
kavrix db init             → [mongodb-url,] label, passphrase, passphrase-confirm
kavrix db vault create     → [mongodb-url,] passphrase, label
kavrix db vault use        → [mongodb-url,] passphrase
kavrix db profile add|use  → (none; paths on argv only)
```

Create-file-profile sequence (matches `scripts/tui-vault-smoke.ts`):
`db profile add` → `db profile use` → `db init` → `db vault create` → `db vault use` → session unlock.

## Profiles screen keys / flows

| Key | Action |
| --- | --- |
| `j` / `k` / arrows | Move selection |
| Enter | `use-profile` for the highlighted row |
| `n` | Create file profile: id → data file (default) → key file (default) → passphrase → confirm → backend `create-file-profile` |
| Esc | Back to Home (or cancel overlay) |
| `a` | Toggle ASCII (global) |
| `q` | Quit (global) |

## Test counts

| Suite | Tests |
| --- | --- |
| `packages/tui/test` | 66 |
| `apps/cli/test/tui-session.test.ts` | 2 |
| `scripts/tui-smoke.mjs` | 12 screens |
| `scripts/tui-vault-smoke.mjs` | ALL PASS |

## Remaining gaps

1. **Recovery create/verify/revoke / policy mutations / MongoDB profile create** remain CLI-gated (navigable + message-gated in TUI).
2. **Interactive TTY color paint** validated via unit render helpers (`TERM=dumb`); full human TTY session not driven in CI.
3. **Structured vault projection** browse is metadata-level until a projection library adapter is deepened.
4. Create-file-profile is file-datastore only (no MongoDB URL frames from TUI).

## Commands used

```bash
pnpm --filter @kavrix/tui build
pnpm --filter @kavrix/tui test
pnpm --filter kavrix build
node apps/cli/dist/bin.js frames put
node apps/cli/dist/bin.js frames "db init"
node apps/cli/dist/bin.js tui --help
node scripts/tui-smoke.mjs
node scripts/tui-vault-smoke.mjs
```
