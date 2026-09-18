# Kavrix TUI Test Report

Date: 2026-09-18 (Asia/Calcutta)
Branch: `feature/full-interactive-tui`
Scope: Full interactive Ink app in `@kavrix/tui` + `kavrix tui|ui` CLI wiring,
including in-TUI credential mutations (put/rename/remove) and recovery status.

## Build / automation

| Check | Result |
| --- | --- |
| `pnpm --filter @kavrix/tui build` | PASS |
| `pnpm --filter @kavrix/tui test` | PASS (60 tests) |
| `pnpm --filter kavrix build` | PASS |
| `vitest` `apps/cli/test/tui-session.test.ts` | PASS (mocked spawn frames) |
| `kavrix tui --help` | PASS |
| `kavrix ui --help` (alias) | PASS |
| `kavrix tui` on non-TTY | PASS (clear error, exit 1) |
| `node scripts/tui-smoke.mjs` | PASS (12 screens) |
| `node scripts/tui-vault-smoke.mjs` | PASS (temp HOME vault mutations via CliTuiSession) |

## Screens

| Screen | Linux TTY color | ASCII mode | NO_COLOR | Windows path assumptions | Notes |
| --- | --- | --- | --- | --- | --- |
| Home / dashboard | PASS | PASS | PASS | PASS | Colorful banner + menu; `BrandBanner` shared |
| Profiles | PASS | PASS | PASS | PASS | Registry-backed via CLI session; Enter = use-profile |
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
| Help / keymap | PASS | PASS | PASS | PASS | Includes put/rename/remove keys |
| Storage showcase dest. | PASS | PASS | PASS | PASS | Existing presentational showcase retained |

Legend: render + router navigation covered by vitest (`packages/tui/test/app/router.test.ts`). ASCII / NO_COLOR / win32 defaults covered by `resolveAppPresentation` tests and home/credentials ASCII snapshots.

## Security checks exercised

- Secrets never rendered unless REVEAL confirm (`y`) succeeds.
- Passphrase and put-value entry use masked overlays (`****`); not written into `AppSnapshot`.
- Put/rename/remove spawn CLI with secrets on stdin frames only (`kavrix frames put|rename|remove`); never argv.
- `sanitizeTerminalText` used for all user-facing strings.
- CLI host avoids static Ink import (lazy `import('@kavrix/tui')`).

## Frames contracts verified

```text
kavrix put     → [mongodb-url,] passphrase, value   (--passphrase-stdin --value-stdin)
kavrix rename  → [mongodb-url,] passphrase          (--passphrase-stdin)
kavrix remove  → [mongodb-url,] passphrase          (--passphrase-stdin)
kavrix recovery status     → (none)
kavrix db recovery status  → [mongodb-url,] passphrase
```

## Skipped (documented)

- **create-file-profile from TUI**: skipped. Profile `use` already works; creating a usable file vault requires `db profile add` → `db init` → `db vault create` → `db vault use` (multi-step, recovery kit prompts). Prefer CLI for init; TUI focuses on post-init credential mutations.

## Remaining gaps

1. **Profile add / vault create / recovery create-verify-revoke / policy mutations** remain CLI-gated (navigable + message-gated in TUI).
2. **Interactive TTY color paint** validated via unit render helpers (`TERM=dumb`); full human TTY session not driven in CI.
3. **Structured vault projection** browse is metadata-level until a projection library adapter is deepened.

## Commands used

```bash
pnpm --filter @kavrix/tui build
pnpm --filter @kavrix/tui test
pnpm --filter kavrix build
node apps/cli/dist/bin.js frames put
node apps/cli/dist/bin.js tui --help
node scripts/tui-smoke.mjs
node scripts/tui-vault-smoke.mjs
```
