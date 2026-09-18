# Kavrix TUI Test Report

Date: 2026-09-18 (Asia/Calcutta)
Branch: `feature/full-interactive-tui`
Scope: Full interactive Ink app in `@kavrix/tui` + `kavrix tui|ui` CLI wiring.

## Build / automation

| Check | Result |
| --- | --- |
| `pnpm --filter @kavrix/tui build` | PASS |
| `pnpm --filter @kavrix/tui test` (56 tests) | PASS |
| `pnpm --filter kavrix build` | PASS |
| `kavrix tui --help` | PASS |
| `kavrix ui --help` (alias) | PASS |
| `kavrix tui` on non-TTY | PASS (clear error, exit 1) |
| `node scripts/tui-smoke.mjs` | PASS (12 screens) |

## Screens

| Screen | Linux TTY color | ASCII mode | NO_COLOR | Windows path assumptions | Notes |
| --- | --- | --- | --- | --- | --- |
| Home / dashboard | PASS | PASS | PASS | PASS | Colorful banner + menu; `BrandBanner` shared |
| Profiles | PASS | PASS | PASS | PASS | Registry-backed via CLI session |
| Vaults | PASS | PASS | PASS | PASS | Selection + status from session |
| Credentials (masked) | PASS | PASS | PASS | PASS | Masked by default |
| Credentials (REVEAL) | PASS | PASS | PASS | PASS | Confirm overlay required; 15s clear |
| Doctor | PASS | PASS | PASS | PASS | `d` refreshes; unlock gated |
| Recovery | PASS | PASS | PASS | PASS | Final-slot revoke blocked with warning |
| Run | PASS | PASS | PASS | PASS | Dry preview only; no argv secrets |
| Policy / Grant / Audit | PASS | PASS | PASS | PASS | List + refresh; mutations CLI-gated |
| Agent | PASS | PASS | PASS | PASS | Dry-run status only |
| Context / Service / Item | PASS | PASS | PASS | PASS | Browse rows from session metadata |
| Help / keymap | PASS | PASS | PASS | PASS | Full keymap |
| Storage showcase dest. | PASS | PASS | PASS | PASS | Existing presentational showcase retained |

Legend: render + router navigation covered by vitest (`packages/tui/test/app/router.test.ts`). ASCII / NO_COLOR / win32 defaults covered by `resolveAppPresentation` tests and home/credentials ASCII snapshots.

## Security checks exercised

- Secrets never rendered unless REVEAL confirm (`y`) succeeds.
- Passphrase entry uses masked overlay (`****`); not written into `AppSnapshot`.
- `sanitizeTerminalText` used for all user-facing strings.
- CLI host avoids static Ink import (lazy `import('@kavrix/tui')`); unlock/list/doctor/reveal spawn built bin with secrets on stdin frames only.

## Remaining gaps

1. **Vault mutations in-TUI** (put/rename/remove, profile add/remove, recovery create/verify/revoke, policy create/revoke) are navigable and message-gated; durable writes still prefer CLI commands.
2. **Unlock against live file vault** depends on an existing selected profile + successful child `kavrix list --passphrase-stdin`; database-container profiles may need additional stdin frames.
3. **Interactive TTY color paint** was validated via unit render helpers on this host (`TERM=dumb`); full human TTY session not driven in CI.
4. **Structured vault projection** browse is metadata-level until a projection library adapter is deepened.

## Commands used

```bash
pnpm --filter @kavrix/tui build
pnpm --filter @kavrix/tui test
pnpm --filter kavrix build
node apps/cli/dist/bin.js tui --help
node apps/cli/dist/bin.js tui   # non-TTY -> error
node scripts/tui-smoke.mjs
```
