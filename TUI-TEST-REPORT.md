# Kavrix TUI Test Report

Date: 2026-09-18 (Asia/Calcutta)
Branch: `feature/full-interactive-tui`
Scope: Full interactive Ink app in `@kavrix/tui` + `kavrix tui|ui` CLI wiring,
including credential mutations, create-file-profile, **create-mongodb-profile**,
and **real CLI-backed** recovery / policy / grant / doctor / run-preview /
agent-dry-run / browse actions via `createCliTuiBackend` (production).
`createStaticAppBackend` remains test-only.

## Build / automation

| Check | Result |
| --- | --- |
| `pnpm --filter @kavrix/tui build` | PASS |
| `pnpm --filter @kavrix/tui test` | PASS (68 tests) |
| `pnpm --filter kavrix build` | PASS |
| `vitest` `apps/cli/test/tui-session.test.ts` | PASS (4 tests, mocked spawn frames) |
| `kavrix tui --help` | PASS |
| `kavrix ui --help` (alias) | PASS |
| `kavrix tui` on non-TTY | PASS (clear error, exit 1) |
| `node scripts/tui-smoke.mjs` | PASS (12 screens) |
| `node scripts/tui-vault-smoke.mjs` | PASS (real HOME vault; recovery/policy/grant/doctor/preview/agent/browse; mongo SKIP without MONGO_URL) |

## Screens

| Screen | Linux TTY color | ASCII mode | NO_COLOR | Windows path assumptions | Notes |
| --- | --- | --- | --- | --- | --- |
| Home / dashboard | PASS | PASS | PASS | PASS | Colorful banner + menu; `BrandBanner` shared |
| Profiles | PASS | PASS | PASS | PASS | Enter = use-profile; `n` = file; `m` = mongodb |
| Vaults | PASS | PASS | PASS | PASS | Selection + status from session |
| Credentials (masked) | PASS | PASS | PASS | PASS | Masked by default |
| Credentials (REVEAL) | PASS | PASS | PASS | PASS | Confirm overlay required; 15s clear |
| Credentials (put/rename/remove) | PASS | PASS | PASS | PASS | `n` put, `m` rename, `x` confirm-remove; stdin frames only |
| Doctor | PASS | PASS | PASS | PASS | `d` / enter runs real `doctor` or `db doctor health`; rows from CLI JSON |
| Recovery | PASS | PASS | PASS | PASS | `n` create, `v` verify, Enter/`x` revoke; last active slot blocked |
| Run | PASS | PASS | PASS | PASS | `p` → list+has + `kavrix run --help` (no secret inject; no `--dry-run` on run) |
| Policy / Grant / Audit | PASS | PASS | PASS | PASS | Enter refresh; `n`/`x` policy; `g`/`r` grant — real CLI |
| Agent | PASS | PASS | PASS | PASS | `g` → `kavrix agent run --dry-run` (real CLI text/errors; empty status until run) |
| Context / Service / Item | PASS | PASS | PASS | PASS | Browse from real `context`/`service`/`item` list when unlocked |
| Help / keymap | PASS | PASS | PASS | PASS | Includes recovery/policy/grant/mongo keys |
| Storage showcase dest. | PASS | PASS | PASS | PASS | Existing presentational showcase retained |

Legend: render + router navigation covered by vitest (`packages/tui/test/app/router.test.ts`). ASCII / NO_COLOR / win32 defaults covered by `resolveAppPresentation` tests and home/credentials/profiles ASCII snapshots.

## Exact keybindings (product TUI)

### Global
| Key | Action |
| --- | --- |
| `j` / `k` / arrows | Move selection |
| Enter | Activate selection (screen-specific) |
| Esc | Back to Home (or cancel overlay) |
| `u` | Unlock (mongodb: URL overlay then passphrase; file: passphrase) |
| `l` | Lock (confirm) |
| `a` | Toggle ASCII |
| `?` | Help |
| `q` | Quit |

### Profiles
| Key | Action |
| --- | --- |
| Enter | `use-profile` |
| `n` | create-file-profile wizard (id → data file → key file → passphrase → confirm) |
| `m` | create-mongodb-profile wizard (id → database → key file → URL → passphrase → confirm) |

### Credentials
| Key | Action |
| --- | --- |
| `/` | Search |
| `n` | Put credential |
| `m` | Rename selected |
| `x` | Remove selected (confirm) |
| `r` then `y` | REVEAL selected (15s) |

### Doctor
| Key | Action |
| --- | --- |
| `d` / enter screen | `run-doctor` → real `kavrix doctor` or `db doctor health` |

### Recovery
| Key | Action |
| --- | --- |
| Enter screen | `recovery-status` |
| `n` / `c` | `recovery-create` (file path → recovery passphrase → confirm) |
| `v` | `recovery-verify` (file path → recovery passphrase) |
| Enter / `x` | `recovery-revoke` selected slot (blocked when only one active) |

### Policy / Grant / Audit
| Key | Action |
| --- | --- |
| Enter | `refresh-policy` (`policy list` + `grant list` + `audit`) |
| `n` | `policy-create` (id → secret → command) |
| `x` | `policy-remove` selected policy row (confirm) |
| `g` | `grant-create` (secret → command → TTL) |
| `r` | `grant-revoke` selected grant row (confirm) |

### Run
| Key | Action |
| --- | --- |
| `p` | `preview-run` — unlocked list + `kavrix has` per name + `kavrix run --help` (surfaces CLI stderr on failure) |

### Agent
| Key | Action |
| --- | --- |
| `g` | `agent-dry-run` → `kavrix agent run --dry-run --json` |

### Browse
| Key | Action |
| --- | --- |
| Enter / enter screen | `refresh-browse` → `context list` then nested `service list` / `item list` when unlocked |

## win32 presentation assumptions

| Assumption | Behavior | Covered by |
| --- | --- | --- |
| `process.platform === 'win32'` | ASCII borders/glyphs default on (same as `--ascii`) | `resolveAppPresentation({ platform: 'win32' })` |
| Explicit `--ascii` | Forces ASCII even on UTF-capable Unix terminals | `resolveAppPresentation({ ascii: true })` |
| `NO_COLOR` / `noColor: true` / `TERM=dumb` | Color disabled | presentation unit tests |
| Path construction | Defaults use `node:path.join` / `path.sep` (no bashisms) | `defaultFileProfilePaths` / `defaultMongoProfilePaths` + `pathSeparator()` tests |
| Default file profile paths | `~/.local/share/kavrix/<id>/db.kavrix` and `owner.key` via `join(homedir(), …)` | router create-profile overlay + paths helper |
| Default mongo key path | `~/.local/share/kavrix/<id>/owner.key` (URL never on disk) | router mongo wizard + paths helper |

On Windows hosts, `path.sep` is `\\`; the TUI never concatenates paths with `/` literals for profile files.

## Security checks exercised

- Secrets never rendered unless REVEAL confirm (`y`) succeeds.
- Passphrase, MongoDB URL, and put-value entry use masked overlays (`****`); not written into `AppSnapshot`.
- Create-file-profile / create-mongodb-profile / recovery / policy / grant hold secrets only in ephemeral router state or stdin frames.
- Product path spawns built CLI bin; secrets never on argv (Mongo URL + passphrase frames only).
- `sanitizeTerminalText` used for all user-facing strings.
- CLI host avoids static Ink import (lazy `import('@kavrix/tui')`).
- Last active recovery slot revoke is blocked in TUI and by CLI.
- Session Mongo URL buffer is zeroized on lock / profile switch.

## Frames contracts verified

```text
kavrix put                 → [mongodb-url,] passphrase, value
kavrix rename / remove     → [mongodb-url,] passphrase
kavrix has                 → [mongodb-url,] passphrase
kavrix doctor              → [mongodb-url,] passphrase
kavrix db doctor health    → [mongodb-url,] passphrase
kavrix recovery status     → (none)
kavrix db recovery status  → [mongodb-url,] passphrase
kavrix db recovery create  → [mongodb-url,] passphrase, rec-passphrase, rec-passphrase-confirm
kavrix db recovery verify  → [mongodb-url,] passphrase, rec-passphrase
kavrix db recovery revoke  → [mongodb-url,] passphrase
kavrix recovery create     → key-passphrase, recovery-passphrase
kavrix recovery verify     → recovery-passphrase
kavrix recovery revoke     → key-passphrase
kavrix policy list|create|remove → [mongodb-url,] passphrase
kavrix grant list|create|revoke  → [mongodb-url,] passphrase
kavrix audit               → [mongodb-url,] passphrase
kavrix agent run --dry-run → [mongodb-url,] passphrase (when unlocked)
kavrix context|service|item list → [mongodb-url,] passphrase
kavrix db init             → [mongodb-url,] label, passphrase, passphrase-confirm
kavrix db vault create     → [mongodb-url,] passphrase, label
kavrix db vault use        → [mongodb-url,] passphrase
kavrix db profile add      → (none; routing only)
```

## Test counts

| Suite | Tests |
| --- | --- |
| `packages/tui/test` | 68 |
| `apps/cli/test/tui-session.test.ts` | 4 (incl. mocked create-mongodb-profile + browse) |
| `scripts/tui-smoke.mjs` | 12 screens |
| `scripts/tui-vault-smoke.mjs` | ALL PASS; create-mongodb-profile SKIP without `MONGO_URL` / `KAVRIX_MONGODB_URI` |

## Remaining gaps (true leftovers)

1. **Live MongoDB smoke** — code path + spawn-mock unit test are real; vault smoke prints clear `SKIP` unless `MONGO_URL` (or `KAVRIX_MONGODB_URI`) is set to a replica-set capable URI.
2. **Interactive TTY color paint** — validated via unit render helpers (`TERM=dumb`); full human TTY session not driven in CI.
3. **Browse depth caps** — context/service/item lists are bounded (20/20/30) for UI size; no field-level projection drill-down yet.
4. **`kavrix run` has no `--dry-run`** — TUI preview validates via unlocked list + `kavrix has` + `run --help` only; does not inject secrets into a child process.
5. **Agent dry-run** still needs a project agent config (`--config` / `kavrix.yaml`); without it the TUI surfaces the real CLI error (status starts empty until `g`).

## Commands used

```bash
pnpm --filter @kavrix/tui build
pnpm --filter @kavrix/tui test
pnpm --filter kavrix build
pnpm exec vitest run apps/cli/test/tui-session.test.ts
node apps/cli/dist/bin.js tui --help
node scripts/tui-smoke.mjs
node scripts/tui-vault-smoke.mjs
# optional live mongo:
# MONGO_URL='mongodb://127.0.0.1:27017/?replicaSet=rs0' node scripts/tui-vault-smoke.mjs
```
