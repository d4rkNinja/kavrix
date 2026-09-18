# TUI Release Gate

Date: 2026-09-18 (Asia/Calcutta)

Branch: `feature/full-interactive-tui`  
Worktree: `/workspace/kavrix-tui-dev`  
Passphrase used for live vault tests: `correct horse battery staple`  
CLI binary: `node apps/cli/dist/bin.js` (spawned by `createCliTuiBackend` / smoke)

## Phase 1 — Mock / stub audit

| Check | Result | Notes |
| --- | --- | --- |
| `runInteractiveTui` mounts only `createCliTuiBackend` | PASS | `apps/cli/src/tui-command.ts` |
| `createStaticAppBackend` product-path usage | PASS | Tests only (`packages/tui/test`); comment says never for `kavrix tui` |
| Agent dry-run invents `--agent noop` | PASS (fixed) | Requires real agent name; TUI prompts `input-agent-name` then optional config |
| Storage showcase fake vault ops | PASS (fixed) | Renamed to **Storage docs (read-only)**; shows live home/doctor; no mutate |
| Grep mock\|stub\|fake\|noop\|placeholder in product paths | PASS | Remaining hits only in `static-backend.ts` (test backend) + build esbuild `__require` bridge comments |

## Phase 2 — Live file vault (`scripts/tui-vault-smoke.ts`)

Command:

```bash
pnpm --filter kavrix build
MONGO_URL='mongodb://127.0.0.1:27017/?replicaSet=rs0' \
  node --import tsx scripts/tui-vault-smoke.ts
```

| Item | Result | Exact path / command |
| --- | --- | --- |
| profiles: list | PASS | session unlock → snapshot.profiles |
| profiles: use | PASS | `dispatch({ type: 'use-profile', profileId: 'smoke' })` |
| profiles: create-file-profile | PASS | `dispatch({ type: 'create-file-profile', ... })` → real `db profile add/use/init/vault create/use` |
| unlock | PASS | `dispatch({ type: 'unlock', passphrase })` → `kavrix list --json --passphrase-stdin` |
| lock | PASS | `dispatch({ type: 'lock' })` |
| vaults: list | PASS | snapshot.vaults after unlock |
| vaults: use | PASS | `dispatch({ type: 'use-vault', vaultId })` → real `kavrix db vault use` |
| credentials: list | PASS | unlock list |
| credentials: put | PASS | `put-credential` |
| credentials: rename | PASS | `rename-credential` |
| credentials: remove | PASS | `remove-credential` |
| credentials: reveal | PASS | `reveal-credential` |
| credentials: copy (OSC52 / clipboard) | PASS | `copy-credential` (headless: system clipboard shim on PATH; product prefers OSC 52 on TTY) |
| doctor | PASS | `run-doctor` → `kavrix doctor` |
| recovery: status | PASS | `recovery-status` |
| recovery: create | PASS | two kits A/B |
| recovery: verify | PASS | `recovery-verify` |
| recovery: revoke (non-last) | PASS | revoked one of two active slots; one remained |
| policy: create | PASS | `policy-create` |
| policy: list | PASS | `refresh-policy` |
| policy: remove | PASS | `policy-remove` |
| grant: create | PASS | `grant-create` |
| grant: revoke | PASS | `grant-revoke` |
| browse refresh (context/service/item) | PASS | `refresh-browse` (3 nodes) before and after profile switch |
| preview-run (list+has+run --help) | PASS | no `--dry-run` on `kavrix run` (documented in preview text) |
| agent dry-run (real CLI + config) | PASS | `agent run --dry-run --json --agent <name> --config <file>` |
| agent dry-run missing name (no noop) | PASS | honest error; CLI not spawned |
| mongodb profile create (27017 rs0) | PASS | `MONGO_URL=mongodb://127.0.0.1:27017/?replicaSet=rs0` |

**Smoke summary:** `tui-vault-smoke: ALL PASS`

### Direct CLI agent honesty checks

```bash
node apps/cli/dist/bin.js agent run --dry-run --json
# → EXIT 2: required option '--agent <name>' not specified

node apps/cli/dist/bin.js agent run --dry-run --json --agent missing
# → EXIT 14: Agent permissions live in a project file; pass --config or create kavrix.yaml.
```

## Phase 3 — Automated gates

| Gate | Result | Command |
| --- | --- | --- |
| `@kavrix/tui` unit tests | PASS (77) | `pnpm --filter @kavrix/tui test` |
| `@kavrix/tui` build | PASS | `pnpm --filter @kavrix/tui build` |
| `kavrix` build | PASS | `pnpm --filter kavrix build` |
| `apps/cli/test/tui-session.test.ts` | PASS (5) | `pnpm exec vitest run apps/cli/test/tui-session.test.ts` |
| `scripts/tui-smoke.mjs` inventory | PASS (12 screens) | `node scripts/tui-smoke.mjs` |
| `scripts/tui-vault-smoke` + mongo | PASS | see Phase 2 |
| Windows / ASCII presentation | PASS | `resolveAppPresentation({ platform:'win32' })` → `{ ascii: true }`; `--ascii` help OK; router ASCII/NO_COLOR tests green |

## Phase 4 — Honest remaining gaps (CLI product limits only)

1. **`kavrix run` has no `--dry-run`.** TUI `preview-run` validates via `list` + `has` + `run --help` without injecting secrets. This is intentional CLI surface, not a TUI stub.
2. **Headless copy without TTY** cannot use OSC 52; needs a system clipboard CLI (`wl-copy` / `xclip` / `xsel`) or a real TTY for OSC 52. Interactive `kavrix tui` on a TTY uses OSC 52 first.
3. **Agent dry-run needs a real project agent config** (`--config` / `kavrix.yaml`) and a named agent entry — the TUI no longer invents `noop`.

## Product fixes landed in this gate

- Dropped invented `--agent noop`; require agent name (TUI overlay + session guard).
- Storage screen → docs-only with live profile/doctor summary (no fake vault ops).
- **Bugfix:** `use-profile` cleared stale `#vaultId` so browse/recovery no longer send a foreign `--vault` after profile switch.
- **Bugfix:** `use-vault` now runs real `kavrix db vault use` (was in-memory only).
- Clearer clipboard fallback error when OSC 52 and system CLIs are unavailable.

## Release readiness

- **Blockers:** none found for TUI release on file vault + available Mongo rs0.
- **Ready to open PR / tag:** YES (do not push secrets; demo home passphrase is test-only).
- Prefer tagging after PR review; smoke + unit gates are green on this branch.
