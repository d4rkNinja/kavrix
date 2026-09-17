# Fix summary

## Prior install/docs fixes (kept)

- Issue 1: README notes npm may lag `main` and shows a from-source build; no publication change.
- Issue 2: README adds a non-root `~/.local` npm prefix and PATH setup for `EACCES`.
- Issue 3: README distinguishes `~/.config/kavrix/` profiles from `~/.kavrix/` vault files.
- Issue 4: README quick starts pipe required input into `db vault use` with `--passphrase-stdin`.
- Issue 5: README clarifies non-TTY root init uses legacy v2 and CWD paths; recommends profiles for scripts.
- Issue 6: New `scripts/ensure-bin-shim.mjs` repairs the workspace bin on non-Windows systems; `package.json` runs it after build, and CONTRIBUTING documents workspace execution and repair.
- Issue 7: CONTRIBUTING already distinguishes the `.nvmrc` contributor baseline from CLI engines; that explanation is unchanged in this diff.
- Issue 8: README quick start states the 16-byte passphrase minimum.
- Issue 9: `stdin-frames.ts` accepts multi-word commands, suggests full commands for parent lookups, and sanitizes unknown-command control characters; regression assertions added.
- Issue 10: `--config-dir` aliases profile routing across database, local, structured, and execution commands; explicit `--profile-config-dir` takes precedence, with regression assertions added.
- Issue 11: README and CONTRIBUTING recommend packing and installing the `.tgz` into a user prefix instead of `npm link --prefix`.
- Issue 13: `db vault create` JSON adds top-level `vaultId` while preserving `created.id` and `created.createdAt`; regression assertions added.
- README simplified for normal users, with separate local-file and MongoDB happy paths and explicit stdin flows.

## FAIL / SKIP product fixes (2026-09-17 refix)

- **FAIL `db vault remove`:** `verifyDatabaseRevisionAnchor` rejected removed vault heads after a successful store delete, causing `#anchoredMutation` to poison the session (`ambiguous-commit` / exit 15). Removals are now allowed when `databaseRevision` advances (exact vault-set mode still rejects). Files: `packages/key-files/src/database-revision-anchor.ts` (+ test).
- **FAIL `db key create` (mongodb):** CLI wrongly rejected non-file datastores before share-key creation. MongoDB profiles are allowed; `--output-key-file` still required. Files: `apps/cli/src/database-commands.ts` (+ test update).
- **FAIL `migrate database`:** Documented path works on a fresh legacy v2 vault (`init --passphrase-stdin` source profile + bound dest + `--source-vault` + `--secrets-stdin`). Auth error text is more actionable; migrate help documents the path; `frames migrate database` aliases the stdin contract. Files: `database-migration.ts`, `local-vault-cli.ts`, `stdin-frames.ts`.
- **FAIL legacy `vault list` / `vault status` vs database-container MongoDB:** Clear redirect to `db vault list/status`; profile selection options added so `--profile` works. Files: `apps/cli/src/local-vault-cli.ts`.
- **FAIL `frames migrate database --secrets-stdin`:** `allowUnknownOption` so flag tokens in contract keys are look-up-able; `migrate database` aliased to the secrets-stdin contract. Files: `stdin-frames.ts` (+ regressions).
- **SKIP `agent run` / `agent exec`:** `--dry-run` validates config/profile (run) or permission (exec) without a third-party agent/broker. Fixture: `apps/cli/test/fixtures/noop-agent.kavrix.json` (+ `noop-agent.sh`). Files: `execution/agent-command.ts`, `execution/register.ts`.
- **SKIP `recovery revoke` / `db recovery revoke`:** `db recovery status` now includes non-secret `slots:[{id,state}]`; create→revoke using create `slotId` works (need ≥2 active slots to revoke one). Files: `database-session.ts`, `database-commands.ts`.
- **SKIP migrate on mongodb destination:** Exercised successfully in refix matrix (legacy file → mongodb dest).

## Mid Dev (2yr) P0 (2026-09-17)

- **Bin shim kept in tree:** `scripts/ensure-bin-shim.mjs` + `scripts/ensure-bin-shim.test.mjs` remain (node:test passes); `package.json` `build` still runs `node scripts/ensure-bin-shim.mjs`. No `opencode.json` added.
- **Authorized `db vault remove` success path:** session test creates two vaults, authorized-deletes the extra, then asserts `listVaults` / `status` stay usable and further create works (no `ambiguous-commit` / exit 15). File: `apps/cli/test/database-session.test.ts`.
- **README datastore footgun restored:** without `--profile`, root `put`/`get`/`list`/… still default datastore to **mongodb** (`datastoreFrom` → `options.datastore ?? 'mongodb'`). Noted near file quick start and Options. `--config-dir` alias row added. PATH-shadow note: prefer `pnpm exec kavrix` / `node apps/cli/dist/bin.js`.
- **Root stdin frames:** flat secret commands document optional `[mongodb-url,]` before passphrase (and value for `put`), matching MongoDB runtime. `report-regressions` expects `frames put` → `[mongodb-url,] passphrase, value`.
- **P1 docs/tests:** `docs/cli-reference.md` documents `--config-dir` as alias across profile/db/credential commands; minimal `agent run --dry-run` / `agent exec --dry-run` regressions use `apps/cli/test/fixtures/noop-agent.kavrix.json`.

## Senior hand-review P1 (2026-09-17)

- **`frames migrate database`:** contract is now `[mongodb-url,] source-passphrase, destination-passphrase, migrated-vault-label` so mongo destinations get the leading URI frame (avoids exit 2 when label is eaten as passphrase). Regressions updated.
- **`db vault remove` selection:** removing the profile's selected vault clears `defaultVaultId`, or auto-reselects when exactly one vault remains; JSON includes `selection: { action, vaultId }`. Files: `datastore-profiles.ts` (`clearDefaultVaultId`), `database-commands.ts` (+ tests).

### Verification

- `pnpm verify:quick` — pass (this session).
- Refix matrix: `/workspace/kavrix-audit-20260917/logs/command-matrix-refix.md` (0 FAILs).

### OpenCode note

Prompt: `/workspace/kavrix-audit-20260917/opencode-fix-fails-prompt.md`. Model `opencode/union-alpha` was rate-limited (`Rate limit exceeded`) during chunk1 attempts (`ses_f511a7188ffegoNxBAD7obc5o5`, `ses_f511540daffeRKHjynjqSBMfeu`). Fixes were applied by the executor using the same root-cause analysis in that prompt; model was never switched.
