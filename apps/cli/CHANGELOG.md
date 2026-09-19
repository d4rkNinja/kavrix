# kavrix

## 0.2.14

- Scripted/`--json` file `kavrix init` creates a bound database-container profile (db + default vault) so `put`/`run` work immediately; `--legacy` retains version-2 single-vault migrate sources; MongoDB scripted init hard-fails with the `db profile`/`db init`/`db vault` recipe.
- Align root CRUD `--datastore` default with init (`file`) via a shared `root-datastore` resolution helper; require explicit `--datastore mongodb`; invalid datastore / failed resolution exits non-zero.
- `doctor health` exits non-zero when `healthy: false` (after emitting JSON).
- Windows: serialize/retry PowerShell ACL helpers to clear KEY_FILE_UNSAFE flake under concurrent secure temp dirs.
- README honesty: Node engines, init→run path, recovery claims, secrets-firewall + zero-knowledge positioning.

## 0.2.13

- Ship the full interactive Ink TUI (animated startup splash; `--no-splash` / `KAVRIX_TUI_NO_SPLASH`): `kavrix tui` / `kavrix ui` drives real CLI commands (no product mocks). Bare TTY `kavrix init` defaults to Ink onboarding; use `--no-tui` for classic line prompts or scripts. Demo screenshot/GIF ship in the npm package for the README; GitHub README links the terminal demo video.

## 0.2.12

- Fix CLI FAIL/SKIP issues from hand QA: allow `db vault remove` when the database revision advances (no longer poison the session with `ambiguous-commit`); allow `db key create` on MongoDB profiles with `--output-key-file`; improve `migrate database` auth errors and `frames migrate database` stdin contract (including Mongo URL-first frames); redirect legacy `vault list`/`vault status` on database-container profiles; add `agent run`/`agent exec --dry-run`; expose non-secret recovery `slots` on `db recovery status` for revoke flows; clear or auto-reselect profile default vault after remove; alias `--config-dir` to profile config routing.

## 0.2.11

- Fix 12 FAILs from the 0.2.10 QA: standalone `db init` now surfaces the replica-set sentence (`unsupported`, exit 15) instead of `The database may have changed` by preserving the store `unsupported` code through `DatabaseSession` and treating it as proven-rejected during init; document `db vault remove`/`db vault use` stdin frames and remove the unimplemented confirmation claim; accept `--passphrase-stdin`/`--secrets-stdin` on legacy `recovery create`; distinguish unbound profiles (`run`/`agent run`/authorization now say the profile is not bound and to run `db init`); `db recovery use` prints a rotation notice that the old owner key is dead and the profile still names it.

## 0.2.10

- Fix 21 FAIL / 1 BROKEN / 2 UNIMPLEMENTED from the 0.2.9 QA: add `--json` to `db profile list/status`, `db vault create`, `db recovery status`, `key status/verify`; make `get --json --reveal` return JSON; reject `db init` on standalone with a replica-set sentence; allow `db ping` on bound profiles; repair hidden `destroy --help`; add `db profile show` and `db vault remove`; accept `--secrets-stdin` / `--passphrase-stdin` aliases and guide database-owner keys to `db key` commands; preserve key-file not-found errors instead of collapsing to authentication failures.

## 0.2.0

### Minor Changes

- 3757e77: Add credential execution and policy firewall capabilities:

  - `kavrix run`: process-scoped secret execution with environment-only injection, project-file mappings, TTL caps, confirmations, and redacted JSON capture.
  - `kavrix policy` / `kavrix grant` / `kavrix audit`: sealed authorization state with allowlists, executable pins, working-directory restrictions, reveal separation, temporary grants, and stable exit codes.
  - `kavrix agent run` / `kavrix agent exec`: brokered credential firewall for AI coding agents.
  - MongoDB store: eagerly materialize both collections on connect so first-use transactions are race-free on empty deployments.

### Patch Changes

- Explicit standalone routing (`--datastore` without `--profile`) now always selects the legacy single-vault path. An ambient current datastore profile no longer adopts such invocations into database-container mode, so commands with explicit routing behave identically on machines with and without a selected profile.
- Guided `init` onboarding, flat credential commands, database commands, and `db ping` share that selection rule consistently.
- Test-suite reliability: every Vitest worker runs against an isolated home directory so machine-local Kavrix state cannot influence results, stale MongoDB connection-shape assertions were corrected, and a load-sensitive key-files publication test tolerates transient Windows rename failures without weakening its assertions.
