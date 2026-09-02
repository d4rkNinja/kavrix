# kavrix

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
