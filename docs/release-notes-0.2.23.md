# Release notes — 0.2.23 agent broker hardening / live isolation journey

Completes the recorded agent-broker hole and proves the credential-firewall
contract live. Changes:

- `agent exec` child-start parity with `kavrix run`: the broker announces the
  allow decision only after the authorized child actually spawns
  (`child.once('spawn')`); spawn misses and unresolvable executables return
  the execution-failure exit (`EXECUTION_FAILED`, exit 18) through an
  exit-only frame instead of a fabricated `invalid-request` deny. The client
  maps an exit without allow/deny to the same coded errors, so `--json`
  reports `EXECUTION_FAILED` like `run --json`.
- Denial-audit persistence fix: deny audits carried `safeCommandName(argv[0])`
  as `command`, which fails the sealed audit schema whenever argv[0] is a
  full path (always, on Windows agents) — the schema rejection swallowed the
  whole `authorization-denied` event silently. Denial audits now use the new
  `auditCommandName` (bare basename, schema-validated, omitted when it still
  cannot qualify) so denials are always recorded; broker flood/teardown
  audits get the same treatment.
- `db profile add` / `db profile use` now accept `--json` (handlers always
  wrote JSON; the flags were never registered — same defect class as the
  0.2.22 `remove` fix).

Verified live on win32 against the real CLI subprocess by
`apps/cli/test/live-qa-agent-broker.test.ts`: the agent process's
environment and argv contain no credential material (canary scan), only the
broker endpoint and one-session token; an authorized `agent exec` injects
the secret into the allowed grandchild only; a command-allowlist violation
and an unknown permission are denied before any child starts (no leak in
stdout); the missing-executable case returns `EXECUTION_FAILED` (exit 18)
via both JSON and human paths; `kavrix audit` records
`authorization-allowed` and `authorization-denied` without ever containing
the secret; and secrets never appear on any argv across all spawns.
`apps/cli/test/agent-broker-deny-audit.test.ts` regression-covers the
denial-audit fix through the in-process broker.
