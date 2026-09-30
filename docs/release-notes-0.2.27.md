# Release notes — 0.2.27 bare `kavrix` interactive default

Typing `kavrix` with no arguments on an interactive TTY now opens the
product directly instead of printing help:

- Onboarded sessions (a protected profile registry with at least one
  datastore profile) mount `kavrix tui` immediately.
- Fresh machines run the same Ink onboarding wizard as interactive
  `kavrix init` (real profile/vault/recovery creation); a completed wizard
  prints the SETUP COMPLETE block and then opens the TUI in the same
  invocation. Cancelled onboarding exits cleanly with a retry hint; a failed
  wizard surfaces through the standard CLI error path.
- If stderr is not a TTY (onboarding cannot render there), the TUI still
  opens and profiles can be created from its Profiles screen.
- Non-interactive bare `kavrix` (pipes, cron, scripts) keeps the exact
  classic behavior: help on stderr, exit 0. Subcommands, flags, `--help`,
  `--version`, and unknown-command failures (exit 2, "did you mean"
  suggestions) are untouched because the commander program is not modified —
  the default is intercepted in `runLocalCli` before parse.

Verified by `apps/cli/test/default-interactive.test.ts` (route resolution
against real registries, TTY eligibility, onboarding→TUI continuation,
cancel/fail paths, non-TTY help, unknown-command exit 2, `--version`
passthrough, and a spawned built-CLI help check) plus the neighboring suites
(`public-command-help`, `launch-routing-guards`, `package`,
`local-vault-cli-coverage`, `init-onboarding-command`, `datastore-profiles`).

0.2.27 also refreshes the transitive devDependency `brace-expansion` to
5.0.12 through a scoped `pnpm-workspace.yaml` override after two new
high-severity DoS advisories (GHSA-qhr7-859c-m2p7, GHSA-6j4f-fj2g-mc7p)
landed in the eslint toolchain chain between 0.2.26 and this release;
`pnpm audit --audit-level high` (the publish gate) is clean again and the
shipped CLI package never contained the vulnerable code (devDependency
chain only).
