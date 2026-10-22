# Release notes — 0.2.50

This patch fixes the packaged TUI's child-command launcher and a startup warning
when a terminal or parent process sets both `NO_COLOR` and `FORCE_COLOR`.
Release publication follows the
[trusted-publishing procedure](release.md).

## Working TUI child commands

- Doctor and other TUI actions that launch the CLI now resolve its executable
  beside the package's public ESM entry point. They no longer request a private
  package-export path or look for `bin.js` inside a bundled `dist/chunks` folder.
- This repairs the shared launcher used by setup, authenticated health checks,
  policies, browse and other child-command actions. The existing command
  timeouts, shell-free execution, protected stdin frames and redaction remain.
- A regression journey uses the default launcher, without a replacement command
  runner or executable override, to create a disposable profile and exercise
  Doctor, credential storage, policy creation and browse.

## Clean terminal startup

- Kavrix now resolves conflicting inherited color flags before loading the CLI
  or interactive UI. `NO_COLOR` keeps its documented precedence, so Node does
  not emit the misleading warning that `NO_COLOR` was ignored.
- `FORCE_COLOR` remains available when `NO_COLOR` is absent. Explicit TUI color
  options retain their existing behavior.
- The local verification runner also respects the presence of `NO_COLOR`,
  including an empty value, and no longer adds a conflicting `FORCE_COLOR` to
  its child processes.

The fix does not suppress Node warnings globally. Unrelated runtime warnings and
errors remain visible. No credential, encryption, authorization, storage format,
command or exit-code behavior changes.

## Regression coverage and verification

Packed-entrypoint tests execute version and TUI-help commands with conflicting
color flags and require warning-free, ANSI-free output. They cover empty and
nonempty `NO_COLOR`, and `FORCE_COLOR` levels `0`, `1` and `3`.

Startup contract tests also preserve force-color-only sessions and prove that
warning handling is not disabled. The installed-archive smoke now unlocks the
real packaged TUI and runs Doctor through its unmodified child launcher.

A credential-history tampering fixture now flips an authenticated ciphertext bit
instead of swapping two random base64 characters that can be identical. Its
authentication-failure assertion is unchanged and the fixture explicitly checks
that ciphertext bytes were changed.

Windows local verification passed the frozen install, build, formatting, lint,
type checking, the full unit/integration suite with coverage, installed-package
smoke including the default TUI Doctor launcher, packed all-command local-file
acceptance, packed database-container acceptance, allowlist inspection and the
high-severity dependency audit. The full suite passed 2,226 tests with 25
environment-gated or platform-specific skips. Coverage is 86.82% statements,
80.03% branches, 91.09% functions and 88.39% lines. No assertion, release gate
or coverage threshold was reduced. Local coverage used four workers on the
32-thread development host; CI retains its configured platform concurrency.

Native Windows terminal QA separately confirmed an authenticated Doctor result
from the built split bundle. Stream-harness package tests are not physical TTY
evidence. Publication still requires successful CI and CodeQL on the exact
release commit. Windows local evidence alone does not establish Linux or macOS
behavior.
