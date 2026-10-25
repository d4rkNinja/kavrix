# Release notes — 0.2.51

This patch repairs TUI search, paste, action selection, and process-boundary
failures. It includes the packaged launcher and color-startup improvements
described in [0.2.50](release-notes-0.2.50.md), plus recovery after slow verified
profile loading. Publication follows the [trusted-publishing procedure](release.md).

## TUI reliability

- Credential and action searches retain typed `j` and `k`. Arrow keys navigate
  search results; ordinary lists retain their `j/k` shortcuts.
- The action palette accepts bracketed paste, highlights the correct filtered
  row, and activates the displayed command when clicked. Reveal still requires
  explicit confirmation.
- A profile load that completes after the initial loading deadline can recover
  the interface instead of leaving a permanent loading error.
- Clipboard helpers handle broken stdin and have a five-second deadline per
  backend. Windows PowerShell explicitly decodes UTF-8 stdin so non-ASCII values
  survive copying. Values continue to travel through stdin, never arguments.
- The installed TUI resolves its child launcher beside the public package entry
  point. Inherited `NO_COLOR` takes precedence over `FORCE_COLOR` before startup.

## Execution and validation

- Cancellation during working-directory validation prevents the child from
  starting. A throwing spawn observer terminates and reaps the child and returns
  a generic error.
- Relative PATH entries resolve against the requested child working directory.
  POSIX lookup skips files without execute permission. Canonical Windows command
  script targets remain refused when reached through a symlink.
- Zod 4.6.6 rejects oversized bounded collections before accumulating per-element
  errors. Trusted-publishing archive checks require that same pinned version.
  Vitest and its coverage provider use the 4.1.12 security fixes.
- Full and acceptance-only local verification run packed database-container
  acceptance without requiring Docker; that journey exercises the file datastore.
- Local `.tmp` artifacts no longer interfere with formatting and lint checks.

## Verification and limits

The application fixes passed native Linux x64 and macOS arm64 full suites,
all four Windows x64 shards, packed Windows database/migration and all-command
acceptance, installed package/TUI smoke, CodeQL, coverage, and dependency checks
in [PR #173](https://github.com/d4rkNinja/kavrix/pull/173/checks). Additional local
Windows checks covered Node 24.12.0 and Node 26.10.0. Detailed evidence and scope
are recorded in the [reliability audit](reliability-audit-2026-10-25.md).

The release version is separately gated by local preflight and successful main
CI/CodeQL on its exact commit before tagging. Prior branch checks do not replace
that release evidence. Service-dependent integrations skip when their services
are unavailable; stream harnesses do not establish physical-terminal or native
clipboard interoperability on every desktop. OSC 52 clearing remains best effort,
and native clipboard automatic clearing remains unavailable.
