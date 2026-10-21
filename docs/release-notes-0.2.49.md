# Release notes — 0.2.49

This patch increments the checkout's 0.2.48 version by 0.0.1. It changes only
the terminal UI layout. Publication requires exact-commit CI and CodeQL
followed by trusted publishing, as described in
[the release procedure](release.md).

## TUI polish

- From 60 columns, the profile, vault, session, recovery, browse, doctor, and
  policy lists share one label column, so each row's detail starts at the same
  position. The label column takes at most 45% of the panel. Narrower
  terminals keep labels at their natural width so details still have room.
- Rows, list position lines, and guidance lines that do not fit now end with
  an ellipsis (`…`) instead of being cut mid-word. ASCII mode keeps the plain
  cell-boundary cut and still emits only ASCII characters.
- The doctor and policy screens now show the same `Showing x-y of n` position
  line as the other lists.

## Tests

`packages/tui/test/app/layout-integrity.test.ts` now also checks that list
details line up in one column at 80 columns, that an overflowing doctor row
ends with an ellipsis, that doctor and policy show their position line, and
that every screen at 40x12 and 80x24 renders only ASCII characters in ASCII
mode.

## Verification status

Windows local verification passed the frozen install, build, formatting, lint,
type checking, the full unit/integration suite with coverage, the packed
package smoke, packed all-command local-file acceptance, packed
database-container acceptance, packed allowlist inspection, and the
high-severity dependency audit. Coverage includes 2,218 passing tests and 25
skipped tests: 86.81% statements, 80.03% branches, 91.09% functions, and 88.38%
lines. Skipped tests are environment-gated or platform-specific and are not
verification evidence. No gate or coverage threshold was reduced.

No encryption format, storage format, authorization policy, command, exit
code, or reveal requirement changes. Local Windows evidence does not establish
Linux or macOS terminal rendering; the release CI must supply its own platform
evidence.
