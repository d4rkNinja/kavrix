# Release notes — 0.2.48

This patch increments the checkout's 0.2.47 version by 0.0.1. It changes only
the terminal UI layout. Publication requires exact-commit CI and CodeQL
followed by trusted publishing, as described in
[the release procedure](release.md).

## Responsive TUI layout

- Screen panels now fill the rows left between the header and the footer and
  clip their content inside their own border. On short terminals a panel no
  longer loses its closing border, and body text no longer paints over the
  notice row or the footer.
- Terminals shorter than 16 rows use a one-line header (screen title, lock
  state, profile and vault), which leaves more rows for the list.
- From 60 columns, each credential takes one row: the name column (at most
  three fifths of the width) followed by the masked value. Narrower terminals
  keep the two-row card. More credentials fit per page, and page-up and
  page-down move by the visible page.
- Profile, vault, doctor, recovery, policy, and browse lists size their window
  from the terminal height instead of a fixed row count.
- Labels that do not fit their column end with an ellipsis (`...` in ASCII
  mode) instead of being cut mid-word without a marker.
- Ink 7.1.1 is patched through `pnpm patch` (`patches/ink@7.1.1.patch`) so a
  nested clipping box intersects its ancestor's clip instead of replacing it.
  Without this, a one-row clipped label inside a clipped panel could still
  paint over the panel border. The patch changes only clip bookkeeping in
  Ink's output buffer and ships in the bundled executable.

## Tests

`packages/tui/test/app/layout-integrity.test.ts` renders every screen and the
setup wizard at 40x12, 60x20, 80x24, 120x36, and 200x50. It asserts that each
frame fits the terminal, that every opened panel closes, and that no closing
border row contains text. It also covers the one-row credential layout, the
clear notice row, and nested clipping inside a filled panel. Existing paging
tests were updated to the larger visible page.

## Verification status

Windows local verification passed the frozen install, build, formatting, lint,
type checking, the full unit/integration suite with coverage, the packed
package smoke, packed all-command local-file acceptance, packed
database-container acceptance, packed allowlist inspection, and the
high-severity dependency audit. Coverage includes 2,215 passing tests and 25
skipped tests: 86.81% statements, 80.03% branches, 91.09% functions, and 88.38%
lines. The skipped tests are the environment-gated MongoDB integration suites
and platform-specific cases; skipped tests are not verification evidence. No
gate or coverage threshold was reduced. The bundled executable was checked to
contain the patched Ink clip intersection.

No encryption format, storage format, authorization policy, command, exit
code, or reveal requirement changes. Local Windows evidence does not establish
Linux or macOS terminal rendering; the release CI must supply its own platform
evidence.
