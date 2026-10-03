# Release notes — 0.2.34 TUI refreshed

This release ships the interactive workspace refresh together with the defects
found while verifying it. It covers everything prepared for 0.2.32 and 0.2.33,
neither of which was published: the first published build to contain this work
is 0.2.34. Existing CLI commands, output, and encrypted-storage boundaries are
unchanged.

## Changes

- Compact session chrome shows the active profile, vault, lock state, and screen.
  Home offers a next step based on whether a profile exists and the vault is
  unlocked.
- An interactive session paints in the terminal's alternate screen and restores
  the original screen on exit. This no longer depends on mouse support, so
  `--no-mouse` or `KAVRIX_TUI_MOUSE=0` keeps native terminal selection without
  giving up the full-screen layout. Shift+drag selection depends on the terminal
  emulator.
- Click navigation tabs, Home destinations, credentials, themes, and action chips.
  Wheel input moves the current list selection. Reveal and destructive actions
  retain explicit confirmation.
- Profiles and vaults require a selection click followed by a use click, so
  entering a list no longer doubles as a confirmation of its first row.
- Home and secondary lists use bounded windows. Help has five navigable topics.
  Contextual action chips remain reachable on narrow terminals, and `u unlock` is
  prioritized while the vault is locked. `?` opens Help from any screen. `+N more`
  reports how many chips are hidden and is no longer a click target, so it can no
  longer navigate somewhere unrelated.
- `Ctrl+C` quits from any screen, including an open overlay. Previously the
  control byte reached the router unmapped, so a session waiting on a blocked
  command had no keyboard way out.
- Submitting an empty passphrase from the unlock overlay keeps the overlay open
  and explains the problem instead of silently dropping the attempt.
- Backend work displays a busy notice and blocks duplicate input actions, and a
  backend command that never returns is bounded and reported instead of freezing
  the interface. The deadline is finite: an out-of-range override is rejected
  before a child is spawned, and a child that exits before its input is drained no
  longer raises an unhandled stream error.
- Late reveal results are rejected after cancellation, navigation, or lock. Locked
  snapshots clear revealed values, and refreshed list cursors remain valid.
- Backend results preserve newer input overlays. Initial-load failures use generic
  recovery guidance instead of rendering raw exception messages.

## Security fixes

- Mouse bytes can no longer be delivered into masked fields. Legacy X10 reports
  are decoded alongside SGR 1006, and a control sequence that arrives split is
  resolved fail-closed: an incomplete introducer and the tail that follows it are
  discarded rather than typed into a passphrase or secret field. A genuine Escape
  keypress, ordinary typing, and bracketed paste are unaffected. The malformed
  frame and unterminated paste budgets were tightened so a bad frame cannot
  swallow a screenful of keystrokes.
- The terminal's mouse modes are released before the alternate screen is left, so
  a returning shell never inherits live mouse reporting, and they are restored on
  abnormal exit as well as normal quit.
- A blank first frame no longer strands the session: the first-frame watchdog now
  tears the terminal state down before exiting instead of leaving an empty
  alternate screen, a hidden cursor, and raw input behind.

## Deliberately unchanged

- Non-interactive output is still ANSI-free and redacts secrets. Mouse support and
  the full-screen layout apply to the interactive workspace only.
- Reveal remains explicit, time-bounded, and never printed as a side effect.
- Storage adapters, schemas, cryptography, and the runner are untouched.

## Known limits

- A control sequence split by more than the escape window at exactly the
  `ESC`/`ESC[` boundary can still cost one keystroke: the decoder discards the
  ambiguous byte rather than risk submitting a corrupted secret. The mask shows
  the shorter length immediately, so the character is visibly missing and can be
  retyped.
- The layout validation matrix covers 40×18, 80×24, and 120×36 cells, plus the
  40×12 and 80×14 minimum-height cases. Headless Ink stream tests are not proof of
  physical mouse behavior on every operating system; native macOS and Linux
  terminal verification remains a separate check.
- `0.3.0` exists on the npm registry but was an accidental publish of a CI-only
  change: its tag was deleted, it has no GitHub release, and no dist-tag points to
  it. It contains an older codebase than this release. Install `0.2.34` or a
  `0.2.x` range; a range that admits `0.3.x` will resolve to that orphan. It
  cannot be unpublished because it is past the registry's 72-hour window.

## Verification

- `pnpm verify`: build, format check, lint, typecheck, and the full unit and
  integration suite.
- `pnpm test:coverage` for the release hygiene gate.
- Packed-artifact inspection with `pnpm --filter kavrix pack:check` and the
  package smoke test against the built tarball.
- Regression coverage for each fix listed above, including masked-field
  contamination, terminal restore ordering, click staleness, row activation, and
  the child-command deadline ceiling.
