# Release notes — 0.2.36 fullscreen setup and pointer controls

## UI improvements

- Setup and the main app fill the available terminal rows and keep their action
  controls at the bottom. Child panels remain content-sized, and compact layouts
  keep controls visible down to 40×12 cells.
- Setup uses a quieter header, a focused current-step panel, generous primary
  click targets on taller terminals, and a progress guide on wide screens.
- Main-app dialogs keep their actions at the bottom. Compact dialogs retain
  a single-line profile/vault header and keep protected input masked.
- Setup storage rows and Continue/Back/Help/Quit controls accept mouse clicks.
  Touch taps work when the terminal translates them into mouse reports.
- `Ctrl+G` or the Help control opens paged public instructions. Enter, arrows,
  and the wheel read them; Escape returns to the field without submitting it.
- `kavrix init --no-mouse` preserves native text selection and keyboard controls.
  Screen-reader and dumb-terminal sessions retain line-oriented output.
- ASCII mode sanitizes panel headings as well as field values.

## Protected interaction

Setup reuses the existing bounded pointer decoder so malformed, split, or stale
reports cannot become secret input. Duplicate destination/create/session actions
are blocked. Mouse reporting is released before the original terminal screen is
restored, including unmount and failed-mount cleanup. Help excludes protected
input values. The early destination checks and repair flow from 0.2.35 remain.

Version 0.2.35 remains available as its original immutable npm package and GitHub
release; this UI update ships as 0.2.36.

## Verification and limits

Regression tests cover terminal-filling layouts, compact and tall screens,
clickable setup journeys, padded targets, resize, masked-input canaries, stale
clicks, blocked duplicate actions, complete paged guidance, and terminal cleanup.
Additional tests cover portable POSIX permission decisions, bounded session
envelopes, malformed collaboration records, identity retirement, and exact
approval and transfer bindings. Coverage thresholds remain unchanged; native
platform CI separately exercises the real filesystem permission adapters.
Headless pointer tests do not establish physical touchscreen support in every
terminal. Publication requires the [release gates](release.md) and exact-commit
CI/CodeQL checks.
