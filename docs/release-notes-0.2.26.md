# Release notes — 0.2.26 TUI interaction and motion redesign

Applies the OpenTUI skill's component/motion vocabulary to the existing Ink
renderer; the renderer stays Ink (Node cross-OS packaging unchanged) and no
backend, crypto, or storage boundary moved. All changes are presentation or
router-navigation only:

- Navigation: a screen tab strip renders under the header (hidden below 56
  columns, truncated with an ellipsis otherwise, active tab forced into the
  kept set); digits 1-9 jump to the numbered screen from any overlay-free
  screen; Tab/Shift+Tab cycle screens with wrap-around; Escape keeps
  home semantics and is tracked as a backward navigation. Doctor/recovery/
  policy/browse still fire their refresh effects when entered this way.
- Feedback: an active REVEAL shows a live "remasks in Ns" countdown bar
  driven by router `tick` (which now advances a `nowMs` clock only while a
  reveal is on screen); notices lead with tone glyphs (`[ok]`/`[!]`/`[x]`
  ASCII); modal key guides render as structured chips (confirm y/n/Esc,
  input Enter/Esc/paste, detail r/c/Esc); masked overlay input renders
  bullets with a blinking caret (static under reduced motion).
- Progress: new `ProgressBar` (determinate), `SweepBar` (indeterminate
  traveling segment that claims no percentage), `StepDots`; onboarding shows
  step dots plus a determinate bar beside the ACTIVE cue and a completed bar
  on success; the splash reveals the wordmark line-by-line, sweeps an eased
  underline, and shows the indeterminate sweep while hydrating.
- ASCII/color fidelity: every new glyph has a printable-ASCII fallback, and
  authored typographic punctuation (middle dot, dashes, ellipsis) now degrades
  to readable ASCII separators instead of `?`; unknown non-ASCII still maps
  to `?` in ascii mode. Loading labels animate dots and elapsed seconds only
  when motion is enabled and settle fully for static snapshots.

Verified by `packages/tui/test/enhancements.test.ts` (22 tests: bar/sweep/
countdown math, tone-glyph and separator ASCII purity, tab-strip truncation
and hiding, digit/tab/shift-tab routing including overlay locking, reveal
clock ticks, rendered countdown/progress/dots, home numbering parity with
the tab strip, help copy, onboarding progress) plus the pre-existing 154
TUI tests, which pass unchanged, and the full local suite on this tree
(1805 passed; the only 4 failures — three self-update EPERM symlink layout
tests and one broker denial-audit read — reproduce identically on the
pristine pre-0.2.26 tree in the same environment and pass in isolation or
on CI runners, so they are environmental, not regressions). Live-desktop
Jr/Mid/Senior paint proof remains unrecorded, as before.
