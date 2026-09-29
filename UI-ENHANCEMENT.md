# Kavrix TUI UI Enhancement

Date: 2026-09-18 (Asia/Calcutta)
Branch: `feature/full-interactive-tui`
Runtime: **Ink + React** (not OpenTUI native renderer)

## Why Ink (not OpenTUI runtime)

OpenTUI’s native Zig renderer requires Bun or Node 26.4+ with `--experimental-ffi`.
Kavrix ships as a Node/npm CLI for Linux / macOS / Windows, so `kavrix tui` stays on
**Ink + React** for cross-OS compatibility. This work applies the **OpenTUI skill
design system** (layouts, containers, selects, banners, modals) using Ink equivalents.

## Copy / paste (2026-09-18)

### Paste into text overlays

- Ink `usePaste` is wired in `packages/tui/src/app/app.tsx` alongside `useInput`.
  Bracketed paste arrives as one string and is **never** forwarded as Enter.
- Router `sanitizePasteText` + `appendOverlayText` strip `\x1b[200~` / `\x1b[201~`,
  trailing `\r`/`\n`, and remaining controls; multi-char `input` is treated as paste.
- Masked overlays (passphrase, Mongo URL, put value) still mask display; long pastes
  append once up to field limits.
- Unlock / URL / put-value modals show: `Paste works (Ctrl+Shift+V / Cmd+V)`.

### Copy credential without printing forever

- Credentials screen: `c` → backend `copy-credential` (no on-screen plaintext).
- CLI session (`apps/cli/src/tui-session.ts` + `tui-clipboard.ts`): fetch via `get --reveal`,
  write clipboard preferring **OSC 52**, fallback to `pbcopy` / PowerShell / `wl-copy` /
  `xclip` / `xsel`. Best-effort OSC clear after ~30s.
- Notice: `Copied (clipboard clears in ~30s)`. Reveal remains `r` then `y` (15s UI timer).
- Footer on Credentials documents `c copy` / `r reveal`.

### Mouse selection

- Mouse tracking is **not** enabled (Ink default). OS terminal drag-select / Shift+drag
  still works. Documented on the Help screen.

## UX polish

- Contextual footer key chips (home / credentials / profiles / default).
- Empty states with next action (credentials unlock/put; vaults profile+unlock).
- Navigate menu: aligned label + hint columns via `SelectRow` `labelWidth`.
- Unlock modal: clearer title (`Unlock vault`) + paste hint.
- Help: short “Getting started” + copy/paste notes.
- ASCII / Windows (`--ascii`, win32) and `NO_COLOR` unchanged.

## Verify

```bash
pnpm --filter @kavrix/tui test
pnpm --filter @kavrix/tui build
pnpm --filter kavrix build
```

## Animated splash (2026-09-18)

- `kavrix tui` / `kavrix ui` and Ink init onboarding show a centered dual-tone **KAV/RIX** splash with braille spinner (ASCII `|/-\` when `--ascii` / win32), tagline, and CLI version.
- Auto-dismiss: backend ready + ≥1.2s, or force at 1.8s. Skip with `--no-splash` or `KAVRIX_TUI_NO_SPLASH=1` (NO_COLOR/CI/non-TTY already skip mount).
- Presentation only — no mocks. Tests in `packages/tui/test/splash.test.ts`.

## Interaction + motion redesign (2026-09-29)

OpenTUI-skill patterns (tab-select, progress bar, staged reveal, layered
keys) ported onto the same Ink renderer. No backend/crypto change.

### Navigation

- **Tab strip** under the header lists screens with digit numbers (`1 Home …
9 Policy …`), inverse-highlights the active screen, truncates with `…` on
  narrow widths, and hides below 56 columns.
- **Digits 1-9** jump to the numbered screen from any overlay-free screen;
  the Home menu rows and Help document the same numbers.
- **Tab / Shift+Tab** cycle screens forward/backward with wrap-around
  (Esc keeps its Home semantics).
- Router tracks `navDirection` so screen transitions can settle differently
  for forward vs. backward navigation.

### Feedback + progress

- Timed REVEAL shows a live `REVEAL remasks in Ns ██████░░░░` countdown bar
  (router `tick` advances a `nowMs` clock only while a reveal is visible).
- New widgets: `ProgressBar` (determinate `█/░`, ASCII `#/-`), `SweepBar`
  (indeterminate traveling segment — decorative, claims no percentage),
  `StepDots`, `Divider`, `TabNav`, `RevealCountdown`.
- Notices lead with tone glyphs (`✓ ⚠ ✕ ℹ` / ASCII `[ok] [!] [x] [i]`).
- Modal key guides render structured chips: confirm `y/n/Esc`, input
  `Enter/Esc/^V paste`, detail `r/c/Esc`. Masked input shows `•` bullets
  (ASCII `*`) with a blinking caret; caret is static under reduced motion.
- Loading labels animate trailing dots + elapsed seconds (motion-gated).
- Onboarding: step dots + determinate progress bar beside the ACTIVE cue,
  completed bar + `✓` on success.
- Splash: wordmark reveals line-by-line, eased underline sweep, indeterminate
  sweep track while hydrating; full wordmark still paints in the static
  (`animate=false`) frame the tests lock.

### ASCII / typography

- Authored punctuation (`·`, `—`, `–`, `…`) degrades to readable ASCII
  (`-`, `...`) instead of `?`; unknown non-ASCII still fails closed to `?`.
  Home layout keeps `[ HOME / DASHBOARD ]` on one line; menu numbers only
  appear for screens that actually have digit shortcuts (1-9).

### Verify

```bash
pnpm --filter @kavrix/tui test   # includes test/enhancements.test.ts (22 new tests)
pnpm verify
```
