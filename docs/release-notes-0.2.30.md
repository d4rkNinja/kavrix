# Release notes — 0.2.30 five TUI themes with an in-app picker

New presentation feature: the interactive TUI ships five complete color
themes — genuinely different palettes, not accent tints — with a platform
default, an in-app picker, and persistence. No backend, crypto, or storage
boundary moved; every change is presentation, router navigation, or a
non-secret preference file.

## What ships

- Five themes, each a full palette (accent, heading, selection highlight,
  progress-bar color, and panel border style):
  | Theme                  | Accent  | Feel                                                     |
  | ---------------------- | ------- | -------------------------------------------------------- |
  | Classic Gold (`gold`)  | yellow  | The Kavrix signature; warm gold on quiet white.          |
  | Deep Ocean (`ocean`)   | cyan    | Cool cyan accents, blue headings, square panels.         |
  | Magma (`magma`)        | red     | Hot red accent, magenta highlights, heavy double panels. |
  | Forest (`forest`)      | green   | Calm green chrome throughout.                            |
  | Violet Dusk (`violet`) | magenta | Purple accent, blue selection, framed panels.            |
- Per-OS default: `ocean` on Windows (harmonizes with Windows Terminal's
  Campbell palette), `gold` on macOS and Linux. The user's saved choice
  always wins over the platform default.
- In-app picker: pressing `t` on any screen opens a modal listing all five
  themes. Arrow keys or digits 1-5 move a cursor that **live-previews** the
  highlighted palette (chrome tokens repaint immediately); `Enter` applies
  it and saves; `Esc` restores the previously committed theme. Each row
  paints its label in its own accent so the list itself previews the
  palettes; the committed theme is tagged `[active]`.
- Persistence: the choice is saved to `~/.kavrix/tui-theme.json` through
  the protected canonical-JSON writer (strict schema, owner-only
  permissions, atomic create/replace). It is non-secret configuration.
  Save failures (for example an unwritable home) revert the visible theme
  and surface a clear notice; nothing silently diverges.
- Explicit overrides: `kavrix tui --theme <id>` and the `KAVRIX_TUI_THEME`
  environment variable, validated against the installed ids with a
  reviewed error listing the choices. Precedence: flag/env > saved
  preference > platform default.
- All themes use the terminal's named ANSI colors, so every palette adapts
  to the host terminal scheme instead of fighting it. Semantic status
  colors (success/warning/danger/info) stay fixed across themes; `NO_COLOR`
  and dumb terminals keep the exact previous colorless behavior; ASCII mode
  still degrades borders to `+-+` regardless of theme (modals stay
  double-framed in unicode mode).

## Implementation

- `packages/tui/src/app/theme.ts` — `THEMES` registry, `defaultThemeForPlatform`,
  and the mutable active-chrome tokens swapped only through `applyTuiTheme`;
  every existing `CHROME.*` call site keeps working unchanged.
- `packages/tui/src/app/router.ts` — `theme-picker` overlay with live
  preview cursor; hydrate/backend-result adopt a valid host-reported theme
  and ignore unknown ids; `t` opens the picker from any overlay-free
  screen.
- `packages/tui/src/app/screens.tsx` — `ThemePickerRows` modal renderer
  (numbered rows, per-theme accent labels, `[active]` tag).
- `packages/tui/src/app/backend.ts` — snapshot carries `theme`;
  `set-theme` action. `packages/tui/src/app/static-backend.ts` handles it
  for tests.
- `apps/cli/src/tui-session.ts` — the host backend validates and saves the
  preference, reports the effective theme in every snapshot, and keeps
  save-failure semantics visible.
- `apps/cli/src/tui-command.ts` — `--theme` flag and `KAVRIX_TUI_THEME`
  env with fail-closed validation.

## Verification

`packages/tui/test/theme.test.ts` (8) locks the registry: exactly five
distinct ids and accents, platform defaults, token swaps, fixed semantic
tones, border-style mapping with ASCII degradation, and the screen-accent
overrides. `packages/tui/test/app/theme-picker.test.ts` (7) drives the
router: `t` opens at the active theme, cursor/preview behavior, Enter
commits with a `set-theme` effect, Esc restores, digit routing inside the
overlay, hostile snapshot ids ignored, backend round-trip, and a painted
chrome render containing every theme row. `apps/cli/test/tui-session.test.ts`
gains persistence coverage (save → reload → explicit-option precedence,
and unknown ids rejected without writing a preferences file);
`apps/cli/test/tui-command.test.ts` covers `--theme` validation. The full
TUI suite (192 tests) passes unchanged.
