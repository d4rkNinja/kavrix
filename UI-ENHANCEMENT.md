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

- `kavrix tui` / `kavrix ui` and Ink init onboarding show a centered dual-tone **KAV/RIX** splash with braille spinner (ASCII `|/-\\` when `--ascii` / win32), tagline, and CLI version.
- Auto-dismiss: backend ready + ≥1.2s, or force at 1.8s. Skip with `--no-splash` or `KAVRIX_TUI_NO_SPLASH=1` (NO_COLOR/CI/non-TTY already skip mount).
- Presentation only — no mocks. Tests in `packages/tui/test/splash.test.ts`.
