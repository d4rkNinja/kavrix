# Kavrix TUI demo assets

- `kavrix-tui-demo.mp4` — terminal-window-only demo (~13s): animated splash → unlock → profiles → credentials → help.
- `kavrix-tui-demo.gif` — same walkthrough for README embeds.
- `demo-hero.png` — unlocked Home after splash (primary hero still).
- `demo-frame-home-unlocked.png` — copy of the hero still for npm/README embeds.
- `demo-frame-profiles.png` / `demo-frame-mid.png` — older stills kept for docs.

Recorded from the interactive Ink TUI (`kavrix tui`) against a real local vault (no mocks). Splash is presentation-only (`--no-splash` / `KAVRIX_TUI_NO_SPLASH=1` to skip).

npm ships copies of the hero PNG and GIF as `apps/cli/media/` so the published package README can render them.
