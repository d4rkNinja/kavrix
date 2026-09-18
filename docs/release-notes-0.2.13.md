# Kavrix 0.2.13 — Full interactive TUI and Ink-first init

Kavrix 0.2.13 ships the colorful Ink terminal UI as a first-class product surface and makes interactive onboarding match that experience.

## What changed

- **`kavrix tui` / `kavrix ui`.** Mounts the Ink app against the real CLI backend: unlock, profiles (including create-file and create-mongodb), vaults, credentials (put/rename/remove/reveal/copy), doctor, recovery, run preview, policy/grant/audit, agent dry-run, browse, and help. Product paths use zero mocks.
- **`kavrix init` defaults to TUI onboarding** on an interactive TTY. Pass `--no-tui` for classic masked line prompts, or use stdin/explicit routing for automation and legacy v2 paths.
- **Demo assets.** Terminal-only walkthrough (`docs/assets/kavrix-tui-demo.mp4` / `.gif`) plus unlocked-home and profiles screenshots. npm packs the hero PNG and GIF under `apps/cli/media/` so the registry README can render them.

## Operator notes

- Requires Node.js `>=24.12.0 <25` or `>=25.1.0` (Linux, macOS, Windows).
- Scripts and CI should keep using numbered CLI commands with `--passphrase-stdin` / `--secrets-stdin`, or `kavrix init --no-tui` when a classic guided TTY is preferred.
- Reveal and copy stay explicit; passphrases are never echoed by default.

## Verification

- Live vault smoke (`scripts/tui-vault-smoke.ts`) and the TUI release gate document zero product mocks.
- Packed CLI allowlist includes `media/demo-frame-home-unlocked.png` and `media/kavrix-tui-demo.gif`.

Previous release: 0.2.12 — install/docs UX and CLI issue fixes.
