# Kavrix TUI assets

- `demo-frame-home-unlocked.png` — current Home, including every grouped destination.
- `demo-frame-credentials.png` — current Credentials list, with all values masked.
- `demo-frame-actions.png` — current command palette, including blocked-action reasons.
- `kavrix-tui-demo.gif` — these three settled frames, held for 4/5/5 seconds.

These are reproducible captures of the actual Ink components at 104×34 cells,
using explicitly synthetic metadata. They are not a recording of a real vault
or evidence of backend execution. No passphrase, credential value, local path,
or other user data is used. Terminal colors use a readable dark palette.

Regenerate with `pnpm exec tsx --tsconfig packages/tui/tsconfig.json scripts/capture-readme-tui.mjs`.
The script requires `sharp`; if supplied by an external tool runtime, set
`KAVRIX_SCREENSHOT_SHARP` to that module's entry file before running.

The Home PNG and GIF are copied to `apps/cli/media/`. npm's existing README
loads those paths from GitHub `HEAD`, so refreshing them also refreshes the
already-published npm page without changing an immutable package version.

`kavrix-tui-demo.mp4`, `demo-hero.png`, `demo-frame-profiles.png`, and
`demo-frame-mid.png` are historical assets, not current README illustrations.
