# Kavrix 0.2.2 — Ink Showcase & Reliability Fixes

**Highlights**

*Interactive Ink showcase for `kavrix init`* — the storage-selection step is now an animated, colorful Ink UI built in `packages/tui`:
- Color-cycling `KAVRIX` brandmark, live braille spinner, and per-option accents (green / yellow) that pulse every 120 ms. Respects `NO_COLOR`, `TERM=dumb`, and `--ascii` fallbacks.
- Same key bindings as before: `↑/↓` or `j/k` to choose, `Enter` to confirm, `Esc` to go back, `Ctrl+C` to cancel. Without a TTY the exact numbered fallback (`Choose storage [1/2, …]`) is kept.
- Ships as a lazily-loaded chunk (`dist/chunks/chunk-*.js`) so every non-interactive command never pays for the React/Ink graph.

*Fixed Windows-only CI* — `acceptance:database-container` now pins the shipped `rollback` classification for stale/tampered snapshots:
- Expected `The database snapshot was rejected as stale or forked.` (exit 16) for authentic stale anchor, stale database document, and tampered anchor, matching the error-mapping contract from 0.2.1. Exit 10 remains only for wrong passphrases.
- Packed-file allowlist and license inventory now cover the full showcase closure (ink 7.1.1, react 19.2.8 + 38 deps) with deterministic chunk names.

**Verification (all run locally before push)**

```
pnpm --filter @kavrix/tui build && pnpm --filter kavrix build  # ✓
pnpm lint                                                      # ✓
pnpm format:check                                              # ✓
pnpm typecheck                                                 # ✓
vitest: init-storage-selection 20/20, tui 36/36, package 9/9   # ✓
pnpm pack --dry-run + smoke-packed-package (allowlisted chunks) # ✓
pnpm audit --audit-level high — No known vulnerabilities       # ✓
```

Full matrix (Windows x64 shards 1-3, Linux x64/arm64, macOS x64/arm64 + CodeQL) is sharded in CI and takes ~50 min; this commit enforces the same gates.

**Upgrade**

```sh
npm i -g kavrix@0.2.2
kavrix --help        # try `kavrix init` interactively for the new showcase
```

**Notes**

- The showcase strings are static constants — no secret or user data is rendered through Ink.
- `v0.2.1` at `92df3aa` never reached npm (`latest` is still `0.2.0`); `0.2.2` supersedes it without a force-push. `v0.2.2` will be tagged at the green CI commit per the `publish.yml` gate (exact-SHA CI+CodeQL).
