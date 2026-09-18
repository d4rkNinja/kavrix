# Kavrix TUI UI Enhancement

Date: 2026-09-18 (Asia/Calcutta)
Branch: `feature/full-interactive-tui`
Runtime: **Ink + React** (not OpenTUI native renderer)

## Why Ink (not OpenTUI runtime)

OpenTUI’s native Zig renderer requires Bun or Node 26.4+ with `--experimental-ffi`.
Kavrix ships as a Node/npm CLI for Linux / macOS / Windows, so `kavrix tui` stays on
**Ink + React** for cross-OS compatibility. This work applies the **OpenTUI skill
design system** (layouts, containers, selects, banners, modals) using Ink equivalents.

Skill references adapted:

- `.agents/skills/opentui/references/layout/patterns.md` — header / content / footer;
  sidebar-style split when width ≥ 80; centered modals
- `.agents/skills/opentui/references/components/containers.md` — bordered boxes, title
  simulation, padding, per-screen `borderColor`, styles round | double | classic
- `.agents/skills/opentui/references/components/inputs.md` — select rows with clear
  active highlight (inverse / accent bar)
- `.agents/skills/opentui/references/components/text-display.md` — dual-tone brand banner

## OpenTUI → Ink mapping

| OpenTUI | Ink equivalent |
| --- | --- |
| `box` + `borderStyle="rounded"` | `Box borderStyle="round"` |
| `borderStyle="double"` (modals) | `Box borderStyle="double"` |
| ASCII / Windows borders | `Box borderStyle="classic"` (`+-+|`) |
| `title=` on box | `Panel` header via `sectionTitle()` label row |
| `select` active row | `SelectRow` with `inverse` + accent / dim inactive |
| Full-screen column layout | `AppChrome`: Header → `flexGrow={1}` Content → Footer |
| Sidebar when width > 60 | Home: row at width ≥ 80, stacked otherwise |
| Centered modal | `ModalFrame` (double / classic) for passphrase & confirms |
| Status chrome | `StatusPill` row (lock, profile, vault, creds) |
| Footer keymap | `KeyChip` colored keys + dim labels |

## Presentation changes (wiring untouched)

- New widgets: `packages/tui/src/app/widgets.tsx`
  (`Panel`, `StatusPill`, `KeyChip`, `SelectRow`, `SectionTitle`, `ModalFrame`, `CardRow`)
- Theme helpers: `panelBorderStyle`, `screenAccent`, `doctorStatusAccent`
- `screens.tsx` — premium panel chrome on every screen; credentials card rows +
  warning reveal inset; doctor pass/warn/fail colorization
- `showcase.tsx` — `BrandBanner` dual-tone cyan/magenta (`dualTone` prop)
- **No** changes to `createCliTuiBackend` / router action semantics — presentation only

## Cross-OS / accessibility

- `process.platform === 'win32'` or `--ascii` or ASCII presentation → classic borders,
  `>` pointers, `********` masks, no fancy unicode
- `NO_COLOR` / `--no-color` / `TERM=dumb` → no color props
- No Bun-only APIs

## Verify

```bash
pnpm --filter @kavrix/tui test   # 68 PASS
pnpm --filter @kavrix/tui build
pnpm --filter kavrix build
```
