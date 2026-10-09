# Release notes — 0.2.45 friendly TUI

This release redesigns the interactive terminal app around orientation and
next steps. No encrypted format, key hierarchy, recovery guarantee, or
authorization decision changes.

## What was wrong

The app was _complete_ but not _readable_. Thirteen destinations were one flat
list under a generic "Choose an action" heading; nothing on screen said what
the current screen was for; an empty list explained itself in prose but offered
no key to press; and the notice row painted its text without any indication of
whether it was success, a warning, or a failure. A first-time user had to
memorise a keymap before they could accomplish anything.

## What changed

### Grouped destinations

The Home menu is no longer twelve undifferentiated rows. Destinations are
banded into four named sections — **Set up**, **Secrets**, **Security**, and
**Tools** — in `packages/tui/src/app/ids.ts` (`AppNavGroup`, `NAV_GROUPS`), and
rendered by the new `GroupBand` widget in `packages/tui/src/app/widgets.tsx`.
Each band reports how many destinations the section holds, so a truncated list
still tells the user how much is there.

- Section bands share the body budget with the destinations, and
  `groupedNavWindow` (`packages/tui/src/app/navigation.ts`) never leaves a band
  as the last visible row — a section header that promises entries scrolled out
  of view is worse than no header.
- Bands are presentation only. They never consume a cursor slot, so the
  router's menu-index semantics, the digit shortcuts, and `Tab` cycling are
  unchanged, and the number on a row still matches the number in the tab strip.
- `Storage docs` moved from **Set up** to **Tools**: it is read-only
  documentation, not a step in standing a vault up.

### Every screen says what it is for

A `ScreenHint` row under the header states the screen's purpose and its keys,
sourced from `SCREEN_GUIDES` in `packages/tui/src/app/ids.ts` and resolved
through `screenGuide`. The row is omitted below 16 rows so a compact viewport
spends its budget on the body instead, and the body's height budget pays for it
when it is present — the frame still fills exactly the terminal height.

`screenGuide` is state-aware, and that matters: while the Credentials name
filter is open every printable key is filter text, so the guide switches to
"Name filter open: every key narrows the list. Esc clears." rather than
advertising `n put` / `c copy` / `r reveal`, which would type into the search
instead of running. This is the same discipline the footer's filtering chip set
already follows, and it is asserted in
`packages/tui/test/app/friendly-ui.test.ts`.

Guide copy is bounded to 73 characters so it survives the 80-column layout
matrix; a clipped hint loses its tail, and the tail is usually the key.

### Empty states carry the next step

`EmptyState` gained an optional `action` slot, and the screens that most often
start empty use it: Profiles offers `n create a file profile`, Credentials
offers `n put a credential` while unlocked and `u unlock your vault` while
locked, Recovery offers `n create a recovery kit`, Doctor offers
`d run doctor checks`, and Policy offers `n create policy` / `g issue a grant`.

An affordance the screen cannot honour is worse than none, so:

- Vaults offers `u unlock your vault` only while the vault is locked, and its
  empty message changes from "Select a profile, then unlock (u)." to
  "No vaults in this datastore yet. Press n to create one." once it is open.
- Session unlock offers the same gated unlock chip, because session unlock only
  exists on an unlocked profile.
- Lists that have rows keep a single guidance line inside the panel
  (`ListScreen`'s new `hint` prop) instead of a separate paragraph below it, so
  the count, the guidance, and the rows read as one block.

### Notices are legible without colour

The notice row now prefixes the snapshot's tone glyph (`✓`, `⚠`, `✕`, `ℹ`)
alongside its existing colour, so `NO_COLOR`, `--ascii`, and dumb terminals get
the same information from the wordless shape as a colour terminal does. The
glyph comes from the same `toneGlyph` helper the rest of the chrome uses, so
ASCII mode keeps the bracketed `[ok]` / `[!]` / `[x]` tokens.

### The chrome reads like a product, not a spec

The first draft of the grouping landed the destinations but still wrote its
titles, hints, and separators the way an implementer thinks about the code. Four
follow-on fixes close that gap:

- **Titles match the menu.** Panels are titled `[ PROFILES ]`,
  `[ DOCTOR / HEAL ]`, `[ RECOVERY KIT ]`, `[ RUN PREVIEW ]`,
  `[ SESSION UNLOCK ]`, `[ STORAGE DOCS ]` — the same label the tab strip and
  the Home menu already use — instead of internal prose such as
  `Doctor / heal (local health, not recovery kit)`. The disambiguation those
  parentheticals carried moved to the body copy that already discussed it, so
  nothing is lost and nothing reads as a schema field name.
- **Leading glyphs keep their space.** `toneGlyphLead` (`theme.ts`) joins the
  Unicode glyph (which is pre-padded) and the ASCII token (which is not) into a
  single form that always ends in exactly one space. ASCII sessions previously
  rendered `[i]Pick a destination below…` and `[ok]Vault default is loaded.`;
  they now render `[i] Pick…` and `[ok] Vault…`.
- **Empty-state steps are labelled.** The chip row is prefixed `Next step >`,
  so `n create a file profile` reads as an instruction rather than decoration.
  Screens with two first steps use `ActionChips`, which separates them with a
  dim `·`; Policy previously rendered one glued line,
  `n create policy g issue a grant`.
- **List guidance is bounded, not silently cut.** A guidance row is one cell
  tall, so `ListScreen` truncates to `LIST_HINT_MAX_CELLS` (76) cells — the same
  bound `SCREEN_GUIDES` already carries — and every hint was rewritten to fit it.
  The Profiles hint used to read `…x removes it and keeps its files`; at 80
  columns the tail was cut mid-word and the user never learned that removal
  keeps the files. Policy rows now lead with the identifier and trail the badges
  (`policy.read [POLICY]`, `grant.agent [GRANT] [ACTIVE]`) instead of
  `policy policy.read`, which reads like a typo.

## Verification

- `GroupBand`, `ScreenHint`, and the grouped window are covered by 26 new
  assertions in `packages/tui/test/app/friendly-ui.test.ts`: grouping order and
  counts, cursor visibility at every position, no trailing band at window sizes
  1–40, filter-aware guide text, exact frame heights at 80×24 / 100×30 /
  120×36, ASCII-only chrome for all thirteen screens, and the gated unlock
  affordances.
- The polish pass adds assertions for the readable panel titles and the copy
  that replaces them, the `Next step >` label, the chip separator, the glyph
  spacing on every screen, the `LIST_HINT_MAX_CELLS` budget, and the frame still
  filling exactly the terminal height at 80×24 / 100×30 / 120×36 / 80×14 / 40×18.
  `packages/tui/test/theme.test.ts` asserts the lead form ends in exactly one
  space in both text modes.
- Full suite: 2202 tests across the workspace (21 skipped), 467 of them in
  `packages/tui`, all green. Coverage is 86.83% statements / 80.37% branches /
  91.18% functions / 88.38% lines — the same thresholds and numbers as the
  previous release, so no gate was moved to accommodate this change. Format,
  lint, typecheck, and build are green, `pnpm audit --audit-level high` reports
  no known vulnerabilities, the packed all-command local-file acceptance flow
  passes, `npm pack --dry-run` reports `kavrix-0.2.45` with only the 58 files the
  `files` allowlist names, the CLI include guard confirms all 68 source modules
  are in both tsconfig include lists, and the note/history packaged-executable
  smoke passes.
- `docs/tui-guide.md` now documents the grouped menu, the orientation row, the
  actionable empty states, and the title/copy/spacing rules above.

## What this release does not do

It does not add, remove, or renumber a screen; the tab-strip numbering and
per-screen mnemonics are unchanged, so existing muscle memory still works. It
does not change any keybinding, the command palette, the theme system, the
mouse layer, or the masking and REVEAL rules. Secrets remain masked until an
explicit, confirmed REVEAL, and every rendered string still passes through
`sanitizeTerminalText`.
