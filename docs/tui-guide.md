# Terminal output and interactive TUI

The public `kavrix` CLI uses Commander for command parsing and sanitized
terminal rendering. Values are masked by default; plaintext display requires an
explicit guard such as `get --reveal` or a TUI **REVEAL** confirmation.
Non-interactive output is ANSI-free.

## Interactive onboarding (`kavrix init`)

Bare interactive `kavrix init` mounts Ink onboarding by default when stdin,
stdout, and stderr are TTYs. It creates a local-file database, default vault,
and recovery kit through the same real CLI backend as `kavrix tui`. Pass
`--no-tui` for classic masked line prompts. Explicit routing or stdin flags
keep the non-interactive / legacy paths.

## Interactive app (`kavrix tui` / `kavrix ui`)

`kavrix tui` (alias `ui`) mounts the colorful Ink app from `@kavrix/tui` when
both stdin and stdout are TTYs. Non-TTY sessions print a clear error and exit
non-zero so automation keeps using numbered CLI commands. Every screen action
runs the published CLI (no product mocks).

Screens: Home, Profiles, Vaults, Credentials (masked / REVEAL; Enter opens
detail), Doctor / heal (local health, not key recovery), Recovery kit
(key-material slots), Run preview (not `run --environment`),
Policy/Grant/Audit, Agent, Vault context / service / item browse (vault
hierarchy, not the CLI project-file `--environment` flag), Help, and the
existing storage showcase destination.

Security and presentation rules:

- Never echo passphrases or secret values by default.
- Reveal only after an explicit confirm step labeled REVEAL (15s UI timer).
- Sanitize all terminal strings (`packages/tui/src/terminal-text.ts`).
- Honor `NO_COLOR` and `TERM=dumb` (disable color).
- Honor `KAVRIX_TUI_REDUCED_MOTION` / `PREFERS_REDUCED_MOTION` (skip splash,
  list stagger, and status pulse). Non-TTY and non-interactive sessions never
  mount the app.
- Support `--ascii` and auto-ASCII on Windows (`process.platform === 'win32'`)
  or terminals without Unicode.
- Paths use `node:path` joins; no bashisms.
- Prefer library calls; when the host spawns the CLI, secrets travel only as
  stdin frames — never argv.

Flags: `--ascii`, `--color`, `--no-color`, `--no-splash`, `--no-mouse`, `--profile-config-dir`
/ `--config-dir`. `KAVRIX_TUI_NO_SPLASH=1` also skips the startup splash.

Chrome is content-sized, capped below the terminal row count, and remounts after
hydrate, resize, and screen/step changes. An interactive session paints in the
terminal's alternate screen and restores the original screen on exit, which also
keeps mouse hit regions aligned with the live layout. Onboarding shows an
`ACTIVE n/m — <step>` cue so the focused field is obvious. `kavrix tui` shows a
Loading… state until vault hydrate completes (or an error/timeout banner if it
fails). Missing TTY columns/rows fall back to 80×24 so Mid-style fixtures still
paint. Footer chips prioritize Enter/detail, Esc, and q on narrow terminals, plus
`u` unlock while the vault is locked, so the unlock control survives overflow.
`+N more` reports how many chips are hidden and is not itself clickable; press
`?` for Help from any screen. Home and data lists render bounded windows; `/`
search filters client-side. Escape remasks a REVEAL and returns focus to the
credentials list. Clicking the startup splash skips it.

## Mouse and workflow navigation (0.2.34)

Click a tab or Home destination to open it. Click a credential to open masked
detail. For profiles and vaults, click to select, then click the selected row to
use it. Other data rows select without activating a destructive operation. Click
an action chip to invoke the displayed key action. Click a theme to preview it;
Enter applies and saves it. Mouse wheel input moves the current selection.
Reveal, lock, removal, and revocation keep their existing confirmation steps.

Home recommends profile creation, unlock, or credential browsing based on the
current session. Help has five topics selected with arrows, the wheel, or topic
chips. While an operation is running, a busy notice appears and duplicate actions
are blocked. Escape can still cancel an overlay; `q` (outside inputs) or `Ctrl+C`
exits from anywhere, including an open overlay.

The workspace paints in the terminal's alternate screen and restores your original
scrollback on exit, so it behaves like a full-screen application rather than an
inline frame. This is independent of mouse support.

Mouse input uses the SGR protocol, with the legacy X10 encoding also decoded so
terminals that track clicks but ignore SGR 1006 cannot leak printable mouse
bytes into masked fields. A control sequence that arrives split by the terminal is
resolved fail-closed: the incomplete part is discarded rather than typed into a
masked field, which can cost one keystroke on a very slow link. Wheel input is
honoured with Shift, Ctrl, or Meta held. This works on Windows, macOS, and Linux
terminals that support VT output and mouse reporting. Unsupported terminals
retain keyboard controls. Tracking is disabled by `--no-mouse`,
`KAVRIX_TUI_MOUSE=0`, `TERM=dumb`, or `INK_SCREEN_READER=true` (the value Ink
itself reads). Shift+drag usually selects text while tracking is active; the exact
selection modifier depends on the terminal. Use `--no-mouse` for native selection
without giving up the full-screen layout. The layout matrix is 40×12, 40×18,
80×14, 80×24, and 120×36 cells; physical terminal mouse behavior on every OS is
not established by the headless stream tests.

## Themes

The TUI ships five color themes: Classic Gold (the Kavrix signature), Deep
Ocean, Magma, Forest, and Violet Dusk. Press `t` on any screen to open the
picker — arrows or 1-5 preview a theme live, `Enter` applies and saves it,
`Esc` restores. The choice persists in `~/.kavrix/tui-theme.json`; override
for one session with `kavrix tui --theme <id>` or `KAVRIX_TUI_THEME`. The
default is Deep Ocean on Windows and Classic Gold elsewhere. Semantic
status colors stay fixed in every theme, and `NO_COLOR` still disables all
color.

## Storage showcase

The active `@kavrix/tui` workspace also keeps a read-only storage docs /
showcase screen inside the full app. Presentational strings there have no
persistence, cryptographic, or secret-input authority. Primary onboarding is
`mountOnboardingApp` from bare TTY `kavrix init`; `--no-tui` and non-TTY paths
retain classic guided or legacy flows.

Masked interactive prompts render textual requirement, success, and error
markers and retry a locally invalid field without discarding unrelated answers.
Color is supplemental, appears only on a capable TTY, and is disabled by
`NO_COLOR` or `TERM=dumb`; protected stdin remains silent and ANSI-free.

Terminal-rendered content is treated as hostile. Control, ANSI, and OSC
sequences are sanitized before display.
