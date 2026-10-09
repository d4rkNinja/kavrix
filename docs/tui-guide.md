# Terminal output and interactive TUI

The public `kavrix` CLI uses Commander for command parsing and sanitized
terminal rendering. Values are masked by default; plaintext display requires an
explicit guard such as `get --reveal` or a TUI **REVEAL** confirmation.
Non-interactive output is ANSI-free.

## Interactive onboarding (`kavrix init`)

Bare interactive `kavrix init` mounts Ink onboarding by default when stdin,
stdout, and stderr are TTYs. It creates a file or MongoDB database, default vault,
and recovery kit through the same real CLI backend as `kavrix tui`. Pass
`--no-tui` for classic masked line prompts. Explicit routing or stdin flags
keep the non-interactive / legacy paths.

Setup fills the terminal and keeps its controls at the bottom. Wide screens show
a progress guide; compact screens prioritize the current field and actions.
Click a storage row to select it, then click Continue to confirm. Continue, Back,
Help, and Quit use the same guards as keyboard input. Controls have larger click
targets when at least 24 rows are available. Touchscreen taps work only when the
terminal translates them into mouse reports; keyboard input is always available.

Press `Ctrl+G` or click Help for the complete current instructions. Enter, arrows,
or the wheel page through them; Escape returns to the field. Reading Help never
submits or changes that field, and protected values are excluded from Help.
`Ctrl+C` quits except while a destination check or protected create/session
operation is running. Duplicate actions are blocked until it finishes.
Use `kavrix init --no-mouse` or `KAVRIX_TUI_MOUSE=0` for native selection.

## Interactive app (`kavrix tui` / `kavrix ui`)

For an existing vault, open `kavrix tui`, press `u` to unlock, then `4` for
Credentials. Use `Shift+U` to enter a passphrase directly if OS session unlock
is unavailable. Escape closes overlays; `?` opens Help. Agent validates a project
configuration; start a live broker with the CLI rather than leaving that screen open.

### Seeing what you can do: `:` or `Ctrl+K`

Thirteen screens with per-screen mnemonic keys are hard to learn, so the app
carries a command palette. Press `:` (or `Ctrl+K`) on any screen to list every
action that screen can perform, grouped by screen and "Always available".

Each row shows the key and what it does:

```text
Actions                                    (packages/tui/src/app/commands.ts)
  Credentials
    Enter  view masked detail
    c      copy to clipboard
    r      reveal value
    n      add credential
    ...
  Always available
    u      unlock vault
    l      lock vault
    t      change theme
    a      toggle ascii
    ?      help
    Tab    next screen
    Esc    back to home
    q      quit
```

- `j`/`k` or the arrow keys move; `1`–`9` jump to a row; `Enter` runs it.
- Typing filters by label, hint, or key — `reveal` narrows to one row.
- When an action cannot run, its row stays visible and shows why, for example
  "Unlock the vault first (u) to add a credential." A blocked action never
  silently does nothing.
- `Esc` closes without running anything.

Choosing a palette entry dispatches the same keystroke as pressing the key, so
the palette cannot mean something different from the key it names. This is
asserted for every command on every screen in
`packages/tui/test/command-palette.test.ts`, which additionally checks that every
key the footer advertises exists as a palette entry.

### Keys that behave the same everywhere

These are advertised in the footer of every screen, not only Home:

| Key                 | Action                                                   |
| ------------------- | -------------------------------------------------------- |
| `u` / `Shift+U`     | unlock (session / forced passphrase)                     |
| `l`                 | lock                                                     |
| `t`                 | theme picker                                             |
| `a`                 | toggle ASCII                                             |
| `?`                 | Help from any screen                                     |
| `Tab` / `Shift+Tab` | cycle screens                                            |
| `Esc`               | return Home (also clears a REVEAL first, on Credentials) |
| `q`                 | quit (outside input overlays)                            |
| `Ctrl+C`            | quit from anywhere, including inside overlays            |

`/` starts a live name filter on the Credentials screen. Typing narrows the list
on every keystroke — no search box opens, so nothing you type is ever invisible.
`Backspace` edits, `Esc` clears the filter and restores every row, `Enter` opens
the highlighted credential, and `j`/`k` plus the arrow keys move through the
matches. While a filter is open every other printable key is filter text, so
screen shortcuts are suspended until you press `Esc`. `/` is a Credentials-only
control; on any other screen it answers that search lives on Credentials (press 4) instead of opening a search box that screen could not use.

### If the terminal feels choppy

Finite entrance, list, and splash-reveal animations release their clock
subscriptions when they settle. Loading elapsed seconds share the spinner clock
instead of requesting a repaint every 32 ms. Continuous spinners and input caret
blink still run while needed; these changes do not shorten storage or unlock work.

For remote terminals or reduced motion, use this in PowerShell:

```powershell
$env:KAVRIX_TUI_REDUCED_MOTION = '1'
kavrix tui --no-splash --no-mouse --ascii
```

Or on a POSIX shell:

```sh
KAVRIX_TUI_REDUCED_MOTION=1 kavrix tui --no-splash --no-mouse --ascii
```

This retains keyboard controls and native terminal text selection. If loading
fails, read the displayed error and use `kavrix doctor --help` for diagnostic
options. Preserve existing protected files and recovery kits; initialization
is not an unlock repair. See [agent setup](getting-started.md) for CLI workflows.

Resize bursts are coalesced over one 32 ms window using the latest dimensions;
pending resize work is canceled on unmount. Onboarding ignores unchanged sizes.
Input readiness waits for the resized frame, and pointer reports are discarded
while the layout is pending rather than acting on old coordinates.
Loading spinners honor reduced-motion settings as well as list and input motion.

`kavrix tui` (alias `ui`) mounts the colorful Ink app from `@kavrix/tui` when
both stdin and stdout are TTYs. Non-TTY sessions print a clear error and exit
non-zero so automation keeps using numbered CLI commands. Screens call CLI-owned
use cases; administrative and legacy actions invoke the published CLI.

Screens: Home, Profiles, Vaults, Credentials (masked / REVEAL; Enter opens
detail), Doctor / heal (local health, not key recovery), Recovery kit
(key-material slots), Run preview (not `run --environment`),
Policy/Grant/Audit, Agent, Vault context / service / item browse (vault
hierarchy, not the CLI project-file `--environment` flag), Help, and the
existing storage showcase destination.

On Home, press `u` to unlock and `4` to open Credentials. `Shift+U` always
opens protected passphrase input, so an unavailable OS keychain cannot trap
you in repeated session-unlock attempts. Expired sessions open passphrase
input directly. MongoDB unlock first asks for its masked connection string;
the connection stays in memory for later operations and is cleared on lock
or an unsuccessful authentication attempt.

While a command runs, the footer names the operation and shows elapsed seconds.
`q` exits the app. A child command that exceeds its 60-second deadline is stopped;
this is a timeout, not evidence that the passphrase was wrong. Storage permission
checks remain mandatory. Common credential actions share one fresh verified
profile read for their routing and stdin frames, and use the selected vault.

These TUI changes do not change encrypted vault, portable-key, or profile formats.
Opening an existing vault does not request migration or reinitialization. Package
updates and data-format compatibility are separate checks; preserve your existing
protected files and recovery kit, and never run initialization over them to fix
an unlock error. Cross-platform and real MongoDB verification must still pass
before a release is claimed.

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

The viewport fills the terminal row count while child panels remain content-sized,
with footer controls pinned at the bottom. Chrome remounts after hydrate, resize,
and screen/step changes. An interactive session paints in the
terminal's alternate screen and restores the original screen on exit, which also
keeps mouse hit regions aligned with the live layout. Onboarding shows an
`ACTIVE n/m — <step>` cue so the focused field is obvious. `kavrix tui` shows a
Loading… state until vault hydrate completes (or an error/timeout banner if it
fails). Missing TTY columns/rows fall back to 80×24 so Mid-style fixtures still
paint. Footer chips prioritize Enter/detail, Esc, and q on narrow terminals, plus
`u` unlock while the vault is locked, so the unlock control survives overflow.
`+N more` reports how many chips are hidden and is not itself clickable; press
`?` for Help from any screen. Home and data lists render bounded windows; `/`
filters credential names live on Credentials. Home/End select the first/last
row; Page Up/Page Down jump through lists. Credential paging adapts to terminal
height and the visible reveal panel, and uses the filtered list. Screen
shortcuts do not act behind input or confirmation overlays, and are suspended
while a credential name filter is open. Repeated resize reports and ignored keys avoid redundant
state updates and mouse-frame invalidations. The reveal countdown updates once per displayed second; the expiry check
still runs every 250ms. Escape remasks a REVEAL and returns focus to the
credentials list. Clicking the startup splash skips it.

The splash also dismisses as soon as the backend is ready; there is no minimum
animation wait. Browse loads one authenticated metadata snapshot, available to
scripts as `kavrix context list --tree --json`, including context, service, and active item
labels, never field values. The preview is bounded to 20 contexts, 20 services
per context, and 30 items per service. A warning identifies truncation; use the
individual CLI lists for the full hierarchy. Agent dry-run validates the project
configuration and database profile without forwarding passphrases or connection
strings; it does not verify that secrets exist or that execution will succeed.
The optional Agent config path now discovers one `kavrix.yaml`, `kavrix.yml`, or
`kavrix.json` in the working directory. Multiple defaults require an explicit
path; invalid or unreadable discovered files fail closed. See the
[agent guide](agent-guide.md) before starting a live broker.

For bound database profiles, unlock, credential CRUD, copy/reveal, Browse, and
Policy/Grant/Audit refresh reuse one in-memory authenticated session. Storage is
reopened for each operation and closed afterward, so no file writer lock remains
held while idle. Every reuse verifies protected key-file bytes and permissions,
the profile binding, authenticated database/vault state, and the rollback anchor.
Changed key files or database catalogs, corruption, and failed operations clear
the session and require unlocking again. External authenticated vault writes are
read afresh; mutation revision checks remain mandatory.

The TUI locks after two minutes without backend actions or fifteen minutes since
unlock. Keyboard-only navigation does not extend the idle deadline. Expiry clears
keys, retained passphrase/connection buffers, metadata, and visible reveal state.
An action already in progress is allowed to settle before cleanup. Profile
changes and app exit dispose the session. Administrative subprocess actions
release reusable keys before running; the next common action authenticates again.
Legacy standalone profiles retain their existing subprocess route and the same
TUI lifetime bounds. OS keychain session unlock is a separate facility with its
own configured TTL.

`kavrix policy snapshot --json` reads policies, grants, and the bounded audit ring
from one authenticated sidecar read. TUI refresh renders all three together and
reports read failures instead of presenting a missing audit result as success.

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

### Screens

Thirteen screens are reachable by `Tab`, `Shift+Tab`, the digits `1`–`9`, the Home
menu, or the command palette:

|   # | Screen                 | What it is for                                         |
| --: | ---------------------- | ------------------------------------------------------ |
|   1 | Home                   | status dashboard and the menu                          |
|   2 | Profiles               | datastore routing (file / MongoDB)                     |
|   3 | Vaults                 | vault selection and creation                           |
|   4 | Credentials            | flat name/value credentials: add, filter, copy, reveal |
|   5 | Doctor / heal          | local health and permission checks                     |
|   6 | Session unlock         | OS-credential-store session unlock                     |
|   7 | Recovery kit           | key-material slots                                     |
|   8 | Run preview            | dry-run check for a command (never injects secrets)    |
|   9 | Policy / Grant / Audit | authorization state and activity                       |
|   — | Agent                  | agent dry-run validation                               |
|   — | Browse                 | context / service / item hierarchy (metadata only)     |
|   — | Help                   | the full keymap, in five topics                        |
|   — | Storage docs           | read-only storage summary                              |

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

## Guided setup (0.2.37)

Path fields offer `Ctrl+D` for the secure default, `Ctrl+B` to browse folders,
and `Ctrl+R` to preview directory permission repair. Enter confirms a repair;
Escape cancels. Only Kavrix's owned artifact directory can be repaired by this
control. Other locations require manual repair or a different destination.
Enter on a path checks it again and retains other answers on rejection.

The browser lists at most 100 folders while scanning at most 1,000 entries.
Arrows select, Enter opens, `Ctrl+P` moves to the parent, and `Ctrl+S` chooses
the current folder while preserving the filename. It never reads file contents.
Secure default paths start browsing at the home folder, so a first installation
does not require the artifact directory to exist already.
Inputs support cursor arrows, Home/End, Delete, and `Ctrl+A/E/U`.

### Editing a typed answer

The main app's overlay fields (passphrases, paths, vault and profile names,
policy and grant values) are linear strings, so they offer the line-editing keys
that a linear field can honour exactly rather than a caret it does not have:

| Key                      | Effect                                               |
| ------------------------ | ---------------------------------------------------- |
| `Backspace`              | delete one character (code point, never half a pair) |
| `Ctrl+U`                 | clear the field; the overlay stays open              |
| `Ctrl+W`                 | delete the last word and the space before it         |
| `Ctrl+Shift+V` / `Cmd+V` | paste                                                |

Every field keeps its own length bound, and these keys do not loosen one.

MongoDB addresses remain masked. `Ctrl+T` tests the connection; Enter tests an
unverified address before continuing. Remote connections require TLS; insecure
TLS options are refused. The probe sends only `ping`, suppresses diagnostics,
and terminates its isolated worker after 15 seconds. Its success does not prove
write permissions or future availability.

The final review shows public settings and provides numbered Edit controls.
Compact terminals scroll the summary with arrows; `Ctrl+G` shows full details.
Protected answers remain hidden and need not be re-entered after a public edit.
Enter on this screen starts creation. Creation displays real stages and elapsed
time, including recovery verification, with duplicate actions blocked.

Clipboard messages distinguish terminal and system copying. Terminal copying
schedules a best-effort clear after about 30 seconds while Kavrix stays open.
System copying requires manual clearing. Terminal behavior and clipboard
history prevent a guarantee that copied values have been removed.

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
