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

Screens: Home, Profiles, Vaults, Credentials (masked / REVEAL), Doctor,
Recovery, Run (dry preview), Policy/Grant/Audit, Agent, Context/Service/Item
browse, Help, and the existing storage showcase destination.

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

Flags: `--ascii`, `--color`, `--no-color`, `--no-splash`, `--profile-config-dir`
/ `--config-dir`. `KAVRIX_TUI_NO_SPLASH=1` also skips the startup splash.

Chrome is content-sized (not pinned to the full TTY row count) and remounts after
navigation/input so first paint and onboarding step transitions stay visible on
flaky or maximized terminals. `kavrix tui` shows a Loading… state until vault
hydrate completes (or an error/timeout banner if it fails).

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
