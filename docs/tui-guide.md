# Terminal output and interactive TUI

The public `kavrix` CLI uses Commander for command parsing and sanitized
terminal rendering. Values are masked by default; plaintext display requires an
explicit guard such as `get --reveal` or a TUI **REVEAL** confirmation.
Non-interactive output is ANSI-free.

## Interactive app (`kavrix tui` / `kavrix ui`)

`kavrix tui` (alias `ui`) mounts the colorful Ink app from `@kavrix/tui` when
both stdin and stdout are TTYs. Non-TTY sessions print a clear error and exit
non-zero so automation keeps using numbered CLI commands.

Screens: Home, Profiles, Vaults, Credentials (masked / REVEAL), Doctor,
Recovery, Run (dry preview), Policy/Grant/Audit, Agent, Context/Service/Item
browse, Help, and the existing storage showcase destination.

Security and presentation rules:

- Never echo passphrases or secret values by default.
- Reveal only after an explicit confirm step labeled REVEAL (15s UI timer).
- Sanitize all terminal strings (`packages/tui/src/terminal-text.ts`).
- Honor `NO_COLOR` and `TERM=dumb` (disable color).
- Support `--ascii` and auto-ASCII on Windows (`process.platform === 'win32'`)
  or terminals without Unicode.
- Paths use `node:path` joins; no bashisms.
- Prefer library calls; when the host spawns the CLI, secrets travel only as
  stdin frames — never argv.

Flags: `--ascii`, `--color`, `--no-color`, `--profile-config-dir` /
`--config-dir`.

## Storage showcase

The active `@kavrix/tui` workspace still provides the Ink 7.1.1 / React 19.2.8
storage-selection showcase used by interactive onboarding helpers. It is a
presentational boundary only: its strings are static and it has no persistence,
cryptographic, or secret-input authority. The CLI loads it lazily, and the
non-TTY path retains the numbered storage-selection fallback.

Masked interactive prompts render textual requirement, success, and error
markers and retry a locally invalid field without discarding unrelated answers.
Color is supplemental, appears only on a capable TTY, and is disabled by
`NO_COLOR` or `TERM=dumb`; protected stdin remains silent and ANSI-free.

Terminal-rendered content is treated as hostile. Control, ANSI, and OSC
sequences are sanitized before display.
