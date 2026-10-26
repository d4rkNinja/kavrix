# Release notes — 0.3.1

0.3.1 is a focused simplification and reliability release. It structures the
public command surface into a small everyday core and hardens the TUI so a
task failure reports a notice instead of breaking the session.

## Simplified command surface

The everyday credential commands are:

| Command                 | Purpose                                 |
| ----------------------- | --------------------------------------- |
| `kavrix add <name>`     | Encrypt and store one secret.           |
| `kavrix get <name>`     | Show one credential, masked by default. |
| `kavrix ls`             | List every credential name.             |
| `kavrix ls <pattern>`   | Filter names by glob or substring.      |
| `kavrix rm <name>`      | Delete one credential.                  |
| `kavrix mv <from> <to>` | Rename a credential, keeping its value. |

`kavrix get <name>` keeps its masked-by-default behavior; `--reveal` remains
the explicit plaintext guard.

Advanced database, owner-key, recovery, and migration operations live under
`kavrix db ...`; explicit copy-first migration runs as `kavrix db migrate`. In
the structured-vault groups, `context`, `service`, `item`, `field`, and `note`
are the only spellings, and a secret grant is created with
`kavrix grant create <secret>`. `kavrix tui` opens the interactive app.

`kavrix --help` leads with a "start here" hint and registers the everyday
commands first; the advanced database group (`kavrix db`) is listed last.

Hidden but still functional (kept for the TUI, version 2 vaults, and scripts;
absent from `--help`):

- `kavrix view`, `kavrix stats`, `kavrix has`, `kavrix frames`
- Flat-vault operations: `kavrix key ...`, `kavrix recovery ...`,
  `kavrix vault ...` (database-container profiles use `kavrix db key`,
  `db recovery`, and `db vault`)
- `kavrix destroy`

## TUI reliability

The TUI used to crash the whole process whenever an exception escaped an input,
mouse, resize, animation, or notification path, because those callbacks run
inside raw stdin listeners, timers, and void-ed promise chains. Every such path
now fails safe:

- Router transitions (`packages/tui/src/app/app.tsx`,
  `app/onboarding-app.tsx`, `components.tsx`) catch a failing transition and
  degrade to a visible notice or a dropped keypress instead of an uncaught
  exception.
- Mouse click/scroll handlers (`packages/tui/src/app/mouse.tsx`) survive a
  detached-region measurement race or a throwing handler.
- The shared animation clock (`packages/tui/src/frame-clock.ts`) drops a
  throwing subscriber instead of killing every animation.
- Terminal-resize coalescing (`packages/tui/src/app/terminal-resize.ts`)
  releases held input even when the update throws.
- Backend failures keep the real error in the notice (`Operation failed
safely. <detail>`) instead of discarding it, and onboarding setup results no
  longer reclassify a successful setup as failed on a schema drift.
- TUI child-command JSON parsing reports the exact command to re-run when a
  child emits non-JSON output, and CLI stderr notices keep up to three lines
  of guidance instead of one.
- Session expiry can no longer wedge the app: the vault lock remains the hard
  boundary, and a one-off snapshot/listener failure after locking no longer
  bricks every later action with "restart the app".
- A process-level guard restores the terminal (unmount, sanitized one-line
  error, documented exit code) if something unexpected still escapes, so a
  crash never leaves the shell in raw/alternate-screen mode.

## Why these names

`add/get/ls/rm/mv` match the file verbs developers already know; `ls <pattern>`
covers both listing and filtering because they are one task; and `db` groups
everything an everyday user can defer. Hidden commands keep the TUI and
version 2 vault owners working without cluttering help.

## Compatibility

- Exit codes, output shapes, stdin frame orders, and the TUI are unchanged
  from prior releases.
- `kavrix frames <command>` reflects the current names (`frames add`,
  `frames db migrate`).
- The published npm package ships `apps/cli/README.md`; the repository README
  and user docs describe the command surface directly.

## Version note

`0.3.0` was already occupied on the npm registry, so this release is
`0.3.1`.
