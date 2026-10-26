# Release notes — 0.3.1

0.3.1 is a focused simplification and reliability release. It restructures the
public command surface into a small everyday core and hardens the TUI so a
task failure reports a notice instead of breaking the session.

## Simplified command surface (breaking)

The everyday credential commands are renamed and merged. Old names are removed,
not hidden:

| Old                         | New                     |
| --------------------------- | ----------------------- |
| `kavrix put <name>`         | `kavrix add <name>`     |
| `kavrix list`               | `kavrix ls`             |
| `kavrix search <pattern>`   | `kavrix ls <pattern>`   |
| `kavrix remove <name>`      | `kavrix rm <name>`      |
| `kavrix rename <from> <to>` | `kavrix mv <from> <to>` |

Removed without replacement:

- Alias commands: `kavrix ui` (use `tui`), `environment` (use `context`),
  `group` (use `service`), `credential` (use `item`), `db profile show`
  (use `db profile status`), `key replicate` and `key assign` (use
  `key copy`), and the bare `kavrix grant <secret>` form (use
  `grant create <secret>`).
- Top-level `migrate database` moved to `kavrix db migrate` with the same
  options and stdin frames.

Hidden but still functional (kept for the TUI, legacy vaults, and scripts;
absent from `--help`):

- `kavrix view`, `kavrix stats`, `kavrix has`, `kavrix frames`
- Legacy flat-vault operations: `kavrix key ...`, `kavrix recovery ...`,
  `kavrix vault ...` (database-container profiles use `kavrix db key`,
  `db recovery`, and `db vault`)
- `kavrix destroy` (unchanged)

`kavrix --help` now leads with a "start here" hint and registers the everyday
commands first; the advanced database group (`kavrix db`) is listed last.
`kavrix get <name>` keeps its masked-by-default behavior; `--reveal` remains
the explicit plaintext guard.

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
absorbs `search` because listing and filtering are one task; and `db` groups
everything an everyday user can defer. Hidden commands keep the TUI and legacy
vault owners working without cluttering help.

## Compatibility

- Scripts and docs written against 0.2.x command names must update to the table
  above. Exit codes, output shapes, stdin frame orders, and the TUI are
  unchanged.
- `kavrix frames <command>` reflects the new names (`frames add`,
  `frames db migrate`).
- The published npm package ships `apps/cli/README.md`; the repository README
  and user docs were rewritten around the new surface.

## Version note

`0.3.0` was already occupied on the npm registry, so this release is
`0.3.1`.
