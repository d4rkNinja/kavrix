# Terminal UI guide

The `@kavrix/tui` package is the Ink presentation and interaction layer for an
already-unlocked vault. It does not persist data, access MongoDB, implement
cryptography, or own a clipboard. The CLI must supply a `TuiUseCasePort` whose
methods enforce those application policies.

## Layout

At 80 columns and wider, the browser renders three panes: groups, credentials in
the selected group, and the selected credential's dynamic details. Below 80
columns it renders one focused pane and `Tab`, left, or right changes panes. The
layout is recomputed on terminal resize and is tested at 80x24 and in narrow
mode.

The detail pane is derived from canonical `FieldDefinition`, `StoredFieldValue`,
and `Note` records from `@kavrix/schemas`. It never selects a form based on a
credential type. The field registry covers every canonical field type and maps
it to an input mode, scalar kind, multiline behavior, and multiplicity. Template
fields and item-only fields use the same path. Group and item notes remain
separate records and are rendered as independent lists.

## Keyboard controls

| Key                | Action                                                                 |
| ------------------ | ---------------------------------------------------------------------- |
| `Tab`, left, right | Change the focused pane                                                |
| `j`, `k`, up, down | Move within the focused pane                                           |
| `/`                | Search titles, aliases, tags, environment, owner, and subtitle locally |
| `e`                | Open the schema-driven editor for the selected field                   |
| `r`                | Reveal an eligible secret for 15 seconds                               |
| `c`                | Request a policy-checked clipboard copy without rendering the value    |
| `s`                | Save the canonical local draft with its expected revision              |
| `Ctrl+P`           | Open the command palette                                               |
| `?`                | Open help                                                              |
| `a`                | Toggle ASCII fallback                                                  |
| `l`                | Lock; unsaved changes require confirmation                             |
| `Ctrl+C`           | Securely discard the draft, lock, and exit                             |
| `Esc`              | Cancel or close the active overlay                                     |

Copy effects contain only item and field identifiers. The supplied use case owns
clipboard access and expiry. Conflict responses stay explicit until the user
accepts the remote revision or retries the local draft against it. Starting a
new asynchronous effect aborts the older effect, and stale completions are
ignored by request ID.

The CLI composition must render Ink with `exitOnCtrlC: false`; `VaultTui` owns
`Ctrl+C` so it can clear decrypted screen state and complete the lock port before
exiting.

## Terminal safety

All decrypted text is treated as hostile. A linear scanner removes CSI, OSC,
DCS, APC, PM, SOS, C0, C1, carriage-return, and other terminal controls before
rendering. Bidirectional controls are replaced visibly. ASCII mode also replaces
non-ASCII glyphs and uses ASCII masks and borders.

Sensitive fields and sensitive note content are masked with a fixed-length mask
by default. Reveal is an explicit, field-policy-gated, timed state and locking
clears groups, items, drafts, conflicts, editor input, search input, and reveal
timers from the TUI state. JavaScript cannot guarantee immediate physical memory
erasure for strings, and an explicit reveal can still be captured by terminal
recording, screen capture, or same-user malware.

## Composition status

The package is a real composable TUI and its runtime port is covered with an Ink
integration test. It is not yet launched by the public `creds` command in this
phase. Clipboard adapters, unlocked-vault use cases, and persistence composition
must be supplied by the CLI; the TUI contains no fallback, fake data path, or
direct storage access.
