# Release notes — 0.2.44 discoverable TUI and honest history

This release makes the interactive app learnable and extends the structured
credential surface, without changing any encrypted format, key hierarchy, or
authorization contract.

## Discoverability

The interactive app carried thirteen screens with per-screen mnemonics that
actively conflict: `n` means "new" everywhere except Profiles, where it means
"file profile"; `m` means rename on Credentials but "MongoDB" on Profiles; `r`
means refresh on Home, **REVEAL** on Credentials, and **revoke grant** on Policy;
`c` means copy on Credentials but **create recovery kit** on Recovery. Nothing
told a user what they could do.

- **Command palette.** `:` or `Ctrl+K` on any screen lists every action that
  screen can perform, with its key and a plain-language description, grouped by
  screen and "Always available". Type to filter by label, hint, or key; `1`–`9`
  jump to a row; `Enter` runs it; `Esc` closes without acting. A choice
  dispatches the same keystroke as pressing the key, so the palette cannot mean
  something different from the key it names — asserted for every command on
  every screen.
- **Blocked actions explain themselves.** An action that cannot run stays visible
  and states the precondition, for example "Unlock the vault first (u) to add a
  credential.", instead of silently doing nothing.
- **Global keys are advertised globally.** `l` (lock) and `a` (ASCII) worked on
  all thirteen screens but were only shown on Home, and `a` had no footer chip at
  all. Both are now in one shared footer tail used by every screen.
- **Live name filtering.** `/` on Credentials narrows the list on every
  keystroke, with `Backspace` to edit and `Esc` to clear. The other twelve
  screens now answer that search is a Credentials-only control instead of
  opening an input box whose result was silently invisible.
- **Line editing.** Overlay fields accepted printable text and Backspace only,
  so a typo in a long path meant deleting back to the error and retyping the
  tail. `Ctrl+U` clears the field and `Ctrl+W` deletes the last word, operating
  on code points. Arrow-key editing is deliberately **not** offered: the overlay
  query is a linear string with no caret, and claiming one would be false.
- Two provably dead branches (`u`/`l` in `screenKey`, unreachable because
  `keyTransition` already returns for both) were removed, and the read-only
  storage-docs screen no longer advertises an `Enter` it does not have.

## Structured credentials

- **`kavrix note list/add/show/remove`** attaches encrypted notes to credential
  items. Note content is read only from a masked prompt or the
  `--content-stdin` / `--content-stdin-base64` frames — never argv, a flag, or
  an environment variable. `--sensitive` masks a note behind the same stored
  reveal policy that `field get --reveal` uses; an unmarked note shows its
  content, matching a non-sensitive field. Removal archives the note inside its
  item aggregate rather than discarding it. Every mutation goes through the
  existing revision-checked compare-and-swap path.
- **`kavrix item history list <title>` / `credential history list`** and
  **`item history show <title> <version>`** report the non-sensitive metadata of
  one item's encrypted history records: the opaque record identity, the item
  revision each snapshot captured, its timestamp, the envelope's schema and key
  versions, and its ciphertext digest. `--limit` bounds one page (default 50,
  maximum 500) with `truncated: true`.

### What history is not

This group is deliberately read-only, and the reason is structural rather than a
missing implementation:

- **No command writes a history record.** `history` is declared, authenticated,
  schema-bounded, counted by `item show`, and item-scoped, but nothing appends to
  it. A non-empty history can only arrive in a container that already carried
  records when it was imported or restored.
- **History ciphertext is not restorable.** An `encryptedHistoryRecord` carries
  its envelope and the item revision it captured but **no wrapped-key record**,
  and the structured payload stores item content inside the vault-level envelope.
  No key reachable from an authenticated vault can decrypt a history payload, so
  no command can reveal, restore, diff, or prune snapshot values. There is
  deliberately no `--reveal` on this group: requesting one is a usage error.

## Security and correctness

- **Protected secret store input validation.** The sealed secret store is
  fallback storage for the OS credential store. Service and account names are
  caller-supplied but are interpolated directly into cryptographic domain
  separators, so an ambiguous label would have produced an ambiguous binding
  rather than an error. Labels are now constrained to one short, NUL-free,
  printable charset and refused with `KEY_FILE_UNSAFE` before any key material
  exists.
- **Source-file hygiene.** `packages/key-files/src/sealed-secret-store.ts` held
  five literal NUL bytes inside two template literals used as AAD separators. The
  cryptography was correct, but the file was unreadable as text — diffs rendered
  garbage, which is the kind of artifact that hides tampering. Separators are now
  written as escapes, producing byte-identical output.
- **Error classification across a package boundary.**
  `authorization-state-file.ts` decided whether a corrupt sidecar was an
  integrity failure or a bad key by matching another package's message text.
  Classification now uses the exported error classes, so reformatting a message
  cannot silently reclassify a failure.
- **MongoDB capability probe fails closed.** A `hello` command that threw was
  caught and treated as "this deployment can run transactions". It now reports
  `connection` rather than assuming capability after a caller has prepared state.
- **Consistent AEAD failure shapes.** `decryptAead` collapsed malformed input and
  a wrong-length key into `AuthenticationError`; the state and backup envelope
  paths in the same package already preserved that distinction. All four now do.

None of these change an encrypted format, key hierarchy, recovery guarantee, or
authorization decision.

## Verification

`pnpm verify` passed formatting, linting, type checking, build, and the full
suite: **2,166 tests across 171 files passed**, with 21 environment-dependent
tests skipped. Both packed-CLI acceptance flows, package smoke and content
inspection, and the dependency audit passed. `pnpm test:coverage` measured
**86.83% statements, 80.37% branches, 91.18% functions, and 88.38% lines** — every
category above the previous release's 86.66 / 80.25 / 91.04 / 88.21, with all
existing thresholds preserved.

New end-to-end coverage runs against the **packaged** binary over a real
encrypted database and asserts that no note body, passphrase, or field value
appears in the container bytes on disk.

Two new release guards were added because the defects they catch are invisible to
every gate the repository already runs:

- `pnpm verify:cli-includes` fails when a source file under `apps/cli/src` is
  missing from either tsconfig `include` list. New modules can otherwise compile
  green while being absent from `dist`, shipping a command that fails at runtime.
  On its first run it found three further pre-existing gaps: `credential-name.ts`,
  `credential-mutations.ts`, and `tui-vault-session.ts` were built but never
  typechecked.
- `pnpm smoke:cli` runs the note and history command families through the
  packaged executable.

Local preflight passed formatting, linting, type checking, build, the full test
suite, coverage, package smoke and content inspection, both packed CLI acceptance
flows, and the dependency audit at `--audit-level high`.

## Upgrade notes

No migration, reinitialization, or key-file change is required. Existing
databases, key files, recovery kits, profiles, policies, grants, and audit state
are read unchanged. Preserve existing protected files and recovery kits;
initialization is not an unlock repair.
