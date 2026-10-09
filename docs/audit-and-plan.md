# Kavrix audit and prioritized plan

Audit date: 2026-10-08. Tree: commit `6e28be8` on `main`.

This page records what the audit actually found, in the order it should be
addressed. It distinguishes completed work from open work and never presents a
plan as a shipped capability. Sections marked **done** have tests; sections
marked **open** do not.

**Verification after this pass:** `pnpm build` green, `prettier --check .`
clean, `eslint . --max-warnings 0` clean, `tsc -b` + `tsc -p` green in every
package, `pnpm test` green across the workspace, and
`scripts/smoke-note-history.mjs` passing against the **packaged** binary
(full command surface verified over a real encrypted database, including that no
plaintext note body, passphrase, or field value reaches the container bytes).

Everything in §2 and §4 shipped in **0.2.44**; see
[the release notes](release-notes-0.2.44.md) for the user-facing account.
Sections §3, §5, and §6 describe what remains open.

## 1. What already works, and works well

Kavrix is not an early prototype. The security core is real and heavily tested.

- **Cryptography** (`packages/crypto`, ~6,600 lines of source, 2,700+ lines of
  tests): XChaCha20-Poly1305-IETF AEAD with a hand-serialized canonical AAD that
  has **golden byte vectors**, an explicit collision-pair test
  (`entityId="a", groupId="bc"` vs `"ab", "c"`), and Argon2id floors enforced
  _before_ allocation. HKDF-SHA-256 domain separation, RFC 9106 and RFC 5869
  test vectors, copy-form keys with a SHA-256 checksum for typo detection, and
  `crypto_secretstream` attachment streaming with explicit WASM state wipe. Every
  failure path collapses to one generic error; no partial credential is ever
  disclosed.
- **Hierarchy and key slots**: DRK → VRK → group → item → attachment wrapping with
  every context asserted, four independent unlock paths, read-back verification
  after every wrap, and a last-valid-slot guard.
- **Protected file I/O** (`packages/key-files`, ~9,000 lines): real TOCTOU
  defence — `lstat` → `O_NOFOLLOW` open → `fstat` → read → `fstat` → re-`lstat`
  with a trust cache keyed on the full metadata snapshot. Atomic publish with
  backup-and-rename, bounded Windows `EPERM` retry that re-verifies both inode
  identities before every attempt, and quarantine-then-unlink deletion. The
  Windows ACL helper is a fixed, non-interpolated PowerShell program that never
  receives key material.
- **Storage** (`packages/storage`): one bounded local container with a provably
  dead-PID stale-lock recovery; MongoDB uses exact-revision CAS plus
  majority-snapshot transactions for catalog+vault atomicity. Every error
  message is a fixed string per code — no paths, ids, document content, or driver
  text. A plaintext-canary test asserts no plaintext reaches the store.
- **Runner** (`packages/runner`): deny-by-default environment (16 inheritable
  names, ~48 reserved names refused case-insensitively), a hard refusal to pass a
  mapped secret anywhere in the executable or arguments, and output redaction
  that survives stream-chunk boundaries.
- **CLI surface**: 97 leaf commands, all wired to real implementations, with a
  closed exit-code table and a documented precedence rule that a missing
  executable is an execution failure, never an authorization denial.
- **Agent broker**: local named-pipe (Windows) / Unix-socket broker with a
  per-session token, constant-time token comparison, bounded NDJSON frames, up
  to four concurrent requests, a 32-request admission queue, and drain-on-shutdown.

## 2. Security and correctness defects found and fixed

### 2.1 Protected secret store held a non-textual source file — **done**

`packages/key-files/src/sealed-secret-store.ts` contained five literal NUL
(0x00) bytes inside two template literals used as AAD domain separators. The
bytes produced correct cryptography but made the file unreadable as text:
`read` refused it as binary, diffs rendered garbage, and the exact kind of
artifact that hides tampering.

Fixed by writing the separators as `\u0000` escapes (byte-identical output) and
adding an assertion that the separator inputs are one short, NUL-free charset.
Service/account names are caller-supplied but are interpolated straight into a
cryptographic domain separator; before this change a `\n` or NUL in a label
would have produced an ambiguous binding rather than an error. Now refused with
`KEY_FILE_UNSAFE` before any key material exists.
Tests: `packages/key-files/test/sealed-secret-store.test.ts` — six hostile
labels plus a 64-character boundary round-trip.

### 2.2 Authorization-state errors classified by message text — **done**

`packages/key-files/src/authorization-state-file.ts:143-164` decided whether a
corrupt sidecar was an integrity failure or a bad key by matching
`error.message.includes('Authentication failed')` and `includes('32 bytes')` —
message text owned by another package. Reformatting a message in
`@kavrix/crypto` would silently have reclassified an integrity failure as a
pass-through. Replaced with `instanceof AuthenticationError` /
`instanceof CryptoInputError`, importing both classes, and the key-length check
is now made locally rather than inferred from wording. Behaviour is unchanged;
the classification no longer depends on another package's prose.

### 2.3 MongoDB capability probe silently assumed "capable" — **done**

`packages/storage/src/mongo-encrypted-database.ts:246-250` caught every error
from the `hello` capability probe and `return`ed, i.e. treated an
unanswerable probe as "this deployment can run transactions". That only moved
the failure into the transaction, after the caller had already prepared state.
Now an unreachable or unauthenticated `hello` throws `connection` and the
standalone case still throws `unsupported`.

### 2.4 `decryptAead` collapsed input errors into authentication errors — **done**

`packages/crypto/src/aead.ts:103-104` turned _every_ failure, including a
malformed envelope or a wrong-length key, into `AuthenticationError`. The state
and backup envelope paths in the same package deliberately re-throw
`CryptoInputError`. Aligned with a test that asserts the two shapes stay
distinguishable, because "the caller passed garbage" and "the key is wrong" need
different operator responses.

## 3. Open security and robustness observations

Not yet fixed. Ordered by how much damage a mistake here would do.

1. **`decrypt` is not the only place message-coupled logic lives.** The
   `SessionUnlockError`, `PortableKeyFileError`, and `DatabaseMigrationError`
   exit-code mappings in `apps/cli/src/cli-errors.ts` and
   `cli-registration.ts:124-127` repeat literal code tables instead of reading
   `CLI_EXIT_CODES`. They can drift from the single source of truth. Fix by
   deriving them.
2. **`libsodium-wrappers` private API use.** `packages/crypto/src/secretstream.ts`
   reaches into `sodium.libsodium.HEAPU8` and `_free` to wipe WASM stream state.
   A dependency upgrade could break state cleanup and turn a successful encrypt
   into a runtime error. Needs a version pin with a test that fails loudly.
3. **`@kavrix/core` holds a second, uncalled copy of the collaboration policy.**
   `packages/core/src/collaboration-policy.ts` (1,123 lines) re-derives
   authorization decisions that are independently encoded as Zod refinements in
   `packages/schemas/src/collaboration.ts` (~2,750 lines). **No source file in
   the workspace imports `@kavrix/core`.** This is the largest duplication in the
   repository and the most likely place for a security rule to be strengthened in
   one copy and not the other. Either wire core into the real paths or delete it.
4. **`packages/schemas/src/api.ts` (~1,017 lines) and much of `sync.ts` are
   wire contracts for an HTTP service that does not exist.** They are tested but
   never executed. That is honest test spend on unreachable code; it also
   invites someone to document a hosted API that is not shipped.
5. **Two unimplemented envelopes.** `storage/vitest.config.ts` includes
   `mongo-collaboration.integration.test.ts` but the root `vitest.config.ts`
   does not, so no MongoDB integration coverage runs in a default `pnpm test`.
   Same for `packages/key-files/test/integration/platform-key-file.integration.ts`.
6. **`fast-check` is declared as a devDependency in `packages/schemas` and
   `packages/crypto` with no property-based test in either.**
7. **`apps/cli`'s explicit `include` lists are a silent release-verification
   gap.** Both `tsconfig.build.json` and `tsconfig.json` enumerate source files,
   so a new file that is not added compiles **never** — yet `tsc -b`, `tsc -p`,
   and `eslint` all still report success, because they are not looking at it.
   During this pass the `credential-history-*` modules were added to the working
   tree, were green under a temporary project config, and were still **absent
   from `dist`** — a published package would have shipped a command that threw
   `MODULE_NOT_FOUND` the first time a user ran it. Any new file under
   `apps/cli/src` must be added to both lists. `scripts/verify-cli-includes.mjs`
   is the new gate that closes this permanently; it found **three further
   pre-existing gaps** on its first run (`credential-name.ts`,
   `credential-mutations.ts`, `tui-vault-session.ts` were built but never
   typechecked).
8. **A test that builds its own program silently stops testing the CLI.** The
   `credential-history` tests called `buildLocalCli()` and _then_ registered the
   family again. That was correct while the family was unwired and became a
   duplicate-route failure the moment it was wired in: the tests passed
   standalone but six of fourteen failed in a full run, and the failure
   (`credential history --help` → exit 1) looked like a registration bug rather
   than a test bug. Any test that composes its own `Command` must not re-register
   what the real CLI already registers.

## 4. Usability defects found and fixed

### 4.1 Global keys that worked everywhere but were only advertised somewhere — **done**

`l` (lock) runs on all 13 screens but its footer chip appeared only on Home and
the `default` case. `a` (ASCII toggle) is a global key with no footer chip
anywhere and was discoverable only inside Help. Both are now in one shared
global tail used by every screen.

### 4.2 The dead `u`/`l` branches — **done**

`router.ts:720-742` handled `u` and `l` unconditionally after `keyTransition`
had already returned for both, so those ~22 lines could never execute. Removed.
The surviving `keyTransition` versions are the better ones: they distinguish
session unlock from forced passphrase unlock (`Shift+U`), which the dead copy
did not.

### 4.3 `/` opened a search overlay on screens where search does nothing — **done**

Pressing `/` on Doctor, Recovery, Policy, Browse, Agent, Run, or Showcase opened
the `input-search` overlay, and the resulting filter was silently invisible
because `credentialFilter` only affects the Credentials list.

Replaced with live type-to-filter on Credentials: printable characters narrow
the list on every keystroke, `Backspace` edits, `Esc` clears the filter and
retires any on-screen reveal, `Enter` opens the filtered row. While a filter is
open every other printable key is filter text, so screen mnemonics and digit
jumps are suspended — the same discipline the command palette uses. On the
other twelve screens `/` now answers "Search is available on the Credentials
screen (press 4)." rather than opening a box it cannot use.

The `input-search` overlay state was **deleted** rather than left unreachable, so
no future screen can open a dead overlay. The filter is sanitized before it is
matched or painted, and the test suite covers CSI and OSC paste sanitization,
control-byte exclusion, and a 64-character bound.
Tests: `packages/tui/test/app/credential-filter.test.ts` (21 tests).

### 4.4 `showcase` advertised a row action it does not have — **done**

The read-only storage-docs screen fell into the footer's `default` case and
advertised `Enter open`. It now advertises only the global controls.

### 4.6 No line editing in overlay fields — **done**

The main app's overlay fields accepted printable characters and Backspace and
nothing else, so a typo in a 200-character path had to be corrected by deleting
back to the error and retyping everything after it. Onboarding supported
`Ctrl+A/E/U` and cursor movement; the main app had none of it.

Added `Ctrl+U` (clear the field, overlay stays open) and `Ctrl+W`
(`unix-word-rubout`: kill the last word and the space before it), operating on
code points so a surrogate pair is never split, and advertised as `^U clear` /
`^W word` chips next to the existing paste chip.

Arrow keys are deliberately **not** claimed: the overlay query is a linear string
with no caret offset, so cursor movement would be a lie. All eleven input blocks
now share one `editOrAppendOverlayText` entry point, and each field's existing
length bound is enforced through it, so editing is not a route past a bound.
Tests: `packages/tui/test/overlay-line-editing.test.ts` (8 tests).

### 4.5 No command palette — **done**

This is the structural cause of "too complicated". The app is 13 screens with
per-screen mnemonics that actively conflict (`n` = new everywhere except
Profiles where it means "file profile"; `m` = rename on Credentials but
"MongoDB" on Profiles; `r` = refresh on Home, REVEAL on Credentials, and
**revoke grant** on Policy; `c` = copy on Credentials but **create recovery
kit** on Recovery). Nothing told a user what they could do.

Added `packages/tui/src/app/commands.ts` plus a `command-palette` overlay:

- `:` or `Ctrl+K` opens a grouped, filtered list of everything the current
  screen can do, each row carrying its key, a plain-language hint, and — when it
  cannot run — the precondition ("Unlock the vault first (u) to add a
  credential.").
- **A palette choice is the keystroke**, not a parallel implementation: the
  catalogue stores the `AppKey` and Enter re-enters the router with it. This is
  asserted for every command on every screen, so the palette cannot drift from
  the router.
- Typing filters by label, hint, and key; digits jump to a row; `Esc` closes;
  a blocked action reports its reason instead of silently doing nothing.
- Rendered alongside the theme picker, with mouse-clickable rows and no caret,
  so it is not mistaken for a text field.

Because the catalogue is the single description of each action, the footer chips
and the palette are now covered by a parity test that walks all 13 screens and
asserts every advertised footer key exists as a palette entry — the guard the
codebase was missing.

Files: `packages/tui/src/app/commands.ts` (new),
`packages/tui/src/app/router.ts`, `packages/tui/src/app/screens.tsx`,
`packages/tui/test/command-palette.test.ts` (new, 11 tests).

## 5. Missing capabilities (the honest product gap)

These are the largest gaps between the schemas that exist and the product that
ships. Ordered by usefulness.

| Gap                                             | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Priority                                                                                                                                                  |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Secret versioning / rotation / history**      | `encryptedHistoryRecordSchema` is real, fully refined, and bounded at 1,000,000 records by the structured payload — but two blockers make it unusable as versioning: (a) **no production code path writes a history record** (it is declared, authenticated, counted by `item show`, item-scoped, and never appended to); and (b) an `encryptedHistoryRecord` carries **no wrapped-key record**, so no key reachable from an authenticated vault can decrypt one. `kavrix item history list/show` now exposes the non-sensitive metadata. | High — restoring, revealing, or diffing a snapshot needs a new write path **and** a key-wrap schema decision, which is a migration rather than a command. |
| **Key-slot rotation is not credential history** | `packages/crypto/src/rotation.ts` and `portable-key-rotation.ts` (668 lines, tested, RFC-vector-backed) rotate **key slots**, not item content.                                                                                                                                                                                                                                                                                                                                                                                           | Informational — the most commonly misread files in the repository; the audit originally made the same mistake.                                            |
| **Export**                                      | `import env` exists; there is no `export`. `encryptedBackupHeaderSchema`/`Footer` exist and `backup create/verify/restore` work, so an encrypted export is close to free.                                                                                                                                                                                                                                                                                                                                                                 | High                                                                                                                                                      |
| **Notes**                                       | `noteSchema`/`noteCollectionSchema` are canonical and embedded in item and group payloads; `kavrix note list/add/show/remove` now covers item notes through the encrypted structured-vault mutation path. Service/group note collections still have no command.                                                                                                                                                                                                                                                                           | Medium — item notes shipped; group notes and note tags/pinning in the TUI remain                                                                          |
| **Search on values**                            | `kavrix search` matches names only, never values. Safe by design (no value-side index), but there is no scoped "search within this credential's field labels" either.                                                                                                                                                                                                                                                                                                                                                                     | Medium                                                                                                                                                    |
| **MCP server**                                  | Nothing in the repository references MCP. There is no local HTTP server either — only the NDJSON broker socket.                                                                                                                                                                                                                                                                                                                                                                                                                           | Medium — the broker protocol is already a working, authenticated local transport, so an MCP surface on top is an adapter, not a rewrite.                  |
| **Integration SDKs**                            | No Python and no standalone TypeScript SDK. `kavrix` does expose `DatabaseSession` from its main entry, but it is the CLI's own export, not a designed API.                                                                                                                                                                                                                                                                                                                                                                               | Medium                                                                                                                                                    |
| **Approvals**                                   | The only approval flow is an inline interactive confirmation (`requestApproval`). There is no durable approval request/queue. `approvalRequestSchema` exists in `collaboration.ts`.                                                                                                                                                                                                                                                                                                                                                       | Low                                                                                                                                                       |
| **Attachment transfer**                         | `attachmentStream*Schema` and the secretstream implementation are complete and tested; no command transfers an attachment.                                                                                                                                                                                                                                                                                                                                                                                                                | Low                                                                                                                                                       |

## 6. Performance

Not yet measured in this pass. `docs/performance.md` exists and should be
treated as the baseline; the audit produced no evidence that any operation is
slow enough to matter, and no optimization was attempted. The measurement plan
is unchanged: median and p95 CLI startup, CRUD, crypto, datastore, and broker
overhead, plus concurrency and memory, measured rather than asserted.

## 7. Sequencing recommendation

1. ~~Finish the TUI usability stream (§4.3)~~ — shipped with §4.1, §4.2, §4.4,
   §4.5 and §4.6 in the same pass.
2. **Decide what history should be** (§5, first row). Either add a real write
   path plus a wrapped-key record for snapshots, or delete `encryptedHistoryRecordSchema`
   and its schema test surface. A read-only viewer over records this CLI cannot
   produce is an honest stopgap, not a destination.
3. Drive the exit-code tables from `CLI_EXIT_CODES` (§3.1).
4. Decide `@kavrix/core`: wire it in or delete it (§3.3).
5. Encrypted export (§5, third row).
6. MCP surface over the existing broker (§5, sixth row).
7. Delete or clearly quarantine the unused HTTP/sync contract surface (§3.4).

Every item above is independent of the others and can be implemented and
reviewed separately.
