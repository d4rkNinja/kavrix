# Release notes — 0.2.24 session unlock (OS keychain convenience)

New optional session-unlock feature answering the every-command-passphrase
prompt cost, without weakening the passphrase root:

- `kavrix session enable|status|revoke` and a `--session` flag on every
  passphrase-consuming command. Enable seals the unlock material with a
  random 32-byte wrapping key (XChaCha20-Poly1305, AAD-bound to the
  profile/database/creation time/TTL in
  `packages/crypto/src/session-unlock.ts`), writes the sealed envelope beside
  the portable key file via the protected-JSON writer, and stores the
  wrapping key in the OS credential store (Windows PasswordVault through the
  hardened PowerShell bridge, macOS `security`, Linux `secret-tool`).
  Secrets never travel through argv; the Windows value rides in the child's
  own environment for the store operation only.
- Either half alone is useless; revocation removes both. Expiry, tampering,
  and keychain loss fail closed with actionable messages and stable exit
  codes (14/15/16 via the CLI classification).
- TUI: new `session` screen (enable after passphrase unlock, remove with
  confirm, refresh), `u` unlocks through the session when one is active,
  lock pill shows `open·session`, footer chips and help updated, onboarding
  asks `Enable OS session unlock?` after a successful `kavrix init` create
  (skip keeps the passphrase path).
- `packages/keychain` gains `NativeSessionUnlockStore` (schema-validated
  32-byte wrapping keys under derived `v1:session-unlock:<account>` names);
  the CLI uses its own hardened child-process keychain port because the
  packed CLI carries no native binaries.

Verified live on win32 by `apps/cli/test/live-qa-session-unlock.test.ts`
(real PasswordVault): enable, status before/after, `list --session` with no
passphrase, wrong-passphrase still fails, revoke then `--session` fails with
`no session unlock`, passphrase still works, and the sealed session file
never contains the passphrase. Crypto coverage in
`packages/crypto/test/session-unlock.test.ts` (round-trip, AAD transplant,
wrong key, tamper, size limits). TUI coverage in
`packages/tui/test/app/router.test.ts` (60) and onboarding router updated
for the enable-session step (16).
