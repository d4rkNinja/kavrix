# Release notes — 0.2.22 TUI full CRUD / discoverability / live journey

The TUI already implemented policy/grant create/remove behind single keys
that were invisible once rows existed (the footer showed only navigation).
0.2.22 makes every screen's actions discoverable and completes the CRUD
surface that the CLI already supports:

- Per-screen footer chips: policy (`n` create · `x` remove · `g` grant ·
  `r` revoke · `Enter` refresh), vaults (`n` new vault), profiles
  (`x` remove), recovery (`n` create · `v` verify · `x` revoke), doctor
  (`d`), run (`p`), agent (`g`), browse (`Enter`).
- New backend actions: `create-vault` (label prompt; uses stored unlock
  material; creates and selects the vault via `db vault create`/`use`) and
  `remove-profile` (confirm overlay; `db profile remove`; removing the
  current profile locks the session and clears derived state).
- Grant rows carry typed `status` (active/expired/exhausted/revoked/
  clock-invalid); the Policy screen renders `[REVOKED]`-style tags and mutes
  inactive grants.
- CLI fix found by the new live journey: `kavrix db profile remove` now
  accepts `--json` (the option was never registered; scripted and TUI
  callers failed with "unknown option").

Verified on win32 against the real bundled CLI subprocess:
`apps/cli/test/live-qa-tui-crud.test.ts` drives profile creation, unlock,
credential put/rename/remove, policy create/remove, grant create/revoke
(with typed status assertions), run preview, second-vault create, recovery
create/verify, doctor, lock, profile removal, and asserts secrets never
reach argv. Router coverage in `packages/tui/test/app/router.test.ts` (55)
and backend coverage in `apps/cli/test/tui-session.test.ts` (12) cover the
new overlays, footer chips, and state resets.
