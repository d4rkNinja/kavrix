# Kavrix 0.2.3 — First-run Onboarding Reference

**Changed**

`kavrix init` remains the legacy version 2 single-vault compatibility path. On
first run (TTY, no `--secrets-stdin` or routing flags), it creates a protected
`~/.kavrix/config.toml` (`%USERPROFILE%\.kavrix\config.toml` on Windows) with
non-secret command examples; it does not initialize a vault and current
commands do not load it automatically. Secrets (passphrases, MongoDB URLs) are
never written to the file and are still read via masked prompts or
`--passphrase-stdin` / `--database-url-stdin`. The file lives in the secure
`~/.kavrix` directory (`0o600` / user-only ACL) and is never overwritten once
created.

The canonical multi-vault first-run path is datastore profile, database
initialization, then vault creation:

```sh
kavrix db profile add work --datastore file \
  --data-file ./work.kavrix --key-file ./work.kavrix.key
kavrix db profile use work
kavrix db init --profile work
kavrix db vault create --profile work
```

The profile contains active non-secret routing. `config.toml` is an onboarding
reference only. Neither stores a MongoDB URI, passphrase, or key bytes. MongoDB
is optional, and database-container writes require a transaction-capable
replica set or sharded topology.

**Added**

- New module `apps/cli/src/kavrix-config.ts`; `generateDefaultConfigToml()` is the single source for the protected onboarding reference.
- The reference includes the canonical file-profile, database-init, vault-create, and explicit credential-routing examples.

**Fixed**

- Tests for the guided init flow now expect the new `Kavrix configuration` banner and protected onboarding-reference creation. The interactive Ink showcase for storage selection remains available but is no longer invoked by `init`.

**Verification (run locally before push)**

```
pnpm --filter @kavrix/tui build && pnpm --filter kavrix build  # ✓
pnpm lint                                                      # ✓
pnpm format:check                                              # ✓
pnpm typecheck                                                 # ✓
vitest: init-onboarding 12/12, init-storage-selection 20/20, tui 36/36, package 9/9  # ✓
pnpm audit --audit-level high — No known vulnerabilities       # ✓
```

**Upgrade**

```sh
npm i -g kavrix@0.2.3
kavrix init          # creates the non-secret onboarding reference
kavrix db profile add work --datastore file --data-file ./work.kavrix --key-file ./work.kavrix.key
kavrix db profile use work
kavrix db init --profile work
kavrix db vault create --profile work
kavrix --help
```
