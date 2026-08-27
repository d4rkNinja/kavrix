# Kavrix 0.2.3 — Declarative Config File

**Changed**

`kavrix init` now generates a declarative `config.toml` instead of the interactive wizard. On first run (TTY, no `--secrets-stdin` or routing flags), it creates `~/.kavrix/config.toml` (`%USERPROFILE%\.kavrix\config.toml` on Windows) with every non-secret option, proper `#` comments, and working examples. Edit the file, then run `kavrix init --secrets-stdin` to initialize. Secrets (passphrases, MongoDB URLs) are never written to the file and are still read via masked prompts or `--passphrase-stdin` / `--database-url-stdin`. The file lives in the secure `~/.kavrix` directory (`0o600` / user-only ACL) and is never overwritten once created.

**Added**

- New module `apps/cli/src/kavrix-config.ts` with `zod`-validated schema, `smol-toml` 1.3.1 parsing, and `flattenConfig` support for `[datastore]` tables. `generateDefaultConfigToml()` is the single source for the template.
- Example `config.toml` sections: `[datastore]` (`type`, `dataFile`, `database`, `collection`), `[security]` (`keyFile`, `anchorFile`), `[mongodb]`, `[vault]` (`vaultLabel`), and `[profile]` — all commented with allowed values and examples.

**Fixed**

- Tests for the guided init flow now expect the new `Kavrix configuration` banner and `config.toml` creation, matching the declarative behavior. The interactive Ink showcase for storage selection remains available but is no longer invoked by `init`.

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
kavrix init          # creates ~/.kavrix/config.toml — edit it, then
kavrix init --secrets-stdin  # enter label, passphrase x2
kavrix --help
```
