# Release notes — post-0.2.0 external-test hardening

This record preserves the hardening work that followed the post-0.2.0
external test report.

- `run --grant` resolves the grant's credential in-session before consuming any
  use; missing credentials fail with exit 11 without burning the use; grants
  without `env` inject under a derived destination name (`production/database`
  → `PRODUCTION_DATABASE`) and unmappable names fail closed with exit 14.
- Session error mapping no longer reports duplicate labels, missing
  credentials, invalid input, or secret-frame mistakes as "Database
  authentication failed"; reviewed command-layer errors pass through and store
  codes map to truthful classes with documented exit codes (10/11/14/15/16).
  Store `unsupported` (standalone without replica set/sharding) is preserved as
  session `unsupported` with the replica-set sentence instead of collapsing to
  "invalid" or "may have changed"; init treats it as proven-rejected so no
  ambiguous-commit cleanup is claimed.
- Usage errors exit `2`; wrong unlock/run passphrases exit `10` even when the
  attempt is shorter than the create-passphrase minimum; missing credentials
  exit `11`; missing child executables exit `18` per the CLI reference table.
- Local file locks record their owner PID; locks from provably dead processes
  are auto-removed on the next invocation while live owners keep failing
  closed with a visible message. `db doctor health [--accept-current] [--heal]`
  adds bounded repairs: full authenticated verification then re-anchor of the
  local rollback guard after explicit human consent (`--accept-current`); and
  safe local-state heal (`--heal`) for incomplete unbound profiles, dangling
  selection pointers, and owner-only ACL/mode drift (`--heal --dry-run` plans
  without applying). Heal chmods only the immediate parent of an existing
  Kavrix-owned key/data file — never a `--config-dir` that is a project root
  or that does not contain those files. Heal never invents passphrase recovery
  or deletes vault data.
- Reserved vault identifiers (`__proto__`, `constructor`, `prototype`) are
  refused at init with reviewed messages.
- Multi-line and empty credential values are supported via
  `put --value-stdin-base64` (one strict base64 frame). Mixed-stdin `put`
  errors name the missing flag (for example `Missing --value-stdin`) when
  only `--passphrase-stdin` is set.
- The documented project-file example now validates; agent permissions require
  `env` for exec injection as documented; search accepts glob patterns plus
  `--case-sensitive`; credential names reject whitespace/slash/dot abuse;
  owner-visible vault labels are available via `--show-labels`; share-key
  staleness is warned at creation; `init` defaults to the local file datastore
  outside the guided wizard.
