# Kavrix 0.2.11 — QA follow-up: truthful standalone errors, operable vault removal, and recovery/profile guidance

Kavrix 0.2.11 addresses the 12 FAILs from the 2026-09-03 hands-on QA of 0.2.10 (score 7.3/10). No security boundary is weakened. Every change is covered by build, typecheck, lint, and packed-CLI tests.

## What changed (every 0.2.10 QA row addressed)

- **Standalone replica-set error (M8, M21).** The storage `unsupported` code (`MongoDB deployments without replica sets or sharding are not supported for database writes; initialize against a replica set or sharded cluster.`) is now preserved through `DatabaseSession` as a dedicated `unsupported` failure (exit 15) instead of collapsing to `invalid` or `The database may have changed; reopen it before continuing.` Init treats it as proven-rejected so no ambiguous-commit cleanup is claimed.
- **Vault removal operability (V8, V8b, V8c, V8d, V8e, V9).** `kavrix frames "db vault remove"` now documents `[mongodb-url,] passphrase`; `db vault remove --help` no longer claims an unimplemented confirmation step. A failed removal never advances the revision anchor, so a previously working key keeps working.
- **Recovery rotation guidance (AG1, AG1b, B5, V9).** `db recovery use` prints that the previous owner key can no longer open the database and that the selected profile still names its old key path until updated (`--key-file` pointing at the recovered key).
- **Agent/run profile errors (AG1c).** `agent run`, `run`, and authorization commands distinguish an existing-but-unbound profile (`run kavrix db init for that profile first`) from a missing profile (`create one with kavrix db profile add`).
- **Legacy stdin alias (L4b).** Legacy `recovery create` accepts `--secrets-stdin` alongside `--recovery-passphrase-stdin`/`--passphrase-stdin`; `--secrets-stdin` alone now reads the full frame set instead of failing with `unknown option`.
- **Registry (M29).** `db profile remove` not-found remains truthful; unbound profiles survive unrelated `use`/`bind` mutations (covered by existing registry publication tests).
- **Defaults and transport honesty (docs).** README now states in bold that root `put/get/list` default to `--datastore mongodb` without a profile and that the MongoDB URI is never stored; the CLI reference documents the replica-set sentence, the URI-every-command rule, and that TLS/hostname/replica-set/unreachable failures intentionally share `The database connection failed.` without distinguishing the cause.

## Operator notes

- MongoDB writes still require a replica set or sharded cluster. `kavrix db ping --database-url-stdin` validates connectivity without unlocking a vault.
- `db recovery use` rotates the owner key by design: keep the recovered key file and its anchor together, and update the profile before the next command.
- `kavrix frames` remains the single source of truth for stdin frame contracts.

## Verification

- `pnpm verify` (build, format:check, lint, typecheck, tests), `pnpm --filter kavrix package:smoke`, and `pnpm --filter kavrix test` pass.
- No plaintext secrets, URIs, or tokens appear in logs or argv. Zero-knowledge ciphertext-only MongoDB storage unchanged.

Previous release: 0.2.10 — QA follow-up: replica-set enforcement, JSON parity, and hidden-command repair.
