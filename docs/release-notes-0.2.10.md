# Kavrix 0.2.10 — QA follow-up: replica-set enforcement, JSON parity, and hidden-command repair

Kavrix 0.2.10 addresses the 21 FAIL / 1 BROKEN / 2 UNIMPLEMENTED findings from the 2026-09-03 hands-on QA of 0.2.9. No security boundary is weakened. Every change is covered by build, typecheck, lint, and packed-CLI tests.

## What changed (every QA row addressed)

- **--json parity (P2, P4, V1, R3, K1, K2).** Added `--json` to `kavrix db profile list`, `kavrix db profile status`, `kavrix db vault create`, `kavrix db recovery status`, `kavrix key status`, and `kavrix key verify`. These commands already emitted JSON; the flag was missing and commander rejected it with exit 2.
- **get --json --reveal wrapper (C21 gap).** `kavrix get --json --reveal` now returns `{"name","value","revision"}` JSON when `--json` is present. Plaintext-only output remains when `--json` is omitted. Previously the command dumped raw secret text even with `--json`.
- **Replica-set enforcement (M8b).** `kavrix db init` against a standalone `mongod` now fails closed with `MongoDB deployments without replica sets or sharding are not supported for database writes; initialize against a replica set or sharded cluster.` The previous build initialized a database file that could never accept a vault write, then later reported the stale/fork message `The database may have changed; reopen it before continuing.` The storage layer now probes `hello` for `setName`/`isdbgrid` and rejects standalone writes with code `unsupported` before any write.
- **db ping after init (M24, M24b, T3b, T4).** `kavrix db ping` now succeeds on a database-bound profile. The routing resolver no longer throws `A database-bound datastore profile requires database container commands.` when `databaseId` is present; it resolves the bound routing and pings the underlying MongoDB.
- **destroy --help (BROKEN X2).** Hidden command `kavrix destroy` now answers `-h/--help` with its usage instead of `unknown option --help (Did you mean --help?)`.
- **Profile and vault aliases (P5, V6).** Added `kavrix db profile show` as an alias of `db profile status`, and `kavrix db vault remove <vaultId>` that delegates to the authenticated `DatabaseSession.deleteVault` path with a privileged authorization token. Previously these were `unknown command` (UNIMPLEMENTED).
- **Stdin flag unification (D2, K7, L4, L5, L4b).** Database commands accept both `--secrets-stdin` and the legacy alias `--passphrase-stdin`; legacy recovery commands accept `--recovery-passphrase-stdin`, `--passphrase-stdin`, or `--secrets-stdin` as compatible shorthands. Wrong-dialect mismatches previously produced `unknown option` instead of a frame hint.
- **Key commands on database-owner keys (K1b, K2b, K1c, K2c, K4, K7).** `kavrix key status/verify/copy/rewrap` now detects a database-owner key file via its binding header and fails with `This is a database-owner key. Use kavrix db key ...` instead of the generic `Kavrix operation failed.` or the TTY prompt `A masked prompt requires a terminal; use the matching stdin flags.`
- **Error de-collapsing (B1 vs C6, M2/M4/TLS).** `DatabaseSession.mapError` now preserves `PortableKeyFileError` (missing key file → exit 11, distinct from wrong passphrase → exit 10) instead of collapsing everything to `Database authentication failed.` Storage-level standalone-transaction errors map to `unsupported` with the replica-set sentence above.

## Operator notes

- MongoDB writes still require a replica set or sharded cluster. `kavrix db ping --database-url-stdin` validates connectivity without unlocking a vault; it now works on bound profiles as well as unbound ones. TLS policy remains fail-closed; `--allow-insecure-transport` is required only for non-local hosts.
- Vault labels remain local-only and are never stored in MongoDB documents. `kavrix db vault list --show-labels` still requires authentication.
- `kavrix frames` remains the single source of truth for stdin frame contracts. The six inconsistent families now have compatibility aliases but the canonical names are `--secrets-stdin` (database) and `--passphrase-stdin`/`--value-stdin`/etc (flat).

## Verification

- `pnpm verify` (build, format:check, lint, typecheck, tests), `pnpm --filter kavrix package:smoke`, and `pnpm --filter kavrix test` pass.
- Test expectations updated for the new `db profile show` command and corrected `destroy --help` behavior.
- No plaintext secrets, URIs, or tokens appear in logs or argv. Zero-knowledge ciphertext-only MongoDB storage unchanged.

Previous release: 0.2.9 — Recovery-verified local onboarding.
