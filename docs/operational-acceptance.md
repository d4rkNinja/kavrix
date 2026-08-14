# API and MongoDB operational acceptance

This is the release procedure for the private API process. It assumes a
transaction-capable MongoDB replica set, a service manager that injects
`KAVRIX_MONGODB_URI` without placing it in argv, and an exact built workspace
commit.

## Deployment sequence

1. Install the frozen workspace and build `@kavrix/api`.
2. Take the normal encrypted-vault and MongoDB backups required by the
   operator’s retention policy. Backups are a prerequisite for rollback; this
   procedure does not perform an in-place downgrade.
3. Run `pnpm --filter @kavrix/api migrate` against the target database. The
   command owns canonical validator/index DDL and records schema version 1 in
   `_kavrix_schema_state`. It is idempotent for the same contract and fails
   closed for a malformed or future state.
4. Start each API process with the same database and production environment.
   Startup performs read-only schema compatibility validation. It does not
   create collections or alter validators/indexes.
5. Route traffic only through the configured TLS proxy. Check `/health` for
   process liveness and `/ready` for the MongoDB dependency; `/ready` is HTTP
   200 only for `{ "status": "ready" }` and is HTTP 503 with
   `{ "status": "not_ready" }` otherwise.

The migration command and API process emit only generic success/failure events.
They never print the MongoDB URI, exception text, request bodies, or decrypted
vault data. Keep bootstrap disabled except for a short, isolated provisioning
window.

## Acceptance command

After a build and before routing production traffic, inject the same MongoDB URI
through the protected service environment and run:

```sh
pnpm operational:acceptance
```

The gate fails before child execution when the URI is absent, uses two bounded
shell-free child processes (migration and one exact Vitest file), and gives the
test a generated isolated database name. The real acceptance file verifies:

- replica-set identity, writable-primary status, and logical sessions;
- two independently started production API processes;
- liveness and dependency readiness through the trusted TLS-proxy boundary;
- authenticated bootstrap/session access across processes;
- opaque sync push/pull and secretstream attachment open/chunk/finalize;
- a transaction-consistent `MongoBackupSource` snapshot containing the opaque
  records; and
- process-output bounds and absence of the URI/plaintext canaries.

The command reports only a count on success or a generic failure. CI runs it
against the pinned MongoDB replica set after the existing storage and API
integration gates.

## Upgrade and rollback

Schema changes are forward-only and must be introduced with a new migration
version, a compatibility validator, and an isolated restore/upgrade rehearsal.
For the current baseline:

- Do not start an older binary after a newer schema state has been recorded;
  startup rejects future schema versions.
- If the new application binary must be withdrawn, stop all API processes and
  restore the previous application only when its recorded schema contract is
  compatible. Otherwise restore the pre-upgrade backup into a new isolated
  database, run the matching migration/preflight there, verify `/ready` and the
  API smoke paths, then repoint the TLS proxy.
- Preserve the original database and backup when outcome or commit state is
  uncertain. Do not drop, overwrite, or “repair” a production database in
  place to force an older binary to start.
- Repeat the acceptance command against the isolated target before cutover and
  retain its exact commit, migration result, topology details, and redacted
  service logs as deployment evidence.

This runbook does not claim automatic rollback, online schema downgrade,
MongoDB backup scheduling, or a public container image.
