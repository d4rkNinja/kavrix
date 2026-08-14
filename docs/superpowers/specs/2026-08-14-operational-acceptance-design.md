# Production API and Mongo Operational Acceptance

## Problem

The API currently installs MongoDB validators and indexes during every server
startup. That makes the long-running service need schema-management privileges,
does not identify which schema contract was applied, and leaves upgrade order to
operator memory. The only probe is `GET /health`, which reports process liveness
without checking MongoDB. The repository has data-plane Mongo integration
suites, but no bounded operator command that proves migration, topology,
multi-process startup, readiness, graceful shutdown, and log privacy together.

## Goals

- Give the operator an idempotent `@kavrix/api` migration command that owns
  validator/index installation, compatibility scanning, and a versioned schema
  marker.
- Make the production API entrypoint perform read-only schema compatibility
  validation and Mongo ping before serving traffic. It must not run DDL.
- Add a dependency-aware `GET /ready` response with strict shared schemas,
  `200 {"status":"ready"}` on success, and generic `503
{"status":"not_ready"}` on dependency failure.
- Add a bounded root `pnpm operational:acceptance` gate that keeps the MongoDB
  URI in the environment, runs migration through the operator command, then
  executes one exact multi-process acceptance file.
- Exercise a real transaction-capable replica set, two API processes sharing
  one database, health/readiness, graceful SIGTERM shutdown, and the absence of
  the Mongo URI and opaque/plaintext canaries from child output.
- Document separate migration/service responsibilities, least-privilege role
  separation, forward-only upgrade behavior, backup-first rollback, and exact
  local/CI limitations.

## Non-goals

- Do not add a container image, Helm chart, service-manager unit, cloud
  deployment, or production deployment action.
- Do not change API authentication, encrypted record formats, sync semantics,
  or backup data-plane behavior.
- Do not implement automatic destructive rollback. A failed upgrade remains
  fail-closed and is recovered by restoring an operator-verified backup into an
  isolated database.
- Do not print MongoDB URIs, credentials, request bodies, bearer tokens, or
  upstream exception text.

## Chosen design

### Versioned migration and read-only service startup

Add an API-owned operational module with these exact constants:

- `MONGO_SCHEMA_VERSION = 1`.
- `MONGO_SCHEMA_STATE_COLLECTION = '_kavrix_schema_state'`.
- State document `_id = 'kavrix'`, `schemaVersion = 1`,
  `migrationId = 'baseline-contracts-v1'`, and an ISO `appliedAt` timestamp.

The migration function installs the canonical storage and API collection
validators/indexes, scans every supported document with the existing redacted
compatibility preflight, and upserts the strict state document. A future schema
change must add a new explicit migration step and version before increasing the
constant. A state version newer than the running binary or a malformed/missing
state document fails closed.

`createMongoApiServer` accepts an explicit `schemaMode` of `validate` or
`install`, defaulting to `validate`. The production `startMongoApiServer`
entrypoint uses validation only. `install` exists for direct adapter/test
composition that intentionally exercises the DDL phase; the documented
operator path always runs the migration command first. Validation checks the
state marker, all storage/API documents, and indexes/validators indirectly via
the canonical contract definitions without mutating the database.

### Readiness

`BuildApiOptions` carries an injected `readiness` function. The Mongo server
composition supplies a callback that runs a bounded `ping` command on its
connected database and returns a boolean without exposing the driver error.
The default test composition returns ready. `/health` remains the cheap process
liveness route. `/ready` catches dependency failures, logs no exception detail,
and returns only the strict readiness status. Production HTTPS and source-rate
limits continue to apply to both probes.

### Operational acceptance gate

The root gate requires a nonblank `KAVRIX_MONGODB_URI`, chooses a validated
operator database name through the environment, and passes the URI only in
child `env` objects. It invokes the API migration script and then Vitest with an
explicit operational config and exact acceptance file. Both child processes
use `shell: false`, bounded output capture, a ten-minute timeout, and generic
failure text.

The acceptance file uses a unique database, verifies replica-set identity and
transaction capability with `hello` plus a short transaction, starts two built
API entrypoint processes on separate loopback ports with production HTTPS
configuration, waits for both `/health` and `/ready`, and stops both with
SIGTERM. It rejects nonzero/forced shutdown and scans combined stdout/stderr
for the URI and canary values. Existing storage/API integration gates continue
to cover opaque sync, attachment, backup, authorization, rollback, and
plaintext persistence behavior.

### Operational procedure

The self-hosting guide will require a migration run with a migration-capable
principal before the API service is restarted with its narrower service
principal. Upgrades are forward-only: snapshot/backup first, run the exact
versioned migration, run compatibility/readiness gates, then roll out API
processes. There is no in-place down migration. If validation fails, stop the
rollout and restore/verify an isolated backup rather than weakening validators
or starting an older binary against a newer schema.

## Verification and evidence

Focused unit tests cover readiness statuses, schema-state validation, migration
command redaction/bounds, exact child invocation, and malformed/empty reports.
The operational integration is the real Mongo/process evidence and is skipped
from claims when MongoDB, a built API, or a transaction-capable topology is not
available. Build, typecheck, format, targeted lint, focused API tests, and the
root gate's no-environment fail-closed behavior are run locally. The
implementation-status row remains pending until a same-SHA hosted transaction
topology run exists.
