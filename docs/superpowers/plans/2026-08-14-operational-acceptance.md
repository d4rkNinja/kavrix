# Production API and Mongo Operational Acceptance Implementation Plan

> For agentic workers: use the subagent-driven-development or executing-plans skill to implement this plan task by task. Steps use checkbox syntax for tracking.

Goal: Separate Mongo schema management from API startup, add dependency-aware readiness, and prove the production operational path with a bounded multi-process acceptance gate.

Architecture: apps/api/src/mongo-operations.ts owns the versioned state and composes the canonical validator/index installers. The service entrypoint validates state and documents read-only; apps/api/scripts/mongo-migrate.ts is the DDL owner. scripts/operational-acceptance.ts runs migration and one exact real-Mongo process smoke file with shell-free bounded children.

Tech stack: strict ESM TypeScript, Zod, Fastify, MongoDB Node driver, Vitest, tsx, child_process.spawn, GitHub Actions.

## Global constraints

- MONGO_SCHEMA_VERSION is exactly 1 and MONGO_SCHEMA_STATE_COLLECTION is exactly _kavrix_schema_state.
- The state document is _id=kavrix, schemaVersion=1, migrationId=baseline-contracts-v1, and appliedAt.
- startMongoApiServer performs read-only compatibility validation and never runs createCollection, collMod, or createIndexes.
- GET /ready returns only {status: ready} with 200 or {status: not_ready} with 503.
- Mongo URIs stay in child environment objects and never enter process arguments, output, or docs as usable credentials.
- Operational children use shell:false, a 4 MiB capture bound, and a 10 minute timeout.
- No automatic destructive rollback, container image, deployment, release, or external GitHub mutation is included.

---

### Task 1: Add the readiness wire contract

Files:

- Modify: packages/schemas/src/api.ts
- Modify: packages/schemas/test/api.test.ts
- Modify: apps/api/src/route-context.ts
- Modify: apps/api/src/app.ts
- Modify: apps/api/src/routes/health.ts
- Modify: apps/api/test/api.test.ts

Interfaces:

- Produces readinessResponseSchema, ReadinessResponse, and an injected readiness callback of type () => Promise<boolean>.

- [x] Step 1: Write failing schema and route tests.

Add tests that accept exactly ready and not_ready, reject an extra detail field, return 200 with {status: ready} when the callback resolves true, return 503 with {status: not_ready} when it resolves false, hide a rejected callback error, and require HTTPS for /ready in production.

```ts
const response = await app.inject({ method: 'GET', url: '/ready' });
expect(response.statusCode).toBe(503);
expect(response.json()).toEqual({ status: 'not_ready' });
expect(response.body).not.toContain('readiness plaintext-canary');
```

- [x] Step 2: Run the focused tests and observe the failure.

Run:

```powershell
node_modules/.bin/vitest.CMD run packages/schemas/test/api.test.ts apps/api/test/api.test.ts
```

Expected: the new schema and route assertions fail because the readiness contract is absent.

- [x] Step 3: Implement the minimal shared schema and route.

Define the strict Zod schema:

```ts
export const readinessResponseSchema = z
  .object({ status: z.enum(['ready', 'not_ready']) })
  .strict();
export type ReadinessResponse = z.infer<typeof readinessResponseSchema>;
```

Add readiness to RouteContext and BuildApiOptions, defaulting to an async true callback for in-memory compositions. Register /ready in health.ts. Catch dependency errors without logging them and send the strict 503 response.

- [x] Step 4: Run focused tests and formatting.

Run:

```powershell
node_modules/.bin/vitest.CMD run packages/schemas/test/api.test.ts apps/api/test/api.test.ts
node_modules/.bin/prettier.CMD --check packages/schemas/src/api.ts packages/schemas/test/api.test.ts apps/api/src/route-context.ts apps/api/src/app.ts apps/api/src/routes/health.ts apps/api/test/api.test.ts
```

Expected: all focused tests and formatting checks pass.

### Task 2: Add versioned Mongo migration and read-only startup

Files:

- Create: apps/api/src/mongo-operations.ts
- Modify: apps/api/src/index.ts
- Modify: apps/api/src/server.ts
- Modify: apps/api/test/service.test.ts
- Create: apps/api/test/mongo-operations.test.ts

Interfaces:

- Produces MONGO_SCHEMA_VERSION, MONGO_SCHEMA_STATE_COLLECTION, migrateMongoApiDatabase(database, now?), assertMongoApiDatabaseCompatibility(database), and MongoApiServerOptions.

- [x] Step 1: Write state and server-mode tests.

Test that version 1 and collection name _kavrix_schema_state are exact; valid state passes; missing, malformed, and future state fail with generic Mongo schema compatibility check failed; and the existing server fixture can still explicitly exercise DDL with schemaMode install. Add a test that production start uses validation and does not install contracts.

```ts
await expect(
  assertMongoApiDatabaseCompatibility(databaseWithState(1)),
).resolves.toBeUndefined();
await expect(assertMongoApiDatabaseCompatibility(databaseWithState(2))).rejects.toThrow(
  'Mongo schema compatibility check failed',
);
```

- [x] Step 2: Implement the operational state and migration composition.

Use a strict state schema with _id=kavrix, schemaVersion literal 1, migrationId literal baseline-contracts-v1, and an offset ISO timestamp. Add a MongoSchemaCompatibilityError whose only message is Mongo schema compatibility check failed. migrateMongoApiDatabase must install both existing storage/API contract families, scan both with the existing redacted compatibility preflight, create or collMod the state collection with a strict validator, and upsert one state document. A future state version fails before mutation; no application collection or document is deleted.

assertMongoApiDatabaseCompatibility must read and parse the state before scanning storage and API documents and must not call any DDL method.

- [x] Step 3: Separate server modes.

Add:

```ts
export type MongoApiServerSchemaMode = 'validate' | 'install';
export interface MongoApiServerOptions {
  readonly schemaMode?: MongoApiServerSchemaMode;
}
```

Change createMongoApiServer(input, runtime, options = {}) to default to validate. install preserves direct unit composition that intentionally tests DDL. startMongoApiServer must pass validate explicitly. Pass this Mongo readiness callback into BuildApiOptions:

```ts
readiness: async () => {
  try {
    await database.command({ ping: 1 });
    return true;
  } catch {
    return false;
  }
},
```

- [x] Step 4: Run focused server tests and lint.

Run:

```powershell
node_modules/.bin/vitest.CMD run apps/api/test/mongo-operations.test.ts apps/api/test/service.test.ts
node_modules/.bin/eslint.CMD apps/api/src/mongo-operations.ts apps/api/src/server.ts apps/api/test/mongo-operations.test.ts apps/api/test/service.test.ts
```

Expected: all tests pass and no changed-file lint error exists.

### Task 3: Add the operator migration command

Files:

- Create: apps/api/scripts/mongo-migrate.ts
- Modify: apps/api/package.json
- Modify: apps/api/test/service-environment.test.ts

- [x] Step 1: Write the command redaction contract.

Read the script source in a focused test and assert that the URI is read from the environment/service parser, never process.argv, and that output does not interpolate upstream errors. Keep database-name and URI validation covered by service-environment tests.

- [x] Step 2: Implement the command.

The command parses process.env with parseMongoApiServiceEnvironment, connects using MongoClient with appName kavrix-api-migrator, calls migrateMongoApiDatabase, and closes in finally. Success output is exactly [kavrix-api] migration complete. Invalid configuration uses exit code 78 and only the setting name. Connection or migration failure uses exit code 1 and exactly [kavrix-api] migration failed. Never print URI, database contents, error.message, or a stack trace.

- [x] Step 3: Wire and exercise the package script.

Add this script:

```json
"migrate": "tsx ./scripts/mongo-migrate.ts"
```

Run:

```powershell
pnpm.cmd --filter @kavrix/api migrate
```

Expected without KAVRIX_MONGODB_URI: exit code 1, generic environment failure, and no URI.

### Task 4: Build the bounded operational gate

Files:

- Create: scripts/operational-acceptance.ts
- Create: scripts/operational-acceptance.test.ts
- Create: apps/api/vitest.operational.config.ts
- Modify: package.json

Interfaces:

- Produces runOperationalAcceptance(options?), executeOperationalAcceptance(options?), and root command operational:acceptance.
- Reuses BoundedChildInvocation and runBoundedChild from apps/api/scripts/api-integration-gate.ts.

- [x] Step 1: Write gate contract tests.

Cover absent or blank URI failure before child execution; URI only in environment and never args; shell false; exact migration and Vitest args; generic migration/Vitest failure; malformed/empty/pending JSON reports; output-limit overflow; and timeout. A successful fake migration plus valid one-file JSON report returns a summary.

```ts
await expect(runOperationalAcceptance({ environment: {}, runChild })).rejects.toThrow(
  'MongoDB operational acceptance environment is required.',
);
expect(runChild).not.toHaveBeenCalled();
```

- [x] Step 2: Implement the two-child bounded gate.

Require nonblank KAVRIX_MONGODB_URI. Preserve a valid KAVRIX_DATABASE_NAME or generate one matching the API database grammar, then pass it only through child env. First invoke process.execPath with the resolved tsx CLI and apps/api/scripts/mongo-migrate.ts. Then invoke Vitest with apps/api/vitest.operational.config.ts and exactly apps/api/operational/operational-acceptance.integration.ts. Validate every report field using the existing no-skip/all-passed rules. Use a 4 MiB bound and 10 minute timeout for both children. Print only Operational acceptance passed (N tests). or generic failure text.

- [x] Step 3: Add the config and root command.

Add operational:acceptance: tsx ./scripts/operational-acceptance.ts. Configure one exact include, fileParallelism false, 30-second test/hook timeouts, and passWithNoTests false. Include apps/api/operational in the API typecheck configuration.

- [x] Step 4: Run contract tests and the no-environment command.

Run:

```powershell
node_modules/.bin/vitest.CMD run scripts/operational-acceptance.test.ts apps/api/test/api-integration-gate.test.ts
pnpm.cmd operational:acceptance
```

Expected: contract tests pass; the command exits 1 with only the generic missing-environment message because no Mongo URI is configured locally.

### Task 5: Add real topology and multi-process acceptance

Files:

- Create: apps/api/operational/operational-acceptance.integration.ts
- Create: apps/api/vitest.operational.config.ts
- Modify: apps/api/integration/mongo-service.integration.ts
- Modify: apps/api/integration/mongo-bootstrap.integration.ts
- Modify: apps/api/integration/mongo-api.integration.ts

- [x] Step 1: Implement topology and transaction proof.

Use KAVRIX_MONGODB_URI and KAVRIX_DATABASE_NAME from env, connect to admin, require hello.setName and a positive logicalSessionTimeoutMinutes, and execute one bounded withTransaction probe with an opaque identifier. Run migrateMongoApiDatabase on the same database and assert state version 1.

- [x] Step 2: Implement the two-process smoke.

Spawn process.execPath with only the built apps/api/dist/main.js argument, production env, loopback host, separate ports, and KAVRIX_API_TRUSTED_PROXIES=127.0.0.1. Wait for both /health and /ready using x-forwarded-proto=https. Send SIGTERM to both, require clean exit code 0 within a bound, and assert combined stdout/stderr excludes the URI, operational-plaintext-canary, and operational-opaque-secret-canary. Stop children and drop the unique DB in finally.

- [x] Step 3: Migrate direct integration setup first.

Before real createMongoApiServer or startMongoApiServer calls in the three existing integration files, run the migration function for the unique database. Preserve unit tests that intentionally call installMongo*Contracts.

- [x] Step 4: Run focused source checks.

Run:

```powershell
node_modules/.bin/vitest.CMD run apps/api/test/api.test.ts apps/api/test/service.test.ts apps/api/test/mongo-adapters.test.ts
pnpm.cmd --filter @kavrix/api build
pnpm.cmd --filter @kavrix/api typecheck
```

Expected: source tests, build, and typecheck pass. Real Mongo acceptance is claimed only when the dedicated gate runs with a built API and transaction-capable replica set.

### Task 6: Update runbook, CI, status, and complete verification

Files:

- Modify: docs/self-hosting.md
- Modify: docs/implementation-status.md
- Modify: .github/workflows/ci.yml
- Modify: docs/superpowers/plans/2026-08-14-operational-acceptance.md

- [x] Step 1: Document migration, least privilege, readiness, and rollback.

Replace the stale no-migration/no-readiness wording. Document the order: frozen install, API build, API migrate, operational acceptance, then API start. State that the migration principal owns validator/index DDL and the running API principal is data-plane only; upgrades are forward-only; rollback restores an operator-verified backup into an isolated database; and /ready is the dependency-aware probe.

- [x] Step 2: Add the exact CI invocation.

After the existing Mongo build and storage/API gates in the pinned mongo-integration job, add:

```yaml
- name: Run bounded operational acceptance
  run: pnpm operational:acceptance
```

Keep URI values in the job environment and preserve all existing image, runner, canary, and coverage pins.

- [x] Step 3: Record honest status.

Add or update a Production API and Mongo operational acceptance row as Pending rerun until a changed-SHA hosted run exists. Record local readiness/migration/gate evidence and the exact local Mongo/topology blockers. Do not reuse an older successful run.

- [x] Step 4: Run final checks and commit.

Run:

```powershell
node_modules/.bin/prettier.CMD --check .
node_modules/.bin/eslint.CMD apps/api/src apps/api/scripts apps/api/test scripts/operational-acceptance.ts scripts/operational-acceptance.test.ts --max-warnings 0
pnpm.cmd build
pnpm.cmd typecheck
git diff --check
```

Expected: formatting, targeted lint, build, typecheck, and diff checks pass. Record any repository-wide pre-existing failures without weakening assertions.

Commit:

```powershell
git add packages/schemas apps/api scripts/operational-acceptance.ts scripts/operational-acceptance.test.ts package.json docs/self-hosting.md docs/implementation-status.md .github/workflows/ci.yml docs/superpowers/specs/2026-08-14-operational-acceptance-design.md docs/superpowers/plans/2026-08-14-operational-acceptance.md
git commit -m "feat: add API Mongo operational acceptance (#75)"
```

## Verification notes

- Focused #75 coverage: 91 tests passed across readiness, migration, service
  startup, schemas, and the bounded gate; API unit tests passed 140/140 and
  storage unit tests passed 69/69.
- Build, Prettier, and all 15 workspace typecheck projects passed. Targeted
  ESLint for the changed source passed. Repository ESLint still reports the
  existing 18 CLI-only violations; the full test command timed out after
  managed Windows ACL/native-keychain failures.
- A temporary MongoDB 8.3 single-member replica set passed the complete
  two-process operational acceptance gate. Existing real-Mongo storage and API
  suites also ran, but exposed two pre-existing backup/restore expectation
  failures and two pre-existing Mongo authorization update-path conflicts;
  those are not attributed to #75.
