# Exact-discovery Mongo integration and plaintext-canary gate design (#52)

## Goal

Make the storage integration command fail closed unless an explicit MongoDB
environment exists and every discovered storage integration file reports only
passed tests. The gate must preserve generic output, bounded child execution,
and the existing plaintext-canary/restore/teardown behavior inside the real
integration suites.

## Architecture

The API package already owns a bounded Vitest JSON-report gate. The storage
package gets the same boundary locally, because its integration files live in a
different package and the storage package must not depend on `apps/api`. The
new `packages/storage/scripts/storage-integration-gate.ts` recursively discovers
only `*.integration.ts` files, invokes Vitest with an explicit file list and
`--passWithNoTests=false`, rejects failed/pending/todo/missing/extra reports,
and prints only a generic error when a child fails.

The child receives `KAVRIX_MONGODB_URI` only through its environment and runs
with `shell: false`, a bounded output buffer, and a hard timeout. The existing
Mongo integration files remain responsible for real transactions, restore
semantics, raw BSON/archive canary scans, and database teardown; this issue
does not weaken or duplicate those production assertions.

## Acceptance flow

1. Require a nonblank `KAVRIX_MONGODB_URI` before discovery or child spawn.
2. Discover all storage integration files recursively in stable normalized order.
3. Spawn the pinned workspace Vitest entry with the storage integration config,
   explicit files, JSON reporter, and no-test failure mode.
4. Validate exact file coverage and zero failed, pending, todo, or total-less
   results; return only file/test counts on success.
5. Run the focused gate tests without Mongo, then run the real command when a
   transaction-capable replica set is available. Record the missing URI/tool
   blocker otherwise.

## Security and failure coverage

- A URI can be present in the child environment but never appears in argv,
  generic stderr, or success output.
- Discovery drift, empty directories, skipped tests, pending tests, failed
  tests, malformed JSON, output overflow, signal termination, and timeout all
  fail closed.
- Child processes use argument arrays and `shell: false`; output is bounded and
  child details are never replayed to the operator.
- Existing integration cleanup and canary assertions are untouched and remain
  part of the live Mongo gate.

## Out of scope

This issue does not add a MongoDB server, alter storage schemas, change API
behavior, expose MongoDB through the CLI, or claim a live result without
`KAVRIX_MONGODB_URI` and a transaction-capable replica set.

## Verification

Run the focused storage gate tests, storage typecheck/build/format/lint, the
missing-environment command, and the real integration command when the local
Mongo prerequisite exists. Update implementation status with exact results.
