# Interruption and recovery acceptance implementation plan

> **For agentic workers:** Execute this plan task-by-task in the current issue
> branch. Keep the change limited to issue #46; fresh-home recovery/device B,
> backup/restore, and whole-system plaintext scanning remain separate issues.

**Goal:** Prove that the production mutation and synchronization boundaries
resume exact durable work after offline transport, ambiguous local commits,
response loss, and explicit conflicts, without data loss, duplicate
publication, rollback-anchor weakening, or plaintext leakage.

**Architecture:** Use the real SQLite sync adapter, production mutation
composition, the real `SyncEngine`, and the native protected-sync-state adapter
behind a test-owned keychain entry seam. The transport fixture carries only
schema-validated opaque records and public change metadata. Faults are injected
at port boundaries after the real adapter has performed its durable operation,
so recovery assertions inspect reopened SQLite/protected state rather than an
in-memory imitation.

## Global constraints

- Keep the zero-knowledge boundary intact: fixtures, request captures, durable
  rows, errors, and assertions must not contain decrypted credential canaries.
- Reuse canonical schemas and inferred types for every opaque mutation, cursor,
  response, conflict, and protected state.
- Do not add production fault flags, test-only branches, or new public CLI
  behavior merely to make the matrix injectable.
- Close and reopen real SQLite stores between interrupted runs; verify exact
  batch/idempotency identities and queue cardinality after every retry.
- Preserve generic failure mapping and best-effort zeroization of all mutable
  key material used to seed the local encrypted vault.

## Task 1: Add the production durable mutation recovery case

**Files:**

- Create: `apps/cli/test/interruption-recovery-acceptance.test.ts`.
- Reuse: `apps/cli/src/production/mutations.ts` and the real
  `@kavrix/local-store` SQLite adapter.

**Scenario:** Seed one authenticated encrypted vault record in a real SQLite
sync store, run `executeProductionCreateGroup`, and wrap only the queue's
`enqueueBatch` acknowledgement so the first call throws
`OpaqueMutationDurabilityUnknownError` after the underlying store committed.
The service must retry the exact canonical batch, return one group identity,
and leave one opaque pending mutation after close/reopen. Assert the canary is
absent from serialized rows and the retry did not generate a second mutation.

- [x] Step 1: Define the failing observable test and bounded encrypted-vault
      seed using canonical schemas.
- [x] Step 2: Run the focused test against the current production composition;
      the initial run exposed the Windows secure-parent setup issue in the test
      harness, which was corrected without changing production behavior.
- [x] Step 3: Review the owning layers; no production fix was required because
      the existing mutation retry and SQLite idempotency behavior preserved the
      exact committed batch.

## Task 2: Add the real SQLite synchronization recovery matrix

**Files:**

- Modify: `apps/cli/test/interruption-recovery-acceptance.test.ts`.
- Inspect only if needed: `packages/sync/src/engine.ts`,
  `packages/local-store/src/sqlite-local-store.ts`, and the protected-state
  adapter.

**Scenarios:** With an opaque scripted transport and real SQLite/protected
state, cover offline before publication, interruption after active-batch
persistence, remote commit followed by response loss, interruption after
reconciliation, interruption after protected completion, and pull-apply
acknowledgement ambiguity. Reopen the store/adapter after each injected
failure, retry, and assert exact request identity, monotonic cursor, one
remote publication per mutation, empty active work after success, and no
rollback-anchor decrease.

- [x] Step 1: Add the faulting transport/local/protected wrappers around real
      adapters; do not replace the adapter itself.
- [x] Step 2: Assert offline/retry and response-loss replay behavior.
- [x] Step 3: Assert explicit conflict retention, redacted metadata, and
      revision-bound keep-local/accept-remote resolution after reopen.
- [x] Step 4: Assert all captured opaque payloads and durable rows exclude the
      test plaintext canary.

## Task 3: Verify and document the issue

**Files:**

- Modify: `docs/implementation-status.md` only for behavior demonstrated by
  the passing acceptance matrix.

- [x] Step 1: Run the focused acceptance test, affected client/sync/local-store
      suites, typecheck, targeted lint, formatting, and `git diff --check`.
- [x] Step 2: Review the diff for secret material, production mocks, weakened
      assertions, duplicate IDs, and stale documentation.
- [x] Step 3: Run the CLI build and package smoke gate when the focused matrix
      is green.
- [x] Step 4: Create one local commit for issue #46; external push/PR remains
      blocked until explicit authorization is available.

**Spec coverage self-review:** This plan covers durable local mutation
acknowledgement, offline queue preservation, exact sync replay, response-loss
deduplication, protected rollback-anchor recovery, explicit conflict handling,
reopen semantics, and plaintext-canary checks. Device-B recovery, backups, and
the repository-wide scan are intentionally out of scope.
