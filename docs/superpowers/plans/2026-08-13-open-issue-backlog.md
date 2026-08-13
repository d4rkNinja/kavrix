# Kavrix Open Issue Backlog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Work through every actionable open Kavrix issue in dependency-safe oldest-first order, with one focused implementation, test cycle, commit, branch, and linked pull request per granular issue.

**Architecture:** Keep canonical schemas in `packages/schemas`, domain policies and ports in `packages/core`, client-side cryptography and lifecycle in the client-facing packages, opaque persistence/sync in `packages/local-store`/`packages/sync`/`packages/storage`, and composition in `apps/cli`/`apps/api`. Tracking epics receive verification and checklist accounting only; they do not receive duplicate implementation when their atomic children already provide the behavior. Every issue is investigated against the current tree and existing merged PRs before code changes.

**Tech Stack:** Node.js 24.19.x development baseline, pnpm 11.21.0, strict ESM TypeScript, Zod schemas, Vitest, SQLite local state, MongoDB replica-set integration, Fastify API, libsodium XChaCha20-Poly1305/secretstream, and GitHub Actions.

## Global Constraints

- Preserve the zero-knowledge boundary: the API and MongoDB never receive plaintext keys, passphrases, tokens, unwrapped keys, or decrypted vault records.
- Use canonical runtime schemas and inferred types; do not duplicate contracts in consumers.
- Fail closed on authentication, validation, corruption, ambiguity, unsafe permissions, and cleanup failure.
- Never put secret material in argv, URLs, ordinary environment variables, logs, fixtures, snapshots, or unprotected files.
- Use `spawn`/`execFile` with argument arrays and `shell: false`; never interpolate secret-bearing commands.
- Do not weaken assertions, bounds, coverage thresholds, security checks, or CI gates to make a change pass.
- Preserve unrelated user work, including the existing untracked `apps/cli/test/production-offline-retry.test.ts` until issue #31 is either completed or explicitly handed back.
- Do not publish, tag, deploy, or release; GitHub branch push and pull-request creation are authorized only for the issue-specific branches described below.

## Current issue order and triage

The 2026-08-13 read-only GitHub index contains open issues `#6`–`#13`, `#31`–`#75` (with the closed gaps omitted), and `#77`. Issues `#6`, `#7`, `#8`, `#9`, `#10`, `#11`, `#12`, `#13`, and `#57`/`#77` are tracking epics. Their child issues are the implementation units. The merged PR map confirms issues `#14`–`#30` are already implemented and closed; they are evidence for parent-epic verification, not duplicate work.

The first actionable child is issue #31 because issue #30 is merged and its parent #8 cannot be completed until #31 and #32 are handled. After each granular issue, refresh the open issue list and dependency state; do not assume issue descriptions or checklists have stayed current.

### Task 1: Repository inventory and baseline

**Files:**

- Read: `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, `apps/AGENTS.md`, `packages/AGENTS.md`, `docs/AGENTS.md`, `SECURITY.md`, all files in `docs/`, package manifests, TypeScript/Vitest/ESLint configuration, and CI workflows.
- Preserve: `apps/cli/test/production-offline-retry.test.ts`.

- [x] Read repository instructions, architecture/security/data-model documentation, release/testing guidance, and the current implementation ledger.
- [x] Record the working-tree branch and unrelated changes before editing.
- [x] Retrieve the open issue index and existing PR/branch history read-only.
- [x] Run the baseline `pnpm.cmd verify`; record that the present tree stops at formatting because the untracked issue-31 test is not formatted.
- [x] Run the focused production mutation tests with the real Windows ACL boundary; fix the archive/restore schema regression encountered while verifying the issue-31 mutation path.

### Task 2: Verify resolved tracking epics #6 and #7

**Files:**

- Test: `apps/cli/test/group-commands.test.ts`, `apps/cli/test/credential-commands.test.ts`, `apps/cli/test/field-commands.test.ts`, `apps/cli/test/note-commands.test.ts`, `apps/cli/test/package.test.ts`, and the production show/copy/reveal/get tests already present in `apps/cli/test/`.
- Review: merged PRs #87–#97 and issues #22–#30.

- [x] Run the child command and packed-smoke tests on the current base history.
- [x] Confirm that the child issues are closed and their merged PRs contain the behavior described by the parent acceptance criteria.
- [ ] If the evidence is complete, add a concise issue comment with exact commands/results and close the tracking epics through the authorized GitHub workflow; create no duplicate code PR.
- [ ] If a child behavior is missing, return to that child as the next actionable issue with a focused branch instead of closing the parent.

### Task 3: Issue #31 — offline mutation and retry behavior

**Files:**

- Modify: `apps/cli/test/production-offline-retry.test.ts` (the existing user-owned untracked regression fixture, preserving its intent and correcting only issue-scoped defects).
- Inspect and modify only if the focused regression proves a production gap: `apps/cli/src/catalog.ts`, `apps/cli/src/production/mutations.ts`, `apps/cli/src/production/ports.ts`, `apps/cli/src/production/unlock.ts`, `packages/client/src/vault-mutation-service.ts`, `packages/sync/src/engine.ts`, or `packages/local-store/src/sqlite-local-store.ts`.
- Test: affected `apps/cli/test/production-*.test.ts`, `packages/sync/test/`, `packages/local-store/test/`, and the issue-specific test above.
- Documentation only if observable status changes: `docs/implementation-status.md` and the relevant CLI guide.

**Interfaces:**

- Consumes `VaultMutationService`'s `OpaqueMutationQueuePort` and `VaultMutationStatePort`.
- Uses `SqliteSyncLocalStore.enqueueBatch`, `listPendingMutations`, `getCurrentGroup`, and `getCurrentItem` for durable opaque local state.
- Uses `SyncEngine.synchronize` and its `SyncTransportPort` for ordered push, response-loss recovery, and queue completion.
- Produces a production-level regression proving local mutation overlays survive a close/reopen and that failed/offline sync leaves the exact pending queue intact.

- [x] Correct the fixture's `encryptPayload(plaintext, rootKey, context)` argument order and ensure every generated root key/byte buffer is wiped in `finally`.
- [x] Add the failing observable assertions: group/credential/field mutation while the transport is unavailable, close and reopen the SQLite environment, pending opaque rows and visible overlays after reopen, no plaintext canary in serialized rows, and a sanitized offline status.
- [ ] Exercise a real durable sync retry with a fake opaque transport: first transport failure keeps the queue; an accepted response removes each idempotency key once; an ambiguous response is replayed with the same durable batch key and does not duplicate publication.
- [x] If the focused test fails because the production composition drops, duplicates, or prematurely acknowledges work, implement the smallest owning-layer fix and add a regression at that boundary.
- [x] Run the focused test before and after the fix, then run the affected CLI/client/sync/local-store suites, format, lint, typecheck, and build.
- [ ] Review all callers of changed ports/functions, scan the serialized local state and errors for canaries, commit only issue #31, push `feat/issue-31-offline-mutations`, and open one PR targeting `main` with `Closes #31` and `Refs #8`.

### Task 4: Continue the dependency-safe granular backlog

For each next open granular issue, create a fresh issue branch from the latest `main` (or reuse the already isolated issue branch only when it contains no unrelated changes), read the complete issue discussion and linked PRs, locate the owning boundary, write a failing observable test, implement the smallest root-cause fix, run the affected and repository gates, commit, push, create the linked PR, inspect CI, and only then advance. The next dependency sequence after #31 is #32, then the parent #8; subsequent parent/child sequences are #33–#36 for #9, #37–#40 for #10, #41–#44 for #11, #45–#53 for #12, #54–#56 for #13, and #58–#75 for #57. Refresh this list from GitHub before each transition so already-closed or reordered work is not duplicated.

- [x] Issue #32: expose explicit CLI conflict listing and resolution locally; durable v4 ledger, migration, redacted CLI contracts, revision-bound policies, and focused tests pass. Push/PR remains pending explicit external authorization.
- [x] Issue #74: compose a non-destructive existing-vault `connect` flow after #32; validate exact session/vault/device binding and active device slot, persist only the canonical profile, bootstrap the opaque local sync store, and close resources on success/failure. Push/PR remains pending explicit external authorization.
- [ ] Verify/close parent #8 after #30–#32 evidence is complete.
- [ ] Issues #33–#36: protected import/recovery/unlock-slot/portable-key rotation composition.
- [ ] Issues #37–#40: device invite/join/list/revoke/remember/forget composition.
- [ ] Issues #41–#44: backup create/verify/restore and semantic history/audit handling.
- [ ] Issues #45–#53: command-only journey, package/plaintext-canary acceptance, and adjacent acceptance gates.
- [ ] Issues #54–#56: release/security/platform verification children and parent #13.
- [ ] Issues #58–#75: post-basic CLI capabilities in their strict predecessor order.
- [ ] Verify/close parent epics #9–#13, #57, and #77 only after their child evidence is complete.

### Task 5: Final repository-wide review

**Files:**

- Review: all changed files, `docs/implementation-status.md`, CI workflows, package manifests, and pull-request evidence.

- [ ] Refresh the open issue list and confirm every actionable issue has a merged/accepted focused PR or an evidence-backed no-code resolution.
- [ ] Run `pnpm.cmd build`, `pnpm.cmd format:check`, `pnpm.cmd lint`, `pnpm.cmd typecheck`, `pnpm.cmd test`, `pnpm.cmd test:coverage`, and `pnpm.cmd audit --audit-level high` on the final combined tree.
- [ ] Run MongoDB integration and packaged CLI smoke gates when their required services/tooling are available; record unavailable infrastructure without fabricating a pass.
- [ ] Reconcile documentation with observable evidence and list known limitations, remaining CI failures, blocked issues, tests added, branches, and PR URLs.
