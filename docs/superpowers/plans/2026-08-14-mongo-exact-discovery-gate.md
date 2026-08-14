# Exact-discovery Mongo integration and plaintext-canary gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fail-closed storage Mongo integration gate that discovers every integration file, runs the exact list, rejects skips and drift, and preserves generic secret-safe output.

**Architecture:** Mirror the existing API integration gate inside `packages/storage` without introducing a cross-layer dependency. The gate owns discovery, bounded `spawn`, JSON report validation, and CLI exit behavior; the current storage integration files continue to own real Mongo transactions, restore behavior, canary scans, and cleanup.

**Tech Stack:** Strict ESM TypeScript, Vitest JSON reporter, Node `child_process.spawn`, bounded buffers/timeouts, MongoDB replica-set integration, and Vitest unit tests with injected child runners.

## Global Constraints

- Require nonblank `KAVRIX_MONGODB_URI` before discovery or child spawn and pass it only through the child environment.
- Use `shell: false`, argument arrays, stable recursive file discovery, bounded output, and a finite timeout.
- Reject zero tests, failed tests, pending/todo tests, missing discovered files, and unexpected report files.
- Emit only generic environment/gate errors; never echo URI, driver output, or child detail.
- Do not weaken existing integration canary, restore, transaction, or teardown assertions.

---

### Task 1: Add failing storage-gate contract tests

**Files:**

- Create: `packages/storage/test/storage-integration-gate.test.ts`

- [x] **Step 1: Test that missing/blank Mongo environment fails before discovery or child execution.**
- [x] **Step 2: Test recursive stable discovery, URI non-disclosure, shell-free invocation, and generic child failure handling.**
- [x] **Step 3: Test rejection of empty, skipped, pending, failed, malformed, and discovery-drift reports plus acceptance of a complete all-passed report.**
- [x] **Step 4: Run the focused tests; the implemented gate passes the contract suite.**

### Task 2: Implement the bounded exact-discovery gate

**Files:**

- Create: `packages/storage/scripts/storage-integration-gate.ts`
- Modify: `packages/storage/package.json`
- Modify: `packages/storage/tsconfig.json`

- [x] **Step 1: Add stable recursive discovery for `packages/storage/integration/**/*.integration.ts`.**
- [x] **Step 2: Add bounded shell-free child execution with generic errors and no child-output disclosure.**
- [x] **Step 3: Invoke Vitest with explicit files, JSON reporting, and `--passWithNoTests=false`; validate every discovered file and zero skipped/failed/todo results.**
- [x] **Step 4: Replace the direct storage integration script with the new gate and typecheck/build it.**

### Task 3: Run affected gates and document exact evidence

**Files:**

- Modify: `docs/implementation-status.md`
- Modify: this plan

- [x] **Step 1: Run focused storage gate tests, storage typecheck/build/lint/format, and the no-environment integration command.**
- [x] **Step 2: Attempt the real storage/API/Mongo gate; record the exact missing prerequisite when no transaction-capable Mongo environment is available.**
- [x] **Step 3: Review the diff for URI leakage, broad skips, shell execution, unbounded output, and altered production assertions.**
- [x] **Step 4: Stage only issue #52 changes and create one local commit named `test(storage): enforce exact Mongo integration discovery (#52)`.**
