# Exact repository verification gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run issue #50's build, format, lint, typecheck, unit, integration, and coverage gates against one exact local commit without suppressing failures, then record the exact evidence and blockers.

**Architecture:** This is a verification-only issue. It changes no production behavior, schemas, cryptographic envelopes, assertions, thresholds, or CI skip logic. The only expected repository change is factual status/plan documentation when a command result requires it.

**Tech Stack:** Node 24.13.1 on Windows, pnpm 11.21.0, TypeScript project references, ESLint, Prettier, Vitest, Vitest V8 coverage, and the existing MongoDB replica-set integration contract.

## Global Constraints

- Run every command against the same checked-out commit and record the branch, SHA, runtime, package-manager version, and environment variables.
- Do not weaken assertions, coverage thresholds, validation, security bounds, or integration skips to make a gate pass.
- Keep Mongo integration disabled only when `KAVRIX_MONGODB_URI` is absent; record the exact prerequisite instead of claiming a pass.
- Preserve zero-knowledge boundaries and never add secrets, generated credentials, or environment files to the repository.
- Do not publish, push, create a pull request, close issues, tag releases, or modify deployment state without the required external authorization.

---

### Task 1: Freeze the verification context

**Files:**

- Read: `package.json`
- Read: `pnpm-lock.yaml`
- Read: `vitest.config.ts`
- Read: `.github/workflows/ci.yml`
- Read: `docs/release.md`

- [x] **Step 1: Record the exact branch/SHA, Node version, pnpm version, operating system, and Mongo/auxiliary tool availability.**
- [x] **Step 2: Confirm that the worktree is clean before running the gates and that `KAVRIX_MONGODB_URI` is either a transaction-capable replica-set URI or unset.**
- [x] **Step 3: Identify the focused observable blockers without changing production code: the #49 real-vault canary flow, the existing Windows ACL/key-file tests, and the native keychain tests.**

### Task 2: Run the exact static and build gates

**Files:**

- Modify: `docs/implementation-status.md` only when exact results need recording
- Modify: this plan

- [x] **Step 1: Run `pnpm.cmd --workspace-root run build` and retain the complete result.**
- [x] **Step 2: Run `pnpm.cmd --workspace-root run format:check` and retain the complete result.**
- [x] **Step 3: Run `pnpm.cmd --workspace-root run lint` without `--fix` and retain every failure.**
- [x] **Step 4: Run `pnpm.cmd --workspace-root run typecheck` and retain the complete result.**

### Task 3: Run unit, integration, and coverage gates

**Files:**

- Read: `vitest.config.ts`
- Read: package integration scripts
- Modify: `docs/implementation-status.md` only when exact results need recording

- [x] **Step 1: Run `pnpm.cmd --workspace-root test` with the repository's configured timeout and retain test failures and timeout evidence.**
- [x] **Step 2: When a transaction-capable Mongo replica set is available, run storage/API integration and the #48 canary gate with `KAVRIX_MONGODB_URI`; otherwise record the unset-variable blocker and do not fabricate a result.**
- [x] **Step 3: Run `pnpm.cmd --workspace-root run test:coverage` with the configured thresholds and retain the report or exact environment failure.**
- [x] **Step 4: Run the focused changed-file tests and affected package checks separately so passing evidence is not hidden by unrelated platform failures.**

### Task 4: Record and commit exact evidence

**Files:**

- Modify: `docs/implementation-status.md`
- Modify: this plan

- [x] **Step 1: Record exact command results, counts, timeouts, skipped integration reason, and platform limitations without labeling blocked gates as verified.**
- [x] **Step 2: Review the diff for threshold suppression, skip broadening, plaintext leakage, and unrelated implementation changes.**
- [x] **Step 3: Run `git diff --check`, stage only issue #50 documentation, and create one local commit named `test(verification): record exact repository gates (#50)`.**
