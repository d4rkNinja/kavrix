# Native platform acceptance gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit opt-in gate that runs real keychain, protected key-file, and clipboard platform acceptance without allowing skips or leaking child output.

**Architecture:** A root TypeScript gate owns prerequisite validation, exact file selection, bounded shell-free Vitest execution, and JSON report validation. A dedicated Vitest config includes the existing keychain and clipboard integration suites plus one new key-file integration suite; ordinary unit tests remain non-mutating and do not invoke native stores or the clipboard.

**Tech Stack:** Strict ESM TypeScript, Node `child_process.spawn`, Vitest JSON reporting, `@napi-rs/keyring`, platform ACL/mode APIs, native clipboard commands, and Vitest adversarial tests.

## Global Constraints

- Require all four non-secret opt-in flags before spawn: `KAVRIX_KEYCHAIN_INTEGRATION=1`, `KAVRIX_KEY_FILE_INTEGRATION=1`, `KAVRIX_CLIPBOARD_INTEGRATION=1`, and `KAVRIX_CLIPBOARD_EXCLUSIVE_SESSION=1`.
- Run the exact three integration files with `shell: false`, argument arrays, bounded output, and a finite timeout.
- Reject zero, skipped, pending, todo, failed, malformed, or incomplete reports.
- Never print child stdout/stderr, paths containing secret-bearing values, or clipboard/key bytes.
- Keep native integration opt-in; do not rename mutating tests into the ordinary unit glob.
- Preserve existing no-fallback, ACL/mode, link-count, compare-before-clear, cleanup, and buffer-wipe assertions.

---

### Task 1: Add the failing platform-gate contract tests

**Files:**

- Create: `scripts/platform-acceptance.test.ts`
- Create: `scripts/platform-acceptance.ts`

- [ ] **Step 1: Test missing/blank opt-in flags fail before child execution.**
- [ ] **Step 2: Test exact file arguments, environment-only flags, `shell: false`, and generic failure output with a child canary.**
- [ ] **Step 3: Test malformed, empty, skipped, pending, failed, and file-drift JSON reports plus the all-passed result.**
- [ ] **Step 4: Test child timeout/output bounds and run the focused suite before implementation.**

### Task 2: Implement the exact native-platform gate

**Files:**

- Create: `scripts/platform-acceptance.ts`
- Create: `vitest.platform.config.ts`
- Modify: `package.json`
- Modify: `tsconfig.json`

- [ ] **Step 1: Require all opt-in flags and select the three exact integration files.**
- [ ] **Step 2: Add bounded shell-free child execution and generic error handling.**
- [ ] **Step 3: Invoke Vitest with the platform config and validate exact all-passed/no-skip JSON coverage.**
- [ ] **Step 4: Add `platform:acceptance` and typecheck/lint the gate.**

### Task 3: Add real key-file platform acceptance

**Files:**

- Create: `packages/key-files/integration/platform-key-file.integration.ts`
- Modify: `packages/key-files/tsconfig.json`

- [ ] **Step 1: Add an opt-in test that writes/reads a generated key and wipes it.**
- [ ] **Step 2: Assert hard-link rejection and real Unix mode or Windows ACL rejection.**
- [ ] **Step 3: Run the integration file only through the explicit platform config.**

### Task 4: Run affected gates and record exact evidence

**Files:**

- Modify: `docs/dependency-policy.md`
- Modify: `docs/implementation-status.md`
- Modify: this plan

- [ ] **Step 1: Run the new gate contract tests, affected package tests, build/typecheck/lint/format checks.**
- [ ] **Step 2: Run `platform:acceptance` on this Windows workstation with all flags; record native-store/desktop/ACL blockers without claiming a pass.**
- [ ] **Step 3: Review the diff for plaintext, fallback, shell, skip, cleanup, and unrelated workflow changes.**
- [ ] **Step 4: Stage only issue #53 changes and commit `test(platform): add opt-in native acceptance gate (#53)`.**
