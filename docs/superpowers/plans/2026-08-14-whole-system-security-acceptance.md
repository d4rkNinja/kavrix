# Whole-system plaintext canary and hostile terminal acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a focused whole-system plaintext-canary acceptance gate and close the remaining hostile terminal-control gaps in CLI and TUI sanitization.

**Architecture:** Reuse the production-backed basic CLI acceptance journey for local storage, opaque HTTP, backup, output, completion, logs, and clipboard evidence. Keep the scanner test-only and bounded. Harden the two existing sanitization boundaries without changing cryptographic or transport contracts.

**Tech Stack:** Strict ESM TypeScript, Vitest, Node filesystem/crypto primitives, `@kavrix` CLI/TUI packages, real SQLite local storage, encrypted opaque HTTP fixture, and the existing encrypted backup commands.

## Global Constraints

- Never print or persist the runtime canary from failure reporting; identify only the surface, encoding, and a one-way fingerprint.
- Keep initialization's explicitly acknowledged portable/recovery display as the only intentional guarded output; never allowlist the credential canary.
- Scan raw bytes and UTF-8, UTF-16LE, Base64, Base64url, JSON-escaped, and direct substring representations.
- Preserve the packed CLI's zero-knowledge boundary and the existing public command surface.
- Keep MongoDB verification mapped to #48's live integration gate; do not add a CLI Mongo adapter.
- Use `apply_patch`, focused tests, affected package gates, and one local issue-specific commit.

---

### Task 1: Establish failing hostile-terminal regressions

**Files:**

- Modify: `apps/cli/test/boundaries.test.ts`
- Modify: `packages/tui/test/state-edges.test.ts`

- [x] **Step 1: Add CLI cases for 8-bit OSC/DCS/SOS/PM/APC payloads, unterminated strings, and Unicode line separators.**
- [x] **Step 2: Add the corresponding TUI sanitizer cases and assert that payloads and control code points do not survive.**
- [x] **Step 3: Run the two focused suites and capture the expected failures before the production change.**

### Task 2: Harden both terminal sanitizers

**Files:**

- Modify: `apps/cli/src/terminal.ts`
- Modify: `packages/tui/src/terminal-text.ts`

- [x] **Step 1: Consume 8-bit C1 string commands through BEL, ST, or the 8-bit string terminator.**
- [x] **Step 2: Treat U+2028 and U+2029 as unsafe terminal controls at both boundaries.**
- [x] **Step 3: Run focused CLI/TUI tests, typechecks, lint, and formatting checks.**

### Task 3: Add the whole-system canary acceptance evidence

**Files:**

- Modify: `apps/cli/test/basic-vault-acceptance.test.ts`
- Modify: `apps/cli/test/public-security-tools.test.ts`

- [x] **Step 1: Generate a per-run high-entropy credential canary and add a scanner for all required byte and text encodings without exposing the value on failure.**
- [ ] **Step 2: Record command arguments/environment/output and logs, inspect opaque HTTP bodies and real home-directory artifacts, and verify the canary is absent.**
- [ ] **Step 3: Exercise encrypted backup create/verify and shell completion, then scan archive bytes and post-lock clipboard state.**
- [ ] **Step 4: Run the focused acceptance suite and review the test for hidden plaintext allowances or fixture leakage.**

### Task 4: Document and verify the issue

**Files:**

- Modify: `docs/implementation-status.md`
- Modify: `apps/cli/README.md`
- Modify: this plan

- [x] **Step 1: Document the local #49 gate, its covered surfaces, the #48 Mongo ownership boundary, and known environment blockers.**
- [ ] **Step 2: Run affected package tests, typechecks, builds, lint, format, and diff checks.**
- [x] **Step 3: Review the diff for secret leakage, unsafe allowlists, and unrelated issue changes.**
- [ ] **Step 4: Create one local commit with message `test(security): prove whole-system canary boundaries (#49)`; external push/PR remains blocked without authorization.**
