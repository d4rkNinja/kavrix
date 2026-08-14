# Package security and packed-install verification gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Audit the exact lockfile and lifecycle surface, verify the public archive allowlist and SBOM/hash contract, run offline installation, and execute the generated `creds` launcher without weakening package checks.

**Architecture:** This is a verification-only issue. `apps/cli/scripts/build-package.js` is the source of the public bundle/SBOM invariants and `apps/cli/scripts/smoke-packed-package.js` is the authoritative offline-install, launcher, canary, lazy-loading, and local-status smoke. The branch records exact command results and changes no package behavior unless an independently observed defect requires a focused fix.

**Tech Stack:** Node 24.13.1 on Windows, pnpm 11.21.0, pnpm lockfile v9, npm audit, esbuild, CycloneDX 1.6, npm pack, offline npm install, generated Windows launcher, and the existing packed-package smoke script.

## Global Constraints

- Inspect and verify the committed `pnpm-lock.yaml`; do not regenerate or loosen dependency ranges during audit.
- Do not accept unknown lifecycle scripts, unreviewed bundled runtime packages, workspace protocols, source files, source-map contents, or plaintext canaries in the public archive.
- Keep the package self-contained and dependency-free at runtime; preserve the exact allowlist and per-artifact SHA-256 SBOM checks.
- Run the smoke against the exact archive produced by the package workflow and wipe test-owned secret buffers during cleanup.
- Do not publish, push, create a pull request, close issues, or modify release state without explicit external authorization.

---

### Task 1: Freeze package and lockfile context

**Files:**

- Read: `package.json`
- Read: `apps/cli/package.json`
- Read: `pnpm-lock.yaml`
- Read: `apps/cli/scripts/build-package.js`
- Read: `apps/cli/scripts/smoke-packed-package.js`
- Read: `.github/workflows/ci.yml`
- Read: `.github/workflows/publish.yml`

- [x] **Step 1: Record the exact branch/SHA, Node version, pnpm version, lockfile version, package version, and platform.**
- [x] **Step 2: Enumerate package lifecycle scripts and verify that no new unreviewed install/prepare/postinstall path exists.**
- [x] **Step 3: Identify the exact archive allowlist, reviewed runtime dependencies, SBOM component/hash assertions, lazy-load checks, and offline launcher checks.**

### Task 2: Run dependency and archive inspection gates

**Files:**

- Modify: `docs/implementation-status.md` only for exact evidence
- Modify: this plan

- [x] **Step 1: Run `pnpm.cmd audit --audit-level high` and record advisories or the exact registry/network blocker.**
- [x] **Step 2: Run `pnpm.cmd --dir apps/cli run pack:check` and inspect the JSON archive file list against the package allowlist.**
- [x] **Step 3: Run the package build and unpack/inspect the produced archive, verifying package metadata, no workspace/runtime dependency declarations, exact generated artifacts, and SBOM hashes.**
- [x] **Step 4: Run `git diff --check` and scan the staged diff for secrets, source leakage, altered thresholds, or allowlist suppression.**

### Task 3: Run offline installation and launcher smoke

**Files:**

- Read: `apps/cli/scripts/smoke-packed-package.js`
- Modify: `docs/implementation-status.md` only for exact evidence

- [x] **Step 1: Run `pnpm.cmd --dir apps/cli run package:smoke` with the existing Windows ACL/keychain environment and retain the exact result.**
- [x] **Step 2: If the default npm cache is blocked, retry only with a task-scoped temporary npm cache and record the difference; do not disable package or smoke assertions.**
- [x] **Step 3: Verify the smoke covers offline installation, generated `creds` launcher execution, public catalog/completion, hidden-command refusal, no plaintext canary persistence, lazy production loading, sealed status, lease handling, and cleanup.**

### Task 4: Record and commit exact evidence

**Files:**

- Modify: `docs/implementation-status.md`
- Modify: this plan

- [x] **Step 1: Record exact audit, pack, archive, SBOM, and smoke outcomes without labeling blocked package gates as verified.**
- [x] **Step 2: Review the package scripts and diff for lifecycle, archive, SBOM, dependency, canary, or release-boundary weakening.**
- [x] **Step 3: Stage only issue #51 documentation and create one local commit named `test(package): record package security gates (#51)`.**
