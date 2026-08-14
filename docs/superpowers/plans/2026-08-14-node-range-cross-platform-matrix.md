# Declared Node Range Cross-Platform CI Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the exact Linux/macOS/Windows architecture and Node runtime matrix required by issue #54 and protect it with local regression coverage.

**Architecture:** Keep the workflow declarative with explicit `matrix.include` records. Extend the existing workflow-policy test to inspect the two job blocks and assert exact supported pairings and validation steps; update status evidence without claiming an unavailable GitHub run.

**Tech Stack:** GitHub Actions YAML, pnpm, Vitest, strict TypeScript tests, Markdown project evidence.

## Global Constraints

- `verify` must include Linux x64, Linux arm64, macOS x64, macOS arm64, and Windows x64.
- `runtime-range` must include Node 24.12.0 on Linux/Windows/macOS, Node 25.1.0 on Linux/Windows, and Node 26.7.0 on Linux/Windows.
- Keep `ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-15-intel`, `macos-15`, and `windows-2025` explicit; do not use `ubuntu-latest`.
- Keep all action references pinned to 40-character commit SHAs and preserve shell-free Node assertions.
- Do not claim a remote pass until GitHub runs the changed workflow at its exact SHA.
- Do not push, open a pull request, or alter external GitHub state.

---

### Task 1: Encode the exact CI matrices

**Files:**
- Modify: `.github/workflows/ci.yml:14-96`

**Interfaces:**
- Consumes: the existing `verify` and `runtime-range` job contracts, including `matrix.runner`, `matrix.expected_arch`, and `matrix.node`.
- Produces: five `verify` matrix records and seven `runtime-range` matrix records consumed by the existing job steps.

- [ ] **Step 1: Replace the narrowed verification matrix**

Replace the single Windows record with these exact records:

```yaml
          - label: Linux x64
            runner: ubuntu-24.04
            expected_arch: x64
          - label: Linux arm64
            runner: ubuntu-24.04-arm
            expected_arch: arm64
          - label: macOS x64
            runner: macos-15-intel
            expected_arch: x64
          - label: macOS arm64
            runner: macos-15
            expected_arch: arm64
          - label: Windows x64
            runner: windows-2025
            expected_arch: x64
```

Remove the spending-limit comments that describe the matrix as intentionally
narrowed. Keep the architecture assertion, `pnpm verify`, and packed CLI smoke
step unchanged.

- [ ] **Step 2: Replace the Windows-only runtime matrix**

Use these exact records under `runtime-range.strategy.matrix.include`:

```yaml
          - label: Linux · Node 24.12.0 · engines floor
            runner: ubuntu-24.04
            node: 24.12.0
          - label: Windows · Node 24.12.0 · engines floor
            runner: windows-2025
            node: 24.12.0
          - label: macOS · Node 24.12.0 · engines floor
            runner: macos-15
            node: 24.12.0
          - label: Linux · Node 25.1.0
            runner: ubuntu-24.04
            node: 25.1.0
          - label: Windows · Node 25.1.0
            runner: windows-2025
            node: 25.1.0
          - label: Linux · Node 26.7.0 · newest
            runner: ubuntu-24.04
            node: 26.7.0
          - label: Windows · Node 26.7.0 · newest
            runner: windows-2025
            node: 26.7.0
```

Update the nearby explanation to state that macOS runs the floor only and that
Linux/Windows cover newer-Node API drift. Preserve the exact-version runtime
probe and package smoke step.

- [ ] **Step 3: Inspect the workflow diff**

Run:

```powershell
git diff --check -- .github/workflows/ci.yml
```

Expected: no whitespace errors, no `ubuntu-latest`, and no remaining
spending-limit narrowing text.

### Task 2: Add regression coverage for matrix drift

**Files:**
- Modify: `apps/cli/test/release-policy.test.ts` near the existing CI workflow policy tests

**Interfaces:**
- Consumes: the existing `ciWorkflow` fixture and `jobBlock(source, jobName)` helper.
- Produces: a deterministic Vitest contract that fails if the required matrix set or validation commands change.

- [ ] **Step 1: Add exact matrix-set assertions**

Add a `cross-platform CI matrix policy` suite that extracts both jobs and checks
the exact records with regular expressions. The assertions must include:

```ts
expect(verify).toMatch(/runner: ubuntu-24\.04\s+expected_arch: x64/u);
expect(verify).toMatch(/runner: ubuntu-24\.04-arm\s+expected_arch: arm64/u);
expect(verify).toMatch(/runner: macos-15-intel\s+expected_arch: x64/u);
expect(verify).toMatch(/runner: macos-15\s+expected_arch: arm64/u);
expect(verify).toMatch(/runner: windows-2025\s+expected_arch: x64/u);
expect(runtime).toMatch(/runner: ubuntu-24\.04\s+node: 24\.12\.0/u);
expect(runtime).toMatch(/runner: windows-2025\s+node: 24\.12\.0/u);
expect(runtime).toMatch(/runner: macos-15\s+node: 24\.12\.0/u);
expect(runtime).toMatch(/runner: ubuntu-24\.04\s+node: 25\.1\.0/u);
expect(runtime).toMatch(/runner: windows-2025\s+node: 25\.1\.0/u);
expect(runtime).toMatch(/runner: ubuntu-24\.04\s+node: 26\.7\.0/u);
expect(runtime).toMatch(/runner: windows-2025\s+node: 26\.7\.0/u);
```

Count the `label:` records to prevent accidental duplicate or extra entries,
assert the required architecture/runtime probes and package smoke commands,
and assert that the old spending-limit narrowing phrase is absent.

- [ ] **Step 2: Run the focused regression test**

Run:

```powershell
pnpm exec vitest run apps/cli/test/release-policy.test.ts
```

Expected: all release-policy tests pass, including the new exact matrix suite.

### Task 3: Update evidence and run repository checks

**Files:**
- Modify: `docs/implementation-status.md` rows for cross-platform CI and declared Node range
- Modify: `docs/superpowers/plans/2026-08-14-node-range-cross-platform-matrix.md`

**Interfaces:**
- Consumes: the local test output and workflow diff from Tasks 1-2.
- Produces: factual status that distinguishes the restored contract from the still-missing remote run.

- [ ] **Step 1: Record local evidence without overstating completion**

Change the cross-platform CI evidence from a historical `Verified` claim to a
pending rerun for the changed workflow. State that the local policy suite
proves the five-entry architecture matrix and seven-entry runtime matrix, but
that GitHub must execute the implementation SHA before the row can be marked
verified. Keep the declared Node range values and local Windows test evidence.

- [ ] **Step 2: Run formatting, build, and type checks**

Run:

```powershell
pnpm exec prettier --check .github/workflows/ci.yml apps/cli/test/release-policy.test.ts docs/implementation-status.md docs/superpowers/specs/2026-08-14-node-range-cross-platform-matrix-design.md docs/superpowers/plans/2026-08-14-node-range-cross-platform-matrix.md
pnpm build
pnpm typecheck
git diff --check
```

Expected: formatting, build, typecheck, and diff checks pass. If the
repository-wide lint/test gates reproduce known managed-Windows failures or
pre-existing violations, record their exact scope rather than weakening them.

- [ ] **Step 3: Review the final worktree**

Run:

```powershell
git diff --stat
git status --short --branch
```

Expected: only the workflow, focused policy test, status evidence, and issue
#54 design/plan documents are changed; the branch is clean after committing.

- [ ] **Step 4: Commit the implementation**

```powershell
git add .github/workflows/ci.yml apps/cli/test/release-policy.test.ts docs/implementation-status.md docs/superpowers/specs/2026-08-14-node-range-cross-platform-matrix-design.md docs/superpowers/plans/2026-08-14-node-range-cross-platform-matrix.md
git commit -m "ci: restore cross-platform Node matrix (#54)"
```
