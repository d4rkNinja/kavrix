# Declared Node Range Cross-Platform CI Matrix

## Problem

Issue #54 requires Kavrix CI to execute the declared runtime and architecture
contracts on the supported hosted operating systems. The current workflow was
temporarily narrowed to Windows x64 while the repository's Actions spending
limit was unresolved. That narrowing is now an unguarded configuration drift:
the workflow can report a green result without exercising Linux, macOS, or the
published Node range outside Windows.

## Goals

- Make `verify` execute the full architecture matrix:
  Linux x64, Linux arm64, macOS x64, macOS arm64, and Windows x64.
- Make `runtime-range` execute the declared Node boundaries on the intended
  operating systems:
  Node 24.12.0 on Linux, Windows, and macOS; Node 25.1.0 on Linux and Windows;
  and Node 26.7.0 on Linux and Windows.
- Preserve the existing architecture assertion, runtime assertion, build,
  runtime-sensitive tests, package smoke test, pinned actions, and pinned
  MongoDB job.
- Add a focused repository test that fails if either matrix is narrowed,
  changes a runner/runtime pairing, or loses its required validation steps.
- Keep implementation-status evidence precise: local checks prove the workflow
  contract, while the exact GitHub run at the implementation SHA remains
  unverified until GitHub executes that SHA.

## Non-goals

- Do not change application code, Node engine declarations, package contents,
  native platform acceptance behavior, MongoDB integration logic, or release
  publication controls.
- Do not add a dynamic runner generator or a third-party YAML parser.
- Do not push a branch, open a pull request, or claim a remote matrix result.

## Chosen design

Use explicit GitHub Actions `strategy.matrix.include` entries. The matrix is
part of the repository's compatibility contract, so each supported pairing is
visible in the workflow and reviewable without resolving external data. The
verification matrix contains five entries with an `expected_arch` field. The
runtime matrix contains seven entries with an explicit runner and exact Node
version. The macOS runtime floor is intentional: Linux and Windows cover the
newer Node API edges, while macOS still exercises the platform-specific
launcher and path behavior at the oldest supported runtime.

The existing shell-free Node probes remain the runtime assertions. Every job
continues to use the pinned checkout, pnpm, and setup-node actions; no
`ubuntu-latest` alias is introduced. The Mongo, dependency-audit, and package
jobs remain pinned to `ubuntu-24.04` and are outside the matrix expansion.

## Regression contract

Extend the existing release-policy test, which already loads and inspects
`.github/workflows/ci.yml`, with a focused cross-platform matrix suite. It will
extract the `verify` and `runtime-range` job blocks and assert the exact
runner/architecture and runner/Node entry sets, required probes, build/test
commands, package smoke command, and absence of the old spending-limit
narrowing text. The test remains textual because the repository has no YAML
runtime dependency and the workflow shape is deliberately small and stable;
the assertions target exact job boundaries and matrix lines rather than
parsing arbitrary YAML.

## Verification and evidence

Run the focused policy test, formatting check, diff check, root build, and root
project-reference typecheck. Inspect the final diff and clean worktree. The
implementation-status row for cross-platform CI stays pending until a
successful GitHub Actions run is available for the implementation SHA; a
previous green run cannot be reused as evidence for this changed workflow.
