# Task 3 CLI stabilization report

## Scope

Stabilized the pre-existing CLI patch in the four owned tracked source files and
added focused CLI regression coverage. The pre-existing untracked
`apps/cli/src/production/sensitive-display.ts` was not edited, staged, or
committed.

## RED evidence

Before the fix, `pnpm --filter kavrix test -- --reporter=dot` completed with
8 test files, 113 passing tests, and 4 failures:

- Public bash completion advertised `init`, `status`, `lock`, `show`, `copy`,
  and `device` instead of only the production-backed command families (three
  assertions).
- `init resume` called its injected coordinator with a trailing `undefined`
  server argument.

## GREEN evidence

- `pnpm --filter kavrix test -- --reporter=dot` — 8 test files passed, 119
  tests passed.
- `pnpm --filter kavrix typecheck` — passed.
- `pnpm exec prettier --check apps/cli/src/catalog.ts apps/cli/src/contracts.ts apps/cli/src/initialization.ts apps/cli/src/production/ports.ts apps/cli/test/cli.test.ts apps/cli/test/initialization.test.ts` — passed.
- `git diff --check` — passed before committing.

## Changes

- Kept `CLI_COMMAND_CATALOG` as the full dependency-injected internal catalog.
- Restored an explicit public catalog with exactly `version`, `generate`,
  `totp`, `key`, and its self-referential `completion` descriptor.
- Covered public help and bash, zsh, fish, and PowerShell completion output;
  excluded vault commands return public usage exit code 2.
- Forwarded `--server` to internal init start/resume/cancel and invite join only
  when supplied, preserving the previous injected-port arity when absent.
- Used Commander combined option state for nested init commands so their parent
  `--server` option is observed.
- Kept invite join's already-read portable key flowing into `createProductionPorts`
  without a second prompt/read.

## Files committed

- `apps/cli/src/catalog.ts`
- `apps/cli/src/contracts.ts`
- `apps/cli/src/initialization.ts`
- `apps/cli/src/production/ports.ts`
- `apps/cli/test/cli.test.ts`
- `apps/cli/test/initialization.test.ts`

## Commit

`c48ca33fe62c8b4b3b42f13865643034afe5f477` — `fix(cli): stabilize public catalog and server forwarding`

## Self-review

Verified that no secret-valued argv, option, environment lookup, output, or
completion data was introduced. The public binary no longer advertises or
accepts commands without production composition, server values are forwarded
verbatim only when explicit, and all existing terminal-sanitization and stable
exit-code tests remain green.

## Concern

Production composition for the withheld vault command families remains outside
this task, as required. The untracked sensitive-display implementation remains
for that separate task and is intentionally not part of either commit.
