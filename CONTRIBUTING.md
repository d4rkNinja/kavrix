# Contributing to Kavrix

Thank you for helping improve Kavrix. Credential-vault changes have an unusually
high cost when they are wrong, so small, reviewable patches and explicit evidence
are preferred over broad rewrites.

Read [AGENTS.md](./AGENTS.md) before changing code. Security-sensitive behavior
must also be consistent with `docs/threat-model.md` and `docs/cryptography.md`.

## Development setup

Requirements:

- Node.js 24.19.x, matching `.nvmrc` (the oldest LTS marking built-in Argon2
  stable). The published CLI supports the wider `>=24.12.0 <25 || >=25.1.0`;
  contributors stay on one baseline so gate results are comparable, and CI
  covers the rest of the range.
- pnpm 11 through Corepack

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm verify:all
pnpm test:coverage
```

## Pre-push checklist

Run all of this before every push. It mirrors CI; if it is green locally, CI
has no reason to fail on your platform:

```sh
pnpm install --frozen-lockfile
pnpm verify:all        # format, lint, typecheck, build, full tests,
                       # packed-CLI acceptance, package smoke
pnpm test:coverage     # coverage thresholds (release gate)
pnpm audit --audit-level high
```

- `pnpm verify:all --quick` skips the Docker-dependent database acceptance and
  packed-CLI acceptance when the change cannot affect them (docs, comments).
- Changed any `package.json`? Run `pnpm install` and commit the updated
  `pnpm-lock.yaml` in the same commit.

### Rules that prevent the failures CI actually catches

- Package scripts must be self-sufficient: CI typechecks a fresh checkout with
  no `dist/`. Use `tsc -b tsconfig.build.json && tsc -p tsconfig.json`; never
  assume another package built first.
- Canonicalize paths in tests with `realpath`. Raw `tmpdir()` comparisons fail
  on macOS (`/private/var` prefix) and Windows (`RUNNER~1` short names).
- Never call `process.exit()` right after writing large stdout; set
  `process.exitCode` instead so pipes flush before the process dies.
- Keep the packed manifest minimal: no devDependencies, no `workspace:` or
  `@kavrix/` references. The smoke gate enforces the exact file allowlist,
  canary-free artifacts, and SBOM accuracy.
- Test platform-specific code on that platform. One local OS does not cover
  the matrix: Linux x64/arm64, macOS x64/arm64, Windows x64.

### When CI fails, and when it passes

| Job                                     | Fails when                                                                                                     |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Static checks                           | lockfile drift, formatting, lint (zero warnings), type errors, or a script that cannot run on a fresh checkout |
| Verify (5 runners, Windows in 3 shards) | any test fails on any OS/arch; database acceptance or packed-CLI smoke fails (Windows shard 1)                 |
| Published CLI (runtime range)           | the packed CLI breaks on Node 24.12 / 25.1 / 26.7 — engines-range API drift or packaging regressions           |
| Dependency audit                        | any high or critical npm advisory                                                                              |
| Package contents                        | `pnpm pack` output violates manifest policy                                                                    |
| Active release hygiene                  | coverage drops below the configured thresholds                                                                 |
| CodeQL                                  | a security query flags a flow                                                                                  |

CI passes only when every gate is green on the exact pushed commit; gates
cannot be skipped or retried. Green CI still does not prove real-keychain
behavior, non-containerized MongoDB topologies, or OS behavior outside the
five runner images — those need the explicit integration gates in
`docs/security-testing.md`.

## Pull requests

- Explain the observable behavior and security impact.
- Add tests that fail without the change, including negative/tampering cases when
  a trust boundary is involved.
- Do not place real credentials, realistic private keys, tokens, vault files, or
  secret-bearing logs in issues, fixtures, snapshots, or commits.
- Do not weaken assertions, redaction, validation, permissions, or cryptographic
  parameters to make a test pass.
- Update the architecture/security documentation and implementation status when
  behavior changes.

Use clearly fake values such as `example.invalid` and generated test-only byte
sequences. Report vulnerabilities privately using the process in `SECURITY.md`.
