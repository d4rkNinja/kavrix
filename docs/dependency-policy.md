# Dependency policy

## Active workspace

The supported build contains these seven workspaces:

- `apps/cli` (`kavrix`)
- `packages/schemas` (`@kavrix/schemas`)
- `packages/crypto` (`@kavrix/crypto`)
- `packages/key-files` (`@kavrix/key-files`)
- `packages/storage` (`@kavrix/storage`)
- `packages/runner` (`@kavrix/runner`)
- `packages/tui` (`@kavrix/tui`)

The CLI composes those packages; schemas remain the canonical contract and do
not depend on consumers. The source directories for `client`, `clipboard`,
`import-export`, `keychain`, `local-store`, and `sync` are parked/incubating.
They are not workspace members, release artifacts, or evidence for the shipped
CLI.

## Public npm artifact

The public artifact is the `kavrix` CLI. Its build bundles the reviewed CLI,
schema, cryptography, runner, and presentation code required by the executable;
the lazily loaded Ink/React showcase is part of that reviewed closure. MongoDB
`7.5.0` remains the explicit runtime dependency for direct database connections.
No workspace protocol, local path, optional package, or unreviewed runtime
import may reach the published `dist` output.

The build validates external imports, emits a CycloneDX 1.6 SBOM, records
artifact hashes, and includes required license attribution. The package smoke
test installs the archive and checks the same contract from the consumer side.

## Review requirements

Dependency additions require a pinned version, license evidence, SBOM coverage,
and a focused test or runtime justification. Keep the lockfile updated by the
same reviewed change; do not bypass the frozen-lockfile checks.

The repository's automated dependency checks are deliberately narrower than the
full release gate:

- `.github/workflows/dependency-review.yml` runs on pull requests for a public
  repository and uses `actions/dependency-review-action` with
  `fail-on-severity: high` plus these allowed licenses: MIT, Apache-2.0,
  Python-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, BlueOak-1.0.0, and
  0BSD.
- `.github/workflows/ci.yml` has a `dependency-audit` job on the workflow's push,
  pull-request, and manual triggers. It installs with
  `pnpm install --frozen-lockfile --ignore-scripts` and runs
  `pnpm audit --audit-level high`.

Run the same audit locally before release. A clean dependency review or audit
does not replace package inspection, SBOM verification, cryptographic review,
or the tampering, malformed-input, concurrency, canary, restore, and
platform tests in [security-testing.md](security-testing.md).
