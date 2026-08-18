# npm release

## Artifact contract

The public package is \`kavrix\`. Its npm artifact contains:

- \`dist/**/*.js\`
- \`dist/**/*.d.ts\`
- \`dist/*.cdx.json\`
- \`README.md\`
- \`LICENSE\`

The compiled bundle is an ESM Node.js CLI with a \`kavrix\` bin entry. MongoDB
\`7.5.0\` is the only runtime dependency. Workspace packages, TypeScript source,
tests, local state, coverage, and build metadata are not publishable artifacts.

\`apps/cli/scripts/build-package.js\` emits the bundle, a CycloneDX 1.6 SBOM, and
artifact hashes. The SBOM records Commander, Zod, MongoDB, its resolved runtime
dependency graph (including \`@mongodb-js/saslprep\`, \`@types/webidl-conversions\`,
\`@types/whatwg-url\`, \`bson\`, \`memory-pager\`,
\`mongodb-connection-string-url\`, \`punycode\`, \`sparse-bitfield\`, \`tr46\`,
\`webidl-conversions\`, and \`whatwg-url\`), libsodium-wrappers, libsodium, and
the EFF word-list attribution.

## Local preflight

Run from the repository root:

\`\`\`sh
pnpm install --frozen-lockfile
pnpm verify
pnpm --filter kavrix package:smoke
pnpm --filter kavrix pack:check
pnpm audit --audit-level high
\`\`\`

\`package:smoke\` installs the exact archive into a temporary directory and
executes the installed bundle's version and help commands. It rejects workspace
references, plaintext canaries, undeclared files, missing attribution, and
unreviewed SBOM dependencies.

## CI and publication policy

CI verifies the build on the supported Node and operating-system matrix, runs
focused tests, checks the packed artifact, and runs the dependency audit. A
MongoDB replica-set job exercises the direct storage adapter when the runner
provides the configured integration URI.

Publication is intentionally separate from local verification. The reviewed
workflow requires:

- a public repository and a release tag exactly matching \`v<package-version>\`;
- successful exact-SHA CI and CodeQL runs;
- no long-lived npm token;
- npm trusted publishing/OIDC with the \`npm\` environment and public registry;
- one inspected archive whose SHA-256 is checked again before \`npm publish\`.

Do not publish, tag, or configure external npm credentials from a local
development session without explicit authorization.

## Release blockers

The package is not a release claim until npm ownership, OIDC trusted-publishing
configuration, and signed release policy are reviewed by the project owner. A
live MongoDB integration run and supported Windows ACL run are also required
before claiming cross-platform production readiness.
