# Dependency policy

## Workspace

The supported build includes only \`@kavrix/schemas\`, \`@kavrix/crypto\`,
\`@kavrix/key-files\`, \`@kavrix/storage\`, and the \`kavrix\` CLI. Dependency
direction points from the CLI into those packages; schemas remain the canonical
contract and never depend on consumers.

The historical API, client, sync, SQLite, keychain, runner, import/export, TUI,
and clipboard packages are outside the active workspace and public artifact.

## Public npm artifact

The CLI bundles Commander, Zod, libsodium-wrappers, and libsodium. MongoDB
\`7.5.0\` remains an explicit runtime dependency because the CLI connects to the
database directly. No workspace protocol, local path, optional package, or
unreviewed runtime import may reach \`dist\`.

The build validates external imports, emits a CycloneDX 1.6 SBOM, records
artifact hashes, and includes the EFF word-list attribution. The package smoke
test installs the archive and checks the same contract from the consumer side.

## Review requirements

Dependency additions require a pinned version, license evidence, SBOM coverage,
and a focused test or runtime justification. Run \`pnpm audit --audit-level high\`
before release; an unavailable registry is a validation blocker, not a reason
to suppress the audit.
