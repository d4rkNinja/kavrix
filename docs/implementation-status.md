# Implementation status

## Supported product

The supported product is the \`kavrix\` CLI in \`apps/cli\`. It connects directly
to MongoDB and persists one authenticated encrypted local-vault document per
vault. The public npm artifact contains only compiled CLI output, declarations,
the SBOM, README, and license metadata.

The active workspace packages are:

- \`@kavrix/schemas\`: canonical local-vault and encrypted-envelope schemas.
- \`@kavrix/crypto\`: reviewed key derivation, wrapping, and AEAD operations.
- \`@kavrix/key-files\`: protected portable-key and recovery-kit file handling.
- \`@kavrix/storage\`: direct MongoDB adapter with fail-closed URI policy.
- \`kavrix\`: command composition and masked interactive input.

The old HTTP API, sync/client graph, SQLite store, TUI, and self-hosting commands
are not part of the supported build or npm artifact.

Only local-vault version 2 documents with authenticated metadata binding are
accepted. Older local-vault documents are rejected rather than silently
decrypted without the binding. No automatic migration is provided; an old
release must be used offline to unlock and re-enter values into a newly
initialized v2 vault.

## Command coverage

The CLI supports vault initialization, database ping, encrypted put/get/list
operations, guarded view/search/stats output, remove/has/rename/doctor checks
(including fail-closed \`doctor health\` with bounded transient retry and
explicit revision-anchor initialization), vault selection/status, protected key
lifecycle operations, and recovery-kit create/verify/revoke/status/use flows.

Recovery-kit use unwraps the root key and rotates the vault root key before
persisting the updated document. A revoked slot is rejected by the local
decrypt path. Recovery files must remain protected and separate from the
portable key file.

## Release validation

The release gate is:

1. \`pnpm install --frozen-lockfile\`
2. \`pnpm build\`
3. \`pnpm format:check\`
4. \`pnpm lint\`
5. \`pnpm typecheck\`
6. focused Vitest suites
7. \`pnpm --filter kavrix package:smoke\`
8. \`pnpm audit --audit-level high\`

A real MongoDB replica-set integration test runs only when
\`KAVRIX_MONGODB_URI\` is provided. No local MongoDB daemon is bundled or
started by Kavrix. Windows protected-file ACL behavior depends on the host
account and filesystem policy and must be verified on a supported Windows
runner.

The latest local verification passed formatting, lint, strict typecheck, build,
24 CLI test files (264 tests), the key-files suite (2 files, 9 tests), and the npm pack allowlist. Packed-install smoke and
the npm advisory audit remain unverified here because registry access returns
EACCES; live MongoDB and supported Windows ACL evidence are also unavailable.

## Known security limits

MongoDB metadata such as vault identifiers, revisions, timestamps, and envelope
sizes remains visible. A local revision anchor now blocks lower-revision and
same-revision metadata-fork replay for the active key-file path and recovery
operations. It is local state, not tamper-proof remote storage: deleting the
anchor is fail-closed unless an operator explicitly accepts the current state
with \`doctor health --accept-current\`.

No release process, documentation, or command accepts plaintext unlock material
as a positional argument or writes it to logs.
