# Kavrix engineering guide

## Mission

Kavrix is a production-grade, local-first secrets firewall for developers,
applications, and AI agents. Encrypted vault storage is infrastructure behind
scoped secret execution, policies, grants, and agent brokers. The product is
Kavrix and the published executable is `kavrix`. The CLI encrypts sensitive
data before it reaches any datastore adapter (local file or MongoDB). Never
weaken this boundary for convenience.

## Non-negotiable security rules

- Never persist, transmit, log, or place in process arguments any plaintext
  portable key, passphrase, recovery key, device token, root/group/item key, or
  decrypted credential data.
- Use reviewed cryptographic libraries and versioned, authenticated envelopes.
  Do not invent primitives or add placeholder/fake cryptography.
- Treat all terminal-rendered content as hostile. Sanitize ANSI/OSC/control
  sequences and mask sensitive values by default.
- Secret input is allowed only through masked prompts, dedicated protected key
  files, native keychains, or explicit stdin flows.
- MongoDB is a zero-knowledge storage layer. It must be structurally unable to
  decrypt vault records.
- Fail closed on authentication, validation, corruption, ambiguity, or unsafe
  file permissions. Do not reveal which part of an unlock credential was close.

## Architecture boundaries

The pnpm workspace contains `apps/cli` and these packages — these are the
only live boundaries:

- `packages/schemas`: canonical runtime schemas and inferred shared types.
  Define a data contract once; do not duplicate interfaces in consumers.
- `packages/core`: framework-free entities, policies, ports, and use cases.
- `packages/crypto`: small, misuse-resistant cryptographic APIs.
- `packages/storage`: adapters implementing core storage ports (local file
  and MongoDB).
- `packages/key-files`: protected portable-key file I/O, path safety, and
  ACL/mode enforcement.
- `packages/runner`: shell-free child execution with bounded, secret-redacted
  process boundaries.
- `packages/tui`: dynamic, schema-driven Ink components; no hard-coded form per
  credential type.
- `apps/cli`: command composition, interactive input, and the CLI-owned
  platform ports that ship today (session unlock, clipboard copy, backup and
  import commands). Extract these into dedicated packages only when the
  packages exist in this workspace.

Legacy directories (`packages/client`, `packages/sync`, `packages/keychain`,
`packages/clipboard`, `packages/import-export`, `packages/local-store`) are
not workspace members, are not built or shipped, and are pending removal.
Do not import from them, extend them, or document them as architecture.
There is no `apps/api`; Kavrix is local-first with no hosted service.

Dependency direction points inward. Core never imports CLI, TUI, HTTP, MongoDB,
or platform adapters. UI and commands call use cases instead of databases.

## TypeScript and implementation standards

- Use strict ESM TypeScript with `exactOptionalPropertyTypes`,
  `noUncheckedIndexedAccess`, and project references where useful.
- Prefer runtime schemas with inferred types over parallel hand-written
  interfaces. Use branded/opaque types for identifiers and secret byte values.
- Build dynamic components and operations from schemas/templates. Avoid copied
  command handlers, copied field models, and credential-type-specific forms.
- Keep modules focused, APIs explicit, and side effects behind ports. Avoid
  speculative abstractions, giant services, and barrel files that create cycles.
- Production code must not contain mocks, fake data paths, empty implementations,
  TODO security behavior, or catch-and-ignore error handling.
- Use `spawn`/`execFile` with argument arrays and `shell: false`; never interpolate
  secret-bearing commands.

## Verification and documentation

- Develop crypto and storage boundaries test-first. Include tampering, AAD swap,
  malformed input, concurrency, and plaintext-canary tests.
- Run formatting, linting, type checking, unit/integration tests, build, audit,
  and package-content checks before release claims.
- Preserve stable CLI output and exit codes. Non-interactive output is ANSI-free
  and redacts secrets unless a separately guarded unsafe flow is explicit.
- A feature is complete only when observable tests pass. Record security
  decisions and honest limitations as implementation proceeds, and never
  document planned or retired commands as available.
- Keep changes focused and preserve unrelated work. Never lower an assertion to
  hide a defect.

## Public release hygiene

- Publish only compiled artifacts, declarations, documentation, and required
  metadata. Exclude sources of secrets, fixtures with sensitive-looking values,
  local state, coverage, caches, and environment files.
- Use provenance-capable CI, least-privilege release permissions, an explicit
  `files` allowlist, `prepack` verification, and `npm pack --dry-run` inspection.
- Do not publish, tag, push, or create releases unless the user has authorized the
  external action and the exact target has been verified.

## `publish with rocket` release authorization

When the repository owner uses the exact phrase `publish with rocket`, treat it
as explicit authorization to complete the current Kavrix release end to end:

1. Confirm the intended package version and release scope.
2. Run the complete local release gates and stop on any failure.
3. Commit the reviewed release changes and push `main`.
4. Wait for required CI and CodeQL checks on the exact commit; never bypass them.
5. Create and push the matching `v<package-version>` tag only after those checks pass.
6. Monitor the trusted-publishing workflow until npm publication, registry-integrity reconciliation, and GitHub release creation succeed.
7. Verify the npm version/dist-tag and GitHub release, then report exact evidence.

The phrase does not authorize force pushes, history rewriting, secret exposure,
manual token publication, check bypasses, or publishing a different version.
