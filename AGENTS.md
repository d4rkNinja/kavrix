# Kavrix engineering guide

## Mission

Kavrix is a production-grade, zero-knowledge credentials vault. `CredVault` is the
default product label and `creds` is the default executable; both must remain
configurable. The CLI encrypts sensitive data before it reaches the API or
MongoDB. Never weaken this boundary for convenience.

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
- The API and MongoDB are zero-knowledge storage and sync layers. They must be
  structurally unable to decrypt vault records.
- Fail closed on authentication, validation, corruption, ambiguity, or unsafe
  file permissions. Do not reveal which part of an unlock credential was close.

## Architecture boundaries

- `packages/schemas`: canonical runtime schemas and inferred shared types.
  Define a data contract once; do not duplicate interfaces in consumers.
- `packages/core`: framework-free entities, policies, ports, and use cases.
- `packages/crypto`: small, misuse-resistant cryptographic APIs.
- `packages/storage`: adapters implementing core storage ports.
- `packages/sync`: opaque change tracking and conflict handling.
- `packages/client`: hardened HTTPS control/sync transport and unlocked-vault
  orchestration; it never sends local unlock material.
- `packages/keychain`: native secure-storage abstraction with no plaintext-file
  fallback.
- `packages/key-files`: protected portable-key file I/O, path safety, and
  ACL/mode enforcement.
- `packages/clipboard`: guarded native clipboard copy and conditional clearing.
- `packages/runner`: shell-free child execution with bounded, secret-redacted
  process boundaries.
- `packages/import-export`: encrypted backup and guarded transfer flows.
- `packages/tui`: dynamic, schema-driven Ink components; no hard-coded form per
  credential type.
- `apps/cli`: command composition and interactive input only; no persistence or
  crypto implementation details.
- `apps/api`: authenticated opaque storage only; never import decryption APIs.

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
- Keep `docs/implementation-status.md` factual: a feature is complete only when
  observable tests pass. Record security decisions and honest limitations as
  implementation proceeds.
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
