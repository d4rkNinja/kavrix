# Kavrix

Kavrix is an in-development, zero-knowledge credentials vault for the terminal.
`CredVault` is the default product label and `creds` is the planned executable.
Sensitive values are encrypted locally before they cross the process boundary;
the sync API and MongoDB are designed to store only ciphertext, authenticated
key envelopes, token hashes, and minimal synchronization metadata.

> **Development status:** Kavrix is not released and must not be trusted with
> real credentials yet. The implemented foundation is being security-reviewed;
> the API, CLI, TUI, native keychain integration, and release artifacts are not
> yet complete. See [Implementation Status](./docs/implementation-status.md) for
> evidence and current limitations.

## Security model

- A random Vault Root Key is created and used only on the client.
- A portable vault key derives a wrapping key with HKDF-SHA-256; the portable
  key itself is never uploaded or stored by the API.
- Optional passphrase slots use Argon2id. Recovery and device slots are
  independent rather than aliases for the portable key.
- Vault, group, item, and attachment keys are random and independently wrapped.
- Sensitive payloads use XChaCha20-Poly1305-IETF with identity-bound associated
  data. Attachments use bounded, authenticated secretstream records.
- The server authenticates devices and coordinates opaque records, but imports
  no decryption code and has no key capable of decrypting a vault.

This design cannot protect secrets from a compromised local device while the
vault is unlocked, malicious terminal software, screen capture, or values a user
explicitly copies or reveals. Read the [Threat Model](./docs/threat-model.md),
[Cryptography](./docs/cryptography.md), and [Security Policy](./SECURITY.md)
before evaluating the project.

## Installation

There is no supported installation yet. The `kavrix` npm package has not been
published, and no source checkout is approved for real vault data. A future
release will be installed with:

```sh
npm install --global kavrix
```

Do not treat that command as available until a signed release and matching npm
provenance are linked from this repository.

## Planned quick start

The stable command surface will include direct, scriptable credential access in
addition to the TUI:

```sh
creds init
creds show "Production Databases" "Main MongoDB"
creds copy "Production Databases" "Main MongoDB" password
```

Portable-key creation and second-device enrollment will use masked interactive
input or protected key files—never command arguments. Exact commands will be
documented only after the real end-to-end flows pass their acceptance tests.

## Development

Requirements:

- Node.js 24.19.x
- pnpm 11.21.0

```sh
pnpm install --frozen-lockfile
pnpm verify
pnpm test:coverage
pnpm audit --audit-level high
```

The workspace uses strict ESM TypeScript. Runtime schemas are the canonical
contracts; consumer packages infer types instead of duplicating interfaces.
Read [CONTRIBUTING.md](./CONTRIBUTING.md) and [AGENTS.md](./AGENTS.md) before
changing security-sensitive code.

## Repository map

- `packages/schemas` — canonical runtime and persistence schemas
- `packages/core` — framework-free policies, ports, and use cases
- `packages/crypto` — small, misuse-resistant cryptographic operations
- `packages/storage` — planned ciphertext-only storage adapters
- `packages/sync` — planned synchronization and conflict handling
- `apps/api` — planned zero-knowledge storage API
- `apps/cli` — planned `creds` CLI and TUI composition

Kavrix is licensed under the [MIT License](./LICENSE).
