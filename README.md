# Kavrix

Kavrix is an in-development, zero-knowledge credentials vault for the terminal.
`CredVault` is the default product label and `creds` is the executable.
Sensitive values are encrypted locally before they cross the process boundary;
the sync API and MongoDB are designed to store only ciphertext, authenticated
key envelopes, token hashes, and minimal synchronization metadata.

> **Development status:** Kavrix is not released and must not be trusted with
> real credentials yet. Core, crypto, opaque storage/sync, API, CLI/TUI,
> keychain, and encrypted backup boundaries now have implementation evidence, but
> the complete supported product and public release do not. See
> [Implementation Status](./docs/implementation-status.md) for exact evidence and
> current limitations.

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

There is no supported installation yet. A self-contained public-package archive
and cross-platform packed-bin smoke gate are prepared, but the `kavrix` npm
package has not been published and npm ownership is not established. No source
checkout is approved for real vault data. A future release will be installed
with:

```sh
npm install --global kavrix
```

Do not treat that command as available until a signed release and matching npm
provenance are linked from this repository. The prepared packed executable
exposes only production-backed local behavior: help, `--version`/`creds
version`, static Bash/Zsh/Fish/PowerShell completion, password and passphrase
generation, TOTP generation, create-only portable key-file creation, crash-safe
local initialization with resume/cancel, guarded unlock/lock, a locked local
`creds status` diagnostic for one already-enrolled data home, encrypted
local group and credential CRUD, dynamic field operations, encrypted note CRUD, redacted credential inspection (`creds show`), guarded clipboard copy (`creds copy`), guarded credential reveal (`creds reveal`), scriptable field retrieval (`creds get`), stored-seed TOTP generation (`creds totp code`), vault synchronization (`creds sync`), and guarded vault-to-vault transfer under a separate confirmed passphrase (`creds transfer`).
Status reads only the canonical profile, opaque pending-mutation count, and
protected rollback timestamp. With `sealed-file`, it authenticates and unseals
only that local protected rollback metadata; it never obtains vault
root/group/item keys or decrypts credential records. It does not contact
the stored server or open clipboard/lifecycle-journal resources. Public
device workflows remain
unavailable. See the [CLI Reference](./docs/cli-reference.md) and
[Public Release Process](./docs/release.md).

The package is a deterministic ESM entry with content-hashed lazy chunks; local
cryptography is not evaluated by version or completion. Its CycloneDX SBOM
records aggregate and per-JavaScript-artifact hashes, four bundled npm libraries,
and the attributed EFF passphrase word list as a separate data component.

Prepared local commands include:

```sh
creds generate password
creds generate passphrase
creds totp
creds totp code "Engineering" "Database Admin" --stdout
creds key create --file portable-key.cvk
creds init
creds unlock --check
creds status
creds sync
creds group create "Engineering"
creds credential create "Engineering" "Database Admin"
creds credential list "Engineering"
creds show "Engineering" "Database Admin"
creds copy "Engineering" "Database Admin" "password"
creds reveal "Engineering" "Database Admin" "password" --stdout
creds get "Engineering" "Database Admin" "username"
creds set "Engineering" "Database Admin" "password" --value-stdin --if-revision 7
creds update "Engineering" "Database Admin" "password" --label "DB password"
creds note add "Engineering" "Database Admin" --title "Rotation SOP" --content-stdin
creds transfer export --file engineering.cvtx --group "Engineering"
creds transfer import --file engineering.cvtx --on-collision rename
```

A transfer is not a backup. It is protected by its own passphrase — confirmed
twice on export, never the vault's unlock material — so a transfer file that
leaks cannot be opened with vault credentials. Export applies field export
policy: a value whose field declares `exportPolicy: never` is omitted rather
than carried, and every omission is declared in a manifest holding only a stable
key, a scope, and a reason. Import authenticates the whole file and plans the
whole application before creating the first group, so a malformed, oversized,
tampered, or colliding transfer leaves the destination vault untouched.

A field value is never accepted as an argument: `set` reads it from
`--value-stdin` or a masked prompt. `set` resolves the field the same way `get`
does, so a mistyped name fails closed instead of defining a new field; pass
`--create` to define one deliberately. `--if-revision` takes the `revision`
reported by `creds get --json` and refuses the write when the record has moved
on, and a repeatable or collection field refuses a whole-value write rather than
discarding its elements.

Generated values and TOTP codes require an interactive output stream unless
`--stdout` is explicit. TOTP seeds, protected-file passphrases, and sealed
status-backend passphrases use masked input or explicit bounded stdin modes;
they are never accepted as arguments or environment settings. `creds totp code`
takes no seed input at all: it decrypts a seed already stored in the vault,
wipes the decoded bytes before returning, prints only the code, and refuses a
field whose reveal policy is `never`. `key create`
never prints the portable key and refuses to replace an existing file. Local
group/credential creation is encrypted at rest and requires an unlocked local
lifecycle (see [CLI Reference](./docs/cli-reference.md)).

## Planned vault quick start

The stable command surface will include direct, scriptable credential access in
addition to the TUI:

```sh
creds init
creds show "Production Databases" "Main MongoDB"
creds copy "Production Databases" "Main MongoDB" password
```

Portable-key import and second-device enrollment will use masked interactive
input or protected key files—never command arguments. Exact commands will be
documented only after the real end-to-end vault flows pass their acceptance tests.

## Development

Requirements:

- Node.js 24.19.x for development (the published CLI supports
  `>=24.12.0 <25 || >=25.1.0`; contributors stay on one pinned baseline so
  lockfile and gate results are comparable)
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
- `packages/storage` — ciphertext-only MongoDB storage adapter
- `packages/sync` — opaque synchronization and conflict handling
- `packages/client` — hardened HTTPS control/sync transport and local read session
- `packages/local-store` — restrictive SQLite ciphertext cache and offline queue
- `packages/keychain` — native keychain adapter with no plaintext-file fallback
- `packages/key-files` — protected portable-key file and ACL/mode enforcement
- `packages/clipboard` — guarded native clipboard copy and conditional clearing
- `packages/runner` — shell-free, bounded, secret-redacted child processes
- `packages/import-export` — authenticated encrypted backup and guarded restore
- `packages/tui` — dynamic schema-driven terminal components
- `apps/api` — zero-knowledge HTTP and MongoDB composition
- `apps/cli` — dynamic command composition and public `creds` package

The private API package now has a real `kavrix-api` process and an evaluation
runbook, but there is no supported server image or released deployment yet. See
[Self-hosting Kavrix](./docs/self-hosting.md) for the exact boundary and current
limitations.

Kavrix is licensed under the [MIT License](./LICENSE).
