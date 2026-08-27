# Security Policy

Kavrix is an experimental `0.2.x` Node.js CLI for zero-knowledge credential
storage and scoped credential execution. It encrypts credential labels and
values in the local CLI process before writing authenticated ciphertext to a
protected local database file or directly to the operator's MongoDB. Security
claims here are limited to the implementation and evidence recorded in
[docs/implementation-status.md](./docs/implementation-status.md).

The supported product does not run a Kavrix API server, sync service, account
system, or device-enrollment flow. MongoDB is a direct storage adapter, not a
Kavrix-hosted service.

## Supported versions

The published `0.2.x` release line is supported on a best-effort basis while it
is experimental. Upgrade to the latest published `0.2.x` release for fixes.

| Version                                    | Security support                               |
| ------------------------------------------ | ---------------------------------------------- |
| Published `0.2.x` releases                 | Supported; upgrade to the latest patch release |
| `0.1.x` and earlier                        | Not supported                                  |
| `main`, previews, copied, or ad-hoc builds | Not supported for sensitive data               |

The package requires Node.js `>=24.12.0 <25` or `>=25.1.0`. Experimental status
means that the product has not had an independent security audit; do not treat
the support table as a guarantee of fitness for a particular risk profile.

## Reporting a vulnerability

Do not open a public issue, discussion, pull request, or chat containing an
unfixed vulnerability, exploit, key, credential, token, private vault record,
or database dump.

Use the repository host's private vulnerability-reporting feature (on GitHub,
**Security → Report a vulnerability**) when it is available. If it is not
available, ask the repository owner for a private reporting route through the
hosting platform without disclosing technical details publicly. No response
time or safe-harbor promise is implied.

Include, through the private route:

- affected version or commit, package, platform, and installation method;
- the impact and trust boundary crossed;
- minimal reproduction steps or a clearly fake proof of concept;
- whether protected key files, recovery kits, plaintext, backups, or release
  artifacts may be exposed;
- any known exploitation or disclosure deadline; and
- a safe way to contact you.

Never send real secrets as evidence. Use a unique fake canary and redact
passphrases, MongoDB credentials, key-file contents, decrypted records,
authorization headers, and memory dumps. Coordinate any necessary protected
transfer and retention plan before sending a dump.

## Response and disclosure process

Maintainers should:

1. acknowledge the report privately and assign a tracking identifier;
2. reproduce without requesting production secrets;
3. assess affected versions, data exposure, exploitability, and required key or
   recovery-material rotation;
4. add regression tests covering the reported and adjacent trust boundaries;
5. obtain review proportional to the impact;
6. release a minimal fix with upgrade and recovery guidance; and
7. coordinate public disclosure after users have a practical mitigation.

These are process targets, not guaranteed service levels.

## Security model summary

- Key derivation and encryption occur in the local `kavrix` process. The CLI
  stores encrypted database/catalog/vault envelopes in a local file or in the
  operator's MongoDB; it does not send unlock material to a server.
- Vault payloads and wrapped key material use versioned
  XChaCha20-Poly1305-IETF authenticated encryption. Argon2id protects
  passphrase-based files, HKDF-SHA-256 separates key purposes, and revision
  anchors detect rollback, forks, and inconsistent authenticated state.
- Profiles contain active routing and other non-secret configuration.
  `~/.kavrix/config.toml` is a protected onboarding reference that current
  commands do not load automatically. Passphrases and MongoDB URLs are read
  through masked prompts or explicit protected stdin flows.
- MongoDB receives opaque IDs, revisions, timestamps, sizes, wrapped-key
  metadata, encrypted envelopes, and the database/collection namespaces used
  for routing. Human-readable Kavrix labels remain encrypted. Remote MongoDB
  connections require explicit validated TLS; database-container writes
  require a transaction-capable replica set or sharded topology.
- `kavrix run`, stored policies, grants, and the per-session agent broker add
  authorization and process-hygiene controls. They do not turn an authorized
  child process into a sandbox.

See [docs/cryptography.md](./docs/cryptography.md),
[docs/threat-model.md](./docs/threat-model.md),
[docs/data-model.md](./docs/data-model.md), and
[docs/local-database.md](./docs/local-database.md) for the detailed model.

## What must never be submitted or stored

Plaintext portable or owner keys, passphrases, recovery keys, decrypted
credential data, MongoDB credentials, or production dumps must not be placed
in:

- issues, pull requests, patches, commit messages, or test fixtures;
- command-line arguments, URLs, shell history, screenshots, or recordings;
- logs, telemetry, crash reports, snapshots, or CI artifacts; or
- unprotected reports, backups, local settings, or datastore documents.

If real material was exposed, treat it as compromised. Revoke or replace the
affected protected key or recovery material as appropriate, preserve only
sanitized evidence, and follow the relevant provider's credential-rotation
process.

## Dependency and cryptography policy

- Do not invent cryptographic primitives or add placeholder cryptography.
- Security-sensitive dependencies require a documented purpose, pinned lockfile
  entry, license and advisory review, dependency-tree review, and package
  inspection. The exact automated checks are documented in
  [docs/dependency-policy.md](./docs/dependency-policy.md).
- Argon2id parameters, HKDF domains, AAD, envelope formats, key-file formats,
  and key-lifecycle changes require compatibility tests, a threat-model review,
  and a release that records the interpretation change.
- A clean dependency audit is not proof of secure design. Release evidence must
  also cover tampering, AAD swaps, malformed input, concurrency, plaintext
  canaries, restore behavior, and relevant platform boundaries as described in
  [docs/security-testing.md](./docs/security-testing.md).

## Safe research guidelines

Test only local files, MongoDB deployments, accounts, and data that you own or
are explicitly authorized to test. Do not:

- access, modify, retain, or disclose another person's vault or metadata;
- run destructive or denial tests against shared infrastructure;
- use credential stuffing, malware, persistence, or physical attacks; or
- publish an unpatched exploit or any retrieved secret.

Stop if a test exposes data outside its authorized scope. Preserve minimal
sanitized evidence and report privately. These guidelines do not grant access
to any system or create a safe-harbor promise.

## Security update and release policy

Security fixes must include a regression test and must not weaken an assertion,
silently change a wire or cryptographic format, or add a server-side decryption
path. Maintainers must determine whether users need to upgrade, rotate owner
keys or recovery kits, recreate backups, or restore from a known-good revision.

Public release claims require the relevant formatting, lint, typecheck, test,
build, package, audit, and platform evidence. Follow the canonical
[release procedure](./docs/release.md); a local package build alone is not
release evidence.

## Important limitations

- MongoDB and local-file observers can see opaque IDs, revisions, timestamps,
  ciphertext sizes, routing relationships, and access timing. A datastore
  operator can delete or withhold ciphertext, and authenticated local anchors
  do not make that storage remotely tamper-proof.
- Kavrix cannot protect an unlocked host from administrators, same-user malware,
  keyloggers, screen or terminal capture, clipboard capture, process-memory
  inspection, swap, or crash dumps. JavaScript secret wiping is best effort and
  cannot guarantee complete erasure.
- An authorized child can read its own environment and disclose values it was
  given. Execution policy and the agent broker are authorization and process
  hygiene controls, not a sandbox.
- Local-file sharing is whole-database access: the exact encrypted snapshot and
  its matching share key can open every vault in that snapshot. There is no
  vault-scoped local sharing or copied-key revocation.
- User identities, public enrollment, recipient discovery, per-vault roles,
  VRK rotation, and ownership transfer are not implemented. Database-vault
  deletion is not exposed by the current public CLI.
- Losing every valid owner key file and recovery kit is permanently
  unrecoverable by design. There is no vendor reset or escrow.
