# Architecture

> Design status: this document defines the target architecture. It is not proof
> that a component exists or is production-ready. See
> [implementation-status.md](./implementation-status.md) for verified status.

## Goals and invariants

Kavrix is a client-encrypted credentials vault. `CredVault` is the default
product label and `creds` is the default executable name; neither name is an
architectural constant.

The central invariant is that secret material is encrypted inside the CLI/TUI
process before it crosses a local persistence, network, API, or MongoDB
boundary. The API is a zero-knowledge storage and synchronization service: it
authenticates devices and coordinates opaque records, but has no decryption
capability.

These rules are architectural, not optional configuration:

- The portable key, passphrase, recovery key, device secret, Vault Root Key
  (VRK), group keys, item keys, attachment keys, and decrypted vault records
  never reach the API or MongoDB.
- Secrets never enter process arguments, URLs, routine logs, telemetry, or
  shell history.
- Every persisted sensitive payload uses a versioned authenticated-encryption
  envelope and context-bound Additional Authenticated Data (AAD).
- The server stores bearer tokens and enrollment invites only as cryptographic
  hashes.
- The production CLI talks to the API over authenticated HTTPS. Direct MongoDB
  access is not the default architecture.
- Corruption, ambiguity, authentication failure, unsupported versions, and
  unsafe key-file permissions fail closed.

## Technology baseline

- An engine range of `>=24.12.0 <25 || >=25.1.0`. The floor is the oldest release
  carrying both runtime APIs this design requires: `DatabaseSync.enableDefensive`
  (added in v25.1.0, backported to v24.12.0 — the pair that also makes 25.0.x
  unusable and so excluded) and `crypto.argon2` (added in v24.7.0). The range is
  deliberately open above 25.1.0 so a user on a current Node can install without
  waiting on a release of this project; CI tests both edges and the newest
  release. Development and release pipelines stay on 24.x LTS, which Node.js
  recommends for production applications:
  [Node.js releases](https://nodejs.org/en/about/previous-releases). Because the
  range spans releases where these APIs are still marked release-candidate, the
  CLI probes for the primitives it needs at startup rather than trusting the
  version string; see `apps/cli/src/runtime-preflight.ts`.
- Strict ESM TypeScript with `strict`, `exactOptionalPropertyTypes`, and
  `noUncheckedIndexedAccess`.
- pnpm workspaces and project references where they make dependency boundaries
  enforceable.
- XChaCha20-Poly1305 and secretstream through the standard
  `libsodium-wrappers` 0.8.4 package (not the sumo build) for application AEAD,
  key wrapping, and attachment streams.
- HKDF-SHA-256 for high-entropy portable, recovery, and device key slots.
- Argon2id through the asynchronous built-in `node:crypto` `argon2` API for human
  passphrase slots and passphrase-protected portable-key files. Node marked the
  API stable in 24.19, while Kavrix still owns a versioned serialized parameter
  contract and compatibility tests. A native third-party Argon2 package is
  intentionally excluded to avoid another binary/install-script dependency.
- Random, independent 256-bit VRK, group, item, attachment, device, and recovery
  keys.
- Runtime schemas are the canonical wire and persistence contracts; TypeScript
  types are inferred from them.

Dependency selection remains subject to maintenance, advisory, install-script,
cross-platform, and package-content review. The baseline names primitives and
runtime constraints; it does not pre-approve a package.

## Trust boundaries and data flow

```text
User
  | masked prompt / protected key file / explicit stdin / native keychain
  v
CLI or TUI process                    trusted only while the host is trusted
  | local validation, unlock, encrypt/decrypt, sanitize output
  | ciphertext + wrapped keys + opaque metadata + device bearer token
  v
Authenticated HTTPS API              authenticates and coordinates; cannot decrypt
  | ciphertext + wrapped keys + hashes + sync metadata
  v
MongoDB                               untrusted for confidentiality
```

The local process is the only normal decryption boundary. The native OS
keychain may retain remembered-device material after explicit user consent. It
is a protection mechanism supplied by the host OS, not a defense against an
already compromised host.

The API is trusted for availability, token enforcement, sequencing, and honest
delivery only to the extent described in the threat model. It is deliberately
not trusted with confidentiality. TLS protects transport metadata and bearer
tokens in transit; client-side AEAD independently protects vault content.

## Repository boundaries

| Area                     | Responsibility                                                                    | Must not do                                                         |
| ------------------------ | --------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `packages/schemas`       | Canonical runtime schemas, envelope versions, inferred shared types               | Duplicate contracts in consumers or contain business workflows      |
| `packages/core`          | Framework-free entities, policies, ports, typed errors, use cases                 | Import CLI, TUI, HTTP, MongoDB, or platform adapters                |
| `packages/crypto`        | Random generation, KDF, AEAD, key wrapping, slot and rotation primitives          | Perform network/storage I/O or expose easy-to-misuse raw primitives |
| `packages/storage`       | Implement core storage ports for API, MongoDB where explicitly allowed, and tests | Decrypt application records or invent parallel domain types         |
| `packages/sync`          | Opaque change tracking, cursors, idempotency, conflicts, and rollback policy      | Persist plaintext or resolve conflicts with silent last-write-wins  |
| `packages/client`        | HTTPS API transport, opaque snapshot application, and unlocked read sessions      | Send unlock material to the API or bypass canonical wire schemas    |
| `packages/local-store`   | Restrictive SQLite ciphertext cache, cursors, and durable offline mutation queue  | Store plaintext or replace the native protected rollback anchor     |
| `packages/keychain`      | Native secure-storage abstraction and capability detection                        | Fall back to plaintext files                                        |
| `packages/key-files`     | Protected portable-key file I/O, path checks, ACL/mode enforcement, atomic writes | Follow links, accept broad access, or expose key content in argv    |
| `packages/clipboard`     | Fixed native clipboard backends, generation-safe copy and conditional clearing    | Put copied values in argv or erase unrelated clipboard content      |
| `packages/runner`        | Shell-free child execution with bounded, secret-redacted process boundaries       | Inherit stdin/stdio or interpolate a secret-bearing shell command   |
| `packages/import-export` | Encrypted backup/restore and guarded explicit transfer flows                      | Create plaintext temporary files by default                         |
| `packages/tui`           | Ink screens, dynamic schema-driven forms, terminal sanitization                   | Access databases or implement cryptography                          |
| `packages/test-utils`    | Clearly fake fixtures, fake keychain, encrypted test vaults, canary helpers       | Leak into production dependency graphs                              |
| `apps/cli`               | Command parsing, composition, prompts, process/clipboard adapters                 | Persist data or implement cryptographic details directly            |
| `apps/api`               | Authenticated opaque storage/sync HTTP service                                    | Import decryption APIs or accept plaintext unlock material          |

Dependency direction points inward. Applications and adapters depend on use
cases and ports; `core` depends only on framework-free contracts. Avoid broad
barrel files where they hide cycles.

## Primary runtime flows

### Vault initialization

1. The CLI generates or imports a portable key locally.
2. A generated key is shown only in the explicit creation flow, then the user
   must re-enter it or re-import the saved file before initialization continues.
3. The client generates the VRK, recovery key, and initial device token using a
   cryptographically secure random source.
4. Local code derives independent slot Key Encryption Keys (KEKs), wraps the
   same VRK into portable and recovery slots, and discards transient KEKs.
5. The API receives wrapped VRK envelopes, public KDF metadata, the device-token
   hash or an enrollment exchange that results in one, and opaque identifiers.
6. Preferences and any initial domain payloads are encrypted before upload.

No reversible key verifier is stored. Possession of an unlock key is validated
by authenticated VRK unwrapping.

### Unlock and ordinary item access

1. The client obtains a candidate unlock secret through an allowed local input
   channel.
2. It derives the relevant KEK from serialized slot parameters and attempts to
   authenticate and unwrap the VRK.
3. The VRK unwraps only the selected group key; the group key unwraps only the
   selected item key; the item key decrypts that item's payload.
4. Plaintext remains local and short-lived. Terminal values are sanitized;
   sensitive fields are masked unless a guarded copy/reveal action is used.
5. Modified ciphertext, nonce, tag, AAD, identity, or key version produces a
   generic closed failure and no partial plaintext.

This hierarchy limits rotation scope and avoids decrypting the full vault for a
single `creds show <group> <credential>` request.

### Synchronization

The client pulls an ordered change feed by opaque cursor, downloads the affected
encrypted records, verifies their envelopes locally, and advances its protected
highest-seen vault revision. Pushes carry idempotency keys and expected record
versions. Version conflicts are explicit; independently edited secret payloads
must be resolved locally by the user or a safe use case.

Rollback detection is best effort. A protected local highest-seen revision can
detect a server presenting an older state to the same retained device, but it
cannot prove freshness to a new device or survive deletion of all local state.

### Second-device enrollment

An already authorized device creates a random, short-lived, single-use invite.
The API stores only its hash. The joining device exchanges the invite for its
own independent device token, downloads public slot metadata and the portable
slot envelope, and uses the shared portable key locally to unwrap the VRK. The
portable key is never an invite, bearer token, or API payload. See
[portable-key-and-device-enrollment.md](./portable-key-and-device-enrollment.md).

### Backup and restore

Backups contain a versioned manifest, opaque records, wrapped keys, and encrypted
payloads. Verification authenticates every manifest entry and attachment chunk
before final output. A restore never creates plaintext database records and is
not considered successful until a clean target can unlock and decrypt expected
records with an independent valid slot.

## Storage and API design

MongoDB collections hold only the public/opaque columns described in
[data-model.md](./data-model.md). MongoDB schema validation rejects unknown or
malformed wire records, and indexes enforce entity identity, device-token hash
uniqueness, sync sequencing, and optimistic concurrency where applicable.

The API must additionally:

- reject request fields shaped like portable keys, passphrases, recovery keys,
  device tokens outside authorization, or unwrapped keys;
- enforce HTTPS in production, request-size limits, runtime schemas, rate
  limits, pagination, and least-privilege MongoDB access;
- redact authorization headers and avoid request/response body logging;
- use `spawn`/`execFile` with argument arrays and `shell: false` for any
  authorized child process;
- make push operations idempotent and return explicit conflicts;
- keep encrypted audit details opaque.

"Zero knowledge" here has a narrow meaning: the service cannot decrypt vault
content. It still observes operational metadata such as vault/device opaque IDs,
record counts and sizes, timestamps, request timing, revisions, IP addresses,
and traffic volume. It can also delete, withhold, replay within undetected
limits, or deny access to data.

## Local state and platform services

Local persistence may contain ciphertext, opaque identifiers, cursors, and
encrypted pending changes. Decrypted search indexes and normal drafts stay in
memory; a crash-recovery draft is allowed only when encrypted before writing.
Files use OS application-data directories and restrictive permissions.

### Backup/restore trust boundary

Archive HMAC and graph verification proves only that the opaque archive is
complete and authenticated by its VRK. It does not prove that inner payloads can
be decrypted or interpreted. Known-v1 semantic restore therefore freshly
unwraps one explicit current portable-key, passphrase, or recovery-key slot from
the archived vault, seals hidden storage staging, and has the client verify the
exact `readSealed` stream through true EOF before storage may publish. The
strict receipt binds the selected slot, vault revision, session, transcript,
canonical entry commitment, record count, and supported-family algebra;
finalization alone yields committed success.

The supported semantic subset is canonical preferences, groups, items,
attachments, deleted/restored tombstones, v1 item-history snapshots, and v1
key-slot audit payloads. History opens under the referenced item key and audit
opens under the vault root key; each validator checks the decrypted identity,
revision, slot/action relationship, and canonical representation without
retaining plaintext in the receipt. Authentication-only parsing still accepts
outer-valid records, while malformed/tampered semantic payloads fail closed and
future semantic versions remain explicitly unsupported. MongoDB remains unable
to decrypt any record and never receives the credential or VRK.

This boundary does not automatically fence concurrent normal writers. Until
Task 5B's shared writer epoch is implemented and proven, restore requires a new
isolated database with the API and every other writer stopped. The Commit 6
acceptance source exists, but its final real-Mongo exact-discovery/zero-skip run
is pending because `KAVRIX_MONGODB_URI` is not configured in this workspace.

Remembered unlock material is optional and uses only macOS Keychain, Windows
Credential Manager/DPAPI-backed storage, or Linux Secret Service/libsecret. A
missing or broken keychain causes a prompt on every unlock; it never causes a
plaintext-file fallback. Removing local remembered material is distinct from
revoking the device's API token.

## Failure and lifecycle rules

- Writes are atomic at the use-case boundary and retryable where remote I/O can
  be interrupted.
- Attachment uploads use bounded hidden staging. Individual headers and chunks
  are never visible mutations or change-feed entries; one finalize operation
  atomically publishes the attachment record and its verified contiguous stream.
  Interrupted sessions resume by idempotency key or abort without partial
  visibility.
- Rotations use explicit states/checkpoints. Old keys remain only until all
  affected envelopes are verifiably migrated, then are removed deliberately.
- The last verified unlock slot cannot be deleted.
- Deletion first creates a tombstone/trash state. Permanent purge is a separate,
  explicit operation.
- Removed template fields move to encrypted archived/orphaned storage before any
  later purge.
- Lock, normal exit, cancellation, and fatal signals clear decrypted UI state and
  overwrite mutable key buffers on a best-effort basis.
- JavaScript cannot guarantee that all copies are erased from managed runtime
  memory. This limitation is not represented as a solved problem.

## Planned extensibility

Team sharing may later use public-key cryptography and per-recipient wrapped
group keys behind new slot/envelope versions. Version 1 must not ship common-
passphrase sharing, fake permissions, or an API-side decryption escape hatch.
Alternative hardware-backed or agent-based unlock providers may add independent
VRK slots without replacing the portable-key workflow.

## Architecture verification gates

Architecture conformance requires more than compiling. Before any production or
release claim, tests must demonstrate dependency direction, same-key
cross-device unlock, API inability to decrypt, authenticated context binding,
tamper failure, token/invite hashing, ciphertext-only persistence, plaintext-
canary absence, safe interruption of rotation/sync, and real-platform keychain,
key-file, clipboard, and terminal behavior. The authoritative matrix is
[security-testing.md](./security-testing.md).
