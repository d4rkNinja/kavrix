# Glossary

Plain-language definitions for the terms used across the Kavrix docs. Links
point to the deeper reference for each topic.

## Storage model

- **Database (database container)** — the encrypted storage unit Kavrix
  creates. One database holds many vaults and lives either in a local file or
  in your MongoDB. [Data model](data-model.md)
- **Vault** — one independently encrypted group of credentials inside a
  database. Unlocking one vault never decrypts another.
- **Datastore profile** — a named, non-secret route to a database: which
  datastore (file or MongoDB), where the data file and key file live, and
  which vault is the default. Profiles never contain passphrases or
  connection credentials.
- **Structured payload** — the versioned format inside database vaults that
  stores project contexts, groups/services, typed fields, notes, and expiry
  metadata. Older flat records (one name → one value) remain supported.
- **Legacy version 2 (v2)** — the older single-vault format. Still readable
  through compatibility commands; `kavrix migrate database` copies a v2
  vault into a modern database.
- **Stdin frames** — when scripting, Kavrix reads secrets from stdin in a
  strict per-command order (for `put`: passphrase, then value).
  `kavrix frames "<command>"` prints the exact order.

## Keys and files

- **DRK (database root key)** — the random 256-bit master key of a database.
  It exists only inside your local process and is stored wrapped inside the
  owner key file. [Cryptography](cryptography.md)
- **VRK (vault root key)** — the random key that encrypts one vault's
  payload. Every vault has its own; compromising one exposes no others.
- **Owner key file (portable key)** — the passphrase-protected file that
  unwraps the DRK. This is your main key to the database.
- **Recovery kit** — an independently protected file that also unwraps the
  DRK, made for the "I lost my owner key" case.
  [Recovery](backup-and-recovery.md)
- **Share key** — a portable key that, together with the exact matching
  database file, grants full access to a complete local database. There is no
  vault-scoped local sharing.
- **Wrapped key slot** — an encrypted copy of a key stored inside a document,
  for example the DRK wrapped for the owner key and once per recovery kit.

## Tamper protection

- **AAD (associated data)** — identity information cryptographically bound to
  a ciphertext: which database, which vault, which purpose, which revision.
  Ciphertext moved somewhere else fails to decrypt instead of silently
  succeeding.
- **AEAD** — authenticated encryption (here XChaCha20-Poly1305): decryption
  fails unless both ciphertext and AAD are intact.
- **Revision anchor** — a small, key-authenticated marker beside the owner
  key recording the latest known database state. It lets Kavrix reject
  rollback attacks — someone restoring older data — before any plaintext is
  shown.
- **Sealed authorization sidecar** — the encrypted file beside the owner key
  that stores policies, grants, and the audit trail, authenticated with a key
  derived from the DRK. Tampering or reformatting fails closed.

## Crypto primitives (background)

- **XChaCha20-Poly1305** — the authenticated-encryption cipher used for vault
  payloads and wrapped keys.
- **Argon2id** — the password-to-key function used for passphrase-protected
  key files.
- **HKDF-SHA-256** — derives separate keys for separate purposes from the
  DRK, so no two uses share a key.

## Firewall concepts

- **Scoped secret execution** — giving exactly one process exactly the
  credentials it needs, as environment variables, for that process only
  (`kavrix run`).
- **Policy** — a stored, fail-closed rule set for a credential: allowed
  commands, executable hashes, execution time window, working directory,
  reveal gating, confirmation requirements.
- **Grant** — a temporary, consumable authorization to use a credential:
  bounded by TTL and maximum uses, and revocable at any time.
- **Agent broker** — the local service behind `kavrix agent run`. Agents hold
  no secrets; they request each operation, and the broker injects the secret
  directly into the one authorized child.
- **Audit ring** — the bounded, append-only event history inside the sealed
  sidecar; `kavrix audit` reads it.
- **Fail closed** — when validation, authentication, or integrity is
  uncertain, Kavrix refuses the operation instead of continuing.

## Input and output rules

- **Masked output** — terminal output is sanitized (control sequences
  stripped) and secret values are hidden unless you pass an explicit reveal
  option such as `get --reveal`.
- **Session unlock** — optional convenience: the unlock material is sealed in
  a file and its wrapping key lives in the OS credential store (Windows
  PasswordVault, macOS Keychain, Linux Secret Service). Either half alone is
  useless; the passphrase remains the root and always still works.
