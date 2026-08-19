# Architecture

## Supported path

```text
masked input / exact protected stdin frames
|
v
kavrix CLI
(profiles, unlock, AEAD, migration)
|
v
EncryptedDatabaseStore
|-- FileEncryptedDatabaseStore --> one protected database container
`-- MongoEncryptedDatabaseStore --> database + vault collections
```

The CLI is the only Kavrix process in the supported product. It composes
canonical schemas, cryptography, protected file I/O, database sessions, and
storage adapters. The datastore is a zero-knowledge storage layer: it can store
and compare opaque authenticated documents but has no database root key (DRK),
vault root key (VRK), passphrase, or decrypted payload.

## Database and vault hierarchy

A datastore profile selects one database route. A random 256-bit DRK protects
the database's private catalog, which contains the database label, encrypted
vault labels, ordering, and opaque ID mapping. Every vault receives an
independent random VRK. The DRK wraps each VRK using a database-and-vault-bound
authenticated envelope; a VRK cannot derive the DRK or another VRK.

The database owner key file contains a passphrase-protected portable key that
unwraps the DRK slot. It is bound to the database ID, key slot, versions, and
datastore type. It does not contain MongoDB credentials. Database recovery kits
wrap the same DRK under separately protected recovery material. Legacy version
2 vault key and recovery files remain separate formats and cannot be substituted
for database files.

## Boundaries

- `packages/schemas` owns canonical database, catalog, vault, local-container,
  legacy version 2, and authenticated-envelope contracts.
- `packages/crypto` owns Argon2id passphrase derivation, HKDF-SHA-256 domain
  separation, XChaCha20-Poly1305 encryption, wrapping, and secret-byte handling.
- `packages/key-files` owns protected database-owner key/recovery formats,
  revision anchors, path/link safety, POSIX modes, and Windows ACL enforcement.
- `packages/storage` owns the database-scoped compare-and-swap port, atomic local
  container, MongoDB two-collection adapter, URI/TLS policy, and transactions.
- `apps/cli` owns protected input, non-secret profile routing, database sessions,
  explicit legacy migration, flat credential projection, and sanitized output.

No API server, sync daemon, SQLite store, or TUI is required. The public package
bundles the CLI and reviewed cryptographic/schema libraries while leaving the
MongoDB driver external and pinned.

## Persistence and concurrency

The local adapter stores one bounded database document and a map of bounded
vault documents in one protected file. It uses a sibling lock, expected
revisions, restrictive temporary files, atomic replacement, directory sync,
link rejection, and owner-only permissions or Windows ACLs.

MongoDB stores database/catalog state in `kavrix_databases` and vault documents
in `kavrix_vaults` by default. Collection names are configurable profile routing
metadata. Catalog-plus-vault publication uses an exact prior revision and a
transaction, so MongoDB requires a replica set or sharded topology. A standalone
MongoDB server is not a supported write topology for this container.

## Anchors, reconciliation, and recovery

A restrictive sidecar beside each database-owner key file records a
DRK-authenticated database revision, catalog digest, and authenticated vault-head
set. Unlock reconciles the datastore with that anchor. Lower revisions,
same-revision forks, missing vault heads, unexpected reappearance, and invalid
authentication fail closed. Ordinary owner-key opens require an exact anchor
match and reject an authenticated newer datastore state. Only recovery may
forward-reconcile its authenticated companion anchor after an owner mutation;
failed or ambiguous publication is never reported as success.

Vault deletion uses authenticated catalog removal and storage deletion;
tombstone-equivalent absence checks prevent a removed vault from silently
reappearing during reconciliation. The current public CLI does not expose a
database-vault delete command.

Database recovery restores a fresh protected owner key for the same DRK after
authenticating the recovery kit, database state, and trusted anchor. It does not
recover a forgotten passphrase, erase old snapshots, or make missing ciphertext
available.

## Trust and residual risk

Kavrix uses versioned, reviewed constructions; it does not claim permanently
unbreakable encryption. MongoDB and local-file observers can see opaque IDs,
revisions, timestamps, sizes, routing relationships, and access timing. They can
delete, withhold, replay, or corrupt ciphertext, although supported rollback and
fork cases are detected while the trusted local anchor survives.

A privileged or same-user process on an unlocked host can inspect memory or
terminal output. JavaScript cannot guarantee removal of every runtime copy.
Availability, endpoint security, backup retention, and secure sharing of local
database/key files remain operator responsibilities.
