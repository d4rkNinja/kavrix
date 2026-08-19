# Threat model

## Assets

- database/vault labels and credential names, values, and encrypted payloads;
- database-owner key files, database recovery kits, and legacy protected files;
- database root keys, independent vault root keys, slot metadata, and recovery state;
- MongoDB connection credentials supplied at runtime.

## Intended protections

Kavrix derives and unwraps keys locally, authenticates every persisted envelope,
and sends MongoDB only an opaque database document and opaque vault documents.
Private database/vault labels and credential data remain encrypted. A DRK wraps
independent VRKs; database, vault, entity, purpose, version, revision, and digest
bindings prevent authenticated envelopes from being transplanted.

The MongoDB adapter requires transactions for database/catalog-plus-vault
publication and rejects remote connections without explicit validated TLS. It
rejects invalid-certificate, invalid-hostname, and explicit TLS-disablement options.

Protected files are passphrase-bound and permission checked. Secret input is
masked or framed through stdin; secrets are not accepted as positional command
arguments, logged, or written to settings files.

## Out of scope

A fully privileged or same-user process running after unlock can inspect process
memory, keylog input, capture screen/terminal/clipboard output, or copy plaintext.
JavaScript cannot guarantee erasure of every secret copy. MongoDB and local-file
observers can see opaque IDs, revisions, timestamps, sizes, routing relationships,
and access timing. A datastore operator can deny service, delete data, or retain
historical snapshots. Losing every authorized owner key and database recovery kit
is intentionally unrecoverable.

The design uses versioned XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, and SHA-256
through reviewed libraries. It does not claim encryption is permanently
unbreakable or protect against future cryptanalytic advances without migration.

## Rollback protection

Database and vault envelopes authenticate their metadata and exact revision.
After unlock, Kavrix maintains a restrictive DRK-authenticated local anchor with
the database/catalog head and authenticated vault-head set. A datastore-only
administrator who presents a lower revision, same-revision fork, missing expected
vault, or invalid reappearance is rejected before credentials are exposed.
Valid newer state advances the anchor; stale writers fail their expected-revision
publication rather than overwrite another writer.

Database recovery requires the matching recovery kit, database snapshot, and
trusted anchor. Deleting or corrupting the anchor fails closed and is a manual
recovery condition. Recovery does not erase old ciphertext snapshots.

## Sharing boundary

Local-file sharing means sharing the encrypted database file and matching owner
key file; once unlocked, this grants access to all vaults. Kavrix cannot revoke a
copied local key or snapshot. Fine-grained identities, recipient discovery,
signed grants, reader/editor/owner roles, revocation through VRK rotation, and
ownership transfer are future work and provide no current protection.

## Release evidence

The release gate includes schema/crypto tamper tests, protected-file tests,
Mongo URI policy tests, native Windows ACL/masked-terminal tests, packed-package
database-container acceptance on Windows/macOS/Linux, and a live MongoDB
integration test only when `KAVRIX_MONGODB_URI` names a disposable transaction-
capable topology. The repository does not claim live MongoDB proof when that URI
is absent.
