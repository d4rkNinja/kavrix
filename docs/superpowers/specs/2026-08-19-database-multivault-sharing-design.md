# Database-scoped multi-vault and sharing design

**Status:** Proposed for implementation after user review
**Date:** 2026-08-19
**Product:** Kavrix CLI
**Primary audience:** developers
**Secondary audience:** DevOps operators

## 1. Objective

Kavrix will support one encrypted datastore containing multiple independently
named vaults. One protected database-owner key file will manage the database
catalog and every vault in that database. MongoDB mode will additionally support
user identities and vault-scoped sharing, so a recipient can access only the
vaults explicitly granted to that identity.

Local-file mode will use the same multi-vault encrypted container but will not
implement users or fine-grained grants. Sharing a local database means securely
sharing exactly two protected artifacts: the encrypted database file and its
database-owner key file. Anyone holding both artifacts and the key-file
passphrase has access to every vault in that local database.

No plaintext project name, vault name, environment name, credential name,
credential field, secret value, private user key, database root key, or vault
root key may be persisted in MongoDB or the local database file. Encryption and
decryption happen only in the local Kavrix process.

## 2. Security claims and non-claims

Kavrix will use established, versioned cryptographic constructions and fail
closed on unsupported versions, malformed data, authentication failure,
authorization failure, rollback, concurrency conflicts, and ambiguous state.
The product will not claim that encryption is permanently unbreakable.

The design protects against a datastore operator reading secret content or
forging authenticated state. A datastore operator can still observe bounded
routing metadata, deny service, delete records, replay old snapshots, measure
ciphertext sizes, and observe access timing. Local authenticated revision
anchors detect supported rollback and same-revision fork cases but do not make
the datastore available or erase historical copies.

An authorized user can copy plaintext while a vault is unlocked. Revocation
prevents that identity from decrypting future vault revisions after rotation; it
cannot erase plaintext or old ciphertext and keys already copied by that user.

## 3. Rejected alternatives

### 3.1 One shared database key for every user

Rejected because sharing the database-owner key grants access to every vault and
makes vault-specific revocation impossible.

### 3.2 One unrelated key file per vault

Rejected as the primary owner workflow because it conflicts with the approved
requirement that one database key manage multiple vaults. Vaults still receive
independent random root keys internally.

### 3.3 One opaque encrypted blob for the entire MongoDB database

Rejected because it prevents bounded per-vault updates, efficient grant
discovery, vault-scoped sharing, and practical concurrency. MongoDB will see
only the minimum opaque routing and authorization metadata defined below.

### 3.4 Custom cryptographic primitives

Rejected. Kavrix will compose reviewed library operations behind small,
misuse-resistant APIs and will include algorithm and envelope versions in every
authenticated contract.

## 4. Hierarchy

The user-facing hierarchy is:

```text
Datastore profile
└── Database
    ├── Private encrypted catalog
    ├── User public identities (MongoDB only)
    └── Vaults
        └── Vault (normally one developer project)
            ├── Environments (development, staging, production, custom)
            ├── Groups/services (servers, databases, email, APIs, custom)
            └── Credential items
                └── Typed fields (username, password, token, URL, notes, custom)
```

Vault, environment, group, item, and field labels are encrypted. The datastore
uses opaque random identifiers rather than labels for routing. A vault is the
cryptographic sharing and revocation boundary. An environment is an encrypted
organizational boundary, not a separate authorization boundary in the first
release.

## 5. Key hierarchy

### 5.1 Database owner

Initialization generates a random 256-bit database root key (`DRK`). The DRK is
wrapped by a random portable database key stored in a protected key file. The
key file is passphrase-protected with the existing Argon2id and
XChaCha20-Poly1305 construction and is bound to:

- an opaque database ID;
- a database-key slot ID;
- the datastore format and cryptographic versions; and
- the expected datastore type.

The database key file never contains MongoDB credentials. A database key file
must fail against a different database ID even if collection names and vault IDs
match.

The DRK derives independent catalog, owner-manifest, and local-anchor keys with
HKDF-SHA-256 using distinct versioned domain strings. A fresh random vault root
key (`VRK`) is generated for every vault and wrapped by a DRK-derived wrapping
key with XChaCha20-Poly1305. Compromise of one VRK must not derive the DRK or any
other VRK.

The database owner's Ed25519 and X25519 private identity keys are stored only
inside the DRK-encrypted private catalog. Unlocking the database-owner key file
opens that catalog locally and makes owner operations available without a
second identity file. The database header contains only the corresponding
public keys and fingerprint.

### 5.2 User identity

MongoDB sharing uses a protected user identity file containing two independent
private keys:

- an Ed25519 signing key for authenticated revisions and membership actions;
- an X25519 encryption key for recipient-specific vault grants.

The corresponding public keys and a SHA-256 identity fingerprint are safe to
share. Private identity material is encrypted at rest with Argon2id-derived
key-encryption material and XChaCha20-Poly1305, using a strict versioned file
format, owner-only permissions or Windows ACLs, path/link rejection, bounded
input, and atomic writes.

Recipient grants use a reviewed libsodium public-key sealed-box construction to
encrypt the VRK to the recipient X25519 public key. The sealed box alone is not
treated as authorization: it is embedded in an owner-signed membership
manifest bound to the database ID, vault ID, recipient fingerprint, role, key
version, membership revision, and grant ID.

### 5.3 Encryption algorithms

- Secret and metadata payloads: XChaCha20-Poly1305-IETF.
- Passphrase protection: Argon2id with bounded, versioned parameters followed by
  XChaCha20-Poly1305-IETF.
- Symmetric key derivation: HKDF-SHA-256 with unique versioned domains.
- User signatures: Ed25519.
- Recipient key wrapping: libsodium sealed boxes using X25519-based public-key
  encryption.
- Digests and identity fingerprints: SHA-256 where collision resistance, not
  password hashing, is required.

Every encrypted envelope authenticates its database ID, vault ID where
applicable, entity type, entity ID, parent IDs, schema version, cryptographic
version, key version, revision, and metadata digest. Envelopes cannot be copied
between databases, vaults, groups, items, revisions, or purposes.

## 6. MongoDB persistence model

MongoDB stores one bounded database header, one encrypted private catalog, and
one document per vault. The default collection names remain configurable but
are validated and fixed for a profile.

### 6.1 Database header

Datastore-visible fields are limited to:

- format and supported versions;
- opaque database ID;
- database revision and timestamps;
- active database-key slot metadata and wrapped DRK;
- owner public signing/encryption keys and fingerprint;
- authenticated catalog-envelope metadata, nonce, ciphertext, and tag; and
- the database-head signature and digest.

The encrypted catalog contains database label, vault labels, preferred ordering,
profile preferences, and the opaque vault-ID mapping.

### 6.2 Vault document

Each document contains:

- opaque database and vault IDs;
- schema, cryptographic, key, membership, and document revisions;
- the VRK wrapped for the DRK owner;
- a minimal recipient-discovery index containing recipient fingerprint, grant
  ID, sealed VRK envelope, grant revision, and owner signature;
- an encrypted membership manifest containing roles, member public signing
  keys, grant states, revocation history, and authorization revisions;
- encrypted vault payload envelope;
- writer fingerprint and revision signature;
- timestamps and authenticated metadata digests.

The encrypted vault payload contains all labels and the environment, group,
item, and typed-field hierarchy. The encrypted membership manifest keeps roles
and user labels hidden as well. Credential names and values are never indexed
in plaintext. MongoDB queries only opaque database/vault IDs and recipient
fingerprints.

Every update uses compare-and-swap on the exact prior document, membership, and
key revisions. A stale or unauthorized writer receives a generic conflict or
authorization error.

### 6.3 Roles

The first release supports:

- `reader`: can decrypt the current vault but cannot produce an accepted vault
  revision;
- `editor`: can decrypt and sign ordinary vault mutations;
- `owner`: can mutate, grant, revoke, rotate keys, transfer ownership, and
  destroy the vault.

Every accepted vault revision is signed by an active editor or owner identity.
Clients verify the owner-signed membership manifest and writer role before
decrypting or accepting the revision. A reader who has direct MongoDB write
credentials can corrupt or delete ciphertext, but cannot forge an accepted
revision. Availability attacks remain in scope for detection, not prevention.

The database-owner key is an administrative recovery authority for every vault
in that database. It must not be shared with ordinary users.

## 7. Grant, revoke, and ownership flows

### 7.1 User creation

```sh
kavrix user key create --output alice.kavrix-user
kavrix user key export-public \
  --key-file alice.kavrix-user \
  --output alice.kavrix-public
```

Creation uses a masked passphrase prompt or an explicit protected stdin flow.
The public enrollment file contains no private key or secret. Kavrix displays a
stable fingerprint for out-of-band comparison.

### 7.2 Grant

```sh
kavrix vault grant \
  --vault project-a \
  --recipient alice.kavrix-public \
  --role editor
```

The owner validates the public file, shows the vault, recipient fingerprint,
and role, then requires one explicit authorization confirmation. It wraps the
current VRK to the recipient, appends an owner-signed membership record, signs
the new vault revision, and publishes it with compare-and-swap. No recipient
private key is requested.

### 7.3 Access discovery

An enrolled user supplies a MongoDB connection through the existing masked or
stdin boundary and unlocks the protected identity file locally. Kavrix queries
only documents containing that public recipient fingerprint, verifies each
owner signature and database binding, opens the recipient grant locally, and
decrypts only authorized vaults.

### 7.4 Revoke

```sh
kavrix vault revoke --vault project-a --user <fingerprint>
```

Revocation is not a flag-only metadata edit. The owner must:

1. reload and verify the exact current vault and membership revision;
2. mark the target grant revoked in the signed membership history;
3. generate a fresh VRK and key version;
4. decrypt and re-encrypt the current vault payload locally;
5. create fresh grants for every remaining active member;
6. sign the new membership manifest and vault revision;
7. atomically compare-and-swap the complete vault document; and
8. update the local authenticated database revision anchor.

Failure before publication leaves the old revision active. A publication
conflict leaves no partially active new grant set. Secret buffers and generated
keys are zeroized on every terminal path where the runtime permits.

Revocation prevents the removed identity from reading future revisions. It does
not invalidate plaintext, keys, or snapshots the identity copied earlier.

### 7.5 Ownership transfer

Ownership transfer is a separate two-party operation, not a role edit. The
current owner signs a transfer intent and the recipient owner identity signs an
acceptance bound to the exact vault and membership revision. The transfer and
new owner grant publish atomically. The original owner remains an owner unless
explicitly revoked in the same signed transition.

## 8. Local-file mode

The local adapter evolves from one vault document per file to one strict,
bounded database container containing:

- the database header and encrypted catalog;
- a map of opaque vault IDs to vault documents;
- one database revision and authenticated container digest.

It retains exclusive locking, owner-only mode or Windows ACL verification,
link rejection, expected-revision writes, restrictive temporary files, atomic
publication, and directory synchronization. The complete container is rewritten
for a mutation in the first release. Maximum database, vault, item, and field
sizes are independently bounded before allocation and encryption.

User identity, grant, role, and recipient-discovery commands reject local-file
profiles with an explicit unsupported-operation error. Sharing the local file
and its matching database-owner key grants full database access. Kavrix cannot
revoke a copied local key file or erase copied database snapshots.

## 9. Datastore profiles and switching

Developers may register non-secret datastore profiles:

```sh
kavrix db profile add work-mongo --datastore mongodb
kavrix db profile add project-file \
  --datastore file \
  --data-file ./project.kavrix-db
kavrix db profile list
kavrix db profile use work-mongo
kavrix db profile status
```

Profiles store only:

- profile alias;
- datastore type;
- local file path or sanitized MongoDB host/database/collection routing data;
- opaque expected database ID after initialization; and
- default protected database/user key-file paths.

Profiles never store MongoDB passwords, connection tokens, key-file
passphrases, private keys, DRKs, VRKs, recovery keys, or credential values.
MongoDB authentication remains a masked prompt, native protected integration in
a separately reviewed future feature, or explicit stdin. URI credentials remain
forbidden in command arguments.

Switching profiles changes only the selected routing configuration. Every
operation verifies the connected database ID against the protected key-file
binding before accepting or decrypting any vault. Explicit command options may
override a profile but must still satisfy the same binding checks.

## 10. CLI surface and compatibility

The proposed primary commands are:

```text
kavrix db init
kavrix db status
kavrix db profile add|list|use|status|remove
kavrix vault create|list|status|rename|destroy
kavrix vault grant|revoke|members|transfer-owner
kavrix user key create|status|verify|rewrap|export-public
kavrix environment create|list|rename|remove
kavrix group create|list|rename|remove
kavrix item put|get|list|rename|remove
```

Existing flat credential commands remain compatible during migration by
operating on an explicitly selected vault and a default encrypted environment
and group. Existing `--datastore`, `--data-file`, `--database`, `--collection`,
`--vault`, protected key-file, masked prompt, and stdin contracts remain
supported unless a separately documented migration requires otherwise.

No new command accepts secret values, private keys, passphrases, or MongoDB
credentials as positional or ordinary option arguments. Non-interactive output
remains ANSI-free and sanitized. `--json` output never includes secret values or
private material.

## 11. Migration

The current local-vault version 2 format is never silently interpreted as the
new database container. Migration is explicit and copy-first:

```sh
kavrix migrate database \
  --source-profile legacy \
  --destination-profile work
```

The migration:

1. validates both protected destinations before secret input;
2. unlocks and authenticates the source locally;
3. creates a new database and first vault with fresh DRK and VRK values;
4. maps flat credential names into one encrypted default environment and group;
5. verifies counts, names, values, revisions, bindings, and plaintext canaries
   entirely in the local process;
6. writes and verifies new authenticated anchors; and
7. leaves the source untouched until the user separately archives or destroys
   it.

Cross-database copy or move is an export/import operation with destination
re-encryption. Ciphertext and wrapped keys cannot be copied directly because
their authenticated database and vault bindings differ.

## 12. Error handling and recovery

Errors remain generic at secret boundaries. Kavrix must not reveal whether a
passphrase, private key, grant, or database key was nearly correct. It reports
distinct safe categories for invalid input, authentication failure,
authorization failure, conflict, unavailable datastore, unsafe file, corrupt
state, rollback, and unsupported operation.

Multi-step operations use prepare/verify/publish sequencing with one atomic
compare-and-swap publication boundary. Temporary files and generated key
material are registered for cleanup immediately. Cleanup attempts every owned
artifact and aggregates failures without hiding the primary error.

The database-owner recovery kit protects the DRK, not a single VRK. Recovery
restores owner access to the database catalog and all current vault wrappers.
User identity recovery and owner database recovery are separate formats and
cannot substitute for each other.

## 13. Delivery decomposition

This architecture is intentionally delivered as dependent subprojects rather
than one high-risk rewrite:

1. **Database container foundation:** canonical database header/catalog schemas,
   DRK hierarchy, multi-vault MongoDB storage, local multi-vault container,
   datastore profiles, switching, and explicit v2 migration.
2. **Encrypted hierarchy:** environment/group/item/typed-field contracts and
   compatible flat-command projection.
3. **User identities and grants:** protected identity files, public enrollment,
   recipient envelopes, membership signatures, discovery, and reader/editor/
   owner verification.
4. **Revocation and ownership:** atomic VRK rotation, remaining-member regrant,
   signed ownership transfer, and rollback-anchor integration.
5. **Operational acceptance:** packed all-command tests, disposable MongoDB
   integration, Windows ACL proof, migration drills, docs, package checks, and
   security audit.

Each subproject receives its own implementation plan and must leave the main
branch releasable. Sharing commands do not ship until grant, authorization,
revocation, and rollback tests pass together.

## 14. Verification requirements

### 14.1 Cryptography and schema tests

- Known-answer and round-trip tests for every versioned envelope.
- Tampered nonce, ciphertext, tag, signature, role, public key, revision, and
  metadata digest rejection.
- Database/vault/entity/AAD swap rejection.
- Wrong database key, wrong user identity, wrong vault, revoked grant, stale
  key version, and unsupported version rejection.
- Reader-forged write and removed-editor signature rejection.
- Grant duplication, fingerprint collision input, malformed public file, and
  ambiguous identity rejection.
- Plaintext canaries across every MongoDB document, local file, profile,
  temporary file, log, JSON output, package, and failure path.

### 14.2 Storage and concurrency tests

- Multiple vaults in one MongoDB database and one local database file.
- Atomic independent vault updates and expected-revision conflicts.
- Concurrent grant, revoke, edit, rotation, and ownership-transfer races.
- Datastore deletion, truncation, replay, same-revision fork, and partial-write
  rejection.
- Local lock, symlink/hard-link, path replacement, permission/ACL, temporary
  file, crash-cleanup, and maximum-size tests on supported operating systems.

### 14.3 End-to-end acceptance

- Owner creates a database and multiple project vaults with one database key.
- Developer switches between MongoDB and local profiles without credential
  persistence or cross-database key acceptance.
- Owner grants one of several vaults to a second user; the user can discover and
  access only that vault.
- Reader cannot publish, editor can publish, and owner can grant/revoke.
- Revoked user cannot read the next revision; remaining users can.
- Local sharing works with the database file plus matching owner key and rejects
  all user/grant commands.
- v2 migration preserves every credential and leaves the source intact.
- Cleanup succeeds after both passing and intentionally failing flows.

The full repository gates remain formatting, lint, strict type checking, unit
and integration tests, builds, dependency audit, packed-install smoke,
package-content allowlisting, SBOM verification, and supported OS/Node CI.

## 15. Documentation and release constraints

Documentation must distinguish:

- database-owner keys from user identity keys;
- local full-database sharing from MongoDB vault-scoped grants;
- encryption confidentiality from observable routing metadata;
- role enforcement from datastore availability; and
- future-revision revocation from impossible retroactive erasure.

No feature is marked complete in `docs/implementation-status.md` until its
observable tests pass. Existing stable commands and formats remain supported
during the documented migration window. No package publication, tag, release,
or remote migration is part of implementation without separate authorization.
