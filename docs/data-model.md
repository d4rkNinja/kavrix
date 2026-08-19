# Data model

The canonical contracts live in `packages/schemas/src/database-container.ts`
and `packages/schemas/src/local-vault.ts`. The database-container format is the
current multi-vault model. The local-vault version 2 format remains supported as
an explicit, copy-first migration source.

## Database document and private catalog

One database document contains a format/version discriminator, opaque database
ID, schema/cryptographic/key versions, one active portable database-key slot,
bounded database recovery slots, database revision, timestamps, catalog digest,
and an authenticated encrypted catalog envelope.

The catalog plaintext never reaches storage. It contains the private database
label and an ordered mapping from opaque vault IDs to private vault labels and
creation times. The CLI masks labels in ordinary `db vault list` and status
output. Database and vault labels are not plaintext indexes.

## Vault documents

Each vault document contains its opaque database/vault IDs, the VRK wrapped for
the database owner, database and vault revisions, timestamps, metadata digest,
and the authenticated encrypted flat credential payload. Credential names,
values, and record timestamps are inside that payload. `list`, `search`, and
`view` decrypt locally; values remain masked unless a guarded reveal flow is
explicitly requested.

The current flat payload is a compatibility projection. Environments, groups,
items, and typed fields have not been implemented yet and are not present as a
partially supported hierarchy.

## What storage can observe

MongoDB uses two collections: one database document in `kavrix_databases` and
one document per vault in `kavrix_vaults` by default. It can observe opaque IDs,
revisions, timestamps, envelope sizes, collection access, and timing. It cannot
search plaintext database labels, vault labels, credential names, or values.

The local adapter stores the same database document and a bounded opaque-ID map
of vault documents in one canonical protected file. A process able to read that
file sees the same metadata and update timing.

## Key hierarchy

Initialization generates a random 256-bit database root key (DRK). A portable
database key wraps the DRK and is stored only in the passphrase-protected owner
key file. Each vault has a separate random vault root key (VRK), wrapped under a
DRK-derived key bound to the exact database and vault. The DRK also derives
independent catalog and anchor keys with HKDF-SHA-256 domain separation.

Database recovery slots wrap the DRK, not an individual VRK. Consequently, the
owner key or a database recovery kit authorizes recovery of every vault in the
database. A fresh share key created by `kavrix db key create`, its exact matching
database snapshot, and its separately delivered passphrase form a full-database
authorization, not a vault-scoped grant. The primary owner key is not the sharing
artifact.

## Revisions, transactions, and reconciliation

Database/catalog changes and vault creation/deletion use the exact prior
database revision. Vault payload mutations use the exact prior vault revision.
The local adapter publishes one atomic replacement under an exclusive lock.
MongoDB publishes multi-document changes in a transaction and therefore
requires a replica set or sharded topology. Conflicts fail rather than overwrite.

A DRK-authenticated local anchor records the trusted database revision, catalog
digest, and vault head revisions/digests. Reconciliation rejects rollback,
same-revision forks, catalog/document disagreement, missing expected vaults, and
reappearance inconsistent with an authenticated deletion/tombstone-equivalent
head. Ordinary owner-key opens require an exact anchor match and reject even an
authenticated newer datastore state. Only the recovery workflow may
forward-reconcile its authenticated companion anchor after an owner mutation.

## Legacy migration

`kavrix migrate database` authenticates and decrypts one version 2 source vault,
copies its complete flat payload into a newly encrypted destination vault, then
reopens and compares the result before reporting success. The source document,
source key, and source anchor remain unchanged. Initialization of a new local
destination is explicit with `--initialize`; there is no silent in-place format
upgrade.

## Validation

Strict runtime schemas reject unknown versions, extra fields, invalid IDs,
noncanonical encodings, oversized values, malformed envelopes, inconsistent
associated data, duplicate vault IDs, and catalog/document revision mismatch
before plaintext is used. Authentication failures are generic and fail closed.
