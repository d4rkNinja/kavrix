# Data model

The canonical contracts live in `packages/schemas/src/database-container.ts`,
`packages/schemas/src/local-vault.ts`, and
`packages/schemas/src/structured-vault.ts`. The database-container format is the
current multi-vault model. The local-vault version 2 format remains supported as
an explicit, copy-first migration source and as a legacy payload at the
database-vault boundary.

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
and an authenticated encrypted credential payload. The payload is either the
legacy flat version 2 record map or the versioned structured representation.
Credential names, values, field definitions, and record timestamps are inside
that payload. `list`, `search`, and `view` decrypt locally; values remain masked
unless a guarded reveal flow is explicitly requested.

### Structured vault payload

New database vaults use the structured payload defined by
`structuredVaultPayloadSchema`. Its private hierarchy is:

```text
database
└── vault
    └── project context (optional environment label)
        └── group / service
            └── credential item
                ├── typed fields and schema-driven field policies
                ├── notes, tags, expiry, and rotation metadata
                ├── encrypted attachment records
                └── encrypted history records
```

The persisted collection is named `groups` because it reuses the canonical
`groupPayloadSchema`; “service” is the product vocabulary alias for that level.
Project contexts, groups, items, attachments, and history records carry opaque
identifiers and are checked for duplicate identities, dangling references, and
cross-vault ownership before plaintext is used. The top-level payload carries
the vault ID and a separate structured-payload version, so an authenticated
payload cannot be replayed into another vault or silently interpreted as a
different representation.

Typed field definitions are canonical contracts from
`packages/schemas/src/fields.ts`. They cover, among other types, username,
password, API key, URL, certificate, TOTP seed, recovery-code list, JSON, and
environment-map values. Copy, reveal, reauthentication, and export behavior is
stored on each field definition through its policy values; unknown policy or
field combinations fail schema validation. Notes, expiry/rotation metadata,
attachments, and history are modeled in the item and encrypted-record schemas;
the compatibility root commands preserve records outside their projection.

### Flat compatibility projection

The root `put`, `get`, `list`, `view`, `search`, `stats`, `has`, `rename`, and
`remove` commands continue to operate on a deliberately narrow projection: the
default project context, the default group/service, and each item's canonical
`value` password field. A flat name, including a path separator such as
`github/token`, remains one literal item title; it is never parsed as a project,
service, or item path. Non-default contexts, groups/services, and items are
invisible to this projection, and an invalid or colliding projection fails
closed rather than guessing.

An existing flat database payload remains flat when it is read or updated by
these root commands. Explicit structured access upgrades a legacy payload to
the in-memory hierarchy, and a structured update persists that upgrade. The
projection adapter in `apps/cli/src/structured-vault-projection.ts` preserves
structured identities and metadata while applying a flat update; it does not
create a parallel plaintext record store.

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
stages its records into the destination's default project context and
default group/service as structured items, then reopens and compares the result
before reporting success. The root flat projection therefore retains the same
names and values after migration, while the destination also has the
structured-field representation. The source document, source key, and source
anchor remain unchanged. Initialization of a new local destination is explicit
with `--initialize`; there is no silent in-place format upgrade.

## Validation

Strict runtime schemas reject unknown versions, extra fields, invalid IDs,
noncanonical encodings, oversized values, malformed envelopes, inconsistent
associated data, duplicate vault IDs, and catalog/document revision mismatch
before plaintext is used. Authentication failures are generic and fail closed.
