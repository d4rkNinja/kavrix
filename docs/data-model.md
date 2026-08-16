# Data Model

> Design status: this document defines target domain and storage contracts. The
> schemas and collections are not verified until referenced in
> [implementation-status.md](./implementation-status.md).

## Modeling rules

- `packages/schemas` owns each runtime contract once and exports its inferred
  TypeScript type. Consumers must not maintain parallel interfaces.
- IDs, revisions, key versions, ciphertext, and secret bytes use branded/opaque
  types where practical.
- Database/API records are separate from decrypted domain payloads. A storage
  DTO must be structurally unable to contain plaintext credential fields.
- Unknown schema, envelope, algorithm, AAD, and key versions fail closed.
- Optional and absent are distinct. `exactOptionalPropertyTypes` and runtime
  schemas must preserve that distinction.
- Timestamps are canonical UTC instants on the wire. Presentation converts to
  the user's local time.
- Opaque IDs are random, stable, non-secret identifiers. They must not encode a
  name, email, type, tenant, or sortable business value.
- User-controlled strings are untrusted even after successful decryption and
  must be sanitized before terminal or path use.

## Data classification

| Class                              | Examples                                                                                                                 | Persistence rule                                                                                  |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| Secret key material                | Portable/recovery/device keys, passphrases, KEKs, unwrapped VRK/group/item/attachment keys                               | Local memory only, except explicit native-keychain or protected key-file flow; never API/MongoDB  |
| Encrypted application content      | Names, aliases, tags, field definitions/values, notes, preferences, history/audit details, attachment metadata/content   | XChaCha20-Poly1305 AEAD or secretstream ciphertext only outside the active client                 |
| Wrapped key material               | VRK slots, group keys, item keys, attachment keys                                                                        | Versioned authenticated envelope only                                                             |
| Authentication secret              | Plaintext API session/device token, enrollment credential, or invite                                                     | Held only in an explicit protected local flow/native keychain; server stores a cryptographic hash |
| Public/opaque operational metadata | Opaque IDs, versions, salts/KDF costs, nonces, revisions, sequence, timestamps, tombstone state, ciphertext sizes/hashes | May be stored by API/MongoDB; minimize and document                                               |

Ciphertext and its hash are not treated as harmless log data. Routine request/
response logging omits encrypted bodies to reduce correlation, volume, and
future cryptanalytic exposure.

## Identifier and version types

The schema package defines distinct branded types for at least:

```text
VaultId, SlotId, DeviceId, InviteId, GroupId, ItemId, FieldId, StableFieldKey,
NoteId, AttachmentId, AuditEventId, ChangeSequence, RecordRevision, KeyVersion,
SchemaVersion, EnvelopeVersion, CiphertextBytes, SecretBytes
```

An identifier for one entity cannot be passed where another is expected without
an explicit checked conversion. Revisions are non-negative monotonic integers
within their defined scope and are checked for overflow/unsafe JSON integer
representation. Wire schemas choose a canonical integer/string encoding and do
not accept both ambiguously.

## Cryptographic records

### AEAD envelope

All non-streaming encrypted or wrapped content uses one canonical family:

```text
AeadEnvelopeV1 {
  envelopeVersion: 1
  algorithm: "xchacha20-poly1305-ietf"
  aadVersion: 1
  payloadType: <closed versioned enum>
  keyVersion: KeyVersion
  nonce: Base64UrlBytes<24>
  ciphertext: Base64UrlBytes<bounded>
}
```

The authentication tag is represented in the exact form returned/required by
the chosen binding and covered by the envelope schema. AAD is reconstructed from
the record's immutable typed context rather than trusted from a free-form stored
blob. See [cryptography.md](./cryptography.md).

### Unlock slot

```text
UnlockSlotV1 {
  slotId: SlotId
  slotType: "portable" | "passphrase" | "recovery" | "device"
  slotVersion: 1
  derivation: PortableHkdfV1 | PassphraseArgon2idV1 |
              RecoveryHkdfV1 | DeviceHkdfV1
  wrappedVrk: AeadEnvelopeV1<payloadType="vrk-slot">
  keyVersion: KeyVersion
  state: "pending" | "active" | "revoked"
  createdAt: Instant
  revokedAt?: Instant
  encryptedLabel?: AeadEnvelopeV1
}
```

Derivation metadata includes exact algorithm/version, random salt, output
length, context identifier, and all Argon2id memory/pass/parallelism values when
applicable. It never contains the input key/passphrase or derived KEK.

## Decrypted domain model

### Vault

The client-visible vault aggregate contains:

- stable `vaultId`, schema/cryptographic versions, current VRK version, and
  current vault revision;
- versioned unlock slots;
- encrypted preferences after local decryption;
- authorized device summaries;
- group references, sync cursor/state, and encrypted audit/history state;
- created and updated instants.

Server-visible vault data excludes decrypted preferences and all key material
except authenticated wrapped envelopes.

### Group and template

A group is both a container and a reusable credential schema. Its encrypted
payload contains:

```text
GroupPayloadV1 {
  name
  slug?
  aliases[]
  description?
  iconToken?
  colorToken?
  tags[]
  notes[]
  template
  sortOrder
  favorite/pinned state
  archived domain metadata
}
```

The outer record carries opaque IDs, wrapped group key, ciphertext envelope,
template/record versions required for sync, timestamps, and tombstone/archive
state. Names, aliases, tags, template fields, and note text remain encrypted.

A template contains a stable version and ordered field definitions. Each field
definition supports:

```text
FieldDefinition {
  id
  stableKey
  label
  description?
  type
  required
  sensitive
  repeatable
  copyable
  searchableLocally
  showInPreview
  defaultValueForNonSecretFieldsOnly?
  placeholder?
  validationRules[]
  selectOptions[]
  environmentVariableName?
  copyPolicy
  revealPolicy
  reauthenticationPolicy
  exportPolicy
  sortOrder
  createdAt
  updatedAt
  archivedAt?
}
```

`id` is immutable identity. `stableKey` is immutable automation identity within
its scope and does not change when `label` changes. Stable keys have a strict,
portable syntax and uniqueness constraint. Labels are user-facing and may be
Unicode. Secret defaults are schema-invalid. A repeatable field's values carry
stable element IDs so one recovery code can be marked used without relying on
array position.

Supported field types are a closed, versioned registry rather than arbitrary
executable code. The initial registry includes text, secret/password, username,
email, URL, phone, number, boolean, date/datetime, multiline/secure multiline,
API/access/refresh tokens, client ID/secret, connection string, host, port,
database name, private/public key, certificate, TOTP secret, recovery-code list,
JSON, select/multi-select, tags, environment map, command snippet, attachment,
credential reference, and schema-defined custom validators. Security-sensitive
types default to `sensitive: true`; weakening that default is an explicit policy
change.

### Template migration

A template edit creates a migration record with source/target template versions,
operation list, affected-item count, state, checkpoint, and encrypted audit
details. Safe operations include add, label rename, reorder, and requiredness
changes with validation. Type conversion requires a versioned conversion rule;
destructive conversions require separate confirmation.

Removing a definition moves each value to encrypted orphan storage keyed by the
original field ID/stable key and source template version. It does not erase the
value. Restore reverses that mapping. Permanent purge is a separate operation
with its own authorization, audit event, and retention consequences. Migration
writes are resumable and idempotent.

### Credential item

An item's encrypted payload contains:

```text
ItemPayloadV1 {
  title
  slug?
  aliases[]
  subtitle?
  templateVersion
  templateValues: FieldValueByFieldId
  itemFieldDefinitions[]
  itemFieldValues: FieldValueByFieldId
  orphanedValues[]
  notes[]
  tags[]
  favorite
  environment?
  owner?
  purpose?
  productionSensitive
  expiresAt?
  rotationInterval?
  lastRotatedAt?
  lastVerifiedAt?
  relatedItemIds[]
  attachmentIds[]
  copySequences[]
  createdAt
  updatedAt
}
```

Values are discriminated by field type and validated against the referenced
definition. Missing, explicitly empty, archived/orphaned, inapplicable, and
unreadable values have distinct representations; magic empty strings are not
used. Copy sequences contain stable field keys only, never values.

`FieldValueV1` is a closed union on `state`. Active values use `missing`,
`empty`, `present`, `inapplicable`, or `unreadable`. An archived value uses the
`orphaned` state and embeds the exact complete prior active value together with
its field definition and source-template provenance; archive and restore never
coerce a prior state. Present values distinguish single from repeatable
content. Every repeatable element has a stable opaque element ID and a
versioned lifecycle. Recovery-code elements may transition from `available` to
`used` and require `usedAt` in the latter state; other repeatable field types
cannot use the recovery-code-only `used` lifecycle. Sensitive scalar and
sensitive environment-map values use the branded `SecretValue` variant rather
than an ordinary string. Item and attachment value references use their
respective branded opaque IDs.

Item-only field definitions follow the same contract and can be promoted through
a migration that maps the existing stable identity safely.

`relatedItemIds` is the authoritative relation list. Every field-level
`item-reference` value must resolve through it, so a payload whose reference field
names a target absent from the list is refused and the two are always written in
the same mutation. The list is unique, excludes the item itself, and is bounded.
A relation may exist with no field binding it, because a field reference is
required to appear in the list and not the reverse; an unbound relation is
therefore a valid state and is reported rather than treated as an error.

Reference resolution is local and reports three target states. A readable target
is `active`. A target carrying `archivedAt` is `archived`, which retires the
credential without breaking the relation. A tombstoned target is excluded from
every read, so its relation survives with nothing behind it and resolves as
`missing` rather than being dropped. Outward traversal is breadth-first, expands
each credential at most once, and is bounded by both a maximum depth and a node
ceiling; a truncated walk says so instead of presenting itself as complete. A
repeat and a cycle are distinct: a credential reached again on a sibling branch is
a shared target, while one reached again on its own path back to the root closes a
loop. Cycles are legal, disclosed with the path they close, and never silently
pruned.

### Notes

Group and item payloads can contain any number of notes:

```text
Note {
  id
  title
  content
  isSensitive
  isPinned
  tags[]
  sortOrder
  createdAt
  updatedAt
  archivedAt?
}
```

All notes are encrypted, including non-sensitive notes. `isSensitive` controls
local reveal/export/search behavior; it is not permission to persist plaintext.
Archive and restore are distinct from permanent deletion.

### Attachment

Attachment metadata is encrypted and includes original filename, media type,
description, original size, cryptographic content hash, chunk count/size, and
attachment-key version. The outer attachment record exposes only bounded opaque
data needed to fetch chunks. Content uses one versioned libsodium secretstream
with a public header, ordered ciphertext chunks, and a required final tag. Each
chunk index is bound through canonical AAD; chunk order, count, sizes, and the
content hash are authenticated by the stream and encrypted metadata. The final
file is not committed to a plaintext destination until the complete stream and
metadata verify.

### Audit and history

Audit details and history payloads are encrypted. Minimal outer metadata may
identify vault, opaque entity, operation class, sequence/revision, ciphertext
hash, and timestamp only when synchronization requires it. Plaintext field
names, values, diffs, names, or notes never appear in the outer event.

History stores versioned encrypted item snapshots and can report changed field
labels only after local decryption. Known-v1 restore validates the snapshot's
item/vault/group identity, revision, and outer ciphertext hash with the item
key. The documented v1 audit payload records key-slot create/revoke state and
is validated against the archived slot metadata under the vault root key.
Retention and purge are explicit.

## MongoDB collections

### `vaults`

Public/opaque fields:

- `_id`/vault ID;
- schema and cryptographic versions;
- current key version and vault revision;
- versioned unlock slots with derivation metadata and wrapped VRK envelopes;
- encrypted preferences envelope;
- created/updated timestamps.

Forbidden: portable/passphrase/recovery/device plaintext, any KEK/unwrapped VRK,
or decrypted preferences.

### `api_devices`, `api_sessions`, and `api_credential_claims`

- device and vault IDs;
- device-token hash and token version;
- encrypted label when a label is needed;
- scope, confirmed key version, created/last-seen/revoked timestamps.

The joining client generates and durably protects the plaintext device token
before its completion exchange. The service receives it only through the
dedicated redacted successor header and never returns or stores it; the device,
session, and global credential-claim records contain only its SHA-256 hash.

Initial vault creation uses the same canonical 32-byte session credential but
has no parent invite: the caller stores it in the native keychain before sending
it as the bootstrap request's HTTPS bearer. A bootstrap credential claim stores
the bearer hash plus an exact-request digest for retry safety. The bootstrap
transaction atomically inserts the revision-zero `vaults` document, its
`vault_counters`/first `changes` sync anchor, first `api_devices` record,
`api_sessions` record, and globally unique `api_credential_claims` record.
Incompatible retry, vault/device collision, or reuse of any invite, enrollment,
or session hash fails without a partial insert.

`api_invites` and `api_enrollments` are dedicated collections. They store invite
ID where applicable, vault/creator IDs, credential hashes, scope, expiry, state,
and created/consumed/revoked timestamps. One `_id` namespace in
`api_credential_claims` prevents a hash from being reused across invite,
enrollment, bootstrap-session, and enrolled-session credentials.

### `groups`

- opaque group and vault IDs;
- wrapped group-key envelope;
- encrypted group payload;
- template, record, schema, and key versions required for safe interpretation;
- minimal sort metadata only if it cannot remain encrypted;
- revision, ciphertext hash, timestamps, archive/tombstone state.

### `items`

- opaque item, vault, and group IDs;
- wrapped item-key envelope;
- encrypted item payload;
- record/schema/key versions, revision, ciphertext hash, timestamps, tombstone
  state.

There are no plaintext titles, aliases, field names, usernames, emails, URLs,
tags, environments, notes, or credential types.

### `attachments.files` and `attachments.chunks`

Outer records contain opaque vault/item/attachment IDs, encrypted metadata,
wrapped attachment key, secretstream version/header, bounded chunk index/size
information, key versions, ciphertext hashes, revisions, and timestamps.
Filename, MIME type, description, original size, plaintext content hash, and
chunk count remain inside authenticated encrypted metadata unless a specific
operational value is proven necessary and documented. Storage may know how many
opaque chunks exist operationally; it must not treat that count as the trusted
manifest.

The persisted stream header and every chunk are separate canonical records.
Each repeats the complete vault/group/item/attachment and schema/key/stream
identity, carries its own record revision, canonical SHA-256 content hash, and
timestamps. Chunk ciphertext decodes to at most 8 MiB plus the reviewed
secretstream overhead.

Upload uses a hidden, idempotent staging session instead of an in-memory stream
aggregate or standalone header/chunk mutations. The session validates each chunk
incrementally: indexes are contiguous from zero, identity and versions match the
single staged header, byte totals stay within protocol caps, and exactly one last
chunk has final semantics. Staged records are invisible to normal reads and the
change feed. Finalization checks the encrypted attachment record's identity,
revision, and expected chunk count, then atomically publishes metadata, header,
and chunks as one attachment change. Abort discards unpublished staging;
restarting with the same idempotency key either resumes the matching hidden
session or fails closed on incompatible reuse. Published chunk iteration remains
strictly ascending and contiguous.

### `changes`

Append-only sync feed:

```text
vaultId, serverSequence, entityType, entityId, recordRevision,
operation, ciphertextHash, timestamp
```

`entityType` and operation are coarse closed enums. The feed contains no titles,
labels, tags, field/note content, usernames, emails, URLs, or diffs.

### `audit_events` and history collections

Encrypted payload plus only the opaque sequencing/retention metadata needed to
retrieve it. Audit outer data must not become a shadow plaintext activity log.

### `tombstones`

Opaque vault/entity IDs, entity type, last record version/hash, deletion
revision, retention/purge time, and encrypted deletion details as needed.
Deletion sync remains possible without exposing the deleted entity's name.

## Validation and indexes

MongoDB validators and application runtime schemas reject unknown critical
fields, wrong BSON types, invalid lengths, non-canonical base64url, unsupported
versions, oversized payloads, unsafe numbers, and attempts to store explicit
plaintext secret fields.

Required indexes include:

- unique entity ID within a vault;
- `(vaultId, serverSequence)` unique/ordered for sync;
- `(vaultId, groupId)` for item retrieval;
- `(vaultId, updatedAt)` and `(vaultId, tombstoneState)` for bounded sync/admin
  operations;
- unique device-token hash and invite hash where applicable;
- `(vaultId, recordRevision)`/expected-version paths needed for optimistic
  concurrency;
- attachment `(vaultId, attachmentId, chunkIndex)` uniqueness.

Indexes are tested against a real MongoDB instance. Never accept client-supplied
MongoDB operators or build dynamic query objects from untrusted keys.

## Concurrency and synchronization

Every mutable record has an expected revision. A write succeeds only against the
expected prior revision or returns an explicit conflict; retries use an
idempotency key. Multi-record transactions are used only when they add actual
correctness, such as atomic invite consumption or a commit marker that must move
with a record set.

The server sequence is monotonic within a vault and distinct from each entity's
revision. Cursors are opaque and bounded. An encrypted offline queue contains
already-encrypted mutations and their public expected revisions; it never
stores plaintext drafts. Concurrent secret edits are not silently resolved by
last-write-wins.

## Local data

The local cache may store ciphertext records, wrapped keys, opaque IDs, sync
cursors, idempotency state, and encrypted pending mutations. The highest-seen
vault revision belongs in protected local state for rollback detection. A local
search index, if persisted, is encrypted; decrypted search state exists only
while unlocked.

Configuration contains server URL, product/profile preferences, and opaque IDs,
but no plaintext portable/recovery key, passphrase, device/session token,
MongoDB credential, or decrypted vault data. Native keychain references are
opaque. A session credential uses a device-scoped `api-session` locator; it is
not a key-slot locator and cannot be loaded through the device-unlock port.

## Schema evolution

Every stored family has an explicit schema version and a pure validation step
before migration. Migrations are monotonic, bounded, resumable, and tested from
all supported prior versions. A data-schema migration does not silently change
the cryptographic interpretation of an existing envelope; that requires an
explicit re-encryption/version migration. Unknown future records remain opaque
and must not be partially decoded or overwritten by an older client.
