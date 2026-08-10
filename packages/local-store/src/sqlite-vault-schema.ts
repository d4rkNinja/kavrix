import type {
  HashableOpaqueRecord,
  OpaqueMutation,
  TombstoneRecord,
} from '@kavrix/schemas';

export const VAULT_STATE_SCHEMA_DEFINITIONS = {
  deletion_predecessors: `CREATE TABLE deletion_predecessors (
    vault_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('vault','group','item','attachment')),
    entity_id TEXT NOT NULL,
    owner_key TEXT NOT NULL CHECK(length(owner_key) = 0 OR length(owner_key) BETWEEN 16 AND 256),
    revision INTEGER NOT NULL CHECK(revision >= 0),
    record_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2),
    PRIMARY KEY(vault_id, entity_type, entity_id, owner_key)
  ) STRICT, WITHOUT ROWID`,
  deletion_predecessors_pending_owner: `CREATE UNIQUE INDEX deletion_predecessors_pending_owner
    ON deletion_predecessors(owner_key) WHERE owner_key <> ''`,
  pending_template_migrations: `CREATE TABLE pending_template_migrations (
    vault_id TEXT PRIMARY KEY NOT NULL,
    batch_key TEXT NOT NULL UNIQUE,
    publication_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2)
  ) STRICT, WITHOUT ROWID`,
  pending_template_migration_mutations: `CREATE TABLE pending_template_migration_mutations (
    batch_key TEXT NOT NULL,
    position INTEGER NOT NULL CHECK(position >= 0 AND position < 100),
    vault_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('group','item')),
    entity_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    mutation_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2),
    PRIMARY KEY(batch_key, position),
    FOREIGN KEY(batch_key) REFERENCES pending_template_migrations(batch_key) ON DELETE CASCADE
  ) STRICT, WITHOUT ROWID`,
  pending_template_migration_entity: `CREATE INDEX pending_template_migration_entity
    ON pending_template_migration_mutations(vault_id, entity_type, entity_id, position)`,
  completed_template_migrations: `CREATE TABLE completed_template_migrations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id TEXT NOT NULL,
    batch_key TEXT NOT NULL UNIQUE,
    publication_json TEXT NOT NULL,
    response_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 4)
  ) STRICT`,
  completed_mutation_receipts: `CREATE TABLE completed_mutation_receipts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    queue_kind TEXT NOT NULL CHECK(queue_kind IN ('generic','template-migration')),
    mutation_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2)
  ) STRICT`,
} as const;

export type VaultStateLimits = Readonly<{
  maxRecords: number;
  maxRecordBytes: number;
  maxPendingMutations: number;
  maxPendingBytes: number;
  maxCompletedBatches: number;
  maxCompletedMutations: number;
  maxCompletedMutationBytes: number;
  maxCompletedPublicationBytes: number;
  maxSerializedRowBytes: number;
}>;

export type EntityType = 'attachment' | 'group' | 'item' | 'vault';
export type MutationEntityType = OpaqueMutation['entityType'];
export type DeletedState = Readonly<{
  state: 'deleted';
  tombstone: TombstoneRecord;
  predecessor: HashableOpaqueRecord;
}>;
export type CurrentState =
  Readonly<{ state: 'active'; record: HashableOpaqueRecord }> | DeletedState;

export type PersistedRecordRow = Readonly<{
  vault_id: unknown;
  entity_type: unknown;
  entity_id: unknown;
  revision: unknown;
  record_json: unknown;
  serialized_bytes: unknown;
}>;

export type PersistedMutationRow = Readonly<{
  vault_id: unknown;
  entity_type: unknown;
  entity_id: unknown;
  idempotency_key: unknown;
  mutation_json: unknown;
  serialized_bytes: unknown;
}>;

export type PersistedPredecessorRow = Readonly<{
  vault_id: unknown;
  entity_type: unknown;
  entity_id: unknown;
  owner_key: unknown;
  revision: unknown;
  record_json: unknown;
  serialized_bytes: unknown;
}>;

export type PersistedPublicationRow = Readonly<{
  vault_id: unknown;
  batch_key: unknown;
  publication_json: unknown;
  serialized_bytes: unknown;
}>;

export type PersistedCompletionRow = Readonly<{
  vault_id: unknown;
  batch_key: unknown;
  publication_json: unknown;
  response_json: unknown;
  serialized_bytes: unknown;
}>;
