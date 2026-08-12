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
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2),
    replay_from_server_sequence INTEGER CHECK(replay_from_server_sequence >= 0)
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
  completed_outbound_observations: `CREATE TABLE completed_outbound_observations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('generic-push','template-publication')),
    batch_key TEXT NOT NULL,
    observation_id TEXT NOT NULL UNIQUE CHECK(length(observation_id) = 43),
    request_hash TEXT NOT NULL CHECK(length(request_hash) = 43),
    response_hash TEXT NOT NULL CHECK(length(response_hash) = 43),
    response_vault_revision INTEGER NOT NULL CHECK(response_vault_revision >= 0),
    replay_from_server_sequence INTEGER NOT NULL CHECK(replay_from_server_sequence >= 0),
    required_through_server_sequence INTEGER NOT NULL CHECK(required_through_server_sequence >= replay_from_server_sequence),
    request_json TEXT NOT NULL,
    response_json TEXT NOT NULL,
    final_cursor_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 6),
    UNIQUE(kind, batch_key)
  ) STRICT`,
  outbound_observation_pins: `CREATE TABLE outbound_observation_pins (
    vault_id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL,
    observation_id TEXT NOT NULL UNIQUE CHECK(length(observation_id) = 43),
    kind TEXT NOT NULL CHECK(kind IN ('generic-push','template-publication')),
    state TEXT NOT NULL CHECK(state IN ('pinned','released')),
    accepted_keys_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2)
  ) STRICT, WITHOUT ROWID`,
} as const;

const {
  completed_outbound_observations: _completedOutboundObservations,
  outbound_observation_pins: _outboundObservationPins,
  pending_template_migrations: _pendingTemplateMigrations,
  ...LEGACY_V2_UNCHANGED_VAULT_STATE_SCHEMA_DEFINITIONS
} = VAULT_STATE_SCHEMA_DEFINITIONS;
void _completedOutboundObservations;
void _outboundObservationPins;
void _pendingTemplateMigrations;

export const LEGACY_V2_VAULT_STATE_SCHEMA_DEFINITIONS = {
  ...LEGACY_V2_UNCHANGED_VAULT_STATE_SCHEMA_DEFINITIONS,
  pending_template_migrations: `CREATE TABLE pending_template_migrations (
    vault_id TEXT PRIMARY KEY NOT NULL,
    batch_key TEXT NOT NULL UNIQUE,
    publication_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2)
  ) STRICT, WITHOUT ROWID`,
} as const;

export type VaultStateLimits = Readonly<{
  maxVaults: number;
  maxRecords: number;
  maxRecordBytes: number;
  maxPendingMutations: number;
  maxPendingBytes: number;
  maxCompletedBatches: number;
  maxCompletedPushBatchBytes: number;
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
  replay_from_server_sequence?: unknown;
}>;

export type PersistedOutboundObservationRow = Readonly<{
  sequence?: unknown;
  vault_id: unknown;
  device_id: unknown;
  kind: unknown;
  batch_key: unknown;
  observation_id: unknown;
  request_hash: unknown;
  response_hash: unknown;
  response_vault_revision: unknown;
  replay_from_server_sequence: unknown;
  required_through_server_sequence: unknown;
  request_json: unknown;
  response_json: unknown;
  final_cursor_json: unknown;
  serialized_bytes: unknown;
}>;

export type PersistedOutboundObservationPinRow = Readonly<{
  vault_id: unknown;
  device_id: unknown;
  observation_id: unknown;
  kind: unknown;
  state: unknown;
  accepted_keys_json: unknown;
  serialized_bytes: unknown;
}>;

export type PersistedCompletionRow = Readonly<{
  vault_id: unknown;
  batch_key: unknown;
  publication_json: unknown;
  response_json: unknown;
  serialized_bytes: unknown;
}>;
