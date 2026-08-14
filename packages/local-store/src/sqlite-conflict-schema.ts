import {
  syncConflictResolutionSchema,
  type SyncConflictResolution,
} from '@kavrix/schemas';
import type {
  ResolveSyncConflictInput,
  SyncConflictResolutionStrategy,
} from '@kavrix/sync';

export const SYNC_CONFLICT_SCHEMA_DEFINITIONS = {
  sync_conflicts: `CREATE TABLE sync_conflicts (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('vault','group','item')),
    entity_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    mutation_json TEXT NOT NULL,
    current_revision INTEGER NOT NULL CHECK(current_revision >= 0),
    current_json TEXT,
    resolution_json TEXT,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2)
  ) STRICT`,
  sync_conflicts_vault_sequence: `CREATE INDEX sync_conflicts_vault_sequence
    ON sync_conflicts(vault_id, sequence)`,
} as const;

export type PersistedConflictRow = Readonly<{
  sequence?: unknown;
  vault_id: unknown;
  entity_type: unknown;
  entity_id: unknown;
  idempotency_key: unknown;
  mutation_json: unknown;
  current_revision: unknown;
  current_json: unknown;
  resolution_json: unknown;
  serialized_bytes: unknown;
}>;

export const conflictResolutionSchema = syncConflictResolutionSchema;

export type ConflictResolution = SyncConflictResolution;

export type ConflictResolutionStrategy = SyncConflictResolutionStrategy;

export function resolutionFromInput(
  input: ResolveSyncConflictInput,
): ConflictResolution {
  return conflictResolutionSchema.parse({
    version: 1,
    strategy: input.strategy,
    currentRevision: input.currentRevision,
    replacementIdempotencyKey: input.replacementIdempotencyKey,
    resolvedAt: input.resolvedAt,
  });
}
