import type { DatabaseSync } from 'node:sqlite';

import type { ItemMutationState } from '@kavrix/client';
import {
  contentHashForRecord,
  encryptedAttachmentRecordSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  opaqueMutationSchema,
  opaqueSyncRecordSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  tombstoneRecordSchema,
  vaultRecordSchema,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type HashableOpaqueRecord,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type TemplateMigrationPublicationRequest,
  type TemplateMigrationPublicationResponse,
  type TombstoneRecord,
  type VaultId,
} from '@kavrix/schemas';
import { SyncLocalStateError } from '@kavrix/sync';

import type {
  CurrentState,
  EntityType,
  PersistedMutationRow,
  PersistedPredecessorRow,
  PersistedPublicationRow,
  PersistedRecordRow,
} from './sqlite-vault-schema.js';

export function parseMutationInput(input: unknown): OpaqueMutation {
  const parsed = opaqueMutationSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  const mutation = parsed.data;
  const expected =
    mutation.entityType === 'vault'
      ? mutation.expectedVaultRevision
      : mutation.expectedRecordRevision;
  if (
    activeRecordRevision(mutation.record) !== (expected === null ? 0 : expected + 1)
  ) {
    throw invalidState();
  }
  return mutation;
}

export function parseMutationRow(
  row: PersistedMutationRow,
  vaultId: VaultId,
  entityType: EntityType,
  entityId: string,
): OpaqueMutation {
  if (
    row.vault_id !== vaultId ||
    row.entity_type !== entityType ||
    row.entity_id !== entityId ||
    typeof row.idempotency_key !== 'string' ||
    typeof row.mutation_json !== 'string' ||
    getInteger(row, 'serialized_bytes') !== Buffer.byteLength(row.mutation_json)
  ) {
    throw invalidState();
  }
  const mutation = parseMutationInput(parseJson(row.mutation_json));
  if (
    mutationVaultId(mutation) !== vaultId ||
    mutation.entityType !== entityType ||
    mutation.record.id !== entityId ||
    mutation.idempotencyKey !== row.idempotency_key ||
    JSON.stringify(mutation) !== row.mutation_json
  ) {
    throw invalidState();
  }
  return mutation;
}

export function parseRecordRow(
  row: PersistedRecordRow,
  vaultId: VaultId,
  entityType: EntityType,
  entityId: string,
): OpaqueSyncRecord {
  if (
    row.vault_id !== vaultId ||
    row.entity_type !== entityType ||
    row.entity_id !== entityId ||
    typeof row.record_json !== 'string' ||
    getInteger(row, 'serialized_bytes') !== Buffer.byteLength(row.record_json)
  ) {
    throw invalidState();
  }
  const record = parseOpaqueRecord(parseJson(row.record_json));
  if (
    recordVaultId(record) !== vaultId ||
    recordEntityType(record) !== entityType ||
    recordIdentity(record) !== entityId ||
    syncRecordRevision(record) !== getInteger(row, 'revision') ||
    JSON.stringify(record) !== row.record_json
  ) {
    throw invalidState();
  }
  return record;
}

export function parsePredecessorRow(
  row: PersistedPredecessorRow,
  vaultId: VaultId,
  entityType: EntityType,
  entityId: string,
  ownerKey: string,
): HashableOpaqueRecord {
  if (
    row.vault_id !== vaultId ||
    row.entity_type !== entityType ||
    row.entity_id !== entityId ||
    row.owner_key !== ownerKey ||
    typeof row.record_json !== 'string' ||
    getInteger(row, 'serialized_bytes') !== Buffer.byteLength(row.record_json)
  ) {
    throw invalidState();
  }
  const record = parseActiveRecord(parseJson(row.record_json));
  if (
    recordVaultId(record) !== vaultId ||
    recordEntityType(record) !== entityType ||
    recordIdentity(record) !== entityId ||
    activeRecordRevision(record) !== getInteger(row, 'revision') ||
    JSON.stringify(record) !== row.record_json
  ) {
    throw invalidState();
  }
  return record;
}

export function parsePublication(input: unknown): TemplateMigrationPublicationRequest {
  const parsed = templateMigrationPublicationRequestSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

export function parsePublicationRow(
  row: PersistedPublicationRow,
  vaultId: VaultId,
): TemplateMigrationPublicationRequest {
  if (
    row.vault_id !== vaultId ||
    typeof row.batch_key !== 'string' ||
    typeof row.publication_json !== 'string' ||
    getInteger(row, 'serialized_bytes') !== Buffer.byteLength(row.publication_json)
  ) {
    throw invalidState();
  }
  const publication = parsePublication(parseJson(row.publication_json));
  if (
    publication.vaultId !== vaultId ||
    publication.batchIdempotencyKey !== row.batch_key ||
    JSON.stringify(publication) !== row.publication_json
  ) {
    throw invalidState();
  }
  return publication;
}

export function parsePublicationResponse(
  input: unknown,
  publication: TemplateMigrationPublicationRequest,
): TemplateMigrationPublicationResponse {
  const parsed = templateMigrationPublicationResponseSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  const response = parsed.data;
  if (
    response.vaultId !== publication.vaultId ||
    response.batchIdempotencyKey !== publication.batchIdempotencyKey ||
    response.results.length !== publication.mutations.length
  ) {
    throw invalidState();
  }
  for (const [index, result] of response.results.entries()) {
    const mutation = publication.mutations[index];
    if (
      mutation?.idempotencyKey === undefined ||
      result.idempotencyKey !== mutation.idempotencyKey ||
      result.change.vaultId !== publication.vaultId ||
      result.change.entityType !== mutation.entityType ||
      result.change.entityId !== mutation.record.id ||
      result.change.recordRevision !== activeRecordRevision(mutation.record) ||
      result.change.ciphertextHash !== contentHashForRecord(mutation.record) ||
      result.change.operation !== 'upsert'
    ) {
      throw invalidState();
    }
  }
  return response;
}

export function parseOpaqueRecord(input: unknown): OpaqueSyncRecord {
  const parsed = opaqueSyncRecordSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

export function parseActiveRecord(input: unknown): HashableOpaqueRecord {
  for (const schema of [
    vaultRecordSchema,
    encryptedGroupRecordSchema,
    encryptedItemRecordSchema,
    encryptedAttachmentRecordSchema,
  ] as const) {
    const parsed = schema.safeParse(input);
    if (parsed.success) {
      if ('tombstonedAt' in parsed.data && parsed.data.tombstonedAt !== undefined) {
        throw invalidState();
      }
      return parsed.data;
    }
  }
  throw invalidState();
}

export function synthesizeTombstone(
  mutation: Extract<OpaqueMutation, { entityType: 'group' | 'item' }>,
  predecessor: HashableOpaqueRecord,
): TombstoneRecord {
  const deletedAt = mutation.record.tombstonedAt;
  if (deletedAt === undefined) throw invalidState();
  const tombstone = tombstoneRecordSchema.safeParse({
    vaultId: mutation.record.vaultId,
    entityType: mutation.entityType,
    entityId: mutation.record.id,
    state: 'deleted',
    tombstoneRevision: mutation.record.recordRevision,
    lastRecordRevision: activeRecordRevision(predecessor),
    lastCiphertextHash: contentHashForRecord(predecessor),
    deletedAt,
  });
  if (!tombstone.success) throw invalidState();
  assertTombstonePredecessor(tombstone.data, predecessor);
  return tombstone.data;
}

export function assertTombstonePredecessor(
  tombstone: TombstoneRecord,
  predecessor: HashableOpaqueRecord,
): void {
  if (
    tombstone.vaultId !== recordVaultId(predecessor) ||
    tombstone.entityType !== recordEntityType(predecessor) ||
    tombstone.entityId !== recordIdentity(predecessor) ||
    tombstone.lastRecordRevision !== activeRecordRevision(predecessor) ||
    tombstone.lastCiphertextHash !== contentHashForRecord(predecessor)
  ) {
    throw invalidState();
  }
}

export function samePulledState(
  state: CurrentState,
  record: OpaqueSyncRecord | null,
): boolean {
  if (record === null) return false;
  return state.state === 'active'
    ? JSON.stringify(state.record) === JSON.stringify(record)
    : JSON.stringify(state.tombstone) === JSON.stringify(record);
}

export function isDeleteMutation(
  mutation: OpaqueMutation,
): mutation is Extract<OpaqueMutation, { entityType: 'group' | 'item' }> {
  return mutation.entityType !== 'vault' && mutation.record.tombstonedAt !== undefined;
}

export function isTombstone(record: OpaqueSyncRecord): record is TombstoneRecord {
  return 'state' in record;
}

export function mutationVaultId(mutation: OpaqueMutation): VaultId {
  return mutation.entityType === 'vault' ? mutation.record.id : mutation.record.vaultId;
}

export function recordVaultId(
  record: OpaqueSyncRecord | HashableOpaqueRecord,
): VaultId {
  return 'vaultId' in record ? record.vaultId : record.id;
}

export function recordIdentity(
  record: OpaqueSyncRecord | HashableOpaqueRecord,
): string {
  return 'state' in record ? record.entityId : record.id;
}

export function recordEntityType(
  record: OpaqueSyncRecord | HashableOpaqueRecord,
): EntityType {
  if ('state' in record) return record.entityType;
  if ('revision' in record) return 'vault';
  if ('itemId' in record) return 'attachment';
  if ('groupId' in record) return 'item';
  return 'group';
}

export function activeRecordRevision(record: HashableOpaqueRecord): number {
  return 'revision' in record ? record.revision : record.recordRevision;
}

export function syncRecordRevision(record: OpaqueSyncRecord): number {
  return isTombstone(record) ? record.tombstoneRevision : activeRecordRevision(record);
}

export function stateRevision(state: CurrentState): number {
  return state.state === 'active'
    ? activeRecordRevision(state.record)
    : state.tombstone.tombstoneRevision;
}

export function stateRecord(state: ItemMutationState): EncryptedItemRecord {
  return state.state === 'active' ? state.record : state.predecessor;
}

export function requireGroupTombstone(
  tombstone: TombstoneRecord,
): Extract<TombstoneRecord, { entityType: 'group' }> {
  if (tombstone.entityType !== 'group') throw invalidState();
  return tombstone;
}

export function requireItemTombstone(
  tombstone: TombstoneRecord,
): Extract<TombstoneRecord, { entityType: 'item' }> {
  if (tombstone.entityType !== 'item') throw invalidState();
  return tombstone;
}

export function encodeBounded(
  value: unknown,
  maxBytes: number,
): Readonly<{ json: string; bytes: number }> {
  const json = JSON.stringify(value);
  if (typeof json !== 'string') throw invalidState();
  const bytes = Buffer.byteLength(json);
  if (bytes < 2 || bytes > maxBytes) throw invalidState();
  return { json, bytes };
}

export function parseJson(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw invalidState();
  }
}

export function countRows(
  database: DatabaseSync,
  table: string,
  vaultId?: VaultId,
): number {
  const row =
    vaultId === undefined
      ? database.prepare(`SELECT COUNT(*) AS value FROM ${table}`).get()
      : database
          .prepare(`SELECT COUNT(*) AS value FROM ${table} WHERE vault_id = ?`)
          .get(vaultId);
  return getInteger(row, 'value');
}

export function getInteger(row: unknown, key: string): number {
  if (typeof row !== 'object' || row === null || !(key in row)) {
    throw invalidState();
  }
  const value = (row as Record<string, unknown>)[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw invalidState();
  }
  return value;
}

export function required<Value>(value: Value | null | undefined): Value {
  if (value === null || value === undefined) throw invalidState();
  return value;
}

export function invalidState(): SyncLocalStateError {
  return new SyncLocalStateError();
}

export type { EncryptedGroupRecord, EncryptedItemRecord };
