import {
  contentHashForRecord,
  opaqueMutationSchema,
  recordRevisionSchema,
  syncCursorSchema,
  syncPullResponseSchema,
  syncPushResponseSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  vaultRevisionSchema,
} from '@kavrix/schemas';
import type {
  ChangeRecord,
  OpaqueMutation,
  RecordRevision,
  VaultId,
  VaultRevision,
  TemplateMigrationPublicationRequest,
  TemplateMigrationPublicationResponse,
} from '@kavrix/schemas';

import { SyncLocalStateError, SyncProtocolError } from './errors.js';
import type {
  ActivePushBatch,
  OpaqueSyncRecord,
  PullPageResponse,
  PushBatchResponse,
  PushMutationResult,
  SyncCursor,
} from './types.js';

const IDEMPOTENCY_KEY_MIN_LENGTH = 16;
const IDEMPOTENCY_KEY_MAX_LENGTH = 256;

export function parseCursor(value: unknown, vaultId: VaultId): SyncCursor {
  const result = syncCursorSchema.safeParse(value);
  if (!result.success || result.data.vaultId !== vaultId)
    throw new SyncLocalStateError();
  return result.data;
}

export function validatePendingMutations(
  values: readonly OpaqueMutation[],
  vaultId: VaultId,
): readonly OpaqueMutation[] {
  const keys = new Set<string>();
  return values.map((value) => {
    const result = opaqueMutationSchema.safeParse(value);
    if (!result.success) throw new SyncLocalStateError();
    const mutation = result.data;
    if (
      mutationVaultId(mutation) !== vaultId ||
      keys.has(mutation.idempotencyKey) ||
      mutationRecordRevision(mutation) !== expectedNextMutationRevision(mutation)
    ) {
      throw new SyncLocalStateError();
    }
    keys.add(mutation.idempotencyKey);
    return mutation;
  });
}

export function validateActiveBatch(
  value: ActivePushBatch,
  vaultId: VaultId,
): ActivePushBatch {
  if (
    !hasExactKeys(value, [
      'vaultId',
      'batchIdempotencyKey',
      'mutationIdempotencyKeys',
    ]) ||
    value.vaultId !== vaultId ||
    !isIdempotencyKey(value.batchIdempotencyKey) ||
    !Array.isArray(value.mutationIdempotencyKeys) ||
    value.mutationIdempotencyKeys.length === 0 ||
    value.mutationIdempotencyKeys.some((key) => !isIdempotencyKey(key)) ||
    new Set(value.mutationIdempotencyKeys).size !== value.mutationIdempotencyKeys.length
  ) {
    throw new SyncLocalStateError();
  }
  return value;
}

export function validateGeneratedIdempotencyKey(value: string): string {
  if (!isIdempotencyKey(value)) throw new SyncLocalStateError();
  return value;
}

export function parsePullPage(
  value: unknown,
  requestVaultId: VaultId,
  previousCursor: SyncCursor,
  limit: number,
): PullPageResponse {
  const result = syncPullResponseSchema.safeParse(value);
  if (
    !result.success ||
    result.data.vaultId !== requestVaultId ||
    result.data.changes.length > limit
  ) {
    throw new SyncProtocolError();
  }

  let expectedSequence = previousCursor.serverSequence + 1;
  for (const pulled of result.data.changes) {
    if (pulled.change.serverSequence !== expectedSequence) {
      throw new SyncProtocolError();
    }
    if (
      (pulled.change.operation === 'upsert' || pulled.change.operation === 'restore') &&
      (pulled.record === null ||
        isTombstone(pulled.record) ||
        pulled.change.ciphertextHash !== contentHashForRecord(pulled.record))
    ) {
      throw new SyncProtocolError();
    }
    expectedSequence += 1;
  }
  const expectedLastSequence = expectedSequence - 1;
  if (result.data.nextCursor.serverSequence !== expectedLastSequence) {
    throw new SyncProtocolError();
  }
  return result.data;
}

export function parsePushResponse(
  value: unknown,
  vaultId: VaultId,
  batchIdempotencyKey: string,
  mutations: readonly OpaqueMutation[],
): PushBatchResponse {
  const parsedResponse = syncPushResponseSchema.safeParse(value);
  if (
    !parsedResponse.success ||
    parsedResponse.data.vaultId !== vaultId ||
    parsedResponse.data.batchIdempotencyKey !== batchIdempotencyKey ||
    parsedResponse.data.results.length !== mutations.length
  ) {
    throw new SyncProtocolError();
  }

  const results = parsedResponse.data.results.map((candidate, index) => {
    const mutation = mutations[index];
    if (mutation === undefined) throw new SyncProtocolError();
    return parsePushResult(candidate, mutation, vaultId);
  });
  return {
    vaultId,
    serverVaultRevision: parsedResponse.data.serverVaultRevision,
    batchIdempotencyKey,
    results,
  };
}

export function validatePendingTemplateMigrationPublication(
  value: unknown,
  vaultId: VaultId,
): TemplateMigrationPublicationRequest {
  const result = templateMigrationPublicationRequestSchema.safeParse(value);
  if (!result.success || result.data.vaultId !== vaultId) {
    throw new SyncLocalStateError();
  }
  return result.data;
}

export function parseTemplateMigrationPublicationResponse(
  value: unknown,
  publication: TemplateMigrationPublicationRequest,
): TemplateMigrationPublicationResponse {
  const parsed = templateMigrationPublicationResponseSchema.safeParse(value);
  if (
    !parsed.success ||
    parsed.data.vaultId !== publication.vaultId ||
    parsed.data.batchIdempotencyKey !== publication.batchIdempotencyKey ||
    parsed.data.results.length !== publication.mutations.length
  ) {
    throw new SyncProtocolError();
  }
  for (const [index, result] of parsed.data.results.entries()) {
    const mutation = publication.mutations[index];
    if (mutation === undefined) throw new SyncProtocolError();
    if (
      result.idempotencyKey !== mutation.idempotencyKey ||
      result.change.vaultId !== publication.vaultId ||
      result.change.entityType !== mutation.entityType ||
      result.change.entityId !== mutation.record.id ||
      result.change.recordRevision !== mutationRecordRevision(mutation) ||
      result.change.operation !== 'upsert' ||
      result.change.ciphertextHash !== contentHashForRecord(mutation.record)
    ) {
      throw new SyncProtocolError();
    }
  }
  return parsed.data;
}

function parsePushResult(
  value: PushMutationResult,
  mutation: OpaqueMutation,
  vaultId: VaultId,
): PushMutationResult {
  if (value.idempotencyKey !== mutation.idempotencyKey) {
    throw new SyncProtocolError();
  }
  if (value.status === 'accepted') {
    validateAcceptedChange(value.change, mutation, vaultId);
    return value;
  }
  const revision =
    mutation.entityType === 'vault'
      ? vaultRevisionSchema.safeParse(value.currentRevision)
      : recordRevisionSchema.safeParse(value.currentRevision);
  if (!revision.success) throw new SyncProtocolError();
  const current = value.current;
  if (current !== null) {
    validateCurrentBinding(current, mutation, vaultId);
    if (recordRevision(current) !== revision.data) {
      throw new SyncProtocolError();
    }
  }
  return {
    status: 'conflict',
    idempotencyKey: mutation.idempotencyKey,
    currentRevision: revision.data,
    current,
  };
}

function validateAcceptedChange(
  change: ChangeRecord,
  mutation: OpaqueMutation,
  vaultId: VaultId,
): void {
  const identity = mutationIdentity(mutation);
  const revision = mutationRecordRevision(mutation);
  if (
    change.vaultId !== vaultId ||
    change.entityType !== mutation.entityType ||
    change.entityId !== identity ||
    !acceptedOperationMatches(change.operation, mutation) ||
    change.recordRevision !== revision ||
    change.ciphertextHash !== contentHashForRecord(mutation.record)
  ) {
    throw new SyncProtocolError();
  }
}

function acceptedOperationMatches(
  operation: ChangeRecord['operation'],
  mutation: OpaqueMutation,
): boolean {
  if (mutation.entityType === 'vault') return operation === 'upsert';
  if (mutation.record.tombstonedAt !== undefined) return operation === 'tombstone';
  return operation === 'upsert' || operation === 'restore';
}

function validateCurrentBinding(
  record: OpaqueSyncRecord,
  mutation: OpaqueMutation,
  vaultId: VaultId,
): void {
  if (
    recordVaultId(record) !== vaultId ||
    recordEntityType(record) !== mutation.entityType ||
    recordIdentity(record) !== mutationIdentity(mutation)
  ) {
    throw new SyncProtocolError();
  }
}

function isTombstone(
  record: OpaqueSyncRecord,
): record is Extract<OpaqueSyncRecord, { state: 'deleted' | 'restored' }> {
  return 'state' in record;
}

function recordVaultId(record: OpaqueSyncRecord): VaultId {
  return 'vaultId' in record ? record.vaultId : record.id;
}

function recordIdentity(record: OpaqueSyncRecord): string {
  if (isTombstone(record)) return record.entityId;
  return record.id;
}

function recordEntityType(record: OpaqueSyncRecord): ChangeRecord['entityType'] {
  if (isTombstone(record)) return record.entityType;
  if ('revision' in record) return 'vault';
  if ('itemId' in record) return 'attachment';
  if ('groupId' in record) return 'item';
  return 'group';
}

function recordRevision(record: OpaqueSyncRecord): number {
  if (isTombstone(record)) return record.tombstoneRevision;
  return 'revision' in record ? record.revision : record.recordRevision;
}

function mutationVaultId(mutation: OpaqueMutation): VaultId {
  return mutation.entityType === 'vault' ? mutation.record.id : mutation.record.vaultId;
}

function mutationIdentity(mutation: OpaqueMutation): string {
  return mutation.record.id;
}

function mutationRecordRevision(mutation: OpaqueMutation): number {
  return mutation.entityType === 'vault'
    ? mutation.record.revision
    : mutation.record.recordRevision;
}

function expectedNextMutationRevision(mutation: OpaqueMutation): number {
  const expected =
    mutation.entityType === 'vault'
      ? mutation.expectedVaultRevision
      : mutation.expectedRecordRevision;
  return expected === null ? 0 : expected + 1;
}

function isIdempotencyKey(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= IDEMPOTENCY_KEY_MIN_LENGTH &&
    value.length <= IDEMPOTENCY_KEY_MAX_LENGTH
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  if (!isObject(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => key in value);
}

export function asVaultRevision(value: number): VaultRevision {
  const result = vaultRevisionSchema.safeParse(value);
  if (!result.success) throw new SyncLocalStateError();
  return result.data;
}

export type RevisionNumber = RecordRevision | VaultRevision;
