import {
  syncPullResponseSchema,
  syncPushResponseSchema,
  templateMigrationPublicationResponseSchema,
  type ChangeRecord,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type SyncCursor,
  type SyncPullResponse,
  type SyncPushRequest,
  type SyncPushResponse,
  type TemplateMigrationPublicationRequest,
  type TemplateMigrationPublicationResponse,
  type VaultId,
} from '@kavrix/schemas';

export function validatePullPage(
  candidate: unknown,
  vaultId: VaultId,
  previousCursor: SyncCursor,
  limit: number,
): SyncPullResponse {
  const page = syncPullResponseSchema.parse(candidate);
  if (
    page.vaultId !== vaultId ||
    page.changes.length > limit ||
    page.serverVaultRevision < previousCursor.highestSeenVaultRevision
  ) {
    throw new Error('Storage returned an invalid sync page boundary');
  }
  let expectedSequence = previousCursor.serverSequence + 1;
  for (const { change } of page.changes) {
    if (change.serverSequence !== expectedSequence) {
      throw new Error('Storage returned a non-contiguous sync page');
    }
    expectedSequence += 1;
  }
  if (page.nextCursor.serverSequence !== expectedSequence - 1) {
    throw new Error('Storage returned an invalid next sync cursor');
  }
  return page;
}

export function validatePushBatch(
  candidate: unknown,
  request: SyncPushRequest,
): SyncPushResponse {
  const response = syncPushResponseSchema.parse(candidate);
  if (
    response.vaultId !== request.vaultId ||
    response.batchIdempotencyKey !== request.batchIdempotencyKey ||
    response.results.length !== request.mutations.length
  ) {
    throw new Error('Storage returned an invalid sync batch boundary');
  }
  for (const [index, result] of response.results.entries()) {
    const mutation = request.mutations[index];
    if (mutation?.idempotencyKey !== result.idempotencyKey) {
      throw new Error('Storage returned sync results out of request order');
    }
    if (result.status === 'accepted') {
      validateAcceptedChange(result.change, mutation, request.vaultId);
    } else if (
      result.current !== null &&
      (!recordMatchesMutation(result.current, mutation, request.vaultId) ||
        recordRevision(result.current) !== result.currentRevision)
    ) {
      throw new Error('Storage returned a conflict for a different record');
    }
  }
  return response;
}

export function validateTemplateMigrationPublication(
  candidate: unknown,
  request: TemplateMigrationPublicationRequest,
): TemplateMigrationPublicationResponse {
  const response = templateMigrationPublicationResponseSchema.parse(candidate);
  if (
    response.vaultId !== request.vaultId ||
    response.batchIdempotencyKey !== request.batchIdempotencyKey ||
    response.results.length !== request.mutations.length
  ) {
    throw new Error('Storage returned an invalid template migration boundary');
  }
  for (const [index, result] of response.results.entries()) {
    const mutation = request.mutations[index];
    if (mutation?.idempotencyKey !== result.idempotencyKey) {
      throw new Error('Storage acknowledged a different template migration');
    }
    if (
      result.change.vaultId !== request.vaultId ||
      result.change.entityType !== mutation.entityType ||
      result.change.entityId !== mutation.record.id ||
      result.change.recordRevision !== mutationRevision(mutation) ||
      result.change.operation !== 'upsert'
    ) {
      throw new Error('Storage acknowledged a different template migration');
    }
  }
  return response;
}

function validateAcceptedChange(
  change: ChangeRecord,
  mutation: OpaqueMutation,
  vaultId: VaultId,
): void {
  if (
    change.vaultId !== vaultId ||
    change.entityType !== mutation.entityType ||
    change.entityId !== mutation.record.id ||
    change.recordRevision !== mutationRevision(mutation) ||
    !acceptedOperationMatches(change.operation, mutation)
  ) {
    throw new Error('Storage acknowledged a different mutation');
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

function recordMatchesMutation(
  record: OpaqueSyncRecord,
  mutation: OpaqueMutation,
  vaultId: VaultId,
): boolean {
  return (
    recordVaultId(record) === vaultId &&
    recordEntityType(record) === mutation.entityType &&
    recordId(record) === mutation.record.id
  );
}

function isTombstone(
  record: OpaqueSyncRecord,
): record is Extract<OpaqueSyncRecord, { state: 'deleted' | 'restored' }> {
  return 'state' in record;
}

function recordVaultId(record: OpaqueSyncRecord): VaultId {
  return 'vaultId' in record ? record.vaultId : record.id;
}

function recordId(record: OpaqueSyncRecord): string {
  return isTombstone(record) ? record.entityId : record.id;
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

function mutationRevision(mutation: OpaqueMutation): number {
  return mutation.entityType === 'vault'
    ? mutation.record.revision
    : mutation.record.recordRevision;
}
