import {
  opaqueMutationSchema,
  syncPushRequestSchema,
  timestampSchema,
  type OpaqueMutation,
  type Timestamp,
  type VaultId,
} from '@kavrix/schemas';

import { ApiConflictError, ApiValidationError } from './errors.js';
import type { ApiStoragePort } from './ports.js';
import { validatePushBatch } from './sync-validation.js';

export function timestamp(date: Date): Timestamp {
  return timestampSchema.parse(date.toISOString());
}

export function addSeconds(date: Date, seconds: number): Timestamp {
  return timestamp(new Date(date.getTime() + seconds * 1_000));
}

export function requireMutationVault(
  mutation: OpaqueMutation,
  vaultId: VaultId,
): OpaqueMutation {
  const parsed = opaqueMutationSchema.parse(mutation);
  if (mutationVaultId(parsed) !== vaultId) {
    throw new ApiValidationError();
  }
  return parsed;
}

export function mutationVaultId(mutation: OpaqueMutation): VaultId {
  return mutation.entityType === 'vault' ? mutation.record.id : mutation.record.vaultId;
}

export async function commitOpaqueMutation(
  storage: ApiStoragePort,
  mutation: OpaqueMutation,
): Promise<void> {
  const vaultId = mutationVaultId(mutation);
  const batch = syncPushRequestSchema.parse({
    vaultId,
    batchIdempotencyKey: mutation.idempotencyKey,
    mutations: [mutation],
  });
  const response = validatePushBatch(await storage.pushSyncBatch(batch), batch);
  const result = response.results[0];
  if (result === undefined) {
    throw new Error('Storage omitted a direct mutation result');
  }
  if (result.status === 'conflict') {
    throw new ApiConflictError(
      mutation.entityType,
      mutation.record.id,
      mutation.entityType === 'vault'
        ? mutation.expectedVaultRevision
        : mutation.expectedRecordRevision,
      result.currentRevision,
    );
  }
}
