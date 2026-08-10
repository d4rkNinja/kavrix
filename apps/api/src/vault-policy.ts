import { isDeepStrictEqual } from 'node:util';

import type { OpaqueMutation, VaultId, VaultRecord } from '@kavrix/schemas';

import { ApiNotFoundError, ApiValidationError } from './errors.js';
import type { ApiStoragePort } from './ports.js';

/**
 * Generic sync may update encrypted vault preferences, but key hierarchy and
 * recovery-slot changes must use the dedicated device-management endpoints.
 */
export async function assertSafeGenericVaultMutation(
  storage: ApiStoragePort,
  mutations: readonly OpaqueMutation[],
  vaultId: VaultId,
): Promise<void> {
  const vaultMutations = mutations.filter(
    (mutation): mutation is Extract<OpaqueMutation, { entityType: 'vault' }> =>
      mutation.entityType === 'vault',
  );
  if (vaultMutations.length === 0) return;
  if (vaultMutations.length !== 1) throw new ApiValidationError();

  const current = await storage.getVault(vaultId);
  if (current === null) throw new ApiNotFoundError();
  const mutation = vaultMutations[0];
  if (
    mutation?.record.id !== vaultId ||
    mutation.expectedVaultRevision === null ||
    mutation.record.revision !== mutation.expectedVaultRevision + 1 ||
    Date.parse(mutation.record.updatedAt) < Date.parse(current.updatedAt) ||
    !isDeepStrictEqual(
      protectedVaultFields(current),
      protectedVaultFields(mutation.record),
    )
  ) {
    throw new ApiValidationError();
  }
}

function protectedVaultFields(vault: VaultRecord): object {
  return {
    id: vault.id,
    schemaVersion: vault.schemaVersion,
    cryptographicVersion: vault.cryptographicVersion,
    keySlots: vault.keySlots,
    currentKeyVersion: vault.currentKeyVersion,
    createdAt: vault.createdAt,
  };
}
