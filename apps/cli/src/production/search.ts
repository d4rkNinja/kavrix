import { VaultReadSession, type VaultReadSourcePort } from '@kavrix/client';
import { searchVault, type VaultSearchResult } from '@kavrix/core';
import type { VaultRootKey } from '@kavrix/crypto';
import type { VaultId } from '@kavrix/schemas';

import type { CliVaultSearchRequest } from '../mutation-contracts.js';

export type ProductionSearchOptions = Readonly<{
  source: VaultReadSourcePort;
  vaultId: VaultId;
  rootKey: VaultRootKey;
}>;

/**
 * Runs a local search against the unlocked vault.
 *
 * Reading and matching are separate concerns and stay that way: the read session
 * owns decryption and key lifetime, and the core policy owns what may be matched
 * and what may be reported. Nothing is indexed, cached, or written — the
 * decrypted payloads live only for the duration of this call, and the session is
 * locked before it returns whether or not the scan succeeded.
 */
export async function executeProductionVaultSearch(
  options: ProductionSearchOptions,
  request: CliVaultSearchRequest,
): Promise<VaultSearchResult> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  try {
    const scopes = await readSession.listScopes(request.groupQuery);
    return searchVault(
      scopes.map(({ group, items }) => ({ group, credentials: items })),
      request.term,
      {
        includeSecretValues: request.includeSecretValues,
        includeArchived: request.includeArchived,
        ...(request.limit === undefined ? {} : { limit: request.limit }),
      },
    );
  } finally {
    readSession.lock();
  }
}
