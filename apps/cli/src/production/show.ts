import { VaultReadSession, type VaultReadSourcePort } from '@kavrix/client';
import type { VaultRootKey } from '@kavrix/crypto';
import type { VaultId } from '@kavrix/schemas';

export type ProductionQueryOptions = Readonly<{
  source: VaultReadSourcePort;
  vaultId: VaultId;
  rootKey: VaultRootKey;
}>;

export async function executeProductionShow(
  options: ProductionQueryOptions,
  groupQuery: string,
  credentialQuery: string,
) {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  try {
    return await readSession.show(groupQuery, credentialQuery);
  } finally {
    readSession.lock();
  }
}
