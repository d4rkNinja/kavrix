import {
  VaultInteractionService,
  VaultReadSession,
  type CredentialCopyOptions,
  type CredentialCopyReceipt,
  type VaultReadSourcePort,
} from '@kavrix/client';
import type { SecureClipboard } from '@kavrix/clipboard';
import type { VaultRootKey } from '@kavrix/crypto';
import type { VaultId } from '@kavrix/schemas';

export const CLIPBOARD_CLEAR_MS = 30_000;

export type ProductionCopyOptions = Readonly<{
  source: VaultReadSourcePort;
  vaultId: VaultId;
  rootKey: VaultRootKey;
  clipboard: SecureClipboard;
  clearAfterMs?: number;
  /**
   * Cancels the copy when the invocation ends. The clipboard checks this before
   * writing and while verifying, so an interrupted command cannot leave a secret
   * on the clipboard that nothing is left alive to clear.
   */
  signal?: AbortSignal;
}>;

export async function executeProductionCopy(
  options: ProductionCopyOptions,
  groupQuery: string,
  credentialQuery: string,
  fieldQuery: string,
  copyOptions: CredentialCopyOptions = {},
): Promise<CredentialCopyReceipt> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  try {
    const service = new VaultInteractionService(readSession, options.clipboard, {
      clearAfterMs: options.clearAfterMs ?? CLIPBOARD_CLEAR_MS,
    });
    return await service.copy(groupQuery, credentialQuery, fieldQuery, {
      ...copyOptions,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  } finally {
    readSession.lock();
  }
}
