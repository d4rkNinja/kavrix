import type { LocalVaultDocument } from '@kavrix/schemas';

export type EncryptedVaultStoreErrorCode =
  'busy' | 'closed' | 'conflict' | 'connection' | 'exists' | 'invalid' | 'operation';

export class EncryptedVaultStoreError extends Error {
  readonly code: EncryptedVaultStoreErrorCode;

  constructor(code: EncryptedVaultStoreErrorCode, message: string) {
    super(message);
    this.name = 'EncryptedVaultStoreError';
    this.code = code;
  }
}

/**
 * Persistence boundary for the canonical, already-encrypted local vault document.
 * Implementations must not interpret or transform encrypted payload contents.
 */
export interface EncryptedVaultStore {
  ping(): Promise<void>;
  get(vaultId: string): Promise<LocalVaultDocument | null>;
  listVaultIds(): Promise<string[]>;
  create(document: LocalVaultDocument): Promise<void>;
  update(
    document: LocalVaultDocument,
    expectedRevision: LocalVaultDocument['revision'],
  ): Promise<void>;
  delete(
    vaultId: string,
    expectedRevision: LocalVaultDocument['revision'],
  ): Promise<void>;
  close(): Promise<void>;
}
