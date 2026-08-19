import type {
  DatabaseId,
  DatabaseRevision,
  DatabaseVaultDocument,
  EncryptedDatabaseDocument,
  VaultId,
  VaultRevision,
} from '@kavrix/schemas';

export type EncryptedDatabaseStoreErrorCode =
  | 'busy'
  | 'closed'
  | 'conflict'
  | 'connection'
  | 'exists'
  | 'invalid'
  | 'operation'
  | 'unsupported';

const ERROR_MESSAGES: Readonly<Record<EncryptedDatabaseStoreErrorCode, string>> = {
  busy: 'The database storage is busy.',
  closed: 'The database storage is closed.',
  conflict: 'The database changed while this operation was running.',
  connection: 'The database connection failed.',
  exists: 'A database record already exists.',
  invalid: 'The database operation is invalid.',
  operation: 'The database operation failed.',
  unsupported: 'This database operation is unsupported.',
};

/**
 * A redacted persistence failure. Public messages intentionally contain no
 * document content, datastore details, paths, or opaque identifiers.
 */
export class EncryptedDatabaseStoreError extends Error {
  readonly code: EncryptedDatabaseStoreErrorCode;

  constructor(code: EncryptedDatabaseStoreErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = 'EncryptedDatabaseStoreError';
    this.code = code;
  }
}

export type CreateVaultInput = Readonly<{
  database: EncryptedDatabaseDocument;
  expectedDatabaseRevision: DatabaseRevision;
  vault: DatabaseVaultDocument;
}>;

export type UpdateVaultInput = Readonly<{
  vault: DatabaseVaultDocument;
  expectedVaultRevision: VaultRevision;
}>;

export type DeleteVaultInput = Readonly<{
  database: EncryptedDatabaseDocument;
  expectedDatabaseRevision: DatabaseRevision;
  vaultId: VaultId;
  expectedVaultRevision: VaultRevision;
}>;

/**
 * Opaque persistence boundary for one encrypted database and its vaults.
 *
 * An adapter must validate documents at its trust boundary, never interpret
 * encrypted content, return detached values, compare every supplied revision
 * exactly, and reject use after close. A successful database mutation advances
 * the database document revision by exactly one. A successful vault mutation
 * advances the vault document revision by exactly one. Catalog-plus-vault
 * create and delete operations publish both supplied database state and vault
 * state atomically. For a mutation, `conflict`, `exists`, and `invalid` prove
 * that no write was accepted. Every other rejection after the adapter was
 * entered has an unknown commit outcome and callers must fail closed.
 */
export interface EncryptedDatabaseStore {
  ping(): Promise<void>;
  getDatabase(databaseId: DatabaseId): Promise<EncryptedDatabaseDocument | null>;
  createDatabase(document: EncryptedDatabaseDocument): Promise<void>;
  updateDatabase(
    document: EncryptedDatabaseDocument,
    expectedRevision: DatabaseRevision,
  ): Promise<void>;
  listVaults(databaseId: DatabaseId): Promise<readonly DatabaseVaultDocument[]>;
  getVault(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<DatabaseVaultDocument | null>;
  createVault(input: CreateVaultInput): Promise<void>;
  updateVault(input: UpdateVaultInput): Promise<void>;
  deleteVault(input: DeleteVaultInput): Promise<void>;
  close(): Promise<void>;
}
