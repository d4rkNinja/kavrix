/**
 * The persistence ports are owned by @kavrix/core; this barrel re-exports
 * them so consumers can keep a single storage import. The adapters below
 * implement the core-owned ports.
 */
export { EncryptedVaultStoreError } from '@kavrix/core';
export type { EncryptedVaultStore, EncryptedVaultStoreErrorCode } from '@kavrix/core';
export { EncryptedDatabaseStoreError } from '@kavrix/core';
export type {
  CreateVaultInput,
  DeleteVaultInput,
  EncryptedDatabaseStore,
  EncryptedDatabaseStoreErrorCode,
  UpdateVaultInput,
} from '@kavrix/core';
export type {
  ActivateCollaborativeGenesisInput,
  BeginCollaborativeMigrationInput,
  CollaborativeProofPosition,
  CollaborativeVaultStore,
  CompactCollaborativeOperationOutcomeInput,
  DestroyCollaborativeVaultInput,
  GetCollaborativeMutationProofRangeInput,
  PublishCollaborativeVaultInput,
} from '@kavrix/core';
export {
  FileLocalVaultError,
  FileLocalVaultStore,
  MAX_FILE_LOCAL_VAULT_BYTES,
  type FileLocalVaultErrorCode,
} from './file-local-vault.js';
export {
  FileEncryptedDatabaseStore,
  MAX_FILE_ENCRYPTED_DATABASE_BYTES,
} from './file-encrypted-database.js';
export {
  assertMongoUriAllowed,
  MongoLocalVaultError,
  MongoLocalVaultStore,
  type MongoLocalVaultErrorCode,
  type MongoLocalVaultStoreOptions,
} from './mongo-local-vault.js';
export {
  MongoEncryptedDatabaseStore,
  type MongoEncryptedDatabaseStoreOptions,
} from './mongo-encrypted-database.js';
export { probeMongoConnection } from './mongo-connection-probe.js';
export {
  MongoCollaborativeVaultStore,
  type MongoCollaborativeVaultCollectionNames,
} from './collaborative-vault-store.js';
