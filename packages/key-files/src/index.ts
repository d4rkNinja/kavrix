export * from './errors.js';
export {
  SealedSecretStore,
  sealedEntryFactory,
  type SealedSecretStoreOptions,
} from './sealed-secret-store.js';
export { setWindowsUserOnlyAcl, verifyWindowsUserOnlyAcl } from './windows-acl.js';
export {
  MAX_SECURE_STREAM_CHUNK_BYTES,
  MAX_SECURE_STREAM_FILE_BYTES,
  deleteSecureFile,
  readSecureFile,
  validateSecureFileDestination,
  validateSecureFileSource,
  writeSecureStreamFile,
  type SecureFileStreamWriteResult,
} from './filesystem.js';
export {
  readProtectedJsonDocument,
  transitionProtectedJsonDocument,
  transitionProtectedJsonDocumentWithPublicationStatus,
  writeProtectedJsonDocument,
  ProtectedJsonDocumentError,
  type CanonicalJsonDocumentSchema,
  type ProtectedJsonDocumentOptions,
  type ProtectedJsonDocumentPublication,
  type ProtectedJsonDocumentTransition,
  type ProtectedJsonDocumentTransitionPublicationResult,
} from './canonical-json-document.js';
export {
  readPortableKeyFile,
  validatePortableKeyFile,
  writePortableKeyFile,
  type ParsedPortableKeyFile,
  type PortableKey,
  type PortableKeyFileBinding,
  type PortableKeyFileProtection,
  type PortableKeyFileWriteOptions,
} from './portable-key-files.js';
export {
  readRecoveryKitFile,
  writeRecoveryKitFile,
  type ParsedRecoveryKit,
  type RecoveryKitBinding,
} from './recovery-kit-files.js';
export {
  copyRevisionAnchor,
  readRevisionAnchor,
  validateRevisionAnchorFile,
  writeRevisionAnchor,
  type RevisionAnchor,
} from './revision-anchor.js';
export {
  cleanupOwnedDatabaseKeyFile,
  consumeDatabaseLocalShareBootstrap,
  createOwnedDatabaseKeyFile,
  createOwnedDatabaseLocalShareKeyFile,
  readDatabaseKeyFileBinding,
  readDatabaseKeyFile,
  writeDatabaseKeyFile,
  type DatabaseKeyBinding,
  type DatabaseKeyFileCreateOptions,
  type DatabaseKeyFileCreateResult,
  type DatabaseKeyFilePublication,
  type DatabaseKeyFileWriteOptions,
  type ParsedDatabaseKeyFile,
} from './database-key-files.js';
export {
  cleanupOwnedDatabaseRecoveryKitFile,
  createOwnedDatabaseRecoveryKitFile,
  readDatabaseRecoveryKitFileBinding,
  readDatabaseRecoveryKitFile,
  writeDatabaseRecoveryKitFile,
  type DatabaseRecoveryBinding,
  type DatabaseRecoveryKitCreateOptions,
  type DatabaseRecoveryKitFileCreateResult,
  type DatabaseRecoveryKitFilePublication,
  type DatabaseRecoveryKitWriteOptions,
  type ParsedDatabaseRecoveryKit,
} from './database-recovery-kit-files.js';
export {
  cleanupOwnedDatabaseRevisionAnchor,
  createOwnedDatabaseRevisionAnchor,
  databaseRevisionAnchorPath,
  databaseRevisionAnchorSchema,
  databaseVaultRevisionAnchorSchema,
  readDatabaseRevisionAnchor,
  transitionDatabaseRevisionAnchor,
  transitionOwnedDatabaseRevisionAnchor,
  verifyDatabaseRevisionAnchor,
  writeDatabaseRevisionAnchor,
  type DatabaseRevisionAnchor,
  type DatabaseRevisionAnchorCreateResult,
  type DatabaseRevisionAnchorPublication,
  type DatabaseRevisionAnchorVerificationOptions,
  type DatabaseRevisionAnchorTransitionResult,
  type DatabaseVaultRevisionAnchor,
  type OwnedDatabaseRevisionAnchorTransitionResult,
} from './database-revision-anchor.js';
