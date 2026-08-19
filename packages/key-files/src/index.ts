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
  writeProtectedJsonDocument,
  ProtectedJsonDocumentError,
  type CanonicalJsonDocumentSchema,
  type ProtectedJsonDocumentOptions,
  type ProtectedJsonDocumentTransition,
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
  readDatabaseKeyFile,
  writeDatabaseKeyFile,
  type DatabaseKeyBinding,
  type DatabaseKeyFileWriteOptions,
  type ParsedDatabaseKeyFile,
} from './database-key-files.js';
export {
  readDatabaseRecoveryKitFile,
  writeDatabaseRecoveryKitFile,
  type DatabaseRecoveryBinding,
  type DatabaseRecoveryKitWriteOptions,
  type ParsedDatabaseRecoveryKit,
} from './database-recovery-kit-files.js';
export {
  databaseRevisionAnchorPath,
  databaseRevisionAnchorSchema,
  databaseVaultRevisionAnchorSchema,
  readDatabaseRevisionAnchor,
  transitionDatabaseRevisionAnchor,
  verifyDatabaseRevisionAnchor,
  writeDatabaseRevisionAnchor,
  type DatabaseRevisionAnchor,
  type DatabaseRevisionAnchorVerificationOptions,
  type DatabaseRevisionAnchorTransitionResult,
  type DatabaseVaultRevisionAnchor,
} from './database-revision-anchor.js';
