export * from './errors.js';
export {
  SealedSecretStore,
  sealedEntryFactory,
  type SealedSecretStoreOptions,
} from './sealed-secret-store.js';
export { setWindowsUserOnlyAcl } from './windows-acl.js';
export {
  MAX_SECURE_STREAM_CHUNK_BYTES,
  MAX_SECURE_STREAM_FILE_BYTES,
  readSecureFile,
  validateSecureFileDestination,
  validateSecureFileSource,
  writeSecureStreamFile,
  type SecureFileStreamWriteResult,
} from './filesystem.js';
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
