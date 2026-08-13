export * from './errors.js';
export {
  SealedSecretStore,
  sealedEntryFactory,
  type SealedSecretStoreOptions,
} from './sealed-secret-store.js';
export { setWindowsUserOnlyAcl } from './windows-acl.js';
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
