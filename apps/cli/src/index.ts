export { buildLocalCli, runLocalCli, type LocalCliOptions } from './local-vault-cli.js';
export {
  DatabaseSession,
  DatabaseSessionError,
  type DatabaseInitializationOptions,
  type DatabaseOpenOptions,
  type DatabaseOpenWithSecretOptions,
  type DatabaseRecoveryCreateOptions,
  type DatabaseRecoveryUseOptions,
  type DatabaseRecoveryVerifyOptions,
  type DatabaseSessionErrorCode,
  type DatabaseVaultCatalogEntry,
  type MigrationInitializationOwnership,
  type MigrationVaultOwnership,
} from './database-session.js';
export {
  DatabaseMigrationError,
  migrateLegacyVaultToDatabase,
  type DatabaseMigrationDestination,
  type DatabaseMigrationErrorCode,
  type LegacyDatabaseMigrationOptions,
  type LegacyDatabaseMigrationResult,
  type LegacyMigrationSource,
} from './database-migration.js';
export {
  DatastoreProfileError,
  DatastoreProfileRegistry,
  resolveDatastoreProfileRouting,
  resolveProfilePath,
  verifyDatastoreProfileDatabaseId,
  type DatastoreProfile,
  type DatastoreProfileBindingPublication,
  type DatastoreProfileBindingPublicationResult,
  type DatastoreProfileRoutingOverrides,
  type DatastoreProfileRegistryOptions,
} from './datastore-profiles.js';
export { CLI_VERSION } from './version.js';
