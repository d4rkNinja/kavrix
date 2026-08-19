export { buildLocalCli, runLocalCli, type LocalCliOptions } from './local-vault-cli.js';
export {
  DatastoreProfileError,
  DatastoreProfileRegistry,
  resolveDatastoreProfileRouting,
  resolveProfilePath,
  verifyDatastoreProfileDatabaseId,
  type DatastoreProfile,
  type DatastoreProfileRoutingOverrides,
  type DatastoreProfileRegistryOptions,
} from './datastore-profiles.js';
export { CLI_VERSION } from './version.js';
