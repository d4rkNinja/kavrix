import {
  databaseRevisionAnchorPath,
  validateSecureFileDestination,
  validateSecureFileSource,
} from '@kavrix/key-files';
import {
  profileIdSchema,
  vaultIdSchema,
  type DatabaseId,
  type LocalVaultDocument,
} from '@kavrix/schemas';
import {
  FileEncryptedDatabaseStore,
  FileLocalVaultStore,
  MongoEncryptedDatabaseStore,
  MongoLocalVaultStore,
  type EncryptedDatabaseStore,
} from '@kavrix/storage';

import { migrateLegacyVaultToDatabase } from './database-migration.js';
import { DatabaseSessionError } from './database-session.js';
import { DatastoreProfileRegistry } from './datastore-profiles.js';
import { LocalSecretInput, type LocalSecretKind } from './local-secrets.js';

export type DatabaseMigrationCommandOptions = Readonly<{
  sourceProfile?: string;
  destinationProfile?: string;
  sourceVault?: string;
  profileConfigDir?: string;
  secretsStdin?: boolean;
  initialize?: boolean;
  allowInsecureTransport?: boolean;
}>;

export type DatabaseMigrationCommandResult = Readonly<{
  migrated: true;
  databaseId: DatabaseId;
  vaultId: ReturnType<typeof vaultIdSchema.parse>;
  recordCount: number;
}>;

export class DatabaseMigrationCommandError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'DatabaseMigrationCommandError';
  }
}

/** Composes explicit profile routing and bounded secret input around migration. */
export async function executeDatabaseMigrationCommand(
  options: DatabaseMigrationCommandOptions,
): Promise<DatabaseMigrationCommandResult> {
  const sourceProfileId = required(options.sourceProfile, '--source-profile');
  const destinationProfileId = required(
    options.destinationProfile,
    '--destination-profile',
  );
  if (sourceProfileId === destinationProfileId) {
    throw new DatabaseMigrationCommandError(
      'Migration source and destination profiles must differ.',
    );
  }
  const registry = await DatastoreProfileRegistry.open(
    options.profileConfigDir === undefined
      ? {}
      : { configDirectory: options.profileConfigDir },
  );
  const sourceProfile = await registry.get(profileIdSchema.parse(sourceProfileId));
  const destinationProfile = await registry.get(
    profileIdSchema.parse(destinationProfileId),
  );
  if (
    sourceProfile.databaseId !== undefined ||
    (options.initialize === true
      ? destinationProfile.databaseId !== undefined
      : destinationProfile.databaseId === undefined)
  ) {
    throw new DatabaseMigrationCommandError(
      options.initialize === true
        ? 'Explicit initialization requires one legacy source and one unbound destination profile.'
        : 'Use one legacy source profile and one initialized database destination profile.',
    );
  }
  if (options.initialize === true && destinationProfile.datastore === 'mongodb') {
    throw new DatabaseMigrationCommandError(
      'MongoDB destination initialization is unavailable without ownership-bound cleanup.',
    );
  }
  const sourceVaultId = vaultIdSchema.parse(
    required(options.sourceVault, '--source-vault'),
  );
  await prevalidateProfiles(sourceProfile, destinationProfile, options.initialize);

  const kinds = databaseMigrationSecretKinds(
    sourceProfile.datastore,
    destinationProfile.datastore,
    options.initialize === true,
  );
  const values = await new LocalSecretInput(process.stdin, process.stderr).read(
    kinds,
    options.secretsStdin === true,
  );
  let offset = 0;
  const sourceDatabaseUrl =
    sourceProfile.datastore === 'mongodb' ? values[offset++] : undefined;
  const destinationDatabaseUrl =
    destinationProfile.datastore === 'mongodb' ? values[offset++] : undefined;
  const sourcePassphrase = secret(values, offset++);
  const expectedSourceVaultLabel =
    options.initialize === true ? secret(values, offset++) : undefined;
  const destinationPassphrase = secret(values, offset++);
  if (
    options.initialize === true &&
    destinationPassphrase !== secret(values, offset++)
  ) {
    throw new DatabaseMigrationCommandError('Passphrases do not match.');
  }
  const databaseLabel =
    options.initialize === true ? secret(values, offset++) : undefined;
  const vaultLabel = secret(values, offset);

  const sourceStore =
    sourceProfile.datastore === 'file'
      ? await FileLocalVaultStore.open(sourceProfile.dataFile)
      : await MongoLocalVaultStore.connect(
          secret([sourceDatabaseUrl ?? ''], 0),
          sourceProfile.database,
          {
            collectionName: sourceProfile.vaultCollection,
            allowInsecureTransport: options.allowInsecureTransport === true,
          },
        );
  let sourceDocument: LocalVaultDocument | null;
  try {
    sourceDocument = await sourceStore.get(sourceVaultId);
  } finally {
    await sourceStore.close();
  }
  if (sourceDocument === null) {
    throw new DatabaseMigrationCommandError('Vault is not initialized.');
  }

  let initializedFileStore: FileEncryptedDatabaseStore | undefined;
  const openDestination = async (): Promise<EncryptedDatabaseStore> => {
    if (destinationProfile.datastore === 'file') {
      const store = await FileEncryptedDatabaseStore.open(destinationProfile.dataFile);
      initializedFileStore ??= store;
      return store;
    }
    return MongoEncryptedDatabaseStore.connect(
      secret([destinationDatabaseUrl ?? ''], 0),
      destinationProfile.database,
      {
        databaseCollectionName: destinationProfile.databaseCollection,
        vaultCollectionName: destinationProfile.vaultCollection,
        allowInsecureTransport: options.allowInsecureTransport === true,
      },
    );
  };
  const result = await migrateLegacyVaultToDatabase({
    source: {
      document: sourceDocument,
      keyFile: sourceProfile.keyFile,
      ...(expectedSourceVaultLabel === undefined
        ? {}
        : {
            readExpectedVaultLabel: () =>
              Promise.resolve(Buffer.from(expectedSourceVaultLabel, 'utf8')),
          }),
      readPassphrase: () => Promise.resolve(Buffer.from(sourcePassphrase, 'utf8')),
    },
    destination: {
      openStore: openDestination,
      keyFile: destinationProfile.keyFile,
      ...(destinationProfile.databaseId === undefined
        ? {}
        : { expectedDatabaseId: destinationProfile.databaseId }),
      vaultLabel,
      readPassphrase: () => Promise.resolve(Buffer.from(destinationPassphrase, 'utf8')),
      ...(options.initialize !== true || databaseLabel === undefined
        ? {}
        : {
            initialize: {
              databaseLabel,
              rollbackDatabase: async (databaseId) => {
                if (destinationProfile.datastore !== 'file') {
                  throw new DatabaseSessionError('operation');
                }
                const store = initializedFileStore;
                if (store === undefined) throw new DatabaseSessionError('operation');
                await store.rollbackOwnedInitialization(databaseId);
              },
              publishBinding: (databaseId: DatabaseId) =>
                registry.bindDatabaseIdForInitialization(
                  destinationProfile.id,
                  databaseId,
                ),
            },
          }),
    },
  });
  return { migrated: true, ...result };
}

export function databaseMigrationSecretKinds(
  sourceDatastore: 'file' | 'mongodb',
  destinationDatastore: 'file' | 'mongodb',
  initialize: boolean,
): LocalSecretKind[] {
  return [
    ...(sourceDatastore === 'mongodb' ? (['database-url'] as const) : []),
    ...(destinationDatastore === 'mongodb' ? (['database-url'] as const) : []),
    'passphrase',
    ...(initialize
      ? (['label', 'new-passphrase', 'new-passphrase', 'label'] as const)
      : (['passphrase'] as const)),
    'label',
  ];
}

async function prevalidateProfiles(
  source: Awaited<ReturnType<DatastoreProfileRegistry['get']>>,
  destination: Awaited<ReturnType<DatastoreProfileRegistry['get']>>,
  initialize: boolean | undefined,
): Promise<void> {
  await validateSecureFileSource(source.keyFile);
  await validateSecureFileSource(`${source.keyFile}.anchor`);
  if (initialize === true) {
    await validateSecureFileDestination(destination.keyFile);
    await validateSecureFileDestination(
      databaseRevisionAnchorPath(destination.keyFile),
    );
  } else {
    await validateSecureFileSource(destination.keyFile);
    await validateSecureFileSource(databaseRevisionAnchorPath(destination.keyFile));
  }
  if (source.datastore === 'file') {
    await FileLocalVaultStore.validatePath(source.dataFile);
  }
  if (destination.datastore === 'file') {
    await FileEncryptedDatabaseStore.validatePath(destination.dataFile);
  }
}

function required(value: string | undefined, name: string): string {
  if (value === undefined || value.length === 0) {
    throw new DatabaseMigrationCommandError(`${name} is required.`);
  }
  return value;
}

function secret(values: readonly string[], index: number): string {
  const value = values[index];
  if (value === undefined) {
    throw new DatabaseMigrationCommandError('Secret input is incomplete.');
  }
  return value;
}
