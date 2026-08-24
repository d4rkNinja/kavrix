import { zeroize } from '@kavrix/crypto';
import { profileIdSchema, vaultIdSchema, type VaultId } from '@kavrix/schemas';
import {
  FileEncryptedDatabaseStore,
  MongoEncryptedDatabaseStore,
} from '@kavrix/storage';

import { DatabaseSession } from './database-session.js';
import {
  DatastoreProfileRegistry,
  resolveDatastoreProfileRouting,
  type DatastoreProfile,
  type DatastoreProfileRoutingOverrides,
} from './datastore-profiles.js';
import { LocalSecretInput, type LocalSecretKind } from './local-secrets.js';

const LEGACY_DEFAULT_VAULT_ID = 'default';

export class DatabaseFlatCommandError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'DatabaseFlatCommandError';
  }
}

export type DatabaseFlatCommandOptions = Readonly<{
  profile?: string;
  profileConfigDir?: string;
  vault: string;
  datastore?: string;
  dataFile?: string;
  database?: string;
  collection?: string;
  keyFile?: string;
  routingOverrides?: DatastoreProfileRoutingOverrides;
  databaseUrlStdin?: boolean;
  passphraseStdin?: boolean;
  valueStdin?: boolean;
  allowInsecureTransport?: boolean;
}>;

export type DatabaseFlatSecrets = Readonly<{
  databaseUrl?: string;
  passphrase: string;
  extras: readonly string[];
}>;

export async function usesDatabaseContainer(
  options: DatabaseFlatCommandOptions,
): Promise<boolean> {
  return (await selectedDatabaseProfile(options)) !== null;
}

export async function readDatabaseFlatSecrets(
  options: DatabaseFlatCommandOptions,
  extras: readonly LocalSecretKind[],
): Promise<DatabaseFlatSecrets> {
  const profile = await selectedDatabaseProfile(options);
  if (profile === null)
    throw new DatabaseFlatCommandError('A database profile is required.');
  if (
    options.vault === LEGACY_DEFAULT_VAULT_ID ||
    !options.vault.startsWith('vault_')
  ) {
    throw new DatabaseFlatCommandError(
      'Select one database vault explicitly with --vault before reading secrets.',
    );
  }
  const kinds: LocalSecretKind[] = [
    ...(profile.datastore === 'mongodb' ? (['database-url'] as const) : []),
    'passphrase',
    ...extras,
  ];
  const flags = kinds.map((kind) => {
    if (kind === 'database-url') return options.databaseUrlStdin === true;
    if (kind === 'passphrase') return options.passphraseStdin === true;
    return options.valueStdin === true;
  });
  const anyStdin = flags.some(Boolean);
  if (anyStdin && !flags.every(Boolean)) {
    throw new DatabaseFlatCommandError(
      'Use stdin flags for every secret in a command, or use masked prompts for all of them.',
    );
  }
  const values = await new LocalSecretInput(process.stdin, process.stderr).read(
    kinds,
    anyStdin,
  );
  const offset = profile.datastore === 'mongodb' ? 1 : 0;
  const passphrase = values[offset];
  if (passphrase === undefined) {
    throw new DatabaseFlatCommandError('Secret input is incomplete.');
  }
  return {
    ...(profile.datastore === 'mongodb' ? { databaseUrl: required(values[0]) } : {}),
    passphrase,
    extras: values.slice(offset + 1),
  };
}

export type OpenDatabaseFlatVaultHandle = Readonly<{
  session: DatabaseSession;
  vaultId: VaultId;
  profile: DatastoreProfile;
}>;

/**
 * Opens one bound database vault session. Callers own the handle lifecycle
 * and must close it; `withDatabaseFlatVault` composes this for simple cases.
 */
export async function openDatabaseFlatVault(
  options: DatabaseFlatCommandOptions,
  secrets: DatabaseFlatSecrets,
): Promise<OpenDatabaseFlatVaultHandle> {
  const profile = await selectedDatabaseProfile(options);
  if (profile?.databaseId === undefined) {
    throw new DatabaseFlatCommandError('A database profile is required.');
  }
  const vaultId = vaultIdSchema.parse(options.vault);
  const store =
    profile.datastore === 'file'
      ? await FileEncryptedDatabaseStore.open(profile.dataFile)
      : await MongoEncryptedDatabaseStore.connect(
          required(secrets.databaseUrl),
          profile.database,
          {
            databaseCollectionName: profile.databaseCollection,
            vaultCollectionName: profile.vaultCollection,
            allowInsecureTransport: options.allowInsecureTransport === true,
          },
        );
  let session: DatabaseSession | undefined;
  const passphrase = Buffer.from(secrets.passphrase, 'utf8');
  try {
    session = await DatabaseSession.open({
      store,
      keyFile: profile.keyFile,
      passphrase,
      expectedDatabaseId: profile.databaseId,
    });
  } finally {
    zeroize(passphrase);
    if (session === undefined) await store.close().catch(() => undefined);
  }
  return Object.freeze({ session, vaultId, profile });
}

export async function closeDatabaseFlatVault(
  handle: OpenDatabaseFlatVaultHandle,
): Promise<void> {
  await handle.session.close();
}

export async function withDatabaseFlatVault(
  options: DatabaseFlatCommandOptions,
  secrets: DatabaseFlatSecrets,
  operation: (
    session: DatabaseSession,
    vaultId: VaultId,
    profile: DatastoreProfile,
  ) => Promise<void>,
): Promise<void> {
  const handle = await openDatabaseFlatVault(options, secrets);
  try {
    await operation(handle.session, handle.vaultId, handle.profile);
  } finally {
    await handle.session.close();
  }
}

async function selectedDatabaseProfile(
  options: DatabaseFlatCommandOptions,
): Promise<DatastoreProfile | null> {
  const registryOptions =
    options.profileConfigDir === undefined
      ? {}
      : { configDirectory: options.profileConfigDir };
  const registry =
    options.profile === undefined
      ? await DatastoreProfileRegistry.openIfPresent(registryOptions)
      : await DatastoreProfileRegistry.open(registryOptions);
  if (registry === null) return null;
  const profile =
    options.profile === undefined
      ? await registry.current()
      : await registry.get(profileIdSchema.parse(options.profile));
  if (profile?.databaseId === undefined) return null;
  return resolveSelectedProfileRouting(profile, options);
}

function resolveSelectedProfileRouting(
  profile: DatastoreProfile,
  options: DatabaseFlatCommandOptions,
): DatastoreProfile {
  const overrides = options.routingOverrides ?? {};
  const effectiveDatastore = overrides.datastore ?? profile.datastore;

  if (overrides.dataFile !== undefined && effectiveDatastore !== 'file') {
    throw new DatabaseFlatCommandError('--data-file requires --datastore file.');
  }
  if (
    (overrides.database !== undefined ||
      overrides.databaseCollection !== undefined ||
      overrides.vaultCollection !== undefined) &&
    effectiveDatastore !== 'mongodb'
  ) {
    throw new DatabaseFlatCommandError(
      'MongoDB routing options cannot be used with a file datastore.',
    );
  }

  return resolveDatastoreProfileRouting(profile, overrides);
}

function required(value: string | undefined): string {
  if (value === undefined || value.length === 0) {
    throw new DatabaseFlatCommandError('Secret input is incomplete.');
  }
  return value;
}
