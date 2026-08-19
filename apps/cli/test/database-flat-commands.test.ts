import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { databaseIdSchema, profileIdSchema } from '@kavrix/schemas';
import {
  FileEncryptedDatabaseStore,
  MongoEncryptedDatabaseStore,
} from '@kavrix/storage';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  DatabaseFlatCommandError,
  withDatabaseFlatVault,
} from '../src/database-flat-commands.js';
import { DatabaseSession } from '../src/database-session.js';
import {
  DatastoreProfileRegistry,
  type DatastoreProfile,
} from '../src/datastore-profiles.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';

let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-database-flat-'));
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(directory, { force: true, recursive: true });
});

function fileProfile(dataFile: string, keyFile: string): DatastoreProfile {
  return {
    id: profileIdSchema.parse('local'),
    datastore: 'file',
    databaseId: databaseIdSchema.parse('db_local'),
    dataFile,
    keyFile,
  };
}

function mongoProfile(): DatastoreProfile {
  return {
    id: profileIdSchema.parse('work'),
    datastore: 'mongodb',
    databaseId: databaseIdSchema.parse('db_work'),
    database: 'credentials',
    databaseCollection: 'kavrix_databases',
    vaultCollection: 'kavrix_vaults',
    keyFile: join(directory, 'work.key'),
  };
}

async function addCurrentProfile(profile: DatastoreProfile): Promise<void> {
  const registry = await DatastoreProfileRegistry.open({
    configDirectory: directory,
  });
  await registry.add(profile);
  await registry.use(profile.id);
}

describe('flat database command routing', () => {
  it('honors bound file data-file and key-file overrides while retaining the database binding', async () => {
    const originalDataFile = join(directory, 'original.database');
    const originalKeyFile = join(directory, 'original.key');
    const overrideDataFile = join(directory, 'override.database');
    const overrideKeyFile = join(directory, 'override.key');
    const profile = fileProfile(originalDataFile, originalKeyFile);
    await addCurrentProfile(profile);

    const store = { close: vi.fn(async () => undefined) } as never;
    const session = { close: vi.fn(async () => undefined) } as never;
    const openStore = vi
      .spyOn(FileEncryptedDatabaseStore, 'open')
      .mockResolvedValue(store);
    const openSession = vi.spyOn(DatabaseSession, 'open').mockResolvedValue(session);
    let selected: DatastoreProfile | undefined;

    await withDatabaseFlatVault(
      {
        profile: 'local',
        profileConfigDir: directory,
        vault: 'vault_project',
        datastore: 'file',
        dataFile: overrideDataFile,
        keyFile: overrideKeyFile,
        routingOverrides: {
          datastore: 'file',
          dataFile: overrideDataFile,
          keyFile: overrideKeyFile,
        },
      },
      { passphrase: 'correct horse battery staple', extras: [] },
      async (_session, _vaultId, routedProfile) => {
        selected = routedProfile;
      },
    );

    expect(openStore).toHaveBeenCalledWith(overrideDataFile);
    expect(openSession).toHaveBeenCalledWith(
      expect.objectContaining({
        store,
        keyFile: overrideKeyFile,
        expectedDatabaseId: profile.databaseId,
      }),
    );
    expect(selected).toEqual({
      ...profile,
      dataFile: overrideDataFile,
      keyFile: overrideKeyFile,
    });
  });

  it('keeps a bound profile route when merged Commander defaults are present', async () => {
    const dataFile = join(directory, 'local.database');
    const keyFile = join(directory, 'local.key');
    const profile = fileProfile(dataFile, keyFile);
    await addCurrentProfile(profile);

    const store = { close: vi.fn(async () => undefined) } as never;
    const session = { close: vi.fn(async () => undefined) } as never;
    const openStore = vi
      .spyOn(FileEncryptedDatabaseStore, 'open')
      .mockResolvedValue(store);
    vi.spyOn(DatabaseSession, 'open').mockResolvedValue(session);

    await withDatabaseFlatVault(
      {
        profile: 'local',
        profileConfigDir: directory,
        vault: 'vault_project',
        datastore: 'mongodb',
        collection: 'kavrix_vaults',
        keyFile: './kavrix.key',
        routingOverrides: {},
      },
      { passphrase: 'correct horse battery staple', extras: [] },
      async () => undefined,
    );

    expect(openStore).toHaveBeenCalledWith(dataFile);
  });

  it('rejects a data-file override that leaves a bound Mongo profile on MongoDB', async () => {
    const profile = mongoProfile();
    await addCurrentProfile(profile);
    const openStore = vi.spyOn(MongoEncryptedDatabaseStore, 'connect');

    await expect(
      withDatabaseFlatVault(
        {
          profile: 'work',
          profileConfigDir: directory,
          vault: 'vault_project',
          datastore: 'mongodb',
          dataFile: join(directory, 'wrong.database'),
          routingOverrides: { dataFile: join(directory, 'wrong.database') },
        },
        {
          databaseUrl: 'mongodb://localhost/ignored',
          passphrase: 'correct horse battery staple',
          extras: [],
        },
        async () => undefined,
      ),
    ).rejects.toBeInstanceOf(DatabaseFlatCommandError);
    expect(openStore).not.toHaveBeenCalled();
  });

  it('honors bound Mongo database, collection, and key-file overrides', async () => {
    const profile = mongoProfile();
    await addCurrentProfile(profile);
    const overrideKeyFile = join(directory, 'override-work.key');
    const store = { close: vi.fn(async () => undefined) } as never;
    const session = { close: vi.fn(async () => undefined) } as never;
    const connect = vi
      .spyOn(MongoEncryptedDatabaseStore, 'connect')
      .mockResolvedValue(store);
    const openSession = vi.spyOn(DatabaseSession, 'open').mockResolvedValue(session);

    await withDatabaseFlatVault(
      {
        profile: 'work',
        profileConfigDir: directory,
        vault: 'vault_project',
        datastore: 'mongodb',
        database: 'explicit_database',
        collection: 'explicit_collection',
        keyFile: overrideKeyFile,
        routingOverrides: {
          database: 'explicit_database',
          vaultCollection: 'explicit_collection',
          keyFile: overrideKeyFile,
        },
      },
      {
        databaseUrl: 'mongodb://localhost/ignored-by-routing',
        passphrase: 'correct horse battery staple',
        extras: [],
      },
      async () => undefined,
    );

    expect(connect).toHaveBeenCalledWith(
      'mongodb://localhost/ignored-by-routing',
      'explicit_database',
      {
        databaseCollectionName: profile.databaseCollection,
        vaultCollectionName: 'explicit_collection',
      },
    );
    expect(openSession).toHaveBeenCalledWith(
      expect.objectContaining({
        store,
        keyFile: overrideKeyFile,
        expectedDatabaseId: profile.databaseId,
      }),
    );
  });
});
