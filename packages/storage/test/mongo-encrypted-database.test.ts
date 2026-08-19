import { beforeEach, describe, expect, it, vi } from 'vitest';

const mongodb = vi.hoisted(() => {
  const databaseCollection = {
    createIndex: vi.fn(async () => '_id_'),
    deleteOne: vi.fn(),
    find: vi.fn(),
    findOne: vi.fn(),
    insertOne: vi.fn(),
    updateOne: vi.fn(),
  };
  const vaultCollection = {
    createIndex: vi.fn(async () => 'database_vault_identity'),
    deleteOne: vi.fn(),
    find: vi.fn(),
    findOne: vi.fn(),
    insertOne: vi.fn(),
    updateOne: vi.fn(),
  };
  const session = {
    endSession: vi.fn(),
    withTransaction: vi.fn(async (callback: (session: unknown) => Promise<unknown>) =>
      callback(session),
    ),
  };
  const client = {
    close: vi.fn(async () => undefined),
    connect: vi.fn(async () => undefined),
    db: vi.fn(),
    withSession: vi.fn(async (callback: (session: unknown) => Promise<unknown>) =>
      callback(session),
    ),
  };

  return {
    client,
    clients: [] as Array<{ uri: string; options: unknown }>,
    databaseCollection,
    session,
    vaultCollection,
  };
});

vi.mock('mongodb', () => {
  class MongoServerError extends Error {
    code?: number;
  }
  class MongoClient {
    constructor(
      readonly uri: string,
      readonly options: unknown,
    ) {
      mongodb.clients.push(this);
    }

    connect = mongodb.client.connect;
    close = mongodb.client.close;
    db = mongodb.client.db;
    withSession = mongodb.client.withSession;
  }
  return { MongoClient, MongoServerError };
});

import { MongoEncryptedDatabaseStore } from '../src/mongo-encrypted-database.js';
import { EncryptedDatabaseStoreError } from '../src/encrypted-database-store.js';
import {
  databaseDocument,
  databaseRevision,
  makeDatabaseId,
  makeVaultId,
  vaultDocument,
  vaultRevision,
} from './database-store-fixtures.js';

const URI = 'mongodb://localhost/kavrix';
const DATABASE_NAME = 'kavrix_test';

describe('MongoEncryptedDatabaseStore', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('uses bounded connection timeouts, safe defaults, and exact collection names', async () => {
    const database = {
      collection: vi.fn((name: string) =>
        name === 'database_records'
          ? mongodb.databaseCollection
          : mongodb.vaultCollection,
      ),
    };
    mongodb.client.db.mockReturnValue(database);

    const store = await MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME, {
      databaseCollectionName: 'database_records',
      vaultCollectionName: 'vault_records',
    });

    expect(mongodb.client.connect).toHaveBeenCalledOnce();
    expect(mongodb.clients.at(-1)).toMatchObject({
      uri: URI,
      options: {
        connectTimeoutMS: 5_000,
        serverSelectionTimeoutMS: 5_000,
        socketTimeoutMS: 10_000,
        timeoutMS: 10_000,
      },
    });
    expect(mongodb.client.db).toHaveBeenCalledWith(DATABASE_NAME);
    expect(database.collection).toHaveBeenNthCalledWith(1, 'database_records');
    expect(database.collection).toHaveBeenNthCalledWith(2, 'vault_records');
    expect(mongodb.vaultCollection.createIndex).toHaveBeenCalledWith(
      { databaseId: 1, id: 1 },
      { name: 'database_vault_identity', unique: true },
    );
    await store.close();
  });

  it('closes the client and redacts index initialization failures', async () => {
    const sensitive = new Error('mongodb://user:password@example.test/private');
    mongodb.vaultCollection.createIndex.mockRejectedValueOnce(sensitive);
    mongodb.client.db.mockReturnValue({
      collection: vi.fn((name: string) =>
        name === 'kavrix_databases'
          ? mongodb.databaseCollection
          : mongodb.vaultCollection,
      ),
    });

    await expect(
      MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME),
    ).rejects.toEqual(new EncryptedDatabaseStoreError('connection'));
    expect(mongodb.client.close).toHaveBeenCalledOnce();
  });

  it('uses the exact default database and vault collection names', async () => {
    const database = { collection: vi.fn(() => mongodb.databaseCollection) };
    mongodb.client.db.mockReturnValue(database);

    const store = await MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME);

    expect(database.collection).toHaveBeenNthCalledWith(1, 'kavrix_databases');
    expect(database.collection).toHaveBeenNthCalledWith(2, 'kavrix_vaults');
    await store.close();
  });

  it('rejects unsafe runtime configuration without reflecting it', async () => {
    await expect(
      MongoEncryptedDatabaseStore.connect(
        'mongodb://example.test/kavrix',
        DATABASE_NAME,
      ),
    ).rejects.toMatchObject({ code: 'connection' });
    await expect(
      MongoEncryptedDatabaseStore.connect(URI, 'db name with spaces'),
    ).rejects.toMatchObject({ code: 'invalid' });
    await expect(
      MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME, {
        databaseCollectionName: '$bad',
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
  });

  it('closes the client when connect or construction fails', async () => {
    mongodb.client.connect.mockRejectedValueOnce(new Error('sensitive failure'));
    await expect(
      MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME),
    ).rejects.toMatchObject({
      code: 'connection',
    });
    expect(mongodb.client.close).toHaveBeenCalledOnce();
  });

  it('uses canonical composite ids, bounded projection, and opaque vault ordering', async () => {
    const database = databaseDocument(
      makeDatabaseId('db_01JMONGOQUERIES'),
      databaseRevision(0),
    );
    const vaultId = makeVaultId('vault_01JMONGOQUERY');
    const vault = vaultDocument(
      database.id,
      vaultId,
      databaseRevision(0),
      vaultRevision(0),
    );
    const cursor = {
      sort: vi.fn().mockReturnThis(),
      toArray: vi.fn(async () => [{ ...vault, _id: `${database.id}:${vault.id}` }]),
    };
    mongodb.databaseCollection.findOne.mockResolvedValueOnce({
      ...database,
      _id: database.id,
    });
    mongodb.vaultCollection.findOne.mockResolvedValueOnce({
      ...vault,
      _id: `${database.id}:${vault.id}`,
    });
    mongodb.vaultCollection.find.mockReturnValueOnce(cursor);
    mongodb.client.db.mockReturnValue({
      command: vi.fn(),
      collection: vi.fn((name: string) =>
        name === 'kavrix_databases'
          ? mongodb.databaseCollection
          : mongodb.vaultCollection,
      ),
    });
    const store = await MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME);

    await expect(store.getDatabase(database.id)).resolves.toEqual(database);
    await expect(store.getVault(database.id, vault.id)).resolves.toEqual(vault);
    await expect(store.listVaults(database.id)).resolves.toEqual([vault]);

    expect(mongodb.databaseCollection.findOne).toHaveBeenCalledWith(
      { _id: database.id },
      { projection: { _id: 0 } },
    );
    expect(mongodb.vaultCollection.findOne).toHaveBeenCalledWith(
      { _id: `${database.id}:${vault.id}`, databaseId: database.id },
      { projection: { _id: 0 } },
    );
    expect(mongodb.vaultCollection.find).toHaveBeenCalledWith(
      { databaseId: database.id },
      { projection: { _id: 0 } },
    );
    expect(cursor.sort).toHaveBeenCalledWith({ id: 1 });
    await store.close();
  });

  it('uses exact CAS filters and independent vault replacement', async () => {
    const database = databaseDocument(
      makeDatabaseId('db_01JMONGOCAS'),
      databaseRevision(1),
    );
    const vault = vaultDocument(
      database.id,
      makeVaultId('vault_01JMONGOCAS'),
      databaseRevision(1),
      vaultRevision(1),
    );
    mongodb.databaseCollection.updateOne.mockResolvedValueOnce({ matchedCount: 1 });
    mongodb.vaultCollection.updateOne.mockResolvedValueOnce({ matchedCount: 1 });
    mongodb.client.db.mockReturnValue({
      command: vi.fn(),
      collection: vi.fn((name: string) =>
        name === 'kavrix_databases'
          ? mongodb.databaseCollection
          : mongodb.vaultCollection,
      ),
    });
    const store = await MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME);

    await store.createDatabase(database);
    await store.updateDatabase(database, databaseRevision(0));
    await store.updateVault({ vault, expectedVaultRevision: vaultRevision(0) });

    expect(mongodb.databaseCollection.insertOne).toHaveBeenCalledWith({
      ...database,
      _id: database.id,
    });
    expect(mongodb.databaseCollection.updateOne).toHaveBeenCalledWith(
      { _id: database.id, revision: databaseRevision(0) },
      { $set: database },
    );
    expect(mongodb.vaultCollection.updateOne).toHaveBeenCalledWith(
      {
        _id: `${vault.databaseId}:${vault.id}`,
        databaseId: vault.databaseId,
        revision: vaultRevision(0),
      },
      { $set: vault },
    );
    await store.close();
  });

  it('uses a majority snapshot transaction for catalog-plus-vault creation and aborts conflicts', async () => {
    const database = databaseDocument(
      makeDatabaseId('db_01JMONGOTRANSACTION'),
      databaseRevision(1),
    );
    const vault = vaultDocument(
      database.id,
      makeVaultId('vault_01JMONGOTRANSACTION'),
      databaseRevision(1),
      vaultRevision(0),
    );
    mongodb.databaseCollection.updateOne.mockResolvedValueOnce({ matchedCount: 1 });
    mongodb.vaultCollection.insertOne.mockResolvedValueOnce({
      acknowledged: true,
      insertedId: `${database.id}:${vault.id}`,
    });
    mongodb.client.db.mockReturnValue({
      command: vi.fn(),
      collection: vi.fn((name: string) =>
        name === 'kavrix_databases'
          ? mongodb.databaseCollection
          : mongodb.vaultCollection,
      ),
    });
    const store = await MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME);

    await store.createVault({
      database,
      expectedDatabaseRevision: databaseRevision(0),
      vault,
    });

    expect(mongodb.client.withSession).toHaveBeenCalledOnce();
    expect(mongodb.session.withTransaction).toHaveBeenCalledWith(expect.any(Function), {
      readConcern: { level: 'snapshot' },
      writeConcern: { w: 'majority' },
    });
    expect(mongodb.databaseCollection.updateOne).toHaveBeenCalledWith(
      { _id: database.id, revision: databaseRevision(0) },
      { $set: database },
      { session: mongodb.session },
    );
    expect(mongodb.vaultCollection.insertOne).toHaveBeenCalledWith(
      { ...vault, _id: `${database.id}:${vault.id}` },
      { session: mongodb.session },
    );
    await store.close();
  });

  it('aborts catalog transactions before an insert or after a failed vault comparison', async () => {
    const database = databaseDocument(
      makeDatabaseId('db_01JMONGOABORT'),
      databaseRevision(1),
    );
    const vault = vaultDocument(
      database.id,
      makeVaultId('vault_01JMONGOABORT'),
      databaseRevision(1),
      vaultRevision(0),
    );
    mongodb.client.db.mockReturnValue({
      command: vi.fn(),
      collection: vi.fn((name: string) =>
        name === 'kavrix_databases'
          ? mongodb.databaseCollection
          : mongodb.vaultCollection,
      ),
    });
    mongodb.databaseCollection.updateOne.mockResolvedValueOnce({ matchedCount: 0 });
    const store = await MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME);

    await expect(
      store.createVault({
        database,
        expectedDatabaseRevision: databaseRevision(0),
        vault,
      }),
    ).rejects.toMatchObject({ code: 'conflict' });
    expect(mongodb.vaultCollection.insertOne).not.toHaveBeenCalled();

    mongodb.databaseCollection.updateOne.mockResolvedValueOnce({ matchedCount: 1 });
    mongodb.vaultCollection.deleteOne.mockResolvedValueOnce({ deletedCount: 0 });
    await expect(
      store.deleteVault({
        database,
        expectedDatabaseRevision: databaseRevision(0),
        vaultId: vault.id,
        expectedVaultRevision: vaultRevision(0),
      }),
    ).rejects.toMatchObject({ code: 'conflict' });
    expect(mongodb.vaultCollection.deleteOne).toHaveBeenCalledWith(
      {
        _id: `${database.id}:${vault.id}`,
        databaseId: database.id,
        revision: vaultRevision(0),
      },
      { session: mongodb.session },
    );
    await store.close();
  });

  it('maps duplicate and all untrusted operational errors to redacted store errors', async () => {
    const database = databaseDocument(
      makeDatabaseId('db_01JMONGOERROR'),
      databaseRevision(0),
    );
    mongodb.databaseCollection.insertOne.mockRejectedValueOnce(
      Object.assign(new Error(), { code: 11_000 }),
    );
    mongodb.client.db.mockReturnValue({
      command: vi.fn(),
      collection: vi.fn((name: string) =>
        name === 'kavrix_databases'
          ? mongodb.databaseCollection
          : mongodb.vaultCollection,
      ),
    });
    const store = await MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME);

    await expect(store.createDatabase(database)).rejects.toMatchObject({
      code: 'exists',
    });
    await expect(store.ping()).resolves.toBeUndefined();
    await store.close();
    await expect(store.ping()).rejects.toEqual(
      new EncryptedDatabaseStoreError('closed'),
    );
  });

  it('maps arbitrary normal and transactional driver errors to redacted operation errors', async () => {
    const database = databaseDocument(
      makeDatabaseId('db_01JMONGOREDAC'),
      databaseRevision(1),
    );
    const vault = vaultDocument(
      database.id,
      makeVaultId('vault_01JMONGOREDAC'),
      databaseRevision(1),
      vaultRevision(0),
    );
    const updatedVault = vaultDocument(
      database.id,
      vault.id,
      databaseRevision(1),
      vaultRevision(1),
    );
    const driverError = new Error(
      'mongodb://user:password@example.test/db_01JMONGOREDAC ciphertext AQID',
    );
    mongodb.client.db.mockReturnValue({
      command: vi.fn(),
      collection: vi.fn((name: string) =>
        name === 'kavrix_databases'
          ? mongodb.databaseCollection
          : mongodb.vaultCollection,
      ),
    });
    mongodb.databaseCollection.findOne.mockRejectedValueOnce(driverError);
    mongodb.vaultCollection.updateOne.mockRejectedValueOnce(driverError);
    mongodb.databaseCollection.updateOne.mockRejectedValueOnce(driverError);
    const store = await MongoEncryptedDatabaseStore.connect(URI, DATABASE_NAME);

    await expectRedactedStoreError(
      store.getDatabase(database.id),
      'operation',
      driverError,
    );
    await expectRedactedStoreError(
      store.updateVault({
        vault: updatedVault,
        expectedVaultRevision: vaultRevision(0),
      }),
      'operation',
      driverError,
    );
    await expectRedactedStoreError(
      store.createVault({
        database,
        expectedDatabaseRevision: databaseRevision(0),
        vault,
      }),
      'operation',
      driverError,
    );
    expect(mongodb.client.withSession).toHaveBeenCalledOnce();
    expect(mongodb.session.withTransaction).toHaveBeenCalledOnce();
    expect(mongodb.vaultCollection.insertOne).not.toHaveBeenCalled();
    await store.close();
  });
});

async function expectRedactedStoreError(
  operation: Promise<unknown>,
  code: EncryptedDatabaseStoreError['code'],
  original: Error,
): Promise<void> {
  try {
    await operation;
    throw new Error('Expected an encrypted database store error');
  } catch (error: unknown) {
    expect(error).toEqual(new EncryptedDatabaseStoreError(code));
    expect(error).not.toBe(original);
    const storageError = error as EncryptedDatabaseStoreError & { cause?: unknown };
    expect(storageError.cause).toBeUndefined();
    for (const forbidden of [
      'mongodb://',
      'password',
      'db_01J',
      'vault_01J',
      'ciphertext',
      'AQID',
    ]) {
      expect(storageError.message).not.toContain(forbidden);
      expect(String(storageError)).not.toContain(forbidden);
    }
  }
}
