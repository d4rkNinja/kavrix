import { beforeEach, describe, expect, it, vi } from 'vitest';

const mongodb = vi.hoisted(() => {
  class MongoServerError extends Error {
    code?: number;
  }

  const collection = {
    deleteOne: vi.fn(),
    find: vi.fn(),
    findOne: vi.fn(),
    insertOne: vi.fn(),
    updateOne: vi.fn(),
  };
  const database = {
    collection: vi.fn(),
    command: vi.fn(),
  };
  const client = {
    close: vi.fn(),
    connect: vi.fn(),
    db: vi.fn(),
  };
  const cursor = {
    sort: vi.fn(),
    toArray: vi.fn(),
  };

  return {
    client,
    collection,
    cursor,
    database,
    clients: [] as Array<{ uri: string; options: unknown }>,
    MongoServerError,
  };
});

vi.mock('mongodb', () => {
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
  }

  return { MongoClient, MongoServerError: mongodb.MongoServerError };
});

import {
  MongoLocalVaultError,
  MongoLocalVaultStore,
} from '../src/mongo-local-vault.js';
import {
  localVaultDocumentSchema,
  vaultRevisionSchema,
  type LocalVaultDocument,
} from '@kavrix/schemas';

const URI = 'mongodb://localhost/kavrix';
const DATABASE_NAME = 'kavrix_test';

beforeEach(() => {
  mongodb.client.connect.mockReset().mockResolvedValue(undefined);
  mongodb.client.close.mockReset().mockResolvedValue(undefined);
  mongodb.client.db.mockReset().mockReturnValue(mongodb.database);
  mongodb.database.collection.mockReset().mockReturnValue(mongodb.collection);
  mongodb.database.command.mockReset().mockResolvedValue({ ok: 1 });
  mongodb.collection.deleteOne.mockReset().mockResolvedValue({ deletedCount: 1 });
  mongodb.collection.findOne.mockReset().mockResolvedValue(null);
  mongodb.collection.find.mockReset().mockReturnValue(mongodb.cursor);
  mongodb.collection.insertOne.mockReset().mockResolvedValue({ acknowledged: true });
  mongodb.collection.updateOne.mockReset().mockResolvedValue({ matchedCount: 1 });
  mongodb.cursor.sort.mockReset().mockReturnValue(mongodb.cursor);
  mongodb.cursor.toArray.mockReset().mockResolvedValue([]);
  mongodb.clients.length = 0;
});

describe('MongoLocalVaultStore', () => {
  it('connects with bounded timeouts and the default collection, then closes cleanly', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);

    expect(mongodb.client.connect).toHaveBeenCalledOnce();
    expect(mongodb.clients).toHaveLength(1);
    expect(mongodb.clients[0]).toMatchObject({
      uri: URI,
      options: {
        serverSelectionTimeoutMS: 5_000,
        connectTimeoutMS: 5_000,
        socketTimeoutMS: 10_000,
        timeoutMS: 10_000,
      },
    });
    expect(mongodb.client.db).toHaveBeenCalledWith(DATABASE_NAME);
    expect(mongodb.database.collection).toHaveBeenCalledWith('kavrix_vaults');

    await store.close();
    expect(mongodb.client.close).toHaveBeenCalledOnce();
  });

  it('uses a validated custom collection name', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME, {
      collectionName: 'vault_records-01',
    });

    expect(mongodb.database.collection).toHaveBeenCalledWith('vault_records-01');
    await store.close();
  });

  it('maps client and construction failures to connection errors and closes the client', async () => {
    mongodb.client.connect.mockRejectedValueOnce(
      new Error('mongodb://user:password@example.test/private'),
    );

    await expect(MongoLocalVaultStore.connect(URI, DATABASE_NAME)).rejects.toEqual(
      new MongoLocalVaultError('connection'),
    );
    expect(mongodb.client.close).toHaveBeenCalledOnce();

    await expect(
      MongoLocalVaultStore.connect(URI, DATABASE_NAME, {
        collectionName: '$unsafe',
      }),
    ).rejects.toEqual(new MongoLocalVaultError('connection'));
    expect(mongodb.client.close).toHaveBeenCalledTimes(2);
  });

  it('rejects an unsafe URI before constructing a client', async () => {
    await expect(
      MongoLocalVaultStore.connect('https://example.test/kavrix', DATABASE_NAME),
    ).rejects.toEqual(new MongoLocalVaultError('connection'));
    expect(mongodb.clients).toHaveLength(0);
  });

  it('pings the database and maps driver failures to connection errors', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);

    await expect(store.ping()).resolves.toBeUndefined();
    expect(mongodb.database.command).toHaveBeenCalledWith({ ping: 1 });

    mongodb.database.command.mockRejectedValueOnce(
      new Error('mongodb://user:password@example.test/private'),
    );
    await expect(store.ping()).rejects.toEqual(new MongoLocalVaultError('connection'));
    await store.close();
  });

  it('gets absent and persisted documents while stripping MongoDB _id', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);
    const initial = document();

    await expect(store.get(initial.id)).resolves.toBeNull();
    expect(mongodb.collection.findOne).toHaveBeenCalledWith({ _id: initial.id });

    mongodb.collection.findOne.mockResolvedValueOnce({ ...initial, _id: initial.id });
    await expect(store.get(initial.id)).resolves.toEqual(initial);
    expect(mongodb.collection.findOne).toHaveBeenLastCalledWith({ _id: initial.id });
    await store.close();
  });

  it('rejects invalid ids and corrupt persisted documents without querying further', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);
    const initial = document();
    mongodb.collection.findOne.mockResolvedValueOnce({
      ...initial,
      _id: initial.id,
      revision: 99,
    });

    await expect(store.get('')).rejects.toEqual(new MongoLocalVaultError('invalid'));
    expect(mongodb.collection.findOne).not.toHaveBeenCalled();
    await expect(store.get(initial.id)).rejects.toEqual(
      new MongoLocalVaultError('invalid'),
    );
    await store.close();
  });

  it('maps get driver errors to a redacted operation error', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);
    const driverError = new Error(
      'mongodb://user:password@example.test/private ciphertext AQID',
    );
    mongodb.collection.findOne.mockRejectedValueOnce(driverError);

    await expect(store.get('vault.one')).rejects.toEqual(
      new MongoLocalVaultError('operation'),
    );
    await store.close();
  });

  it('lists ids with a bounded projection and stable ordering', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);
    mongodb.cursor.toArray.mockResolvedValueOnce([
      { _id: 'vault.one' },
      { _id: 'vault.two' },
    ]);

    await expect(store.listVaultIds()).resolves.toEqual(['vault.one', 'vault.two']);
    expect(mongodb.collection.find).toHaveBeenCalledWith(
      {},
      { projection: { _id: 1 } },
    );
    expect(mongodb.cursor.sort).toHaveBeenCalledWith({ _id: 1 });
    await store.close();
  });

  it('maps invalid list rows and list driver failures to store errors', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);
    mongodb.cursor.toArray.mockResolvedValueOnce([{ _id: '' }]);
    await expect(store.listVaultIds()).rejects.toEqual(
      new MongoLocalVaultError('invalid'),
    );

    mongodb.collection.find.mockImplementationOnce(() => {
      throw new Error('driver failure');
    });
    await expect(store.listVaultIds()).rejects.toEqual(
      new MongoLocalVaultError('operation'),
    );
    await store.close();
  });

  it('creates a validated document with the canonical MongoDB id', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);
    const initial = document();

    await expect(store.create(initial)).resolves.toBeUndefined();
    expect(mongodb.collection.insertOne).toHaveBeenCalledWith({
      ...initial,
      _id: initial.id,
    });
    await store.close();
  });

  it('maps invalid, duplicate, and normal create failures', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);
    const initial = document();

    await expect(
      store.create({ ...initial, id: '' } as LocalVaultDocument),
    ).rejects.toEqual(new MongoLocalVaultError('invalid'));
    expect(mongodb.collection.insertOne).not.toHaveBeenCalled();

    const duplicate = Object.assign(new Error('duplicate'), { code: 11_000 });
    mongodb.collection.insertOne.mockRejectedValueOnce(duplicate);
    await expect(store.create(initial)).rejects.toEqual(
      new MongoLocalVaultError('operation'),
    );

    mongodb.collection.insertOne.mockRejectedValueOnce(
      Object.assign(new mongodb.MongoServerError('duplicate'), { code: 11_000 }),
    );
    await expect(store.create(initial)).rejects.toEqual(
      new MongoLocalVaultError('exists'),
    );

    mongodb.collection.insertOne.mockRejectedValueOnce(new Error('driver failure'));
    await expect(store.create(initial)).rejects.toEqual(
      new MongoLocalVaultError('operation'),
    );
    await store.close();
  });

  it('updates with an exact revision CAS filter and selected fields', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);
    const updated = document('vault.one', 1);

    await expect(store.update(updated, revision(0))).resolves.toBeUndefined();
    expect(mongodb.collection.updateOne).toHaveBeenCalledWith(
      { _id: updated.id, revision: revision(0) },
      {
        $set: {
          version: updated.version,
          encryptedPayload: updated.encryptedPayload,
          keySlot: updated.keySlot,
          recoverySlots: updated.recoverySlots,
          currentKeyVersion: updated.currentKeyVersion,
          revision: updated.revision,
          updatedAt: updated.updatedAt,
        },
      },
    );
    await store.close();
  });

  it('rejects invalid update revisions and maps compare-and-set conflicts', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);
    const updated = document('vault.one', 2);

    await expect(store.update(updated, revision(0))).rejects.toEqual(
      new MongoLocalVaultError('invalid'),
    );
    expect(mongodb.collection.updateOne).not.toHaveBeenCalled();

    await expect(
      store.update(document('vault.one', 1), -1 as LocalVaultDocument['revision']),
    ).rejects.toEqual(new MongoLocalVaultError('invalid'));

    mongodb.collection.updateOne.mockResolvedValueOnce({ matchedCount: 0 });
    await expect(store.update(document('vault.one', 1), revision(0))).rejects.toEqual(
      new MongoLocalVaultError('conflict'),
    );
    await store.close();
  });

  it('maps update driver errors to operation errors', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);
    mongodb.collection.updateOne.mockRejectedValueOnce(
      new Error('mongodb://user:password@example.test/private'),
    );

    await expect(store.update(document('vault.one', 1), revision(0))).rejects.toEqual(
      new MongoLocalVaultError('operation'),
    );
    await store.close();
  });

  it('deletes by id and expected revision, then reports conflicts', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);

    await expect(store.delete('vault.one', revision(3))).resolves.toBeUndefined();
    expect(mongodb.collection.deleteOne).toHaveBeenCalledWith({
      _id: 'vault.one',
      revision: revision(3),
    });

    mongodb.collection.deleteOne.mockResolvedValueOnce({ deletedCount: 0 });
    await expect(store.delete('vault.one', revision(3))).rejects.toEqual(
      new MongoLocalVaultError('conflict'),
    );
    await store.close();
  });

  it('rejects invalid delete inputs and maps delete driver errors', async () => {
    const store = await MongoLocalVaultStore.connect(URI, DATABASE_NAME);

    await expect(store.delete('', revision(0))).rejects.toEqual(
      new MongoLocalVaultError('invalid'),
    );
    await expect(
      store.delete('vault.one', -1 as LocalVaultDocument['revision']),
    ).rejects.toEqual(new MongoLocalVaultError('invalid'));
    expect(mongodb.collection.deleteOne).not.toHaveBeenCalled();

    mongodb.collection.deleteOne.mockRejectedValueOnce(new Error('driver failure'));
    await expect(store.delete('vault.one', revision(0))).rejects.toEqual(
      new MongoLocalVaultError('operation'),
    );
    await store.close();
  });
});

function document(id = 'vault.one', revision = 0): LocalVaultDocument {
  const slotId = 'slot.one';
  const metadataDigest = Buffer.alloc(32).toString('base64url');
  const nonce = Buffer.alloc(24).toString('base64url');
  const authenticationTag = Buffer.alloc(16).toString('base64url');
  const wrappedRootKey = {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce,
    ciphertext: Buffer.alloc(32).toString('base64url'),
    authenticationTag,
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: id,
      entityType: 'wrapped-root-key',
      entityId: slotId,
      purpose: 'vrk-slot',
    },
    keyVersion: 1,
  };
  return localVaultDocumentSchema.parse({
    format: 'kavrix-local-vault',
    version: 2,
    id,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    keySlot: {
      slotVersion: 1,
      id: slotId,
      state: 'active',
      keyVersion: 1,
      wrappedRootKey,
      createdAt: TIMESTAMP,
      type: 'portable-key',
      derivation: {
        algorithm: 'hkdf-sha256',
        version: 1,
        salt: Buffer.alloc(32).toString('base64url'),
        context: 'credvault/v1/portable-key-wrap',
        outputLength: 32,
      },
    },
    recoverySlots: [],
    revision,
    encryptedPayload: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce,
      ciphertext: Buffer.from('opaque-ciphertext').toString('base64url'),
      authenticationTag,
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId: id,
        revision,
        metadataDigest,
        entityType: 'vault-preferences',
        entityId: id,
        purpose: 'vault-preferences',
      },
      keyVersion: 1,
    },
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
}

function revision(value: number): LocalVaultDocument['revision'] {
  return vaultRevisionSchema.parse(value);
}

const TIMESTAMP = '2026-08-19T00:00:00.000Z';
