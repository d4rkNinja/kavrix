import { randomBytes } from 'node:crypto';

import { MongoClient } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  EncryptedDatabaseStoreError,
  MongoEncryptedDatabaseStore,
  type EncryptedDatabaseStore,
} from '../src/index.js';
import {
  databaseDocument,
  databaseRevision,
  makeDatabaseId,
  makeVaultId,
  vaultDocument,
  vaultRevision,
} from './database-store-fixtures.js';

const mongoUri = process.env['KAVRIX_MONGODB_URI'];
const databaseName = `kavrixit_${randomBytes(20).toString('hex')}`;
const plaintextCanary = randomBytes(32).toString('base64url');
const integration = mongoUri === undefined ? describe.skip : describe;

integration('MongoEncryptedDatabaseStore replica-set integration', () => {
  let store: EncryptedDatabaseStore | undefined;

  beforeAll(async () => {
    store = await MongoEncryptedDatabaseStore.connect(mongoUri as string, databaseName);
  });

  afterAll(async () => {
    if (store !== undefined) await store.close();
    if (!/^[A-Za-z0-9_-]{1,64}$/u.test(databaseName)) {
      throw new Error(
        'Refusing to drop a database outside the generated test namespace',
      );
    }
    const cleanupClient = new MongoClient(mongoUri as string, {
      connectTimeoutMS: 5_000,
      serverSelectionTimeoutMS: 5_000,
      socketTimeoutMS: 10_000,
      timeoutMS: 10_000,
    });
    try {
      await cleanupClient.connect();
      await cleanupClient.db(databaseName).dropDatabase();
    } finally {
      await cleanupClient.close();
    }
  });

  it('persists two vaults transactionally, detects all revision conflicts, and contains no plaintext canary', async () => {
    const activeStore = store;
    if (activeStore === undefined)
      throw new Error('Integration store was not initialized');
    const databaseId = makeDatabaseId('db_01JMONGOINTEGRATION');
    const firstVaultId = makeVaultId('vault_01JMONGOINTEGRATIONA');
    const secondVaultId = makeVaultId('vault_01JMONGOINTEGRATIONB');
    const initialDatabase = databaseDocument(databaseId, databaseRevision(0));
    await expectStoreError(
      activeStore.createDatabase({ ...initialDatabase, plaintextCanary } as never),
      'invalid',
    );
    await activeStore.createDatabase(initialDatabase);
    await expectStoreError(activeStore.createDatabase(initialDatabase), 'exists');

    const firstVault = vaultDocument(
      databaseId,
      firstVaultId,
      databaseRevision(1),
      vaultRevision(0),
    );
    await activeStore.createVault({
      database: databaseDocument(databaseId, databaseRevision(1)),
      expectedDatabaseRevision: databaseRevision(0),
      vault: firstVault,
    });
    const secondVault = vaultDocument(
      databaseId,
      secondVaultId,
      databaseRevision(2),
      vaultRevision(0),
    );
    await activeStore.createVault({
      database: databaseDocument(databaseId, databaseRevision(2)),
      expectedDatabaseRevision: databaseRevision(1),
      vault: secondVault,
    });

    expect((await activeStore.listVaults(databaseId)).map((vault) => vault.id)).toEqual(
      [firstVaultId, secondVaultId],
    );
    await expectStoreError(
      activeStore.updateDatabase(
        databaseDocument(databaseId, databaseRevision(3)),
        databaseRevision(1),
      ),
      'conflict',
    );
    await expectStoreError(
      activeStore.createVault({
        database: databaseDocument(databaseId, databaseRevision(3)),
        expectedDatabaseRevision: databaseRevision(2),
        vault: vaultDocument(
          databaseId,
          firstVaultId,
          databaseRevision(3),
          vaultRevision(0),
        ),
      }),
      'exists',
    );
    expect((await activeStore.getDatabase(databaseId))?.revision).toBe(
      databaseRevision(2),
    );

    const updatedFirstVault = vaultDocument(
      databaseId,
      firstVaultId,
      databaseRevision(1),
      vaultRevision(1),
    );
    await activeStore.updateVault({
      vault: updatedFirstVault,
      expectedVaultRevision: vaultRevision(0),
    });
    await expectStoreError(
      activeStore.updateVault({
        vault: updatedFirstVault,
        expectedVaultRevision: vaultRevision(0),
      }),
      'conflict',
    );
    await expectStoreError(
      activeStore.updateVault({
        vault: vaultDocument(
          databaseId,
          makeVaultId('vault_01JMONGOINTEGRATIONMISSING'),
          databaseRevision(2),
          vaultRevision(1),
        ),
        expectedVaultRevision: vaultRevision(0),
      }),
      'conflict',
    );

    const deletionDatabase = databaseDocument(databaseId, databaseRevision(3));
    await expectStoreError(
      activeStore.deleteVault({
        database: deletionDatabase,
        expectedDatabaseRevision: databaseRevision(2),
        vaultId: firstVaultId,
        expectedVaultRevision: vaultRevision(0),
      }),
      'conflict',
    );
    await expectStoreError(
      activeStore.deleteVault({
        database: deletionDatabase,
        expectedDatabaseRevision: databaseRevision(1),
        vaultId: firstVaultId,
        expectedVaultRevision: vaultRevision(1),
      }),
      'conflict',
    );
    await activeStore.deleteVault({
      database: deletionDatabase,
      expectedDatabaseRevision: databaseRevision(2),
      vaultId: firstVaultId,
      expectedVaultRevision: vaultRevision(1),
    });
    expect(await activeStore.getVault(databaseId, firstVaultId)).toBeNull();

    const scanner = new MongoClient(mongoUri as string);
    try {
      await scanner.connect();
      const collections = ['kavrix_databases', 'kavrix_vaults'];
      for (const collectionName of collections) {
        const documents = await scanner
          .db(databaseName)
          .collection(collectionName)
          .find({})
          .toArray();
        for (const document of documents) {
          expect(JSON.stringify(document)).not.toContain(plaintextCanary);
        }
      }
    } finally {
      await scanner.close();
    }
  });
});

async function expectStoreError(
  operation: Promise<unknown>,
  code: EncryptedDatabaseStoreError['code'],
): Promise<void> {
  await expect(operation).rejects.toMatchObject({ code });
}
