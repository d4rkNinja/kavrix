import { randomBytes } from 'node:crypto';

import {
  encryptAead,
  encryptDatabaseCatalog,
  generateDatabaseRootKey,
  generateVaultRootKey,
  wrapVaultRootForDatabase,
  zeroize,
  type DatabaseRootKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import { Binary, MongoClient } from 'mongodb';
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

  it('installs the required idempotent vault discovery index', async () => {
    const inspectionClient = new MongoClient(mongoUri as string, {
      connectTimeoutMS: 5_000,
      serverSelectionTimeoutMS: 5_000,
      socketTimeoutMS: 10_000,
      timeoutMS: 10_000,
    });
    try {
      await inspectionClient.connect();
      const databaseIndexes = await inspectionClient
        .db(databaseName)
        .collection('kavrix_databases')
        .listIndexes()
        .toArray();
      const vaultIndexes = await inspectionClient
        .db(databaseName)
        .collection('kavrix_vaults')
        .listIndexes()
        .toArray();
      expect(databaseIndexes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: '_id_', key: { _id: 1 } }),
        ]),
      );
      expect(vaultIndexes).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: '_id_', key: { _id: 1 } }),
          expect.objectContaining({
            name: 'database_vault_identity',
            key: { databaseId: 1, id: 1 },
            unique: true,
          }),
        ]),
      );
    } finally {
      await inspectionClient.close();
    }
  });

  it('persists two vaults transactionally, detects all revision conflicts, and contains no plaintext canary', async () => {
    const activeStore = store;
    if (activeStore === undefined)
      throw new Error('Integration store was not initialized');
    const canarySeed = randomBytes(32);
    const plaintextCanary = canarySeed.toString('base64url');
    zeroize(canarySeed);
    const plaintextCanaryBytes = new TextEncoder().encode(plaintextCanary);
    const databaseRootKey = generateDatabaseRootKey();
    const firstVaultRootKey = generateVaultRootKey();
    const secondVaultRootKey = generateVaultRootKey();
    const missingVaultRootKey = generateVaultRootKey();
    const databaseId = makeDatabaseId('db_01JMONGOINTEGRATION');
    const firstVaultId = makeVaultId('vault_01JMONGOINTEGRATIONA');
    const secondVaultId = makeVaultId('vault_01JMONGOINTEGRATIONB');
    try {
      const initialDatabase = await encryptedDatabaseDocument(
        databaseId,
        databaseRevision(0),
        databaseRootKey,
        plaintextCanaryBytes,
      );
      await expectStoreError(
        activeStore.createDatabase({ ...initialDatabase, plaintextCanary } as never),
        'invalid',
      );
      await activeStore.createDatabase(initialDatabase);
      await expectStoreError(activeStore.createDatabase(initialDatabase), 'exists');

      const firstDatabaseUpdate = await encryptedDatabaseDocument(
        databaseId,
        databaseRevision(1),
        databaseRootKey,
        plaintextCanaryBytes,
      );
      const firstVault = await encryptedVaultDocument(
        databaseId,
        firstVaultId,
        databaseRevision(1),
        vaultRevision(0),
        databaseRootKey,
        firstVaultRootKey,
        plaintextCanaryBytes,
      );
      await activeStore.createVault({
        database: firstDatabaseUpdate,
        expectedDatabaseRevision: databaseRevision(0),
        vault: firstVault,
      });
      const secondDatabaseUpdate = await encryptedDatabaseDocument(
        databaseId,
        databaseRevision(2),
        databaseRootKey,
        plaintextCanaryBytes,
      );
      const secondVault = await encryptedVaultDocument(
        databaseId,
        secondVaultId,
        databaseRevision(2),
        vaultRevision(0),
        databaseRootKey,
        secondVaultRootKey,
        plaintextCanaryBytes,
      );
      await activeStore.createVault({
        database: secondDatabaseUpdate,
        expectedDatabaseRevision: databaseRevision(1),
        vault: secondVault,
      });

      expect(
        (await activeStore.listVaults(databaseId)).map((vault) => vault.id),
      ).toEqual([firstVaultId, secondVaultId]);
      const thirdDatabaseUpdate = await encryptedDatabaseDocument(
        databaseId,
        databaseRevision(3),
        databaseRootKey,
        plaintextCanaryBytes,
      );
      await expectStoreError(
        activeStore.updateDatabase(thirdDatabaseUpdate, databaseRevision(1)),
        'conflict',
      );
      await expectStoreError(
        activeStore.createVault({
          database: thirdDatabaseUpdate,
          expectedDatabaseRevision: databaseRevision(2),
          vault: await encryptedVaultDocument(
            databaseId,
            firstVaultId,
            databaseRevision(3),
            vaultRevision(0),
            databaseRootKey,
            firstVaultRootKey,
            plaintextCanaryBytes,
          ),
        }),
        'exists',
      );
      expect((await activeStore.getDatabase(databaseId))?.revision).toBe(
        databaseRevision(2),
      );

      const updatedFirstVault = await encryptedVaultDocument(
        databaseId,
        firstVaultId,
        databaseRevision(1),
        vaultRevision(1),
        databaseRootKey,
        firstVaultRootKey,
        plaintextCanaryBytes,
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
          vault: await encryptedVaultDocument(
            databaseId,
            makeVaultId('vault_01JMONGOINTEGRATIONMISSING'),
            databaseRevision(2),
            vaultRevision(1),
            databaseRootKey,
            missingVaultRootKey,
            plaintextCanaryBytes,
          ),
          expectedVaultRevision: vaultRevision(0),
        }),
        'conflict',
      );

      await expectStoreError(
        activeStore.deleteVault({
          database: thirdDatabaseUpdate,
          expectedDatabaseRevision: databaseRevision(2),
          vaultId: firstVaultId,
          expectedVaultRevision: vaultRevision(0),
        }),
        'conflict',
      );
      await expectStoreError(
        activeStore.deleteVault({
          database: thirdDatabaseUpdate,
          expectedDatabaseRevision: databaseRevision(1),
          vaultId: firstVaultId,
          expectedVaultRevision: vaultRevision(1),
        }),
        'conflict',
      );
      await activeStore.deleteVault({
        database: thirdDatabaseUpdate,
        expectedDatabaseRevision: databaseRevision(2),
        vaultId: firstVaultId,
        expectedVaultRevision: vaultRevision(1),
      });
      expect(await activeStore.getVault(databaseId, firstVaultId)).toBeNull();

      const scanner = new MongoClient(mongoUri as string);
      try {
        await scanner.connect();
        for (const collectionName of ['kavrix_databases', 'kavrix_vaults']) {
          const documents = await scanner
            .db(databaseName)
            .collection(collectionName)
            .find({})
            .toArray();
          for (const document of documents) {
            assertCanaryAbsent(document, plaintextCanary, plaintextCanaryBytes);
          }
        }
      } finally {
        await scanner.close();
      }
    } finally {
      zeroize(plaintextCanaryBytes);
      zeroize(databaseRootKey);
      zeroize(firstVaultRootKey);
      zeroize(secondVaultRootKey);
      zeroize(missingVaultRootKey);
    }
  });
});

async function encryptedDatabaseDocument(
  databaseId: ReturnType<typeof makeDatabaseId>,
  revision: ReturnType<typeof databaseRevision>,
  databaseRootKey: DatabaseRootKey,
  plaintext: Uint8Array,
) {
  const document = databaseDocument(databaseId, revision);
  return {
    ...document,
    encryptedCatalog: await encryptDatabaseCatalog(
      plaintext,
      databaseRootKey,
      document.encryptedCatalog.aad,
    ),
  };
}

async function encryptedVaultDocument(
  databaseId: ReturnType<typeof makeDatabaseId>,
  vaultId: ReturnType<typeof makeVaultId>,
  databaseRevisionValue: ReturnType<typeof databaseRevision>,
  revision: ReturnType<typeof vaultRevision>,
  databaseRootKey: DatabaseRootKey,
  vaultRootKey: VaultRootKey,
  plaintext: Uint8Array,
) {
  const document = vaultDocument(databaseId, vaultId, databaseRevisionValue, revision);
  return {
    ...document,
    wrappedVaultRoot: await wrapVaultRootForDatabase(
      vaultRootKey,
      databaseRootKey,
      document.wrappedVaultRoot.aad,
    ),
    encryptedPayload: await encryptAead(
      plaintext,
      vaultRootKey,
      document.encryptedPayload.aad,
    ),
  };
}

function assertCanaryAbsent(
  value: unknown,
  plaintextCanary: string,
  plaintextCanaryBytes: Uint8Array,
  seen = new WeakSet<object>(),
): void {
  if (typeof value === 'string') {
    expect(value).not.toContain(plaintextCanary);
    return;
  }
  if (value instanceof Uint8Array) {
    expect(containsBytes(value, plaintextCanaryBytes)).toBe(false);
    return;
  }
  if (value === null || value === undefined) return;
  if (typeof value !== 'object') {
    expect(String(value)).not.toContain(plaintextCanary);
    return;
  }
  if (seen.has(value)) return;
  seen.add(value);
  if (value instanceof Binary) {
    expect(containsBytes(value.buffer, plaintextCanaryBytes)).toBe(false);
  }
  expect(String(value)).not.toContain(plaintextCanary);
  for (const nested of Object.values(value)) {
    assertCanaryAbsent(nested, plaintextCanary, plaintextCanaryBytes, seen);
  }
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.byteLength === 0 || needle.byteLength > haystack.byteLength) return false;
  for (let offset = 0; offset <= haystack.byteLength - needle.byteLength; offset += 1) {
    let matches = true;
    for (let index = 0; index < needle.byteLength; index += 1) {
      if (haystack[offset + index] !== needle[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

async function expectStoreError(
  operation: Promise<unknown>,
  code: EncryptedDatabaseStoreError['code'],
): Promise<void> {
  await expect(operation).rejects.toMatchObject({ code });
}
