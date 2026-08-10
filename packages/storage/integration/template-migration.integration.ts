import { randomUUID } from 'node:crypto';

import { SyncConflictError } from '@kavrix/core';
import {
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  opaqueMutationSchema,
  syncCursorSchema,
  templateMigrationPublicationRequestSchema,
  type EncryptedItemRecord,
  type OpaqueMutation,
  type TemplateMigrationPublicationRequest,
} from '@kavrix/schemas';
import { MongoClient, type Db } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { MongoVaultStorage, mongoStorageCollectionNames } from '../src/index.js';
import {
  groupRecord,
  itemRecord,
  later,
  mutation,
  plaintextCanary,
  timestamp,
  vaultRecord,
} from '../test/fixtures.js';

const mongodbUri = process.env['KAVRIX_MONGODB_URI'];
if (mongodbUri === undefined || mongodbUri.length === 0) {
  throw new Error(
    'KAVRIX_MONGODB_URI is required and must select a transaction-capable MongoDB 7 replica set.',
  );
}

type TestContext = Readonly<{
  database: Db;
  storage: MongoVaultStorage;
  itemOne: EncryptedItemRecord;
  itemTwo: EncryptedItemRecord;
  cursor: ReturnType<typeof syncCursorSchema.parse>;
}>;

describe('atomic group-template migration publication', () => {
  const client = new MongoClient(mongodbUri, {
    appName: 'kavrix-template-migration-integration',
  });

  beforeAll(async () => client.connect());
  afterAll(async () => client.close());

  it('publishes one opaque migration atomically and replays a lost response exactly', async () => {
    await withStorage(
      client,
      async ({ database, storage, itemOne, itemTwo, cursor }) => {
        const batch = migrationBatch(itemOne, itemTwo);
        const publication = storage.publishTemplateMigration(batch);
        const observation = storage.pullSyncPage(cursor, 100);
        const [response, during] = await Promise.all([publication, observation]);
        expect([0, 3]).toContain(during.changes.length);
        if (during.changes.length > 0) {
          expect(during.changes).toHaveLength(3);
        }
        expect(response).toMatchObject({
          vaultId: 'vault.1',
          batchIdempotencyKey: batch.batchIdempotencyKey,
          serverVaultRevision: 6,
        });
        expect(response.results.map(({ change }) => change.serverSequence)).toEqual([
          5, 6, 7,
        ]);
        expect(response.results.map(({ change }) => change.entityType)).toEqual([
          'item',
          'item',
          'group',
        ]);

        const pulled = await storage.pullSyncPage(cursor, 100);
        expect(pulled.changes).toHaveLength(3);
        expect(pulled.changes.map(({ change }) => change.entityType)).toEqual([
          'item',
          'item',
          'group',
        ]);
        expect(pulled.changes.map(({ record }) => record)).toEqual(
          batch.mutations.map(({ record }) => record),
        );
        await expect(storage.publishTemplateMigration(batch)).resolves.toEqual(
          response,
        );

        const raw = await Promise.all(
          Object.values(mongoStorageCollectionNames).map((collection) =>
            database.collection(collection).find({}).toArray(),
          ),
        );
        expect(JSON.stringify(raw)).not.toContain(plaintextCanary);
        expect(
          await database
            .collection(mongoStorageCollectionNames.templateMigrationPublications)
            .countDocuments(),
        ).toBe(1);
      },
    );
  });

  it('fails stale, cross-group, duplicate, tombstoned, and incompatible-key batches without writes', async () => {
    await withStorage(client, async (context) => {
      const base = migrationBatch(context.itemOne, context.itemTwo);
      const staleItem = migratedItem(context.itemOne, 2);
      const stale = templateMigrationPublicationRequestSchema.parse({
        ...base,
        batchIdempotencyKey: 'migration-stale-batch-0001',
        mutations: [
          opaqueMutationSchema.parse({
            entityType: 'item',
            expectedRecordRevision: 1,
            idempotencyKey: 'migration-stale-item-0001',
            record: staleItem,
          }),
          base.mutations[1],
          base.mutations[2],
        ],
      });
      await expectNoWrites(context, stale);
    });

    await withStorage(client, async (context) => {
      const base = migrationBatch(context.itemOne, context.itemTwo);
      const crossedItem = rebindItemGroup(
        migratedItem(context.itemOne, 1),
        'group.other',
      );
      await expectNoWrites(context, {
        ...base,
        batchIdempotencyKey: 'migration-cross-batch-0001',
        mutations: [
          {
            ...base.mutations[0],
            idempotencyKey: 'migration-cross-item-0001',
            record: crossedItem,
          },
          base.mutations[1],
          base.mutations[2],
        ],
      } as never);
    });

    await withStorage(client, async (context) => {
      const base = migrationBatch(context.itemOne, context.itemTwo);
      await expectNoWrites(context, {
        ...base,
        batchIdempotencyKey: 'migration-duplicate-batch-01',
        mutations: [base.mutations[0], base.mutations[0], base.mutations[2]],
      } as never);
    });

    await withStorage(client, async (context) => {
      await context.storage.commit(
        mutation('item', itemRecord(1, later), 0, 'migration-delete-item-0001'),
      );
      const base = migrationBatch(context.itemOne, context.itemTwo, 1);
      await expectNoWrites(context, base);
    });

    await withStorage(client, async (context) => {
      const base = migrationBatch(context.itemOne, context.itemTwo);
      const first = base.mutations[0];
      if (first?.entityType !== 'item') throw new Error('Expected item mutation');
      const incompatible = encryptedItemRecordSchema.parse({
        ...first.record,
        wrappedItemKey: {
          ...first.record.wrappedItemKey,
          ciphertext: 'BAUG',
        },
      });
      const batch = templateMigrationPublicationRequestSchema.parse({
        ...base,
        batchIdempotencyKey: 'migration-incompatible-0001',
        mutations: [{ ...first, record: incompatible }, ...base.mutations.slice(1)],
      });
      await expectNoWrites(context, batch);
    });
  });

  it('serializes concurrent identical and competing migrations safely', async () => {
    await withStorage(client, async (context) => {
      const batch = migrationBatch(context.itemOne, context.itemTwo);
      const [left, right] = await Promise.all([
        context.storage.publishTemplateMigration(batch),
        context.storage.publishTemplateMigration(batch),
      ]);
      expect(left).toEqual(right);
      expect(
        await context.database
          .collection(mongoStorageCollectionNames.changes)
          .countDocuments(),
      ).toBe(7);
    });

    await withStorage(client, async (context) => {
      const first = migrationBatch(context.itemOne, context.itemTwo);
      const second = migrationBatch(
        context.itemOne,
        context.itemTwo,
        1,
        'migration-competing-batch-01',
        'competing',
      );
      const settled = await Promise.allSettled([
        context.storage.publishTemplateMigration(first),
        context.storage.publishTemplateMigration(second),
      ]);
      expect(settled.filter(({ status }) => status === 'fulfilled')).toHaveLength(1);
      const rejected = settled.find(({ status }) => status === 'rejected');
      if (rejected?.status !== 'rejected') {
        throw new Error('Expected one competing migration to fail');
      }
      const reason: unknown = rejected.reason;
      expect(reason).toBeInstanceOf(SyncConflictError);
      expect(
        await context.database
          .collection(mongoStorageCollectionNames.changes)
          .countDocuments(),
      ).toBe(7);
      expect(
        await context.database
          .collection(mongoStorageCollectionNames.templateMigrationPublications)
          .countDocuments(),
      ).toBe(1);
    });
  });
});

async function withStorage(
  client: MongoClient,
  work: (context: TestContext) => Promise<void>,
): Promise<void> {
  const database = client.db(
    `kavrix_template_migration_${randomUUID().replaceAll('-', '')}`,
  );
  const storage = new MongoVaultStorage(client, database, {
    now: () => new Date(timestamp),
  });
  try {
    await storage.initialize();
    const itemOne = itemRecord();
    const itemTwo = secondItemRecord();
    await storage.commit(
      mutation('vault', vaultRecord(), null, 'migration-vault-init-0001'),
    );
    await storage.commit(
      mutation('group', groupRecord(), null, 'migration-group-init-0001'),
    );
    await storage.commit(mutation('item', itemOne, null, 'migration-item-one-init'));
    await storage.commit(mutation('item', itemTwo, null, 'migration-item-two-init'));
    await work({
      database,
      storage,
      itemOne,
      itemTwo,
      cursor: syncCursorSchema.parse({
        vaultId: 'vault.1',
        serverSequence: 4,
        highestSeenVaultRevision: 3,
      }),
    });
  } finally {
    await database.dropDatabase();
  }
}

async function expectNoWrites(
  context: TestContext,
  batch: TemplateMigrationPublicationRequest,
): Promise<void> {
  const before = await durableState(context);
  await expect(context.storage.publishTemplateMigration(batch)).rejects.toThrow();
  expect(await durableState(context)).toEqual(before);
}

async function durableState(context: TestContext): Promise<unknown> {
  const [vault, groups, items, changes, counters, idempotency, receipts] =
    await Promise.all([
      context.database
        .collection(mongoStorageCollectionNames.vaults)
        .find({})
        .toArray(),
      context.database
        .collection(mongoStorageCollectionNames.groups)
        .find({})
        .toArray(),
      context.database.collection(mongoStorageCollectionNames.items).find({}).toArray(),
      context.database
        .collection(mongoStorageCollectionNames.changes)
        .find({})
        .toArray(),
      context.database
        .collection(mongoStorageCollectionNames.counters)
        .find({})
        .toArray(),
      context.database
        .collection(mongoStorageCollectionNames.idempotency)
        .find({})
        .toArray(),
      context.database
        .collection(mongoStorageCollectionNames.templateMigrationPublications)
        .find({})
        .toArray(),
    ]);
  return { vault, groups, items, changes, counters, idempotency, receipts };
}

function migrationBatch(
  itemOne: EncryptedItemRecord,
  itemTwo: EncryptedItemRecord,
  expectedRevision = 0,
  batchIdempotencyKey = 'migration-atomic-batch-0001',
  keySuffix = 'primary',
): TemplateMigrationPublicationRequest {
  const items = [itemOne, itemTwo]
    .map((record) => migratedItem(record, expectedRevision + 1))
    .sort((left, right) => left.id.localeCompare(right.id));
  const group = encryptedGroupRecordSchema.parse({
    ...groupRecord(expectedRevision + 1),
    templateVersion: 2,
    updatedAt: later,
  });
  const mutations: OpaqueMutation[] = [
    ...items.map((record, index) =>
      opaqueMutationSchema.parse({
        entityType: 'item',
        expectedRecordRevision: expectedRevision,
        idempotencyKey: `migration-${keySuffix}-item-${String(index + 1).padStart(4, '0')}`,
        record,
      }),
    ),
    opaqueMutationSchema.parse({
      entityType: 'group',
      expectedRecordRevision: expectedRevision,
      idempotencyKey: `migration-${keySuffix}-group-0001`,
      record: group,
    }),
  ];
  return templateMigrationPublicationRequestSchema.parse({
    vaultId: 'vault.1',
    batchIdempotencyKey,
    mutations,
  });
}

function migratedItem(
  current: EncryptedItemRecord,
  revision: number,
): EncryptedItemRecord {
  return encryptedItemRecordSchema.parse({
    ...current,
    recordRevision: revision,
    encryptedPayload: {
      ...current.encryptedPayload,
      ciphertext: Buffer.from(
        `${plaintextCanary}-migration-${current.id}-${String(revision)}`,
      ).toString('base64url'),
    },
    updatedAt: later,
  });
}

function secondItemRecord(): EncryptedItemRecord {
  const current = itemRecord();
  return encryptedItemRecordSchema.parse({
    ...current,
    id: 'item.2',
    wrappedItemKey: {
      ...current.wrappedItemKey,
      aad: { ...current.wrappedItemKey.aad, entityId: 'item.2' },
    },
    encryptedPayload: {
      ...current.encryptedPayload,
      aad: { ...current.encryptedPayload.aad, entityId: 'item.2' },
    },
  });
}

function rebindItemGroup(
  current: EncryptedItemRecord,
  groupId: string,
): EncryptedItemRecord {
  return encryptedItemRecordSchema.parse({
    ...current,
    groupId,
    wrappedItemKey: {
      ...current.wrappedItemKey,
      aad: { ...current.wrappedItemKey.aad, groupId },
    },
    encryptedPayload: {
      ...current.encryptedPayload,
      aad: { ...current.encryptedPayload.aad, groupId },
    },
  });
}
