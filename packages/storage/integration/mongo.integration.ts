import { randomUUID } from 'node:crypto';

import { SyncConflictError } from '@kavrix/core';
import {
  attachmentIdSchema,
  attachmentHeaderContentHash,
  attachmentStreamFinalizeInputSchema,
  attachmentStreamStartInputSchema,
  encryptedItemRecordSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  syncCursorSchema,
  syncPushRequestSchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { MongoClient, type Db } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { MongoVaultStorage, mongoStorageCollectionNames } from '../src/index.js';
import {
  attachmentChunk,
  attachmentFinalize,
  attachmentStart,
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

type RawMongoDocument = { _id: string } & Record<string, unknown>;

describe('MongoVaultStorage against MongoDB 7', () => {
  const client = new MongoClient(mongodbUri, { appName: 'kavrix-storage-integration' });
  const databaseName = `kavrix_storage_test_${randomUUID().replaceAll('-', '')}`;
  let database: Db;
  let storage: MongoVaultStorage;

  beforeAll(async () => {
    await client.connect();
    database = client.db(databaseName);
    storage = new MongoVaultStorage(client, database, {
      now: () => new Date(timestamp),
    });
    await storage.initialize();
  });

  afterAll(async () => {
    await client.db(databaseName).dropDatabase();
    await client.close();
  });

  it('commits opaque records idempotently with monotonic changes and no plaintext', async () => {
    const vaultMutation = mutation('vault', vaultRecord(), null);
    const groupMutation = mutation('group', groupRecord(), null);
    const itemMutation = mutation('item', itemRecord(), null);

    await storage.commit(vaultMutation);
    await expect(storage.getVault(vaultRecord().id)).resolves.toMatchObject({
      revision: 0,
    });
    await storage.commit(groupMutation);
    await expect(storage.getVault(vaultRecord().id)).resolves.toMatchObject({
      revision: 1,
    });
    await storage.commit(itemMutation);
    await expect(storage.getVault(vaultRecord().id)).resolves.toMatchObject({
      revision: 2,
    });
    await storage.commit(itemMutation);

    await expect(
      storage.getGroup(groupRecord().vaultId, groupRecord().id),
    ).resolves.toEqual(groupRecord());
    await expect(
      storage.getItem(itemRecord().vaultId, itemRecord().id),
    ).resolves.toEqual(itemRecord());

    const rawItem = await database
      .collection<RawMongoDocument>(mongoStorageCollectionNames.items)
      .findOne({ itemId: itemRecord().id });
    expect(rawItem).not.toBeNull();
    expect(JSON.stringify(rawItem)).not.toContain(plaintextCanary);
    expect(rawItem).not.toHaveProperty('title');
    expect(rawItem).not.toHaveProperty('record.title');

    if (rawItem === null) throw new Error('Expected the stored item fixture');
    await expect(
      database
        .collection<RawMongoDocument>(mongoStorageCollectionNames.items)
        .insertOne({
          ...rawItem,
          _id: 'vault.1|item.invalid',
          itemId: 'item.invalid',
          record: {
            ...asPlainDocument(rawItem['record']),
            title: plaintextCanary,
          },
        }),
    ).rejects.toThrow();

    await expect(
      storage.commit(mutation('item', itemRecord(), null, itemMutation.idempotencyKey)),
    ).resolves.toBeUndefined();
    await expect(
      storage.commit(
        mutation(
          'item',
          { ...itemRecord(), updatedAt: later },
          null,
          itemMutation.idempotencyKey,
        ),
      ),
    ).rejects.toThrow(SyncConflictError);
    await expect(
      storage.commit(mutation('item', itemRecord(), null, 'idempotency-item-conflict')),
    ).rejects.toThrow(SyncConflictError);

    const changes = await storage.pullChanges(
      syncCursorSchema.parse({
        vaultId: 'vault.1',
        serverSequence: 0,
        highestSeenVaultRevision: 0,
      }),
      100,
    );
    expect(
      changes.map(({ serverSequence, entityType }) => [serverSequence, entityType]),
    ).toEqual([
      [1, 'vault'],
      [2, 'group'],
      [3, 'item'],
    ]);

    const firstPage = await storage.pullSyncPage(
      syncCursorSchema.parse({
        vaultId: 'vault.1',
        serverSequence: 0,
        highestSeenVaultRevision: 0,
      }),
      2,
    );
    expect(firstPage).toMatchObject({
      serverVaultRevision: 2,
      hasMore: true,
      nextCursor: { serverSequence: 2, highestSeenVaultRevision: 2 },
    });
    expect(firstPage.changes.map(({ record }) => record)).toEqual([
      vaultRecord(),
      groupRecord(),
    ]);
    const secondPage = await storage.pullSyncPage(firstPage.nextCursor, 2);
    expect(secondPage).toMatchObject({
      serverVaultRevision: 2,
      hasMore: false,
      nextCursor: { serverSequence: 3, highestSeenVaultRevision: 2 },
    });
    expect(secondPage.changes[0]?.record).toEqual(itemRecord());
  });

  it('keeps staged chunks hidden and publishes a contiguous stream atomically', async () => {
    const session = await storage.beginAttachmentStream(attachmentStart());
    expect(session.progress.state).toBe('empty');
    const first = attachmentChunk(0, 'message');
    const second = attachmentChunk(1, 'final');
    await expect(session.writeChunk(first)).resolves.toMatchObject({
      state: 'writing',
      nextChunkIndex: 1,
    });
    await expect(session.writeChunk(first)).resolves.toMatchObject({
      state: 'writing',
      nextChunkIndex: 1,
    });
    await expect(
      storage.getAttachment(
        attachmentStart().header.record.vaultId,
        attachmentStart().header.record.attachmentId,
      ),
    ).resolves.toBeNull();
    await expect(
      storage.getAttachmentChunk(
        attachmentStart().header.record.vaultId,
        attachmentStart().header.record.attachmentId,
        0,
      ),
    ).resolves.toBeNull();

    await expect(session.writeChunk(second)).resolves.toMatchObject({
      state: 'ready-to-finalize',
      nextChunkIndex: 2,
    });
    await session.finalize(attachmentFinalize());
    await session.finalize(attachmentFinalize());
    await expect(storage.getVault(vaultRecord().id)).resolves.toMatchObject({
      revision: 3,
    });

    await expect(
      storage.getAttachment(
        attachmentStart().header.record.vaultId,
        attachmentStart().header.record.attachmentId,
      ),
    ).resolves.toEqual(attachmentFinalize().record);
    await expect(
      storage.getAttachmentStreamHeader(
        attachmentStart().header.record.vaultId,
        attachmentStart().header.record.attachmentId,
      ),
    ).resolves.toEqual(attachmentStart().header);

    const chunks = [];
    for await (const chunk of storage.listAttachmentChunks(
      attachmentStart().header.record.vaultId,
      attachmentStart().header.record.attachmentId,
      0,
    )) {
      chunks.push(chunk);
    }
    expect(chunks).toEqual([first, second]);

    const rawAttachment = await database
      .collection<RawMongoDocument>(mongoStorageCollectionNames.attachments)
      .findOne({ attachmentId: attachmentStart().header.record.attachmentId });
    const rawChunks = await database
      .collection<RawMongoDocument>(mongoStorageCollectionNames.attachmentStagingChunks)
      .find({ attachmentId: attachmentStart().header.record.attachmentId })
      .toArray();
    expect(JSON.stringify([rawAttachment, rawChunks])).not.toContain(plaintextCanary);
    expect(
      rawChunks.every(
        (document) =>
          asPlainDocument(document['record'])['entityType'] === 'attachment-chunk',
      ),
    ).toBe(true);
  });

  it('discards aborted staging and persists item tombstone/restore transitions', async () => {
    const baseStart = attachmentStart();
    const abortHeader = persistedAttachmentHeaderRecordSchema.parse({
      ...baseStart.header,
      record: {
        ...baseStart.header.record,
        attachmentId: 'attachment.abort',
      },
    });
    const abortStart = attachmentStreamStartInputSchema.parse({
      ...baseStart,
      idempotencyKey: 'attachment-stream-abort-0001',
      header: {
        ...abortHeader,
        contentHash: attachmentHeaderContentHash(abortHeader),
      },
    });
    const baseChunk = attachmentChunk(0, 'final');
    const abortChunk = persistedAttachmentChunkRecordSchema.parse({
      ...baseChunk,
      record: {
        ...baseChunk.record,
        attachmentId: 'attachment.abort',
      },
    });
    const session = await storage.beginAttachmentStream(abortStart);
    await session.writeChunk(abortChunk);
    await storage.commit(
      mutation('item', itemRecord(1, later), 0, 'idempotency-item-delete-0001'),
    );
    await expect(storage.getVault(vaultRecord().id)).resolves.toMatchObject({
      revision: 4,
    });
    await expect(
      storage.getItem(itemRecord().vaultId, itemRecord().id),
    ).resolves.toBeNull();

    const baseFinalize = attachmentFinalize(1);
    const abortFinalize = attachmentStreamFinalizeInputSchema.parse({
      ...baseFinalize,
      record: {
        ...baseFinalize.record,
        id: 'attachment.abort',
        wrappedAttachmentKey: {
          ...baseFinalize.record.wrappedAttachmentKey,
          aad: {
            ...baseFinalize.record.wrappedAttachmentKey.aad,
            entityId: 'attachment.abort',
          },
        },
        encryptedManifest: {
          ...baseFinalize.record.encryptedManifest,
          aad: {
            ...baseFinalize.record.encryptedManifest.aad,
            entityId: 'attachment.abort',
          },
        },
      },
    });
    await expect(session.finalize(abortFinalize)).rejects.toThrow(SyncConflictError);
    await session.abort();
    await session.abort();
    expect(
      await database
        .collection(mongoStorageCollectionNames.attachmentStagingChunks)
        .countDocuments({ attachmentId: 'attachment.abort' }),
    ).toBe(0);
    await expect(
      storage.getAttachmentChunk(
        abortStart.header.record.vaultId,
        attachmentIdSchema.parse('attachment.abort'),
        0,
      ),
    ).resolves.toBeNull();

    const restoredItem = encryptedItemRecordSchema.parse({
      ...itemRecord(2),
      ciphertextHash: Buffer.alloc(32, 3).toString('base64url'),
      encryptedPayload: {
        ...itemRecord(2).encryptedPayload,
        ciphertext: Buffer.from('restored-current-ciphertext', 'utf8').toString(
          'base64url',
        ),
      },
    });
    await storage.commit(
      mutation('item', restoredItem, 1, 'idempotency-item-restore-0001'),
    );
    await expect(storage.getVault(vaultRecord().id)).resolves.toMatchObject({
      revision: 5,
    });
    await expect(
      storage.getItem(itemRecord().vaultId, itemRecord().id),
    ).resolves.toEqual(restoredItem);

    const changes = await storage.pullChanges(
      syncCursorSchema.parse({
        vaultId: 'vault.1',
        serverSequence: 4,
        highestSeenVaultRevision: 0,
      }),
      100,
    );
    expect(changes.map(({ operation }) => operation)).toEqual(['tombstone', 'restore']);
    const page = await storage.pullSyncPage(
      syncCursorSchema.parse({
        vaultId: 'vault.1',
        serverSequence: 4,
        highestSeenVaultRevision: 3,
      }),
      100,
    );
    expect(page.serverVaultRevision).toBe(5);
    expect(page.changes[0]).toMatchObject({
      change: { operation: 'tombstone' },
      record: { state: 'deleted', tombstoneRevision: 1 },
    });
    expect(page.changes[1]).toEqual({
      change: changes[1],
      record: restoredItem,
    });
    expect(page.changes[1]?.record).toMatchObject({
      recordRevision: 2,
      encryptedPayload: { ciphertext: restoredItem.encryptedPayload.ciphertext },
    });
  });

  it('accepts the next full-vault mutation from the synchronized revision', async () => {
    await storage.commit(
      mutation('vault', vaultRecord(6), 5, 'idempotency-vault-update-0001'),
    );
    await expect(storage.getVault(vaultRecord().id)).resolves.toEqual(vaultRecord(6));

    const page = await storage.pullSyncPage(
      syncCursorSchema.parse({
        vaultId: 'vault.1',
        serverSequence: 6,
        highestSeenVaultRevision: 6,
      }),
      10,
    );
    expect(page).toMatchObject({
      serverVaultRevision: 6,
      hasMore: false,
      changes: [
        {
          change: { serverSequence: 7, entityType: 'vault', recordRevision: 6 },
          record: { revision: 6 },
        },
      ],
    });
  });

  it('checkpoints ordered mixed push results and replays batches exactly', async () => {
    const first = mutation('vault', vaultRecord(7), 6, 'idempotency-push-vault-0001');
    const conflict = mutation(
      'vault',
      vaultRecord(7),
      6,
      'idempotency-push-vault-0002',
    );
    const third = mutation('vault', vaultRecord(8), 7, 'idempotency-push-vault-0003');
    const batch = syncPushRequestSchema.parse({
      vaultId: 'vault.1',
      batchIdempotencyKey: 'sync-push-batch-0001',
      mutations: [first, conflict, third],
    });
    const response = await storage.pushSyncBatch(batch);
    expect(response).toMatchObject({
      serverVaultRevision: 8,
      results: [
        { status: 'accepted', disposition: 'committed' },
        {
          status: 'conflict',
          currentRevision: 7,
          current: { id: 'vault.1', revision: 7 },
        },
        { status: 'accepted', disposition: 'committed' },
      ],
    });
    await expect(storage.pushSyncBatch(batch)).resolves.toEqual(response);
    await expect(storage.getVault(vaultRecord().id)).resolves.toEqual(vaultRecord(8));

    const duplicateBatch = syncPushRequestSchema.parse({
      vaultId: 'vault.1',
      batchIdempotencyKey: 'sync-push-batch-0002',
      mutations: [third],
    });
    await expect(storage.pushSyncBatch(duplicateBatch)).resolves.toMatchObject({
      serverVaultRevision: 8,
      results: [{ status: 'accepted', disposition: 'duplicate' }],
    });
    const incompatibleMutationKeyBatch = syncPushRequestSchema.parse({
      vaultId: 'vault.1',
      batchIdempotencyKey: 'sync-push-batch-0003',
      mutations: [mutation('vault', vaultRecord(9), 8, 'idempotency-push-vault-0003')],
    });
    await expect(
      storage.pushSyncBatch(incompatibleMutationKeyBatch),
    ).resolves.toMatchObject({
      serverVaultRevision: 8,
      results: [
        {
          status: 'conflict',
          currentRevision: 8,
          current: { id: 'vault.1', revision: 8 },
        },
      ],
    });

    await expect(
      storage.pushSyncBatch(
        syncPushRequestSchema.parse({
          ...batch,
          mutations: [first],
        }),
      ),
    ).rejects.toThrow(SyncConflictError);
    await expect(
      storage.pushSyncBatch({
        ...duplicateBatch,
        vaultId: vaultIdSchema.parse('vault.other'),
        batchIdempotencyKey: 'sync-push-batch-cross-vault',
      }),
    ).rejects.toThrow();

    const storedBatch = await database
      .collection(mongoStorageCollectionNames.syncPushBatches)
      .findOne({ batchIdempotencyKey: batch.batchIdempotencyKey });
    expect(storedBatch).toMatchObject({
      state: 'completed',
      nextMutationIndex: 3,
      response,
    });
  });
});

function asPlainDocument(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Expected a plain MongoDB document');
  }
  return value as Record<string, unknown>;
}
