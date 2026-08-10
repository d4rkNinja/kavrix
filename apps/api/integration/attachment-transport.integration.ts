import { randomUUID } from 'node:crypto';

import {
  apiBearerTokenSchema,
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  attachmentStreamFinalizeInputSchema,
  attachmentStreamStartInputSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  vaultIdSchema,
  type AttachmentStreamFinalizeInput,
  type AttachmentStreamStartInput,
  type PersistedAttachmentChunkRecord,
} from '@kavrix/schemas';
import { MongoVaultStorage, mongoStorageCollectionNames } from '@kavrix/storage';
import type { FastifyInstance } from 'fastify';
import { MongoClient, type Db } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { buildApi, type ApiPorts } from '../src/index.js';
import { authHeader, createTestPorts } from '../test/helpers.js';
import {
  attachmentChunk,
  attachmentFinalize,
  attachmentStart,
  groupRecord,
  itemRecord,
  mutation,
  plaintextCanary,
  vaultRecord,
} from '../../../packages/storage/test/fixtures.js';

const mongodbUri = process.env['KAVRIX_MONGODB_URI'];
const describeMongo =
  mongodbUri === undefined || mongodbUri.length === 0 ? describe.skip : describe;
const opaqueCiphertextCanary = 'opaque-rs0-attachment-ciphertext';

type RawMongoDocument = { _id: string } & Record<string, unknown>;

describeMongo('attachment HTTP transport against MongoDB rs0', () => {
  const uri = requireMongoUri();
  const client = new MongoClient(uri, { appName: 'kavrix-api-attachment-integration' });
  const databaseName = `kavrix_api_attachment_${randomUUID().replaceAll('-', '')}`;
  let database: Db;

  beforeAll(async () => {
    await client.connect();
    database = client.db(databaseName);
  });

  afterAll(async () => {
    await client.db(databaseName).dropDatabase();
    await client.close();
  });

  it('resumes after reopen, stays hidden until finalize, and serves exact ordered ciphertext', async () => {
    let storage = new MongoVaultStorage(client, database, {
      now: () => new Date('2026-08-10T00:00:00.000Z'),
    });
    await storage.initialize();
    await storage.commit(mutation('vault', vaultRecord(), null));
    await storage.commit(mutation('group', groupRecord(), null));
    await storage.commit(mutation('item', itemRecord(), null));

    const start = attachmentStart();
    const first = ciphertextCanaryChunk(attachmentChunk(0, 'message'));
    const final = attachmentChunk(1, 'final');
    const metadata = attachmentFinalize(2);
    const logs: string[] = [];
    const fixture = await apiFixture(storage, logs);
    let app = fixture.app;
    const base = attachmentUrl(start);

    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${base}/stream/open`,
          headers: authHeader(fixture.token),
          payload: start,
        })
      ).statusCode,
    ).toBe(200);
    expect((await stage(app, fixture.token, base, start, final)).statusCode).toBe(409);
    expect((await stage(app, fixture.token, base, start, first)).statusCode).toBe(200);
    expect(
      (await stage(app, fixture.token, base, start, replacementChunk(first)))
        .statusCode,
    ).toBe(409);
    const crossVault = rebindVault(start, 'vault.cross-attachment');
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${base}/stream/open`,
          headers: authHeader(fixture.token),
          payload: crossVault,
        })
      ).statusCode,
    ).toBe(400);
    expect(
      await storage.getAttachment(vaultRecord().id, metadata.record.id),
    ).toBeNull();
    expect(
      (
        await app.inject({
          method: 'GET',
          url: base,
          headers: authHeader(fixture.token),
        })
      ).statusCode,
    ).toBe(404);

    await app.close();
    storage = new MongoVaultStorage(client, database, {
      now: () => new Date('2026-08-10T00:00:01.000Z'),
    });
    await storage.initialize();
    const reopened = await apiFixture(storage, logs, fixture);
    app = reopened.app;
    const resumed = await app.inject({
      method: 'POST',
      url: `${base}/stream/open`,
      headers: authHeader(fixture.token),
      payload: start,
    });
    expect(resumed.json()).toMatchObject({ state: 'writing', nextChunkIndex: 1 });
    expect((await stage(app, fixture.token, base, start, first)).statusCode).toBe(200);
    expect((await stage(app, fixture.token, base, start, final)).json()).toMatchObject({
      state: 'ready-to-finalize',
      nextChunkIndex: 2,
    });

    for (let attempt = 0; attempt < 2; attempt += 1) {
      expect(
        (
          await app.inject({
            method: 'POST',
            url: `${base}/stream/finalize`,
            headers: authHeader(fixture.token),
            payload: { start, finalize: metadata },
          })
        ).statusCode,
      ).toBe(204);
    }
    const readChunks = await Promise.all(
      [0, 1].map(async (index) =>
        app.inject({
          method: 'GET',
          url: `${base}/chunks/${String(index)}`,
          headers: authHeader(fixture.token),
        }),
      ),
    );
    expect(readChunks.map((response) => response.statusCode)).toEqual([200, 200]);
    const parsedReadChunks = readChunks.map((response) =>
      persistedAttachmentChunkRecordSchema.parse(response.json()),
    );
    expect(parsedReadChunks.map(({ record }) => record.index)).toEqual([0, 1]);
    expect(
      Buffer.from(parsedReadChunks[0]?.record.ciphertext ?? '', 'base64url')
        .subarray(0, Buffer.byteLength(opaqueCiphertextCanary))
        .toString('utf8'),
    ).toBe(opaqueCiphertextCanary);

    const rawChunks = await database
      .collection<RawMongoDocument>(mongoStorageCollectionNames.attachmentStagingChunks)
      .find({})
      .sort({ chunkIndex: 1 })
      .toArray();
    const rawFirst = rawChunks[0];
    if (rawFirst === undefined) throw new Error('Missing staged chunk evidence');
    const rawPersisted = asDocument(rawFirst['record']);
    const rawRecord = asDocument(rawPersisted['record']);
    expect(
      Buffer.from(String(rawRecord['ciphertext']), 'base64url')
        .subarray(0, Buffer.byteLength(opaqueCiphertextCanary))
        .toString('utf8'),
    ).toBe(opaqueCiphertextCanary);
    const allRaw = JSON.stringify(
      await Promise.all(
        Object.values(mongoStorageCollectionNames).map(async (name) =>
          database.collection(name).find({}).toArray(),
        ),
      ),
    );
    expect(allRaw).not.toContain(plaintextCanary);
    expect(logs.join('')).not.toContain(plaintextCanary);
    expect(logs.join('')).not.toContain(opaqueCiphertextCanary);
    expect(logs.join('')).not.toContain(fixture.token);

    const aborted = rebindAttachment(start, metadata, 'attachment.aborted');
    const abortedBase = attachmentUrl(aborted.start);
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${abortedBase}/stream/open`,
          headers: authHeader(fixture.token),
          payload: aborted.start,
        })
      ).statusCode,
    ).toBe(200);
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${abortedBase}/stream/abort`,
          headers: authHeader(fixture.token),
          payload: aborted.start,
        })
      ).statusCode,
    ).toBe(204);
    expect(
      await storage.getAttachment(vaultRecord().id, aborted.finalize.record.id),
    ).toBeNull();

    const deletedItem = encryptedItemRecordSchema.parse({
      ...itemRecord(),
      recordRevision: 1,
      updatedAt: '2026-08-10T00:03:00.000Z',
      tombstonedAt: '2026-08-10T00:03:00.000Z',
    });
    await storage.commit(
      mutation('item', deletedItem, 0, 'attachment-parent-item-delete'),
    );
    await expectMongoParentHidden(
      app,
      fixture.token,
      base,
      storage,
      metadata.record.id,
    );
    const restoredItem = encryptedItemRecordSchema.parse({
      ...itemRecord(),
      recordRevision: 2,
      updatedAt: '2026-08-10T00:04:00.000Z',
    });
    await storage.commit(
      mutation('item', restoredItem, 1, 'attachment-parent-item-restore'),
    );
    const pendingGroupDelete = rebindAttachment(
      start,
      metadata,
      'attachment.group-finalize-blocked',
    );
    const pendingBase = attachmentUrl(pendingGroupDelete.start);
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${pendingBase}/stream/open`,
          headers: authHeader(fixture.token),
          payload: pendingGroupDelete.start,
        })
      ).statusCode,
    ).toBe(200);
    expect(
      (
        await stage(
          app,
          fixture.token,
          pendingBase,
          pendingGroupDelete.start,
          rebindChunk(first, pendingGroupDelete.start),
        )
      ).statusCode,
    ).toBe(200);
    expect(
      (
        await stage(
          app,
          fixture.token,
          pendingBase,
          pendingGroupDelete.start,
          rebindChunk(final, pendingGroupDelete.start),
        )
      ).statusCode,
    ).toBe(200);
    const deletedGroup = encryptedGroupRecordSchema.parse({
      ...groupRecord(),
      recordRevision: 1,
      updatedAt: '2026-08-10T00:05:00.000Z',
      tombstonedAt: '2026-08-10T00:05:00.000Z',
    });
    await storage.commit(
      mutation('group', deletedGroup, 0, 'attachment-parent-group-delete'),
    );
    await expectMongoParentHidden(
      app,
      fixture.token,
      base,
      storage,
      metadata.record.id,
    );
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${pendingBase}/stream/finalize`,
          headers: authHeader(fixture.token),
          payload: {
            start: pendingGroupDelete.start,
            finalize: pendingGroupDelete.finalize,
          },
        })
      ).statusCode,
    ).toBe(409);
    expect(
      await storage.getAttachment(
        vaultRecord().id,
        pendingGroupDelete.finalize.record.id,
      ),
    ).toBeNull();
    const blockedOpen = rebindAttachment(
      start,
      metadata,
      'attachment.group-open-blocked',
    );
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${attachmentUrl(blockedOpen.start)}/stream/open`,
          headers: authHeader(fixture.token),
          payload: blockedOpen.start,
        })
      ).statusCode,
    ).toBe(409);
    await app.close();
  });

  it('rejects a missing parent without creating visible or staged bytes', async () => {
    const storage = new MongoVaultStorage(client, database, {
      now: () => new Date('2026-08-10T00:02:00.000Z'),
    });
    await storage.initialize();
    const fixture = await apiFixture(storage, []);
    const missingParent = rebindItem(attachmentStart(), 'item.missing-parent');
    const response = await fixture.app.inject({
      method: 'POST',
      url: `${attachmentUrl(missingParent)}/stream/open`,
      headers: authHeader(fixture.token),
      payload: missingParent,
    });
    expect(response.statusCode).toBe(409);
    const staged = await database
      .collection(mongoStorageCollectionNames.attachmentStaging)
      .countDocuments({ idempotencyKey: missingParent.idempotencyKey });
    expect(staged).toBe(0);
    await fixture.app.close();
  });
});

async function apiFixture(
  storage: MongoVaultStorage,
  logs: string[],
  existing?: Readonly<{ token: string; ports: ApiPorts; app: FastifyInstance }>,
): Promise<Readonly<{ token: string; ports: ApiPorts; app: FastifyInstance }>> {
  if (existing !== undefined) {
    return {
      ...existing,
      app: buildApi({
        ports: { ...existing.ports, storage },
        environment: 'test',
        logStream: { write: (message) => logs.push(message) },
      }),
    };
  }
  const fixture = await createTestPorts();
  const hash = await fixture.ports.tokens.hash(
    apiBearerTokenSchema.parse(fixture.token),
  );
  const principal = fixture.authorization.sessions.get(hash);
  if (principal === undefined) throw new Error('Missing authorization fixture');
  fixture.authorization.sessions.set(hash, {
    ...principal,
    vaultId: vaultIdSchema.parse('vault.1'),
  });
  const ports = { ...fixture.ports, storage };
  return {
    token: fixture.token,
    ports,
    app: buildApi({
      ports,
      environment: 'test',
      logStream: { write: (message) => logs.push(message) },
    }),
  };
}

function stage(
  app: ReturnType<typeof buildApi>,
  token: string,
  base: string,
  start: ReturnType<typeof attachmentStart>,
  chunk: ReturnType<typeof attachmentChunk>,
): Promise<{ readonly statusCode: number; json(): unknown }> {
  return app.inject({
    method: 'PUT',
    url: `${base}/stream/chunks/${String(chunk.record.index)}`,
    headers: authHeader(token),
    payload: { start, chunk },
  });
}

function ciphertextCanaryChunk(
  input: ReturnType<typeof attachmentChunk>,
): PersistedAttachmentChunkRecord {
  const plaintextBytes = Buffer.byteLength(opaqueCiphertextCanary);
  const ciphertext = Buffer.concat([
    Buffer.from(opaqueCiphertextCanary),
    Buffer.alloc(17, 17),
  ]).toString('base64url');
  const initial = persistedAttachmentChunkRecordSchema.parse({
    ...input,
    plaintextBytes,
    record: { ...input.record, ciphertext },
  });
  return persistedAttachmentChunkRecordSchema.parse({
    ...initial,
    ciphertextHash: attachmentChunkCiphertextHash(initial),
  });
}

function replacementChunk(
  input: ReturnType<typeof attachmentChunk>,
): PersistedAttachmentChunkRecord {
  const ciphertext = Buffer.alloc(input.plaintextBytes + 17, 31).toString('base64url');
  const initial = persistedAttachmentChunkRecordSchema.parse({
    ...input,
    record: { ...input.record, ciphertext },
  });
  return persistedAttachmentChunkRecordSchema.parse({
    ...initial,
    ciphertextHash: attachmentChunkCiphertextHash(initial),
  });
}

function rebindChunk(
  chunk: PersistedAttachmentChunkRecord,
  start: AttachmentStreamStartInput,
): PersistedAttachmentChunkRecord {
  return persistedAttachmentChunkRecordSchema.parse({
    ...chunk,
    recordRevision: start.header.recordRevision,
    record: {
      ...chunk.record,
      vaultId: start.header.record.vaultId,
      groupId: start.header.record.groupId,
      itemId: start.header.record.itemId,
      attachmentId: start.header.record.attachmentId,
    },
  });
}

function rebindAttachment(
  startValue: ReturnType<typeof attachmentStart>,
  finalizeValue: ReturnType<typeof attachmentFinalize>,
  attachmentId: string,
): Readonly<{
  start: AttachmentStreamStartInput;
  finalize: AttachmentStreamFinalizeInput;
}> {
  const header = persistedAttachmentHeaderRecordSchema.parse({
    ...startValue.header,
    record: { ...startValue.header.record, attachmentId },
  });
  const start = attachmentStreamStartInputSchema.parse({
    ...startValue,
    idempotencyKey: `stream-${attachmentId}-idempotency`,
    header: {
      ...header,
      contentHash: attachmentHeaderContentHash(header),
    },
  });
  const finalize = attachmentStreamFinalizeInputSchema.parse({
    ...finalizeValue,
    record: {
      ...finalizeValue.record,
      id: attachmentId,
      wrappedAttachmentKey: {
        ...finalizeValue.record.wrappedAttachmentKey,
        aad: {
          ...finalizeValue.record.wrappedAttachmentKey.aad,
          entityId: attachmentId,
        },
      },
      encryptedManifest: {
        ...finalizeValue.record.encryptedManifest,
        aad: {
          ...finalizeValue.record.encryptedManifest.aad,
          entityId: attachmentId,
        },
      },
    },
  });
  return { start, finalize };
}

function rebindItem(
  startValue: ReturnType<typeof attachmentStart>,
  itemId: string,
): AttachmentStreamStartInput {
  const header = persistedAttachmentHeaderRecordSchema.parse({
    ...startValue.header,
    record: { ...startValue.header.record, itemId },
  });
  return attachmentStreamStartInputSchema.parse({
    ...startValue,
    idempotencyKey: 'stream-missing-parent-idempotency',
    header: {
      ...header,
      contentHash: attachmentHeaderContentHash(header),
    },
  });
}

function rebindVault(
  startValue: ReturnType<typeof attachmentStart>,
  targetVaultId: string,
): AttachmentStreamStartInput {
  const header = persistedAttachmentHeaderRecordSchema.parse({
    ...startValue.header,
    record: { ...startValue.header.record, vaultId: targetVaultId },
  });
  return attachmentStreamStartInputSchema.parse({
    ...startValue,
    idempotencyKey: 'stream-cross-vault-idempotency',
    header: {
      ...header,
      contentHash: attachmentHeaderContentHash(header),
    },
  });
}

function attachmentUrl(start: ReturnType<typeof attachmentStart>): string {
  const record = start.header.record;
  return `/v1/vaults/${record.vaultId}/groups/${record.groupId}/items/${record.itemId}/attachments/${record.attachmentId}`;
}

function asDocument(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('Expected Mongo document');
  }
  return value as Record<string, unknown>;
}

async function expectMongoParentHidden(
  app: FastifyInstance,
  token: string,
  base: string,
  storage: MongoVaultStorage,
  attachmentId: ReturnType<typeof attachmentFinalize>['record']['id'],
): Promise<void> {
  await expect(
    storage.getAttachment(vaultRecord().id, attachmentId),
  ).resolves.toBeNull();
  const responses = await Promise.all(
    [base, `${base}/header`, `${base}/chunks/0`].map(async (url) =>
      app.inject({ method: 'GET', url, headers: authHeader(token) }),
    ),
  );
  expect(responses.map(({ statusCode }) => statusCode)).toEqual([404, 404, 404]);
}

function requireMongoUri(): string {
  if (mongodbUri === undefined || mongodbUri.length === 0) {
    return 'mongodb://integration-test-is-skipped.invalid';
  }
  return mongodbUri;
}
