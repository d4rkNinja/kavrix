import { createHash, randomUUID } from 'node:crypto';

import {
  createPortableKeySlot,
  encryptAttachmentStream,
  encryptPayload,
  generateAttachmentKey,
  generateGroupKey,
  generateItemKey,
  generatePortableKey,
  generateVaultRootKey,
  wrapAttachmentKey,
  wrapGroupKey,
  wrapItemKey,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  createEncryptedBackup,
  restoreEncryptedBackup,
  verifyEncryptedBackup,
  type BackupVerification,
} from '@kavrix/import-export';
import {
  associatedDataSchema,
  canonicalJson,
  contentHashForRecord,
  encryptedAttachmentRecordSchema,
  encryptedAuditRecordSchema,
  encryptedGroupRecordSchema,
  encryptedHistoryRecordSchema,
  encryptedItemRecordSchema,
  keySlotIdSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  sha256DigestSchema,
  recordRevisionSchema,
  syncCursorSchema,
  timestampSchema,
  tombstoneRecordSchema,
  vaultRecordSchema,
  vaultIdSchema,
  type AeadEnvelope,
  type AttachmentSecretStreamChunkRecord,
  type AttachmentSecretStreamHeaderRecord,
  type AttachmentSecretStreamManifest,
  type EncryptedAttachmentRecord,
  type EncryptedAuditRecord,
  type EncryptedBackupEntry,
  type EncryptedGroupRecord,
  type EncryptedHistoryRecord,
  type EncryptedItemRecord,
  type PersistedAttachmentChunkRecord,
  type PersistedAttachmentHeaderRecord,
  type Sha256Digest,
  type TombstoneRecord,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import { MongoClient, type Db } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { OpaqueVaultSnapshot } from '@kavrix/client';

import {
  MongoBackupRestoreStore,
  MongoVaultStorage,
  mongoStorageCollectionNames,
  toVaultDocument,
} from '../src/index.js';

const mongodbUri = process.env['KAVRIX_MONGODB_URI'];
if (mongodbUri === undefined || mongodbUri.length === 0) {
  throw new Error(
    'KAVRIX_MONGODB_URI is required and must select a transaction-capable MongoDB replica set.',
  );
}

const CREATED_AT = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const DELETED_AT = timestampSchema.parse('2026-08-10T00:05:00.000Z');
const LIMITS = { maximumBytes: 8 * 1024 * 1024, maximumRecords: 100 } as const;
const CANARIES = [
  'KAVRIX_TEST_ONLY_GROUP_PLAINTEXT',
  'KAVRIX_TEST_ONLY_ITEM_PLAINTEXT',
  'KAVRIX_TEST_ONLY_DELETED_ITEM_PLAINTEXT',
  'KAVRIX_TEST_ONLY_ATTACHMENT_PLAINTEXT',
  'KAVRIX_TEST_ONLY_AUDIT_PLAINTEXT',
  'KAVRIX_TEST_ONLY_HISTORY_PLAINTEXT',
] as const;

interface BackupFixture {
  readonly vaultId: VaultId;
  readonly rootKey: VaultRootKey;
  readonly vault: VaultRecord;
  readonly group: EncryptedGroupRecord;
  readonly activeItem: EncryptedItemRecord;
  readonly deletedItemPredecessor: EncryptedItemRecord;
  readonly deletedItem: EncryptedItemRecord;
  readonly attachment: EncryptedAttachmentRecord;
  readonly attachmentHeader: PersistedAttachmentHeaderRecord;
  readonly attachmentChunks: readonly PersistedAttachmentChunkRecord[];
  readonly audit: EncryptedAuditRecord;
  readonly history: EncryptedHistoryRecord;
  readonly tombstone: TombstoneRecord;
  readonly orderedRecords: readonly EncryptedBackupEntry[];
  readonly archive: Buffer;
  readonly summary: BackupVerification;
}

describe('authenticated encrypted-backup restore against a MongoDB replica set', () => {
  const client = new MongoClient(mongodbUri, {
    appName: 'kavrix-backup-restore-integration',
  });
  let fixture: BackupFixture;
  let otherFixture: BackupFixture;

  beforeAll(async () => {
    await client.connect();
    fixture = await createFixture('restore-a');
    otherFixture = await createFixture('restore-b');
  });

  afterAll(async () => {
    zeroize(fixture.rootKey);
    zeroize(otherFixture.rootKey);
    await client.close();
  });

  it('keeps resumable staging hidden, rejects divergent/cross-vault replay, and aborts durably', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database, {
        now: () => new Date(CREATED_AT),
      });
      await store.initialize();
      const first = await store.open(fixture.summary.restoreSessionId, LIMITS);
      await first.write({ kind: 'vault', record: fixture.vault });
      await expect(
        first.write({
          kind: 'group',
          record: { ...fixture.group, plaintext: CANARIES[0] },
        } as never),
      ).rejects.toThrow('Invalid encrypted backup entry');
      await expect(first.commit(null as never)).rejects.toThrow(
        'restore summary is invalid',
      );

      const visible = new MongoVaultStorage(client, database);
      await expect(visible.getVault(fixture.vaultId)).resolves.toBeNull();
      await expect(
        database.collection(mongoStorageCollectionNames.vaults).countDocuments(),
      ).resolves.toBe(0);
      await expect(
        database
          .collection(mongoStorageCollectionNames.backupRestoreEntries)
          .countDocuments(),
      ).resolves.toBe(1);

      const resumed = await store.open(fixture.summary.restoreSessionId, LIMITS);
      await resumed.write({ kind: 'vault', record: fixture.vault });
      await resumed.write({ kind: 'group', record: fixture.group });

      const divergent = await store.open(fixture.summary.restoreSessionId, LIMITS);
      await divergent.write({ kind: 'vault', record: fixture.vault });
      await expect(
        divergent.write({
          kind: 'group',
          record: {
            ...fixture.group,
            recordRevision: recordRevisionSchema.parse(2),
          },
        }),
      ).rejects.toThrow('exactly match');

      const crossVault = await store.open(fixture.summary.restoreSessionId, LIMITS);
      await crossVault.write({ kind: 'vault', record: fixture.vault });
      await expect(
        crossVault.write({ kind: 'group', record: otherFixture.group }),
      ).rejects.toThrow('different vault');

      await resumed.abort();
      await expect(resumed.status()).resolves.toBe('aborted');
      await expect(resumed.abort()).resolves.toBeUndefined();
      await expect(
        database
          .collection(mongoStorageCollectionNames.backupRestoreEntries)
          .countDocuments(),
      ).resolves.toBe(0);
      await expect(visible.getVault(fixture.vaultId)).resolves.toBeNull();
    });
  });

  it('verifies, atomically restores, reopens, and exactly reads every supported record family', async () => {
    await withEmptyDatabase(client, async (database) => {
      const verified = await verifyEncryptedBackup(
        chunks(fixture.archive, 29),
        fixture.rootKey,
        fixture.vaultId,
        LIMITS,
      );
      expect(verified).toEqual(fixture.summary);

      const store = new MongoBackupRestoreStore(client, database, {
        now: () => new Date(CREATED_AT),
      });
      await store.initialize();
      await expect(
        restoreEncryptedBackup(
          chunks(fixture.archive, 31),
          fixture.rootKey,
          fixture.vaultId,
          store,
          LIMITS,
        ),
      ).resolves.toEqual(fixture.summary);
      await expect(
        restoreEncryptedBackup(
          chunks(fixture.archive, 37),
          fixture.rootKey,
          fixture.vaultId,
          store,
          LIMITS,
        ),
      ).resolves.toEqual(fixture.summary);

      const reopened = new MongoVaultStorage(client, database);
      await expect(reopened.getVault(fixture.vaultId)).resolves.toEqual(fixture.vault);
      await expect(
        reopened.getGroup(fixture.vaultId, fixture.group.id),
      ).resolves.toEqual(fixture.group);
      await expect(
        reopened.getItem(fixture.vaultId, fixture.activeItem.id),
      ).resolves.toEqual(fixture.activeItem);
      await expect(
        reopened.getItem(fixture.vaultId, fixture.deletedItem.id),
      ).resolves.toBeNull();
      await expect(
        reopened.getTombstone(fixture.vaultId, 'item', fixture.deletedItem.id),
      ).resolves.toEqual(fixture.tombstone);
      await expect(
        reopened.getAttachment(fixture.vaultId, fixture.attachment.id),
      ).resolves.toEqual(fixture.attachment);
      await expect(
        reopened.getAttachmentStreamHeader(fixture.vaultId, fixture.attachment.id),
      ).resolves.toEqual(fixture.attachmentHeader);
      await expect(
        collectAsync(
          reopened.listAttachmentChunks(fixture.vaultId, fixture.attachment.id, 0),
        ),
      ).resolves.toEqual(fixture.attachmentChunks);
      await expect(
        reopened.getAudit(fixture.vaultId, fixture.audit.id),
      ).resolves.toEqual(fixture.audit);
      await expect(collectAsync(reopened.listAudits(fixture.vaultId))).resolves.toEqual(
        [fixture.audit],
      );
      await expect(
        reopened.getHistory(fixture.vaultId, fixture.history.id),
      ).resolves.toEqual(fixture.history);
      await expect(
        collectAsync(reopened.listItemHistory(fixture.vaultId, fixture.activeItem.id)),
      ).resolves.toEqual([fixture.history]);

      const page = await reopened.pullSyncPage(
        syncCursorSchema.parse({
          vaultId: fixture.vaultId,
          serverSequence: 0,
          highestSeenVaultRevision: 0,
        }),
        100,
      );
      expect(page.serverVaultRevision).toBe(fixture.vault.revision);
      expect(page.nextCursor.highestSeenVaultRevision).toBe(fixture.vault.revision);
      expect(page.changes.map(({ change }) => change.entityType)).toEqual([
        'vault',
        'group',
        'item',
        'item',
        'attachment',
        'item',
      ]);
      expect(page.changes[3]?.record).toEqual(fixture.deletedItemPredecessor);
      expect(page.changes[5]?.record).toEqual(fixture.tombstone);
      const cleanClient = new OpaqueVaultSnapshot(fixture.vaultId);
      cleanClient.applyPullPage(page);
      await expect(
        cleanClient.getItem(fixture.vaultId, fixture.deletedItem.id),
      ).resolves.toBeNull();
      await expect(
        cleanClient.getItem(fixture.vaultId, fixture.activeItem.id),
      ).resolves.toEqual(fixture.activeItem);

      const raw = await readAllDocuments(database);
      for (const canary of CANARIES) {
        expect(raw).not.toContain(canary);
        expect(fixture.archive.toString('utf8')).not.toContain(canary);
      }
      await expect(
        database
          .collection(mongoStorageCollectionNames.backupRestoreEntries)
          .countDocuments(),
      ).resolves.toBe(0);
      await expect(
        database
          .collection<{ _id: string } & Record<string, unknown>>(
            mongoStorageCollectionNames.backupRestoreSessions,
          )
          .findOne({ _id: fixture.summary.restoreSessionId }),
      ).resolves.toMatchObject({
        state: 'committed',
        stagedBytes: 0,
        stagedRecords: 0,
        vaultId: fixture.vaultId,
        transcriptSha256: fixture.summary.transcriptSha256,
      });
    });
  });

  it('fails closed on a non-empty target and never overwrites existing state', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database, {
        now: () => new Date(CREATED_AT),
      });
      await store.initialize();
      const original = toVaultDocument(otherFixture.vault);
      await database
        .collection<typeof original>(mongoStorageCollectionNames.vaults)
        .insertOne(original);

      await expect(
        restoreEncryptedBackup(
          chunks(fixture.archive),
          fixture.rootKey,
          fixture.vaultId,
          store,
          LIMITS,
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_COMMIT_UNCERTAIN' });
      await expect(
        database
          .collection<typeof original>(mongoStorageCollectionNames.vaults)
          .findOne({ _id: original._id }),
      ).resolves.toEqual(original);
      await expect(
        database.collection(mongoStorageCollectionNames.vaults).countDocuments(),
      ).resolves.toBe(1);
      const staged = await store.open(fixture.summary.restoreSessionId, LIMITS);
      await expect(staged.status()).resolves.toBe('staging');
      await staged.abort();
    });
  });
});

async function createFixture(prefix: string): Promise<BackupFixture> {
  const vaultId = vaultIdSchema.parse(`${prefix}.vault`);
  const groupId = `${prefix}.group`;
  const activeItemId = `${prefix}.item.active`;
  const deletedItemId = `${prefix}.item.deleted`;
  const attachmentId = `${prefix}.attachment`;
  const auditId = `${prefix}.audit`;
  const historyId = `${prefix}.history`;
  const rootKey = generateVaultRootKey();
  const portableKey = generatePortableKey();
  const groupKey = generateGroupKey();
  const activeItemKey = generateItemKey();
  const deletedItemKey = generateItemKey();
  const attachmentKey = generateAttachmentKey();

  try {
    const slot = await createPortableKeySlot(
      {
        vaultId,
        slotId: keySlotIdSchema.parse(`${prefix}.slot`),
        schemaVersion: 1,
        keyVersion: 1,
        createdAt: CREATED_AT,
      },
      portableKey,
      rootKey,
    );
    const vault = vaultRecordSchema.parse({
      id: vaultId,
      schemaVersion: 1,
      cryptographicVersion: 1,
      keySlots: [slot],
      currentKeyVersion: 1,
      revision: 27,
      encryptedPreferences: await encryptText(
        '{"testOnly":true}',
        rootKey,
        associatedData('vault-preferences', vaultId, vaultId),
      ),
      createdAt: CREATED_AT,
      updatedAt: CREATED_AT,
    });
    const group = encryptedGroupRecordSchema.parse({
      id: groupId,
      vaultId,
      schemaVersion: 1,
      wrappedGroupKey: await wrapGroupKey(
        groupKey,
        rootKey,
        associatedData('wrapped-group-key', vaultId, groupId),
      ),
      encryptedPayload: await encryptText(
        CANARIES[0],
        groupKey,
        associatedData('group', vaultId, groupId),
      ),
      templateVersion: 1,
      recordRevision: 4,
      createdAt: CREATED_AT,
      updatedAt: CREATED_AT,
    });
    const activePayload = await encryptText(
      CANARIES[1],
      activeItemKey,
      associatedData('item', vaultId, activeItemId, groupId),
    );
    const activeItem = encryptedItemRecordSchema.parse({
      id: activeItemId,
      vaultId,
      groupId,
      schemaVersion: 1,
      wrappedItemKey: await wrapItemKey(
        activeItemKey,
        groupKey,
        associatedData('wrapped-item-key', vaultId, activeItemId, groupId),
      ),
      encryptedPayload: activePayload,
      recordRevision: 7,
      ciphertextHash: digestCiphertext(activePayload),
      createdAt: CREATED_AT,
      updatedAt: CREATED_AT,
    });
    const deletedPayload = await encryptText(
      CANARIES[2],
      deletedItemKey,
      associatedData('item', vaultId, deletedItemId, groupId),
    );
    const deletedItemPredecessor = encryptedItemRecordSchema.parse({
      id: deletedItemId,
      vaultId,
      groupId,
      schemaVersion: 1,
      wrappedItemKey: await wrapItemKey(
        deletedItemKey,
        groupKey,
        associatedData('wrapped-item-key', vaultId, deletedItemId, groupId),
      ),
      encryptedPayload: deletedPayload,
      recordRevision: 8,
      ciphertextHash: digestCiphertext(deletedPayload),
      createdAt: CREATED_AT,
      updatedAt: CREATED_AT,
    });
    const deletedCurrentPayload = await encryptText(
      CANARIES[2],
      deletedItemKey,
      associatedData('item', vaultId, deletedItemId, groupId),
    );
    const deletedItem = encryptedItemRecordSchema.parse({
      ...deletedItemPredecessor,
      encryptedPayload: deletedCurrentPayload,
      ciphertextHash: digestCiphertext(deletedCurrentPayload),
      recordRevision: 9,
      updatedAt: DELETED_AT,
      tombstonedAt: DELETED_AT,
    });
    const tombstone = tombstoneRecordSchema.parse({
      vaultId,
      entityType: 'item',
      entityId: deletedItemId,
      state: 'deleted',
      tombstoneRevision: deletedItem.recordRevision,
      lastRecordRevision: 8,
      lastCiphertextHash: contentHashForRecord(deletedItemPredecessor),
      deletedAt: DELETED_AT,
    });
    expect(contentHashForRecord(deletedItem)).not.toBe(tombstone.lastCiphertextHash);

    const stream = await encryptAttachmentFixture(
      attachmentKey,
      vaultId,
      groupId,
      activeItemId,
      attachmentId,
    );
    const encryptedManifest = await encryptText(
      canonicalJson(stream.manifest),
      attachmentKey,
      associatedData('attachment', vaultId, attachmentId, groupId, activeItemId),
    );
    const attachment = encryptedAttachmentRecordSchema.parse({
      id: attachmentId,
      vaultId,
      groupId,
      itemId: activeItemId,
      schemaVersion: 1,
      wrappedAttachmentKey: await wrapAttachmentKey(
        attachmentKey,
        activeItemKey,
        associatedData(
          'wrapped-attachment-key',
          vaultId,
          attachmentId,
          groupId,
          activeItemId,
        ),
      ),
      encryptedManifest,
      chunkCount: stream.chunks.length,
      recordRevision: 3,
      createdAt: CREATED_AT,
      updatedAt: CREATED_AT,
    });
    const attachmentHeader = persistedAttachmentHeaderRecordSchema.parse({
      entityType: 'attachment-header',
      record: stream.header,
      recordRevision: attachment.recordRevision,
      contentHash: digestCanonical(stream.header),
      createdAt: CREATED_AT,
      updatedAt: CREATED_AT,
    });
    const attachmentChunks = stream.chunks.map((chunk, index) =>
      persistedAttachmentChunkRecordSchema.parse({
        entityType: 'attachment-chunk',
        record: chunk,
        plaintextBytes: stream.plaintextBytes[index],
        recordRevision: attachment.recordRevision,
        ciphertextHash: digestBytes(Buffer.from(chunk.ciphertext, 'base64url')),
        createdAt: CREATED_AT,
        updatedAt: CREATED_AT,
      }),
    );
    const audit = encryptedAuditRecordSchema.parse({
      id: auditId,
      vaultId,
      schemaVersion: 1,
      encryptedPayload: await encryptText(
        CANARIES[4],
        rootKey,
        associatedData('audit-event', vaultId, auditId),
      ),
      recordRevision: 5,
      createdAt: CREATED_AT,
    });
    const historyPayload = await encryptText(
      CANARIES[5],
      activeItemKey,
      associatedData('history', vaultId, historyId, groupId, activeItemId),
    );
    const history = encryptedHistoryRecordSchema.parse({
      id: historyId,
      vaultId,
      groupId,
      itemId: activeItemId,
      schemaVersion: 1,
      encryptedPayload: historyPayload,
      itemRecordRevision: 6,
      ciphertextHash: digestCiphertext(historyPayload),
      createdAt: CREATED_AT,
    });

    const orderedRecords: readonly EncryptedBackupEntry[] = [
      { kind: 'group', record: group },
      { kind: 'item', record: activeItem },
      { kind: 'history', record: history },
      { kind: 'item', record: deletedItem },
      {
        kind: 'tombstone-predecessor',
        entityType: 'item',
        record: deletedItemPredecessor,
      },
      { kind: 'tombstone', record: tombstone },
      { kind: 'attachment', record: attachment },
      { kind: 'attachment-header', record: attachmentHeader },
      ...attachmentChunks.map((record) => ({
        kind: 'attachment-chunk' as const,
        record,
      })),
      { kind: 'audit', record: audit },
    ];
    const archive = await collectBytes(
      createEncryptedBackup(
        {
          vault,
          records: asyncValues(orderedRecords),
          createdAt: CREATED_AT,
          limits: LIMITS,
        },
        rootKey,
      ),
    );
    const summary = await verifyEncryptedBackup(
      chunks(archive),
      rootKey,
      vaultId,
      LIMITS,
    );
    expect(summary.recordCount).toBe(orderedRecords.length + 1);
    return {
      vaultId,
      rootKey,
      vault,
      group,
      activeItem,
      deletedItemPredecessor,
      deletedItem,
      attachment,
      attachmentHeader,
      attachmentChunks,
      audit,
      history,
      tombstone,
      orderedRecords,
      archive,
      summary,
    };
  } catch (error) {
    zeroize(rootKey);
    throw error;
  } finally {
    zeroize(portableKey);
    zeroize(groupKey);
    zeroize(activeItemKey);
    zeroize(deletedItemKey);
    zeroize(attachmentKey);
  }
}

async function encryptAttachmentFixture(
  attachmentKey: Uint8Array,
  vaultId: VaultId,
  groupId: string,
  itemId: string,
  attachmentId: string,
): Promise<{
  readonly header: AttachmentSecretStreamHeaderRecord;
  readonly chunks: readonly AttachmentSecretStreamChunkRecord[];
  readonly manifest: AttachmentSecretStreamManifest;
  readonly plaintextBytes: readonly number[];
}> {
  const plaintext = [
    Buffer.from(CANARIES[3].slice(0, 20), 'utf8'),
    Buffer.from(CANARIES[3].slice(20), 'utf8'),
  ];
  const stream = encryptAttachmentStream(
    plaintext,
    attachmentKey,
    associatedData('attachment-chunk', vaultId, attachmentId, groupId, itemId),
  );
  let header: AttachmentSecretStreamHeaderRecord | undefined;
  const encryptedChunks: AttachmentSecretStreamChunkRecord[] = [];
  try {
    for (;;) {
      const next = await stream.next();
      if (next.done) {
        if (header === undefined)
          throw new Error('Secretstream header was not emitted.');
        return {
          header,
          chunks: encryptedChunks,
          manifest: next.value,
          plaintextBytes: plaintext.map(({ byteLength }) => byteLength),
        };
      }
      if (next.value.recordType === 'header') header = next.value;
      else encryptedChunks.push(next.value);
    }
  } finally {
    for (const value of plaintext) zeroize(value);
  }
}

function associatedData(
  entityType:
    | 'vault-preferences'
    | 'group'
    | 'item'
    | 'attachment'
    | 'attachment-chunk'
    | 'audit-event'
    | 'history'
    | 'wrapped-group-key'
    | 'wrapped-item-key'
    | 'wrapped-attachment-key',
  vaultId: VaultId,
  entityId: string,
  groupId?: string,
  parentId?: string,
): ReturnType<typeof associatedDataSchema.parse> {
  const purpose = {
    'vault-preferences': 'vault-preferences',
    group: 'group-payload',
    item: 'item-payload',
    attachment: 'attachment-metadata',
    'attachment-chunk': 'attachment-chunk',
    'audit-event': 'audit-event',
    history: 'history-event',
    'wrapped-group-key': 'group-key',
    'wrapped-item-key': 'item-key',
    'wrapped-attachment-key': 'attachment-key',
  } as const;
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId,
    entityType,
    entityId,
    ...(groupId === undefined ? {} : { groupId }),
    ...(parentId === undefined ? {} : { parentId }),
    purpose: purpose[entityType],
  });
}

async function encryptText(
  text: string,
  key: Uint8Array,
  context: ReturnType<typeof associatedDataSchema.parse>,
): Promise<AeadEnvelope> {
  const plaintext = Buffer.from(text, 'utf8');
  try {
    return await encryptPayload(plaintext, key, context);
  } finally {
    zeroize(plaintext);
  }
}

function digestCiphertext(envelope: AeadEnvelope): Sha256Digest {
  return digestBytes(Buffer.from(envelope.ciphertext, 'base64url'));
}

function digestCanonical(value: unknown): Sha256Digest {
  return digestBytes(Buffer.from(canonicalJson(value), 'utf8'));
}

function digestBytes(value: Uint8Array): Sha256Digest {
  return sha256DigestSchema.parse(
    createHash('sha256').update(value).digest('base64url'),
  );
}

async function withEmptyDatabase(
  client: MongoClient,
  work: (database: Db) => Promise<void>,
): Promise<void> {
  const name = `kavrix_restore_test_${randomUUID().replaceAll('-', '')}`;
  const database = client.db(name);
  try {
    await work(database);
  } finally {
    await database.dropDatabase();
  }
}

async function readAllDocuments(database: Db): Promise<string> {
  const collections = await database.listCollections({}, { nameOnly: true }).toArray();
  const documents: unknown[] = [];
  for (const { name } of collections) {
    documents.push(...(await database.collection(name).find({}).toArray()));
  }
  return JSON.stringify(documents);
}

async function collectBytes(source: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const values: Uint8Array[] = [];
  for await (const value of source) values.push(value);
  return Buffer.concat(values);
}

async function collectAsync<T>(source: AsyncIterable<T>): Promise<readonly T[]> {
  const values: T[] = [];
  for await (const value of source) values.push(value);
  return values;
}

function chunks(value: Uint8Array, size = value.byteLength): AsyncIterable<Uint8Array> {
  const values: Uint8Array[] = [];
  for (let offset = 0; offset < value.byteLength; offset += size) {
    values.push(value.subarray(offset, Math.min(offset + size, value.byteLength)));
  }
  return asyncValues(values);
}

function asyncValues<T>(values: readonly T[]): AsyncIterable<T> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<T> {
      let index = 0;
      return {
        next(): Promise<IteratorResult<T>> {
          const value = values[index];
          index += 1;
          return Promise.resolve(
            value === undefined
              ? { done: true, value: undefined }
              : { done: false, value },
          );
        },
      };
    },
  };
}
