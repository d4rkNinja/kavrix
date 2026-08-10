import { createHash, randomUUID } from 'node:crypto';

import { generateVaultRootKey, zeroize, type VaultRootKey } from '@kavrix/crypto';
import {
  createEncryptedBackup,
  restoreEncryptedBackup,
  verifyEncryptedBackup,
} from '@kavrix/import-export';
import {
  aeadEnvelopeSchema,
  attachmentHeaderContentHash,
  canonicalJson,
  contentHashForRecord,
  encryptedAttachmentRecordSchema,
  encryptedAuditRecordSchema,
  encryptedGroupRecordSchema,
  encryptedHistoryRecordSchema,
  encryptedItemRecordSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  tombstoneRecordSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type AeadEnvelope,
  type EncryptedAttachmentRecord,
  type EncryptedAuditRecord,
  type EncryptedBackupEntry,
  type EncryptedGroupRecord,
  type EncryptedHistoryRecord,
  type EncryptedItemRecord,
  type PersistedAttachmentChunkRecord,
  type PersistedAttachmentHeaderRecord,
  type TombstoneRecord,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import { MongoClient, type Db } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  MongoBackupRestoreStore,
  MongoBackupSource,
  mongoStorageCollectionNames,
  toAuditDocument,
  toItemDocument,
  toTombstoneDocument,
} from '../src/index.js';

const mongodbUri = process.env['KAVRIX_MONGODB_URI'];
if (mongodbUri === undefined || mongodbUri.length === 0) {
  throw new Error(
    'KAVRIX_MONGODB_URI is required and must select a transaction-capable MongoDB replica set.',
  );
}

const CREATED_AT = '2026-08-10T00:00:00.000Z';
const DELETED_AT = '2026-08-10T00:01:00.000Z';
const RESTORED_AT = '2026-08-10T00:02:00.000Z';
const LIMITS = { maximumBytes: 8 * 1024 * 1024, maximumRecords: 100 } as const;
const CANARIES = [
  'MONGO_SOURCE_GROUP_PLAINTEXT_CANARY',
  'MONGO_SOURCE_ACTIVE_ITEM_PLAINTEXT_CANARY',
  'MONGO_SOURCE_DELETED_ITEM_PLAINTEXT_CANARY',
  'MONGO_SOURCE_RESTORED_ITEM_PLAINTEXT_CANARY',
  'MONGO_SOURCE_ATTACHMENT_PLAINTEXT_CANARY',
  'MONGO_SOURCE_AUDIT_PLAINTEXT_CANARY',
  'MONGO_SOURCE_HISTORY_PLAINTEXT_CANARY',
] as const;

type NonVaultEntry = Exclude<EncryptedBackupEntry, { kind: 'vault' }>;

interface SourceFixture {
  readonly rootKey: VaultRootKey;
  readonly vaultId: VaultId;
  readonly vault: VaultRecord;
  readonly group: EncryptedGroupRecord;
  readonly activeItem: EncryptedItemRecord;
  readonly deletedItem: EncryptedItemRecord;
  readonly deletedPredecessor: EncryptedItemRecord;
  readonly deletedTombstone: TombstoneRecord;
  readonly restoredItem: EncryptedItemRecord;
  readonly restoredTombstone: TombstoneRecord;
  readonly attachment: EncryptedAttachmentRecord;
  readonly attachmentHeader: PersistedAttachmentHeaderRecord;
  readonly attachmentChunks: readonly PersistedAttachmentChunkRecord[];
  readonly history: EncryptedHistoryRecord;
  readonly audit: EncryptedAuditRecord;
  readonly records: readonly NonVaultEntry[];
  readonly archive: Buffer;
}

describe('MongoBackupSource against a replica-set snapshot', () => {
  const client = new MongoClient(mongodbUri, {
    appName: 'kavrix-mongo-backup-source-integration',
  });
  let fixture: SourceFixture;

  beforeAll(async () => {
    await client.connect();
    fixture = await createFixture();
  });

  afterAll(async () => {
    zeroize(fixture.rootKey);
    await client.close();
  });

  it('round-trips every supported family in deterministic restore-safe order', async () => {
    await withRestoredFixture(client, fixture, async (database) => {
      const source = new MongoBackupSource(client, database);
      const first = await source.open(fixture.vaultId, LIMITS);
      const records = await collect(first.records);

      expect(first.vault).toEqual(fixture.vault);
      expect(records).toEqual(fixture.records);
      expect(records.map(entryIdentity)).toEqual([
        `group:${fixture.group.id}`,
        `item:${fixture.activeItem.id}`,
        `history:${fixture.history.id}`,
        `attachment:${fixture.attachment.id}`,
        `attachment-header:${fixture.attachment.id}`,
        `attachment-chunk:${fixture.attachment.id}:0`,
        `attachment-chunk:${fixture.attachment.id}:1`,
        `item:${fixture.deletedItem.id}`,
        `tombstone-predecessor:${fixture.deletedItem.id}`,
        `tombstone:${fixture.deletedItem.id}:deleted`,
        `item:${fixture.restoredItem.id}`,
        `tombstone:${fixture.restoredItem.id}:restored`,
        `audit:${fixture.audit.id}`,
      ]);

      const deletedIndex = records.findIndex(
        (entry) => entry.kind === 'tombstone' && entry.record.state === 'deleted',
      );
      expect(records[deletedIndex - 1]).toEqual({
        kind: 'tombstone-predecessor',
        entityType: 'item',
        record: fixture.deletedPredecessor,
      });
      expect(contentHashForRecord(fixture.deletedPredecessor)).toBe(
        fixture.deletedTombstone.lastCiphertextHash,
      );

      const restoredIndex = records.findIndex(
        (entry) => entry.kind === 'tombstone' && entry.record.state === 'restored',
      );
      expect(records[restoredIndex - 1]).toEqual({
        kind: 'item',
        record: fixture.restoredItem,
      });
      expect(records[restoredIndex - 2]?.kind).not.toBe('tombstone-predecessor');

      const second = await source.open(fixture.vaultId, LIMITS);
      const archive = await collectBytes(
        createEncryptedBackup(
          {
            vault: second.vault,
            records: second.records,
            createdAt: CREATED_AT,
            limits: LIMITS,
          },
          fixture.rootKey,
        ),
      );
      const verification = await verifyEncryptedBackup(
        chunks(archive, 37),
        fixture.rootKey,
        fixture.vaultId,
        LIMITS,
      );
      expect(verification.recordCount).toBe(fixture.records.length + 1);
      expect(verification.header.vaultId).toBe(fixture.vaultId);

      await withEmptyDatabase(client, async (restoredDatabase) => {
        const restoreStore = new MongoBackupRestoreStore(client, restoredDatabase, {
          now: () => new Date(CREATED_AT),
        });
        await restoreStore.initialize();
        await restoreEncryptedBackup(
          chunks(archive, 43),
          fixture.rootKey,
          fixture.vaultId,
          restoreStore,
          LIMITS,
        );
        const restoredSnapshot = await new MongoBackupSource(
          client,
          restoredDatabase,
        ).open(fixture.vaultId, LIMITS);
        expect(restoredSnapshot.vault).toEqual(fixture.vault);
        const restoredRecords = await collect(restoredSnapshot.records);
        expect(restoredRecords).toEqual(fixture.records);
        expect(
          restoredRecords.filter((entry) => entry.kind === 'tombstone-predecessor'),
        ).toEqual([
          {
            kind: 'tombstone-predecessor',
            entityType: 'item',
            record: fixture.deletedPredecessor,
          },
        ]);

        const rawInspection = await inspectVaultCollections(restoredDatabase);
        for (const canary of CANARIES) expect(rawInspection).not.toContain(canary);
      });

      const inspection = canonicalJson({ vault: first.vault, records });
      const archiveInspection = archive.toString('utf8');
      for (const canary of CANARIES) {
        expect(inspection).not.toContain(canary);
        expect(archiveInspection).not.toContain(canary);
      }
    });
  });

  it('pins a none-or-all snapshot across a concurrent write', async () => {
    await withRestoredFixture(client, fixture, async (database) => {
      const source = new MongoBackupSource(client, database);
      const pinned = await source.open(fixture.vaultId, LIMITS);
      const concurrentAudit = encryptedAuditRecordSchema.parse({
        ...fixture.audit,
        id: 'audit.concurrent',
        encryptedPayload: envelope(
          'audit-event',
          'audit.concurrent',
          fixture.vaultId,
          CANARIES[5],
        ),
      });
      await database
        .collection<Record<string, unknown> & { _id: string }>(
          mongoStorageCollectionNames.audits,
        )
        .insertOne(toAuditDocument(concurrentAudit));

      const pinnedRecords = await collect(pinned.records);
      expect(pinnedRecords).not.toContainEqual({
        kind: 'audit',
        record: concurrentAudit,
      });

      const current = await source.open(fixture.vaultId, LIMITS);
      const currentRecords = await collect(current.records);
      expect(currentRecords).toContainEqual({ kind: 'audit', record: concurrentAudit });
    });
  });

  it('fails generically when a deleted predecessor or attachment chunk is missing', async () => {
    await withRestoredFixture(client, fixture, async (database) => {
      await database.collection(mongoStorageCollectionNames.changes).deleteMany({
        vaultId: fixture.vaultId,
        'record.entityType': 'item',
        'record.entityId': fixture.deletedItem.id,
        'record.recordRevision': fixture.deletedTombstone.lastRecordRevision,
      });
      const source = new MongoBackupSource(client, database);
      const snapshot = await source.open(fixture.vaultId, LIMITS);
      const caught = await collect(snapshot.records).catch((error: unknown) => error);
      expect(caught).toEqual(expect.objectContaining({ code: 'BACKUP_SOURCE_FAILED' }));
      expect(String(caught)).toBe(
        'MongoBackupSourceError: The encrypted backup source could not be read safely.',
      );
      for (const canary of CANARIES) expect(String(caught)).not.toContain(canary);
    });

    await withRestoredFixture(client, fixture, async (database) => {
      await database
        .collection(mongoStorageCollectionNames.attachmentStagingChunks)
        .deleteOne({ attachmentId: fixture.attachment.id, chunkIndex: 1 });
      const source = new MongoBackupSource(client, database);
      const snapshot = await source.open(fixture.vaultId, LIMITS);
      await expect(collect(snapshot.records)).rejects.toEqual(
        expect.objectContaining({ code: 'BACKUP_SOURCE_FAILED' }),
      );
    });
  });

  it('rejects orphan records and same-staging chunks with a foreign identity', async () => {
    await withRestoredFixture(client, fixture, async (database) => {
      const orphan = itemRecord(
        fixture.vaultId,
        'group.missing',
        'item.orphan',
        0,
        CREATED_AT,
        CANARIES[1],
      );
      await database
        .collection<Record<string, unknown> & { _id: string }>(
          mongoStorageCollectionNames.items,
        )
        .insertOne(toItemDocument(orphan));
      const snapshot = await new MongoBackupSource(client, database).open(
        fixture.vaultId,
        LIMITS,
      );
      await expect(collect(snapshot.records)).rejects.toEqual(
        expect.objectContaining({ code: 'BACKUP_SOURCE_FAILED' }),
      );
    });

    await withRestoredFixture(client, fixture, async (database) => {
      const collection = database.collection<Record<string, unknown> & { _id: string }>(
        mongoStorageCollectionNames.attachmentStagingChunks,
      );
      const original = await collection.findOne({
        attachmentId: fixture.attachment.id,
      });
      if (original === null) throw new Error('Integration fixture chunk is missing.');
      const storedRecord = requireRecord(original['record']);
      const chunkIdentity = requireRecord(storedRecord['record']);
      await collection.insertOne({
        ...original,
        _id: `${original._id}:foreign`,
        attachmentId: 'attachment.foreign',
        chunkIndex: 99,
        record: {
          ...storedRecord,
          record: {
            ...chunkIdentity,
            attachmentId: 'attachment.foreign',
            index: 99,
          },
        },
      });
      const snapshot = await new MongoBackupSource(client, database).open(
        fixture.vaultId,
        LIMITS,
      );
      await expect(collect(snapshot.records)).rejects.toEqual(
        expect.objectContaining({ code: 'BACKUP_SOURCE_FAILED' }),
      );
    });
  });

  it('enforces one-shot ownership, configured limits, and cancellation', async () => {
    await withRestoredFixture(client, fixture, async (database) => {
      const source = new MongoBackupSource(client, database);
      const active = await source.open(fixture.vaultId, LIMITS);
      active.records[Symbol.asyncIterator]();
      expect(() => active.records[Symbol.asyncIterator]()).toThrow(
        expect.objectContaining({ code: 'BACKUP_SOURCE_BUSY' }),
      );
      await active.close();

      const closed = await source.open(fixture.vaultId, LIMITS);
      await closed.close();
      expect(() => closed.records[Symbol.asyncIterator]()).toThrow(
        expect.objectContaining({ code: 'BACKUP_SOURCE_BUSY' }),
      );

      const bounded = await source.open(fixture.vaultId, {
        maximumBytes: LIMITS.maximumBytes,
        maximumRecords: 1,
      });
      const tooLarge = await collect(bounded.records).catch((error: unknown) => error);
      expect(tooLarge).toEqual(
        expect.objectContaining({ code: 'BACKUP_SOURCE_TOO_LARGE' }),
      );
      expect(String(tooLarge)).toContain('exceeds its configured limits');

      const controller = new AbortController();
      const cancelled = await source.open(fixture.vaultId, {
        ...LIMITS,
        signal: controller.signal,
      });
      controller.abort('MONGO_SOURCE_CANCEL_CANARY');
      const aborted = await collect(cancelled.records).catch((error: unknown) => error);
      expect(aborted).toEqual(
        expect.objectContaining({ code: 'BACKUP_SOURCE_ABORTED' }),
      );
      expect(String(aborted)).not.toContain('MONGO_SOURCE_CANCEL_CANARY');
    });
  });

  it.each([
    {
      name: 'group revision beyond the vault',
      mutate: async (database: Db, value: SourceFixture) =>
        database
          .collection(mongoStorageCollectionNames.groups)
          .updateOne(
            { groupId: value.group.id },
            { $set: { 'record.recordRevision': 6 } },
          ),
    },
    {
      name: 'item revision beyond the vault',
      mutate: async (database: Db, value: SourceFixture) =>
        database
          .collection(mongoStorageCollectionNames.items)
          .updateOne(
            { itemId: value.activeItem.id },
            { $set: { 'record.recordRevision': 6 } },
          ),
    },
    {
      name: 'history revision beyond its item',
      mutate: async (database: Db, value: SourceFixture) =>
        database
          .collection(mongoStorageCollectionNames.histories)
          .updateOne(
            { historyId: value.history.id },
            { $set: { 'record.itemRecordRevision': 1 } },
          ),
    },
    {
      name: 'attachment revision beyond the vault',
      mutate: async (database: Db, value: SourceFixture) =>
        database
          .collection(mongoStorageCollectionNames.attachments)
          .updateOne(
            { attachmentId: value.attachment.id },
            { $set: { 'record.recordRevision': 6 } },
          ),
    },
    {
      name: 'audit revision beyond the vault',
      mutate: async (database: Db, value: SourceFixture) =>
        database
          .collection(mongoStorageCollectionNames.audits)
          .updateOne(
            { auditId: value.audit.id },
            { $set: { 'record.recordRevision': 6 } },
          ),
    },
    {
      name: 'tombstoned current record without a tombstone',
      mutate: async (database: Db, value: SourceFixture) =>
        database.collection(mongoStorageCollectionNames.items).updateOne(
          { itemId: value.activeItem.id },
          {
            $set: {
              'record.updatedAt': DELETED_AT,
              'record.tombstonedAt': DELETED_AT,
            },
          },
        ),
    },
    {
      name: 'deleted current timestamp mismatch',
      mutate: async (database: Db, value: SourceFixture) =>
        database
          .collection(mongoStorageCollectionNames.items)
          .updateOne(
            { itemId: value.deletedItem.id },
            { $set: { 'record.tombstonedAt': RESTORED_AT } },
          ),
    },
    {
      name: 'restored current timestamp mismatch',
      mutate: async (database: Db, value: SourceFixture) =>
        database
          .collection(mongoStorageCollectionNames.items)
          .updateOne(
            { itemId: value.restoredItem.id },
            { $set: { 'record.updatedAt': CREATED_AT } },
          ),
    },
    {
      name: 'tombstone revision mismatch',
      mutate: async (database: Db, value: SourceFixture) =>
        database
          .collection(mongoStorageCollectionNames.tombstones)
          .updateOne(
            { entityId: value.deletedItem.id },
            { $set: { 'record.tombstoneRevision': 3 } },
          ),
    },
    {
      name: 'missing finalized attachment staging',
      mutate: async (database: Db, value: SourceFixture) =>
        database
          .collection(mongoStorageCollectionNames.attachmentStaging)
          .deleteOne({ attachmentId: value.attachment.id }),
    },
    {
      name: 'change sequence drift',
      mutate: async (database: Db, value: SourceFixture) =>
        database
          .collection(mongoStorageCollectionNames.counters)
          .updateOne({ _id: value.vaultId }, { $inc: { changeSequence: 1 } }),
    },
    {
      name: 'orphan tombstone',
      mutate: async (database: Db, value: SourceFixture) => {
        const record = tombstoneRecordSchema.parse({
          vaultId: value.vaultId,
          entityType: 'item',
          entityId: 'item.missing',
          state: 'restored',
          tombstoneRevision: 1,
          lastRecordRevision: 0,
          lastCiphertextHash: digest(Buffer.from('missing-predecessor')),
          deletedAt: DELETED_AT,
          restoredAt: RESTORED_AT,
        });
        return database
          .collection<Record<string, unknown> & { _id: string }>(
            mongoStorageCollectionNames.tombstones,
          )
          .insertOne(toTombstoneDocument(record));
      },
    },
  ])('fails closed for $name', async ({ mutate }) => {
    await withRestoredFixture(client, fixture, async (database) => {
      await mutate(database, fixture);
      const snapshot = await new MongoBackupSource(client, database).open(
        fixture.vaultId,
        LIMITS,
      );
      const caught = await collect(snapshot.records).catch((error: unknown) => error);
      expect(caught).toEqual(expect.objectContaining({ code: 'BACKUP_SOURCE_FAILED' }));
      for (const canary of CANARIES) expect(String(caught)).not.toContain(canary);
    });
  });
});

async function createFixture(): Promise<SourceFixture> {
  const vaultId = vaultIdSchema.parse('source.vault');
  const rootKey = generateVaultRootKey();
  const vault = vaultRecordSchema.parse({
    id: vaultId,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [
      {
        id: 'source.slot',
        slotVersion: 1,
        type: 'portable-key',
        state: 'active',
        keyVersion: 1,
        derivation: {
          algorithm: 'hkdf-sha256',
          version: 1,
          salt: digest(Buffer.from('source-slot-salt')),
          context: 'credvault/v1/portable-key-wrap',
          outputLength: 32,
        },
        wrappedRootKey: envelope('wrapped-root-key', 'source.slot', vaultId),
        createdAt: CREATED_AT,
      },
    ],
    currentKeyVersion: 1,
    revision: 5,
    encryptedPreferences: envelope(
      'vault-preferences',
      vaultId,
      vaultId,
      'MONGO_SOURCE_PREFERENCES_CANARY',
    ),
    createdAt: CREATED_AT,
    updatedAt: RESTORED_AT,
  });
  const group = groupRecord(vaultId, 'group.a', CANARIES[0]);
  const activeItem = itemRecord(
    vaultId,
    group.id,
    'item.a-active',
    0,
    CREATED_AT,
    CANARIES[1],
  );
  const deletedPredecessor = itemRecord(
    vaultId,
    group.id,
    'item.b-deleted',
    0,
    CREATED_AT,
    CANARIES[2],
  );
  const deletedItem = encryptedItemRecordSchema.parse({
    ...deletedPredecessor,
    recordRevision: 1,
    updatedAt: DELETED_AT,
    tombstonedAt: DELETED_AT,
  });
  const deletedTombstone = tombstoneRecordSchema.parse({
    vaultId,
    entityType: 'item',
    entityId: deletedItem.id,
    state: 'deleted',
    tombstoneRevision: 1,
    lastRecordRevision: 0,
    lastCiphertextHash: contentHashForRecord(deletedPredecessor),
    deletedAt: DELETED_AT,
  });
  const restoredPredecessor = itemRecord(
    vaultId,
    group.id,
    'item.c-restored',
    0,
    CREATED_AT,
    CANARIES[3],
  );
  const restoredItem = encryptedItemRecordSchema.parse({
    ...restoredPredecessor,
    encryptedPayload: envelope(
      'item',
      restoredPredecessor.id,
      vaultId,
      CANARIES[3],
      group.id,
    ),
    ciphertextHash: digest(Buffer.from(CANARIES[3])),
    recordRevision: 2,
    updatedAt: RESTORED_AT,
  });
  const restoredTombstone = tombstoneRecordSchema.parse({
    vaultId,
    entityType: 'item',
    entityId: restoredItem.id,
    state: 'restored',
    tombstoneRevision: 2,
    lastRecordRevision: 0,
    lastCiphertextHash: contentHashForRecord(restoredPredecessor),
    deletedAt: DELETED_AT,
    restoredAt: RESTORED_AT,
  });
  const attachment = encryptedAttachmentRecordSchema.parse({
    id: 'attachment.a',
    vaultId,
    groupId: group.id,
    itemId: activeItem.id,
    schemaVersion: 1,
    wrappedAttachmentKey: envelope(
      'wrapped-attachment-key',
      'attachment.a',
      vaultId,
      'wrapped-attachment',
      group.id,
      activeItem.id,
    ),
    encryptedManifest: envelope(
      'attachment',
      'attachment.a',
      vaultId,
      CANARIES[4],
      group.id,
      activeItem.id,
    ),
    chunkCount: 2,
    recordRevision: 0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
  const attachmentHeaderBase = persistedAttachmentHeaderRecordSchema.parse({
    entityType: 'attachment-header',
    record: {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      groupId: group.id,
      itemId: activeItem.id,
      attachmentId: attachment.id,
      recordType: 'header',
      header: Buffer.alloc(24, 7).toString('base64url'),
    },
    recordRevision: 0,
    contentHash: digest(Buffer.from('placeholder')),
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
  const attachmentHeader = persistedAttachmentHeaderRecordSchema.parse({
    ...attachmentHeaderBase,
    contentHash: attachmentHeaderContentHash(attachmentHeaderBase),
  });
  const attachmentChunks = [
    attachmentChunk(vaultId, group.id, activeItem.id, attachment.id, 0, 'message'),
    attachmentChunk(vaultId, group.id, activeItem.id, attachment.id, 1, 'final'),
  ];
  const history = encryptedHistoryRecordSchema.parse({
    id: 'history.a',
    vaultId,
    groupId: group.id,
    itemId: activeItem.id,
    schemaVersion: 1,
    encryptedPayload: envelope(
      'history',
      'history.a',
      vaultId,
      CANARIES[6],
      group.id,
      activeItem.id,
    ),
    itemRecordRevision: 0,
    ciphertextHash: digest(Buffer.from(CANARIES[6])),
    createdAt: CREATED_AT,
  });
  const audit = encryptedAuditRecordSchema.parse({
    id: 'audit.a',
    vaultId,
    schemaVersion: 1,
    encryptedPayload: envelope('audit-event', 'audit.a', vaultId, CANARIES[5]),
    recordRevision: 0,
    createdAt: CREATED_AT,
  });
  const records: readonly NonVaultEntry[] = [
    { kind: 'group', record: group },
    { kind: 'item', record: activeItem },
    { kind: 'history', record: history },
    { kind: 'attachment', record: attachment },
    { kind: 'attachment-header', record: attachmentHeader },
    ...attachmentChunks.map((record) => ({
      kind: 'attachment-chunk' as const,
      record,
    })),
    { kind: 'item', record: deletedItem },
    { kind: 'tombstone-predecessor', entityType: 'item', record: deletedPredecessor },
    { kind: 'tombstone', record: deletedTombstone },
    { kind: 'item', record: restoredItem },
    { kind: 'tombstone', record: restoredTombstone },
    { kind: 'audit', record: audit },
  ];
  const archive = await collectBytes(
    createEncryptedBackup(
      { vault, records: asyncValues(records), createdAt: CREATED_AT, limits: LIMITS },
      rootKey,
    ),
  );
  return {
    rootKey,
    vaultId,
    vault,
    group,
    activeItem,
    deletedItem,
    deletedPredecessor,
    deletedTombstone,
    restoredItem,
    restoredTombstone,
    attachment,
    attachmentHeader,
    attachmentChunks,
    history,
    audit,
    records,
    archive,
  };
}

function groupRecord(
  vaultId: VaultId,
  id: string,
  canary: string,
): EncryptedGroupRecord {
  return encryptedGroupRecordSchema.parse({
    id,
    vaultId,
    schemaVersion: 1,
    wrappedGroupKey: envelope('wrapped-group-key', id, vaultId),
    encryptedPayload: envelope('group', id, vaultId, canary),
    templateVersion: 1,
    recordRevision: 0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
}

function itemRecord(
  vaultId: VaultId,
  groupId: string,
  id: string,
  recordRevision: number,
  updatedAt: string,
  canary: string,
): EncryptedItemRecord {
  return encryptedItemRecordSchema.parse({
    id,
    vaultId,
    groupId,
    schemaVersion: 1,
    wrappedItemKey: envelope('wrapped-item-key', id, vaultId, 'wrapped-item', groupId),
    encryptedPayload: envelope('item', id, vaultId, canary, groupId),
    recordRevision,
    ciphertextHash: digest(Buffer.from(canary)),
    createdAt: CREATED_AT,
    updatedAt,
  });
}

function attachmentChunk(
  vaultId: VaultId,
  groupId: string,
  itemId: string,
  attachmentId: string,
  index: number,
  tag: 'message' | 'final',
): PersistedAttachmentChunkRecord {
  const plaintext = Buffer.from(`${CANARIES[4]}:${String(index)}`);
  const ciphertext = Buffer.concat([plaintext, Buffer.alloc(17, index + 1)]);
  return persistedAttachmentChunkRecordSchema.parse({
    entityType: 'attachment-chunk',
    record: {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      groupId,
      itemId,
      attachmentId,
      recordType: 'chunk',
      index,
      ciphertext: ciphertext.toString('base64url'),
      tag,
    },
    plaintextBytes: plaintext.byteLength,
    recordRevision: 0,
    ciphertextHash: digest(ciphertext),
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
}

function envelope(
  entityType:
    | 'wrapped-root-key'
    | 'vault-preferences'
    | 'wrapped-group-key'
    | 'group'
    | 'wrapped-item-key'
    | 'item'
    | 'wrapped-attachment-key'
    | 'attachment'
    | 'audit-event'
    | 'history',
  entityId: string,
  vaultId: string,
  plaintext = 'opaque-test-record',
  groupId?: string,
  parentId?: string,
): AeadEnvelope {
  const purposes = {
    'wrapped-root-key': 'vrk-slot',
    'vault-preferences': 'vault-preferences',
    'wrapped-group-key': 'group-key',
    group: 'group-payload',
    'wrapped-item-key': 'item-key',
    item: 'item-payload',
    'wrapped-attachment-key': 'attachment-key',
    attachment: 'attachment-metadata',
    'audit-event': 'audit-event',
    history: 'history-event',
  } as const;
  return aeadEnvelopeSchema.parse({
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: Buffer.alloc(24, 1).toString('base64url'),
    ciphertext: Buffer.from(plaintext).toString('base64url'),
    authenticationTag: Buffer.alloc(16, 2).toString('base64url'),
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType,
      entityId,
      ...(groupId === undefined ? {} : { groupId }),
      ...(parentId === undefined ? {} : { parentId }),
      purpose: purposes[entityType],
    },
    keyVersion: 1,
  });
}

function digest(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('base64url');
}

async function withRestoredFixture(
  client: MongoClient,
  fixture: SourceFixture,
  use: (database: Db) => Promise<void>,
): Promise<void> {
  const database = client.db(`kavrix_source_${randomUUID().replaceAll('-', '')}`);
  try {
    const store = new MongoBackupRestoreStore(client, database, {
      now: () => new Date(CREATED_AT),
    });
    await store.initialize();
    await restoreEncryptedBackup(
      chunks(fixture.archive, 41),
      fixture.rootKey,
      fixture.vaultId,
      store,
      LIMITS,
    );
    await use(database);
  } finally {
    await database.dropDatabase();
  }
}

async function withEmptyDatabase(
  client: MongoClient,
  use: (database: Db) => Promise<void>,
): Promise<void> {
  const database = client.db(
    `kavrix_source_target_${randomUUID().replaceAll('-', '')}`,
  );
  try {
    await use(database);
  } finally {
    await database.dropDatabase();
  }
}

async function inspectVaultCollections(database: Db): Promise<string> {
  const collectionNames = [
    mongoStorageCollectionNames.vaults,
    mongoStorageCollectionNames.groups,
    mongoStorageCollectionNames.items,
    mongoStorageCollectionNames.attachments,
    mongoStorageCollectionNames.audits,
    mongoStorageCollectionNames.histories,
    mongoStorageCollectionNames.tombstones,
    mongoStorageCollectionNames.attachmentStaging,
    mongoStorageCollectionNames.attachmentStagingChunks,
    mongoStorageCollectionNames.changes,
    mongoStorageCollectionNames.counters,
  ] as const;
  const documents: unknown[] = [];
  for (const collectionName of collectionNames) {
    documents.push(...(await database.collection(collectionName).find({}).toArray()));
  }
  return canonicalJson(documents);
}

function entryIdentity(entry: NonVaultEntry): string {
  if (entry.kind === 'tombstone-predecessor') {
    return `${entry.kind}:${entry.record.id}`;
  }
  if (entry.kind === 'tombstone') {
    return `${entry.kind}:${entry.record.entityId}:${entry.record.state}`;
  }
  if (entry.kind === 'attachment-header') {
    return `${entry.kind}:${entry.record.record.attachmentId}`;
  }
  if (entry.kind === 'attachment-chunk') {
    return `${entry.kind}:${entry.record.record.attachmentId}:${String(entry.record.record.index)}`;
  }
  return `${entry.kind}:${entry.record.id}`;
}

async function collect<T>(source: AsyncIterable<T>): Promise<T[]> {
  const values: T[] = [];
  for await (const value of source) values.push(value);
  return values;
}

async function collectBytes(source: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const values: Buffer[] = [];
  for await (const value of source) values.push(Buffer.from(value));
  return Buffer.concat(values);
}

async function* asyncValues<T>(values: readonly T[]): AsyncGenerator<T> {
  await Promise.resolve();
  for (const value of values) yield value;
}

async function* chunks(
  bytes: Uint8Array,
  width = bytes.byteLength,
): AsyncGenerator<Uint8Array> {
  await Promise.resolve();
  for (let offset = 0; offset < bytes.byteLength; offset += width) {
    yield bytes.subarray(offset, Math.min(bytes.byteLength, offset + width));
  }
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Integration fixture document is malformed.');
  }
  return value as Record<string, unknown>;
}
