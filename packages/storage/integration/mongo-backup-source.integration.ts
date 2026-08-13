import { createHash, randomUUID } from 'node:crypto';

import {
  cloneSecretKey,
  generateVaultRootKey,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import { OpaqueVaultSnapshot } from '@kavrix/client';
import {
  createEncryptedBackup,
  restoreEncryptedBackup,
  verifyEncryptedBackup,
  type RestoreEncryptedBackupResult,
  type RestoreVerificationSessionFactory,
} from '@kavrix/import-export';
import {
  aeadEnvelopeSchema,
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  canonicalJson,
  contentHashForRecord,
  encryptedAttachmentRecordSchema,
  encryptedAuditRecordSchema,
  encryptedBackupEntrySchema,
  encryptedGroupRecordSchema,
  encryptedHistoryRecordSchema,
  encryptedItemRecordSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  restoreKnownRecordsVerificationV1Schema,
  sha256DigestSchema,
  syncCursorSchema,
  tombstoneRecordSchema,
  vaultIdSchema,
  vaultRecordSchema,
  vaultRevisionSchema,
  backupRestoreStatusSchema,
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
  type BackupRestoreStager,
  type BackupRestoreStore,
  type BackupVerification,
  type RestoreKnownRecordsVerificationV1,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import { BSON, MongoClient, type Db } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import {
  MongoBackupRestoreStore,
  MongoBackupSource,
  MongoVaultStorage,
  backupRestoreSessionDocumentSchema,
  hashCanonical,
  mongoStorageCollectionNames,
  toAuditDocument,
  toHistoryDocument,
  toItemDocument,
  toTombstoneDocument,
} from '../src/index.js';
import {
  CANONICAL_RESTORE_EXPECTED_COUNTS,
  CANONICAL_RESTORE_LIMITS,
  CANONICAL_RESTORE_PLAINTEXT_CANARIES,
  createCanonicalKnownV1RestoreFixture,
  type CanonicalKnownV1RestoreFixture,
  type CanonicalInnerCorruption,
  type CanonicalRestoreSlotType,
} from './canonical-known-v1-restore-fixture.js';

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
}

describe('MongoBackupSource against a replica-set snapshot', () => {
  const client = new MongoClient(mongodbUri, {
    appName: 'kavrix-mongo-backup-source-integration',
  });
  let fixture: SourceFixture;

  beforeAll(async () => {
    await client.connect();
    fixture = createFixture();
  });

  afterAll(async () => {
    zeroize(fixture.rootKey);
    await client.close();
  });

  it('exports every opaque family in deterministic restore-safe order', async () => {
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
        await expect(
          restoreEncryptedBackup(
            chunks(archive, 43),
            fixture.vaultId,
            restoreStore,
            unsupportedRestoreFactory(fixture),
            LIMITS,
          ),
        ).rejects.toMatchObject({
          code: 'BACKUP_DECRYPTABILITY_UNSUPPORTED',
        });
        expect(
          await restoredDatabase
            .collection(mongoStorageCollectionNames.vaults)
            .countDocuments(),
        ).toBe(0);
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

  it.each(['header', 'chunk'] as const)(
    'fails before a footer when raw MongoDB contains a noncanonical attachment %s hash',
    async (kind) => {
      await withRestoredFixture(client, fixture, async (database) => {
        const invalidHash = sha256DigestSchema.parse(
          Buffer.alloc(32).toString('base64url'),
        );
        if (kind === 'header') {
          await database
            .collection(mongoStorageCollectionNames.attachmentStaging)
            .updateOne(
              { attachmentId: fixture.attachment.id },
              { $set: { 'input.header.contentHash': invalidHash } },
            );
        } else {
          await database
            .collection(mongoStorageCollectionNames.attachmentStagingChunks)
            .updateOne(
              { attachmentId: fixture.attachment.id, chunkIndex: 0 },
              { $set: { 'record.ciphertextHash': invalidHash } },
            );
        }

        const snapshot = await new MongoBackupSource(client, database).open(
          fixture.vaultId,
          LIMITS,
        );
        const emitted: Uint8Array[] = [];
        const caught = await (async (): Promise<unknown> => {
          try {
            for await (const bytes of createEncryptedBackup(
              {
                vault: snapshot.vault,
                records: snapshot.records,
                createdAt: CREATED_AT,
                limits: LIMITS,
              },
              fixture.rootKey,
            )) {
              emitted.push(bytes);
            }
            return undefined;
          } catch (error) {
            return error;
          }
        })();

        expect(caught).toEqual(
          expect.objectContaining({ code: 'BACKUP_SOURCE_FAILED' }),
        );
        expect(Buffer.concat(emitted).toString('utf8')).not.toContain(
          '"type":"footer"',
        );
      });
    },
  );

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

describe('canonical known-v1 restore coordinator against a replica-set target', () => {
  const client = new MongoClient(mongodbUri, {
    appName: 'kavrix-canonical-restore-acceptance',
  });
  let canonical: CanonicalKnownV1RestoreFixture;

  beforeAll(async () => {
    await client.connect();
    canonical = await createCanonicalKnownV1RestoreFixture();
  });

  afterAll(async () => {
    canonical.close();
    await client.close();
  });

  it.each(['portable-key', 'passphrase', 'recovery-key'] as const)(
    'restores one canonical archive through each supported archived slot and semantically reopens it: %s',
    async (slotType) => {
      await withEmptyDatabase(client, async (database) => {
        const store = new MongoBackupRestoreStore(client, database);
        await store.initialize();
        const result = await restoreEncryptedBackup(
          chunks(canonical.archive, 41),
          canonical.vaultId,
          store,
          canonical.verificationFactory(slotType),
          CANONICAL_RESTORE_LIMITS,
        );
        expect(result.disposition).toBe('verified-and-committed');
        if (result.disposition !== 'verified-and-committed') {
          throw new Error('Canonical restore did not produce a fresh receipt.');
        }
        const receipt = restoreKnownRecordsVerificationV1Schema.parse(
          result.verification,
        );
        expect(receipt).toMatchObject({
          vaultId: canonical.vaultId,
          vaultRevision: canonical.vaultRevision,
          restoreSessionId: canonical.summary.restoreSessionId,
          transcriptSha256: canonical.summary.transcriptSha256,
          canonicalEntriesSha256: canonical.summary.canonicalEntriesSha256,
          recordCount: 14,
          selectedSlot: {
            id: canonical.slotIds[slotType],
            type: slotType,
            keyVersion: canonical.vault.currentKeyVersion,
          },
          verified: CANONICAL_RESTORE_EXPECTED_COUNTS,
        });
        const reopened = await store.open(
          canonical.summary.restoreSessionId,
          CANONICAL_RESTORE_LIMITS,
        );
        expect(backupRestoreStatusSchema.parse(await reopened.status())).toMatchObject({
          state: 'committed',
          summary: canonical.summary,
        });
        await expect(
          database
            .collection(mongoStorageCollectionNames.backupRestoreEntries)
            .countDocuments(),
        ).resolves.toBe(0);
        await expectCanonicalVisibleCounts(database);

        const firstSource = await new MongoBackupSource(client, database).open(
          canonical.vaultId,
          CANONICAL_RESTORE_LIMITS,
        );
        const sourceRecords = await collect(firstSource.records);
        expect(firstSource.vault).toEqual(canonical.vault);
        expect(sourceRecords).toEqual(canonical.records);
        const freshArchive = await canonical.createArchive(sourceRecords);
        const freshSummary = await canonical.authenticate(freshArchive);
        const secondSource = await new MongoBackupSource(client, database).open(
          canonical.vaultId,
          CANONICAL_RESTORE_LIMITS,
        );
        const semanticSession = await canonical.verificationFactory(slotType)(
          secondSource.vault,
        );
        try {
          await expect(
            semanticSession.verify(
              prependVault(secondSource.vault, secondSource.records),
              freshSummary,
            ),
          ).resolves.toMatchObject({
            recordCount: 14,
            verified: CANONICAL_RESTORE_EXPECTED_COUNTS,
          });
        } finally {
          semanticSession.close();
        }

        const visible = new MongoVaultStorage(client, database);
        const page = await visible.pullSyncPage(
          syncCursorSchema.parse({
            vaultId: canonical.vaultId,
            serverSequence: 0,
            highestSeenVaultRevision: 0,
          }),
          100,
        );
        const snapshot = new OpaqueVaultSnapshot(canonical.vaultId);
        snapshot.applyPullPage(page);
        await expect(
          snapshot.getItem(canonical.vaultId, canonical.activeItem.id),
        ).resolves.toEqual(canonical.activeItem);
        await expect(
          snapshot.getItem(canonical.vaultId, canonical.deletedItem.id),
        ).resolves.toBeNull();
        await expect(
          snapshot.getItem(canonical.vaultId, canonical.restoredItem.id),
        ).resolves.toEqual(canonical.restoredItem);

        const durable = await readAllBson(database);
        for (const canary of [
          ...CANONICAL_RESTORE_PLAINTEXT_CANARIES,
          ...canonical.credentialCanaries(),
        ]) {
          expect(Buffer.from(canonical.archive).toString('utf8')).not.toContain(canary);
          expect(durable).not.toContain(canary);
          expect(JSON.stringify(sourceRecords)).not.toContain(canary);
        }
      });
    },
  );

  it('returns previously-committed for an exact archive without fabricating a receipt', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database);
      await store.initialize();
      const first = await restoreCanonical(canonical, store, 'portable-key');
      expect(first.disposition).toBe('verified-and-committed');
      const before = await readAllBson(database);
      const replay = await restoreCanonical(canonical, store, 'portable-key');
      expect(replay).toEqual({
        disposition: 'previously-committed',
        backup: canonical.summary,
      });
      expect('verification' in replay).toBe(false);
      expect(await readAllBson(database)).toBe(before);
      await expect(
        database
          .collection(mongoStorageCollectionNames.backupRestoreEntries)
          .countDocuments(),
      ).resolves.toBe(0);
    });
  });

  it.each(['publish', 'finalize'] as const)(
    'reconciles publish and finalize response loss from durable Mongo state: %s',
    async (phase) => {
      await withEmptyDatabase(client, async (database) => {
        const realStore = new MongoBackupRestoreStore(client, database);
        await realStore.initialize();
        const result = await restoreEncryptedBackup(
          chunks(canonical.archive, 53),
          canonical.vaultId,
          responseLossStore(realStore, phase),
          canonical.verificationFactory('portable-key'),
          CANONICAL_RESTORE_LIMITS,
        );
        expect(result).toMatchObject({
          disposition: 'verified-and-committed',
          backup: canonical.summary,
        });
        if (result.disposition !== 'verified-and-committed') {
          throw new Error('Response-loss reconciliation omitted its receipt.');
        }
        expect(
          restoreKnownRecordsVerificationV1Schema.parse(result.verification),
        ).toMatchObject({
          vaultId: canonical.vaultId,
          vaultRevision: canonical.vaultRevision,
          restoreSessionId: canonical.summary.restoreSessionId,
          transcriptSha256: canonical.summary.transcriptSha256,
          canonicalEntriesSha256: canonical.summary.canonicalEntriesSha256,
          recordCount: 14,
          selectedSlot: {
            id: canonical.slotIds['portable-key'],
            type: 'portable-key',
            keyVersion: canonical.vault.currentKeyVersion,
          },
          verified: CANONICAL_RESTORE_EXPECTED_COUNTS,
        });
        const status = await (
          await realStore.open(
            canonical.summary.restoreSessionId,
            CANONICAL_RESTORE_LIMITS,
          )
        ).status();
        expect(status).toMatchObject({ state: 'committed' });
        await expect(
          database
            .collection(mongoStorageCollectionNames.backupRestoreEntries)
            .countDocuments(),
        ).resolves.toBe(0);
        expect(JSON.stringify(result)).not.toContain('response-loss-canary');
      });
    },
  );

  it('reconciles a later top-level replay from durable published state', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database);
      await store.initialize();
      const stager = await store.open(
        canonical.summary.restoreSessionId,
        CANONICAL_RESTORE_LIMITS,
      );
      for (const entry of canonical.entries) await stager.write(entry);
      await stager.seal(canonical.summary);
      const session = await canonical.verificationFactory('portable-key')(
        canonical.vault,
      );
      let receipt: RestoreKnownRecordsVerificationV1;
      try {
        receipt = await session.verify(
          stager.readSealed(canonical.summary),
          canonical.summary,
        );
      } finally {
        session.close();
      }
      await stager.publish(canonical.summary, receipt);
      await expect(stager.status()).resolves.toMatchObject({ state: 'published' });

      const reconciled = await restoreCanonical(canonical, store, 'portable-key');
      expect(reconciled).toMatchObject({
        disposition: 'verified-and-committed',
        backup: canonical.summary,
      });
      await expect(stager.status()).resolves.toMatchObject({ state: 'committed' });
      await expectCanonicalVisibleCounts(database);
    });
  });

  it('accepts an equal rollback anchor and rejects a lower archived revision before publication', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database);
      await store.initialize();
      const accepted = await restoreEncryptedBackup(
        chunks(canonical.archive),
        canonical.vaultId,
        store,
        canonical.verificationFactory('recovery-key', canonical.vaultRevision),
        CANONICAL_RESTORE_LIMITS,
      );
      expect(accepted.disposition).toBe('verified-and-committed');
    });
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database);
      await store.initialize();
      const caught = await restoreEncryptedBackup(
        chunks(canonical.archive),
        canonical.vaultId,
        store,
        canonical.verificationFactory(
          'recovery-key',
          vaultRevisionAbove(canonical.vaultRevision),
        ),
        CANONICAL_RESTORE_LIMITS,
      ).catch((error: unknown) => error);
      expect(caught).toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
      expect(String(caught)).not.toContain(String(canonical.vaultRevision));
      await expectNoVisibleRestore(client, database, canonical);
    });
  });

  it.each(['history', 'audit'] as const)(
    'keeps authenticated future history and audit versions explicit: %s',
    async (family) => {
      const archive = await canonical.unsupportedArchive(family);
      const summary = await canonical.authenticate(archive);
      expect(summary.recordCount).toBe(14);
      await withEmptyDatabase(client, async (database) => {
        const store = new MongoBackupRestoreStore(client, database);
        await store.initialize();
        const caught = await restoreEncryptedBackup(
          chunks(archive, 47),
          canonical.vaultId,
          store,
          canonical.verificationFactory('portable-key'),
          CANONICAL_RESTORE_LIMITS,
        ).catch((error: unknown) => error);
        expect(caught).toMatchObject({
          code: 'BACKUP_DECRYPTABILITY_UNSUPPORTED',
        });
        expect(String(caught)).not.toContain(family);
        await expectNoVisibleRestore(client, database, canonical, summary);
      });
    },
  );

  it.each([
    'preferences',
    'wrapped-group-key',
    'group-payload',
    'wrapped-item-key',
    'item-payload',
    'wrapped-attachment-key',
    'attachment-manifest',
    'attachment-stream',
  ] as const)(
    'rejects each HMAC-valid inner corruption without visible target mutation: %s',
    async (kind: CanonicalInnerCorruption) => {
      const archive = await canonical.innerCorruptionArchive(kind);
      const summary = await canonical.authenticate(archive);
      expect(summary.recordCount).toBe(14);
      await withEmptyDatabase(client, async (database) => {
        const store = new MongoBackupRestoreStore(client, database);
        await store.initialize();
        const capture = captureConsoleOutput();
        const caught = await restoreEncryptedBackup(
          chunks(archive, 37),
          canonical.vaultId,
          store,
          canonical.verificationFactory('portable-key'),
          CANONICAL_RESTORE_LIMITS,
        )
          .catch((error: unknown) => error)
          .finally(capture.restore);
        expect(caught).toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
        expect(String(caught)).not.toContain(kind);
        for (const canary of [
          ...CANONICAL_RESTORE_PLAINTEXT_CANARIES,
          ...canonical.credentialCanaries(),
        ]) {
          expect(String(caught)).not.toContain(canary);
          expect(capture.output()).not.toContain(canary);
        }
        await expectNoVisibleRestore(client, database, canonical, summary);
      });
    },
  );

  it.each(['before-readback', 'before-publication'] as const)(
    'rejects sealed staging substitution before readback and before publication: %s',
    async (window) => {
      await withEmptyDatabase(client, async (database) => {
        const realStore = new MongoBackupRestoreStore(client, database);
        await realStore.initialize();
        const caught = await restoreEncryptedBackup(
          chunks(canonical.archive, 59),
          canonical.vaultId,
          stagingSubstitutionStore(realStore, database, window),
          canonical.verificationFactory('portable-key'),
          CANONICAL_RESTORE_LIMITS,
        ).catch((error: unknown) => error);
        expect(caught).toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
        await expectNoVisibleRestore(client, database, canonical);
      });
    },
  );

  it('keeps the staging wrapper observational when no tamper is injected', async () => {
    let controlResult: unknown;
    let controlStatus: unknown;
    await withEmptyDatabase(client, async (database) => {
      const control = new MongoBackupRestoreStore(client, database, {
        now: () => new Date(CREATED_AT),
      });
      await control.initialize();
      controlResult = await restoreCanonical(canonical, control, 'portable-key');
      controlStatus = await (
        await control.open(canonical.summary.restoreSessionId, CANONICAL_RESTORE_LIMITS)
      ).status();
    });
    await withEmptyDatabase(client, async (database) => {
      const realStore = new MongoBackupRestoreStore(client, database, {
        now: () => new Date(CREATED_AT),
      });
      await realStore.initialize();
      const result = await restoreEncryptedBackup(
        chunks(canonical.archive, 61),
        canonical.vaultId,
        stagingSubstitutionStore(realStore, database, 'no-tamper'),
        canonical.verificationFactory('portable-key'),
        CANONICAL_RESTORE_LIMITS,
      );
      expect(result).toMatchObject({
        disposition: 'verified-and-committed',
        backup: canonical.summary,
      });
      await expectCanonicalVisibleCounts(database);
      const status = await (
        await realStore.open(
          canonical.summary.restoreSessionId,
          CANONICAL_RESTORE_LIMITS,
        )
      ).status();
      expect(status).toMatchObject({ state: 'committed', summary: canonical.summary });
      expect(result).toEqual(controlResult);
      expect(status).toEqual(controlStatus);
    });
  });

  it('keeps plaintext and credential canaries out of archive staging BSON source errors and logs', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database);
      await store.initialize();
      const stager = await store.open(
        canonical.summary.restoreSessionId,
        CANONICAL_RESTORE_LIMITS,
      );
      for (const entry of canonical.entries) await stager.write(entry);
      await stager.seal(canonical.summary);
      const hiddenScan = await collectDurableScanValues(database);
      const archiveBytes = Buffer.from(canonical.archive);
      const canaries = [
        ...CANONICAL_RESTORE_PLAINTEXT_CANARIES,
        ...canonical.credentialCanaries(),
      ];
      assertNoRawCanaries([archiveBytes, ...hiddenScan], canaries);

      const session = await canonical.verificationFactory('passphrase')(
        canonical.vault,
      );
      let receipt: RestoreKnownRecordsVerificationV1;
      try {
        receipt = await session.verify(
          stager.readSealed(canonical.summary),
          canonical.summary,
        );
      } finally {
        session.close();
      }
      await stager.publish(canonical.summary, receipt);
      await stager.finalize(canonical.summary, receipt);

      const source = await new MongoBackupSource(client, database).open(
        canonical.vaultId,
        CANONICAL_RESTORE_LIMITS,
      );
      const sourceRecords = await collect(source.records);
      const visible = new MongoVaultStorage(client, database);
      const page = await visible.pullSyncPage(
        syncCursorSchema.parse({
          vaultId: canonical.vaultId,
          serverSequence: 0,
          highestSeenVaultRevision: 0,
        }),
        100,
      );
      const committedScan = await collectDurableScanValues(database);
      assertNoRawCanaries(
        [
          ...committedScan,
          Buffer.from(JSON.stringify(sourceRecords)),
          Buffer.from(JSON.stringify(page)),
        ],
        canaries,
      );

      const capture = captureConsoleOutput();
      const failure = await restoreEncryptedBackup(
        chunks(await canonical.innerCorruptionArchive('preferences')),
        canonical.vaultId,
        store,
        canonical.verificationFactory('portable-key'),
        CANONICAL_RESTORE_LIMITS,
      )
        .catch((error: unknown) => error)
        .finally(capture.restore);
      for (const canary of [...canaries]) {
        expect(String(failure)).not.toContain(canary);
        expect(capture.output()).not.toContain(canary);
      }
      for (const forbidden of [
        canonical.vaultId,
        canonical.group.id,
        canonical.activeItem.id,
        'portable-key',
        'passphrase',
        'recovery-key',
        'history',
        'audit',
        'response-loss-canary',
      ]) {
        expect(String(failure)).not.toContain(forbidden);
        expect(capture.output()).not.toContain(forbidden);
      }
      expect(failure).toBeInstanceOf(Error);
      expect((failure as Error & { cause?: unknown }).cause).toBeUndefined();
    });
  });
});

function createFixture(): SourceFixture {
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
  const base = persistedAttachmentChunkRecordSchema.parse({
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
  return persistedAttachmentChunkRecordSchema.parse({
    ...base,
    ciphertextHash: attachmentChunkCiphertextHash(base),
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
    await seedOpaqueSourceFixtureForTestOnly(store, database, fixture);
    await use(database);
  } finally {
    await database.dropDatabase();
  }
}

/**
 * Test-only opaque source seeding. This is not semantic restore evidence: the
 * history/audit records are inserted only after the known-v1 structural subset
 * has crossed the direct protocol-v2 storage boundary.
 */
async function seedOpaqueSourceFixtureForTestOnly(
  store: MongoBackupRestoreStore,
  database: Db,
  fixture: SourceFixture,
): Promise<void> {
  const records = fixture.records.filter(
    (entry) => entry.kind !== 'history' && entry.kind !== 'audit',
  );
  const archive = await collectBytes(
    createEncryptedBackup(
      {
        vault: fixture.vault,
        records: asyncValues(records),
        createdAt: CREATED_AT,
        limits: LIMITS,
      },
      fixture.rootKey,
    ),
  );
  const summary = await verifyEncryptedBackup(
    chunks(archive),
    fixture.rootKey,
    fixture.vaultId,
    LIMITS,
  );
  const entries = [{ kind: 'vault' as const, record: fixture.vault }, ...records];
  const selectedSlot = fixture.vault.keySlots[0];
  if (selectedSlot === undefined || selectedSlot.type === 'device-key') {
    throw new Error('Fixture requires a portable restore slot.');
  }
  const receipt = restoreKnownRecordsVerificationV1Schema.parse({
    version: 1,
    scope: 'known-v1-records',
    vaultId: fixture.vaultId,
    vaultRevision: fixture.vault.revision,
    restoreSessionId: summary.restoreSessionId,
    transcriptSha256: summary.transcriptSha256,
    canonicalEntriesSha256: summary.canonicalEntriesSha256,
    recordCount: summary.recordCount,
    selectedSlot: {
      id: selectedSlot.id,
      type: selectedSlot.type,
      keyVersion: selectedSlot.keyVersion,
    },
    verified: {
      vaults: 1,
      groups: 1,
      items: 3,
      attachments: 1,
      attachmentHeaders: 1,
      attachmentChunks: fixture.attachmentChunks.length,
      tombstonePredecessors: { groups: 0, items: 1, attachments: 0 },
      tombstones: 2,
      histories: 0,
      audits: 0,
    },
  });
  const stager = await store.open(summary.restoreSessionId, LIMITS);
  for (const entry of entries) await stager.write(entry);
  await stager.seal(summary);
  for await (const entry of stager.readSealed(summary)) {
    void entry;
    // Deliberately exhaust the fresh sealed snapshot before direct test publish.
  }
  await stager.publish(summary, receipt);
  await stager.finalize(summary, receipt);
  await database
    .collection<ReturnType<typeof toHistoryDocument>>(
      mongoStorageCollectionNames.histories,
    )
    .insertOne(toHistoryDocument(fixture.history));
  await database
    .collection<ReturnType<typeof toAuditDocument>>(mongoStorageCollectionNames.audits)
    .insertOne(toAuditDocument(fixture.audit));
}

function unsupportedRestoreFactory(
  fixture: SourceFixture,
): RestoreVerificationSessionFactory {
  return () => {
    const rootKey = cloneSecretKey(fixture.rootKey);
    const selectedSlot = fixture.vault.keySlots[0];
    if (selectedSlot === undefined || selectedSlot.type === 'device-key') {
      zeroize(rootKey);
      throw new Error('Fixture requires a portable restore slot.');
    }
    return Promise.resolve({
      vaultRootKey: rootKey,
      selectedSlot: {
        id: selectedSlot.id,
        type: selectedSlot.type,
        keyVersion: selectedSlot.keyVersion,
      },
      verify(): Promise<RestoreKnownRecordsVerificationV1> {
        const failure = new Error(
          'Encrypted backup decryptability verification failed.',
        ) as Error & {
          name: string;
          safe: true;
          kind: 'unsupported';
        };
        failure.name = 'RestoreKnownRecordsVerificationError';
        failure.safe = true;
        failure.kind = 'unsupported';
        return Promise.reject(failure);
      },
      close(): void {
        zeroize(rootKey);
      },
    });
  };
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

function restoreCanonical(
  fixture: CanonicalKnownV1RestoreFixture,
  store: BackupRestoreStore,
  slotType: CanonicalRestoreSlotType,
): Promise<RestoreEncryptedBackupResult> {
  return restoreEncryptedBackup(
    chunks(fixture.archive, 43),
    fixture.vaultId,
    store,
    fixture.verificationFactory(slotType),
    CANONICAL_RESTORE_LIMITS,
  );
}

function responseLossStore(
  realStore: BackupRestoreStore,
  phase: 'publish' | 'finalize',
): BackupRestoreStore {
  let injected = false;
  return {
    async open(restoreSessionId, limits): Promise<BackupRestoreStager> {
      const real = await realStore.open(restoreSessionId, limits);
      return {
        write: (entry) => real.write(entry),
        seal: (summary) => real.seal(summary),
        readSealed: (summary) => real.readSealed(summary),
        async publish(summary, receipt) {
          await real.publish(summary, receipt);
          if (phase === 'publish' && !injected) {
            injected = true;
            throw new Error('response-loss-canary');
          }
        },
        async finalize(summary, receipt) {
          await real.finalize(summary, receipt);
          if (phase === 'finalize' && !injected) {
            injected = true;
            throw new Error('response-loss-canary');
          }
        },
        status: () => real.status(),
        abort: () => real.abort(),
      };
    },
  };
}

function stagingSubstitutionStore(
  realStore: BackupRestoreStore,
  database: Db,
  window: 'before-readback' | 'before-publication' | 'no-tamper',
): BackupRestoreStore {
  let mutated = false;
  const mutate = async (restoreSessionId: string): Promise<void> => {
    if (mutated) return;
    mutated = true;
    const collection = database.collection(
      mongoStorageCollectionNames.backupRestoreEntries,
    );
    const stored = await collection.findOne({
      restoreSessionId,
      'entry.kind': 'group',
    });
    if (stored === null) throw new Error('Sealed group entry is missing.');
    const entry = encryptedBackupEntrySchema.parse(stored['entry']);
    if (entry.kind !== 'group') throw new Error('Sealed entry is not a group.');
    const mutatedEntry = encryptedBackupEntrySchema.parse({
      ...entry,
      record: {
        ...entry.record,
        recordRevision: entry.record.recordRevision + 1,
      },
    });
    await collection.replaceOne(
      { _id: stored._id },
      {
        ...stored,
        entry: mutatedEntry,
        entryHash: hashCanonical(mutatedEntry),
        bytes: Buffer.byteLength(canonicalJson(mutatedEntry), 'utf8') + 1,
      },
      { bypassDocumentValidation: true },
    );
  };
  return {
    async open(restoreSessionId, limits): Promise<BackupRestoreStager> {
      const real = await realStore.open(restoreSessionId, limits);
      return {
        write: (entry) => real.write(entry),
        async seal(summary) {
          await real.seal(summary);
          if (window === 'before-readback') await mutate(restoreSessionId);
        },
        readSealed(summary) {
          const source = real.readSealed(summary);
          if (window !== 'before-publication') return source;
          return (async function* () {
            for await (const entry of source) yield entry;
            await mutate(restoreSessionId);
          })();
        },
        publish: (summary, receipt) => real.publish(summary, receipt),
        finalize: (summary, receipt) => real.finalize(summary, receipt),
        status: () => real.status(),
        abort: () => real.abort(),
      };
    },
  };
}

function captureConsoleOutput(): Readonly<{
  output(): string;
  restore(): void;
}> {
  const values: unknown[][] = [];
  const spies = (['log', 'warn', 'error'] as const).map((method) =>
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      values.push(args);
    }),
  );
  return {
    output: () => values.map((args) => args.map(String).join(' ')).join('\n'),
    restore: () => {
      for (const spy of spies) spy.mockRestore();
    },
  };
}

function vaultRevisionAbove(
  revision: number,
): ReturnType<typeof vaultRevisionSchema.parse> {
  return vaultRevisionSchema.parse(revision + 1);
}

async function expectNoVisibleRestore(
  client: MongoClient,
  database: Db,
  fixture: CanonicalKnownV1RestoreFixture,
  summary: BackupVerification = fixture.summary,
): Promise<void> {
  for (const collectionName of [
    mongoStorageCollectionNames.vaults,
    mongoStorageCollectionNames.groups,
    mongoStorageCollectionNames.items,
    mongoStorageCollectionNames.attachments,
    mongoStorageCollectionNames.histories,
    mongoStorageCollectionNames.audits,
    mongoStorageCollectionNames.tombstones,
    mongoStorageCollectionNames.changes,
    mongoStorageCollectionNames.counters,
    mongoStorageCollectionNames.idempotency,
    mongoStorageCollectionNames.syncPushBatches,
    mongoStorageCollectionNames.templateMigrationPublications,
    mongoStorageCollectionNames.attachmentStaging,
    mongoStorageCollectionNames.attachmentStagingChunks,
  ]) {
    await expect(database.collection(collectionName).countDocuments()).resolves.toBe(0);
  }
  await expect(
    database
      .collection(mongoStorageCollectionNames.backupRestoreEntries)
      .countDocuments(),
  ).resolves.toBe(0);
  const sessions = await database
    .collection(mongoStorageCollectionNames.backupRestoreSessions)
    .find({})
    .toArray();
  expect(sessions).toHaveLength(1);
  const session = backupRestoreSessionDocumentSchema.parse(sessions[0]);
  if (session.state !== 'aborted') {
    throw new Error('Failed restore did not leave an aborted marker.');
  }
  expect(session).toEqual({
    _id: summary.restoreSessionId,
    state: 'aborted',
    protocolVersion: 2,
    restoreSessionId: summary.restoreSessionId,
    abortedAt: session.abortedAt,
  });
  expect('summary' in session).toBe(false);
  expect('receiptCommitment' in session).toBe(false);
  expect('publishedAt' in session).toBe(false);
  expect('committedAt' in session).toBe(false);
  await expect(
    new MongoBackupSource(client, database).open(
      fixture.vaultId,
      CANONICAL_RESTORE_LIMITS,
    ),
  ).rejects.toThrow();
}

async function expectCanonicalVisibleCounts(database: Db): Promise<void> {
  const expected = new Map<string, number>([
    [mongoStorageCollectionNames.vaults, 1],
    [mongoStorageCollectionNames.groups, 1],
    [mongoStorageCollectionNames.items, 3],
    [mongoStorageCollectionNames.attachments, 1],
    [mongoStorageCollectionNames.tombstones, 2],
    [mongoStorageCollectionNames.changes, 7],
    [mongoStorageCollectionNames.counters, 1],
    [mongoStorageCollectionNames.histories, 1],
    [mongoStorageCollectionNames.audits, 1],
    [mongoStorageCollectionNames.attachmentStaging, 1],
    [mongoStorageCollectionNames.attachmentStagingChunks, 2],
    [mongoStorageCollectionNames.backupRestoreSessions, 1],
    [mongoStorageCollectionNames.backupRestoreEntries, 0],
  ]);
  for (const [name, count] of expected) {
    await expect(database.collection(name).countDocuments()).resolves.toBe(count);
  }
  const deleted = await database
    .collection(mongoStorageCollectionNames.tombstones)
    .findOne({ entityId: canonicalDeletedItemId() });
  const changes = await database
    .collection(mongoStorageCollectionNames.changes)
    .find({ 'record.entityId': canonicalDeletedItemId() })
    .sort({ serverSequence: 1 })
    .toArray();
  expect(deleted).not.toBeNull();
  if (deleted === null) throw new Error('Deleted tombstone is missing.');
  expect(requireRecord(deleted)['record']).toEqual(
    expect.objectContaining({
      state: 'deleted',
      lastRecordRevision: 2,
    }),
  );
  expect(changes).toHaveLength(2);
  const predecessorChange = changes[0];
  if (predecessorChange === undefined) {
    throw new Error('Deleted predecessor change is missing.');
  }
  expect(changes.map((value) => requireRecord(value['record'])['operation'])).toEqual([
    'upsert',
    'tombstone',
  ]);
  expect(requireRecord(predecessorChange)['payload']).toEqual(
    expect.objectContaining({
      id: canonicalDeletedItemId(),
      recordRevision: 2,
    }),
  );
  const chunks = await database
    .collection(mongoStorageCollectionNames.attachmentStagingChunks)
    .find({})
    .sort({ chunkIndex: 1 })
    .toArray();
  expect(chunks.map((value) => Number(requireRecord(value)['chunkIndex']))).toEqual([
    0, 1,
  ]);
}

function canonicalDeletedItemId(): string {
  return 'restore.acceptance.item.deleted';
}

function prependVault(
  vault: VaultRecord,
  records: AsyncIterable<NonVaultEntry>,
): AsyncIterable<EncryptedBackupEntry> {
  return (async function* () {
    yield encryptedBackupEntrySchema.parse({ kind: 'vault', record: vault });
    for await (const entry of records) yield encryptedBackupEntrySchema.parse(entry);
  })();
}

async function collectDurableScanValues(database: Db): Promise<readonly Uint8Array[]> {
  const result: Uint8Array[] = [];
  for (const { name } of await database
    .listCollections({}, { nameOnly: true })
    .toArray()) {
    for (const document of await database.collection(name).find({}).toArray()) {
      result.push(BSON.serialize(document));
    }
  }
  return result;
}

function assertNoRawCanaries(
  values: readonly Uint8Array[],
  canaries: readonly string[],
): void {
  for (const canary of canaries) {
    const bytes = Buffer.from(canary, 'utf8');
    expect(values.some((value) => Buffer.from(value).includes(bytes))).toBe(false);
  }
}

async function readAllBson(database: Db): Promise<string> {
  return (await collectDurableScanValues(database))
    .map((value) => Buffer.from(value).toString('base64url'))
    .join('.');
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
