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
  verifyEncryptedBackup,
  type BackupVerification,
} from '@kavrix/import-export';
import {
  associatedDataSchema,
  canonicalJson,
  contentHashForRecord,
  createBackupStagedEntryCommitment,
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
  vaultRevisionSchema,
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
  type RestoreKnownRecordsVerificationV1,
  type Sha256Digest,
  type TombstoneRecord,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import { FindCursor, MongoClient, type Db } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { OpaqueVaultSnapshot } from '@kavrix/client';

import {
  MongoBackupRestoreStore,
  MongoVaultStorage,
  hashCanonical,
  mongoStorageCollectionNames,
  toVaultDocument,
} from '../src/index.js';
import {
  CANONICAL_RESTORE_EXPECTED_COUNTS,
  createCanonicalKnownV1RestoreFixture,
  type CanonicalKnownV1RestoreFixture,
} from './canonical-known-v1-restore-fixture.js';

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

function restoreProtocolFixture(fixture: BackupFixture): {
  readonly entries: readonly EncryptedBackupEntry[];
  readonly summary: BackupVerification;
  readonly receipt: RestoreKnownRecordsVerificationV1;
} {
  const entries = [
    { kind: 'vault' as const, record: fixture.vault },
    ...fixture.orderedRecords.filter(
      (entry) => entry.kind !== 'history' && entry.kind !== 'audit',
    ),
  ];
  const commitment = createBackupStagedEntryCommitment();
  for (const entry of entries) commitment.update(entry);
  const summary = {
    ...fixture.summary,
    recordCount: entries.length,
    canonicalEntriesSha256: commitment.finalize(),
  };
  const selectedSlot = fixture.vault.keySlots[0];
  if (selectedSlot === undefined || selectedSlot.type === 'device-key') {
    throw new Error('Fixture has no supported restore slot.');
  }
  const receipt: RestoreKnownRecordsVerificationV1 = {
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
      items: 2,
      attachments: 1,
      attachmentHeaders: 1,
      attachmentChunks: fixture.attachmentChunks.length,
      tombstonePredecessors: { groups: 0, items: 1, attachments: 0 },
      tombstones: 1,
      histories: 0,
      audits: 0,
    },
  };
  return { entries, summary, receipt };
}

function canonicalProtocolFixture(fixture: CanonicalKnownV1RestoreFixture): Readonly<{
  entries: readonly EncryptedBackupEntry[];
  summary: BackupVerification;
  receipt: RestoreKnownRecordsVerificationV1;
}> {
  const selectedSlot = fixture.vault.keySlots.find(
    (slot) => slot.id === fixture.slotIds['portable-key'],
  );
  if (selectedSlot?.type !== 'portable-key') {
    throw new Error('Canonical fixture portable slot is missing.');
  }
  return {
    entries: fixture.entries,
    summary: fixture.summary,
    receipt: {
      version: 1,
      scope: 'known-v1-records',
      vaultId: fixture.vaultId,
      vaultRevision: fixture.vaultRevision,
      restoreSessionId: fixture.summary.restoreSessionId,
      transcriptSha256: fixture.summary.transcriptSha256,
      canonicalEntriesSha256: fixture.summary.canonicalEntriesSha256,
      recordCount: fixture.summary.recordCount,
      selectedSlot: {
        id: selectedSlot.id,
        type: selectedSlot.type,
        keyVersion: selectedSlot.keyVersion,
      },
      verified: CANONICAL_RESTORE_EXPECTED_COUNTS,
    },
  };
}

describe('authenticated encrypted-backup restore against a MongoDB replica set', () => {
  const client = new MongoClient(mongodbUri, {
    appName: 'kavrix-backup-restore-integration',
  });
  let fixture: BackupFixture;
  let otherFixture: BackupFixture;
  let canonicalFixture: CanonicalKnownV1RestoreFixture;

  beforeAll(async () => {
    await client.connect();
    fixture = await createFixture('restore-a');
    otherFixture = await createFixture('restore-b');
    canonicalFixture = await createCanonicalKnownV1RestoreFixture();
  });

  afterAll(async () => {
    zeroize(fixture.rootKey);
    zeroize(otherFixture.rootKey);
    canonicalFixture.close();
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
      await expect(first.seal(null as never)).rejects.toThrow(
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
      await expect(
        store.open(fixture.summary.restoreSessionId, {
          ...LIMITS,
          maximumRecords: LIMITS.maximumRecords - 1,
        }),
      ).rejects.toThrow('different bounds');
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
      await expect(resumed.status()).resolves.toMatchObject({ state: 'aborted' });
      await expect(resumed.abort()).rejects.toThrow();
      await expect(
        database
          .collection(mongoStorageCollectionNames.backupRestoreEntries)
          .countDocuments(),
      ).resolves.toBe(0);
      await expect(visible.getVault(fixture.vaultId)).resolves.toBeNull();
    });
  });

  it('aborts a sealed restore but rejects every operation after abort', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database);
      await store.initialize();
      const protocol = restoreProtocolFixture(fixture);
      const staged = await store.open(protocol.summary.restoreSessionId, LIMITS);
      for (const entry of protocol.entries) await staged.write(entry);
      await staged.seal(protocol.summary);
      await staged.abort();
      await expect(staged.status()).resolves.toMatchObject({ state: 'aborted' });
      const entry = protocol.entries[0];
      if (entry === undefined) throw new Error('Fixture has no entries.');
      await expect(staged.write(entry)).rejects.toThrow();
      await expect(staged.seal(protocol.summary)).rejects.toThrow();
      await expect(collectAsync(staged.readSealed(protocol.summary))).rejects.toThrow();
      await expect(
        staged.publish(protocol.summary, protocol.receipt),
      ).rejects.toThrow();
      await expect(
        staged.finalize(protocol.summary, protocol.receipt),
      ).rejects.toThrow();
      await expect(staged.abort()).rejects.toThrow();
    });
  });

  it('publishes and finalizes an exact protocol-v2 zero-history/audit entry set', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database, {
        now: () => new Date(CREATED_AT),
      });
      await store.initialize();
      const protocol = restoreProtocolFixture(fixture);
      const staged = await store.open(protocol.summary.restoreSessionId, LIMITS);
      for (const entry of protocol.entries) await staged.write(entry);
      await staged.seal(protocol.summary);
      await expect(staged.seal(protocol.summary)).resolves.toBeUndefined();
      const firstEntry = protocol.entries[0];
      if (firstEntry === undefined) throw new Error('Fixture has no entries.');
      await expect(staged.write(firstEntry)).rejects.toThrow();
      await expect(
        staged.seal({
          ...protocol.summary,
          recordCount: protocol.summary.recordCount + 1,
        }),
      ).rejects.toThrow();
      const cursorClose = vi.spyOn(FindCursor.prototype, 'close');
      await expect(collectAsync(staged.readSealed(protocol.summary))).resolves.toEqual(
        protocol.entries,
      );
      expect(cursorClose).toHaveBeenCalled();
      cursorClose.mockClear();
      for await (const entry of staged.readSealed(protocol.summary)) {
        void entry;
        break;
      }
      expect(cursorClose).toHaveBeenCalled();
      cursorClose.mockRestore();
      for (const receipt of [
        {
          ...protocol.receipt,
          vaultRevision: vaultRevisionSchema.parse(protocol.receipt.vaultRevision + 1),
        },
        {
          ...protocol.receipt,
          selectedSlot: {
            ...protocol.receipt.selectedSlot,
            id: keySlotIdSchema.parse('slot.wrong'),
          },
        },
      ]) {
        await expect(staged.publish(protocol.summary, receipt)).rejects.toThrow();
      }
      await staged.publish(protocol.summary, protocol.receipt);
      await expect(staged.status()).resolves.toMatchObject({ state: 'published' });
      await expect(staged.abort()).rejects.toThrow();
      await expect(
        staged.publish(protocol.summary, protocol.receipt),
      ).rejects.toThrow();
      await expect(
        database
          .collection(mongoStorageCollectionNames.backupRestoreEntries)
          .countDocuments({ restoreSessionId: protocol.summary.restoreSessionId }),
      ).resolves.toBe(protocol.entries.length);
      await expect(collectAsync(staged.readSealed(protocol.summary))).resolves.toEqual(
        protocol.entries,
      );
      await expect(
        staged.finalize(protocol.summary, {
          ...protocol.receipt,
          vaultRevision: vaultRevisionSchema.parse(protocol.receipt.vaultRevision + 1),
        }),
      ).rejects.toThrow();
      await staged.finalize(protocol.summary, protocol.receipt);
      await expect(staged.status()).resolves.toMatchObject({ state: 'committed' });
      await expect(
        staged.finalize(protocol.summary, protocol.receipt),
      ).rejects.toThrow();

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
      ).resolves.toBeNull();
      await expect(collectAsync(reopened.listAudits(fixture.vaultId))).resolves.toEqual(
        [],
      );
      await expect(
        reopened.getHistory(fixture.vaultId, fixture.history.id),
      ).resolves.toBeNull();
      await expect(
        collectAsync(reopened.listItemHistory(fixture.vaultId, fixture.activeItem.id)),
      ).resolves.toEqual([]);

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
        protocolVersion: 2,
        summary: protocol.summary,
      });
    });
  });

  it('publishes and finalizes a canonical protocol-v2 known-v1 entry set', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database, {
        now: () => new Date(CREATED_AT),
      });
      await store.initialize();
      const protocol = canonicalProtocolFixture(canonicalFixture);
      const staged = await store.open(protocol.summary.restoreSessionId, LIMITS);
      for (const entry of protocol.entries) await staged.write(entry);
      await staged.seal(protocol.summary);
      await expect(collectAsync(staged.readSealed(protocol.summary))).resolves.toEqual(
        protocol.entries,
      );
      await staged.publish(protocol.summary, protocol.receipt);
      await staged.finalize(protocol.summary, protocol.receipt);

      await expect(staged.status()).resolves.toMatchObject({
        state: 'committed',
        protocolVersion: 2,
        summary: protocol.summary,
      });
      const visible = new MongoVaultStorage(client, database);
      await expect(visible.getVault(canonicalFixture.vaultId)).resolves.toEqual(
        canonicalFixture.vault,
      );
      await expect(
        visible.getGroup(canonicalFixture.vaultId, canonicalFixture.group.id),
      ).resolves.toEqual(canonicalFixture.group);
      await expect(
        visible.getItem(canonicalFixture.vaultId, canonicalFixture.activeItem.id),
      ).resolves.toEqual(canonicalFixture.activeItem);
      await expect(
        visible.getItem(canonicalFixture.vaultId, canonicalFixture.deletedItem.id),
      ).resolves.toBeNull();
      await expect(
        visible.getItem(canonicalFixture.vaultId, canonicalFixture.restoredItem.id),
      ).resolves.toEqual(canonicalFixture.restoredItem);
      await expect(
        visible.getAttachment(canonicalFixture.vaultId, canonicalFixture.attachment.id),
      ).resolves.toEqual(canonicalFixture.attachment);
      await expect(
        database
          .collection(mongoStorageCollectionNames.backupRestoreEntries)
          .countDocuments(),
      ).resolves.toBe(0);
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

      const protocol = restoreProtocolFixture(fixture);
      const staged = await store.open(protocol.summary.restoreSessionId, LIMITS);
      for (const entry of protocol.entries) await staged.write(entry);
      await staged.seal(protocol.summary);
      await expect(staged.publish(protocol.summary, protocol.receipt)).rejects.toThrow(
        'empty, isolated target',
      );
      await expect(
        database
          .collection<typeof original>(mongoStorageCollectionNames.vaults)
          .findOne({ _id: original._id }),
      ).resolves.toEqual(original);
      await expect(
        database.collection(mongoStorageCollectionNames.vaults).countDocuments(),
      ).resolves.toBe(1);
      await expect(staged.status()).resolves.toMatchObject({ state: 'sealed' });
      await staged.abort();
    });
  });

  it('re-reads the canonical entry set inside publish and rejects post-readback mutation', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database);
      await store.initialize();
      const protocol = canonicalProtocolFixture(canonicalFixture);
      const staged = await store.open(protocol.summary.restoreSessionId, LIMITS);
      for (const entry of protocol.entries) await staged.write(entry);
      await staged.seal(protocol.summary);
      await expect(collectAsync(staged.readSealed(protocol.summary))).resolves.toEqual(
        protocol.entries,
      );

      const collection = database.collection(
        mongoStorageCollectionNames.backupRestoreEntries,
      );
      const stored = await collection.findOne({
        restoreSessionId: protocol.summary.restoreSessionId,
        'entry.kind': 'group',
      });
      if (stored === null) throw new Error('Staged group entry is missing.');
      const entry = stored['entry'] as EncryptedBackupEntry;
      if (entry.kind !== 'group') throw new Error('Unexpected staged entry kind.');
      const mutatedEntry = {
        ...entry,
        record: {
          ...entry.record,
          recordRevision: recordRevisionSchema.parse(entry.record.recordRevision + 1),
        },
      };
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

      let readError: unknown;
      try {
        await collectAsync(staged.readSealed(protocol.summary));
      } catch (caught: unknown) {
        readError = caught;
      }
      expect(readError).toBeInstanceOf(Error);
      expect(String(readError)).toBe(
        'ValidationError: The sealed restore stream could not be read safely.',
      );
      expect(String(readError)).not.toMatch(/group|revision|canary/iu);
      await expect(staged.publish(protocol.summary, protocol.receipt)).rejects.toThrow(
        'entry set is inconsistent',
      );
      await expect(staged.status()).resolves.toMatchObject({ state: 'sealed' });
      await staged.abort();
    });
  });

  it.each(['ordinal', 'identity', 'entryHash', 'bytes', 'vaultId'] as const)(
    'rejects staged canonical metadata corruption during seal: %s',
    async (field) => {
      await withEmptyDatabase(client, async (database) => {
        const store = new MongoBackupRestoreStore(client, database);
        await store.initialize();
        const protocol = canonicalProtocolFixture(canonicalFixture);
        const staged = await store.open(protocol.summary.restoreSessionId, LIMITS);
        for (const entry of protocol.entries) await staged.write(entry);
        const collection = database.collection(
          mongoStorageCollectionNames.backupRestoreEntries,
        );
        const stored = await collection.findOne({
          restoreSessionId: protocol.summary.restoreSessionId,
          ordinal: 1,
        });
        if (stored === null) throw new Error('Staged entry is missing.');
        const corrupted = {
          ...stored,
          ...(field === 'ordinal' ? { ordinal: 99 } : {}),
          ...(field === 'identity' ? { identity: 'group.wrong' } : {}),
          ...(field === 'entryHash' ? { entryHash: '0'.repeat(64) } : {}),
          ...(field === 'bytes' ? { bytes: Number(stored['bytes']) + 1 } : {}),
          ...(field === 'vaultId' ? { vaultId: otherFixture.vaultId } : {}),
        };
        await collection.replaceOne({ _id: stored._id }, corrupted, {
          bypassDocumentValidation: true,
        });
        await expect(staged.seal(protocol.summary)).rejects.toThrow();
        await expect(staged.status()).resolves.toMatchObject({ state: 'staging' });
        await staged.abort();
      });
    },
  );

  it('rejects history/audit publication even when a schema-valid receipt lies about counts', async () => {
    await withEmptyDatabase(client, async (database) => {
      const store = new MongoBackupRestoreStore(client, database);
      await store.initialize();
      const entries = [
        { kind: 'vault' as const, record: fixture.vault },
        ...fixture.orderedRecords,
      ];
      const commitment = createBackupStagedEntryCommitment();
      for (const entry of entries) commitment.update(entry);
      const summary = {
        ...fixture.summary,
        recordCount: entries.length,
        canonicalEntriesSha256: commitment.finalize(),
      };
      const base = restoreProtocolFixture(fixture).receipt;
      const receipt = {
        ...base,
        recordCount: summary.recordCount,
        canonicalEntriesSha256: summary.canonicalEntriesSha256,
        verified: { ...base.verified, groups: base.verified.groups + 2 },
      } as RestoreKnownRecordsVerificationV1;
      const staged = await store.open(summary.restoreSessionId, LIMITS);
      for (const entry of entries) await staged.write(entry);
      await staged.seal(summary);
      let error: unknown;
      try {
        await staged.publish(summary, receipt);
      } catch (caught: unknown) {
        error = caught;
      }
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).not.toMatch(/history|audit|canary/iu);
      await staged.abort();
    });
  });

  it.each(['header', 'chunk'] as const)(
    'rejects canonical attachment wrapper hash corruption at write and publication: write %s',
    async (kind) => {
      await withEmptyDatabase(client, async (database) => {
        const store = new MongoBackupRestoreStore(client, database, {
          now: () => new Date(CREATED_AT),
        });
        await store.initialize();
        const protocol = canonicalProtocolFixture(canonicalFixture);
        const staged = await store.open(protocol.summary.restoreSessionId, LIMITS);
        const invalidHash = sha256DigestSchema.parse(
          Buffer.alloc(32).toString('base64url'),
        );

        for (const entry of protocol.entries) {
          const candidate =
            kind === 'header' && entry.kind === 'attachment-header'
              ? { ...entry, record: { ...entry.record, contentHash: invalidHash } }
              : kind === 'chunk' && entry.kind === 'attachment-chunk'
                ? {
                    ...entry,
                    record: { ...entry.record, ciphertextHash: invalidHash },
                  }
                : entry;
          if (candidate === entry) {
            await staged.write(candidate);
          } else {
            await expect(staged.write(candidate)).rejects.toThrow();
            break;
          }
        }

        for (const collectionName of [
          mongoStorageCollectionNames.vaults,
          mongoStorageCollectionNames.groups,
          mongoStorageCollectionNames.items,
          mongoStorageCollectionNames.attachments,
          mongoStorageCollectionNames.attachmentStaging,
          mongoStorageCollectionNames.attachmentStagingChunks,
          mongoStorageCollectionNames.changes,
          mongoStorageCollectionNames.counters,
        ]) {
          await expect(
            database.collection(collectionName).countDocuments(),
          ).resolves.toBe(0);
        }
        await expect(staged.status()).resolves.toMatchObject({ state: 'staging' });
        await staged.abort();
      });
    },
  );

  it.each(['header', 'chunk'] as const)(
    'rejects canonical attachment wrapper hash corruption at write and publication: publication %s',
    async (kind) => {
      await withEmptyDatabase(client, async (database) => {
        const store = new MongoBackupRestoreStore(client, database, {
          now: () => new Date(CREATED_AT),
        });
        await store.initialize();
        const protocol = canonicalProtocolFixture(canonicalFixture);
        const staged = await store.open(protocol.summary.restoreSessionId, LIMITS);
        for (const entry of protocol.entries) await staged.write(entry);
        await staged.seal(protocol.summary);

        const entriesCollection = database.collection(
          mongoStorageCollectionNames.backupRestoreEntries,
        );
        const stored = await entriesCollection.findOne({
          restoreSessionId: protocol.summary.restoreSessionId,
          'entry.kind': kind === 'header' ? 'attachment-header' : 'attachment-chunk',
        });
        if (stored === null) throw new Error('Staged attachment entry is missing.');
        const entry = stored['entry'] as EncryptedBackupEntry;
        const invalidHash = sha256DigestSchema.parse(
          Buffer.alloc(32).toString('base64url'),
        );
        const mutatedEntry =
          entry.kind === 'attachment-header'
            ? { ...entry, record: { ...entry.record, contentHash: invalidHash } }
            : entry.kind === 'attachment-chunk'
              ? { ...entry, record: { ...entry.record, ciphertextHash: invalidHash } }
              : undefined;
        if (mutatedEntry === undefined) {
          throw new Error('Unexpected staged attachment entry kind.');
        }
        await entriesCollection.replaceOne(
          { _id: stored._id },
          {
            ...stored,
            entry: mutatedEntry,
            entryHash: hashCanonical(mutatedEntry),
          },
        );

        await expect(
          staged.publish(protocol.summary, protocol.receipt),
        ).rejects.toThrow();
        for (const collectionName of [
          mongoStorageCollectionNames.vaults,
          mongoStorageCollectionNames.groups,
          mongoStorageCollectionNames.items,
          mongoStorageCollectionNames.attachments,
          mongoStorageCollectionNames.attachmentStaging,
          mongoStorageCollectionNames.attachmentStagingChunks,
          mongoStorageCollectionNames.changes,
          mongoStorageCollectionNames.counters,
        ]) {
          await expect(
            database.collection(collectionName).countDocuments(),
          ).resolves.toBe(0);
        }
        await expect(staged.status()).resolves.toMatchObject({ state: 'sealed' });
        await staged.abort();
        await expect(staged.status()).resolves.toMatchObject({ state: 'aborted' });
      });
    },
  );
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
