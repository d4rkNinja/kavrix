import {
  ValidationError,
  advanceAttachmentStaging,
  createAttachmentStagingProgress,
  validateAttachmentStagingFinalization,
} from '@kavrix/core';
import {
  DEFAULT_MAX_BACKUP_RECORDS,
  MAX_SUPPORTED_BACKUP_BYTES,
  attachmentRecordHashMatchesCanonicalContent,
  backupVerificationSchema,
  canonicalJson,
  changeRecordSchema,
  contentHashForRecord,
  createBackupStagedEntryCommitment,
  recordRevisionSchema,
  restoreKnownRecordsVerificationV1Schema,
  sha256DigestSchema,
  timestampSchema,
  type AttachmentStreamProgress,
  type BackupRestoreStager,
  type BackupRestoreStore,
  type BackupRestoreStatus,
  type BackupVerification,
  type EncryptedAttachmentRecord,
  type EncryptedBackupEntry,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type OpaqueSyncRecord,
  type PersistedAttachmentChunkRecord,
  type PersistedAttachmentHeaderRecord,
  type ResolvedBackupLimits,
  type RestoreKnownRecordsVerificationV1,
  type RecordRevision,
  type Sha256Digest,
  type TombstoneRecord,
  type VaultRecord,
} from '@kavrix/schemas';
import {
  BSON,
  MongoServerError,
  type ClientSession,
  type Collection,
  type Db,
  type Document,
  type MongoClient,
  type OptionalUnlessRequiredId,
} from 'mongodb';

import { mongoStorageCollectionNames } from './collections.js';
import {
  attachmentStagingDocumentSchema,
  finalizeHash,
  hashCanonical,
  makeStagedChunkDocument,
  stagingDocumentId,
  storageCounterDocumentSchema as storedCounterDocumentSchema,
  toAttachmentDocument,
  toAuditDocument,
  toChangeDocument,
  toGroupDocument,
  toHistoryDocument,
  toItemDocument,
  toTombstoneDocument,
  toVaultDocument,
  type AttachmentStagingDocument,
  type StorageCounterDocument,
  type StagedAttachmentChunkDocument,
  type StoredAttachmentDocument,
  type StoredAuditDocument,
  type StoredChangeDocument,
  type StoredGroupDocument,
  type StoredHistoryDocument,
  type StoredItemDocument,
  type StoredTombstoneDocument,
  type StoredVaultDocument,
} from './documents.js';
import { initializeMongoStorage } from './mongo-vault-storage.js';
import {
  MAX_MONGO_RESTORE_ENTRY_BYTES,
  backupEntryVaultId,
  backupRestoreSessionDocumentSchema,
  backupRestoreStatusFromDocument,
  makeRestoreEntryDocument,
  parseRestoreEntry,
  parseRestoreEntryDocument,
  parseRestoreSessionDocument,
  type BackupRestoreEntryDocument,
  type BackupRestoreSessionDocument,
} from './restore-documents.js';

export const MAX_MONGO_RESTORE_BYTES = 128 * 1024 * 1024;
export const MAX_MONGO_RESTORE_RECORDS = 10_000;

const transactionOptions = {
  readConcern: { level: 'snapshot' as const },
  writeConcern: { w: 'majority' as const },
};

export type MongoBackupRestoreStoreOptions = Readonly<{
  now?: () => Date;
}>;

/** Durable, hidden Mongo staging for authenticated encrypted-backup restores. */
export class MongoBackupRestoreStore implements BackupRestoreStore {
  readonly #client: MongoClient;
  readonly #database: Db;
  readonly #now: () => Date;

  constructor(
    client: MongoClient,
    database: Db,
    options: MongoBackupRestoreStoreOptions = {},
  ) {
    this.#client = client;
    this.#database = database;
    this.#now = options.now ?? (() => new Date());
  }

  async initialize(): Promise<void> {
    await initializeMongoStorage(this.#database);
  }

  async open(
    restoreSessionIdInput: Sha256Digest,
    limitsInput: ResolvedBackupLimits,
  ): Promise<BackupRestoreStager> {
    const restoreSessionId = sha256DigestSchema.parse(restoreSessionIdInput);
    const limits = parseMongoLimits(limitsInput);
    const now = this.#timestamp();
    const candidate = backupRestoreSessionDocumentSchema.parse({
      _id: restoreSessionId,
      protocolVersion: 2,
      restoreSessionId,
      maximumBytes: limits.maximumBytes,
      maximumRecords: limits.maximumRecords,
      state: 'staging',
      stagedBytes: 0,
      stagedRecords: 0,
      createdAt: now,
      updatedAt: now,
    });

    try {
      await this.#sessions().insertOne(candidate);
    } catch (error) {
      if (!isDuplicateKey(error)) throw error;
      const existingValue = await this.#sessions().findOne({ _id: restoreSessionId });
      if (existingValue === null) {
        throw new ValidationError('The restore session could not be reopened safely.');
      }
      const existing = parseRestoreSessionDocument(existingValue);
      if (
        'maximumBytes' in existing &&
        (existing.maximumBytes !== limits.maximumBytes ||
          existing.maximumRecords !== limits.maximumRecords)
      ) {
        throw new ValidationError(
          'A restore session cannot be reopened with different bounds.',
        );
      }
    }

    return new MongoBackupRestoreStager(this, restoreSessionId);
  }

  async write(
    restoreSessionId: Sha256Digest,
    position: number,
    entryInput: EncryptedBackupEntry,
  ): Promise<void> {
    const entry = parseRestoreEntry(entryInput);
    assertCanonicalAttachmentHash(entry);
    const entryBytes = Buffer.byteLength(canonicalJson(entry), 'utf8') + 1;
    if (entryBytes > MAX_MONGO_RESTORE_ENTRY_BYTES) {
      throw new ValidationError('A restore entry exceeds the Mongo staging limit.');
    }

    await this.#withTransaction(async (session) => {
      const sessionValue = await this.#sessions().findOne(
        { _id: restoreSessionId },
        { session },
      );
      if (sessionValue === null) {
        throw new ValidationError('The restore session does not exist.');
      }
      const restore = parseRestoreSessionDocument(sessionValue);
      if (restore.state !== 'staging') {
        throw new ValidationError('Restore entries can only be written while staging.');
      }

      const candidate = makeRestoreEntryDocument(
        restoreSessionId,
        position,
        entryBytes,
        entry,
      );
      if (BSON.calculateObjectSize(candidate) > MAX_MONGO_RESTORE_ENTRY_BYTES) {
        throw new ValidationError('A restore entry exceeds the Mongo document limit.');
      }
      if (
        position > 0 &&
        (restore.vaultId === undefined || candidate.vaultId !== restore.vaultId)
      ) {
        throw new ValidationError('A restore entry belongs to a different vault.');
      }
      if (position > restore.stagedRecords) {
        throw new ValidationError(
          'Restore entries must be replayed in canonical order.',
        );
      }

      const existingValue = await this.#entries().findOne(
        { _id: candidate._id },
        { session },
      );
      if (existingValue !== null) {
        const existing = parseRestoreEntryDocument(existingValue);
        if (
          position >= restore.stagedRecords ||
          existing.ordinal !== position ||
          existing.identity !== candidate.identity ||
          existing.entryHash !== candidate.entryHash ||
          existing.bytes !== candidate.bytes ||
          canonicalJson(existing.entry) !== canonicalJson(candidate.entry)
        ) {
          throw new ValidationError(
            'A repeated restore entry must exactly match its staged value.',
          );
        }
        return;
      }
      if (position !== restore.stagedRecords) {
        throw new ValidationError('Restore replay diverged from its staged prefix.');
      }
      if (position === 0 && candidate.entry.kind !== 'vault') {
        throw new ValidationError('The first restore entry must be the vault record.');
      }
      const stagedBytes = restore.stagedBytes + candidate.bytes;
      const stagedRecords = restore.stagedRecords + 1;
      if (
        stagedBytes > restore.maximumBytes ||
        stagedRecords > restore.maximumRecords
      ) {
        throw new ValidationError('The restore staging bounds were exceeded.');
      }

      await this.#entries().insertOne(candidate, { session });
      const update = await this.#sessions().updateOne(
        {
          _id: restoreSessionId,
          state: 'staging',
          stagedBytes: restore.stagedBytes,
          stagedRecords: restore.stagedRecords,
        },
        {
          $set: {
            stagedBytes,
            stagedRecords,
            updatedAt: this.#timestamp(),
            ...(position === 0 ? { vaultId: candidate.vaultId } : {}),
          },
        },
        { session },
      );
      if (update.modifiedCount !== 1) {
        throw new ValidationError('The restore session changed concurrently.');
      }
    });
  }

  async seal(
    restoreSessionId: Sha256Digest,
    summaryInput: BackupVerification,
  ): Promise<void> {
    const summary = parseSummary(summaryInput);
    if (summary.restoreSessionId !== restoreSessionId) {
      throw new ValidationError('The restore summary identifies a different session.');
    }

    await this.#withTransaction(async (session) => {
      const sessionValue = await this.#sessions().findOne(
        { _id: restoreSessionId },
        { session },
      );
      if (sessionValue === null) {
        throw new ValidationError('The restore session does not exist.');
      }
      const restore = parseRestoreSessionDocument(sessionValue);
      if (restore.state === 'sealed') {
        assertExactSummary(restore.summary, summary);
        return;
      }
      if (restore.state !== 'staging') {
        throw new ValidationError('Only a staging restore session can be sealed.');
      }
      if (
        restore.vaultId === undefined ||
        restore.vaultId !== summary.header.vaultId ||
        restore.stagedRecords !== summary.recordCount
      ) {
        throw new ValidationError('The restore summary does not match staged records.');
      }

      const entryValues = await this.#entries()
        .find({ restoreSessionId }, { session })
        .sort({ ordinal: 1 })
        .toArray();
      if (summary.recordCount > restore.maximumRecords) {
        throw new ValidationError('The restore summary exceeds its record limit.');
      }
      validateEntrySet(entryValues, summary, restore.stagedBytes);
      const now = this.#timestamp();
      const sealed = backupRestoreSessionDocumentSchema.parse({
        ...restore,
        state: 'sealed',
        summary,
        sealedAt: now,
        updatedAt: now,
      });
      const update = await this.#sessions().replaceOne(
        { _id: restoreSessionId, state: 'staging' },
        sealed,
        { session },
      );
      if (update.modifiedCount !== 1) {
        throw new ValidationError('The restore session changed concurrently.');
      }
    });
  }

  async *readSealed(
    restoreSessionId: Sha256Digest,
    summaryInput: BackupVerification,
  ): AsyncIterable<EncryptedBackupEntry> {
    const summary = parseSummary(summaryInput);
    if (summary.restoreSessionId !== restoreSessionId) {
      throw new ValidationError('The restore summary identifies a different session.');
    }
    const value = await this.#sessions().findOne({ _id: restoreSessionId });
    if (value === null)
      throw new ValidationError('The restore session does not exist.');
    const restore = parseRestoreSessionDocument(value);
    if (restore.state !== 'sealed' && restore.state !== 'published') {
      throw new ValidationError('Only a sealed restore session can be read.');
    }
    assertExactSummary(restore.summary, summary);
    const cursor = this.#entries().find({ restoreSessionId }).sort({ ordinal: 1 });
    const commitment = createBackupStagedEntryCommitment({
      maximumEntryBytes: MAX_MONGO_RESTORE_ENTRY_BYTES,
    });
    let ordinal = 0;
    let bytes = 0;
    let failed = false;
    try {
      for await (const raw of cursor) {
        const document = validateEntryDocument(raw, summary, ordinal);
        commitment.update(document.entry);
        bytes += document.bytes;
        ordinal += 1;
        yield document.entry;
      }
      if (
        ordinal !== summary.recordCount ||
        ordinal !== restore.stagedRecords ||
        bytes !== restore.stagedBytes ||
        commitment.finalize() !== summary.canonicalEntriesSha256
      ) {
        throw new ValidationError('The sealed restore entry set is inconsistent.');
      }
    } catch {
      failed = true;
      throw sanitizeSealedReadError();
    } finally {
      await closeRestoreCursor(cursor, failed);
    }
  }

  async publish(
    restoreSessionId: Sha256Digest,
    summaryInput: BackupVerification,
    receiptInput: RestoreKnownRecordsVerificationV1,
  ): Promise<void> {
    const summary = parseSummary(summaryInput);
    const receipt = parseReceipt(receiptInput);
    assertReceiptSummary(receipt, summary);
    await this.#withTransaction(async (session) => {
      const value = await this.#sessions().findOne(
        { _id: restoreSessionId },
        { session },
      );
      if (value === null)
        throw new ValidationError('The restore session does not exist.');
      const restore = parseRestoreSessionDocument(value);
      if (restore.state !== 'sealed') {
        throw new ValidationError('Only a sealed restore session can be published.');
      }
      assertExactSummary(restore.summary, summary);
      assertReceiptSummary(receipt, restore.summary);
      const rawEntries = await this.#entries()
        .find({ restoreSessionId }, { session })
        .sort({ ordinal: 1 })
        .toArray();
      const entries = validateEntrySet(rawEntries, summary, restore.stagedBytes);
      const publication = buildPublication(entries, summary);
      assertReceiptPublication(receipt, entries, publication, summary);
      await this.#assertEmptyTarget(restoreSessionId, session);
      await this.#publish(publication, session);
      const now = this.#timestamp();
      const published = backupRestoreSessionDocumentSchema.parse({
        ...restore,
        state: 'published',
        publishedAt: now,
        updatedAt: now,
      });
      const update = await this.#sessions().replaceOne(
        { _id: restoreSessionId, state: 'sealed' },
        published,
        { session },
      );
      if (update.modifiedCount !== 1) {
        throw new ValidationError('The restore session changed concurrently.');
      }
    });
  }

  async finalize(
    restoreSessionId: Sha256Digest,
    summaryInput: BackupVerification,
    receiptInput: RestoreKnownRecordsVerificationV1,
  ): Promise<void> {
    const summary = parseSummary(summaryInput);
    const receipt = parseReceipt(receiptInput);
    assertReceiptSummary(receipt, summary);
    await this.#withTransaction(async (session) => {
      const value = await this.#sessions().findOne(
        { _id: restoreSessionId },
        { session },
      );
      if (value === null)
        throw new ValidationError('The restore session does not exist.');
      const restore = parseRestoreSessionDocument(value);
      if (restore.state !== 'published') {
        throw new ValidationError('Only a published restore session can be finalized.');
      }
      assertExactSummary(restore.summary, summary);
      assertReceiptSummary(receipt, restore.summary);
      const rawEntries = await this.#entries()
        .find({ restoreSessionId }, { session })
        .sort({ ordinal: 1 })
        .toArray();
      const entries = validateEntrySet(rawEntries, summary, restore.stagedBytes);
      const publication = buildPublication(entries, summary);
      assertReceiptPublication(receipt, entries, publication, summary);
      const deletion = await this.#entries().deleteMany(
        { restoreSessionId },
        { session },
      );
      if (deletion.deletedCount !== restore.stagedRecords) {
        throw new ValidationError('The restore session changed concurrently.');
      }
      const committed = backupRestoreSessionDocumentSchema.parse({
        _id: restore._id,
        state: 'committed',
        protocolVersion: 2,
        restoreSessionId,
        summary: restore.summary,
        committedAt: this.#timestamp(),
      });
      const update = await this.#sessions().replaceOne(
        { _id: restoreSessionId, state: 'published' },
        committed,
        { session },
      );
      if (update.modifiedCount !== 1) {
        throw new ValidationError('The restore session changed concurrently.');
      }
    });
  }

  async status(restoreSessionId: Sha256Digest): Promise<BackupRestoreStatus> {
    const value = await this.#sessions().findOne({ _id: restoreSessionId });
    if (value === null)
      throw new ValidationError('The restore session does not exist.');
    return backupRestoreStatusFromDocument(value);
  }

  async abort(restoreSessionId: Sha256Digest): Promise<void> {
    await this.#withTransaction(async (session) => {
      const value = await this.#sessions().findOne(
        { _id: restoreSessionId },
        { session },
      );
      if (value === null) {
        throw new ValidationError('The restore session does not exist.');
      }
      const restore = parseRestoreSessionDocument(value);
      if (restore.state === 'published' || restore.state === 'committed') {
        throw new ValidationError('A published restore session cannot be aborted.');
      }
      if (restore.state === 'aborted') {
        throw new ValidationError('Only a staging or sealed restore can be aborted.');
      }
      await this.#entries().deleteMany({ restoreSessionId }, { session });
      const now = this.#timestamp();
      const aborted = backupRestoreSessionDocumentSchema.parse({
        _id: restore._id,
        protocolVersion: 2,
        restoreSessionId: restore.restoreSessionId,
        state: 'aborted',
        abortedAt: now,
      });
      const update = await this.#sessions().replaceOne(
        { _id: restoreSessionId, state: restore.state },
        aborted,
        { session },
      );
      if (update.modifiedCount !== 1) {
        throw new ValidationError('The restore session changed concurrently.');
      }
    });
  }

  async #assertEmptyTarget(
    restoreSessionId: Sha256Digest,
    session: ClientSession,
  ): Promise<void> {
    const collections = await this.#database
      .listCollections({}, { nameOnly: true })
      .toArray();
    for (const { name } of collections) {
      if (name.startsWith('system.')) continue;
      const count =
        name === mongoStorageCollectionNames.backupRestoreSessions
          ? await this.#sessions().countDocuments(
              { _id: { $ne: restoreSessionId } },
              { limit: 1, session },
            )
          : name === mongoStorageCollectionNames.backupRestoreEntries
            ? await this.#entries().countDocuments(
                { restoreSessionId: { $ne: restoreSessionId } },
                { limit: 1, session },
              )
            : await this.#database
                .collection(name)
                .countDocuments({}, { limit: 1, session });
      if (count !== 0) {
        throw new ValidationError(
          'Backup restore requires an empty, isolated target database.',
        );
      }
    }
  }

  async #publish(publication: Publication, session: ClientSession): Promise<void> {
    await this.#database
      .collection<StoredVaultDocument>(mongoStorageCollectionNames.vaults)
      .insertOne(publication.vault, { session });
    await insertManyIfPresent(
      this.#database.collection<StoredGroupDocument>(
        mongoStorageCollectionNames.groups,
      ),
      publication.groups,
      session,
    );
    await insertManyIfPresent(
      this.#database.collection<StoredItemDocument>(mongoStorageCollectionNames.items),
      publication.items,
      session,
    );
    await insertManyIfPresent(
      this.#database.collection<AttachmentStagingDocument>(
        mongoStorageCollectionNames.attachmentStaging,
      ),
      publication.attachmentStaging,
      session,
    );
    await insertManyIfPresent(
      this.#database.collection<StagedAttachmentChunkDocument>(
        mongoStorageCollectionNames.attachmentStagingChunks,
      ),
      publication.attachmentChunks,
      session,
    );
    await insertManyIfPresent(
      this.#database.collection<StoredAttachmentDocument>(
        mongoStorageCollectionNames.attachments,
      ),
      publication.attachments,
      session,
    );
    await insertManyIfPresent(
      this.#database.collection<StoredAuditDocument>(
        mongoStorageCollectionNames.audits,
      ),
      publication.audits,
      session,
    );
    await insertManyIfPresent(
      this.#database.collection<StoredHistoryDocument>(
        mongoStorageCollectionNames.histories,
      ),
      publication.histories,
      session,
    );
    await insertManyIfPresent(
      this.#database.collection<StoredTombstoneDocument>(
        mongoStorageCollectionNames.tombstones,
      ),
      publication.tombstones,
      session,
    );
    await insertManyIfPresent(
      this.#database.collection<StoredChangeDocument>(
        mongoStorageCollectionNames.changes,
      ),
      publication.changes,
      session,
    );
    await this.#database
      .collection<StorageCounterDocument>(mongoStorageCollectionNames.counters)
      .insertOne(publication.counter, { session });
  }

  async #withTransaction<T>(work: (session: ClientSession) => Promise<T>): Promise<T> {
    const session = this.#client.startSession();
    try {
      return await session.withTransaction(() => work(session), transactionOptions);
    } finally {
      await session.endSession();
    }
  }

  #timestamp(): string {
    return timestampSchema.parse(this.#now().toISOString());
  }

  #sessions(): Collection<BackupRestoreSessionDocument> {
    return this.#database.collection(mongoStorageCollectionNames.backupRestoreSessions);
  }

  #entries(): Collection<BackupRestoreEntryDocument> {
    return this.#database.collection(mongoStorageCollectionNames.backupRestoreEntries);
  }
}

function assertCanonicalAttachmentHash(entry: EncryptedBackupEntry): void {
  if (
    (entry.kind === 'attachment-header' || entry.kind === 'attachment-chunk') &&
    !attachmentRecordHashMatchesCanonicalContent(entry.record)
  ) {
    throw new ValidationError(
      'A restore entry contains a noncanonical attachment hash.',
    );
  }
}

class MongoBackupRestoreStager implements BackupRestoreStager {
  readonly #store: MongoBackupRestoreStore;
  readonly #restoreSessionId: Sha256Digest;
  #position = 0;

  constructor(store: MongoBackupRestoreStore, restoreSessionId: Sha256Digest) {
    this.#store = store;
    this.#restoreSessionId = restoreSessionId;
  }

  async write(entry: EncryptedBackupEntry): Promise<void> {
    await this.#store.write(this.#restoreSessionId, this.#position, entry);
    this.#position += 1;
  }

  async seal(summary: BackupVerification): Promise<void> {
    await this.#store.seal(this.#restoreSessionId, summary);
  }

  readSealed(summary: BackupVerification): AsyncIterable<EncryptedBackupEntry> {
    return this.#store.readSealed(this.#restoreSessionId, summary);
  }

  async publish(
    summary: BackupVerification,
    receipt: RestoreKnownRecordsVerificationV1,
  ): Promise<void> {
    await this.#store.publish(this.#restoreSessionId, summary, receipt);
  }

  async finalize(
    summary: BackupVerification,
    receipt: RestoreKnownRecordsVerificationV1,
  ): Promise<void> {
    await this.#store.finalize(this.#restoreSessionId, summary, receipt);
  }

  async status(): Promise<BackupRestoreStatus> {
    return this.#store.status(this.#restoreSessionId);
  }

  async abort(): Promise<void> {
    await this.#store.abort(this.#restoreSessionId);
  }
}

type Publication = Readonly<{
  vault: ReturnType<typeof toVaultDocument>;
  groups: readonly ReturnType<typeof toGroupDocument>[];
  items: readonly ReturnType<typeof toItemDocument>[];
  attachments: readonly ReturnType<typeof toAttachmentDocument>[];
  audits: readonly ReturnType<typeof toAuditDocument>[];
  histories: readonly ReturnType<typeof toHistoryDocument>[];
  tombstones: readonly ReturnType<typeof toTombstoneDocument>[];
  attachmentStaging: readonly AttachmentStagingDocument[];
  attachmentChunks: readonly StagedAttachmentChunkDocument[];
  changes: readonly ReturnType<typeof toChangeDocument>[];
  counter: ReturnType<typeof storedCounterDocumentSchema.parse>;
}>;

interface AttachmentPlan {
  readonly record: EncryptedAttachmentRecord;
  header?: PersistedAttachmentHeaderRecord;
  readonly chunks: PersistedAttachmentChunkRecord[];
  progress: AttachmentStreamProgress;
}

type TombstonePredecessor = Extract<
  EncryptedBackupEntry,
  { kind: 'tombstone-predecessor' }
>['record'];

function buildPublication(
  entries: readonly BackupRestoreEntryDocument[],
  summary: BackupVerification,
): Publication {
  if (entries.length !== summary.recordCount) {
    throw new ValidationError('The staged restore record count is inconsistent.');
  }
  let vault: VaultRecord | undefined;
  const groups = new Map<string, EncryptedGroupRecord>();
  const items = new Map<string, EncryptedItemRecord>();
  const attachments = new Map<string, AttachmentPlan>();
  const audits: ReturnType<typeof toAuditDocument>[] = [];
  const histories: ReturnType<typeof toHistoryDocument>[] = [];
  const tombstonePredecessors = new Map<string, TombstonePredecessor>();
  const tombstones = new Map<string, TombstoneRecord>();

  for (const [expectedOrdinal, document] of entries.entries()) {
    if (document.ordinal !== expectedOrdinal) {
      throw new ValidationError('Staged restore ordinals are not contiguous.');
    }
    const entry = document.entry;
    if (backupEntryVaultId(entry) !== summary.header.vaultId) {
      throw new ValidationError('A staged restore record belongs to another vault.');
    }
    assertCanonicalAttachmentHash(entry);
    switch (entry.kind) {
      case 'vault':
        if (expectedOrdinal !== 0 || vault !== undefined) {
          throw new ValidationError('A restore requires exactly one leading vault.');
        }
        vault = entry.record;
        break;
      case 'group':
        requireVault(vault);
        if (groups.has(entry.record.id)) duplicateEntry();
        groups.set(entry.record.id, entry.record);
        break;
      case 'item':
        requireVault(vault);
        if (!groups.has(entry.record.groupId)) missingParent();
        if (items.has(entry.record.id)) duplicateEntry();
        items.set(entry.record.id, entry.record);
        break;
      case 'attachment':
        requireVault(vault);
        if (items.get(entry.record.itemId)?.groupId !== entry.record.groupId) {
          missingParent();
        }
        if (attachments.has(entry.record.id)) duplicateEntry();
        attachments.set(entry.record.id, {
          record: entry.record,
          chunks: [],
          progress: createAttachmentStagingProgress(),
        });
        break;
      case 'attachment-header': {
        const id = entry.record.record.attachmentId;
        const attachment = attachments.get(id);
        if (attachment === undefined || attachment.header !== undefined) {
          missingParent();
        }
        assertAttachmentHeader(attachment.record, entry.record);
        attachment.header = entry.record;
        break;
      }
      case 'attachment-chunk': {
        const id = entry.record.record.attachmentId;
        const attachment = attachments.get(id);
        if (attachment?.header === undefined) missingParent();
        const advanced = advanceAttachmentStaging(
          {
            version: 1,
            idempotencyKey: attachmentIdempotencyKey(summary.restoreSessionId, id),
            expectedAttachmentRevision: previousRevision(
              attachment.record.recordRevision,
            ),
            header: attachment.header,
          },
          attachment.progress,
          entry.record,
        );
        if (advanced.disposition !== 'staged') duplicateEntry();
        attachment.progress = advanced.progress;
        attachment.chunks.push(entry.record);
        break;
      }
      case 'audit':
        audits.push(toAuditDocument(entry.record));
        break;
      case 'history':
        if (items.get(entry.record.itemId)?.groupId !== entry.record.groupId) {
          missingParent();
        }
        histories.push(toHistoryDocument(entry.record));
        break;
      case 'tombstone-predecessor': {
        const key = `${entry.entityType}:${entry.record.id}`;
        if (
          currentRecord(
            entry.entityType,
            entry.record.id,
            groups,
            items,
            attachments,
          ) === undefined
        ) {
          missingParent();
        }
        if (tombstonePredecessors.has(key)) duplicateEntry();
        tombstonePredecessors.set(key, entry.record);
        break;
      }
      case 'tombstone': {
        if (entry.record.entityType === 'vault') {
          throw new ValidationError('Vault tombstones cannot be restored.');
        }
        const key = `${entry.record.entityType}:${entry.record.entityId}`;
        if (tombstones.has(key)) duplicateEntry();
        const current = currentRecord(
          entry.record.entityType,
          entry.record.entityId,
          groups,
          items,
          attachments,
        );
        if (current === undefined) missingParent();
        assertTombstoneMatches(current, entry.record, tombstonePredecessors.get(key));
        tombstones.set(key, entry.record);
        break;
      }
    }
  }
  requireVault(vault);
  if (vault.id !== summary.header.vaultId) {
    throw new ValidationError('The restore vault does not match its header.');
  }

  const publishedAttachmentMetadata: ReturnType<typeof toAttachmentDocument>[] = [];
  const publishedAttachmentStaging: AttachmentStagingDocument[] = [];
  const publishedChunks: StagedAttachmentChunkDocument[] = [];
  for (const [attachmentId, attachment] of attachments) {
    if (attachment.header === undefined) {
      throw new ValidationError('An attachment restore is missing its header.');
    }
    const idempotencyKey = attachmentIdempotencyKey(
      summary.restoreSessionId,
      attachmentId,
    );
    const start = {
      version: 1 as const,
      idempotencyKey,
      expectedAttachmentRevision: previousRevision(attachment.record.recordRevision),
      header: attachment.header,
    };
    const finalize = { version: 1 as const, record: attachment.record };
    validateAttachmentStagingFinalization(start, attachment.progress, finalize);
    const stagingId = stagingDocumentId(vault.id, idempotencyKey);
    const staged = attachmentStagingDocumentSchema.parse({
      _id: stagingId,
      vaultId: vault.id,
      attachmentId,
      idempotencyKey,
      inputHash: hashCanonical(start),
      state: 'finalized',
      input: start,
      progress: attachment.progress,
      finalizeHash: finalizeHash(finalize),
      createdAt: attachment.record.createdAt,
      updatedAt: attachment.record.updatedAt,
      finalizedAt: attachment.record.updatedAt,
    });
    publishedAttachmentStaging.push(staged);
    publishedAttachmentMetadata.push(
      toAttachmentDocument(attachment.record, stagingId),
    );
    publishedChunks.push(
      ...attachment.chunks.map((chunk) => makeStagedChunkDocument(stagingId, chunk)),
    );
  }

  assertTombstoneCoverage(groups.values(), 'group', tombstones);
  assertTombstoneCoverage(items.values(), 'item', tombstones);
  assertTombstoneCoverage(
    [...attachments.values()].map(({ record }) => record),
    'attachment',
    tombstones,
  );
  for (const key of tombstonePredecessors.keys()) {
    if (tombstones.get(key)?.state !== 'deleted') {
      throw new ValidationError(
        'A tombstone predecessor requires its following deleted tombstone.',
      );
    }
  }

  const changes: ReturnType<typeof toChangeDocument>[] = [];
  const appendChange = (
    entityType: 'vault' | 'group' | 'item' | 'attachment',
    record:
      | VaultRecord
      | EncryptedGroupRecord
      | EncryptedItemRecord
      | EncryptedAttachmentRecord,
    operation: 'upsert' | 'tombstone',
    payload: OpaqueSyncRecord,
    ciphertextHash: string,
    createdAt: string,
  ): void => {
    changes.push(
      toChangeDocument(
        changeRecordSchema.parse({
          id: `change.${String(changes.length + 1)}`,
          vaultId: vault.id,
          serverSequence: changes.length + 1,
          entityType,
          entityId: record.id,
          recordRevision:
            operation === 'tombstone' && 'state' in payload
              ? payload.tombstoneRevision
              : entityType === 'vault'
                ? (record as VaultRecord).revision
                : (record as Exclude<typeof record, VaultRecord>).recordRevision,
          operation,
          ciphertextHash,
          createdAt,
        }),
        payload,
      ),
    );
  };
  const appendCurrentOrPredecessor = (
    entityType: 'group' | 'item' | 'attachment',
    record: EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord,
  ): void => {
    const tombstone = tombstones.get(`${entityType}:${record.id}`);
    const published =
      tombstone?.state === 'deleted'
        ? tombstonePredecessors.get(`${entityType}:${record.id}`)
        : record;
    if (published === undefined) {
      throw new ValidationError('A deleted record is missing its predecessor.');
    }
    appendChange(
      entityType,
      published,
      'upsert',
      published,
      contentHashForRecord(published),
      published.updatedAt,
    );
  };
  appendChange(
    'vault',
    vault,
    'upsert',
    vault,
    contentHashForRecord(vault),
    vault.updatedAt,
  );
  for (const record of groups.values()) appendCurrentOrPredecessor('group', record);
  for (const record of items.values()) appendCurrentOrPredecessor('item', record);
  for (const { record } of attachments.values()) {
    appendCurrentOrPredecessor('attachment', record);
  }
  for (const tombstone of tombstones.values()) {
    if (tombstone.state !== 'deleted') continue;
    const predecessor = tombstonePredecessors.get(
      `${tombstone.entityType}:${tombstone.entityId}`,
    );
    if (predecessor === undefined || tombstone.entityType === 'vault') {
      throw new ValidationError('A deleted record is missing its predecessor.');
    }
    appendChange(
      tombstone.entityType,
      predecessor,
      'tombstone',
      tombstone,
      tombstone.lastCiphertextHash,
      tombstone.deletedAt,
    );
  }

  return {
    vault: toVaultDocument(vault),
    groups: [...groups.values()].map(toGroupDocument),
    items: [...items.values()].map(toItemDocument),
    attachments: publishedAttachmentMetadata,
    audits,
    histories,
    tombstones: [...tombstones.values()].map(toTombstoneDocument),
    attachmentStaging: publishedAttachmentStaging,
    attachmentChunks: publishedChunks,
    changes,
    counter: storedCounterDocumentSchema.parse({
      _id: vault.id,
      changeSequence: changes.length,
      vaultRevision: vault.revision,
    }),
  };
}

function assertAttachmentHeader(
  attachment: EncryptedAttachmentRecord,
  header: PersistedAttachmentHeaderRecord,
): void {
  const identity = header.record;
  if (
    identity.vaultId !== attachment.vaultId ||
    identity.groupId !== attachment.groupId ||
    identity.itemId !== attachment.itemId ||
    identity.attachmentId !== attachment.id ||
    identity.schemaVersion !== attachment.schemaVersion ||
    identity.keyVersion !== attachment.encryptedManifest.aad.keyVersion ||
    header.recordRevision !== attachment.recordRevision
  ) {
    throw new ValidationError(
      'Attachment header identity or revision is inconsistent.',
    );
  }
}

function currentRecord(
  entityType: TombstoneRecord['entityType'],
  entityId: string,
  groups: ReadonlyMap<string, EncryptedGroupRecord>,
  items: ReadonlyMap<string, EncryptedItemRecord>,
  attachments: ReadonlyMap<string, AttachmentPlan>,
): EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord | undefined {
  if (entityType === 'group') return groups.get(entityId);
  if (entityType === 'item') return items.get(entityId);
  if (entityType === 'attachment') return attachments.get(entityId)?.record;
  return undefined;
}

function assertTombstoneMatches(
  record: EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord,
  tombstone: TombstoneRecord,
  predecessor: TombstonePredecessor | undefined,
): void {
  if (
    tombstone.tombstoneRevision !== record.recordRevision ||
    (tombstone.state === 'deleted' && record.tombstonedAt !== tombstone.deletedAt) ||
    (tombstone.state === 'restored' && record.tombstonedAt !== undefined) ||
    (tombstone.state === 'deleted' &&
      (predecessor === undefined ||
        !sameRecordIdentity(record, predecessor) ||
        predecessor.recordRevision !== tombstone.lastRecordRevision ||
        contentHashForRecord(predecessor) !== tombstone.lastCiphertextHash))
  ) {
    throw new ValidationError('A tombstone does not match its current opaque record.');
  }
}

function sameRecordIdentity(
  current: EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord,
  predecessor: TombstonePredecessor,
): boolean {
  if ('itemId' in current || 'itemId' in predecessor) {
    return (
      'itemId' in current &&
      'itemId' in predecessor &&
      current.id === predecessor.id &&
      current.vaultId === predecessor.vaultId &&
      current.groupId === predecessor.groupId &&
      current.itemId === predecessor.itemId
    );
  }
  if ('groupId' in current || 'groupId' in predecessor) {
    return (
      'groupId' in current &&
      'groupId' in predecessor &&
      current.id === predecessor.id &&
      current.vaultId === predecessor.vaultId &&
      current.groupId === predecessor.groupId
    );
  }
  return current.id === predecessor.id && current.vaultId === predecessor.vaultId;
}

function assertTombstoneCoverage(
  records: Iterable<
    EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord
  >,
  entityType: 'group' | 'item' | 'attachment',
  tombstones: ReadonlyMap<string, TombstoneRecord>,
): void {
  for (const record of records) {
    const tombstone = tombstones.get(`${entityType}:${record.id}`);
    if ((record.tombstonedAt !== undefined) !== (tombstone?.state === 'deleted')) {
      throw new ValidationError(
        'Tombstoned opaque records require matching deleted tombstones.',
      );
    }
  }
}

function validateEntryDocument(
  input: unknown,
  summary: BackupVerification,
  expectedOrdinal: number,
): BackupRestoreEntryDocument {
  const document = parseRestoreEntryDocument(input);
  if (
    document.restoreSessionId !== summary.restoreSessionId ||
    document.ordinal !== expectedOrdinal ||
    document.vaultId !== summary.header.vaultId
  ) {
    throw new ValidationError('A staged restore entry has inconsistent metadata.');
  }
  assertCanonicalAttachmentHash(document.entry);
  return document;
}

function validateEntrySet(
  inputs: readonly unknown[],
  summary: BackupVerification,
  expectedBytes: number,
): readonly BackupRestoreEntryDocument[] {
  const commitment = createBackupStagedEntryCommitment({
    maximumEntryBytes: MAX_MONGO_RESTORE_ENTRY_BYTES,
  });
  let bytes = 0;
  const entries = inputs.map((input, ordinal) => {
    const document = validateEntryDocument(input, summary, ordinal);
    commitment.update(document.entry);
    bytes += document.bytes;
    return document;
  });
  if (
    entries.length !== summary.recordCount ||
    bytes !== expectedBytes ||
    commitment.finalize() !== summary.canonicalEntriesSha256
  ) {
    throw new ValidationError('The staged restore entry set is inconsistent.');
  }
  return entries;
}

function assertReceiptPublication(
  receipt: RestoreKnownRecordsVerificationV1,
  entries: readonly BackupRestoreEntryDocument[],
  publication: Publication,
  summary: BackupVerification,
): void {
  const counts = {
    vaults: 0,
    groups: 0,
    items: 0,
    attachments: 0,
    attachmentHeaders: 0,
    attachmentChunks: 0,
    tombstonePredecessors: { groups: 0, items: 0, attachments: 0 },
    tombstones: 0,
    histories: 0,
    audits: 0,
  };
  for (const { entry } of entries) {
    switch (entry.kind) {
      case 'vault':
        counts.vaults += 1;
        break;
      case 'group':
        counts.groups += 1;
        break;
      case 'item':
        counts.items += 1;
        break;
      case 'attachment':
        counts.attachments += 1;
        break;
      case 'attachment-header':
        counts.attachmentHeaders += 1;
        break;
      case 'attachment-chunk':
        counts.attachmentChunks += 1;
        break;
      case 'tombstone-predecessor':
        counts.tombstonePredecessors[`${entry.entityType}s`] += 1;
        break;
      case 'tombstone':
        counts.tombstones += 1;
        break;
      case 'history':
        counts.histories += 1;
        break;
      case 'audit':
        counts.audits += 1;
        break;
    }
  }
  const vault = publication.vault.record;
  const slot = vault.keySlots.find(({ id }) => id === receipt.selectedSlot.id);
  if (
    canonicalJson(counts) !== canonicalJson(receipt.verified) ||
    receipt.vaultRevision !== vault.revision ||
    !slotMatchesReceipt(slot, receipt, vault.currentKeyVersion) ||
    receipt.recordCount !== summary.recordCount
  ) {
    throw new ValidationError(
      'The restore verification receipt does not match publication.',
    );
  }
}

function slotMatchesReceipt(
  slot: VaultRecord['keySlots'][number] | undefined,
  receipt: RestoreKnownRecordsVerificationV1,
  currentKeyVersion: number,
): boolean {
  return (
    slot?.type === receipt.selectedSlot.type &&
    slot.keyVersion === receipt.selectedSlot.keyVersion &&
    slot.state === 'active' &&
    slot.keyVersion === currentKeyVersion
  );
}

function parseMongoLimits(limits: ResolvedBackupLimits): ResolvedBackupLimits {
  if (
    !Number.isSafeInteger(limits.maximumBytes) ||
    limits.maximumBytes < 1 ||
    limits.maximumBytes >
      Math.min(MAX_SUPPORTED_BACKUP_BYTES, MAX_MONGO_RESTORE_BYTES) ||
    !Number.isSafeInteger(limits.maximumRecords) ||
    limits.maximumRecords < 1 ||
    limits.maximumRecords >
      Math.min(DEFAULT_MAX_BACKUP_RECORDS, MAX_MONGO_RESTORE_RECORDS)
  ) {
    throw new RangeError('Mongo restore limits are outside the supported range.');
  }
  return { ...limits };
}

function parseSummary(summary: unknown): BackupVerification {
  const result = backupVerificationSchema.safeParse(summary);
  if (!result.success) throw new ValidationError('The restore summary is invalid.');
  return result.data;
}

function parseReceipt(input: unknown): RestoreKnownRecordsVerificationV1 {
  const result = restoreKnownRecordsVerificationV1Schema.safeParse(input);
  if (!result.success) {
    throw new ValidationError('The restore verification receipt is invalid.');
  }
  return result.data;
}

function assertExactSummary(
  persisted: BackupVerification,
  summary: BackupVerification,
): void {
  if (canonicalJson(persisted) !== canonicalJson(summary)) {
    throw new ValidationError('The restore summary does not match sealed state.');
  }
}

function assertReceiptSummary(
  receipt: RestoreKnownRecordsVerificationV1,
  summary: BackupVerification,
): void {
  if (
    receipt.vaultId !== summary.header.vaultId ||
    receipt.restoreSessionId !== summary.restoreSessionId ||
    receipt.transcriptSha256 !== summary.transcriptSha256 ||
    receipt.canonicalEntriesSha256 !== summary.canonicalEntriesSha256 ||
    receipt.recordCount !== summary.recordCount
  ) {
    throw new ValidationError(
      'The restore verification receipt does not match its summary.',
    );
  }
}

function sanitizeSealedReadError(): ValidationError {
  return new ValidationError('The sealed restore stream could not be read safely.');
}

async function closeRestoreCursor(
  cursor: Readonly<{ close(): Promise<void> }>,
  preservePrimaryError: boolean,
): Promise<void> {
  try {
    await cursor.close();
  } catch {
    if (!preservePrimaryError) throw sanitizeSealedReadError();
  }
}

function attachmentIdempotencyKey(
  restoreSessionId: Sha256Digest,
  attachmentId: string,
): string {
  return `restore.${restoreSessionId}.${attachmentId}`;
}

function previousRevision(recordRevision: RecordRevision): RecordRevision | null {
  return recordRevision === 0 ? null : recordRevisionSchema.parse(recordRevision - 1);
}

function requireVault(vault: VaultRecord | undefined): asserts vault is VaultRecord {
  if (vault === undefined) {
    throw new ValidationError('The restore vault record is missing.');
  }
}

function duplicateEntry(): never {
  throw new ValidationError('The restore contains a duplicate record identity.');
}

function missingParent(): never {
  throw new ValidationError('A restore record is missing its canonical parent.');
}

async function insertManyIfPresent<T extends Document>(
  collection: Collection<T>,
  documents: readonly OptionalUnlessRequiredId<T>[],
  session: ClientSession,
): Promise<void> {
  if (documents.length > 0) {
    await collection.insertMany([...documents], { ordered: true, session });
  }
}

function isDuplicateKey(error: unknown): boolean {
  return error instanceof MongoServerError && error.code === 11_000;
}
