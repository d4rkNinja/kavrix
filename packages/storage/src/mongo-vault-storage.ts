import {
  SyncConflictError,
  ValidationError,
  advanceAttachmentStaging,
  createAttachmentStagingProgress,
  validateAttachmentStagingFinalization,
  type AttachmentStreamStagingSession,
  type VaultStoragePort,
} from '@kavrix/core';
import {
  attachmentIdSchema,
  auditEventIdSchema,
  changeRecordSchema,
  encryptedAuditRecordSchema,
  groupIdSchema,
  historyIdSchema,
  itemIdSchema,
  recordRevisionSchema,
  syncCursorSchema,
  syncPullResponseSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  timestampSchema,
  tombstoneRecordSchema,
  vaultIdSchema,
  type AttachmentId,
  type AttachmentStreamFinalizeInput,
  type AttachmentStreamProgress,
  type AttachmentStreamStartInput,
  type ChangeRecord,
  type AuditEventId,
  type EncryptedAttachmentRecord,
  type EncryptedAuditRecord,
  type EncryptedGroupRecord,
  type EncryptedHistoryRecord,
  type EncryptedItemRecord,
  type GroupId,
  type HistoryId,
  type ItemId,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type PersistedAttachmentChunkRecord,
  type PersistedAttachmentHeaderRecord,
  type SyncCursor,
  type SyncPullResponse,
  type SyncPushRequest,
  type SyncPushResponse,
  type TemplateMigrationPublicationRequest,
  type TemplateMigrationPublicationResponse,
  type TombstoneRecord,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import {
  MongoServerError,
  type ClientSession,
  type Collection,
  type Db,
  type MongoClient,
} from 'mongodb';

import {
  mongoStorageCollectionNames,
  mongoStorageCollectionOptions,
  mongoStorageDocumentSchemas,
  mongoStorageIndexes,
} from './collections.js';
import { assertMongoDocumentCompatibility } from './mongo-document-preflight.js';
import {
  attachmentStagingDocumentSchema,
  contentHashForRecord,
  entityDocumentId,
  expectedNextRevision,
  finalizeHash,
  fromAttachmentDocument,
  fromAuditDocument,
  fromChangeDocument,
  fromGroupDocument,
  fromHistoryDocument,
  fromItemDocument,
  fromSyncPulledChangeDocument,
  fromTombstoneDocument,
  fromVaultDocument,
  hashCanonical,
  idempotencyDocumentSchema,
  makeStagedChunkDocument,
  mutationExpectedRevision,
  mutationRecordRevision,
  mutationVaultId,
  parseAttachmentChunk,
  parseAttachmentFinalize,
  parseAttachmentStart,
  parseCounterDocument,
  parseIdempotencyDocument,
  parseMutation,
  parseStagedChunkDocument,
  parseStagingDocument,
  parseSyncPushBatchDocument,
  parseTemplateMigrationPublicationDocument,
  stagedChunkDocumentId,
  stagingDocumentId,
  storageCounterDocumentSchema,
  syncPushBatchDocumentId,
  syncPushBatchDocumentSchema,
  templateMigrationPublicationDocumentId,
  templateMigrationPublicationDocumentSchema,
  synchronizeVaultRecordRevision,
  toAttachmentDocument,
  toAuditDocument,
  toChangeDocument,
  toGroupDocument,
  toItemDocument,
  toTombstoneDocument,
  toVaultDocument,
  type AttachmentStagingDocument,
  type IdempotencyDocument,
  type StagedAttachmentChunkDocument,
  type StorageCounterDocument,
  type SyncPushBatchDocument,
  type TemplateMigrationPublicationDocument,
  type StoredAttachmentDocument,
  type StoredAuditDocument,
  type StoredChangeDocument,
  type StoredGroupDocument,
  type StoredHistoryDocument,
  type StoredItemDocument,
  type StoredTombstoneDocument,
  type StoredVaultDocument,
} from './documents.js';

const MAX_PULL_CHANGES = 10_000;
const MAX_SYNC_PAGE_CHANGES = 500;
const transactionOptions = {
  readConcern: { level: 'snapshot' as const },
  writeConcern: { w: 'majority' as const },
};

export type MongoVaultStorageOptions = Readonly<{
  now?: () => Date;
}>;

export async function installMongoStorageContracts(database: Db): Promise<void> {
  const existing = new Set(
    (await database.listCollections({}, { nameOnly: true }).toArray()).map(
      ({ name }) => name,
    ),
  );
  for (const name of Object.values(mongoStorageCollectionNames)) {
    const options = mongoStorageCollectionOptions[name];
    if (existing.has(name)) {
      await database.command({
        collMod: name,
        validator: options.validator,
        validationLevel: options.validationLevel,
        validationAction: options.validationAction,
      });
    } else {
      await database.createCollection(name, options);
    }
    const indexes = mongoStorageIndexes[name];
    if (indexes.length > 0) {
      await database.collection(name).createIndexes([...indexes]);
    }
  }
}

export async function assertMongoStorageCompatibility(database: Db): Promise<void> {
  await assertMongoDocumentCompatibility(database, mongoStorageDocumentSchemas);
}

export async function initializeMongoStorage(database: Db): Promise<void> {
  await installMongoStorageContracts(database);
  await assertMongoStorageCompatibility(database);
}

export class MongoVaultStorage implements VaultStoragePort {
  readonly #client: MongoClient;
  readonly #database: Db;
  readonly #now: () => Date;

  constructor(
    client: MongoClient,
    database: Db,
    options: MongoVaultStorageOptions = {},
  ) {
    this.#client = client;
    this.#database = database;
    this.#now = options.now ?? (() => new Date());
  }

  async initialize(): Promise<void> {
    await initializeMongoStorage(this.#database);
  }

  async getVault(vaultIdInput: VaultId): Promise<VaultRecord | null> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const document = await this.#vaults().findOne({ _id: vaultId });
    return document === null ? null : fromVaultDocument(document);
  }

  async commit(mutationInput: OpaqueMutation): Promise<void> {
    const mutation = parseMutation(mutationInput);
    const result = await this.#withTransaction(async (session) =>
      this.#processSyncMutation(mutation, session),
    );
    if (result.status === 'conflict') throw new SyncConflictError();
  }

  /** Commits a slot revision and its opaque encrypted audit in one transaction. */
  async commitKeySlotMutation(
    mutationInput: Extract<OpaqueMutation, { entityType: 'vault' }>,
    auditInput: EncryptedAuditRecord,
  ): Promise<void> {
    const mutation = parseMutation(mutationInput);
    if (mutation.entityType !== 'vault') throw new ValidationError();
    const audit = parseSchema(encryptedAuditRecordSchema, auditInput, 'key-slot audit');
    if (
      audit.vaultId !== mutation.record.id ||
      audit.recordRevision !== recordRevisionSchema.parse(mutation.record.revision) ||
      audit.encryptedPayload.aad.vaultId !== mutation.record.id ||
      audit.encryptedPayload.aad.keyVersion !== mutation.record.currentKeyVersion
    ) {
      throw new ValidationError();
    }
    await this.#withTransaction(async (session) => {
      const result = await this.#processSyncMutation(mutation, session);
      if (result.status === 'conflict') throw new SyncConflictError();
      const auditId = entityDocumentId(audit.vaultId, audit.id);
      const existingValue = await this.#audits().findOne({ _id: auditId }, { session });
      if (existingValue !== null) {
        if (hashCanonical(fromAuditDocument(existingValue)) !== hashCanonical(audit)) {
          throw new SyncConflictError();
        }
        return;
      }
      await this.#audits().insertOne(toAuditDocument(audit), { session });
    });
  }

  async pushSyncBatch(batchInput: SyncPushRequest): Promise<SyncPushResponse> {
    const batch = parseSchema(syncPushRequestSchema, batchInput, 'sync push batch');
    const requestHash = hashCanonical(batch);
    const batchId = syncPushBatchDocumentId(batch.vaultId, batch.batchIdempotencyKey);

    try {
      await this.#withTransaction(async (session) => {
        const existingValue = await this.#syncPushBatches().findOne(
          { _id: batchId },
          { session },
        );
        if (existingValue !== null) {
          const existing = parseSyncPushBatchDocument(existingValue);
          if (existing.requestHash !== requestHash) throw new SyncConflictError();
          return;
        }
        const now = this.#timestamp();
        await this.#syncPushBatches().insertOne(
          syncPushBatchDocumentSchema.parse({
            _id: batchId,
            vaultId: batch.vaultId,
            batchIdempotencyKey: batch.batchIdempotencyKey,
            requestHash,
            mutationCount: batch.mutations.length,
            state: 'running',
            nextMutationIndex: 0,
            results: [],
            createdAt: now,
            updatedAt: now,
          }),
          { session },
        );
      });
    } catch (error) {
      if (!isDuplicateKey(error)) throw error;
      const existing = await this.#syncPushBatches().findOne({ _id: batchId });
      if (
        existing === null ||
        parseSyncPushBatchDocument(existing).requestHash !== requestHash
      ) {
        throw new SyncConflictError();
      }
    }

    for (;;) {
      const response = await this.#withTransaction(async (session) => {
        const storedValue = await this.#syncPushBatches().findOne(
          { _id: batchId },
          { session },
        );
        if (storedValue === null) {
          throw new ValidationError('The durable sync push checkpoint is missing.');
        }
        const stored = parseSyncPushBatchDocument(storedValue);
        if (stored.requestHash !== requestHash) throw new SyncConflictError();
        if (stored.state === 'completed') return stored.response;

        const mutation = batch.mutations[stored.nextMutationIndex];
        if (mutation === undefined) {
          const counterValue = await this.#counters().findOne(
            { _id: batch.vaultId },
            { session },
          );
          const serverVaultRevision =
            counterValue === null
              ? 0
              : parseCounterDocument(counterValue).vaultRevision;
          const completedAt = this.#timestamp();
          const completed = syncPushResponseSchema.parse({
            vaultId: batch.vaultId,
            serverVaultRevision,
            batchIdempotencyKey: batch.batchIdempotencyKey,
            results: stored.results,
          });
          const replacement = syncPushBatchDocumentSchema.parse({
            ...stored,
            state: 'completed',
            response: completed,
            updatedAt: completedAt,
            completedAt,
          });
          const update = await this.#syncPushBatches().replaceOne(
            {
              _id: batchId,
              state: 'running',
              nextMutationIndex: stored.nextMutationIndex,
            },
            replacement,
            { session },
          );
          if (update.modifiedCount !== 1) throw new SyncConflictError();
          return completed;
        }

        const result = await this.#processSyncMutation(mutation, session);
        const updatedAt = this.#timestamp();
        const update = await this.#syncPushBatches().updateOne(
          {
            _id: batchId,
            state: 'running',
            nextMutationIndex: stored.nextMutationIndex,
          },
          {
            $push: { results: result },
            $inc: { nextMutationIndex: 1 },
            $set: { updatedAt },
          },
          { session },
        );
        if (update.modifiedCount !== 1) throw new SyncConflictError();
        return null;
      });
      if (response !== null) return response;
    }
  }

  async publishTemplateMigration(
    batchInput: TemplateMigrationPublicationRequest,
  ): Promise<TemplateMigrationPublicationResponse> {
    const batch = parseSchema(
      templateMigrationPublicationRequestSchema,
      batchInput,
      'template migration publication',
    );
    const requestHash = hashCanonical(batch);
    const publicationId = templateMigrationPublicationDocumentId(
      batch.vaultId,
      batch.batchIdempotencyKey,
    );

    return this.#withTransaction(async (session) => {
      const existingValue = await this.#templateMigrationPublications().findOne(
        { _id: publicationId },
        { session },
      );
      if (existingValue !== null) {
        const existing = parseTemplateMigrationPublicationDocument(existingValue);
        if (existing.requestHash !== requestHash) throw new SyncConflictError();
        return existing.response;
      }

      const groupMutation = batch.mutations.at(-1);
      if (groupMutation?.entityType !== 'group') {
        throw new ValidationError('A template migration requires one group last.');
      }
      const vaultValue = await this.#vaults().findOne(
        { _id: batch.vaultId },
        { session },
      );
      if (vaultValue === null) throw new SyncConflictError();
      fromVaultDocument(vaultValue);

      for (const mutation of batch.mutations) {
        if (mutation.entityType !== 'group' && mutation.entityType !== 'item') {
          throw new ValidationError(
            'A template migration accepts only group and item mutations.',
          );
        }
        const previous = await this.#loadMutationRecord(mutation, session);
        if (
          previous === null ||
          'revision' in previous ||
          previous.tombstonedAt !== undefined
        ) {
          throw new SyncConflictError();
        }
        this.#assertExpectedMutationRevision(mutation, previous);
        this.#assertTemplateMigrationRecordCompatibility(
          mutation,
          previous,
          groupMutation.record.id,
        );
        const idempotencyValue = await this.#idempotency().findOne(
          {
            _id: stagingDocumentId(batch.vaultId, mutation.idempotencyKey),
          },
          { session },
        );
        if (idempotencyValue !== null) throw new SyncConflictError();
      }

      const results: TemplateMigrationPublicationResponse['results'][number][] = [];
      for (const mutation of batch.mutations) {
        const result = await this.#processSyncMutation(mutation, session);
        if (result.status !== 'accepted' || result.disposition !== 'committed') {
          throw new SyncConflictError();
        }
        results.push({
          idempotencyKey: mutation.idempotencyKey,
          change: result.change,
        });
      }
      const counterValue = await this.#counters().findOne(
        { _id: batch.vaultId },
        { session },
      );
      if (counterValue === null) throw new SyncConflictError();
      const counter = parseCounterDocument(counterValue);
      const response = templateMigrationPublicationResponseSchema.parse({
        vaultId: batch.vaultId,
        batchIdempotencyKey: batch.batchIdempotencyKey,
        serverVaultRevision: counter.vaultRevision,
        results,
      });
      await this.#templateMigrationPublications().insertOne(
        templateMigrationPublicationDocumentSchema.parse({
          _id: publicationId,
          vaultId: batch.vaultId,
          batchIdempotencyKey: batch.batchIdempotencyKey,
          requestHash,
          response,
          committedAt: this.#timestamp(),
        }),
        { session },
      );
      return response;
    });
  }

  async getGroup(
    vaultIdInput: VaultId,
    groupIdInput: GroupId,
  ): Promise<EncryptedGroupRecord | null> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const groupId = parseId(groupIdSchema, groupIdInput, 'group ID');
    const document = await this.#groups().findOne({
      _id: entityDocumentId(vaultId, groupId),
      'record.tombstonedAt': { $exists: false },
    });
    return document === null ? null : fromGroupDocument(document);
  }

  async *listGroups(vaultIdInput: VaultId): AsyncIterable<EncryptedGroupRecord> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const cursor = this.#groups()
      .find({ vaultId, 'record.tombstonedAt': { $exists: false } })
      .sort({ groupId: 1 });
    for await (const document of cursor) yield fromGroupDocument(document);
  }

  async getItem(
    vaultIdInput: VaultId,
    itemIdInput: ItemId,
  ): Promise<EncryptedItemRecord | null> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const itemId = parseId(itemIdSchema, itemIdInput, 'item ID');
    const document = await this.#items().findOne({
      _id: entityDocumentId(vaultId, itemId),
      'record.tombstonedAt': { $exists: false },
    });
    return document === null ? null : fromItemDocument(document);
  }

  async *listItems(
    vaultIdInput: VaultId,
    groupIdInput: GroupId,
  ): AsyncIterable<EncryptedItemRecord> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const groupId = parseId(groupIdSchema, groupIdInput, 'group ID');
    const cursor = this.#items()
      .find({ vaultId, groupId, 'record.tombstonedAt': { $exists: false } })
      .sort({ itemId: 1 });
    for await (const document of cursor) yield fromItemDocument(document);
  }

  async getAudit(
    vaultIdInput: VaultId,
    auditIdInput: AuditEventId,
  ): Promise<EncryptedAuditRecord | null> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const auditId = parseId(auditEventIdSchema, auditIdInput, 'audit event ID');
    const document = await this.#audits().findOne({
      _id: entityDocumentId(vaultId, auditId),
    });
    return document === null ? null : fromAuditDocument(document);
  }

  async *listAudits(vaultIdInput: VaultId): AsyncIterable<EncryptedAuditRecord> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const cursor = this.#audits().find({ vaultId }).sort({ auditId: 1 });
    for await (const document of cursor) yield fromAuditDocument(document);
  }

  async getHistory(
    vaultIdInput: VaultId,
    historyIdInput: HistoryId,
  ): Promise<EncryptedHistoryRecord | null> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const historyId = parseId(historyIdSchema, historyIdInput, 'history ID');
    const document = await this.#histories().findOne({
      _id: entityDocumentId(vaultId, historyId),
    });
    return document === null ? null : fromHistoryDocument(document);
  }

  async *listItemHistory(
    vaultIdInput: VaultId,
    itemIdInput: ItemId,
  ): AsyncIterable<EncryptedHistoryRecord> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const itemId = parseId(itemIdSchema, itemIdInput, 'item ID');
    const cursor = this.#histories()
      .find({ vaultId, itemId })
      .sort({ 'record.itemRecordRevision': 1, historyId: 1 });
    for await (const document of cursor) yield fromHistoryDocument(document);
  }

  async getTombstone(
    vaultIdInput: VaultId,
    entityType: TombstoneRecord['entityType'],
    entityId: string,
  ): Promise<TombstoneRecord | null> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const parsedEntityId = parseOpaqueEntityId(entityId);
    const document = await this.#tombstones().findOne({
      _id: entityDocumentId(vaultId, parsedEntityId),
      entityType,
    });
    return document === null ? null : fromTombstoneDocument(document);
  }

  async getAttachment(
    vaultIdInput: VaultId,
    attachmentIdInput: AttachmentId,
  ): Promise<EncryptedAttachmentRecord | null> {
    const document = await this.#loadVisibleAttachment(vaultIdInput, attachmentIdInput);
    return document === null ? null : fromAttachmentDocument(document);
  }

  async beginAttachmentStream(
    inputValue: AttachmentStreamStartInput,
  ): Promise<AttachmentStreamStagingSession> {
    const input = parseAttachmentStart(inputValue);
    const vaultId = input.header.record.vaultId;
    const attachmentId = input.header.record.attachmentId;
    const stagingId = stagingDocumentId(vaultId, input.idempotencyKey);
    const inputHash = hashCanonical(input);
    let opened: AttachmentStagingDocument | undefined;

    try {
      await this.#withTransaction(async (session) => {
        const existing = await this.#staging().findOne({ _id: stagingId }, { session });
        if (existing !== null) {
          const parsed = parseStagingDocument(existing);
          if (parsed.inputHash !== inputHash) throw new SyncConflictError();
          if (parsed.state === 'aborted') {
            throw new ValidationError(
              'An aborted attachment stream cannot be resumed.',
            );
          }
          opened = parsed;
          return;
        }

        await this.#assertAttachmentParents(input, session);
        await this.#assertExpectedAttachmentRevision(
          vaultId,
          attachmentId,
          input.expectedAttachmentRevision,
          session,
        );
        const now = this.#timestamp();
        const document = attachmentStagingDocumentSchema.parse({
          _id: stagingId,
          vaultId,
          attachmentId,
          idempotencyKey: input.idempotencyKey,
          inputHash,
          state: 'active',
          input,
          progress: createAttachmentStagingProgress(),
          createdAt: now,
          updatedAt: now,
        });
        await this.#staging().insertOne(document, { session });
        opened = document;
      });
    } catch (error) {
      if (isDuplicateKey(error)) {
        const existing = await this.#staging().findOne({ _id: stagingId });
        if (existing !== null) {
          const parsed = parseStagingDocument(existing);
          if (parsed.inputHash === inputHash && parsed.state !== 'aborted') {
            opened = parsed;
          } else {
            throw new SyncConflictError();
          }
        } else {
          throw new SyncConflictError();
        }
      } else {
        throw error;
      }
    }

    if (opened === undefined || opened.state === 'aborted') {
      throw new ValidationError('The attachment stream could not be opened safely.');
    }
    return new MongoAttachmentStagingSession(this, stagingId, opened.progress);
  }

  async abortAttachmentStream(inputValue: AttachmentStreamStartInput): Promise<void> {
    const input = parseAttachmentStart(inputValue);
    const stagingId = stagingDocumentId(
      input.header.record.vaultId,
      input.idempotencyKey,
    );
    const existing = await this.#staging().findOne({ _id: stagingId });
    if (existing === null) {
      const session = await this.beginAttachmentStream(input);
      await session.abort();
      return;
    }
    await this.abortStagedAttachment(stagingId, hashCanonical(input));
  }

  async getAttachmentStreamHeader(
    vaultIdInput: VaultId,
    attachmentIdInput: AttachmentId,
  ): Promise<PersistedAttachmentHeaderRecord | null> {
    const attachment = await this.#loadVisibleAttachment(
      vaultIdInput,
      attachmentIdInput,
    );
    if (attachment === null) return null;
    const staging = await this.#staging().findOne({ _id: attachment.stagingId });
    if (staging === null) {
      throw new ValidationError('Published attachment staging metadata is missing.');
    }
    const parsed = parseStagingDocument(staging);
    if (parsed.state !== 'finalized') {
      throw new ValidationError('Published attachment staging metadata is incomplete.');
    }
    return parsed.input.header;
  }

  async getAttachmentChunk(
    vaultIdInput: VaultId,
    attachmentIdInput: AttachmentId,
    chunkIndexInput: number,
  ): Promise<PersistedAttachmentChunkRecord | null> {
    const chunkIndex = parseChunkIndex(chunkIndexInput);
    const attachment = await this.#loadVisibleAttachment(
      vaultIdInput,
      attachmentIdInput,
    );
    if (attachment === null || chunkIndex >= attachment.record.chunkCount) return null;
    await this.#assertFinalizedStaging(attachment.stagingId);
    const chunk = await this.#stagedChunks().findOne({
      _id: stagedChunkDocumentId(attachment.stagingId, chunkIndex),
    });
    if (chunk === null) {
      throw new ValidationError('Published attachment chunks are not contiguous.');
    }
    const parsed = parseStagedChunkDocument(chunk);
    if (
      parsed.vaultId !== attachment.vaultId ||
      parsed.attachmentId !== attachment.attachmentId
    ) {
      throw new ValidationError('Published attachment chunk identity is inconsistent.');
    }
    return parsed.record;
  }

  async *listAttachmentChunks(
    vaultIdInput: VaultId,
    attachmentIdInput: AttachmentId,
    startIndexInput: number,
  ): AsyncIterable<PersistedAttachmentChunkRecord> {
    const startIndex = parseChunkIndex(startIndexInput);
    const attachment = await this.#loadVisibleAttachment(
      vaultIdInput,
      attachmentIdInput,
    );
    if (attachment === null || startIndex >= attachment.record.chunkCount) return;
    await this.#assertFinalizedStaging(attachment.stagingId);
    let expectedIndex = startIndex;
    const cursor = this.#stagedChunks()
      .find({ stagingId: attachment.stagingId, chunkIndex: { $gte: startIndex } })
      .sort({ chunkIndex: 1 });
    for await (const document of cursor) {
      const chunk = parseStagedChunkDocument(document);
      if (
        chunk.vaultId !== attachment.vaultId ||
        chunk.attachmentId !== attachment.attachmentId ||
        chunk.chunkIndex !== expectedIndex ||
        chunk.chunkIndex >= attachment.record.chunkCount
      ) {
        throw new ValidationError('Published attachment chunks are not contiguous.');
      }
      expectedIndex += 1;
      yield chunk.record;
    }
    if (expectedIndex !== attachment.record.chunkCount) {
      throw new ValidationError('Published attachment chunks are not contiguous.');
    }
  }

  async pullChanges(
    cursorInput: SyncCursor,
    limitInput: number,
  ): Promise<readonly ChangeRecord[]> {
    const cursor = parseSchema(syncCursorSchema, cursorInput, 'sync cursor');
    const limit = parseLimit(limitInput);
    const counter = await this.#counters().findOne({ _id: cursor.vaultId });
    if (counter === null) return [];
    const parsedCounter = parseCounterDocument(counter);
    if (cursor.highestSeenVaultRevision > parsedCounter.vaultRevision) {
      throw new SyncConflictError();
    }
    const documents = await this.#changes()
      .find({
        vaultId: cursor.vaultId,
        serverSequence: { $gt: cursor.serverSequence },
      })
      .sort({ serverSequence: 1 })
      .limit(limit)
      .toArray();
    return documents.map((document) => fromChangeDocument(document));
  }

  async pullSyncPage(
    cursorInput: SyncCursor,
    limitInput: number,
  ): Promise<SyncPullResponse> {
    const cursor = parseSchema(syncCursorSchema, cursorInput, 'sync cursor');
    const limit = parsePageLimit(limitInput);
    return this.#withTransaction(async (session) => {
      const counterValue = await this.#counters().findOne(
        { _id: cursor.vaultId },
        { session },
      );
      if (counterValue === null) throw new SyncConflictError();
      const counter = parseCounterDocument(counterValue);
      if (cursor.highestSeenVaultRevision > counter.vaultRevision) {
        throw new SyncConflictError();
      }
      const documents = await this.#changes()
        .find(
          {
            vaultId: cursor.vaultId,
            serverSequence: { $gt: cursor.serverSequence },
          },
          { session },
        )
        .sort({ serverSequence: 1 })
        .limit(limit + 1)
        .toArray();
      const pageDocuments = documents.slice(0, limit);
      const changes = pageDocuments.map((document) =>
        fromSyncPulledChangeDocument(document),
      );
      const lastSequence =
        changes.at(-1)?.change.serverSequence ?? cursor.serverSequence;
      return syncPullResponseSchema.parse({
        vaultId: cursor.vaultId,
        serverVaultRevision: counter.vaultRevision,
        changes,
        nextCursor: {
          vaultId: cursor.vaultId,
          serverSequence: lastSequence,
          highestSeenVaultRevision: counter.vaultRevision,
        },
        hasMore: documents.length > limit,
      });
    });
  }

  async writeStagedChunk(
    stagingId: string,
    inputValue: PersistedAttachmentChunkRecord,
  ): Promise<AttachmentStreamProgress> {
    const chunk = parseAttachmentChunk(inputValue);
    let result: AttachmentStreamProgress | undefined;
    await this.#withTransaction(async (session) => {
      const stagingValue = await this.#staging().findOne(
        { _id: stagingId },
        { session },
      );
      if (stagingValue === null) {
        throw new ValidationError('The attachment staging session does not exist.');
      }
      const staging = parseStagingDocument(stagingValue);
      if (staging.state !== 'active') {
        throw new ValidationError('Only an active attachment stream accepts chunks.');
      }
      const advanced = advanceAttachmentStaging(staging.input, staging.progress, chunk);
      if (advanced.disposition === 'idempotent-retry') {
        const stored = await this.#stagedChunks().findOne(
          { _id: stagedChunkDocumentId(stagingId, chunk.record.index) },
          { session },
        );
        if (
          stored === null ||
          hashCanonical(parseStagedChunkDocument(stored).record) !==
            hashCanonical(chunk)
        ) {
          throw new SyncConflictError();
        }
        result = advanced.progress;
        return;
      }

      await this.#stagedChunks().insertOne(makeStagedChunkDocument(stagingId, chunk), {
        session,
      });
      const update = await this.#staging().updateOne(
        {
          _id: stagingId,
          state: 'active',
          'progress.nextChunkIndex': staging.progress.nextChunkIndex,
        },
        { $set: { progress: advanced.progress, updatedAt: this.#timestamp() } },
        { session },
      );
      if (update.modifiedCount !== 1) throw new SyncConflictError();
      result = advanced.progress;
    });
    if (result === undefined) {
      throw new ValidationError('The attachment chunk was not staged.');
    }
    return result;
  }

  async finalizeStagedAttachment(
    stagingId: string,
    inputValue: AttachmentStreamFinalizeInput,
  ): Promise<void> {
    const input = parseAttachmentFinalize(inputValue);
    const requestedHash = finalizeHash(input);
    await this.#withTransaction(async (session) => {
      const stagingValue = await this.#staging().findOne(
        { _id: stagingId },
        { session },
      );
      if (stagingValue === null) {
        throw new ValidationError('The attachment staging session does not exist.');
      }
      const staging = parseStagingDocument(stagingValue);
      if (staging.state === 'aborted') {
        throw new ValidationError('An aborted attachment stream cannot be finalized.');
      }
      if (staging.state === 'finalized') {
        if (staging.finalizeHash !== requestedHash) throw new SyncConflictError();
        return;
      }

      validateAttachmentStagingFinalization(staging.input, staging.progress, input);
      const stagedCount = await this.#stagedChunks().countDocuments(
        { stagingId },
        { session },
      );
      if (stagedCount !== staging.progress.nextChunkIndex) {
        throw new ValidationError('Staged attachment chunks are incomplete.');
      }
      await this.#assertExpectedAttachmentRevision(
        staging.vaultId,
        staging.attachmentId,
        staging.input.expectedAttachmentRevision,
        session,
      );
      await this.#assertAttachmentParents(staging.input, session);

      const counter = await this.#advanceAttachmentCounter(
        staging.vaultId,
        input.record.updatedAt,
        session,
      );
      const attachment = toAttachmentDocument(input.record, stagingId);
      const previousDocument = await this.#attachments().findOne(
        { _id: attachment._id },
        { session },
      );
      const previousRecord =
        previousDocument === null ? null : fromAttachmentDocument(previousDocument);
      assertMonotonicTimestamps(previousRecord, input.record);
      const operation = await this.#writeAttachmentTombstone(
        input.record,
        previousRecord,
        session,
      );
      const payload =
        operation === 'tombstone'
          ? await this.#loadTombstonePayload(staging.vaultId, input.record.id, session)
          : input.record;
      if (previousDocument === null) {
        await this.#attachments().insertOne(attachment, { session });
      } else {
        await this.#attachments().replaceOne({ _id: attachment._id }, attachment, {
          session,
        });
      }

      const now = this.#timestamp();
      const update = await this.#staging().updateOne(
        { _id: stagingId, state: 'active' },
        {
          $set: {
            state: 'finalized',
            finalizeHash: requestedHash,
            finalizedAt: now,
            updatedAt: now,
          },
        },
        { session },
      );
      if (update.modifiedCount !== 1) throw new SyncConflictError();

      await this.#changes().insertOne(
        toChangeDocument(
          changeRecordSchema.parse({
            id: `change.${String(counter.changeSequence)}`,
            vaultId: staging.vaultId,
            serverSequence: counter.changeSequence,
            entityType: 'attachment',
            entityId: input.record.id,
            recordRevision: input.record.recordRevision,
            operation,
            ciphertextHash: contentHashForRecord(input.record),
            createdAt: input.record.updatedAt,
          }),
          payload,
        ),
        { session },
      );
    });
  }

  async abortStagedAttachment(
    stagingId: string,
    expectedInputHash?: string,
  ): Promise<void> {
    await this.#withTransaction(async (session) => {
      const stagingValue = await this.#staging().findOne(
        { _id: stagingId },
        { session },
      );
      if (stagingValue === null) return;
      const staging = parseStagingDocument(stagingValue);
      if (expectedInputHash !== undefined && staging.inputHash !== expectedInputHash) {
        throw new SyncConflictError();
      }
      if (staging.state === 'aborted') return;
      if (staging.state === 'finalized') {
        throw new ValidationError('A published attachment stream cannot be aborted.');
      }
      await this.#stagedChunks().deleteMany({ stagingId }, { session });
      const now = this.#timestamp();
      const update = await this.#staging().replaceOne(
        { _id: stagingId, state: 'active' },
        attachmentStagingDocumentSchema.parse({
          _id: staging._id,
          vaultId: staging.vaultId,
          attachmentId: staging.attachmentId,
          idempotencyKey: staging.idempotencyKey,
          inputHash: staging.inputHash,
          state: 'aborted',
          createdAt: staging.createdAt,
          updatedAt: now,
          abortedAt: now,
        }),
        { session },
      );
      if (update.modifiedCount !== 1) throw new SyncConflictError();
    });
  }

  async #withTransaction<TResult>(
    work: (session: ClientSession) => Promise<TResult>,
  ): Promise<TResult> {
    const session = this.#client.startSession();
    try {
      return await session.withTransaction(
        async () => work(session),
        transactionOptions,
      );
    } finally {
      await session.endSession();
    }
  }

  async #processSyncMutation(
    mutation: OpaqueMutation,
    session: ClientSession,
  ): Promise<SyncPushResponse['results'][number]> {
    const vaultId = vaultIdSchema.parse(mutationVaultId(mutation));
    const inputHash = hashCanonical(mutation);
    const idempotencyId = stagingDocumentId(vaultId, mutation.idempotencyKey);
    const previousCommitValue = await this.#idempotency().findOne(
      { _id: idempotencyId },
      { session },
    );
    const previousRecord = await this.#loadMutationRecord(mutation, session);
    if (previousCommitValue !== null) {
      const previousCommit = parseIdempotencyDocument(previousCommitValue);
      if (previousCommit.inputHash === inputHash) {
        return {
          status: 'accepted',
          idempotencyKey: mutation.idempotencyKey,
          disposition: 'duplicate',
          change: previousCommit.change,
        };
      }
      return this.#makeMutationConflict(mutation, previousRecord, session);
    }

    try {
      this.#assertExpectedMutationRevision(mutation, previousRecord);
      await this.#assertMutationParents(mutation, session);
    } catch (error) {
      if (error instanceof SyncConflictError) {
        return this.#makeMutationConflict(mutation, previousRecord, session);
      }
      throw error;
    }

    const counter = await this.#advanceCounter(mutation, vaultId, session);
    await this.#writeMutationRecord(mutation, session);
    const operation = await this.#writeMutationTombstone(
      mutation,
      previousRecord,
      session,
    );
    const payload =
      operation === 'tombstone'
        ? await this.#loadTombstonePayload(vaultId, mutation.record.id, session)
        : mutation.record;
    const change = this.#makeMutationChange(
      mutation,
      counter.changeSequence,
      operation,
    );
    await this.#changes().insertOne(toChangeDocument(change, payload), { session });
    await this.#idempotency().insertOne(
      idempotencyDocumentSchema.parse({
        _id: idempotencyId,
        vaultId,
        idempotencyKey: mutation.idempotencyKey,
        inputHash,
        entityType: mutation.entityType,
        change,
        committedAt: this.#timestamp(),
      }),
      { session },
    );
    return {
      status: 'accepted',
      idempotencyKey: mutation.idempotencyKey,
      disposition: 'committed',
      change,
    };
  }

  async #makeMutationConflict(
    mutation: OpaqueMutation,
    previousRecord: VaultRecord | EncryptedGroupRecord | EncryptedItemRecord | null,
    session: ClientSession,
  ): Promise<SyncPushResponse['results'][number]> {
    let current: OpaqueSyncRecord | null = previousRecord;
    if (
      previousRecord !== null &&
      !('revision' in previousRecord) &&
      previousRecord.tombstonedAt !== undefined
    ) {
      current = await this.#loadTombstonePayload(
        previousRecord.vaultId,
        previousRecord.id,
        session,
      );
    }
    const currentRevision =
      current === null
        ? recordRevisionSchema.parse(0)
        : 'state' in current
          ? current.tombstoneRevision
          : 'revision' in current
            ? current.revision
            : current.recordRevision;
    return {
      status: 'conflict',
      idempotencyKey: mutation.idempotencyKey,
      currentRevision,
      current,
    };
  }

  async #loadMutationRecord(
    mutation: OpaqueMutation,
    session: ClientSession,
  ): Promise<VaultRecord | EncryptedGroupRecord | EncryptedItemRecord | null> {
    switch (mutation.entityType) {
      case 'vault': {
        const document = await this.#vaults().findOne(
          { _id: mutation.record.id },
          { session },
        );
        return document === null ? null : fromVaultDocument(document);
      }
      case 'group': {
        const document = await this.#groups().findOne(
          { _id: entityDocumentId(mutation.record.vaultId, mutation.record.id) },
          { session },
        );
        return document === null ? null : fromGroupDocument(document);
      }
      case 'item': {
        const document = await this.#items().findOne(
          { _id: entityDocumentId(mutation.record.vaultId, mutation.record.id) },
          { session },
        );
        return document === null ? null : fromItemDocument(document);
      }
    }
  }

  #assertExpectedMutationRevision(
    mutation: OpaqueMutation,
    previous: VaultRecord | EncryptedGroupRecord | EncryptedItemRecord | null,
  ): void {
    const expected = mutationExpectedRevision(mutation);
    const actual =
      previous === null
        ? null
        : 'revision' in previous
          ? previous.revision
          : previous.recordRevision;
    if (actual !== expected) throw new SyncConflictError();
    if (mutationRecordRevision(mutation) !== expectedNextRevision(expected)) {
      throw new ValidationError(
        'A committed record revision must immediately follow the expected revision.',
      );
    }
    assertMonotonicTimestamps(previous, mutation.record);
  }

  async #assertMutationParents(
    mutation: OpaqueMutation,
    session: ClientSession,
  ): Promise<void> {
    if (mutation.entityType === 'vault') return;
    const vault = await this.#vaults().findOne(
      { _id: mutation.record.vaultId },
      { session },
    );
    if (vault === null) throw new SyncConflictError();
    fromVaultDocument(vault);
    if (mutation.entityType === 'item') {
      const group = await this.#groups().findOne(
        {
          _id: entityDocumentId(mutation.record.vaultId, mutation.record.groupId),
          'record.tombstonedAt': { $exists: false },
        },
        { session },
      );
      if (group === null) throw new SyncConflictError();
      fromGroupDocument(group);
    }
  }

  #assertTemplateMigrationRecordCompatibility(
    mutation: Extract<OpaqueMutation, { entityType: 'group' | 'item' }>,
    previous: EncryptedGroupRecord | EncryptedItemRecord,
    migratedGroupId: GroupId,
  ): void {
    if (mutation.entityType === 'group') {
      if (
        'groupId' in previous ||
        mutation.record.id !== migratedGroupId ||
        mutation.record.id !== previous.id ||
        mutation.record.vaultId !== previous.vaultId ||
        mutation.record.schemaVersion !== previous.schemaVersion ||
        mutation.record.templateVersion <= previous.templateVersion ||
        mutation.record.encryptedPayload.keyVersion !==
          previous.encryptedPayload.keyVersion ||
        hashCanonical(mutation.record.wrappedGroupKey) !==
          hashCanonical(previous.wrappedGroupKey)
      ) {
        throw new SyncConflictError();
      }
      return;
    }
    if (
      !('groupId' in previous) ||
      mutation.record.id !== previous.id ||
      mutation.record.vaultId !== previous.vaultId ||
      mutation.record.groupId !== migratedGroupId ||
      previous.groupId !== migratedGroupId ||
      mutation.record.schemaVersion !== previous.schemaVersion ||
      mutation.record.encryptedPayload.keyVersion !==
        previous.encryptedPayload.keyVersion ||
      hashCanonical(mutation.record.wrappedItemKey) !==
        hashCanonical(previous.wrappedItemKey)
    ) {
      throw new SyncConflictError();
    }
  }

  async #writeMutationRecord(
    mutation: OpaqueMutation,
    session: ClientSession,
  ): Promise<void> {
    switch (mutation.entityType) {
      case 'vault': {
        const document = toVaultDocument(mutation.record);
        const existing = await this.#vaults().findOne(
          { _id: document._id },
          { session },
        );
        if (existing === null) {
          await this.#vaults().insertOne(document, { session });
        } else {
          await this.#vaults().replaceOne({ _id: document._id }, document, {
            session,
          });
        }
        return;
      }
      case 'group': {
        const document = toGroupDocument(mutation.record);
        const existing = await this.#groups().findOne(
          { _id: document._id },
          { session },
        );
        if (existing === null) {
          await this.#groups().insertOne(document, { session });
        } else {
          await this.#groups().replaceOne({ _id: document._id }, document, {
            session,
          });
        }
        return;
      }
      case 'item': {
        const document = toItemDocument(mutation.record);
        const existing = await this.#items().findOne(
          { _id: document._id },
          { session },
        );
        if (existing === null) {
          await this.#items().insertOne(document, { session });
        } else {
          await this.#items().replaceOne({ _id: document._id }, document, {
            session,
          });
        }
      }
    }
  }

  async #writeMutationTombstone(
    mutation: OpaqueMutation,
    previous: VaultRecord | EncryptedGroupRecord | EncryptedItemRecord | null,
    session: ClientSession,
  ): Promise<'upsert' | 'tombstone' | 'restore'> {
    if (mutation.entityType === 'vault') return 'upsert';
    if (previous !== null && 'revision' in previous) {
      throw new ValidationError('Stored record kind does not match its mutation.');
    }
    const tombstonedAt = mutation.record.tombstonedAt;
    const previousTombstonedAt =
      previous !== null && 'tombstonedAt' in previous
        ? previous.tombstonedAt
        : undefined;
    const id = entityDocumentId(mutation.record.vaultId, mutation.record.id);

    if (tombstonedAt !== undefined) {
      if (previous === null || previousTombstonedAt !== undefined) {
        throw new SyncConflictError();
      }
      const tombstone = tombstoneRecordSchema.parse({
        vaultId: mutation.record.vaultId,
        entityType: mutation.entityType,
        entityId: mutation.record.id,
        state: 'deleted',
        tombstoneRevision: mutation.record.recordRevision,
        lastRecordRevision: previous.recordRevision,
        lastCiphertextHash: contentHashForRecord(previous),
        deletedAt: tombstonedAt,
      });
      await this.#tombstones().replaceOne({ _id: id }, toTombstoneDocument(tombstone), {
        session,
        upsert: true,
      });
      return 'tombstone';
    }

    if (previousTombstonedAt !== undefined) {
      const stored = await this.#tombstones().findOne({ _id: id }, { session });
      if (stored === null) {
        throw new ValidationError('A restored record is missing its tombstone.');
      }
      const previousTombstone = fromTombstoneDocument(stored);
      const restored = tombstoneRecordSchema.parse({
        vaultId: previousTombstone.vaultId,
        entityType: previousTombstone.entityType,
        entityId: previousTombstone.entityId,
        state: 'restored',
        tombstoneRevision: mutation.record.recordRevision,
        lastRecordRevision: previousTombstone.lastRecordRevision,
        lastCiphertextHash: previousTombstone.lastCiphertextHash,
        deletedAt: previousTombstone.deletedAt,
        restoredAt: mutation.record.updatedAt,
      });
      await this.#tombstones().replaceOne({ _id: id }, toTombstoneDocument(restored), {
        session,
      });
      return 'restore';
    }
    return 'upsert';
  }

  async #advanceCounter(
    mutation: OpaqueMutation,
    vaultId: VaultId,
    session: ClientSession,
  ): Promise<StorageCounterDocument> {
    if (mutation.entityType === 'vault') {
      if (mutation.expectedVaultRevision === null) {
        const counter = storageCounterDocumentSchema.parse({
          _id: vaultId,
          changeSequence: 1,
          vaultRevision: mutation.record.revision,
        });
        await this.#counters().insertOne(counter, { session });
        return counter;
      }
      const updated = await this.#counters().findOneAndUpdate(
        { _id: vaultId, vaultRevision: mutation.expectedVaultRevision },
        {
          $inc: { changeSequence: 1 },
          $set: { vaultRevision: mutation.record.revision },
        },
        { session, returnDocument: 'after' },
      );
      if (updated === null) throw new SyncConflictError();
      return parseCounterDocument(updated);
    }
    return this.#advanceAttachmentCounter(vaultId, mutation.record.updatedAt, session);
  }

  async #writeAttachmentTombstone(
    record: EncryptedAttachmentRecord,
    previous: EncryptedAttachmentRecord | null,
    session: ClientSession,
  ): Promise<'upsert' | 'tombstone' | 'restore'> {
    const id = entityDocumentId(record.vaultId, record.id);
    if (record.tombstonedAt !== undefined) {
      if (previous === null || previous.tombstonedAt !== undefined) {
        throw new SyncConflictError();
      }
      const tombstone = tombstoneRecordSchema.parse({
        vaultId: record.vaultId,
        entityType: 'attachment',
        entityId: record.id,
        state: 'deleted',
        tombstoneRevision: record.recordRevision,
        lastRecordRevision: previous.recordRevision,
        lastCiphertextHash: contentHashForRecord(previous),
        deletedAt: record.tombstonedAt,
      });
      await this.#tombstones().replaceOne({ _id: id }, toTombstoneDocument(tombstone), {
        session,
        upsert: true,
      });
      return 'tombstone';
    }
    if (previous?.tombstonedAt !== undefined) {
      const stored = await this.#tombstones().findOne({ _id: id }, { session });
      if (stored === null) {
        throw new ValidationError('A restored attachment is missing its tombstone.');
      }
      const previousTombstone = fromTombstoneDocument(stored);
      const restored = tombstoneRecordSchema.parse({
        vaultId: previousTombstone.vaultId,
        entityType: previousTombstone.entityType,
        entityId: previousTombstone.entityId,
        state: 'restored',
        tombstoneRevision: record.recordRevision,
        lastRecordRevision: previousTombstone.lastRecordRevision,
        lastCiphertextHash: previousTombstone.lastCiphertextHash,
        deletedAt: previousTombstone.deletedAt,
        restoredAt: record.updatedAt,
      });
      await this.#tombstones().replaceOne({ _id: id }, toTombstoneDocument(restored), {
        session,
      });
      return 'restore';
    }
    return 'upsert';
  }

  async #loadTombstonePayload(
    vaultId: VaultId,
    entityId: string,
    session: ClientSession,
  ): Promise<OpaqueSyncRecord> {
    const document = await this.#tombstones().findOne(
      { _id: entityDocumentId(vaultId, entityId) },
      { session },
    );
    if (document === null) {
      throw new ValidationError('A change is missing its opaque tombstone payload.');
    }
    return fromTombstoneDocument(document);
  }

  async #advanceAttachmentCounter(
    vaultId: VaultId,
    observedUpdatedAt: string,
    session: ClientSession,
  ): Promise<StorageCounterDocument> {
    const updated = await this.#counters().findOneAndUpdate(
      { _id: vaultId },
      { $inc: { changeSequence: 1, vaultRevision: 1 } },
      { session, returnDocument: 'after' },
    );
    if (updated === null) throw new SyncConflictError();
    const counter = parseCounterDocument(updated);
    const vaultDocument = await this.#vaults().findOne({ _id: vaultId }, { session });
    if (vaultDocument === null) throw new SyncConflictError();
    const vault = fromVaultDocument(vaultDocument);
    const synchronized = synchronizeVaultRecordRevision(
      vault,
      counter.vaultRevision,
      observedUpdatedAt,
    );
    const result = await this.#vaults().updateOne(
      { _id: vaultId, 'record.revision': vault.revision },
      {
        $set: {
          'record.revision': synchronized.revision,
          'record.updatedAt': synchronized.updatedAt,
        },
      },
      { session },
    );
    if (result.modifiedCount !== 1) throw new SyncConflictError();
    return counter;
  }

  #makeMutationChange(
    mutation: OpaqueMutation,
    sequence: number,
    operation: 'upsert' | 'tombstone' | 'restore',
  ): ChangeRecord {
    const record = mutation.record;
    const vaultId = vaultIdSchema.parse(mutationVaultId(mutation));
    return changeRecordSchema.parse({
      id: `change.${String(sequence)}`,
      vaultId,
      serverSequence: sequence,
      entityType: mutation.entityType,
      entityId: record.id,
      recordRevision: mutationRecordRevision(mutation),
      operation,
      ciphertextHash: contentHashForRecord(record),
      createdAt: record.updatedAt,
    });
  }

  async #assertAttachmentParents(
    input: AttachmentStreamStartInput,
    session: ClientSession,
  ): Promise<void> {
    const header = input.header.record;
    const [vault, group, item] = await Promise.all([
      this.#vaults().findOne({ _id: header.vaultId }, { session }),
      this.#groups().findOne(
        {
          _id: entityDocumentId(header.vaultId, header.groupId),
          'record.tombstonedAt': { $exists: false },
        },
        { session },
      ),
      this.#items().findOne(
        {
          _id: entityDocumentId(header.vaultId, header.itemId),
          groupId: header.groupId,
          'record.tombstonedAt': { $exists: false },
        },
        { session },
      ),
    ]);
    if (vault === null || group === null || item === null) {
      throw new SyncConflictError();
    }
    fromVaultDocument(vault);
    fromGroupDocument(group);
    fromItemDocument(item);
  }

  async #assertExpectedAttachmentRevision(
    vaultId: VaultId,
    attachmentId: AttachmentId,
    expectedRevision: number | null,
    session: ClientSession,
  ): Promise<void> {
    const document = await this.#attachments().findOne(
      { _id: entityDocumentId(vaultId, attachmentId) },
      { session },
    );
    const actual =
      document === null ? null : fromAttachmentDocument(document).recordRevision;
    if (actual !== expectedRevision) throw new SyncConflictError();
  }

  async #loadVisibleAttachment(
    vaultIdInput: VaultId,
    attachmentIdInput: AttachmentId,
  ): Promise<StoredAttachmentDocument | null> {
    const vaultId = parseId(vaultIdSchema, vaultIdInput, 'vault ID');
    const attachmentId = parseId(
      attachmentIdSchema,
      attachmentIdInput,
      'attachment ID',
    );
    return this.#withTransaction(async (session) => {
      const document = await this.#attachments().findOne(
        {
          _id: entityDocumentId(vaultId, attachmentId),
          'record.tombstonedAt': { $exists: false },
        },
        { session },
      );
      if (document === null) return null;
      const record = fromAttachmentDocument(document);
      const [group, item, staging] = await Promise.all([
        this.#groups().findOne(
          {
            _id: entityDocumentId(vaultId, record.groupId),
            'record.tombstonedAt': { $exists: false },
          },
          { session },
        ),
        this.#items().findOne(
          {
            _id: entityDocumentId(vaultId, record.itemId),
            groupId: record.groupId,
            'record.tombstonedAt': { $exists: false },
          },
          { session },
        ),
        this.#staging().findOne({ _id: document.stagingId }, { session }),
      ]);
      if (group === null || item === null) return null;
      fromGroupDocument(group);
      fromItemDocument(item);
      if (staging === null) {
        throw new ValidationError('Published attachment staging metadata is missing.');
      }
      const parsedStaging = parseStagingDocument(staging);
      if (
        parsedStaging.state !== 'finalized' ||
        parsedStaging.vaultId !== document.vaultId ||
        parsedStaging.attachmentId !== document.attachmentId
      ) {
        throw new ValidationError(
          'Published attachment staging metadata is incomplete.',
        );
      }
      return document;
    });
  }

  async #assertFinalizedStaging(stagingId: string): Promise<void> {
    const staging = await this.#staging().findOne({ _id: stagingId });
    if (staging === null || parseStagingDocument(staging).state !== 'finalized') {
      throw new ValidationError('Published attachment staging metadata is incomplete.');
    }
  }

  #timestamp(): string {
    return timestampSchema.parse(this.#now().toISOString());
  }

  #vaults(): Collection<StoredVaultDocument> {
    return this.#database.collection(mongoStorageCollectionNames.vaults);
  }

  #groups(): Collection<StoredGroupDocument> {
    return this.#database.collection(mongoStorageCollectionNames.groups);
  }

  #items(): Collection<StoredItemDocument> {
    return this.#database.collection(mongoStorageCollectionNames.items);
  }

  #attachments(): Collection<StoredAttachmentDocument> {
    return this.#database.collection(mongoStorageCollectionNames.attachments);
  }

  #audits(): Collection<StoredAuditDocument> {
    return this.#database.collection(mongoStorageCollectionNames.audits);
  }

  #histories(): Collection<StoredHistoryDocument> {
    return this.#database.collection(mongoStorageCollectionNames.histories);
  }

  #changes(): Collection<StoredChangeDocument> {
    return this.#database.collection(mongoStorageCollectionNames.changes);
  }

  #tombstones(): Collection<StoredTombstoneDocument> {
    return this.#database.collection(mongoStorageCollectionNames.tombstones);
  }

  #counters(): Collection<StorageCounterDocument> {
    return this.#database.collection(mongoStorageCollectionNames.counters);
  }

  #idempotency(): Collection<IdempotencyDocument> {
    return this.#database.collection(mongoStorageCollectionNames.idempotency);
  }

  #syncPushBatches(): Collection<SyncPushBatchDocument> {
    return this.#database.collection(mongoStorageCollectionNames.syncPushBatches);
  }

  #templateMigrationPublications(): Collection<TemplateMigrationPublicationDocument> {
    return this.#database.collection(
      mongoStorageCollectionNames.templateMigrationPublications,
    );
  }

  #staging(): Collection<AttachmentStagingDocument> {
    return this.#database.collection(mongoStorageCollectionNames.attachmentStaging);
  }

  #stagedChunks(): Collection<StagedAttachmentChunkDocument> {
    return this.#database.collection(
      mongoStorageCollectionNames.attachmentStagingChunks,
    );
  }
}

class MongoAttachmentStagingSession implements AttachmentStreamStagingSession {
  readonly progress: AttachmentStreamProgress;
  readonly #storage: MongoVaultStorage;
  readonly #stagingId: string;

  constructor(
    storage: MongoVaultStorage,
    stagingId: string,
    progress: AttachmentStreamProgress,
  ) {
    this.#storage = storage;
    this.#stagingId = stagingId;
    this.progress = progress;
  }

  async writeChunk(
    record: PersistedAttachmentChunkRecord,
  ): Promise<AttachmentStreamProgress> {
    return this.#storage.writeStagedChunk(this.#stagingId, record);
  }

  async finalize(input: AttachmentStreamFinalizeInput): Promise<void> {
    await this.#storage.finalizeStagedAttachment(this.#stagingId, input);
  }

  async abort(): Promise<void> {
    await this.#storage.abortStagedAttachment(this.#stagingId);
  }
}

type TimestampedRecord = Readonly<{
  createdAt: string;
  updatedAt: string;
}>;

function assertMonotonicTimestamps(
  previous: TimestampedRecord | null,
  next: TimestampedRecord,
): void {
  if (next.updatedAt < next.createdAt) {
    throw new ValidationError('A record update cannot predate its creation.');
  }
  if (
    previous !== null &&
    (next.createdAt !== previous.createdAt || next.updatedAt < previous.updatedAt)
  ) {
    throw new ValidationError('Record timestamps must advance monotonically.');
  }
}

function parseId<T extends string>(
  schema: {
    safeParse(input: unknown): { success: true; data: T } | { success: false };
  },
  input: unknown,
  label: string,
): T {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new ValidationError(`The ${label} is invalid.`);
  return parsed.data;
}

function parseOpaqueEntityId(input: string): string {
  if (
    input.length < 1 ||
    input.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._~-]*$/u.test(input)
  ) {
    throw new ValidationError('The tombstone entity ID is invalid.');
  }
  return input;
}

function parseSchema<T>(
  schema: {
    safeParse(input: unknown): { success: true; data: T } | { success: false };
  },
  input: unknown,
  label: string,
): T {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new ValidationError(`The ${label} is invalid.`);
  return parsed.data;
}

function parseLimit(input: number): number {
  if (!Number.isSafeInteger(input) || input < 1 || input > MAX_PULL_CHANGES) {
    throw new ValidationError(
      `Change limits must be between 1 and ${String(MAX_PULL_CHANGES)}.`,
    );
  }
  return input;
}

function parsePageLimit(input: number): number {
  if (!Number.isSafeInteger(input) || input < 1 || input > MAX_SYNC_PAGE_CHANGES) {
    throw new ValidationError(
      `Sync page limits must be between 1 and ${String(MAX_SYNC_PAGE_CHANGES)}.`,
    );
  }
  return input;
}

function parseChunkIndex(input: number): number {
  if (!Number.isSafeInteger(input) || input < 0) {
    throw new ValidationError('Attachment chunk indexes must be nonnegative integers.');
  }
  return input;
}

function isDuplicateKey(error: unknown): boolean {
  return error instanceof MongoServerError && error.code === 11_000;
}
