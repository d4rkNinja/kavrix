import {
  advanceAttachmentStaging,
  createAttachmentStagingProgress,
  validateAttachmentStagingFinalization,
} from '@kavrix/core';
import {
  canonicalJson,
  contentHashForRecord,
  attachmentRecordHashMatchesCanonicalContent,
  encryptedBackupEntrySchema,
  vaultIdSchema,
  type EncryptedAttachmentRecord,
  type EncryptedBackupEntry,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type OpaqueSyncRecord,
  type TombstoneRecord,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import {
  ReadPreference,
  type ClientSession,
  type Db,
  type Document,
  type Filter,
  type FindCursor,
  type MongoClient,
  type Sort,
} from 'mongodb';
import { z } from 'zod';

import { mongoStorageCollectionNames } from './collections.js';
import {
  fromAttachmentDocument,
  fromAuditDocument,
  fromGroupDocument,
  fromHistoryDocument,
  fromItemDocument,
  fromTombstoneDocument,
  fromVaultDocument,
  parseCounterDocument,
  parseStagedChunkDocument,
  parseStagingDocument,
  storedChangeDocumentSchema,
} from './documents.js';

export const MAX_MONGO_BACKUP_SOURCE_BYTES = 128 * 1024 * 1024;
export const MAX_MONGO_BACKUP_SOURCE_RECORDS = 10_000;

const CURSOR_BATCH_SIZE = 128;
const SIMPLE_COLLATION = Object.freeze({ locale: 'simple' as const });

const coveredCollections = [
  mongoStorageCollectionNames.groups,
  mongoStorageCollectionNames.items,
  mongoStorageCollectionNames.attachments,
  mongoStorageCollectionNames.histories,
  mongoStorageCollectionNames.audits,
] as const;

type CoveredCollection = (typeof coveredCollections)[number];

const sourceOptionsSchema = z
  .object({
    maximumBytes: z
      .number()
      .int()
      .positive()
      .max(MAX_MONGO_BACKUP_SOURCE_BYTES)
      .default(MAX_MONGO_BACKUP_SOURCE_BYTES),
    maximumRecords: z
      .number()
      .int()
      .positive()
      .max(MAX_MONGO_BACKUP_SOURCE_RECORDS)
      .default(MAX_MONGO_BACKUP_SOURCE_RECORDS),
    signal: z.custom<AbortSignal>((value) => value instanceof AbortSignal).optional(),
  })
  .strict();

export type MongoBackupSourceOptions = Readonly<{
  maximumBytes?: number;
  maximumRecords?: number;
  signal?: AbortSignal;
}>;

export type MongoBackupRecordEntry = Exclude<EncryptedBackupEntry, { kind: 'vault' }>;

type MongoBackupPredecessor =
  EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord;

export interface MongoBackupSnapshot {
  readonly vault: VaultRecord;
  readonly records: AsyncIterable<MongoBackupRecordEntry>;
  readonly maximumBytes: number;
  readonly maximumRecords: number;
  close(): Promise<void>;
}

export type MongoBackupSourceErrorCode =
  | 'BACKUP_SOURCE_ABORTED'
  | 'BACKUP_SOURCE_BUSY'
  | 'BACKUP_SOURCE_FAILED'
  | 'BACKUP_SOURCE_TOO_LARGE';

export class MongoBackupSourceError extends Error {
  readonly code: MongoBackupSourceErrorCode;

  constructor(code: MongoBackupSourceErrorCode) {
    super(messageForCode(code));
    this.name = 'MongoBackupSourceError';
    this.code = code;
  }
}

/**
 * Opens one read-only MongoDB snapshot for a whole-vault encrypted backup.
 * `vault` is passed to createEncryptedBackup and `records` is its one-shot,
 * non-vault record stream. Consuming or returning the stream releases the
 * transaction; callers that never consume it must call close().
 */
export class MongoBackupSource {
  readonly #client: MongoClient;
  readonly #database: Db;

  constructor(client: MongoClient, database: Db) {
    this.#client = client;
    this.#database = database;
  }

  async open(
    vaultIdInput: VaultId,
    optionsInput: MongoBackupSourceOptions = {},
  ): Promise<MongoBackupSnapshot> {
    const vaultResult = vaultIdSchema.safeParse(vaultIdInput);
    const optionsResult = sourceOptionsSchema.safeParse(optionsInput);
    if (!vaultResult.success || !optionsResult.success) {
      throw new MongoBackupSourceError('BACKUP_SOURCE_FAILED');
    }
    const options = optionsResult.data;
    if (options.signal?.aborted === true) {
      throw new MongoBackupSourceError('BACKUP_SOURCE_ABORTED');
    }

    let session: ClientSession | undefined;
    try {
      session = this.#client.startSession({ causalConsistency: false });
      session.startTransaction({
        readConcern: { level: 'snapshot' },
        readPreference: ReadPreference.primary,
      });
      const vaultDocument = await this.#database
        .collection(mongoStorageCollectionNames.vaults)
        .findOne(
          { _id: vaultResult.data, vaultId: vaultResult.data },
          { session, signal: options.signal },
        );
      checkAborted(options.signal);
      if (vaultDocument === null) fail();
      const vault = fromVaultDocument(vaultDocument);
      const counterDocument = await this.#database
        .collection(mongoStorageCollectionNames.counters)
        .findOne({ _id: vault.id }, { session, signal: options.signal });
      if (counterDocument === null) fail();
      const counter = parseCounterDocument(counterDocument);
      if (counter.vaultRevision !== vault.revision) fail();

      const budget = new SourceBudget(options.maximumBytes, options.maximumRecords);
      budget.accept({ kind: 'vault', record: vault });
      return new MongoBackupSnapshotImpl(
        this.#database,
        session,
        vault,
        counter.changeSequence,
        budget,
        options.signal,
      );
    } catch (error) {
      await releaseSession(session);
      throw normalizeError(error, options.signal);
    }
  }
}

class MongoBackupSnapshotImpl implements MongoBackupSnapshot {
  readonly vault: VaultRecord;
  readonly records: AsyncIterable<MongoBackupRecordEntry> = this;
  readonly maximumBytes: number;
  readonly maximumRecords: number;
  readonly #database: Db;
  readonly #session: ClientSession;
  readonly #counterChangeSequence: number;
  readonly #budget: SourceBudget;
  readonly #signal: AbortSignal | undefined;
  #started = false;
  #closed = false;
  #releasePromise: Promise<void> | undefined;

  constructor(
    database: Db,
    session: ClientSession,
    vault: VaultRecord,
    counterChangeSequence: number,
    budget: SourceBudget,
    signal: AbortSignal | undefined,
  ) {
    this.#database = database;
    this.#session = session;
    this.vault = vault;
    this.#counterChangeSequence = counterChangeSequence;
    this.#budget = budget;
    this.#signal = signal;
    this.maximumBytes = budget.maximumBytes;
    this.maximumRecords = budget.maximumRecords;
  }

  [Symbol.asyncIterator](): AsyncIterator<MongoBackupRecordEntry> {
    if (this.#started || this.#closed) {
      throw new MongoBackupSourceError('BACKUP_SOURCE_BUSY');
    }
    this.#started = true;
    return this.#iterate();
  }

  async close(): Promise<void> {
    await this.#release();
  }

  async *#iterate(): AsyncGenerator<MongoBackupRecordEntry> {
    try {
      const expectedCounts = await this.#loadCoveredCounts();
      const visited = new Map<CoveredCollection, Set<string>>(
        coveredCollections.map((collection) => [collection, new Set<string>()]),
      );
      const tombstones = await this.#loadTombstones();
      for await (const groupDocument of this.#documents(
        mongoStorageCollectionNames.groups,
        { vaultId: this.vault.id },
        { groupId: 1, _id: 1 },
      )) {
        const group = fromGroupDocument(groupDocument);
        remember(visited, mongoStorageCollectionNames.groups, group.id);
        this.#assertSchema(group.schemaVersion);
        if (group.recordRevision > this.vault.revision) fail();
        yield this.#entry({ kind: 'group', record: group });
        yield* this.#tombstoneEntries('group', group, tombstones);

        for await (const itemDocument of this.#documents(
          mongoStorageCollectionNames.items,
          { vaultId: this.vault.id, groupId: group.id },
          { itemId: 1, _id: 1 },
        )) {
          const item = fromItemDocument(itemDocument);
          remember(visited, mongoStorageCollectionNames.items, item.id);
          this.#assertSchema(item.schemaVersion);
          if (item.recordRevision > this.vault.revision) fail();
          yield this.#entry({ kind: 'item', record: item });

          for await (const historyDocument of this.#documents(
            mongoStorageCollectionNames.histories,
            { vaultId: this.vault.id, groupId: group.id, itemId: item.id },
            { historyId: 1, _id: 1 },
          )) {
            const history = fromHistoryDocument(historyDocument);
            remember(visited, mongoStorageCollectionNames.histories, history.id);
            this.#assertSchema(history.schemaVersion);
            if (history.itemRecordRevision > item.recordRevision) fail();
            yield this.#entry({ kind: 'history', record: history });
          }

          yield* this.#tombstoneEntries('item', item, tombstones);

          for await (const attachmentDocument of this.#documents(
            mongoStorageCollectionNames.attachments,
            { vaultId: this.vault.id, groupId: group.id, itemId: item.id },
            { attachmentId: 1, _id: 1 },
          )) {
            const attachment = fromAttachmentDocument(attachmentDocument);
            remember(visited, mongoStorageCollectionNames.attachments, attachment.id);
            this.#assertSchema(attachment.schemaVersion);
            if (attachment.recordRevision > this.vault.revision) fail();
            yield this.#entry({ kind: 'attachment', record: attachment });
            yield* this.#attachmentStream(attachment, attachmentDocument);
            yield* this.#tombstoneEntries('attachment', attachment, tombstones);
          }
        }
      }

      for await (const auditDocument of this.#documents(
        mongoStorageCollectionNames.audits,
        { vaultId: this.vault.id },
        { auditId: 1, _id: 1 },
      )) {
        const audit = fromAuditDocument(auditDocument);
        remember(visited, mongoStorageCollectionNames.audits, audit.id);
        this.#assertSchema(audit.schemaVersion);
        if (audit.recordRevision > this.vault.revision) fail();
        yield this.#entry({ kind: 'audit', record: audit });
      }

      this.#assertCoveredCounts(expectedCounts, visited);
      if (tombstones.size !== 0) fail();
      await this.#assertChangeSequence();
    } catch (error) {
      throw normalizeError(error, this.#signal);
    } finally {
      await this.#release();
    }
  }

  async #loadCoveredCounts(): Promise<ReadonlyMap<CoveredCollection, number>> {
    const values = new Map<CoveredCollection, number>();
    let total = 0;
    for (const collection of coveredCollections) {
      checkAborted(this.#signal);
      const count = await this.#database
        .collection(collection)
        .countDocuments(
          { vaultId: this.vault.id },
          { session: this.#session, signal: this.#signal },
        );
      if (!Number.isSafeInteger(count) || count < 0) fail();
      total += count;
      if (total > this.maximumRecords) tooLarge();
      values.set(collection, count);
    }
    return values;
  }

  #assertCoveredCounts(
    expected: ReadonlyMap<CoveredCollection, number>,
    visited: ReadonlyMap<CoveredCollection, ReadonlySet<string>>,
  ): void {
    for (const collection of coveredCollections) {
      if (expected.get(collection) !== visited.get(collection)?.size) fail();
    }
  }

  async #loadTombstones(): Promise<Map<string, TombstoneRecord>> {
    const values = new Map<string, TombstoneRecord>();
    let retainedBytes = 0;
    for await (const document of this.#documents(
      mongoStorageCollectionNames.tombstones,
      { vaultId: this.vault.id },
      { entityType: 1, entityId: 1, _id: 1 },
    )) {
      const record = fromTombstoneDocument(document);
      if (record.entityType === 'vault') fail();
      const key = tombstoneKey(record.entityType, record.entityId);
      if (values.has(key)) fail();
      retainedBytes += canonicalEntryBytes({ kind: 'tombstone', record });
      if (values.size >= this.maximumRecords || retainedBytes > this.maximumBytes) {
        tooLarge();
      }
      values.set(key, record);
    }
    return values;
  }

  async *#tombstoneEntries(
    entityType: 'group' | 'item' | 'attachment',
    current: EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord,
    tombstones: Map<string, TombstoneRecord>,
  ): AsyncGenerator<MongoBackupRecordEntry> {
    const key = tombstoneKey(entityType, current.id);
    const tombstone = tombstones.get(key);
    if (tombstone === undefined) {
      if (current.tombstonedAt !== undefined) fail();
      return;
    }
    if (
      tombstone.vaultId !== this.vault.id ||
      tombstone.entityType !== entityType ||
      tombstone.entityId !== current.id ||
      tombstone.tombstoneRevision !== current.recordRevision ||
      tombstone.lastRecordRevision >= tombstone.tombstoneRevision
    ) {
      fail();
    }

    if (tombstone.state === 'deleted') {
      if (current.tombstonedAt !== tombstone.deletedAt) fail();
      const predecessor = await this.#loadPredecessor(entityType, current, tombstone);
      yield this.#entry({
        kind: 'tombstone-predecessor',
        entityType,
        record: predecessor,
      });
    } else if (
      current.tombstonedAt !== undefined ||
      tombstone.restoredAt !== current.updatedAt
    ) {
      fail();
    }

    yield this.#entry({ kind: 'tombstone', record: tombstone });
    tombstones.delete(key);
  }

  async #loadPredecessor(
    entityType: 'group' | 'item' | 'attachment',
    current: EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord,
    tombstone: TombstoneRecord,
  ): Promise<EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord> {
    checkAborted(this.#signal);
    const cursor = this.#database.collection(mongoStorageCollectionNames.changes).find(
      {
        vaultId: this.vault.id,
        'record.entityType': entityType,
        'record.entityId': current.id,
        'record.recordRevision': tombstone.lastRecordRevision,
        'record.operation': { $in: ['upsert', 'restore'] },
        'record.ciphertextHash': tombstone.lastCiphertextHash,
      },
      {
        session: this.#session,
        signal: this.#signal,
        limit: 2,
        sort: { serverSequence: -1 },
        collation: SIMPLE_COLLATION,
      },
    );
    let documents: Document[];
    try {
      documents = await cursor.toArray();
    } finally {
      await cursor.close();
    }
    checkAborted(this.#signal);
    if (documents.length !== 1) fail();
    const change = storedChangeDocumentSchema.parse(documents[0]);
    const predecessor = change.payload;
    if (
      predecessor === null ||
      !isMongoBackupPredecessor(predecessor) ||
      change.record.vaultId !== this.vault.id ||
      change.record.entityType !== entityType ||
      change.record.entityId !== current.id ||
      change.record.recordRevision !== tombstone.lastRecordRevision ||
      change.record.ciphertextHash !== tombstone.lastCiphertextHash ||
      predecessor.recordRevision !== tombstone.lastRecordRevision ||
      predecessor.tombstonedAt !== undefined ||
      predecessor.schemaVersion !== current.schemaVersion ||
      contentHashForRecord(predecessor) !== tombstone.lastCiphertextHash ||
      !sameRecordIdentity(current, predecessor, entityType)
    ) {
      fail();
    }
    return predecessor;
  }

  async *#attachmentStream(
    attachment: EncryptedAttachmentRecord,
    attachmentDocument: Document,
  ): AsyncGenerator<MongoBackupRecordEntry> {
    const stagingId = attachmentDocument['stagingId'] as unknown;
    if (typeof stagingId !== 'string' || stagingId.length === 0) fail();
    const stagingDocument = await this.#database
      .collection<Document & { _id: string }>(
        mongoStorageCollectionNames.attachmentStaging,
      )
      .findOne({ _id: stagingId }, { session: this.#session, signal: this.#signal });
    if (stagingDocument === null) fail();
    const staging = parseStagingDocument(stagingDocument);
    if (
      staging.state !== 'finalized' ||
      staging._id !== stagingId ||
      staging.vaultId !== this.vault.id ||
      staging.attachmentId !== attachment.id
    ) {
      fail();
    }
    const start = staging.input;
    if (!attachmentRecordHashMatchesCanonicalContent(start.header)) fail();
    let progress = createAttachmentStagingProgress();
    yield this.#entry({ kind: 'attachment-header', record: start.header });

    for await (const chunkDocument of this.#documents(
      mongoStorageCollectionNames.attachmentStagingChunks,
      { stagingId },
      { chunkIndex: 1, _id: 1 },
    )) {
      const parsedChunk = parseStagedChunkDocument(chunkDocument);
      const chunk = parsedChunk.record;
      if (
        parsedChunk.stagingId !== stagingId ||
        parsedChunk.vaultId !== this.vault.id ||
        parsedChunk.attachmentId !== attachment.id ||
        parsedChunk.chunkIndex !== chunk.record.index ||
        chunk.record.vaultId !== this.vault.id ||
        chunk.record.groupId !== attachment.groupId ||
        chunk.record.itemId !== attachment.itemId ||
        chunk.record.attachmentId !== attachment.id ||
        !attachmentRecordHashMatchesCanonicalContent(chunk)
      ) {
        fail();
      }
      const advanced = advanceAttachmentStaging(start, progress, chunk);
      if (advanced.disposition !== 'staged') fail();
      progress = advanced.progress;
      yield this.#entry({ kind: 'attachment-chunk', record: chunk });
    }
    if (canonicalJson(progress) !== canonicalJson(staging.progress)) fail();
    validateAttachmentStagingFinalization(start, progress, {
      version: 1,
      record: attachment,
    });
  }

  async #assertChangeSequence(): Promise<void> {
    const latest = await this.#database
      .collection(mongoStorageCollectionNames.changes)
      .findOne(
        { vaultId: this.vault.id },
        {
          session: this.#session,
          signal: this.#signal,
          sort: { serverSequence: -1 },
        },
      );
    if (latest === null) {
      if (this.#counterChangeSequence !== 0) fail();
      return;
    }
    const parsed = storedChangeDocumentSchema.parse(latest);
    if (parsed.serverSequence !== this.#counterChangeSequence) fail();
  }

  async *#documents(
    collectionName: string,
    filter: Filter<Document>,
    sort: Sort,
  ): AsyncGenerator<Document> {
    checkAborted(this.#signal);
    const cursor: FindCursor<Document> = this.#database
      .collection(collectionName)
      .find(filter, {
        session: this.#session,
        signal: this.#signal,
        batchSize: CURSOR_BATCH_SIZE,
        sort,
        collation: SIMPLE_COLLATION,
      });
    try {
      while (await cursor.hasNext()) {
        checkAborted(this.#signal);
        const document = await cursor.next();
        if (document === null) fail();
        yield document;
      }
    } finally {
      await cursor.close();
    }
  }

  #entry(candidate: unknown): MongoBackupRecordEntry {
    const entry = this.#budget.accept(candidate);
    if (entry.kind === 'vault') fail();
    return entry;
  }

  #assertSchema(schemaVersion: number): void {
    if (schemaVersion !== this.vault.schemaVersion) fail();
  }

  async #release(): Promise<void> {
    if (this.#releasePromise !== undefined) return this.#releasePromise;
    this.#closed = true;
    this.#releasePromise = releaseSession(this.#session);
    try {
      await this.#releasePromise;
    } catch {
      throw new MongoBackupSourceError('BACKUP_SOURCE_FAILED');
    }
  }
}

class SourceBudget {
  readonly maximumBytes: number;
  readonly maximumRecords: number;
  #bytes = 0;
  #records = 0;

  constructor(maximumBytes: number, maximumRecords: number) {
    this.maximumBytes = maximumBytes;
    this.maximumRecords = maximumRecords;
  }

  accept(candidate: unknown): EncryptedBackupEntry {
    const parsed = encryptedBackupEntrySchema.safeParse(candidate);
    if (!parsed.success) fail();
    const nextRecords = this.#records + 1;
    const nextBytes = this.#bytes + canonicalEntryBytes(parsed.data);
    if (nextRecords > this.maximumRecords || nextBytes > this.maximumBytes) {
      tooLarge();
    }
    this.#records = nextRecords;
    this.#bytes = nextBytes;
    return parsed.data;
  }
}

function canonicalEntryBytes(entry: EncryptedBackupEntry): number {
  return Buffer.byteLength(canonicalJson(entry), 'utf8') + 1;
}

function sameRecordIdentity(
  current: EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord,
  predecessor: MongoBackupPredecessor,
  entityType: 'group' | 'item' | 'attachment',
): boolean {
  if (entityType === 'attachment') {
    return (
      'itemId' in current &&
      'itemId' in predecessor &&
      current.id === predecessor.id &&
      current.vaultId === predecessor.vaultId &&
      current.groupId === predecessor.groupId &&
      current.itemId === predecessor.itemId
    );
  }
  if (entityType === 'item') {
    return (
      'groupId' in current &&
      !('itemId' in current) &&
      'groupId' in predecessor &&
      !('itemId' in predecessor) &&
      current.id === predecessor.id &&
      current.vaultId === predecessor.vaultId &&
      current.groupId === predecessor.groupId
    );
  }
  return (
    !('groupId' in current) &&
    !('groupId' in predecessor) &&
    current.id === predecessor.id &&
    current.vaultId === predecessor.vaultId
  );
}

function isMongoBackupPredecessor(
  record: OpaqueSyncRecord,
): record is MongoBackupPredecessor {
  return !('state' in record) && !('revision' in record);
}

function tombstoneKey(
  entityType: TombstoneRecord['entityType'],
  entityId: string,
): string {
  return `${entityType}:${entityId}`;
}

function remember(
  visited: Map<CoveredCollection, Set<string>>,
  collection: CoveredCollection,
  id: string,
): void {
  const values = visited.get(collection);
  if (values === undefined || values.has(id)) fail();
  values.add(id);
}

function checkAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new MongoBackupSourceError('BACKUP_SOURCE_ABORTED');
  }
}

function fail(): never {
  throw new MongoBackupSourceError('BACKUP_SOURCE_FAILED');
}

function tooLarge(): never {
  throw new MongoBackupSourceError('BACKUP_SOURCE_TOO_LARGE');
}

function normalizeError(
  error: unknown,
  signal: AbortSignal | undefined,
): MongoBackupSourceError {
  if (signal?.aborted === true) {
    return new MongoBackupSourceError('BACKUP_SOURCE_ABORTED');
  }
  if (error instanceof MongoBackupSourceError) return error;
  return new MongoBackupSourceError('BACKUP_SOURCE_FAILED');
}

async function releaseSession(session: ClientSession | undefined): Promise<void> {
  if (session === undefined) return;
  let failed = false;
  try {
    if (session.inTransaction()) await session.abortTransaction();
  } catch {
    failed = true;
  }
  try {
    await session.endSession();
  } catch {
    failed = true;
  }
  if (failed) throw new MongoBackupSourceError('BACKUP_SOURCE_FAILED');
}

function messageForCode(code: MongoBackupSourceErrorCode): string {
  switch (code) {
    case 'BACKUP_SOURCE_ABORTED':
      return 'The encrypted backup read was cancelled.';
    case 'BACKUP_SOURCE_BUSY':
      return 'The encrypted backup snapshot is unavailable.';
    case 'BACKUP_SOURCE_TOO_LARGE':
      return 'The encrypted backup source exceeds its configured limits.';
    default:
      return 'The encrypted backup source could not be read safely.';
  }
}
