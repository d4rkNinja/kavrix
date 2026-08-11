import type { Db, MongoClient } from 'mongodb';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import {
  MONGO_DOCUMENT_ID_UNAVAILABLE,
  MONGO_DOCUMENT_PREFLIGHT_BATCH_SIZE,
  MongoDocumentCompatibilityError,
  MongoDocumentPreflightError,
  assertMongoDocumentCompatibility,
  type MongoDocumentSchemaMap,
} from '../src/mongo-document-preflight.js';
import {
  MongoBackupRestoreStore,
  MongoVaultStorage,
  assertMongoStorageCompatibility,
  attachmentStagingDocumentSchema,
  backupRestoreEntryDocumentSchema,
  backupRestoreSessionDocumentSchema,
  idempotencyDocumentSchema,
  initializeMongoStorage,
  installMongoStorageContracts,
  mongoStorageCollectionNames,
  mongoStorageDocumentSchemas,
  mongoStorageIndexes,
  stagedAttachmentChunkDocumentSchema,
  storageCounterDocumentSchema,
  storedAttachmentDocumentSchema,
  storedAuditDocumentSchema,
  storedChangeDocumentSchema,
  storedGroupDocumentSchema,
  storedHistoryDocumentSchema,
  storedItemDocumentSchema,
  storedTombstoneDocumentSchema,
  storedVaultDocumentSchema,
  syncPushBatchDocumentSchema,
  templateMigrationPublicationDocumentSchema,
} from '../src/index.js';

type CursorBehavior = Readonly<{
  rows?: readonly unknown[];
  iterationError?: Error;
  closeError?: Error;
}>;

class TestCursor {
  public yielded = 0;
  public readonly toArray = vi.fn(() =>
    Promise.reject(new Error('scanner-toArray-canary')),
  );
  public readonly close = vi.fn((): Promise<void> => {
    return this.#behavior.closeError === undefined
      ? Promise.resolve()
      : Promise.reject(this.#behavior.closeError);
  });
  readonly #behavior: CursorBehavior;
  #index = 0;
  #iterationFailureRaised = false;

  public constructor(behavior: CursorBehavior) {
    this.#behavior = behavior;
  }

  public readonly hasNext = vi.fn((): Promise<boolean> => {
    if (this.#index < (this.#behavior.rows?.length ?? 0)) {
      return Promise.resolve(true);
    }
    if (this.#behavior.iterationError !== undefined && !this.#iterationFailureRaised) {
      this.#iterationFailureRaised = true;
      return Promise.reject(this.#behavior.iterationError);
    }
    return Promise.resolve(false);
  });

  public readonly next = vi.fn((): Promise<unknown> => {
    const row = this.#behavior.rows?.[this.#index] ?? null;
    this.#index += 1;
    if (row !== null) this.yielded += 1;
    return Promise.resolve(row);
  });
}

function scannerDatabase(behaviors: Readonly<Record<string, CursorBehavior>>): {
  readonly database: Db;
  readonly cursors: readonly TestCursor[];
  readonly findCalls: readonly Readonly<{
    collectionName: string;
    filter: unknown;
    options: unknown;
  }>[];
} {
  const cursors: TestCursor[] = [];
  const findCalls: {
    collectionName: string;
    filter: unknown;
    options: unknown;
  }[] = [];
  const database = {
    collection: (collectionName: string) => ({
      find: (filter: unknown, options: unknown) => {
        findCalls.push({ collectionName, filter, options });
        const cursor = new TestCursor(behaviors[collectionName] ?? {});
        cursors.push(cursor);
        return cursor;
      },
    }),
  };
  return { database: database as unknown as Db, cursors, findCalls };
}

const valueSchema = z
  .object({
    _id: z.string(),
    value: z.literal('valid'),
  })
  .strict();

describe('Mongo document compatibility preflight', () => {
  it('streams empty and valid collections with an explicit small batch and closes every cursor', async () => {
    const schemas = {
      empty_documents: valueSchema,
      valid_documents: valueSchema,
    } satisfies MongoDocumentSchemaMap<'empty_documents' | 'valid_documents'>;
    const fixture = scannerDatabase({
      empty_documents: { rows: [] },
      valid_documents: {
        rows: [
          { _id: 'document.one', value: 'valid' },
          { _id: 'document.two', value: 'valid' },
        ],
      },
    });

    await expect(
      assertMongoDocumentCompatibility(fixture.database, schemas),
    ).resolves.toBeUndefined();

    expect(MONGO_DOCUMENT_PREFLIGHT_BATCH_SIZE).toBeGreaterThan(0);
    expect(MONGO_DOCUMENT_PREFLIGHT_BATCH_SIZE).toBeLessThanOrEqual(100);
    expect(fixture.findCalls).toEqual([
      {
        collectionName: 'empty_documents',
        filter: {},
        options: { batchSize: MONGO_DOCUMENT_PREFLIGHT_BATCH_SIZE },
      },
      {
        collectionName: 'valid_documents',
        filter: {},
        options: { batchSize: MONGO_DOCUMENT_PREFLIGHT_BATCH_SIZE },
      },
    ]);
    expect(fixture.cursors).toHaveLength(2);
    for (const cursor of fixture.cursors) {
      expect(cursor.toArray).not.toHaveBeenCalled();
      expect(cursor.close).toHaveBeenCalledOnce();
    }
  });

  it('stops at the first invalid row and exposes only its collection and safe ID', async () => {
    const schema = z
      .object({
        _id: z.string(),
        value: z.literal('valid'),
        opaquePayloadCanary: z.string().optional(),
      })
      .strict()
      .superRefine((document, context) => {
        if (document._id === 'document.invalid') {
          context.addIssue({ code: 'custom', message: 'zod-issue-canary' });
        }
      });
    const fixture = scannerDatabase({
      canonical_documents: {
        rows: [
          { _id: 'document.first', value: 'valid' },
          {
            _id: 'document.invalid',
            value: 'valid',
            opaquePayloadCanary: 'document-content-canary',
          },
          { _id: 'document.unreached', value: 'valid' },
        ],
      },
    });

    const error = await assertMongoDocumentCompatibility(fixture.database, {
      canonical_documents: schema,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(MongoDocumentCompatibilityError);
    expect(error).toMatchObject({
      collectionName: 'canonical_documents',
      documentId: 'document.invalid',
    });
    expect(fixture.cursors[0]?.yielded).toBe(2);
    expect(fixture.cursors[0]?.close).toHaveBeenCalledOnce();
    expect(publicErrorText(error)).not.toContain('document-content-canary');
    expect(publicErrorText(error)).not.toContain('zod-issue-canary');
    expect(publicErrorText(error)).not.toContain('document.unreached');
    expect(error).not.toHaveProperty('cause');
  });

  it('converts a throwing canonical parser into the same sanitized compatibility error', async () => {
    const fixture = scannerDatabase({
      canonical_documents: {
        rows: [{ _id: 'document.invalid', opaquePayload: 'document-canary' }],
      },
    });

    const error = await assertMongoDocumentCompatibility(fixture.database, {
      canonical_documents: {
        safeParse: () => {
          throw new Error('parser-document-canary');
        },
      },
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(MongoDocumentCompatibilityError);
    expect(error).toMatchObject({ documentId: 'document.invalid' });
    expect(publicErrorText(error)).not.toContain('parser-document-canary');
    expect(publicErrorText(error)).not.toContain('opaquePayload');
    expect(error).not.toHaveProperty('cause');
    expect(fixture.cursors[0]?.close).toHaveBeenCalledOnce();
  });

  it.each([
    ['non-string', 42],
    ['control-bearing', 'document.\u001B]8;;https://unsafe.invalid\u0007canary'],
    ['space-bearing', 'document unsafe'],
    ['Unicode-bearing', 'document.\u202Ecanary'],
    ['oversized', `document.${'x'.repeat(1_024)}`],
  ])('replaces a %s document ID with a fixed safe placeholder', async (_label, id) => {
    const fixture = scannerDatabase({
      canonical_documents: { rows: [{ _id: id, value: 'invalid' }] },
    });

    const error = await assertMongoDocumentCompatibility(fixture.database, {
      canonical_documents: valueSchema,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(MongoDocumentCompatibilityError);
    expect(error).toMatchObject({ documentId: MONGO_DOCUMENT_ID_UNAVAILABLE });
    expect(publicErrorText(error)).not.toContain(String(id));
    expect(fixture.cursors[0]?.close).toHaveBeenCalledOnce();
  });

  it('redacts otherwise safe identifiers when the caller marks IDs sensitive', async () => {
    const fixture = scannerDatabase({
      api_sessions: { rows: [{ _id: 'tokenHashSafeLookingValue', value: 'invalid' }] },
    });

    const error = await assertMongoDocumentCompatibility(
      fixture.database,
      { api_sessions: valueSchema },
      { redactDocumentIds: true },
    ).catch((caught: unknown) => caught);

    expect(error).toMatchObject({ documentId: MONGO_DOCUMENT_ID_UNAVAILABLE });
    expect(publicErrorText(error)).not.toContain('tokenHashSafeLookingValue');
  });

  it('preserves the sanitized invalid-row error when cursor close also fails', async () => {
    const fixture = scannerDatabase({
      canonical_documents: {
        rows: [{ _id: 'document.invalid', value: 'invalid' }],
        closeError: new Error('close-mongodb://operator:secret@host/canary'),
      },
    });

    const error = await assertMongoDocumentCompatibility(fixture.database, {
      canonical_documents: valueSchema,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(MongoDocumentCompatibilityError);
    expect(error).toMatchObject({ documentId: 'document.invalid' });
    expect(publicErrorText(error)).not.toContain('operator:secret');
    expect(error).not.toHaveProperty('cause');
    expect(fixture.cursors[0]?.close).toHaveBeenCalledOnce();
  });

  it.each(['iteration', 'close'] as const)(
    'sanitizes a raw cursor %s failure without attaching its cause',
    async (failure) => {
      const canary = `${failure}-mongodb://operator:secret@host/canary`;
      const fixture = scannerDatabase({
        canonical_documents: {
          rows: [{ _id: 'document.valid', value: 'valid' }],
          ...(failure === 'iteration' ? { iterationError: new Error(canary) } : {}),
          ...(failure === 'close' ? { closeError: new Error(canary) } : {}),
        },
      });

      const error = await assertMongoDocumentCompatibility(fixture.database, {
        canonical_documents: valueSchema,
      }).catch((caught: unknown) => caught);

      expect(error).toBeInstanceOf(MongoDocumentPreflightError);
      expect(error).not.toBeInstanceOf(MongoDocumentCompatibilityError);
      expect(error).toMatchObject({ collectionName: 'canonical_documents' });
      expect(publicErrorText(error)).not.toContain(canary);
      expect(error).not.toHaveProperty('cause');
      expect(fixture.cursors[0]?.close).toHaveBeenCalledOnce();
    },
  );
});

describe('Mongo storage preflight composition', () => {
  it('maps every declared storage collection to its exact canonical parser', () => {
    expect(Object.keys(mongoStorageDocumentSchemas).sort()).toEqual(
      Object.values(mongoStorageCollectionNames).sort(),
    );
    expect(mongoStorageDocumentSchemas).toEqual({
      vaults: storedVaultDocumentSchema,
      groups: storedGroupDocumentSchema,
      items: storedItemDocumentSchema,
      attachments: storedAttachmentDocumentSchema,
      audits: storedAuditDocumentSchema,
      histories: storedHistoryDocumentSchema,
      changes: storedChangeDocumentSchema,
      tombstones: storedTombstoneDocumentSchema,
      vault_counters: storageCounterDocumentSchema,
      idempotency_commits: idempotencyDocumentSchema,
      sync_push_batches: syncPushBatchDocumentSchema,
      template_migration_publications: templateMigrationPublicationDocumentSchema,
      attachment_staging: attachmentStagingDocumentSchema,
      attachment_staging_chunks: stagedAttachmentChunkDocumentSchema,
      backup_restore_sessions: backupRestoreSessionDocumentSchema,
      backup_restore_entries: backupRestoreEntryDocumentSchema,
    });
  });

  it('keeps contract installation and compatibility scanning as explicit phases', async () => {
    const names = Object.values(mongoStorageCollectionNames);
    const fixture = storageInitializationDatabase(
      names.filter((_name, index) => index % 2 === 0),
    );

    await installMongoStorageContracts(fixture.database);
    expect(fixture.scanNames).toEqual([]);

    await assertMongoStorageCompatibility(fixture.database);
    expect(fixture.scanNames).toEqual(Object.values(mongoStorageCollectionNames));
    expect(fixture.installWasCompleteBeforeEveryScan()).toBe(true);
  });

  it.each([
    [
      'combined storage initializer',
      (database: Db) => initializeMongoStorage(database),
    ],
    [
      'vault adapter initializer',
      (database: Db) => new MongoVaultStorage({} as MongoClient, database).initialize(),
    ],
    [
      'backup-restore adapter initializer',
      (database: Db) =>
        new MongoBackupRestoreStore({} as MongoClient, database).initialize(),
    ],
  ])(
    '%s installs every contract before scanning every collection',
    async (_name, run) => {
      const fixture = storageInitializationDatabase();

      await run(fixture.database);

      expect(fixture.scanNames).toEqual(Object.values(mongoStorageCollectionNames));
      expect(fixture.installWasCompleteBeforeEveryScan()).toBe(true);
      expect(fixture.cursors).toHaveLength(
        Object.values(mongoStorageCollectionNames).length,
      );
      for (const cursor of fixture.cursors) {
        expect(cursor.close).toHaveBeenCalledOnce();
      }
    },
  );
});

function storageInitializationDatabase(existingNames: readonly string[] = []): {
  readonly database: Db;
  readonly scanNames: readonly string[];
  readonly cursors: readonly TestCursor[];
  installWasCompleteBeforeEveryScan(): boolean;
} {
  const expectedNames = Object.values(mongoStorageCollectionNames);
  const namesRequiringIndexes = expectedNames.filter(
    (name) => mongoStorageIndexes[name].length > 0,
  );
  const installed = new Set<string>();
  const indexed = new Set<string>();
  const scanNames: string[] = [];
  const cursors: TestCursor[] = [];
  let installWasComplete = true;
  const database = {
    listCollections: () => ({
      toArray: () => Promise.resolve(existingNames.map((name) => ({ name }))),
    }),
    command: (command: Readonly<{ collMod: string }>) => {
      installed.add(command.collMod);
      return Promise.resolve({});
    },
    createCollection: (name: string) => {
      installed.add(name);
      return Promise.resolve({});
    },
    collection: (name: string) => ({
      createIndexes: () => {
        indexed.add(name);
        return Promise.resolve([]);
      },
      find: () => {
        scanNames.push(name);
        if (
          expectedNames.some((expected) => !installed.has(expected)) ||
          namesRequiringIndexes.some((expected) => !indexed.has(expected))
        ) {
          installWasComplete = false;
        }
        const cursor = new TestCursor({ rows: [] });
        cursors.push(cursor);
        return cursor;
      },
    }),
  };
  return {
    database: database as unknown as Db,
    scanNames,
    cursors,
    installWasCompleteBeforeEveryScan: () => installWasComplete,
  };
}

function publicErrorText(error: unknown): string {
  if (!(error instanceof Error)) return String(error);
  return `${error.name}\n${error.message}\n${JSON.stringify(error)}`;
}
