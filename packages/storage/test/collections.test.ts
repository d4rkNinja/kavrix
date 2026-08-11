import { describe, expect, it } from 'vitest';

import {
  aeadEnvelopeFragment,
  canonicalTimestampFragment,
  keySlotFragment,
  mongoStorageCollectionNames,
  mongoStorageCollectionOptions,
  mongoStorageIndexes,
  nonnegativeSemanticRevisionFragment,
  opaqueIdentifierFragment,
  persistedAttachmentChunkFragment,
  sha256DigestFragment,
  supportedCryptographicVersionFragment,
  supportedSchemaVersionFragment,
} from '../src/index.js';

interface TestMongoSchema {
  bsonType?: string | readonly string[];
  required?: readonly string[];
  additionalProperties?: boolean;
  properties?: Record<string, TestMongoSchema>;
  oneOf?: readonly TestMongoSchema[];
  enum?: readonly unknown[];
  items?: TestMongoSchema;
  minItems?: number;
  maxItems?: number;
  uniqueItems?: boolean;
  multipleOf?: number;
  minimum?: number;
  maximum?: number;
}

function requireValue<T>(value: T | undefined, message: string): T {
  if (value === undefined) throw new Error(message);
  return value;
}

function collectionSchema(
  name: keyof typeof mongoStorageCollectionOptions,
): TestMongoSchema {
  const validator = mongoStorageCollectionOptions[name].validator as
    Record<string, unknown> | undefined;
  expect(validator).toBeDefined();
  return requireValue(
    validator?.['$jsonSchema'] as TestMongoSchema | undefined,
    `missing validator for ${name}`,
  );
}

function property(schema: TestMongoSchema, ...path: string[]): TestMongoSchema {
  let current = schema;
  for (const segment of path) {
    const next = current.properties?.[segment];
    expect(next, `missing Mongo validator path ${path.join('.')}`).toBeDefined();
    current = requireValue(next, `missing Mongo validator path ${path.join('.')}`);
  }
  return current;
}

function branch(
  schema: TestMongoSchema,
  discriminator: string,
  value: string,
): TestMongoSchema {
  const match = branchMatching(schema, { [discriminator]: value });
  expect(match, `missing ${discriminator}=${value} branch`).toBeDefined();
  return requireValue(match, `missing ${discriminator}=${value} branch`);
}

function branchMatching(
  schema: TestMongoSchema,
  discriminators: Readonly<Record<string, string>>,
): TestMongoSchema | undefined {
  return schema.oneOf?.find((candidate) =>
    Object.entries(discriminators).every(([name, value]) =>
      candidate.properties?.[name]?.enum?.includes(value),
    ),
  );
}

function expectExactBranch(
  schema: TestMongoSchema,
  discriminator: string,
  value: string,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const selected = branch(schema, discriminator, value);
  expect(selected.additionalProperties).toBe(false);
  expect([...(selected.required ?? [])].sort()).toEqual([...required].sort());
  expect(Object.keys(selected.properties ?? {}).sort()).toEqual(
    [...required, ...optional].sort(),
  );
}

function walkSchemas(
  schema: TestMongoSchema,
  visit: (schema: TestMongoSchema) => void,
): void {
  visit(schema);
  for (const child of Object.values(schema.properties ?? {})) walkSchemas(child, visit);
  for (const child of schema.oneOf ?? []) walkSchemas(child, visit);
  if (schema.items !== undefined) walkSchemas(schema.items, visit);
}

describe('Mongo collection definitions', () => {
  it('defines strict validators for every collection', () => {
    const names = Object.values(mongoStorageCollectionNames);
    expect(Object.keys(mongoStorageCollectionOptions).sort()).toEqual(
      [...names].sort(),
    );
    for (const name of names) {
      const options = mongoStorageCollectionOptions[name];
      expect(options.validationAction).toBe('error');
      expect(options.validationLevel).toBe('strict');
      const jsonSchema = options.validator?.['$jsonSchema'] as
        | {
            additionalProperties?: boolean;
            oneOf?: { additionalProperties?: boolean }[];
          }
        | undefined;
      expect(
        jsonSchema?.additionalProperties === false ||
          jsonSchema?.oneOf?.every(
            ({ additionalProperties }) => additionalProperties === false,
          ),
      ).toBe(true);
    }
  });

  it('contains no plaintext credential fields in persisted validator shapes', () => {
    const validators = JSON.stringify(mongoStorageCollectionOptions);
    for (const forbidden of [
      '"title"',
      '"username"',
      '"password"',
      '"secretValue"',
      '"decrypted"',
    ]) {
      expect(validators).not.toContain(forbidden);
    }
    expect(validators).toContain('"ciphertext"');
    expect(validators).toContain('"authenticationTag"');
  });

  it('composes canonical shared fragments into persisted record roots', () => {
    const vault = property(collectionSchema('vaults'), 'record');
    expect(property(vault, 'id')).toBe(opaqueIdentifierFragment);
    expect(property(vault, 'schemaVersion')).toBe(supportedSchemaVersionFragment);
    expect(property(vault, 'cryptographicVersion')).toBe(
      supportedCryptographicVersionFragment,
    );
    expect(property(vault, 'keySlots').items).toBe(keySlotFragment);
    expect(property(vault, 'revision')).toBe(nonnegativeSemanticRevisionFragment);
    expect(property(vault, 'encryptedPreferences')).toBe(aeadEnvelopeFragment);
    expect(property(vault, 'createdAt')).toBe(canonicalTimestampFragment);

    expect(property(collectionSchema('items'), 'record', 'ciphertextHash')).toBe(
      sha256DigestFragment,
    );
    expect(property(collectionSchema('attachment_staging_chunks'), 'record')).toBe(
      persistedAttachmentChunkFragment,
    );
  });

  it('bounds every persisted numeric and array fragment without Decimal128', () => {
    let numericCount = 0;
    let arrayCount = 0;
    for (const name of Object.values(mongoStorageCollectionNames)) {
      walkSchemas(collectionSchema(name), (schema) => {
        if (schema.bsonType !== undefined && typeof schema.bsonType !== 'string') {
          const numericTypes = schema.bsonType.filter((type) =>
            ['int', 'long', 'double', 'decimal'].includes(type),
          );
          if (numericTypes.length > 0) {
            numericCount += 1;
            expect(schema.bsonType).toEqual(['int', 'long', 'double']);
            expect(schema.multipleOf).toBe(1);
            expect(Number.isSafeInteger(schema.minimum)).toBe(true);
            expect(Number.isSafeInteger(schema.maximum)).toBe(true);
            const minimum = requireValue(schema.minimum, 'missing numeric minimum');
            const maximum = requireValue(schema.maximum, 'missing numeric maximum');
            expect(minimum).toBeLessThanOrEqual(maximum);
          }
        }
        if (schema.bsonType === 'array') {
          arrayCount += 1;
          expect(Number.isSafeInteger(schema.minItems)).toBe(true);
          expect(Number.isSafeInteger(schema.maxItems)).toBe(true);
          const minItems = requireValue(schema.minItems, 'missing array minimum');
          const maxItems = requireValue(schema.maxItems, 'missing array maximum');
          expect(minItems).toBeLessThanOrEqual(maxItems);
        }
      });
    }
    expect(numericCount).toBeGreaterThan(0);
    expect(arrayCount).toBeGreaterThan(0);

    const vaultSlots = property(collectionSchema('vaults'), 'record', 'keySlots');
    expect(vaultSlots).toMatchObject({ minItems: 1, maxItems: 128 });
    const runningResults = property(
      branch(collectionSchema('sync_push_batches'), 'state', 'running'),
      'results',
    );
    expect(runningResults).toMatchObject({ minItems: 0, maxItems: 100 });
    const completed = branch(
      collectionSchema('sync_push_batches'),
      'state',
      'completed',
    );
    expect(property(completed, 'results')).toMatchObject({
      minItems: 1,
      maxItems: 100,
    });
    expect(property(completed, 'response', 'results')).toMatchObject({
      minItems: 1,
      maxItems: 100,
    });
    expect(
      property(
        collectionSchema('template_migration_publications'),
        'response',
        'results',
      ),
    ).toMatchObject({ minItems: 1, maxItems: 100 });
  });

  it('closes every composed BSON object and pins direct format versions to v1', () => {
    for (const name of Object.values(mongoStorageCollectionNames)) {
      walkSchemas(collectionSchema(name), (schema) => {
        if (schema.bsonType !== 'object') return;
        expect(schema.additionalProperties).toBe(false);
        expect(schema.required).toBeDefined();
        for (const required of schema.required ?? []) {
          expect(schema.properties).toHaveProperty(required);
        }
      });
    }

    const vault = property(collectionSchema('vaults'), 'record');
    expect(property(vault, 'schemaVersion').enum).toEqual([1]);
    expect(property(vault, 'cryptographicVersion').enum).toEqual([1]);
    const activeStaging = branch(
      collectionSchema('attachment_staging'),
      'state',
      'active',
    );
    expect(property(activeStaging, 'input', 'version').enum).toEqual([1]);
    expect(
      property(
        collectionSchema('attachment_staging_chunks'),
        'record',
        'record',
        'schemaVersion',
      ).enum,
    ).toEqual([1]);
  });

  it('closes state-dependent storage documents with exact branches', () => {
    const syncRunning = [
      '_id',
      'vaultId',
      'batchIdempotencyKey',
      'requestHash',
      'mutationCount',
      'state',
      'nextMutationIndex',
      'results',
      'createdAt',
      'updatedAt',
    ] as const;
    expectExactBranch(
      collectionSchema('sync_push_batches'),
      'state',
      'running',
      syncRunning,
    );
    expectExactBranch(collectionSchema('sync_push_batches'), 'state', 'completed', [
      ...syncRunning,
      'response',
      'completedAt',
    ]);

    const stagingCommon = [
      '_id',
      'vaultId',
      'attachmentId',
      'idempotencyKey',
      'inputHash',
      'state',
      'createdAt',
      'updatedAt',
    ] as const;
    expectExactBranch(collectionSchema('attachment_staging'), 'state', 'active', [
      ...stagingCommon,
      'input',
      'progress',
    ]);
    expectExactBranch(collectionSchema('attachment_staging'), 'state', 'finalized', [
      ...stagingCommon,
      'input',
      'progress',
      'finalizeHash',
      'finalizedAt',
    ]);
    expectExactBranch(collectionSchema('attachment_staging'), 'state', 'aborted', [
      ...stagingCommon,
      'abortedAt',
    ]);

    const restoreCommon = [
      '_id',
      'restoreSessionId',
      'maximumBytes',
      'maximumRecords',
      'state',
      'stagedBytes',
      'stagedRecords',
      'createdAt',
      'updatedAt',
    ] as const;
    expectExactBranch(
      collectionSchema('backup_restore_sessions'),
      'state',
      'staging',
      restoreCommon,
      ['vaultId'],
    );
    expectExactBranch(
      collectionSchema('backup_restore_sessions'),
      'state',
      'committed',
      [
        ...restoreCommon,
        'vaultId',
        'transcriptSha256',
        'summaryRecordCount',
        'committedAt',
      ],
    );
    expectExactBranch(
      collectionSchema('backup_restore_sessions'),
      'state',
      'aborted',
      [...restoreCommon, 'abortedAt'],
      ['vaultId'],
    );

    const tombstone = property(collectionSchema('tombstones'), 'record');
    for (const entityType of ['vault', 'group', 'item', 'attachment']) {
      const deleted = branchMatching(tombstone, { entityType, state: 'deleted' });
      const restored = branchMatching(tombstone, {
        entityType,
        state: 'restored',
      });
      expect(deleted).toBeDefined();
      expect(restored).toBeDefined();
      const deletedBranch = requireValue(deleted, 'missing deleted branch');
      const restoredBranch = requireValue(restored, 'missing restored branch');
      expect(deletedBranch.required).not.toContain('restoredAt');
      expect(deletedBranch.properties).not.toHaveProperty('restoredAt');
      expect(deletedBranch.properties).toHaveProperty('purgeAfter');
      expect(restoredBranch.required).toContain('restoredAt');
      expect(restoredBranch.properties).not.toHaveProperty('purgeAfter');
    }

    const progress = property(
      branch(collectionSchema('attachment_staging'), 'state', 'active'),
      'progress',
    );
    const progressCommon = [
      'version',
      'state',
      'nextChunkIndex',
      'totalPlaintextBytes',
      'totalCiphertextBytes',
    ] as const;
    expectExactBranch(progress, 'state', 'empty', progressCommon);
    const progressWithLastChunk = [
      ...progressCommon,
      'lastChunkIndex',
      'lastChunkCiphertextHash',
      'lastChunkPlaintextBytes',
    ] as const;
    expectExactBranch(progress, 'state', 'writing', progressWithLastChunk);
    expect(
      property(branch(progress, 'state', 'writing'), 'nextChunkIndex'),
    ).toMatchObject({ minimum: 1, maximum: 999_999 });
    expectExactBranch(progress, 'state', 'ready-to-finalize', progressWithLastChunk);
    expect(
      property(branch(progress, 'state', 'ready-to-finalize'), 'nextChunkIndex'),
    ).toMatchObject({ minimum: 1, maximum: 1_000_000 });

    const syncResults = property(
      branch(collectionSchema('sync_push_batches'), 'state', 'running'),
      'results',
    );
    const syncResultItems = requireValue(
      syncResults.items,
      'missing sync result items',
    );
    expectExactBranch(syncResultItems, 'status', 'accepted', [
      'status',
      'idempotencyKey',
      'disposition',
      'change',
    ]);
    expectExactBranch(syncResultItems, 'status', 'conflict', [
      'status',
      'idempotencyKey',
      'currentRevision',
      'current',
    ]);

    const change = property(collectionSchema('changes'), 'record');
    for (const entityType of ['vault', 'group', 'item', 'attachment']) {
      for (const operation of ['upsert', 'tombstone', 'restore', 'purge']) {
        const candidate = branchMatching(change, { entityType, operation });
        expect(candidate).toBeDefined();
        const changeBranch = requireValue(candidate, 'missing change branch');
        expect(property(changeBranch, 'ciphertextHash')).toBe(sha256DigestFragment);
        if (operation === 'purge') {
          expect(changeBranch.required).not.toContain('ciphertextHash');
        } else {
          expect(changeBranch.required).toContain('ciphertextHash');
        }
      }
    }

    const backupEntry = property(collectionSchema('backup_restore_entries'), 'entry');
    const kinds = (backupEntry.oneOf ?? [])
      .flatMap((candidate) => candidate.properties?.['kind']?.enum ?? [])
      .filter((kind): kind is string => typeof kind === 'string');
    expect(kinds).toEqual([
      'vault',
      'group',
      'item',
      'attachment',
      'attachment-header',
      'attachment-chunk',
      'audit',
      'history',
      'tombstone-predecessor',
      'tombstone',
    ]);
    for (const kind of kinds) {
      const entry = branch(backupEntry, 'kind', kind);
      expect(entry.additionalProperties).toBe(false);
      expect(entry.required).toContain('record');
      expect(entry.properties).toHaveProperty('record');
    }
    const predecessor = branch(backupEntry, 'kind', 'tombstone-predecessor');
    expect(predecessor.required).toContain('entityType');
    expect(property(predecessor, 'record').oneOf).toHaveLength(3);
  });

  it('uniquely indexes revision, idempotency, and contiguous staging identities', () => {
    expect(mongoStorageIndexes.changes).toContainEqual(
      expect.objectContaining({
        key: { vaultId: 1, serverSequence: 1 },
        unique: true,
      }),
    );
    expect(mongoStorageIndexes.idempotency_commits).toContainEqual(
      expect.objectContaining({
        key: { vaultId: 1, idempotencyKey: 1 },
        unique: true,
      }),
    );
    expect(mongoStorageIndexes.attachment_staging_chunks).toContainEqual(
      expect.objectContaining({
        key: { stagingId: 1, chunkIndex: 1 },
        unique: true,
      }),
    );
    expect(mongoStorageIndexes.backup_restore_entries).toContainEqual(
      expect.objectContaining({
        key: { restoreSessionId: 1, ordinal: 1 },
        unique: true,
      }),
    );
  });
});
