import { z } from 'zod';
import type { CreateCollectionOptions, Db, Document } from 'mongodb';

import {
  assertMongoStorageCompatibility,
  installMongoStorageContracts,
} from '@kavrix/storage';

import {
  assertMongoApiCompatibility,
  installMongoApiContracts,
} from './mongo-persistence.js';

export const MONGO_SCHEMA_VERSION = 1 as const;
export const MONGO_SCHEMA_STATE_COLLECTION = '_kavrix_schema_state' as const;
const MONGO_SCHEMA_MIGRATION_ID = 'baseline-contracts-v1' as const;

const mongoSchemaStateSchema = z
  .object({
    _id: z.literal('kavrix'),
    schemaVersion: z.literal(MONGO_SCHEMA_VERSION),
    migrationId: z.literal(MONGO_SCHEMA_MIGRATION_ID),
    appliedAt: z.iso.datetime({ offset: true }),
  })
  .strict();

const storedSchemaVersionSchema = z.looseObject({
  schemaVersion: z.number().int().nonnegative(),
});

type MongoSchemaStateRecord = Document & { readonly _id: string };

const mongoSchemaStateCollectionOptions: CreateCollectionOptions = {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['_id', 'schemaVersion', 'migrationId', 'appliedAt'],
      additionalProperties: false,
      properties: {
        _id: { bsonType: 'string', enum: ['kavrix'] },
        schemaVersion: { bsonType: 'int', enum: [MONGO_SCHEMA_VERSION] },
        migrationId: { bsonType: 'string', enum: [MONGO_SCHEMA_MIGRATION_ID] },
        appliedAt: { bsonType: 'string' },
      },
    } as Document,
  },
  validationLevel: 'strict',
  validationAction: 'error',
};

export type MongoSchemaStateDocument = z.infer<typeof mongoSchemaStateSchema>;

export class MongoSchemaCompatibilityError extends Error {
  public constructor() {
    super('Mongo schema compatibility check failed');
    this.name = 'MongoSchemaCompatibilityError';
  }
}

/** Installs the canonical DDL and records the exact schema contract. */
export async function migrateMongoApiDatabase(
  database: Db,
  now: () => Date = () => new Date(),
): Promise<MongoSchemaStateDocument> {
  await assertExistingStateCanAdvance(database);
  await installMongoStorageContracts(database);
  await installMongoApiContracts(database);
  await assertMongoStorageCompatibility(database);
  await assertMongoApiCompatibility(database);
  await ensureSchemaStateCollection(database);

  const state = mongoSchemaStateSchema.parse({
    _id: 'kavrix',
    schemaVersion: MONGO_SCHEMA_VERSION,
    migrationId: MONGO_SCHEMA_MIGRATION_ID,
    appliedAt: now().toISOString(),
  });
  await database
    .collection<MongoSchemaStateDocument>(MONGO_SCHEMA_STATE_COLLECTION)
    .replaceOne({ _id: 'kavrix' }, state, { upsert: true });
  return state;
}

/** Validates the recorded migration and all opaque application documents without DDL. */
export async function assertMongoApiDatabaseCompatibility(database: Db): Promise<void> {
  const state = await database
    .collection<MongoSchemaStateRecord>(MONGO_SCHEMA_STATE_COLLECTION)
    .findOne({ _id: 'kavrix' });
  if (!mongoSchemaStateSchema.safeParse(state).success) {
    throw new MongoSchemaCompatibilityError();
  }
  await assertMongoStorageCompatibility(database);
  await assertMongoApiCompatibility(database);
}

async function assertExistingStateCanAdvance(database: Db): Promise<void> {
  const existing = await database
    .collection<MongoSchemaStateRecord>(MONGO_SCHEMA_STATE_COLLECTION)
    .findOne({ _id: 'kavrix' });
  if (existing === null) return;

  const version = storedSchemaVersionSchema.safeParse(existing);
  if (!version.success || version.data.schemaVersion > MONGO_SCHEMA_VERSION) {
    throw new MongoSchemaCompatibilityError();
  }
  if (!mongoSchemaStateSchema.safeParse(existing).success) {
    throw new MongoSchemaCompatibilityError();
  }
}

async function ensureSchemaStateCollection(database: Db): Promise<void> {
  const existing = await database
    .listCollections({ name: MONGO_SCHEMA_STATE_COLLECTION }, { nameOnly: true })
    .toArray();
  if (existing.length === 0) {
    await database.createCollection(
      MONGO_SCHEMA_STATE_COLLECTION,
      mongoSchemaStateCollectionOptions,
    );
    return;
  }
  await database.command({
    collMod: MONGO_SCHEMA_STATE_COLLECTION,
    validator: mongoSchemaStateCollectionOptions.validator,
    validationLevel: mongoSchemaStateCollectionOptions.validationLevel,
    validationAction: mongoSchemaStateCollectionOptions.validationAction,
  });
}
