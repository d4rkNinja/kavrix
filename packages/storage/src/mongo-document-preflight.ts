import {
  MAX_OPAQUE_ID_CHARS,
  MIN_OPAQUE_ID_CHARS,
  OPAQUE_ID_PATTERN_SOURCE,
} from '@kavrix/schemas';
import type { Db, Document, FindCursor } from 'mongodb';

export const MONGO_DOCUMENT_PREFLIGHT_BATCH_SIZE = 100;
export const MONGO_DOCUMENT_ID_UNAVAILABLE = 'unavailable';

export interface MongoDocumentRuntimeSchema {
  safeParse(input: unknown): { readonly success: boolean };
}

export type MongoDocumentSchemaMap<CollectionName extends string = string> = Readonly<
  Record<CollectionName, MongoDocumentRuntimeSchema>
>;

export type MongoDocumentPreflightOptions = Readonly<{
  redactDocumentIds?: boolean;
}>;

export class MongoDocumentCompatibilityError extends Error {
  public readonly collectionName: string;
  public readonly documentId: string;

  public constructor(collectionName: string, documentId: string) {
    super(
      `Mongo document compatibility check failed in ${collectionName} at ${documentId}`,
    );
    this.name = 'MongoDocumentCompatibilityError';
    this.collectionName = collectionName;
    this.documentId = documentId;
  }
}

export class MongoDocumentPreflightError extends Error {
  public readonly collectionName: string;

  public constructor(collectionName: string) {
    super(`Mongo document preflight failed for ${collectionName}`);
    this.name = 'MongoDocumentPreflightError';
    this.collectionName = collectionName;
  }
}

const opaqueIdPattern = new RegExp(OPAQUE_ID_PATTERN_SOURCE, 'u');

export async function assertMongoDocumentCompatibility<CollectionName extends string>(
  database: Db,
  schemas: MongoDocumentSchemaMap<CollectionName>,
  options: MongoDocumentPreflightOptions = {},
): Promise<void> {
  for (const collectionName of Object.keys(schemas) as CollectionName[]) {
    await assertCollectionCompatibility(
      database,
      collectionName,
      schemas[collectionName],
      options.redactDocumentIds === true,
    );
  }
}

async function assertCollectionCompatibility(
  database: Db,
  collectionName: string,
  schema: MongoDocumentRuntimeSchema,
  redactDocumentIds: boolean,
): Promise<void> {
  let cursor: FindCursor<Document>;
  try {
    cursor = database
      .collection(collectionName)
      .find({}, { batchSize: MONGO_DOCUMENT_PREFLIGHT_BATCH_SIZE });
  } catch {
    throw new MongoDocumentPreflightError(collectionName);
  }

  let failure:
    MongoDocumentCompatibilityError | MongoDocumentPreflightError | undefined;
  try {
    while (await cursor.hasNext()) {
      const document = await cursor.next();
      let compatible = false;
      try {
        compatible = schema.safeParse(document).success;
      } catch {
        compatible = false;
      }
      if (!compatible) {
        failure = new MongoDocumentCompatibilityError(
          collectionName,
          safeDocumentId(document, redactDocumentIds),
        );
        break;
      }
    }
  } catch {
    failure = new MongoDocumentPreflightError(collectionName);
  } finally {
    try {
      await cursor.close();
    } catch {
      failure ??= new MongoDocumentPreflightError(collectionName);
    }
  }
  if (failure !== undefined) throw failure;
}

function safeDocumentId(document: unknown, redact: boolean): string {
  if (redact || typeof document !== 'object' || document === null) {
    return MONGO_DOCUMENT_ID_UNAVAILABLE;
  }
  let candidate: unknown;
  try {
    candidate = (document as Readonly<{ _id?: unknown }>)._id;
  } catch {
    return MONGO_DOCUMENT_ID_UNAVAILABLE;
  }
  if (
    typeof candidate !== 'string' ||
    candidate.length < MIN_OPAQUE_ID_CHARS ||
    candidate.length > MAX_OPAQUE_ID_CHARS ||
    !opaqueIdPattern.test(candidate)
  ) {
    return MONGO_DOCUMENT_ID_UNAVAILABLE;
  }
  return candidate;
}
