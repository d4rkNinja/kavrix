import { MongoClient, MongoServerError, type Collection, type Db } from 'mongodb';

import {
  localVaultDocumentSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type LocalVaultDocument,
} from '@kavrix/schemas';

import {
  EncryptedVaultStoreError,
  type EncryptedVaultStore,
} from './encrypted-vault-store.js';

const DEFAULT_COLLECTION_NAME = 'kavrix_vaults';
const COLLECTION_NAME_PATTERN = /^[A-Za-z0-9_-]{1,64}$/u;

interface StoredLocalVaultDocument {
  _id: string;
  [key: string]: unknown;
}

export type MongoLocalVaultErrorCode =
  'conflict' | 'connection' | 'exists' | 'invalid' | 'operation';

export class MongoLocalVaultError extends EncryptedVaultStoreError {
  constructor(code: MongoLocalVaultErrorCode) {
    const message =
      code === 'conflict'
        ? 'The vault changed while this command was running.'
        : code === 'exists'
          ? 'A vault already exists in this database.'
          : code === 'invalid'
            ? 'The database contains an invalid Kavrix vault document.'
            : code === 'connection'
              ? 'The database connection failed.'
              : 'The database operation failed.';
    super(code, message);
    this.name = 'MongoLocalVaultError';
  }
}

export type MongoLocalVaultStoreOptions = Readonly<{
  collectionName?: string;
  /** Explicit operator opt-in to plaintext transport for non-local hosts. */
  allowInsecureTransport?: boolean;
}>;

export class MongoLocalVaultStore implements EncryptedVaultStore {
  readonly #client: MongoClient;
  readonly #database: Db;
  readonly #collection: Collection<StoredLocalVaultDocument>;

  private constructor(
    client: MongoClient,
    database: Db,
    options: MongoLocalVaultStoreOptions = {},
  ) {
    const collectionName = options.collectionName ?? DEFAULT_COLLECTION_NAME;
    if (!COLLECTION_NAME_PATTERN.test(collectionName)) {
      throw new MongoLocalVaultError('invalid');
    }
    this.#client = client;
    this.#database = database;
    this.#collection = database.collection(collectionName);
  }

  static async connect(
    uri: string,
    databaseName: string,
    options: MongoLocalVaultStoreOptions = {},
  ): Promise<MongoLocalVaultStore> {
    assertMongoUriAllowed(uri, {
      allowInsecureTransport: options.allowInsecureTransport === true,
    });
    const client = new MongoClient(uri, {
      serverSelectionTimeoutMS: 5_000,
      connectTimeoutMS: 5_000,
      socketTimeoutMS: 10_000,
      timeoutMS: 10_000,
    });
    try {
      await client.connect();
      return new MongoLocalVaultStore(client, client.db(databaseName), options);
    } catch {
      await client.close().catch(() => undefined);
      throw new MongoLocalVaultError('connection');
    }
  }

  async ping(): Promise<void> {
    try {
      await this.#database.command({ ping: 1 });
    } catch {
      throw new MongoLocalVaultError('connection');
    }
  }

  async get(vaultId: string): Promise<LocalVaultDocument | null> {
    const id = parseVaultId(vaultId);
    try {
      const stored = await this.#collection.findOne({ _id: id });
      return stored === null ? null : parseStoredDocument(stored);
    } catch (error: unknown) {
      if (error instanceof MongoLocalVaultError) throw error;
      throw new MongoLocalVaultError('operation');
    }
  }

  async listVaultIds(): Promise<string[]> {
    try {
      const rows = await this.#collection
        .find({}, { projection: { _id: 1 } })
        .sort({ _id: 1 })
        .toArray();
      return rows.map((row) => parseVaultId(row._id));
    } catch (error: unknown) {
      if (error instanceof MongoLocalVaultError) throw error;
      throw new MongoLocalVaultError('operation');
    }
  }

  async create(document: LocalVaultDocument): Promise<void> {
    const parsed = parseDocument(document);
    try {
      await this.#collection.insertOne({ ...parsed, _id: parsed.id });
    } catch (error: unknown) {
      if (error instanceof MongoServerError && error.code === 11_000) {
        throw new MongoLocalVaultError('exists');
      }
      throw new MongoLocalVaultError('operation');
    }
  }

  async update(
    document: LocalVaultDocument,
    expectedRevision: LocalVaultDocument['revision'],
  ): Promise<void> {
    const parsed = parseDocument(document);
    if (parsed.revision !== expectedRevision + 1) {
      throw new MongoLocalVaultError('invalid');
    }
    const expected = parseRevision(expectedRevision);
    try {
      const result = await this.#collection.updateOne(
        { _id: parsed.id, revision: expected },
        {
          $set: {
            version: parsed.version,
            encryptedPayload: parsed.encryptedPayload,
            keySlot: parsed.keySlot,
            recoverySlots: parsed.recoverySlots,
            currentKeyVersion: parsed.currentKeyVersion,
            revision: parsed.revision,
            updatedAt: parsed.updatedAt,
          },
        },
      );
      if (result.matchedCount !== 1) {
        throw new MongoLocalVaultError('conflict');
      }
    } catch (error: unknown) {
      if (error instanceof MongoLocalVaultError) throw error;
      throw new MongoLocalVaultError('operation');
    }
  }

  async delete(
    vaultId: string,
    expectedRevision: LocalVaultDocument['revision'],
  ): Promise<void> {
    const id = parseVaultId(vaultId);
    const expected = parseRevision(expectedRevision);
    try {
      const result = await this.#collection.deleteOne({ _id: id, revision: expected });
      if (result.deletedCount !== 1) throw new MongoLocalVaultError('conflict');
    } catch (error: unknown) {
      if (error instanceof MongoLocalVaultError) throw error;
      throw new MongoLocalVaultError('operation');
    }
  }

  async close(): Promise<void> {
    await this.#client.close();
  }
}

function parseVaultId(value: unknown): string {
  try {
    return vaultIdSchema.parse(value);
  } catch {
    throw new MongoLocalVaultError('invalid');
  }
}

function parseRevision(value: unknown): LocalVaultDocument['revision'] {
  try {
    return vaultRevisionSchema.parse(value);
  } catch {
    throw new MongoLocalVaultError('invalid');
  }
}

function parseDocument(value: unknown): LocalVaultDocument {
  try {
    return localVaultDocumentSchema.parse(value);
  } catch {
    throw new MongoLocalVaultError('invalid');
  }
}

function parseStoredDocument(value: StoredLocalVaultDocument): LocalVaultDocument {
  const withoutMongoId: Record<string, unknown> = {};
  for (const [key, fieldValue] of Object.entries(value)) {
    if (key !== '_id') withoutMongoId[key] = fieldValue;
  }
  return parseDocument(withoutMongoId);
}

/**
 * Fail-closed URI policy: insecure-TLS flags are always rejected, and remote
 * hosts require explicit TLS unless the caller passes an explicit
 * allow-insecure-transport opt-in (an operator's conscious choice for
 * isolated networks); local loopback is exempt from the TLS requirement.
 */
export function assertMongoUriAllowed(
  uri: string,
  transport: Readonly<{ allowInsecureTransport?: boolean }> = {},
): void {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new MongoLocalVaultError('connection');
  }
  if (parsed.protocol !== 'mongodb:' && parsed.protocol !== 'mongodb+srv:') {
    throw new MongoLocalVaultError('connection');
  }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/gu, '');
  if (hostname.length === 0) throw new MongoLocalVaultError('connection');

  const isLocal =
    hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  const parameters = new Map<string, string[]>();
  for (const [name, value] of parsed.searchParams.entries()) {
    const normalizedName = name.toLowerCase();
    const values = parameters.get(normalizedName) ?? [];
    values.push(value.trim().toLowerCase());
    parameters.set(normalizedName, values);
  }
  const valuesFor = (name: string): string[] =>
    parameters.get(name.toLowerCase()) ?? [];
  const tlsValues = ['tls', 'ssl'].flatMap((name) => valuesFor(name));
  if (tlsValues.some(isFalse)) throw new MongoLocalVaultError('connection');
  for (const parameter of [
    'tlsInsecure',
    'tlsAllowInvalidCertificates',
    'tlsAllowInvalidHostnames',
    'sslInsecure',
    'sslAllowInvalidCertificates',
    'sslAllowInvalidHostnames',
  ]) {
    if (valuesFor(parameter).some(isTrue)) throw new MongoLocalVaultError('connection');
  }
  if (valuesFor('sslValidate').some(isFalse)) {
    throw new MongoLocalVaultError('connection');
  }
  if (
    !isLocal &&
    !tlsValues.some(isTrue) &&
    transport.allowInsecureTransport !== true
  ) {
    throw new MongoLocalVaultError('connection');
  }
}

function isTrue(value: string): boolean {
  return value === 'true' || value === '1' || value === 'yes' || value === 'on';
}

function isFalse(value: string): boolean {
  return value === 'false' || value === '0' || value === 'no' || value === 'off';
}
