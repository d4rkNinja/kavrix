import { MongoClient, type ClientSession, type Collection, type Db } from 'mongodb';

import {
  databaseIdSchema,
  databaseRevisionSchema,
  databaseVaultDocumentSchema,
  encryptedDatabaseDocumentSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type DatabaseId,
  type DatabaseRevision,
  type DatabaseVaultDocument,
  type EncryptedDatabaseDocument,
  type VaultId,
  type VaultRevision,
} from '@kavrix/schemas';

import {
  EncryptedDatabaseStoreError,
  type CreateVaultInput,
  type DeleteVaultInput,
  type EncryptedDatabaseStore,
  type UpdateVaultInput,
} from './encrypted-database-store.js';
import { assertMongoUriAllowed } from './mongo-local-vault.js';

const DEFAULT_DATABASE_COLLECTION = 'kavrix_databases';
const DEFAULT_VAULT_COLLECTION = 'kavrix_vaults';
const MONGO_NAME_PATTERN = /^[A-Za-z0-9_-]{1,64}$/u;
const CONNECT_TIMEOUT_MS = 5_000;
const SOCKET_TIMEOUT_MS = 10_000;

type StoredDocument = Readonly<{ _id: string }> & Record<string, unknown>;

export type MongoEncryptedDatabaseStoreOptions = Readonly<{
  databaseCollectionName?: string;
  vaultCollectionName?: string;
  /** Explicit operator opt-in to plaintext transport for non-local hosts. */
  allowInsecureTransport?: boolean;
}>;

/**
 * Transactional opaque storage for one encrypted database catalog and its vault
 * documents. MongoDB only receives validated ciphertext envelopes and routing
 * metadata; it never receives any unlock material or plaintext credentials.
 */
export class MongoEncryptedDatabaseStore implements EncryptedDatabaseStore {
  readonly #client: MongoClient;
  readonly #database: Db;
  readonly #databases: Collection<StoredDocument>;
  readonly #vaults: Collection<StoredDocument>;
  #closed = false;

  private constructor(
    client: MongoClient,
    database: Db,
    collectionNames: Readonly<{
      databaseCollectionName: string;
      vaultCollectionName: string;
    }>,
  ) {
    this.#client = client;
    this.#database = database;
    this.#databases = database.collection<StoredDocument>(
      collectionNames.databaseCollectionName,
    );
    this.#vaults = database.collection<StoredDocument>(
      collectionNames.vaultCollectionName,
    );
  }

  static async connect(
    uri: string,
    databaseName: string,
    options: MongoEncryptedDatabaseStoreOptions = {},
  ): Promise<MongoEncryptedDatabaseStore> {
    const allowInsecureTransport = options.allowInsecureTransport === true;
    const collectionNames = parseConfiguration(
      uri,
      databaseName,
      {
        databaseCollectionName: options.databaseCollectionName,
        vaultCollectionName: options.vaultCollectionName,
      },
      { allowInsecureTransport },
    );
    let client: MongoClient | undefined;
    try {
      client = new MongoClient(uri, {
        connectTimeoutMS: CONNECT_TIMEOUT_MS,
        serverSelectionTimeoutMS: CONNECT_TIMEOUT_MS,
        socketTimeoutMS: SOCKET_TIMEOUT_MS,
        timeoutMS: SOCKET_TIMEOUT_MS,
      });
      await client.connect();
      const store = new MongoEncryptedDatabaseStore(
        client,
        client.db(databaseName),
        collectionNames,
      );
      await store.#initializeIndexes();
      return store;
    } catch {
      if (client !== undefined) {
        try {
          await client.close();
        } catch {
          // The canonical connection error is safer than exposing cleanup details.
        }
      }
      throw new EncryptedDatabaseStoreError('connection');
    }
  }

  async #initializeIndexes(): Promise<void> {
    // MongoDB cannot create a collection inside the transaction that first
    // touches it, so both collections must be materialized before any CAS
    // write. Index creation auto-creates the parent collection and is
    // idempotent, which keeps first use race-free on an empty deployment.
    const listing = this.#database.listCollections({
      name: this.#databases.collectionName,
    });
    const listed =
      typeof listing.toArray === 'function'
        ? await listing.toArray()
        : await Promise.resolve(listing as unknown as { name: string }[]);
    if (listed.length === 0) {
      await this.#database.createCollection(this.#databases.collectionName);
    }
    await this.#vaults.createIndex(
      { databaseId: 1, id: 1 },
      { name: 'database_vault_identity', unique: true },
    );
  }

  async ping(): Promise<void> {
    this.#assertOpen();
    try {
      await this.#database.command({ ping: 1 });
    } catch {
      throw new EncryptedDatabaseStoreError('connection');
    }
  }

  async getDatabase(databaseId: DatabaseId): Promise<EncryptedDatabaseDocument | null> {
    this.#assertOpen();
    const id = parseDatabaseId(databaseId);
    try {
      const stored = await this.#databases.findOne(
        { _id: id },
        { projection: { _id: 0 } },
      );
      return stored === null ? null : parseStoredDatabase(stored);
    } catch (error: unknown) {
      throw mapOperationError(error);
    }
  }

  async createDatabase(document: EncryptedDatabaseDocument): Promise<void> {
    this.#assertOpen();
    const parsed = parseDatabaseDocument(document);
    try {
      await this.#databases.insertOne({ ...parsed, _id: parsed.id });
    } catch (error: unknown) {
      throw mapOperationError(error);
    }
  }

  async updateDatabase(
    document: EncryptedDatabaseDocument,
    expectedRevision: DatabaseRevision,
  ): Promise<void> {
    this.#assertOpen();
    const parsed = parseDatabaseDocument(document);
    const expected = parseDatabaseRevision(expectedRevision);
    assertNextRevision(parsed.revision, expected);
    try {
      const result = await this.#databases.updateOne(
        { _id: parsed.id, revision: expected },
        { $set: parsed },
      );
      if (result.matchedCount !== 1) throw new EncryptedDatabaseStoreError('conflict');
    } catch (error: unknown) {
      throw mapOperationError(error);
    }
  }

  async listVaults(databaseId: DatabaseId): Promise<readonly DatabaseVaultDocument[]> {
    this.#assertOpen();
    const id = parseDatabaseId(databaseId);
    try {
      const rows = await this.#vaults
        .find({ databaseId: id }, { projection: { _id: 0 } })
        .sort({ id: 1 })
        .toArray();
      return rows.map((row) => parseStoredVault(row));
    } catch (error: unknown) {
      throw mapOperationError(error);
    }
  }

  async getVault(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<DatabaseVaultDocument | null> {
    this.#assertOpen();
    const database = parseDatabaseId(databaseId);
    const vault = parseVaultId(vaultId);
    try {
      const stored = await this.#vaults.findOne(
        { _id: vaultKey(database, vault), databaseId: database },
        { projection: { _id: 0 } },
      );
      return stored === null ? null : parseStoredVault(stored);
    } catch (error: unknown) {
      throw mapOperationError(error);
    }
  }

  async createVault(input: CreateVaultInput): Promise<void> {
    this.#assertOpen();
    const { database, expectedDatabaseRevision, vault } = parseCreateVaultInput(input);
    validateCreateVaultInput(database, expectedDatabaseRevision, vault);

    await this.#runCatalogTransaction(async (session) => {
      const databaseResult = await this.#databases.updateOne(
        { _id: database.id, revision: expectedDatabaseRevision },
        { $set: database },
        { session },
      );
      if (databaseResult.matchedCount !== 1) {
        throw new EncryptedDatabaseStoreError('conflict');
      }
      const vaultResult = await this.#vaults.insertOne(
        { ...vault, _id: vaultKey(vault.databaseId, vault.id) },
        { session },
      );
      if (
        !vaultResult.acknowledged ||
        vaultResult.insertedId !== vaultKey(vault.databaseId, vault.id)
      ) {
        throw new EncryptedDatabaseStoreError('operation');
      }
    });
  }

  async updateVault(input: UpdateVaultInput): Promise<void> {
    this.#assertOpen();
    const { vault, expectedVaultRevision: expected } = parseUpdateVaultInput(input);
    assertNextRevision(vault.revision, expected);
    try {
      const result = await this.#vaults.updateOne(
        {
          _id: vaultKey(vault.databaseId, vault.id),
          databaseId: vault.databaseId,
          revision: expected,
        },
        { $set: vault },
      );
      if (result.matchedCount !== 1) throw new EncryptedDatabaseStoreError('conflict');
    } catch (error: unknown) {
      throw mapOperationError(error);
    }
  }

  async deleteVault(input: DeleteVaultInput): Promise<void> {
    this.#assertOpen();
    const { database, expectedDatabaseRevision, vaultId, expectedVaultRevision } =
      parseDeleteVaultInput(input);
    assertNextRevision(database.revision, expectedDatabaseRevision);

    await this.#runCatalogTransaction(async (session) => {
      const databaseResult = await this.#databases.updateOne(
        { _id: database.id, revision: expectedDatabaseRevision },
        { $set: database },
        { session },
      );
      if (databaseResult.matchedCount !== 1) {
        throw new EncryptedDatabaseStoreError('conflict');
      }
      const vaultResult = await this.#vaults.deleteOne(
        {
          _id: vaultKey(database.id, vaultId),
          databaseId: database.id,
          revision: expectedVaultRevision,
        },
        { session },
      );
      if (vaultResult.deletedCount !== 1)
        throw new EncryptedDatabaseStoreError('conflict');
    });
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    try {
      await this.#client.close();
    } catch {
      throw new EncryptedDatabaseStoreError('operation');
    }
  }

  async #runCatalogTransaction(
    operation: (session: ClientSession) => Promise<void>,
  ): Promise<void> {
    try {
      await this.#client.withSession(async (session) =>
        session.withTransaction(operation, {
          readConcern: { level: 'snapshot' },
          writeConcern: { w: 'majority' },
        }),
      );
    } catch (error: unknown) {
      throw mapOperationError(error);
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new EncryptedDatabaseStoreError('closed');
  }
}

function parseConfiguration(
  uri: unknown,
  databaseName: unknown,
  options: unknown,
  transport: Readonly<{ allowInsecureTransport?: boolean }> = {},
): Readonly<{ databaseCollectionName: string; vaultCollectionName: string }> {
  if (typeof uri !== 'string') throw new EncryptedDatabaseStoreError('connection');
  try {
    assertMongoUriAllowed(uri, transport);
  } catch {
    throw new EncryptedDatabaseStoreError('connection');
  }
  if (typeof databaseName !== 'string' || !MONGO_NAME_PATTERN.test(databaseName)) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  if (
    typeof options !== 'object' ||
    options === null ||
    Array.isArray(options) ||
    !Object.keys(options).every(
      (key) => key === 'databaseCollectionName' || key === 'vaultCollectionName',
    )
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  const optionValues = options as Record<string, unknown>;
  const databaseCollectionName =
    optionValues['databaseCollectionName'] ?? DEFAULT_DATABASE_COLLECTION;
  const vaultCollectionName =
    optionValues['vaultCollectionName'] ?? DEFAULT_VAULT_COLLECTION;
  if (
    typeof databaseCollectionName !== 'string' ||
    typeof vaultCollectionName !== 'string' ||
    !MONGO_NAME_PATTERN.test(databaseCollectionName) ||
    !MONGO_NAME_PATTERN.test(vaultCollectionName) ||
    databaseCollectionName === vaultCollectionName
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  return { databaseCollectionName, vaultCollectionName };
}

function parseDatabaseId(value: unknown): DatabaseId {
  try {
    return databaseIdSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseVaultId(value: unknown): VaultId {
  try {
    return vaultIdSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseDatabaseRevision(value: unknown): DatabaseRevision {
  try {
    return databaseRevisionSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseVaultRevision(value: unknown): VaultRevision {
  try {
    return vaultRevisionSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseDatabaseDocument(value: unknown): EncryptedDatabaseDocument {
  try {
    return encryptedDatabaseDocumentSchema.parse(structuredClone(value));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseVaultDocument(value: unknown): DatabaseVaultDocument {
  try {
    return databaseVaultDocumentSchema.parse(structuredClone(value));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseCreateVaultInput(input: unknown): Readonly<{
  database: EncryptedDatabaseDocument;
  expectedDatabaseRevision: DatabaseRevision;
  vault: DatabaseVaultDocument;
}> {
  const fields = parseInputRecord(input);
  return {
    database: parseDatabaseDocument(fields['database']),
    expectedDatabaseRevision: parseDatabaseRevision(fields['expectedDatabaseRevision']),
    vault: parseVaultDocument(fields['vault']),
  };
}

function parseUpdateVaultInput(input: unknown): Readonly<{
  expectedVaultRevision: VaultRevision;
  vault: DatabaseVaultDocument;
}> {
  const fields = parseInputRecord(input);
  return {
    vault: parseVaultDocument(fields['vault']),
    expectedVaultRevision: parseVaultRevision(fields['expectedVaultRevision']),
  };
}

function parseDeleteVaultInput(input: unknown): Readonly<{
  database: EncryptedDatabaseDocument;
  expectedDatabaseRevision: DatabaseRevision;
  expectedVaultRevision: VaultRevision;
  vaultId: VaultId;
}> {
  const fields = parseInputRecord(input);
  return {
    database: parseDatabaseDocument(fields['database']),
    expectedDatabaseRevision: parseDatabaseRevision(fields['expectedDatabaseRevision']),
    vaultId: parseVaultId(fields['vaultId']),
    expectedVaultRevision: parseVaultRevision(fields['expectedVaultRevision']),
  };
}

function parseInputRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  return value as Record<string, unknown>;
}

function parseStoredDatabase(value: StoredDocument): EncryptedDatabaseDocument {
  return parseDatabaseDocument(withoutMongoId(value));
}

function parseStoredVault(value: StoredDocument): DatabaseVaultDocument {
  return parseVaultDocument(withoutMongoId(value));
}

function withoutMongoId(value: StoredDocument): Record<string, unknown> {
  const { _id: mongoId, ...document } = value;
  void mongoId;
  return document;
}

function assertNextRevision(actual: number, expected: number): void {
  if (actual !== expected + 1) throw new EncryptedDatabaseStoreError('invalid');
}

function validateCreateVaultInput(
  database: EncryptedDatabaseDocument,
  expectedDatabaseRevision: DatabaseRevision,
  vault: DatabaseVaultDocument,
): void {
  assertNextRevision(database.revision, expectedDatabaseRevision);
  if (
    vault.databaseId !== database.id ||
    vault.databaseRevision !== database.revision
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function vaultKey(databaseId: DatabaseId, vaultId: VaultId): string {
  return `${databaseId}:${vaultId}`;
}

function isDuplicateKeyError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 11_000
  );
}

function mapOperationError(error: unknown): EncryptedDatabaseStoreError {
  if (error instanceof EncryptedDatabaseStoreError) return error;
  if (isDuplicateKeyError(error)) return new EncryptedDatabaseStoreError('exists');
  return new EncryptedDatabaseStoreError('operation');
}
