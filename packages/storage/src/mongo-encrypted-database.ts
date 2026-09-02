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
import {
  MongoCollaborativeVaultStore,
  type CollaborativeVaultStore,
  type CompactCollaborativeOperationOutcomeInput,
  type DestroyCollaborativeVaultInput,
  type MongoCollaborativeVaultCollectionNames,
} from './collaborative-vault-store.js';
import { assertMongoUriAllowed } from './mongo-local-vault.js';

const DEFAULT_DATABASE_COLLECTION = 'kavrix_databases';
const DEFAULT_VAULT_COLLECTION = 'kavrix_vaults';
const DEFAULT_COLLABORATIVE_VAULT_COLLECTION = 'kavrix_collaborative_vaults';
const DEFAULT_DATABASE_DEVICE_REGISTRY_COLLECTION =
  'kavrix_collaboration_device_registries';
const DEFAULT_OPERATION_OUTCOME_COLLECTION = 'kavrix_collaboration_operation_outcomes';
const DEFAULT_OPERATION_TOMBSTONE_COLLECTION =
  'kavrix_collaboration_operation_tombstones';
const DEFAULT_VAULT_DESTRUCTION_TOMBSTONE_COLLECTION =
  'kavrix_collaboration_vault_destruction_tombstones';
const DEFAULT_FINALIZED_MUTATION_LINK_COLLECTION =
  'kavrix_collaboration_finalized_mutation_links';
const DEFAULT_AUTHORIZATION_CHECKPOINT_COLLECTION =
  'kavrix_collaboration_authorization_checkpoints';
const MONGO_NAME_PATTERN = /^[A-Za-z0-9_-]{1,64}$/u;
const CONNECT_TIMEOUT_MS = 5_000;
const SOCKET_TIMEOUT_MS = 10_000;

type StoredDocument = Readonly<{ _id: string }> & Record<string, unknown>;

export type MongoEncryptedDatabaseStoreOptions = Readonly<{
  databaseCollectionName?: string;
  vaultCollectionName?: string;
  /** Dedicated collection for versioned collaborative vault documents. */
  collaborativeVaultCollectionName?: string;
  /** Dedicated singleton collection for signed database device registries. */
  databaseDeviceRegistryCollectionName?: string;
  /** Dedicated collection for full operation outcomes. */
  operationOutcomeCollectionName?: string;
  /** Dedicated, non-TTL collection for compact operation tombstones. */
  operationTombstoneCollectionName?: string;
  /** Dedicated permanent, non-TTL collection fencing destroyed vault identities. */
  vaultDestructionTombstoneCollectionName?: string;
  /** Dedicated append-only collection for finalized mutation proof links. */
  finalizedMutationLinkCollectionName?: string;
  /** Dedicated append-only collection for owner-signed authorization checkpoints. */
  authorizationCheckpointCollectionName?: string;
  /** Explicit operator opt-in to plaintext transport for non-local hosts. */
  allowInsecureTransport?: boolean;
}>;

/**
 * Transactional opaque storage for one encrypted database catalog and its vault
 * documents. MongoDB only receives validated ciphertext envelopes and routing
 * metadata; it never receives any unlock material or plaintext credentials.
 */
export class MongoEncryptedDatabaseStore
  implements EncryptedDatabaseStore, CollaborativeVaultStore
{
  readonly #client: MongoClient;
  readonly #database: Db;
  readonly #databases: Collection<StoredDocument>;
  readonly #vaults: Collection<StoredDocument>;
  readonly #collaboration: MongoCollaborativeVaultStore;
  #closed = false;

  private constructor(
    client: MongoClient,
    database: Db,
    collectionNames: Readonly<{
      databaseCollectionName: string;
      vaultCollectionName: string;
    }> &
      MongoCollaborativeVaultCollectionNames,
  ) {
    this.#client = client;
    this.#database = database;
    this.#databases = database.collection<StoredDocument>(
      collectionNames.databaseCollectionName,
    );
    this.#vaults = database.collection<StoredDocument>(
      collectionNames.vaultCollectionName,
    );
    this.#collaboration = new MongoCollaborativeVaultStore(
      client,
      database,
      collectionNames,
      this.#vaults,
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
        collaborativeVaultCollectionName: options.collaborativeVaultCollectionName,
        databaseDeviceRegistryCollectionName:
          options.databaseDeviceRegistryCollectionName,
        operationOutcomeCollectionName: options.operationOutcomeCollectionName,
        operationTombstoneCollectionName: options.operationTombstoneCollectionName,
        vaultDestructionTombstoneCollectionName:
          options.vaultDestructionTombstoneCollectionName,
        finalizedMutationLinkCollectionName:
          options.finalizedMutationLinkCollectionName,
        authorizationCheckpointCollectionName:
          options.authorizationCheckpointCollectionName,
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
        // Strict schemas model absent optionals as JSON omission. Without this,
        // BSON turns an explicitly present `undefined` into `null`, making a
        // value accepted before publication unparsable on readback or replay.
        ignoreUndefined: true,
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
    await this.#collaboration.initializeIndexes();
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

  async #assertTransactionCapable(): Promise<void> {
    try {
      const hello = (await this.#database.command({ hello: 1 })) as
        Record<string, unknown> | null | undefined;
      if (
        hello === null ||
        hello === undefined ||
        typeof hello !== 'object' ||
        typeof hello['setName'] === 'string' ||
        hello['msg'] === 'isdbgrid' ||
        hello['isWritablePrimary'] === false
      ) {
        return;
      }
      if (hello['ok'] === 1 || hello['ok'] === true) {
        // Standalone without replica set: writes that require transactions cannot succeed.
        throw new EncryptedDatabaseStoreError('unsupported');
      }
    } catch (error) {
      if (error instanceof EncryptedDatabaseStoreError && error.code === 'unsupported')
        throw error;
      return;
    }
  }

  async createDatabase(document: EncryptedDatabaseDocument): Promise<void> {
    this.#assertOpen();
    await this.#assertTransactionCapable();
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

  async getCollaborativeVault(
    databaseId: Parameters<CollaborativeVaultStore['getCollaborativeVault']>[0],
    vaultId: Parameters<CollaborativeVaultStore['getCollaborativeVault']>[1],
  ): ReturnType<CollaborativeVaultStore['getCollaborativeVault']> {
    this.#assertOpen();
    return this.#collaboration.getCollaborativeVault(databaseId, vaultId);
  }

  async discoverCollaborativeMemberships(
    databaseId: Parameters<
      CollaborativeVaultStore['discoverCollaborativeMemberships']
    >[0],
    discoveryTags: Parameters<
      CollaborativeVaultStore['discoverCollaborativeMemberships']
    >[1],
    limit?: Parameters<CollaborativeVaultStore['discoverCollaborativeMemberships']>[2],
  ): ReturnType<CollaborativeVaultStore['discoverCollaborativeMemberships']> {
    this.#assertOpen();
    return this.#collaboration.discoverCollaborativeMemberships(
      databaseId,
      discoveryTags,
      limit,
    );
  }

  async getDatabaseDeviceRegistry(
    databaseId: Parameters<CollaborativeVaultStore['getDatabaseDeviceRegistry']>[0],
  ): ReturnType<CollaborativeVaultStore['getDatabaseDeviceRegistry']> {
    this.#assertOpen();
    return this.#collaboration.getDatabaseDeviceRegistry(databaseId);
  }

  async publishDatabaseDeviceRegistry(
    candidate: Parameters<CollaborativeVaultStore['publishDatabaseDeviceRegistry']>[0],
  ): ReturnType<CollaborativeVaultStore['publishDatabaseDeviceRegistry']> {
    this.#assertOpen();
    return this.#collaboration.publishDatabaseDeviceRegistry(candidate);
  }

  async publishCollaborativeVault(
    input: Parameters<CollaborativeVaultStore['publishCollaborativeVault']>[0],
  ): ReturnType<CollaborativeVaultStore['publishCollaborativeVault']> {
    this.#assertOpen();
    return this.#collaboration.publishCollaborativeVault(input);
  }

  async destroyCollaborativeVault(
    input: DestroyCollaborativeVaultInput,
  ): ReturnType<CollaborativeVaultStore['destroyCollaborativeVault']> {
    this.#assertOpen();
    return this.#collaboration.destroyCollaborativeVault(input);
  }

  async getCollaborativeVaultDestructionTombstone(
    databaseId: Parameters<
      CollaborativeVaultStore['getCollaborativeVaultDestructionTombstone']
    >[0],
    vaultId: Parameters<
      CollaborativeVaultStore['getCollaborativeVaultDestructionTombstone']
    >[1],
  ): ReturnType<CollaborativeVaultStore['getCollaborativeVaultDestructionTombstone']> {
    this.#assertOpen();
    return this.#collaboration.getCollaborativeVaultDestructionTombstone(
      databaseId,
      vaultId,
    );
  }

  async getCollaborativeFinalizedMutationLinkByHead(
    databaseId: Parameters<
      CollaborativeVaultStore['getCollaborativeFinalizedMutationLinkByHead']
    >[0],
    vaultId: Parameters<
      CollaborativeVaultStore['getCollaborativeFinalizedMutationLinkByHead']
    >[1],
    resultingHeadDigest: Parameters<
      CollaborativeVaultStore['getCollaborativeFinalizedMutationLinkByHead']
    >[2],
  ): ReturnType<
    CollaborativeVaultStore['getCollaborativeFinalizedMutationLinkByHead']
  > {
    this.#assertOpen();
    return this.#collaboration.getCollaborativeFinalizedMutationLinkByHead(
      databaseId,
      vaultId,
      resultingHeadDigest,
    );
  }

  async getCollaborativeFinalizedMutationLinkByOperation(
    databaseId: Parameters<
      CollaborativeVaultStore['getCollaborativeFinalizedMutationLinkByOperation']
    >[0],
    vaultId: Parameters<
      CollaborativeVaultStore['getCollaborativeFinalizedMutationLinkByOperation']
    >[1],
    operationId: Parameters<
      CollaborativeVaultStore['getCollaborativeFinalizedMutationLinkByOperation']
    >[2],
  ): ReturnType<
    CollaborativeVaultStore['getCollaborativeFinalizedMutationLinkByOperation']
  > {
    this.#assertOpen();
    return this.#collaboration.getCollaborativeFinalizedMutationLinkByOperation(
      databaseId,
      vaultId,
      operationId,
    );
  }

  async getCollaborativeMutationProofRange(
    input: Parameters<CollaborativeVaultStore['getCollaborativeMutationProofRange']>[0],
  ): ReturnType<CollaborativeVaultStore['getCollaborativeMutationProofRange']> {
    this.#assertOpen();
    return this.#collaboration.getCollaborativeMutationProofRange(input);
  }

  async getCollaborationAuthorizationWitness(
    databaseId: Parameters<
      CollaborativeVaultStore['getCollaborationAuthorizationWitness']
    >[0],
    vaultId: Parameters<
      CollaborativeVaultStore['getCollaborationAuthorizationWitness']
    >[1],
    authorizationStateDigest: Parameters<
      CollaborativeVaultStore['getCollaborationAuthorizationWitness']
    >[2],
    atOrBeforeDocumentRevision: Parameters<
      CollaborativeVaultStore['getCollaborationAuthorizationWitness']
    >[3],
  ): ReturnType<CollaborativeVaultStore['getCollaborationAuthorizationWitness']> {
    this.#assertOpen();
    return this.#collaboration.getCollaborationAuthorizationWitness(
      databaseId,
      vaultId,
      authorizationStateDigest,
      atOrBeforeDocumentRevision,
    );
  }

  async appendCollaborationAuthorizationCheckpoint(
    checkpoint: Parameters<
      CollaborativeVaultStore['appendCollaborationAuthorizationCheckpoint']
    >[0],
  ): ReturnType<CollaborativeVaultStore['appendCollaborationAuthorizationCheckpoint']> {
    this.#assertOpen();
    return this.#collaboration.appendCollaborationAuthorizationCheckpoint(checkpoint);
  }

  async getCollaborationAuthorizationCheckpoint(
    databaseId: Parameters<
      CollaborativeVaultStore['getCollaborationAuthorizationCheckpoint']
    >[0],
    vaultId: Parameters<
      CollaborativeVaultStore['getCollaborationAuthorizationCheckpoint']
    >[1],
    checkpointDigest: Parameters<
      CollaborativeVaultStore['getCollaborationAuthorizationCheckpoint']
    >[2],
  ): ReturnType<CollaborativeVaultStore['getCollaborationAuthorizationCheckpoint']> {
    this.#assertOpen();
    return this.#collaboration.getCollaborationAuthorizationCheckpoint(
      databaseId,
      vaultId,
      checkpointDigest,
    );
  }

  async beginCollaborativeMigration(
    input: Parameters<CollaborativeVaultStore['beginCollaborativeMigration']>[0],
  ): ReturnType<CollaborativeVaultStore['beginCollaborativeMigration']> {
    this.#assertOpen();
    return this.#collaboration.beginCollaborativeMigration(input);
  }

  async activateCollaborativeGenesis(
    input: Parameters<CollaborativeVaultStore['activateCollaborativeGenesis']>[0],
  ): ReturnType<CollaborativeVaultStore['activateCollaborativeGenesis']> {
    this.#assertOpen();
    return this.#collaboration.activateCollaborativeGenesis(input);
  }

  async getCollaborativeOperationOutcome(
    databaseId: Parameters<
      CollaborativeVaultStore['getCollaborativeOperationOutcome']
    >[0],
    vaultId: Parameters<CollaborativeVaultStore['getCollaborativeOperationOutcome']>[1],
    operationId: Parameters<
      CollaborativeVaultStore['getCollaborativeOperationOutcome']
    >[2],
  ): ReturnType<CollaborativeVaultStore['getCollaborativeOperationOutcome']> {
    this.#assertOpen();
    return this.#collaboration.getCollaborativeOperationOutcome(
      databaseId,
      vaultId,
      operationId,
    );
  }

  async compactCollaborativeOperationOutcome(
    input: CompactCollaborativeOperationOutcomeInput,
  ): ReturnType<CollaborativeVaultStore['compactCollaborativeOperationOutcome']> {
    this.#assertOpen();
    return this.#collaboration.compactCollaborativeOperationOutcome(input);
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
): Readonly<
  {
    databaseCollectionName: string;
    vaultCollectionName: string;
  } & MongoCollaborativeVaultCollectionNames
> {
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
      (key) =>
        key === 'databaseCollectionName' ||
        key === 'vaultCollectionName' ||
        key === 'collaborativeVaultCollectionName' ||
        key === 'databaseDeviceRegistryCollectionName' ||
        key === 'operationOutcomeCollectionName' ||
        key === 'operationTombstoneCollectionName' ||
        key === 'vaultDestructionTombstoneCollectionName' ||
        key === 'finalizedMutationLinkCollectionName' ||
        key === 'authorizationCheckpointCollectionName',
    )
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  const optionValues = options as Record<string, unknown>;
  const databaseCollectionName =
    optionValues['databaseCollectionName'] ?? DEFAULT_DATABASE_COLLECTION;
  const vaultCollectionName =
    optionValues['vaultCollectionName'] ?? DEFAULT_VAULT_COLLECTION;
  const collaborativeVaultCollectionName =
    optionValues['collaborativeVaultCollectionName'] ??
    DEFAULT_COLLABORATIVE_VAULT_COLLECTION;
  const databaseDeviceRegistryCollectionName =
    optionValues['databaseDeviceRegistryCollectionName'] ??
    DEFAULT_DATABASE_DEVICE_REGISTRY_COLLECTION;
  const operationOutcomeCollectionName =
    optionValues['operationOutcomeCollectionName'] ??
    DEFAULT_OPERATION_OUTCOME_COLLECTION;
  const operationTombstoneCollectionName =
    optionValues['operationTombstoneCollectionName'] ??
    DEFAULT_OPERATION_TOMBSTONE_COLLECTION;
  const vaultDestructionTombstoneCollectionName =
    optionValues['vaultDestructionTombstoneCollectionName'] ??
    DEFAULT_VAULT_DESTRUCTION_TOMBSTONE_COLLECTION;
  const finalizedMutationLinkCollectionName =
    optionValues['finalizedMutationLinkCollectionName'] ??
    DEFAULT_FINALIZED_MUTATION_LINK_COLLECTION;
  const authorizationCheckpointCollectionName =
    optionValues['authorizationCheckpointCollectionName'] ??
    DEFAULT_AUTHORIZATION_CHECKPOINT_COLLECTION;
  const collectionNames = [
    databaseCollectionName,
    vaultCollectionName,
    collaborativeVaultCollectionName,
    databaseDeviceRegistryCollectionName,
    operationOutcomeCollectionName,
    operationTombstoneCollectionName,
    vaultDestructionTombstoneCollectionName,
    finalizedMutationLinkCollectionName,
    authorizationCheckpointCollectionName,
  ];
  if (
    typeof databaseCollectionName !== 'string' ||
    typeof vaultCollectionName !== 'string' ||
    typeof collaborativeVaultCollectionName !== 'string' ||
    typeof databaseDeviceRegistryCollectionName !== 'string' ||
    typeof operationOutcomeCollectionName !== 'string' ||
    typeof operationTombstoneCollectionName !== 'string' ||
    typeof vaultDestructionTombstoneCollectionName !== 'string' ||
    typeof finalizedMutationLinkCollectionName !== 'string' ||
    typeof authorizationCheckpointCollectionName !== 'string' ||
    !MONGO_NAME_PATTERN.test(databaseCollectionName) ||
    !MONGO_NAME_PATTERN.test(vaultCollectionName) ||
    !MONGO_NAME_PATTERN.test(collaborativeVaultCollectionName) ||
    !MONGO_NAME_PATTERN.test(databaseDeviceRegistryCollectionName) ||
    !MONGO_NAME_PATTERN.test(operationOutcomeCollectionName) ||
    !MONGO_NAME_PATTERN.test(operationTombstoneCollectionName) ||
    !MONGO_NAME_PATTERN.test(vaultDestructionTombstoneCollectionName) ||
    !MONGO_NAME_PATTERN.test(finalizedMutationLinkCollectionName) ||
    !MONGO_NAME_PATTERN.test(authorizationCheckpointCollectionName) ||
    new Set(collectionNames).size !== collectionNames.length
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  return {
    databaseCollectionName,
    vaultCollectionName,
    collaborativeVaultCollectionName,
    databaseDeviceRegistryCollectionName,
    operationOutcomeCollectionName,
    operationTombstoneCollectionName,
    vaultDestructionTombstoneCollectionName,
    finalizedMutationLinkCollectionName,
    authorizationCheckpointCollectionName,
  };
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

function isStandaloneTransactionError(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const candidate = error as Record<string, unknown>;
  const message = typeof candidate['message'] === 'string' ? candidate['message'] : '';
  return (
    message.includes('Transaction numbers are only allowed') ||
    message.includes('not support multi-document transactions') ||
    message.includes('Transactions are not supported on standalone')
  );
}

function mapOperationError(error: unknown): EncryptedDatabaseStoreError {
  if (error instanceof EncryptedDatabaseStoreError) return error;
  if (isDuplicateKeyError(error)) return new EncryptedDatabaseStoreError('exists');
  if (isStandaloneTransactionError(error))
    return new EncryptedDatabaseStoreError('unsupported');
  return new EncryptedDatabaseStoreError('operation');
}
