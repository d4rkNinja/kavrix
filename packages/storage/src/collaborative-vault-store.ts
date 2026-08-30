import type { ClientSession, Collection, Db, MongoClient } from 'mongodb';

import {
  COLLABORATION_GENESIS_HEAD_DIGEST,
  collaborationAuthorizationCheckpointSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationMutationProofEntrySchema,
  collaborationMutationProofSchema,
  collaborationMigrationActiveMarkerSchema,
  collaborationMigrationMarkerSchema,
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationRequestSchema,
  collaborationOperationIdSchema,
  collaborationVaultDestructionTombstoneSchema,
  collaborativeVaultDocumentSchema,
  databaseVaultDocumentSchema,
  databaseIdSchema,
  durableOperationOutcomeSchema,
  operationDeduplicationTombstoneSchema,
  revisionSchema,
  sha256DigestSchema,
  vaultIdSchema,
  type CollaborationAuthorizationCheckpoint,
  type CollaborationAuthorizationWitness,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationDiscoveryRecord,
  type CollaborationFinalizedMutationLink,
  type CollaborationMigrationActiveMarker,
  type CollaborationMigrationPreparedMarker,
  type CollaborationMigrationRequest,
  type CollaborationMutationProof,
  type CollaborationVaultDestructionTombstone,
  type CollaborativeVaultDocument,
  type DatabaseId,
  type DatabaseVaultDocument,
  type DurableOperationOutcome,
  type OperationDeduplicationTombstone,
  type Sha256Digest,
  type VaultId,
} from '@kavrix/schemas';

import {
  EncryptedDatabaseStoreError,
  type EncryptedDatabaseStoreErrorCode,
} from './encrypted-database-store.js';

/**
 * The opaque persistence port for the Mongo-only collaboration protocol.
 *
 * Callers prepare every protocol value before entering this adapter. The
 * adapter validates and atomically stores those values, but never creates
 * protocol identifiers, timestamps, nonces, signatures, or ciphertext.
 */
export interface CollaborativeVaultStore {
  getCollaborativeVault(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<CollaborativeVaultDocument | null>;
  discoverCollaborativeMemberships(
    databaseId: DatabaseId,
    discoveryTags: readonly Sha256Digest[] | Sha256Digest,
    limit?: number,
  ): Promise<readonly CollaborationDiscoveryRecord[]>;
  getDatabaseDeviceRegistry(
    databaseId: DatabaseId,
  ): Promise<CollaborationDatabaseDeviceRegistry | null>;
  publishDatabaseDeviceRegistry(
    candidate: CollaborationDatabaseDeviceRegistry,
  ): Promise<void>;
  publishCollaborativeVault(
    input: PublishCollaborativeVaultInput,
  ): Promise<DurableOperationOutcome | OperationDeduplicationTombstone>;
  destroyCollaborativeVault(
    input: DestroyCollaborativeVaultInput,
  ): Promise<DurableOperationOutcome | OperationDeduplicationTombstone>;
  getCollaborativeVaultDestructionTombstone(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<CollaborationVaultDestructionTombstone | null>;
  getCollaborativeFinalizedMutationLinkByHead(
    databaseId: DatabaseId,
    vaultId: VaultId,
    resultingHeadDigest: Sha256Digest,
  ): Promise<CollaborationFinalizedMutationLink | null>;
  getCollaborativeFinalizedMutationLinkByOperation(
    databaseId: DatabaseId,
    vaultId: VaultId,
    operationId: string,
  ): Promise<CollaborationFinalizedMutationLink | null>;
  getCollaborativeMutationProofRange(
    input: GetCollaborativeMutationProofRangeInput,
  ): Promise<CollaborationMutationProof>;
  getCollaborationAuthorizationWitness(
    databaseId: DatabaseId,
    vaultId: VaultId,
    authorizationStateDigest: Sha256Digest,
    atOrBeforeDocumentRevision: number,
  ): Promise<CollaborationAuthorizationWitness | null>;
  appendCollaborationAuthorizationCheckpoint(
    checkpoint: CollaborationAuthorizationCheckpoint,
  ): Promise<void>;
  getCollaborationAuthorizationCheckpoint(
    databaseId: DatabaseId,
    vaultId: VaultId,
    checkpointDigest: Sha256Digest,
  ): Promise<CollaborationAuthorizationCheckpoint | null>;
  beginCollaborativeMigration(
    input: BeginCollaborativeMigrationInput,
  ): Promise<CollaborationMigrationPreparedMarker>;
  activateCollaborativeGenesis(
    input: ActivateCollaborativeGenesisInput,
  ): Promise<DurableOperationOutcome>;
  getCollaborativeOperationOutcome(
    databaseId: DatabaseId,
    vaultId: VaultId,
    operationId: string,
  ): Promise<DurableOperationOutcome | OperationDeduplicationTombstone | null>;
  compactCollaborativeOperationOutcome(
    input: CompactCollaborativeOperationOutcomeInput,
  ): Promise<OperationDeduplicationTombstone>;
}

export type PublishCollaborativeVaultInput = Readonly<{
  /** Complete next state; persisted unchanged apart from the internal _id. */
  candidate: CollaborativeVaultDocument;
  /** Complete signed durable result for the exact operation. */
  outcome: DurableOperationOutcome;
  /** Exact immutable proof entry persisted beside the candidate and outcome. */
  proofEntry: CollaborationMutationProof['entries'][number];
}>;

export type DestroyCollaborativeVaultInput = Readonly<{
  /** Permanent terminal identity fence carrying the exact final proof entry. */
  tombstone: CollaborationVaultDestructionTombstone;
  /** Complete committed result for the exact irreversible destruction. */
  outcome: DurableOperationOutcome;
}>;

export type CollaborativeProofPosition = Readonly<{
  documentRevision: number;
  headDigest: Sha256Digest;
}>;

export type GetCollaborativeMutationProofRangeInput = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  fromExclusive: CollaborativeProofPosition;
  toInclusive: CollaborativeProofPosition;
  /** Upper bound supplied by the caller; protocol maximum is 256 links. */
  limit?: number;
}>;

export type CompactCollaborativeOperationOutcomeInput = Readonly<{
  /** Immutable tombstone prepared by the caller from the full outcome. */
  tombstone: OperationDeduplicationTombstone;
}>;

export type BeginCollaborativeMigrationInput = Readonly<{
  request: CollaborationMigrationRequest;
  preparedMarker: CollaborationMigrationPreparedMarker;
}>;

export type ActivateCollaborativeGenesisInput = Readonly<{
  preparedMarker: CollaborationMigrationPreparedMarker;
  candidate: CollaborativeVaultDocument;
  outcome: DurableOperationOutcome;
  proofEntry: CollaborationMutationProof['entries'][number];
  activeMarker: CollaborationMigrationActiveMarker;
}>;

export type MongoCollaborativeVaultCollectionNames = Readonly<{
  collaborativeVaultCollectionName: string;
  databaseDeviceRegistryCollectionName: string;
  operationOutcomeCollectionName: string;
  operationTombstoneCollectionName: string;
  vaultDestructionTombstoneCollectionName: string;
  finalizedMutationLinkCollectionName: string;
  authorizationCheckpointCollectionName: string;
}>;

type StoredDocument = Readonly<{ _id: string }> & Record<string, unknown>;

const MAX_DISCOVERY_LIMIT = 256;
const DEFAULT_DISCOVERY_LIMIT = 64;
const MAX_PROOF_RANGE_LIMIT = 256;
const TRANSACTION_OPTIONS = {
  readConcern: { level: 'snapshot' as const },
  writeConcern: { w: 'majority' as const },
};

/**
 * MongoDB implementation of the collaboration port. The parent encrypted
 * database store owns the connection and delegates to this class so legacy
 * collections and predicates remain completely independent.
 */
export class MongoCollaborativeVaultStore implements CollaborativeVaultStore {
  readonly #client: MongoClient;
  readonly #vaults: Collection<StoredDocument>;
  readonly #registries: Collection<StoredDocument>;
  readonly #outcomes: Collection<StoredDocument>;
  readonly #tombstones: Collection<StoredDocument>;
  readonly #vaultDestructionTombstones: Collection<StoredDocument>;
  readonly #mutationLinks: Collection<StoredDocument>;
  readonly #authorizationCheckpoints: Collection<StoredDocument>;
  readonly #legacyVaults: Collection<StoredDocument> | undefined;

  constructor(
    client: MongoClient,
    database: Db,
    collectionNames: MongoCollaborativeVaultCollectionNames,
    legacyVaults?: Collection<StoredDocument>,
  ) {
    this.#client = client;
    this.#vaults = database.collection<StoredDocument>(
      collectionNames.collaborativeVaultCollectionName,
    );
    this.#registries = database.collection<StoredDocument>(
      collectionNames.databaseDeviceRegistryCollectionName,
    );
    this.#outcomes = database.collection<StoredDocument>(
      collectionNames.operationOutcomeCollectionName,
    );
    this.#tombstones = database.collection<StoredDocument>(
      collectionNames.operationTombstoneCollectionName,
    );
    this.#vaultDestructionTombstones = database.collection<StoredDocument>(
      collectionNames.vaultDestructionTombstoneCollectionName,
    );
    this.#mutationLinks = database.collection<StoredDocument>(
      collectionNames.finalizedMutationLinkCollectionName,
    );
    this.#authorizationCheckpoints = database.collection<StoredDocument>(
      collectionNames.authorizationCheckpointCollectionName,
    );
    this.#legacyVaults = legacyVaults;
  }

  /** Create identity indexes before a transaction first touches each collection. */
  async initializeIndexes(): Promise<void> {
    try {
      await this.#vaults.createIndex(
        { databaseId: 1, vaultId: 1 },
        { name: 'collaborative_vault_identity', unique: true },
      );
      await this.#registries.createIndex(
        { databaseId: 1 },
        { name: 'database_device_registry_identity', unique: true },
      );
      await this.#outcomes.createIndex(
        { databaseId: 1, vaultId: 1, operationId: 1 },
        { name: 'collaborative_operation_outcome_identity', unique: true },
      );
      // Tombstones are permanent deduplication boundaries. Deliberately no
      // expireAfterSeconds option is present on this index.
      await this.#tombstones.createIndex(
        { databaseId: 1, vaultId: 1, operationId: 1 },
        { name: 'collaborative_operation_tombstone_identity', unique: true },
      );
      // This is the permanent identity fence for a destroyed vault, not an
      // operation-retention record. It must never receive a TTL index.
      await this.#vaultDestructionTombstones.createIndex(
        { databaseId: 1, vaultId: 1 },
        { name: 'collaborative_vault_destruction_identity', unique: true },
      );
      await this.#mutationLinks.createIndex(
        { databaseId: 1, vaultId: 1, 'link.resultingHeadDigest': 1 },
        { name: 'collaborative_mutation_link_head', unique: true },
      );
      await this.#mutationLinks.createIndex(
        { databaseId: 1, vaultId: 1, 'link.commitment.operationId': 1 },
        { name: 'collaborative_mutation_link_operation', unique: true },
      );
      await this.#mutationLinks.createIndex(
        { databaseId: 1, vaultId: 1, 'link.commitment.documentRevision': 1 },
        { name: 'collaborative_mutation_link_revision', unique: true },
      );
      await this.#mutationLinks.createIndex(
        {
          databaseId: 1,
          vaultId: 1,
          'authorizationWitness.tuple.authorizationStateDigest': 1,
          'authorizationWitness.tuple.documentRevision': -1,
        },
        { name: 'collaborative_authorization_witness_lookup' },
      );
      await this.#authorizationCheckpoints.createIndex(
        { databaseId: 1, vaultId: 1, checkpointId: 1 },
        { name: 'collaborative_authorization_checkpoint_identity', unique: true },
      );
      await this.#authorizationCheckpoints.createIndex(
        { databaseId: 1, vaultId: 1, checkpointDigest: 1 },
        { name: 'collaborative_authorization_checkpoint_digest', unique: true },
      );
      await this.#authorizationCheckpoints.createIndex(
        { databaseId: 1, vaultId: 1, 'tuple.documentRevision': 1 },
        { name: 'collaborative_authorization_checkpoint_revision' },
      );
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error, 'connection');
    }
  }

  async getCollaborativeVault(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<CollaborativeVaultDocument | null> {
    const database = parseDatabaseId(databaseId);
    const vault = parseVaultId(vaultId);
    try {
      const stored = await this.#vaults.findOne(
        {
          _id: collaborativeVaultKey(database, vault),
          databaseId: database,
          vaultId: vault,
        },
        { projection: { _id: 0 } },
      );
      return stored === null ? null : parseStoredCollaborativeVault(stored);
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async discoverCollaborativeMemberships(
    databaseId: DatabaseId,
    discoveryTags: readonly Sha256Digest[] | Sha256Digest,
    limit = DEFAULT_DISCOVERY_LIMIT,
  ): Promise<readonly CollaborationDiscoveryRecord[]> {
    const database = parseDatabaseId(databaseId);
    const tags = parseDiscoveryTags(discoveryTags);
    const boundedLimit = parseDiscoveryLimit(limit);
    try {
      const cursor = this.#vaults
        .find(
          {
            databaseId: database,
            'discoveryRecords.discoveryTag': { $in: tags },
          },
          { projection: { _id: 0 } },
        )
        .sort({ vaultId: 1 });
      // Bound the database work as well as the returned record count. A
      // document can contain more than one matching record, so the final
      // slice is required to make the public result bound exact.
      const boundedCursor =
        typeof cursor.limit === 'function' ? cursor.limit(boundedLimit) : cursor;
      const rows = await boundedCursor.toArray();
      const memberships: CollaborationDiscoveryRecord[] = [];
      for (const row of rows) {
        // Strictly parse the complete remote document before exposing any
        // nested record. Corrupt nonmatching metadata is still corruption.
        const document = parseStoredCollaborativeVault(row);
        for (const record of document.discoveryRecords) {
          if (tags.includes(record.discoveryTag)) {
            // Re-parse at the narrow public boundary so the returned object
            // is detached and its exact record shape is checked.
            memberships.push(parseStoredDiscoveryRecord(record));
            if (memberships.length === boundedLimit) return memberships;
          }
        }
      }
      return memberships;
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async getDatabaseDeviceRegistry(
    databaseId: DatabaseId,
  ): Promise<CollaborationDatabaseDeviceRegistry | null> {
    const database = parseDatabaseId(databaseId);
    try {
      const stored = await this.#registries.findOne(
        {
          _id: databaseDeviceRegistryKey(database),
          databaseId: database,
        },
        { projection: { _id: 0 } },
      );
      return stored === null ? null : parseStoredRegistry(stored);
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async publishDatabaseDeviceRegistry(
    candidate: CollaborationDatabaseDeviceRegistry,
  ): Promise<void> {
    const parsed = parseRegistryCandidate(candidate);
    const replacement: StoredDocument = {
      ...parsed,
      _id: databaseDeviceRegistryKey(parsed.databaseId),
    };
    try {
      await this.#runTransaction(async (session) => {
        const currentRow = await this.#registries.findOne(
          {
            _id: databaseDeviceRegistryKey(parsed.databaseId),
            databaseId: parsed.databaseId,
          },
          { projection: { _id: 0 }, session },
        );

        if (currentRow === null) {
          // The first signed registry is protocol-fixed at generation one.
          // There is no zero-generation registry document in Mongo.
          if (parsed.generation !== 1) {
            throw new EncryptedDatabaseStoreError('conflict');
          }
          const inserted = await this.#registries.replaceOne(
            {
              _id: databaseDeviceRegistryKey(parsed.databaseId),
              databaseId: parsed.databaseId,
              generation: { $exists: false },
              registryDigest: { $exists: false },
            },
            replacement,
            { session, upsert: true },
          );
          if (inserted.matchedCount !== 0 || inserted.upsertedCount !== 1) {
            throw new EncryptedDatabaseStoreError('conflict');
          }
          return;
        }

        const current = parseStoredRegistry(currentRow);
        if (recordsEqual(current, parsed)) return;
        if (
          parsed.generation !== current.generation + 1 ||
          parsed.previousRegistryDigest !== current.registryDigest ||
          parsed.authorityEpoch !== current.authorityEpoch ||
          parsed.authorityFingerprint !== current.authorityFingerprint ||
          !registryDenialsAreMonotonic(current, parsed)
        ) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        const replaced = await this.#registries.replaceOne(
          {
            _id: databaseDeviceRegistryKey(parsed.databaseId),
            databaseId: parsed.databaseId,
            generation: current.generation,
            registryDigest: current.registryDigest,
          },
          replacement,
          { session },
        );
        if (replaced.matchedCount !== 1) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
      });
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async publishCollaborativeVault(
    input: PublishCollaborativeVaultInput,
  ): Promise<DurableOperationOutcome | OperationDeduplicationTombstone> {
    const { candidate, outcome, proofEntry } = parsePublicationInput(input);
    const link = proofEntry.link;
    const commitment = link.commitment;
    if (
      commitment.operationType === 'genesis-migration' ||
      commitment.previousDocumentRevision === 0
    ) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    const operationKey = operationIdentityKey(
      candidate.databaseId,
      candidate.vaultId,
      commitment.operationId,
    );
    const replacement: StoredDocument = {
      ...candidate,
      _id: collaborativeVaultKey(candidate.databaseId, candidate.vaultId),
    };
    const outcomeDocument: StoredDocument = { ...outcome, _id: operationKey };
    const linkDocument = storedMutationProofEntryDocument(proofEntry, outcome);
    try {
      return await this.#runTransaction(async (session) => {
        const existingOutcome = await this.#outcomes.findOne(
          {
            _id: operationKey,
            databaseId: candidate.databaseId,
            vaultId: candidate.vaultId,
            operationId: commitment.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingOutcome !== null) {
          const parsedExisting = parseStoredOutcome(existingOutcome);
          if (parsedExisting.state === 'committed') {
            const replay = assertReplayOutcome(existingOutcome, outcome);
            await this.#assertStoredReplayLink(session, proofEntry, outcome);
            return replay;
          }
          await discardUnsignedOutcome(this.#outcomes, session, parsedExisting);
        }

        const existingTombstone = await this.#tombstones.findOne(
          {
            _id: operationKey,
            databaseId: candidate.databaseId,
            vaultId: candidate.vaultId,
            operationId: commitment.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingTombstone !== null) {
          const replay = assertReplayTombstone(existingTombstone, outcome);
          await this.#assertStoredReplayLink(session, proofEntry, outcome);
          return replay;
        }

        const registryRow = await this.#registries.findOne(
          {
            _id: databaseDeviceRegistryKey(candidate.databaseId),
            databaseId: candidate.databaseId,
          },
          { projection: { _id: 0 }, session },
        );
        if (registryRow === null) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        const registry = parseStoredRegistry(registryRow);
        assertRegistryFence(candidate, registry);
        await this.#lockRegistryForPublication(
          session,
          candidate.databaseId,
          candidate.vaultId,
          candidate.authorityEpoch,
          candidate.databaseDeviceGeneration,
          candidate.databaseDeviceRegistryDigest,
          commitment.operationId,
        );
        assertWriterNotDenied(
          commitment.writerPrincipalId,
          commitment.writerDeviceId,
          registry,
        );

        const priorTuple = priorTupleFromCandidate(candidate);
        const priorFilter = priorVaultFilter(candidate, priorTuple);
        const priorVault = await this.#vaults.findOne(priorFilter, {
          projection: { _id: 0 },
          session,
        });
        if (priorVault === null) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        // CAS fields are repeated in the query, but the complete document
        // must still parse strictly before it can be replaced.
        const parsedPrior = parseStoredCollaborativeVault(priorVault);
        assertImmutableDelegation(parsedPrior, candidate);

        const replaced = await this.#vaults.replaceOne(priorFilter, replacement, {
          session,
        });
        if (replaced.matchedCount !== 1) {
          throw new EncryptedDatabaseStoreError('conflict');
        }

        const insertedLink = await this.#mutationLinks.insertOne(linkDocument, {
          session,
        });
        if (!insertedLink.acknowledged) {
          throw new EncryptedDatabaseStoreError('operation');
        }

        const insertedOutcome = await this.#outcomes.insertOne(outcomeDocument, {
          session,
        });
        if (!insertedOutcome.acknowledged) {
          throw new EncryptedDatabaseStoreError('operation');
        }
        return outcome;
      });
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async destroyCollaborativeVault(
    input: DestroyCollaborativeVaultInput,
  ): Promise<DurableOperationOutcome | OperationDeduplicationTombstone> {
    const { tombstone, outcome } = parseVaultDestructionInput(input);
    const { core, proofEntry } = tombstone;
    const operationKey = operationIdentityKey(
      tombstone.databaseId,
      tombstone.vaultId,
      core.operationId,
    );
    const vaultKey = collaborativeVaultKey(tombstone.databaseId, tombstone.vaultId);
    const permanentTombstoneDocument: StoredDocument = {
      ...tombstone,
      _id: vaultKey,
    };
    const outcomeDocument: StoredDocument = { ...outcome, _id: operationKey };
    const linkDocument = storedMutationProofEntryDocument(proofEntry, outcome);

    try {
      return await this.#runTransaction(async (session) => {
        const permanentRow = await this.#vaultDestructionTombstones.findOne(
          {
            _id: vaultKey,
            databaseId: tombstone.databaseId,
            vaultId: tombstone.vaultId,
          },
          { projection: { _id: 0 }, session },
        );
        if (permanentRow !== null) {
          const permanent = parseStoredVaultDestructionTombstone(permanentRow);
          assertPermanentDestructionReplay(permanent, tombstone);

          const liveRow = await this.#vaults.findOne(
            {
              _id: vaultKey,
              databaseId: tombstone.databaseId,
              vaultId: tombstone.vaultId,
            },
            { projection: { _id: 0 }, session },
          );
          if (liveRow !== null) {
            parseStoredCollaborativeVault(liveRow);
            throw new EncryptedDatabaseStoreError('invalid');
          }

          const outcomeRow = await this.#outcomes.findOne(
            {
              _id: operationKey,
              databaseId: tombstone.databaseId,
              vaultId: tombstone.vaultId,
              operationId: core.operationId,
            },
            { projection: { _id: 0 }, session },
          );
          const operationTombstoneRow = await this.#tombstones.findOne(
            {
              _id: operationKey,
              databaseId: tombstone.databaseId,
              vaultId: tombstone.vaultId,
              operationId: core.operationId,
            },
            { projection: { _id: 0 }, session },
          );
          if (outcomeRow !== null && operationTombstoneRow !== null) {
            throw new EncryptedDatabaseStoreError('invalid');
          }
          const replay =
            outcomeRow !== null
              ? assertReplayOutcome(outcomeRow, outcome)
              : operationTombstoneRow !== null
                ? assertReplayTombstone(operationTombstoneRow, outcome)
                : undefined;
          if (replay === undefined) {
            throw new EncryptedDatabaseStoreError('invalid');
          }
          await this.#assertStoredReplayLink(session, proofEntry, outcome);
          return replay;
        }

        // A destroy-vault outcome, compact operation tombstone, or proof link
        // without its permanent vault-identity fence is partial-state
        // corruption. Unlike ordinary rejected outcomes, it must not be
        // discarded and retried into an irreversible transition.
        const existingOutcome = await this.#outcomes.findOne(
          {
            _id: operationKey,
            databaseId: tombstone.databaseId,
            vaultId: tombstone.vaultId,
            operationId: core.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingOutcome !== null) {
          parseStoredOutcome(existingOutcome);
          throw new EncryptedDatabaseStoreError('invalid');
        }
        const existingOperationTombstone = await this.#tombstones.findOne(
          {
            _id: operationKey,
            databaseId: tombstone.databaseId,
            vaultId: tombstone.vaultId,
            operationId: core.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingOperationTombstone !== null) {
          parseStoredTombstone(existingOperationTombstone);
          throw new EncryptedDatabaseStoreError('invalid');
        }
        const existingLink = await this.#mutationLinks.findOne(
          {
            _id: mutationLinkKey(
              tombstone.databaseId,
              tombstone.vaultId,
              core.operationId,
            ),
            databaseId: tombstone.databaseId,
            vaultId: tombstone.vaultId,
            'link.commitment.operationId': core.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingLink !== null) {
          parseStoredMutationProofEntry(existingLink);
          throw new EncryptedDatabaseStoreError('invalid');
        }

        const registryRow = await this.#registries.findOne(
          {
            _id: databaseDeviceRegistryKey(tombstone.databaseId),
            databaseId: tombstone.databaseId,
          },
          { projection: { _id: 0 }, session },
        );
        if (registryRow === null) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        const registry = parseStoredRegistry(registryRow);
        assertDestructionRegistryFence(tombstone, registry);
        await this.#lockRegistryForPublication(
          session,
          tombstone.databaseId,
          tombstone.vaultId,
          core.authorityEpoch,
          core.priorTuple.databaseDeviceGeneration,
          core.priorTuple.databaseDeviceRegistryDigest,
          core.operationId,
        );
        assertWriterNotDenied(core.actorPrincipalId, core.actorDeviceId, registry);

        const priorFilter = destructionPriorVaultFilter(tombstone);
        const priorRow = await this.#vaults.findOne(priorFilter, {
          projection: { _id: 0 },
          session,
        });
        if (priorRow === null) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        const prior = parseStoredCollaborativeVault(priorRow);
        assertDestructionPriorBindings(prior, tombstone);

        const removed = await this.#vaults.deleteOne(priorFilter, { session });
        if (removed.deletedCount !== 1) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        const insertedPermanentTombstone =
          await this.#vaultDestructionTombstones.insertOne(permanentTombstoneDocument, {
            session,
          });
        if (!insertedPermanentTombstone.acknowledged) {
          throw new EncryptedDatabaseStoreError('operation');
        }
        const insertedLink = await this.#mutationLinks.insertOne(linkDocument, {
          session,
        });
        if (!insertedLink.acknowledged) {
          throw new EncryptedDatabaseStoreError('operation');
        }
        const insertedOutcome = await this.#outcomes.insertOne(outcomeDocument, {
          session,
        });
        if (!insertedOutcome.acknowledged) {
          throw new EncryptedDatabaseStoreError('operation');
        }
        return outcome;
      });
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async getCollaborativeVaultDestructionTombstone(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<CollaborationVaultDestructionTombstone | null> {
    const database = parseDatabaseId(databaseId);
    const vault = parseVaultId(vaultId);
    try {
      const stored = await this.#vaultDestructionTombstones.findOne(
        {
          _id: collaborativeVaultKey(database, vault),
          databaseId: database,
          vaultId: vault,
        },
        { projection: { _id: 0 } },
      );
      return stored === null ? null : parseStoredVaultDestructionTombstone(stored);
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async getCollaborativeFinalizedMutationLinkByHead(
    databaseId: DatabaseId,
    vaultId: VaultId,
    resultingHeadDigest: Sha256Digest,
  ): Promise<CollaborationFinalizedMutationLink | null> {
    const database = parseDatabaseId(databaseId);
    const vault = parseVaultId(vaultId);
    const head = parseDigest(resultingHeadDigest);
    try {
      const stored = await this.#mutationLinks.findOne(
        { databaseId: database, vaultId: vault, 'link.resultingHeadDigest': head },
        { projection: { _id: 0 } },
      );
      return stored === null ? null : parseStoredMutationProofEntry(stored).entry.link;
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async getCollaborativeFinalizedMutationLinkByOperation(
    databaseId: DatabaseId,
    vaultId: VaultId,
    operationId: string,
  ): Promise<CollaborationFinalizedMutationLink | null> {
    const database = parseDatabaseId(databaseId);
    const vault = parseVaultId(vaultId);
    const operation = parseOperationId(operationId);
    try {
      const stored = await this.#mutationLinks.findOne(
        {
          databaseId: database,
          vaultId: vault,
          'link.commitment.operationId': operation,
        },
        { projection: { _id: 0 } },
      );
      return stored === null ? null : parseStoredMutationProofEntry(stored).entry.link;
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async getCollaborativeMutationProofRange(
    input: GetCollaborativeMutationProofRangeInput,
  ): Promise<CollaborationMutationProof> {
    const range = parseProofRangeInput(input);
    try {
      const rows = await this.#mutationLinks
        .find(
          {
            databaseId: range.databaseId,
            vaultId: range.vaultId,
            'link.commitment.documentRevision': {
              $gt: range.fromExclusive.documentRevision,
              $lte: range.toInclusive.documentRevision,
            },
          },
          { projection: { _id: 0 } },
        )
        .sort({ 'link.commitment.documentRevision': 1 })
        .limit(range.limit)
        .toArray();
      const entries = rows.map((row) => parseStoredMutationProofEntry(row).entry);
      const firstEntry = entries[0];
      if (firstEntry === undefined) throw new EncryptedDatabaseStoreError('invalid');
      const witnessRow = await this.#mutationLinks.findOne(
        {
          databaseId: range.databaseId,
          vaultId: range.vaultId,
          'authorizationWitness.tuple.authorizationStateDigest':
            firstEntry.link.commitment.previousAuthorizationStateDigest,
          'authorizationWitness.tuple.documentRevision': {
            $lte: range.fromExclusive.documentRevision,
          },
        },
        {
          projection: { _id: 0 },
          sort: { 'authorizationWitness.tuple.documentRevision': -1 },
        },
      );
      if (witnessRow === null) throw new EncryptedDatabaseStoreError('invalid');
      const startingAuthorizationWitness =
        parseStoredMutationProofEntry(witnessRow).entry.authorizationWitness;
      if (startingAuthorizationWitness === undefined) {
        throw new EncryptedDatabaseStoreError('invalid');
      }
      const proof = parseMutationProof({
        format: 'kavrix-collaborative-mutation-proof',
        protocolVersion: 1,
        databaseId: range.databaseId,
        vaultId: range.vaultId,
        authorityDelegationDigest: entries[0]?.link.authorityDelegationDigest,
        fromDocumentRevision: range.fromExclusive.documentRevision,
        fromHeadDigest: range.fromExclusive.headDigest,
        toDocumentRevision: range.toInclusive.documentRevision,
        toHeadDigest: range.toInclusive.headDigest,
        startingAuthorizationWitness,
        entries,
      });
      return proof;
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async getCollaborationAuthorizationWitness(
    databaseId: DatabaseId,
    vaultId: VaultId,
    authorizationStateDigest: Sha256Digest,
    atOrBeforeDocumentRevision: number,
  ): Promise<CollaborationAuthorizationWitness | null> {
    const database = parseDatabaseId(databaseId);
    const vault = parseVaultId(vaultId);
    const digest = parseDigest(authorizationStateDigest);
    const revision = parseRevision(atOrBeforeDocumentRevision);
    try {
      const stored = await this.#mutationLinks.findOne(
        {
          databaseId: database,
          vaultId: vault,
          'authorizationWitness.tuple.authorizationStateDigest': digest,
          'authorizationWitness.tuple.documentRevision': { $lte: revision },
        },
        {
          projection: { _id: 0 },
          sort: { 'authorizationWitness.tuple.documentRevision': -1 },
        },
      );
      if (stored === null) return null;
      const witness = parseStoredMutationProofEntry(stored).entry.authorizationWitness;
      if (witness === undefined) throw new EncryptedDatabaseStoreError('invalid');
      return witness;
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async appendCollaborationAuthorizationCheckpoint(
    checkpoint: CollaborationAuthorizationCheckpoint,
  ): Promise<void> {
    const parsed = parseCheckpoint(checkpoint);
    const checkpointKey = authorizationCheckpointKey(
      parsed.databaseId,
      parsed.vaultId,
      parsed.checkpointId,
    );
    const document: StoredDocument = { ...parsed, _id: checkpointKey };
    try {
      await this.#runTransaction(async (session) => {
        const existing = await this.#authorizationCheckpoints.findOne(
          {
            _id: checkpointKey,
            databaseId: parsed.databaseId,
            vaultId: parsed.vaultId,
            checkpointId: parsed.checkpointId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existing !== null) {
          if (!recordsEqual(parseStoredCheckpoint(existing), parsed)) {
            throw new EncryptedDatabaseStoreError('invalid');
          }
          return;
        }
        const linkRow = await this.#mutationLinks.findOne(
          {
            databaseId: parsed.databaseId,
            vaultId: parsed.vaultId,
            'link.resultingHeadDigest': parsed.headDigest,
            'link.commitment.documentRevision': parsed.tuple.documentRevision,
            finalizedMutationLinkDigest: parsed.finalizedMutationLinkDigest,
          },
          { projection: { _id: 0 }, session },
        );
        if (linkRow === null) throw new EncryptedDatabaseStoreError('conflict');
        const storedProofEntry = parseStoredMutationProofEntry(linkRow);
        assertCheckpointMatchesStoredLink(parsed, storedProofEntry);
        if (parsed.previousCheckpointDigest !== undefined) {
          const previous = await this.#authorizationCheckpoints.findOne(
            {
              databaseId: parsed.databaseId,
              vaultId: parsed.vaultId,
              checkpointDigest: parsed.previousCheckpointDigest,
            },
            { projection: { _id: 0 }, session },
          );
          if (previous === null) throw new EncryptedDatabaseStoreError('conflict');
          const previousCheckpoint = parseStoredCheckpoint(previous);
          if (
            previousCheckpoint.databaseId !== parsed.databaseId ||
            previousCheckpoint.vaultId !== parsed.vaultId ||
            previousCheckpoint.authorityDelegationDigest !==
              parsed.authorityDelegationDigest ||
            previousCheckpoint.tuple.documentRevision >= parsed.tuple.documentRevision
          ) {
            throw new EncryptedDatabaseStoreError('invalid');
          }
        }
        const inserted = await this.#authorizationCheckpoints.insertOne(document, {
          session,
        });
        if (!inserted.acknowledged) throw new EncryptedDatabaseStoreError('operation');
      });
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async getCollaborationAuthorizationCheckpoint(
    databaseId: DatabaseId,
    vaultId: VaultId,
    checkpointDigest: Sha256Digest,
  ): Promise<CollaborationAuthorizationCheckpoint | null> {
    const database = parseDatabaseId(databaseId);
    const vault = parseVaultId(vaultId);
    const digest = parseDigest(checkpointDigest);
    try {
      const stored = await this.#authorizationCheckpoints.findOne(
        { databaseId: database, vaultId: vault, checkpointDigest: digest },
        { projection: { _id: 0 } },
      );
      return stored === null ? null : parseStoredCheckpoint(stored);
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async beginCollaborativeMigration(
    input: BeginCollaborativeMigrationInput,
  ): Promise<CollaborationMigrationPreparedMarker> {
    const { request, preparedMarker } = parseBeginMigrationInput(input);
    const legacyVaults = this.#legacyVaults;
    if (legacyVaults === undefined) {
      throw new EncryptedDatabaseStoreError('unsupported');
    }
    const vaultKey = collaborativeVaultKey(request.databaseId, request.vaultId);
    const markerDocument: StoredDocument = {
      ...preparedMarker,
      _id: vaultKey,
    };
    try {
      return await this.#runTransaction(async (session) => {
        const existingCollaborativeVault = await this.#vaults.findOne(
          {
            _id: vaultKey,
            databaseId: request.databaseId,
            vaultId: request.vaultId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingCollaborativeVault !== null) {
          parseStoredCollaborativeVault(existingCollaborativeVault);
          throw new EncryptedDatabaseStoreError('conflict');
        }

        const operationKey = operationIdentityKey(
          request.databaseId,
          request.vaultId,
          request.operationId,
        );
        const existingOutcome = await this.#outcomes.findOne(
          {
            _id: operationKey,
            databaseId: request.databaseId,
            vaultId: request.vaultId,
            operationId: request.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingOutcome !== null) {
          const parsedExisting = parseStoredOutcome(existingOutcome);
          if (parsedExisting.state === 'committed') {
            throw new EncryptedDatabaseStoreError('conflict');
          }
          await discardUnsignedOutcome(this.#outcomes, session, parsedExisting);
        }
        const existingTombstone = await this.#tombstones.findOne(
          {
            _id: operationKey,
            databaseId: request.databaseId,
            vaultId: request.vaultId,
            operationId: request.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingTombstone !== null) {
          parseStoredTombstone(existingTombstone);
          throw new EncryptedDatabaseStoreError('conflict');
        }
        const existingLink = await this.#mutationLinks.findOne(
          {
            _id: mutationLinkKey(
              request.databaseId,
              request.vaultId,
              request.operationId,
            ),
            databaseId: request.databaseId,
            vaultId: request.vaultId,
            'link.commitment.operationId': request.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingLink !== null) {
          parseStoredMutationProofEntry(existingLink);
          throw new EncryptedDatabaseStoreError('conflict');
        }

        const existingLegacyRow = await legacyVaults.findOne(
          {
            _id: vaultKey,
            databaseId: request.databaseId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingLegacyRow === null) {
          throw new EncryptedDatabaseStoreError('conflict');
        }

        if (!hasField(existingLegacyRow, 'revision')) {
          const existingMarker = parseStoredMigrationMarker(existingLegacyRow);
          if (
            existingMarker.state === 'prepared' &&
            recordsEqual(existingMarker, preparedMarker)
          ) {
            return preparedMarker;
          }
          if (existingMarker.operationId === preparedMarker.operationId) {
            throw new EncryptedDatabaseStoreError('invalid');
          }
          throw new EncryptedDatabaseStoreError('conflict');
        }

        const source = parseStoredLegacyVault(existingLegacyRow);
        if (!recordsEqual(source, preparedMarker.legacySource)) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        const replaced = await legacyVaults.replaceOne(
          legacyVaultFilter(source),
          markerDocument,
          { session },
        );
        if (replaced.matchedCount !== 1) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        return preparedMarker;
      });
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async activateCollaborativeGenesis(
    input: ActivateCollaborativeGenesisInput,
  ): Promise<DurableOperationOutcome> {
    const { preparedMarker, candidate, outcome, proofEntry, activeMarker } =
      parseActivateGenesisInput(input);
    const legacyVaults = this.#legacyVaults;
    if (legacyVaults === undefined) {
      throw new EncryptedDatabaseStoreError('unsupported');
    }
    const vaultKey = collaborativeVaultKey(candidate.databaseId, candidate.vaultId);
    const link = proofEntry.link;
    const commitment = link.commitment;
    const operationKey = operationIdentityKey(
      candidate.databaseId,
      candidate.vaultId,
      commitment.operationId,
    );
    const candidateDocument: StoredDocument = { ...candidate, _id: vaultKey };
    const outcomeDocument: StoredDocument = { ...outcome, _id: operationKey };
    const linkDocument = storedMutationProofEntryDocument(proofEntry, outcome);
    const registryDocument: StoredDocument = {
      ...preparedMarker.registryCandidate,
      _id: databaseDeviceRegistryKey(preparedMarker.databaseId),
    };
    const activeMarkerDocument: StoredDocument = {
      ...activeMarker,
      _id: vaultKey,
    };
    try {
      return await this.#runTransaction(async (session) => {
        const destructionRow = await this.#vaultDestructionTombstones.findOne(
          {
            _id: vaultKey,
            databaseId: preparedMarker.databaseId,
            vaultId: preparedMarker.vaultId,
          },
          { projection: { _id: 0 }, session },
        );
        if (destructionRow !== null) {
          parseStoredVaultDestructionTombstone(destructionRow);
          throw new EncryptedDatabaseStoreError('conflict');
        }
        const markerRow = await legacyVaults.findOne(
          {
            _id: vaultKey,
            databaseId: preparedMarker.databaseId,
          },
          { projection: { _id: 0 }, session },
        );
        if (markerRow === null) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        if (hasField(markerRow, 'revision')) {
          parseStoredLegacyVault(markerRow);
          throw new EncryptedDatabaseStoreError('conflict');
        }

        const marker = parseStoredMigrationMarker(markerRow);
        if (marker.state === 'active') {
          assertActiveMigrationReplay(marker, activeMarker);
          const storedRegistry = await this.#registries.findOne(
            {
              _id: databaseDeviceRegistryKey(preparedMarker.databaseId),
              databaseId: preparedMarker.databaseId,
            },
            { projection: { _id: 0 }, session },
          );
          if (storedRegistry === null) {
            throw new EncryptedDatabaseStoreError('conflict');
          }
          const registry = parseStoredRegistry(storedRegistry);
          if (!recordsEqual(registry, preparedMarker.registryCandidate)) {
            throw new EncryptedDatabaseStoreError('conflict');
          }
          const storedCandidate = await this.#vaults.findOne(
            {
              _id: vaultKey,
              databaseId: preparedMarker.databaseId,
              vaultId: preparedMarker.vaultId,
            },
            { projection: { _id: 0 }, session },
          );
          const storedOutcome = await this.#outcomes.findOne(
            {
              _id: operationKey,
              databaseId: preparedMarker.databaseId,
              vaultId: preparedMarker.vaultId,
              operationId: preparedMarker.operationId,
            },
            { projection: { _id: 0 }, session },
          );
          const storedLink = await this.#mutationLinks.findOne(
            {
              _id: mutationLinkKey(
                preparedMarker.databaseId,
                preparedMarker.vaultId,
                preparedMarker.operationId,
              ),
              databaseId: preparedMarker.databaseId,
              vaultId: preparedMarker.vaultId,
              'link.commitment.operationId': preparedMarker.operationId,
            },
            { projection: { _id: 0 }, session },
          );
          const storedTombstone = await this.#tombstones.findOne(
            {
              _id: operationKey,
              databaseId: preparedMarker.databaseId,
              vaultId: preparedMarker.vaultId,
              operationId: preparedMarker.operationId,
            },
            { projection: { _id: 0 }, session },
          );
          if (storedTombstone !== null) {
            parseStoredTombstone(storedTombstone);
            throw new EncryptedDatabaseStoreError('conflict');
          }
          if (
            storedCandidate === null ||
            storedOutcome === null ||
            storedLink === null
          ) {
            throw new EncryptedDatabaseStoreError('conflict');
          }
          const parsedCandidate = parseStoredCollaborativeVault(storedCandidate);
          const parsedOutcome = parseStoredOutcome(storedOutcome);
          const parsedLink = parseStoredMutationProofEntry(storedLink);
          if (
            !recordsEqual(parsedCandidate, candidate) ||
            !recordsEqual(parsedOutcome, outcome) ||
            !recordsEqual(parsedLink.entry, proofEntry) ||
            parsedLink.finalizedMutationLinkDigest !==
              outcome.finalizedMutationLinkDigest
          ) {
            throw new EncryptedDatabaseStoreError('invalid');
          }
          return parsedOutcome;
        }

        if (!recordsEqual(marker, preparedMarker)) {
          if (marker.operationId === preparedMarker.operationId) {
            throw new EncryptedDatabaseStoreError('invalid');
          }
          throw new EncryptedDatabaseStoreError('conflict');
        }

        const existingCollaborativeVault = await this.#vaults.findOne(
          {
            _id: vaultKey,
            databaseId: preparedMarker.databaseId,
            vaultId: preparedMarker.vaultId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingCollaborativeVault !== null) {
          parseStoredCollaborativeVault(existingCollaborativeVault);
          throw new EncryptedDatabaseStoreError('conflict');
        }
        const existingOutcome = await this.#outcomes.findOne(
          {
            _id: operationKey,
            databaseId: preparedMarker.databaseId,
            vaultId: preparedMarker.vaultId,
            operationId: preparedMarker.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingOutcome !== null) {
          const parsedExisting = parseStoredOutcome(existingOutcome);
          if (parsedExisting.state === 'committed') {
            throw new EncryptedDatabaseStoreError('conflict');
          }
          await discardUnsignedOutcome(this.#outcomes, session, parsedExisting);
        }
        const existingTombstone = await this.#tombstones.findOne(
          {
            _id: operationKey,
            databaseId: preparedMarker.databaseId,
            vaultId: preparedMarker.vaultId,
            operationId: preparedMarker.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingTombstone !== null) {
          parseStoredTombstone(existingTombstone);
          throw new EncryptedDatabaseStoreError('conflict');
        }

        await this.#fenceGenesisRegistry(
          session,
          preparedMarker.registryCandidate,
          registryDocument,
          candidate.vaultId,
          commitment.operationId,
        );
        const insertedCandidate = await this.#vaults.insertOne(candidateDocument, {
          session,
        });
        if (!insertedCandidate.acknowledged) {
          throw new EncryptedDatabaseStoreError('operation');
        }
        const insertedLink = await this.#mutationLinks.insertOne(linkDocument, {
          session,
        });
        if (!insertedLink.acknowledged) {
          throw new EncryptedDatabaseStoreError('operation');
        }
        const insertedOutcome = await this.#outcomes.insertOne(outcomeDocument, {
          session,
        });
        if (!insertedOutcome.acknowledged) {
          throw new EncryptedDatabaseStoreError('operation');
        }
        const activated = await legacyVaults.replaceOne(
          migrationMarkerFilter(preparedMarker),
          activeMarkerDocument,
          { session },
        );
        if (activated.matchedCount !== 1) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        return outcome;
      });
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async getCollaborativeOperationOutcome(
    databaseId: DatabaseId,
    vaultId: VaultId,
    operationId: string,
  ): Promise<DurableOperationOutcome | OperationDeduplicationTombstone | null> {
    const database = parseDatabaseId(databaseId);
    const vault = parseVaultId(vaultId);
    const operation = parseOperationId(operationId);
    const key = operationIdentityKey(database, vault, operation);
    try {
      return await this.#runTransaction(async (session) => {
        // Read both collections from one snapshot. This is authoritative
        // after an ambiguous commit: cleanup cannot be observed as a
        // cross-collection gap between the two reads.
        const outcomeRow = await this.#outcomes.findOne(
          { _id: key, databaseId: database, vaultId: vault, operationId: operation },
          { projection: { _id: 0 }, session },
        );
        const tombstoneRow = await this.#tombstones.findOne(
          { _id: key, databaseId: database, vaultId: vault, operationId: operation },
          { projection: { _id: 0 }, session },
        );
        if (outcomeRow !== null && tombstoneRow !== null) {
          throw new EncryptedDatabaseStoreError('invalid');
        }
        if (outcomeRow !== null) {
          const outcome = parseStoredOutcome(outcomeRow);
          return outcome.state === 'committed' ? outcome : null;
        }
        if (tombstoneRow !== null) return parseStoredTombstone(tombstoneRow);
        return null;
      });
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async compactCollaborativeOperationOutcome(
    input: CompactCollaborativeOperationOutcomeInput,
  ): Promise<OperationDeduplicationTombstone> {
    const tombstone = parseTombstoneInput(input);
    const key = operationIdentityKey(
      tombstone.databaseId,
      tombstone.vaultId,
      tombstone.operationId,
    );
    const tombstoneDocument: StoredDocument = { ...tombstone, _id: key };
    try {
      return await this.#runTransaction(async (session) => {
        // MongoDB sessions do not support parallel operations inside a
        // transaction. Keep both reads in this serial snapshot before the
        // insert/delete pair below.
        const outcomeRow = await this.#outcomes.findOne(
          {
            _id: key,
            databaseId: tombstone.databaseId,
            vaultId: tombstone.vaultId,
            operationId: tombstone.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        const existingTombstoneRow = await this.#tombstones.findOne(
          {
            _id: key,
            databaseId: tombstone.databaseId,
            vaultId: tombstone.vaultId,
            operationId: tombstone.operationId,
          },
          { projection: { _id: 0 }, session },
        );
        if (existingTombstoneRow !== null) {
          const existing = parseStoredTombstone(existingTombstoneRow);
          assertSameTombstone(existing, tombstone);
          if (outcomeRow !== null) {
            throw new EncryptedDatabaseStoreError('invalid');
          }
          return existing;
        }
        if (outcomeRow === null) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        const outcome = parseStoredOutcome(outcomeRow);
        assertTombstoneMatchesOutcome(tombstone, outcome);

        // These two writes intentionally share one transaction. A tombstone
        // is never visible without removing the full outcome, and cleanup can
        // never create a replay/deduplication gap.
        const inserted = await this.#tombstones.insertOne(tombstoneDocument, {
          session,
        });
        if (!inserted.acknowledged) {
          throw new EncryptedDatabaseStoreError('operation');
        }
        const removed = await this.#outcomes.deleteOne(
          {
            _id: key,
            databaseId: tombstone.databaseId,
            vaultId: tombstone.vaultId,
            operationId: tombstone.operationId,
          },
          { session },
        );
        if (removed.deletedCount !== 1) {
          throw new EncryptedDatabaseStoreError('conflict');
        }
        return tombstone;
      });
    } catch (error: unknown) {
      throw mapCollaborativeOperationError(error);
    }
  }

  async #fenceGenesisRegistry(
    session: ClientSession,
    candidate: CollaborationDatabaseDeviceRegistry,
    replacement: StoredDocument,
    vaultId: VaultId,
    operationId: string,
  ): Promise<void> {
    const registryKey = databaseDeviceRegistryKey(candidate.databaseId);
    const currentRow = await this.#registries.findOne(
      { _id: registryKey, databaseId: candidate.databaseId },
      { projection: { _id: 0 }, session },
    );
    if (currentRow === null) {
      if (candidate.generation !== 1) {
        throw new EncryptedDatabaseStoreError('conflict');
      }
      const inserted = await this.#registries.replaceOne(
        {
          _id: registryKey,
          databaseId: candidate.databaseId,
          generation: { $exists: false },
          registryDigest: { $exists: false },
        },
        replacement,
        { session, upsert: true },
      );
      if (inserted.matchedCount !== 0 || inserted.upsertedCount !== 1) {
        throw new EncryptedDatabaseStoreError('conflict');
      }
      return;
    }

    const current = parseStoredRegistry(currentRow);
    if (recordsEqual(current, candidate)) {
      await this.#lockRegistryForPublication(
        session,
        candidate.databaseId,
        vaultId,
        candidate.authorityEpoch,
        candidate.generation,
        candidate.registryDigest,
        operationId,
      );
      return;
    }
    if (
      candidate.generation !== current.generation + 1 ||
      candidate.previousRegistryDigest !== current.registryDigest ||
      candidate.authorityEpoch !== current.authorityEpoch ||
      candidate.authorityFingerprint !== current.authorityFingerprint ||
      !registryDenialsAreMonotonic(current, candidate)
    ) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    const replaced = await this.#registries.replaceOne(
      {
        _id: registryKey,
        databaseId: candidate.databaseId,
        generation: current.generation,
        registryDigest: current.registryDigest,
      },
      replacement,
      { session },
    );
    if (replaced.matchedCount !== 1) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
  }

  async #lockRegistryForPublication(
    session: ClientSession,
    databaseId: DatabaseId,
    vaultId: VaultId,
    authorityEpoch: number,
    generation: number,
    registryDigest: Sha256Digest,
    operationId: string,
  ): Promise<void> {
    const publicationFence = operationIdentityKey(databaseId, vaultId, operationId);
    const locked = await this.#registries.updateOne(
      {
        _id: databaseDeviceRegistryKey(databaseId),
        databaseId,
        authorityEpoch,
        generation,
        registryDigest,
        storagePublicationFence: { $ne: publicationFence },
      },
      { $set: { storagePublicationFence: publicationFence } },
      { session },
    );
    if (locked.matchedCount !== 1 || locked.modifiedCount !== 1) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
  }

  async #assertStoredReplayLink(
    session: ClientSession,
    expectedEntry: CollaborationMutationProof['entries'][number],
    expectedOutcome: DurableOperationOutcome,
  ): Promise<void> {
    const expectedLink = expectedEntry.link;
    const stored = await this.#mutationLinks.findOne(
      {
        _id: mutationLinkKey(
          expectedLink.databaseId,
          expectedLink.vaultId,
          expectedLink.commitment.operationId,
        ),
        databaseId: expectedLink.databaseId,
        vaultId: expectedLink.vaultId,
        'link.commitment.operationId': expectedLink.commitment.operationId,
      },
      { projection: { _id: 0 }, session },
    );
    if (stored === null) throw new EncryptedDatabaseStoreError('invalid');
    const actual = parseStoredMutationProofEntry(stored);
    if (
      actual.finalizedMutationLinkDigest !==
        expectedOutcome.finalizedMutationLinkDigest ||
      !recordsEqual(actual.entry, expectedEntry)
    ) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
  }

  async #runTransaction<T>(
    operation: (session: ClientSession) => Promise<T>,
  ): Promise<T> {
    return this.#client.withSession(async (session) =>
      session.withTransaction(operation, TRANSACTION_OPTIONS),
    );
  }
}

function parsePublicationInput(input: unknown): PublishCollaborativeVaultInput {
  if (
    !isRecord(input) ||
    !hasExactKeys(input, ['candidate', 'outcome', 'proofEntry'])
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  try {
    const candidate = collaborativeVaultDocumentSchema.parse(
      structuredClone(input['candidate']),
    );
    const outcome = durableOperationOutcomeSchema.parse(
      structuredClone(input['outcome']),
    );
    const proofEntry = collaborationMutationProofEntrySchema.parse(
      structuredClone(input['proofEntry']),
    );
    const link = proofEntry.link;
    const commitment = link.commitment;
    const priorTuple = priorTupleFromCandidate(candidate);
    const committedTuple = currentTupleFromCandidate(candidate);
    if (
      outcome.databaseId !== candidate.databaseId ||
      outcome.vaultId !== candidate.vaultId ||
      outcome.operationId !== commitment.operationId ||
      outcome.operationType !== commitment.operationType ||
      outcome.requestDigest !== commitment.requestDigest ||
      outcome.actorPrincipalId !== commitment.writerPrincipalId ||
      outcome.actorDeviceId !== commitment.writerDeviceId ||
      outcome.state !== 'committed' ||
      outcome.priorHeadDigest !== candidate.previousHeadDigest ||
      !tuplesEqual(outcome.priorTuple, priorTuple) ||
      outcome.committedHeadDigest !== candidate.headDigest ||
      outcome.finalizedMutationLinkDigest === undefined ||
      outcome.signedMutationReceipt === undefined ||
      outcome.committedTuple === undefined ||
      !tuplesEqual(outcome.committedTuple, committedTuple) ||
      link.resultingHeadDigest !== outcome.committedHeadDigest ||
      commitment.documentRevision !== commitment.previousDocumentRevision + 1 ||
      (proofEntry.authorizationWitness !== undefined &&
        proofEntry.authorizationWitness.finalizedMutationLinkDigest !==
          outcome.finalizedMutationLinkDigest)
    ) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    if (!recordsEqual(candidate.currentMutationLink, link)) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    const transition = link.authorizationTransition;
    if (
      transition !== undefined &&
      (!tuplesEqual(transition.previousTuple, priorTuple) ||
        !tuplesEqual(transition.nextTuple, committedTuple))
    ) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    return { candidate, outcome, proofEntry };
  } catch (error: unknown) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseVaultDestructionInput(input: unknown): DestroyCollaborativeVaultInput {
  if (!isRecord(input) || !hasExactKeys(input, ['tombstone', 'outcome'])) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  try {
    const tombstone = collaborationVaultDestructionTombstoneSchema.parse(
      structuredClone(input['tombstone']),
    );
    const outcome = durableOperationOutcomeSchema.parse(
      structuredClone(input['outcome']),
    );
    const { core, proofEntry, signedMutationReceipt } = tombstone;
    const { commitment } = proofEntry.link;
    const witness = proofEntry.authorizationWitness;
    if (
      outcome.state !== 'committed' ||
      outcome.operationType !== 'destroy-vault' ||
      commitment.operationType !== 'destroy-vault' ||
      witness === undefined ||
      outcome.databaseId !== tombstone.databaseId ||
      outcome.vaultId !== tombstone.vaultId ||
      outcome.operationId !== core.operationId ||
      outcome.operationId !== commitment.operationId ||
      outcome.requestDigest !== commitment.requestDigest ||
      outcome.actorPrincipalId !== core.actorPrincipalId ||
      outcome.actorDeviceId !== core.actorDeviceId ||
      outcome.priorHeadDigest !== core.priorHeadDigest ||
      outcome.committedHeadDigest !== tombstone.terminalHeadDigest ||
      outcome.outcomeDigest !== tombstone.outcomeDigest ||
      outcome.finalizedMutationLinkDigest !== witness.finalizedMutationLinkDigest ||
      outcome.finalizedMutationLinkDigest !==
        signedMutationReceipt.finalizedMutationLinkDigest ||
      outcome.committedAt !== signedMutationReceipt.committedAt ||
      outcome.signedMutationReceipt === undefined ||
      outcome.committedTuple === undefined ||
      !tuplesEqual(outcome.priorTuple, core.priorTuple) ||
      !tuplesEqual(outcome.committedTuple, core.terminalTuple) ||
      !recordsEqual(outcome.signedMutationReceipt, signedMutationReceipt)
    ) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    return { tombstone, outcome };
  } catch (error: unknown) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseBeginMigrationInput(input: unknown): BeginCollaborativeMigrationInput {
  if (!isRecord(input) || !hasExactKeys(input, ['request', 'preparedMarker'])) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  try {
    const request = collaborationMigrationRequestSchema.parse(
      structuredClone(input['request']),
    );
    const preparedMarker = collaborationMigrationPreparedMarkerSchema.parse(
      structuredClone(input['preparedMarker']),
    );
    assertRequestMatchesPreparedMarker(request, preparedMarker);
    return { request, preparedMarker };
  } catch (error: unknown) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseActivateGenesisInput(input: unknown): ActivateCollaborativeGenesisInput {
  if (
    !isRecord(input) ||
    !hasExactKeys(input, [
      'preparedMarker',
      'candidate',
      'outcome',
      'proofEntry',
      'activeMarker',
    ])
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  try {
    const preparedMarker = collaborationMigrationPreparedMarkerSchema.parse(
      structuredClone(input['preparedMarker']),
    );
    const activeMarker = collaborationMigrationActiveMarkerSchema.parse(
      structuredClone(input['activeMarker']),
    );
    const publication = parsePublicationInput({
      candidate: input['candidate'],
      outcome: input['outcome'],
      proofEntry: input['proofEntry'],
    });
    assertGenesisActivationBindings(
      preparedMarker,
      publication.candidate,
      publication.outcome,
      activeMarker,
    );
    return {
      preparedMarker,
      candidate: publication.candidate,
      outcome: publication.outcome,
      proofEntry: publication.proofEntry,
      activeMarker,
    };
  } catch (error: unknown) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function assertRequestMatchesPreparedMarker(
  request: CollaborationMigrationRequest,
  marker: CollaborationMigrationPreparedMarker,
): void {
  if (
    request.operationId !== marker.operationId ||
    request.databaseId !== marker.databaseId ||
    request.vaultId !== marker.vaultId ||
    request.requestDigest !== marker.requestDigest ||
    Number(request.legacyVaultRevision) !== Number(marker.legacySource.revision) ||
    request.legacySourceDigest !== marker.legacySourceDigest ||
    request.authorityEpoch !== marker.authorityEpoch ||
    request.authorityFingerprint !== marker.authorityFingerprint ||
    request.databaseDeviceGeneration !== marker.databaseDeviceGeneration ||
    request.databaseDeviceRegistryDigest !== marker.databaseDeviceRegistryDigest
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function assertGenesisActivationBindings(
  preparedMarker: CollaborationMigrationPreparedMarker,
  candidate: CollaborativeVaultDocument,
  outcome: DurableOperationOutcome,
  activeMarker: CollaborationMigrationActiveMarker,
): void {
  const commitment = candidate.currentMutationLink.commitment;
  const priorTuple = priorTupleFromCandidate(candidate);
  if (
    candidate.databaseId !== preparedMarker.databaseId ||
    candidate.vaultId !== preparedMarker.vaultId ||
    candidate.authorityEpoch !== preparedMarker.authorityEpoch ||
    candidate.databaseDeviceGeneration !== preparedMarker.databaseDeviceGeneration ||
    candidate.databaseDeviceRegistryDigest !==
      preparedMarker.databaseDeviceRegistryDigest ||
    candidate.documentRevision !== 1 ||
    candidate.membershipRevision !== 1 ||
    candidate.policyRevision !== 1 ||
    candidate.keyEpoch !== 1 ||
    candidate.authorityDelegation.authoritySigningKeyFingerprint !==
      preparedMarker.authorityFingerprint ||
    candidate.authorityDelegation.genesisOperationId !== preparedMarker.operationId ||
    candidate.authorityDelegation.genesisHeadDigest !== candidate.headDigest ||
    commitment.operationId !== preparedMarker.operationId ||
    commitment.operationType !== 'genesis-migration' ||
    commitment.requestDigest !== preparedMarker.requestDigest ||
    commitment.writerPrincipalId !== outcome.actorPrincipalId ||
    commitment.writerDeviceId !== outcome.actorDeviceId ||
    priorTuple.authorityEpoch !== preparedMarker.authorityEpoch ||
    priorTuple.databaseDeviceGeneration !== preparedMarker.databaseDeviceGeneration ||
    priorTuple.databaseDeviceRegistryDigest !==
      preparedMarker.databaseDeviceRegistryDigest ||
    priorTuple.documentRevision !== 0 ||
    priorTuple.membershipRevision !== 0 ||
    priorTuple.policyRevision !== 0 ||
    priorTuple.keyEpoch !== 1 ||
    candidate.previousHeadDigest !== COLLABORATION_GENESIS_HEAD_DIGEST ||
    commitment.previousHeadDigest !== COLLABORATION_GENESIS_HEAD_DIGEST ||
    preparedMarker.candidateHeadDigest !== candidate.headDigest ||
    preparedMarker.candidateHeadDigest !== activeMarker.candidateHeadDigest ||
    outcome.operationType !== 'genesis-migration' ||
    outcome.requestDigest !== preparedMarker.requestDigest ||
    activeMarker.databaseId !== preparedMarker.databaseId ||
    activeMarker.vaultId !== preparedMarker.vaultId ||
    activeMarker.operationId !== preparedMarker.operationId ||
    activeMarker.requestDigest !== preparedMarker.requestDigest ||
    activeMarker.legacySourceDigest !== preparedMarker.legacySourceDigest ||
    activeMarker.authorityEpoch !== preparedMarker.authorityEpoch ||
    activeMarker.authorityFingerprint !== preparedMarker.authorityFingerprint ||
    activeMarker.databaseDeviceGeneration !== preparedMarker.databaseDeviceGeneration ||
    activeMarker.databaseDeviceRegistryDigest !==
      preparedMarker.databaseDeviceRegistryDigest ||
    activeMarker.preparedAt !== preparedMarker.preparedAt ||
    activeMarker.authoritySignature !== preparedMarker.authoritySignature ||
    activeMarker.candidateHeadDigest !== candidate.headDigest ||
    activeMarker.outcomeDigest !== outcome.outcomeDigest
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function assertActiveMigrationReplay(
  actual: CollaborationMigrationActiveMarker,
  expected: CollaborationMigrationActiveMarker,
): void {
  if (recordsEqual(actual, expected)) return;
  if (actual.operationId === expected.operationId) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  throw new EncryptedDatabaseStoreError('conflict');
}

function parseRegistryCandidate(
  candidate: unknown,
): CollaborationDatabaseDeviceRegistry {
  try {
    return collaborationDatabaseDeviceRegistrySchema.parse(structuredClone(candidate));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseTombstoneInput(input: unknown): OperationDeduplicationTombstone {
  if (!isRecord(input) || !hasExactKeys(input, ['tombstone'])) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  try {
    return operationDeduplicationTombstoneSchema.parse(
      structuredClone(input['tombstone']),
    );
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseCheckpoint(value: unknown): CollaborationAuthorizationCheckpoint {
  try {
    return collaborationAuthorizationCheckpointSchema.parse(structuredClone(value));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseMutationProof(value: unknown): CollaborationMutationProof {
  try {
    return collaborationMutationProofSchema.parse(structuredClone(value));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

type ParsedProofRange = Readonly<{
  databaseId: DatabaseId;
  vaultId: VaultId;
  fromExclusive: CollaborativeProofPosition;
  toInclusive: CollaborativeProofPosition;
  limit: number;
}>;

function parseProofRangeInput(input: unknown): ParsedProofRange {
  if (
    !isRecord(input) ||
    !Object.keys(input).every((key) =>
      ['databaseId', 'vaultId', 'fromExclusive', 'toInclusive', 'limit'].includes(key),
    ) ||
    !hasField(input, 'databaseId') ||
    !hasField(input, 'vaultId') ||
    !hasField(input, 'fromExclusive') ||
    !hasField(input, 'toInclusive') ||
    !isRecord(input['fromExclusive']) ||
    !hasExactKeys(input['fromExclusive'], ['documentRevision', 'headDigest']) ||
    !isRecord(input['toInclusive']) ||
    !hasExactKeys(input['toInclusive'], ['documentRevision', 'headDigest'])
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  try {
    const databaseId = parseDatabaseId(input['databaseId']);
    const vaultId = parseVaultId(input['vaultId']);
    const fromExclusive = {
      documentRevision: Number(
        revisionSchema.parse(input['fromExclusive']['documentRevision']),
      ),
      headDigest: parseDigest(input['fromExclusive']['headDigest']),
    };
    const toInclusive = {
      documentRevision: Number(
        revisionSchema.parse(input['toInclusive']['documentRevision']),
      ),
      headDigest: parseDigest(input['toInclusive']['headDigest']),
    };
    const limitValue = input['limit'] ?? MAX_PROOF_RANGE_LIMIT;
    if (
      typeof limitValue !== 'number' ||
      !Number.isSafeInteger(limitValue) ||
      limitValue < 1 ||
      limitValue > MAX_PROOF_RANGE_LIMIT ||
      toInclusive.documentRevision <= fromExclusive.documentRevision ||
      toInclusive.documentRevision - fromExclusive.documentRevision > limitValue ||
      toInclusive.documentRevision - fromExclusive.documentRevision < 1
    ) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    return { databaseId, vaultId, fromExclusive, toInclusive, limit: limitValue };
  } catch (error: unknown) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function assertReplayOutcome(
  value: StoredDocument,
  expected: DurableOperationOutcome,
): DurableOperationOutcome {
  const actual = parseStoredOutcome(value);
  if (
    actual.databaseId !== expected.databaseId ||
    actual.vaultId !== expected.vaultId ||
    actual.operationId !== expected.operationId
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  if (actual.requestDigest !== expected.requestDigest) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  if (
    actual.outcomeDigest !== expected.outcomeDigest ||
    !recordsEqual(actual, expected)
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  return actual;
}

function assertReplayTombstone(
  value: StoredDocument,
  expected: DurableOperationOutcome,
): OperationDeduplicationTombstone {
  const actual = parseStoredTombstone(value);
  if (
    actual.databaseId !== expected.databaseId ||
    actual.vaultId !== expected.vaultId ||
    actual.operationId !== expected.operationId ||
    actual.operationType !== expected.operationType ||
    actual.requestDigest !== expected.requestDigest ||
    actual.outcomeDigest !== expected.outcomeDigest ||
    expected.signedMutationReceipt === undefined ||
    !recordsEqual(actual.signedMutationReceipt, expected.signedMutationReceipt)
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  return actual;
}

function assertRegistryFence(
  candidate: CollaborativeVaultDocument,
  registry: CollaborationDatabaseDeviceRegistry,
): void {
  if (
    registry.databaseId !== candidate.databaseId ||
    registry.authorityEpoch !== candidate.authorityEpoch ||
    registry.generation !== candidate.databaseDeviceGeneration ||
    registry.registryDigest !== candidate.databaseDeviceRegistryDigest
  ) {
    throw new EncryptedDatabaseStoreError('conflict');
  }
}

function assertDestructionRegistryFence(
  tombstone: CollaborationVaultDestructionTombstone,
  registry: CollaborationDatabaseDeviceRegistry,
): void {
  const { core, proofEntry } = tombstone;
  const witness = proofEntry.authorizationWitness;
  if (
    witness === undefined ||
    registry.databaseId !== tombstone.databaseId ||
    registry.authorityEpoch !== core.authorityEpoch ||
    registry.generation !== core.priorTuple.databaseDeviceGeneration ||
    registry.registryDigest !== core.priorTuple.databaseDeviceRegistryDigest ||
    !recordsEqual(registry, witness.databaseDeviceRegistry)
  ) {
    throw new EncryptedDatabaseStoreError('conflict');
  }
}

function registryDenialsAreMonotonic(
  current: CollaborationDatabaseDeviceRegistry,
  candidate: CollaborationDatabaseDeviceRegistry,
): boolean {
  return current.deniedDevices.every((denial) =>
    candidate.deniedDevices.some(
      (nextDenial) =>
        nextDenial.principalId === denial.principalId &&
        nextDenial.deviceId === denial.deviceId &&
        recordsEqual(nextDenial, denial),
    ),
  );
}

function assertWriterNotDenied(
  writerPrincipalId: string,
  writerDeviceId: string,
  registry: CollaborationDatabaseDeviceRegistry,
): void {
  if (
    registry.deniedDevices.some(
      (denial) =>
        denial.principalId === writerPrincipalId && denial.deviceId === writerDeviceId,
    )
  ) {
    throw new EncryptedDatabaseStoreError('conflict');
  }
}

function assertCheckpointMatchesStoredLink(
  checkpoint: CollaborationAuthorizationCheckpoint,
  storedProofEntry: Readonly<{
    entry: CollaborationMutationProof['entries'][number];
    finalizedMutationLinkDigest: Sha256Digest;
  }>,
): void {
  const link = storedProofEntry.entry.link;
  const commitment = link.commitment;
  const tuple = checkpoint.tuple;
  if (
    checkpoint.databaseId !== link.databaseId ||
    checkpoint.vaultId !== link.vaultId ||
    checkpoint.authorityDelegationDigest !== link.authorityDelegationDigest ||
    checkpoint.headDigest !== link.resultingHeadDigest ||
    checkpoint.finalizedMutationLinkDigest !==
      storedProofEntry.finalizedMutationLinkDigest ||
    tuple.authorityEpoch !== commitment.authorityEpoch ||
    tuple.documentRevision !== commitment.documentRevision ||
    tuple.membershipRevision !== commitment.membershipRevision ||
    tuple.policyRevision !== commitment.policyRevision ||
    tuple.keyEpoch !== commitment.keyEpoch ||
    tuple.databaseDeviceGeneration !== commitment.databaseDeviceGeneration ||
    tuple.databaseDeviceRegistryDigest !== commitment.databaseDeviceRegistryDigest ||
    tuple.authorizationStateDigest !== commitment.authorizationStateDigest ||
    checkpoint.authorizationStateDigest !== commitment.authorizationStateDigest
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function assertImmutableDelegation(
  prior: CollaborativeVaultDocument,
  candidate: CollaborativeVaultDocument,
): void {
  if (
    prior.authorityDelegationDigest !== candidate.authorityDelegationDigest ||
    !recordsEqual(prior.authorityDelegation, candidate.authorityDelegation)
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function assertDestructionPriorBindings(
  prior: CollaborativeVaultDocument,
  tombstone: CollaborationVaultDestructionTombstone,
): void {
  const { core, proofEntry } = tombstone;
  const commitment = proofEntry.link.commitment;
  const witness = proofEntry.authorizationWitness;
  if (
    witness === undefined ||
    prior.databaseId !== tombstone.databaseId ||
    prior.vaultId !== tombstone.vaultId ||
    prior.authorityEpoch !== core.authorityEpoch ||
    prior.authorityDelegation.databaseId !== tombstone.databaseId ||
    prior.authorityDelegation.vaultId !== tombstone.vaultId ||
    prior.authorityDelegation.authorityEpoch !== core.authorityEpoch ||
    prior.authorityDelegationDigest !== core.authorityDelegationDigest ||
    prior.headDigest !== core.priorHeadDigest ||
    !tuplesEqual(currentTupleFromCandidate(prior), core.priorTuple) ||
    prior.encryptedEnvelopesDigest !== commitment.encryptedEnvelopesDigest ||
    prior.policyDigest !== commitment.policyDigest ||
    !recordsEqual(
      prior.databaseAuthorityRecoveryEnvelope,
      witness.databaseAuthorityRecoveryEnvelope,
    )
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function assertPermanentDestructionReplay(
  actual: CollaborationVaultDestructionTombstone,
  expected: CollaborationVaultDestructionTombstone,
): void {
  if (recordsEqual(actual, expected)) return;
  if (actual.core.operationId === expected.core.operationId) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  throw new EncryptedDatabaseStoreError('conflict');
}

function assertTombstoneMatchesOutcome(
  tombstone: OperationDeduplicationTombstone,
  outcome: DurableOperationOutcome,
): void {
  if (
    tombstone.databaseId !== outcome.databaseId ||
    tombstone.vaultId !== outcome.vaultId ||
    tombstone.operationId !== outcome.operationId ||
    tombstone.operationType !== outcome.operationType ||
    tombstone.requestDigest !== outcome.requestDigest ||
    tombstone.outcomeDigest !== outcome.outcomeDigest ||
    outcome.signedMutationReceipt === undefined ||
    !recordsEqual(tombstone.signedMutationReceipt, outcome.signedMutationReceipt)
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function assertSameTombstone(
  left: OperationDeduplicationTombstone,
  right: OperationDeduplicationTombstone,
): void {
  if (!recordsEqual(left, right)) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function priorTupleFromCandidate(
  candidate: CollaborativeVaultDocument,
): CollaborationTuple {
  const commitment = candidate.currentMutationLink.commitment;
  return {
    authorityEpoch: commitment.previousAuthorityEpoch,
    databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
    databaseDeviceRegistryDigest: commitment.previousDatabaseDeviceRegistryDigest,
    documentRevision: commitment.previousDocumentRevision,
    membershipRevision: commitment.previousMembershipRevision,
    policyRevision: commitment.previousPolicyRevision,
    keyEpoch: commitment.previousKeyEpoch,
    authorizationStateDigest: commitment.previousAuthorizationStateDigest,
  };
}

function currentTupleFromCandidate(
  candidate: CollaborativeVaultDocument,
): CollaborationTuple {
  return {
    authorityEpoch: candidate.authorityEpoch,
    databaseDeviceGeneration: candidate.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
    documentRevision: candidate.documentRevision,
    membershipRevision: candidate.membershipRevision,
    policyRevision: candidate.policyRevision,
    keyEpoch: candidate.keyEpoch,
    authorizationStateDigest: candidate.authorizationStateDigest,
  };
}

type CollaborationTuple = Readonly<{
  authorityEpoch: number;
  databaseDeviceGeneration: number;
  databaseDeviceRegistryDigest: string;
  documentRevision: number;
  membershipRevision: number;
  policyRevision: number;
  keyEpoch: number;
  authorizationStateDigest: string;
}>;

function tuplesEqual(left: CollaborationTuple, right: CollaborationTuple): boolean {
  return (
    left.authorityEpoch === right.authorityEpoch &&
    left.databaseDeviceGeneration === right.databaseDeviceGeneration &&
    left.databaseDeviceRegistryDigest === right.databaseDeviceRegistryDigest &&
    left.documentRevision === right.documentRevision &&
    left.membershipRevision === right.membershipRevision &&
    left.policyRevision === right.policyRevision &&
    left.keyEpoch === right.keyEpoch &&
    left.authorizationStateDigest === right.authorizationStateDigest
  );
}

function priorVaultFilter(
  candidate: CollaborativeVaultDocument,
  priorTuple: CollaborationTuple,
): Record<string, unknown> {
  return {
    _id: collaborativeVaultKey(candidate.databaseId, candidate.vaultId),
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    authorityEpoch: priorTuple.authorityEpoch,
    databaseDeviceGeneration: priorTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: priorTuple.databaseDeviceRegistryDigest,
    documentRevision: priorTuple.documentRevision,
    membershipRevision: priorTuple.membershipRevision,
    policyRevision: priorTuple.policyRevision,
    keyEpoch: priorTuple.keyEpoch,
    headDigest: candidate.previousHeadDigest,
    authorizationStateDigest:
      candidate.currentMutationLink.commitment.previousAuthorizationStateDigest,
    authorityDelegationDigest: candidate.authorityDelegationDigest,
  };
}

function destructionPriorVaultFilter(
  tombstone: CollaborationVaultDestructionTombstone,
): Record<string, unknown> {
  const { core } = tombstone;
  return {
    _id: collaborativeVaultKey(tombstone.databaseId, tombstone.vaultId),
    databaseId: tombstone.databaseId,
    vaultId: tombstone.vaultId,
    authorityEpoch: core.priorTuple.authorityEpoch,
    databaseDeviceGeneration: core.priorTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: core.priorTuple.databaseDeviceRegistryDigest,
    documentRevision: core.priorTuple.documentRevision,
    membershipRevision: core.priorTuple.membershipRevision,
    policyRevision: core.priorTuple.policyRevision,
    keyEpoch: core.priorTuple.keyEpoch,
    headDigest: core.priorHeadDigest,
    authorizationStateDigest: core.priorTuple.authorizationStateDigest,
    authorityDelegationDigest: core.authorityDelegationDigest,
  };
}

function legacyVaultFilter(source: DatabaseVaultDocument): Record<string, unknown> {
  return {
    _id: collaborativeVaultKey(source.databaseId, source.id),
    databaseId: source.databaseId,
    id: source.id,
    schemaVersion: source.schemaVersion,
    cryptographicVersion: source.cryptographicVersion,
    currentKeyVersion: source.currentKeyVersion,
    databaseRevision: source.databaseRevision,
    revision: source.revision,
    wrappedVaultRoot: source.wrappedVaultRoot,
    encryptedPayload: source.encryptedPayload,
    payloadMetadataDigest: source.payloadMetadataDigest,
    createdAt: source.createdAt,
    updatedAt: source.updatedAt,
  };
}

function migrationMarkerFilter(
  marker: CollaborationMigrationPreparedMarker,
): Record<string, unknown> {
  return {
    _id: collaborativeVaultKey(marker.databaseId, marker.vaultId),
    ...marker,
  };
}

function parseStoredCollaborativeVault(value: unknown): CollaborativeVaultDocument {
  try {
    return collaborativeVaultDocumentSchema.parse(
      structuredClone(withoutMongoId(value)),
    );
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseStoredLegacyVault(value: unknown): DatabaseVaultDocument {
  try {
    return databaseVaultDocumentSchema.parse(structuredClone(withoutMongoId(value)));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseStoredMigrationMarker(
  value: unknown,
): CollaborationMigrationPreparedMarker | CollaborationMigrationActiveMarker {
  try {
    return collaborationMigrationMarkerSchema.parse(
      structuredClone(withoutMongoId(value)),
    );
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseStoredDiscoveryRecord(value: unknown): CollaborationDiscoveryRecord {
  try {
    return collaborationDiscoveryRecordSchema.parse(structuredClone(value));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseStoredRegistry(value: unknown): CollaborationDatabaseDeviceRegistry {
  try {
    const stored = withoutMongoId(value);
    const { storagePublicationFence: ignoredStorageFence, ...registry } = stored;
    void ignoredStorageFence;
    return collaborationDatabaseDeviceRegistrySchema.parse(structuredClone(registry));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseStoredOutcome(value: unknown): DurableOperationOutcome {
  try {
    return durableOperationOutcomeSchema.parse(structuredClone(withoutMongoId(value)));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

async function discardUnsignedOutcome(
  collection: Collection<StoredDocument>,
  session: ClientSession,
  outcome: DurableOperationOutcome,
): Promise<void> {
  if (outcome.state === 'committed' || outcome.signedMutationReceipt !== undefined) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  const removed = await collection.deleteOne(
    {
      _id: operationIdentityKey(
        outcome.databaseId,
        outcome.vaultId,
        outcome.operationId,
      ),
      databaseId: outcome.databaseId,
      vaultId: outcome.vaultId,
      operationId: outcome.operationId,
      state: outcome.state,
      requestDigest: outcome.requestDigest,
      outcomeDigest: outcome.outcomeDigest,
    },
    { session },
  );
  if (removed.deletedCount !== 1) {
    throw new EncryptedDatabaseStoreError('conflict');
  }
}

function parseStoredTombstone(value: unknown): OperationDeduplicationTombstone {
  try {
    return operationDeduplicationTombstoneSchema.parse(
      structuredClone(withoutMongoId(value)),
    );
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseStoredVaultDestructionTombstone(
  value: unknown,
): CollaborationVaultDestructionTombstone {
  try {
    return collaborationVaultDestructionTombstoneSchema.parse(
      structuredClone(withoutMongoId(value)),
    );
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function storedMutationProofEntryDocument(
  entry: CollaborationMutationProof['entries'][number],
  outcome: DurableOperationOutcome,
): StoredDocument {
  const finalizedMutationLinkDigest = outcome.finalizedMutationLinkDigest;
  if (finalizedMutationLinkDigest === undefined) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  const link = entry.link;
  return {
    ...entry,
    _id: mutationLinkKey(link.databaseId, link.vaultId, link.commitment.operationId),
    databaseId: link.databaseId,
    vaultId: link.vaultId,
    finalizedMutationLinkDigest,
  };
}

function parseStoredMutationProofEntry(value: unknown): Readonly<{
  entry: CollaborationMutationProof['entries'][number];
  finalizedMutationLinkDigest: Sha256Digest;
}> {
  try {
    const stored = withoutMongoId(value);
    const finalizedMutationLinkDigest = sha256DigestSchema.parse(
      stored['finalizedMutationLinkDigest'],
    );
    const {
      finalizedMutationLinkDigest: ignoredDigest,
      databaseId: ignoredDatabaseId,
      vaultId: ignoredVaultId,
      ...entryValue
    } = stored;
    void ignoredDigest;
    void ignoredDatabaseId;
    void ignoredVaultId;
    const entry = collaborationMutationProofEntrySchema.parse(
      structuredClone(entryValue),
    );
    return { entry, finalizedMutationLinkDigest };
  } catch (error: unknown) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseStoredCheckpoint(value: unknown): CollaborationAuthorizationCheckpoint {
  try {
    return collaborationAuthorizationCheckpointSchema.parse(
      structuredClone(withoutMongoId(value)),
    );
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function withoutMongoId(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  const { _id: mongoId, ...document } = value as Record<string, unknown>;
  void mongoId;
  return document;
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

function parseOperationId(value: unknown): string {
  try {
    return collaborationOperationIdSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseRevision(value: unknown): number {
  try {
    return Number(revisionSchema.parse(value));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseDigest(value: unknown): Sha256Digest {
  try {
    return sha256DigestSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseDiscoveryTags(
  values: readonly Sha256Digest[] | Sha256Digest,
): readonly Sha256Digest[] {
  const candidates = typeof values === 'string' ? [values] : values;
  if (
    !Array.isArray(candidates) ||
    candidates.length === 0 ||
    candidates.length > MAX_DISCOVERY_LIMIT
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  try {
    const parsed = candidates.map((value) => sha256DigestSchema.parse(value));
    return [...new Set(parsed)];
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseDiscoveryLimit(value: unknown): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > MAX_DISCOVERY_LIMIT
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  return value;
}

function collaborativeVaultKey(databaseId: DatabaseId, vaultId: VaultId): string {
  return `${databaseId}:${vaultId}`;
}

function databaseDeviceRegistryKey(databaseId: DatabaseId): string {
  return databaseId;
}

function operationIdentityKey(
  databaseId: DatabaseId,
  vaultId: VaultId,
  operationId: string,
): string {
  return `${databaseId}:${vaultId}:${operationId}`;
}

function mutationLinkKey(
  databaseId: DatabaseId,
  vaultId: VaultId,
  operationId: string,
): string {
  return operationIdentityKey(databaseId, vaultId, operationId);
}

function authorizationCheckpointKey(
  databaseId: DatabaseId,
  vaultId: VaultId,
  checkpointId: string,
): string {
  return `${databaseId}:${vaultId}:${checkpointId}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasField(value: unknown, field: string): boolean {
  return isRecord(value) && Object.prototype.hasOwnProperty.call(value, field);
}

function recordsEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) {
      return false;
    }
    return left.every((value, index) => recordsEqual(value, right[index]));
  }
  if (!isRecord(left) || !isRecord(right)) return false;
  // Canonical JSON and MongoDB both represent optional `undefined` object
  // properties by omitting them. Treat an explicitly present optional as the
  // same wire value as absence, while retaining exact array/value comparison.
  const leftKeys = Object.keys(left)
    .filter((key) => left[key] !== undefined)
    .sort();
  const rightKeys = Object.keys(right)
    .filter((key) => right[key] !== undefined)
    .sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) => key === rightKeys[index] && recordsEqual(left[key], right[key]),
    )
  );
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => key in value);
}

function isDuplicateKeyError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 11_000
  );
}

function mapCollaborativeOperationError(
  error: unknown,
  fallback: EncryptedDatabaseStoreErrorCode = 'operation',
): EncryptedDatabaseStoreError {
  if (error instanceof EncryptedDatabaseStoreError) return error;
  // A duplicate on a CAS insert/upsert means another writer won the race.
  // It is therefore a stale/conflicting operation, never a generic "exists"
  // result that callers might treat as an ordinary create failure.
  if (isDuplicateKeyError(error)) return new EncryptedDatabaseStoreError('conflict');
  return new EncryptedDatabaseStoreError(fallback);
}
