import { randomBytes } from 'node:crypto';

import { Binary, MongoClient, type Db } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationAuthorityDelegationSchema,
  collaborationMigrationActiveMarkerSchema,
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationRequestSchema,
  collaborationMutationProofEntrySchema,
  collaborationRevisionTupleSchema,
  collaborationVaultDestructionTombstoneSchema,
  collaborativeVaultDocumentSchema,
  databaseVaultDocumentSchema,
  durableOperationOutcomeSchema,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationAuthorityDelegation,
  type CollaborationMigrationActiveMarker,
  type CollaborationMigrationPreparedMarker,
  type CollaborationMutationProof,
  type CollaborationRevisionTuple,
  type CollaborationVaultDestructionTombstone,
  type CollaborativeVaultDocument,
  type DatabaseId,
  type DatabaseVaultDocument,
  type DurableOperationOutcome,
  type Sha256Digest,
  type VaultId,
} from '@kavrix/schemas';

import {
  computeAadMetadataDigest,
  computeEncryptedPayloadDigest,
  encryptCollaborationEnvelope,
  zeroize,
} from '@kavrix/crypto';
import { MongoEncryptedDatabaseStore } from '../src/index.js';
import {
  databaseRevision,
  makeDatabaseId,
  makeVaultId,
  vaultDocument,
  vaultRevision,
} from './database-store-fixtures.js';

const mongoUri = process.env['KAVRIX_MONGODB_URI'];
const databaseName = `kavrixit_${randomBytes(20).toString('hex')}`;
const integration = mongoUri === undefined ? describe.skip : describe;

const LEGACY_VAULT_COLLECTION = 'kavrix_vaults';
const COLLABORATIVE_VAULT_COLLECTION = 'kavrix_collaborative_vaults';
const REGISTRY_COLLECTION = 'kavrix_collaboration_device_registries';
const OUTCOME_COLLECTION = 'kavrix_collaboration_operation_outcomes';
const TOMBSTONE_COLLECTION = 'kavrix_collaboration_operation_tombstones';
const DESTRUCTION_COLLECTION = 'kavrix_collaboration_vault_destruction_tombstones';
const LINK_COLLECTION = 'kavrix_collaboration_finalized_mutation_links';
const CHECKPOINT_COLLECTION = 'kavrix_collaboration_authorization_checkpoints';

const connectionOptions = {
  connectTimeoutMS: 5_000,
  serverSelectionTimeoutMS: 5_000,
  socketTimeoutMS: 10_000,
  timeoutMS: 10_000,
  ignoreUndefined: true,
};

type StoredDocument = Readonly<{ _id: string }> & Record<string, unknown>;

let store: MongoEncryptedDatabaseStore | undefined;
let rawClient: MongoClient | undefined;
let database: Db | undefined;
let plaintextCanary = '';
let plaintextCanaryBytes: Uint8Array | undefined;

integration('Mongo collaborative vault replica-set integration', () => {
  beforeAll(async () => {
    const configuredMongoUri = requireMongoUri();
    store = await MongoEncryptedDatabaseStore.connect(configuredMongoUri, databaseName);
    rawClient = new MongoClient(configuredMongoUri, connectionOptions);
    await rawClient.connect();
    database = rawClient.db(databaseName);
    const canarySeed = randomBytes(32);
    plaintextCanary = canarySeed.toString('base64url');
    plaintextCanaryBytes = new Uint8Array(canarySeed);
    zeroize(canarySeed);
  });

  afterAll(async () => {
    if (rawClient !== undefined) await rawClient.close();
    if (store !== undefined) await store.close();
    if (plaintextCanaryBytes !== undefined) zeroize(plaintextCanaryBytes);
    if (mongoUri === undefined) return;
    if (!/^kavrixit_[A-Za-z0-9_-]{1,64}$/u.test(databaseName)) {
      throw new Error(
        'Refusing to drop a database outside the generated test namespace',
      );
    }
    const cleanupClient = new MongoClient(mongoUri, connectionOptions);
    try {
      await cleanupClient.connect();
      await cleanupClient.db(databaseName).dropDatabase();
    } finally {
      await cleanupClient.close();
    }
  });

  it('creates every required collaboration index before first transaction use', async () => {
    const activeDatabase = requireDatabase();
    const expectedIndexes: readonly [
      collectionName: string,
      indexName: string,
      key: Readonly<Record<string, 1 | -1>>,
      unique: boolean,
    ][] = [
      [
        LEGACY_VAULT_COLLECTION,
        'database_vault_identity',
        { databaseId: 1, id: 1 },
        true,
      ],
      [
        COLLABORATIVE_VAULT_COLLECTION,
        'collaborative_vault_identity',
        { databaseId: 1, vaultId: 1 },
        true,
      ],
      [
        REGISTRY_COLLECTION,
        'database_device_registry_identity',
        { databaseId: 1 },
        true,
      ],
      [
        OUTCOME_COLLECTION,
        'collaborative_operation_outcome_identity',
        { databaseId: 1, vaultId: 1, operationId: 1 },
        true,
      ],
      [
        TOMBSTONE_COLLECTION,
        'collaborative_operation_tombstone_identity',
        { databaseId: 1, vaultId: 1, operationId: 1 },
        true,
      ],
      [
        DESTRUCTION_COLLECTION,
        'collaborative_vault_destruction_identity',
        { databaseId: 1, vaultId: 1 },
        true,
      ],
      [
        CHECKPOINT_COLLECTION,
        'collaborative_authorization_checkpoint_identity',
        { databaseId: 1, vaultId: 1, checkpointId: 1 },
        true,
      ],
      [
        CHECKPOINT_COLLECTION,
        'collaborative_authorization_checkpoint_digest',
        { databaseId: 1, vaultId: 1, checkpointDigest: 1 },
        true,
      ],
      [
        CHECKPOINT_COLLECTION,
        'collaborative_authorization_checkpoint_revision',
        { databaseId: 1, vaultId: 1, 'tuple.documentRevision': 1 },
        false,
      ],
      [
        LINK_COLLECTION,
        'collaborative_mutation_link_head',
        { databaseId: 1, vaultId: 1, 'link.resultingHeadDigest': 1 },
        true,
      ],
      [
        LINK_COLLECTION,
        'collaborative_mutation_link_operation',
        { databaseId: 1, vaultId: 1, 'link.commitment.operationId': 1 },
        true,
      ],
      [
        LINK_COLLECTION,
        'collaborative_mutation_link_revision',
        { databaseId: 1, vaultId: 1, 'link.commitment.documentRevision': 1 },
        true,
      ],
      [
        LINK_COLLECTION,
        'collaborative_authorization_witness_lookup',
        {
          databaseId: 1,
          vaultId: 1,
          'authorizationWitness.tuple.authorizationStateDigest': 1,
          'authorizationWitness.tuple.documentRevision': -1,
        },
        false,
      ],
    ];
    for (const [
      collectionName,
      indexName,
      expectedKey,
      expectedUnique,
    ] of expectedIndexes) {
      const indexes = await activeDatabase.collection(collectionName).indexes();
      const index = indexes.find((candidate) => candidate.name === indexName);
      expect(index?.key).toEqual(expectedKey);
      if (expectedUnique) expect(index?.unique).toBe(true);
      else expect(index).not.toHaveProperty('unique', true);
    }
    for (const [collectionName, indexName] of [
      [TOMBSTONE_COLLECTION, 'collaborative_operation_tombstone_identity'],
      [DESTRUCTION_COLLECTION, 'collaborative_vault_destruction_identity'],
    ] as const) {
      const indexes = await activeDatabase.collection(collectionName).indexes();
      expect(indexes.find((index) => index.name === indexName)).not.toHaveProperty(
        'expireAfterSeconds',
      );
    }
    await assertDatabaseCanaryAbsent();
  });

  it('activates genesis, commits one mutation atomically, replays exactly, and rejects a different request with the same ID', async () => {
    const context = makeFixtureContext('mutation');
    const genesis = await makeMigrationArtifacts(context);
    await seedAndActivateGenesis(genesis);

    const activeStore = requireStore();
    const activeDatabase = requireDatabase();
    const mutation = makeOrdinaryArtifacts(context, genesis.candidate);
    await expect(
      activeStore.publishCollaborativeVault({
        candidate: withForbiddenPlaintextCanary(mutation.candidate),
        proofEntry: mutation.proofEntry,
        outcome: mutation.outcome,
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
    await expect(
      activeStore.getCollaborativeVault(context.databaseId, context.vaultId),
    ).resolves.toEqual(genesis.candidate);
    await expect(
      activeStore.getCollaborativeOperationOutcome(
        context.databaseId,
        context.vaultId,
        mutation.outcome.operationId,
      ),
    ).resolves.toBeNull();
    await expect(
      activeStore.publishCollaborativeVault({
        candidate: mutation.candidate,
        proofEntry: mutation.proofEntry,
        outcome: mutation.outcome,
      }),
    ).resolves.toEqual(mutation.outcome);
    await expect(
      activeStore.publishCollaborativeVault({
        candidate: mutation.candidate,
        proofEntry: mutation.proofEntry,
        outcome: mutation.outcome,
      }),
    ).resolves.toEqual(mutation.outcome);

    await expect(
      activeStore.getCollaborativeVault(context.databaseId, context.vaultId),
    ).resolves.toEqual(mutation.candidate);
    await expect(
      activeStore.getCollaborativeFinalizedMutationLinkByOperation(
        context.databaseId,
        context.vaultId,
        mutation.outcome.operationId,
      ),
    ).resolves.toEqual(mutation.proofEntry.link);
    await expect(
      activeStore.getCollaborativeFinalizedMutationLinkByHead(
        context.databaseId,
        context.vaultId,
        mutation.candidate.headDigest,
      ),
    ).resolves.toEqual(mutation.proofEntry.link);
    await expect(
      activeStore.getCollaborativeOperationOutcome(
        context.databaseId,
        context.vaultId,
        mutation.outcome.operationId,
      ),
    ).resolves.toEqual(mutation.outcome);

    const conflictingRequest = makeOrdinaryArtifacts(
      context,
      genesis.candidate,
      mutation.outcome.operationId,
    );
    await expect(
      activeStore.publishCollaborativeVault({
        candidate: conflictingRequest.candidate,
        proofEntry: conflictingRequest.proofEntry,
        outcome: conflictingRequest.outcome,
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
    await expect(
      activeStore.getCollaborativeVault(context.databaseId, context.vaultId),
    ).resolves.toEqual(mutation.candidate);
    await expect(
      activeStore.getCollaborativeFinalizedMutationLinkByOperation(
        context.databaseId,
        context.vaultId,
        mutation.outcome.operationId,
      ),
    ).resolves.toEqual(mutation.proofEntry.link);
    await expect(
      activeStore.getCollaborativeFinalizedMutationLinkByHead(
        context.databaseId,
        context.vaultId,
        mutation.candidate.headDigest,
      ),
    ).resolves.toEqual(mutation.proofEntry.link);
    await expect(
      activeStore.getCollaborativeOperationOutcome(
        context.databaseId,
        context.vaultId,
        mutation.outcome.operationId,
      ),
    ).resolves.toEqual(mutation.outcome);
    await expect(
      activeDatabase
        .collection<StoredDocument>(REGISTRY_COLLECTION)
        .findOne({ _id: context.databaseId }),
    ).resolves.toEqual({
      _id: context.databaseId,
      ...genesis.preparedMarker.registryCandidate,
      storagePublicationFence: `${context.databaseId}:${context.vaultId}:${mutation.outcome.operationId}`,
    });
    await assertDatabaseCanaryAbsent();
  });

  it('rolls back the document, registry fence, link, and outcome after a late unique-link conflict', async () => {
    const context = makeFixtureContext('rollback');
    const genesis = await makeMigrationArtifacts(context);
    await seedAndActivateGenesis(genesis);

    const activeStore = requireStore();
    const mutation = makeOrdinaryArtifacts(context, genesis.candidate);
    const conflictingLink = makeOrdinaryArtifacts(
      context,
      genesis.candidate,
      `${context.suffix}-head-conflict`,
      mutation.candidate.headDigest,
    );
    const activeDatabase = requireDatabase();
    const registryBefore = await activeDatabase
      .collection<StoredDocument>(REGISTRY_COLLECTION)
      .findOne({ _id: context.databaseId });
    const conflictingStoredProofEntry = storedProofEntry(
      conflictingLink.proofEntry,
      conflictingLink.outcome,
    );
    await activeDatabase
      .collection<StoredDocument>(LINK_COLLECTION)
      .insertOne(conflictingStoredProofEntry);

    await expect(
      activeStore.publishCollaborativeVault({
        candidate: mutation.candidate,
        proofEntry: mutation.proofEntry,
        outcome: mutation.outcome,
      }),
    ).rejects.toMatchObject({ code: 'conflict' });
    await expect(
      activeStore.getCollaborativeVault(context.databaseId, context.vaultId),
    ).resolves.toEqual(genesis.candidate);
    await expect(
      activeStore.getCollaborativeOperationOutcome(
        context.databaseId,
        context.vaultId,
        mutation.outcome.operationId,
      ),
    ).resolves.toBeNull();
    await expect(
      activeStore.getCollaborativeFinalizedMutationLinkByOperation(
        context.databaseId,
        context.vaultId,
        mutation.outcome.operationId,
      ),
    ).resolves.toBeNull();

    const registry = await activeDatabase
      .collection<StoredDocument>(REGISTRY_COLLECTION)
      .findOne({ _id: context.databaseId });
    expect(registry).toEqual({
      _id: context.databaseId,
      ...genesis.preparedMarker.registryCandidate,
    });
    expect(registry).toEqual(registryBefore);
    expect(registry).not.toHaveProperty('storagePublicationFence');
    await expect(
      activeDatabase.collection<StoredDocument>(LINK_COLLECTION).findOne({
        _id: `${context.databaseId}:${context.vaultId}:${mutation.outcome.operationId}`,
      }),
    ).resolves.toBeNull();
    const conflictingStoredId = `${context.databaseId}:${context.vaultId}:${conflictingLink.outcome.operationId}`;
    await expect(
      activeDatabase
        .collection<StoredDocument>(LINK_COLLECTION)
        .findOne({ _id: conflictingStoredId }),
    ).resolves.toEqual(conflictingStoredProofEntry);
    await expect(
      activeDatabase.collection<StoredDocument>(LINK_COLLECTION).deleteOne({
        _id: conflictingStoredId,
        databaseId: context.databaseId,
        vaultId: context.vaultId,
        'link.commitment.operationId': conflictingLink.outcome.operationId,
      }),
    ).resolves.toMatchObject({ deletedCount: 1 });
    await expect(
      activeStore.publishCollaborativeVault({
        candidate: mutation.candidate,
        proofEntry: mutation.proofEntry,
        outcome: mutation.outcome,
      }),
    ).resolves.toEqual(mutation.outcome);
    await expect(
      activeStore.getCollaborativeVault(context.databaseId, context.vaultId),
    ).resolves.toEqual(mutation.candidate);
    await expect(
      activeStore.getCollaborativeFinalizedMutationLinkByOperation(
        context.databaseId,
        context.vaultId,
        mutation.outcome.operationId,
      ),
    ).resolves.toEqual(mutation.proofEntry.link);
    await expect(
      activeStore.getCollaborativeFinalizedMutationLinkByHead(
        context.databaseId,
        context.vaultId,
        mutation.candidate.headDigest,
      ),
    ).resolves.toEqual(mutation.proofEntry.link);
    await expect(
      activeStore.getCollaborativeOperationOutcome(
        context.databaseId,
        context.vaultId,
        mutation.outcome.operationId,
      ),
    ).resolves.toEqual(mutation.outcome);
    await expect(
      activeDatabase
        .collection<StoredDocument>(REGISTRY_COLLECTION)
        .findOne({ _id: context.databaseId }),
    ).resolves.toEqual({
      _id: context.databaseId,
      ...genesis.preparedMarker.registryCandidate,
      storagePublicationFence: `${context.databaseId}:${context.vaultId}:${mutation.outcome.operationId}`,
    });
    await assertDatabaseCanaryAbsent();
  });

  it('destroys a vault atomically, stores permanent terminal evidence, replays exactly, and rejects resurrection', async () => {
    const context = makeFixtureContext('destruction');
    const genesis = await makeMigrationArtifacts(context);
    await seedAndActivateGenesis(genesis);

    const activeStore = requireStore();
    const destruction = makeDestructionArtifacts(
      context,
      genesis.candidate,
      undefined,
      genesis.preparedMarker.registryCandidate,
    );
    await expect(
      activeStore.destroyCollaborativeVault({
        tombstone: destruction.tombstone,
        outcome: destruction.outcome,
      }),
    ).resolves.toEqual(destruction.outcome);
    await expect(
      activeStore.getCollaborativeVault(context.databaseId, context.vaultId),
    ).resolves.toBeNull();
    await expect(
      activeStore.getCollaborativeVaultDestructionTombstone(
        context.databaseId,
        context.vaultId,
      ),
    ).resolves.toEqual(destruction.tombstone);
    await expect(
      activeStore.getCollaborativeFinalizedMutationLinkByOperation(
        context.databaseId,
        context.vaultId,
        destruction.outcome.operationId,
      ),
    ).resolves.toEqual(destruction.tombstone.proofEntry.link);
    await expect(
      activeStore.getCollaborativeOperationOutcome(
        context.databaseId,
        context.vaultId,
        destruction.outcome.operationId,
      ),
    ).resolves.toEqual(destruction.outcome);

    const activeDatabase = requireDatabase();
    await expect(
      activeDatabase
        .collection<StoredDocument>(COLLABORATIVE_VAULT_COLLECTION)
        .findOne({
          _id: `${context.databaseId}:${context.vaultId}`,
        }),
    ).resolves.toBeNull();
    await expect(
      activeStore.destroyCollaborativeVault({
        tombstone: destruction.tombstone,
        outcome: destruction.outcome,
      }),
    ).resolves.toEqual(destruction.outcome);

    const incompatible = makeDestructionArtifacts(
      context,
      genesis.candidate,
      destruction.outcome.operationId,
    );
    await expect(
      activeStore.destroyCollaborativeVault({
        tombstone: incompatible.tombstone,
        outcome: incompatible.outcome,
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
    await expect(
      activeStore.activateCollaborativeGenesis({
        preparedMarker: genesis.preparedMarker,
        candidate: genesis.candidate,
        proofEntry: genesis.proofEntry,
        outcome: genesis.outcome,
        activeMarker: genesis.activeMarker,
      }),
    ).rejects.toMatchObject({ code: 'conflict' });
    const postDestructionMutation = makeOrdinaryArtifacts(context, genesis.candidate);
    await expect(
      activeStore.publishCollaborativeVault({
        candidate: postDestructionMutation.candidate,
        proofEntry: postDestructionMutation.proofEntry,
        outcome: postDestructionMutation.outcome,
      }),
    ).rejects.toMatchObject({ code: 'conflict' });
    await expect(
      activeStore.getCollaborativeVault(context.databaseId, context.vaultId),
    ).resolves.toBeNull();
    await expect(
      activeStore.getCollaborativeVaultDestructionTombstone(
        context.databaseId,
        context.vaultId,
      ),
    ).resolves.toEqual(destruction.tombstone);
    await assertDatabaseCanaryAbsent();
  });
});

function requireStore(): MongoEncryptedDatabaseStore {
  if (store === undefined) throw new Error('Integration store was not initialized');
  return store;
}

function requireDatabase(): Db {
  if (database === undefined)
    throw new Error('Integration database was not initialized');
  return database;
}

function requireMongoUri(): string {
  if (mongoUri === undefined)
    throw new Error('Mongo integration URI was not configured');
  return mongoUri;
}

function requirePlaintextCanaryBytes(): Uint8Array {
  if (plaintextCanaryBytes === undefined) {
    throw new Error('Plaintext canary was not initialized');
  }
  return plaintextCanaryBytes;
}

async function seedAndActivateGenesis(artifacts: MigrationArtifacts): Promise<void> {
  const activeDatabase = requireDatabase();
  const activeStore = requireStore();
  await activeDatabase.collection<StoredDocument>(LEGACY_VAULT_COLLECTION).insertOne({
    ...artifacts.source,
    _id: `${artifacts.source.databaseId}:${artifacts.source.id}`,
  });
  await expect(
    activeStore.beginCollaborativeMigration({
      request: artifacts.request,
      preparedMarker: artifacts.preparedMarker,
    }),
  ).resolves.toEqual(artifacts.preparedMarker);
  await expect(
    activeStore.activateCollaborativeGenesis({
      preparedMarker: artifacts.preparedMarker,
      candidate: artifacts.candidate,
      proofEntry: artifacts.proofEntry,
      outcome: artifacts.outcome,
      activeMarker: artifacts.activeMarker,
    }),
  ).resolves.toEqual(artifacts.outcome);
}

function withForbiddenPlaintextCanary(
  candidate: CollaborativeVaultDocument,
): CollaborativeVaultDocument {
  const canaryBytes = requirePlaintextCanaryBytes();
  const tampered = structuredClone(candidate) as unknown as {
    encryptedPayload: Record<string, unknown>;
  };
  tampered.encryptedPayload['plaintextCanary'] = plaintextCanary;
  tampered.encryptedPayload['plaintextCanaryBytes'] = Uint8Array.from(canaryBytes);
  return tampered as unknown as CollaborativeVaultDocument;
}

async function assertDatabaseCanaryAbsent(): Promise<void> {
  const activeDatabase = requireDatabase();
  const bytesToFind = requirePlaintextCanaryBytes();
  const collections = await activeDatabase.listCollections().toArray();
  for (const collectionInfo of collections) {
    const documents = await activeDatabase
      .collection(collectionInfo.name)
      .find({})
      .toArray();
    for (const document of documents) {
      assertCanaryAbsent(document, plaintextCanary, bytesToFind);
    }
  }
}

function assertCanaryAbsent(
  value: unknown,
  canary: string,
  canaryBytes: Uint8Array,
  seen = new WeakSet<object>(),
): void {
  if (typeof value === 'string') {
    expect(value).not.toContain(canary);
    return;
  }
  if (value instanceof Uint8Array) {
    expect(containsBytes(value, canaryBytes)).toBe(false);
    return;
  }
  if (value === null || value === undefined) return;
  if (typeof value !== 'object') return;
  if (seen.has(value)) return;
  seen.add(value);
  if (value instanceof Binary) {
    expect(containsBytes(value.buffer, canaryBytes)).toBe(false);
  }
  for (const nested of Object.values(value)) {
    assertCanaryAbsent(nested, canary, canaryBytes, seen);
  }
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.byteLength === 0 || needle.byteLength > haystack.byteLength) return false;
  for (let offset = 0; offset <= haystack.byteLength - needle.byteLength; offset += 1) {
    let matches = true;
    for (let index = 0; index < needle.byteLength; index += 1) {
      if (haystack[offset + index] !== needle[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

interface FixtureContext {
  suffix: string;
  databaseId: DatabaseId;
  vaultId: VaultId;
  authorityDelegationDigest: Sha256Digest;
  authoritySigningKeyFingerprint: Sha256Digest;
  authorityRecoveryKeyFingerprint: Sha256Digest;
  registryDigest: Sha256Digest;
  authorizationStateDigest: Sha256Digest;
  genesisRequestDigest: Sha256Digest;
  genesisTransitionDigest: Sha256Digest;
  genesisHeadDigest: Sha256Digest;
  genesisFinalizedMutationLinkDigest: Sha256Digest;
  principalId: string;
  deviceId: string;
  membershipId: string;
}

interface MigrationArtifacts {
  source: DatabaseVaultDocument;
  candidate: CollaborativeVaultDocument;
  proofEntry: CollaborationMutationProof['entries'][number];
  outcome: DurableOperationOutcome;
  request: ReturnType<typeof collaborationMigrationRequestSchema.parse>;
  preparedMarker: CollaborationMigrationPreparedMarker;
  activeMarker: CollaborationMigrationActiveMarker;
}

interface MutationArtifacts {
  candidate: CollaborativeVaultDocument;
  proofEntry: CollaborationMutationProof['entries'][number];
  outcome: DurableOperationOutcome;
}

function makeFixtureContext(label: string): FixtureContext {
  const suffix = `${label}-${randomBytes(8).toString('hex')}`;
  return {
    suffix,
    databaseId: makeDatabaseId(`database-${suffix}`),
    vaultId: makeVaultId(`vault-${suffix}`),
    authorityDelegationDigest: digest(),
    authoritySigningKeyFingerprint: digest(),
    authorityRecoveryKeyFingerprint: digest(),
    registryDigest: digest(),
    authorizationStateDigest: digest(),
    genesisRequestDigest: digest(),
    genesisTransitionDigest: digest(),
    genesisHeadDigest: digest(),
    genesisFinalizedMutationLinkDigest: digest(),
    principalId: `principal-${suffix}`,
    deviceId: `device-${suffix}`,
    membershipId: `membership-${suffix}`,
  };
}

function opaqueBytes(length: number): string {
  return randomBytes(length).toString('base64url');
}

function digest(): Sha256Digest {
  return opaqueBytes(32) as Sha256Digest;
}

function signature(): string {
  return opaqueBytes(64);
}

function tuple(
  context: FixtureContext,
  documentRevision: number,
  authorizationStateDigest: Sha256Digest,
): CollaborationRevisionTuple {
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: 1,
    documentRevision,
    membershipRevision: documentRevision === 0 ? 0 : 1,
    policyRevision: documentRevision === 0 ? 0 : 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: context.registryDigest,
    authorizationStateDigest,
  });
}

function makeAuthorityDelegation(
  context: FixtureContext,
): CollaborationAuthorityDelegation {
  return collaborationAuthorityDelegationSchema.parse({
    format: 'kavrix-collaborative-authority-delegation' as const,
    protocolVersion: 1 as const,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    authorityEpoch: 1,
    authoritySigningPublicKey: opaqueBytes(32),
    authoritySigningKeyFingerprint: context.authoritySigningKeyFingerprint,
    authorityRecoveryPublicKey: opaqueBytes(32),
    authorityRecoveryKeyFingerprint: context.authorityRecoveryKeyFingerprint,
    genesisOperationId: `operation-genesis-${context.suffix}`,
    genesisTuple: tuple(context, 1, context.authorizationStateDigest),
    genesisHeadDigest: context.genesisHeadDigest,
    initialAuthorizationStateDigest: context.authorizationStateDigest,
    initialOwnerPrincipalId: context.principalId,
    initialOwnerRootKeyFingerprint: digest(),
    initialOwnerDeviceId: context.deviceId,
    initialOwnerDeviceSigningKeyFingerprint: digest(),
    initialOwnerDeviceEncryptionKeyFingerprint: digest(),
    issuedAt: '2026-01-01T00:00:00.000Z',
    authoritySignature: signature(),
  });
}

function makeRegistry(
  context: FixtureContext,
  generation = 1,
  registryDigest = context.registryDigest,
): CollaborationDatabaseDeviceRegistry {
  return collaborationDatabaseDeviceRegistrySchema.parse({
    format: 'kavrix-collaborative-device-registry',
    protocolVersion: 1,
    databaseId: context.databaseId,
    authorityEpoch: 1,
    authorityFingerprint: context.authoritySigningKeyFingerprint,
    generation,
    previousRegistryDigest: digest(),
    registryDigest,
    deniedDevices: [],
    updatedAt: '2026-01-02T00:00:00.000Z',
    authoritySignature: signature(),
  });
}

async function makeGenesisDocument(
  context: FixtureContext,
): Promise<CollaborativeVaultDocument> {
  const authorityDelegation = makeAuthorityDelegation(context);
  const previousTuple = tuple(
    context,
    0,
    COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  );
  const nextTuple = tuple(context, 1, context.authorizationStateDigest);
  const encryptedMembershipDigest = digest();
  const encryptedEnvelopesDigest = digest();
  const policyDigest = digest();
  const payloadAadMetadata = {
    protocolVersion: 1 as const,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    ...nextTuple,
    entityType: 'vault-payload' as const,
    entityId: context.vaultId,
  };
  const payloadAad = {
    ...payloadAadMetadata,
    metadataDigest: computeAadMetadataDigest(payloadAadMetadata),
  };
  const membershipAadMetadata = {
    ...payloadAadMetadata,
    entityType: 'membership-manifest' as const,
  };
  const membershipAad = {
    ...membershipAadMetadata,
    metadataDigest: computeAadMetadataDigest(membershipAadMetadata),
  };
  const plaintext = new TextEncoder().encode(plaintextCanary);
  const encryptionKey = Uint8Array.from(requirePlaintextCanaryBytes());
  let encryptedPayload: CollaborativeVaultDocument['encryptedPayload'] | undefined;
  try {
    encryptedPayload = await encryptCollaborationEnvelope(
      plaintext,
      encryptionKey,
      payloadAad,
    );
  } finally {
    zeroize(plaintext);
    zeroize(encryptionKey);
  }
  const encryptedPayloadDigest = computeEncryptedPayloadDigest(encryptedPayload);
  const commitment = {
    protocolVersion: 1 as const,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    operationId: authorityDelegation.genesisOperationId,
    operationType: 'genesis-migration' as const,
    requestDigest: context.genesisRequestDigest,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousAuthorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
    authorizationStateDigest: context.authorizationStateDigest,
    authorizationTransitionDigest: context.genesisTransitionDigest,
    previousAuthorityEpoch: 1,
    previousDocumentRevision: 0,
    previousMembershipRevision: 0,
    previousPolicyRevision: 0,
    previousKeyEpoch: 1,
    previousDatabaseDeviceGeneration: 1,
    previousDatabaseDeviceRegistryDigest: context.registryDigest,
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: context.registryDigest,
    encryptedPayloadDigest,
    encryptedMembershipDigest,
    encryptedEnvelopesDigest,
    policyDigest,
    writerPrincipalId: context.principalId,
    writerDeviceId: context.deviceId,
    timestamp: '2026-01-01T00:00:00.000Z',
  };
  const currentMutationLink = {
    format: 'kavrix-collaborative-finalized-mutation-link' as const,
    protocolVersion: 1 as const,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    authorityDelegationDigest: context.authorityDelegationDigest,
    commitment,
    authorizationTransition: {
      format: 'kavrix-collaborative-authorization-transition' as const,
      protocolVersion: 1 as const,
      databaseId: context.databaseId,
      vaultId: context.vaultId,
      operationId: commitment.operationId,
      operationType: commitment.operationType,
      previousHeadDigest: commitment.previousHeadDigest,
      previousAuthorizationStateDigest:
        COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
      authorizationStateDigest: context.authorizationStateDigest,
      previousTuple,
      nextTuple,
      evidence: { kind: 'none' as const },
      issuedAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2026-01-03T00:00:00.000Z',
      transitionDigest: context.genesisTransitionDigest,
      transitionSignature: {
        signerKind: 'owner-device' as const,
        signerPrincipalId: context.principalId,
        signerDeviceId: context.deviceId,
        signature: signature(),
      },
    },
    resultingHeadDigest: context.genesisHeadDigest,
    writerSignature: {
      algorithm: 'ed25519' as const,
      writerPrincipalId: context.principalId,
      writerDeviceId: context.deviceId,
      commitmentDigest: context.genesisHeadDigest,
      signature: signature(),
    },
    finalizedAt: '2026-01-02T00:00:00.000Z',
  };
  return collaborativeVaultDocumentSchema.parse({
    format: 'kavrix-collaborative-vault',
    documentVersion: 1,
    protocolVersion: 1,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: context.registryDigest,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    headDigest: context.genesisHeadDigest,
    authorityDelegation,
    authorityDelegationDigest: context.authorityDelegationDigest,
    authorizationStateDigest: context.authorizationStateDigest,
    encryptedPayloadDigest,
    encryptedMembershipDigest,
    encryptedEnvelopesDigest,
    policyDigest,
    databaseAuthorityRecoveryEnvelope: {
      format: 'kavrix-collaborative-authority-recovery-envelope',
      protocolVersion: 1,
      algorithm: 'x25519-sealed-box',
      databaseId: context.databaseId,
      vaultId: context.vaultId,
      authorityEpoch: 1,
      authorityRecoveryKeyFingerprint: context.authorityRecoveryKeyFingerprint,
      keyEpoch: 1,
      membershipRevision: 1,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: context.registryDigest,
      sealedVaultRootKey: opaqueBytes(80),
      envelopeDigest: digest(),
      sealedByPrincipalId: context.principalId,
      sealedByDeviceId: context.deviceId,
      createdAt: '2026-01-01T00:00:00.000Z',
      ownerSignature: signature(),
    },
    encryptedPayload,
    encryptedMembershipManifest: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: opaqueBytes(24),
      ciphertext: opaqueBytes(64),
      authenticationTag: opaqueBytes(16),
      aad: membershipAad,
    },
    discoveryRecords: [],
    currentMutationLink,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-02T00:00:00.000Z',
  });
}

function makeLegacySource(context: FixtureContext): DatabaseVaultDocument {
  return databaseVaultDocumentSchema.parse(
    vaultDocument(
      context.databaseId,
      context.vaultId,
      databaseRevision(4),
      vaultRevision(7),
    ),
  );
}

async function makeMigrationArtifacts(
  context: FixtureContext,
): Promise<MigrationArtifacts> {
  const source = makeLegacySource(context);
  const candidate = await makeGenesisDocument(context);
  const registryCandidate = makeRegistry(context);
  const proofEntry = makeProofEntry(
    candidate,
    context.genesisFinalizedMutationLinkDigest,
    registryCandidate,
  );
  const outcome = makeOutcome(candidate, context.genesisFinalizedMutationLinkDigest);
  const request = collaborationMigrationRequestSchema.parse({
    format: 'kavrix-collaborative-migration-request',
    protocolVersion: 1,
    operationType: 'genesis-migration',
    operationId: candidate.currentMutationLink.commitment.operationId,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    legacyVaultRevision: source.revision,
    legacySourceDigest: digest(),
    authorityEpoch: 1,
    authorityFingerprint: context.authoritySigningKeyFingerprint,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: context.registryDigest,
    initialOwnerPrincipalId: context.principalId,
    initialOwnerDeviceId: context.deviceId,
    initialMembershipId: context.membershipId,
    requestedAt: '2026-01-01T00:00:00.000Z',
    requestDigest: context.genesisRequestDigest,
    authoritySignature: signature(),
    ownerSignature: signature(),
  });
  const preparedMarker = collaborationMigrationPreparedMarkerSchema.parse({
    format: 'kavrix-collaborative-migration-marker',
    markerVersion: 1,
    protocolVersion: 1,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    operationId: request.operationId,
    requestDigest: request.requestDigest,
    legacySourceDigest: request.legacySourceDigest,
    authorityEpoch: 1,
    authorityFingerprint: request.authorityFingerprint,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: context.registryDigest,
    candidateHeadDigest: candidate.headDigest,
    preparedAt: '2026-01-01T00:00:00.000Z',
    authoritySignature: signature(),
    state: 'prepared',
    legacySource: source,
    registryCandidate,
  });
  const activeMarker = collaborationMigrationActiveMarkerSchema.parse({
    format: preparedMarker.format,
    markerVersion: preparedMarker.markerVersion,
    protocolVersion: 1,
    databaseId: preparedMarker.databaseId,
    vaultId: preparedMarker.vaultId,
    operationId: preparedMarker.operationId,
    requestDigest: preparedMarker.requestDigest,
    legacySourceDigest: preparedMarker.legacySourceDigest,
    authorityEpoch: preparedMarker.authorityEpoch,
    authorityFingerprint: preparedMarker.authorityFingerprint,
    databaseDeviceGeneration: preparedMarker.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: preparedMarker.databaseDeviceRegistryDigest,
    candidateHeadDigest: preparedMarker.candidateHeadDigest,
    preparedAt: preparedMarker.preparedAt,
    authoritySignature: preparedMarker.authoritySignature,
    state: 'active',
    outcomeDigest: outcome.outcomeDigest,
    activatedAt: '2026-01-02T00:00:00.000Z',
  });
  return {
    source,
    candidate,
    proofEntry,
    outcome,
    request,
    preparedMarker,
    activeMarker,
  };
}

function makeProofEntry(
  candidate: CollaborativeVaultDocument,
  finalizedMutationLinkDigest: Sha256Digest,
  databaseDeviceRegistry: CollaborationDatabaseDeviceRegistry,
): CollaborationMutationProof['entries'][number] {
  const link = candidate.currentMutationLink;
  if (link.commitment.operationType === 'ordinary-write') return { link };
  return {
    link,
    authorizationWitness: {
      format: 'kavrix-collaborative-authorization-witness',
      protocolVersion: 1,
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      authorityDelegationDigest: candidate.authorityDelegationDigest,
      tuple: tuple(
        {
          suffix: '',
          databaseId: candidate.databaseId,
          vaultId: candidate.vaultId,
          authorityDelegationDigest: candidate.authorityDelegationDigest,
          authoritySigningKeyFingerprint:
            candidate.authorityDelegation.authoritySigningKeyFingerprint,
          authorityRecoveryKeyFingerprint:
            candidate.authorityDelegation.authorityRecoveryKeyFingerprint,
          registryDigest: candidate.databaseDeviceRegistryDigest,
          authorizationStateDigest: candidate.authorizationStateDigest,
          genesisRequestDigest: candidate.currentMutationLink.commitment.requestDigest,
          genesisTransitionDigest:
            candidate.currentMutationLink.commitment.authorizationTransitionDigest ??
            finalizedMutationLinkDigest,
          genesisHeadDigest: candidate.headDigest,
          genesisFinalizedMutationLinkDigest: finalizedMutationLinkDigest,
          principalId: candidate.authorityDelegation.initialOwnerPrincipalId,
          deviceId: candidate.authorityDelegation.initialOwnerDeviceId,
          membershipId: 'membership-genesis',
        },
        candidate.documentRevision,
        candidate.authorizationStateDigest,
      ),
      previousHeadDigest: candidate.previousHeadDigest,
      headDigest: candidate.headDigest,
      encryptedMembershipDigest: candidate.encryptedMembershipDigest,
      encryptedEnvelopesDigest: candidate.encryptedEnvelopesDigest,
      policyDigest: candidate.policyDigest,
      databaseDeviceRegistry,
      databaseAuthorityRecoveryEnvelope: candidate.databaseAuthorityRecoveryEnvelope,
      encryptedMembershipManifest: candidate.encryptedMembershipManifest,
      discoveryRecords: candidate.discoveryRecords,
      finalizedMutationLinkDigest,
    },
  };
}

function makeOrdinaryArtifacts(
  context: FixtureContext,
  previous: CollaborativeVaultDocument,
  operationId = `operation-mutation-${context.suffix}`,
  resultingHeadDigest?: Sha256Digest,
): MutationArtifacts {
  const documentRevision = previous.documentRevision + 1;
  const headDigest = resultingHeadDigest ?? digest();
  const requestDigest = digest();
  const commitment = {
    ...previous.currentMutationLink.commitment,
    operationId,
    operationType: 'ordinary-write' as const,
    requestDigest,
    previousHeadDigest: previous.headDigest,
    previousAuthorizationStateDigest: previous.authorizationStateDigest,
    authorizationStateDigest: previous.authorizationStateDigest,
    authorizationTransitionDigest: undefined,
    previousAuthorityEpoch: previous.authorityEpoch,
    previousDocumentRevision: previous.documentRevision,
    previousMembershipRevision: previous.membershipRevision,
    previousPolicyRevision: previous.policyRevision,
    previousKeyEpoch: previous.keyEpoch,
    previousDatabaseDeviceGeneration: previous.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: previous.databaseDeviceRegistryDigest,
    authorityEpoch: previous.authorityEpoch,
    documentRevision,
    membershipRevision: previous.membershipRevision,
    policyRevision: previous.policyRevision,
    keyEpoch: previous.keyEpoch,
    databaseDeviceGeneration: previous.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: previous.databaseDeviceRegistryDigest,
    encryptedPayloadDigest: previous.encryptedPayloadDigest,
    encryptedMembershipDigest: previous.encryptedMembershipDigest,
    encryptedEnvelopesDigest: previous.encryptedEnvelopesDigest,
    policyDigest: previous.policyDigest,
    writerPrincipalId: context.principalId,
    writerDeviceId: context.deviceId,
    timestamp: '2026-01-02T00:00:00.000Z',
  };
  const currentMutationLink = {
    format: 'kavrix-collaborative-finalized-mutation-link' as const,
    protocolVersion: 1 as const,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    authorityDelegationDigest: context.authorityDelegationDigest,
    commitment,
    resultingHeadDigest: headDigest,
    writerSignature: {
      algorithm: 'ed25519' as const,
      writerPrincipalId: context.principalId,
      writerDeviceId: context.deviceId,
      commitmentDigest: headDigest,
      signature: signature(),
    },
    finalizedAt: '2026-01-02T00:00:00.000Z',
  };
  const candidate = collaborativeVaultDocumentSchema.parse({
    ...previous,
    documentRevision,
    previousHeadDigest: previous.headDigest,
    headDigest,
    encryptedPayload: {
      ...previous.encryptedPayload,
      aad: { ...previous.encryptedPayload.aad, documentRevision },
    },
    encryptedMembershipManifest: {
      ...previous.encryptedMembershipManifest,
      aad: { ...previous.encryptedMembershipManifest.aad, documentRevision },
    },
    currentMutationLink,
    updatedAt: '2026-01-02T00:00:00.000Z',
  });
  const finalizedMutationLinkDigest = digest();
  const proofEntry: CollaborationMutationProof['entries'][number] = {
    link: candidate.currentMutationLink,
  };
  const outcome = makeOutcome(candidate, finalizedMutationLinkDigest, digest());
  return { candidate, proofEntry, outcome };
}

function makeOutcome(
  candidate: CollaborativeVaultDocument,
  finalizedMutationLinkDigest: Sha256Digest,
  outcomeDigest: Sha256Digest = digest(),
): DurableOperationOutcome {
  const commitment = candidate.currentMutationLink.commitment;
  const priorTuple: CollaborationRevisionTuple = {
    authorityEpoch: commitment.previousAuthorityEpoch,
    documentRevision: commitment.previousDocumentRevision,
    membershipRevision: commitment.previousMembershipRevision,
    policyRevision: commitment.previousPolicyRevision,
    keyEpoch: commitment.previousKeyEpoch,
    databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
    databaseDeviceRegistryDigest: commitment.previousDatabaseDeviceRegistryDigest,
    authorizationStateDigest: commitment.previousAuthorizationStateDigest,
  };
  const committedTuple = tuple(
    {
      suffix: '',
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      authorityDelegationDigest: candidate.authorityDelegationDigest,
      authoritySigningKeyFingerprint:
        candidate.authorityDelegation.authoritySigningKeyFingerprint,
      authorityRecoveryKeyFingerprint:
        candidate.authorityDelegation.authorityRecoveryKeyFingerprint,
      registryDigest: candidate.databaseDeviceRegistryDigest,
      authorizationStateDigest: candidate.authorizationStateDigest,
      genesisRequestDigest: commitment.requestDigest,
      genesisTransitionDigest:
        commitment.authorizationTransitionDigest ?? finalizedMutationLinkDigest,
      genesisHeadDigest: candidate.headDigest,
      genesisFinalizedMutationLinkDigest: finalizedMutationLinkDigest,
      principalId: commitment.writerPrincipalId,
      deviceId: commitment.writerDeviceId,
      membershipId: 'membership-outcome',
    },
    candidate.documentRevision,
    candidate.authorizationStateDigest,
  );
  const signedMutationReceipt = {
    format: 'kavrix-collaborative-mutation-receipt' as const,
    protocolVersion: 1 as const,
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    operationId: commitment.operationId,
    operationType: commitment.operationType,
    requestDigest: commitment.requestDigest,
    actorPrincipalId: commitment.writerPrincipalId,
    actorDeviceId: commitment.writerDeviceId,
    priorTuple,
    priorHeadDigest: candidate.previousHeadDigest,
    committedTuple,
    committedHeadDigest: candidate.headDigest,
    finalizedMutationLinkDigest,
    outcomeDigest,
    committedAt: '2026-01-02T00:00:00.000Z',
    receiptSignature: signature(),
  };
  return durableOperationOutcomeSchema.parse({
    format: 'kavrix-collaborative-operation-outcome',
    protocolVersion: 1,
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    operationId: commitment.operationId,
    operationType: commitment.operationType,
    requestDigest: commitment.requestDigest,
    actorPrincipalId: commitment.writerPrincipalId,
    actorDeviceId: commitment.writerDeviceId,
    priorTuple,
    priorHeadDigest: candidate.previousHeadDigest,
    state: 'committed',
    committedTuple,
    committedHeadDigest: candidate.headDigest,
    finalizedMutationLinkDigest,
    committedAt: '2026-01-02T00:00:00.000Z',
    outcomeDigest,
    signedMutationReceipt,
    createdAt: '2026-01-01T00:00:00.000Z',
    resolvedAt: '2026-01-02T00:00:00.000Z',
    detailsRetainedUntil: '2026-01-03T00:00:00.000Z',
  });
}

function makeDestructionArtifacts(
  context: FixtureContext,
  prior: CollaborativeVaultDocument,
  operationId = `operation-destroy-${context.suffix}`,
  registry = makeRegistry(context),
): Readonly<{
  tombstone: CollaborationVaultDestructionTombstone;
  outcome: DurableOperationOutcome;
}> {
  const priorTuple = tuple(
    context,
    prior.documentRevision,
    prior.authorizationStateDigest,
  );
  const terminalTuple = collaborationRevisionTupleSchema.parse({
    ...priorTuple,
    documentRevision: prior.documentRevision + 1,
  });
  const destroyedPayloadDigest = digest();
  const terminalHeadDigest = digest();
  const finalizedMutationLinkDigest = digest();
  const outcomeDigest = digest();
  const transitionDigest = digest();
  const terminalEncryptedMembershipDigest = digest();
  const terminalDiscoveryRecords = prior.discoveryRecords.map((record) => ({
    ...record,
    encryptedMembershipMetadataDigest: terminalEncryptedMembershipDigest,
    discoveryRecordDigest: digest(),
    writerSignature: signature(),
    updatedAt: '2026-01-02T00:00:00.000Z',
  }));
  const commitment = {
    ...prior.currentMutationLink.commitment,
    operationId,
    operationType: 'destroy-vault' as const,
    requestDigest: digest(),
    previousHeadDigest: prior.headDigest,
    previousAuthorizationStateDigest: prior.authorizationStateDigest,
    authorizationStateDigest: prior.authorizationStateDigest,
    authorizationTransitionDigest: transitionDigest,
    previousAuthorityEpoch: prior.authorityEpoch,
    previousDocumentRevision: prior.documentRevision,
    previousMembershipRevision: prior.membershipRevision,
    previousPolicyRevision: prior.policyRevision,
    previousKeyEpoch: prior.keyEpoch,
    previousDatabaseDeviceGeneration: prior.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: prior.databaseDeviceRegistryDigest,
    authorityEpoch: terminalTuple.authorityEpoch,
    documentRevision: terminalTuple.documentRevision,
    membershipRevision: terminalTuple.membershipRevision,
    policyRevision: terminalTuple.policyRevision,
    keyEpoch: terminalTuple.keyEpoch,
    databaseDeviceGeneration: terminalTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: terminalTuple.databaseDeviceRegistryDigest,
    encryptedPayloadDigest: destroyedPayloadDigest,
    encryptedMembershipDigest: terminalEncryptedMembershipDigest,
    encryptedEnvelopesDigest: prior.encryptedEnvelopesDigest,
    policyDigest: prior.policyDigest,
    writerPrincipalId: context.principalId,
    writerDeviceId: context.deviceId,
    timestamp: '2026-01-02T00:00:00.000Z',
  };
  const link = {
    format: 'kavrix-collaborative-finalized-mutation-link' as const,
    protocolVersion: 1 as const,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    authorityDelegationDigest: context.authorityDelegationDigest,
    commitment,
    authorizationTransition: {
      format: 'kavrix-collaborative-authorization-transition' as const,
      protocolVersion: 1 as const,
      databaseId: context.databaseId,
      vaultId: context.vaultId,
      operationId,
      operationType: 'destroy-vault' as const,
      previousHeadDigest: prior.headDigest,
      previousAuthorizationStateDigest: prior.authorizationStateDigest,
      authorizationStateDigest: prior.authorizationStateDigest,
      previousTuple: priorTuple,
      nextTuple: terminalTuple,
      evidence: { kind: 'none' as const },
      issuedAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2026-01-03T00:00:00.000Z',
      transitionDigest,
      transitionSignature: {
        signerKind: 'owner-device' as const,
        signerPrincipalId: context.principalId,
        signerDeviceId: context.deviceId,
        signature: signature(),
      },
    },
    resultingHeadDigest: terminalHeadDigest,
    writerSignature: {
      algorithm: 'ed25519' as const,
      writerPrincipalId: context.principalId,
      writerDeviceId: context.deviceId,
      commitmentDigest: terminalHeadDigest,
      signature: signature(),
    },
    finalizedAt: '2026-01-02T00:00:00.000Z',
  };
  const proofEntry = collaborationMutationProofEntrySchema.parse({
    link,
    authorizationWitness: {
      format: 'kavrix-collaborative-authorization-witness',
      protocolVersion: 1,
      databaseId: context.databaseId,
      vaultId: context.vaultId,
      authorityDelegationDigest: context.authorityDelegationDigest,
      tuple: terminalTuple,
      previousHeadDigest: prior.headDigest,
      headDigest: terminalHeadDigest,
      encryptedMembershipDigest: terminalEncryptedMembershipDigest,
      encryptedEnvelopesDigest: prior.encryptedEnvelopesDigest,
      policyDigest: prior.policyDigest,
      databaseDeviceRegistry: registry,
      databaseAuthorityRecoveryEnvelope: prior.databaseAuthorityRecoveryEnvelope,
      encryptedMembershipManifest: {
        ...prior.encryptedMembershipManifest,
        aad: {
          ...prior.encryptedMembershipManifest.aad,
          ...terminalTuple,
        },
      },
      discoveryRecords: terminalDiscoveryRecords,
      finalizedMutationLinkDigest,
    },
  });
  const signedMutationReceipt = {
    format: 'kavrix-collaborative-mutation-receipt' as const,
    protocolVersion: 1 as const,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    operationId,
    operationType: 'destroy-vault' as const,
    requestDigest: commitment.requestDigest,
    actorPrincipalId: context.principalId,
    actorDeviceId: context.deviceId,
    priorTuple,
    priorHeadDigest: prior.headDigest,
    committedTuple: terminalTuple,
    committedHeadDigest: terminalHeadDigest,
    finalizedMutationLinkDigest,
    outcomeDigest,
    committedAt: '2026-01-02T00:00:00.000Z',
    receiptSignature: signature(),
  };
  const tombstone = collaborationVaultDestructionTombstoneSchema.parse({
    format: 'kavrix-collaborative-vault-destruction-tombstone',
    protocolVersion: 1,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    core: {
      format: 'kavrix-collaborative-vault-destruction-core',
      protocolVersion: 1,
      databaseId: context.databaseId,
      vaultId: context.vaultId,
      operationId,
      authorityEpoch: prior.authorityEpoch,
      authorityDelegationDigest: context.authorityDelegationDigest,
      priorTuple,
      priorHeadDigest: prior.headDigest,
      terminalTuple,
      actionParametersDigest: digest(),
      actorPrincipalId: context.principalId,
      actorDeviceId: context.deviceId,
      destructionMode: 'irreversible',
      destroyedAt: '2026-01-02T00:00:00.000Z',
    },
    destroyedPayloadDigest,
    terminalHeadDigest,
    proofEntry,
    outcomeDigest,
    signedMutationReceipt,
  });
  const outcome = durableOperationOutcomeSchema.parse({
    format: 'kavrix-collaborative-operation-outcome',
    protocolVersion: 1,
    databaseId: context.databaseId,
    vaultId: context.vaultId,
    operationId,
    operationType: 'destroy-vault',
    requestDigest: commitment.requestDigest,
    actorPrincipalId: context.principalId,
    actorDeviceId: context.deviceId,
    priorTuple,
    priorHeadDigest: prior.headDigest,
    state: 'committed',
    committedTuple: terminalTuple,
    committedHeadDigest: terminalHeadDigest,
    finalizedMutationLinkDigest,
    committedAt: '2026-01-02T00:00:00.000Z',
    outcomeDigest,
    signedMutationReceipt,
    createdAt: '2026-01-01T00:00:00.000Z',
    resolvedAt: '2026-01-02T00:00:00.000Z',
    detailsRetainedUntil: '2026-01-03T00:00:00.000Z',
  });
  return { tombstone, outcome };
}

function storedProofEntry(
  entry: CollaborationMutationProof['entries'][number],
  outcome: DurableOperationOutcome,
): StoredDocument {
  if (outcome.finalizedMutationLinkDigest === undefined) {
    throw new Error('Stored proof fixtures require a finalized link digest');
  }
  return {
    ...entry,
    _id: `${entry.link.databaseId}:${entry.link.vaultId}:${entry.link.commitment.operationId}`,
    databaseId: entry.link.databaseId,
    vaultId: entry.link.vaultId,
    finalizedMutationLinkDigest: outcome.finalizedMutationLinkDigest,
  };
}
