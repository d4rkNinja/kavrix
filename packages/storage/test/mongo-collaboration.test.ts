import type { Collection, Db, MongoClient } from 'mongodb';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  collaborationAuthorizationCheckpointSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationMigrationActiveMarkerSchema,
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationRequestSchema,
  collaborationRevisionTupleSchema,
  collaborationVaultDestructionTombstoneSchema,
  collaborativeVaultDocumentSchema,
  databaseVaultDocumentSchema,
  durableOperationOutcomeSchema,
  operationDeduplicationTombstoneSchema,
  type CollaborationAuthorizationCheckpoint,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationDiscoveryRecord,
  type CollaborationMigrationActiveMarker,
  type CollaborationMigrationPreparedMarker,
  type CollaborationMigrationRequest,
  type CollaborationMutationProof,
  type CollaborationRevisionTuple,
  type CollaborationVaultDestructionTombstone,
  type CollaborativeVaultDocument,
  type DatabaseId,
  type DatabaseVaultDocument,
  type DurableOperationOutcome,
  type OperationDeduplicationTombstone,
  type Sha256Digest,
  type VaultId,
} from '@kavrix/schemas';

import { EncryptedDatabaseStoreError } from '../src/encrypted-database-store.js';
import {
  MongoCollaborativeVaultStore,
  type MongoCollaborativeVaultCollectionNames,
} from '../src/collaborative-vault-store.js';
import {
  databaseRevision,
  makeDatabaseId,
  makeVaultId,
  vaultDocument,
  vaultRevision,
} from './database-store-fixtures.js';

const COLLECTION_NAMES: MongoCollaborativeVaultCollectionNames = {
  collaborativeVaultCollectionName: 'collaborative-vaults',
  databaseDeviceRegistryCollectionName: 'device-registries',
  operationOutcomeCollectionName: 'operation-outcomes',
  operationTombstoneCollectionName: 'operation-tombstones',
  vaultDestructionTombstoneCollectionName: 'vault-destruction-tombstones',
  finalizedMutationLinkCollectionName: 'mutation-links',
  authorizationCheckpointCollectionName: 'authorization-checkpoints',
};

const timestamp = '2026-01-01T00:00:00.000Z';
const laterTimestamp = '2026-01-02T00:00:00.000Z';
const expiryTimestamp = '2026-01-03T00:00:00.000Z';
const bytes = (length: number, value: number): string =>
  Buffer.alloc(length, value).toString('base64url');
const digest = (value: number): Sha256Digest => bytes(32, value) as Sha256Digest;
const key = (value: number): string => bytes(32, value);
const signature = (value: number): string => bytes(64, value);
const DATABASE_ID = 'database-a' as DatabaseId;
const VAULT_ID = 'vault-a' as VaultId;
const AUTHORIZATION_STATE_DIGEST = digest(50);
const PREVIOUS_AUTHORIZATION_STATE_DIGEST =
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST;
const AUTHORITY_DELEGATION_DIGEST = digest(49);
const REGISTRY_DIGEST = digest(2);

function tuple(
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
    databaseDeviceRegistryDigest: REGISTRY_DIGEST,
    authorizationStateDigest,
  });
}

const authorityDelegation = {
  format: 'kavrix-collaborative-authority-delegation' as const,
  protocolVersion: 1 as const,
  databaseId: DATABASE_ID,
  vaultId: VAULT_ID,
  authorityEpoch: 1,
  authoritySigningPublicKey: key(40),
  authoritySigningKeyFingerprint: digest(41),
  authorityRecoveryPublicKey: key(42),
  authorityRecoveryKeyFingerprint: digest(43),
  genesisOperationId: 'operation-genesis',
  genesisTuple: tuple(1, AUTHORIZATION_STATE_DIGEST),
  genesisHeadDigest: digest(7),
  initialAuthorizationStateDigest: AUTHORIZATION_STATE_DIGEST,
  initialOwnerPrincipalId: 'principal-a',
  initialOwnerRootKeyFingerprint: digest(45),
  initialOwnerDeviceId: 'device-a',
  initialOwnerDeviceSigningKeyFingerprint: digest(46),
  initialOwnerDeviceEncryptionKeyFingerprint: digest(47),
  issuedAt: timestamp,
  authoritySignature: signature(48),
};

function makeRegistry(
  generation = 1,
  previousRegistryDigest = digest(1),
  registryDigest = REGISTRY_DIGEST,
  deniedDevices: readonly unknown[] = [],
): CollaborationDatabaseDeviceRegistry {
  return collaborationDatabaseDeviceRegistrySchema.parse({
    format: 'kavrix-collaborative-device-registry',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    authorityEpoch: 1,
    authorityFingerprint: authorityDelegation.authoritySigningKeyFingerprint,
    generation,
    previousRegistryDigest,
    registryDigest,
    deniedDevices,
    updatedAt: laterTimestamp,
    authoritySignature: signature(66),
  });
}

function makeGenesisDocument(): CollaborativeVaultDocument {
  const previousTuple = tuple(0, PREVIOUS_AUTHORIZATION_STATE_DIGEST);
  const nextTuple = tuple(1, AUTHORIZATION_STATE_DIGEST);
  const payloadAad = {
    protocolVersion: 1 as const,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    ...nextTuple,
    entityType: 'vault-payload' as const,
    entityId: VAULT_ID,
    metadataDigest: digest(16),
  };
  const membershipAad = {
    ...payloadAad,
    entityType: 'membership-manifest' as const,
    metadataDigest: digest(17),
  };
  const commitment = {
    protocolVersion: 1 as const,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: 'operation-genesis',
    operationType: 'genesis-migration' as const,
    requestDigest: digest(25),
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousAuthorizationStateDigest: PREVIOUS_AUTHORIZATION_STATE_DIGEST,
    authorizationStateDigest: AUTHORIZATION_STATE_DIGEST,
    authorizationTransitionDigest: digest(52),
    previousAuthorityEpoch: 1,
    previousDocumentRevision: 0,
    previousMembershipRevision: 0,
    previousPolicyRevision: 0,
    previousKeyEpoch: 1,
    previousDatabaseDeviceGeneration: 1,
    previousDatabaseDeviceRegistryDigest: REGISTRY_DIGEST,
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: REGISTRY_DIGEST,
    encryptedPayloadDigest: digest(16),
    encryptedMembershipDigest: digest(17),
    encryptedEnvelopesDigest: digest(18),
    policyDigest: digest(4),
    writerPrincipalId: 'principal-a',
    writerDeviceId: 'device-a',
    timestamp,
  };
  const currentMutationLink = {
    format: 'kavrix-collaborative-finalized-mutation-link' as const,
    protocolVersion: 1 as const,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityDelegationDigest: AUTHORITY_DELEGATION_DIGEST,
    commitment,
    authorizationTransition: {
      format: 'kavrix-collaborative-authorization-transition' as const,
      protocolVersion: 1 as const,
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      operationId: commitment.operationId,
      operationType: commitment.operationType,
      previousHeadDigest: commitment.previousHeadDigest,
      previousAuthorizationStateDigest: PREVIOUS_AUTHORIZATION_STATE_DIGEST,
      authorizationStateDigest: AUTHORIZATION_STATE_DIGEST,
      previousTuple,
      nextTuple,
      evidence: { kind: 'none' as const },
      issuedAt: timestamp,
      expiresAt: expiryTimestamp,
      transitionDigest: digest(52),
      transitionSignature: {
        signerKind: 'owner-device' as const,
        signerPrincipalId: 'principal-a',
        signerDeviceId: 'device-a',
        signature: signature(56),
      },
    },
    resultingHeadDigest: digest(7),
    writerSignature: {
      algorithm: 'ed25519' as const,
      writerPrincipalId: 'principal-a',
      writerDeviceId: 'device-a',
      commitmentDigest: digest(7),
      signature: signature(8),
    },
    finalizedAt: laterTimestamp,
  };
  return collaborativeVaultDocumentSchema.parse({
    format: 'kavrix-collaborative-vault',
    documentVersion: 1,
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: REGISTRY_DIGEST,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    headDigest: digest(7),
    authorityDelegation,
    authorityDelegationDigest: AUTHORITY_DELEGATION_DIGEST,
    authorizationStateDigest: AUTHORIZATION_STATE_DIGEST,
    encryptedPayloadDigest: digest(16),
    encryptedMembershipDigest: digest(17),
    encryptedEnvelopesDigest: digest(18),
    policyDigest: digest(4),
    databaseAuthorityRecoveryEnvelope: {
      format: 'kavrix-collaborative-authority-recovery-envelope',
      protocolVersion: 1,
      algorithm: 'x25519-sealed-box',
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      authorityEpoch: 1,
      authorityRecoveryKeyFingerprint:
        authorityDelegation.authorityRecoveryKeyFingerprint,
      keyEpoch: 1,
      membershipRevision: 1,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: REGISTRY_DIGEST,
      sealedVaultRootKey: bytes(80, 60),
      envelopeDigest: digest(61),
      sealedByPrincipalId: 'principal-a',
      sealedByDeviceId: 'device-a',
      createdAt: timestamp,
      ownerSignature: signature(62),
    },
    encryptedPayload: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: bytes(24, 19),
      ciphertext: bytes(64, 20),
      authenticationTag: bytes(16, 21),
      aad: payloadAad,
    },
    encryptedMembershipManifest: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: bytes(24, 22),
      ciphertext: bytes(64, 23),
      authenticationTag: bytes(16, 24),
      aad: membershipAad,
    },
    discoveryRecords: [],
    currentMutationLink,
    createdAt: timestamp,
    updatedAt: laterTimestamp,
  });
}

function makeDiscoveryRecord(
  document: CollaborativeVaultDocument,
  encryptedMembershipMetadataDigest: Sha256Digest,
  seed: number,
): CollaborationDiscoveryRecord {
  return collaborationDiscoveryRecordSchema.parse({
    format: 'kavrix-collaborative-discovery-record',
    protocolVersion: 1,
    databaseId: document.databaseId,
    vaultId: document.vaultId,
    authorityEpoch: document.authorityEpoch,
    databaseDeviceGeneration: document.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: document.databaseDeviceRegistryDigest,
    discoveryTag: digest(seed),
    membershipId: 'membership-a',
    membershipState: 'active',
    keyEpoch: document.keyEpoch,
    membershipRevision: document.membershipRevision,
    authorizationStateDigest: document.authorizationStateDigest,
    encryptedMemberKeyEnvelope: {
      format: 'kavrix-collaborative-member-key-envelope',
      protocolVersion: 1,
      algorithm: 'x25519-sealed-box',
      databaseId: document.databaseId,
      vaultId: document.vaultId,
      authorityEpoch: document.authorityEpoch,
      membershipId: 'membership-a',
      principalId: 'principal-a',
      deviceId: 'device-a',
      recipientEncryptionKeyFingerprint: digest(seed + 1),
      keyEpoch: document.keyEpoch,
      membershipRevision: document.membershipRevision,
      databaseDeviceGeneration: document.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: document.databaseDeviceRegistryDigest,
      sealedVaultRootKey: bytes(80, seed + 2),
      envelopeDigest: digest(seed + 3),
      createdAt: timestamp,
      ownerSignature: signature(seed + 4),
    },
    encryptedMembershipMetadataDigest,
    discoveryRecordDigest: digest(seed + 5),
    signerPrincipalId: 'principal-a',
    signerDeviceId: 'device-a',
    writerSignature: signature(seed + 6),
    createdAt: timestamp,
    updatedAt: laterTimestamp,
  });
}

function makeOrdinaryUpdate(
  previous: CollaborativeVaultDocument,
  documentRevision: number,
): CollaborativeVaultDocument {
  const headDigest = digest(70 + documentRevision);
  const operationId = `operation-update-${String(documentRevision)}`;
  const commitment = {
    ...previous.currentMutationLink.commitment,
    operationId,
    operationType: 'ordinary-write' as const,
    requestDigest: digest(80 + documentRevision),
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
    documentRevision,
    timestamp: laterTimestamp,
  };
  const currentMutationLink = {
    format: 'kavrix-collaborative-finalized-mutation-link' as const,
    protocolVersion: 1 as const,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityDelegationDigest: AUTHORITY_DELEGATION_DIGEST,
    commitment,
    resultingHeadDigest: headDigest,
    writerSignature: {
      algorithm: 'ed25519' as const,
      writerPrincipalId: 'principal-a',
      writerDeviceId: 'device-a',
      commitmentDigest: headDigest,
      signature: signature(80 + documentRevision),
    },
    finalizedAt: laterTimestamp,
  };
  return collaborativeVaultDocumentSchema.parse({
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
    updatedAt: expiryTimestamp,
  });
}

function makeProofEntry(
  candidate: CollaborativeVaultDocument,
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
      tuple: tuple(candidate.documentRevision, candidate.authorizationStateDigest),
      previousHeadDigest: candidate.previousHeadDigest,
      headDigest: candidate.headDigest,
      encryptedMembershipDigest: candidate.encryptedMembershipDigest,
      encryptedEnvelopesDigest: candidate.encryptedEnvelopesDigest,
      policyDigest: candidate.policyDigest,
      databaseDeviceRegistry: makeRegistry(
        candidate.databaseDeviceGeneration,
        digest(1),
        candidate.databaseDeviceRegistryDigest,
      ),
      databaseAuthorityRecoveryEnvelope: candidate.databaseAuthorityRecoveryEnvelope,
      encryptedMembershipManifest: candidate.encryptedMembershipManifest,
      discoveryRecords: candidate.discoveryRecords,
      finalizedMutationLinkDigest: digest(90 + candidate.documentRevision),
    },
  };
}

function makeOutcome(candidate: CollaborativeVaultDocument): DurableOperationOutcome {
  const commitment = candidate.currentMutationLink.commitment;
  const priorTuple = {
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
    candidate.documentRevision,
    candidate.authorizationStateDigest,
  );
  const outcomeDigest = digest(100 + candidate.documentRevision);
  const finalizedMutationLinkDigest = digest(90 + candidate.documentRevision);
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
    committedAt: laterTimestamp,
    receiptSignature: signature(110 + candidate.documentRevision),
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
    committedAt: laterTimestamp,
    outcomeDigest,
    signedMutationReceipt,
    createdAt: timestamp,
    resolvedAt: laterTimestamp,
    detailsRetainedUntil: expiryTimestamp,
  });
}

function makeDestructionArtifacts(
  prior: CollaborativeVaultDocument = makeGenesisDocument(),
  operationId = 'operation-destroy',
  seed = 130,
): Readonly<{
  tombstone: CollaborationVaultDestructionTombstone;
  outcome: DurableOperationOutcome;
}> {
  const priorTuple = tuple(prior.documentRevision, prior.authorizationStateDigest);
  const terminalTuple = collaborationRevisionTupleSchema.parse({
    ...priorTuple,
    documentRevision: prior.documentRevision + 1,
  });
  const destroyedPayloadDigest = digest(seed);
  const terminalHeadDigest = digest(seed + 1);
  const finalizedMutationLinkDigest = digest(seed + 2);
  const outcomeDigest = digest(seed + 3);
  const transitionDigest = digest(seed + 4);
  const terminalEncryptedMembershipDigest = digest(seed + 10);
  const terminalDiscoveryRecords = prior.discoveryRecords.map((record, index) => ({
    ...record,
    encryptedMembershipMetadataDigest: terminalEncryptedMembershipDigest,
    discoveryRecordDigest: digest(seed + 11 + index),
    writerSignature: signature(seed + 12 + index),
    updatedAt: laterTimestamp,
  }));
  const commitment = {
    ...prior.currentMutationLink.commitment,
    operationId,
    operationType: 'destroy-vault' as const,
    requestDigest: digest(seed + 5),
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
    writerPrincipalId: 'principal-a',
    writerDeviceId: 'device-a',
    timestamp: laterTimestamp,
  };
  const link = {
    format: 'kavrix-collaborative-finalized-mutation-link' as const,
    protocolVersion: 1 as const,
    databaseId: prior.databaseId,
    vaultId: prior.vaultId,
    authorityDelegationDigest: prior.authorityDelegationDigest,
    commitment,
    authorizationTransition: {
      format: 'kavrix-collaborative-authorization-transition' as const,
      protocolVersion: 1 as const,
      databaseId: prior.databaseId,
      vaultId: prior.vaultId,
      operationId,
      operationType: 'destroy-vault' as const,
      previousHeadDigest: prior.headDigest,
      previousAuthorizationStateDigest: prior.authorizationStateDigest,
      authorizationStateDigest: prior.authorizationStateDigest,
      previousTuple: priorTuple,
      nextTuple: terminalTuple,
      evidence: { kind: 'none' as const },
      issuedAt: timestamp,
      expiresAt: expiryTimestamp,
      transitionDigest,
      transitionSignature: {
        signerKind: 'owner-device' as const,
        signerPrincipalId: 'principal-a',
        signerDeviceId: 'device-a',
        signature: signature(seed + 6),
      },
    },
    resultingHeadDigest: terminalHeadDigest,
    writerSignature: {
      algorithm: 'ed25519' as const,
      writerPrincipalId: 'principal-a',
      writerDeviceId: 'device-a',
      commitmentDigest: terminalHeadDigest,
      signature: signature(seed + 7),
    },
    finalizedAt: laterTimestamp,
  };
  const proofEntry = {
    link,
    authorizationWitness: {
      format: 'kavrix-collaborative-authorization-witness' as const,
      protocolVersion: 1 as const,
      databaseId: prior.databaseId,
      vaultId: prior.vaultId,
      authorityDelegationDigest: prior.authorityDelegationDigest,
      tuple: terminalTuple,
      previousHeadDigest: prior.headDigest,
      headDigest: terminalHeadDigest,
      encryptedMembershipDigest: terminalEncryptedMembershipDigest,
      encryptedEnvelopesDigest: prior.encryptedEnvelopesDigest,
      policyDigest: prior.policyDigest,
      databaseDeviceRegistry: makeRegistry(),
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
  };
  const signedMutationReceipt = {
    format: 'kavrix-collaborative-mutation-receipt' as const,
    protocolVersion: 1 as const,
    databaseId: prior.databaseId,
    vaultId: prior.vaultId,
    operationId,
    operationType: 'destroy-vault' as const,
    requestDigest: commitment.requestDigest,
    actorPrincipalId: 'principal-a',
    actorDeviceId: 'device-a',
    priorTuple,
    priorHeadDigest: prior.headDigest,
    committedTuple: terminalTuple,
    committedHeadDigest: terminalHeadDigest,
    finalizedMutationLinkDigest,
    outcomeDigest,
    committedAt: laterTimestamp,
    receiptSignature: signature(seed + 8),
  };
  const tombstone = collaborationVaultDestructionTombstoneSchema.parse({
    format: 'kavrix-collaborative-vault-destruction-tombstone',
    protocolVersion: 1,
    databaseId: prior.databaseId,
    vaultId: prior.vaultId,
    core: {
      format: 'kavrix-collaborative-vault-destruction-core',
      protocolVersion: 1,
      databaseId: prior.databaseId,
      vaultId: prior.vaultId,
      operationId,
      authorityEpoch: prior.authorityEpoch,
      authorityDelegationDigest: prior.authorityDelegationDigest,
      priorTuple,
      priorHeadDigest: prior.headDigest,
      terminalTuple,
      actionParametersDigest: digest(seed + 9),
      actorPrincipalId: 'principal-a',
      actorDeviceId: 'device-a',
      destructionMode: 'irreversible',
      destroyedAt: laterTimestamp,
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
    databaseId: prior.databaseId,
    vaultId: prior.vaultId,
    operationId,
    operationType: 'destroy-vault',
    requestDigest: commitment.requestDigest,
    actorPrincipalId: 'principal-a',
    actorDeviceId: 'device-a',
    priorTuple,
    priorHeadDigest: prior.headDigest,
    state: 'committed',
    committedTuple: terminalTuple,
    committedHeadDigest: terminalHeadDigest,
    finalizedMutationLinkDigest,
    committedAt: laterTimestamp,
    outcomeDigest,
    signedMutationReceipt,
    createdAt: timestamp,
    resolvedAt: laterTimestamp,
    detailsRetainedUntil: expiryTimestamp,
  });
  return { tombstone, outcome };
}

function storedProofEntry(
  entry: CollaborationMutationProof['entries'][number],
  outcome: DurableOperationOutcome,
): StoredProofEntry {
  return {
    ...entry,
    _id: `${DATABASE_ID}:${VAULT_ID}:${entry.link.commitment.operationId}`,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    finalizedMutationLinkDigest: outcome.finalizedMutationLinkDigest,
  };
}

function makeTombstone(
  outcome: DurableOperationOutcome,
): OperationDeduplicationTombstone {
  return operationDeduplicationTombstoneSchema.parse({
    format: 'kavrix-collaborative-operation-tombstone',
    protocolVersion: 1,
    databaseId: outcome.databaseId,
    vaultId: outcome.vaultId,
    operationId: outcome.operationId,
    operationType: outcome.operationType,
    requestDigest: outcome.requestDigest,
    outcomeDigest: outcome.outcomeDigest,
    signedMutationReceipt: outcome.signedMutationReceipt,
    createdAt: laterTimestamp,
    retainedUntilVaultDestruction: true,
  });
}

function makeUnsignedRejectedOutcome(
  candidate: CollaborativeVaultDocument,
): DurableOperationOutcome {
  const commitment = candidate.currentMutationLink.commitment;
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
    priorTuple: {
      authorityEpoch: commitment.previousAuthorityEpoch,
      documentRevision: commitment.previousDocumentRevision,
      membershipRevision: commitment.previousMembershipRevision,
      policyRevision: commitment.previousPolicyRevision,
      keyEpoch: commitment.previousKeyEpoch,
      databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
      databaseDeviceRegistryDigest: commitment.previousDatabaseDeviceRegistryDigest,
      authorizationStateDigest: commitment.previousAuthorizationStateDigest,
    },
    priorHeadDigest: commitment.previousHeadDigest,
    state: 'rejected',
    outcomeDigest: digest(126),
    createdAt: timestamp,
    resolvedAt: laterTimestamp,
    detailsRetainedUntil: expiryTimestamp,
  });
}

function makeCheckpoint(
  candidate: CollaborativeVaultDocument,
  outcome: DurableOperationOutcome,
): CollaborationAuthorizationCheckpoint {
  return collaborationAuthorizationCheckpointSchema.parse({
    format: 'kavrix-collaborative-authorization-checkpoint',
    protocolVersion: 1,
    checkpointId: `checkpoint-${String(candidate.documentRevision)}`,
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    authorityDelegationDigest: candidate.authorityDelegationDigest,
    tuple: tuple(candidate.documentRevision, candidate.authorizationStateDigest),
    headDigest: candidate.headDigest,
    authorizationStateDigest: candidate.authorizationStateDigest,
    finalizedMutationLinkDigest: outcome.finalizedMutationLinkDigest,
    compactedThroughDocumentRevision: candidate.documentRevision,
    checkpointDigest: digest(120 + candidate.documentRevision),
    signerPrincipalId: 'principal-a',
    signerDeviceId: 'device-a',
    createdAt: laterTimestamp,
    ownerSignature: signature(120 + candidate.documentRevision),
  });
}

interface StoredProofEntry extends Record<string, unknown> {
  _id: string;
}

interface FakeCollection {
  createIndex: ReturnType<typeof vi.fn>;
  find: ReturnType<typeof vi.fn>;
  findOne: ReturnType<typeof vi.fn>;
  replaceOne: ReturnType<typeof vi.fn>;
  updateOne: ReturnType<typeof vi.fn>;
  insertOne: ReturnType<typeof vi.fn>;
  deleteOne: ReturnType<typeof vi.fn>;
}

interface FakeMongo {
  store: MongoCollaborativeVaultStore;
  legacy: FakeCollection;
  vaults: FakeCollection;
  registries: FakeCollection;
  outcomes: FakeCollection;
  tombstones: FakeCollection;
  vaultDestructions: FakeCollection;
  links: FakeCollection;
  checkpoints: FakeCollection;
}

interface FakeCursor {
  sort: ReturnType<typeof vi.fn>;
  limit: ReturnType<typeof vi.fn>;
  toArray: ReturnType<typeof vi.fn>;
}

function collection(): FakeCollection {
  return {
    createIndex: vi.fn(() => Promise.resolve('index')),
    find: vi.fn(),
    findOne: vi.fn(),
    replaceOne: vi.fn(),
    updateOne: vi.fn(),
    insertOne: vi.fn(),
    deleteOne: vi.fn(),
  };
}

function makeFakeMongo(): FakeMongo {
  const legacy = collection();
  const vaults = collection();
  const registries = collection();
  const outcomes = collection();
  const tombstones = collection();
  const vaultDestructions = collection();
  vaultDestructions.findOne.mockResolvedValue(null);
  const links = collection();
  const checkpoints = collection();
  const collections = new Map<string, FakeCollection>([
    [COLLECTION_NAMES.collaborativeVaultCollectionName, vaults],
    [COLLECTION_NAMES.databaseDeviceRegistryCollectionName, registries],
    [COLLECTION_NAMES.operationOutcomeCollectionName, outcomes],
    [COLLECTION_NAMES.operationTombstoneCollectionName, tombstones],
    [COLLECTION_NAMES.vaultDestructionTombstoneCollectionName, vaultDestructions],
    [COLLECTION_NAMES.finalizedMutationLinkCollectionName, links],
    [COLLECTION_NAMES.authorizationCheckpointCollectionName, checkpoints],
  ]);
  const session = {
    withTransaction: vi.fn(async (callback: (session: unknown) => Promise<unknown>) =>
      callback(session),
    ),
  };
  const client = {
    withSession: vi.fn(async (callback: (session: unknown) => Promise<unknown>) =>
      callback(session),
    ),
  };
  const database = { collection: vi.fn((name: string) => collections.get(name)) };
  return {
    store: new MongoCollaborativeVaultStore(
      client as unknown as MongoClient,
      database as unknown as Db,
      COLLECTION_NAMES,
      legacy as unknown as Collection<
        Readonly<{ _id: string }> & Record<string, unknown>
      >,
    ),
    legacy,
    vaults,
    registries,
    outcomes,
    tombstones,
    vaultDestructions,
    links,
    checkpoints,
  };
}

function cursor(rows: readonly unknown[]): FakeCursor {
  return {
    sort: vi.fn().mockReturnThis(),
    limit: vi.fn().mockReturnThis(),
    toArray: vi.fn(() => Promise.resolve(rows)),
  };
}

function stored<T>(value: T, id: string): T & { _id: string } {
  return { ...value, _id: id };
}

function errorCode(error: unknown): string | undefined {
  return error instanceof EncryptedDatabaseStoreError ? error.code : undefined;
}

describe('MongoCollaborativeVaultStore', () => {
  beforeEach(() => vi.clearAllMocks());

  it('creates unique append-only link and checkpoint indexes without a tombstone TTL', async () => {
    const mongo = makeFakeMongo();
    await mongo.store.initializeIndexes();
    expect(mongo.links.createIndex).toHaveBeenCalledWith(
      { databaseId: 1, vaultId: 1, 'link.resultingHeadDigest': 1 },
      { name: 'collaborative_mutation_link_head', unique: true },
    );
    expect(mongo.links.createIndex).toHaveBeenCalledWith(
      { databaseId: 1, vaultId: 1, 'link.commitment.documentRevision': 1 },
      { name: 'collaborative_mutation_link_revision', unique: true },
    );
    expect(mongo.checkpoints.createIndex).toHaveBeenCalledWith(
      { databaseId: 1, vaultId: 1, checkpointDigest: 1 },
      { name: 'collaborative_authorization_checkpoint_digest', unique: true },
    );
    expect(mongo.tombstones.createIndex.mock.calls[0]?.[1]).not.toHaveProperty(
      'expireAfterSeconds',
    );
    expect(mongo.vaultDestructions.createIndex).toHaveBeenCalledWith(
      { databaseId: 1, vaultId: 1 },
      { name: 'collaborative_vault_destruction_identity', unique: true },
    );
    expect(mongo.vaultDestructions.createIndex.mock.calls[0]?.[1]).not.toHaveProperty(
      'expireAfterSeconds',
    );
  });

  it('publishes and advances the authority deny registry through exact generation CAS', async () => {
    const mongo = makeFakeMongo();
    const genesis = makeRegistry();
    mongo.registries.findOne.mockResolvedValueOnce(null);
    mongo.registries.replaceOne.mockResolvedValueOnce({
      matchedCount: 0,
      upsertedCount: 1,
    });
    await mongo.store.publishDatabaseDeviceRegistry(genesis);

    const denial = {
      principalId: 'principal-a',
      deviceId: 'device-a',
      deviceGeneration: 1,
      signingKeyFingerprint: digest(121),
      reason: 'compromised' as const,
      deniedAt: laterTimestamp,
    };
    const next = makeRegistry(2, genesis.registryDigest, digest(122), [denial]);
    mongo.registries.findOne.mockResolvedValueOnce(stored(genesis, DATABASE_ID));
    mongo.registries.replaceOne.mockResolvedValueOnce({ matchedCount: 1 });
    await mongo.store.publishDatabaseDeviceRegistry(next);
    expect(mongo.registries.replaceOne).toHaveBeenLastCalledWith(
      expect.objectContaining({
        generation: genesis.generation,
        registryDigest: genesis.registryDigest,
      }),
      expect.objectContaining({ deniedDevices: [denial] }),
      expect.anything(),
    );
  });

  it('rejects a stale deny-registry update before its replacement write', async () => {
    const mongo = makeFakeMongo();
    const current = makeRegistry(2, digest(1), digest(122));
    const stale = makeRegistry(3, digest(123), digest(124));
    mongo.registries.findOne.mockResolvedValueOnce(stored(current, DATABASE_ID));
    await expect(mongo.store.publishDatabaseDeviceRegistry(stale)).rejects.toSatisfy(
      (error: unknown) => errorCode(error) === 'conflict',
    );
    expect(mongo.registries.replaceOne).not.toHaveBeenCalled();
  });

  it('rejects deny removal and in-place authority replacement', async () => {
    const denial = {
      principalId: 'principal-a',
      deviceId: 'device-a',
      deviceGeneration: 1,
      signingKeyFingerprint: digest(121),
      reason: 'compromised' as const,
      deniedAt: laterTimestamp,
    };
    const current = makeRegistry(2, digest(1), digest(122), [denial]);

    for (const candidate of [
      makeRegistry(3, current.registryDigest, digest(123), []),
      {
        ...makeRegistry(3, current.registryDigest, digest(124), [denial]),
        authorityEpoch: 2,
      },
      {
        ...makeRegistry(3, current.registryDigest, digest(125), [denial]),
        authorityFingerprint: digest(126),
      },
    ]) {
      const mongo = makeFakeMongo();
      mongo.registries.findOne.mockResolvedValueOnce(stored(current, DATABASE_ID));
      await expect(
        mongo.store.publishDatabaseDeviceRegistry(
          collaborationDatabaseDeviceRegistrySchema.parse(candidate),
        ),
      ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'conflict');
      expect(mongo.registries.replaceOne).not.toHaveBeenCalled();
    }
  });

  it('strips the internal publication fence before returning a registry', async () => {
    const mongo = makeFakeMongo();
    const registry = makeRegistry();
    mongo.registries.findOne.mockResolvedValueOnce({
      ...stored(registry, DATABASE_ID),
      storagePublicationFence: `${DATABASE_ID}:${VAULT_ID}:operation-update-2`,
    });
    await expect(mongo.store.getDatabaseDeviceRegistry(DATABASE_ID)).resolves.toEqual(
      registry,
    );
  });

  it('atomically CAS-replaces a candidate and inserts its proof entry and committed outcome', async () => {
    const mongo = makeFakeMongo();
    const prior = makeGenesisDocument();
    const candidate = makeOrdinaryUpdate(prior, 2);
    const outcome = makeOutcome(candidate);
    const proofEntry = makeProofEntry(candidate);
    mongo.outcomes.findOne.mockResolvedValueOnce(null);
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.registries.findOne.mockResolvedValueOnce(stored(makeRegistry(), DATABASE_ID));
    mongo.registries.updateOne.mockResolvedValueOnce({
      matchedCount: 1,
      modifiedCount: 1,
    });
    mongo.vaults.findOne.mockResolvedValueOnce(
      stored(prior, `${DATABASE_ID}:${VAULT_ID}`),
    );
    mongo.vaults.replaceOne.mockResolvedValueOnce({ matchedCount: 1 });
    mongo.links.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.outcomes.insertOne.mockResolvedValueOnce({ acknowledged: true });

    await expect(
      mongo.store.publishCollaborativeVault({ candidate, outcome, proofEntry }),
    ).resolves.toEqual(outcome);
    expect(mongo.registries.updateOne).toHaveBeenCalledWith(
      {
        _id: DATABASE_ID,
        databaseId: DATABASE_ID,
        authorityEpoch: candidate.authorityEpoch,
        generation: candidate.databaseDeviceGeneration,
        registryDigest: candidate.databaseDeviceRegistryDigest,
        storagePublicationFence: {
          $ne: `${DATABASE_ID}:${VAULT_ID}:${outcome.operationId}`,
        },
      },
      {
        $set: {
          storagePublicationFence: `${DATABASE_ID}:${VAULT_ID}:${outcome.operationId}`,
        },
      },
      expect.anything(),
    );
    expect(mongo.vaults.findOne).toHaveBeenCalledWith(
      expect.objectContaining({
        documentRevision: 1,
        headDigest: prior.headDigest,
        authorizationStateDigest: prior.authorizationStateDigest,
        authorityDelegationDigest: prior.authorityDelegationDigest,
      }),
      expect.anything(),
    );
    expect(mongo.links.insertOne).toHaveBeenCalledWith(
      expect.objectContaining({
        link: proofEntry.link,
        finalizedMutationLinkDigest: outcome.finalizedMutationLinkDigest,
      }),
      expect.anything(),
    );
  });

  it('rejects publication when the exact registry row cannot be write-fenced', async () => {
    const prior = makeGenesisDocument();
    const candidate = makeOrdinaryUpdate(prior, 2);
    const mongo = makeFakeMongo();
    mongo.outcomes.findOne.mockResolvedValueOnce(null);
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.registries.findOne.mockResolvedValueOnce(stored(makeRegistry(), DATABASE_ID));
    mongo.registries.updateOne.mockResolvedValueOnce({
      matchedCount: 0,
      modifiedCount: 0,
    });
    await expect(
      mongo.store.publishCollaborativeVault({
        candidate,
        outcome: makeOutcome(candidate),
        proofEntry: makeProofEntry(candidate),
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'conflict');
    expect(mongo.vaults.findOne).not.toHaveBeenCalled();
    expect(mongo.links.insertOne).not.toHaveBeenCalled();
  });

  it('rejects genesis through the ordinary publish path and stale full-state CAS', async () => {
    const genesis = makeGenesisDocument();
    const genesisOutcome = makeOutcome(genesis);
    const genesisEntry = makeProofEntry(genesis);
    const mongo = makeFakeMongo();
    await expect(
      mongo.store.publishCollaborativeVault({
        candidate: genesis,
        outcome: genesisOutcome,
        proofEntry: genesisEntry,
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');

    const candidate = makeOrdinaryUpdate(genesis, 2);
    const outcome = makeOutcome(candidate);
    mongo.outcomes.findOne.mockResolvedValueOnce(null);
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.registries.findOne.mockResolvedValueOnce(stored(makeRegistry(), DATABASE_ID));
    mongo.registries.updateOne.mockResolvedValueOnce({
      matchedCount: 1,
      modifiedCount: 1,
    });
    mongo.vaults.findOne.mockResolvedValueOnce(null);
    await expect(
      mongo.store.publishCollaborativeVault({
        candidate,
        outcome,
        proofEntry: makeProofEntry(candidate),
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'conflict');
    expect(mongo.links.insertOne).not.toHaveBeenCalled();
  });

  it('reconciles an ambiguous retry only when outcome and proof entry are exact', async () => {
    const prior = makeGenesisDocument();
    const candidate = makeOrdinaryUpdate(prior, 2);
    const outcome = makeOutcome(candidate);
    const proofEntry = makeProofEntry(candidate);
    const mongo = makeFakeMongo();
    mongo.outcomes.findOne.mockResolvedValueOnce(
      stored(outcome, `${DATABASE_ID}:${VAULT_ID}:${outcome.operationId}`),
    );
    mongo.links.findOne.mockResolvedValueOnce(storedProofEntry(proofEntry, outcome));
    await expect(
      mongo.store.publishCollaborativeVault({ candidate, outcome, proofEntry }),
    ).resolves.toEqual(outcome);
    expect(mongo.vaults.replaceOne).not.toHaveBeenCalled();

    const conflictingCandidate = collaborativeVaultDocumentSchema.parse({
      ...candidate,
      currentMutationLink: {
        ...candidate.currentMutationLink,
        writerSignature: {
          ...candidate.currentMutationLink.writerSignature,
          signature: signature(127),
        },
      },
    });
    const conflictingEntry = makeProofEntry(conflictingCandidate);
    mongo.outcomes.findOne.mockResolvedValueOnce(
      stored(outcome, `${DATABASE_ID}:${VAULT_ID}:${outcome.operationId}`),
    );
    mongo.links.findOne.mockResolvedValueOnce(storedProofEntry(proofEntry, outcome));
    await expect(
      mongo.store.publishCollaborativeVault({
        candidate: conflictingCandidate,
        outcome,
        proofEntry: conflictingEntry,
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
  });

  it('maps duplicate link/head/revision races to conflict', async () => {
    const prior = makeGenesisDocument();
    const candidate = makeOrdinaryUpdate(prior, 2);
    const mongo = makeFakeMongo();
    mongo.outcomes.findOne.mockResolvedValueOnce(null);
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.registries.findOne.mockResolvedValueOnce(stored(makeRegistry(), DATABASE_ID));
    mongo.registries.updateOne.mockResolvedValueOnce({
      matchedCount: 1,
      modifiedCount: 1,
    });
    mongo.vaults.findOne.mockResolvedValueOnce(
      stored(prior, `${DATABASE_ID}:${VAULT_ID}`),
    );
    mongo.vaults.replaceOne.mockResolvedValueOnce({ matchedCount: 1 });
    mongo.links.insertOne.mockRejectedValueOnce({ code: 11_000 });
    await expect(
      mongo.store.publishCollaborativeVault({
        candidate,
        outcome: makeOutcome(candidate),
        proofEntry: makeProofEntry(candidate),
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'conflict');
  });

  it('discards an unsigned persisted rejection so it cannot poison an operation ID', async () => {
    const prior = makeGenesisDocument();
    const candidate = makeOrdinaryUpdate(prior, 2);
    const outcome = makeOutcome(candidate);
    const proofEntry = makeProofEntry(candidate);
    const rejected = makeUnsignedRejectedOutcome(candidate);
    const mongo = makeFakeMongo();
    mongo.outcomes.findOne.mockResolvedValueOnce(
      stored(rejected, `${DATABASE_ID}:${VAULT_ID}:${rejected.operationId}`),
    );
    mongo.outcomes.deleteOne.mockResolvedValueOnce({ deletedCount: 1 });
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.registries.findOne.mockResolvedValueOnce(stored(makeRegistry(), DATABASE_ID));
    mongo.registries.updateOne.mockResolvedValueOnce({
      matchedCount: 1,
      modifiedCount: 1,
    });
    mongo.vaults.findOne.mockResolvedValueOnce(
      stored(prior, `${DATABASE_ID}:${VAULT_ID}`),
    );
    mongo.vaults.replaceOne.mockResolvedValueOnce({ matchedCount: 1 });
    mongo.links.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.outcomes.insertOne.mockResolvedValueOnce({ acknowledged: true });
    await expect(
      mongo.store.publishCollaborativeVault({ candidate, outcome, proofEntry }),
    ).resolves.toEqual(outcome);
    expect(mongo.outcomes.deleteOne).toHaveBeenCalledWith(
      expect.objectContaining({ state: 'rejected' }),
      expect.anything(),
    );
  });

  it('returns a contiguous proof with the latest prior encrypted authorization witness', async () => {
    const genesis = makeGenesisDocument();
    const second = makeOrdinaryUpdate(genesis, 2);
    const third = makeOrdinaryUpdate(second, 3);
    const genesisEntry = makeProofEntry(genesis);
    const secondEntry = makeProofEntry(second);
    const thirdEntry = makeProofEntry(third);
    const mongo = makeFakeMongo();
    mongo.links.find.mockReturnValueOnce(
      cursor([
        storedProofEntry(secondEntry, makeOutcome(second)),
        storedProofEntry(thirdEntry, makeOutcome(third)),
      ]),
    );
    mongo.links.findOne.mockResolvedValueOnce(
      storedProofEntry(genesisEntry, makeOutcome(genesis)),
    );
    const proof = await mongo.store.getCollaborativeMutationProofRange({
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      fromExclusive: { documentRevision: 1, headDigest: genesis.headDigest },
      toInclusive: { documentRevision: 3, headDigest: third.headDigest },
      limit: 2,
    });
    expect(proof.entries).toEqual([secondEntry, thirdEntry]);
    expect(proof.startingAuthorizationWitness).toEqual(
      genesisEntry.authorizationWitness,
    );
  });

  it('reads exact immutable links by resulting head and operation ID', async () => {
    const candidate = makeOrdinaryUpdate(makeGenesisDocument(), 2);
    const entry = makeProofEntry(candidate);
    const outcome = makeOutcome(candidate);
    const mongo = makeFakeMongo();
    mongo.links.findOne
      .mockResolvedValueOnce(storedProofEntry(entry, outcome))
      .mockResolvedValueOnce(storedProofEntry(entry, outcome));
    await expect(
      mongo.store.getCollaborativeFinalizedMutationLinkByHead(
        DATABASE_ID,
        VAULT_ID,
        candidate.headDigest,
      ),
    ).resolves.toEqual(entry.link);
    await expect(
      mongo.store.getCollaborativeFinalizedMutationLinkByOperation(
        DATABASE_ID,
        VAULT_ID,
        entry.link.commitment.operationId,
      ),
    ).resolves.toEqual(entry.link);
  });

  it.each([
    [
      'missing',
      (second: unknown, third: unknown) => {
        void third;
        return [second];
      },
    ],
    ['reordered', (second: unknown, third: unknown) => [third, second]],
    [
      'gapped',
      (second: unknown, third: unknown) => {
        void second;
        return [third];
      },
    ],
  ])('rejects %s proof ranges', async (_name, rowsFor) => {
    const genesis = makeGenesisDocument();
    const second = makeOrdinaryUpdate(genesis, 2);
    const third = makeOrdinaryUpdate(second, 3);
    const mongo = makeFakeMongo();
    const secondStored = storedProofEntry(makeProofEntry(second), makeOutcome(second));
    const thirdStored = storedProofEntry(makeProofEntry(third), makeOutcome(third));
    mongo.links.find.mockReturnValueOnce(cursor(rowsFor(secondStored, thirdStored)));
    mongo.links.findOne.mockResolvedValueOnce(
      storedProofEntry(makeProofEntry(genesis), makeOutcome(genesis)),
    );
    await expect(
      mongo.store.getCollaborativeMutationProofRange({
        databaseId: DATABASE_ID,
        vaultId: VAULT_ID,
        fromExclusive: { documentRevision: 1, headDigest: genesis.headDigest },
        toInclusive: { documentRevision: 3, headDigest: third.headDigest },
        limit: 2,
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
  });

  it('rejects structurally tampered proof records and out-of-bound ranges', async () => {
    const genesis = makeGenesisDocument();
    const second = makeOrdinaryUpdate(genesis, 2);
    const mongo = makeFakeMongo();
    mongo.links.find.mockReturnValueOnce(
      cursor([
        {
          ...storedProofEntry(makeProofEntry(second), makeOutcome(second)),
          unexpected: true,
        },
      ]),
    );
    await expect(
      mongo.store.getCollaborativeMutationProofRange({
        databaseId: DATABASE_ID,
        vaultId: VAULT_ID,
        fromExclusive: { documentRevision: 1, headDigest: genesis.headDigest },
        toInclusive: { documentRevision: 2, headDigest: second.headDigest },
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
    await expect(
      mongo.store.getCollaborativeMutationProofRange({
        databaseId: DATABASE_ID,
        vaultId: VAULT_ID,
        fromExclusive: { documentRevision: 1, headDigest: genesis.headDigest },
        toInclusive: { documentRevision: 258, headDigest: digest(127) },
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
  });

  it('appends an owner checkpoint only when its exact finalized link exists', async () => {
    const genesis = makeGenesisDocument();
    const outcome = makeOutcome(genesis);
    const entry = makeProofEntry(genesis);
    const checkpoint = makeCheckpoint(genesis, outcome);
    const mongo = makeFakeMongo();
    mongo.checkpoints.findOne.mockResolvedValueOnce(null);
    mongo.links.findOne.mockResolvedValueOnce(storedProofEntry(entry, outcome));
    mongo.checkpoints.insertOne.mockResolvedValueOnce({ acknowledged: true });
    await mongo.store.appendCollaborationAuthorizationCheckpoint(checkpoint);
    expect(mongo.checkpoints.insertOne).toHaveBeenCalledWith(
      expect.objectContaining({ checkpointDigest: checkpoint.checkpointDigest }),
      expect.anything(),
    );

    mongo.checkpoints.findOne.mockResolvedValueOnce(
      stored(checkpoint, `${DATABASE_ID}:${VAULT_ID}:${checkpoint.checkpointId}`),
    );
    await expect(
      mongo.store.appendCollaborationAuthorizationCheckpoint(checkpoint),
    ).resolves.toBeUndefined();
  });

  it('rejects a checkpoint whose delegation differs from its stored link', async () => {
    const genesis = makeGenesisDocument();
    const outcome = makeOutcome(genesis);
    const entry = makeProofEntry(genesis);
    const checkpoint = collaborationAuthorizationCheckpointSchema.parse({
      ...makeCheckpoint(genesis, outcome),
      authorityDelegationDigest: digest(198),
    });
    const mongo = makeFakeMongo();
    mongo.checkpoints.findOne.mockResolvedValueOnce(null);
    mongo.links.findOne.mockResolvedValueOnce(storedProofEntry(entry, outcome));
    await expect(
      mongo.store.appendCollaborationAuthorizationCheckpoint(checkpoint),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
    expect(mongo.checkpoints.insertOne).not.toHaveBeenCalled();
  });

  it.each([
    ['authority epoch', { authorityEpoch: 2 }],
    ['document revision', { documentRevision: 2 }],
    ['membership revision', { membershipRevision: 2 }],
    ['policy revision', { policyRevision: 2 }],
    ['key epoch', { keyEpoch: 2 }],
    ['database-device generation', { databaseDeviceGeneration: 2 }],
    ['registry digest', { databaseDeviceRegistryDigest: digest(197) }],
    ['authorization-state digest', { authorizationStateDigest: digest(196) }],
  ] as const)(
    'rejects a checkpoint with a mismatched %s',
    async (_name, tuplePatch) => {
      const genesis = makeGenesisDocument();
      const outcome = makeOutcome(genesis);
      const entry = makeProofEntry(genesis);
      const original = makeCheckpoint(genesis, outcome);
      const mismatchedTuple = { ...original.tuple, ...tuplePatch };
      const checkpoint = collaborationAuthorizationCheckpointSchema.parse({
        ...original,
        tuple: mismatchedTuple,
        authorizationStateDigest: mismatchedTuple.authorizationStateDigest,
      });
      const mongo = makeFakeMongo();
      mongo.checkpoints.findOne.mockResolvedValueOnce(null);
      mongo.links.findOne.mockResolvedValueOnce(storedProofEntry(entry, outcome));
      await expect(
        mongo.store.appendCollaborationAuthorizationCheckpoint(checkpoint),
      ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
      expect(mongo.checkpoints.insertOne).not.toHaveBeenCalled();
    },
  );

  it('rejects a previous checkpoint from another delegation', async () => {
    const genesis = makeGenesisDocument();
    const second = makeOrdinaryUpdate(genesis, 2);
    const genesisOutcome = makeOutcome(genesis);
    const secondOutcome = makeOutcome(second);
    const previous = collaborationAuthorizationCheckpointSchema.parse({
      ...makeCheckpoint(genesis, genesisOutcome),
      authorityDelegationDigest: digest(195),
    });
    const current = collaborationAuthorizationCheckpointSchema.parse({
      ...makeCheckpoint(second, secondOutcome),
      previousCheckpointDigest: previous.checkpointDigest,
    });
    const mongo = makeFakeMongo();
    mongo.checkpoints.findOne
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(
        stored(previous, `${DATABASE_ID}:${VAULT_ID}:${previous.checkpointId}`),
      );
    mongo.links.findOne.mockResolvedValueOnce(
      storedProofEntry(makeProofEntry(second), secondOutcome),
    );
    await expect(
      mongo.store.appendCollaborationAuthorizationCheckpoint(current),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
    expect(mongo.checkpoints.insertOne).not.toHaveBeenCalled();
  });

  it('compacts committed outcomes without losing the exact writer-signed receipt', async () => {
    const candidate = makeOrdinaryUpdate(makeGenesisDocument(), 2);
    const outcome = makeOutcome(candidate);
    const tombstone = makeTombstone(outcome);
    const mongo = makeFakeMongo();
    mongo.outcomes.findOne.mockResolvedValueOnce(
      stored(outcome, `${DATABASE_ID}:${VAULT_ID}:${outcome.operationId}`),
    );
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.tombstones.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.outcomes.deleteOne.mockResolvedValueOnce({ deletedCount: 1 });
    await expect(
      mongo.store.compactCollaborativeOperationOutcome({ tombstone }),
    ).resolves.toEqual(tombstone);
    expect(tombstone.signedMutationReceipt).toEqual(outcome.signedMutationReceipt);
  });

  it('atomically deletes the exact live vault and commits its permanent destruction evidence', async () => {
    const genesis = makeGenesisDocument();
    const prior = collaborativeVaultDocumentSchema.parse({
      ...genesis,
      discoveryRecords: [
        makeDiscoveryRecord(genesis, genesis.encryptedMembershipDigest, 200),
      ],
    });
    const { tombstone, outcome } = makeDestructionArtifacts(prior);
    const mongo = makeFakeMongo();
    mongo.vaultDestructions.findOne.mockResolvedValueOnce(null);
    mongo.outcomes.findOne.mockResolvedValueOnce(null);
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.links.findOne.mockResolvedValueOnce(null);
    mongo.registries.findOne.mockResolvedValueOnce(stored(makeRegistry(), DATABASE_ID));
    mongo.registries.updateOne.mockResolvedValueOnce({
      matchedCount: 1,
      modifiedCount: 1,
    });
    mongo.vaults.findOne.mockResolvedValueOnce(
      stored(prior, `${DATABASE_ID}:${VAULT_ID}`),
    );
    mongo.vaults.deleteOne.mockResolvedValueOnce({ deletedCount: 1 });
    mongo.vaultDestructions.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.links.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.outcomes.insertOne.mockResolvedValueOnce({ acknowledged: true });

    await expect(
      mongo.store.destroyCollaborativeVault({ tombstone, outcome }),
    ).resolves.toEqual(outcome);
    expect(tombstone.proofEntry.link.commitment.encryptedMembershipDigest).not.toBe(
      prior.encryptedMembershipDigest,
    );
    expect(tombstone.proofEntry.authorizationWitness?.discoveryRecords).not.toEqual(
      prior.discoveryRecords,
    );
    expect(mongo.vaults.deleteOne).toHaveBeenCalledWith(
      expect.objectContaining({
        _id: `${DATABASE_ID}:${VAULT_ID}`,
        authorityEpoch: prior.authorityEpoch,
        documentRevision: prior.documentRevision,
        membershipRevision: prior.membershipRevision,
        policyRevision: prior.policyRevision,
        keyEpoch: prior.keyEpoch,
        databaseDeviceGeneration: prior.databaseDeviceGeneration,
        databaseDeviceRegistryDigest: prior.databaseDeviceRegistryDigest,
        authorizationStateDigest: prior.authorizationStateDigest,
        authorityDelegationDigest: prior.authorityDelegationDigest,
        headDigest: prior.headDigest,
      }),
      expect.anything(),
    );
    expect(mongo.vaults.deleteOne.mock.invocationCallOrder[0]).toBeLessThan(
      mongo.vaultDestructions.insertOne.mock.invocationCallOrder[0] ?? 0,
    );
    expect(mongo.vaultDestructions.insertOne.mock.invocationCallOrder[0]).toBeLessThan(
      mongo.links.insertOne.mock.invocationCallOrder[0] ?? 0,
    );
    expect(mongo.links.insertOne.mock.invocationCallOrder[0]).toBeLessThan(
      mongo.outcomes.insertOne.mock.invocationCallOrder[0] ?? 0,
    );
    expect(mongo.vaultDestructions.insertOne).toHaveBeenCalledWith(
      expect.objectContaining({
        _id: `${DATABASE_ID}:${VAULT_ID}`,
        proofEntry: tombstone.proofEntry,
        signedMutationReceipt: tombstone.signedMutationReceipt,
      }),
      expect.anything(),
    );
  });

  it('returns only live state from the live getter and exact terminal evidence from the destruction getter', async () => {
    const { tombstone } = makeDestructionArtifacts();
    const mongo = makeFakeMongo();
    mongo.vaults.findOne.mockResolvedValueOnce(null);
    mongo.vaultDestructions.findOne.mockResolvedValueOnce(
      stored(tombstone, `${DATABASE_ID}:${VAULT_ID}`),
    );
    await expect(
      mongo.store.getCollaborativeVault(DATABASE_ID, VAULT_ID),
    ).resolves.toBeNull();
    await expect(
      mongo.store.getCollaborativeVaultDestructionTombstone(DATABASE_ID, VAULT_ID),
    ).resolves.toEqual(tombstone);
  });

  it('replays destruction only when the permanent tombstone, proof, and full outcome are exact', async () => {
    const { tombstone, outcome } = makeDestructionArtifacts();
    const mongo = makeFakeMongo();
    mongo.vaultDestructions.findOne.mockResolvedValueOnce(
      stored(tombstone, `${DATABASE_ID}:${VAULT_ID}`),
    );
    mongo.vaults.findOne.mockResolvedValueOnce(null);
    mongo.outcomes.findOne.mockResolvedValueOnce(
      stored(outcome, `${DATABASE_ID}:${VAULT_ID}:${outcome.operationId}`),
    );
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.links.findOne.mockResolvedValueOnce(
      storedProofEntry(tombstone.proofEntry, outcome),
    );
    await expect(
      mongo.store.destroyCollaborativeVault({ tombstone, outcome }),
    ).resolves.toEqual(outcome);
    expect(mongo.vaults.deleteOne).not.toHaveBeenCalled();
    expect(mongo.vaultDestructions.insertOne).not.toHaveBeenCalled();
  });

  it('replays an exact compact operation tombstone only with the permanent fence and proof', async () => {
    const { tombstone, outcome } = makeDestructionArtifacts();
    const operationTombstone = makeTombstone(outcome);
    const mongo = makeFakeMongo();
    mongo.vaultDestructions.findOne.mockResolvedValueOnce(
      stored(tombstone, `${DATABASE_ID}:${VAULT_ID}`),
    );
    mongo.vaults.findOne.mockResolvedValueOnce(null);
    mongo.outcomes.findOne.mockResolvedValueOnce(null);
    mongo.tombstones.findOne.mockResolvedValueOnce(
      stored(operationTombstone, `${DATABASE_ID}:${VAULT_ID}:${outcome.operationId}`),
    );
    mongo.links.findOne.mockResolvedValueOnce(
      storedProofEntry(tombstone.proofEntry, outcome),
    );
    await expect(
      mongo.store.destroyCollaborativeVault({ tombstone, outcome }),
    ).resolves.toEqual(operationTombstone);
  });

  it('rejects replay when a live vault coexists with its permanent destruction tombstone', async () => {
    const prior = makeGenesisDocument();
    const { tombstone, outcome } = makeDestructionArtifacts(prior);
    const mongo = makeFakeMongo();
    mongo.vaultDestructions.findOne.mockResolvedValueOnce(
      stored(tombstone, `${DATABASE_ID}:${VAULT_ID}`),
    );
    mongo.vaults.findOne.mockResolvedValueOnce(
      stored(prior, `${DATABASE_ID}:${VAULT_ID}`),
    );
    await expect(
      mongo.store.destroyCollaborativeVault({ tombstone, outcome }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
    expect(mongo.outcomes.findOne).not.toHaveBeenCalled();
    expect(mongo.vaults.deleteOne).not.toHaveBeenCalled();
  });

  it('fails closed on incompatible permanent destruction and partial terminal state', async () => {
    const first = makeDestructionArtifacts();
    const incompatible = makeDestructionArtifacts(
      makeGenesisDocument(),
      'operation-destroy-other',
      150,
    );
    const fenced = makeFakeMongo();
    fenced.vaultDestructions.findOne.mockResolvedValueOnce(
      stored(incompatible.tombstone, `${DATABASE_ID}:${VAULT_ID}`),
    );
    await expect(fenced.store.destroyCollaborativeVault(first)).rejects.toSatisfy(
      (error: unknown) => errorCode(error) === 'conflict',
    );
    expect(fenced.vaults.deleteOne).not.toHaveBeenCalled();

    const partial = makeFakeMongo();
    partial.vaultDestructions.findOne.mockResolvedValueOnce(null);
    partial.outcomes.findOne.mockResolvedValueOnce(
      stored(first.outcome, `${DATABASE_ID}:${VAULT_ID}:${first.outcome.operationId}`),
    );
    await expect(partial.store.destroyCollaborativeVault(first)).rejects.toSatisfy(
      (error: unknown) => errorCode(error) === 'invalid',
    );
    expect(partial.vaults.deleteOne).not.toHaveBeenCalled();
    expect(partial.vaultDestructions.insertOne).not.toHaveBeenCalled();
  });

  it('rejects tombstone, outcome, proof, and extra-field substitution before storage writes', async () => {
    const first = makeDestructionArtifacts();
    const alternate = makeDestructionArtifacts(
      makeGenesisDocument(),
      'operation-destroy-other',
      150,
    );
    const substitutedProof = {
      ...first.tombstone,
      proofEntry: alternate.tombstone.proofEntry,
    };
    for (const input of [
      { tombstone: first.tombstone, outcome: alternate.outcome },
      { tombstone: substitutedProof, outcome: first.outcome },
      { ...first, unexpected: true },
    ]) {
      const mongo = makeFakeMongo();
      await expect(
        mongo.store.destroyCollaborativeVault(
          input as unknown as Parameters<
            MongoCollaborativeVaultStore['destroyCollaborativeVault']
          >[0],
        ),
      ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
      expect(mongo.vaults.deleteOne).not.toHaveBeenCalled();
      expect(mongo.vaultDestructions.insertOne).not.toHaveBeenCalled();
    }
  });

  it.each([
    ['live delete CAS', 'delete', 'conflict'],
    ['permanent tombstone insert', 'tombstone', 'operation'],
    ['proof insert', 'proof', 'operation'],
    ['outcome insert', 'outcome', 'operation'],
  ] as const)(
    'fails closed when the %s fails inside the destruction transaction',
    async (_name, failure, expectedCode) => {
      const prior = makeGenesisDocument();
      const artifacts = makeDestructionArtifacts(prior);
      const mongo = makeFakeMongo();
      mongo.vaultDestructions.findOne.mockResolvedValueOnce(null);
      mongo.outcomes.findOne.mockResolvedValueOnce(null);
      mongo.tombstones.findOne.mockResolvedValueOnce(null);
      mongo.links.findOne.mockResolvedValueOnce(null);
      mongo.registries.findOne.mockResolvedValueOnce(
        stored(makeRegistry(), DATABASE_ID),
      );
      mongo.registries.updateOne.mockResolvedValueOnce({
        matchedCount: 1,
        modifiedCount: 1,
      });
      mongo.vaults.findOne.mockResolvedValueOnce(
        stored(prior, `${DATABASE_ID}:${VAULT_ID}`),
      );
      mongo.vaults.deleteOne.mockResolvedValueOnce({
        deletedCount: failure === 'delete' ? 0 : 1,
      });
      mongo.vaultDestructions.insertOne.mockResolvedValueOnce({
        acknowledged: failure !== 'tombstone',
      });
      mongo.links.insertOne.mockResolvedValueOnce({
        acknowledged: failure !== 'proof',
      });
      mongo.outcomes.insertOne.mockResolvedValueOnce({
        acknowledged: failure !== 'outcome',
      });
      await expect(mongo.store.destroyCollaborativeVault(artifacts)).rejects.toSatisfy(
        (error: unknown) => errorCode(error) === expectedCode,
      );
      expect(mongo.outcomes.deleteOne).not.toHaveBeenCalled();
      if (failure === 'delete') {
        expect(mongo.vaultDestructions.insertOne).not.toHaveBeenCalled();
      }
      if (failure === 'tombstone') expect(mongo.links.insertOne).not.toHaveBeenCalled();
      if (failure === 'proof') expect(mongo.outcomes.insertOne).not.toHaveBeenCalled();
    },
  );
});

function makeLegacySource(): DatabaseVaultDocument {
  return databaseVaultDocumentSchema.parse(
    vaultDocument(
      makeDatabaseId('database-a'),
      makeVaultId('vault-a'),
      databaseRevision(4),
      vaultRevision(7),
    ),
  );
}

function migrationArtifacts(): {
  source: DatabaseVaultDocument;
  candidate: CollaborativeVaultDocument;
  proofEntry: CollaborationMutationProof['entries'][number];
  outcome: DurableOperationOutcome;
  request: CollaborationMigrationRequest;
  preparedMarker: CollaborationMigrationPreparedMarker;
  activeMarker: CollaborationMigrationActiveMarker;
} {
  const source = makeLegacySource();
  const candidate = makeGenesisDocument();
  const proofEntry = makeProofEntry(candidate);
  const outcome = makeOutcome(candidate);
  const registryCandidate = makeRegistry();
  const request = collaborationMigrationRequestSchema.parse({
    format: 'kavrix-collaborative-migration-request',
    protocolVersion: 1,
    operationType: 'genesis-migration',
    operationId: candidate.currentMutationLink.commitment.operationId,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    legacyVaultRevision: source.revision,
    legacySourceDigest: digest(130),
    authorityEpoch: 1,
    authorityFingerprint: authorityDelegation.authoritySigningKeyFingerprint,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: REGISTRY_DIGEST,
    initialOwnerPrincipalId: 'principal-a',
    initialOwnerDeviceId: 'device-a',
    initialMembershipId: 'membership-a',
    requestedAt: timestamp,
    requestDigest: candidate.currentMutationLink.commitment.requestDigest,
    authoritySignature: signature(131),
    ownerSignature: signature(132),
  });
  const preparedMarker = collaborationMigrationPreparedMarkerSchema.parse({
    format: 'kavrix-collaborative-migration-marker',
    markerVersion: 1,
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: request.operationId,
    requestDigest: request.requestDigest,
    legacySourceDigest: request.legacySourceDigest,
    authorityEpoch: 1,
    authorityFingerprint: request.authorityFingerprint,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: REGISTRY_DIGEST,
    candidateHeadDigest: candidate.headDigest,
    preparedAt: timestamp,
    authoritySignature: signature(133),
    state: 'prepared',
    legacySource: source,
    registryCandidate,
  });
  const activeMarker = collaborationMigrationActiveMarkerSchema.parse({
    format: preparedMarker.format,
    markerVersion: preparedMarker.markerVersion,
    protocolVersion: preparedMarker.protocolVersion,
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
    activatedAt: laterTimestamp,
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

describe('Mongo collaborative migration', () => {
  beforeEach(() => vi.clearAllMocks());

  it('atomically fences a legacy row with a resumable prepared marker', async () => {
    const artifacts = migrationArtifacts();
    const mongo = makeFakeMongo();
    mongo.vaults.findOne.mockResolvedValueOnce(null);
    mongo.outcomes.findOne.mockResolvedValueOnce(null);
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.links.findOne.mockResolvedValueOnce(null);
    mongo.legacy.findOne.mockResolvedValueOnce(
      stored(artifacts.source, `${DATABASE_ID}:${VAULT_ID}`),
    );
    mongo.legacy.replaceOne.mockResolvedValueOnce({ matchedCount: 1 });
    await expect(
      mongo.store.beginCollaborativeMigration({
        request: artifacts.request,
        preparedMarker: artifacts.preparedMarker,
      }),
    ).resolves.toEqual(artifacts.preparedMarker);
    expect(mongo.legacy.replaceOne).toHaveBeenCalledWith(
      expect.objectContaining({ revision: artifacts.source.revision }),
      expect.objectContaining({ state: 'prepared' }),
      expect.anything(),
    );
  });

  it('activates registry, genesis, proof entry, outcome, and marker in one transaction', async () => {
    const artifacts = migrationArtifacts();
    const mongo = makeFakeMongo();
    mongo.legacy.findOne.mockResolvedValueOnce(
      stored(artifacts.preparedMarker, `${DATABASE_ID}:${VAULT_ID}`),
    );
    mongo.vaults.findOne.mockResolvedValueOnce(null);
    mongo.outcomes.findOne.mockResolvedValueOnce(null);
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.registries.findOne.mockResolvedValueOnce(null);
    mongo.registries.replaceOne.mockResolvedValueOnce({
      matchedCount: 0,
      upsertedCount: 1,
    });
    mongo.vaults.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.links.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.outcomes.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.legacy.replaceOne.mockResolvedValueOnce({ matchedCount: 1 });
    await expect(
      mongo.store.activateCollaborativeGenesis({
        preparedMarker: artifacts.preparedMarker,
        candidate: artifacts.candidate,
        proofEntry: artifacts.proofEntry,
        outcome: artifacts.outcome,
        activeMarker: artifacts.activeMarker,
      }),
    ).resolves.toEqual(artifacts.outcome);
    expect(mongo.links.insertOne).toHaveBeenCalledWith(
      expect.objectContaining({
        link: artifacts.proofEntry.link,
        authorizationWitness: artifacts.proofEntry.authorizationWitness,
      }),
      expect.anything(),
    );
    expect(mongo.legacy.replaceOne).toHaveBeenCalledWith(
      expect.objectContaining({ state: 'prepared' }),
      expect.objectContaining({ state: 'active' }),
      expect.anything(),
    );
  });

  it('write-fences an equal existing registry before genesis activation', async () => {
    const artifacts = migrationArtifacts();
    const mongo = makeFakeMongo();
    mongo.legacy.findOne.mockResolvedValueOnce(
      stored(artifacts.preparedMarker, `${DATABASE_ID}:${VAULT_ID}`),
    );
    mongo.vaults.findOne.mockResolvedValueOnce(null);
    mongo.outcomes.findOne.mockResolvedValueOnce(null);
    mongo.tombstones.findOne.mockResolvedValueOnce(null);
    mongo.registries.findOne.mockResolvedValueOnce(
      stored(artifacts.preparedMarker.registryCandidate, DATABASE_ID),
    );
    mongo.registries.updateOne.mockResolvedValueOnce({
      matchedCount: 1,
      modifiedCount: 1,
    });
    mongo.vaults.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.links.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.outcomes.insertOne.mockResolvedValueOnce({ acknowledged: true });
    mongo.legacy.replaceOne.mockResolvedValueOnce({ matchedCount: 1 });
    await expect(
      mongo.store.activateCollaborativeGenesis({
        preparedMarker: artifacts.preparedMarker,
        candidate: artifacts.candidate,
        proofEntry: artifacts.proofEntry,
        outcome: artifacts.outcome,
        activeMarker: artifacts.activeMarker,
      }),
    ).resolves.toEqual(artifacts.outcome);
    expect(mongo.registries.updateOne).toHaveBeenCalledWith(
      {
        _id: DATABASE_ID,
        databaseId: DATABASE_ID,
        authorityEpoch: artifacts.preparedMarker.registryCandidate.authorityEpoch,
        generation: artifacts.preparedMarker.registryCandidate.generation,
        registryDigest: artifacts.preparedMarker.registryCandidate.registryDigest,
        storagePublicationFence: {
          $ne: `${DATABASE_ID}:${VAULT_ID}:${artifacts.outcome.operationId}`,
        },
      },
      {
        $set: {
          storagePublicationFence: `${DATABASE_ID}:${VAULT_ID}:${artifacts.outcome.operationId}`,
        },
      },
      expect.anything(),
    );
    expect(mongo.registries.replaceOne).not.toHaveBeenCalled();
  });

  it('rejects prepared candidate-head substitution during activation', async () => {
    const artifacts = migrationArtifacts();
    const substitutedMarker = collaborationMigrationPreparedMarkerSchema.parse({
      ...artifacts.preparedMarker,
      candidateHeadDigest: digest(194),
    });
    const mongo = makeFakeMongo();
    await expect(
      mongo.store.activateCollaborativeGenesis({
        preparedMarker: substitutedMarker,
        candidate: artifacts.candidate,
        proofEntry: artifacts.proofEntry,
        outcome: artifacts.outcome,
        activeMarker: artifacts.activeMarker,
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
    expect(mongo.legacy.findOne).not.toHaveBeenCalled();
  });

  it('rejects a noncanonical genesis predecessor head', async () => {
    const artifacts = migrationArtifacts();
    const noncanonicalPreviousHead = digest(193);
    const candidate = {
      ...artifacts.candidate,
      previousHeadDigest: noncanonicalPreviousHead,
      currentMutationLink: {
        ...artifacts.candidate.currentMutationLink,
        commitment: {
          ...artifacts.candidate.currentMutationLink.commitment,
          previousHeadDigest: noncanonicalPreviousHead,
        },
        authorizationTransition: {
          ...artifacts.candidate.currentMutationLink.authorizationTransition,
          previousHeadDigest: noncanonicalPreviousHead,
        },
      },
    } as CollaborativeVaultDocument;
    const mongo = makeFakeMongo();
    await expect(
      mongo.store.activateCollaborativeGenesis({
        preparedMarker: artifacts.preparedMarker,
        candidate,
        proofEntry: artifacts.proofEntry,
        outcome: artifacts.outcome,
        activeMarker: artifacts.activeMarker,
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
    expect(mongo.legacy.findOne).not.toHaveBeenCalled();
  });

  it('rejects a genesis witness whose claimed link digest differs from the outcome', async () => {
    const artifacts = migrationArtifacts();
    const witness = artifacts.proofEntry.authorizationWitness;
    if (witness === undefined) throw new Error('genesis witness missing');
    const conflictingProofEntry = {
      ...artifacts.proofEntry,
      authorizationWitness: {
        ...witness,
        finalizedMutationLinkDigest: digest(199),
      },
    };
    const mongo = makeFakeMongo();
    await expect(
      mongo.store.activateCollaborativeGenesis({
        preparedMarker: artifacts.preparedMarker,
        candidate: artifacts.candidate,
        proofEntry: conflictingProofEntry,
        outcome: artifacts.outcome,
        activeMarker: artifacts.activeMarker,
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'invalid');
    expect(mongo.vaults.insertOne).not.toHaveBeenCalled();
  });

  it('permanently rejects genesis activation for a destroyed vault identity', async () => {
    const artifacts = migrationArtifacts();
    const destruction = makeDestructionArtifacts();
    const mongo = makeFakeMongo();
    mongo.vaultDestructions.findOne.mockResolvedValueOnce(
      stored(destruction.tombstone, `${DATABASE_ID}:${VAULT_ID}`),
    );
    await expect(
      mongo.store.activateCollaborativeGenesis({
        preparedMarker: artifacts.preparedMarker,
        candidate: artifacts.candidate,
        proofEntry: artifacts.proofEntry,
        outcome: artifacts.outcome,
        activeMarker: artifacts.activeMarker,
      }),
    ).rejects.toSatisfy((error: unknown) => errorCode(error) === 'conflict');
    expect(mongo.legacy.findOne).not.toHaveBeenCalled();
    expect(mongo.vaults.insertOne).not.toHaveBeenCalled();
  });
});
