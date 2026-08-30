import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  collaborationDatabaseDeviceRegistrySchema,
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  COLLABORATIVE_AUTHORITY_DELEGATION_FORMAT,
  COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT,
  collaborationMigrationActiveMarkerSchema,
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationRequestSchema,
  collaborationMutationProofEntrySchema,
  collaborationMutationReceiptSchema,
  collaborativeVaultDocumentSchema,
  COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT,
  databaseVaultDocumentSchema,
  durableOperationOutcomeSchema,
  publicIdentityExportSchema,
  recipientRollbackAnchorSchema,
  type CollaborationMigrationActiveMarker,
  type DurableOperationOutcome,
} from '@kavrix/schemas';
import {
  computeAuthorizationTransitionDigest,
  computeDiscoveryTag,
  computeLegacySourceDigest,
  computeMigrationRequestDigest,
  computeMutationHead,
  computePublicKeyFingerprint,
  encodeBase64Url,
  zeroize,
} from '@kavrix/crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(async () => undefined),
  verifyWindowsDirectoryAcl: vi.fn(async () => undefined),
  verifyWindowsUserOnlyAcl: vi.fn(async () => undefined),
}));

import {
  collaborationMigrationJournalCreateInputSchema,
  collaborationMigrationJournalPath,
  createCollaborationMigrationJournal,
  markCollaborationMigrationActive,
  markCollaborationMigrationAnchored,
  readCollaborationMigrationJournal,
  reconcileCollaborationMigrationPublication,
  type CollaborationMigrationJournalCreateInput,
  type CollaborationMigrationJournalScope,
} from '../src/collaboration-migration-journal.js';
import {
  computeFinalizedMutationLinkDigest,
  createRecipientRollbackAnchor,
} from '../src/collaboration-anchor.js';
import {
  collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument,
  createCollaborationAuthorityRollbackAnchor,
} from '../src/collaboration-authority-anchor.js';

const requestedAt = '2026-01-01T00:00:00.000Z';
const preparedAt = '2026-01-02T00:00:00.000Z';
const activatedAt = '2026-01-03T00:00:00.000Z';
const retainedUntil = '2026-02-01T00:00:00.000Z';
const transitionExpiresAt = '2026-01-02T12:00:00.000Z';
const bytes = (length: number, value: number): string =>
  Buffer.alloc(length, value).toString('base64url');
const digest = (value: number): string => bytes(32, value);
const signature = (value: number): string => bytes(64, value);
const legacySourceDigest = computeLegacySourceDigest(legacySource());
const requestDigest = computeMigrationRequestDigest({
  format: 'kavrix-collaborative-migration-request',
  protocolVersion: 1,
  operationType: 'genesis-migration',
  operationId: 'operation-genesis',
  databaseId: 'database-a',
  vaultId: 'vault-a',
  legacyVaultRevision: 7,
  legacySourceDigest,
  authorityEpoch: 1,
  authorityFingerprint: digest(3),
  databaseDeviceGeneration: 1,
  databaseDeviceRegistryDigest: digest(2),
  initialOwnerPrincipalId: 'principal-a',
  initialOwnerDeviceId: 'device-a',
  initialMembershipId: 'membership-a',
  requestedAt,
  requestDigest: digest(25),
  authoritySignature: signature(10),
  ownerSignature: signature(11),
});
const priorHeadDigest = COLLABORATION_GENESIS_HEAD_DIGEST;

const scope: CollaborationMigrationJournalScope = {
  databaseId: 'database-a' as CollaborationMigrationJournalScope['databaseId'],
  vaultId: 'vault-a' as CollaborationMigrationJournalScope['vaultId'],
  principalId: 'principal-a' as CollaborationMigrationJournalScope['principalId'],
  deviceId: 'device-a' as CollaborationMigrationJournalScope['deviceId'],
  operationId: 'operation-genesis' as CollaborationMigrationJournalScope['operationId'],
  requestDigest: requestDigest as CollaborationMigrationJournalScope['requestDigest'],
};

function legacySource() {
  const databaseEnvelope = {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf' as const,
    nonce: bytes(24, 40),
    ciphertext: bytes(48, 41),
    authenticationTag: bytes(16, 42),
    aad: {
      version: 1,
      databaseId: 'database-a',
      entityType: 'wrapped-vault-root' as const,
      entityId: 'vault-a',
      purpose: 'vault-root' as const,
      schemaVersion: 1,
      keyVersion: 1,
      revision: 7,
      vaultId: 'vault-a',
      metadataDigest: digest(43),
    },
    keyVersion: 1,
  };
  return databaseVaultDocumentSchema.parse({
    databaseId: 'database-a',
    id: 'vault-a',
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    databaseRevision: 7,
    revision: 7,
    wrappedVaultRoot: databaseEnvelope,
    encryptedPayload: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: bytes(24, 44),
      ciphertext: bytes(64, 45),
      authenticationTag: bytes(16, 46),
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId: 'vault-a',
        entityType: 'vault-preferences',
        entityId: 'vault-a',
        purpose: 'vault-preferences',
        revision: 7,
        metadataDigest: digest(47),
      },
      keyVersion: 1,
    },
    payloadMetadataDigest: digest(47),
    createdAt: requestedAt,
    updatedAt: requestedAt,
  });
}

function registryCandidate() {
  return collaborationDatabaseDeviceRegistrySchema.parse({
    format: 'kavrix-collaborative-device-registry',
    protocolVersion: 1,
    databaseId: 'database-a',
    authorityEpoch: 1,
    authorityFingerprint: digest(3),
    generation: 1,
    previousRegistryDigest: digest(1),
    registryDigest: digest(2),
    deniedDevices: [],
    updatedAt: preparedAt,
    authoritySignature: signature(3),
  });
}

function initialOwnerIdentity() {
  return publicIdentityExportSchema.parse({
    format: 'kavrix-collaborative-public-identity',
    protocolVersion: 1,
    principalId: 'principal-a',
    identityGeneration: 1,
    rootSigningPublicKey: bytes(32, 63),
    devices: [
      {
        protocolVersion: 1,
        principalId: 'principal-a',
        deviceId: 'device-a',
        deviceGeneration: 1,
        signingPublicKey: bytes(32, 64),
        encryptionPublicKey: bytes(32, 65),
        state: 'active',
        createdAt: requestedAt,
        stateChangedAt: requestedAt,
        rootSignature: signature(64),
      },
    ],
    createdAt: requestedAt,
    selfSignature: signature(63),
  });
}

function migrationRequest() {
  return collaborationMigrationRequestSchema.parse({
    format: 'kavrix-collaborative-migration-request',
    protocolVersion: 1,
    operationType: 'genesis-migration',
    operationId: 'operation-genesis',
    databaseId: 'database-a',
    vaultId: 'vault-a',
    legacyVaultRevision: 7,
    legacySourceDigest,
    authorityEpoch: 1,
    authorityFingerprint: digest(3),
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    initialOwnerPrincipalId: 'principal-a',
    initialOwnerDeviceId: 'device-a',
    initialMembershipId: 'membership-a',
    requestedAt,
    requestDigest,
    authoritySignature: signature(10),
    ownerSignature: signature(11),
  });
}

function collaborativeCandidate() {
  const identity = initialOwnerIdentity();
  const writer = identity.devices[0];
  if (writer === undefined) throw new Error('missing fixture writer');
  const rootFingerprint = computePublicKeyFingerprint(
    identity.rootSigningPublicKey,
    'ed25519',
  );
  const stateFence = {
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
  } as const;
  const authorizationStateDigest = digest(12);
  const previousAuthorizationStateDigest =
    COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST;
  let nextHeadDigest = digest(7);
  const previousTuple = {
    authorityEpoch: 1,
    documentRevision: 0,
    membershipRevision: 0,
    policyRevision: 0,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    authorizationStateDigest: previousAuthorizationStateDigest,
  } as const;
  const nextTuple = {
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    authorizationStateDigest,
  } as const;
  const aad = {
    protocolVersion: 1 as const,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    ...stateFence,
    authorizationStateDigest,
    entityType: 'vault-payload' as const,
    entityId: 'vault-a',
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    metadataDigest: digest(16),
  };
  const delegation = {
    format: COLLABORATIVE_AUTHORITY_DELEGATION_FORMAT,
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    authorityEpoch: 1,
    authoritySigningPublicKey: bytes(32, 60),
    authoritySigningKeyFingerprint: digest(3),
    authorityRecoveryPublicKey: bytes(32, 61),
    authorityRecoveryKeyFingerprint: digest(62),
    genesisOperationId: 'operation-genesis',
    genesisTuple: nextTuple,
    genesisHeadDigest: nextHeadDigest,
    initialAuthorizationStateDigest: authorizationStateDigest,
    initialOwnerPrincipalId: 'principal-a',
    initialOwnerRootKeyFingerprint: rootFingerprint,
    initialOwnerDeviceId: 'device-a',
    initialOwnerDeviceSigningKeyFingerprint: computePublicKeyFingerprint(
      writer.signingPublicKey,
      'ed25519',
    ),
    initialOwnerDeviceEncryptionKeyFingerprint: computePublicKeyFingerprint(
      writer.encryptionPublicKey,
      'x25519',
    ),
    issuedAt: preparedAt,
    authoritySignature: signature(66),
  };
  const commitment = {
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId: 'operation-genesis',
    operationType: 'genesis-migration' as const,
    requestDigest,
    previousHeadDigest: priorHeadDigest,
    previousAuthorizationStateDigest,
    authorizationStateDigest,
    authorizationTransitionDigest: digest(67),
    previousAuthorityEpoch: previousTuple.authorityEpoch,
    previousDocumentRevision: previousTuple.documentRevision,
    previousMembershipRevision: previousTuple.membershipRevision,
    previousPolicyRevision: previousTuple.policyRevision,
    previousKeyEpoch: previousTuple.keyEpoch,
    previousDatabaseDeviceGeneration: previousTuple.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: previousTuple.databaseDeviceRegistryDigest,
    ...stateFence,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    encryptedPayloadDigest: digest(16),
    encryptedMembershipDigest: digest(17),
    encryptedEnvelopesDigest: digest(18),
    policyDigest: digest(19),
    writerPrincipalId: 'principal-a',
    writerDeviceId: 'device-a',
    timestamp: preparedAt,
  };
  const authorizationTransition = {
    format: 'kavrix-collaborative-authorization-transition',
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId: 'operation-genesis',
    operationType: 'genesis-migration' as const,
    previousHeadDigest: priorHeadDigest,
    previousAuthorizationStateDigest,
    authorizationStateDigest,
    previousTuple,
    nextTuple,
    evidence: { kind: 'none' as const },
    issuedAt: preparedAt,
    expiresAt: transitionExpiresAt,
    transitionDigest: digest(67),
    transitionSignature: {
      signerKind: 'owner-device' as const,
      signerPrincipalId: 'principal-a',
      signerDeviceId: 'device-a',
      signature: signature(68),
    },
  };
  const transitionDigest = computeAuthorizationTransitionDigest(
    authorizationTransition,
  );
  authorizationTransition.transitionDigest = transitionDigest;
  commitment.authorizationTransitionDigest = transitionDigest;
  nextHeadDigest = computeMutationHead(commitment);
  delegation.genesisHeadDigest = nextHeadDigest;
  const currentMutationLink = {
    format: COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT,
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    authorityDelegationDigest: digest(69),
    commitment,
    authorizationTransition,
    resultingHeadDigest: nextHeadDigest,
    writerSignature: {
      algorithm: 'ed25519' as const,
      writerPrincipalId: 'principal-a',
      writerDeviceId: 'device-a',
      commitmentDigest: nextHeadDigest,
      signature: signature(70),
    },
    finalizedAt: activatedAt,
  };
  return collaborativeVaultDocumentSchema.parse({
    format: 'kavrix-collaborative-vault',
    documentVersion: 1,
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    ...stateFence,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    previousHeadDigest: priorHeadDigest,
    headDigest: nextHeadDigest,
    authorityDelegation: delegation,
    authorityDelegationDigest: digest(69),
    authorizationStateDigest,
    encryptedPayloadDigest: digest(16),
    encryptedMembershipDigest: digest(17),
    encryptedEnvelopesDigest: digest(18),
    policyDigest: digest(19),
    databaseAuthorityRecoveryEnvelope: {
      format: 'kavrix-collaborative-authority-recovery-envelope',
      protocolVersion: 1,
      algorithm: 'x25519-sealed-box',
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityEpoch: 1,
      authorityRecoveryKeyFingerprint: digest(62),
      keyEpoch: 1,
      membershipRevision: 1,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: digest(2),
      sealedVaultRootKey: bytes(80, 90),
      envelopeDigest: digest(72),
      sealedByPrincipalId: 'principal-a',
      sealedByDeviceId: 'device-a',
      createdAt: requestedAt,
      ownerSignature: signature(73),
    },
    encryptedPayload: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: bytes(24, 20),
      ciphertext: bytes(64, 21),
      authenticationTag: bytes(16, 22),
      aad,
    },
    encryptedMembershipManifest: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: bytes(24, 23),
      ciphertext: bytes(64, 24),
      authenticationTag: bytes(16, 25),
      aad: {
        ...aad,
        entityType: 'membership-manifest',
        metadataDigest: digest(17),
      },
    },
    discoveryRecords: [
      {
        format: 'kavrix-collaborative-discovery-record',
        protocolVersion: 1,
        databaseId: 'database-a',
        vaultId: 'vault-a',
        authorityEpoch: 1,
        databaseDeviceGeneration: 1,
        databaseDeviceRegistryDigest: digest(2),
        discoveryTag: computeDiscoveryTag('database-a', rootFingerprint),
        membershipId: 'membership-a',
        membershipState: 'active',
        keyEpoch: 1,
        membershipRevision: 1,
        authorizationStateDigest,
        encryptedMemberKeyEnvelope: {
          format: 'kavrix-collaborative-member-key-envelope',
          protocolVersion: 1,
          algorithm: 'x25519-sealed-box',
          databaseId: 'database-a',
          vaultId: 'vault-a',
          authorityEpoch: 1,
          membershipId: 'membership-a',
          principalId: 'principal-a',
          deviceId: 'device-a',
          recipientEncryptionKeyFingerprint: computePublicKeyFingerprint(
            writer.encryptionPublicKey,
            'x25519',
          ),
          keyEpoch: 1,
          membershipRevision: 1,
          databaseDeviceGeneration: 1,
          databaseDeviceRegistryDigest: digest(2),
          sealedVaultRootKey: bytes(80, 66),
          envelopeDigest: digest(67),
          createdAt: preparedAt,
          ownerSignature: signature(67),
        },
        encryptedMembershipMetadataDigest: digest(17),
        discoveryRecordDigest: digest(68),
        signerPrincipalId: 'principal-a',
        signerDeviceId: 'device-a',
        writerSignature: signature(68),
        createdAt: preparedAt,
        updatedAt: preparedAt,
      },
    ],
    currentMutationLink,
    createdAt: preparedAt,
    updatedAt: activatedAt,
  });
}

function proofEntryFor(candidate = collaborativeCandidate()) {
  const link = candidate.currentMutationLink;
  const commitment = link.commitment;
  return collaborationMutationProofEntrySchema.parse({
    link,
    authorizationWitness: {
      format: COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT,
      protocolVersion: candidate.protocolVersion,
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      authorityDelegationDigest: link.authorityDelegationDigest,
      tuple: {
        authorityEpoch: candidate.authorityEpoch,
        documentRevision: candidate.documentRevision,
        membershipRevision: candidate.membershipRevision,
        policyRevision: candidate.policyRevision,
        keyEpoch: candidate.keyEpoch,
        databaseDeviceGeneration: candidate.databaseDeviceGeneration,
        databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
        authorizationStateDigest: candidate.authorizationStateDigest,
      },
      previousHeadDigest: candidate.previousHeadDigest,
      headDigest: candidate.headDigest,
      encryptedMembershipDigest: commitment.encryptedMembershipDigest,
      encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
      policyDigest: commitment.policyDigest,
      databaseDeviceRegistry: registryCandidate(),
      databaseAuthorityRecoveryEnvelope: candidate.databaseAuthorityRecoveryEnvelope,
      encryptedMembershipManifest: candidate.encryptedMembershipManifest,
      discoveryRecords: [],
      finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(link),
    },
  });
}

function committedOutcome(candidate = collaborativeCandidate()) {
  const priorTuple = {
    authorityEpoch: 1,
    documentRevision: 0,
    membershipRevision: 0,
    policyRevision: 0,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    authorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  } as const;
  const committedTuple = {
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    authorizationStateDigest: digest(12),
  } as const;
  const receipt = collaborationMutationReceiptSchema.parse({
    format: 'kavrix-collaborative-mutation-receipt',
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId: 'operation-genesis',
    operationType: 'genesis-migration',
    requestDigest,
    actorPrincipalId: 'principal-a',
    actorDeviceId: 'device-a',
    priorTuple,
    priorHeadDigest,
    committedTuple,
    committedHeadDigest: candidate.headDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
      candidate.currentMutationLink,
    ),
    outcomeDigest: digest(26),
    committedAt: activatedAt,
    receiptSignature: signature(26),
  });
  return durableOperationOutcomeSchema.parse({
    format: 'kavrix-collaborative-operation-outcome',
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId: 'operation-genesis',
    operationType: 'genesis-migration',
    requestDigest,
    actorPrincipalId: 'principal-a',
    actorDeviceId: 'device-a',
    priorTuple,
    priorHeadDigest,
    state: 'committed',
    committedTuple,
    committedHeadDigest: candidate.headDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
      candidate.currentMutationLink,
    ),
    committedAt: activatedAt,
    outcomeDigest: digest(26),
    signedMutationReceipt: receipt,
    createdAt: preparedAt,
    resolvedAt: activatedAt,
    detailsRetainedUntil: retainedUntil,
  });
}

function initialAnchor(
  candidate = collaborativeCandidate(),
  overrides: Record<string, unknown> = {},
) {
  return recipientRollbackAnchorSchema.parse({
    format: 'kavrix-collaborative-recipient-rollback-anchor',
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    principalId: 'principal-a',
    deviceId: 'device-a',
    authorityEpoch: 1,
    authorityDelegationDigest: digest(69),
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    membershipRevision: 1,
    membershipDigest: digest(31),
    policyRevision: 1,
    policyDigest: digest(19),
    keyEpoch: 1,
    documentRevision: 1,
    encryptedPayloadDigest: digest(16),
    headDigest: candidate.headDigest,
    authorizationStateDigest: candidate.authorizationStateDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
      candidate.currentMutationLink,
    ),
    updatedAt: activatedAt,
    ...overrides,
  });
}

function preparedInput(): CollaborationMigrationJournalCreateInput {
  const request = migrationRequest();
  const registry = registryCandidate();
  const candidate = collaborativeCandidate();
  const outcome = committedOutcome(candidate);
  const preparedMarker = collaborationMigrationPreparedMarkerSchema.parse({
    format: 'kavrix-collaborative-migration-marker',
    markerVersion: 1,
    protocolVersion: 1,
    state: 'prepared',
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId: request.operationId,
    requestDigest: request.requestDigest,
    legacySourceDigest,
    authorityEpoch: 1,
    authorityFingerprint: digest(3),
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    candidateHeadDigest: candidate.headDigest,
    preparedAt,
    authoritySignature: signature(27),
    legacySource: legacySource(),
    registryCandidate: registry,
  });
  const activeMarker = collaborationMigrationActiveMarkerSchema.parse({
    format: 'kavrix-collaborative-migration-marker',
    markerVersion: 1,
    protocolVersion: 1,
    state: 'active',
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId: request.operationId,
    requestDigest: request.requestDigest,
    legacySourceDigest,
    authorityEpoch: 1,
    authorityFingerprint: digest(3),
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    candidateHeadDigest: candidate.headDigest,
    preparedAt,
    authoritySignature: signature(28),
    outcomeDigest: outcome.outcomeDigest,
    activatedAt,
  });
  return collaborationMigrationJournalCreateInputSchema.parse({
    request,
    registryCandidate: registry,
    preparedMarker,
    activeMarker,
    collaborativeCandidate: candidate,
    proofEntry: proofEntryFor(candidate),
    proposedOutcome: outcome,
    initialRecipientAnchor: initialAnchor(candidate),
    initialOwnerIdentity: initialOwnerIdentity(),
    restartRecipient: {
      principalId: 'principal-a',
      deviceId: 'device-a',
    },
  });
}

function incompatibleOutcome(): DurableOperationOutcome {
  const proposed = committedOutcome();
  return durableOperationOutcomeSchema.parse({
    format: proposed.format,
    protocolVersion: proposed.protocolVersion,
    databaseId: proposed.databaseId,
    vaultId: proposed.vaultId,
    operationId: proposed.operationId,
    operationType: proposed.operationType,
    requestDigest: proposed.requestDigest,
    actorPrincipalId: proposed.actorPrincipalId,
    actorDeviceId: proposed.actorDeviceId,
    priorTuple: proposed.priorTuple,
    priorHeadDigest: proposed.priorHeadDigest,
    state: 'conflicted',
    outcomeDigest: digest(61),
    createdAt: proposed.createdAt,
    resolvedAt: proposed.resolvedAt,
    detailsRetainedUntil: proposed.detailsRetainedUntil,
  });
}

let directory = '';
beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-migration-journal-'));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

function file(name = 'vault.cvkx'): string {
  return collaborationMigrationJournalPath(
    join(directory, name),
    scope.databaseId,
    scope.vaultId,
    scope.operationId,
  );
}

function anchorFile(name = 'recipient-anchor.cvkx'): string {
  return join(directory, name);
}

function authorityAnchorFile(name = 'authority-anchor.cvkx'): string {
  return join(directory, name);
}

const anchorScope = {
  databaseId: scope.databaseId,
  vaultId: scope.vaultId,
  principalId: scope.principalId,
  deviceId: scope.deviceId,
};

const authorityScope = {
  databaseId: scope.databaseId,
  vaultId: scope.vaultId,
  authorityEpoch: 1,
  authorityDelegationDigest: digest(69),
};

function authorityAnchor(input: CollaborationMigrationJournalCreateInput) {
  return collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
    input.collaborativeCandidate,
    {
      membershipDigest: input.initialRecipientAnchor.membershipDigest,
      policyDigest: input.initialRecipientAnchor.policyDigest,
    },
  );
}

describe('protected collaboration migration journal', () => {
  it('creates and reads the exact prepared bundle without secret or plaintext canaries', async () => {
    const secret = new Uint8Array(32).fill(71);
    const input = preparedInput();
    try {
      await createCollaborationMigrationJournal(file(), secret, input);
      const record = await readCollaborationMigrationJournal(file(), secret, {
        expectedScope: scope,
      });
      expect(record).toMatchObject({ state: 'prepared', ...input });
      const serialized = await readFile(file(), 'utf8');
      expect(serialized).not.toContain('plaintext-credential-canary');
      expect(serialized).not.toContain('private-identity-key-canary');
      expect(serialized).not.toContain('portable-key-canary');
      expect(serialized).not.toContain('passphrase-canary');
      expect(serialized).not.toContain(encodeBase64Url(secret));
    } finally {
      zeroize(secret);
    }
  });

  it('accepts an exact create replay and rejects every changed immutable component', async () => {
    const secret = new Uint8Array(32).fill(72);
    const input = preparedInput();
    try {
      await createCollaborationMigrationJournal(file(), secret, input);
      await expect(
        createCollaborationMigrationJournal(file(), secret, input),
      ).resolves.toBeUndefined();

      const mutations: Array<(value: Record<string, any>) => void> = [
        (value) => {
          value.request.ownerSignature = signature(40);
        },
        (value) => {
          value.registryCandidate.authoritySignature = signature(41);
          value.preparedMarker.registryCandidate.authoritySignature = signature(41);
        },
        (value) => {
          value.preparedMarker.authoritySignature = signature(42);
        },
        (value) => {
          value.activeMarker.authoritySignature = signature(43);
        },
        (value) => {
          value.collaborativeCandidate.currentMutationLink.writerSignature.signature =
            signature(44);
        },
        (value) => {
          value.proofEntry.link.writerSignature.signature = signature(45);
        },
        (value) => {
          value.proofEntry.authorizationWitness.finalizedMutationLinkDigest =
            digest(46);
        },
        (value) => {
          value.proposedOutcome.signedMutationReceipt.receiptSignature = signature(47);
        },
        (value) => {
          value.initialRecipientAnchor.membershipDigest = digest(48);
        },
        (value) => {
          value.initialRecipientAnchor.authorityDelegationDigest = digest(49);
        },
        (value) => {
          value.initialRecipientAnchor.authorizationStateDigest = digest(50);
        },
        (value) => {
          value.initialRecipientAnchor.finalizedMutationLinkDigest = digest(51);
        },
        (value) => {
          value.request.legacySourceDigest = digest(52);
        },
        (value) => {
          value.request.requestDigest = digest(53);
        },
        (value) => {
          value.initialOwnerIdentity.selfSignature = signature(54);
        },
        (value) => {
          value.restartRecipient.deviceId = 'substituted-device';
        },
      ];
      for (const mutate of mutations) {
        const changed = structuredClone(input) as unknown as Record<string, any>;
        mutate(changed);
        let parsed: CollaborationMigrationJournalCreateInput;
        try {
          parsed = collaborationMigrationJournalCreateInputSchema.parse(changed);
        } catch {
          continue;
        }
        await expect(
          createCollaborationMigrationJournal(file(), secret, parsed),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      }
    } finally {
      zeroize(secret);
    }
  });

  it('rejects proof omission and stale canonical source/request digests before write', async () => {
    const secret = new Uint8Array(32).fill(75);
    const input = preparedInput();
    try {
      const proofOmitted = structuredClone(input) as Record<string, any>;
      delete proofOmitted.proofEntry;
      await expect(
        createCollaborationMigrationJournal(
          file('proof-omitted.cvkx'),
          secret,
          proofOmitted as never,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const witnessOmitted = structuredClone(input) as Record<string, any>;
      delete witnessOmitted.proofEntry.authorizationWitness;
      await expect(
        createCollaborationMigrationJournal(
          file('witness-omitted.cvkx'),
          secret,
          witnessOmitted as never,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const identityOmitted = structuredClone(input) as Record<string, any>;
      delete identityOmitted.initialOwnerIdentity;
      await expect(
        createCollaborationMigrationJournal(
          file('identity-omitted.cvkx'),
          secret,
          identityOmitted as never,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const selectorOmitted = structuredClone(input) as Record<string, any>;
      delete selectorOmitted.restartRecipient;
      await expect(
        createCollaborationMigrationJournal(
          file('selector-omitted.cvkx'),
          secret,
          selectorOmitted as never,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const sourceDigestStale = structuredClone(input) as Record<string, any>;
      sourceDigestStale.request.legacySourceDigest = digest(76);
      await expect(
        createCollaborationMigrationJournal(
          file('source-digest-mismatch.cvkx'),
          secret,
          sourceDigestStale as never,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const requestDigestStale = structuredClone(input) as Record<string, any>;
      requestDigestStale.request.requestDigest = digest(77);
      await expect(
        createCollaborationMigrationJournal(
          file('request-digest-mismatch.cvkx'),
          secret,
          requestDigestStale as never,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
    }
  });

  it('rejects wrong secret, complete-scope mismatch, tampering, and malformed bytes', async () => {
    const secret = new Uint8Array(32).fill(73);
    const wrongSecret = new Uint8Array(32).fill(74);
    try {
      await createCollaborationMigrationJournal(file(), secret, preparedInput());
      await expect(
        readCollaborationMigrationJournal(file(), wrongSecret, {
          expectedScope: scope,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readCollaborationMigrationJournal(file(), secret, {
          expectedScope: {
            ...scope,
            requestDigest: digest(75) as typeof scope.requestDigest,
          },
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const tampered = JSON.parse(await readFile(file(), 'utf8')) as Record<
        string,
        any
      >;
      tampered.initialRecipientAnchor.membershipDigest = digest(76);
      await writeFile(file(), JSON.stringify(tampered), { mode: 0o600 });
      await expect(
        readCollaborationMigrationJournal(file(), secret, { expectedScope: scope }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      await writeFile(file(), '{"state":"prepared"}', { mode: 0o600 });
      await expect(
        readCollaborationMigrationJournal(file(), secret, { expectedScope: scope }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
      zeroize(wrongSecret);
    }
  });

  it('resumes every valid crash boundary with monotonic same-state replay', async () => {
    const secret = new Uint8Array(32).fill(77);
    const databaseRootKey = new Uint8Array(32).fill(177);
    const input = preparedInput();
    try {
      await createCollaborationMigrationJournal(file(), secret, input);
      await expect(
        reconcileCollaborationMigrationPublication(
          file(),
          secret,
          input.proposedOutcome,
        ),
      ).resolves.toBe('published');
      await expect(
        reconcileCollaborationMigrationPublication(
          file(),
          secret,
          input.proposedOutcome,
        ),
      ).resolves.toBe('published');
      expect(
        (
          await readCollaborationMigrationJournal(file(), secret, {
            expectedScope: scope,
          })
        )?.state,
      ).toBe('published');

      await createRecipientRollbackAnchor(
        anchorFile(),
        secret,
        input.initialRecipientAnchor,
      );
      await createCollaborationAuthorityRollbackAnchor(
        authorityAnchorFile(),
        databaseRootKey,
        authorityAnchor(input),
      );
      await markCollaborationMigrationAnchored(
        file(),
        secret,
        anchorFile(),
        anchorScope,
        authorityAnchorFile(),
        databaseRootKey,
        authorityScope,
      );
      await markCollaborationMigrationAnchored(
        file(),
        secret,
        anchorFile(),
        anchorScope,
        authorityAnchorFile(),
        databaseRootKey,
        authorityScope,
      );
      expect(
        (
          await readCollaborationMigrationJournal(file(), secret, {
            expectedScope: scope,
          })
        )?.state,
      ).toBe('anchored');

      await markCollaborationMigrationActive(file(), secret, input.activeMarker);
      await markCollaborationMigrationActive(file(), secret, input.activeMarker);
      expect(
        (
          await readCollaborationMigrationJournal(file(), secret, {
            expectedScope: scope,
          })
        )?.state,
      ).toBe('active');
    } finally {
      zeroize(secret);
      zeroize(databaseRootKey);
    }
  });

  it('rejects skipped and backward transitions and changed same-state evidence', async () => {
    const secret = new Uint8Array(32).fill(78);
    const databaseRootKey = new Uint8Array(32).fill(178);
    const input = preparedInput();
    try {
      await createCollaborationMigrationJournal(file(), secret, input);
      await expect(
        markCollaborationMigrationAnchored(
          file(),
          secret,
          anchorFile('missing-anchor.cvkx'),
          anchorScope,
          authorityAnchorFile('missing-authority-anchor.cvkx'),
          databaseRootKey,
          authorityScope,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        markCollaborationMigrationActive(file(), secret, input.activeMarker),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      await reconcileCollaborationMigrationPublication(
        file(),
        secret,
        input.proposedOutcome,
      );
      await expect(
        markCollaborationMigrationActive(file(), secret, input.activeMarker),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await createRecipientRollbackAnchor(
        anchorFile(),
        secret,
        input.initialRecipientAnchor,
      );
      await createRecipientRollbackAnchor(
        anchorFile('mismatched-anchor.cvkx'),
        secret,
        initialAnchor(collaborativeCandidate(), { membershipDigest: digest(79) }),
      );
      await createCollaborationAuthorityRollbackAnchor(
        authorityAnchorFile(),
        databaseRootKey,
        authorityAnchor(input),
      );
      await createCollaborationAuthorityRollbackAnchor(
        authorityAnchorFile('mismatched-authority-anchor.cvkx'),
        databaseRootKey,
        {
          ...authorityAnchor(input),
          membershipDigest: digest(80),
        },
      );
      await markCollaborationMigrationAnchored(
        file(),
        secret,
        anchorFile(),
        anchorScope,
        authorityAnchorFile(),
        databaseRootKey,
        authorityScope,
      );
      await expect(
        reconcileCollaborationMigrationPublication(
          file(),
          secret,
          input.proposedOutcome,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        markCollaborationMigrationAnchored(
          file(),
          secret,
          anchorFile('mismatched-anchor.cvkx'),
          anchorScope,
          authorityAnchorFile(),
          databaseRootKey,
          authorityScope,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        markCollaborationMigrationAnchored(
          file(),
          secret,
          anchorFile(),
          anchorScope,
          authorityAnchorFile('mismatched-authority-anchor.cvkx'),
          databaseRootKey,
          authorityScope,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await markCollaborationMigrationActive(file(), secret, input.activeMarker);
      await expect(
        markCollaborationMigrationAnchored(
          file(),
          secret,
          anchorFile(),
          anchorScope,
          authorityAnchorFile(),
          databaseRootKey,
          authorityScope,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
      zeroize(databaseRootKey);
    }
  });

  it('preserves the prepared bundle for unsigned incompatible outcomes', async () => {
    const secret = new Uint8Array(32).fill(80);
    const incompatible = incompatibleOutcome();
    try {
      await createCollaborationMigrationJournal(file(), secret, preparedInput());
      await expect(
        reconcileCollaborationMigrationPublication(file(), secret, incompatible),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        reconcileCollaborationMigrationPublication(file(), secret, incompatible),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      const record = await readCollaborationMigrationJournal(file(), secret, {
        expectedScope: scope,
      });
      expect(record).toMatchObject({
        state: 'prepared',
      });
    } finally {
      zeroize(secret);
    }
  });

  it('rejects an oversized collaborative candidate before publication', async () => {
    const secret = new Uint8Array(32).fill(81);
    const oversized = structuredClone(preparedInput()) as unknown as Record<
      string,
      any
    >;
    oversized.collaborativeCandidate.encryptedPayload.ciphertext = Buffer.alloc(
      8 * 1024 * 1024 + 1,
      82,
    ).toString('base64url');
    try {
      await expect(
        createCollaborationMigrationJournal(
          file(),
          secret,
          oversized as unknown as CollaborationMigrationJournalCreateInput,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
    }
  });

  it.runIf(process.platform !== 'win32')(
    'rejects a journal whose permissions become unsafe',
    async () => {
      const secret = new Uint8Array(32).fill(83);
      try {
        await createCollaborationMigrationJournal(file(), secret, preparedInput());
        await chmod(file(), 0o644);
        await expect(
          readCollaborationMigrationJournal(file(), secret, {
            expectedScope: scope,
          }),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      } finally {
        zeroize(secret);
      }
    },
  );
});
