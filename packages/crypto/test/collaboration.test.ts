import { describe, expect, it } from 'vitest';

import {
  AuthenticationError,
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
  COLLABORATION_DOMAINS,
  CryptoInputError,
  computeAadMetadataDigest,
  computeAdministrativeActionParametersDigest,
  computeAuthorityDelegationDigest,
  computeAuthorizationCheckpointDigest,
  computeAuthorizationStateDigest,
  computeAuthorizationTransitionDigest,
  computeCollaborativeVaultDestroyedPayloadDigest,
  computeCollaborativeVaultDestructionActionDigest,
  computeEncryptedPayloadDigest,
  computeDiscoveryTag,
  computeDiscoveryRecordDigest,
  computeFinalizedMutationLinkDigest,
  computeLegacySourceDigest,
  computeMigrationRequestDigest,
  computeMembershipHistoryCompactionDigest,
  computeMembershipStateDigest,
  computeMutationHead,
  computeMutationRequestDigest,
  computeOperationOutcomeDigest,
  computeOperationTombstoneDigest,
  computePolicyStateDigest,
  computePublicKeyFingerprint,
  computeTransferIntentDigest,
  decryptCollaborationEnvelope,
  deriveDatabaseAuthorityRecoveryKeyPair,
  deriveDatabaseAuthoritySigningKeyPair,
  digestCanonicalCollaborationValue,
  encodeCollaborationPublicKey,
  encryptCollaborationEnvelope,
  generateDeviceEncryptionKeyPair,
  generateDeviceKeyPairs,
  generateDeviceSigningKeyPair,
  generatePrincipalSigningKeyPair,
  openCollaborationVaultRootForDatabaseAuthority,
  openVaultRootKeyForDevice,
  sealCollaborationVaultRootForDatabaseAuthority,
  sealVaultRootKeyForDevice,
  signApprovalEvidence,
  signAuthorityDelegation,
  signAuthorizationCheckpoint,
  signAuthorizationTransitionAuthority,
  signAuthorizationTransitionOwner,
  signEnrollmentReceipt,
  signDiscoveryRecord,
  signFinalizedMutationLink,
  signMigrationActiveMarker,
  signMigrationPreparedMarker,
  signMigrationRequestAuthority,
  signMigrationRequestOwner,
  signMutationCommitment,
  signMutationReceipt,
  signOwnershipTransferAcceptance,
  signTransferIntent,
  verifyApprovalEvidence,
  verifyAuthorityDelegation,
  verifyAuthorizationCheckpoint,
  verifyAuthorizationTransitionAuthority,
  verifyAuthorizationTransitionOwner,
  verifyCanonicalCollaborationValue,
  verifyCollaborationRecord,
  verifyCommittedOperationOutcome,
  verifyEnrollmentReceipt,
  verifyDiscoveryRecord,
  verifyFinalizedMutationLink,
  verifyMigrationActiveMarker,
  verifyMigrationPreparedMarker,
  verifyMigrationRequestAuthority,
  verifyMigrationRequestOwner,
  verifyMutationCommitment,
  verifyMutationReceipt,
  verifyOperationTombstone,
  verifyOwnershipTransferAcceptance,
  verifyTransferIntent,
} from '../src/index.js';
import {
  approvalEvidenceSchema,
  collaborationAadSchema,
  collaborationAuthorizationCheckpointSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationTransitionSchema,
  collaborationAuthorityDelegationSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationMigrationActiveMarkerSchema,
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationRequestSchema,
  collaborationKeyEnvelopeSchema,
  collaborationMutationCommitmentSchema,
  collaborationMutationReceiptSchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborationVaultDestructionCoreSchema,
  collaborationVaultDestructionActionSchema,
  databaseVaultDocumentSchema,
  durableOperationOutcomeSchema,
  enrollmentReceiptSchema,
  membershipHistoryCompactionInputSchema,
  operationDeduplicationTombstoneSchema,
  ownershipTransferAcceptanceSchema,
  transferIntentSchema,
  type CollaborationMutationCommitment,
} from '@kavrix/schemas';

type CollaborationAad = ReturnType<typeof collaborationAadSchema.parse>;

const bytes = (value: number, length = 32): string =>
  Buffer.alloc(length, value).toString('base64url');

const baseCommitment = (): CollaborationMutationCommitment =>
  collaborationMutationCommitmentSchema.parse({
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId: 'operation-a',
    operationType: 'ordinary-write',
    requestDigest: bytes(1),
    previousHeadDigest: bytes(2),
    previousAuthorizationStateDigest: bytes(24),
    authorizationStateDigest: bytes(24),
    previousAuthorityEpoch: 1,
    previousDocumentRevision: 0,
    previousMembershipRevision: 0,
    previousPolicyRevision: 0,
    previousKeyEpoch: 1,
    previousDatabaseDeviceGeneration: 1,
    previousDatabaseDeviceRegistryDigest: bytes(3),
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 0,
    policyRevision: 0,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: bytes(3),
    encryptedPayloadDigest: bytes(4),
    encryptedMembershipDigest: bytes(5),
    encryptedEnvelopesDigest: bytes(6),
    policyDigest: bytes(7),
    writerPrincipalId: 'principal-a',
    writerDeviceId: 'device-a',
    timestamp: '2026-08-29T00:00:00.000Z',
  });

const baseAadMetadata = (): Record<string, unknown> => ({
  protocolVersion: 1,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  authorityEpoch: 1,
  entityType: 'vault-payload',
  entityId: 'vault-a',
  documentRevision: 1,
  membershipRevision: 0,
  policyRevision: 0,
  keyEpoch: 1,
  databaseDeviceGeneration: 1,
  databaseDeviceRegistryDigest: bytes(3),
  authorizationStateDigest: bytes(24),
});

const baseAad = (): CollaborationAad =>
  collaborationAadSchema.parse({
    ...baseAadMetadata(),
    metadataDigest: computeAadMetadataDigest(baseAadMetadata()),
  });

const historyCompactionInput = (): ReturnType<
  typeof membershipHistoryCompactionInputSchema.parse
> => {
  const registryDigest = bytes(91);
  return membershipHistoryCompactionInputSchema.parse({
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    authorityEpoch: 1,
    compactingOperationId: 'operation-compact-a',
    previousHeadDigest: bytes(92),
    previousTuple: {
      authorityEpoch: 1,
      documentRevision: 7,
      membershipRevision: 4,
      policyRevision: 3,
      keyEpoch: 3,
      databaseDeviceGeneration: 2,
      databaseDeviceRegistryDigest: registryDigest,
      authorizationStateDigest: bytes(93),
    },
    priorHistory: {
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityEpoch: 1,
      databaseDeviceGeneration: 2,
      databaseDeviceRegistryDigest: registryDigest,
      events: [
        {
          protocolVersion: 1,
          operationId: 'operation-device-added',
          eventType: 'device-added',
          actorPrincipalId: 'principal-owner',
          actorDeviceId: 'device-owner',
          targetPrincipalId: 'principal-member',
          targetDeviceId: 'device-member-2',
          previousDocumentRevision: 5,
          newDocumentRevision: 6,
          previousMembershipRevision: 3,
          newMembershipRevision: 4,
          previousPolicyRevision: 2,
          newPolicyRevision: 2,
          previousKeyEpoch: 2,
          newKeyEpoch: 3,
          previousAuthorityEpoch: 1,
          newAuthorityEpoch: 1,
          previousDatabaseDeviceGeneration: 2,
          newDatabaseDeviceGeneration: 2,
          previousDatabaseDeviceRegistryDigest: registryDigest,
          newDatabaseDeviceRegistryDigest: registryDigest,
          previousAuthorizationStateDigest: bytes(94),
          newAuthorizationStateDigest: bytes(95),
          previousHeadDigest: bytes(96),
          timestamp: '2026-08-29T00:00:00.000Z',
          signature: bytes(97, 64),
        },
        {
          protocolVersion: 1,
          operationId: 'operation-policy-changed',
          eventType: 'policy-changed',
          actorPrincipalId: 'principal-owner',
          actorDeviceId: 'device-owner',
          previousDocumentRevision: 6,
          newDocumentRevision: 7,
          previousMembershipRevision: 4,
          newMembershipRevision: 4,
          previousPolicyRevision: 2,
          newPolicyRevision: 3,
          previousKeyEpoch: 3,
          newKeyEpoch: 3,
          previousAuthorityEpoch: 1,
          newAuthorityEpoch: 1,
          previousDatabaseDeviceGeneration: 2,
          newDatabaseDeviceGeneration: 2,
          previousDatabaseDeviceRegistryDigest: registryDigest,
          newDatabaseDeviceRegistryDigest: registryDigest,
          previousAuthorizationStateDigest: bytes(95),
          newAuthorizationStateDigest: bytes(98),
          previousHeadDigest: bytes(99),
          timestamp: '2026-08-30T00:00:00.000Z',
          signature: bytes(100, 64),
        },
      ],
      checkpoints: [
        {
          protocolVersion: 1,
          checkpointId: 'history-checkpoint-prior',
          authorityEpoch: 1,
          databaseDeviceGeneration: 2,
          databaseDeviceRegistryDigest: registryDigest,
          membershipRevision: 3,
          documentRevision: 5,
          policyRevision: 2,
          keyEpoch: 2,
          previousHeadDigest: bytes(101),
          compactedThroughRevision: 3,
          compactedHistoryDigest: bytes(102),
          signerPrincipalId: 'principal-member',
          signerDeviceId: 'device-member',
          createdAt: '2026-08-28T00:00:00.000Z',
          signature: bytes(103, 64),
        },
      ],
      compactedThroughRevision: 3,
      compactedHistoryDigest: bytes(102),
      previousHeadDigest: bytes(104),
      previousHistoryDigest: bytes(105),
      currentHistoryDigest: bytes(106),
    },
  });
};

const vaultDestructionCore = (): ReturnType<
  typeof collaborationVaultDestructionCoreSchema.parse
> =>
  collaborationVaultDestructionCoreSchema.parse({
    format: 'kavrix-collaborative-vault-destruction-core',
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId: 'operation-destroy-a',
    authorityEpoch: 1,
    authorityDelegationDigest: bytes(113),
    priorTuple: {
      authorityEpoch: 1,
      documentRevision: 7,
      membershipRevision: 4,
      policyRevision: 3,
      keyEpoch: 3,
      databaseDeviceGeneration: 2,
      databaseDeviceRegistryDigest: bytes(114),
      authorizationStateDigest: bytes(115),
    },
    priorHeadDigest: bytes(116),
    terminalTuple: {
      authorityEpoch: 1,
      documentRevision: 8,
      membershipRevision: 4,
      policyRevision: 3,
      keyEpoch: 3,
      databaseDeviceGeneration: 2,
      databaseDeviceRegistryDigest: bytes(114),
      authorizationStateDigest: bytes(115),
    },
    actionParametersDigest: bytes(117),
    actorPrincipalId: 'principal-owner',
    actorDeviceId: 'device-owner',
    destructionMode: 'irreversible',
    destroyedAt: '2026-08-29T01:00:00.000Z',
  });

function mutateBase64(value: string): string {
  const replacement = value.startsWith('A') ? 'B' : 'A';
  return `${replacement}${value.slice(1)}`;
}

const baseTransferIntent = (): Record<string, unknown> => ({
  format: 'kavrix-collaborative-transfer-intent',
  protocolVersion: 1,
  transferIntentId: 'transfer-a',
  operationId: 'operation-transfer-a',
  databaseId: 'database-a',
  vaultId: 'vault-a',
  initiatorPrincipalId: 'principal-a',
  initiatorDeviceId: 'device-a',
  recipientPrincipalId: 'principal-b',
  recipientDeviceId: 'device-b',
  targetRole: 'owner',
  originalOwnerDisposition: 'remain-owner',
  authorityEpoch: 1,
  databaseDeviceGeneration: 1,
  databaseDeviceRegistryDigest: bytes(3),
  documentRevision: 1,
  membershipRevision: 1,
  policyRevision: 1,
  keyEpoch: 1,
  currentHeadDigest: bytes(4),
  authorizationStateDigest: bytes(24),
  intentDigest: bytes(0),
  state: 'intent-created',
  createdAt: '2026-08-29T00:00:00.000Z',
  expiresAt: '2026-09-01T00:00:00.000Z',
});

const baseApprovalEvidence = (requestDigest: string): Record<string, unknown> => ({
  protocolVersion: 1,
  approvalRequestId: 'approval-a',
  operationId: 'operation-transfer-a',
  databaseId: 'database-a',
  vaultId: 'vault-a',
  requestDigest,
  authorityEpoch: 1,
  databaseDeviceGeneration: 1,
  databaseDeviceRegistryDigest: bytes(3),
  documentRevision: 1,
  membershipRevision: 1,
  policyRevision: 1,
  keyEpoch: 1,
  priorHeadDigest: bytes(4),
  authorizationStateDigest: bytes(24),
  requestingPrincipalId: 'principal-a',
  approverPrincipalId: 'principal-b',
  approverDeviceId: 'device-b',
  approvedAt: '2026-08-30T00:00:00.000Z',
  signature: bytes(8, 64),
});

const baseLegacyVaultDocument = (): Record<string, unknown> => ({
  databaseId: 'database-a',
  id: 'vault-a',
  schemaVersion: 1,
  cryptographicVersion: 1,
  currentKeyVersion: 1,
  databaseRevision: 1,
  revision: 1,
  wrappedVaultRoot: {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: bytes(53, 24),
    ciphertext: bytes(54, 64),
    authenticationTag: bytes(55, 16),
    aad: {
      version: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      entityType: 'wrapped-vault-root',
      entityId: 'vault-a',
      purpose: 'vault-root',
      schemaVersion: 1,
      keyVersion: 1,
      revision: 1,
      metadataDigest: bytes(56),
    },
    keyVersion: 1,
  },
  encryptedPayload: {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: bytes(57, 24),
    ciphertext: bytes(58, 64),
    authenticationTag: bytes(59, 16),
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: 'vault-a',
      entityType: 'vault-preferences',
      entityId: 'vault-a',
      purpose: 'vault-preferences',
      revision: 1,
      metadataDigest: bytes(60),
    },
    keyVersion: 1,
  },
  payloadMetadataDigest: bytes(60),
  createdAt: '2026-08-29T00:00:00.000Z',
  updatedAt: '2026-08-30T00:00:00.000Z',
});

const baseMigrationRequest = (): Record<string, unknown> => ({
  format: 'kavrix-collaborative-migration-request',
  protocolVersion: 1,
  operationType: 'genesis-migration',
  operationId: 'operation-genesis',
  databaseId: 'database-a',
  vaultId: 'vault-a',
  legacyVaultRevision: 1,
  legacySourceDigest: bytes(61),
  authorityEpoch: 1,
  authorityFingerprint: bytes(62),
  databaseDeviceGeneration: 1,
  databaseDeviceRegistryDigest: bytes(63),
  initialOwnerPrincipalId: 'principal-a',
  initialOwnerDeviceId: 'device-a',
  initialMembershipId: 'membership-a',
  requestedAt: '2026-08-30T00:00:00.000Z',
  requestDigest: bytes(0),
  authoritySignature: bytes(0, 64),
  ownerSignature: bytes(0, 64),
});

const baseRegistryCandidate = (): Record<string, unknown> => ({
  format: 'kavrix-collaborative-device-registry',
  protocolVersion: 1,
  databaseId: 'database-a',
  authorityEpoch: 1,
  authorityFingerprint: bytes(62),
  generation: 1,
  previousRegistryDigest: bytes(64),
  registryDigest: bytes(63),
  deniedDevices: [],
  updatedAt: '2026-08-30T00:00:00.000Z',
  authoritySignature: bytes(1, 64),
});

const baseMigrationMarker = (
  request: Record<string, unknown>,
  legacySourceDigest: string,
): Record<string, unknown> => ({
  format: 'kavrix-collaborative-migration-marker',
  markerVersion: 1,
  protocolVersion: 1,
  databaseId: request['databaseId'],
  vaultId: request['vaultId'],
  operationId: request['operationId'],
  requestDigest: request['requestDigest'],
  legacySourceDigest,
  authorityEpoch: request['authorityEpoch'],
  authorityFingerprint: request['authorityFingerprint'],
  databaseDeviceGeneration: request['databaseDeviceGeneration'],
  databaseDeviceRegistryDigest: request['databaseDeviceRegistryDigest'],
  candidateHeadDigest: bytes(65),
  preparedAt: '2026-08-30T00:00:00.000Z',
  authoritySignature: bytes(0, 64),
});

const authorizationState = (): ReturnType<
  typeof collaborationAuthorizationStateCoreSchema.parse
> =>
  collaborationAuthorizationStateCoreSchema.parse({
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: bytes(3),
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    memberships: [
      {
        membershipId: 'membership-a',
        principalId: 'principal-a',
        principalFingerprint: bytes(25),
        rootSigningPublicKey: bytes(26),
        identityGeneration: 1,
        role: 'owner',
        state: 'active',
        devices: [
          {
            protocolVersion: 1,
            principalId: 'principal-a',
            deviceId: 'device-a',
            deviceGeneration: 1,
            signingPublicKey: bytes(27),
            encryptionPublicKey: bytes(28),
            state: 'active',
            createdAt: '2026-08-29T00:00:00.000Z',
            stateChangedAt: '2026-08-29T00:00:00.000Z',
          },
        ],
        createdAt: '2026-08-29T00:00:00.000Z',
        updatedAt: '2026-08-30T00:00:00.000Z',
      },
    ],
    ownerPrincipalIds: ['principal-a'],
    keyEnvelopes: [
      {
        format: 'kavrix-collaborative-member-key-envelope',
        protocolVersion: 1,
        algorithm: 'x25519-sealed-box',
        databaseId: 'database-a',
        vaultId: 'vault-a',
        authorityEpoch: 1,
        membershipId: 'membership-a',
        principalId: 'principal-a',
        deviceId: 'device-a',
        recipientEncryptionKeyFingerprint: bytes(29),
        keyEpoch: 1,
        membershipRevision: 1,
        databaseDeviceGeneration: 1,
        databaseDeviceRegistryDigest: bytes(3),
        sealedVaultRootKey: bytes(30, 80),
      },
      {
        format: 'kavrix-collaborative-authority-recovery-envelope',
        protocolVersion: 1,
        algorithm: 'x25519-sealed-box',
        databaseId: 'database-a',
        vaultId: 'vault-a',
        authorityEpoch: 1,
        authorityRecoveryKeyFingerprint: bytes(31),
        keyEpoch: 1,
        membershipRevision: 1,
        databaseDeviceGeneration: 1,
        databaseDeviceRegistryDigest: bytes(3),
        sealedVaultRootKey: bytes(32, 80),
        sealedByPrincipalId: 'principal-a',
        sealedByDeviceId: 'device-a',
      },
    ],
    approvalPolicy: 'none',
  });

const tuple = (
  documentRevision: number,
  membershipRevision: number,
  policyRevision: number,
  authorizationStateDigest: string,
): ReturnType<typeof collaborationRevisionTupleSchema.parse> =>
  collaborationRevisionTupleSchema.parse({
    authorityEpoch: 1,
    documentRevision,
    membershipRevision,
    policyRevision,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: bytes(3),
    authorizationStateDigest,
  });

describe('collaboration crypto foundation', () => {
  it('domain-separates and commits every exact vault-destruction action field', () => {
    const action = collaborationVaultDestructionActionSchema.parse({
      protocolVersion: 1,
      operationType: 'destroy-vault',
      databaseId: 'database-a',
      vaultId: 'vault-a',
      destructionMode: 'irreversible',
    });
    const digest = computeCollaborativeVaultDestructionActionDigest(action);

    expect(COLLABORATION_DOMAINS.collaborativeVaultDestructionActionDigest).toBe(
      'kavrix/collaboration/vault-destruction-action-digest/v1',
    );
    expect(
      computeCollaborativeVaultDestructionActionDigest(
        Object.fromEntries(Object.entries(action).reverse()),
      ),
    ).toBe(digest);
    expect(
      digestCanonicalCollaborationValue(
        COLLABORATION_DOMAINS.collaborativeVaultDestroyedPayloadDigest,
        action,
        collaborationVaultDestructionActionSchema,
      ),
    ).not.toBe(digest);

    for (const candidate of [
      { ...action, databaseId: 'database-substituted' },
      { ...action, vaultId: 'vault-substituted' },
    ]) {
      expect(computeCollaborativeVaultDestructionActionDigest(candidate)).not.toBe(
        digest,
      );
    }
    for (const candidate of [
      { ...action, protocolVersion: 2 },
      { ...action, operationType: 'ordinary-write' },
      { ...action, destructionMode: 'recoverable' },
      { ...action, unexpected: true },
    ]) {
      expect(() => computeCollaborativeVaultDestructionActionDigest(candidate)).toThrow(
        CryptoInputError,
      );
    }
  });

  it('domain-separates and commits every exact vault-destruction core field', () => {
    const core = vaultDestructionCore();
    const originalDigest = computeCollaborativeVaultDestroyedPayloadDigest(core);
    const expectDifferent = (candidate: unknown): void => {
      expect(computeCollaborativeVaultDestroyedPayloadDigest(candidate)).not.toBe(
        originalDigest,
      );
    };
    const withTuples = (
      prior: Record<string, unknown>,
      terminal: Record<string, unknown>,
    ): Record<string, unknown> => ({
      ...core,
      priorTuple: prior,
      terminalTuple: terminal,
    });

    expect(COLLABORATION_DOMAINS.collaborativeVaultDestroyedPayloadDigest).toBe(
      'kavrix/collaboration/vault-destroyed-payload-digest/v1',
    );
    expect(
      computeCollaborativeVaultDestroyedPayloadDigest(
        Object.fromEntries(Object.entries(core).reverse()),
      ),
    ).toBe(originalDigest);
    expect(
      computeCollaborativeVaultDestroyedPayloadDigest({
        ...core,
        priorTuple: Object.fromEntries(Object.entries(core.priorTuple).reverse()),
        terminalTuple: Object.fromEntries(Object.entries(core.terminalTuple).reverse()),
      }),
    ).toBe(originalDigest);
    expect(originalDigest).not.toBe(
      digestCanonicalCollaborationValue(
        COLLABORATION_DOMAINS.operationTombstoneDigest,
        core,
        collaborationVaultDestructionCoreSchema,
      ),
    );
    expectDifferent({ ...core, databaseId: 'database-substituted' });
    expectDifferent({ ...core, vaultId: 'vault-substituted' });
    expectDifferent({ ...core, operationId: 'operation-destroy-substituted' });
    expectDifferent({ ...core, authorityDelegationDigest: bytes(118) });
    expectDifferent({ ...core, priorHeadDigest: bytes(119) });
    expectDifferent({ ...core, actionParametersDigest: bytes(120) });
    expectDifferent({ ...core, actorPrincipalId: 'principal-substituted' });
    expectDifferent({ ...core, actorDeviceId: 'device-substituted' });
    expectDifferent({ ...core, destroyedAt: '2026-08-29T02:00:00.000Z' });
    expectDifferent({
      ...core,
      authorityEpoch: 2,
      priorTuple: { ...core.priorTuple, authorityEpoch: 2 },
      terminalTuple: { ...core.terminalTuple, authorityEpoch: 2 },
    });
    expectDifferent(
      withTuples(
        { ...core.priorTuple, documentRevision: 8 },
        { ...core.terminalTuple, documentRevision: 9 },
      ),
    );
    expectDifferent(
      withTuples(
        { ...core.priorTuple, membershipRevision: 5 },
        { ...core.terminalTuple, membershipRevision: 5 },
      ),
    );
    expectDifferent(
      withTuples(
        { ...core.priorTuple, policyRevision: 4 },
        { ...core.terminalTuple, policyRevision: 4 },
      ),
    );
    expectDifferent(
      withTuples(
        { ...core.priorTuple, keyEpoch: 4 },
        { ...core.terminalTuple, keyEpoch: 4 },
      ),
    );
    expectDifferent(
      withTuples(
        { ...core.priorTuple, databaseDeviceGeneration: 3 },
        { ...core.terminalTuple, databaseDeviceGeneration: 3 },
      ),
    );
    expectDifferent(
      withTuples(
        { ...core.priorTuple, databaseDeviceRegistryDigest: bytes(121) },
        { ...core.terminalTuple, databaseDeviceRegistryDigest: bytes(121) },
      ),
    );
    expectDifferent(
      withTuples(
        { ...core.priorTuple, authorizationStateDigest: bytes(122) },
        { ...core.terminalTuple, authorizationStateDigest: bytes(122) },
      ),
    );
    expect(() =>
      computeCollaborativeVaultDestroyedPayloadDigest({
        ...core,
        destructionMode: 'recoverable',
      }),
    ).toThrow(CryptoInputError);
    expect(() =>
      computeCollaborativeVaultDestroyedPayloadDigest({
        ...core,
        format: 'kavrix-collaborative-vault-destruction-core-legacy',
      }),
    ).toThrow(CryptoInputError);
    expect(() =>
      computeCollaborativeVaultDestroyedPayloadDigest({
        ...core,
        protocolVersion: 2,
      }),
    ).toThrow(CryptoInputError);
    expect(() =>
      computeCollaborativeVaultDestroyedPayloadDigest({
        ...core,
        terminalHeadDigest: bytes(123),
      }),
    ).toThrow(CryptoInputError);
  });

  it('domain-separates and commits every exact prior-history compaction field', () => {
    const input = historyCompactionInput();
    const originalDigest = computeMembershipHistoryCompactionDigest(input);
    const firstEvent = input.priorHistory.events[0];
    const secondEvent = input.priorHistory.events[1];
    const checkpoint = input.priorHistory.checkpoints[0];
    if (
      firstEvent === undefined ||
      secondEvent === undefined ||
      checkpoint === undefined
    ) {
      throw new Error('History compaction fixture is incomplete');
    }
    const expectDifferent = (candidate: unknown): void => {
      expect(computeMembershipHistoryCompactionDigest(candidate)).not.toBe(
        originalDigest,
      );
    };

    expect(COLLABORATION_DOMAINS.membershipHistoryCompactionDigest).toBe(
      'kavrix/collaboration/membership-history-compaction-digest/v1',
    );
    expect(
      computeMembershipHistoryCompactionDigest(
        Object.fromEntries(Object.entries(input).reverse()),
      ),
    ).toBe(originalDigest);
    expectDifferent({
      ...input,
      compactingOperationId: 'operation-compact-substituted',
    });
    expectDifferent({ ...input, previousHeadDigest: bytes(107) });
    expectDifferent({
      ...input,
      previousTuple: {
        ...input.previousTuple,
        documentRevision: input.previousTuple.documentRevision + 1,
      },
    });
    expectDifferent({
      ...input,
      priorHistory: {
        ...input.priorHistory,
        events: [secondEvent, firstEvent],
      },
    });
    expectDifferent({
      ...input,
      priorHistory: {
        ...input.priorHistory,
        events: [
          { ...firstEvent, targetDeviceId: 'device-member-substituted' },
          secondEvent,
        ],
      },
    });
    expectDifferent({
      ...input,
      priorHistory: {
        ...input.priorHistory,
        checkpoints: [{ ...checkpoint, previousHeadDigest: bytes(108) }],
      },
    });
    expectDifferent({
      ...input,
      priorHistory: {
        ...input.priorHistory,
        checkpoints: [{ ...checkpoint, signature: bytes(109, 64) }],
      },
    });
    expectDifferent({
      ...input,
      priorHistory: {
        ...input.priorHistory,
        compactedHistoryDigest: bytes(110),
      },
    });
    expectDifferent({
      ...input,
      priorHistory: {
        ...input.priorHistory,
        compactedThroughRevision: 2,
      },
    });
    expectDifferent({
      ...input,
      priorHistory: {
        ...input.priorHistory,
        currentHistoryDigest: bytes(111),
      },
    });
    expectDifferent({
      ...input,
      databaseId: 'database-substituted',
      priorHistory: {
        ...input.priorHistory,
        databaseId: 'database-substituted',
      },
    });
    expectDifferent({
      ...input,
      vaultId: 'vault-substituted',
      priorHistory: {
        ...input.priorHistory,
        vaultId: 'vault-substituted',
      },
    });
    expectDifferent({
      ...input,
      authorityEpoch: 2,
      previousTuple: { ...input.previousTuple, authorityEpoch: 2 },
      priorHistory: {
        ...input.priorHistory,
        authorityEpoch: 2,
        events: input.priorHistory.events.map((event) => ({
          ...event,
          previousAuthorityEpoch: 2,
          newAuthorityEpoch: 2,
        })),
        checkpoints: input.priorHistory.checkpoints.map((value) => ({
          ...value,
          authorityEpoch: 2,
        })),
      },
    });
    const substitutedRegistryDigest = bytes(112);
    expectDifferent({
      ...input,
      previousTuple: {
        ...input.previousTuple,
        databaseDeviceRegistryDigest: substitutedRegistryDigest,
      },
      priorHistory: {
        ...input.priorHistory,
        databaseDeviceRegistryDigest: substitutedRegistryDigest,
        events: input.priorHistory.events.map((event) => ({
          ...event,
          previousDatabaseDeviceRegistryDigest: substitutedRegistryDigest,
          newDatabaseDeviceRegistryDigest: substitutedRegistryDigest,
        })),
        checkpoints: input.priorHistory.checkpoints.map((value) => ({
          ...value,
          databaseDeviceRegistryDigest: substitutedRegistryDigest,
        })),
      },
    });
    expect(() =>
      computeMembershipHistoryCompactionDigest({
        ...input,
        trustedWithoutVerification: true,
      }),
    ).toThrow(CryptoInputError);
  });

  it('generates distinct root/device signing and device encryption key types', async () => {
    const principal = await generatePrincipalSigningKeyPair();
    const device = await generateDeviceKeyPairs();

    expect(principal.algorithm).toBe('ed25519');
    expect(device.signing.algorithm).toBe('ed25519');
    expect(device.encryption.algorithm).toBe('x25519');
    expect(principal.publicKey).toHaveLength(32);
    expect(device.signing.publicKey).toHaveLength(32);
    expect(device.encryption.publicKey).toHaveLength(32);
    expect(principal.privateKey).toHaveLength(64);
    expect(device.signing.privateKey).toHaveLength(64);
    expect(device.encryption.privateKey).toHaveLength(32);
    expect(device.signing.publicKey).not.toEqual(device.encryption.publicKey);
    expect(device.signing.publicKeyBase64).toBe(
      encodeCollaborationPublicKey(device.signing.publicKey),
    );

    principal.privateKey.fill(0);
    device.signing.privateKey.fill(0);
    device.encryption.privateKey.fill(0);
  });

  it('binds signatures to the explicit domain, every commitment field, and key', async () => {
    const signer = await generateDeviceSigningKeyPair();
    const otherSigner = await generateDeviceSigningKeyPair();
    const commitment = baseCommitment();
    const signature = await signMutationCommitment(commitment, signer.privateKey);

    await expect(
      verifyMutationCommitment(commitment, signature, signer.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyMutationCommitment(commitment, signature, otherSigner.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyCanonicalCollaborationValue(
        COLLABORATION_DOMAINS.mutationHead,
        commitment,
        collaborationMutationCommitmentSchema,
        signature,
        signer.publicKeyBase64,
      ),
    ).resolves.toBe(false);

    const fieldChanged = collaborationMutationCommitmentSchema.parse({
      ...commitment,
      requestDigest: bytes(9),
    });
    await expect(
      verifyMutationCommitment(fieldChanged, signature, signer.publicKeyBase64),
    ).resolves.toBe(false);
    const tupleChanged = collaborationMutationCommitmentSchema.parse({
      ...commitment,
      documentRevision: 2,
    });
    await expect(
      verifyMutationCommitment(tupleChanged, signature, signer.publicKeyBase64),
    ).resolves.toBe(false);

    signer.privateKey.fill(0);
    otherSigner.privateKey.fill(0);
  });

  it('hashes the exact non-genesis mutation request projection without its self-field', () => {
    const commitment = baseCommitment();
    const digest = computeMutationRequestDigest(commitment);
    const expectDifferent = (overrides: Record<string, unknown>): void => {
      expect(
        computeMutationRequestDigest({
          ...commitment,
          ...overrides,
        }),
      ).not.toBe(digest);
    };

    expect(computeMutationRequestDigest({ ...commitment })).toBe(digest);
    expect(
      computeMutationRequestDigest({
        ...commitment,
        requestDigest: bytes(91),
      }),
    ).toBe(digest);
    expect(digest).not.toBe(computeMutationHead(commitment));

    expectDifferent({ operationId: 'operation-b' });
    expectDifferent({ previousHeadDigest: bytes(92) });
    expectDifferent({ previousDocumentRevision: 1 });
    expectDifferent({ documentRevision: 2 });
    expectDifferent({ encryptedPayloadDigest: bytes(93) });
    expectDifferent({ encryptedMembershipDigest: bytes(94) });
    expectDifferent({ encryptedEnvelopesDigest: bytes(95) });
    expectDifferent({ policyDigest: bytes(96) });
    expectDifferent({ writerPrincipalId: 'principal-b' });
    expectDifferent({ writerDeviceId: 'device-b' });
    expectDifferent({ timestamp: '2026-08-29T00:01:00.000Z' });
    expectDifferent({ expiresAt: '2026-08-30T00:00:00.000Z' });

    const administrativeCommitment = collaborationMutationCommitmentSchema.parse({
      ...commitment,
      operationType: 'add-member',
      authorizationStateDigest: bytes(97),
      authorizationTransitionDigest: bytes(98),
    });
    const administrativeDigest = computeMutationRequestDigest(administrativeCommitment);
    expect(
      computeMutationRequestDigest({
        ...administrativeCommitment,
        operationType: 'remove-member',
      }),
    ).not.toBe(administrativeDigest);
    expect(
      computeMutationRequestDigest({
        ...administrativeCommitment,
        authorizationTransitionDigest: bytes(99),
      }),
    ).not.toBe(administrativeDigest);
    expect(
      computeMutationRequestDigest({
        ...administrativeCommitment,
        previousAuthorizationStateDigest: bytes(100),
      }),
    ).not.toBe(administrativeDigest);
    expect(
      computeMutationRequestDigest({
        ...administrativeCommitment,
        authorizationStateDigest: bytes(101),
      }),
    ).not.toBe(administrativeDigest);

    const missingRequestDigest: Record<string, unknown> = { ...commitment };
    delete missingRequestDigest['requestDigest'];
    expect(() => computeMutationRequestDigest(missingRequestDigest)).toThrow(
      CryptoInputError,
    );
    expect(() =>
      computeMutationRequestDigest({ ...commitment, extra: 'reject-me' }),
    ).toThrow(CryptoInputError);
    expect(() =>
      computeMutationRequestDigest({
        ...administrativeCommitment,
        operationType: 'genesis-migration',
      }),
    ).toThrow(CryptoInputError);
  });

  it('derives deterministic authority keys bound to database and epoch', async () => {
    const drk = Uint8Array.from({ length: 32 }, (_, index) => index);
    const first = await deriveDatabaseAuthoritySigningKeyPair(drk, 'database-a', 1);
    const second = await deriveDatabaseAuthoritySigningKeyPair(drk, 'database-a', 1);
    const otherDatabase = await deriveDatabaseAuthoritySigningKeyPair(
      drk,
      'database-b',
      1,
    );
    const otherEpoch = await deriveDatabaseAuthoritySigningKeyPair(
      drk,
      'database-a',
      2,
    );

    expect(first.publicKey).toEqual(second.publicKey);
    expect(first.privateKey).toEqual(second.privateKey);
    expect(first.publicKey).not.toEqual(otherDatabase.publicKey);
    expect(first.publicKey).not.toEqual(otherEpoch.publicKey);

    first.privateKey.fill(0);
    second.privateKey.fill(0);
    otherDatabase.privateKey.fill(0);
    otherEpoch.privateKey.fill(0);
  });

  it('derives an independent deterministic recovery pair and seals with only its public key', async () => {
    const drk = Uint8Array.from({ length: 32 }, (_, index) => index ^ 0x5a);
    const wrongDrk = Uint8Array.from(drk, (value) => value ^ 0xff);
    const vrk = Uint8Array.from({ length: 32 }, (_, index) => index ^ 0xa5);
    const drkCanary = Uint8Array.from(drk);
    const vrkCanary = Uint8Array.from(vrk);
    const first = await deriveDatabaseAuthorityRecoveryKeyPair(drk, 'database-a', 1);
    const second = await deriveDatabaseAuthorityRecoveryKeyPair(drk, 'database-a', 1);
    const otherDatabase = await deriveDatabaseAuthorityRecoveryKeyPair(
      drk,
      'database-b',
      1,
    );
    const otherEpoch = await deriveDatabaseAuthorityRecoveryKeyPair(
      drk,
      'database-a',
      2,
    );
    const signing = await deriveDatabaseAuthoritySigningKeyPair(drk, 'database-a', 1);

    expect(first.publicKey).toEqual(second.publicKey);
    expect(first.privateKey).toEqual(second.privateKey);
    expect(first.publicKey).not.toEqual(otherDatabase.publicKey);
    expect(first.publicKey).not.toEqual(otherEpoch.publicKey);
    expect(first.publicKey).not.toEqual(signing.publicKey);

    const sealed = await sealCollaborationVaultRootForDatabaseAuthority(
      vrk,
      first.publicKeyBase64,
    );
    const opened = await openCollaborationVaultRootForDatabaseAuthority(
      sealed,
      drk,
      'database-a',
      1,
      first.publicKeyBase64,
    );
    expect(opened).toEqual(vrk);
    expect(drk).toEqual(drkCanary);
    expect(vrk).toEqual(vrkCanary);

    await expect(
      openCollaborationVaultRootForDatabaseAuthority(
        sealed,
        wrongDrk,
        'database-a',
        1,
        first.publicKeyBase64,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      openCollaborationVaultRootForDatabaseAuthority(
        sealed,
        drk,
        'database-b',
        1,
        first.publicKeyBase64,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      openCollaborationVaultRootForDatabaseAuthority(
        sealed,
        drk,
        'database-a',
        2,
        first.publicKeyBase64,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      openCollaborationVaultRootForDatabaseAuthority(
        sealed,
        drk,
        'database-a',
        1,
        otherDatabase.publicKeyBase64,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      openCollaborationVaultRootForDatabaseAuthority(
        mutateBase64(sealed),
        drk,
        'database-a',
        1,
        first.publicKeyBase64,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);

    opened.fill(0);
    first.privateKey.fill(0);
    second.privateKey.fill(0);
    otherDatabase.privateKey.fill(0);
    otherEpoch.privateKey.fill(0);
    signing.privateKey.fill(0);
    expect(opened.every((value) => value === 0)).toBe(true);
    expect(first.privateKey.every((value) => value === 0)).toBe(true);
  });

  it('seals exactly one VRK and fails closed for wrong pairs or tampering', async () => {
    const recipient = await generateDeviceEncryptionKeyPair();
    const wrongRecipient = await generateDeviceEncryptionKeyPair();
    const vrk = Uint8Array.from({ length: 32 }, (_, index) => index ^ 0xa5);
    const sealed = await sealVaultRootKeyForDevice(vrk, recipient.publicKeyBase64);

    await expect(
      openVaultRootKeyForDevice(
        sealed,
        recipient.publicKeyBase64,
        recipient.privateKey,
      ),
    ).resolves.toEqual(vrk);
    await expect(
      openVaultRootKeyForDevice(
        sealed,
        wrongRecipient.publicKeyBase64,
        wrongRecipient.privateKey,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      openVaultRootKeyForDevice(
        mutateBase64(sealed),
        recipient.publicKeyBase64,
        recipient.privateKey,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('authenticates the complete collaboration AAD tuple and ciphertext/tag', async () => {
    const key = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
    const aad = baseAad();
    const plaintext = new TextEncoder().encode('collaboration plaintext canary');
    const envelope = await encryptCollaborationEnvelope(plaintext, key, aad);

    expect(computeAadMetadataDigest(baseAadMetadata())).toBe(aad.metadataDigest);
    expect(computeAadMetadataDigest({ ...baseAadMetadata(), keyEpoch: 2 })).not.toBe(
      aad.metadataDigest,
    );
    expect(computeAadMetadataDigest({ ...aad, metadataDigest: bytes(20) })).toBe(
      aad.metadataDigest,
    );
    await expect(decryptCollaborationEnvelope(envelope, key, aad)).resolves.toEqual(
      plaintext,
    );
    expect(computeEncryptedPayloadDigest(envelope)).toBe(
      computeEncryptedPayloadDigest({ ...envelope }),
    );
    expect(
      computeEncryptedPayloadDigest({
        ...envelope,
        ciphertext: mutateBase64(envelope.ciphertext),
      }),
    ).not.toBe(computeEncryptedPayloadDigest(envelope));
    expect(
      computeEncryptedPayloadDigest({
        ...envelope,
        authenticationTag: mutateBase64(envelope.authenticationTag),
      }),
    ).not.toBe(computeEncryptedPayloadDigest(envelope));
    await expect(
      decryptCollaborationEnvelope(
        envelope,
        key,
        collaborationAadSchema.parse({ ...aad, keyEpoch: 2 }),
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      decryptCollaborationEnvelope(
        { ...envelope, ciphertext: mutateBase64(envelope.ciphertext) },
        key,
        aad,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      decryptCollaborationEnvelope(
        {
          ...envelope,
          authenticationTag: mutateBase64(envelope.authenticationTag),
        },
        key,
        aad,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('scopes discovery tags to the database and computes an acyclic deterministic head', () => {
    expect(COLLABORATION_GENESIS_HEAD_DIGEST).toHaveLength(43);
    expect(COLLABORATION_GENESIS_HEAD_DIGEST).not.toBe(bytes(0));
    expect(COLLABORATION_GENESIS_HEAD_DIGEST).toBe(
      digestCanonicalCollaborationValue(
        COLLABORATION_DOMAINS.genesisHead,
        {
          protocolVersion: 1,
        },
        {
          parse(value: unknown) {
            if (
              typeof value !== 'object' ||
              value === null ||
              Array.isArray(value) ||
              Object.keys(value).length !== 1 ||
              (value as { protocolVersion?: unknown }).protocolVersion !== 1
            ) {
              throw new Error('invalid genesis-head input');
            }
            return { protocolVersion: 1 as const };
          },
        },
      ),
    );
    expect(COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST).toBe(
      digestCanonicalCollaborationValue(
        COLLABORATION_DOMAINS.genesisAuthorizationState,
        {
          protocolVersion: 1,
        },
        {
          parse(value: unknown) {
            if (
              typeof value !== 'object' ||
              value === null ||
              Array.isArray(value) ||
              Object.keys(value).length !== 1 ||
              (value as { protocolVersion?: unknown }).protocolVersion !== 1
            ) {
              throw new Error('invalid genesis authorization-state input');
            }
            return { protocolVersion: 1 as const };
          },
        },
      ),
    );
    const genesisSentinelSchema = {
      parse(value: unknown) {
        if (
          typeof value !== 'object' ||
          value === null ||
          Array.isArray(value) ||
          Object.keys(value).length !== 1 ||
          (value as { protocolVersion?: unknown }).protocolVersion !== 1
        ) {
          throw new Error('invalid genesis sentinel input');
        }
        return { protocolVersion: 1 as const };
      },
    };
    expect(COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST).toBe(
      digestCanonicalCollaborationValue(
        COLLABORATION_DOMAINS.genesisMembershipState,
        { protocolVersion: 1 },
        genesisSentinelSchema,
      ),
    );
    expect(COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST).toBe(
      digestCanonicalCollaborationValue(
        COLLABORATION_DOMAINS.genesisMembershipHistory,
        { protocolVersion: 1 },
        genesisSentinelSchema,
      ),
    );
    expect(COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST).toBe(
      digestCanonicalCollaborationValue(
        COLLABORATION_DOMAINS.genesisCompactedHistory,
        { protocolVersion: 1 },
        genesisSentinelSchema,
      ),
    );
    expect(
      new Set([
        COLLABORATION_GENESIS_HEAD_DIGEST,
        COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
        COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
        COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
        COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
      ]).size,
    ).toBe(5);
    const fingerprint = bytes(17);
    expect(computeDiscoveryTag('database-a', fingerprint)).toBe(
      computeDiscoveryTag('database-a', fingerprint),
    );
    expect(computeDiscoveryTag('database-a', fingerprint)).not.toBe(
      computeDiscoveryTag('database-b', fingerprint),
    );

    const commitment = baseCommitment();
    const first = computeMutationHead(commitment);
    expect(computeMutationHead({ ...commitment })).toBe(first);
    expect(
      computeMutationHead(
        collaborationMutationCommitmentSchema.parse({
          ...commitment,
          policyDigest: bytes(18),
        }),
      ),
    ).not.toBe(first);
    expect(
      computeMutationHead(
        collaborationMutationCommitmentSchema.parse({
          ...commitment,
          expiresAt: '2026-08-30T00:00:00.000Z',
        }),
      ),
    ).not.toBe(first);
  });

  it('binds discovery records to the exact finalized-mutation writer', async () => {
    const writer = await generateDeviceSigningKeyPair();
    const wrongWriter = await generateDeviceSigningKeyPair();
    const state = authorizationState();
    const envelopeCore = state.keyEnvelopes[0];
    if (envelopeCore === undefined || !('membershipId' in envelopeCore)) {
      throw new Error('Discovery fixture requires one member envelope');
    }
    const envelope = collaborationKeyEnvelopeSchema.parse({
      ...envelopeCore,
      envelopeDigest: bytes(72),
      createdAt: '2026-08-30T00:00:00.000Z',
      ownerSignature: bytes(73, 64),
    });
    const base = collaborationDiscoveryRecordSchema.parse({
      format: 'kavrix-collaborative-discovery-record',
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityEpoch: 1,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: bytes(3),
      discoveryTag: computeDiscoveryTag('database-a', bytes(25)),
      membershipId: 'membership-a',
      membershipState: 'active',
      keyEpoch: 1,
      membershipRevision: 1,
      authorizationStateDigest: computeAuthorizationStateDigest(state),
      encryptedMemberKeyEnvelope: envelope,
      encryptedMembershipMetadataDigest: bytes(74),
      discoveryRecordDigest: bytes(0),
      signerPrincipalId: 'principal-a',
      signerDeviceId: 'device-a',
      writerSignature: bytes(0, 64),
      createdAt: '2026-08-30T00:00:00.000Z',
      updatedAt: '2026-08-30T00:00:00.000Z',
    });
    const withDigest = collaborationDiscoveryRecordSchema.parse({
      ...base,
      discoveryRecordDigest: computeDiscoveryRecordDigest(base),
    });
    const writerSignature = await signDiscoveryRecord(withDigest, writer.privateKey);
    const signed = collaborationDiscoveryRecordSchema.parse({
      ...withDigest,
      writerSignature,
    });

    await expect(verifyDiscoveryRecord(signed, writer.publicKeyBase64)).resolves.toBe(
      true,
    );
    await expect(
      verifyDiscoveryRecord(signed, wrongWriter.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyDiscoveryRecord(
        { ...signed, signerDeviceId: 'device-b' },
        writer.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    expect(
      computeDiscoveryRecordDigest({
        ...signed,
        writerSignature: bytes(75, 64),
      }),
    ).toBe(signed.discoveryRecordDigest);

    writer.privateKey.fill(0);
    wrongWriter.privateKey.fill(0);
  });

  it('binds transfer signatures to the immutable intent core and stored digest', async () => {
    const initiator = await generateDeviceSigningKeyPair();
    const wrongSigner = await generateDeviceSigningKeyPair();
    const base = transferIntentSchema.parse(baseTransferIntent());
    const digest = computeTransferIntentDigest(base);
    const withDigest = transferIntentSchema.parse({
      ...base,
      intentDigest: digest,
    });
    const initiatorSignature = await signTransferIntent(
      withDigest,
      initiator.privateKey,
    );
    const signed = transferIntentSchema.parse({
      ...withDigest,
      state: 'initiator-signed',
      initiatorSignedAt: '2026-08-29T00:01:00.000Z',
      initiatorSignature,
    });

    expect(computeTransferIntentDigest(signed)).toBe(digest);
    expect(
      computeTransferIntentDigest(Object.fromEntries(Object.entries(signed).reverse())),
    ).toBe(digest);
    await expect(verifyTransferIntent(signed, initiator.publicKeyBase64)).resolves.toBe(
      true,
    );
    await expect(
      verifyTransferIntent(signed, wrongSigner.publicKeyBase64),
    ).resolves.toBe(false);

    const lifecycleChanged = transferIntentSchema.parse({
      ...signed,
      initiatorSignedAt: '2026-08-29T00:02:00.000Z',
    });
    expect(computeTransferIntentDigest(lifecycleChanged)).toBe(digest);
    await expect(
      verifyTransferIntent(lifecycleChanged, initiator.publicKeyBase64),
    ).resolves.toBe(true);

    const expired = transferIntentSchema.parse({
      ...withDigest,
      state: 'expired',
      terminalAt: '2026-09-01T00:00:00.000Z',
    });
    expect(computeTransferIntentDigest(expired)).toBe(digest);

    const immutableChanges: [string, unknown][] = [
      ['transferIntentId', 'transfer-b'],
      ['operationId', 'operation-transfer-b'],
      ['databaseId', 'database-b'],
      ['vaultId', 'vault-b'],
      ['initiatorPrincipalId', 'principal-c'],
      ['initiatorDeviceId', 'device-c'],
      ['recipientPrincipalId', 'principal-c'],
      ['recipientDeviceId', 'device-c'],
      ['originalOwnerDisposition', 'editor'],
      ['authorityEpoch', 2],
      ['databaseDeviceGeneration', 2],
      ['databaseDeviceRegistryDigest', bytes(18)],
      ['documentRevision', 2],
      ['membershipRevision', 2],
      ['policyRevision', 2],
      ['keyEpoch', 2],
      ['currentHeadDigest', bytes(19)],
      ['createdAt', '2026-08-28T00:00:00.000Z'],
      ['expiresAt', '2026-09-02T00:00:00.000Z'],
      ['approvalRequestId', 'approval-a'],
    ];
    for (const [field, value] of immutableChanges) {
      expect(computeTransferIntentDigest({ ...base, [field]: value }), field).not.toBe(
        digest,
      );
    }

    await expect(
      verifyTransferIntent(
        transferIntentSchema.parse({ ...signed, recipientPrincipalId: 'principal-c' }),
        initiator.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyTransferIntent(
        transferIntentSchema.parse({ ...signed, intentDigest: bytes(9) }),
        initiator.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyTransferIntent(
        transferIntentSchema.parse({
          ...signed,
          initiatorSignature: mutateBase64(initiatorSignature),
        }),
        initiator.publicKeyBase64,
      ),
    ).resolves.toBe(false);
  });

  it('signs and verifies ownership-transfer acceptance over exactly its record', async () => {
    const recipient = await generateDeviceSigningKeyPair();
    const wrongSigner = await generateDeviceSigningKeyPair();
    const intentDigest = computeTransferIntentDigest(
      transferIntentSchema.parse(baseTransferIntent()),
    );
    const unsigned = ownershipTransferAcceptanceSchema.parse({
      protocolVersion: 1,
      transferIntentId: 'transfer-a',
      operationId: 'operation-transfer-a',
      databaseId: 'database-a',
      vaultId: 'vault-a',
      intentDigest,
      authorityEpoch: 1,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: bytes(3),
      authorizationStateDigest: bytes(24),
      recipientPrincipalId: 'principal-b',
      recipientDeviceId: 'device-b',
      acceptedAt: '2026-08-30T00:00:00.000Z',
      signature: bytes(8, 64),
    });
    const signature = await signOwnershipTransferAcceptance(
      unsigned,
      recipient.privateKey,
    );
    const acceptance = ownershipTransferAcceptanceSchema.parse({
      ...unsigned,
      signature,
    });

    await expect(
      verifyOwnershipTransferAcceptance(acceptance, recipient.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyOwnershipTransferAcceptance(acceptance, wrongSigner.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyOwnershipTransferAcceptance(
        { ...acceptance, acceptedAt: '2026-08-30T00:01:00.000Z' },
        recipient.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyOwnershipTransferAcceptance(
        { ...acceptance, databaseDeviceGeneration: 2 },
        recipient.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyOwnershipTransferAcceptance(
        { ...acceptance, intentDigest: bytes(9) },
        recipient.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyOwnershipTransferAcceptance(
        { ...acceptance, signature: mutateBase64(signature) },
        recipient.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyCollaborationRecord(
        COLLABORATION_DOMAINS.transferIntentSignature,
        acceptance,
        ownershipTransferAcceptanceSchema,
        'signature',
        recipient.publicKeyBase64,
      ),
    ).resolves.toBe(false);
  });

  it('signs and verifies approval evidence over its complete strict tuple', async () => {
    const approver = await generateDeviceSigningKeyPair();
    const wrongSigner = await generateDeviceSigningKeyPair();
    const requestDigest = bytes(12);
    const unsigned = approvalEvidenceSchema.parse(baseApprovalEvidence(requestDigest));
    const signature = await signApprovalEvidence(unsigned, approver.privateKey);
    const evidence = approvalEvidenceSchema.parse({
      ...unsigned,
      signature,
    });

    await expect(
      verifyApprovalEvidence(evidence, approver.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyApprovalEvidence(evidence, wrongSigner.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyApprovalEvidence(
        { ...evidence, requestDigest: bytes(13) },
        approver.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyApprovalEvidence(
        { ...evidence, approvedAt: '2026-08-30T00:01:00.000Z' },
        approver.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyApprovalEvidence(
        { ...evidence, approverDeviceId: 'device-c' },
        approver.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyApprovalEvidence(
        { ...evidence, signature: mutateBase64(signature) },
        approver.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyCollaborationRecord(
        COLLABORATION_DOMAINS.transferAcceptanceSignature,
        evidence,
        approvalEvidenceSchema,
        'signature',
        approver.publicKeyBase64,
      ),
    ).resolves.toBe(false);
  });

  it('domain-separates and bounds exact administrative action parameters', () => {
    const action = {
      operationType: 'remove-member',
      targetPrincipalId: 'principal-b',
      decryptAccessChanged: true,
    };
    const digest = computeAdministrativeActionParametersDigest(action);

    expect(computeAdministrativeActionParametersDigest({ ...action })).toBe(digest);
    expect(
      computeAdministrativeActionParametersDigest({
        ...action,
        targetPrincipalId: 'principal-c',
      }),
    ).not.toBe(digest);
    expect(() => computeAdministrativeActionParametersDigest(['not-a-record'])).toThrow(
      CryptoInputError,
    );
  });

  it('keeps the anchored logical policy digest stable across registry fencing', () => {
    const policy = collaborationPolicyStateSchema.parse({
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityEpoch: 1,
      policyRevision: 1,
      approvalPolicy: 'none',
      policyDigest: bytes(1),
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: bytes(2),
      changedByPrincipalId: 'principal-a',
      changedByDeviceId: 'device-a',
      changedAt: '2026-08-30T00:00:00.000Z',
      signature: bytes(3, 64),
    });
    const digest = computePolicyStateDigest(policy);
    expect(
      computePolicyStateDigest({
        ...policy,
        databaseDeviceGeneration: 2,
        databaseDeviceRegistryDigest: bytes(4),
        policyDigest: bytes(5),
        changedAt: '2026-08-31T00:00:00.000Z',
        signature: bytes(6, 64),
      }),
    ).toBe(digest);
    expect(
      computePolicyStateDigest({
        ...policy,
        policyRevision: 2,
        approvalPolicy: 'one-additional-owner',
      }),
    ).not.toBe(digest);
  });

  it('hashes the complete strict legacy vault source without accepting extra fields', () => {
    const source = databaseVaultDocumentSchema.parse(baseLegacyVaultDocument());
    const digest = computeLegacySourceDigest(source);

    expect(computeLegacySourceDigest({ ...source })).toBe(digest);
    expect(
      computeLegacySourceDigest({
        ...source,
        updatedAt: '2026-08-31T00:00:00.000Z',
      }),
    ).not.toBe(digest);
    expect(
      computeLegacySourceDigest({
        ...source,
        encryptedPayload: {
          ...source.encryptedPayload,
          ciphertext: mutateBase64(source.encryptedPayload.ciphertext),
        },
      }),
    ).not.toBe(digest);
    expect(() =>
      computeLegacySourceDigest({ ...source, extra: 'reject-me' }),
    ).toThrow();
  });

  it('binds migration request digest and dual signatures to distinct domains', async () => {
    const authority = await generateDeviceSigningKeyPair();
    const owner = await generateDeviceSigningKeyPair();
    const wrongSigner = await generateDeviceSigningKeyPair();
    const base = collaborationMigrationRequestSchema.parse(baseMigrationRequest());
    const requestDigest = computeMigrationRequestDigest(base);
    const withDigest = collaborationMigrationRequestSchema.parse({
      ...base,
      requestDigest,
    });
    const authoritySignature = await signMigrationRequestAuthority(
      withDigest,
      authority.privateKey,
    );
    const ownerSignature = await signMigrationRequestOwner(
      { ...withDigest, authoritySignature },
      owner.privateKey,
    );
    const signed = collaborationMigrationRequestSchema.parse({
      ...withDigest,
      authoritySignature,
      ownerSignature,
    });

    expect(computeMigrationRequestDigest(signed)).toBe(requestDigest);
    expect(
      computeMigrationRequestDigest({
        ...signed,
        requestDigest: bytes(1),
        authoritySignature: bytes(2, 64),
        ownerSignature: bytes(3, 64),
      }),
    ).toBe(requestDigest);
    await expect(
      verifyMigrationRequestAuthority(signed, authority.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyMigrationRequestOwner(signed, owner.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyMigrationRequestAuthority(signed, wrongSigner.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationRequestOwner(signed, wrongSigner.publicKeyBase64),
    ).resolves.toBe(false);

    await expect(
      verifyMigrationRequestAuthority(
        { ...signed, authoritySignature: ownerSignature },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationRequestOwner(
        { ...signed, ownerSignature: authoritySignature },
        owner.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationRequestAuthority(
        { ...signed, requestedAt: '2026-08-31T00:00:00.000Z' },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationRequestOwner(
        { ...signed, initialOwnerDeviceId: 'device-c' },
        owner.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationRequestAuthority(
        { ...signed, requestDigest: bytes(4) },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationRequestOwner(
        { ...signed, ownerSignature: mutateBase64(ownerSignature) },
        owner.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    expect(() =>
      computeMigrationRequestDigest({ ...signed, extra: 'reject-me' }),
    ).toThrow();
  });

  it('binds prepared and active migration marker authority signatures', async () => {
    const authority = await generateDeviceSigningKeyPair();
    const wrongSigner = await generateDeviceSigningKeyPair();
    const source = databaseVaultDocumentSchema.parse(baseLegacyVaultDocument());
    const sourceDigest = computeLegacySourceDigest(source);
    const requestBase =
      collaborationMigrationRequestSchema.parse(baseMigrationRequest());
    const request = collaborationMigrationRequestSchema.parse({
      ...requestBase,
      requestDigest: computeMigrationRequestDigest(requestBase),
    });
    const registryCandidate = collaborationDatabaseDeviceRegistrySchema.parse(
      baseRegistryCandidate(),
    );
    const markerBase = baseMigrationMarker(request, sourceDigest);
    const preparedUnsigned = collaborationMigrationPreparedMarkerSchema.parse({
      ...markerBase,
      state: 'prepared',
      legacySource: source,
      registryCandidate,
    });
    const preparedSignature = await signMigrationPreparedMarker(
      preparedUnsigned,
      authority.privateKey,
    );
    const prepared = collaborationMigrationPreparedMarkerSchema.parse({
      ...preparedUnsigned,
      authoritySignature: preparedSignature,
    });

    await expect(
      verifyMigrationPreparedMarker(prepared, authority.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyMigrationPreparedMarker(prepared, wrongSigner.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationPreparedMarker(
        { ...prepared, candidateHeadDigest: bytes(66) },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationPreparedMarker(
        {
          ...prepared,
          legacySource: {
            ...prepared.legacySource,
            updatedAt: '2026-08-31T00:00:00.000Z',
          },
        },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationPreparedMarker(
        { ...prepared, authoritySignature: mutateBase64(preparedSignature) },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationPreparedMarker(
        { ...prepared, state: 'active' },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);

    const activeUnsigned = collaborationMigrationActiveMarkerSchema.parse({
      ...markerBase,
      state: 'active',
      outcomeDigest: bytes(67),
      activatedAt: '2026-08-31T00:00:00.000Z',
    });
    const activeSignature = await signMigrationActiveMarker(
      activeUnsigned,
      authority.privateKey,
    );
    const active = collaborationMigrationActiveMarkerSchema.parse({
      ...activeUnsigned,
      authoritySignature: activeSignature,
    });
    await expect(
      verifyMigrationActiveMarker(active, authority.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyMigrationActiveMarker(active, wrongSigner.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationActiveMarker(
        { ...active, outcomeDigest: bytes(68) },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationActiveMarker(
        { ...active, activatedAt: '2026-09-01T00:00:00.000Z' },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyMigrationActiveMarker(
        { ...active, authoritySignature: mutateBase64(activeSignature) },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);
  });

  it('hashes only the strict authorization projection and signs one immutable authority delegation', async () => {
    const state = authorizationState();
    const stateDigest = computeAuthorizationStateDigest(state);
    const membershipStateDigest = computeMembershipStateDigest(state);
    expect(
      computeMembershipStateDigest({
        ...state,
        approvalPolicy: 'one-additional-owner',
        policyRevision: state.policyRevision + 1,
      }),
    ).toBe(membershipStateDigest);
    expect(
      computeMembershipStateDigest({
        ...state,
        memberships: state.memberships.map((membership, index) =>
          index === 0
            ? { ...membership, updatedAt: '2026-08-31T00:00:00.000Z' }
            : membership,
        ),
      }),
    ).not.toBe(membershipStateDigest);
    expect(
      computeAuthorizationStateDigest(
        Object.fromEntries(Object.entries(state).reverse()),
      ),
    ).toBe(stateDigest);
    expect(
      computeAuthorizationStateDigest({
        ...state,
        keyEnvelopes: [
          { ...state.keyEnvelopes[0], sealedVaultRootKey: bytes(33, 80) },
          state.keyEnvelopes[1],
        ],
      }),
    ).not.toBe(stateDigest);
    expect(() => computeAuthorizationStateDigest({ ...state, history: [] })).toThrow();
    expect(() =>
      computeAuthorizationStateDigest({
        ...state,
        authorityDelegationDigest: bytes(31),
      }),
    ).toThrow();
    const firstMembership = state.memberships[0];
    if (firstMembership === undefined) {
      throw new Error('Authorization-state fixture requires one membership');
    }
    expect(() =>
      computeAuthorizationStateDigest({
        ...state,
        memberships: [
          {
            ...firstMembership,
            devices: [
              {
                ...firstMembership.devices[0],
                rootSignature: bytes(1, 64),
              },
            ],
          },
        ],
      }),
    ).toThrow();
    expect(() =>
      computeAuthorizationStateDigest({
        ...state,
        keyEnvelopes: [
          { ...state.keyEnvelopes[0], ownerSignature: bytes(1, 64) },
          state.keyEnvelopes[1],
        ],
      }),
    ).toThrow();

    const drk = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
    const authority = await deriveDatabaseAuthoritySigningKeyPair(drk, 'database-a', 1);
    const recovery = await deriveDatabaseAuthorityRecoveryKeyPair(drk, 'database-a', 1);
    const wrongAuthority = await generateDeviceSigningKeyPair();
    const unsigned = collaborationAuthorityDelegationSchema.parse({
      format: 'kavrix-collaborative-authority-delegation',
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityEpoch: 1,
      authoritySigningPublicKey: authority.publicKeyBase64,
      authoritySigningKeyFingerprint: computePublicKeyFingerprint(
        authority.publicKeyBase64,
        'ed25519',
      ),
      authorityRecoveryPublicKey: recovery.publicKeyBase64,
      authorityRecoveryKeyFingerprint: computePublicKeyFingerprint(
        recovery.publicKeyBase64,
        'x25519',
      ),
      genesisOperationId: 'operation-genesis',
      genesisTuple: tuple(1, 1, 1, stateDigest),
      genesisHeadDigest: bytes(34),
      initialAuthorizationStateDigest: stateDigest,
      initialOwnerPrincipalId: 'principal-a',
      initialOwnerRootKeyFingerprint: bytes(35),
      initialOwnerDeviceId: 'device-a',
      initialOwnerDeviceSigningKeyFingerprint: bytes(36),
      initialOwnerDeviceEncryptionKeyFingerprint: bytes(37),
      issuedAt: '2026-08-30T00:00:00.000Z',
      authoritySignature: bytes(0, 64),
    });
    const authoritySignature = await signAuthorityDelegation(
      unsigned,
      authority.privateKey,
    );
    const delegation = collaborationAuthorityDelegationSchema.parse({
      ...unsigned,
      authoritySignature,
    });
    const delegationDigest = computeAuthorityDelegationDigest(delegation);

    await expect(
      verifyAuthorityDelegation(delegation, authority.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyAuthorityDelegation(delegation, wrongAuthority.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyAuthorityDelegation(
        { ...delegation, genesisHeadDigest: bytes(38) },
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    expect(
      computeAuthorityDelegationDigest({
        ...delegation,
        authoritySignature: mutateBase64(authoritySignature),
      }),
    ).not.toBe(delegationDigest);
    expect(() =>
      computeAuthorityDelegationDigest({
        ...delegation,
        authorityRecoveryKeyFingerprint: bytes(39),
      }),
    ).toThrow();

    authority.privateKey.fill(0);
    recovery.privateKey.fill(0);
    wrongAuthority.privateKey.fill(0);
  });

  it('separates owner and authority transition signatures and finalizes an acyclic writer link', async () => {
    const owner = await generateDeviceSigningKeyPair();
    const authority = await generateDeviceSigningKeyPair();
    const wrongWriter = await generateDeviceSigningKeyPair();
    const previousStateDigest = bytes(40);
    const nextStateDigest = computeAuthorizationStateDigest(authorizationState());
    const previousTuple = tuple(1, 1, 1, previousStateDigest);
    const nextTuple = tuple(2, 2, 1, nextStateDigest);
    const transitionBase = collaborationAuthorizationTransitionSchema.parse({
      format: 'kavrix-collaborative-authorization-transition',
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      operationId: 'operation-add-member',
      operationType: 'add-member',
      previousHeadDigest: bytes(41),
      previousAuthorizationStateDigest: previousStateDigest,
      authorizationStateDigest: nextStateDigest,
      previousTuple,
      nextTuple,
      evidence: { kind: 'none' },
      issuedAt: '2026-08-30T00:00:00.000Z',
      expiresAt: '2026-08-31T00:00:00.000Z',
      transitionDigest: bytes(0),
      transitionSignature: {
        signerKind: 'owner-device',
        signerPrincipalId: 'principal-a',
        signerDeviceId: 'device-a',
        signature: bytes(0, 64),
      },
    });
    const transitionDigest = computeAuthorizationTransitionDigest(transitionBase);
    const transitionWithDigest = collaborationAuthorizationTransitionSchema.parse({
      ...transitionBase,
      transitionDigest,
    });
    const ownerSignature = await signAuthorizationTransitionOwner(
      transitionWithDigest,
      owner.privateKey,
    );
    const transition = collaborationAuthorizationTransitionSchema.parse({
      ...transitionWithDigest,
      transitionSignature: {
        ...transitionWithDigest.transitionSignature,
        signature: ownerSignature,
      },
    });

    await expect(
      verifyAuthorizationTransitionOwner(transition, owner.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyAuthorizationTransitionAuthority(transition, owner.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      signAuthorizationTransitionAuthority(transition, authority.privateKey),
    ).rejects.toThrow();
    await expect(
      verifyAuthorizationTransitionOwner(
        {
          ...transition,
          evidence: { kind: 'approval', evidenceDigest: bytes(42) },
        },
        owner.publicKeyBase64,
      ),
    ).resolves.toBe(false);

    const recoveryTransitionBase = collaborationAuthorizationTransitionSchema.parse({
      ...transitionBase,
      operationId: 'operation-recover-owner',
      operationType: 'recover-owner',
      evidence: { kind: 'authority-recovery', evidenceDigest: bytes(43) },
      transitionSignature: {
        signerKind: 'database-authority',
        authorityEpoch: 1,
        authoritySigningKeyFingerprint: computePublicKeyFingerprint(
          authority.publicKeyBase64,
          'ed25519',
        ),
        signature: bytes(0, 64),
      },
    });
    const recoveryTransitionWithDigest =
      collaborationAuthorizationTransitionSchema.parse({
        ...recoveryTransitionBase,
        transitionDigest: computeAuthorizationTransitionDigest(recoveryTransitionBase),
      });
    const recoverySignature = await signAuthorizationTransitionAuthority(
      recoveryTransitionWithDigest,
      authority.privateKey,
    );
    const recoveryTransition = collaborationAuthorizationTransitionSchema.parse({
      ...recoveryTransitionWithDigest,
      transitionSignature: {
        ...recoveryTransitionWithDigest.transitionSignature,
        signature: recoverySignature,
      },
    });
    await expect(
      verifyAuthorizationTransitionAuthority(
        recoveryTransition,
        authority.publicKeyBase64,
      ),
    ).resolves.toBe(true);
    await expect(
      verifyAuthorizationTransitionOwner(recoveryTransition, authority.publicKeyBase64),
    ).resolves.toBe(false);
    const wrongFingerprintTransitionBase = {
      ...recoveryTransition,
      transitionDigest: bytes(0),
      transitionSignature: {
        ...recoveryTransition.transitionSignature,
        authoritySigningKeyFingerprint: bytes(44),
        signature: bytes(0, 64),
      },
    };
    const wrongFingerprintTransition = collaborationAuthorizationTransitionSchema.parse(
      {
        ...wrongFingerprintTransitionBase,
        transitionDigest: computeAuthorizationTransitionDigest(
          wrongFingerprintTransitionBase,
        ),
      },
    );
    await expect(
      signAuthorizationTransitionAuthority(
        wrongFingerprintTransition,
        authority.privateKey,
      ),
    ).rejects.toThrow();
    const wrongEpochTransitionBase = {
      ...recoveryTransition,
      transitionDigest: bytes(0),
      transitionSignature: {
        ...recoveryTransition.transitionSignature,
        authorityEpoch: 2,
        signature: bytes(0, 64),
      },
    };
    const wrongEpochTransition = collaborationAuthorizationTransitionSchema.parse({
      ...wrongEpochTransitionBase,
      transitionDigest: computeAuthorizationTransitionDigest(wrongEpochTransitionBase),
    });
    await expect(
      signAuthorizationTransitionAuthority(wrongEpochTransition, authority.privateKey),
    ).rejects.toThrow();

    const commitment = collaborationMutationCommitmentSchema.parse({
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      operationId: transition.operationId,
      operationType: transition.operationType,
      requestDigest: bytes(44),
      previousHeadDigest: transition.previousHeadDigest,
      previousAuthorizationStateDigest: previousStateDigest,
      authorizationStateDigest: nextStateDigest,
      authorizationTransitionDigest: transition.transitionDigest,
      previousAuthorityEpoch: previousTuple.authorityEpoch,
      previousDocumentRevision: previousTuple.documentRevision,
      previousMembershipRevision: previousTuple.membershipRevision,
      previousPolicyRevision: previousTuple.policyRevision,
      previousKeyEpoch: previousTuple.keyEpoch,
      previousDatabaseDeviceGeneration: previousTuple.databaseDeviceGeneration,
      previousDatabaseDeviceRegistryDigest: previousTuple.databaseDeviceRegistryDigest,
      authorityEpoch: nextTuple.authorityEpoch,
      documentRevision: nextTuple.documentRevision,
      membershipRevision: nextTuple.membershipRevision,
      policyRevision: nextTuple.policyRevision,
      keyEpoch: nextTuple.keyEpoch,
      databaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
      encryptedPayloadDigest: bytes(45),
      encryptedMembershipDigest: bytes(46),
      encryptedEnvelopesDigest: bytes(47),
      policyDigest: bytes(48),
      writerPrincipalId: 'principal-a',
      writerDeviceId: 'device-a',
      timestamp: '2026-08-30T00:00:00.000Z',
    });
    const resultingHeadDigest = computeMutationHead(commitment);
    expect('authorityDelegationDigest' in commitment).toBe(false);
    expect(() =>
      computeMutationHead({
        ...commitment,
        authorityDelegationDigest: bytes(49),
      }),
    ).toThrow();
    const linkBase = collaborationFinalizedMutationLinkSchema.parse({
      format: 'kavrix-collaborative-finalized-mutation-link',
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityDelegationDigest: bytes(49),
      commitment,
      authorizationTransition: transition,
      resultingHeadDigest,
      writerSignature: {
        algorithm: 'ed25519',
        writerPrincipalId: 'principal-a',
        writerDeviceId: 'device-a',
        commitmentDigest: resultingHeadDigest,
        signature: bytes(0, 64),
      },
      finalizedAt: '2026-08-30T00:01:00.000Z',
    });
    const writerSignature = await signFinalizedMutationLink(linkBase, owner.privateKey);
    const link = collaborationFinalizedMutationLinkSchema.parse({
      ...linkBase,
      writerSignature: { ...linkBase.writerSignature, signature: writerSignature },
    });
    const linkDigest = computeFinalizedMutationLinkDigest(link);

    await expect(
      verifyFinalizedMutationLink(link, owner.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyFinalizedMutationLink(link, wrongWriter.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyFinalizedMutationLink(
        { ...link, finalizedAt: '2026-08-30T00:02:00.000Z' },
        owner.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyFinalizedMutationLink(
        { ...link, resultingHeadDigest: bytes(50) },
        owner.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    expect(
      computeFinalizedMutationLinkDigest({
        ...link,
        writerSignature: {
          ...link.writerSignature,
          signature: mutateBase64(link.writerSignature.signature),
        },
      }),
    ).not.toBe(linkDigest);

    owner.privateKey.fill(0);
    authority.privateKey.fill(0);
    wrongWriter.privateKey.fill(0);
  });

  it('signs checkpoints and enrollment receipts over immutable trust evidence', async () => {
    const ownerRoot = await generatePrincipalSigningKeyPair();
    const ownerDevice = await generateDeviceKeyPairs();
    const recipientDevice = await generateDeviceKeyPairs();
    const wrongOwner = await generateDeviceSigningKeyPair();
    const drk = Uint8Array.from({ length: 32 }, (_, index) => index ^ 0x33);
    const authority = await deriveDatabaseAuthoritySigningKeyPair(drk, 'database-a', 1);
    const recovery = await deriveDatabaseAuthorityRecoveryKeyPair(drk, 'database-a', 1);
    const stateDigest = computeAuthorizationStateDigest(authorizationState());
    const checkpointBase = collaborationAuthorizationCheckpointSchema.parse({
      format: 'kavrix-collaborative-authorization-checkpoint',
      protocolVersion: 1,
      checkpointId: 'checkpoint-a',
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityDelegationDigest: bytes(51),
      tuple: tuple(2, 2, 1, stateDigest),
      headDigest: bytes(52),
      authorizationStateDigest: stateDigest,
      finalizedMutationLinkDigest: bytes(53),
      compactedThroughDocumentRevision: 2,
      checkpointDigest: bytes(0),
      signerPrincipalId: 'principal-a',
      signerDeviceId: 'device-a',
      createdAt: '2026-08-30T00:00:00.000Z',
      ownerSignature: bytes(0, 64),
    });
    const checkpointDigest = computeAuthorizationCheckpointDigest(checkpointBase);
    const checkpointWithDigest = collaborationAuthorizationCheckpointSchema.parse({
      ...checkpointBase,
      checkpointDigest,
    });
    const checkpointSignature = await signAuthorizationCheckpoint(
      checkpointWithDigest,
      ownerDevice.signing.privateKey,
    );
    const checkpoint = collaborationAuthorizationCheckpointSchema.parse({
      ...checkpointWithDigest,
      ownerSignature: checkpointSignature,
    });
    await expect(
      verifyAuthorizationCheckpoint(checkpoint, ownerDevice.signing.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyAuthorizationCheckpoint(checkpoint, wrongOwner.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyAuthorizationCheckpoint(
        { ...checkpoint, headDigest: bytes(54) },
        ownerDevice.signing.publicKeyBase64,
      ),
    ).resolves.toBe(false);

    const delegationBase = collaborationAuthorityDelegationSchema.parse({
      format: 'kavrix-collaborative-authority-delegation',
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityEpoch: 1,
      authoritySigningPublicKey: authority.publicKeyBase64,
      authoritySigningKeyFingerprint: computePublicKeyFingerprint(
        authority.publicKeyBase64,
        'ed25519',
      ),
      authorityRecoveryPublicKey: recovery.publicKeyBase64,
      authorityRecoveryKeyFingerprint: computePublicKeyFingerprint(
        recovery.publicKeyBase64,
        'x25519',
      ),
      genesisOperationId: 'operation-genesis',
      genesisTuple: tuple(1, 1, 1, stateDigest),
      genesisHeadDigest: bytes(55),
      initialAuthorizationStateDigest: stateDigest,
      initialOwnerPrincipalId: 'principal-a',
      initialOwnerRootKeyFingerprint: computePublicKeyFingerprint(
        ownerRoot.publicKeyBase64,
        'ed25519',
      ),
      initialOwnerDeviceId: 'device-a',
      initialOwnerDeviceSigningKeyFingerprint: computePublicKeyFingerprint(
        ownerDevice.signing.publicKeyBase64,
        'ed25519',
      ),
      initialOwnerDeviceEncryptionKeyFingerprint: computePublicKeyFingerprint(
        ownerDevice.encryption.publicKeyBase64,
        'x25519',
      ),
      issuedAt: '2026-08-29T00:00:00.000Z',
      authoritySignature: bytes(0, 64),
    });
    const delegationSignature = await signAuthorityDelegation(
      delegationBase,
      authority.privateKey,
    );
    const delegation = collaborationAuthorityDelegationSchema.parse({
      ...delegationBase,
      authoritySignature: delegationSignature,
    });
    const delegationDigest = computeAuthorityDelegationDigest(delegation);
    const ownerCertificate = {
      protocolVersion: 1 as const,
      principalId: 'principal-a',
      deviceId: 'device-a',
      deviceGeneration: 1,
      signingPublicKey: ownerDevice.signing.publicKeyBase64,
      encryptionPublicKey: ownerDevice.encryption.publicKeyBase64,
      state: 'active' as const,
      createdAt: '2026-08-29T00:00:00.000Z',
      stateChangedAt: '2026-08-29T00:00:00.000Z',
      rootSignature: bytes(56, 64),
    };
    const recipientCertificate = {
      protocolVersion: 1 as const,
      principalId: 'principal-b',
      deviceId: 'device-b',
      deviceGeneration: 1,
      signingPublicKey: recipientDevice.signing.publicKeyBase64,
      encryptionPublicKey: recipientDevice.encryption.publicKeyBase64,
      state: 'active' as const,
      createdAt: '2026-08-29T00:00:00.000Z',
      stateChangedAt: '2026-08-29T00:00:00.000Z',
      rootSignature: bytes(57, 64),
    };
    const receiptBase = enrollmentReceiptSchema.parse({
      format: 'kavrix-collaborative-enrollment-receipt',
      protocolVersion: 1,
      operationType: 'add-member',
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityEpoch: 1,
      authorityDelegation: delegation,
      authorityDelegationDigest: delegationDigest,
      ownerPrincipalId: 'principal-a',
      ownerPrincipalFingerprint: bytes(58),
      ownerRootSigningPublicKey: ownerRoot.publicKeyBase64,
      ownerDeviceCertificate: ownerCertificate,
      recipientPrincipalId: 'principal-b',
      recipientPrincipalFingerprint: bytes(59),
      recipientPublicIdentity: {
        format: 'kavrix-collaborative-public-identity',
        protocolVersion: 1,
        principalId: 'principal-b',
        identityGeneration: 1,
        rootSigningPublicKey: bytes(60),
        devices: [recipientCertificate],
        createdAt: '2026-08-29T00:00:00.000Z',
        selfSignature: bytes(60, 64),
      },
      recipientDeviceId: 'device-b',
      recipientDeviceFingerprints: [bytes(61)],
      membershipId: 'membership-b',
      role: 'editor',
      discoveryTag: bytes(62),
      discoveryRecordDigest: bytes(63),
      memberKeyEnvelopeDigest: bytes(64),
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: bytes(3),
      documentRevision: 2,
      membershipRevision: 2,
      policyRevision: 1,
      keyEpoch: 2,
      headDigest: bytes(52),
      authorizationStateDigest: stateDigest,
      finalizedMutationLinkDigest: bytes(53),
      authorizationCheckpointDigest: checkpointDigest,
      issuedAt: '2026-08-30T00:00:00.000Z',
      expiresAt: '2026-09-01T00:00:00.000Z',
      ownerSignature: bytes(0, 64),
    });
    const receiptSignature = await signEnrollmentReceipt(
      receiptBase,
      ownerDevice.signing.privateKey,
    );
    const receipt = enrollmentReceiptSchema.parse({
      ...receiptBase,
      ownerSignature: receiptSignature,
    });
    await expect(
      verifyEnrollmentReceipt(receipt, ownerDevice.signing.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyEnrollmentReceipt(receipt, wrongOwner.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyEnrollmentReceipt(
        { ...receipt, authorizationCheckpointDigest: bytes(65) },
        ownerDevice.signing.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyEnrollmentReceipt(
        { ...receipt, authorityDelegationDigest: bytes(66) },
        ownerDevice.signing.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    await expect(
      verifyEnrollmentReceipt(
        { ...receipt, operationType: 'add-device' },
        ownerDevice.signing.publicKeyBase64,
      ),
    ).resolves.toBe(false);

    ownerRoot.privateKey.fill(0);
    ownerDevice.signing.privateKey.fill(0);
    ownerDevice.encryption.privateKey.fill(0);
    recipientDevice.signing.privateKey.fill(0);
    recipientDevice.encryption.privateKey.fill(0);
    wrongOwner.privateKey.fill(0);
    authority.privateKey.fill(0);
    recovery.privateKey.fill(0);
  });

  it('authenticates durable outcomes and tombstones through the writer-signed receipt', async () => {
    const writer = await generateDeviceSigningKeyPair();
    const wrongWriter = await generateDeviceSigningKeyPair();
    const priorStateDigest = bytes(67);
    const committedStateDigest = bytes(68);
    const priorTuple = tuple(1, 1, 1, priorStateDigest);
    const committedTuple = tuple(2, 2, 1, committedStateDigest);
    const receiptPlaceholder = collaborationMutationReceiptSchema.parse({
      format: 'kavrix-collaborative-mutation-receipt',
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      operationId: 'operation-receipt',
      operationType: 'add-member',
      requestDigest: bytes(69),
      actorPrincipalId: 'principal-a',
      actorDeviceId: 'device-a',
      priorTuple,
      priorHeadDigest: bytes(70),
      committedTuple,
      committedHeadDigest: bytes(71),
      finalizedMutationLinkDigest: bytes(72),
      outcomeDigest: bytes(0),
      committedAt: '2026-08-30T00:01:00.000Z',
      receiptSignature: bytes(0, 64),
    });
    const outcomePlaceholder = durableOperationOutcomeSchema.parse({
      format: 'kavrix-collaborative-operation-outcome',
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      operationId: 'operation-receipt',
      operationType: 'add-member',
      requestDigest: bytes(69),
      actorPrincipalId: 'principal-a',
      actorDeviceId: 'device-a',
      priorTuple,
      priorHeadDigest: bytes(70),
      state: 'committed',
      committedTuple,
      committedHeadDigest: bytes(71),
      finalizedMutationLinkDigest: bytes(72),
      committedAt: '2026-08-30T00:01:00.000Z',
      outcomeDigest: bytes(0),
      signedMutationReceipt: receiptPlaceholder,
      createdAt: '2026-08-30T00:00:00.000Z',
      resolvedAt: '2026-08-30T00:01:00.000Z',
      detailsRetainedUntil: '2026-09-30T00:00:00.000Z',
    });
    const outcomeDigest = computeOperationOutcomeDigest(outcomePlaceholder);
    const receiptWithDigest = collaborationMutationReceiptSchema.parse({
      ...receiptPlaceholder,
      outcomeDigest,
    });
    const receiptSignature = await signMutationReceipt(
      receiptWithDigest,
      writer.privateKey,
    );
    const receipt = collaborationMutationReceiptSchema.parse({
      ...receiptWithDigest,
      receiptSignature,
    });
    const outcome = durableOperationOutcomeSchema.parse({
      ...outcomePlaceholder,
      outcomeDigest,
      signedMutationReceipt: receipt,
    });
    expect(computeOperationOutcomeDigest(outcome)).toBe(outcomeDigest);
    await expect(verifyMutationReceipt(receipt, writer.publicKeyBase64)).resolves.toBe(
      true,
    );
    await expect(
      verifyMutationReceipt(receipt, wrongWriter.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyCommittedOperationOutcome(outcome, writer.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyCommittedOperationOutcome(
        { ...outcome, committedHeadDigest: bytes(73) },
        writer.publicKeyBase64,
      ),
    ).resolves.toBe(false);

    const tombstone = operationDeduplicationTombstoneSchema.parse({
      format: 'kavrix-collaborative-operation-tombstone',
      protocolVersion: 1,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      operationId: 'operation-receipt',
      operationType: 'add-member',
      requestDigest: bytes(69),
      outcomeDigest,
      signedMutationReceipt: receipt,
      createdAt: '2026-10-01T00:00:00.000Z',
      retainedUntilVaultDestruction: true,
    });
    const tombstoneDigest = computeOperationTombstoneDigest(tombstone);
    await expect(
      verifyOperationTombstone(tombstone, writer.publicKeyBase64),
    ).resolves.toBe(true);
    await expect(
      verifyOperationTombstone(tombstone, wrongWriter.publicKeyBase64),
    ).resolves.toBe(false);
    await expect(
      verifyOperationTombstone(
        {
          ...tombstone,
          signedMutationReceipt: {
            ...receipt,
            receiptSignature: mutateBase64(receipt.receiptSignature),
          },
        },
        writer.publicKeyBase64,
      ),
    ).resolves.toBe(false);
    expect(
      computeOperationTombstoneDigest({
        ...tombstone,
        createdAt: '2026-10-02T00:00:00.000Z',
      }),
    ).not.toBe(tombstoneDigest);

    writer.privateKey.fill(0);
    wrongWriter.privateKey.fill(0);
  });
});
