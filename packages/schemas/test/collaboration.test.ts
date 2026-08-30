import { describe, expect, it } from 'vitest';

import {
  COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT,
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
  COLLABORATIVE_MIGRATION_MARKER_FORMAT,
  COLLABORATIVE_MUTATION_PROOF_FORMAT,
  COLLABORATIVE_RECIPIENT_VAULT_DESTRUCTION_ANCHOR_FORMAT,
  COLLABORATIVE_VAULT_DESTRUCTION_CORE_FORMAT,
  COLLABORATIVE_VAULT_DESTRUCTION_TOMBSTONE_FORMAT,
  COLLABORATIVE_VAULT_FORMAT,
  MAX_COLLABORATIVE_ENCRYPTED_PAYLOAD_BYTES,
  approvalRequestSchema,
  collaborationAuthorizationCheckpointSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationTransitionSchema,
  collaborationAuthorizationWitnessSchema,
  collaborationAuthorityDelegationSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationHistoryEventTypeSchema,
  collaborationKeyEnvelopeSchema,
  collaborationMigrationActiveMarkerSchema,
  collaborationMigrationPreparedMarkerSchema,
  collaborationMigrationRequestSchema,
  collaborationMutationCommitmentSchema,
  collaborationMutationProofSchema,
  collaborationMutationReceiptSchema,
  collaborationVaultDestructionActionSchema,
  collaborationVaultDestructionCoreSchema,
  collaborationVaultDestructionTombstoneSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  deviceCertificateSchema,
  durableOperationOutcomeSchema,
  enrollmentReceiptSchema,
  membershipHistoryCheckpointSchema,
  membershipHistoryCompactionInputSchema,
  membershipHistorySchema,
  mutationOperationTypeSchema,
  operationDeduplicationTombstoneSchema,
  principalIdentitySchema,
  recipientRollbackAnchorSchema,
  recipientVaultDestructionAnchorSchema,
  transferIntentSchema,
} from '../src/index.js';

const bytes = (length: number, value: number): string =>
  Buffer.alloc(length, value).toString('base64url');
const key = (value: number): string => bytes(32, value);
const digest = (value: number): string => bytes(32, value);
const signature = (value: number): string => bytes(64, value);
const timestamp = '2026-01-01T00:00:00.000Z';
const laterTimestamp = '2026-01-02T00:00:00.000Z';
const expiryTimestamp = '2026-01-03T00:00:00.000Z';

const stateFence = {
  authorityEpoch: 1,
  databaseDeviceGeneration: 1,
  databaseDeviceRegistryDigest: digest(2),
} as const;

const deviceA = {
  protocolVersion: 1 as const,
  principalId: 'principal-a',
  deviceId: 'device-a',
  deviceGeneration: 1,
  signingPublicKey: key(1),
  encryptionPublicKey: key(2),
  state: 'active' as const,
  createdAt: timestamp,
  stateChangedAt: timestamp,
  rootSignature: signature(1),
};

const deviceB = {
  ...deviceA,
  principalId: 'principal-b',
  deviceId: 'device-b',
  signingPublicKey: key(27),
  encryptionPublicKey: key(28),
  rootSignature: signature(27),
};

const publicIdentityB = {
  format: 'kavrix-collaborative-public-identity' as const,
  protocolVersion: 1 as const,
  principalId: 'principal-b',
  identityGeneration: 1,
  rootSigningPublicKey: key(29),
  devices: [deviceB],
  createdAt: timestamp,
  selfSignature: signature(29),
};

const membershipA = {
  membershipId: 'membership-a',
  principalId: 'principal-a',
  principalFingerprint: digest(3),
  rootSigningPublicKey: key(31),
  identityGeneration: 1,
  role: 'owner' as const,
  state: 'active' as const,
  devices: [deviceA],
  createdAt: timestamp,
  updatedAt: laterTimestamp,
};

const policy = {
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  ...stateFence,
  policyRevision: 1,
  approvalPolicy: 'none' as const,
  policyDigest: digest(4),
  changedByPrincipalId: 'principal-a',
  changedByDeviceId: 'device-a',
  changedAt: timestamp,
  signature: signature(4),
};

const authorityDelegation = {
  format: 'kavrix-collaborative-authority-delegation' as const,
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  authorityEpoch: 1,
  authoritySigningPublicKey: key(40),
  authoritySigningKeyFingerprint: digest(41),
  authorityRecoveryPublicKey: key(42),
  authorityRecoveryKeyFingerprint: digest(43),
  genesisOperationId: 'operation-genesis',
  genesisTuple: {
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: stateFence.databaseDeviceRegistryDigest,
    authorizationStateDigest: digest(50),
  },
  genesisHeadDigest: digest(7),
  initialAuthorizationStateDigest: digest(50),
  initialOwnerPrincipalId: 'principal-a',
  initialOwnerRootKeyFingerprint: digest(45),
  initialOwnerDeviceId: 'device-a',
  initialOwnerDeviceSigningKeyFingerprint: digest(46),
  initialOwnerDeviceEncryptionKeyFingerprint: digest(47),
  issuedAt: timestamp,
  authoritySignature: signature(48),
};

const authorityDelegationDigest = digest(49);
const authorizationStateDigest = digest(50);
const previousAuthorizationStateDigest =
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST;
const authorizationTransitionDigest = digest(52);

const keyEnvelope = {
  format: 'kavrix-collaborative-member-key-envelope' as const,
  protocolVersion: 1 as const,
  algorithm: 'x25519-sealed-box' as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  ...stateFence,
  membershipId: 'membership-a',
  principalId: 'principal-a',
  deviceId: 'device-a',
  recipientEncryptionKeyFingerprint: digest(11),
  keyEpoch: 1,
  membershipRevision: 1,
  sealedVaultRootKey: bytes(80, 12),
  envelopeDigest: digest(13),
  createdAt: timestamp,
  ownerSignature: signature(7),
};

const authorityRecoveryEnvelope = {
  format: 'kavrix-collaborative-authority-recovery-envelope' as const,
  protocolVersion: 1 as const,
  algorithm: 'x25519-sealed-box' as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  authorityEpoch: 1,
  authorityRecoveryKeyFingerprint: authorityDelegation.authorityRecoveryKeyFingerprint,
  keyEpoch: 1,
  membershipRevision: 1,
  databaseDeviceGeneration: 1,
  databaseDeviceRegistryDigest: stateFence.databaseDeviceRegistryDigest,
  sealedVaultRootKey: bytes(80, 53),
  envelopeDigest: digest(54),
  sealedByPrincipalId: 'principal-a',
  sealedByDeviceId: 'device-a',
  createdAt: timestamp,
  ownerSignature: signature(55),
};

const authorizationMembershipA = {
  ...membershipA,
  devices: [
    {
      protocolVersion: deviceA.protocolVersion,
      principalId: deviceA.principalId,
      deviceId: deviceA.deviceId,
      deviceGeneration: deviceA.deviceGeneration,
      signingPublicKey: deviceA.signingPublicKey,
      encryptionPublicKey: deviceA.encryptionPublicKey,
      state: deviceA.state,
      createdAt: deviceA.createdAt,
      stateChangedAt: deviceA.stateChangedAt,
    },
  ],
};

const authorizationKeyEnvelope = {
  format: keyEnvelope.format,
  protocolVersion: keyEnvelope.protocolVersion,
  algorithm: keyEnvelope.algorithm,
  databaseId: keyEnvelope.databaseId,
  vaultId: keyEnvelope.vaultId,
  authorityEpoch: keyEnvelope.authorityEpoch,
  membershipId: keyEnvelope.membershipId,
  principalId: keyEnvelope.principalId,
  deviceId: keyEnvelope.deviceId,
  recipientEncryptionKeyFingerprint: keyEnvelope.recipientEncryptionKeyFingerprint,
  keyEpoch: keyEnvelope.keyEpoch,
  membershipRevision: keyEnvelope.membershipRevision,
  databaseDeviceGeneration: keyEnvelope.databaseDeviceGeneration,
  databaseDeviceRegistryDigest: keyEnvelope.databaseDeviceRegistryDigest,
  sealedVaultRootKey: keyEnvelope.sealedVaultRootKey,
};

const authorizationRecoveryEnvelope = {
  format: authorityRecoveryEnvelope.format,
  protocolVersion: authorityRecoveryEnvelope.protocolVersion,
  algorithm: authorityRecoveryEnvelope.algorithm,
  databaseId: authorityRecoveryEnvelope.databaseId,
  vaultId: authorityRecoveryEnvelope.vaultId,
  authorityEpoch: authorityRecoveryEnvelope.authorityEpoch,
  authorityRecoveryKeyFingerprint:
    authorityRecoveryEnvelope.authorityRecoveryKeyFingerprint,
  keyEpoch: authorityRecoveryEnvelope.keyEpoch,
  membershipRevision: authorityRecoveryEnvelope.membershipRevision,
  databaseDeviceGeneration: authorityRecoveryEnvelope.databaseDeviceGeneration,
  databaseDeviceRegistryDigest: authorityRecoveryEnvelope.databaseDeviceRegistryDigest,
  sealedVaultRootKey: authorityRecoveryEnvelope.sealedVaultRootKey,
  sealedByPrincipalId: authorityRecoveryEnvelope.sealedByPrincipalId,
  sealedByDeviceId: authorityRecoveryEnvelope.sealedByDeviceId,
};

const previousTuple = {
  ...stateFence,
  documentRevision: 0,
  membershipRevision: 0,
  policyRevision: 0,
  keyEpoch: 1,
  authorizationStateDigest: previousAuthorizationStateDigest,
} as const;

const committedTuple = {
  ...stateFence,
  documentRevision: 1,
  membershipRevision: 1,
  policyRevision: 1,
  keyEpoch: 1,
  authorizationStateDigest,
} as const;

const authorizationTransition = {
  format: 'kavrix-collaborative-authorization-transition' as const,
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  operationId: 'operation-genesis',
  operationType: 'genesis-migration' as const,
  previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
  previousAuthorizationStateDigest,
  authorizationStateDigest,
  previousTuple,
  nextTuple: committedTuple,
  evidence: { kind: 'none' as const },
  issuedAt: timestamp,
  expiresAt: expiryTimestamp,
  transitionDigest: authorizationTransitionDigest,
  transitionSignature: {
    signerKind: 'owner-device' as const,
    signerPrincipalId: 'principal-a',
    signerDeviceId: 'device-a',
    signature: signature(56),
  },
};

const history = {
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  ...stateFence,
  events: [
    {
      protocolVersion: 1 as const,
      operationId: 'operation-genesis',
      eventType: 'genesis-created' as const,
      actorPrincipalId: 'principal-a',
      actorDeviceId: 'device-a',
      targetPrincipalId: 'principal-a',
      targetDeviceId: 'device-a',
      newRole: 'owner' as const,
      newState: 'active' as const,
      previousDocumentRevision: 0,
      newDocumentRevision: 1,
      previousMembershipRevision: 0,
      newMembershipRevision: 1,
      previousPolicyRevision: 0,
      newPolicyRevision: 1,
      previousKeyEpoch: 1,
      newKeyEpoch: 1,
      previousAuthorityEpoch: 1,
      newAuthorityEpoch: 1,
      previousDatabaseDeviceGeneration: 1,
      newDatabaseDeviceGeneration: 1,
      previousDatabaseDeviceRegistryDigest: stateFence.databaseDeviceRegistryDigest,
      newDatabaseDeviceRegistryDigest: stateFence.databaseDeviceRegistryDigest,
      previousAuthorizationStateDigest,
      newAuthorizationStateDigest: authorizationStateDigest,
      previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
      timestamp,
      signature: signature(9),
    },
  ],
  checkpoints: [],
  compactedThroughRevision: 0,
  compactedHistoryDigest: COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
  previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
  previousHistoryDigest: COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  currentHistoryDigest: digest(10),
};

const manifest = {
  format: 'kavrix-collaborative-membership-manifest' as const,
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  ...stateFence,
  documentRevision: 1,
  membershipRevision: 1,
  policyRevision: 1,
  keyEpoch: 1,
  authorizationStateDigest,
  memberships: [membershipA],
  ownerPrincipalIds: ['principal-a'],
  keyEnvelopes: [keyEnvelope, authorityRecoveryEnvelope],
  approvalPolicy: 'none' as const,
  policy,
  pendingApprovals: [],
  pendingTransfers: [],
  history,
  previousMembershipDigest: COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
  membershipDigest: digest(15),
  previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
  createdAt: timestamp,
  updatedAt: laterTimestamp,
};

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

const membershipAad = {
  ...aad,
  entityType: 'membership-manifest' as const,
  metadataDigest: digest(17),
};

const mutationCommitment = {
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  operationId: 'operation-genesis',
  operationType: 'genesis-migration' as const,
  requestDigest: digest(25),
  previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
  previousAuthorizationStateDigest,
  authorizationStateDigest,
  authorizationTransitionDigest,
  previousAuthorityEpoch: 1,
  previousDocumentRevision: 0,
  previousMembershipRevision: 0,
  previousPolicyRevision: 0,
  previousKeyEpoch: 1,
  previousDatabaseDeviceGeneration: 1,
  previousDatabaseDeviceRegistryDigest: stateFence.databaseDeviceRegistryDigest,
  ...stateFence,
  documentRevision: 1,
  membershipRevision: 1,
  policyRevision: 1,
  keyEpoch: 1,
  encryptedPayloadDigest: digest(16),
  encryptedMembershipDigest: digest(17),
  encryptedEnvelopesDigest: digest(18),
  policyDigest: policy.policyDigest,
  writerPrincipalId: 'principal-a',
  writerDeviceId: 'device-a',
  timestamp,
};

const currentMutationLink = {
  format: 'kavrix-collaborative-finalized-mutation-link' as const,
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  authorityDelegationDigest,
  commitment: mutationCommitment,
  authorizationTransition,
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

const document = {
  format: COLLABORATIVE_VAULT_FORMAT,
  documentVersion: 1 as const,
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  ...stateFence,
  documentRevision: 1,
  membershipRevision: 1,
  policyRevision: 1,
  keyEpoch: 1,
  previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
  headDigest: digest(7),
  authorityDelegation,
  authorityDelegationDigest,
  authorizationStateDigest,
  encryptedPayloadDigest: digest(16),
  encryptedMembershipDigest: digest(17),
  encryptedEnvelopesDigest: digest(18),
  policyDigest: policy.policyDigest,
  databaseAuthorityRecoveryEnvelope: authorityRecoveryEnvelope,
  encryptedPayload: {
    version: 1 as const,
    algorithm: 'xchacha20-poly1305-ietf' as const,
    nonce: bytes(24, 19),
    ciphertext: bytes(64, 20),
    authenticationTag: bytes(16, 21),
    aad,
  },
  encryptedMembershipManifest: {
    version: 1 as const,
    algorithm: 'xchacha20-poly1305-ietf' as const,
    nonce: bytes(24, 22),
    ciphertext: bytes(64, 23),
    authenticationTag: bytes(16, 24),
    aad: membershipAad,
  },
  discoveryRecords: [],
  currentMutationLink,
  createdAt: timestamp,
  updatedAt: laterTimestamp,
};

const ordinaryCommitment = {
  ...mutationCommitment,
  operationId: 'operation-ordinary',
  operationType: 'ordinary-write' as const,
  requestDigest: digest(73),
  previousHeadDigest: document.headDigest,
  previousAuthorizationStateDigest: authorizationStateDigest,
  authorizationStateDigest,
  authorizationTransitionDigest: undefined,
  previousDocumentRevision: 1,
  previousMembershipRevision: 1,
  previousPolicyRevision: 1,
  previousKeyEpoch: 1,
  previousDatabaseDeviceGeneration: 1,
  previousDatabaseDeviceRegistryDigest: stateFence.databaseDeviceRegistryDigest,
  documentRevision: 2,
  membershipRevision: 1,
  policyRevision: 1,
  keyEpoch: 1,
  encryptedPayloadDigest: digest(74),
  timestamp: laterTimestamp,
};

const ordinaryLink = {
  format: 'kavrix-collaborative-finalized-mutation-link' as const,
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  authorityDelegationDigest,
  commitment: ordinaryCommitment,
  resultingHeadDigest: digest(75),
  writerSignature: {
    algorithm: 'ed25519' as const,
    writerPrincipalId: 'principal-a',
    writerDeviceId: 'device-a',
    commitmentDigest: digest(75),
    signature: signature(76),
  },
  finalizedAt: laterTimestamp,
};

const ordinaryCommitmentTwo = {
  ...ordinaryCommitment,
  operationId: 'operation-ordinary-two',
  requestDigest: digest(77),
  previousHeadDigest: ordinaryLink.resultingHeadDigest,
  previousDocumentRevision: 2,
  documentRevision: 3,
  encryptedPayloadDigest: digest(78),
  timestamp: expiryTimestamp,
};

const ordinaryLinkTwo = {
  ...ordinaryLink,
  commitment: ordinaryCommitmentTwo,
  resultingHeadDigest: digest(79),
  writerSignature: {
    ...ordinaryLink.writerSignature,
    commitmentDigest: digest(79),
    signature: signature(80),
  },
};

const witnessDeviceRegistry = {
  format: 'kavrix-collaborative-device-registry' as const,
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  authorityEpoch: 1,
  authorityFingerprint: authorityDelegation.authoritySigningKeyFingerprint,
  generation: stateFence.databaseDeviceGeneration,
  previousRegistryDigest: digest(65),
  registryDigest: stateFence.databaseDeviceRegistryDigest,
  deniedDevices: [],
  updatedAt: laterTimestamp,
  authoritySignature: signature(66),
};

const authorizationWitness = {
  format: COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT,
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  authorityDelegationDigest,
  tuple: committedTuple,
  previousHeadDigest: mutationCommitment.previousHeadDigest,
  headDigest: currentMutationLink.resultingHeadDigest,
  encryptedMembershipDigest: mutationCommitment.encryptedMembershipDigest,
  encryptedEnvelopesDigest: mutationCommitment.encryptedEnvelopesDigest,
  policyDigest: mutationCommitment.policyDigest,
  databaseDeviceRegistry: witnessDeviceRegistry,
  databaseAuthorityRecoveryEnvelope: authorityRecoveryEnvelope,
  encryptedMembershipManifest: document.encryptedMembershipManifest,
  discoveryRecords: [],
  finalizedMutationLinkDigest: digest(81),
};

const startingAuthorizationWitness = {
  ...authorizationWitness,
  tuple: previousTuple,
  databaseAuthorityRecoveryEnvelope: {
    ...authorityRecoveryEnvelope,
    membershipRevision: previousTuple.membershipRevision,
  },
  previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
  headDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
  encryptedMembershipManifest: {
    ...authorizationWitness.encryptedMembershipManifest,
    aad: {
      ...authorizationWitness.encryptedMembershipManifest.aad,
      ...previousTuple,
    },
  },
  finalizedMutationLinkDigest: digest(82),
};

const destructionTerminalTuple = {
  ...committedTuple,
  documentRevision: committedTuple.documentRevision + 1,
};
const destroyedPayloadDigest = digest(83);
const destructionTerminalHeadDigest = digest(84);
const destructionFinalizedLinkDigest = digest(85);
const destructionOutcomeDigest = digest(86);
const destructionAction = {
  protocolVersion: 1 as const,
  operationType: 'destroy-vault' as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  destructionMode: 'irreversible' as const,
};
const destructionCore = {
  format: COLLABORATIVE_VAULT_DESTRUCTION_CORE_FORMAT,
  protocolVersion: 1 as const,
  databaseId: 'database-a',
  vaultId: 'vault-a',
  operationId: 'operation-destroy',
  authorityEpoch: 1,
  authorityDelegationDigest,
  priorTuple: committedTuple,
  priorHeadDigest: document.headDigest,
  terminalTuple: destructionTerminalTuple,
  actionParametersDigest: digest(87),
  actorPrincipalId: 'principal-a',
  actorDeviceId: 'device-a',
  destructionMode: 'irreversible' as const,
  destroyedAt: laterTimestamp,
};
const destructionTransition = {
  ...authorizationTransition,
  operationId: destructionCore.operationId,
  operationType: 'destroy-vault' as const,
  previousHeadDigest: destructionCore.priorHeadDigest,
  previousAuthorizationStateDigest: authorizationStateDigest,
  authorizationStateDigest,
  previousTuple: committedTuple,
  nextTuple: destructionTerminalTuple,
  transitionDigest: digest(88),
};
const destructionCommitment = {
  ...ordinaryCommitment,
  operationId: destructionCore.operationId,
  operationType: 'destroy-vault' as const,
  requestDigest: digest(89),
  authorizationTransitionDigest: destructionTransition.transitionDigest,
  encryptedPayloadDigest: destroyedPayloadDigest,
  timestamp: destructionCore.destroyedAt,
};
const destructionLink = {
  ...ordinaryLink,
  commitment: destructionCommitment,
  authorizationTransition: destructionTransition,
  resultingHeadDigest: destructionTerminalHeadDigest,
  writerSignature: {
    ...ordinaryLink.writerSignature,
    commitmentDigest: destructionTerminalHeadDigest,
    signature: signature(90),
  },
  finalizedAt: destructionCore.destroyedAt,
};
const destructionAuthorizationWitness = {
  ...authorizationWitness,
  tuple: destructionTerminalTuple,
  databaseAuthorityRecoveryEnvelope: {
    ...authorityRecoveryEnvelope,
    membershipRevision: destructionTerminalTuple.membershipRevision,
    keyEpoch: destructionTerminalTuple.keyEpoch,
    databaseDeviceGeneration: destructionTerminalTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: destructionTerminalTuple.databaseDeviceRegistryDigest,
  },
  previousHeadDigest: destructionCore.priorHeadDigest,
  headDigest: destructionTerminalHeadDigest,
  encryptedMembershipDigest: destructionCommitment.encryptedMembershipDigest,
  encryptedEnvelopesDigest: destructionCommitment.encryptedEnvelopesDigest,
  policyDigest: destructionCommitment.policyDigest,
  encryptedMembershipManifest: {
    ...authorizationWitness.encryptedMembershipManifest,
    aad: {
      ...authorizationWitness.encryptedMembershipManifest.aad,
      ...destructionTerminalTuple,
    },
  },
  finalizedMutationLinkDigest: destructionFinalizedLinkDigest,
};
const destructionReceipt = {
  format: 'kavrix-collaborative-mutation-receipt' as const,
  protocolVersion: 1 as const,
  databaseId: destructionCore.databaseId,
  vaultId: destructionCore.vaultId,
  operationId: destructionCore.operationId,
  operationType: 'destroy-vault' as const,
  requestDigest: destructionCommitment.requestDigest,
  actorPrincipalId: destructionCore.actorPrincipalId,
  actorDeviceId: destructionCore.actorDeviceId,
  priorTuple: destructionCore.priorTuple,
  priorHeadDigest: destructionCore.priorHeadDigest,
  committedTuple: destructionCore.terminalTuple,
  committedHeadDigest: destructionTerminalHeadDigest,
  finalizedMutationLinkDigest: destructionFinalizedLinkDigest,
  outcomeDigest: destructionOutcomeDigest,
  committedAt: destructionCore.destroyedAt,
  receiptSignature: signature(91),
};
const destructionTombstone = {
  format: COLLABORATIVE_VAULT_DESTRUCTION_TOMBSTONE_FORMAT,
  protocolVersion: 1 as const,
  databaseId: destructionCore.databaseId,
  vaultId: destructionCore.vaultId,
  core: destructionCore,
  destroyedPayloadDigest,
  terminalHeadDigest: destructionTerminalHeadDigest,
  proofEntry: {
    link: destructionLink,
    authorizationWitness: destructionAuthorizationWitness,
  },
  outcomeDigest: destructionOutcomeDigest,
  signedMutationReceipt: destructionReceipt,
};
const destructionAnchor = {
  format: COLLABORATIVE_RECIPIENT_VAULT_DESTRUCTION_ANCHOR_FORMAT,
  protocolVersion: 1 as const,
  databaseId: destructionCore.databaseId,
  vaultId: destructionCore.vaultId,
  principalId: 'principal-a',
  deviceId: 'device-a',
  authorityEpoch: destructionCore.authorityEpoch,
  authorityDelegationDigest,
  operationId: destructionCore.operationId,
  priorTuple: destructionCore.priorTuple,
  priorHeadDigest: destructionCore.priorHeadDigest,
  terminalTuple: destructionCore.terminalTuple,
  terminalHeadDigest: destructionTerminalHeadDigest,
  destroyedPayloadDigest,
  finalizedMutationLinkDigest: destructionFinalizedLinkDigest,
  outcomeDigest: destructionOutcomeDigest,
  destroyedAt: destructionCore.destroyedAt,
};

const legacyVault = {
  databaseId: 'database-a',
  id: 'vault-a',
  schemaVersion: 1 as const,
  cryptographicVersion: 1 as const,
  currentKeyVersion: 1,
  databaseRevision: 1,
  revision: 1,
  wrappedVaultRoot: {
    version: 1 as const,
    algorithm: 'xchacha20-poly1305-ietf' as const,
    nonce: bytes(24, 57),
    ciphertext: bytes(64, 58),
    authenticationTag: bytes(16, 59),
    aad: {
      version: 1 as const,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      entityType: 'wrapped-vault-root' as const,
      entityId: 'vault-a',
      purpose: 'vault-root' as const,
      schemaVersion: 1 as const,
      keyVersion: 1,
      revision: 1,
      metadataDigest: digest(60),
    },
    keyVersion: 1,
  },
  encryptedPayload: {
    version: 1 as const,
    algorithm: 'xchacha20-poly1305-ietf' as const,
    nonce: bytes(24, 61),
    ciphertext: bytes(64, 62),
    authenticationTag: bytes(16, 63),
    aad: {
      version: 1 as const,
      schemaVersion: 1 as const,
      keyVersion: 1,
      vaultId: 'vault-a',
      entityType: 'vault-preferences' as const,
      entityId: 'vault-a',
      purpose: 'vault-preferences' as const,
      revision: 1,
      metadataDigest: digest(64),
    },
    keyVersion: 1,
  },
  payloadMetadataDigest: digest(64),
  createdAt: timestamp,
  updatedAt: laterTimestamp,
};

const deviceRegistry = witnessDeviceRegistry;

describe('collaboration schemas', () => {
  it('accepts add-device and strictly binds an exact history compaction input', () => {
    expect(mutationOperationTypeSchema.parse('add-device')).toBe('add-device');
    expect(mutationOperationTypeSchema.safeParse('add-device-unchecked').success).toBe(
      false,
    );

    const compactionInput = {
      protocolVersion: 1 as const,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityEpoch: 1,
      compactingOperationId: 'operation-compact-a',
      previousHeadDigest: document.headDigest,
      previousTuple: committedTuple,
      priorHistory: history,
    };
    expect(membershipHistoryCompactionInputSchema.parse(compactionInput)).toEqual(
      compactionInput,
    );
    expect(
      membershipHistoryCompactionInputSchema.safeParse({
        ...compactionInput,
        unexpectedTrustFlag: true,
      }).success,
    ).toBe(false);
    expect(
      membershipHistoryCompactionInputSchema.safeParse({
        ...compactionInput,
        databaseId: 'database-substituted',
      }).success,
    ).toBe(false);
    expect(
      membershipHistoryCompactionInputSchema.safeParse({
        ...compactionInput,
        authorityEpoch: 2,
      }).success,
    ).toBe(false);
    expect(
      membershipHistoryCompactionInputSchema.safeParse({
        ...compactionInput,
        previousTuple: {
          ...compactionInput.previousTuple,
          databaseDeviceRegistryDigest: digest(99),
        },
      }).success,
    ).toBe(false);
    expect(
      membershipHistoryCompactionInputSchema.safeParse({
        ...compactionInput,
        priorHistory: {
          ...compactionInput.priorHistory,
          events: [
            {
              ...compactionInput.priorHistory.events[0],
              newDocumentRevision: committedTuple.documentRevision + 1,
            },
          ],
        },
      }).success,
    ).toBe(false);
  });

  it('parses only the exact irreversible destruction core, tombstone, and recipient anchor', () => {
    expect(collaborationHistoryEventTypeSchema.parse('vault-destroyed')).toBe(
      'vault-destroyed',
    );
    expect(collaborationVaultDestructionCoreSchema.parse(destructionCore)).toEqual(
      destructionCore,
    );
    expect(collaborationVaultDestructionActionSchema.parse(destructionAction)).toEqual(
      destructionAction,
    );
    for (const field of Object.keys(destructionAction)) {
      const missing = { ...destructionAction } as Record<string, unknown>;
      Reflect.deleteProperty(missing, field);
      expect(collaborationVaultDestructionActionSchema.safeParse(missing).success).toBe(
        false,
      );
    }
    expect(
      collaborationVaultDestructionTombstoneSchema.parse(destructionTombstone),
    ).toEqual(destructionTombstone);
    expect(recipientVaultDestructionAnchorSchema.parse(destructionAnchor)).toEqual(
      destructionAnchor,
    );

    expect(
      collaborationVaultDestructionActionSchema.safeParse({
        ...destructionAction,
        destructionMode: 'recoverable',
      }).success,
    ).toBe(false);
    expect(
      collaborationVaultDestructionActionSchema.safeParse({
        ...destructionAction,
        operationType: 'ordinary-write',
      }).success,
    ).toBe(false);
    expect(
      collaborationVaultDestructionActionSchema.safeParse({
        ...destructionAction,
        confirmationPhrase: 'destroy',
      }).success,
    ).toBe(false);
    expect(
      collaborationVaultDestructionCoreSchema.safeParse({
        ...destructionCore,
        terminalHeadDigest: destructionTerminalHeadDigest,
      }).success,
    ).toBe(false);
    expect(
      collaborationVaultDestructionCoreSchema.safeParse({
        ...destructionCore,
        terminalTuple: {
          ...destructionCore.terminalTuple,
          membershipRevision: destructionCore.terminalTuple.membershipRevision + 1,
        },
      }).success,
    ).toBe(false);
    expect(
      collaborationAuthorizationTransitionSchema.safeParse({
        ...destructionTransition,
        authorizationStateDigest: digest(92),
        nextTuple: {
          ...destructionTransition.nextTuple,
          authorizationStateDigest: digest(92),
        },
      }).success,
    ).toBe(false);
    expect(
      collaborationMutationCommitmentSchema.safeParse({
        ...destructionCommitment,
        authorizationStateDigest: digest(92),
      }).success,
    ).toBe(false);
  });

  it('rejects destruction scope, tuple, head, proof-link, and receipt substitution', () => {
    const rejects = (candidate: unknown): void => {
      expect(
        collaborationVaultDestructionTombstoneSchema.safeParse(candidate).success,
      ).toBe(false);
    };

    rejects({ ...destructionTombstone, databaseId: 'database-substituted' });
    rejects({
      ...destructionTombstone,
      destroyedPayloadDigest: digest(93),
    });
    rejects({
      ...destructionTombstone,
      terminalHeadDigest: digest(94),
    });
    rejects({
      ...destructionTombstone,
      core: {
        ...destructionCore,
        operationId: 'operation-destroy-substituted',
      },
    });
    rejects({
      ...destructionTombstone,
      proofEntry: {
        ...destructionTombstone.proofEntry,
        authorizationWitness: {
          ...destructionAuthorizationWitness,
          finalizedMutationLinkDigest: digest(95),
        },
      },
    });
    rejects({
      ...destructionTombstone,
      signedMutationReceipt: {
        ...destructionReceipt,
        state: 'rejected',
      },
    });
    rejects({
      ...destructionTombstone,
      signedMutationReceipt: {
        ...destructionReceipt,
        outcomeDigest: digest(96),
      },
    });
    rejects({
      ...destructionTombstone,
      signedMutationReceipt: {
        ...destructionReceipt,
        committedTuple: {
          ...destructionReceipt.committedTuple,
          documentRevision: destructionReceipt.committedTuple.documentRevision + 1,
        },
      },
    });
    rejects({
      ...destructionTombstone,
      proofEntry: { link: destructionLink },
    });
    rejects({
      ...destructionTombstone,
      proofEntry: {
        ...destructionTombstone.proofEntry,
        link: {
          ...destructionLink,
          authorityDelegationDigest: digest(97),
        },
      },
    });

    expect(
      collaborationVaultDestructionTombstoneSchema.safeParse(document).success,
    ).toBe(false);
    expect(
      collaborativeVaultDocumentSchema.safeParse(destructionTombstone).success,
    ).toBe(false);
    expect(
      recipientVaultDestructionAnchorSchema.safeParse({
        ...destructionAnchor,
        terminalTuple: {
          ...destructionAnchor.terminalTuple,
          policyRevision: destructionAnchor.terminalTuple.policyRevision + 1,
        },
      }).success,
    ).toBe(false);
    expect(
      recipientVaultDestructionAnchorSchema.safeParse({
        ...destructionAnchor,
        trustedWithoutProof: true,
      }).success,
    ).toBe(false);
  });

  it('parses the immutable authority delegation and authorization-state core', () => {
    expect(collaborationAuthorityDelegationSchema.parse(authorityDelegation)).toEqual(
      authorityDelegation,
    );
    expect(
      collaborationAuthorizationStateCoreSchema.parse({
        protocolVersion: 1,
        databaseId: 'database-a',
        vaultId: 'vault-a',
        ...stateFence,
        membershipRevision: 1,
        policyRevision: 1,
        keyEpoch: 1,
        memberships: [authorizationMembershipA],
        ownerPrincipalIds: ['principal-a'],
        keyEnvelopes: [authorizationKeyEnvelope, authorizationRecoveryEnvelope],
        approvalPolicy: 'none',
      }),
    ).toBeTruthy();
  });

  it('parses a complete genesis document, manifest, link, anchor, and artifacts', () => {
    expect(collaborativeVaultDocumentSchema.parse(document)).toEqual(document);
    expect(collaborativeMembershipManifestSchema.parse(manifest)).toEqual(manifest);
    expect(collaborationFinalizedMutationLinkSchema.parse(currentMutationLink)).toEqual(
      currentMutationLink,
    );
    expect(
      principalIdentitySchema.parse({
        format: 'kavrix-collaborative-principal-identity',
        protocolVersion: 1,
        principalId: 'principal-a',
        identityGeneration: 1,
        rootSigningPublicKey: key(30),
        state: 'active',
        devices: [deviceA],
        createdAt: timestamp,
        selfSignature: signature(30),
      }),
    ).toBeTruthy();
    expect(deviceCertificateSchema.parse(deviceA)).toEqual(deviceA);
    expect(collaborationDatabaseDeviceRegistrySchema.parse(deviceRegistry)).toEqual(
      deviceRegistry,
    );
    expect(collaborationKeyEnvelopeSchema.parse(keyEnvelope)).toEqual(keyEnvelope);
    expect(
      databaseAuthorityRecoveryEnvelopeSchema.parse(authorityRecoveryEnvelope),
    ).toEqual(authorityRecoveryEnvelope);
    expect(membershipHistorySchema.parse(history)).toEqual(history);
    const historyCheckpoint = {
      protocolVersion: 1 as const,
      checkpointId: 'history-checkpoint-a',
      authorityEpoch: 1,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: stateFence.databaseDeviceRegistryDigest,
      membershipRevision: 1,
      documentRevision: 1,
      policyRevision: 1,
      keyEpoch: 1,
      previousHeadDigest: document.previousHeadDigest,
      compactedThroughRevision: 1,
      compactedHistoryDigest: history.currentHistoryDigest,
      signerPrincipalId: 'principal-a',
      signerDeviceId: 'device-a',
      createdAt: laterTimestamp,
      signature: signature(69),
    };
    expect(membershipHistoryCheckpointSchema.parse(historyCheckpoint)).toEqual(
      historyCheckpoint,
    );
    const { signerDeviceId: omittedSignerDevice, ...missingSigner } = historyCheckpoint;
    void omittedSignerDevice;
    expect(membershipHistoryCheckpointSchema.safeParse(missingSigner).success).toBe(
      false,
    );
    expect(
      collaborationAuthorizationCheckpointSchema.parse({
        format: 'kavrix-collaborative-authorization-checkpoint',
        protocolVersion: 1,
        checkpointId: 'checkpoint-a',
        databaseId: 'database-a',
        vaultId: 'vault-a',
        authorityDelegationDigest,
        tuple: committedTuple,
        headDigest: document.headDigest,
        authorizationStateDigest,
        finalizedMutationLinkDigest: digest(67),
        compactedThroughDocumentRevision: 1,
        checkpointDigest: digest(68),
        signerPrincipalId: 'principal-a',
        signerDeviceId: 'device-a',
        createdAt: laterTimestamp,
        ownerSignature: signature(68),
      }),
    ).toBeTruthy();
    expect(
      recipientRollbackAnchorSchema.parse({
        format: 'kavrix-collaborative-recipient-rollback-anchor',
        protocolVersion: 1,
        databaseId: 'database-a',
        vaultId: 'vault-a',
        principalId: 'principal-a',
        deviceId: 'device-a',
        authorityEpoch: 1,
        authorityDelegationDigest,
        databaseDeviceGeneration: 1,
        databaseDeviceRegistryDigest: stateFence.databaseDeviceRegistryDigest,
        membershipRevision: 1,
        membershipDigest: manifest.membershipDigest,
        policyRevision: 1,
        policyDigest: policy.policyDigest,
        keyEpoch: 1,
        documentRevision: 1,
        encryptedPayloadDigest: digest(69),
        headDigest: document.headDigest,
        authorizationStateDigest,
        finalizedMutationLinkDigest: digest(67),
        updatedAt: laterTimestamp,
      }),
    ).toBeTruthy();
  });

  it('rejects unsupported versions, legacy revisions, and positive registry allowlists', () => {
    expect(
      collaborativeVaultDocumentSchema.safeParse({ ...document, protocolVersion: 2 })
        .success,
    ).toBe(false);
    expect(
      collaborativeVaultDocumentSchema.safeParse({ ...document, documentVersion: 2 })
        .success,
    ).toBe(false);
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        format: 'kavrix-encrypted-database',
      }).success,
    ).toBe(false);
    expect(
      collaborativeVaultDocumentSchema.safeParse({ ...document, revision: 1 }).success,
    ).toBe(false);
    expect(
      collaborationDatabaseDeviceRegistrySchema.safeParse({
        ...deviceRegistry,
        devices: [deviceA],
      }).success,
    ).toBe(false);
  });

  it('requires one strict outer recovery envelope bound to the live document tuple', () => {
    const missingOuter = structuredClone(document) as Record<string, unknown>;
    Reflect.deleteProperty(missingOuter, 'databaseAuthorityRecoveryEnvelope');
    expect(collaborativeVaultDocumentSchema.safeParse(missingOuter).success).toBe(
      false,
    );
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        unexpectedOuterRecoveryEnvelope: document.databaseAuthorityRecoveryEnvelope,
      }).success,
    ).toBe(false);
    for (const substituted of [
      { databaseId: 'database-substituted' },
      { vaultId: 'vault-substituted' },
      { authorityEpoch: 2 },
      { authorityRecoveryKeyFingerprint: digest(99) },
      { keyEpoch: 2 },
      { membershipRevision: 2 },
      { databaseDeviceGeneration: 2 },
      { databaseDeviceRegistryDigest: digest(99) },
    ]) {
      expect(
        collaborativeVaultDocumentSchema.safeParse({
          ...document,
          databaseAuthorityRecoveryEnvelope: {
            ...document.databaseAuthorityRecoveryEnvelope,
            ...substituted,
          },
        }).success,
      ).toBe(false);
    }
  });

  it('requires one strict outer recovery envelope bound to an authorization witness', () => {
    const missingOuter = structuredClone(authorizationWitness) as Record<
      string,
      unknown
    >;
    Reflect.deleteProperty(missingOuter, 'databaseAuthorityRecoveryEnvelope');
    expect(
      collaborationAuthorizationWitnessSchema.safeParse(missingOuter).success,
    ).toBe(false);
    expect(
      collaborationAuthorizationWitnessSchema.safeParse({
        ...authorizationWitness,
        unexpectedOuterRecoveryEnvelope:
          authorizationWitness.databaseAuthorityRecoveryEnvelope,
      }).success,
    ).toBe(false);
    for (const substituted of [
      { protocolVersion: 2 },
      { databaseId: 'database-substituted' },
      { vaultId: 'vault-substituted' },
      { authorityEpoch: 2 },
      { keyEpoch: 2 },
      { membershipRevision: 2 },
      { databaseDeviceGeneration: 2 },
      { databaseDeviceRegistryDigest: digest(95) },
    ]) {
      expect(
        collaborationAuthorizationWitnessSchema.safeParse({
          ...authorizationWitness,
          databaseAuthorityRecoveryEnvelope: {
            ...authorizationWitness.databaseAuthorityRecoveryEnvelope,
            ...substituted,
          },
        }).success,
      ).toBe(false);
    }
  });

  it('rejects caller-selected genesis predecessor digests', () => {
    const nonCanonicalAuthorizationState = digest(51);
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        currentMutationLink: {
          ...document.currentMutationLink,
          commitment: {
            ...document.currentMutationLink.commitment,
            previousAuthorizationStateDigest: nonCanonicalAuthorizationState,
          },
          authorizationTransition: {
            ...authorizationTransition,
            previousAuthorizationStateDigest: nonCanonicalAuthorizationState,
            previousTuple: {
              ...authorizationTransition.previousTuple,
              authorizationStateDigest: nonCanonicalAuthorizationState,
            },
          },
        },
      }).success,
    ).toBe(false);
    expect(
      collaborativeMembershipManifestSchema.safeParse({
        ...manifest,
        previousMembershipDigest: digest(14),
      }).success,
    ).toBe(false);
    expect(
      collaborativeMembershipManifestSchema.safeParse({
        ...manifest,
        history: {
          ...manifest.history,
          previousHistoryDigest: digest(9),
        },
      }).success,
    ).toBe(false);
    expect(
      collaborativeMembershipManifestSchema.safeParse({
        ...manifest,
        history: {
          ...manifest.history,
          compactedHistoryDigest: digest(8),
        },
      }).success,
    ).toBe(false);
  });

  it('rejects duplicate principals and a manifest without an active owner', () => {
    expect(
      collaborativeMembershipManifestSchema.safeParse({
        ...manifest,
        memberships: [membershipA, { ...membershipA, membershipId: 'membership-b' }],
      }).success,
    ).toBe(false);
    expect(
      collaborativeMembershipManifestSchema.safeParse({
        ...manifest,
        memberships: [{ ...membershipA, role: 'editor' }],
        ownerPrincipalIds: [],
      }).success,
    ).toBe(false);
  });

  it('rejects missing, duplicate, and non-owner authority recovery envelopes', () => {
    expect(
      collaborativeMembershipManifestSchema.safeParse({
        ...manifest,
        keyEnvelopes: [keyEnvelope],
      }).success,
    ).toBe(false);
    expect(
      collaborativeMembershipManifestSchema.safeParse({
        ...manifest,
        keyEnvelopes: [
          keyEnvelope,
          authorityRecoveryEnvelope,
          authorityRecoveryEnvelope,
        ],
      }).success,
    ).toBe(false);
    expect(
      collaborativeMembershipManifestSchema.safeParse({
        ...manifest,
        keyEnvelopes: [
          keyEnvelope,
          {
            ...authorityRecoveryEnvelope,
            sealedByPrincipalId: 'principal-b',
            sealedByDeviceId: 'device-b',
          },
        ],
      }).success,
    ).toBe(false);
  });

  it('rejects ordinary authorization-state changes and administrative writes without transitions', () => {
    expect(
      collaborationMutationCommitmentSchema.safeParse({
        ...mutationCommitment,
        operationType: 'ordinary-write',
        authorizationTransitionDigest: undefined,
      }).success,
    ).toBe(false);
    expect(
      collaborationMutationCommitmentSchema.safeParse({
        ...mutationCommitment,
        operationType: 'add-member',
        authorizationTransitionDigest: undefined,
      }).success,
    ).toBe(false);
    expect(
      collaborationAuthorizationTransitionSchema.safeParse({
        ...authorizationTransition,
        operationType: 'ordinary-write',
      }).success,
    ).toBe(false);
  });

  it('rejects mismatched finalized links, transitions, and document commitments', () => {
    const noncanonicalGenesisHead = digest(6);
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        previousHeadDigest: noncanonicalGenesisHead,
        currentMutationLink: {
          ...currentMutationLink,
          commitment: {
            ...mutationCommitment,
            previousHeadDigest: noncanonicalGenesisHead,
          },
          authorizationTransition: {
            ...authorizationTransition,
            previousHeadDigest: noncanonicalGenesisHead,
          },
        },
      }).success,
    ).toBe(false);
    expect(
      collaborationAuthorizationTransitionSchema.safeParse({
        ...authorizationTransition,
        previousTuple: {
          ...authorizationTransition.previousTuple,
          authorizationStateDigest: digest(69),
        },
      }).success,
    ).toBe(false);
    expect(
      collaborationAuthorizationTransitionSchema.safeParse({
        ...authorizationTransition,
        nextTuple: {
          ...authorizationTransition.nextTuple,
          authorizationStateDigest: digest(69),
        },
      }).success,
    ).toBe(false);
    expect(
      collaborationAuthorizationCheckpointSchema.safeParse({
        format: 'kavrix-collaborative-authorization-checkpoint',
        protocolVersion: 1,
        checkpointId: 'checkpoint-mismatch',
        databaseId: 'database-a',
        vaultId: 'vault-a',
        authorityDelegationDigest,
        tuple: committedTuple,
        headDigest: document.headDigest,
        authorizationStateDigest: digest(69),
        finalizedMutationLinkDigest: digest(67),
        compactedThroughDocumentRevision: 1,
        checkpointDigest: digest(68),
        signerPrincipalId: 'principal-a',
        signerDeviceId: 'device-a',
        createdAt: laterTimestamp,
        ownerSignature: signature(68),
      }).success,
    ).toBe(false);
    expect(
      collaborationFinalizedMutationLinkSchema.safeParse({
        ...currentMutationLink,
        resultingHeadDigest: digest(70),
      }).success,
    ).toBe(false);
    expect(
      collaborationFinalizedMutationLinkSchema.safeParse({
        ...currentMutationLink,
        authorizationTransition: {
          ...authorizationTransition,
          authorizationStateDigest: digest(71),
        },
      }).success,
    ).toBe(false);
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        currentMutationLink: {
          ...currentMutationLink,
          commitment: { ...mutationCommitment, previousHeadDigest: digest(72) },
        },
      }).success,
    ).toBe(false);
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        encryptedPayload: {
          ...document.encryptedPayload,
          aad: { ...aad, documentRevision: 2 },
        },
      }).success,
    ).toBe(false);
  });

  it('accepts contiguous ordinary and administrative mutation proofs', () => {
    expect(
      collaborationMutationProofSchema.safeParse({
        format: COLLABORATIVE_MUTATION_PROOF_FORMAT,
        protocolVersion: 1,
        databaseId: 'database-a',
        vaultId: 'vault-a',
        authorityDelegationDigest,
        fromDocumentRevision: 1,
        fromHeadDigest: document.headDigest,
        toDocumentRevision: 2,
        toHeadDigest: ordinaryLink.resultingHeadDigest,
        startingAuthorizationWitness: authorizationWitness,
        entries: [{ link: ordinaryLink }],
      }).success,
    ).toBe(true);

    expect(
      collaborationMutationProofSchema.safeParse({
        format: COLLABORATIVE_MUTATION_PROOF_FORMAT,
        protocolVersion: 1,
        databaseId: 'database-a',
        vaultId: 'vault-a',
        authorityDelegationDigest,
        fromDocumentRevision: 0,
        fromHeadDigest: document.previousHeadDigest,
        toDocumentRevision: 1,
        toHeadDigest: document.headDigest,
        startingAuthorizationWitness,
        entries: [{ link: currentMutationLink, authorizationWitness }],
      }).success,
    ).toBe(true);

    expect(
      collaborationMutationProofSchema.safeParse({
        format: COLLABORATIVE_MUTATION_PROOF_FORMAT,
        protocolVersion: 1,
        databaseId: 'database-a',
        vaultId: 'vault-a',
        authorityDelegationDigest,
        fromDocumentRevision: 1,
        fromHeadDigest: document.headDigest,
        toDocumentRevision: 3,
        toHeadDigest: ordinaryLinkTwo.resultingHeadDigest,
        startingAuthorizationWitness: authorizationWitness,
        entries: [{ link: ordinaryLink }, { link: ordinaryLinkTwo }],
      }).success,
    ).toBe(true);
  });

  it('rejects proof witness-role, starting-witness, gap, and reorder violations', () => {
    const ordinaryProof = {
      format: COLLABORATIVE_MUTATION_PROOF_FORMAT,
      protocolVersion: 1 as const,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityDelegationDigest,
      fromDocumentRevision: 1,
      fromHeadDigest: document.headDigest,
      toDocumentRevision: 2,
      toHeadDigest: ordinaryLink.resultingHeadDigest,
      startingAuthorizationWitness: authorizationWitness,
      entries: [{ link: ordinaryLink }],
    };
    expect(
      collaborationMutationProofSchema.safeParse({
        ...ordinaryProof,
        startingAuthorizationWitness: undefined,
      }).success,
    ).toBe(false);
    expect(
      collaborationMutationProofSchema.safeParse({
        ...ordinaryProof,
        startingAuthorizationWitness,
      }).success,
    ).toBe(false);
    expect(
      collaborationMutationProofSchema.safeParse({
        ...ordinaryProof,
        startingAuthorizationWitness: {
          ...authorizationWitness,
          databaseDeviceRegistry: {
            ...witnessDeviceRegistry,
            generation: witnessDeviceRegistry.generation + 1,
          },
        },
      }).success,
    ).toBe(false);
    expect(
      collaborationMutationProofSchema.safeParse({
        ...ordinaryProof,
        entries: [{ link: ordinaryLink, authorizationWitness }],
      }).success,
    ).toBe(false);

    expect(
      collaborationMutationProofSchema.safeParse({
        ...ordinaryProof,
        toDocumentRevision: 3,
        toHeadDigest: ordinaryLinkTwo.resultingHeadDigest,
        entries: [
          { link: ordinaryLink },
          {
            link: {
              ...ordinaryLinkTwo,
              commitment: {
                ...ordinaryCommitmentTwo,
                previousDocumentRevision: 3,
              },
            },
          },
        ],
      }).success,
    ).toBe(false);
    expect(
      collaborationMutationProofSchema.safeParse({
        ...ordinaryProof,
        toDocumentRevision: 3,
        toHeadDigest: ordinaryLinkTwo.resultingHeadDigest,
        entries: [{ link: ordinaryLinkTwo }, { link: ordinaryLink }],
      }).success,
    ).toBe(false);

    expect(
      collaborationMutationProofSchema.safeParse({
        format: COLLABORATIVE_MUTATION_PROOF_FORMAT,
        protocolVersion: 1,
        databaseId: 'database-a',
        vaultId: 'vault-a',
        authorityDelegationDigest,
        fromDocumentRevision: 0,
        fromHeadDigest: document.previousHeadDigest,
        toDocumentRevision: 1,
        toHeadDigest: document.headDigest,
        startingAuthorizationWitness,
        entries: [{ link: currentMutationLink }],
      }).success,
    ).toBe(false);
  });

  it('rejects raw human metadata in discovery records', () => {
    const record = {
      format: 'kavrix-collaborative-discovery-record' as const,
      protocolVersion: 1 as const,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      ...stateFence,
      discoveryTag: digest(31),
      membershipId: 'membership-a',
      membershipState: 'active' as const,
      keyEpoch: 1,
      membershipRevision: 1,
      authorizationStateDigest,
      encryptedMemberKeyEnvelope: keyEnvelope,
      encryptedMembershipMetadataDigest: document.encryptedMembershipDigest,
      discoveryRecordDigest: digest(34),
      signerPrincipalId: 'principal-a',
      signerDeviceId: 'device-a',
      writerSignature: signature(31),
      createdAt: timestamp,
      updatedAt: laterTimestamp,
    };
    expect(collaborationDiscoveryRecordSchema.safeParse(record).success).toBe(true);
    expect(
      collaborativeMembershipManifestSchema.safeParse({
        ...manifest,
        authorityDelegationDigest,
      }).success,
    ).toBe(false);
    expect(
      collaborationDiscoveryRecordSchema.safeParse({
        ...record,
        authorityDelegationDigest,
      }).success,
    ).toBe(false);
    expect(
      collaborationDiscoveryRecordSchema.safeParse({
        ...record,
        headDigest: document.headDigest,
      }).success,
    ).toBe(false);
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        discoveryRecords: [record],
      }).success,
    ).toBe(true);
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        discoveryRecords: [{ ...record, signerDeviceId: 'device-b' }],
      }).success,
    ).toBe(false);
    const secondDeviceRecord = {
      ...record,
      encryptedMemberKeyEnvelope: {
        ...record.encryptedMemberKeyEnvelope,
        deviceId: 'device-b',
      },
    };
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        discoveryRecords: [record, secondDeviceRecord],
      }).success,
    ).toBe(true);
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        discoveryRecords: [record, record],
      }).success,
    ).toBe(false);
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        discoveryRecords: [{ ...record, authorizationStateDigest: digest(83) }],
      }).success,
    ).toBe(false);
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        discoveryRecords: [
          { ...record, encryptedMembershipMetadataDigest: digest(32) },
        ],
      }).success,
    ).toBe(false);
    expect(
      collaborationDiscoveryRecordSchema.safeParse({
        ...record,
        email: 'alice@example.test',
      }).success,
    ).toBe(false);
    expect(
      collaborationDiscoveryRecordSchema.safeParse({ ...record, role: 'owner' })
        .success,
    ).toBe(false);
    expect(
      collaborationDiscoveryRecordSchema.safeParse({
        ...record,
        principalFingerprint: digest(35),
      }).success,
    ).toBe(false);
  });

  it('requires enrollment receipts to bind delegation, authorization, and checkpoint evidence', () => {
    const receipt = {
      format: 'kavrix-collaborative-enrollment-receipt' as const,
      protocolVersion: 1 as const,
      operationType: 'add-member' as const,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityEpoch: 1,
      authorityDelegation,
      authorityDelegationDigest,
      ownerPrincipalId: 'principal-a',
      ownerPrincipalFingerprint: digest(36),
      ownerRootSigningPublicKey: key(36),
      ownerDeviceCertificate: deviceA,
      recipientPrincipalId: 'principal-b',
      recipientPrincipalFingerprint: digest(37),
      recipientPublicIdentity: publicIdentityB,
      recipientDeviceId: 'device-b',
      recipientDeviceFingerprints: [digest(38)],
      membershipId: 'membership-b',
      role: 'editor' as const,
      discoveryTag: digest(39),
      discoveryRecordDigest: digest(40),
      memberKeyEnvelopeDigest: keyEnvelope.envelopeDigest,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: stateFence.databaseDeviceRegistryDigest,
      documentRevision: 1,
      membershipRevision: 1,
      policyRevision: 1,
      keyEpoch: 1,
      headDigest: document.headDigest,
      authorizationStateDigest,
      finalizedMutationLinkDigest: digest(67),
      authorizationCheckpointDigest: digest(68),
      issuedAt: timestamp,
      expiresAt: laterTimestamp,
      ownerSignature: signature(41),
    };
    expect(enrollmentReceiptSchema.safeParse(receipt).success).toBe(true);
    expect(
      enrollmentReceiptSchema.safeParse({
        ...receipt,
        operationType: 'add-device',
      }).success,
    ).toBe(true);
    expect(
      enrollmentReceiptSchema.safeParse({
        ...receipt,
        operationType: undefined,
      }).success,
    ).toBe(false);
    const selfDeviceReceipt = {
      ...receipt,
      operationType: 'add-device' as const,
      recipientPrincipalId: receipt.ownerPrincipalId,
      recipientPrincipalFingerprint: receipt.ownerPrincipalFingerprint,
      recipientPublicIdentity: {
        format: 'kavrix-collaborative-public-identity' as const,
        protocolVersion: 1 as const,
        principalId: receipt.ownerPrincipalId,
        identityGeneration: 2,
        rootSigningPublicKey: receipt.ownerRootSigningPublicKey,
        devices: [deviceA],
        createdAt: timestamp,
        selfSignature: signature(42),
      },
      recipientDeviceId: deviceA.deviceId,
      recipientDeviceFingerprints: [digest(43)],
    };
    expect(enrollmentReceiptSchema.safeParse(selfDeviceReceipt).success).toBe(true);
    expect(
      enrollmentReceiptSchema.safeParse({
        ...selfDeviceReceipt,
        operationType: 'add-member',
      }).success,
    ).toBe(false);
    expect(
      enrollmentReceiptSchema.safeParse({
        ...selfDeviceReceipt,
        recipientPrincipalFingerprint: digest(44),
      }).success,
    ).toBe(false);
    expect(
      enrollmentReceiptSchema.safeParse({
        ...receipt,
        authorityDelegationDigest: undefined,
      }).success,
    ).toBe(false);
    expect(
      enrollmentReceiptSchema.safeParse({
        ...receipt,
        authorizationCheckpointDigest: undefined,
      }).success,
    ).toBe(false);
    expect(
      enrollmentReceiptSchema.safeParse({
        ...receipt,
        authorityDelegation: { ...authorityDelegation, vaultId: 'vault-other' },
      }).success,
    ).toBe(false);
  });

  it('rejects self-approval and approval evidence for a different request', () => {
    const request = {
      format: 'kavrix-collaborative-approval-request' as const,
      protocolVersion: 1 as const,
      approvalRequestId: 'approval-a',
      operationId: 'operation-approval',
      operationType: 'add-member' as const,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      requestDigest: digest(42),
      actionParametersDigest: digest(43),
      ...stateFence,
      documentRevision: 1,
      membershipRevision: 1,
      policyRevision: 1,
      keyEpoch: 1,
      priorHeadDigest: document.headDigest,
      authorizationStateDigest,
      requestingPrincipalId: 'principal-a',
      requestingDeviceId: 'device-a',
      requiredApprovalPolicy: 'one-additional-owner' as const,
      state: 'pending' as const,
      createdAt: timestamp,
      expiresAt: laterTimestamp,
      nonce: bytes(16, 44),
      requesterSignature: signature(45),
      approvals: [],
    };
    expect(approvalRequestSchema.parse(request)).toEqual(request);
    const selfApproval = {
      ...request,
      approvals: [
        {
          protocolVersion: 1 as const,
          approvalRequestId: request.approvalRequestId,
          operationId: request.operationId,
          databaseId: 'database-a',
          vaultId: 'vault-a',
          requestDigest: request.requestDigest,
          ...stateFence,
          documentRevision: request.documentRevision,
          membershipRevision: request.membershipRevision,
          policyRevision: request.policyRevision,
          keyEpoch: request.keyEpoch,
          priorHeadDigest: request.priorHeadDigest,
          authorizationStateDigest: request.authorizationStateDigest,
          requestingPrincipalId: request.requestingPrincipalId,
          approverPrincipalId: request.requestingPrincipalId,
          approverDeviceId: 'device-b',
          approvedAt: laterTimestamp,
          signature: signature(46),
        },
      ],
    };
    expect(approvalRequestSchema.safeParse(selfApproval).success).toBe(false);
    const selfApprovalEvidence = selfApproval.approvals[0];
    if (selfApprovalEvidence === undefined) {
      throw new Error('Expected self-approval fixture evidence.');
    }
    expect(
      approvalRequestSchema.safeParse({
        ...selfApproval,
        approvals: [
          {
            ...selfApprovalEvidence,
            approverPrincipalId: 'principal-b',
            requestDigest: digest(47),
          },
        ],
      }).success,
    ).toBe(false);
  });

  it('rejects mutated transfer intent relationships and terminal inconsistencies', () => {
    const transfer = {
      format: 'kavrix-collaborative-transfer-intent' as const,
      protocolVersion: 1 as const,
      transferIntentId: 'transfer-a',
      operationId: 'operation-transfer',
      databaseId: 'database-a',
      vaultId: 'vault-a',
      initiatorPrincipalId: 'principal-a',
      initiatorDeviceId: 'device-a',
      recipientPrincipalId: 'principal-b',
      recipientDeviceId: 'device-b',
      targetRole: 'owner' as const,
      originalOwnerDisposition: 'editor' as const,
      ...stateFence,
      documentRevision: 1,
      membershipRevision: 1,
      policyRevision: 1,
      keyEpoch: 1,
      currentHeadDigest: document.headDigest,
      authorizationStateDigest,
      intentDigest: digest(48),
      state: 'recipient-accepted' as const,
      createdAt: timestamp,
      expiresAt: expiryTimestamp,
      initiatorSignedAt: laterTimestamp,
      initiatorSignature: signature(49),
      recipientAcceptance: {
        protocolVersion: 1 as const,
        transferIntentId: 'transfer-a',
        operationId: 'operation-transfer',
        databaseId: 'database-a',
        vaultId: 'vault-a',
        intentDigest: digest(48),
        ...stateFence,
        recipientPrincipalId: 'principal-b',
        recipientDeviceId: 'device-b',
        authorizationStateDigest,
        acceptedAt: laterTimestamp,
        signature: signature(50),
      },
    };
    expect(transferIntentSchema.parse(transfer)).toEqual(transfer);
    expect(
      transferIntentSchema.safeParse({
        ...transfer,
        recipientAcceptance: {
          ...transfer.recipientAcceptance,
          intentDigest: digest(51),
        },
      }).success,
    ).toBe(false);
    expect(
      transferIntentSchema.safeParse({ ...transfer, state: 'published' }).success,
    ).toBe(false);
  });

  it('enforces encrypted payload and bounded record sizes', () => {
    const oversizedCiphertext = bytes(
      MAX_COLLABORATIVE_ENCRYPTED_PAYLOAD_BYTES + 1,
      52,
    );
    expect(
      collaborativeVaultDocumentSchema.safeParse({
        ...document,
        encryptedPayload: {
          ...document.encryptedPayload,
          ciphertext: oversizedCiphertext,
        },
      }).success,
    ).toBe(false);
  });

  it('requires complete writer-signed outcomes and exact tombstone receipts', () => {
    const outcomeDigest = digest(53);
    const linkDigest = digest(54);
    const mutationReceipt = {
      format: 'kavrix-collaborative-mutation-receipt' as const,
      protocolVersion: 1 as const,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      operationId: 'operation-genesis',
      operationType: 'genesis-migration' as const,
      requestDigest: mutationCommitment.requestDigest,
      actorPrincipalId: 'principal-a',
      actorDeviceId: 'device-a',
      priorTuple: previousTuple,
      priorHeadDigest: mutationCommitment.previousHeadDigest,
      committedTuple,
      committedHeadDigest: document.headDigest,
      finalizedMutationLinkDigest: linkDigest,
      outcomeDigest,
      committedAt: laterTimestamp,
      receiptSignature: signature(55),
    };
    expect(collaborationMutationReceiptSchema.safeParse(mutationReceipt).success).toBe(
      true,
    );
    const outcome = {
      format: 'kavrix-collaborative-operation-outcome' as const,
      protocolVersion: 1 as const,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      operationId: 'operation-genesis',
      operationType: 'genesis-migration' as const,
      requestDigest: mutationCommitment.requestDigest,
      actorPrincipalId: 'principal-a',
      actorDeviceId: 'device-a',
      priorTuple: previousTuple,
      priorHeadDigest: mutationCommitment.previousHeadDigest,
      state: 'committed' as const,
      committedTuple,
      committedHeadDigest: document.headDigest,
      finalizedMutationLinkDigest: linkDigest,
      committedAt: laterTimestamp,
      outcomeDigest,
      signedMutationReceipt: mutationReceipt,
      createdAt: timestamp,
      resolvedAt: laterTimestamp,
      detailsRetainedUntil: expiryTimestamp,
    };
    expect(durableOperationOutcomeSchema.safeParse(outcome).success).toBe(true);
    expect(
      durableOperationOutcomeSchema.safeParse({
        ...outcome,
        signedMutationReceipt: {
          ...mutationReceipt,
          requestDigest: digest(56),
        },
      }).success,
    ).toBe(false);
    const tombstone = {
      format: 'kavrix-collaborative-operation-tombstone' as const,
      protocolVersion: 1 as const,
      databaseId: 'database-a',
      vaultId: 'vault-a',
      operationId: 'operation-genesis',
      operationType: 'genesis-migration' as const,
      requestDigest: mutationReceipt.requestDigest,
      outcomeDigest,
      signedMutationReceipt: mutationReceipt,
      createdAt: laterTimestamp,
      retainedUntilVaultDestruction: true as const,
    };
    expect(operationDeduplicationTombstoneSchema.safeParse(tombstone).success).toBe(
      true,
    );
    expect(
      operationDeduplicationTombstoneSchema.safeParse({
        ...tombstone,
        signedMutationReceipt: {
          ...mutationReceipt,
          outcomeDigest: digest(57),
        },
      }).success,
    ).toBe(false);
  });

  it('requires a signed, exact, one-way migration request and marker lifecycle', () => {
    const request = {
      format: 'kavrix-collaborative-migration-request' as const,
      protocolVersion: 1 as const,
      operationType: 'genesis-migration' as const,
      operationId: 'operation-genesis',
      databaseId: 'database-a',
      vaultId: 'vault-a',
      legacyVaultRevision: 1,
      legacySourceDigest: digest(58),
      ...stateFence,
      authorityFingerprint: authorityDelegation.authoritySigningKeyFingerprint,
      initialOwnerPrincipalId: 'principal-a',
      initialOwnerDeviceId: 'device-a',
      initialMembershipId: 'membership-a',
      requestedAt: timestamp,
      requestDigest: digest(59),
      authoritySignature: signature(60),
      ownerSignature: signature(61),
    };
    expect(collaborationMigrationRequestSchema.parse(request)).toEqual(request);
    expect(
      collaborationMigrationRequestSchema.safeParse({
        ...request,
        operationType: 'ordinary-write',
      }).success,
    ).toBe(false);

    const markerBase = {
      format: COLLABORATIVE_MIGRATION_MARKER_FORMAT,
      markerVersion: 1 as const,
      protocolVersion: 1 as const,
      databaseId: request.databaseId,
      vaultId: request.vaultId,
      operationId: request.operationId,
      requestDigest: request.requestDigest,
      legacySourceDigest: request.legacySourceDigest,
      authorityEpoch: request.authorityEpoch,
      authorityFingerprint: request.authorityFingerprint,
      databaseDeviceGeneration: request.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: request.databaseDeviceRegistryDigest,
      candidateHeadDigest: document.headDigest,
      preparedAt: timestamp,
      authoritySignature: signature(62),
    };
    const prepared = {
      ...markerBase,
      state: 'prepared' as const,
      legacySource: legacyVault,
      registryCandidate: deviceRegistry,
    };
    expect(collaborationMigrationPreparedMarkerSchema.parse(prepared)).toEqual(
      prepared,
    );
    expect(
      collaborationMigrationPreparedMarkerSchema.safeParse({
        ...prepared,
        revision: 1,
      }).success,
    ).toBe(false);
    expect(
      collaborationMigrationPreparedMarkerSchema.safeParse({
        ...prepared,
        legacySource: { ...legacyVault, id: 'vault-other' },
      }).success,
    ).toBe(false);

    const activeMarker = {
      ...markerBase,
      state: 'active' as const,
      outcomeDigest: digest(63),
      activatedAt: laterTimestamp,
    };
    expect(collaborationMigrationActiveMarkerSchema.parse(activeMarker)).toEqual(
      activeMarker,
    );
    expect(
      collaborationMigrationActiveMarkerSchema.safeParse({
        ...activeMarker,
        activatedAt: '2025-12-31T00:00:00.000Z',
      }).success,
    ).toBe(false);
  });
});
