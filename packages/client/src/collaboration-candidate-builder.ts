import {
  authorizeOperation,
  checkActiveOwnerInvariant,
  evaluateDeviceFence,
  validateApproval,
  validateOwnershipTransfer,
  validateRevisionTransition,
  type CollaborationOperationType,
  type VerifiedApprovalSignature,
} from '@kavrix/core';
import {
  COLLABORATION_DOMAINS,
  computeAadMetadataDigest,
  computeAuthorityDelegationDigest,
  computeAuthorityRecoveryEnvelopeDigest,
  computeAuthorizationStateDigest,
  computeAuthorizationTransitionDigest,
  computeDeviceRegistryDigest,
  computeDiscoveryRecordDigest,
  computeDiscoveryTag,
  computeEncryptedMembershipDigest,
  computeEncryptedPayloadDigest,
  computeFinalizedMutationLinkDigest,
  computeKeyEnvelopeDigest,
  computeKeyEnvelopeSetDigest,
  computeMembershipHistoryDigest,
  computeMembershipManifestDigest,
  computeMembershipStateDigest,
  computeMutationHead,
  computeMutationRequestDigest,
  computeOperationOutcomeDigest,
  computePolicyDigest,
  computePolicyStateDigest,
  computePublicKeyFingerprint,
  constantTimeEqual,
  decryptCollaborationEnvelope,
  encryptCollaborationEnvelope,
  generateVaultRootKey,
  sealCollaborationVaultRootForDatabaseAuthority,
  sealVaultRootKeyForDevice,
  signAuthorizationTransitionAuthority,
  signAuthorizationTransitionOwner,
  signCollaborationRecord,
  signDiscoveryRecord,
  signFinalizedMutationLink,
  signMutationReceipt,
  verifyApprovalEvidence,
  verifyApprovalRequest,
  verifyAuthorityDelegation,
  verifyAuthorizationTransitionAuthority,
  verifyAuthorizationTransitionOwner,
  verifyCollaborationRecord,
  verifyCommittedOperationOutcome,
  verifyDiscoveryRecord,
  verifyFinalizedMutationLink,
  verifyOwnershipTransferAcceptance,
  verifyTransferIntent,
  zeroize,
  type DatabaseAuthoritySigningPrivateKey,
  type DeviceSigningPrivateKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  recipientRollbackAnchorFromCollaborativeVaultDocument,
  type RecipientRollbackAnchorScope,
} from '@kavrix/key-files';
import {
  COLLABORATION_PROTOCOL_VERSION,
  COLLABORATIVE_AUTHORIZATION_TRANSITION_FORMAT,
  COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT,
  COLLABORATIVE_DISCOVERY_RECORD_FORMAT,
  COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT,
  COLLABORATIVE_KEY_ENVELOPE_FORMAT,
  COLLABORATIVE_MEMBERSHIP_MANIFEST_FORMAT,
  COLLABORATIVE_MUTATION_RECEIPT_FORMAT,
  COLLABORATIVE_OPERATION_OUTCOME_FORMAT,
  COLLABORATIVE_VAULT_FORMAT,
  canonicalJson,
  collaborationAadMetadataSchema,
  collaborationAadSchema,
  approvalRequestSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationTransitionSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationKeyEnvelopeSchema,
  collaborationMutationCommitmentSchema,
  collaborationMutationProofEntrySchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  deviceCertificateSchema,
  durableOperationOutcomeSchema,
  membershipHistoryEventSchema,
  membershipHistoryCheckpointSchema,
  membershipHistorySchema,
  recipientRollbackAnchorSchema,
  timestampSchema,
  transferIntentSchema,
  type ApprovalRequest,
  type CollaborationAuthorizationStateCore,
  type CollaborationAuthorizationTransition,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationDiscoveryRecord,
  type CollaborationKeyEnvelope,
  type CollaborationMembership,
  type CollaborationMutationCommitment,
  type CollaborationMutationProof,
  type CollaborationPolicyState,
  type CollaborationRevisionTuple,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DatabaseAuthorityRecoveryEnvelope,
  type DeviceCertificate,
  type DurableOperationOutcome,
  type MembershipHistoryEvent,
  type RecipientRollbackAnchor,
  type Sha256Digest,
  type Timestamp,
  type TransferIntent,
} from '@kavrix/schemas';

import {
  requireDatabaseAuthorityRecoveryEnvelope,
  requireExactDatabaseAuthorityRecoveryEnvelope,
} from './collaboration-recovery-envelope-binding.js';

import {
  computeCollaborativeAdministrativeActionParametersDigest as computeSharedAdministrativeActionParametersDigest,
  projectCollaborativeAdministrativeActionParameters as projectSharedAdministrativeActionParameters,
  verifyCollaborativeAdministrativeManifestTransition,
} from './collaboration-administrative-state.js';
import { appendOrCompactMembershipHistory } from './collaboration-history.js';

const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');
const SAFE_MESSAGE = 'Collaborative mutation candidate preparation failed.';

export type CollaborativeAdministrativeOperationType = Exclude<
  CollaborationOperationType,
  'genesis-migration' | 'ordinary-write' | 'destroy-vault'
>;

export type CollaborativeAdministrativeHistoryEvent = Readonly<{
  eventType: MembershipHistoryEvent['eventType'];
  targetPrincipalId?: MembershipHistoryEvent['targetPrincipalId'];
  targetDeviceId?: MembershipHistoryEvent['targetDeviceId'];
  previousRole?: MembershipHistoryEvent['previousRole'];
  newRole?: MembershipHistoryEvent['newRole'];
  previousState?: MembershipHistoryEvent['previousState'];
  newState?: MembershipHistoryEvent['newState'];
}>;

export type AuthenticatedCollaborativePriorState = Readonly<{
  document: CollaborativeVaultDocument;
  manifest: CollaborativeMembershipManifest;
  deviceRegistry: CollaborationDatabaseDeviceRegistry;
  currentVaultRootKey: VaultRootKey | Uint8Array;
  quarantinedVaultPayload: Uint8Array;
}>;

export type CollaborativeMutationActor = Readonly<{
  principalId: CollaborationMembership['principalId'];
  deviceId: DeviceCertificate['deviceId'];
  rootSigningPublicKey: CollaborationMembership['rootSigningPublicKey'];
  deviceCertificate: DeviceCertificate;
  deviceSigningPrivateKey: DeviceSigningPrivateKey | Uint8Array;
}>;

export type CollaborativeArtifactOwnerSigner = Readonly<{
  principalId: CollaborationMembership['principalId'];
  deviceId: DeviceCertificate['deviceId'];
  deviceSigningPrivateKey: DeviceSigningPrivateKey | Uint8Array;
}>;

type CommonMutationInput = Readonly<{
  prior: AuthenticatedCollaborativePriorState;
  authoritativeDeviceRegistry: CollaborationDatabaseDeviceRegistry;
  actor: CollaborativeMutationActor;
  authorityRecoveryPublicKey: string;
  operationId: CollaborationMutationCommitment['operationId'];
  timestamp: Timestamp;
  expiresAt: Timestamp;
  anchorScope: RecipientRollbackAnchorScope;
}>;

export type BuildOrdinaryCollaborativeMutationInput = CommonMutationInput &
  Readonly<{
    vaultPayload: Uint8Array;
  }>;

export type CollaborativeAdministrativeNextState = Readonly<{
  memberships: readonly CollaborationMembership[];
  ownerPrincipalIds: readonly CollaborationMembership['principalId'][];
  approvalPolicy: CollaborativeMembershipManifest['approvalPolicy'];
  historyEvent: CollaborativeAdministrativeHistoryEvent;
}>;

type PreparedAdministrativeNextState = CollaborativeAdministrativeNextState &
  Readonly<{
    pendingApprovals: readonly ApprovalRequest[];
    pendingTransfers: readonly TransferIntent[];
    evidence: CollaborationAuthorizationTransition['evidence'];
  }>;

export type CollaborativeAdministrativeActionParametersInput = Readonly<{
  operationType: CollaborativeAdministrativeOperationType;
  next: CollaborativeAdministrativeNextState;
  decryptAccessChanged: boolean;
}>;

export type CollaborativeAdministrativeActionParameters = Readonly<{
  protocolVersion: typeof COLLABORATION_PROTOCOL_VERSION;
  operationType: CollaborativeAdministrativeOperationType;
  memberships: readonly CollaborationMembership[];
  ownerPrincipalIds: readonly CollaborationMembership['principalId'][];
  approvalPolicy: CollaborativeMembershipManifest['approvalPolicy'];
  decryptAccessChanged: boolean;
  historyEvent: CollaborativeAdministrativeHistoryEvent;
}>;

type NonRecoveryAdministrativeInput = CommonMutationInput &
  Readonly<{
    operationType: Exclude<CollaborativeAdministrativeOperationType, 'recover-owner'>;
    next: CollaborativeAdministrativeNextState;
    decryptAccessChanged: boolean;
    approvalRequest?: ApprovalRequest;
    transferIntent?: TransferIntent;
    artifactOwnerSigner?: CollaborativeArtifactOwnerSigner;
    authoritySigningPrivateKey?: never;
  }>;

type RecoveryAdministrativeInput = CommonMutationInput &
  Readonly<{
    operationType: 'recover-owner';
    next: CollaborativeAdministrativeNextState;
    decryptAccessChanged: boolean;
    authorityRecoveryEvidenceDigest: Sha256Digest;
    approvalRequest?: never;
    transferIntent?: never;
    artifactOwnerSigner?: never;
    authoritySigningPrivateKey: DatabaseAuthoritySigningPrivateKey | Uint8Array;
  }>;

export type BuildAdministrativeCollaborativeMutationInput =
  NonRecoveryAdministrativeInput | RecoveryAdministrativeInput;

export type PreparedCollaborativeMutation = Readonly<{
  candidate: CollaborativeVaultDocument;
  proofEntry: CollaborationMutationProof['entries'][number];
  proposedOutcome: DurableOperationOutcome;
  candidateAnchor: RecipientRollbackAnchor;
  nextVaultRootKey?: VaultRootKey;
}>;

export class CollaborationCandidatePreparationError extends Error {
  readonly safe = true;

  constructor() {
    super(SAFE_MESSAGE);
    this.name = 'CollaborationCandidatePreparationError';
  }
}

/** Canonical non-secret action projection approved by workflow evidence. */
export function projectCollaborativeAdministrativeActionParameters(
  input: CollaborativeAdministrativeActionParametersInput,
): CollaborativeAdministrativeActionParameters {
  const next = parseAdministrativeSemantic(input.next);
  return projectSharedAdministrativeActionParameters({ ...input, next });
}

/** Digest the exact administrative action projection used by approval requests. */
export function computeCollaborativeAdministrativeActionParametersDigest(
  input: CollaborativeAdministrativeActionParametersInput,
): Sha256Digest {
  return computeSharedAdministrativeActionParametersDigest({
    ...input,
    next: parseAdministrativeSemantic(input.next),
  });
}

type ParsedCommon = Readonly<{
  priorDocument: CollaborativeVaultDocument;
  priorManifest: CollaborativeMembershipManifest;
  priorRegistry: CollaborationDatabaseDeviceRegistry;
  registry: CollaborationDatabaseDeviceRegistry;
  actorMembership: CollaborationMembership;
  actorDevice: DeviceCertificate;
  actorPrivateKey: Uint8Array;
  currentVaultRootKey: Uint8Array;
  priorPayload: Uint8Array;
  authorityRecoveryPublicKey: string;
  timestamp: Timestamp;
  expiresAt: Timestamp;
  operationId: CollaborationMutationCommitment['operationId'];
  anchorScope: RecipientRollbackAnchorScope;
}>;

type BuiltCandidate = Readonly<{
  candidate: CollaborativeVaultDocument;
  proofEntry: CollaborationMutationProof['entries'][number];
  proposedOutcome: DurableOperationOutcome;
  candidateAnchor: RecipientRollbackAnchor;
}>;

/** Build one immutable editor/owner ordinary-write candidate without store access. */
export async function buildOrdinaryCollaborativeMutation(
  input: BuildOrdinaryCollaborativeMutationInput,
): Promise<PreparedCollaborativeMutation> {
  let parsed: ParsedCommon | undefined;
  let payload: Uint8Array | undefined;
  try {
    parsed = await parseAndAuthenticateCommon(input, 'ordinary-write');
    payload = copyBytes(input.vaultPayload);
    const built = await buildCandidate({
      common: parsed,
      operationType: 'ordinary-write',
      payload,
      nextManifestSemantic: ordinarySemanticState(parsed.priorManifest),
      decryptAccessChanged: false,
    });
    return freezePrepared(built);
  } catch {
    throw new CollaborationCandidatePreparationError();
  } finally {
    wipeParsedCommon(parsed);
    zeroize(payload);
  }
}

/** Build one immutable owner/authority administrative candidate without store access. */
export async function buildAdministrativeCollaborativeMutation(
  input: BuildAdministrativeCollaborativeMutationInput,
): Promise<PreparedCollaborativeMutation> {
  let parsed: ParsedCommon | undefined;
  let payload: Uint8Array | undefined;
  let authorityPrivateKey: Uint8Array | undefined;
  let artifactOwnerPrivateKey: Uint8Array | undefined;
  let nextVaultRootKey: VaultRootKey | undefined;
  let returnNextVaultRootKey = false;
  try {
    const requestedNext = parseAdministrativeSemantic(input.next);
    parsed = await parseAndAuthenticateCommon(
      input,
      input.operationType,
      input.operationType === 'recover-owner' ? requestedNext : undefined,
    );
    payload = copyBytes(parsed.priorPayload);
    authorityPrivateKey =
      input.operationType === 'recover-owner'
        ? copySecret(input.authoritySigningPrivateKey, 64)
        : undefined;
    await verifyNextMembershipTrust(
      requestedNext.memberships,
      parsed.registry,
      parsed.timestamp,
    );
    const computedDecryptAccessChanged =
      canonicalJson(decryptAccessSet(parsed.priorManifest.memberships)) !==
      canonicalJson(decryptAccessSet(requestedNext.memberships));
    if (computedDecryptAccessChanged !== input.decryptAccessChanged) fail();
    const actionParametersDigest =
      computeCollaborativeAdministrativeActionParametersDigest({
        operationType: input.operationType,
        next: requestedNext,
        decryptAccessChanged: input.decryptAccessChanged,
      });
    const nextSemantic = await prepareAdministrativeWorkflowState(
      input,
      parsed,
      requestedNext,
      actionParametersDigest,
    );

    const mustRotate = rotationRequired(
      input.operationType,
      input.decryptAccessChanged,
      parsed.priorDocument,
      parsed.registry,
    );
    nextVaultRootKey = mustRotate
      ? generateVaultRootKey()
      : (copySecret(parsed.currentVaultRootKey, 32) as VaultRootKey);

    const ownerSigner = selectArtifactOwnerSigner(input, parsed, nextSemantic);
    artifactOwnerPrivateKey = ownerSigner.privateKey;
    const built = await buildCandidate({
      common: parsed,
      operationType: input.operationType,
      payload,
      nextManifestSemantic: nextSemantic,
      decryptAccessChanged: input.decryptAccessChanged,
      nextVaultRootKey,
      artifactOwnerSigner: ownerSigner,
      ...(authorityPrivateKey === undefined ? {} : { authorityPrivateKey }),
    });

    if (mustRotate) {
      const prepared = freezePrepared({ ...built, nextVaultRootKey });
      returnNextVaultRootKey = true;
      return prepared;
    }
    return freezePrepared(built);
  } catch {
    throw new CollaborationCandidatePreparationError();
  } finally {
    wipeParsedCommon(parsed);
    zeroize(payload);
    zeroize(authorityPrivateKey);
    zeroize(artifactOwnerPrivateKey);
    if (!returnNextVaultRootKey) zeroize(nextVaultRootKey);
  }
}

type CandidateBuildInput = Readonly<{
  common: ParsedCommon;
  operationType: CollaborationOperationType;
  payload: Uint8Array;
  nextManifestSemantic: PreparedAdministrativeNextState;
  decryptAccessChanged: boolean;
  nextVaultRootKey?: VaultRootKey;
  artifactOwnerSigner?: Readonly<{
    principalId: CollaborationMembership['principalId'];
    deviceId: DeviceCertificate['deviceId'];
    privateKey: Uint8Array;
    publicKey: string;
  }>;
  authorityPrivateKey?: Uint8Array;
}>;

async function buildCandidate(input: CandidateBuildInput): Promise<BuiltCandidate> {
  const { common, operationType } = input;
  const ordinary = operationType === 'ordinary-write';
  const nextTupleBase = nextTupleBaseForOperation(
    common,
    operationType,
    input.decryptAccessChanged,
  );
  const activeKey = input.nextVaultRootKey ?? common.currentVaultRootKey;
  const keyEnvelopes = ordinary
    ? common.priorManifest.keyEnvelopes
    : await buildKeyEnvelopes(
        common,
        input.nextManifestSemantic.memberships,
        nextTupleBase,
        activeKey,
        requireValue(input.artifactOwnerSigner),
      );
  const authorizationCore = authorizationCoreOf({
    common,
    nextTupleBase,
    semantic: input.nextManifestSemantic,
    keyEnvelopes,
  });
  const authorizationStateDigest = ordinary
    ? common.priorDocument.authorizationStateDigest
    : computeAuthorizationStateDigest(authorizationCore);
  if (
    ordinary &&
    computeAuthorizationStateDigest(authorizationCore) !== authorizationStateDigest
  ) {
    fail();
  }
  if (
    !ordinary &&
    authorizationStateDigest === common.priorDocument.authorizationStateDigest
  ) {
    fail();
  }

  const nextTuple = collaborationRevisionTupleSchema.parse({
    ...nextTupleBase,
    authorizationStateDigest,
  });
  const policy = await buildPolicy(input, nextTuple);
  const history = await buildHistory(input, nextTuple);
  const manifest = buildManifest(input, nextTuple, keyEnvelopes, policy, history);
  const manifestBytes = Buffer.from(canonicalJson(manifest), 'utf8');
  let encryptedMembershipManifest;
  try {
    encryptedMembershipManifest = await encryptCollaborationEnvelope(
      manifestBytes,
      activeKey,
      aadFor(common, nextTuple, 'membership-manifest'),
    );
  } finally {
    zeroize(manifestBytes);
  }
  const encryptedMembershipDigest = computeEncryptedMembershipDigest(
    encryptedMembershipManifest,
  );
  const encryptedPayload = await encryptCollaborationEnvelope(
    input.payload,
    activeKey,
    aadFor(common, nextTuple, 'vault-payload'),
  );
  const encryptedPayloadDigest = computeEncryptedPayloadDigest(encryptedPayload);
  const discoveryRecords = await buildDiscoveryRecords(
    common,
    manifest,
    encryptedMembershipDigest,
  );
  const encryptedEnvelopesDigest = computeKeyEnvelopeSetDigest(keyEnvelopes);
  const policyDigest = computePolicyDigest(policy);

  let transition: CollaborationAuthorizationTransition | undefined;
  if (!ordinary) {
    transition = await buildAuthorizationTransition(
      input,
      nextTuple,
      authorizationStateDigest,
    );
  }
  const transitionDigest = transition?.transitionDigest;
  const revisionResult = validateRevisionTransition({
    operationType,
    prior: tupleOf(common.priorDocument),
    next: nextTuple,
    decryptAccessChanged: input.decryptAccessChanged,
    ...(transitionDigest === undefined
      ? {}
      : { authorizationTransitionDigest: transitionDigest }),
    ...(nextTuple.databaseDeviceGeneration >
    common.priorDocument.databaseDeviceGeneration
      ? { authoritativeRegistry: common.registry }
      : {}),
  });
  if (!revisionResult.valid) fail();
  const commitment = buildCommitment({
    common,
    operationType,
    nextTuple,
    encryptedPayloadDigest,
    encryptedMembershipDigest,
    encryptedEnvelopesDigest,
    policyDigest,
    ...(transitionDigest === undefined ? {} : { transitionDigest }),
  });
  const resultingHeadDigest = computeMutationHead(commitment);
  const linkInput = {
    format: COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: common.priorDocument.databaseId,
    vaultId: common.priorDocument.vaultId,
    authorityDelegationDigest: common.priorDocument.authorityDelegationDigest,
    commitment,
    ...(transition === undefined ? {} : { authorizationTransition: transition }),
    resultingHeadDigest,
    writerSignature: {
      algorithm: 'ed25519' as const,
      writerPrincipalId: common.actorMembership.principalId,
      writerDeviceId: common.actorDevice.deviceId,
      commitmentDigest: resultingHeadDigest,
      signature: PLACEHOLDER_SIGNATURE,
    },
    finalizedAt: common.timestamp,
  };
  const writerSignature = await signFinalizedMutationLink(
    linkInput,
    common.actorPrivateKey,
  );
  const link = collaborationFinalizedMutationLinkSchema.parse({
    ...linkInput,
    writerSignature: { ...linkInput.writerSignature, signature: writerSignature },
  });
  if (!(await verifyFinalizedMutationLink(link, common.actorDevice.signingPublicKey))) {
    fail();
  }
  if (!ordinary) {
    verifyCollaborativeAdministrativeManifestTransition({
      link,
      priorManifest: common.priorManifest,
      nextManifest: manifest,
    });
  }
  const finalizedMutationLinkDigest = computeFinalizedMutationLinkDigest(link);
  const candidate = collaborativeVaultDocumentSchema.parse({
    format: COLLABORATIVE_VAULT_FORMAT,
    documentVersion: common.priorDocument.documentVersion,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: common.priorDocument.databaseId,
    vaultId: common.priorDocument.vaultId,
    authorityEpoch: nextTuple.authorityEpoch,
    databaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
    documentRevision: nextTuple.documentRevision,
    membershipRevision: nextTuple.membershipRevision,
    policyRevision: nextTuple.policyRevision,
    keyEpoch: nextTuple.keyEpoch,
    previousHeadDigest: common.priorDocument.headDigest,
    headDigest: resultingHeadDigest,
    authorityDelegation: common.priorDocument.authorityDelegation,
    authorityDelegationDigest: common.priorDocument.authorityDelegationDigest,
    authorizationStateDigest,
    encryptedPayloadDigest,
    encryptedMembershipDigest,
    encryptedEnvelopesDigest,
    policyDigest,
    databaseAuthorityRecoveryEnvelope:
      requireDatabaseAuthorityRecoveryEnvelope(manifest),
    encryptedPayload,
    encryptedMembershipManifest,
    discoveryRecords,
    currentMutationLink: link,
    createdAt: common.priorDocument.createdAt,
    updatedAt: common.timestamp,
  });
  const proofEntry = collaborationMutationProofEntrySchema.parse({
    link,
    ...(ordinary
      ? {}
      : {
          authorizationWitness: {
            format: COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT,
            protocolVersion: COLLABORATION_PROTOCOL_VERSION,
            databaseId: candidate.databaseId,
            vaultId: candidate.vaultId,
            authorityDelegationDigest: candidate.authorityDelegationDigest,
            tuple: nextTuple,
            previousHeadDigest: candidate.previousHeadDigest,
            headDigest: candidate.headDigest,
            encryptedMembershipDigest,
            encryptedEnvelopesDigest,
            policyDigest,
            databaseDeviceRegistry: common.registry,
            databaseAuthorityRecoveryEnvelope:
              requireDatabaseAuthorityRecoveryEnvelope(manifest),
            encryptedMembershipManifest,
            discoveryRecords,
            finalizedMutationLinkDigest,
          },
        }),
  });
  const proposedOutcome = await buildCommittedOutcome(
    common,
    operationType,
    nextTuple,
    commitment.requestDigest,
    resultingHeadDigest,
    finalizedMutationLinkDigest,
  );
  const candidateAnchor = recipientRollbackAnchorSchema.parse(
    recipientRollbackAnchorFromCollaborativeVaultDocument(
      candidate,
      common.anchorScope,
      {
        membershipDigest: computeMembershipStateDigest(authorizationCore),
        policyDigest: computePolicyStateDigest(policy),
        finalizedMutationLinkDigest,
        updatedAt: common.timestamp,
      },
    ),
  );
  return { candidate, proofEntry, proposedOutcome, candidateAnchor };
}

function nextTupleBaseForOperation(
  common: ParsedCommon,
  operationType: CollaborationOperationType,
  decryptAccessChanged: boolean,
): Omit<CollaborationRevisionTuple, 'authorizationStateDigest'> {
  const prior = common.priorDocument;
  const membershipChanging = new Set<CollaborationOperationType>([
    'add-member',
    'add-device',
    'remove-member',
    'revoke-device',
    'change-role',
    'transfer-owner',
    'recover-owner',
  ]).has(operationType);
  const keyRotation = rotationRequired(
    operationType,
    decryptAccessChanged,
    prior,
    common.registry,
  );
  const parsed = collaborationRevisionTupleSchema.parse({
    authorityEpoch: prior.authorityEpoch,
    documentRevision: prior.documentRevision + 1,
    membershipRevision: prior.membershipRevision + (membershipChanging ? 1 : 0),
    policyRevision: prior.policyRevision + (operationType === 'change-policy' ? 1 : 0),
    keyEpoch: prior.keyEpoch + (keyRotation ? 1 : 0),
    databaseDeviceGeneration: common.registry.generation,
    databaseDeviceRegistryDigest: common.registry.registryDigest,
    authorizationStateDigest: prior.authorizationStateDigest,
  });
  return {
    authorityEpoch: parsed.authorityEpoch,
    documentRevision: parsed.documentRevision,
    membershipRevision: parsed.membershipRevision,
    policyRevision: parsed.policyRevision,
    keyEpoch: parsed.keyEpoch,
    databaseDeviceGeneration: parsed.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: parsed.databaseDeviceRegistryDigest,
  };
}

function rotationRequired(
  operationType: CollaborationOperationType,
  decryptAccessChanged: boolean,
  prior: CollaborativeVaultDocument,
  registry: CollaborationDatabaseDeviceRegistry,
): boolean {
  return (
    new Set<CollaborationOperationType>([
      'add-member',
      'add-device',
      'remove-member',
      'revoke-device',
      'rotate-key',
      'recover-owner',
      'emergency-rekey',
    ]).has(operationType) ||
    ((operationType === 'transfer-owner' || operationType === 'recover-owner') &&
      decryptAccessChanged) ||
    registry.generation > prior.databaseDeviceGeneration
  );
}

async function buildKeyEnvelopes(
  common: ParsedCommon,
  memberships: readonly CollaborationMembership[],
  tuple: Omit<CollaborationRevisionTuple, 'authorizationStateDigest'>,
  vaultRootKey: Uint8Array,
  ownerSigner: Readonly<{
    principalId: CollaborationMembership['principalId'];
    deviceId: DeviceCertificate['deviceId'];
    privateKey: Uint8Array;
    publicKey: string;
  }>,
): Promise<readonly (CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope)[]> {
  const result: (CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope)[] = [];
  for (const membership of memberships) {
    if (membership.state !== 'active') continue;
    for (const device of membership.devices) {
      if (device.state !== 'active') continue;
      const unsigned = {
        format: COLLABORATIVE_KEY_ENVELOPE_FORMAT,
        protocolVersion: COLLABORATION_PROTOCOL_VERSION,
        algorithm: 'x25519-sealed-box' as const,
        databaseId: common.priorDocument.databaseId,
        vaultId: common.priorDocument.vaultId,
        authorityEpoch: tuple.authorityEpoch,
        membershipId: membership.membershipId,
        principalId: membership.principalId,
        deviceId: device.deviceId,
        recipientEncryptionKeyFingerprint: computePublicKeyFingerprint(
          device.encryptionPublicKey,
          'x25519',
        ),
        keyEpoch: tuple.keyEpoch,
        membershipRevision: tuple.membershipRevision,
        databaseDeviceGeneration: tuple.databaseDeviceGeneration,
        databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
        sealedVaultRootKey: await sealVaultRootKeyForDevice(
          vaultRootKey,
          device.encryptionPublicKey,
        ),
        envelopeDigest: PLACEHOLDER_DIGEST,
        createdAt: common.timestamp,
        ownerSignature: PLACEHOLDER_SIGNATURE,
      };
      const envelopeDigest = computeKeyEnvelopeDigest(unsigned);
      const withDigest = collaborationKeyEnvelopeSchema.parse({
        ...unsigned,
        envelopeDigest,
      });
      const ownerSignature = await signCollaborationRecord(
        COLLABORATION_DOMAINS.keyEnvelopeSignature,
        withDigest,
        collaborationKeyEnvelopeSchema,
        'ownerSignature',
        ownerSigner.privateKey,
      );
      const envelope = collaborationKeyEnvelopeSchema.parse({
        ...withDigest,
        ownerSignature,
      });
      if (
        !(await verifyCollaborationRecord(
          COLLABORATION_DOMAINS.keyEnvelopeSignature,
          envelope,
          collaborationKeyEnvelopeSchema,
          'ownerSignature',
          ownerSigner.publicKey,
        ))
      ) {
        fail();
      }
      result.push(envelope);
    }
  }

  const recoveryUnsigned = {
    format: 'kavrix-collaborative-authority-recovery-envelope' as const,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    algorithm: 'x25519-sealed-box' as const,
    databaseId: common.priorDocument.databaseId,
    vaultId: common.priorDocument.vaultId,
    authorityEpoch: tuple.authorityEpoch,
    authorityRecoveryKeyFingerprint:
      common.priorDocument.authorityDelegation.authorityRecoveryKeyFingerprint,
    keyEpoch: tuple.keyEpoch,
    membershipRevision: tuple.membershipRevision,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    sealedVaultRootKey: await sealCollaborationVaultRootForDatabaseAuthority(
      vaultRootKey,
      common.authorityRecoveryPublicKey,
    ),
    envelopeDigest: PLACEHOLDER_DIGEST,
    sealedByPrincipalId: ownerSigner.principalId,
    sealedByDeviceId: ownerSigner.deviceId,
    createdAt: common.timestamp,
    ownerSignature: PLACEHOLDER_SIGNATURE,
  };
  const recoveryDigest = computeAuthorityRecoveryEnvelopeDigest(recoveryUnsigned);
  const recoveryWithDigest = databaseAuthorityRecoveryEnvelopeSchema.parse({
    ...recoveryUnsigned,
    envelopeDigest: recoveryDigest,
  });
  const recoverySignature = await signCollaborationRecord(
    COLLABORATION_DOMAINS.keyEnvelopeSignature,
    recoveryWithDigest,
    databaseAuthorityRecoveryEnvelopeSchema,
    'ownerSignature',
    ownerSigner.privateKey,
  );
  const recoveryEnvelope = databaseAuthorityRecoveryEnvelopeSchema.parse({
    ...recoveryWithDigest,
    ownerSignature: recoverySignature,
  });
  if (
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.keyEnvelopeSignature,
      recoveryEnvelope,
      databaseAuthorityRecoveryEnvelopeSchema,
      'ownerSignature',
      ownerSigner.publicKey,
    ))
  ) {
    fail();
  }
  result.push(recoveryEnvelope);
  return result;
}

function authorizationCoreOf(
  input: Readonly<{
    common: ParsedCommon;
    nextTupleBase: Omit<CollaborationRevisionTuple, 'authorizationStateDigest'>;
    semantic: CollaborativeAdministrativeNextState;
    keyEnvelopes: readonly (
      CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope
    )[];
  }>,
): CollaborationAuthorizationStateCore {
  return collaborationAuthorizationStateCoreSchema.parse({
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: input.common.priorDocument.databaseId,
    vaultId: input.common.priorDocument.vaultId,
    authorityEpoch: input.nextTupleBase.authorityEpoch,
    databaseDeviceGeneration: input.nextTupleBase.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: input.nextTupleBase.databaseDeviceRegistryDigest,
    membershipRevision: input.nextTupleBase.membershipRevision,
    policyRevision: input.nextTupleBase.policyRevision,
    keyEpoch: input.nextTupleBase.keyEpoch,
    memberships: input.semantic.memberships.map((membership) => ({
      membershipId: membership.membershipId,
      principalId: membership.principalId,
      principalFingerprint: membership.principalFingerprint,
      rootSigningPublicKey: membership.rootSigningPublicKey,
      identityGeneration: membership.identityGeneration,
      role: membership.role,
      state: membership.state,
      devices: membership.devices.map(withoutDeviceRootSignature),
      createdAt: membership.createdAt,
      updatedAt: membership.updatedAt,
      ...(membership.removedAt === undefined
        ? {}
        : { removedAt: membership.removedAt }),
    })),
    ownerPrincipalIds: input.semantic.ownerPrincipalIds,
    keyEnvelopes: input.keyEnvelopes.map(authorizationEnvelopeCore),
    approvalPolicy: input.semantic.approvalPolicy,
  });
}

async function buildPolicy(
  input: CandidateBuildInput,
  nextTuple: CollaborationRevisionTuple,
): Promise<CollaborationPolicyState> {
  const prior = input.common.priorManifest.policy;
  if (
    input.operationType === 'ordinary-write' ||
    (input.operationType !== 'change-policy' &&
      nextTuple.databaseDeviceGeneration === prior.databaseDeviceGeneration)
  ) {
    return collaborationPolicyStateSchema.parse(prior);
  }
  const unsigned = {
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: input.common.priorDocument.databaseId,
    vaultId: input.common.priorDocument.vaultId,
    authorityEpoch: nextTuple.authorityEpoch,
    policyRevision: nextTuple.policyRevision,
    approvalPolicy: input.nextManifestSemantic.approvalPolicy,
    policyDigest: PLACEHOLDER_DIGEST,
    databaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
    changedByPrincipalId: input.common.actorMembership.principalId,
    changedByDeviceId: input.common.actorDevice.deviceId,
    changedAt: input.common.timestamp,
    signature: PLACEHOLDER_SIGNATURE,
  };
  const policyDigest = computePolicyDigest(unsigned);
  const withDigest = collaborationPolicyStateSchema.parse({
    ...unsigned,
    policyDigest,
  });
  const signature = await signCollaborationRecord(
    COLLABORATION_DOMAINS.policySignature,
    withDigest,
    collaborationPolicyStateSchema,
    'signature',
    input.common.actorPrivateKey,
  );
  const policy = collaborationPolicyStateSchema.parse({ ...withDigest, signature });
  if (
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.policySignature,
      policy,
      collaborationPolicyStateSchema,
      'signature',
      input.common.actorDevice.signingPublicKey,
    ))
  ) {
    fail();
  }
  return policy;
}

async function buildHistory(
  input: CandidateBuildInput,
  nextTuple: CollaborationRevisionTuple,
): Promise<CollaborativeMembershipManifest['history']> {
  const prior = input.common.priorManifest.history;
  if (input.operationType !== 'ordinary-write') {
    const details = input.nextManifestSemantic.historyEvent;
    const evidence = input.nextManifestSemantic.evidence;
    const result = await appendOrCompactMembershipHistory({
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: input.common.priorDocument.databaseId,
      vaultId: input.common.priorDocument.vaultId,
      operationId: input.common.operationId,
      previousHeadDigest: input.common.priorDocument.headDigest,
      previousTuple: tupleOf(input.common.priorDocument),
      nextTuple,
      priorHistory: prior,
      actorPrincipalId: input.common.actorMembership.principalId,
      actorDeviceId: input.common.actorDevice.deviceId,
      actorSigningPublicKey: input.common.actorDevice.signingPublicKey,
      event: {
        eventType: details.eventType,
        ...optionalHistoryDetails(details),
        ...(evidence.kind === 'approval'
          ? approvalHistoryFields(input.nextManifestSemantic.pendingApprovals, evidence)
          : {}),
        timestamp: input.common.timestamp,
        expiresAt: input.common.expiresAt,
      },
      deviceSigningPrivateKey: input.common.actorPrivateKey,
    });
    return result.history;
  }
  const historyInput = {
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: input.common.priorDocument.databaseId,
    vaultId: input.common.priorDocument.vaultId,
    authorityEpoch: nextTuple.authorityEpoch,
    databaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
    events: prior.events,
    checkpoints: prior.checkpoints,
    compactedThroughRevision: prior.compactedThroughRevision,
    compactedHistoryDigest: prior.compactedHistoryDigest,
    previousHeadDigest: input.common.priorDocument.headDigest,
    previousHistoryDigest: prior.currentHistoryDigest,
    currentHistoryDigest: PLACEHOLDER_DIGEST,
  };
  const currentHistoryDigest = computeMembershipHistoryDigest(historyInput);
  return membershipHistorySchema.parse({
    ...historyInput,
    currentHistoryDigest,
  });
}

function buildManifest(
  input: CandidateBuildInput,
  nextTuple: CollaborationRevisionTuple,
  keyEnvelopes: readonly (
    CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope
  )[],
  policy: CollaborationPolicyState,
  history: CollaborativeMembershipManifest['history'],
): CollaborativeMembershipManifest {
  const manifestInput = {
    format: COLLABORATIVE_MEMBERSHIP_MANIFEST_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: input.common.priorDocument.databaseId,
    vaultId: input.common.priorDocument.vaultId,
    authorityEpoch: nextTuple.authorityEpoch,
    databaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
    documentRevision: nextTuple.documentRevision,
    membershipRevision: nextTuple.membershipRevision,
    policyRevision: nextTuple.policyRevision,
    keyEpoch: nextTuple.keyEpoch,
    authorizationStateDigest: nextTuple.authorizationStateDigest,
    memberships: input.nextManifestSemantic.memberships,
    ownerPrincipalIds: input.nextManifestSemantic.ownerPrincipalIds,
    keyEnvelopes,
    approvalPolicy: input.nextManifestSemantic.approvalPolicy,
    policy,
    pendingApprovals: input.nextManifestSemantic.pendingApprovals,
    pendingTransfers: input.nextManifestSemantic.pendingTransfers,
    history,
    previousMembershipDigest: input.common.priorManifest.membershipDigest,
    membershipDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest: input.common.priorDocument.headDigest,
    createdAt: input.common.priorManifest.createdAt,
    updatedAt: input.common.timestamp,
  };
  const membershipDigest = computeMembershipManifestDigest(manifestInput);
  return collaborativeMembershipManifestSchema.parse({
    ...manifestInput,
    membershipDigest,
  });
}

async function buildDiscoveryRecords(
  common: ParsedCommon,
  manifest: CollaborativeMembershipManifest,
  encryptedMembershipDigest: Sha256Digest,
): Promise<readonly CollaborationDiscoveryRecord[]> {
  const records: CollaborationDiscoveryRecord[] = [];
  for (const envelope of manifest.keyEnvelopes) {
    if (!('membershipId' in envelope)) continue;
    const membership = manifest.memberships.find(
      (candidate) => candidate.membershipId === envelope.membershipId,
    );
    if (membership?.state !== 'active') fail();
    const prior = common.priorDocument.discoveryRecords.find(
      (record) =>
        record.membershipId === envelope.membershipId &&
        record.encryptedMemberKeyEnvelope.deviceId === envelope.deviceId,
    );
    const unsigned = {
      format: COLLABORATIVE_DISCOVERY_RECORD_FORMAT,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: manifest.databaseId,
      vaultId: manifest.vaultId,
      authorityEpoch: manifest.authorityEpoch,
      databaseDeviceGeneration: manifest.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: manifest.databaseDeviceRegistryDigest,
      discoveryTag: computeDiscoveryTag(
        manifest.databaseId,
        membership.principalFingerprint,
      ),
      membershipId: membership.membershipId,
      membershipState: 'active' as const,
      keyEpoch: manifest.keyEpoch,
      membershipRevision: manifest.membershipRevision,
      authorizationStateDigest: manifest.authorizationStateDigest,
      encryptedMemberKeyEnvelope: envelope,
      encryptedMembershipMetadataDigest: encryptedMembershipDigest,
      discoveryRecordDigest: PLACEHOLDER_DIGEST,
      signerPrincipalId: common.actorMembership.principalId,
      signerDeviceId: common.actorDevice.deviceId,
      writerSignature: PLACEHOLDER_SIGNATURE,
      createdAt: prior?.createdAt ?? common.timestamp,
      updatedAt: common.timestamp,
    };
    const discoveryRecordDigest = computeDiscoveryRecordDigest(unsigned);
    const withDigest = collaborationDiscoveryRecordSchema.parse({
      ...unsigned,
      discoveryRecordDigest,
    });
    const writerSignature = await signDiscoveryRecord(
      withDigest,
      common.actorPrivateKey,
    );
    const record = collaborationDiscoveryRecordSchema.parse({
      ...withDigest,
      writerSignature,
    });
    if (!(await verifyDiscoveryRecord(record, common.actorDevice.signingPublicKey))) {
      fail();
    }
    records.push(record);
  }
  return records;
}

async function buildAuthorizationTransition(
  input: CandidateBuildInput,
  nextTuple: CollaborationRevisionTuple,
  authorizationStateDigest: Sha256Digest,
): Promise<CollaborationAuthorizationTransition> {
  const recovery = input.operationType === 'recover-owner';
  const signatureCore = recovery
    ? {
        signerKind: 'database-authority' as const,
        authorityEpoch: nextTuple.authorityEpoch,
        authoritySigningKeyFingerprint:
          input.common.priorDocument.authorityDelegation.authoritySigningKeyFingerprint,
        signature: PLACEHOLDER_SIGNATURE,
      }
    : {
        signerKind: 'owner-device' as const,
        signerPrincipalId: input.common.actorMembership.principalId,
        signerDeviceId: input.common.actorDevice.deviceId,
        signature: PLACEHOLDER_SIGNATURE,
      };
  const unsigned = {
    format: COLLABORATIVE_AUTHORIZATION_TRANSITION_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: input.common.priorDocument.databaseId,
    vaultId: input.common.priorDocument.vaultId,
    operationId: input.common.operationId,
    operationType: input.operationType,
    previousHeadDigest: input.common.priorDocument.headDigest,
    previousAuthorizationStateDigest:
      input.common.priorDocument.authorizationStateDigest,
    authorizationStateDigest,
    previousTuple: tupleOf(input.common.priorDocument),
    nextTuple,
    evidence: input.nextManifestSemantic.evidence,
    issuedAt: input.common.timestamp,
    expiresAt: input.common.expiresAt,
    transitionDigest: PLACEHOLDER_DIGEST,
    transitionSignature: signatureCore,
  };
  const transitionDigest = computeAuthorizationTransitionDigest(unsigned);
  const withDigest = collaborationAuthorizationTransitionSchema.parse({
    ...unsigned,
    transitionDigest,
  });
  const signature = recovery
    ? await signAuthorizationTransitionAuthority(
        withDigest,
        requireValue(input.authorityPrivateKey),
      )
    : await signAuthorizationTransitionOwner(withDigest, input.common.actorPrivateKey);
  const transition = collaborationAuthorizationTransitionSchema.parse({
    ...withDigest,
    transitionSignature: { ...withDigest.transitionSignature, signature },
  });
  const verified = recovery
    ? await verifyAuthorizationTransitionAuthority(
        transition,
        input.common.priorDocument.authorityDelegation.authoritySigningPublicKey,
      )
    : await verifyAuthorizationTransitionOwner(
        transition,
        input.common.actorDevice.signingPublicKey,
      );
  if (!verified) fail();
  return transition;
}

function buildCommitment(
  input: Readonly<{
    common: ParsedCommon;
    operationType: CollaborationOperationType;
    nextTuple: CollaborationRevisionTuple;
    encryptedPayloadDigest: Sha256Digest;
    encryptedMembershipDigest: Sha256Digest;
    encryptedEnvelopesDigest: Sha256Digest;
    policyDigest: Sha256Digest;
    transitionDigest?: Sha256Digest;
  }>,
): CollaborationMutationCommitment {
  const prior = input.common.priorDocument;
  const placeholder = {
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: prior.databaseId,
    vaultId: prior.vaultId,
    operationId: input.common.operationId,
    operationType: input.operationType,
    requestDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest: prior.headDigest,
    previousAuthorizationStateDigest: prior.authorizationStateDigest,
    authorizationStateDigest: input.nextTuple.authorizationStateDigest,
    ...(input.transitionDigest === undefined
      ? {}
      : { authorizationTransitionDigest: input.transitionDigest }),
    previousAuthorityEpoch: prior.authorityEpoch,
    previousDocumentRevision: prior.documentRevision,
    previousMembershipRevision: prior.membershipRevision,
    previousPolicyRevision: prior.policyRevision,
    previousKeyEpoch: prior.keyEpoch,
    previousDatabaseDeviceGeneration: prior.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: prior.databaseDeviceRegistryDigest,
    authorityEpoch: input.nextTuple.authorityEpoch,
    documentRevision: input.nextTuple.documentRevision,
    membershipRevision: input.nextTuple.membershipRevision,
    policyRevision: input.nextTuple.policyRevision,
    keyEpoch: input.nextTuple.keyEpoch,
    databaseDeviceGeneration: input.nextTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: input.nextTuple.databaseDeviceRegistryDigest,
    encryptedPayloadDigest: input.encryptedPayloadDigest,
    encryptedMembershipDigest: input.encryptedMembershipDigest,
    encryptedEnvelopesDigest: input.encryptedEnvelopesDigest,
    policyDigest: input.policyDigest,
    writerPrincipalId: input.common.actorMembership.principalId,
    writerDeviceId: input.common.actorDevice.deviceId,
    timestamp: input.common.timestamp,
    expiresAt: input.common.expiresAt,
  };
  const requestDigest = computeMutationRequestDigest(placeholder);
  return collaborationMutationCommitmentSchema.parse({
    ...placeholder,
    requestDigest,
  });
}

async function buildCommittedOutcome(
  common: ParsedCommon,
  operationType: CollaborationOperationType,
  nextTuple: CollaborationRevisionTuple,
  requestDigest: Sha256Digest,
  committedHeadDigest: Sha256Digest,
  finalizedMutationLinkDigest: Sha256Digest,
): Promise<DurableOperationOutcome> {
  const outcomeInput = {
    format: COLLABORATIVE_OPERATION_OUTCOME_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: common.priorDocument.databaseId,
    vaultId: common.priorDocument.vaultId,
    operationId: common.operationId,
    operationType,
    requestDigest,
    actorPrincipalId: common.actorMembership.principalId,
    actorDeviceId: common.actorDevice.deviceId,
    priorTuple: tupleOf(common.priorDocument),
    priorHeadDigest: common.priorDocument.headDigest,
    state: 'committed' as const,
    committedTuple: nextTuple,
    committedHeadDigest,
    finalizedMutationLinkDigest,
    committedAt: common.timestamp,
    outcomeDigest: PLACEHOLDER_DIGEST,
    signedMutationReceipt: {
      format: COLLABORATIVE_MUTATION_RECEIPT_FORMAT,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: common.priorDocument.databaseId,
      vaultId: common.priorDocument.vaultId,
      operationId: common.operationId,
      operationType,
      requestDigest,
      actorPrincipalId: common.actorMembership.principalId,
      actorDeviceId: common.actorDevice.deviceId,
      priorTuple: tupleOf(common.priorDocument),
      priorHeadDigest: common.priorDocument.headDigest,
      committedTuple: nextTuple,
      committedHeadDigest,
      finalizedMutationLinkDigest,
      outcomeDigest: PLACEHOLDER_DIGEST,
      committedAt: common.timestamp,
      receiptSignature: PLACEHOLDER_SIGNATURE,
    },
    createdAt: common.timestamp,
    resolvedAt: common.timestamp,
    detailsRetainedUntil: common.expiresAt,
  };
  const outcomeDigest = computeOperationOutcomeDigest(outcomeInput);
  const receiptInput = {
    ...outcomeInput.signedMutationReceipt,
    outcomeDigest,
  };
  const receiptSignature = await signMutationReceipt(
    receiptInput,
    common.actorPrivateKey,
  );
  const outcome = durableOperationOutcomeSchema.parse({
    ...outcomeInput,
    outcomeDigest,
    signedMutationReceipt: { ...receiptInput, receiptSignature },
  });
  if (
    !(await verifyCommittedOperationOutcome(
      outcome,
      common.actorDevice.signingPublicKey,
    ))
  ) {
    fail();
  }
  return outcome;
}

async function prepareAdministrativeWorkflowState(
  input: BuildAdministrativeCollaborativeMutationInput,
  common: ParsedCommon,
  next: CollaborativeAdministrativeNextState,
  actionParametersDigest: Sha256Digest,
): Promise<PreparedAdministrativeNextState> {
  const prior = common.priorManifest;
  const base = {
    ...next,
    pendingApprovals: [...prior.pendingApprovals],
    pendingTransfers: [...prior.pendingTransfers],
  };
  if (input.operationType === 'recover-owner') {
    if (
      Object.hasOwn(input, 'approvalRequest') ||
      Object.hasOwn(input, 'transferIntent')
    ) {
      fail();
    }
    return {
      ...base,
      evidence: collaborationAuthorizationTransitionSchema.shape.evidence.parse({
        kind: 'authority-recovery',
        evidenceDigest: input.authorityRecoveryEvidenceDigest,
      }),
    };
  }

  if (input.operationType === 'transfer-owner') {
    const intent = transferIntentSchema.parse(input.transferIntent);
    if (
      intent.state !== 'recipient-accepted' ||
      intent.operationId !== common.operationId ||
      prior.pendingTransfers.some(
        (candidate) =>
          candidate.transferIntentId === intent.transferIntentId ||
          candidate.intentDigest === intent.intentDigest,
      )
    ) {
      fail();
    }
    const initiator = requireActiveDevice(
      prior.memberships,
      intent.initiatorPrincipalId,
      intent.initiatorDeviceId,
      'owner',
    );
    const priorRecipient = requireActiveDevice(
      prior.memberships,
      intent.recipientPrincipalId,
      intent.recipientDeviceId,
    );
    const nextRecipient = requireActiveDevice(
      next.memberships,
      intent.recipientPrincipalId,
      intent.recipientDeviceId,
      'owner',
    );
    assertNotDenied(common.registry, initiator);
    assertNotDenied(common.registry, priorRecipient);
    assertNotDenied(common.registry, nextRecipient);
    if (
      canonicalJson(priorRecipient) !== canonicalJson(nextRecipient) ||
      intent.recipientAcceptance === undefined ||
      !(await verifyTransferIntent(intent, initiator.signingPublicKey)) ||
      !(await verifyOwnershipTransferAcceptance(
        intent.recipientAcceptance,
        priorRecipient.signingPublicKey,
      ))
    ) {
      fail();
    }
    const result = validateOwnershipTransfer({
      intent,
      priorMemberships: prior.memberships,
      nextMemberships: next.memberships,
      priorTuple: tupleOf(common.priorDocument),
      priorHeadDigest: common.priorDocument.headDigest,
      now: common.timestamp,
      initiatorSignatureVerification: {
        signerPrincipalId: intent.initiatorPrincipalId,
        signerDeviceId: intent.initiatorDeviceId,
        signedIntentDigest: intent.intentDigest,
        signature: intent.initiatorSignature ?? '',
      },
      recipientAcceptanceVerification: {
        signerPrincipalId: intent.recipientPrincipalId,
        signerDeviceId: intent.recipientDeviceId,
        signedIntentDigest: intent.intentDigest,
        signature: intent.recipientAcceptance.signature,
      },
    });
    if (!result.valid || !result.complete) fail();
    let consumedApproval: ApprovalRequest | undefined;
    if (prior.approvalPolicy === 'none') {
      if (
        input.approvalRequest !== undefined ||
        intent.approvalRequestId !== undefined
      ) {
        fail();
      }
    } else {
      const approval = requireValue(input.approvalRequest);
      if (intent.approvalRequestId !== approval.approvalRequestId) fail();
      consumedApproval = await validateAndConsumeApproval(
        common,
        input.operationType,
        approval,
        actionParametersDigest,
      );
    }
    const publishedIntent = transferIntentSchema.parse({
      ...intent,
      state: 'published',
      publishedAt: common.timestamp,
    });
    return {
      ...base,
      pendingApprovals:
        consumedApproval === undefined
          ? base.pendingApprovals
          : [...base.pendingApprovals, consumedApproval],
      pendingTransfers: [...base.pendingTransfers, publishedIntent],
      evidence: collaborationAuthorizationTransitionSchema.shape.evidence.parse({
        kind: 'ownership-transfer',
        evidenceDigest: intent.intentDigest,
      }),
    };
  }

  if (input.transferIntent !== undefined) fail();
  if (prior.approvalPolicy === 'none') {
    if (input.approvalRequest !== undefined) fail();
    return { ...base, evidence: { kind: 'none' } };
  }
  const request = requireValue(input.approvalRequest);
  const consumed = await validateAndConsumeApproval(
    common,
    input.operationType,
    request,
    actionParametersDigest,
  );
  return {
    ...base,
    pendingApprovals: [...base.pendingApprovals, consumed],
    evidence: collaborationAuthorizationTransitionSchema.shape.evidence.parse({
      kind: 'approval',
      evidenceDigest: request.requestDigest,
    }),
  };
}

async function validateAndConsumeApproval(
  common: ParsedCommon,
  operationType: Exclude<CollaborativeAdministrativeOperationType, 'recover-owner'>,
  value: ApprovalRequest,
  actionParametersDigest: Sha256Digest,
): Promise<ApprovalRequest> {
  const prior = common.priorManifest;
  const request = approvalRequestSchema.parse(value);
  if (
    request.state !== 'quorum-reached' ||
    request.operationType !== operationType ||
    request.operationId !== common.operationId ||
    request.actionParametersDigest !== actionParametersDigest ||
    prior.pendingApprovals.some(
      (candidate) =>
        candidate.approvalRequestId === request.approvalRequestId ||
        candidate.requestDigest === request.requestDigest,
    )
  ) {
    fail();
  }
  const requester = requireActiveDevice(
    prior.memberships,
    request.requestingPrincipalId,
    request.requestingDeviceId,
    'owner',
  );
  assertNotDenied(common.registry, requester);
  if (!(await verifyApprovalRequest(request, requester.signingPublicKey))) fail();
  const verifiedApprovals: VerifiedApprovalSignature[] = [];
  for (const evidence of request.approvals) {
    const approver = requireActiveDevice(
      prior.memberships,
      evidence.approverPrincipalId,
      evidence.approverDeviceId,
      'owner',
    );
    assertNotDenied(common.registry, approver);
    if (!(await verifyApprovalEvidence(evidence, approver.signingPublicKey))) fail();
    verifiedApprovals.push({
      approvalRequestId: evidence.approvalRequestId,
      approverPrincipalId: evidence.approverPrincipalId,
      approverDeviceId: evidence.approverDeviceId,
      signedRequestDigest: request.requestDigest,
      signature: evidence.signature,
    });
  }
  const result = validateApproval({
    request,
    priorPolicy: prior.policy,
    priorTuple: tupleOf(common.priorDocument),
    priorHeadDigest: common.priorDocument.headDigest,
    activeMemberships: prior.memberships,
    now: common.timestamp,
    verifiedRequesterSignature: {
      approvalRequestId: request.approvalRequestId,
      requesterPrincipalId: request.requestingPrincipalId,
      requesterDeviceId: request.requestingDeviceId,
      signedRequestDigest: request.requestDigest,
      signature: request.requesterSignature,
    },
    verifiedApprovalSignatures: verifiedApprovals,
  });
  if (!result.valid || !result.eligibleForConsumption) fail();
  return approvalRequestSchema.parse({
    ...request,
    state: 'consumed',
    resolvedAt: common.timestamp,
  });
}

async function parseAndAuthenticateCommon(
  input: CommonMutationInput,
  operationType: CollaborationOperationType,
  recoveryNext?: CollaborativeAdministrativeNextState,
): Promise<ParsedCommon> {
  let actorPrivateKey: Uint8Array | undefined;
  let currentVaultRootKey: Uint8Array | undefined;
  let priorPayload: Uint8Array | undefined;
  let openedManifest: Uint8Array | undefined;
  let openedPayload: Uint8Array | undefined;
  try {
    const priorDocument = collaborativeVaultDocumentSchema.parse(input.prior.document);
    const priorManifest = collaborativeMembershipManifestSchema.parse(
      input.prior.manifest,
    );
    const priorRegistry = collaborationDatabaseDeviceRegistrySchema.parse(
      input.prior.deviceRegistry,
    );
    const registry = collaborationDatabaseDeviceRegistrySchema.parse(
      input.authoritativeDeviceRegistry,
    );
    const timestamp = timestampSchema.parse(input.timestamp);
    const expiresAt = timestampSchema.parse(input.expiresAt);
    if (
      Date.parse(expiresAt) <= Date.parse(timestamp) ||
      Date.parse(timestamp) < Date.parse(priorDocument.updatedAt) ||
      Date.parse(timestamp) < Date.parse(priorManifest.updatedAt) ||
      Date.parse(timestamp) < Date.parse(registry.updatedAt) ||
      input.authorityRecoveryPublicKey !==
        priorDocument.authorityDelegation.authorityRecoveryPublicKey ||
      computePublicKeyFingerprint(input.authorityRecoveryPublicKey, 'x25519') !==
        priorDocument.authorityDelegation.authorityRecoveryKeyFingerprint
    ) {
      fail();
    }
    actorPrivateKey = copySecret(input.actor.deviceSigningPrivateKey, 64);
    currentVaultRootKey = copySecret(input.prior.currentVaultRootKey, 32);
    priorPayload = copyBytes(input.prior.quarantinedVaultPayload);

    await verifyPriorOpaqueAndTrust(priorDocument, priorManifest, priorRegistry);
    await verifyRegistryAdvance(priorRegistry, registry, priorDocument);
    openedManifest = await decryptCollaborationEnvelope(
      priorDocument.encryptedMembershipManifest,
      currentVaultRootKey,
      priorDocument.encryptedMembershipManifest.aad,
    );
    openedPayload = await decryptCollaborationEnvelope(
      priorDocument.encryptedPayload,
      currentVaultRootKey,
      priorDocument.encryptedPayload.aad,
    );
    let expectedManifest: Uint8Array | undefined;
    try {
      expectedManifest = Buffer.from(canonicalJson(priorManifest), 'utf8');
      if (
        !constantTimeEqual(openedManifest, expectedManifest) ||
        !constantTimeEqual(openedPayload, priorPayload)
      ) {
        fail();
      }
      requireExactDatabaseAuthorityRecoveryEnvelope(priorDocument, priorManifest);
    } finally {
      zeroize(expectedManifest);
    }

    const actorMembership =
      operationType === 'recover-owner'
        ? requireRecoveryReplacement(priorManifest, recoveryNext)
        : unique(
            priorManifest.memberships.filter(
              (membership) => membership.principalId === input.actor.principalId,
            ),
          );
    if (actorMembership.principalId !== input.actor.principalId) fail();
    const actorDevice = deviceCertificateSchema.parse(input.actor.deviceCertificate);
    const manifestDevice = unique(
      actorMembership.devices.filter(
        (device) => device.deviceId === input.actor.deviceId,
      ),
    );
    if (
      actorMembership.rootSigningPublicKey !== input.actor.rootSigningPublicKey ||
      canonicalJson(actorDevice) !== canonicalJson(manifestDevice) ||
      actorDevice.principalId !== actorMembership.principalId ||
      computePublicKeyFingerprint(actorMembership.rootSigningPublicKey, 'ed25519') !==
        actorMembership.principalFingerprint
    ) {
      fail();
    }
    assertNotDenied(priorRegistry, actorDevice);
    assertNotDenied(registry, actorDevice);
    assertDeviceUsableAt(actorDevice, timestamp);
    if (operationType !== 'recover-owner') {
      const authorized = authorizeOperation({
        operationType,
        membership: actorMembership,
        device: actorDevice,
        authoritativeRegistry: registry,
        deviceSigningKeyFingerprint: computePublicKeyFingerprint(
          actorDevice.signingPublicKey,
          'ed25519',
        ),
      });
      if (!authorized.authorized) fail();
    }
    const fence = evaluateDeviceFence({
      vault: tupleOf(priorDocument),
      authoritativeRegistry: registry,
      actorDevice,
      actorSigningKeyFingerprint: computePublicKeyFingerprint(
        actorDevice.signingPublicKey,
        'ed25519',
      ),
    });
    if (!fence.canWrite && !fence.rekeyRequired) fail();
    if (operationType === 'ordinary-write' && !fence.canWrite) fail();
    if (
      input.anchorScope.databaseId !== priorDocument.databaseId ||
      input.anchorScope.vaultId !== priorDocument.vaultId ||
      input.anchorScope.principalId !== actorMembership.principalId ||
      input.anchorScope.deviceId !== actorDevice.deviceId
    ) {
      fail();
    }
    return {
      priorDocument,
      priorManifest,
      priorRegistry,
      registry,
      actorMembership,
      actorDevice,
      actorPrivateKey,
      currentVaultRootKey,
      priorPayload,
      authorityRecoveryPublicKey: input.authorityRecoveryPublicKey,
      timestamp,
      expiresAt,
      operationId: input.operationId,
      anchorScope: input.anchorScope,
    };
  } catch {
    zeroize(actorPrivateKey);
    zeroize(currentVaultRootKey);
    zeroize(priorPayload);
    throw new CollaborationCandidatePreparationError();
  } finally {
    zeroize(openedManifest);
    zeroize(openedPayload);
  }
}

function requireRecoveryReplacement(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeAdministrativeNextState | undefined,
): CollaborationMembership {
  if (next === undefined) fail();
  const priorByPrincipal = new Map(
    prior.memberships.map((membership) => [membership.principalId, membership]),
  );
  const replacements = next.memberships.filter((membership) => {
    const previous = priorByPrincipal.get(membership.principalId);
    return (
      membership.state === 'active' &&
      membership.role === 'owner' &&
      (previous?.state !== 'active' || previous.role !== 'owner')
    );
  });
  return unique(replacements);
}

async function verifyPriorOpaqueAndTrust(
  document: CollaborativeVaultDocument,
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
): Promise<void> {
  const delegation = document.authorityDelegation;
  if (
    computeAuthorityDelegationDigest(delegation) !==
      document.authorityDelegationDigest ||
    !(await verifyAuthorityDelegation(
      delegation,
      delegation.authoritySigningPublicKey,
    )) ||
    registry.databaseId !== document.databaseId ||
    registry.authorityEpoch !== document.authorityEpoch ||
    registry.generation !== document.databaseDeviceGeneration ||
    registry.registryDigest !== document.databaseDeviceRegistryDigest ||
    registry.authorityFingerprint !== delegation.authoritySigningKeyFingerprint ||
    computeDeviceRegistryDigest(registry) !== registry.registryDigest ||
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.deviceRegistrySignature,
      registry,
      collaborationDatabaseDeviceRegistrySchema,
      'authoritySignature',
      delegation.authoritySigningPublicKey,
    ))
  ) {
    fail();
  }
  if (
    computeAadMetadataDigest(
      collaborationAadMetadataSchema.parse(
        withoutMetadataDigest(document.encryptedPayload.aad),
      ),
    ) !== document.encryptedPayload.aad.metadataDigest ||
    computeAadMetadataDigest(
      collaborationAadMetadataSchema.parse(
        withoutMetadataDigest(document.encryptedMembershipManifest.aad),
      ),
    ) !== document.encryptedMembershipManifest.aad.metadataDigest ||
    computeEncryptedPayloadDigest(document.encryptedPayload) !==
      document.encryptedPayloadDigest ||
    computeEncryptedMembershipDigest(document.encryptedMembershipManifest) !==
      document.encryptedMembershipDigest ||
    computeMembershipManifestDigest(manifest) !== manifest.membershipDigest ||
    computeMembershipHistoryDigest(manifest.history) !==
      manifest.history.currentHistoryDigest ||
    computePolicyDigest(manifest.policy) !== document.policyDigest ||
    manifest.policy.policyDigest !== document.policyDigest ||
    computeKeyEnvelopeSetDigest(manifest.keyEnvelopes) !==
      document.encryptedEnvelopesDigest ||
    computeAuthorizationStateDigest(authorizationCoreFromManifest(manifest)) !==
      document.authorizationStateDigest ||
    manifest.authorizationStateDigest !== document.authorizationStateDigest ||
    manifest.documentRevision !== document.documentRevision ||
    manifest.membershipRevision !== document.membershipRevision ||
    manifest.policyRevision !== document.policyRevision ||
    manifest.keyEpoch !== document.keyEpoch ||
    manifest.previousHeadDigest !== document.previousHeadDigest
  ) {
    fail();
  }
  const ownerInvariant = checkActiveOwnerInvariant({
    memberships: manifest.memberships,
    ownerPrincipalIds: manifest.ownerPrincipalIds,
  });
  if (!ownerInvariant.valid) fail();
  await verifyManifestTrust(document, manifest, registry);
  const writer = requireDevice(
    manifest.memberships,
    document.currentMutationLink.commitment.writerPrincipalId,
    document.currentMutationLink.commitment.writerDeviceId,
  );
  const priorCommitment = document.currentMutationLink.commitment;
  if (
    Date.parse(document.currentMutationLink.finalizedAt) <
      Date.parse(priorCommitment.timestamp) ||
    (priorCommitment.expiresAt !== undefined &&
      Date.parse(document.currentMutationLink.finalizedAt) >=
        Date.parse(priorCommitment.expiresAt)) ||
    computeMutationHead(priorCommitment) !== document.headDigest ||
    (priorCommitment.operationType !== 'genesis-migration' &&
      computeMutationRequestDigest(priorCommitment) !==
        priorCommitment.requestDigest) ||
    !(await verifyFinalizedMutationLink(
      document.currentMutationLink,
      writer.signingPublicKey,
    ))
  ) {
    fail();
  }
  const authorizationTransition = document.currentMutationLink.authorizationTransition;
  if (authorizationTransition !== undefined) {
    if (
      authorizationTransition.transitionSignature.signerKind === 'database-authority'
    ) {
      if (
        authorizationTransition.operationType !== 'recover-owner' ||
        !(await verifyAuthorizationTransitionAuthority(
          authorizationTransition,
          delegation.authoritySigningPublicKey,
        ))
      ) {
        fail();
      }
    } else {
      const signer = requireDevice(
        manifest.memberships,
        authorizationTransition.transitionSignature.signerPrincipalId,
        authorizationTransition.transitionSignature.signerDeviceId,
      );
      assertNotDenied(registry, signer);
      if (
        !(await verifyAuthorizationTransitionOwner(
          authorizationTransition,
          signer.signingPublicKey,
        ))
      ) {
        fail();
      }
    }
  }
}

async function verifyRegistryAdvance(
  prior: CollaborationDatabaseDeviceRegistry,
  current: CollaborationDatabaseDeviceRegistry,
  document: CollaborativeVaultDocument,
): Promise<void> {
  const delegation = document.authorityDelegation;
  if (
    current.databaseId !== prior.databaseId ||
    current.databaseId !== document.databaseId ||
    current.authorityEpoch !== prior.authorityEpoch ||
    current.authorityEpoch !== delegation.authorityEpoch ||
    current.authorityFingerprint !== prior.authorityFingerprint ||
    current.authorityFingerprint !== delegation.authoritySigningKeyFingerprint ||
    computeDeviceRegistryDigest(current) !== current.registryDigest ||
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.deviceRegistrySignature,
      current,
      collaborationDatabaseDeviceRegistrySchema,
      'authoritySignature',
      delegation.authoritySigningPublicKey,
    ))
  ) {
    fail();
  }
  if (current.generation === prior.generation) {
    if (canonicalJson(current) !== canonicalJson(prior)) fail();
    return;
  }
  if (
    current.generation !== prior.generation + 1 ||
    current.previousRegistryDigest !== prior.registryDigest ||
    !prior.deniedDevices.every((denial) =>
      current.deniedDevices.some(
        (candidate) => canonicalJson(candidate) === canonicalJson(denial),
      ),
    )
  ) {
    fail();
  }
}

async function verifyManifestTrust(
  document: CollaborativeVaultDocument,
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
): Promise<void> {
  for (const membership of manifest.memberships) {
    if (
      computePublicKeyFingerprint(membership.rootSigningPublicKey, 'ed25519') !==
      membership.principalFingerprint
    ) {
      fail();
    }
    for (const device of membership.devices) {
      if (
        !(await verifyCollaborationRecord(
          COLLABORATION_DOMAINS.deviceCertificateSignature,
          device,
          deviceCertificateSchema,
          'rootSignature',
          membership.rootSigningPublicKey,
        ))
      ) {
        fail();
      }
    }
  }
  const policyDevice = requireDevice(
    manifest.memberships,
    manifest.policy.changedByPrincipalId,
    manifest.policy.changedByDeviceId,
  );
  assertNotDenied(registry, policyDevice);
  if (
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.policySignature,
      manifest.policy,
      collaborationPolicyStateSchema,
      'signature',
      policyDevice.signingPublicKey,
    ))
  ) {
    fail();
  }
  for (const event of manifest.history.events) {
    const device = requireHistoricalSigner(
      manifest.memberships,
      registry,
      event.actorPrincipalId,
      event.actorDeviceId,
      event.timestamp,
    );
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistorySignature,
        event,
        membershipHistoryEventSchema,
        'signature',
        device.signingPublicKey,
      ))
    ) {
      fail();
    }
  }
  for (const checkpoint of manifest.history.checkpoints) {
    const signer = requireHistoricalSigner(
      manifest.memberships,
      registry,
      checkpoint.signerPrincipalId,
      checkpoint.signerDeviceId,
      checkpoint.createdAt,
    );
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
        checkpoint,
        membershipHistoryCheckpointSchema,
        'signature',
        signer.signingPublicKey,
      ))
    ) {
      fail();
    }
  }
  const owners = activeOwnerDevices(manifest.memberships).filter(
    (device) => !isDenied(registry, device),
  );
  for (const envelope of manifest.keyEnvelopes) {
    const digest =
      'membershipId' in envelope
        ? computeKeyEnvelopeDigest(envelope)
        : computeAuthorityRecoveryEnvelopeDigest(envelope);
    if (digest !== envelope.envelopeDigest) fail();
    let verified = false;
    for (const owner of owners) {
      const signatureValid =
        'membershipId' in envelope
          ? await verifyCollaborationRecord(
              COLLABORATION_DOMAINS.keyEnvelopeSignature,
              envelope,
              collaborationKeyEnvelopeSchema,
              'ownerSignature',
              owner.signingPublicKey,
            )
          : await verifyCollaborationRecord(
              COLLABORATION_DOMAINS.keyEnvelopeSignature,
              envelope,
              databaseAuthorityRecoveryEnvelopeSchema,
              'ownerSignature',
              owner.signingPublicKey,
            );
      if (signatureValid) {
        verified = true;
        break;
      }
    }
    if (!verified) fail();
  }
  const writer = requireDevice(
    manifest.memberships,
    document.currentMutationLink.writerSignature.writerPrincipalId,
    document.currentMutationLink.writerSignature.writerDeviceId,
  );
  assertNotDenied(registry, writer);
  for (const record of document.discoveryRecords) {
    const membership = unique(
      manifest.memberships.filter(
        (candidate) => candidate.membershipId === record.membershipId,
      ),
    );
    const matchingEnvelope = unique(
      manifest.keyEnvelopes.filter(
        (envelope) =>
          'membershipId' in envelope &&
          envelope.membershipId === record.membershipId &&
          envelope.deviceId === record.encryptedMemberKeyEnvelope.deviceId,
      ),
    );
    if (
      membership.state !== 'active' ||
      computeDiscoveryTag(manifest.databaseId, membership.principalFingerprint) !==
        record.discoveryTag ||
      canonicalJson(matchingEnvelope) !==
        canonicalJson(record.encryptedMemberKeyEnvelope) ||
      computeDiscoveryRecordDigest(record) !== record.discoveryRecordDigest ||
      !(await verifyDiscoveryRecord(record, writer.signingPublicKey))
    ) {
      fail();
    }
  }
  if (
    document.discoveryRecords.length !==
    manifest.keyEnvelopes.filter((envelope) => 'membershipId' in envelope).length
  ) {
    fail();
  }
}

async function verifyNextMembershipTrust(
  memberships: readonly CollaborationMembership[],
  registry: CollaborationDatabaseDeviceRegistry,
  timestamp: Timestamp,
): Promise<void> {
  for (const membership of memberships) {
    if (
      computePublicKeyFingerprint(membership.rootSigningPublicKey, 'ed25519') !==
      membership.principalFingerprint
    ) {
      fail();
    }
    for (const device of membership.devices) {
      if (
        !(await verifyCollaborationRecord(
          COLLABORATION_DOMAINS.deviceCertificateSignature,
          device,
          deviceCertificateSchema,
          'rootSignature',
          membership.rootSigningPublicKey,
        ))
      ) {
        fail();
      }
      if (membership.state === 'active' && device.state === 'active') {
        assertNotDenied(registry, device);
        assertDeviceUsableAt(device, timestamp);
      }
    }
  }
}

function authorizationCoreFromManifest(
  manifest: CollaborativeMembershipManifest,
): CollaborationAuthorizationStateCore {
  return collaborationAuthorizationStateCoreSchema.parse({
    protocolVersion: manifest.protocolVersion,
    databaseId: manifest.databaseId,
    vaultId: manifest.vaultId,
    authorityEpoch: manifest.authorityEpoch,
    databaseDeviceGeneration: manifest.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: manifest.databaseDeviceRegistryDigest,
    membershipRevision: manifest.membershipRevision,
    policyRevision: manifest.policyRevision,
    keyEpoch: manifest.keyEpoch,
    memberships: manifest.memberships.map((membership) => ({
      membershipId: membership.membershipId,
      principalId: membership.principalId,
      principalFingerprint: membership.principalFingerprint,
      rootSigningPublicKey: membership.rootSigningPublicKey,
      identityGeneration: membership.identityGeneration,
      role: membership.role,
      state: membership.state,
      devices: membership.devices.map(withoutDeviceRootSignature),
      createdAt: membership.createdAt,
      updatedAt: membership.updatedAt,
      ...(membership.removedAt === undefined
        ? {}
        : { removedAt: membership.removedAt }),
    })),
    ownerPrincipalIds: manifest.ownerPrincipalIds,
    keyEnvelopes: manifest.keyEnvelopes.map(authorizationEnvelopeCore),
    approvalPolicy: manifest.approvalPolicy,
  });
}

function aadFor(
  common: ParsedCommon,
  tuple: CollaborationRevisionTuple,
  entityType: 'vault-payload' | 'membership-manifest',
): ReturnType<typeof collaborationAadSchema.parse> {
  const metadata = collaborationAadMetadataSchema.parse({
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: common.priorDocument.databaseId,
    vaultId: common.priorDocument.vaultId,
    authorityEpoch: tuple.authorityEpoch,
    entityType,
    entityId: common.priorDocument.vaultId,
    documentRevision: tuple.documentRevision,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    authorizationStateDigest: tuple.authorizationStateDigest,
  });
  return collaborationAadSchema.parse({
    ...metadata,
    metadataDigest: computeAadMetadataDigest(metadata),
  });
}

function withoutMetadataDigest(
  aad: ReturnType<typeof collaborationAadSchema.parse>,
): Record<string, unknown> {
  const metadata: Record<string, unknown> = { ...aad };
  Reflect.deleteProperty(metadata, 'metadataDigest');
  return metadata;
}

function withoutDeviceRootSignature(
  device: DeviceCertificate,
): Record<string, unknown> {
  const core: Record<string, unknown> = { ...device };
  Reflect.deleteProperty(core, 'rootSignature');
  return core;
}

function authorizationEnvelopeCore(
  envelope: CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope,
): Record<string, unknown> {
  const core: Record<string, unknown> = { ...envelope };
  Reflect.deleteProperty(core, 'envelopeDigest');
  Reflect.deleteProperty(core, 'createdAt');
  Reflect.deleteProperty(core, 'ownerSignature');
  return core;
}

function ordinarySemanticState(
  manifest: CollaborativeMembershipManifest,
): PreparedAdministrativeNextState {
  return {
    memberships: manifest.memberships,
    ownerPrincipalIds: manifest.ownerPrincipalIds,
    approvalPolicy: manifest.approvalPolicy,
    pendingApprovals: manifest.pendingApprovals,
    pendingTransfers: manifest.pendingTransfers,
    evidence: { kind: 'none' },
    historyEvent: { eventType: 'key-rotated' },
  };
}

function parseAdministrativeSemantic(
  next: CollaborativeAdministrativeNextState,
): CollaborativeAdministrativeNextState {
  assertExactObjectKeys(next, [
    'memberships',
    'ownerPrincipalIds',
    'approvalPolicy',
    'historyEvent',
  ]);
  const memberships = next.memberships.map((membership) =>
    collaborationMembershipParse(membership),
  );
  return {
    memberships,
    ownerPrincipalIds:
      collaborativeMembershipManifestSchema.shape.ownerPrincipalIds.parse(
        next.ownerPrincipalIds,
      ),
    approvalPolicy: collaborativeMembershipManifestSchema.shape.approvalPolicy.parse(
      next.approvalPolicy,
    ),
    historyEvent: parseAdministrativeHistoryEvent(next.historyEvent),
  };
}

function parseAdministrativeHistoryEvent(
  value: CollaborativeAdministrativeHistoryEvent,
): CollaborativeAdministrativeHistoryEvent {
  assertExactObjectKeys(value, [
    'eventType',
    'targetPrincipalId',
    'targetDeviceId',
    'previousRole',
    'newRole',
    'previousState',
    'newState',
  ]);
  return {
    eventType: membershipHistoryEventSchema.shape.eventType.parse(value.eventType),
    ...(value.targetPrincipalId === undefined
      ? {}
      : {
          targetPrincipalId: membershipHistoryEventSchema.shape.targetPrincipalId.parse(
            value.targetPrincipalId,
          ),
        }),
    ...(value.targetDeviceId === undefined
      ? {}
      : {
          targetDeviceId: membershipHistoryEventSchema.shape.targetDeviceId.parse(
            value.targetDeviceId,
          ),
        }),
    ...(value.previousRole === undefined
      ? {}
      : {
          previousRole: membershipHistoryEventSchema.shape.previousRole.parse(
            value.previousRole,
          ),
        }),
    ...(value.newRole === undefined
      ? {}
      : {
          newRole: membershipHistoryEventSchema.shape.newRole.parse(value.newRole),
        }),
    ...(value.previousState === undefined
      ? {}
      : {
          previousState: membershipHistoryEventSchema.shape.previousState.parse(
            value.previousState,
          ),
        }),
    ...(value.newState === undefined
      ? {}
      : {
          newState: membershipHistoryEventSchema.shape.newState.parse(value.newState),
        }),
  };
}

function assertExactObjectKeys(value: object, allowedKeys: readonly string[]): void {
  const allowed = new Set(allowedKeys);
  if (Object.keys(value).some((key) => !allowed.has(key))) fail();
  const required = allowed.has('memberships')
    ? ['memberships', 'ownerPrincipalIds', 'approvalPolicy', 'historyEvent']
    : ['eventType'];
  for (const key of required) {
    if (!Object.hasOwn(value, key)) fail();
  }
}

function collaborationMembershipParse(
  membership: CollaborationMembership,
): CollaborationMembership {
  return collaborativeMembershipManifestSchema.shape.memberships.element.parse(
    membership,
  );
}

function selectArtifactOwnerSigner(
  input: BuildAdministrativeCollaborativeMutationInput,
  common: ParsedCommon,
  next: CollaborativeAdministrativeNextState,
): Readonly<{
  principalId: CollaborationMembership['principalId'];
  deviceId: DeviceCertificate['deviceId'];
  privateKey: Uint8Array;
  publicKey: string;
}> {
  const supplied = input.artifactOwnerSigner;
  if (input.operationType === 'recover-owner' && supplied !== undefined) fail();
  const principalId = supplied?.principalId ?? common.actorMembership.principalId;
  const deviceId = supplied?.deviceId ?? common.actorDevice.deviceId;
  const device = requireActiveDevice(next.memberships, principalId, deviceId, 'owner');
  assertNotDenied(common.registry, device);
  assertDeviceUsableAt(device, common.timestamp);
  return {
    principalId,
    deviceId,
    privateKey: copySecret(
      supplied?.deviceSigningPrivateKey ?? common.actorPrivateKey,
      64,
    ),
    publicKey: device.signingPublicKey,
  };
}

function decryptAccessSet(
  memberships: readonly CollaborationMembership[],
): readonly string[] {
  return memberships
    .filter((membership) => membership.state === 'active')
    .flatMap((membership) =>
      membership.devices
        .filter((device) => device.state === 'active')
        .map(
          (device) =>
            `${membership.membershipId}:${membership.principalId}:${device.deviceId}:${device.encryptionPublicKey}`,
        ),
    )
    .sort();
}

function optionalHistoryDetails(
  details: CollaborativeAdministrativeHistoryEvent,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(details).filter(
      ([key, value]) => key !== 'eventType' && value !== undefined,
    ),
  );
}

function approvalHistoryFields(
  requests: readonly ApprovalRequest[],
  evidence: Extract<
    CollaborationAuthorizationTransition['evidence'],
    { kind: 'approval' }
  >,
): Readonly<{
  approvalRequestId: ApprovalRequest['approvalRequestId'];
  approvalRequestDigest: Sha256Digest;
}> {
  const request = unique(
    requests.filter((candidate) => candidate.requestDigest === evidence.evidenceDigest),
  );
  return {
    approvalRequestId: request.approvalRequestId,
    approvalRequestDigest: request.requestDigest,
  };
}

function tupleOf(document: CollaborativeVaultDocument): CollaborationRevisionTuple {
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: document.authorityEpoch,
    documentRevision: document.documentRevision,
    membershipRevision: document.membershipRevision,
    policyRevision: document.policyRevision,
    keyEpoch: document.keyEpoch,
    databaseDeviceGeneration: document.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: document.databaseDeviceRegistryDigest,
    authorizationStateDigest: document.authorizationStateDigest,
  });
}

function requireActiveDevice(
  memberships: readonly CollaborationMembership[],
  principalId: string,
  deviceId: string,
  role?: CollaborationMembership['role'],
): DeviceCertificate {
  const membership = unique(
    memberships.filter(
      (candidate) =>
        candidate.principalId === principalId &&
        candidate.state === 'active' &&
        (role === undefined || candidate.role === role),
    ),
  );
  const device = unique(
    membership.devices.filter(
      (candidate) => candidate.deviceId === deviceId && candidate.state === 'active',
    ),
  );
  return device;
}

function requireDevice(
  memberships: readonly CollaborationMembership[],
  principalId: string,
  deviceId: string,
): DeviceCertificate {
  const membership = unique(
    memberships.filter((candidate) => candidate.principalId === principalId),
  );
  return unique(
    membership.devices.filter((candidate) => candidate.deviceId === deviceId),
  );
}

function activeOwnerDevices(
  memberships: readonly CollaborationMembership[],
): readonly DeviceCertificate[] {
  return memberships
    .filter(
      (membership) => membership.state === 'active' && membership.role === 'owner',
    )
    .flatMap((membership) =>
      membership.devices.filter((device) => device.state === 'active'),
    );
}

function assertNotDenied(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
): void {
  if (isDenied(registry, device)) fail();
}

function assertDeviceUsableAt(device: DeviceCertificate, timestamp: Timestamp): void {
  const instant = Date.parse(timestamp);
  if (
    device.state !== 'active' ||
    instant < Date.parse(device.createdAt) ||
    instant < Date.parse(device.stateChangedAt) ||
    (device.expiresAt !== undefined && instant >= Date.parse(device.expiresAt))
  ) {
    fail();
  }
}

function requireHistoricalSigner(
  memberships: readonly CollaborationMembership[],
  registry: CollaborationDatabaseDeviceRegistry,
  principalId: CollaborationMembership['principalId'],
  deviceId: DeviceCertificate['deviceId'],
  timestamp: Timestamp,
): DeviceCertificate {
  const membership = unique(
    memberships.filter((candidate) => candidate.principalId === principalId),
  );
  const device = unique(
    membership.devices.filter((candidate) => candidate.deviceId === deviceId),
  );
  const instant = Date.parse(timestamp);
  if (
    instant < Date.parse(membership.createdAt) ||
    (membership.removedAt !== undefined &&
      instant >= Date.parse(membership.removedAt)) ||
    instant < Date.parse(device.createdAt) ||
    (device.state === 'active'
      ? instant < Date.parse(device.stateChangedAt)
      : instant >= Date.parse(device.stateChangedAt)) ||
    (device.expiresAt !== undefined && instant >= Date.parse(device.expiresAt)) ||
    registry.deniedDevices.some(
      (denial) =>
        denialMatchesDevice(denial, device) && instant >= Date.parse(denial.deniedAt),
    )
  ) {
    fail();
  }
  return device;
}

function isDenied(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
): boolean {
  return registry.deniedDevices.some((denial) => denialMatchesDevice(denial, device));
}

function denialMatchesDevice(
  denial: CollaborationDatabaseDeviceRegistry['deniedDevices'][number],
  device: DeviceCertificate,
): boolean {
  return (
    (denial.principalId === device.principalId &&
      denial.deviceId === device.deviceId) ||
    denial.signingKeyFingerprint ===
      computePublicKeyFingerprint(device.signingPublicKey, 'ed25519')
  );
}

function copySecret(value: Uint8Array, length: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) fail();
  return Uint8Array.from(value);
}

function copyBytes(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength === 0) fail();
  return Uint8Array.from(value);
}

function wipeParsedCommon(value: ParsedCommon | undefined): void {
  zeroize(value?.actorPrivateKey);
  zeroize(value?.currentVaultRootKey);
  zeroize(value?.priorPayload);
}

function unique<T>(values: readonly T[]): T {
  if (values.length !== 1 || values[0] === undefined) fail();
  return values[0];
}

function requireValue<T>(value: T | undefined): T {
  if (value === undefined) fail();
  return value;
}

function fail(): never {
  throw new CollaborationCandidatePreparationError();
}

function freezePrepared(
  value: BuiltCandidate & Readonly<{ nextVaultRootKey?: VaultRootKey }>,
): PreparedCollaborativeMutation {
  deepFreeze(value.candidate);
  deepFreeze(value.proofEntry);
  deepFreeze(value.proposedOutcome);
  deepFreeze(value.candidateAnchor);
  return Object.freeze({
    candidate: value.candidate,
    proofEntry: value.proofEntry,
    proposedOutcome: value.proposedOutcome,
    candidateAnchor: value.candidateAnchor,
    ...(value.nextVaultRootKey === undefined
      ? {}
      : { nextVaultRootKey: value.nextVaultRootKey }),
  });
}

function deepFreeze(value: unknown): void {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
}
