import {
  authorizeOperation,
  checkActiveOwnerInvariant,
  validateApproval,
  validateRevisionTransition,
} from '@kavrix/core';
import {
  COLLABORATION_DOMAINS,
  computeAadMetadataDigest,
  computeAuthorizationStateDigest,
  computeAuthorizationTransitionDigest,
  computeCollaborativeVaultDestroyedPayloadDigest,
  computeCollaborativeVaultDestructionActionDigest,
  computeDiscoveryRecordDigest,
  computeDiscoveryTag,
  computeEncryptedMembershipDigest,
  computeFinalizedMutationLinkDigest,
  computeKeyEnvelopeSetDigest,
  computeMembershipHistoryDigest,
  computeMembershipManifestDigest,
  computeMutationHead,
  computeMutationRequestDigest,
  computeOperationOutcomeDigest,
  computePolicyDigest,
  computePublicKeyFingerprint,
  decryptCollaborationEnvelope,
  encryptCollaborationEnvelope,
  signAuthorizationTransitionOwner,
  signDiscoveryRecord,
  signFinalizedMutationLink,
  signMutationReceipt,
  verifyApprovalEvidence,
  verifyApprovalRequest,
  verifyAuthorizationTransitionOwner,
  verifyCollaborationRecord,
  verifyCommittedOperationOutcome,
  verifyDiscoveryRecord,
  verifyFinalizedMutationLink,
  verifyOperationTombstone,
  zeroize,
  type DeviceEncryptionPrivateKey,
  type DeviceSigningPrivateKey,
} from '@kavrix/crypto';
import {
  createCollaborativeVaultDestructionJournal,
  createOrVerifyRecipientVaultDestructionAnchor,
  readCollaborativeVaultDestructionJournal,
  recipientVaultDestructionAnchorFromTombstone,
  reconcileCollaborativeVaultDestructionJournal,
  verifyCommittedCollaborativeVaultDestructionJournal,
  type CollaborationVaultDestructionJournalScope,
  type CollaborativeVaultDestructionJournalRecord,
  type RecipientVaultDestructionAnchorScope,
} from '@kavrix/key-files';
import {
  COLLABORATION_PROTOCOL_VERSION,
  COLLABORATIVE_AUTHORIZATION_TRANSITION_FORMAT,
  COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT,
  COLLABORATIVE_DISCOVERY_RECORD_FORMAT,
  COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT,
  COLLABORATIVE_MEMBERSHIP_MANIFEST_FORMAT,
  COLLABORATIVE_MUTATION_RECEIPT_FORMAT,
  COLLABORATIVE_OPERATION_OUTCOME_FORMAT,
  COLLABORATIVE_VAULT_DESTRUCTION_CORE_FORMAT,
  COLLABORATIVE_VAULT_DESTRUCTION_TOMBSTONE_FORMAT,
  approvalRequestSchema,
  canonicalJson,
  collaborationAadMetadataSchema,
  collaborationAadSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationTransitionSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationMutationCommitmentSchema,
  collaborationMutationProofEntrySchema,
  collaborationOperationIdSchema,
  collaborationRevisionTupleSchema,
  collaborationVaultDestructionActionSchema,
  collaborationVaultDestructionCoreSchema,
  collaborationVaultDestructionTombstoneSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  durableOperationOutcomeSchema,
  membershipHistoryCheckpointSchema,
  membershipHistoryEventSchema,
  operationDeduplicationTombstoneSchema,
  recipientVaultDestructionAnchorSchema,
  timestampSchema,
  type ApprovalRequest,
  type CollaborationAeadEnvelope,
  type CollaborationAuthorizationTransition,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationDiscoveryRecord,
  type CollaborationMembership,
  type CollaborationMutationCommitment,
  type CollaborationRevisionTuple,
  type CollaborationVaultDestructionTombstone,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DeviceCertificate,
  type DurableOperationOutcome,
  type OperationDeduplicationTombstone,
  type RecipientVaultDestructionAnchor,
  type Sha256Digest,
  type Timestamp,
} from '@kavrix/schemas';
import {
  EncryptedDatabaseStoreError,
  type CollaborativeVaultStore,
} from '@kavrix/storage';

import {
  CollaborationStateVerificationError,
  openCollaborativeVaultWithPinnedTrust,
  type CollaborativeVaultPinnedTrust,
} from './collaboration-state-verifier.js';
import {
  appendOrCompactMembershipHistory,
  verifyMembershipHistoryAppendOrCompaction,
} from './collaboration-history.js';

const SAFE_MESSAGE = 'Collaborative vault destruction failed.';
const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');

export type CollaborationVaultDestructionFailureKind =
  | 'invalid-input'
  | 'trust-invalid'
  | 'current-state-invalid'
  | 'approval-invalid'
  | 'artifact-invalid';

/** Stable, non-oracular failure metadata safe for terminal and log boundaries. */
export class CollaborationVaultDestructionError extends Error {
  readonly safe = true;
  readonly kind: CollaborationVaultDestructionFailureKind;

  constructor(kind: CollaborationVaultDestructionFailureKind) {
    super(SAFE_MESSAGE);
    this.name = 'CollaborationVaultDestructionError';
    this.kind = kind;
  }
}

export type CollaborationVaultDestructionResult =
  | Readonly<{
      status: 'committed';
      disposition: 'published' | 'already-committed';
      tombstone: CollaborationVaultDestructionTombstone;
      outcome: DurableOperationOutcome | OperationDeduplicationTombstone;
    }>
  | Readonly<{
      status: 'retryable';
      reason: 'conflict' | 'rejected';
    }>
  | Readonly<{
      status: 'terminal';
      reason:
        'operation-id-reused' | 'remote-evidence-invalid' | 'remote-state-corrupt';
    }>
  | Readonly<{
      status: 'unknown';
      reason:
        | 'journal-persistence-failed'
        | 'publication-ambiguous'
        | 'readback-unavailable'
        | 'anchor-persistence-failed';
    }>;

export type DestroyCollaborativeVaultWithPinnedTrustInput = Readonly<{
  store: CollaborativeVaultStore;
  document: unknown;
  authoritativeDeviceRegistry: unknown;
  mutationProof?: unknown;
  trusted: CollaborativeVaultPinnedTrust;
  scope: RecipientVaultDestructionAnchorScope;
  recipientEncryptionPrivateKey: DeviceEncryptionPrivateKey | Uint8Array;
  deviceSigningPrivateKey: DeviceSigningPrivateKey | Uint8Array;
  deviceProtectionSecret: Uint8Array;
  rollbackAnchorPath: string;
  destructionJournalPath: string;
  destructionAnchorPath: string;
  operationId: CollaborationMutationCommitment['operationId'];
  destroyedAt: Timestamp;
  expiresAt: Timestamp;
  detailsRetainedUntil: Timestamp;
  approvalRequest?: unknown;
}>;

type ParsedInput = Readonly<{
  store: CollaborativeVaultStore;
  document: unknown;
  authoritativeDeviceRegistry: CollaborationDatabaseDeviceRegistry;
  mutationProof?: unknown;
  trusted: CollaborativeVaultPinnedTrust;
  scope: CollaborationVaultDestructionJournalScope;
  rollbackAnchorPath: string;
  destructionJournalPath: string;
  destructionAnchorPath: string;
  operationId: CollaborationMutationCommitment['operationId'];
  destroyedAt: Timestamp;
  expiresAt: Timestamp;
  detailsRetainedUntil: Timestamp;
  approvalRequest?: unknown;
}>;

type PreparedApproval = Readonly<{
  evidence: CollaborationAuthorizationTransition['evidence'];
  pendingApprovals: readonly ApprovalRequest[];
  consumedApproval?: ApprovalRequest;
}>;

type DestructionArtifacts = Readonly<{
  tombstone: CollaborationVaultDestructionTombstone;
  outcome: DurableOperationOutcome;
  recipientAnchor: RecipientVaultDestructionAnchor;
}>;

type RemoteEvidenceRead =
  | Readonly<{
      kind: 'committed';
      tombstone: CollaborationVaultDestructionTombstone;
      outcome: DurableOperationOutcome | OperationDeduplicationTombstone;
    }>
  | Readonly<{ kind: 'not-committed' }>
  | Readonly<{ kind: 'conflict' }>
  | Readonly<{
      kind: 'invalid';
      reason:
        'operation-id-reused' | 'remote-evidence-invalid' | 'remote-state-corrupt';
    }>
  | Readonly<{ kind: 'unavailable' }>;

/**
 * Authenticates and irreversibly destroys one collaborative vault. The local
 * journal is the source of exact restart bytes; a terminal anchor is created
 * only after authoritative tombstone/outcome readback and journal commitment.
 */
export async function destroyCollaborativeVaultWithPinnedTrust(
  input: DestroyCollaborativeVaultWithPinnedTrustInput,
): Promise<CollaborationVaultDestructionResult> {
  let recipientPrivateKey: Uint8Array | undefined;
  let writerPrivateKey: Uint8Array | undefined;
  let protectionSecret: Uint8Array | undefined;
  let vaultRootKey: Uint8Array | undefined;
  let openedVaultRootKey: Uint8Array | undefined;
  let openedPayload: Uint8Array | undefined;
  try {
    const parsed = parseInput(input);
    recipientPrivateKey = copySecret(input.recipientEncryptionPrivateKey, 32);
    writerPrivateKey = copySecret(input.deviceSigningPrivateKey, 64);
    protectionSecret = copySecret(input.deviceProtectionSecret, 32);

    const opened = await openPriorState(parsed, recipientPrivateKey, protectionSecret);
    openedVaultRootKey = opened.vaultRootKey;
    openedPayload = opened.decryptedPayload;
    vaultRootKey = copySecret(openedVaultRootKey, 32);
    zeroize(openedVaultRootKey);
    openedVaultRootKey = undefined;
    zeroize(openedPayload);
    openedPayload = undefined;

    const priorDocument = collaborativeVaultDocumentSchema.parse(opened.document);
    const priorManifest = collaborativeMembershipManifestSchema.parse(opened.manifest);
    const actorMembership = opened.recipientMembership;
    const actorDevice = opened.recipientDevice;
    authorizeDestroy(
      priorDocument,
      priorManifest,
      parsed.authoritativeDeviceRegistry,
      actorMembership,
      actorDevice,
      parsed.destroyedAt,
    );

    const action = collaborationVaultDestructionActionSchema.parse({
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      operationType: 'destroy-vault',
      databaseId: priorDocument.databaseId,
      vaultId: priorDocument.vaultId,
      destructionMode: 'irreversible',
    });
    const actionParametersDigest =
      computeCollaborativeVaultDestructionActionDigest(action);
    const approval = await prepareApproval({
      priorDocument,
      priorManifest,
      registry: parsed.authoritativeDeviceRegistry,
      approvalInput: parsed.approvalRequest,
      operationId: parsed.operationId,
      actionParametersDigest,
      destroyedAt: parsed.destroyedAt,
    });

    const journal = await readJournal(
      parsed.destructionJournalPath,
      protectionSecret,
      parsed.scope,
    );
    if (journal.kind === 'unavailable') {
      return { status: 'unknown', reason: 'journal-persistence-failed' };
    }
    const existingEnvelope =
      journal.record?.tombstone.proofEntry.authorizationWitness
        ?.encryptedMembershipManifest;
    if (journal.record !== null && existingEnvelope === undefined) {
      throw failure('artifact-invalid');
    }

    const artifacts = await buildArtifacts({
      priorDocument,
      priorManifest,
      registry: parsed.authoritativeDeviceRegistry,
      actorMembership,
      actorDevice,
      writerPrivateKey,
      vaultRootKey,
      operationId: parsed.operationId,
      actionParametersDigest,
      destroyedAt: parsed.destroyedAt,
      expiresAt: parsed.expiresAt,
      detailsRetainedUntil: parsed.detailsRetainedUntil,
      approval,
      ...(existingEnvelope === undefined
        ? {}
        : { retainedEncryptedManifest: existingEnvelope }),
    });

    if (
      journal.record !== null &&
      !journalMatchesArtifacts(journal.record, artifacts, parsed)
    ) {
      return { status: 'terminal', reason: 'operation-id-reused' };
    }
    if (journal.record === null) {
      try {
        await createCollaborativeVaultDestructionJournal(
          parsed.destructionJournalPath,
          protectionSecret,
          {
            tombstone: artifacts.tombstone,
            proposedOutcome: artifacts.outcome,
            recipientAnchor: artifacts.recipientAnchor,
            createdAt: parsed.destroyedAt,
          },
        );
      } catch {
        return { status: 'unknown', reason: 'journal-persistence-failed' };
      }
    }

    const before = await readRemoteEvidence(
      parsed.store,
      priorDocument,
      artifacts,
      actorDevice,
    );
    if (before.kind === 'committed') {
      return await finalizeCommitted(
        parsed,
        protectionSecret,
        artifacts,
        before,
        'already-committed',
      );
    }
    if (before.kind === 'unavailable') {
      return { status: 'unknown', reason: 'readback-unavailable' };
    }
    if (before.kind === 'conflict') {
      return { status: 'retryable', reason: 'conflict' };
    }
    if (before.kind === 'invalid') {
      return { status: 'terminal', reason: before.reason };
    }

    let publicationError: unknown;
    try {
      await parsed.store.destroyCollaborativeVault({
        tombstone: artifacts.tombstone,
        outcome: artifacts.outcome,
      });
    } catch (error) {
      publicationError = error;
    }

    const after = await readRemoteEvidence(
      parsed.store,
      priorDocument,
      artifacts,
      actorDevice,
    );
    if (after.kind === 'committed') {
      return await finalizeCommitted(
        parsed,
        protectionSecret,
        artifacts,
        after,
        publicationError === undefined ? 'published' : 'already-committed',
      );
    }
    if (after.kind === 'unavailable') {
      return {
        status: 'unknown',
        reason:
          publicationError === undefined
            ? 'readback-unavailable'
            : 'publication-ambiguous',
      };
    }
    if (after.kind === 'invalid') {
      return { status: 'terminal', reason: after.reason };
    }
    if (after.kind === 'conflict') {
      return { status: 'retryable', reason: 'conflict' };
    }
    if (publicationError instanceof EncryptedDatabaseStoreError) {
      if (publicationError.code === 'conflict' || publicationError.code === 'exists') {
        return { status: 'retryable', reason: 'conflict' };
      }
      if (publicationError.code === 'invalid') {
        return { status: 'retryable', reason: 'rejected' };
      }
    }
    return { status: 'unknown', reason: 'publication-ambiguous' };
  } catch (error) {
    if (error instanceof CollaborationVaultDestructionError) throw error;
    if (error instanceof CollaborationStateVerificationError) {
      throw failure('trust-invalid');
    }
    throw failure('invalid-input');
  } finally {
    zeroize(recipientPrivateKey);
    zeroize(writerPrivateKey);
    zeroize(protectionSecret);
    zeroize(vaultRootKey);
    zeroize(openedVaultRootKey);
    zeroize(openedPayload);
  }
}

async function openPriorState(
  input: ParsedInput,
  recipientPrivateKey: Uint8Array,
  protectionSecret: Uint8Array,
): Promise<Awaited<ReturnType<typeof openCollaborativeVaultWithPinnedTrust>>> {
  try {
    return await openCollaborativeVaultWithPinnedTrust({
      document: input.document,
      authoritativeDeviceRegistry: input.authoritativeDeviceRegistry,
      ...(input.mutationProof === undefined
        ? {}
        : { mutationProof: input.mutationProof }),
      trusted: input.trusted,
      scope: input.scope,
      recipientEncryptionPrivateKey: recipientPrivateKey,
      deviceProtectionSecret: protectionSecret,
      rollbackAnchorPath: input.rollbackAnchorPath,
      now: input.destroyedAt,
    });
  } catch (error) {
    if (error instanceof CollaborationStateVerificationError) throw error;
    throw failure('trust-invalid');
  }
}

function authorizeDestroy(
  document: CollaborativeVaultDocument,
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
  actorMembership: CollaborationMembership,
  actorDevice: DeviceCertificate,
  destroyedAt: Timestamp,
): void {
  const owners = checkActiveOwnerInvariant({
    memberships: manifest.memberships,
    ownerPrincipalIds: manifest.ownerPrincipalIds,
  });
  const authorization = authorizeOperation({
    operationType: 'destroy-vault',
    membership: actorMembership,
    device: actorDevice,
    authoritativeRegistry: registry,
    deviceSigningKeyFingerprint: computePublicKeyFingerprint(
      actorDevice.signingPublicKey,
      'ed25519',
    ),
  });
  if (
    !owners.valid ||
    !authorization.authorized ||
    actorMembership.role !== 'owner' ||
    registry.databaseId !== document.databaseId ||
    registry.authorityEpoch !== document.authorityEpoch ||
    registry.generation !== document.databaseDeviceGeneration ||
    registry.registryDigest !== document.databaseDeviceRegistryDigest ||
    !deviceUsableAt(actorDevice, destroyedAt)
  ) {
    throw failure('current-state-invalid');
  }
}

async function prepareApproval(
  input: Readonly<{
    priorDocument: CollaborativeVaultDocument;
    priorManifest: CollaborativeMembershipManifest;
    registry: CollaborationDatabaseDeviceRegistry;
    approvalInput?: unknown;
    operationId: CollaborationMutationCommitment['operationId'];
    actionParametersDigest: Sha256Digest;
    destroyedAt: Timestamp;
  }>,
): Promise<PreparedApproval> {
  const { priorDocument, priorManifest, registry } = input;
  if (priorManifest.approvalPolicy === 'none') {
    if (input.approvalInput !== undefined) throw failure('approval-invalid');
    return {
      evidence: { kind: 'none' },
      pendingApprovals: priorManifest.pendingApprovals,
    };
  }
  try {
    const request = approvalRequestSchema.parse(input.approvalInput);
    if (
      request.state !== 'quorum-reached' ||
      request.operationType !== 'destroy-vault' ||
      request.operationId !== input.operationId ||
      request.actionParametersDigest !== input.actionParametersDigest ||
      priorManifest.pendingApprovals.some(
        (candidate) =>
          candidate.approvalRequestId === request.approvalRequestId ||
          candidate.requestDigest === request.requestDigest,
      )
    ) {
      throw failure('approval-invalid');
    }
    const requester = requireActiveOwnerDevice(
      priorManifest,
      request.requestingPrincipalId,
      request.requestingDeviceId,
      input.destroyedAt,
    );
    assertNotDenied(registry, requester);
    if (!(await verifyApprovalRequest(request, requester.signingPublicKey))) {
      throw failure('approval-invalid');
    }
    const verifiedApprovalSignatures = [];
    for (const evidence of request.approvals) {
      const approver = requireActiveOwnerDevice(
        priorManifest,
        evidence.approverPrincipalId,
        evidence.approverDeviceId,
        input.destroyedAt,
      );
      assertNotDenied(registry, approver);
      if (!(await verifyApprovalEvidence(evidence, approver.signingPublicKey))) {
        throw failure('approval-invalid');
      }
      verifiedApprovalSignatures.push({
        approvalRequestId: evidence.approvalRequestId,
        approverPrincipalId: evidence.approverPrincipalId,
        approverDeviceId: evidence.approverDeviceId,
        signedRequestDigest: request.requestDigest,
        signature: evidence.signature,
      });
    }
    const validation = validateApproval({
      request,
      priorPolicy: priorManifest.policy,
      priorTuple: tupleOf(priorDocument),
      priorHeadDigest: priorDocument.headDigest,
      activeMemberships: priorManifest.memberships,
      now: input.destroyedAt,
      verifiedRequesterSignature: {
        approvalRequestId: request.approvalRequestId,
        requesterPrincipalId: request.requestingPrincipalId,
        requesterDeviceId: request.requestingDeviceId,
        signedRequestDigest: request.requestDigest,
        signature: request.requesterSignature,
      },
      verifiedApprovalSignatures,
    });
    if (!validation.valid || !validation.eligibleForConsumption) {
      throw failure('approval-invalid');
    }
    const consumedApproval = approvalRequestSchema.parse({
      ...request,
      state: 'consumed',
      resolvedAt: input.destroyedAt,
    });
    return {
      evidence: { kind: 'approval', evidenceDigest: request.requestDigest },
      pendingApprovals: [...priorManifest.pendingApprovals, consumedApproval],
      consumedApproval,
    };
  } catch (error) {
    if (error instanceof CollaborationVaultDestructionError) throw error;
    throw failure('approval-invalid');
  }
}

async function buildArtifacts(
  input: Readonly<{
    priorDocument: CollaborativeVaultDocument;
    priorManifest: CollaborativeMembershipManifest;
    registry: CollaborationDatabaseDeviceRegistry;
    actorMembership: CollaborationMembership;
    actorDevice: DeviceCertificate;
    writerPrivateKey: Uint8Array;
    vaultRootKey: Uint8Array;
    operationId: CollaborationMutationCommitment['operationId'];
    actionParametersDigest: Sha256Digest;
    destroyedAt: Timestamp;
    expiresAt: Timestamp;
    detailsRetainedUntil: Timestamp;
    approval: PreparedApproval;
    retainedEncryptedManifest?: CollaborationAeadEnvelope;
  }>,
): Promise<DestructionArtifacts> {
  let manifestBytes: Uint8Array | undefined;
  let openedRetainedManifest: Uint8Array | undefined;
  try {
    const priorTuple = tupleOf(input.priorDocument);
    const terminalTuple = collaborationRevisionTupleSchema.parse({
      ...priorTuple,
      documentRevision: priorTuple.documentRevision + 1,
    });
    const transition = await buildTransition(input, priorTuple, terminalTuple);
    const transitionResult = validateRevisionTransition({
      operationType: 'destroy-vault',
      prior: priorTuple,
      next: terminalTuple,
      authorizationTransitionDigest: transition.transitionDigest,
    });
    if (!transitionResult.valid) throw failure('artifact-invalid');

    const manifest = await buildTerminalManifest(input, terminalTuple);
    const authorizationStateDigest = computeAuthorizationStateDigest(
      authorizationCore(manifest),
    );
    if (
      authorizationStateDigest !== input.priorDocument.authorizationStateDigest ||
      manifest.authorizationStateDigest !== authorizationStateDigest
    ) {
      throw failure('artifact-invalid');
    }
    const aad = expectedAad(input.priorDocument, terminalTuple);
    let encryptedMembershipManifest: CollaborationAeadEnvelope;
    if (input.retainedEncryptedManifest === undefined) {
      manifestBytes = Buffer.from(canonicalJson(manifest), 'utf8');
      encryptedMembershipManifest = await encryptCollaborationEnvelope(
        manifestBytes,
        input.vaultRootKey,
        aad,
      );
    } else {
      encryptedMembershipManifest = input.retainedEncryptedManifest;
      openedRetainedManifest = await decryptCollaborationEnvelope(
        encryptedMembershipManifest,
        input.vaultRootKey,
        aad,
      );
      if (
        parseManifest(openedRetainedManifest).membershipDigest !==
        manifest.membershipDigest
      ) {
        throw failure('artifact-invalid');
      }
      if (
        canonicalJson(parseManifest(openedRetainedManifest)) !== canonicalJson(manifest)
      ) {
        throw failure('artifact-invalid');
      }
    }

    const encryptedMembershipDigest = computeEncryptedMembershipDigest(
      encryptedMembershipManifest,
    );
    const encryptedEnvelopesDigest = computeKeyEnvelopeSetDigest(manifest.keyEnvelopes);
    const policyDigest = computePolicyDigest(manifest.policy);
    if (
      encryptedEnvelopesDigest !== input.priorDocument.encryptedEnvelopesDigest ||
      policyDigest !== input.priorDocument.policyDigest
    ) {
      throw failure('artifact-invalid');
    }
    const discoveryRecords = await buildDiscoveryRecords(
      input,
      manifest,
      encryptedMembershipDigest,
    );
    const core = collaborationVaultDestructionCoreSchema.parse({
      format: COLLABORATIVE_VAULT_DESTRUCTION_CORE_FORMAT,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: input.priorDocument.databaseId,
      vaultId: input.priorDocument.vaultId,
      operationId: input.operationId,
      authorityEpoch: input.priorDocument.authorityEpoch,
      authorityDelegationDigest: input.priorDocument.authorityDelegationDigest,
      priorTuple,
      priorHeadDigest: input.priorDocument.headDigest,
      terminalTuple,
      actionParametersDigest: input.actionParametersDigest,
      actorPrincipalId: input.actorMembership.principalId,
      actorDeviceId: input.actorDevice.deviceId,
      destructionMode: 'irreversible',
      destroyedAt: input.destroyedAt,
    });
    const destroyedPayloadDigest =
      computeCollaborativeVaultDestroyedPayloadDigest(core);
    const commitment = buildCommitment({
      input,
      priorTuple,
      terminalTuple,
      destroyedPayloadDigest,
      encryptedMembershipDigest,
      encryptedEnvelopesDigest,
      policyDigest,
      transitionDigest: transition.transitionDigest,
    });
    const terminalHeadDigest = computeMutationHead(commitment);
    const linkInput = {
      format: COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: input.priorDocument.databaseId,
      vaultId: input.priorDocument.vaultId,
      authorityDelegationDigest: input.priorDocument.authorityDelegationDigest,
      commitment,
      authorizationTransition: transition,
      resultingHeadDigest: terminalHeadDigest,
      writerSignature: {
        algorithm: 'ed25519' as const,
        writerPrincipalId: input.actorMembership.principalId,
        writerDeviceId: input.actorDevice.deviceId,
        commitmentDigest: terminalHeadDigest,
        signature: PLACEHOLDER_SIGNATURE,
      },
      finalizedAt: input.destroyedAt,
    };
    const writerSignature = await signFinalizedMutationLink(
      linkInput,
      input.writerPrivateKey,
    );
    const link = collaborationFinalizedMutationLinkSchema.parse({
      ...linkInput,
      writerSignature: { ...linkInput.writerSignature, signature: writerSignature },
    });
    if (
      !(await verifyFinalizedMutationLink(link, input.actorDevice.signingPublicKey))
    ) {
      throw failure('artifact-invalid');
    }
    const finalizedMutationLinkDigest = computeFinalizedMutationLinkDigest(link);
    const authorityRecoveryEnvelope = manifest.keyEnvelopes.find(
      (envelope) => !('membershipId' in envelope),
    );
    if (authorityRecoveryEnvelope === undefined) throw failure('artifact-invalid');
    const proofEntry = collaborationMutationProofEntrySchema.parse({
      link,
      authorizationWitness: {
        format: COLLABORATIVE_AUTHORIZATION_WITNESS_FORMAT,
        protocolVersion: COLLABORATION_PROTOCOL_VERSION,
        databaseId: input.priorDocument.databaseId,
        vaultId: input.priorDocument.vaultId,
        authorityDelegationDigest: input.priorDocument.authorityDelegationDigest,
        tuple: terminalTuple,
        previousHeadDigest: input.priorDocument.headDigest,
        headDigest: terminalHeadDigest,
        encryptedMembershipDigest,
        encryptedEnvelopesDigest,
        policyDigest,
        databaseDeviceRegistry: input.registry,
        databaseAuthorityRecoveryEnvelope: authorityRecoveryEnvelope,
        encryptedMembershipManifest,
        discoveryRecords,
        finalizedMutationLinkDigest,
      },
    });
    const outcome = await buildOutcome({
      input,
      priorTuple,
      terminalTuple,
      requestDigest: commitment.requestDigest,
      terminalHeadDigest,
      finalizedMutationLinkDigest,
    });
    const tombstone = collaborationVaultDestructionTombstoneSchema.parse({
      format: COLLABORATIVE_VAULT_DESTRUCTION_TOMBSTONE_FORMAT,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: input.priorDocument.databaseId,
      vaultId: input.priorDocument.vaultId,
      core,
      destroyedPayloadDigest,
      terminalHeadDigest,
      proofEntry,
      outcomeDigest: outcome.outcomeDigest,
      signedMutationReceipt: outcome.signedMutationReceipt,
    });
    const recipientAnchor = recipientVaultDestructionAnchorSchema.parse(
      recipientVaultDestructionAnchorFromTombstone(tombstone, {
        databaseId: input.priorDocument.databaseId,
        vaultId: input.priorDocument.vaultId,
        principalId: input.actorMembership.principalId,
        deviceId: input.actorDevice.deviceId,
      }),
    );
    await verifyArtifacts(input, manifest, tombstone, outcome, recipientAnchor);
    return { tombstone, outcome, recipientAnchor };
  } catch (error) {
    if (error instanceof CollaborationVaultDestructionError) throw error;
    throw failure('artifact-invalid');
  } finally {
    zeroize(manifestBytes);
    zeroize(openedRetainedManifest);
  }
}

async function buildTransition(
  input: Parameters<typeof buildArtifacts>[0],
  priorTuple: CollaborationRevisionTuple,
  terminalTuple: CollaborationRevisionTuple,
): Promise<CollaborationAuthorizationTransition> {
  const unsigned = {
    format: COLLABORATIVE_AUTHORIZATION_TRANSITION_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: input.priorDocument.databaseId,
    vaultId: input.priorDocument.vaultId,
    operationId: input.operationId,
    operationType: 'destroy-vault' as const,
    previousHeadDigest: input.priorDocument.headDigest,
    previousAuthorizationStateDigest: input.priorDocument.authorizationStateDigest,
    authorizationStateDigest: input.priorDocument.authorizationStateDigest,
    previousTuple: priorTuple,
    nextTuple: terminalTuple,
    evidence: input.approval.evidence,
    issuedAt: input.destroyedAt,
    expiresAt: input.expiresAt,
    transitionDigest: PLACEHOLDER_DIGEST,
    transitionSignature: {
      signerKind: 'owner-device' as const,
      signerPrincipalId: input.actorMembership.principalId,
      signerDeviceId: input.actorDevice.deviceId,
      signature: PLACEHOLDER_SIGNATURE,
    },
  };
  const transitionDigest = computeAuthorizationTransitionDigest(unsigned);
  const withDigest = collaborationAuthorizationTransitionSchema.parse({
    ...unsigned,
    transitionDigest,
  });
  const signature = await signAuthorizationTransitionOwner(
    withDigest,
    input.writerPrivateKey,
  );
  const transition = collaborationAuthorizationTransitionSchema.parse({
    ...withDigest,
    transitionSignature: { ...withDigest.transitionSignature, signature },
  });
  if (
    !(await verifyAuthorizationTransitionOwner(
      transition,
      input.actorDevice.signingPublicKey,
    ))
  ) {
    throw failure('artifact-invalid');
  }
  return transition;
}

async function buildTerminalManifest(
  input: Parameters<typeof buildArtifacts>[0],
  terminalTuple: CollaborationRevisionTuple,
): Promise<CollaborativeMembershipManifest> {
  const prior = input.priorManifest;
  const history = (
    await appendOrCompactMembershipHistory({
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: prior.databaseId,
      vaultId: prior.vaultId,
      operationId: input.operationId,
      previousHeadDigest: input.priorDocument.headDigest,
      previousTuple: tupleOf(input.priorDocument),
      nextTuple: terminalTuple,
      priorHistory: prior.history,
      actorPrincipalId: input.actorMembership.principalId,
      actorDeviceId: input.actorDevice.deviceId,
      actorSigningPublicKey: input.actorDevice.signingPublicKey,
      event: {
        eventType: 'vault-destroyed',
        ...(input.approval.consumedApproval === undefined
          ? {}
          : {
              approvalRequestId: input.approval.consumedApproval.approvalRequestId,
              approvalRequestDigest: input.approval.consumedApproval.requestDigest,
            }),
        timestamp: input.destroyedAt,
        expiresAt: input.expiresAt,
      },
      deviceSigningPrivateKey: input.writerPrivateKey,
    })
  ).history;
  const manifestInput = {
    format: COLLABORATIVE_MEMBERSHIP_MANIFEST_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: prior.databaseId,
    vaultId: prior.vaultId,
    authorityEpoch: terminalTuple.authorityEpoch,
    databaseDeviceGeneration: terminalTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: terminalTuple.databaseDeviceRegistryDigest,
    documentRevision: terminalTuple.documentRevision,
    membershipRevision: terminalTuple.membershipRevision,
    policyRevision: terminalTuple.policyRevision,
    keyEpoch: terminalTuple.keyEpoch,
    authorizationStateDigest: terminalTuple.authorizationStateDigest,
    memberships: prior.memberships,
    ownerPrincipalIds: prior.ownerPrincipalIds,
    keyEnvelopes: prior.keyEnvelopes,
    approvalPolicy: prior.approvalPolicy,
    policy: prior.policy,
    pendingApprovals: input.approval.pendingApprovals,
    pendingTransfers: prior.pendingTransfers,
    history,
    previousMembershipDigest: prior.membershipDigest,
    membershipDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest: input.priorDocument.headDigest,
    createdAt: prior.createdAt,
    updatedAt: input.destroyedAt,
  };
  return collaborativeMembershipManifestSchema.parse({
    ...manifestInput,
    membershipDigest: computeMembershipManifestDigest(manifestInput),
  });
}

async function buildDiscoveryRecords(
  input: Parameters<typeof buildArtifacts>[0],
  manifest: CollaborativeMembershipManifest,
  encryptedMembershipDigest: Sha256Digest,
): Promise<readonly CollaborationDiscoveryRecord[]> {
  const records: CollaborationDiscoveryRecord[] = [];
  for (const envelope of manifest.keyEnvelopes) {
    if (!('membershipId' in envelope)) continue;
    const membership = manifest.memberships.find(
      (candidate) => candidate.membershipId === envelope.membershipId,
    );
    if (membership?.state !== 'active') throw failure('artifact-invalid');
    const prior = input.priorDocument.discoveryRecords.find(
      (record) =>
        record.membershipId === envelope.membershipId &&
        record.encryptedMemberKeyEnvelope.deviceId === envelope.deviceId,
    );
    if (prior === undefined) throw failure('artifact-invalid');
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
      signerPrincipalId: input.actorMembership.principalId,
      signerDeviceId: input.actorDevice.deviceId,
      writerSignature: PLACEHOLDER_SIGNATURE,
      createdAt: prior.createdAt,
      updatedAt: input.destroyedAt,
    };
    const withDigest = collaborationDiscoveryRecordSchema.parse({
      ...unsigned,
      discoveryRecordDigest: computeDiscoveryRecordDigest(unsigned),
    });
    const writerSignature = await signDiscoveryRecord(
      withDigest,
      input.writerPrivateKey,
    );
    const record = collaborationDiscoveryRecordSchema.parse({
      ...withDigest,
      writerSignature,
    });
    if (!(await verifyDiscoveryRecord(record, input.actorDevice.signingPublicKey))) {
      throw failure('artifact-invalid');
    }
    records.push(record);
  }
  return records;
}

function buildCommitment(
  input: Readonly<{
    input: Parameters<typeof buildArtifacts>[0];
    priorTuple: CollaborationRevisionTuple;
    terminalTuple: CollaborationRevisionTuple;
    destroyedPayloadDigest: Sha256Digest;
    encryptedMembershipDigest: Sha256Digest;
    encryptedEnvelopesDigest: Sha256Digest;
    policyDigest: Sha256Digest;
    transitionDigest: Sha256Digest;
  }>,
): CollaborationMutationCommitment {
  const source = input.input;
  const prior = source.priorDocument;
  const placeholder = {
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: prior.databaseId,
    vaultId: prior.vaultId,
    operationId: source.operationId,
    operationType: 'destroy-vault' as const,
    requestDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest: prior.headDigest,
    previousAuthorizationStateDigest: prior.authorizationStateDigest,
    authorizationStateDigest: input.terminalTuple.authorizationStateDigest,
    authorizationTransitionDigest: input.transitionDigest,
    previousAuthorityEpoch: input.priorTuple.authorityEpoch,
    previousDocumentRevision: input.priorTuple.documentRevision,
    previousMembershipRevision: input.priorTuple.membershipRevision,
    previousPolicyRevision: input.priorTuple.policyRevision,
    previousKeyEpoch: input.priorTuple.keyEpoch,
    previousDatabaseDeviceGeneration: input.priorTuple.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: input.priorTuple.databaseDeviceRegistryDigest,
    authorityEpoch: input.terminalTuple.authorityEpoch,
    documentRevision: input.terminalTuple.documentRevision,
    membershipRevision: input.terminalTuple.membershipRevision,
    policyRevision: input.terminalTuple.policyRevision,
    keyEpoch: input.terminalTuple.keyEpoch,
    databaseDeviceGeneration: input.terminalTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: input.terminalTuple.databaseDeviceRegistryDigest,
    encryptedPayloadDigest: input.destroyedPayloadDigest,
    encryptedMembershipDigest: input.encryptedMembershipDigest,
    encryptedEnvelopesDigest: input.encryptedEnvelopesDigest,
    policyDigest: input.policyDigest,
    writerPrincipalId: source.actorMembership.principalId,
    writerDeviceId: source.actorDevice.deviceId,
    timestamp: source.destroyedAt,
    expiresAt: source.expiresAt,
  };
  return collaborationMutationCommitmentSchema.parse({
    ...placeholder,
    requestDigest: computeMutationRequestDigest(placeholder),
  });
}

async function buildOutcome(
  input: Readonly<{
    input: Parameters<typeof buildArtifacts>[0];
    priorTuple: CollaborationRevisionTuple;
    terminalTuple: CollaborationRevisionTuple;
    requestDigest: Sha256Digest;
    terminalHeadDigest: Sha256Digest;
    finalizedMutationLinkDigest: Sha256Digest;
  }>,
): Promise<DurableOperationOutcome> {
  const source = input.input;
  const receiptInput = {
    format: COLLABORATIVE_MUTATION_RECEIPT_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: source.priorDocument.databaseId,
    vaultId: source.priorDocument.vaultId,
    operationId: source.operationId,
    operationType: 'destroy-vault' as const,
    requestDigest: input.requestDigest,
    actorPrincipalId: source.actorMembership.principalId,
    actorDeviceId: source.actorDevice.deviceId,
    priorTuple: input.priorTuple,
    priorHeadDigest: source.priorDocument.headDigest,
    committedTuple: input.terminalTuple,
    committedHeadDigest: input.terminalHeadDigest,
    finalizedMutationLinkDigest: input.finalizedMutationLinkDigest,
    outcomeDigest: PLACEHOLDER_DIGEST,
    committedAt: source.destroyedAt,
    receiptSignature: PLACEHOLDER_SIGNATURE,
  };
  const outcomeInput = {
    format: COLLABORATIVE_OPERATION_OUTCOME_FORMAT,
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: source.priorDocument.databaseId,
    vaultId: source.priorDocument.vaultId,
    operationId: source.operationId,
    operationType: 'destroy-vault' as const,
    requestDigest: input.requestDigest,
    actorPrincipalId: source.actorMembership.principalId,
    actorDeviceId: source.actorDevice.deviceId,
    priorTuple: input.priorTuple,
    priorHeadDigest: source.priorDocument.headDigest,
    state: 'committed' as const,
    committedTuple: input.terminalTuple,
    committedHeadDigest: input.terminalHeadDigest,
    finalizedMutationLinkDigest: input.finalizedMutationLinkDigest,
    committedAt: source.destroyedAt,
    outcomeDigest: PLACEHOLDER_DIGEST,
    signedMutationReceipt: receiptInput,
    createdAt: source.destroyedAt,
    resolvedAt: source.destroyedAt,
    detailsRetainedUntil: source.detailsRetainedUntil,
  };
  const outcomeDigest = computeOperationOutcomeDigest(outcomeInput);
  const receiptWithDigest = { ...receiptInput, outcomeDigest };
  const receiptSignature = await signMutationReceipt(
    receiptWithDigest,
    source.writerPrivateKey,
  );
  const outcome = durableOperationOutcomeSchema.parse({
    ...outcomeInput,
    outcomeDigest,
    signedMutationReceipt: { ...receiptWithDigest, receiptSignature },
  });
  if (
    !(await verifyCommittedOperationOutcome(
      outcome,
      source.actorDevice.signingPublicKey,
    ))
  ) {
    throw failure('artifact-invalid');
  }
  return outcome;
}

async function verifyArtifacts(
  input: Parameters<typeof buildArtifacts>[0],
  manifest: CollaborativeMembershipManifest,
  tombstone: CollaborationVaultDestructionTombstone,
  outcome: DurableOperationOutcome,
  anchor: RecipientVaultDestructionAnchor,
): Promise<void> {
  const { core, proofEntry } = tombstone;
  const { link } = proofEntry;
  const witness = proofEntry.authorizationWitness;
  const historyTransition = verifyMembershipHistoryAppendOrCompaction({
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: input.priorDocument.databaseId,
    vaultId: input.priorDocument.vaultId,
    operationId: input.operationId,
    previousHeadDigest: input.priorDocument.headDigest,
    previousTuple: core.priorTuple,
    nextTuple: core.terminalTuple,
    priorHistory: input.priorManifest.history,
    nextHistory: manifest.history,
    actorPrincipalId: input.actorMembership.principalId,
    actorDeviceId: input.actorDevice.deviceId,
    timestamp: input.destroyedAt,
    expiresAt: input.expiresAt,
  });
  const event = historyTransition.event;
  const checkpoint = historyTransition.checkpoint;
  const expectedApproval = input.approval.consumedApproval;
  if (
    witness === undefined ||
    event.eventType !== 'vault-destroyed' ||
    event.approvalRequestId !== expectedApproval?.approvalRequestId ||
    event.approvalRequestDigest !== expectedApproval?.requestDigest ||
    core.actionParametersDigest !== input.actionParametersDigest ||
    tombstone.destroyedPayloadDigest !==
      computeCollaborativeVaultDestroyedPayloadDigest(core) ||
    link.commitment.requestDigest !== computeMutationRequestDigest(link.commitment) ||
    link.resultingHeadDigest !== computeMutationHead(link.commitment) ||
    witness.finalizedMutationLinkDigest !== computeFinalizedMutationLinkDigest(link) ||
    witness.encryptedMembershipDigest !==
      computeEncryptedMembershipDigest(witness.encryptedMembershipManifest) ||
    witness.encryptedEnvelopesDigest !==
      computeKeyEnvelopeSetDigest(manifest.keyEnvelopes) ||
    witness.policyDigest !== computePolicyDigest(manifest.policy) ||
    manifest.membershipDigest !== computeMembershipManifestDigest(manifest) ||
    manifest.history.currentHistoryDigest !==
      computeMembershipHistoryDigest(manifest.history) ||
    outcome.outcomeDigest !== computeOperationOutcomeDigest(outcome) ||
    tombstone.outcomeDigest !== outcome.outcomeDigest ||
    canonicalJson(anchor) !==
      canonicalJson(
        recipientVaultDestructionAnchorFromTombstone(tombstone, {
          databaseId: input.priorDocument.databaseId,
          vaultId: input.priorDocument.vaultId,
          principalId: input.actorMembership.principalId,
          deviceId: input.actorDevice.deviceId,
        }),
      ) ||
    !(await verifyAuthorizationTransitionOwner(
      link.authorizationTransition,
      input.actorDevice.signingPublicKey,
    )) ||
    !(await verifyFinalizedMutationLink(link, input.actorDevice.signingPublicKey)) ||
    !(await verifyCommittedOperationOutcome(
      outcome,
      input.actorDevice.signingPublicKey,
    )) ||
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.membershipHistorySignature,
      event,
      membershipHistoryEventSchema,
      'signature',
      input.actorDevice.signingPublicKey,
    )) ||
    (checkpoint !== undefined &&
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
        checkpoint,
        membershipHistoryCheckpointSchema,
        'signature',
        input.actorDevice.signingPublicKey,
      )))
  ) {
    throw failure('artifact-invalid');
  }
  for (const record of witness.discoveryRecords) {
    if (!(await verifyDiscoveryRecord(record, input.actorDevice.signingPublicKey))) {
      throw failure('artifact-invalid');
    }
  }
}

async function readRemoteEvidence(
  store: CollaborativeVaultStore,
  priorDocument: CollaborativeVaultDocument,
  artifacts: DestructionArtifacts,
  actorDevice: DeviceCertificate,
): Promise<RemoteEvidenceRead> {
  let tombstone: CollaborationVaultDestructionTombstone | null;
  let outcome: DurableOperationOutcome | OperationDeduplicationTombstone | null;
  let live: CollaborativeVaultDocument | null;
  try {
    [tombstone, outcome, live] = await Promise.all([
      store.getCollaborativeVaultDestructionTombstone(
        priorDocument.databaseId,
        priorDocument.vaultId,
      ),
      store.getCollaborativeOperationOutcome(
        priorDocument.databaseId,
        priorDocument.vaultId,
        artifacts.tombstone.core.operationId,
      ),
      store.getCollaborativeVault(priorDocument.databaseId, priorDocument.vaultId),
    ]);
  } catch {
    return { kind: 'unavailable' };
  }
  try {
    tombstone =
      tombstone === null
        ? null
        : collaborationVaultDestructionTombstoneSchema.parse(tombstone);
    live = live === null ? null : collaborativeVaultDocumentSchema.parse(live);
    if (outcome !== null) {
      outcome =
        outcome.format === 'kavrix-collaborative-operation-tombstone'
          ? operationDeduplicationTombstoneSchema.parse(outcome)
          : durableOperationOutcomeSchema.parse(outcome);
    }
  } catch {
    return { kind: 'invalid', reason: 'remote-evidence-invalid' };
  }

  if (tombstone === null && outcome === null) {
    if (live === null) return { kind: 'invalid', reason: 'remote-state-corrupt' };
    return sameCanonical(live, priorDocument)
      ? { kind: 'not-committed' }
      : { kind: 'conflict' };
  }
  if (tombstone === null || outcome === null) {
    return { kind: 'invalid', reason: 'remote-state-corrupt' };
  }
  if (live !== null) {
    return { kind: 'invalid', reason: 'remote-state-corrupt' };
  }
  if (!sameCanonical(tombstone, artifacts.tombstone)) {
    return {
      kind: 'invalid',
      reason:
        tombstone.core.operationId === artifacts.tombstone.core.operationId
          ? 'remote-evidence-invalid'
          : 'operation-id-reused',
    };
  }
  if (outcome.format === 'kavrix-collaborative-operation-tombstone') {
    if (
      outcome.databaseId !== artifacts.outcome.databaseId ||
      outcome.vaultId !== artifacts.outcome.vaultId ||
      outcome.operationId !== artifacts.outcome.operationId ||
      outcome.operationType !== 'destroy-vault' ||
      outcome.requestDigest !== artifacts.outcome.requestDigest ||
      outcome.outcomeDigest !== artifacts.outcome.outcomeDigest ||
      !sameCanonical(
        outcome.signedMutationReceipt,
        artifacts.outcome.signedMutationReceipt,
      ) ||
      !(await verifyOperationTombstone(outcome, actorDevice.signingPublicKey))
    ) {
      return { kind: 'invalid', reason: 'remote-evidence-invalid' };
    }
  } else if (
    !sameCanonical(outcome, artifacts.outcome) ||
    !(await verifyCommittedOperationOutcome(outcome, actorDevice.signingPublicKey))
  ) {
    return {
      kind: 'invalid',
      reason:
        outcome.operationId === artifacts.outcome.operationId &&
        outcome.requestDigest !== artifacts.outcome.requestDigest
          ? 'operation-id-reused'
          : 'remote-evidence-invalid',
    };
  }
  return { kind: 'committed', tombstone, outcome };
}

async function finalizeCommitted(
  input: ParsedInput,
  protectionSecret: Uint8Array,
  artifacts: DestructionArtifacts,
  remote: Extract<RemoteEvidenceRead, { kind: 'committed' }>,
  disposition: 'published' | 'already-committed',
): Promise<CollaborationVaultDestructionResult> {
  try {
    await reconcileCollaborativeVaultDestructionJournal(
      input.destructionJournalPath,
      protectionSecret,
      { tombstone: remote.tombstone, outcome: artifacts.outcome },
    );
    await verifyCommittedCollaborativeVaultDestructionJournal(
      input.destructionJournalPath,
      protectionSecret,
      { tombstone: remote.tombstone, outcome: artifacts.outcome },
    );
  } catch {
    return { status: 'unknown', reason: 'journal-persistence-failed' };
  }
  try {
    await createOrVerifyRecipientVaultDestructionAnchor(
      input.destructionAnchorPath,
      protectionSecret,
      artifacts.recipientAnchor,
    );
  } catch {
    return { status: 'unknown', reason: 'anchor-persistence-failed' };
  }
  return {
    status: 'committed',
    disposition,
    tombstone: remote.tombstone,
    outcome: remote.outcome,
  };
}

function parseInput(input: DestroyCollaborativeVaultWithPinnedTrustInput): ParsedInput {
  try {
    if (!isRecord(input)) throw failure('invalid-input');
    const allowed = new Set([
      'store',
      'document',
      'authoritativeDeviceRegistry',
      'mutationProof',
      'trusted',
      'scope',
      'recipientEncryptionPrivateKey',
      'deviceSigningPrivateKey',
      'deviceProtectionSecret',
      'rollbackAnchorPath',
      'destructionJournalPath',
      'destructionAnchorPath',
      'operationId',
      'destroyedAt',
      'expiresAt',
      'detailsRetainedUntil',
      'approvalRequest',
    ]);
    if (Object.keys(input).some((key) => !allowed.has(key))) {
      throw failure('invalid-input');
    }
    const store = input.store;
    if (
      !isRecord(store) ||
      typeof store.destroyCollaborativeVault !== 'function' ||
      typeof store.getCollaborativeVault !== 'function' ||
      typeof store.getCollaborativeOperationOutcome !== 'function' ||
      typeof store.getCollaborativeVaultDestructionTombstone !== 'function'
    ) {
      throw failure('invalid-input');
    }
    if (
      !isRecord(input.scope) ||
      Object.keys(input.scope).some(
        (key) =>
          key !== 'databaseId' &&
          key !== 'vaultId' &&
          key !== 'principalId' &&
          key !== 'deviceId',
      )
    ) {
      throw failure('invalid-input');
    }
    const scope = {
      databaseId: recipientVaultDestructionAnchorSchema.shape.databaseId.parse(
        input.scope.databaseId,
      ),
      vaultId: recipientVaultDestructionAnchorSchema.shape.vaultId.parse(
        input.scope.vaultId,
      ),
      principalId: recipientVaultDestructionAnchorSchema.shape.principalId.parse(
        input.scope.principalId,
      ),
      deviceId: recipientVaultDestructionAnchorSchema.shape.deviceId.parse(
        input.scope.deviceId,
      ),
    };
    const parsedRegistry = collaborationDatabaseDeviceRegistrySchema.parse(
      input.authoritativeDeviceRegistry,
    );
    const operationId = collaborationOperationIdSchema.parse(input.operationId);
    const destroyedAt = timestampSchema.parse(input.destroyedAt);
    const expiresAt = timestampSchema.parse(input.expiresAt);
    const detailsRetainedUntil = timestampSchema.parse(input.detailsRetainedUntil);
    if (
      Date.parse(expiresAt) <= Date.parse(destroyedAt) ||
      Date.parse(detailsRetainedUntil) <= Date.parse(destroyedAt)
    ) {
      throw failure('invalid-input');
    }
    assertPath(input.rollbackAnchorPath);
    assertPath(input.destructionJournalPath);
    assertPath(input.destructionAnchorPath);
    return {
      store: input.store,
      document: input.document,
      authoritativeDeviceRegistry: parsedRegistry,
      ...(input.mutationProof === undefined
        ? {}
        : { mutationProof: input.mutationProof }),
      trusted: input.trusted,
      scope,
      rollbackAnchorPath: input.rollbackAnchorPath,
      destructionJournalPath: input.destructionJournalPath,
      destructionAnchorPath: input.destructionAnchorPath,
      operationId,
      destroyedAt,
      expiresAt,
      detailsRetainedUntil,
      ...(input.approvalRequest === undefined
        ? {}
        : { approvalRequest: input.approvalRequest }),
    };
  } catch (error) {
    if (error instanceof CollaborationVaultDestructionError) throw error;
    throw failure('invalid-input');
  }
}

function authorizationCore(
  manifest: CollaborativeMembershipManifest,
): ReturnType<typeof collaborationAuthorizationStateCoreSchema.parse> {
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
      devices: membership.devices.map((device) => {
        const core = { ...device };
        Reflect.deleteProperty(core, 'rootSignature');
        return core;
      }),
      createdAt: membership.createdAt,
      updatedAt: membership.updatedAt,
      ...(membership.removedAt === undefined
        ? {}
        : { removedAt: membership.removedAt }),
    })),
    ownerPrincipalIds: manifest.ownerPrincipalIds,
    keyEnvelopes: manifest.keyEnvelopes.map((envelope) => {
      const core = { ...envelope };
      Reflect.deleteProperty(core, 'envelopeDigest');
      Reflect.deleteProperty(core, 'createdAt');
      Reflect.deleteProperty(core, 'ownerSignature');
      return core;
    }),
    approvalPolicy: manifest.approvalPolicy,
  });
}

function expectedAad(
  document: CollaborativeVaultDocument,
  tuple: CollaborationRevisionTuple,
): ReturnType<typeof collaborationAadSchema.parse> {
  const metadata = collaborationAadMetadataSchema.parse({
    protocolVersion: document.protocolVersion,
    databaseId: document.databaseId,
    vaultId: document.vaultId,
    authorityEpoch: tuple.authorityEpoch,
    entityType: 'membership-manifest',
    entityId: document.vaultId,
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

function requireActiveOwnerDevice(
  manifest: CollaborativeMembershipManifest,
  principalId: string,
  deviceId: string,
  at: Timestamp,
): DeviceCertificate {
  const membership = manifest.memberships.find(
    (candidate) =>
      candidate.principalId === principalId &&
      candidate.state === 'active' &&
      candidate.role === 'owner',
  );
  const device = membership?.devices.find(
    (candidate) => candidate.deviceId === deviceId && candidate.state === 'active',
  );
  if (device === undefined || !deviceUsableAt(device, at)) {
    throw failure('approval-invalid');
  }
  return device;
}

function deviceUsableAt(device: DeviceCertificate, at: Timestamp): boolean {
  const timestamp = Date.parse(at);
  return (
    device.state === 'active' &&
    timestamp >= Date.parse(device.createdAt) &&
    timestamp >= Date.parse(device.stateChangedAt) &&
    (device.expiresAt === undefined || timestamp < Date.parse(device.expiresAt))
  );
}

function assertNotDenied(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
): void {
  const fingerprint = computePublicKeyFingerprint(device.signingPublicKey, 'ed25519');
  if (
    registry.deniedDevices.some(
      (denial) =>
        (denial.principalId === device.principalId &&
          denial.deviceId === device.deviceId) ||
        denial.signingKeyFingerprint === fingerprint,
    )
  ) {
    throw failure('approval-invalid');
  }
}

function parseManifest(bytes: Uint8Array): CollaborativeMembershipManifest {
  try {
    return collaborativeMembershipManifestSchema.parse(
      JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
    );
  } catch {
    throw failure('artifact-invalid');
  }
}

function journalMatchesArtifacts(
  record: CollaborativeVaultDestructionJournalRecord,
  artifacts: DestructionArtifacts,
  input: ParsedInput,
): boolean {
  return (
    record.databaseId === input.scope.databaseId &&
    record.vaultId === input.scope.vaultId &&
    record.operationId === input.operationId &&
    record.actorPrincipalId === input.scope.principalId &&
    record.actorDeviceId === input.scope.deviceId &&
    sameCanonical(record.tombstone, artifacts.tombstone) &&
    sameCanonical(record.proposedOutcome, artifacts.outcome) &&
    sameCanonical(record.recipientAnchor, artifacts.recipientAnchor)
  );
}

async function readJournal(
  path: string,
  secret: Uint8Array,
  scope: CollaborationVaultDestructionJournalScope,
): Promise<
  | Readonly<{
      kind: 'available';
      record: CollaborativeVaultDestructionJournalRecord | null;
    }>
  | Readonly<{ kind: 'unavailable' }>
> {
  try {
    return {
      kind: 'available',
      record: await readCollaborativeVaultDestructionJournal(path, secret, {
        expectedScope: scope,
      }),
    };
  } catch {
    return { kind: 'unavailable' };
  }
}

function sameCanonical(left: unknown, right: unknown): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function copySecret(value: Uint8Array, exactBytes: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== exactBytes) {
    throw failure('invalid-input');
  }
  return Uint8Array.from(value);
}

function assertPath(path: string): void {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\u0000')) {
    throw failure('invalid-input');
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function failure(
  kind: CollaborationVaultDestructionFailureKind,
): CollaborationVaultDestructionError {
  return new CollaborationVaultDestructionError(kind);
}
