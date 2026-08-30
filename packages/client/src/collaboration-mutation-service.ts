import {
  authorizeOperation,
  checkActiveOwnerInvariant,
  validateApproval,
  validateOwnershipTransfer,
  validateRevisionTransition,
} from '@kavrix/core';
import {
  COLLABORATION_DOMAINS,
  computeAadMetadataDigest,
  computeAuthorizationCheckpointDigest,
  computeAuthorityDelegationDigest,
  computeAuthorityRecoveryEnvelopeDigest,
  computeAuthorizationStateDigest,
  computeAuthorizationTransitionDigest,
  computeDeviceRegistryDigest,
  computeDiscoveryRecordDigest,
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
  decryptCollaborationEnvelope,
  verifyApprovalEvidence,
  verifyApprovalRequest,
  verifyAuthorizationCheckpoint,
  verifyAuthorityDelegation,
  verifyAuthorizationTransitionAuthority,
  verifyAuthorizationTransitionOwner,
  verifyCollaborationRecord,
  verifyCommittedOperationOutcome,
  verifyDiscoveryRecord,
  verifyFinalizedMutationLink,
  verifyOperationTombstone,
  verifyOwnershipTransferAcceptance,
  verifyTransferIntent,
  zeroize,
  type DatabaseRootKey,
  type DeviceEncryptionPrivateKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument,
  createCollaborativeOperationJournal,
  createRecipientRollbackAnchor,
  readCollaborationAuthorityRollbackAnchor,
  readCollaborativeOperationJournal,
  readRecipientRollbackAnchor,
  recipientRollbackAnchorFromCollaborativeVaultDocument,
  reconcileCollaborativeOperationJournal,
  transitionCollaborationAuthorityRollbackAnchor,
  transitionRecipientRollbackAnchor,
  type CollaborationAuthorityRollbackAnchor,
  type CollaborationAuthorityRollbackAnchorScope,
  type CollaborationOperationJournalScope,
  type CollaborationRecoveryRestartEvidence,
  type RecipientRollbackAnchorScope,
} from '@kavrix/key-files';
import {
  MAX_COLLABORATIVE_CLOCK_SKEW_SECONDS,
  MAX_COLLABORATIVE_PROOF_LINKS,
  canonicalJson,
  collaborationAadMetadataSchema,
  collaborationAadSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationCheckpointSchema,
  collaborationAuthorizationWitnessSchema,
  collaborationAuthorityDelegationSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationKeyEnvelopeSchema,
  collaborationMutationProofEntrySchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  deviceCertificateSchema,
  durableOperationOutcomeSchema,
  membershipHistoryCheckpointSchema,
  membershipHistoryEventSchema,
  operationDeduplicationTombstoneSchema,
  publicIdentityExportSchema,
  recipientRollbackAnchorSchema,
  timestampSchema,
  type CollaborationAuthorizationTransition,
  type CollaborationAuthorizationCheckpoint,
  type CollaborationAuthorityDelegation,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationDiscoveryRecord,
  type CollaborationFinalizedMutationLink,
  type CollaborationMembership,
  type CollaborationMutationProof,
  type CollaborationRevisionTuple,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DeviceCertificate,
  type DurableOperationOutcome,
  type OperationDeduplicationTombstone,
  type PublicIdentityExport,
  type RecipientRollbackAnchor,
  type Sha256Digest,
  type Timestamp,
} from '@kavrix/schemas';

import { requireExactDatabaseAuthorityRecoveryEnvelope } from './collaboration-recovery-envelope-binding.js';
import {
  EncryptedDatabaseStoreError,
  type CollaborativeVaultStore,
} from '@kavrix/storage';

import type { PreparedCollaborativeMutation } from './collaboration-candidate-builder.js';
import {
  verifyCollaborativeAdministrativeManifestTransition,
  type NormalizedApprovalEvidence,
  type VerifiedCollaborativeAdministrativeManifestTransition,
} from './collaboration-administrative-state.js';
import {
  CollaborationStateVerificationError,
  openCollaborativeVaultForDatabaseAuthorityRecovery,
  openCollaborativeVaultWithPinnedTrust,
  verifyCollaborativeJournalSuccessorChain,
  type CollaborativeVaultPinnedTrust,
} from './collaboration-state-verifier.js';

const SAFE_MESSAGE = 'Collaborative vault mutation publication failed.';
const ABORT_ANCHOR_TRANSITION = new Error('abort-collaboration-anchor-transition');

export type CollaborationMutationPublicationFailureKind =
  | 'invalid-input'
  | 'trust-invalid'
  | 'candidate-invalid'
  | 'current-state-invalid'
  | 'journal-persistence-failed'
  | 'anchor-persistence-failed'
  | 'remote-unavailable';

/** A stable, redacted error safe for logs and terminal boundaries. */
export class CollaborationMutationPublicationError extends Error {
  readonly safe = true;
  readonly kind: CollaborationMutationPublicationFailureKind;

  constructor(kind: CollaborationMutationPublicationFailureKind) {
    super(SAFE_MESSAGE);
    this.name = 'CollaborationMutationPublicationError';
    this.kind = kind;
  }
}

export type CollaborationMutationPublicationResult =
  | Readonly<{
      status: 'committed';
      disposition: 'published' | 'already-committed';
      outcome: DurableOperationOutcome | OperationDeduplicationTombstone;
    }>
  | Readonly<{
      status: 'retryable';
      reason: 'conflict' | 'rejected' | 'checkpoint-append-failed';
    }>
  | Readonly<{
      status: 'terminal';
      reason:
        | 'operation-id-reused'
        | 'remote-outcome-invalid'
        | 'readback-mismatch'
        | 'proof-invalid'
        | 'fork';
    }>
  | Readonly<{
      status: 'unknown';
      reason:
        | 'outcome-unavailable'
        | 'publication-ambiguous'
        | 'readback-unavailable'
        | 'proof-unavailable'
        | 'journal-persistence-failed'
        | 'anchor-persistence-failed';
    }>;

export type PublishPreparedCollaborativeMutationInput = Readonly<{
  store: CollaborativeVaultStore;
  prepared: PreparedCollaborativeMutation;
  trusted: CollaborativeVaultPinnedTrust;
  scope: RecipientRollbackAnchorScope;
  access:
    | Readonly<{
        kind: 'recipient';
        recipientEncryptionPrivateKey: DeviceEncryptionPrivateKey | Uint8Array;
      }>
    | Readonly<{
        kind: 'database-authority-recovery';
        databaseRootKey: DatabaseRootKey | Uint8Array;
        authorityRollbackAnchorPath: string;
      }>;
  deviceProtectionSecret: Uint8Array;
  rollbackAnchorPath: string;
  operationJournalPath: string;
  /** Exact owner-signed checkpoint published only after committed candidate readback. */
  authorizationCheckpoint?: unknown;
  /** Proof from the protected anchor to a remote current state skipped locally. */
  currentMutationProof?: unknown;
  now?: Timestamp;
}>;

export type ResumeCollaborativeMutationFromJournalInput = Readonly<{
  store: CollaborativeVaultStore;
  trusted: CollaborativeVaultPinnedTrust;
  scope: RecipientRollbackAnchorScope;
  access:
    | Readonly<{
        kind: 'recipient';
        recipientEncryptionPrivateKey: DeviceEncryptionPrivateKey | Uint8Array;
      }>
    | Readonly<{
        kind: 'database-authority-recovery';
        databaseRootKey: DatabaseRootKey | Uint8Array;
        authorityRollbackAnchorPath: string;
      }>;
  deviceProtectionSecret: Uint8Array;
  rollbackAnchorPath: string;
  operationJournalPath: string;
  now?: Timestamp;
}>;

type ProofEntry = CollaborationMutationProof['entries'][number];

type ParsedPrepared = Readonly<{
  candidate: CollaborativeVaultDocument;
  proofEntry: ProofEntry;
  proposedOutcome: DurableOperationOutcome;
  candidateAnchor: RecipientRollbackAnchor;
  authorizationCheckpoint?: CollaborationAuthorizationCheckpoint;
  scope: RecipientRollbackAnchorScope;
  now: Timestamp;
  accessMode: 'recipient' | 'database-authority-recovery';
  recoveryRestartEvidence?: CollaborationRecoveryRestartEvidence;
}>;

type TrustedPrincipal = Readonly<{
  principalId: string;
  fingerprint: Sha256Digest;
  rootSigningPublicKey: string;
  devices: ReadonlyMap<string, DeviceCertificate>;
}>;

type TrustContext = Readonly<{
  delegation: CollaborationAuthorityDelegation;
  delegationDigest: Sha256Digest;
  principals: ReadonlyMap<string, TrustedPrincipal>;
}>;

type VerifiedCurrent = Readonly<{
  document: CollaborativeVaultDocument;
  manifest: CollaborativeMembershipManifest;
  registry: CollaborationDatabaseDeviceRegistry;
  candidateRegistry: CollaborationDatabaseDeviceRegistry;
  anchor?: RecipientRollbackAnchor;
  authorityAnchor?: CollaborationAuthorityRollbackAnchor;
  recoveryRestartEvidence?: CollaborationRecoveryRestartEvidence;
  vaultRootKey: VaultRootKey;
}>;

type RemoteOutcomeClassification =
  | Readonly<{
      kind: 'matching';
      outcome: DurableOperationOutcome | OperationDeduplicationTombstone;
    }>
  | Readonly<{ kind: 'retryable'; reason: 'conflict' | 'rejected' }>
  | Readonly<{ kind: 'operation-id-reused' }>
  | Readonly<{ kind: 'invalid' }>;

type OutcomeRead =
  | Readonly<{
      kind: 'available';
      outcome: DurableOperationOutcome | OperationDeduplicationTombstone | null;
    }>
  | Readonly<{ kind: 'unavailable' }>;

type PublicationAttempt =
  | Readonly<{
      kind: 'committed';
      disposition: 'published' | 'already-committed';
      outcome: DurableOperationOutcome | OperationDeduplicationTombstone;
    }>
  | Readonly<{ kind: 'retryable'; reason: 'conflict' | 'rejected' }>
  | Readonly<{
      kind: 'terminal';
      reason: 'operation-id-reused' | 'remote-outcome-invalid';
    }>
  | Readonly<{ kind: 'unknown'; reason: 'publication-ambiguous' }>;

/**
 * Publishes one immutable, already-prepared mutation. No protocol artifact is
 * regenerated here: the exact candidate, proof entry, signed outcome, and
 * anchor are journaled, published, reconciled, and replayed byte-for-byte.
 */
export async function publishPreparedCollaborativeMutation(
  input: PublishPreparedCollaborativeMutationInput,
): Promise<CollaborationMutationPublicationResult> {
  let recipientPrivateKey: Uint8Array | undefined;
  let databaseRootKey: Uint8Array | undefined;
  let protectionSecret: Uint8Array | undefined;
  let nextVaultRootKey: Uint8Array | undefined;
  let currentVaultRootKey: Uint8Array | undefined;
  try {
    const prepared = parseInput(input);
    if (input.access.kind === 'recipient') {
      recipientPrivateKey = copySecret(input.access.recipientEncryptionPrivateKey, 32);
    } else {
      databaseRootKey = copySecret(input.access.databaseRootKey, 32);
    }
    protectionSecret = copySecret(input.deviceProtectionSecret, 32);
    nextVaultRootKey =
      input.prepared.nextVaultRootKey === undefined
        ? undefined
        : copySecret(input.prepared.nextVaultRootKey, 32);
    const trust = await buildTrust(input.trusted, prepared.now);
    const writer = requirePinnedDevice(
      trust,
      prepared.candidate.currentMutationLink.commitment.writerPrincipalId,
      prepared.candidate.currentMutationLink.commitment.writerDeviceId,
    );
    await verifyPreparedOutcome(prepared, writer);

    const journal = await readJournal(
      input.operationJournalPath,
      protectionSecret,
      prepared.scope,
    );
    if (journal.kind === 'unavailable') {
      return { status: 'unknown', reason: 'journal-persistence-failed' };
    }
    if (journal.record !== null && !journalMatches(journal.record, prepared)) {
      return { status: 'terminal', reason: 'operation-id-reused' };
    }

    const before = await readRemoteOutcome(input.store, prepared);
    if (before.kind === 'unavailable') {
      return { status: 'unknown', reason: 'outcome-unavailable' };
    }
    if (before.outcome !== null) {
      const classification = await classifyRemoteOutcome(
        before.outcome,
        prepared,
        writer,
      );
      if (classification.kind === 'matching') {
        if (journal.record === null) {
          return { status: 'unknown', reason: 'journal-persistence-failed' };
        }
        return await finalizeRecoveredCommittedPublication({
          input,
          prepared,
          protectionSecret,
          remoteOutcome: classification.outcome,
          disposition: 'already-committed',
          ...(recipientPrivateKey === undefined ? {} : { recipientPrivateKey }),
          ...(databaseRootKey === undefined ? {} : { databaseRootKey }),
        });
      }
      if (classification.kind === 'operation-id-reused') {
        return { status: 'terminal', reason: 'operation-id-reused' };
      }
      if (classification.kind === 'invalid') {
        return { status: 'terminal', reason: 'remote-outcome-invalid' };
      }
    }

    const current = await loadCurrentState({
      input,
      prepared,
      trust,
      ...(recipientPrivateKey === undefined ? {} : { recipientPrivateKey }),
      ...(databaseRootKey === undefined ? {} : { databaseRootKey }),
      protectionSecret,
    });
    currentVaultRootKey = current.vaultRootKey;
    await verifyCandidate(
      prepared,
      current,
      trust,
      currentVaultRootKey,
      nextVaultRootKey,
    );

    try {
      await createCollaborativeOperationJournal(
        input.operationJournalPath,
        protectionSecret,
        {
          candidate: prepared.candidate,
          accessMode: prepared.accessMode,
          ...(current.recoveryRestartEvidence === undefined
            ? {}
            : { recoveryRestartEvidence: current.recoveryRestartEvidence }),
          candidateAnchor: prepared.candidateAnchor,
          proofEntry: prepared.proofEntry,
          ...(prepared.authorizationCheckpoint === undefined
            ? {}
            : { authorizationCheckpoint: prepared.authorizationCheckpoint }),
          proposedOutcome: prepared.proposedOutcome,
          createdAt: prepared.proposedOutcome.createdAt,
        },
      );
    } catch {
      const replay = await readJournal(
        input.operationJournalPath,
        protectionSecret,
        prepared.scope,
      );
      if (
        replay.kind === 'available' &&
        replay.record !== null &&
        !journalMatches(replay.record, prepared)
      ) {
        return { status: 'terminal', reason: 'operation-id-reused' };
      }
      return { status: 'unknown', reason: 'journal-persistence-failed' };
    }

    if (prepared.accessMode === 'database-authority-recovery') {
      if (current.authorityAnchor === undefined || databaseRootKey === undefined) {
        throw failure('current-state-invalid');
      }
      return await publishUnderDatabaseAuthorityRecovery({
        input,
        prepared,
        trust,
        writer,
        protectionSecret,
        databaseRootKey,
        currentAuthorityAnchor: current.authorityAnchor,
      });
    }
    if (current.anchor === undefined) throw failure('current-state-invalid');
    return await publishUnderAnchorLock({
      input,
      prepared,
      trust,
      writer,
      protectionSecret,
      currentAnchor: current.anchor,
    });
  } catch (error) {
    if (error instanceof CollaborationMutationPublicationError) throw error;
    throw failure('invalid-input');
  } finally {
    zeroize(recipientPrivateKey);
    zeroize(databaseRootKey);
    zeroize(protectionSecret);
    zeroize(nextVaultRootKey);
    zeroize(currentVaultRootKey);
  }
}

/**
 * Resumes one immutable operation using only its authenticated local journal.
 * Candidate material is never regenerated and no vault key is persisted.
 */
export async function resumeCollaborativeMutationFromJournal(
  input: ResumeCollaborativeMutationFromJournalInput,
): Promise<CollaborationMutationPublicationResult> {
  let recipientPrivateKey: Uint8Array | undefined;
  let databaseRootKey: Uint8Array | undefined;
  let protectionSecret: Uint8Array | undefined;
  try {
    assertPath(input.rollbackAnchorPath);
    assertPath(input.operationJournalPath);
    const scope = parseScope(input.scope);
    const now = timestampSchema.parse(input.now ?? new Date().toISOString());
    const accessMode = parseAccessMode(input);
    if (input.access.kind === 'recipient') {
      recipientPrivateKey = copySecret(input.access.recipientEncryptionPrivateKey, 32);
    } else {
      databaseRootKey = copySecret(input.access.databaseRootKey, 32);
    }
    protectionSecret = copySecret(input.deviceProtectionSecret, 32);
    const journalRead = await readJournal(
      input.operationJournalPath,
      protectionSecret,
      scope,
    );
    if (journalRead.kind === 'unavailable' || journalRead.record === null) {
      return { status: 'unknown', reason: 'journal-persistence-failed' };
    }
    const prepared = preparedFromJournal(journalRead.record, scope, now);
    if (prepared.accessMode !== accessMode) {
      return { status: 'terminal', reason: 'operation-id-reused' };
    }
    const trust = await buildTrust(input.trusted, now);
    const writer = requirePinnedDevice(
      trust,
      prepared.candidate.currentMutationLink.commitment.writerPrincipalId,
      prepared.candidate.currentMutationLink.commitment.writerDeviceId,
    );
    await verifyPreparedOutcome(prepared, writer);
    if (
      !(await verifyFinalizedMutationLink(
        prepared.candidate.currentMutationLink,
        writer.signingPublicKey,
      ))
    ) {
      return { status: 'terminal', reason: 'remote-outcome-invalid' };
    }

    const remoteRead = await readRemoteOutcome(input.store, prepared);
    if (remoteRead.kind === 'unavailable') {
      return { status: 'unknown', reason: 'outcome-unavailable' };
    }
    if (remoteRead.outcome === null) {
      if (journalRead.record.state === 'committed') {
        return { status: 'terminal', reason: 'remote-outcome-invalid' };
      }
      const predecessor = await authenticateJournalPredecessor({
        input,
        prepared,
        protectionSecret,
        ...(recipientPrivateKey === undefined ? {} : { recipientPrivateKey }),
        ...(databaseRootKey === undefined ? {} : { databaseRootKey }),
      });
      if (predecessor.kind !== 'authenticated') {
        return predecessor.kind === 'conflict'
          ? { status: 'retryable', reason: 'conflict' }
          : predecessor.kind === 'proof-unavailable'
            ? { status: 'unknown', reason: 'proof-unavailable' }
            : predecessor.kind === 'unavailable'
              ? { status: 'unknown', reason: 'readback-unavailable' }
              : { status: 'terminal', reason: predecessor.kind };
      }
      if (prepared.accessMode === 'database-authority-recovery') {
        if (
          input.access.kind !== 'database-authority-recovery' ||
          databaseRootKey === undefined ||
          !('authorityAnchor' in predecessor)
        ) {
          return { status: 'terminal', reason: 'proof-invalid' };
        }
        return await publishUnderDatabaseAuthorityRecovery({
          input,
          prepared,
          trust,
          writer,
          protectionSecret,
          databaseRootKey,
          currentAuthorityAnchor: predecessor.authorityAnchor,
        });
      }
      if (input.access.kind !== 'recipient' || !('recipientAnchor' in predecessor)) {
        return { status: 'terminal', reason: 'proof-invalid' };
      }
      return await publishUnderAnchorLock({
        input,
        prepared,
        trust,
        writer,
        protectionSecret,
        currentAnchor: predecessor.recipientAnchor,
      });
    }

    const classification = await classifyRemoteOutcome(
      remoteRead.outcome,
      prepared,
      writer,
    );
    if (classification.kind === 'retryable') {
      return { status: 'retryable', reason: classification.reason };
    }
    if (classification.kind === 'operation-id-reused') {
      return { status: 'terminal', reason: 'operation-id-reused' };
    }
    if (classification.kind === 'invalid') {
      return { status: 'terminal', reason: 'remote-outcome-invalid' };
    }
    return await finalizeRecoveredCommittedPublication({
      input,
      prepared,
      protectionSecret,
      remoteOutcome: classification.outcome,
      disposition: 'already-committed',
      ...(recipientPrivateKey === undefined ? {} : { recipientPrivateKey }),
      ...(databaseRootKey === undefined ? {} : { databaseRootKey }),
    });
  } catch (error) {
    if (error instanceof CollaborationMutationPublicationError) throw error;
    throw failure('invalid-input');
  } finally {
    zeroize(recipientPrivateKey);
    zeroize(databaseRootKey);
    zeroize(protectionSecret);
  }
}

type JournalPredecessorAuthentication =
  | Readonly<{
      kind: 'authenticated';
      recipientAnchor: RecipientRollbackAnchor;
    }>
  | Readonly<{
      kind: 'authenticated';
      authorityAnchor: CollaborationAuthorityRollbackAnchor;
    }>
  | Readonly<{
      kind:
        | 'conflict'
        | 'unavailable'
        | 'proof-unavailable'
        | 'remote-outcome-invalid'
        | 'proof-invalid'
        | 'fork';
    }>;

type RecoveryServiceInput =
  | PublishPreparedCollaborativeMutationInput
  | ResumeCollaborativeMutationFromJournalInput;

async function authenticateJournalPredecessor(
  options: Readonly<{
    input: RecoveryServiceInput;
    prepared: ParsedPrepared;
    protectionSecret: Uint8Array;
    recipientPrivateKey?: Uint8Array;
    databaseRootKey?: Uint8Array;
  }>,
): Promise<JournalPredecessorAuthentication> {
  const { input, prepared, protectionSecret, recipientPrivateKey, databaseRootKey } =
    options;
  const current = await readCurrentDocumentAndRegistry(input.store, prepared);
  if (current.kind === 'unavailable') return { kind: 'unavailable' };
  if (current.document === null || current.registry === null) {
    return { kind: 'conflict' };
  }
  if (sameCanonical(current.document, prepared.candidate)) {
    return { kind: 'remote-outcome-invalid' };
  }
  if (!documentMatchesCandidatePredecessor(current.document, prepared.candidate)) {
    return { kind: 'conflict' };
  }

  let openedVaultRootKey: Uint8Array | undefined;
  let openedPayload: Uint8Array | undefined;
  try {
    if (prepared.accessMode === 'recipient') {
      if (recipientPrivateKey === undefined || databaseRootKey !== undefined) {
        return { kind: 'proof-invalid' };
      }
      let anchor: RecipientRollbackAnchor;
      try {
        anchor = await readRecipientRollbackAnchor(
          input.rollbackAnchorPath,
          protectionSecret,
          { expectedScope: prepared.scope },
        );
      } catch {
        return { kind: 'fork' };
      }
      if (!anchorMatchesCandidatePredecessor(anchor, prepared.candidate)) {
        return { kind: 'fork' };
      }
      const opened = await openCollaborativeVaultWithPinnedTrust({
        document: current.document,
        authoritativeDeviceRegistry: current.registry,
        trusted: input.trusted,
        scope: prepared.scope,
        recipientEncryptionPrivateKey: recipientPrivateKey,
        deviceProtectionSecret: protectionSecret,
        rollbackAnchorPath: input.rollbackAnchorPath,
        now: prepared.now,
      });
      openedVaultRootKey = opened.vaultRootKey;
      openedPayload = opened.decryptedPayload;
      const authenticatedAnchor = await readRecipientRollbackAnchor(
        input.rollbackAnchorPath,
        protectionSecret,
        { expectedScope: prepared.scope },
      );
      const expectedAnchor = recipientRollbackAnchorFromCollaborativeVaultDocument(
        current.document,
        prepared.scope,
        {
          membershipDigest: computeMembershipStateDigest(
            authorizationCore(opened.manifest),
          ),
          policyDigest: computePolicyStateDigest(opened.manifest.policy),
          finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
            current.document.currentMutationLink,
          ),
        },
      );
      return sameCanonical(authenticatedAnchor, expectedAnchor)
        ? { kind: 'authenticated', recipientAnchor: authenticatedAnchor }
        : { kind: 'fork' };
    }

    if (databaseRootKey === undefined || recipientPrivateKey !== undefined) {
      return { kind: 'proof-invalid' };
    }
    const authorityPath =
      input.access.kind === 'database-authority-recovery'
        ? input.access.authorityRollbackAnchorPath
        : undefined;
    if (authorityPath === undefined) return { kind: 'proof-invalid' };
    let authorityAnchor: CollaborationAuthorityRollbackAnchor;
    try {
      authorityAnchor = await readCollaborationAuthorityRollbackAnchor(
        authorityPath,
        databaseRootKey,
        { expectedScope: authorityAnchorScope(prepared) },
      );
    } catch {
      return { kind: 'fork' };
    }
    const gap = current.document.documentRevision - authorityAnchor.documentRevision;
    if (gap < 0) return { kind: 'fork' };
    if (gap > MAX_COLLABORATIVE_PROOF_LINKS) {
      return { kind: 'proof-unavailable' };
    }
    let mutationProof: CollaborationMutationProof | undefined;
    if (gap > 0) {
      try {
        mutationProof = await input.store.getCollaborativeMutationProofRange({
          databaseId: current.document.databaseId,
          vaultId: current.document.vaultId,
          fromExclusive: {
            documentRevision: authorityAnchor.documentRevision,
            headDigest: authorityAnchor.headDigest,
          },
          toInclusive: {
            documentRevision: current.document.documentRevision,
            headDigest: current.document.headDigest,
          },
          limit: gap,
        });
      } catch {
        return { kind: 'proof-unavailable' };
      }
    }
    const opened = await openCollaborativeVaultForDatabaseAuthorityRecovery({
      document: current.document,
      authoritativeDeviceRegistry: current.registry,
      ...(mutationProof === undefined ? {} : { mutationProof }),
      trusted: input.trusted,
      databaseRootKey,
      authorityRollbackAnchorPath: authorityPath,
      now: prepared.now,
    });
    openedVaultRootKey = opened.vaultRootKey;
    openedPayload = opened.decryptedPayload;
    const evidence = preparedRecoveryEvidence(prepared);
    if (
      canonicalJson(evidence.priorTuple) !== canonicalJson(tupleOf(current.document)) ||
      evidence.priorHeadDigest !== current.document.headDigest ||
      evidence.priorDatabaseAuthorityRecoveryEnvelopeDigest !==
        computeAuthorityRecoveryEnvelopeDigest(
          current.document.databaseAuthorityRecoveryEnvelope,
        )
    ) {
      return { kind: 'fork' };
    }
    const authenticatedAnchor = await readCollaborationAuthorityRollbackAnchor(
      authorityPath,
      databaseRootKey,
      { expectedScope: authorityAnchorScope(prepared) },
    );
    const expectedAnchor =
      collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
        current.document,
        {
          membershipDigest: computeMembershipStateDigest(
            authorizationCore(opened.manifest),
          ),
          policyDigest: computePolicyStateDigest(opened.manifest.policy),
        },
      );
    return sameCanonical(authenticatedAnchor, expectedAnchor)
      ? { kind: 'authenticated', authorityAnchor: authenticatedAnchor }
      : { kind: 'fork' };
  } catch (error) {
    if (error instanceof CollaborationStateVerificationError) {
      return {
        kind:
          error.kind === 'fork' || error.kind === 'rollback' ? 'fork' : 'proof-invalid',
      };
    }
    return { kind: 'proof-invalid' };
  } finally {
    zeroize(openedVaultRootKey);
    zeroize(openedPayload);
  }
}

async function finalizeRecoveredCommittedPublication(
  options: Readonly<{
    input: RecoveryServiceInput;
    prepared: ParsedPrepared;
    protectionSecret: Uint8Array;
    remoteOutcome: DurableOperationOutcome | OperationDeduplicationTombstone;
    disposition: 'published' | 'already-committed';
    recipientPrivateKey?: Uint8Array;
    databaseRootKey?: Uint8Array;
  }>,
): Promise<CollaborationMutationPublicationResult> {
  const {
    input,
    prepared,
    protectionSecret,
    remoteOutcome,
    disposition,
    recipientPrivateKey,
    databaseRootKey,
  } = options;
  const current = await readCurrentDocumentAndRegistry(input.store, prepared);
  if (current.kind === 'unavailable') {
    return { status: 'unknown', reason: 'readback-unavailable' };
  }
  if (current.document === null || current.registry === null) {
    // A terminal destruction successor is reconciled by the destruction path.
    return { status: 'unknown', reason: 'readback-unavailable' };
  }

  let anchors: readonly RecipientRollbackAnchor[];
  let authorityAnchors: readonly CollaborationAuthorityRollbackAnchor[] | undefined;
  if (sameCanonical(current.document, prepared.candidate)) {
    anchors = [prepared.candidateAnchor];
    if (prepared.accessMode === 'database-authority-recovery') {
      authorityAnchors = [authorityCandidateAnchor(prepared)];
    }
  } else {
    const predecessorRevision =
      prepared.candidate.currentMutationLink.commitment.previousDocumentRevision;
    if (current.document.documentRevision <= prepared.candidate.documentRevision) {
      return { status: 'terminal', reason: 'fork' };
    }
    const gap = current.document.documentRevision - predecessorRevision;
    if (gap > MAX_COLLABORATIVE_PROOF_LINKS) {
      return { status: 'unknown', reason: 'proof-unavailable' };
    }
    let proof: CollaborationMutationProof;
    try {
      proof = await input.store.getCollaborativeMutationProofRange({
        databaseId: prepared.candidate.databaseId,
        vaultId: prepared.candidate.vaultId,
        fromExclusive: {
          documentRevision: predecessorRevision,
          headDigest: prepared.candidate.previousHeadDigest,
        },
        toInclusive: {
          documentRevision: current.document.documentRevision,
          headDigest: current.document.headDigest,
        },
        limit: gap,
      });
    } catch {
      return { status: 'unknown', reason: 'proof-unavailable' };
    }
    try {
      const verified = await verifyCollaborativeJournalSuccessorChain({
        currentDocument: current.document,
        authoritativeDeviceRegistry: current.registry,
        mutationProof: proof,
        trusted: input.trusted,
        scope: prepared.scope,
        journalCandidate: prepared.candidate,
        journalCandidateAnchor: prepared.candidateAnchor,
        journalProofEntry: prepared.proofEntry,
        access:
          prepared.accessMode === 'recipient'
            ? {
                kind: 'recipient',
                recipientEncryptionPrivateKey: requiredSecret(recipientPrivateKey),
              }
            : {
                kind: 'database-authority-recovery',
                databaseRootKey: requiredSecret(databaseRootKey),
              },
        now: prepared.now,
      });
      anchors = verified.anchors;
      authorityAnchors = verified.authorityAnchors;
    } catch (error) {
      if (error instanceof CollaborationStateVerificationError) {
        return {
          status: 'terminal',
          reason:
            error.kind === 'fork' || error.kind === 'rollback'
              ? 'fork'
              : 'proof-invalid',
        };
      }
      return { status: 'terminal', reason: 'proof-invalid' };
    }
  }

  if (!(await appendAuthorizationCheckpoint(input.store, prepared))) {
    return { status: 'retryable', reason: 'checkpoint-append-failed' };
  }
  try {
    await reconcileCollaborativeOperationJournal(
      input.operationJournalPath,
      protectionSecret,
      prepared.proposedOutcome,
    );
  } catch {
    return { status: 'unknown', reason: 'journal-persistence-failed' };
  }
  if (prepared.accessMode === 'database-authority-recovery') {
    if (
      input.access.kind !== 'database-authority-recovery' ||
      databaseRootKey === undefined ||
      authorityAnchors === undefined
    ) {
      return { status: 'terminal', reason: 'proof-invalid' };
    }
    const authorityAdvance = await advanceRecoveredAuthorityAnchorChain(
      input.access.authorityRollbackAnchorPath,
      databaseRootKey,
      prepared,
      authorityAnchors,
    );
    if (authorityAdvance === 'fork') {
      return { status: 'terminal', reason: 'fork' };
    }
    if (authorityAdvance === 'failed') {
      return { status: 'unknown', reason: 'anchor-persistence-failed' };
    }
  }
  const anchorAdvance = await advanceRecoveredAnchorChain(
    input.rollbackAnchorPath,
    protectionSecret,
    prepared,
    anchors,
  );
  if (anchorAdvance === 'fork') return { status: 'terminal', reason: 'fork' };
  if (anchorAdvance === 'failed') {
    return { status: 'unknown', reason: 'anchor-persistence-failed' };
  }
  return { status: 'committed', disposition, outcome: remoteOutcome };
}

async function advanceRecoveredAnchorChain(
  path: string,
  secret: Uint8Array,
  prepared: ParsedPrepared,
  anchors: readonly RecipientRollbackAnchor[],
): Promise<'advanced' | 'fork' | 'failed'> {
  const candidateAnchor = anchors[0];
  if (
    candidateAnchor === undefined ||
    !sameAnchorPosition(candidateAnchor, prepared.candidateAnchor)
  ) {
    return 'fork';
  }
  let current: RecipientRollbackAnchor;
  try {
    current = await readRecipientRollbackAnchor(path, secret, {
      expectedScope: prepared.scope,
    });
  } catch {
    if (prepared.accessMode !== 'database-authority-recovery') return 'failed';
    try {
      await createRecipientRollbackAnchor(path, secret, candidateAnchor);
      current = candidateAnchor;
    } catch {
      try {
        current = await readRecipientRollbackAnchor(path, secret, {
          expectedScope: prepared.scope,
        });
      } catch {
        return 'failed';
      }
    }
  }

  let nextIndex: number;
  if (anchorMatchesCandidatePredecessor(current, prepared.candidate)) {
    nextIndex = 0;
  } else {
    const position = anchors.findIndex((anchor) => sameAnchorPosition(anchor, current));
    if (position < 0) return 'fork';
    nextIndex = position + 1;
  }
  for (; nextIndex < anchors.length; nextIndex += 1) {
    const next = anchors[nextIndex];
    if (next === undefined) return 'fork';
    const expected = current;
    try {
      await transitionRecipientRollbackAnchor(
        path,
        secret,
        next,
        (locked) => {
          if (!sameAnchorPosition(locked, expected)) {
            throw ABORT_ANCHOR_TRANSITION;
          }
          return { nextAnchor: next, result: undefined };
        },
        { expectedScope: prepared.scope },
      );
      current = next;
    } catch {
      return 'failed';
    }
  }
  return 'advanced';
}

async function advanceRecoveredAuthorityAnchorChain(
  path: string,
  databaseRootKey: Uint8Array,
  prepared: ParsedPrepared,
  anchors: readonly CollaborationAuthorityRollbackAnchor[],
): Promise<'advanced' | 'fork' | 'failed'> {
  const candidateAnchor = anchors[0];
  if (
    candidateAnchor === undefined ||
    !sameCanonical(candidateAnchor, authorityCandidateAnchor(prepared))
  ) {
    return 'fork';
  }
  let current: CollaborationAuthorityRollbackAnchor;
  try {
    current = await readCollaborationAuthorityRollbackAnchor(path, databaseRootKey, {
      expectedScope: authorityAnchorScope(prepared),
    });
  } catch {
    return 'failed';
  }

  let nextIndex: number;
  if (authorityAnchorMatchesCandidatePredecessor(current, prepared.candidate)) {
    nextIndex = 0;
  } else {
    const position = anchors.findIndex((anchor) => sameCanonical(anchor, current));
    if (position < 0) return 'fork';
    nextIndex = position + 1;
  }
  for (; nextIndex < anchors.length; nextIndex += 1) {
    const next = anchors[nextIndex];
    if (next === undefined) return 'fork';
    const expected = current;
    try {
      await transitionCollaborationAuthorityRollbackAnchor(
        path,
        databaseRootKey,
        next,
        (locked) => {
          if (!sameCanonical(locked, expected)) {
            throw ABORT_ANCHOR_TRANSITION;
          }
          return { nextAnchor: next, result: undefined };
        },
        { expectedScope: authorityAnchorScope(prepared) },
      );
      current = next;
    } catch {
      return 'failed';
    }
  }
  return 'advanced';
}

async function publishUnderAnchorLock(
  options: Readonly<{
    input: RecoveryServiceInput;
    prepared: ParsedPrepared;
    trust: TrustContext;
    writer: DeviceCertificate;
    protectionSecret: Uint8Array;
    currentAnchor: RecipientRollbackAnchor;
  }>,
): Promise<CollaborationMutationPublicationResult> {
  const { input, prepared, trust, writer, protectionSecret, currentAnchor } = options;
  let abort: CollaborationMutationPublicationResult | undefined;
  try {
    return await transitionRecipientRollbackAnchor(
      input.rollbackAnchorPath,
      protectionSecret,
      currentAnchor,
      async (lockedAnchor) => {
        if (!sameCanonical(lockedAnchor, currentAnchor)) {
          abort = { status: 'unknown', reason: 'anchor-persistence-failed' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        const attempt = await attemptPublication(input.store, prepared, trust, writer);
        if (attempt.kind !== 'committed') {
          abort =
            attempt.kind === 'retryable'
              ? { status: 'retryable', reason: attempt.reason }
              : attempt.kind === 'terminal'
                ? { status: 'terminal', reason: attempt.reason }
                : { status: 'unknown', reason: attempt.reason };
          throw ABORT_ANCHOR_TRANSITION;
        }
        const readback = await readCandidate(input.store, prepared);
        if (readback.kind === 'unavailable') {
          abort = { status: 'unknown', reason: 'readback-unavailable' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        if (readback.document === null) {
          abort = { status: 'terminal', reason: 'readback-mismatch' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        if (!sameCanonical(readback.document, prepared.candidate)) {
          abort =
            readback.document.documentRevision > prepared.candidate.documentRevision
              ? { status: 'unknown', reason: 'readback-unavailable' }
              : { status: 'terminal', reason: 'readback-mismatch' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        if (!(await appendAuthorizationCheckpoint(input.store, prepared))) {
          abort = { status: 'retryable', reason: 'checkpoint-append-failed' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        try {
          await reconcileCollaborativeOperationJournal(
            input.operationJournalPath,
            protectionSecret,
            prepared.proposedOutcome,
          );
        } catch {
          abort = { status: 'unknown', reason: 'journal-persistence-failed' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        return {
          nextAnchor: prepared.candidateAnchor,
          result: {
            status: 'committed' as const,
            disposition: attempt.disposition,
            outcome: attempt.outcome,
          },
        };
      },
      { expectedScope: prepared.scope },
    );
  } catch {
    if (abort !== undefined) return abort;
    return { status: 'unknown', reason: 'anchor-persistence-failed' };
  }
}

async function publishUnderDatabaseAuthorityRecovery(
  options: Readonly<{
    input: RecoveryServiceInput;
    prepared: ParsedPrepared;
    trust: TrustContext;
    writer: DeviceCertificate;
    protectionSecret: Uint8Array;
    databaseRootKey: Uint8Array;
    currentAuthorityAnchor: CollaborationAuthorityRollbackAnchor;
  }>,
): Promise<CollaborationMutationPublicationResult> {
  const {
    input,
    prepared,
    trust,
    writer,
    protectionSecret,
    databaseRootKey,
    currentAuthorityAnchor,
  } = options;
  if (input.access.kind !== 'database-authority-recovery') {
    throw failure('invalid-input');
  }
  const candidateAuthorityAnchor = authorityCandidateAnchor(prepared);
  let abort: CollaborationMutationPublicationResult | undefined;
  let committed: CollaborationMutationPublicationResult;
  try {
    committed = await transitionCollaborationAuthorityRollbackAnchor(
      input.access.authorityRollbackAnchorPath,
      databaseRootKey,
      currentAuthorityAnchor,
      async (lockedAnchor) => {
        if (!sameCanonical(lockedAnchor, currentAuthorityAnchor)) {
          abort = { status: 'unknown', reason: 'anchor-persistence-failed' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        const attempt = await attemptPublication(input.store, prepared, trust, writer);
        if (attempt.kind !== 'committed') {
          abort =
            attempt.kind === 'retryable'
              ? { status: 'retryable', reason: attempt.reason }
              : attempt.kind === 'terminal'
                ? { status: 'terminal', reason: attempt.reason }
                : { status: 'unknown', reason: attempt.reason };
          throw ABORT_ANCHOR_TRANSITION;
        }
        const readback = await readCandidate(input.store, prepared);
        if (readback.kind === 'unavailable') {
          abort = { status: 'unknown', reason: 'readback-unavailable' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        if (readback.document === null) {
          abort = { status: 'terminal', reason: 'readback-mismatch' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        if (!sameCanonical(readback.document, prepared.candidate)) {
          abort =
            readback.document.documentRevision > prepared.candidate.documentRevision
              ? { status: 'unknown', reason: 'readback-unavailable' }
              : { status: 'terminal', reason: 'readback-mismatch' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        if (!(await appendAuthorizationCheckpoint(input.store, prepared))) {
          abort = { status: 'retryable', reason: 'checkpoint-append-failed' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        try {
          await reconcileCollaborativeOperationJournal(
            input.operationJournalPath,
            protectionSecret,
            prepared.proposedOutcome,
          );
        } catch {
          abort = { status: 'unknown', reason: 'journal-persistence-failed' };
          throw ABORT_ANCHOR_TRANSITION;
        }
        return {
          nextAnchor: candidateAuthorityAnchor,
          result: {
            status: 'committed' as const,
            disposition: attempt.disposition,
            outcome: attempt.outcome,
          },
        };
      },
      { expectedScope: authorityAnchorScope(prepared) },
    );
  } catch {
    if (abort !== undefined) return abort;
    return { status: 'unknown', reason: 'anchor-persistence-failed' };
  }
  if (
    !(await ensureExactFirstRecipientAnchor(
      input.rollbackAnchorPath,
      protectionSecret,
      prepared,
    ))
  ) {
    return { status: 'unknown', reason: 'anchor-persistence-failed' };
  }
  return committed;
}

async function ensureExactFirstRecipientAnchor(
  path: string,
  protectionSecret: Uint8Array,
  prepared: ParsedPrepared,
): Promise<boolean> {
  try {
    await createRecipientRollbackAnchor(
      path,
      protectionSecret,
      prepared.candidateAnchor,
    );
    return true;
  } catch {
    try {
      const existing = await readRecipientRollbackAnchor(path, protectionSecret, {
        expectedScope: prepared.scope,
      });
      return sameCanonical(existing, prepared.candidateAnchor);
    } catch {
      return false;
    }
  }
}

async function appendAuthorizationCheckpoint(
  store: CollaborativeVaultStore,
  prepared: ParsedPrepared,
): Promise<boolean> {
  if (prepared.authorizationCheckpoint === undefined) return true;
  try {
    await store.appendCollaborationAuthorizationCheckpoint(
      prepared.authorizationCheckpoint,
    );
    return true;
  } catch {
    return false;
  }
}

function parseInput(input: PublishPreparedCollaborativeMutationInput): ParsedPrepared {
  try {
    const accessMode = parseAccessMode(input);
    assertPath(input.rollbackAnchorPath);
    assertPath(input.operationJournalPath);
    const supplied = input.prepared as unknown as Record<string, unknown>;
    const candidate = deepFreeze(
      collaborativeVaultDocumentSchema.parse(structuredClone(supplied['candidate'])),
    );
    const proofEntry = deepFreeze(
      collaborationMutationProofEntrySchema.parse(
        structuredClone(supplied['proofEntry']),
      ),
    );
    const proposedOutcome = deepFreeze(
      durableOperationOutcomeSchema.parse(structuredClone(supplied['proposedOutcome'])),
    );
    const candidateAnchor = deepFreeze(
      recipientRollbackAnchorSchema.parse(structuredClone(supplied['candidateAnchor'])),
    );
    const authorizationCheckpoint =
      input.authorizationCheckpoint === undefined
        ? undefined
        : deepFreeze(
            collaborationAuthorizationCheckpointSchema.parse(
              structuredClone(input.authorizationCheckpoint),
            ),
          );
    const scope = parseScope(input.scope);
    const now = timestampSchema.parse(input.now ?? new Date().toISOString());
    const commitment = candidate.currentMutationLink.commitment;
    if (
      commitment.operationType === 'genesis-migration' ||
      scope.databaseId !== candidate.databaseId ||
      scope.vaultId !== candidate.vaultId ||
      scope.principalId !== commitment.writerPrincipalId ||
      scope.deviceId !== commitment.writerDeviceId ||
      !sameCanonical(proofEntry.link, candidate.currentMutationLink)
    ) {
      throw failure('invalid-input');
    }
    if (
      accessMode === 'database-authority-recovery' &&
      (commitment.operationType !== 'recover-owner' ||
        input.currentMutationProof !== undefined)
    ) {
      throw failure('invalid-input');
    }
    if (
      (commitment.operationType === 'add-member' ||
        commitment.operationType === 'add-device') &&
      authorizationCheckpoint === undefined
    ) {
      throw failure('invalid-input');
    }
    return {
      candidate,
      proofEntry,
      proposedOutcome,
      candidateAnchor,
      ...(authorizationCheckpoint === undefined ? {} : { authorizationCheckpoint }),
      scope,
      now,
      accessMode,
    };
  } catch (error) {
    if (error instanceof CollaborationMutationPublicationError) throw error;
    throw failure('invalid-input');
  }
}

function preparedFromJournal(
  record: NonNullable<Awaited<ReturnType<typeof readCollaborativeOperationJournal>>>,
  scope: RecipientRollbackAnchorScope,
  now: Timestamp,
): ParsedPrepared {
  const candidate = deepFreeze(
    collaborativeVaultDocumentSchema.parse(structuredClone(record.candidate)),
  );
  const proofEntry = deepFreeze(
    collaborationMutationProofEntrySchema.parse(structuredClone(record.proofEntry)),
  );
  const proposedOutcome = deepFreeze(
    durableOperationOutcomeSchema.parse(
      structuredClone(
        record.state === 'prepared' ? record.proposedOutcome : record.outcome,
      ),
    ),
  );
  const candidateAnchor = deepFreeze(
    recipientRollbackAnchorSchema.parse(structuredClone(record.candidateAnchor)),
  );
  const authorizationCheckpoint =
    record.authorizationCheckpoint === undefined
      ? undefined
      : deepFreeze(
          collaborationAuthorizationCheckpointSchema.parse(
            structuredClone(record.authorizationCheckpoint),
          ),
        );
  if (
    record.databaseId !== scope.databaseId ||
    record.vaultId !== scope.vaultId ||
    record.actorPrincipalId !== scope.principalId ||
    record.actorDeviceId !== scope.deviceId
  ) {
    throw failure('invalid-input');
  }
  return {
    candidate,
    proofEntry,
    proposedOutcome,
    candidateAnchor,
    ...(authorizationCheckpoint === undefined ? {} : { authorizationCheckpoint }),
    scope,
    now,
    accessMode: record.accessMode,
    ...(record.recoveryRestartEvidence === undefined
      ? {}
      : { recoveryRestartEvidence: record.recoveryRestartEvidence }),
  };
}

function preparedRecoveryEvidence(
  prepared: ParsedPrepared,
): CollaborationRecoveryRestartEvidence {
  if (prepared.accessMode !== 'database-authority-recovery') {
    throw failure('invalid-input');
  }
  if (prepared.recoveryRestartEvidence !== undefined) {
    return prepared.recoveryRestartEvidence;
  }
  throw failure('current-state-invalid');
}

async function buildTrust(
  pinned: CollaborativeVaultPinnedTrust,
  now: Timestamp,
): Promise<TrustContext> {
  try {
    const delegation = collaborationAuthorityDelegationSchema.parse(
      structuredClone(pinned.authorityDelegation),
    );
    if (
      computePublicKeyFingerprint(delegation.authoritySigningPublicKey, 'ed25519') !==
        delegation.authoritySigningKeyFingerprint ||
      computePublicKeyFingerprint(delegation.authorityRecoveryPublicKey, 'x25519') !==
        delegation.authorityRecoveryKeyFingerprint ||
      !(await verifyAuthorityDelegation(
        delegation,
        delegation.authoritySigningPublicKey,
      ))
    ) {
      throw failure('trust-invalid');
    }
    const principals = new Map<string, TrustedPrincipal>();
    for (const value of pinned.principalPublicIdentities) {
      const identity = publicIdentityExportSchema.parse(structuredClone(value));
      const verified = await verifyIdentity(identity, now);
      const existing = principals.get(verified.principalId);
      if (existing !== undefined && !samePrincipal(existing, verified)) {
        throw failure('trust-invalid');
      }
      principals.set(verified.principalId, verified);
    }
    if (principals.size === 0) throw failure('trust-invalid');
    return {
      delegation,
      delegationDigest: computeAuthorityDelegationDigest(delegation),
      principals,
    };
  } catch (error) {
    if (error instanceof CollaborationMutationPublicationError) throw error;
    throw failure('trust-invalid');
  }
}

async function verifyIdentity(
  identity: PublicIdentityExport,
  now: Timestamp,
): Promise<TrustedPrincipal> {
  if (
    identity.expiresAt !== undefined &&
    Date.parse(now) >= Date.parse(identity.expiresAt)
  ) {
    throw failure('trust-invalid');
  }
  if (
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.publicIdentitySignature,
      identity,
      publicIdentityExportSchema,
      'selfSignature',
      identity.rootSigningPublicKey,
    ))
  ) {
    throw failure('trust-invalid');
  }
  const devices = new Map<string, DeviceCertificate>();
  for (const device of identity.devices) {
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.deviceCertificateSignature,
        device,
        deviceCertificateSchema,
        'rootSignature',
        identity.rootSigningPublicKey,
      ))
    ) {
      throw failure('trust-invalid');
    }
    devices.set(device.deviceId, device);
  }
  return {
    principalId: identity.principalId,
    fingerprint: computePublicKeyFingerprint(identity.rootSigningPublicKey, 'ed25519'),
    rootSigningPublicKey: identity.rootSigningPublicKey,
    devices,
  };
}

async function verifyPreparedOutcome(
  prepared: ParsedPrepared,
  writer: DeviceCertificate,
): Promise<void> {
  const { candidate, proposedOutcome } = prepared;
  const commitment = candidate.currentMutationLink.commitment;
  const linkDigest = computeFinalizedMutationLinkDigest(candidate.currentMutationLink);
  if (
    proposedOutcome.state !== 'committed' ||
    proposedOutcome.databaseId !== candidate.databaseId ||
    proposedOutcome.vaultId !== candidate.vaultId ||
    proposedOutcome.operationId !== commitment.operationId ||
    proposedOutcome.operationType !== commitment.operationType ||
    proposedOutcome.requestDigest !== commitment.requestDigest ||
    proposedOutcome.actorPrincipalId !== commitment.writerPrincipalId ||
    proposedOutcome.actorDeviceId !== commitment.writerDeviceId ||
    proposedOutcome.priorHeadDigest !== candidate.previousHeadDigest ||
    !sameCanonical(
      proposedOutcome.priorTuple,
      previousTuple(candidate.currentMutationLink),
    ) ||
    !sameCanonical(proposedOutcome.committedTuple, tupleOf(candidate)) ||
    proposedOutcome.committedHeadDigest !== candidate.headDigest ||
    proposedOutcome.finalizedMutationLinkDigest !== linkDigest ||
    proposedOutcome.outcomeDigest !== computeOperationOutcomeDigest(proposedOutcome) ||
    !(await verifyCommittedOperationOutcome(proposedOutcome, writer.signingPublicKey))
  ) {
    throw failure('candidate-invalid');
  }
}

async function loadCurrentState(
  options: Readonly<{
    input: PublishPreparedCollaborativeMutationInput;
    prepared: ParsedPrepared;
    trust: TrustContext;
    recipientPrivateKey?: Uint8Array;
    databaseRootKey?: Uint8Array;
    protectionSecret: Uint8Array;
  }>,
): Promise<VerifiedCurrent> {
  const {
    input,
    prepared,
    trust,
    recipientPrivateKey,
    databaseRootKey,
    protectionSecret,
  } = options;
  let remoteDocument: CollaborativeVaultDocument | null;
  let candidateRegistry: CollaborationDatabaseDeviceRegistry | null;
  try {
    [remoteDocument, candidateRegistry] = await Promise.all([
      input.store.getCollaborativeVault(
        prepared.candidate.databaseId,
        prepared.candidate.vaultId,
      ),
      input.store.getDatabaseDeviceRegistry(prepared.candidate.databaseId),
    ]);
  } catch {
    throw failure('remote-unavailable');
  }
  if (remoteDocument === null || candidateRegistry === null) {
    throw failure('current-state-invalid');
  }
  const document = collaborativeVaultDocumentSchema.parse(remoteDocument);
  const parsedCandidateRegistry =
    collaborationDatabaseDeviceRegistrySchema.parse(candidateRegistry);
  await verifyRegistry(parsedCandidateRegistry, prepared.candidate, trust);

  let currentRegistry = parsedCandidateRegistry;
  if (
    document.databaseDeviceGeneration !== parsedCandidateRegistry.generation ||
    document.databaseDeviceRegistryDigest !== parsedCandidateRegistry.registryDigest
  ) {
    let witness: unknown;
    try {
      witness = await input.store.getCollaborationAuthorizationWitness(
        document.databaseId,
        document.vaultId,
        document.authorizationStateDigest,
        document.documentRevision,
      );
    } catch {
      throw failure('remote-unavailable');
    }
    if (witness === null) throw failure('current-state-invalid');
    const parsedWitness = collaborationAuthorizationWitnessSchema.parse(witness);
    currentRegistry = parsedWitness.databaseDeviceRegistry;
  }
  await verifyRegistry(currentRegistry, document, trust);
  assertDenialsMonotonic(currentRegistry, parsedCandidateRegistry);

  try {
    if (prepared.accessMode === 'database-authority-recovery') {
      if (databaseRootKey === undefined || recipientPrivateKey !== undefined) {
        throw failure('current-state-invalid');
      }
      const authorityPath =
        input.access.kind === 'database-authority-recovery'
          ? input.access.authorityRollbackAnchorPath
          : undefined;
      if (authorityPath === undefined) throw failure('current-state-invalid');
      const authorityScope = authorityAnchorScope(prepared);
      let authorityAnchor: CollaborationAuthorityRollbackAnchor;
      try {
        authorityAnchor = await readCollaborationAuthorityRollbackAnchor(
          authorityPath,
          databaseRootKey,
          { expectedScope: authorityScope },
        );
      } catch {
        throw failure('current-state-invalid');
      }
      let mutationProof: CollaborationMutationProof | undefined;
      const proofGap = document.documentRevision - authorityAnchor.documentRevision;
      if (proofGap < 0 || proofGap > MAX_COLLABORATIVE_PROOF_LINKS) {
        throw failure('remote-unavailable');
      }
      if (proofGap > 0) {
        try {
          mutationProof = await input.store.getCollaborativeMutationProofRange({
            databaseId: document.databaseId,
            vaultId: document.vaultId,
            fromExclusive: {
              documentRevision: authorityAnchor.documentRevision,
              headDigest: authorityAnchor.headDigest,
            },
            toInclusive: {
              documentRevision: document.documentRevision,
              headDigest: document.headDigest,
            },
            limit: proofGap,
          });
        } catch {
          throw failure('remote-unavailable');
        }
      }
      const opened = await openCollaborativeVaultForDatabaseAuthorityRecovery({
        document,
        authoritativeDeviceRegistry: currentRegistry,
        ...(mutationProof === undefined ? {} : { mutationProof }),
        trusted: input.trusted,
        databaseRootKey,
        authorityRollbackAnchorPath: authorityPath,
        now: prepared.now,
      });
      zeroize(opened.decryptedPayload);
      try {
        authorityAnchor = await readCollaborationAuthorityRollbackAnchor(
          authorityPath,
          databaseRootKey,
          { expectedScope: authorityScope },
        );
      } catch {
        zeroize(opened.vaultRootKey);
        throw failure('current-state-invalid');
      }
      return {
        document: opened.document,
        manifest: opened.manifest,
        registry: currentRegistry,
        candidateRegistry: parsedCandidateRegistry,
        recoveryRestartEvidence: {
          priorTuple: tupleOf(opened.document),
          priorHeadDigest: opened.document.headDigest,
          priorDatabaseAuthorityRecoveryEnvelopeDigest:
            computeAuthorityRecoveryEnvelopeDigest(
              opened.document.databaseAuthorityRecoveryEnvelope,
            ),
        },
        authorityAnchor,
        vaultRootKey: opened.vaultRootKey,
      };
    }
    if (recipientPrivateKey === undefined || databaseRootKey !== undefined) {
      throw failure('current-state-invalid');
    }
    const opened = await openCollaborativeVaultWithPinnedTrust({
      document,
      authoritativeDeviceRegistry: currentRegistry,
      ...(input.currentMutationProof === undefined
        ? {}
        : { mutationProof: input.currentMutationProof }),
      trusted: input.trusted,
      scope: prepared.scope,
      recipientEncryptionPrivateKey: recipientPrivateKey,
      deviceProtectionSecret: protectionSecret,
      rollbackAnchorPath: input.rollbackAnchorPath,
      now: prepared.now,
    });
    zeroize(opened.decryptedPayload);
    const anchor = await readRecipientRollbackAnchor(
      input.rollbackAnchorPath,
      protectionSecret,
      { expectedScope: prepared.scope },
    );
    return {
      document: opened.document,
      manifest: opened.manifest,
      registry: currentRegistry,
      candidateRegistry: parsedCandidateRegistry,
      anchor,
      vaultRootKey: opened.vaultRootKey,
    };
  } catch (error) {
    if (error instanceof CollaborationStateVerificationError) {
      throw failure('current-state-invalid');
    }
    if (error instanceof CollaborationMutationPublicationError) throw error;
    throw failure('current-state-invalid');
  }
}

async function verifyCandidate(
  prepared: ParsedPrepared,
  current: VerifiedCurrent,
  trust: TrustContext,
  currentVaultRootKey: Uint8Array,
  nextVaultRootKey: Uint8Array | undefined,
): Promise<void> {
  let manifestPlaintext: Uint8Array | undefined;
  let payloadPlaintext: Uint8Array | undefined;
  try {
    const candidate = prepared.candidate;
    const link = candidate.currentMutationLink;
    const commitment = link.commitment;
    assertCandidatePrior(candidate, current.document, trust);
    if (commitment.expiresAt === undefined) throw failure('candidate-invalid');
    assertCandidateTime(commitment.timestamp, commitment.expiresAt, prepared.now);
    verifyOpaqueDigests(candidate);
    if (
      computeMutationRequestDigest(commitment) !== commitment.requestDigest ||
      computeMutationHead(commitment) !== candidate.headDigest ||
      link.resultingHeadDigest !== candidate.headDigest ||
      !sameCanonical(prepared.proofEntry.link, link)
    ) {
      throw failure('candidate-invalid');
    }
    const recovery = commitment.operationType === 'recover-owner';
    let writer = recovery
      ? undefined
      : requireAuthorizedWriter(
          current.manifest,
          link,
          current.registry,
          current.candidateRegistry,
          trust,
        );
    if (
      writer !== undefined &&
      !(await verifyFinalizedMutationLink(link, writer.signingPublicKey))
    ) {
      throw failure('candidate-invalid');
    }

    const candidateKey =
      candidate.keyEpoch === current.document.keyEpoch
        ? currentVaultRootKey
        : nextVaultRootKey;
    if (
      candidateKey === undefined ||
      (candidate.keyEpoch === current.document.keyEpoch &&
        nextVaultRootKey !== undefined) ||
      (candidate.keyEpoch !== current.document.keyEpoch + 1 &&
        candidate.keyEpoch !== current.document.keyEpoch)
    ) {
      throw failure('candidate-invalid');
    }
    manifestPlaintext = await decryptCollaborationEnvelope(
      candidate.encryptedMembershipManifest,
      candidateKey,
      expectedAad(candidate, 'membership-manifest'),
    );
    const manifest = parseManifest(manifestPlaintext);
    payloadPlaintext = await decryptCollaborationEnvelope(
      candidate.encryptedPayload,
      candidateKey,
      expectedAad(candidate, 'vault-payload'),
    );
    await verifyManifest(manifest, candidate, current.candidateRegistry, trust);
    const witness = prepared.proofEntry.authorizationWitness;
    if (witness !== undefined) {
      requireExactDatabaseAuthorityRecoveryEnvelope(witness, manifest);
      if (
        witness.databaseAuthorityRecoveryEnvelope.authorityRecoveryKeyFingerprint !==
        trust.delegation.authorityRecoveryKeyFingerprint
      ) {
        throw failure('candidate-invalid');
      }
    }
    await verifyCandidateAuthorizationCheckpoint(
      prepared,
      manifest,
      current.candidateRegistry,
    );
    const administrativeState = await verifyCandidateTransition(
      link,
      current.manifest,
      manifest,
      current.registry,
      current.candidateRegistry,
      trust,
    );
    if (recovery) {
      writer = requireRecoveryWriter(
        manifest,
        link,
        current.registry,
        current.candidateRegistry,
        trust,
        administrativeState,
      );
      await verifyEnvelopesByWriter(manifest, writer);
      if (!(await verifyFinalizedMutationLink(link, writer.signingPublicKey))) {
        throw failure('candidate-invalid');
      }
    }
    if (writer === undefined) throw failure('candidate-invalid');
    assertRegistryAdvanceWriterFence(
      link,
      current.registry,
      current.candidateRegistry,
      writer,
    );
    await verifyDiscoveryRecords(
      candidate.discoveryRecords,
      writer,
      current.candidateRegistry,
    );
    verifyProofEntry(prepared.proofEntry, candidate, current.candidateRegistry);
    const expectedAnchor = recipientRollbackAnchorFromCollaborativeVaultDocument(
      candidate,
      prepared.scope,
      {
        membershipDigest: computeMembershipStateDigest(authorizationCore(manifest)),
        policyDigest: computePolicyStateDigest(manifest.policy),
        finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(link),
      },
    );
    if (!sameCanonical(expectedAnchor, prepared.candidateAnchor)) {
      throw failure('candidate-invalid');
    }
  } catch (error) {
    if (error instanceof CollaborationMutationPublicationError) throw error;
    throw failure('candidate-invalid');
  } finally {
    zeroize(manifestPlaintext);
    zeroize(payloadPlaintext);
  }
}

async function verifyCandidateAuthorizationCheckpoint(
  prepared: ParsedPrepared,
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
): Promise<void> {
  const checkpoint = prepared.authorizationCheckpoint;
  if (checkpoint === undefined) return;
  const candidate = prepared.candidate;
  const linkDigest = computeFinalizedMutationLinkDigest(candidate.currentMutationLink);
  if (
    checkpoint.databaseId !== candidate.databaseId ||
    checkpoint.vaultId !== candidate.vaultId ||
    checkpoint.authorityDelegationDigest !== candidate.authorityDelegationDigest ||
    !sameCanonical(checkpoint.tuple, tupleOf(candidate)) ||
    checkpoint.headDigest !== candidate.headDigest ||
    checkpoint.authorizationStateDigest !== candidate.authorizationStateDigest ||
    checkpoint.finalizedMutationLinkDigest !== linkDigest ||
    checkpoint.checkpointDigest !== computeAuthorizationCheckpointDigest(checkpoint)
  ) {
    throw failure('candidate-invalid');
  }
  const signer = requireActiveDevice(
    manifest,
    checkpoint.signerPrincipalId,
    checkpoint.signerDeviceId,
    'owner',
  );
  requireNotDenied(registry, signer);
  if (!(await verifyAuthorizationCheckpoint(checkpoint, signer.signingPublicKey))) {
    throw failure('candidate-invalid');
  }
}

function assertCandidatePrior(
  candidate: CollaborativeVaultDocument,
  current: CollaborativeVaultDocument,
  trust: TrustContext,
): void {
  const commitment = candidate.currentMutationLink.commitment;
  if (
    candidate.databaseId !== current.databaseId ||
    candidate.vaultId !== current.vaultId ||
    candidate.authorityEpoch !== current.authorityEpoch ||
    candidate.authorityDelegationDigest !== trust.delegationDigest ||
    !sameCanonical(candidate.authorityDelegation, trust.delegation) ||
    !sameCanonical(candidate.authorityDelegation, current.authorityDelegation) ||
    commitment.previousHeadDigest !== current.headDigest ||
    !sameCanonical(previousTuple(candidate.currentMutationLink), tupleOf(current))
  ) {
    throw failure('candidate-invalid');
  }
}

async function verifyRegistry(
  registry: CollaborationDatabaseDeviceRegistry,
  document: CollaborativeVaultDocument,
  trust: TrustContext,
): Promise<void> {
  if (
    registry.databaseId !== document.databaseId ||
    registry.authorityEpoch !== document.authorityEpoch ||
    registry.authorityEpoch !== trust.delegation.authorityEpoch ||
    registry.authorityFingerprint !== trust.delegation.authoritySigningKeyFingerprint ||
    registry.generation !== document.databaseDeviceGeneration ||
    registry.registryDigest !== document.databaseDeviceRegistryDigest ||
    computeDeviceRegistryDigest(registry) !== registry.registryDigest ||
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.deviceRegistrySignature,
      registry,
      collaborationDatabaseDeviceRegistrySchema,
      'authoritySignature',
      trust.delegation.authoritySigningPublicKey,
    ))
  ) {
    throw failure('candidate-invalid');
  }
}

function assertDenialsMonotonic(
  prior: CollaborationDatabaseDeviceRegistry,
  next: CollaborationDatabaseDeviceRegistry,
): void {
  if (next.generation < prior.generation) throw failure('candidate-invalid');
  for (const denial of prior.deniedDevices) {
    if (!next.deniedDevices.some((candidate) => sameCanonical(candidate, denial))) {
      throw failure('candidate-invalid');
    }
  }
}

function verifyOpaqueDigests(document: CollaborativeVaultDocument): void {
  const payloadMetadata = collaborationAadMetadataSchema.parse(
    withoutMetadataDigest(document.encryptedPayload.aad),
  );
  const manifestMetadata = collaborationAadMetadataSchema.parse(
    withoutMetadataDigest(document.encryptedMembershipManifest.aad),
  );
  if (
    computeAadMetadataDigest(payloadMetadata) !==
      document.encryptedPayload.aad.metadataDigest ||
    computeAadMetadataDigest(manifestMetadata) !==
      document.encryptedMembershipManifest.aad.metadataDigest ||
    computeEncryptedPayloadDigest(document.encryptedPayload) !==
      document.encryptedPayloadDigest ||
    computeEncryptedMembershipDigest(document.encryptedMembershipManifest) !==
      document.encryptedMembershipDigest
  ) {
    throw failure('candidate-invalid');
  }
}

async function verifyManifest(
  manifest: CollaborativeMembershipManifest,
  document: CollaborativeVaultDocument,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<void> {
  requireExactDatabaseAuthorityRecoveryEnvelope(document, manifest);
  if (
    !sameCanonical(tupleOfManifest(manifest), tupleOf(document)) ||
    manifest.previousHeadDigest !== document.previousHeadDigest ||
    computeMembershipManifestDigest(manifest) !== manifest.membershipDigest ||
    computeMembershipHistoryDigest(manifest.history) !==
      manifest.history.currentHistoryDigest ||
    computeKeyEnvelopeSetDigest(manifest.keyEnvelopes) !==
      document.encryptedEnvelopesDigest ||
    computePolicyDigest(manifest.policy) !== document.policyDigest ||
    manifest.policy.policyDigest !== document.policyDigest ||
    computeAuthorizationStateDigest(authorizationCore(manifest)) !==
      document.authorizationStateDigest ||
    manifest.authorizationStateDigest !== document.authorizationStateDigest ||
    !checkActiveOwnerInvariant({
      memberships: manifest.memberships,
      ownerPrincipalIds: manifest.ownerPrincipalIds,
    }).valid
  ) {
    throw failure('candidate-invalid');
  }
  await verifyManifestDeviceChains(manifest, trust);
  await verifyPolicy(manifest, registry, trust);
  await verifyHistory(manifest, registry, trust);
  await verifyEnvelopes(manifest, registry);
}

async function verifyManifestDeviceChains(
  manifest: CollaborativeMembershipManifest,
  trust: TrustContext,
): Promise<void> {
  for (const membership of manifest.memberships) {
    if (
      computePublicKeyFingerprint(membership.rootSigningPublicKey, 'ed25519') !==
      membership.principalFingerprint
    ) {
      throw failure('candidate-invalid');
    }
    const pinned = trust.principals.get(membership.principalId);
    if (
      pinned !== undefined &&
      (pinned.fingerprint !== membership.principalFingerprint ||
        pinned.rootSigningPublicKey !== membership.rootSigningPublicKey)
    ) {
      throw failure('candidate-invalid');
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
        throw failure('candidate-invalid');
      }
      assertPinnedDeviceIfPresent(trust, device);
    }
  }
}

async function verifyPolicy(
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<void> {
  const policy = collaborationPolicyStateSchema.parse(manifest.policy);
  const signer = requireManifestDevice(
    manifest,
    policy.changedByPrincipalId,
    policy.changedByDeviceId,
  );
  assertPinnedDeviceIfPresent(trust, signer);
  requireNotDenied(registry, signer);
  if (
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.policySignature,
      policy,
      collaborationPolicyStateSchema,
      'signature',
      signer.signingPublicKey,
    ))
  ) {
    throw failure('candidate-invalid');
  }
}

async function verifyHistory(
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<void> {
  for (const event of manifest.history.events) {
    const signer = requireHistoricalSigner(
      manifest,
      event.actorPrincipalId,
      event.actorDeviceId,
      event.timestamp,
      registry,
    );
    assertPinnedDeviceIfPresent(trust, signer);
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistorySignature,
        event,
        membershipHistoryEventSchema,
        'signature',
        signer.signingPublicKey,
      ))
    ) {
      throw failure('candidate-invalid');
    }
  }
  for (const checkpoint of manifest.history.checkpoints) {
    const signer = requireHistoricalSigner(
      manifest,
      checkpoint.signerPrincipalId,
      checkpoint.signerDeviceId,
      checkpoint.createdAt,
      registry,
    );
    assertPinnedDeviceIfPresent(trust, signer);
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
        checkpoint,
        membershipHistoryCheckpointSchema,
        'signature',
        signer.signingPublicKey,
      ))
    ) {
      throw failure('candidate-invalid');
    }
  }
}

function requireHistoricalSigner(
  manifest: CollaborativeMembershipManifest,
  principalId: string,
  deviceId: string,
  signedAt: Timestamp,
  registry: CollaborationDatabaseDeviceRegistry,
): DeviceCertificate {
  const membership = manifest.memberships.find(
    (candidate) => candidate.principalId === principalId,
  );
  const device = membership?.devices.find(
    (candidate) => candidate.deviceId === deviceId,
  );
  if (membership === undefined || device === undefined) {
    throw failure('candidate-invalid');
  }
  const signedTime = Date.parse(signedAt);
  if (
    signedTime < Date.parse(membership.createdAt) ||
    signedTime < Date.parse(device.createdAt) ||
    (membership.removedAt !== undefined &&
      signedTime >= Date.parse(membership.removedAt)) ||
    (device.expiresAt !== undefined && signedTime >= Date.parse(device.expiresAt)) ||
    (device.state === 'active'
      ? signedTime < Date.parse(device.stateChangedAt)
      : signedTime >= Date.parse(device.stateChangedAt)) ||
    isDeniedAt(registry, device, signedAt)
  ) {
    throw failure('candidate-invalid');
  }
  return device;
}

async function verifyEnvelopes(
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
): Promise<void> {
  const owners = activeOwnerDevices(manifest).filter(
    (device) => !isDenied(registry, device),
  );
  if (owners.length === 0) throw failure('candidate-invalid');
  for (const envelope of manifest.keyEnvelopes) {
    const digest =
      'membershipId' in envelope
        ? computeKeyEnvelopeDigest(envelope)
        : computeAuthorityRecoveryEnvelopeDigest(envelope);
    if (digest !== envelope.envelopeDigest) throw failure('candidate-invalid');
    let valid = false;
    for (const owner of owners) {
      valid =
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
      if (valid) break;
    }
    if (!valid) throw failure('candidate-invalid');
  }
}

async function verifyEnvelopesByWriter(
  manifest: CollaborativeMembershipManifest,
  writer: DeviceCertificate,
): Promise<void> {
  for (const envelope of manifest.keyEnvelopes) {
    if (
      !('membershipId' in envelope) &&
      (envelope.sealedByPrincipalId !== writer.principalId ||
        envelope.sealedByDeviceId !== writer.deviceId)
    ) {
      throw failure('candidate-invalid');
    }
    const valid =
      'membershipId' in envelope
        ? await verifyCollaborationRecord(
            COLLABORATION_DOMAINS.keyEnvelopeSignature,
            envelope,
            collaborationKeyEnvelopeSchema,
            'ownerSignature',
            writer.signingPublicKey,
          )
        : await verifyCollaborationRecord(
            COLLABORATION_DOMAINS.keyEnvelopeSignature,
            envelope,
            databaseAuthorityRecoveryEnvelopeSchema,
            'ownerSignature',
            writer.signingPublicKey,
          );
    if (!valid) throw failure('candidate-invalid');
  }
}

async function verifyDiscoveryRecords(
  records: readonly CollaborationDiscoveryRecord[],
  writer: DeviceCertificate,
  registry: CollaborationDatabaseDeviceRegistry,
): Promise<void> {
  requireNotDenied(registry, writer);
  for (const record of records) {
    if (
      record.signerPrincipalId !== writer.principalId ||
      record.signerDeviceId !== writer.deviceId ||
      computeDiscoveryRecordDigest(record) !== record.discoveryRecordDigest ||
      !(await verifyDiscoveryRecord(record, writer.signingPublicKey))
    ) {
      throw failure('candidate-invalid');
    }
  }
}

function verifyProofEntry(
  proofEntry: ProofEntry,
  candidate: CollaborativeVaultDocument,
  registry: CollaborationDatabaseDeviceRegistry,
): void {
  const witness = proofEntry.authorizationWitness;
  if (candidate.currentMutationLink.commitment.operationType === 'ordinary-write') {
    if (witness !== undefined) throw failure('candidate-invalid');
    return;
  }
  if (
    witness === undefined ||
    !sameCanonical(
      witness.encryptedMembershipManifest,
      candidate.encryptedMembershipManifest,
    ) ||
    !sameCanonical(witness.discoveryRecords, candidate.discoveryRecords) ||
    !sameCanonical(witness.databaseDeviceRegistry, registry) ||
    witness.finalizedMutationLinkDigest !==
      computeFinalizedMutationLinkDigest(candidate.currentMutationLink)
  ) {
    throw failure('candidate-invalid');
  }
}

async function verifyCandidateTransition(
  link: CollaborationFinalizedMutationLink,
  priorManifest: CollaborativeMembershipManifest,
  nextManifest: CollaborativeMembershipManifest,
  priorRegistry: CollaborationDatabaseDeviceRegistry,
  nextRegistry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<VerifiedCollaborativeAdministrativeManifestTransition | undefined> {
  const commitment = link.commitment;
  if (commitment.operationType === 'destroy-vault') {
    throw failure('candidate-invalid');
  }
  const prior = previousTuple(link);
  const next = tupleFromCommitment(link);
  if (commitment.operationType === 'ordinary-write') {
    const result = validateRevisionTransition({
      operationType: commitment.operationType,
      prior,
      next,
    });
    if (
      !result.valid ||
      !sameCanonical(authorizationCore(priorManifest), authorizationCore(nextManifest))
    ) {
      throw failure('candidate-invalid');
    }
    return undefined;
  }
  const transition = requireTransition(link);
  let administrativeState: VerifiedCollaborativeAdministrativeManifestTransition;
  try {
    administrativeState = verifyCollaborativeAdministrativeManifestTransition({
      link,
      priorManifest,
      nextManifest,
    });
  } catch {
    throw failure('candidate-invalid');
  }
  await verifyTransitionSignature(
    transition,
    priorManifest,
    priorRegistry,
    trust,
    commitment.timestamp,
  );
  const revision = validateRevisionTransition({
    operationType: commitment.operationType,
    prior,
    next,
    decryptAccessChanged: administrativeState.decryptAccessChanged,
    authorizationTransitionDigest: transition.transitionDigest,
    ...(next.databaseDeviceGeneration > prior.databaseDeviceGeneration
      ? { authoritativeRegistry: nextRegistry }
      : {}),
  });
  if (!revision.valid) throw failure('candidate-invalid');
  await validateTransitionEvidence(
    administrativeState,
    priorManifest,
    nextManifest,
    priorRegistry,
    nextRegistry,
    trust,
    commitment.timestamp,
  );
  return administrativeState;
}

function requireRecoveryWriter(
  nextManifest: CollaborativeMembershipManifest,
  link: CollaborationFinalizedMutationLink,
  priorRegistry: CollaborationDatabaseDeviceRegistry,
  nextRegistry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  administrativeState:
    VerifiedCollaborativeAdministrativeManifestTransition | undefined,
): DeviceCertificate {
  if (
    administrativeState?.operationType !== 'recover-owner' ||
    administrativeState.historyEvent.eventType !== 'owner-recovery' ||
    administrativeState.historyEvent.targetPrincipalId !==
      link.commitment.writerPrincipalId
  ) {
    throw failure('candidate-invalid');
  }
  const writer = requireActiveDevice(
    nextManifest,
    link.commitment.writerPrincipalId,
    link.commitment.writerDeviceId,
    'owner',
  );
  assertPinnedDeviceIfPresent(trust, writer);
  requireUsableAt(writer, link.commitment.timestamp);
  requireNotDenied(priorRegistry, writer);
  requireNotDenied(nextRegistry, writer);
  return writer;
}

function assertRegistryAdvanceWriterFence(
  link: CollaborationFinalizedMutationLink,
  priorRegistry: CollaborationDatabaseDeviceRegistry,
  nextRegistry: CollaborationDatabaseDeviceRegistry,
  writer: DeviceCertificate,
): void {
  if (nextRegistry.generation <= priorRegistry.generation) return;
  requireNotDenied(priorRegistry, writer);
  requireNotDenied(nextRegistry, writer);
  if (Date.parse(link.commitment.timestamp) < Date.parse(nextRegistry.updatedAt)) {
    throw failure('candidate-invalid');
  }
}

async function verifyTransitionSignature(
  transition: CollaborationAuthorizationTransition,
  priorManifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  committedAt: Timestamp,
): Promise<void> {
  if (
    computeAuthorizationTransitionDigest(transition) !== transition.transitionDigest ||
    Date.parse(committedAt) < Date.parse(transition.issuedAt) ||
    Date.parse(committedAt) >= Date.parse(transition.expiresAt)
  ) {
    throw failure('candidate-invalid');
  }
  const signature = transition.transitionSignature;
  if (signature.signerKind === 'database-authority') {
    if (
      transition.operationType !== 'recover-owner' ||
      signature.authorityEpoch !== trust.delegation.authorityEpoch ||
      signature.authoritySigningKeyFingerprint !==
        trust.delegation.authoritySigningKeyFingerprint ||
      !(await verifyAuthorizationTransitionAuthority(
        transition,
        trust.delegation.authoritySigningPublicKey,
      ))
    ) {
      throw failure('candidate-invalid');
    }
    return;
  }
  const owner = requireActiveDevice(
    priorManifest,
    signature.signerPrincipalId,
    signature.signerDeviceId,
    'owner',
  );
  assertPinnedDeviceIfPresent(trust, owner);
  requireUsableAt(owner, committedAt);
  requireNotDenied(registry, owner);
  if (!(await verifyAuthorizationTransitionOwner(transition, owner.signingPublicKey))) {
    throw failure('candidate-invalid');
  }
}

async function validateTransitionEvidence(
  administrativeState: VerifiedCollaborativeAdministrativeManifestTransition,
  priorManifest: CollaborativeMembershipManifest,
  nextManifest: CollaborativeMembershipManifest,
  priorRegistry: CollaborationDatabaseDeviceRegistry,
  nextRegistry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  committedAt: Timestamp,
): Promise<void> {
  const transition = administrativeState.transition;
  if (transition.operationType === 'recover-owner') {
    return;
  }
  if (transition.operationType === 'transfer-owner') {
    const intent = administrativeState.transfer?.recipientAccepted;
    if (intent?.recipientAcceptance === undefined) throw failure('candidate-invalid');
    const initiator = requireActiveDevice(
      priorManifest,
      intent.initiatorPrincipalId,
      intent.initiatorDeviceId,
      'owner',
    );
    const recipient = requireActiveDevice(
      nextManifest,
      intent.recipientPrincipalId,
      intent.recipientDeviceId,
      'owner',
    );
    assertPinnedDeviceIfPresent(trust, initiator);
    assertPinnedDeviceIfPresent(trust, recipient);
    requireNotDenied(priorRegistry, initiator);
    requireNotDenied(nextRegistry, recipient);
    const transferValidation = validateOwnershipTransfer({
      intent,
      priorMemberships: priorManifest.memberships,
      nextMemberships: nextManifest.memberships,
      priorTuple: transition.previousTuple,
      priorHeadDigest: transition.previousHeadDigest,
      now: committedAt,
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
    if (
      !(await verifyTransferIntent(intent, initiator.signingPublicKey)) ||
      !(await verifyOwnershipTransferAcceptance(
        intent.recipientAcceptance,
        recipient.signingPublicKey,
      )) ||
      !transferValidation.valid ||
      !transferValidation.complete
    ) {
      throw failure('candidate-invalid');
    }
    if (administrativeState.approval !== undefined) {
      await validateNormalizedApproval(
        administrativeState.approval,
        transition,
        priorManifest,
        priorRegistry,
        trust,
        committedAt,
      );
    }
    return;
  }
  if (administrativeState.approval === undefined) return;
  await validateNormalizedApproval(
    administrativeState.approval,
    transition,
    priorManifest,
    priorRegistry,
    trust,
    committedAt,
  );
}

async function validateNormalizedApproval(
  normalized: NormalizedApprovalEvidence,
  transition: CollaborationAuthorizationTransition,
  priorManifest: CollaborativeMembershipManifest,
  priorRegistry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  committedAt: Timestamp,
): Promise<void> {
  const request = normalized.quorumReached;
  const requester = requireActiveDevice(
    priorManifest,
    request.requestingPrincipalId,
    request.requestingDeviceId,
    'owner',
  );
  requireNotDenied(priorRegistry, requester);
  if (!(await verifyApprovalRequest(request, requester.signingPublicKey))) {
    throw failure('candidate-invalid');
  }
  const verifiedApprovals = [];
  for (const evidence of request.approvals) {
    const approver = requireActiveDevice(
      priorManifest,
      evidence.approverPrincipalId,
      evidence.approverDeviceId,
      'owner',
    );
    requireNotDenied(priorRegistry, approver);
    if (!(await verifyApprovalEvidence(evidence, approver.signingPublicKey))) {
      throw failure('candidate-invalid');
    }
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
    priorPolicy: priorManifest.policy,
    priorTuple: transition.previousTuple,
    priorHeadDigest: transition.previousHeadDigest,
    activeMemberships: priorManifest.memberships,
    now: committedAt,
    verifiedRequesterSignature: {
      approvalRequestId: request.approvalRequestId,
      requesterPrincipalId: request.requestingPrincipalId,
      requesterDeviceId: request.requestingDeviceId,
      signedRequestDigest: request.requestDigest,
      signature: request.requesterSignature,
    },
    verifiedApprovalSignatures: verifiedApprovals,
  });
  if (!result.valid || !result.eligibleForConsumption) {
    throw failure('candidate-invalid');
  }
}

function requireAuthorizedWriter(
  manifest: CollaborativeMembershipManifest,
  link: CollaborationFinalizedMutationLink,
  priorRegistry: CollaborationDatabaseDeviceRegistry,
  nextRegistry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): DeviceCertificate {
  const commitment = link.commitment;
  const membership = manifest.memberships.find(
    (candidate) =>
      candidate.principalId === commitment.writerPrincipalId &&
      candidate.state === 'active',
  );
  const device = membership?.devices.find(
    (candidate) =>
      candidate.deviceId === commitment.writerDeviceId && candidate.state === 'active',
  );
  if (membership === undefined || device === undefined) {
    throw failure('candidate-invalid');
  }
  assertPinnedDeviceIfPresent(trust, device);
  requireUsableAt(device, commitment.timestamp);
  requireNotDenied(priorRegistry, device);
  requireNotDenied(nextRegistry, device);
  if (
    !authorizeOperation({
      operationType: commitment.operationType,
      membership,
      device,
      authoritativeRegistry: priorRegistry,
      deviceSigningKeyFingerprint: computePublicKeyFingerprint(
        device.signingPublicKey,
        'ed25519',
      ),
    }).authorized
  ) {
    throw failure('candidate-invalid');
  }
  return device;
}

async function attemptPublication(
  store: CollaborativeVaultStore,
  prepared: ParsedPrepared,
  _trust: TrustContext,
  writer: DeviceCertificate,
): Promise<PublicationAttempt> {
  const existing = await readRemoteOutcome(store, prepared);
  if (existing.kind === 'unavailable') {
    return { kind: 'unknown', reason: 'publication-ambiguous' };
  }
  if (existing.outcome !== null) {
    const classified = await classifyRemoteOutcome(existing.outcome, prepared, writer);
    if (classified.kind === 'matching') {
      return {
        kind: 'committed',
        disposition: 'already-committed',
        outcome: classified.outcome,
      };
    }
    if (classified.kind === 'operation-id-reused') {
      return { kind: 'terminal', reason: 'operation-id-reused' };
    }
    if (classified.kind === 'invalid') {
      return { kind: 'terminal', reason: 'remote-outcome-invalid' };
    }
  }

  try {
    const returned = await store.publishCollaborativeVault({
      candidate: prepared.candidate,
      outcome: prepared.proposedOutcome,
      proofEntry: prepared.proofEntry,
    });
    const classification = await classifyRemoteOutcome(returned, prepared, writer);
    if (classification.kind === 'matching') {
      return {
        kind: 'committed',
        disposition: 'published',
        outcome: classification.outcome,
      };
    }
    if (classification.kind === 'retryable') return classification;
    return {
      kind: 'terminal',
      reason:
        classification.kind === 'operation-id-reused'
          ? 'operation-id-reused'
          : 'remote-outcome-invalid',
    };
  } catch (error) {
    const after = await readRemoteOutcome(store, prepared);
    if (after.kind === 'unavailable') {
      return { kind: 'unknown', reason: 'publication-ambiguous' };
    }
    if (after.outcome !== null) {
      const classification = await classifyRemoteOutcome(
        after.outcome,
        prepared,
        writer,
      );
      if (classification.kind === 'matching') {
        return {
          kind: 'committed',
          disposition: 'already-committed',
          outcome: classification.outcome,
        };
      }
      if (classification.kind === 'operation-id-reused') {
        return { kind: 'terminal', reason: 'operation-id-reused' };
      }
      if (classification.kind === 'invalid') {
        return { kind: 'terminal', reason: 'remote-outcome-invalid' };
      }
    }
    if (error instanceof EncryptedDatabaseStoreError) {
      if (error.code === 'conflict' || error.code === 'exists') {
        return { kind: 'retryable', reason: 'conflict' };
      }
      if (error.code === 'invalid') {
        return { kind: 'retryable', reason: 'rejected' };
      }
    }
    return { kind: 'unknown', reason: 'publication-ambiguous' };
  }
}

async function classifyRemoteOutcome(
  remote: DurableOperationOutcome | OperationDeduplicationTombstone,
  prepared: ParsedPrepared,
  writer: DeviceCertificate,
): Promise<RemoteOutcomeClassification> {
  try {
    if (remote.format === 'kavrix-collaborative-operation-tombstone') {
      const tombstone = operationDeduplicationTombstoneSchema.parse(remote);
      if (
        tombstone.databaseId !== prepared.candidate.databaseId ||
        tombstone.vaultId !== prepared.candidate.vaultId ||
        tombstone.operationId !==
          prepared.candidate.currentMutationLink.commitment.operationId ||
        tombstone.requestDigest !== prepared.proposedOutcome.requestDigest
      ) {
        return { kind: 'operation-id-reused' };
      }
      if (
        tombstone.outcomeDigest !== prepared.proposedOutcome.outcomeDigest ||
        !sameCanonical(
          tombstone.signedMutationReceipt,
          prepared.proposedOutcome.signedMutationReceipt,
        ) ||
        !(await verifyOperationTombstone(tombstone, writer.signingPublicKey))
      ) {
        return { kind: 'invalid' };
      }
      return { kind: 'matching', outcome: tombstone };
    }
    const outcome = durableOperationOutcomeSchema.parse(remote);
    if (
      outcome.databaseId !== prepared.candidate.databaseId ||
      outcome.vaultId !== prepared.candidate.vaultId ||
      outcome.operationId !==
        prepared.candidate.currentMutationLink.commitment.operationId
    ) {
      return { kind: 'operation-id-reused' };
    }
    if (outcome.state !== 'committed') {
      return {
        kind: 'retryable',
        reason: outcome.state === 'conflicted' ? 'conflict' : 'rejected',
      };
    }
    if (outcome.requestDigest !== prepared.proposedOutcome.requestDigest) {
      return { kind: 'operation-id-reused' };
    }
    if (
      !sameCanonical(outcome, prepared.proposedOutcome) ||
      !(await verifyCommittedOperationOutcome(outcome, writer.signingPublicKey))
    ) {
      return { kind: 'invalid' };
    }
    return { kind: 'matching', outcome };
  } catch {
    return { kind: 'invalid' };
  }
}

async function readRemoteOutcome(
  store: CollaborativeVaultStore,
  prepared: ParsedPrepared,
): Promise<OutcomeRead> {
  try {
    return {
      kind: 'available',
      outcome: await store.getCollaborativeOperationOutcome(
        prepared.candidate.databaseId,
        prepared.candidate.vaultId,
        prepared.candidate.currentMutationLink.commitment.operationId,
      ),
    };
  } catch {
    return { kind: 'unavailable' };
  }
}

async function readCandidate(
  store: CollaborativeVaultStore,
  prepared: ParsedPrepared,
): Promise<
  | Readonly<{ kind: 'available'; document: CollaborativeVaultDocument | null }>
  | Readonly<{ kind: 'unavailable' }>
> {
  try {
    return {
      kind: 'available',
      document: await store.getCollaborativeVault(
        prepared.candidate.databaseId,
        prepared.candidate.vaultId,
      ),
    };
  } catch {
    return { kind: 'unavailable' };
  }
}

async function readJournal(
  path: string,
  secret: Uint8Array,
  scope: CollaborationOperationJournalScope,
): Promise<
  | Readonly<{
      kind: 'available';
      record: Awaited<ReturnType<typeof readCollaborativeOperationJournal>>;
    }>
  | Readonly<{ kind: 'unavailable' }>
> {
  try {
    return {
      kind: 'available',
      record: await readCollaborativeOperationJournal(path, secret, {
        expectedScope: scope,
      }),
    };
  } catch {
    return { kind: 'unavailable' };
  }
}

function journalMatches(
  journal: NonNullable<Awaited<ReturnType<typeof readCollaborativeOperationJournal>>>,
  prepared: ParsedPrepared,
): boolean {
  const commitment = prepared.candidate.currentMutationLink.commitment;
  if (
    journal.databaseId !== prepared.candidate.databaseId ||
    journal.vaultId !== prepared.candidate.vaultId ||
    journal.operationId !== commitment.operationId ||
    journal.operationType !== commitment.operationType ||
    journal.requestDigest !== commitment.requestDigest ||
    journal.actorPrincipalId !== commitment.writerPrincipalId ||
    journal.actorDeviceId !== commitment.writerDeviceId ||
    journal.accessMode !== prepared.accessMode ||
    (prepared.accessMode === 'recipient'
      ? journal.recoveryRestartEvidence !== undefined
      : journal.recoveryRestartEvidence === undefined) ||
    !sameCanonical(journal.candidateAnchor, prepared.candidateAnchor) ||
    !sameCanonical(journal.proofEntry, prepared.proofEntry) ||
    !sameOptionalCanonical(
      journal.authorizationCheckpoint,
      prepared.authorizationCheckpoint,
    )
  ) {
    return false;
  }
  return journal.state === 'prepared'
    ? sameCanonical(journal.candidate, prepared.candidate) &&
        sameCanonical(journal.proposedOutcome, prepared.proposedOutcome)
    : sameCanonical(journal.outcome, prepared.proposedOutcome);
}

function sameOptionalCanonical(left: unknown, right: unknown): boolean {
  return left === undefined
    ? right === undefined
    : right !== undefined && sameCanonical(left, right);
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

function tupleOfManifest(
  manifest: CollaborativeMembershipManifest,
): CollaborationRevisionTuple {
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: manifest.authorityEpoch,
    documentRevision: manifest.documentRevision,
    membershipRevision: manifest.membershipRevision,
    policyRevision: manifest.policyRevision,
    keyEpoch: manifest.keyEpoch,
    databaseDeviceGeneration: manifest.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: manifest.databaseDeviceRegistryDigest,
    authorizationStateDigest: manifest.authorizationStateDigest,
  });
}

function previousTuple(
  link: CollaborationFinalizedMutationLink,
): CollaborationRevisionTuple {
  const commitment = link.commitment;
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: commitment.previousAuthorityEpoch,
    documentRevision: commitment.previousDocumentRevision,
    membershipRevision: commitment.previousMembershipRevision,
    policyRevision: commitment.previousPolicyRevision,
    keyEpoch: commitment.previousKeyEpoch,
    databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
    databaseDeviceRegistryDigest: commitment.previousDatabaseDeviceRegistryDigest,
    authorizationStateDigest: commitment.previousAuthorizationStateDigest,
  });
}

function tupleFromCommitment(
  link: CollaborationFinalizedMutationLink,
): CollaborationRevisionTuple {
  const commitment = link.commitment;
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: commitment.authorityEpoch,
    documentRevision: commitment.documentRevision,
    membershipRevision: commitment.membershipRevision,
    policyRevision: commitment.policyRevision,
    keyEpoch: commitment.keyEpoch,
    databaseDeviceGeneration: commitment.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: commitment.databaseDeviceRegistryDigest,
    authorizationStateDigest: commitment.authorizationStateDigest,
  });
}

function requireTransition(
  link: CollaborationFinalizedMutationLink,
): CollaborationAuthorizationTransition {
  const transition = link.authorizationTransition;
  if (
    transition === undefined ||
    transition.transitionDigest !== link.commitment.authorizationTransitionDigest ||
    computeAuthorizationTransitionDigest(transition) !== transition.transitionDigest
  ) {
    throw failure('candidate-invalid');
  }
  return transition;
}

function expectedAad(
  document: CollaborativeVaultDocument,
  entityType: 'membership-manifest' | 'vault-payload',
): ReturnType<typeof collaborationAadSchema.parse> {
  const metadata = collaborationAadMetadataSchema.parse({
    protocolVersion: document.protocolVersion,
    databaseId: document.databaseId,
    vaultId: document.vaultId,
    authorityEpoch: document.authorityEpoch,
    entityType,
    entityId: document.vaultId,
    documentRevision: document.documentRevision,
    membershipRevision: document.membershipRevision,
    policyRevision: document.policyRevision,
    keyEpoch: document.keyEpoch,
    databaseDeviceGeneration: document.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: document.databaseDeviceRegistryDigest,
    authorizationStateDigest: document.authorizationStateDigest,
  });
  return collaborationAadSchema.parse({
    ...metadata,
    metadataDigest: computeAadMetadataDigest(metadata),
  });
}

function parseManifest(bytes: Uint8Array): CollaborativeMembershipManifest {
  try {
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return collaborativeMembershipManifestSchema.parse(JSON.parse(decoded));
  } catch {
    throw failure('candidate-invalid');
  }
}

function requirePinnedDevice(
  trust: TrustContext,
  principalId: string,
  deviceId: string,
): DeviceCertificate {
  const device = trust.principals.get(principalId)?.devices.get(deviceId);
  if (device === undefined) throw failure('trust-invalid');
  return device;
}

function assertPinnedDeviceIfPresent(
  trust: TrustContext,
  device: DeviceCertificate,
): void {
  const pinned = trust.principals.get(device.principalId)?.devices.get(device.deviceId);
  if (
    pinned !== undefined &&
    (pinned.deviceGeneration !== device.deviceGeneration ||
      pinned.signingPublicKey !== device.signingPublicKey ||
      pinned.encryptionPublicKey !== device.encryptionPublicKey)
  ) {
    throw failure('candidate-invalid');
  }
}

function requireManifestDevice(
  manifest: CollaborativeMembershipManifest,
  principalId: string,
  deviceId: string,
): DeviceCertificate {
  const membership = manifest.memberships.find(
    (candidate) => candidate.principalId === principalId,
  );
  const device = membership?.devices.find(
    (candidate) => candidate.deviceId === deviceId,
  );
  if (device === undefined) throw failure('candidate-invalid');
  return device;
}

function requireActiveDevice(
  manifest: CollaborativeMembershipManifest,
  principalId: string,
  deviceId: string,
  role: CollaborationMembership['role'],
): DeviceCertificate {
  const membership = manifest.memberships.find(
    (candidate) =>
      candidate.principalId === principalId &&
      candidate.state === 'active' &&
      candidate.role === role,
  );
  const device = membership?.devices.find(
    (candidate) => candidate.deviceId === deviceId && candidate.state === 'active',
  );
  if (device === undefined) throw failure('candidate-invalid');
  return device;
}

function requireUsableAt(device: DeviceCertificate, timestamp: Timestamp): void {
  if (
    device.state !== 'active' ||
    Date.parse(timestamp) < Date.parse(device.createdAt) ||
    Date.parse(timestamp) < Date.parse(device.stateChangedAt) ||
    (device.expiresAt !== undefined &&
      Date.parse(timestamp) >= Date.parse(device.expiresAt))
  ) {
    throw failure('candidate-invalid');
  }
}

function activeOwnerDevices(
  manifest: CollaborativeMembershipManifest,
): readonly DeviceCertificate[] {
  return manifest.memberships
    .filter(
      (membership) => membership.state === 'active' && membership.role === 'owner',
    )
    .flatMap((membership) =>
      membership.devices.filter((device) => device.state === 'active'),
    );
}

function isDenied(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
): boolean {
  return registry.deniedDevices.some((denial) => denialMatchesDevice(denial, device));
}

function isDeniedAt(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
  at: Timestamp,
): boolean {
  const checkpointTime = Date.parse(at);
  return registry.deniedDevices.some(
    (denial) =>
      denialMatchesDevice(denial, device) &&
      checkpointTime >= Date.parse(denial.deniedAt),
  );
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

function requireNotDenied(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
): void {
  if (isDenied(registry, device)) throw failure('candidate-invalid');
}

function assertCandidateTime(
  issuedAt: Timestamp,
  expiresAt: Timestamp,
  now: Timestamp,
): void {
  const skew = MAX_COLLABORATIVE_CLOCK_SKEW_SECONDS * 1000;
  if (
    Date.parse(expiresAt) <= Date.parse(issuedAt) ||
    Date.parse(now) + skew < Date.parse(issuedAt) ||
    Date.parse(now) >= Date.parse(expiresAt)
  ) {
    throw failure('candidate-invalid');
  }
}

function parseAccessMode(
  input:
    | Pick<PublishPreparedCollaborativeMutationInput, 'access'>
    | Pick<ResumeCollaborativeMutationFromJournalInput, 'access'>,
): 'recipient' | 'database-authority-recovery' {
  const inputRecord = input as unknown as Record<string, unknown>;
  if (
    Object.prototype.hasOwnProperty.call(
      inputRecord,
      'recipientEncryptionPrivateKey',
    ) ||
    Object.prototype.hasOwnProperty.call(inputRecord, 'databaseRootKey')
  ) {
    throw failure('invalid-input');
  }
  const value = inputRecord['access'];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw failure('invalid-input');
  }
  const access = value as Record<string, unknown>;
  const keys = Object.keys(access).sort();
  if (
    access['kind'] === 'recipient' &&
    sameStrings(keys, ['kind', 'recipientEncryptionPrivateKey']) &&
    access['recipientEncryptionPrivateKey'] instanceof Uint8Array
  ) {
    return 'recipient';
  }
  if (
    access['kind'] === 'database-authority-recovery' &&
    sameStrings(keys, ['authorityRollbackAnchorPath', 'databaseRootKey', 'kind']) &&
    access['databaseRootKey'] instanceof Uint8Array &&
    typeof access['authorityRollbackAnchorPath'] === 'string'
  ) {
    assertPath(access['authorityRollbackAnchorPath']);
    return 'database-authority-recovery';
  }
  throw failure('invalid-input');
}

type CurrentDocumentRead =
  | Readonly<{
      kind: 'available';
      document: CollaborativeVaultDocument | null;
      registry: CollaborationDatabaseDeviceRegistry | null;
    }>
  | Readonly<{ kind: 'unavailable' }>;

async function readCurrentDocumentAndRegistry(
  store: CollaborativeVaultStore,
  prepared: ParsedPrepared,
): Promise<CurrentDocumentRead> {
  try {
    const [documentInput, latestRegistryInput] = await Promise.all([
      store.getCollaborativeVault(
        prepared.candidate.databaseId,
        prepared.candidate.vaultId,
      ),
      store.getDatabaseDeviceRegistry(prepared.candidate.databaseId),
    ]);
    if (documentInput === null || latestRegistryInput === null) {
      return { kind: 'available', document: documentInput, registry: null };
    }
    const document = collaborativeVaultDocumentSchema.parse(documentInput);
    const latestRegistry =
      collaborationDatabaseDeviceRegistrySchema.parse(latestRegistryInput);
    if (
      document.databaseDeviceGeneration === latestRegistry.generation &&
      document.databaseDeviceRegistryDigest === latestRegistry.registryDigest
    ) {
      return { kind: 'available', document, registry: latestRegistry };
    }
    const witness = await store.getCollaborationAuthorizationWitness(
      document.databaseId,
      document.vaultId,
      document.authorizationStateDigest,
      document.documentRevision,
    );
    if (witness === null) {
      return { kind: 'available', document, registry: null };
    }
    const parsedWitness = collaborationAuthorizationWitnessSchema.parse(witness);
    return {
      kind: 'available',
      document,
      registry: parsedWitness.databaseDeviceRegistry,
    };
  } catch {
    return { kind: 'unavailable' };
  }
}

function documentMatchesCandidatePredecessor(
  document: CollaborativeVaultDocument,
  candidate: CollaborativeVaultDocument,
): boolean {
  return (
    document.databaseId === candidate.databaseId &&
    document.vaultId === candidate.vaultId &&
    document.authorityEpoch === candidate.authorityEpoch &&
    document.authorityDelegationDigest === candidate.authorityDelegationDigest &&
    document.headDigest === candidate.previousHeadDigest &&
    canonicalJson(tupleOf(document)) ===
      canonicalJson(previousTuple(candidate.currentMutationLink))
  );
}

function anchorMatchesCandidatePredecessor(
  anchor: RecipientRollbackAnchor,
  candidate: CollaborativeVaultDocument,
): boolean {
  const tuple = previousTuple(candidate.currentMutationLink);
  const commitment = candidate.currentMutationLink.commitment;
  return (
    anchor.databaseId === candidate.databaseId &&
    anchor.vaultId === candidate.vaultId &&
    anchor.principalId === commitment.writerPrincipalId &&
    anchor.deviceId === commitment.writerDeviceId &&
    anchor.authorityEpoch === tuple.authorityEpoch &&
    anchor.authorityDelegationDigest === candidate.authorityDelegationDigest &&
    anchor.databaseDeviceGeneration === tuple.databaseDeviceGeneration &&
    anchor.databaseDeviceRegistryDigest === tuple.databaseDeviceRegistryDigest &&
    anchor.membershipRevision === tuple.membershipRevision &&
    anchor.policyRevision === tuple.policyRevision &&
    anchor.keyEpoch === tuple.keyEpoch &&
    anchor.documentRevision === tuple.documentRevision &&
    anchor.headDigest === commitment.previousHeadDigest &&
    anchor.authorizationStateDigest === tuple.authorizationStateDigest
  );
}

function authorityAnchorMatchesCandidatePredecessor(
  anchor: CollaborationAuthorityRollbackAnchor,
  candidate: CollaborativeVaultDocument,
): boolean {
  const tuple = previousTuple(candidate.currentMutationLink);
  return (
    anchor.databaseId === candidate.databaseId &&
    anchor.vaultId === candidate.vaultId &&
    anchor.authorityEpoch === tuple.authorityEpoch &&
    anchor.authorityDelegationDigest === candidate.authorityDelegationDigest &&
    anchor.databaseDeviceGeneration === tuple.databaseDeviceGeneration &&
    anchor.databaseDeviceRegistryDigest === tuple.databaseDeviceRegistryDigest &&
    anchor.membershipRevision === tuple.membershipRevision &&
    anchor.policyRevision === tuple.policyRevision &&
    anchor.keyEpoch === tuple.keyEpoch &&
    anchor.documentRevision === tuple.documentRevision &&
    anchor.headDigest === candidate.previousHeadDigest &&
    anchor.authorizationStateDigest === tuple.authorizationStateDigest
  );
}

function authorityAnchorScope(
  prepared: ParsedPrepared,
): CollaborationAuthorityRollbackAnchorScope {
  return {
    databaseId: prepared.candidate.databaseId,
    vaultId: prepared.candidate.vaultId,
    authorityEpoch: prepared.candidate.authorityEpoch,
    authorityDelegationDigest: prepared.candidate.authorityDelegationDigest,
  };
}

function authorityCandidateAnchor(
  prepared: ParsedPrepared,
): CollaborationAuthorityRollbackAnchor {
  return collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
    prepared.candidate,
    {
      membershipDigest: prepared.candidateAnchor.membershipDigest,
      policyDigest: prepared.candidateAnchor.policyDigest,
    },
  );
}

function sameAnchorPosition(
  left: RecipientRollbackAnchor,
  right: RecipientRollbackAnchor,
): boolean {
  // Idempotent recovery accepts only the exact protected anchor bytes. A same
  // tuple/head with substituted logical digests or trust metadata is a fork.
  return canonicalJson(left) === canonicalJson(right);
}

function requiredSecret(value: Uint8Array | undefined): Uint8Array {
  if (value === undefined) throw failure('invalid-input');
  return value;
}

function parseScope(scope: RecipientRollbackAnchorScope): RecipientRollbackAnchorScope {
  return {
    databaseId: recipientRollbackAnchorSchema.shape.databaseId.parse(scope.databaseId),
    vaultId: recipientRollbackAnchorSchema.shape.vaultId.parse(scope.vaultId),
    principalId: recipientRollbackAnchorSchema.shape.principalId.parse(
      scope.principalId,
    ),
    deviceId: recipientRollbackAnchorSchema.shape.deviceId.parse(scope.deviceId),
  };
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length && left.every((value, index) => value === right[index])
  );
}

function withoutMetadataDigest<T extends { metadataDigest: unknown }>(
  value: T,
): Omit<T, 'metadataDigest'> {
  const copy = { ...value };
  Reflect.deleteProperty(copy, 'metadataDigest');
  return copy;
}

function samePrincipal(left: TrustedPrincipal, right: TrustedPrincipal): boolean {
  return (
    left.fingerprint === right.fingerprint &&
    left.rootSigningPublicKey === right.rootSigningPublicKey &&
    sameCanonical([...left.devices], [...right.devices])
  );
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

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
  }
  return value;
}

function failure(
  kind: CollaborationMutationPublicationFailureKind,
): CollaborationMutationPublicationError {
  return new CollaborationMutationPublicationError(kind);
}
