import {
  authorizeOperation,
  checkActiveOwnerInvariant,
  evaluateDeviceFence,
  validateApproval,
  validateOwnershipTransfer,
  validateRevisionTransition,
} from '@kavrix/core';
import {
  COLLABORATION_DOMAINS,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  computeAadMetadataDigest,
  computeAuthorityDelegationDigest,
  computeAuthorityRecoveryEnvelopeDigest,
  computeAuthorizationStateDigest,
  computeAuthorizationTransitionDigest,
  computeDeviceCertificateFingerprint,
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
  computePolicyDigest,
  computePolicyStateDigest,
  computePublicKeyFingerprint,
  decryptCollaborationEnvelope,
  openCollaborationVaultRootForDatabaseAuthority,
  openVaultRootKeyForDevice,
  verifyApprovalEvidence,
  verifyApprovalRequest,
  verifyAuthorityDelegation,
  verifyAuthorizationCheckpoint,
  verifyAuthorizationTransitionAuthority,
  verifyAuthorizationTransitionOwner,
  verifyCollaborationRecord,
  verifyDiscoveryRecord,
  verifyEnrollmentReceipt,
  verifyFinalizedMutationLink,
  verifyOwnershipTransferAcceptance,
  verifyTransferIntent,
  zeroize,
  type DatabaseRootKey,
  type DeviceEncryptionPrivateKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  COLLABORATION_AUTHORITY_ROLLBACK_ANCHOR_FORMAT,
  collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument,
  collaborationAuthorityRollbackAnchorSchema,
  createRecipientRollbackAnchor,
  readCollaborationAuthorityRollbackAnchor,
  readRecipientRollbackAnchor,
  recipientRollbackAnchorFromCollaborativeVaultDocument,
  transitionCollaborationAuthorityRollbackAnchor,
  transitionRecipientRollbackAnchor,
  type CollaborationAuthorityRollbackAnchor,
  type CollaborationAuthorityRollbackAnchorScope,
  type RecipientRollbackAnchorScope,
} from '@kavrix/key-files';
import {
  canonicalJson,
  collaborationAadMetadataSchema,
  collaborationAadSchema,
  collaborationAuthorizationCheckpointSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationWitnessSchema,
  collaborationAuthorityDelegationSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationKeyEnvelopeSchema,
  collaborationMutationProofEntrySchema,
  collaborationMutationProofSchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  databaseIdSchema,
  deviceCertificateSchema,
  deviceIdSchema,
  enrollmentReceiptSchema,
  membershipHistoryCheckpointSchema,
  membershipHistoryEventSchema,
  principalIdSchema,
  publicIdentityExportSchema,
  recipientRollbackAnchorSchema,
  timestampSchema,
  vaultIdSchema,
  type CollaborationAuthorizationCheckpoint,
  type CollaborationAuthorizationTransition,
  type CollaborationAuthorizationWitness,
  type CollaborationAuthorityDelegation,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationDiscoveryRecord,
  type CollaborationFinalizedMutationLink,
  type CollaborationKeyEnvelope,
  type CollaborationMembership,
  type CollaborationMutationProof,
  type CollaborationRevisionTuple,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DeviceCertificate,
  type EnrollmentReceipt,
  type RecipientRollbackAnchor,
  type Sha256Digest,
  type Timestamp,
} from '@kavrix/schemas';

import {
  advanceCollaborativeManifestAcrossOrdinaryLink,
  verifyCollaborativeAdministrativeManifestTransition,
  type NormalizedApprovalEvidence,
  type VerifiedCollaborativeAdministrativeManifestTransition,
} from './collaboration-administrative-state.js';
import { requireExactDatabaseAuthorityRecoveryEnvelope } from './collaboration-recovery-envelope-binding.js';

type CollaborationAad = ReturnType<typeof collaborationAadSchema.parse>;

const SAFE_MESSAGE = 'Collaborative vault state verification failed.';

export type CollaborationStateVerificationFailureKind =
  | 'invalid-input'
  | 'trust-required'
  | 'trust-mismatch'
  | 'trust-expired'
  | 'signature-invalid'
  | 'digest-invalid'
  | 'proof-required'
  | 'proof-invalid'
  | 'device-future'
  | 'rekey-required'
  | 'recipient-inactive'
  | 'writer-inactive'
  | 'writer-unauthorized'
  | 'rollback'
  | 'fork'
  | 'decryption-failed'
  | 'anchor-persistence-failed';

/** Safe, non-oracular error metadata for the caller's control flow. */
export class CollaborationStateVerificationError extends Error {
  readonly safe = true;
  readonly kind: CollaborationStateVerificationFailureKind;

  constructor(kind: CollaborationStateVerificationFailureKind) {
    super(SAFE_MESSAGE);
    this.name = 'CollaborationStateVerificationError';
    this.kind = kind;
  }
}

/** Explicit out-of-band material retained beside the protected local anchor. */
export type CollaborativeVaultPinnedTrust = Readonly<{
  authorityDelegation: unknown;
  principalPublicIdentities: readonly unknown[];
}>;

type CommonOpenInput = Readonly<{
  document: unknown;
  authoritativeDeviceRegistry: unknown;
  mutationProof?: unknown;
  scope: RecipientRollbackAnchorScope;
  recipientEncryptionPrivateKey: DeviceEncryptionPrivateKey | Uint8Array;
  deviceProtectionSecret: Uint8Array;
  rollbackAnchorPath: string;
  now?: Timestamp;
}>;

export type EnrollAndOpenCollaborativeVaultInput = CommonOpenInput &
  Readonly<{
    enrollmentReceipt: unknown;
    enrollmentCheckpoint: unknown;
    additionalTrustedPrincipalPublicIdentities?: readonly unknown[];
  }>;

export type OpenCollaborativeVaultWithPinnedTrustInput = CommonOpenInput &
  Readonly<{
    trusted: CollaborativeVaultPinnedTrust;
  }>;

export type OpenCollaborativeVaultForDatabaseAuthorityRecoveryInput = Readonly<{
  document: unknown;
  authoritativeDeviceRegistry: unknown;
  mutationProof?: unknown;
  trusted: CollaborativeVaultPinnedTrust;
  databaseRootKey: DatabaseRootKey | Uint8Array;
  authorityRollbackAnchorPath: string;
  now?: Timestamp;
}>;

export type OpenedCollaborativeVaultState = Readonly<{
  document: CollaborativeVaultDocument;
  manifest: CollaborativeMembershipManifest;
  recipientMembership: CollaborationMembership;
  recipientDevice: DeviceCertificate;
  vaultRootKey: VaultRootKey;
  decryptedPayload: Uint8Array;
}>;

export type OpenedCollaborativeVaultForDatabaseAuthorityRecoveryState = Readonly<{
  document: CollaborativeVaultDocument;
  manifest: CollaborativeMembershipManifest;
  vaultRootKey: VaultRootKey;
  decryptedPayload: Uint8Array;
}>;

type TrustedPrincipal = Readonly<{
  principalId: string;
  fingerprint: Sha256Digest;
  rootSigningPublicKey: string;
  pinnedDevices: ReadonlyMap<string, DeviceCertificate>;
}>;

type TrustContext = Readonly<{
  delegation: CollaborationAuthorityDelegation;
  delegationDigest: Sha256Digest;
  principals: ReadonlyMap<string, TrustedPrincipal>;
  receipt?: EnrollmentReceipt;
  checkpoint?: CollaborationAuthorizationCheckpoint;
}>;

type ParsedScope = Readonly<{
  databaseId: ReturnType<typeof databaseIdSchema.parse>;
  vaultId: ReturnType<typeof vaultIdSchema.parse>;
  principalId: ReturnType<typeof principalIdSchema.parse>;
  deviceId: ReturnType<typeof deviceIdSchema.parse>;
}>;

type ProofBase = Readonly<{
  tuple: CollaborationRevisionTuple;
  headDigest: Sha256Digest;
  authorizationStateDigest: Sha256Digest;
  finalizedMutationLinkDigest?: Sha256Digest;
  membershipDigest?: Sha256Digest;
  policyDigest?: Sha256Digest;
  encryptedPayloadDigest?: Sha256Digest;
}>;

type ProofAccess =
  | Readonly<{
      kind: 'recipient';
      scope: ParsedScope;
      recipientEncryptionPrivateKey: DeviceEncryptionPrivateKey | Uint8Array;
    }>
  | Readonly<{
      kind: 'database-authority-recovery';
      databaseRootKey: DatabaseRootKey | Uint8Array;
    }>;

type VerifiedManifest = Readonly<{
  manifest: CollaborativeMembershipManifest;
  membershipDigest: Sha256Digest;
  policyDigest: Sha256Digest;
  discoveryRecords: readonly CollaborationDiscoveryRecord[];
  databaseDeviceRegistry: CollaborationDatabaseDeviceRegistry;
}>;

type VerifiedProof = Readonly<{
  endingAuthorizationManifest: CollaborativeMembershipManifest;
  lastLink: CollaborationFinalizedMutationLink;
  lastWriter: DeviceCertificate;
  steps: readonly VerifiedProofStep[];
}>;

type VerifiedProofStep = Readonly<{
  link: CollaborationFinalizedMutationLink;
  manifest: CollaborativeMembershipManifest;
}>;

type OpenedCurrent = VerifiedManifest &
  Readonly<{
    discovery: CollaborationDiscoveryRecord;
    envelope: CollaborationKeyEnvelope;
    recipientMembership: CollaborationMembership;
    recipientDevice: DeviceCertificate;
    vaultRootKey: VaultRootKey;
  }>;

/** First use is pinned by an authenticated receipt plus its exact checkpoint. */
export async function enrollAndOpenCollaborativeVault(
  input: EnrollAndOpenCollaborativeVaultInput,
): Promise<OpenedCollaborativeVaultState> {
  let trust: TrustContext;
  try {
    const scope = parseScope(input.scope);
    const now = parseNow(input.now);
    trust = await trustFromEnrollment(
      input.enrollmentReceipt,
      input.enrollmentCheckpoint,
      input.additionalTrustedPrincipalPublicIdentities ?? [],
      scope,
      now,
    );
  } catch (error) {
    throw mapFailure(error, 'trust-required');
  }
  return verifyOpenAndPersist(input, trust, 'create');
}

/** Subsequent use requires both explicit immutable trust and a protected anchor. */
export async function openCollaborativeVaultWithPinnedTrust(
  input: OpenCollaborativeVaultWithPinnedTrustInput,
): Promise<OpenedCollaborativeVaultState> {
  let trust: TrustContext;
  try {
    trust = await trustFromPinnedMaterial(input.trusted, parseNow(input.now), true);
  } catch (error) {
    throw mapFailure(error, 'trust-required');
  }
  return verifyOpenAndPersist(input, trust, 'transition');
}

/**
 * Opens the current collaboration state from the immutable delegation's
 * database-authority recovery envelope. A DRK-protected authority anchor is
 * the only freshness base: an exact head must match all anchor bindings and a
 * newer head requires a complete authenticated proof from that anchor.
 */
export async function openCollaborativeVaultForDatabaseAuthorityRecovery(
  input: OpenCollaborativeVaultForDatabaseAuthorityRecoveryInput,
): Promise<OpenedCollaborativeVaultForDatabaseAuthorityRecoveryState> {
  let databaseRootKey: Uint8Array | undefined;
  let vaultRootKey: VaultRootKey | undefined;
  let decryptedPayload: Uint8Array | undefined;
  let trustedAuthorityAnchor: CollaborationAuthorityRollbackAnchor | undefined;
  try {
    databaseRootKey = copySecret(input.databaseRootKey, 32);
    const now = parseNow(input.now);
    const trust = await trustFromPinnedMaterial(input.trusted, now, false);
    const document = collaborativeVaultDocumentSchema.parse(input.document);
    const registry = collaborationDatabaseDeviceRegistrySchema.parse(
      input.authoritativeDeviceRegistry,
    );
    const scope = {
      databaseId: trust.delegation.databaseId,
      vaultId: trust.delegation.vaultId,
    };
    await verifyImmutableAndOpaqueDocument(document, registry, trust, scope);
    const authorityScope = authorityAnchorScope(trust);
    try {
      trustedAuthorityAnchor = await readCollaborationAuthorityRollbackAnchor(
        input.authorityRollbackAnchorPath,
        databaseRootKey,
        { expectedScope: authorityScope },
      );
    } catch (error) {
      throw mapFailure(error, 'trust-required');
    }
    verifyAuthorityAnchorTrust(trustedAuthorityAnchor, authorityScope, trust, document);
    const base = proofBaseFromAuthorityAnchor(trustedAuthorityAnchor);
    verifyCandidatePosition(document, base);
    const proof = parseProofForPosition(input.mutationProof, base, document, trust);
    const verifiedProof =
      proof === undefined
        ? undefined
        : await verifyMutationProof(proof, base, document, registry, trust, {
            kind: 'database-authority-recovery',
            databaseRootKey,
          });

    const opened = await openCurrentManifestForDatabaseAuthorityRecovery(
      document,
      registry,
      trust,
      databaseRootKey,
    );
    vaultRootKey = opened.vaultRootKey;
    let currentWriter: DeviceCertificate;
    if (verifiedProof === undefined) {
      currentWriter =
        document.documentRevision === trust.delegation.genesisTuple.documentRevision
          ? requireDelegationGenesisWriter(opened.manifest, registry, trust)
          : requireManifestWriterForLink(
              opened.manifest,
              document.currentMutationLink,
              registry,
              trust,
            );
      await verifyPinnedTipLink(
        document,
        opened.manifest,
        registry,
        trust,
        now,
        currentWriter,
      );
      await verifyManifestEnvelopeSignaturesByWriter(opened.manifest, currentWriter);
    } else {
      currentWriter = verifiedProof.lastWriter;
      if (
        verifiedProof.endingAuthorizationManifest.authorizationStateDigest !==
          opened.manifest.authorizationStateDigest ||
        canonicalJson(authorizationCore(verifiedProof.endingAuthorizationManifest)) !==
          canonicalJson(authorizationCore(opened.manifest)) ||
        canonicalJson(verifiedProof.lastLink) !==
          canonicalJson(document.currentMutationLink)
      ) {
        throw failure('proof-invalid');
      }
    }
    if (base.tuple.documentRevision === document.documentRevision) {
      verifyExactBasePlaintextBindings(
        base,
        document,
        opened.membershipDigest,
        opened.policyDigest,
      );
    }
    await verifyDiscoveryRecords(document.discoveryRecords, currentWriter, registry);
    if (Date.parse(now) < Date.parse(document.createdAt)) {
      throw failure('trust-mismatch');
    }

    decryptedPayload = await decryptCollaborationEnvelope(
      document.encryptedPayload,
      vaultRootKey,
      expectedAad(
        tupleOfDocument(document),
        document.databaseId,
        document.vaultId,
        'vault-payload',
      ),
    );
    const nextAuthorityAnchor =
      collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(document, {
        membershipDigest: opened.membershipDigest,
        policyDigest: opened.policyDigest,
      });
    const chainVerification =
      nextAuthorityAnchor.documentRevision > trustedAuthorityAnchor.documentRevision
        ? {
            kind: 'verified-chain' as const,
            from: trustedAuthorityAnchor,
            to: nextAuthorityAnchor,
          }
        : undefined;
    try {
      await transitionCollaborationAuthorityRollbackAnchor(
        input.authorityRollbackAnchorPath,
        databaseRootKey,
        nextAuthorityAnchor,
        (lockedAnchor) => {
          if (canonicalJson(lockedAnchor) !== canonicalJson(trustedAuthorityAnchor)) {
            throw failure('rollback');
          }
          return { nextAnchor: nextAuthorityAnchor, result: undefined };
        },
        chainVerification === undefined
          ? { expectedScope: authorityScope }
          : { expectedScope: authorityScope, chainVerification },
      );
    } catch (error) {
      throw mapFailure(error, 'anchor-persistence-failed');
    }
    const result = {
      document,
      manifest: opened.manifest,
      vaultRootKey,
      decryptedPayload,
    };
    vaultRootKey = undefined;
    decryptedPayload = undefined;
    return result;
  } catch (error) {
    zeroize(vaultRootKey);
    zeroize(decryptedPayload);
    throw mapFailure(error, 'invalid-input');
  } finally {
    zeroize(databaseRootKey);
  }
}

/**
 * Narrow, file-free verifier for a committed journal candidate and every live
 * successor through the supplied current document. The raw proof base remains
 * private so callers cannot weaken how the journal candidate anchors the chain.
 */
export type VerifyCollaborativeJournalSuccessorChainInput = Readonly<{
  currentDocument: unknown;
  authoritativeDeviceRegistry: unknown;
  mutationProof: unknown;
  trusted: CollaborativeVaultPinnedTrust;
  scope: RecipientRollbackAnchorScope;
  journalCandidate: unknown;
  journalCandidateAnchor: unknown;
  journalProofEntry: unknown;
  access:
    | Readonly<{
        kind: 'recipient';
        recipientEncryptionPrivateKey: DeviceEncryptionPrivateKey | Uint8Array;
      }>
    | Readonly<{
        kind: 'database-authority-recovery';
        databaseRootKey: DatabaseRootKey | Uint8Array;
      }>;
  now?: Timestamp;
}>;

export type VerifiedCollaborativeJournalSuccessorChain = Readonly<{
  currentDocument: CollaborativeVaultDocument;
  anchors: readonly RecipientRollbackAnchor[];
  authorityAnchors?: readonly CollaborationAuthorityRollbackAnchor[];
}>;

export async function verifyCollaborativeJournalSuccessorChain(
  input: VerifyCollaborativeJournalSuccessorChainInput,
): Promise<VerifiedCollaborativeJournalSuccessorChain> {
  let accessSecret: Uint8Array | undefined;
  let vaultRootKey: VaultRootKey | undefined;
  let decryptedPayload: Uint8Array | undefined;
  try {
    const now = parseNow(input.now);
    const scope = parseScope(input.scope);
    const trust = await trustFromPinnedMaterial(
      input.trusted,
      now,
      input.access.kind === 'recipient',
    );
    const currentDocument = collaborativeVaultDocumentSchema.parse(
      structuredClone(input.currentDocument),
    );
    const registry = collaborationDatabaseDeviceRegistrySchema.parse(
      structuredClone(input.authoritativeDeviceRegistry),
    );
    const journalCandidate = collaborativeVaultDocumentSchema.parse(
      structuredClone(input.journalCandidate),
    );
    const journalCandidateAnchor = recipientRollbackAnchorSchema.parse(
      structuredClone(input.journalCandidateAnchor),
    );
    const journalProofEntry = collaborationMutationProofEntrySchema.parse(
      structuredClone(input.journalProofEntry),
    );
    const proof = collaborationMutationProofSchema.parse(
      structuredClone(input.mutationProof),
    );
    if (
      currentDocument.documentRevision <= journalCandidate.documentRevision ||
      journalCandidate.databaseId !== scope.databaseId ||
      journalCandidate.vaultId !== scope.vaultId ||
      canonicalJson(journalCandidate.currentMutationLink) !==
        canonicalJson(journalProofEntry.link) ||
      canonicalJson(proof.entries[0]) !== canonicalJson(journalProofEntry)
    ) {
      throw failure('proof-invalid');
    }

    await verifyImmutableAndOpaqueDocument(currentDocument, registry, trust, scope);
    const base: ProofBase = {
      tuple: previousTupleOfLink(journalCandidate.currentMutationLink),
      headDigest: journalCandidate.previousHeadDigest,
      authorizationStateDigest:
        journalCandidate.currentMutationLink.commitment
          .previousAuthorizationStateDigest,
    };
    verifyCandidatePosition(currentDocument, base);
    const parsedProof = parseProofForPosition(proof, base, currentDocument, trust);
    if (parsedProof === undefined) throw failure('proof-invalid');

    accessSecret =
      input.access.kind === 'recipient'
        ? copySecret(input.access.recipientEncryptionPrivateKey, 32)
        : copySecret(input.access.databaseRootKey, 32);
    const proofAccess: ProofAccess =
      input.access.kind === 'recipient'
        ? {
            kind: 'recipient',
            scope,
            recipientEncryptionPrivateKey: accessSecret,
          }
        : { kind: 'database-authority-recovery', databaseRootKey: accessSecret };
    const verifiedProof = await verifyMutationProof(
      parsedProof,
      base,
      currentDocument,
      registry,
      trust,
      proofAccess,
    );

    const opened =
      input.access.kind === 'recipient'
        ? await openCurrentManifest(
            currentDocument,
            registry,
            trust,
            scope,
            now,
            accessSecret,
            verifiedProof.lastWriter,
          )
        : await openCurrentManifestForDatabaseAuthorityRecovery(
            currentDocument,
            registry,
            trust,
            accessSecret,
          );
    vaultRootKey = opened.vaultRootKey;
    if (
      verifiedProof.endingAuthorizationManifest.authorizationStateDigest !==
        opened.manifest.authorizationStateDigest ||
      canonicalJson(authorizationCore(verifiedProof.endingAuthorizationManifest)) !==
        canonicalJson(authorizationCore(opened.manifest)) ||
      canonicalJson(verifiedProof.lastLink) !==
        canonicalJson(currentDocument.currentMutationLink)
    ) {
      throw failure('proof-invalid');
    }
    await verifyDiscoveryRecords(
      currentDocument.discoveryRecords,
      verifiedProof.lastWriter,
      registry,
    );
    if (Date.parse(now) < Date.parse(currentDocument.createdAt)) {
      throw failure('trust-mismatch');
    }
    decryptedPayload = await decryptCollaborationEnvelope(
      currentDocument.encryptedPayload,
      vaultRootKey,
      expectedAad(
        tupleOfDocument(currentDocument),
        currentDocument.databaseId,
        currentDocument.vaultId,
        'vault-payload',
      ),
    );

    const anchors = verifiedProof.steps.map((step, index) =>
      journalSuccessorAnchor(
        step,
        scope,
        journalCandidateAnchor,
        index === verifiedProof.steps.length - 1
          ? currentDocument.updatedAt
          : undefined,
      ),
    );
    const firstAnchor = anchors[0];
    if (
      firstAnchor === undefined ||
      canonicalJson(firstAnchor) !== canonicalJson(journalCandidateAnchor)
    ) {
      throw failure('proof-invalid');
    }
    const authorityAnchors = verifiedProof.steps.map((step, index) =>
      journalSuccessorAuthorityAnchor(
        step,
        journalCandidateAnchor,
        index === verifiedProof.steps.length - 1
          ? currentDocument.updatedAt
          : undefined,
      ),
    );
    return { currentDocument, anchors, authorityAnchors };
  } catch (error) {
    throw mapFailure(error, 'invalid-input');
  } finally {
    zeroize(accessSecret);
    zeroize(vaultRootKey);
    zeroize(decryptedPayload);
  }
}

async function verifyOpenAndPersist(
  input: CommonOpenInput,
  trust: TrustContext,
  anchorMode: 'create' | 'transition',
): Promise<OpenedCollaborativeVaultState> {
  let vaultRootKey: VaultRootKey | undefined;
  let decryptedPayload: Uint8Array | undefined;
  let trustedAnchor: RecipientRollbackAnchor | undefined;
  try {
    const scope = parseScope(input.scope);
    const now = parseNow(input.now);
    const document = collaborativeVaultDocumentSchema.parse(input.document);
    const registry = collaborationDatabaseDeviceRegistrySchema.parse(
      input.authoritativeDeviceRegistry,
    );

    await verifyImmutableAndOpaqueDocument(document, registry, trust, scope);
    let base: ProofBase;
    if (anchorMode === 'create') {
      base = proofBaseFromReceipt(requireReceipt(trust), document);
    } else {
      try {
        trustedAnchor = await readRecipientRollbackAnchor(
          input.rollbackAnchorPath,
          input.deviceProtectionSecret,
          { expectedScope: scope },
        );
      } catch (error) {
        throw mapFailure(error, 'trust-required');
      }
      verifyAnchorTrust(trustedAnchor, scope, trust, document);
      base = proofBaseFromAnchor(trustedAnchor);
    }

    verifyCandidatePosition(document, base);
    const proof = parseProofForPosition(input.mutationProof, base, document, trust);
    const verifiedProof =
      proof === undefined
        ? undefined
        : await verifyMutationProof(proof, base, document, registry, trust, {
            kind: 'recipient',
            scope,
            recipientEncryptionPrivateKey: input.recipientEncryptionPrivateKey,
          });

    const currentWriter =
      verifiedProof?.lastWriter ??
      requirePinnedWriterForLink(trust, document.currentMutationLink, registry);
    if (verifiedProof === undefined) {
      await verifyCurrentLinkCryptography(
        document.currentMutationLink,
        currentWriter,
        registry,
        trust,
      );
    }

    const opened = await openCurrentManifest(
      document,
      registry,
      trust,
      scope,
      now,
      input.recipientEncryptionPrivateKey,
      currentWriter,
    );
    vaultRootKey = opened.vaultRootKey;

    if (base.tuple.documentRevision === document.documentRevision) {
      verifyExactBasePlaintextBindings(
        base,
        document,
        opened.membershipDigest,
        opened.policyDigest,
      );
    }
    if (verifiedProof !== undefined) {
      if (
        verifiedProof.endingAuthorizationManifest.authorizationStateDigest !==
          opened.manifest.authorizationStateDigest ||
        canonicalJson(authorizationCore(verifiedProof.endingAuthorizationManifest)) !==
          canonicalJson(authorizationCore(opened.manifest)) ||
        canonicalJson(verifiedProof.lastLink) !==
          canonicalJson(document.currentMutationLink)
      ) {
        throw failure('proof-invalid');
      }
    } else {
      await verifyPinnedTipLink(
        document,
        opened.manifest,
        registry,
        trust,
        now,
        currentWriter,
      );
    }

    if (
      trust.receipt !== undefined &&
      base.tuple.documentRevision === document.documentRevision
    ) {
      verifyReceiptAgainstManifest(
        trust.receipt,
        requireCheckpoint(trust),
        opened.manifest,
        document.discoveryRecords,
        registry,
        trust,
        document.currentMutationLink,
      );
    }

    decryptedPayload = await decryptCollaborationEnvelope(
      document.encryptedPayload,
      vaultRootKey,
      expectedAad(
        tupleOfDocument(document),
        document.databaseId,
        document.vaultId,
        'vault-payload',
      ),
    );

    const nextAnchor = recipientRollbackAnchorFromCollaborativeVaultDocument(
      document,
      scope,
      {
        membershipDigest: opened.membershipDigest,
        policyDigest: opened.policyDigest,
        finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
          document.currentMutationLink,
        ),
      },
    );
    try {
      if (anchorMode === 'create') {
        await createRecipientRollbackAnchor(
          input.rollbackAnchorPath,
          input.deviceProtectionSecret,
          nextAnchor,
        );
      } else {
        if (trustedAnchor === undefined) throw failure('anchor-persistence-failed');
        const chainVerification =
          nextAnchor.documentRevision > trustedAnchor.documentRevision
            ? { kind: 'verified-chain' as const, from: trustedAnchor, to: nextAnchor }
            : undefined;
        await transitionRecipientRollbackAnchor(
          input.rollbackAnchorPath,
          input.deviceProtectionSecret,
          nextAnchor,
          (lockedAnchor) => {
            if (canonicalJson(lockedAnchor) !== canonicalJson(trustedAnchor)) {
              throw failure('rollback');
            }
            return { nextAnchor, result: undefined };
          },
          chainVerification === undefined
            ? { expectedScope: scope }
            : { expectedScope: scope, chainVerification },
        );
      }
    } catch (error) {
      throw mapFailure(error, 'anchor-persistence-failed');
    }

    const result: OpenedCollaborativeVaultState = {
      document,
      manifest: opened.manifest,
      recipientMembership: opened.recipientMembership,
      recipientDevice: opened.recipientDevice,
      vaultRootKey,
      decryptedPayload,
    };
    vaultRootKey = undefined;
    decryptedPayload = undefined;
    return result;
  } catch (error) {
    zeroize(vaultRootKey);
    zeroize(decryptedPayload);
    throw mapFailure(error, 'invalid-input');
  }
}

async function verifyCurrentLinkCryptography(
  link: CollaborationFinalizedMutationLink,
  writer: DeviceCertificate,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<void> {
  const commitment = link.commitment;
  if (
    writer.principalId !== commitment.writerPrincipalId ||
    writer.deviceId !== commitment.writerDeviceId
  ) {
    throw failure('trust-mismatch');
  }
  requireFinalizationTime(link);
  requireNotDenied(registry, writer, 'writer-inactive');
  if (!(await verifyFinalizedMutationLink(link, writer.signingPublicKey))) {
    throw failure('signature-invalid');
  }
  if (commitment.operationType === 'ordinary-write') return;

  const transition = requireAuthorizationTransition(link);
  if (transition.transitionSignature.signerKind === 'database-authority') {
    if (
      transition.operationType !== 'recover-owner' ||
      transition.transitionSignature.authorityEpoch !==
        trust.delegation.authorityEpoch ||
      transition.transitionSignature.authoritySigningKeyFingerprint !==
        trust.delegation.authoritySigningKeyFingerprint ||
      !(await verifyAuthorizationTransitionAuthority(
        transition,
        trust.delegation.authoritySigningPublicKey,
      ))
    ) {
      throw failure('signature-invalid');
    }
    return;
  }

  const signer = requirePinnedDevice(
    trust,
    transition.transitionSignature.signerPrincipalId,
    transition.transitionSignature.signerDeviceId,
  );
  requireUsableDeviceAt(signer, commitment.timestamp, 'writer-inactive');
  requireNotDenied(registry, signer, 'writer-inactive');
  if (
    !(await verifyAuthorizationTransitionOwner(transition, signer.signingPublicKey))
  ) {
    throw failure('signature-invalid');
  }
}

async function trustFromEnrollment(
  receiptInput: unknown,
  checkpointInput: unknown,
  additionalIdentities: readonly unknown[],
  scope: ParsedScope,
  now: Timestamp,
): Promise<TrustContext> {
  const receipt = enrollmentReceiptSchema.parse(receiptInput);
  const checkpoint = collaborationAuthorizationCheckpointSchema.parse(checkpointInput);
  if (
    receipt.databaseId !== scope.databaseId ||
    receipt.vaultId !== scope.vaultId ||
    receipt.recipientPrincipalId !== scope.principalId ||
    receipt.recipientDeviceId !== scope.deviceId
  ) {
    throw failure('trust-mismatch');
  }
  requireTimeInside(now, receipt.issuedAt, receipt.expiresAt, 'trust-expired');
  const delegation = await verifyDelegation(receipt.authorityDelegation);
  const delegationDigest = computeAuthorityDelegationDigest(delegation);
  if (
    delegationDigest !== receipt.authorityDelegationDigest ||
    delegation.databaseId !== receipt.databaseId ||
    delegation.vaultId !== receipt.vaultId ||
    delegation.authorityEpoch !== receipt.authorityEpoch
  ) {
    throw failure('trust-mismatch');
  }

  const ownerFingerprint = computePublicKeyFingerprint(
    receipt.ownerRootSigningPublicKey,
    'ed25519',
  );
  if (
    ownerFingerprint !== receipt.ownerPrincipalFingerprint ||
    receipt.ownerDeviceCertificate.principalId !== receipt.ownerPrincipalId
  ) {
    throw failure('trust-mismatch');
  }
  await verifyDeviceCertificate(
    receipt.ownerDeviceCertificate,
    receipt.ownerRootSigningPublicKey,
  );
  requireUsableDeviceAt(
    receipt.ownerDeviceCertificate,
    receipt.issuedAt,
    'trust-mismatch',
  );
  if (
    !(await verifyEnrollmentReceipt(
      receipt,
      receipt.ownerDeviceCertificate.signingPublicKey,
    ))
  ) {
    throw failure('signature-invalid');
  }

  const recipient = await verifyPublicIdentity(receipt.recipientPublicIdentity, now);
  if (recipient.fingerprint !== receipt.recipientPrincipalFingerprint) {
    throw failure('trust-mismatch');
  }
  const deviceFingerprints = [...receipt.recipientPublicIdentity.devices]
    .sort((left, right) => left.deviceId.localeCompare(right.deviceId))
    .map((device) => computeDeviceCertificateFingerprint(device));
  if (!sameStrings(deviceFingerprints, receipt.recipientDeviceFingerprints)) {
    throw failure('trust-mismatch');
  }
  const recipientDevice = recipient.pinnedDevices.get(scope.deviceId);
  if (recipientDevice === undefined) throw failure('trust-mismatch');
  requireUsableDeviceAt(recipientDevice, now, 'trust-expired');
  if (
    receipt.discoveryTag !==
    computeDiscoveryTag(receipt.databaseId, receipt.recipientPrincipalFingerprint)
  ) {
    throw failure('trust-mismatch');
  }

  const principals = new Map<string, TrustedPrincipal>();
  addTrustedPrincipal(principals, recipient);
  addTrustedPrincipal(principals, {
    principalId: receipt.ownerPrincipalId,
    fingerprint: receipt.ownerPrincipalFingerprint,
    rootSigningPublicKey: receipt.ownerRootSigningPublicKey,
    pinnedDevices: new Map([
      [receipt.ownerDeviceCertificate.deviceId, receipt.ownerDeviceCertificate],
    ]),
  });
  for (const identity of additionalIdentities) {
    addTrustedPrincipal(principals, await verifyPublicIdentity(identity, now));
  }
  await verifyCheckpointForReceipt(checkpoint, receipt);
  return { delegation, delegationDigest, principals, receipt, checkpoint };
}

async function trustFromPinnedMaterial(
  pinned: CollaborativeVaultPinnedTrust,
  now: Timestamp,
  requirePrincipal: boolean,
): Promise<TrustContext> {
  const delegation = await verifyDelegation(pinned.authorityDelegation);
  const principals = new Map<string, TrustedPrincipal>();
  for (const identity of pinned.principalPublicIdentities) {
    addTrustedPrincipal(principals, await verifyPublicIdentity(identity, now));
  }
  if (requirePrincipal && principals.size === 0) throw failure('trust-required');
  return {
    delegation,
    delegationDigest: computeAuthorityDelegationDigest(delegation),
    principals,
  };
}

async function verifyDelegation(
  input: unknown,
): Promise<CollaborationAuthorityDelegation> {
  const delegation = collaborationAuthorityDelegationSchema.parse(input);
  if (
    computePublicKeyFingerprint(delegation.authoritySigningPublicKey, 'ed25519') !==
      delegation.authoritySigningKeyFingerprint ||
    computePublicKeyFingerprint(delegation.authorityRecoveryPublicKey, 'x25519') !==
      delegation.authorityRecoveryKeyFingerprint ||
    !(await verifyAuthorityDelegation(delegation, delegation.authoritySigningPublicKey))
  ) {
    throw failure('signature-invalid');
  }
  return delegation;
}

async function verifyPublicIdentity(
  input: unknown,
  now: Timestamp,
): Promise<TrustedPrincipal> {
  const identity = publicIdentityExportSchema.parse(input);
  if (
    identity.expiresAt !== undefined &&
    Date.parse(now) >= Date.parse(identity.expiresAt)
  ) {
    throw failure('trust-expired');
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
    throw failure('signature-invalid');
  }
  const devices = new Map<string, DeviceCertificate>();
  for (const device of identity.devices) {
    await verifyDeviceCertificate(device, identity.rootSigningPublicKey);
    devices.set(device.deviceId, device);
  }
  return {
    principalId: identity.principalId,
    fingerprint: computePublicKeyFingerprint(identity.rootSigningPublicKey, 'ed25519'),
    rootSigningPublicKey: identity.rootSigningPublicKey,
    pinnedDevices: devices,
  };
}

async function verifyCheckpointForReceipt(
  checkpoint: CollaborationAuthorizationCheckpoint,
  receipt: EnrollmentReceipt,
): Promise<void> {
  if (
    checkpoint.databaseId !== receipt.databaseId ||
    checkpoint.vaultId !== receipt.vaultId ||
    checkpoint.authorityDelegationDigest !== receipt.authorityDelegationDigest ||
    checkpoint.checkpointDigest !== receipt.authorizationCheckpointDigest ||
    checkpoint.headDigest !== receipt.headDigest ||
    checkpoint.authorizationStateDigest !== receipt.authorizationStateDigest ||
    checkpoint.finalizedMutationLinkDigest !== receipt.finalizedMutationLinkDigest ||
    checkpoint.signerPrincipalId !== receipt.ownerPrincipalId ||
    checkpoint.signerDeviceId !== receipt.ownerDeviceCertificate.deviceId ||
    Date.parse(checkpoint.createdAt) > Date.parse(receipt.issuedAt) ||
    Date.parse(receipt.authorityDelegation.issuedAt) > Date.parse(receipt.issuedAt) ||
    canonicalJson(checkpoint.tuple) !== canonicalJson(tupleOfReceipt(receipt)) ||
    !(await verifyAuthorizationCheckpoint(
      checkpoint,
      receipt.ownerDeviceCertificate.signingPublicKey,
    ))
  ) {
    throw failure('trust-mismatch');
  }
}

async function verifyImmutableAndOpaqueDocument(
  document: CollaborativeVaultDocument,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  scope: Readonly<{ databaseId: string; vaultId: string }>,
): Promise<void> {
  if (
    document.databaseId !== scope.databaseId ||
    document.vaultId !== scope.vaultId ||
    document.databaseId !== trust.delegation.databaseId ||
    document.vaultId !== trust.delegation.vaultId ||
    document.authorityEpoch !== trust.delegation.authorityEpoch ||
    document.authorityDelegationDigest !== trust.delegationDigest ||
    canonicalJson(document.authorityDelegation) !== canonicalJson(trust.delegation) ||
    computeAuthorityDelegationDigest(document.authorityDelegation) !==
      document.authorityDelegationDigest
  ) {
    throw failure('trust-mismatch');
  }
  await verifyRegistry(registry, document, trust);
  verifyCurrentDeviceFence(document, registry);
  verifyOpaqueDocumentDigests(document);
  const link = document.currentMutationLink;
  if (
    computeMutationHead(link.commitment) !== document.headDigest ||
    link.resultingHeadDigest !== document.headDigest
  ) {
    throw failure('digest-invalid');
  }
}

async function verifyRegistry(
  registry: CollaborationDatabaseDeviceRegistry,
  document: CollaborativeVaultDocument,
  trust: TrustContext,
): Promise<void> {
  await verifyRegistrySnapshot(
    registry,
    document.databaseId,
    document.authorityEpoch,
    document.databaseDeviceGeneration,
    document.databaseDeviceRegistryDigest,
    trust,
  );
}

async function verifyRegistrySnapshot(
  registry: CollaborationDatabaseDeviceRegistry,
  databaseId: string,
  authorityEpoch: number,
  generation: number,
  registryDigest: Sha256Digest,
  trust: TrustContext,
): Promise<void> {
  if (
    registry.databaseId !== databaseId ||
    registry.authorityEpoch !== authorityEpoch ||
    registry.authorityEpoch !== trust.delegation.authorityEpoch ||
    registry.generation !== generation ||
    registry.registryDigest !== registryDigest ||
    registry.authorityFingerprint !== trust.delegation.authoritySigningKeyFingerprint ||
    computeDeviceRegistryDigest(registry) !== registry.registryDigest ||
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.deviceRegistrySignature,
      registry,
      collaborationDatabaseDeviceRegistrySchema,
      'authoritySignature',
      trust.delegation.authoritySigningPublicKey,
    ))
  ) {
    throw failure('signature-invalid');
  }
}

function verifyCurrentDeviceFence(
  document: CollaborativeVaultDocument,
  registry: CollaborationDatabaseDeviceRegistry,
): void {
  const result = evaluateDeviceFence({
    vault: tupleOfDocument(document),
    authoritativeRegistry: registry,
  });
  if (result.status === 'current') return;
  if (result.status === 'rekey-required') throw failure('rekey-required');
  if (result.status === 'future-generation') throw failure('device-future');
  throw failure('trust-mismatch');
}

function verifyOpaqueDocumentDigests(document: CollaborativeVaultDocument): void {
  const payloadMetadata = collaborationAadMetadataSchema.parse(
    withoutMetadataDigest(document.encryptedPayload.aad),
  );
  const membershipMetadata = collaborationAadMetadataSchema.parse(
    withoutMetadataDigest(document.encryptedMembershipManifest.aad),
  );
  if (
    computeAadMetadataDigest(payloadMetadata) !==
      document.encryptedPayload.aad.metadataDigest ||
    computeAadMetadataDigest(membershipMetadata) !==
      document.encryptedMembershipManifest.aad.metadataDigest ||
    computeEncryptedPayloadDigest(document.encryptedPayload) !==
      document.encryptedPayloadDigest ||
    computeEncryptedMembershipDigest(document.encryptedMembershipManifest) !==
      document.encryptedMembershipDigest ||
    computeMutationHead(document.currentMutationLink.commitment) !== document.headDigest
  ) {
    throw failure('digest-invalid');
  }
}

function proofBaseFromReceipt(
  receipt: EnrollmentReceipt,
  document: CollaborativeVaultDocument,
): ProofBase {
  if (
    receipt.databaseId !== document.databaseId ||
    receipt.vaultId !== document.vaultId ||
    receipt.authorityEpoch !== document.authorityEpoch
  ) {
    throw failure('trust-mismatch');
  }
  return {
    tuple: tupleOfReceipt(receipt),
    headDigest: receipt.headDigest,
    authorizationStateDigest: receipt.authorizationStateDigest,
    finalizedMutationLinkDigest: receipt.finalizedMutationLinkDigest,
  };
}

function verifyAnchorTrust(
  anchor: RecipientRollbackAnchor,
  scope: ParsedScope,
  trust: TrustContext,
  document: CollaborativeVaultDocument,
): void {
  if (
    anchor.authorityEpoch !== trust.delegation.authorityEpoch ||
    anchor.authorityDelegationDigest !== trust.delegationDigest ||
    anchor.databaseId !== scope.databaseId ||
    anchor.vaultId !== scope.vaultId ||
    anchor.principalId !== scope.principalId ||
    anchor.deviceId !== scope.deviceId ||
    anchor.databaseId !== document.databaseId ||
    anchor.vaultId !== document.vaultId
  ) {
    throw failure('trust-mismatch');
  }
}

function authorityAnchorScope(
  trust: TrustContext,
): CollaborationAuthorityRollbackAnchorScope {
  return {
    databaseId: trust.delegation.databaseId,
    vaultId: trust.delegation.vaultId,
    authorityEpoch: trust.delegation.authorityEpoch,
    authorityDelegationDigest: trust.delegationDigest,
  };
}

function verifyAuthorityAnchorTrust(
  anchor: CollaborationAuthorityRollbackAnchor,
  scope: CollaborationAuthorityRollbackAnchorScope,
  trust: TrustContext,
  document: CollaborativeVaultDocument,
): void {
  if (
    anchor.databaseId !== scope.databaseId ||
    anchor.vaultId !== scope.vaultId ||
    anchor.authorityEpoch !== scope.authorityEpoch ||
    anchor.authorityDelegationDigest !== scope.authorityDelegationDigest ||
    anchor.authorityEpoch !== trust.delegation.authorityEpoch ||
    anchor.authorityDelegationDigest !== trust.delegationDigest ||
    anchor.databaseId !== document.databaseId ||
    anchor.vaultId !== document.vaultId
  ) {
    throw failure('trust-mismatch');
  }
}

function proofBaseFromAnchor(anchor: RecipientRollbackAnchor): ProofBase {
  return {
    tuple: collaborationRevisionTupleSchema.parse({
      authorityEpoch: anchor.authorityEpoch,
      documentRevision: anchor.documentRevision,
      membershipRevision: anchor.membershipRevision,
      policyRevision: anchor.policyRevision,
      keyEpoch: anchor.keyEpoch,
      databaseDeviceGeneration: anchor.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: anchor.databaseDeviceRegistryDigest,
      authorizationStateDigest: anchor.authorizationStateDigest,
    }),
    headDigest: anchor.headDigest,
    authorizationStateDigest: anchor.authorizationStateDigest,
    finalizedMutationLinkDigest: anchor.finalizedMutationLinkDigest,
    membershipDigest: anchor.membershipDigest,
    policyDigest: anchor.policyDigest,
    encryptedPayloadDigest: anchor.encryptedPayloadDigest,
  };
}

function proofBaseFromAuthorityAnchor(
  anchor: CollaborationAuthorityRollbackAnchor,
): ProofBase {
  return {
    tuple: collaborationRevisionTupleSchema.parse({
      authorityEpoch: anchor.authorityEpoch,
      documentRevision: anchor.documentRevision,
      membershipRevision: anchor.membershipRevision,
      policyRevision: anchor.policyRevision,
      keyEpoch: anchor.keyEpoch,
      databaseDeviceGeneration: anchor.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: anchor.databaseDeviceRegistryDigest,
      authorizationStateDigest: anchor.authorizationStateDigest,
    }),
    headDigest: anchor.headDigest,
    authorizationStateDigest: anchor.authorizationStateDigest,
    finalizedMutationLinkDigest: anchor.finalizedMutationLinkDigest,
    membershipDigest: anchor.membershipDigest,
    policyDigest: anchor.policyDigest,
    encryptedPayloadDigest: anchor.encryptedPayloadDigest,
  };
}

function verifyCandidatePosition(
  document: CollaborativeVaultDocument,
  base: ProofBase,
): void {
  if (document.documentRevision < base.tuple.documentRevision) {
    throw failure('rollback');
  }
  if (document.documentRevision !== base.tuple.documentRevision) return;
  const linkDigest = computeFinalizedMutationLinkDigest(document.currentMutationLink);
  if (
    document.headDigest !== base.headDigest ||
    document.authorizationStateDigest !== base.authorizationStateDigest ||
    (base.finalizedMutationLinkDigest !== undefined &&
      linkDigest !== base.finalizedMutationLinkDigest) ||
    canonicalJson(tupleOfDocument(document)) !== canonicalJson(base.tuple)
  ) {
    throw failure('fork');
  }
  if (
    base.encryptedPayloadDigest !== undefined &&
    document.encryptedPayloadDigest !== base.encryptedPayloadDigest
  ) {
    throw failure('fork');
  }
}

function parseProofForPosition(
  input: unknown,
  base: ProofBase,
  document: CollaborativeVaultDocument,
  trust: TrustContext,
): CollaborationMutationProof | undefined {
  if (document.documentRevision === base.tuple.documentRevision) {
    if (input !== undefined) throw failure('proof-invalid');
    return undefined;
  }
  if (input === undefined) throw failure('proof-required');
  const proof = collaborationMutationProofSchema.parse(input);
  if (
    proof.databaseId !== document.databaseId ||
    proof.vaultId !== document.vaultId ||
    proof.authorityDelegationDigest !== trust.delegationDigest ||
    proof.fromDocumentRevision !== base.tuple.documentRevision ||
    proof.fromHeadDigest !== base.headDigest ||
    proof.toDocumentRevision !== document.documentRevision ||
    proof.toHeadDigest !== document.headDigest
  ) {
    throw failure('proof-invalid');
  }
  return proof;
}

async function verifyMutationProof(
  proof: CollaborationMutationProof,
  base: ProofBase,
  document: CollaborativeVaultDocument,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  access: ProofAccess,
): Promise<VerifiedProof> {
  await verifyProofRegistryChain(proof, registry, trust);
  const starting = await openAuthorizationWitness(
    proof.startingAuthorizationWitness,
    registry,
    trust,
    access,
    { kind: 'starting' },
  );
  verifyStartingWitness(
    proof.startingAuthorizationWitness,
    starting,
    base,
    access.kind === 'database-authority-recovery',
  );
  if (trust.receipt !== undefined) {
    verifyReceiptAgainstManifest(
      trust.receipt,
      requireCheckpoint(trust),
      starting.manifest,
      starting.discoveryRecords,
      registry,
      trust,
    );
  }

  let priorManifest = starting.manifest;
  let priorRegistry = starting.databaseDeviceRegistry;
  let runningTuple = base.tuple;
  let runningHead = base.headDigest;
  let lastLink: CollaborationFinalizedMutationLink | undefined;
  let lastWriter: DeviceCertificate | undefined;
  const steps: VerifiedProofStep[] = [];
  for (const entry of proof.entries) {
    const link = collaborationFinalizedMutationLinkSchema.parse(entry.link);
    const commitment = link.commitment;
    if (
      commitment.previousHeadDigest !== runningHead ||
      canonicalJson(previousTupleOfLink(link)) !== canonicalJson(runningTuple) ||
      computeMutationHead(commitment) !== link.resultingHeadDigest ||
      link.authorityDelegationDigest !== trust.delegationDigest
    ) {
      throw failure('proof-invalid');
    }
    requireFinalizationTime(link);
    const nextTuple = nextTupleOfLink(link);
    let writer: DeviceCertificate;
    if (commitment.operationType === 'recover-owner') {
      const authorizationTransition = requireAuthorizationTransition(link);
      await verifyAdministrativeTransitionSignature(
        authorizationTransition,
        priorManifest,
        priorRegistry,
        trust,
        commitment.timestamp,
      );
      if (entry.authorizationWitness === undefined) throw failure('proof-invalid');
      const nextState = await openAuthorizationWitness(
        entry.authorizationWitness,
        registry,
        trust,
        access,
        { kind: 'recovery-link-bound' },
      );
      if (
        nextState.manifest.authorizationStateDigest !==
          commitment.authorizationStateDigest ||
        entry.authorizationWitness.finalizedMutationLinkDigest !==
          computeFinalizedMutationLinkDigest(link)
      ) {
        throw failure('proof-invalid');
      }
      const administrativeState = await validateAdministrativeStateChange(
        link,
        priorManifest,
        nextState.manifest,
        priorRegistry,
        nextState.databaseDeviceRegistry,
        trust,
      );
      writer = requireRecoveryWriter(
        nextState.manifest,
        link,
        priorRegistry,
        nextState.databaseDeviceRegistry,
        trust,
        administrativeState,
      );
      assertRegistryAdvanceWriterFence(
        link,
        priorRegistry,
        nextState.databaseDeviceRegistry,
        writer,
      );
      await verifyManifestEnvelopeSignaturesByWriter(nextState.manifest, writer);
      if (!(await verifyFinalizedMutationLink(link, writer.signingPublicKey))) {
        throw failure('signature-invalid');
      }
      await verifyDiscoveryRecords(
        entry.authorizationWitness.discoveryRecords,
        writer,
        nextState.databaseDeviceRegistry,
      );
      priorManifest = nextState.manifest;
      priorRegistry = nextState.databaseDeviceRegistry;
    } else {
      writer = requireAuthorizedWriter(priorManifest, link, priorRegistry, trust);
      if (!(await verifyFinalizedMutationLink(link, writer.signingPublicKey))) {
        throw failure('signature-invalid');
      }
      if (commitment.operationType === 'ordinary-write') {
        const transition = validateRevisionTransition({
          operationType: commitment.operationType,
          prior: runningTuple,
          next: nextTuple,
        });
        if (!transition.valid || entry.authorizationWitness !== undefined) {
          throw failure('proof-invalid');
        }
        try {
          priorManifest = advanceCollaborativeManifestAcrossOrdinaryLink(
            priorManifest,
            link,
          );
        } catch {
          throw failure('proof-invalid');
        }
      } else {
        const authorizationTransition = requireAuthorizationTransition(link);
        await verifyAdministrativeTransitionSignature(
          authorizationTransition,
          priorManifest,
          priorRegistry,
          trust,
          commitment.timestamp,
        );
        if (entry.authorizationWitness === undefined) throw failure('proof-invalid');
        const nextState = await openAuthorizationWitness(
          entry.authorizationWitness,
          registry,
          trust,
          access,
          { kind: 'link-bound', writer, writerRegistry: priorRegistry },
        );
        if (
          nextState.manifest.authorizationStateDigest !==
            commitment.authorizationStateDigest ||
          entry.authorizationWitness.finalizedMutationLinkDigest !==
            computeFinalizedMutationLinkDigest(link)
        ) {
          throw failure('proof-invalid');
        }
        await validateAdministrativeStateChange(
          link,
          priorManifest,
          nextState.manifest,
          priorRegistry,
          nextState.databaseDeviceRegistry,
          trust,
        );
        assertRegistryAdvanceWriterFence(
          link,
          priorRegistry,
          nextState.databaseDeviceRegistry,
          writer,
        );
        priorManifest = nextState.manifest;
        priorRegistry = nextState.databaseDeviceRegistry;
      }
    }
    runningTuple = nextTuple;
    runningHead = link.resultingHeadDigest;
    lastLink = link;
    lastWriter = writer;
    steps.push({ link, manifest: priorManifest });
  }
  if (
    lastLink === undefined ||
    lastWriter === undefined ||
    runningHead !== document.headDigest ||
    canonicalJson(runningTuple) !== canonicalJson(tupleOfDocument(document)) ||
    canonicalJson(lastLink) !== canonicalJson(document.currentMutationLink)
  ) {
    throw failure('proof-invalid');
  }
  return { endingAuthorizationManifest: priorManifest, lastLink, lastWriter, steps };
}

async function verifyProofRegistryChain(
  proof: CollaborationMutationProof,
  currentRegistry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<void> {
  let previous = proof.startingAuthorizationWitness.databaseDeviceRegistry;
  await verifyRegistrySnapshot(
    previous,
    proof.databaseId,
    proof.startingAuthorizationWitness.tuple.authorityEpoch,
    proof.startingAuthorizationWitness.tuple.databaseDeviceGeneration,
    proof.startingAuthorizationWitness.tuple.databaseDeviceRegistryDigest,
    trust,
  );
  for (const entry of proof.entries) {
    if (entry.authorizationWitness === undefined) continue;
    const witness = entry.authorizationWitness;
    const next = witness.databaseDeviceRegistry;
    await verifyRegistrySnapshot(
      next,
      witness.databaseId,
      witness.tuple.authorityEpoch,
      witness.tuple.databaseDeviceGeneration,
      witness.tuple.databaseDeviceRegistryDigest,
      trust,
    );
    verifyRegistryProgression(previous, next);
    previous = next;
  }
  verifyRegistryProgression(previous, currentRegistry);
}

function verifyRegistryProgression(
  previous: CollaborationDatabaseDeviceRegistry,
  next: CollaborationDatabaseDeviceRegistry,
): void {
  if (
    previous.databaseId !== next.databaseId ||
    previous.authorityEpoch !== next.authorityEpoch ||
    Date.parse(next.updatedAt) < Date.parse(previous.updatedAt)
  ) {
    throw failure('proof-invalid');
  }
  if (next.generation === previous.generation) {
    if (next.registryDigest !== previous.registryDigest) {
      throw failure('proof-invalid');
    }
  } else if (
    next.generation !== previous.generation + 1 ||
    next.previousRegistryDigest !== previous.registryDigest
  ) {
    throw failure('proof-invalid');
  }
  for (const denial of previous.deniedDevices) {
    if (
      !next.deniedDevices.some(
        (candidate) => canonicalJson(candidate) === canonicalJson(denial),
      )
    ) {
      throw failure('proof-invalid');
    }
  }
}

function verifyStartingWitness(
  witness: CollaborationAuthorizationWitness,
  opened: VerifiedManifest,
  base: ProofBase,
  requireExactGenesis: boolean,
): void {
  const tuple = witness.tuple;
  if (
    (requireExactGenesis
      ? canonicalJson(tuple) !== canonicalJson(base.tuple)
      : tuple.documentRevision > base.tuple.documentRevision) ||
    tuple.authorityEpoch !== base.tuple.authorityEpoch ||
    tuple.membershipRevision !== base.tuple.membershipRevision ||
    tuple.policyRevision !== base.tuple.policyRevision ||
    tuple.keyEpoch !== base.tuple.keyEpoch ||
    tuple.databaseDeviceGeneration !== base.tuple.databaseDeviceGeneration ||
    tuple.databaseDeviceRegistryDigest !== base.tuple.databaseDeviceRegistryDigest ||
    tuple.authorizationStateDigest !== base.authorizationStateDigest ||
    opened.manifest.authorizationStateDigest !== base.authorizationStateDigest ||
    (requireExactGenesis &&
      (witness.previousHeadDigest !== COLLABORATION_GENESIS_HEAD_DIGEST ||
        witness.headDigest !== base.headDigest)) ||
    (base.membershipDigest !== undefined &&
      opened.membershipDigest !== base.membershipDigest) ||
    (base.policyDigest !== undefined && opened.policyDigest !== base.policyDigest)
  ) {
    throw failure('proof-invalid');
  }
  if (
    tuple.documentRevision === base.tuple.documentRevision &&
    (witness.headDigest !== base.headDigest ||
      (base.finalizedMutationLinkDigest !== undefined &&
        witness.finalizedMutationLinkDigest !== base.finalizedMutationLinkDigest))
  ) {
    throw failure('proof-invalid');
  }
}

async function openAuthorizationWitness(
  witnessInput: CollaborationAuthorizationWitness,
  currentRegistry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  access: ProofAccess,
  verification:
    | Readonly<{ kind: 'starting' }>
    | Readonly<{ kind: 'recovery-link-bound' }>
    | Readonly<{
        kind: 'link-bound';
        writer: DeviceCertificate;
        writerRegistry: CollaborationDatabaseDeviceRegistry;
      }>,
): Promise<VerifiedManifest> {
  const witness = collaborationAuthorizationWitnessSchema.parse(witnessInput);
  if (
    witness.databaseId !== trust.delegation.databaseId ||
    witness.vaultId !== trust.delegation.vaultId ||
    witness.authorityDelegationDigest !== trust.delegationDigest ||
    witness.databaseAuthorityRecoveryEnvelope.authorityRecoveryKeyFingerprint !==
      trust.delegation.authorityRecoveryKeyFingerprint ||
    computeEncryptedMembershipDigest(witness.encryptedMembershipManifest) !==
      witness.encryptedMembershipDigest
  ) {
    throw failure('proof-invalid');
  }
  const witnessRegistry = witness.databaseDeviceRegistry;
  await verifyRegistrySnapshot(
    witnessRegistry,
    witness.databaseId,
    witness.tuple.authorityEpoch,
    witness.tuple.databaseDeviceGeneration,
    witness.tuple.databaseDeviceRegistryDigest,
    trust,
  );

  let vaultRootKey: VaultRootKey | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    let discovery: CollaborationDiscoveryRecord | undefined;
    let envelope: CollaborationKeyEnvelope | undefined;
    let recipientPinned: DeviceCertificate | undefined;
    if (access.kind === 'recipient') {
      recipientPinned = requirePinnedRecipientDevice(trust, access.scope);
      requireNotDenied(currentRegistry, recipientPinned, 'recipient-inactive');
      discovery = selectRecipientDiscovery(
        witness.discoveryRecords,
        witness.tuple,
        access.scope,
        trust,
      );
      if (verification.kind === 'starting') {
        verifyStartingDiscoveryTransport(witness.discoveryRecords, discovery, trust);
      }
      envelope = discovery.encryptedMemberKeyEnvelope;
      verifyRecipientEnvelopeBindings(
        envelope,
        witness.tuple,
        access.scope,
        recipientPinned,
      );
      vaultRootKey = await openVaultRootKeyForDevice(
        envelope.sealedVaultRootKey,
        recipientPinned.encryptionPublicKey,
        access.recipientEncryptionPrivateKey,
      );
    } else {
      vaultRootKey = await openCollaborationVaultRootForDatabaseAuthority(
        witness.databaseAuthorityRecoveryEnvelope.sealedVaultRootKey,
        access.databaseRootKey,
        witness.databaseId,
        witness.tuple.authorityEpoch,
        trust.delegation.authorityRecoveryPublicKey,
      );
    }
    plaintext = await decryptCollaborationEnvelope(
      witness.encryptedMembershipManifest,
      vaultRootKey,
      expectedAad(
        witness.tuple,
        witness.databaseId,
        witness.vaultId,
        'membership-manifest',
      ),
    );
    const manifest = parseManifestPlaintext(plaintext);
    requireExactDatabaseAuthorityRecoveryEnvelope(witness, manifest);
    const verified = await verifyManifest(
      manifest,
      {
        tuple: witness.tuple,
        previousHeadDigest: witness.previousHeadDigest,
        encryptedMembershipDigest: witness.encryptedMembershipDigest,
        encryptedEnvelopesDigest: witness.encryptedEnvelopesDigest,
        policyDigest: witness.policyDigest,
      },
      witness.discoveryRecords,
      witnessRegistry,
      trust,
    );
    if (
      access.kind === 'recipient' &&
      discovery !== undefined &&
      envelope !== undefined &&
      recipientPinned !== undefined
    ) {
      verifyRecipientInManifest(
        manifest,
        discovery,
        envelope,
        access.scope,
        recipientPinned,
      );
    } else if (verification.kind === 'starting') {
      const genesisWriter = requireDelegationGenesisWriter(
        manifest,
        witnessRegistry,
        trust,
      );
      await verifyManifestEnvelopeSignaturesByWriter(manifest, genesisWriter);
      await verifyDiscoveryRecords(
        witness.discoveryRecords,
        genesisWriter,
        witnessRegistry,
      );
    }
    if (verification.kind === 'link-bound') {
      await verifyDiscoveryRecords(
        witness.discoveryRecords,
        verification.writer,
        verification.writerRegistry,
      );
    }
    return verified;
  } catch (error) {
    throw mapFailure(error, 'decryption-failed');
  } finally {
    zeroize(vaultRootKey);
    zeroize(plaintext);
  }
}

async function openCurrentManifest(
  document: CollaborativeVaultDocument,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  scope: ParsedScope,
  now: Timestamp,
  recipientEncryptionPrivateKey: DeviceEncryptionPrivateKey | Uint8Array,
  discoveryWriter: DeviceCertificate,
): Promise<OpenedCurrent> {
  const recipientPinned = requirePinnedRecipientDevice(trust, scope);
  requireUsableDeviceAt(recipientPinned, now, 'recipient-inactive');
  requireNotDenied(registry, recipientPinned, 'recipient-inactive');
  const tuple = tupleOfDocument(document);
  const discovery = selectRecipientDiscovery(
    document.discoveryRecords,
    tuple,
    scope,
    trust,
  );
  await verifyDiscoveryRecords(document.discoveryRecords, discoveryWriter, registry);
  if (trust.receipt?.documentRevision === document.documentRevision) {
    verifyReceiptDiscoveryTransport(trust.receipt, discovery);
  }
  const envelope = discovery.encryptedMemberKeyEnvelope;
  verifyRecipientEnvelopeBindings(envelope, tuple, scope, recipientPinned);

  let vaultRootKey: VaultRootKey | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    vaultRootKey = await openVaultRootKeyForDevice(
      envelope.sealedVaultRootKey,
      recipientPinned.encryptionPublicKey,
      recipientEncryptionPrivateKey,
    );
    plaintext = await decryptCollaborationEnvelope(
      document.encryptedMembershipManifest,
      vaultRootKey,
      expectedAad(tuple, document.databaseId, document.vaultId, 'membership-manifest'),
    );
    const manifest = parseManifestPlaintext(plaintext);
    requireExactDatabaseAuthorityRecoveryEnvelope(document, manifest);
    const verified = await verifyManifest(
      manifest,
      {
        tuple,
        previousHeadDigest: document.previousHeadDigest,
        encryptedMembershipDigest: document.encryptedMembershipDigest,
        encryptedEnvelopesDigest: document.encryptedEnvelopesDigest,
        policyDigest: document.policyDigest,
      },
      document.discoveryRecords,
      registry,
      trust,
    );
    const recipient = verifyRecipientInManifest(
      manifest,
      discovery,
      envelope,
      scope,
      recipientPinned,
    );
    const result: OpenedCurrent = {
      ...verified,
      discovery,
      envelope,
      recipientMembership: recipient.membership,
      recipientDevice: recipient.device,
      vaultRootKey,
    };
    vaultRootKey = undefined;
    return result;
  } catch (error) {
    throw mapFailure(error, 'decryption-failed');
  } finally {
    zeroize(vaultRootKey);
    zeroize(plaintext);
  }
}

async function openCurrentManifestForDatabaseAuthorityRecovery(
  document: CollaborativeVaultDocument,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  databaseRootKey: DatabaseRootKey | Uint8Array,
): Promise<VerifiedManifest & Readonly<{ vaultRootKey: VaultRootKey }>> {
  let vaultRootKey: VaultRootKey | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    if (
      document.databaseAuthorityRecoveryEnvelope.authorityRecoveryKeyFingerprint !==
      trust.delegation.authorityRecoveryKeyFingerprint
    ) {
      throw failure('trust-mismatch');
    }
    vaultRootKey = await openCollaborationVaultRootForDatabaseAuthority(
      document.databaseAuthorityRecoveryEnvelope.sealedVaultRootKey,
      databaseRootKey,
      document.databaseId,
      document.authorityEpoch,
      trust.delegation.authorityRecoveryPublicKey,
    );
    plaintext = await decryptCollaborationEnvelope(
      document.encryptedMembershipManifest,
      vaultRootKey,
      expectedAad(
        tupleOfDocument(document),
        document.databaseId,
        document.vaultId,
        'membership-manifest',
      ),
    );
    const manifest = parseManifestPlaintext(plaintext);
    requireExactDatabaseAuthorityRecoveryEnvelope(document, manifest);
    const verified = await verifyManifest(
      manifest,
      {
        tuple: tupleOfDocument(document),
        previousHeadDigest: document.previousHeadDigest,
        encryptedMembershipDigest: document.encryptedMembershipDigest,
        encryptedEnvelopesDigest: document.encryptedEnvelopesDigest,
        policyDigest: document.policyDigest,
      },
      document.discoveryRecords,
      registry,
      trust,
    );
    const result = { ...verified, vaultRootKey };
    vaultRootKey = undefined;
    return result;
  } catch (error) {
    throw mapFailure(error, 'decryption-failed');
  } finally {
    zeroize(vaultRootKey);
    zeroize(plaintext);
  }
}

type ManifestExpectation = Readonly<{
  tuple: CollaborationRevisionTuple;
  previousHeadDigest: Sha256Digest;
  encryptedMembershipDigest: Sha256Digest;
  encryptedEnvelopesDigest: Sha256Digest;
  policyDigest: Sha256Digest;
}>;

async function verifyManifest(
  manifest: CollaborativeMembershipManifest,
  expected: ManifestExpectation,
  discoveryRecords: readonly CollaborationDiscoveryRecord[],
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<VerifiedManifest> {
  if (
    canonicalJson(tupleOfManifest(manifest)) !== canonicalJson(expected.tuple) ||
    manifest.previousHeadDigest !== expected.previousHeadDigest ||
    computeKeyEnvelopeSetDigest(manifest.keyEnvelopes) !==
      expected.encryptedEnvelopesDigest ||
    computePolicyDigest(manifest.policy) !== expected.policyDigest ||
    manifest.policy.policyDigest !== expected.policyDigest ||
    computeMembershipHistoryDigest(manifest.history) !==
      manifest.history.currentHistoryDigest
  ) {
    throw failure('digest-invalid');
  }
  const manifestDigest = computeMembershipManifestDigest(manifest);
  if (manifestDigest !== manifest.membershipDigest) {
    throw failure('digest-invalid');
  }
  const core = authorizationCore(manifest);
  if (
    computeAuthorizationStateDigest(core) !== manifest.authorizationStateDigest ||
    manifest.authorizationStateDigest !== expected.tuple.authorizationStateDigest
  ) {
    throw failure('digest-invalid');
  }
  const ownerInvariant = checkActiveOwnerInvariant({
    memberships: manifest.memberships,
    ownerPrincipalIds: manifest.ownerPrincipalIds,
  });
  if (!ownerInvariant.valid) throw failure('writer-unauthorized');

  await verifyManifestDeviceChains(manifest, trust);
  await verifyPolicySignature(manifest, registry, trust);
  await verifyHistorySignatures(manifest, registry, trust);
  await verifyManifestEnvelopeSignatures(manifest, registry);
  return {
    manifest,
    // Anchors pin logical membership, while the full self-digest above still
    // authenticates this exact revision/head-bound manifest.
    membershipDigest: computeMembershipStateDigest(core),
    // Policy artifact bytes/signature are verified above; anchors pin only
    // the stable logical policy state so registry re-signing is not a fork.
    policyDigest: computePolicyStateDigest(manifest.policy),
    discoveryRecords,
    databaseDeviceRegistry: registry,
  };
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

async function verifyManifestDeviceChains(
  manifest: CollaborativeMembershipManifest,
  trust: TrustContext,
): Promise<void> {
  for (const membership of manifest.memberships) {
    const fingerprint = computePublicKeyFingerprint(
      membership.rootSigningPublicKey,
      'ed25519',
    );
    if (fingerprint !== membership.principalFingerprint) {
      throw failure('trust-mismatch');
    }
    const pinned = trust.principals.get(membership.principalId);
    if (
      pinned !== undefined &&
      (pinned.fingerprint !== membership.principalFingerprint ||
        pinned.rootSigningPublicKey !== membership.rootSigningPublicKey)
    ) {
      throw failure('trust-mismatch');
    }
    for (const device of membership.devices) {
      await verifyDeviceCertificate(device, membership.rootSigningPublicKey);
      const pinnedDevice = pinned?.pinnedDevices.get(device.deviceId);
      if (
        pinnedDevice !== undefined &&
        (pinnedDevice.signingPublicKey !== device.signingPublicKey ||
          pinnedDevice.encryptionPublicKey !== device.encryptionPublicKey ||
          pinnedDevice.deviceGeneration !== device.deviceGeneration)
      ) {
        throw failure('trust-mismatch');
      }
    }
  }
}

async function verifyDeviceCertificate(
  certificate: DeviceCertificate,
  rootSigningPublicKey: string,
): Promise<void> {
  if (
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.deviceCertificateSignature,
      certificate,
      deviceCertificateSchema,
      'rootSignature',
      rootSigningPublicKey,
    ))
  ) {
    throw failure('signature-invalid');
  }
}

async function verifyPolicySignature(
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<void> {
  const policy = collaborationPolicyStateSchema.parse(manifest.policy);
  const device = requireManifestDevice(
    manifest,
    policy.changedByPrincipalId,
    policy.changedByDeviceId,
  );
  requirePinnedKeyIfPresent(trust, device);
  requireNotDenied(registry, device, 'writer-inactive');
  if (
    !(await verifyCollaborationRecord(
      COLLABORATION_DOMAINS.policySignature,
      policy,
      collaborationPolicyStateSchema,
      'signature',
      device.signingPublicKey,
    ))
  ) {
    throw failure('signature-invalid');
  }
}

async function verifyHistorySignatures(
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<void> {
  // These cumulative signatures authenticate actions at their historical
  // registry positions. A later deny fence governs new actions and access; it
  // must not erase already-authenticated history.
  for (const event of manifest.history.events) {
    const membership = manifest.memberships.find(
      (candidate) => candidate.principalId === event.actorPrincipalId,
    );
    const device = membership?.devices.find(
      (candidate) => candidate.deviceId === event.actorDeviceId,
    );
    if (membership === undefined || device === undefined) {
      throw failure('writer-unauthorized');
    }
    requirePinnedKeyIfPresent(trust, device);
    requireHistoricalSignerAt(event.timestamp, membership, device, registry);
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistorySignature,
        event,
        membershipHistoryEventSchema,
        'signature',
        device.signingPublicKey,
      ))
    ) {
      throw failure('signature-invalid');
    }
  }
  for (const checkpoint of manifest.history.checkpoints) {
    const membership = manifest.memberships.find(
      (candidate) => candidate.principalId === checkpoint.signerPrincipalId,
    );
    const device = membership?.devices.find(
      (candidate) => candidate.deviceId === checkpoint.signerDeviceId,
    );
    if (membership === undefined || device === undefined) {
      throw failure('writer-unauthorized');
    }
    requirePinnedKeyIfPresent(trust, device);
    requireHistoricalSignerAt(checkpoint.createdAt, membership, device, registry);
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
        checkpoint,
        membershipHistoryCheckpointSchema,
        'signature',
        device.signingPublicKey,
      ))
    ) {
      throw failure('signature-invalid');
    }
  }
}

function requireHistoricalSignerAt(
  signedTime: Timestamp,
  membership: CollaborationMembership,
  device: DeviceCertificate,
  registry: CollaborationDatabaseDeviceRegistry,
): void {
  const signedAt = Date.parse(signedTime);
  const deviceStateChangedAt = Date.parse(device.stateChangedAt);
  const signedBeforeCreation =
    signedAt < Date.parse(membership.createdAt) ||
    signedAt < Date.parse(device.createdAt) ||
    (device.state === 'active' && signedAt < deviceStateChangedAt);
  const signedAfterEligibility =
    (membership.removedAt !== undefined &&
      signedAt >= Date.parse(membership.removedAt)) ||
    (device.state !== 'active' && signedAt >= deviceStateChangedAt) ||
    (device.expiresAt !== undefined && signedAt >= Date.parse(device.expiresAt)) ||
    isDeniedAt(registry, device, signedAt);
  if (signedBeforeCreation || signedAfterEligibility) {
    throw failure('writer-inactive');
  }
}

async function verifyManifestEnvelopeSignatures(
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
): Promise<void> {
  const ownerDevices = activeOwnerDevices(manifest).filter(
    (device) => !isDenied(registry, device),
  );
  if (ownerDevices.length === 0) throw failure('writer-inactive');
  for (const envelope of manifest.keyEnvelopes) {
    const expectedDigest =
      'membershipId' in envelope
        ? computeKeyEnvelopeDigest(envelope)
        : computeAuthorityRecoveryEnvelopeDigest(envelope);
    if (expectedDigest !== envelope.envelopeDigest) throw failure('digest-invalid');
    let verified = false;
    for (const ownerDevice of ownerDevices) {
      const signatureValid =
        'membershipId' in envelope
          ? await verifyCollaborationRecord(
              COLLABORATION_DOMAINS.keyEnvelopeSignature,
              envelope,
              collaborationKeyEnvelopeSchema,
              'ownerSignature',
              ownerDevice.signingPublicKey,
            )
          : await verifyCollaborationRecord(
              COLLABORATION_DOMAINS.keyEnvelopeSignature,
              envelope,
              databaseAuthorityRecoveryEnvelopeSchema,
              'ownerSignature',
              ownerDevice.signingPublicKey,
            );
      if (signatureValid) {
        verified = true;
        break;
      }
    }
    if (!verified) throw failure('signature-invalid');
  }
}

async function verifyManifestEnvelopeSignaturesByWriter(
  manifest: CollaborativeMembershipManifest,
  writer: DeviceCertificate,
): Promise<void> {
  for (const envelope of manifest.keyEnvelopes) {
    if (
      !('membershipId' in envelope) &&
      (envelope.sealedByPrincipalId !== writer.principalId ||
        envelope.sealedByDeviceId !== writer.deviceId)
    ) {
      throw failure('writer-unauthorized');
    }
    const signatureValid =
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
    if (!signatureValid) throw failure('signature-invalid');
  }
}

async function verifyDiscoveryRecords(
  records: readonly CollaborationDiscoveryRecord[],
  writer: DeviceCertificate,
  registry: CollaborationDatabaseDeviceRegistry,
): Promise<void> {
  requireNotDenied(registry, writer, 'writer-inactive');
  for (const record of records) {
    if (
      record.signerPrincipalId !== writer.principalId ||
      record.signerDeviceId !== writer.deviceId ||
      computeDiscoveryRecordDigest(record) !== record.discoveryRecordDigest
    ) {
      throw failure('digest-invalid');
    }
    if (!(await verifyDiscoveryRecord(record, writer.signingPublicKey))) {
      throw failure('signature-invalid');
    }
  }
}

/**
 * A bare proof starting witness has no corresponding link in the proof shape, so
 * its claimed writer is deliberately not treated as authenticated. Its selected
 * envelope is only key transport: the protected base tuple/core/digests are
 * checked after AEAD open. Receipt bootstrap additionally authenticates the
 * selected record digest before any key is opened.
 */
function verifyStartingDiscoveryTransport(
  records: readonly CollaborationDiscoveryRecord[],
  selected: CollaborationDiscoveryRecord,
  trust: TrustContext,
): void {
  for (const record of records) {
    if (computeDiscoveryRecordDigest(record) !== record.discoveryRecordDigest) {
      throw failure('digest-invalid');
    }
  }
  if (trust.receipt !== undefined) {
    verifyReceiptDiscoveryTransport(trust.receipt, selected);
  }
}

function verifyReceiptDiscoveryTransport(
  receipt: EnrollmentReceipt,
  discovery: CollaborationDiscoveryRecord,
): void {
  if (
    discovery.discoveryTag !== receipt.discoveryTag ||
    discovery.discoveryRecordDigest !== receipt.discoveryRecordDigest ||
    discovery.encryptedMemberKeyEnvelope.envelopeDigest !==
      receipt.memberKeyEnvelopeDigest
  ) {
    throw failure('trust-mismatch');
  }
}

function selectRecipientDiscovery(
  records: readonly CollaborationDiscoveryRecord[],
  tuple: CollaborationRevisionTuple,
  scope: ParsedScope,
  trust: TrustContext,
): CollaborationDiscoveryRecord {
  const principal = trust.principals.get(scope.principalId);
  if (principal === undefined) throw failure('trust-required');
  const discoveryTag = computeDiscoveryTag(scope.databaseId, principal.fingerprint);
  const matches = records.filter(
    (record) =>
      record.discoveryTag === discoveryTag &&
      record.encryptedMemberKeyEnvelope.principalId === scope.principalId &&
      record.encryptedMemberKeyEnvelope.deviceId === scope.deviceId,
  );
  const record = matches[0];
  if (
    matches.length !== 1 ||
    record?.membershipState !== 'active' ||
    record.databaseId !== scope.databaseId ||
    record.vaultId !== scope.vaultId ||
    record.authorityEpoch !== tuple.authorityEpoch ||
    record.databaseDeviceGeneration !== tuple.databaseDeviceGeneration ||
    record.databaseDeviceRegistryDigest !== tuple.databaseDeviceRegistryDigest ||
    record.membershipRevision !== tuple.membershipRevision ||
    record.keyEpoch !== tuple.keyEpoch ||
    record.authorizationStateDigest !== tuple.authorizationStateDigest
  ) {
    throw failure('recipient-inactive');
  }
  return record;
}

function verifyRecipientEnvelopeBindings(
  envelope: CollaborationKeyEnvelope,
  tuple: CollaborationRevisionTuple,
  scope: ParsedScope,
  recipientDevice: DeviceCertificate,
): void {
  if (
    envelope.databaseId !== scope.databaseId ||
    envelope.vaultId !== scope.vaultId ||
    envelope.principalId !== scope.principalId ||
    envelope.deviceId !== scope.deviceId ||
    envelope.authorityEpoch !== tuple.authorityEpoch ||
    envelope.membershipRevision !== tuple.membershipRevision ||
    envelope.keyEpoch !== tuple.keyEpoch ||
    envelope.databaseDeviceGeneration !== tuple.databaseDeviceGeneration ||
    envelope.databaseDeviceRegistryDigest !== tuple.databaseDeviceRegistryDigest ||
    envelope.recipientEncryptionKeyFingerprint !==
      computePublicKeyFingerprint(recipientDevice.encryptionPublicKey, 'x25519') ||
    envelope.envelopeDigest !== computeKeyEnvelopeDigest(envelope)
  ) {
    throw failure('trust-mismatch');
  }
}

function verifyRecipientInManifest(
  manifest: CollaborativeMembershipManifest,
  discovery: CollaborationDiscoveryRecord,
  envelope: CollaborationKeyEnvelope,
  scope: ParsedScope,
  pinnedDevice: DeviceCertificate,
): Readonly<{ membership: CollaborationMembership; device: DeviceCertificate }> {
  const membership = manifest.memberships.find(
    (candidate) =>
      candidate.principalId === scope.principalId && candidate.state === 'active',
  );
  const device = membership?.devices.find(
    (candidate) =>
      candidate.deviceId === scope.deviceId && candidate.state === 'active',
  );
  if (
    membership === undefined ||
    device === undefined ||
    membership.membershipId !== discovery.membershipId ||
    membership.membershipId !== envelope.membershipId ||
    membership.principalFingerprint !==
      computePublicKeyFingerprint(membership.rootSigningPublicKey, 'ed25519') ||
    device.signingPublicKey !== pinnedDevice.signingPublicKey ||
    device.encryptionPublicKey !== pinnedDevice.encryptionPublicKey ||
    device.deviceGeneration !== pinnedDevice.deviceGeneration
  ) {
    throw failure('recipient-inactive');
  }
  return { membership, device };
}

function requireAuthorizedWriter(
  priorManifest: CollaborativeMembershipManifest,
  link: CollaborationFinalizedMutationLink,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): DeviceCertificate {
  const commitment = link.commitment;
  const membership = priorManifest.memberships.find(
    (candidate) =>
      candidate.principalId === commitment.writerPrincipalId &&
      candidate.state === 'active',
  );
  const device = membership?.devices.find(
    (candidate) =>
      candidate.deviceId === commitment.writerDeviceId && candidate.state === 'active',
  );
  if (membership === undefined || device === undefined) {
    throw failure('writer-inactive');
  }
  requirePinnedKeyIfPresent(trust, device);
  requireUsableDeviceAt(device, commitment.timestamp, 'writer-inactive');
  requireNotDenied(registry, device, 'writer-inactive');
  const authorization = authorizeOperation({
    operationType: commitment.operationType,
    membership,
    device,
    authoritativeRegistry: registry,
    deviceSigningKeyFingerprint: computePublicKeyFingerprint(
      device.signingPublicKey,
      'ed25519',
    ),
  });
  if (!authorization.authorized) throw failure('writer-unauthorized');
  return device;
}

async function verifyAdministrativeTransitionSignature(
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
    throw failure('proof-invalid');
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
      throw failure('signature-invalid');
    }
    return;
  }
  const owner = priorManifest.memberships.find(
    (membership) =>
      membership.principalId === signature.signerPrincipalId &&
      membership.state === 'active' &&
      membership.role === 'owner',
  );
  const device = owner?.devices.find(
    (candidate) =>
      candidate.deviceId === signature.signerDeviceId && candidate.state === 'active',
  );
  if (device === undefined) throw failure('writer-unauthorized');
  requirePinnedKeyIfPresent(trust, device);
  requireUsableDeviceAt(device, committedAt, 'writer-inactive');
  requireNotDenied(registry, device, 'writer-inactive');
  if (
    !(await verifyAuthorizationTransitionOwner(transition, device.signingPublicKey))
  ) {
    throw failure('signature-invalid');
  }
}

async function validateAdministrativeStateChange(
  link: CollaborationFinalizedMutationLink,
  priorManifest: CollaborativeMembershipManifest,
  nextManifest: CollaborativeMembershipManifest,
  priorRegistry: CollaborationDatabaseDeviceRegistry,
  nextRegistry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<VerifiedCollaborativeAdministrativeManifestTransition> {
  const commitment = link.commitment;
  const transition = requireAuthorizationTransition(link);
  const prior = previousTupleOfLink(link);
  const next = nextTupleOfLink(link);
  let administrativeState: VerifiedCollaborativeAdministrativeManifestTransition;
  try {
    administrativeState = verifyCollaborativeAdministrativeManifestTransition({
      link,
      priorManifest,
      nextManifest,
    });
  } catch {
    throw failure('proof-invalid');
  }
  if (administrativeState.operationType === 'add-device') {
    const principalId = administrativeState.historyEvent.targetPrincipalId;
    const deviceId = administrativeState.historyEvent.targetDeviceId;
    if (principalId === undefined || deviceId === undefined) {
      throw failure('proof-invalid');
    }
    const addedDevice = requireManifestDevice(nextManifest, principalId, deviceId);
    requireUsableDeviceAt(addedDevice, commitment.timestamp, 'recipient-inactive');
    requireNotDenied(nextRegistry, addedDevice, 'recipient-inactive');
  }
  const revisionInput =
    next.databaseDeviceGeneration > prior.databaseDeviceGeneration
      ? {
          operationType: commitment.operationType,
          prior,
          next,
          decryptAccessChanged: administrativeState.decryptAccessChanged,
          authorizationTransitionDigest: transition.transitionDigest,
          authoritativeRegistry: nextRegistry,
        }
      : {
          operationType: commitment.operationType,
          prior,
          next,
          decryptAccessChanged: administrativeState.decryptAccessChanged,
          authorizationTransitionDigest: transition.transitionDigest,
        };
  if (!validateRevisionTransition(revisionInput).valid) {
    throw failure('proof-invalid');
  }

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
  administrativeState: VerifiedCollaborativeAdministrativeManifestTransition,
): DeviceCertificate {
  if (
    administrativeState.operationType !== 'recover-owner' ||
    administrativeState.historyEvent.eventType !== 'owner-recovery' ||
    administrativeState.historyEvent.targetPrincipalId !==
      link.commitment.writerPrincipalId
  ) {
    throw failure('writer-unauthorized');
  }
  const writer = requireActiveDevice(
    nextManifest,
    link.commitment.writerPrincipalId,
    link.commitment.writerDeviceId,
    'owner',
  );
  requirePinnedKeyIfPresent(trust, writer);
  requireUsableDeviceAt(writer, link.commitment.timestamp, 'writer-inactive');
  requireNotDenied(priorRegistry, writer, 'writer-inactive');
  requireNotDenied(nextRegistry, writer, 'writer-inactive');
  return writer;
}

function assertRegistryAdvanceWriterFence(
  link: CollaborationFinalizedMutationLink,
  priorRegistry: CollaborationDatabaseDeviceRegistry,
  nextRegistry: CollaborationDatabaseDeviceRegistry,
  writer: DeviceCertificate,
): void {
  if (nextRegistry.generation <= priorRegistry.generation) return;
  requireNotDenied(priorRegistry, writer, 'writer-inactive');
  requireNotDenied(nextRegistry, writer, 'writer-inactive');
  if (Date.parse(link.commitment.timestamp) < Date.parse(nextRegistry.updatedAt)) {
    throw failure('proof-invalid');
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
    if (intent?.recipientAcceptance === undefined) {
      throw failure('writer-unauthorized');
    }
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
    requirePinnedKeyIfPresent(trust, initiator);
    requirePinnedKeyIfPresent(trust, recipient);
    requireNotDenied(priorRegistry, initiator, 'writer-inactive');
    requireNotDenied(nextRegistry, recipient, 'recipient-inactive');
    if (
      !(await verifyTransferIntent(intent, initiator.signingPublicKey)) ||
      !(await verifyOwnershipTransferAcceptance(
        intent.recipientAcceptance,
        recipient.signingPublicKey,
      ))
    ) {
      throw failure('signature-invalid');
    }
    const result = validateOwnershipTransfer({
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
    if (!result.valid || !result.complete) throw failure('writer-unauthorized');
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
  requirePinnedKeyIfPresent(trust, requester);
  requireNotDenied(priorRegistry, requester, 'writer-inactive');
  if (!(await verifyApprovalRequest(request, requester.signingPublicKey))) {
    throw failure('signature-invalid');
  }
  const verifiedApprovals = [];
  for (const evidence of request.approvals) {
    const approver = requireActiveDevice(
      priorManifest,
      evidence.approverPrincipalId,
      evidence.approverDeviceId,
      'owner',
    );
    requirePinnedKeyIfPresent(trust, approver);
    requireNotDenied(priorRegistry, approver, 'writer-inactive');
    if (!(await verifyApprovalEvidence(evidence, approver.signingPublicKey))) {
      throw failure('signature-invalid');
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
    throw failure('writer-unauthorized');
  }
}

async function verifyPinnedTipLink(
  document: CollaborativeVaultDocument,
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  now: Timestamp,
  writer: DeviceCertificate,
): Promise<void> {
  const link = document.currentMutationLink;
  requireFinalizationTime(link);
  if (document.documentRevision === 1) {
    await verifyGenesisTip(document, manifest, registry, trust);
    return;
  }
  const commitment = link.commitment;
  if (
    writer.principalId !== commitment.writerPrincipalId ||
    writer.deviceId !== commitment.writerDeviceId
  ) {
    throw failure('trust-mismatch');
  }
  if (commitment.operationType === 'ordinary-write') {
    const authorizedWriter = requireAuthorizedWriter(manifest, link, registry, trust);
    if (
      authorizedWriter.signingPublicKey !== writer.signingPublicKey ||
      authorizedWriter.deviceGeneration !== writer.deviceGeneration
    ) {
      throw failure('trust-mismatch');
    }
    if (!(await verifyFinalizedMutationLink(link, writer.signingPublicKey))) {
      throw failure('signature-invalid');
    }
    return;
  }

  // Receipt/anchor pins this exact administrative head. Its prior state is not
  // reconstructed; the link and transition still require exact cryptographic signers.
  requireNotDenied(registry, writer, 'writer-inactive');
  if (!(await verifyFinalizedMutationLink(link, writer.signingPublicKey))) {
    throw failure('signature-invalid');
  }
  const transition = requireAuthorizationTransition(link);
  if (transition.transitionSignature.signerKind === 'database-authority') {
    if (
      transition.operationType !== 'recover-owner' ||
      transition.transitionSignature.authorityEpoch !==
        trust.delegation.authorityEpoch ||
      transition.transitionSignature.authoritySigningKeyFingerprint !==
        trust.delegation.authoritySigningKeyFingerprint ||
      !(await verifyAuthorizationTransitionAuthority(
        transition,
        trust.delegation.authoritySigningPublicKey,
      ))
    ) {
      throw failure('signature-invalid');
    }
    const replacement = requireActiveDevice(
      manifest,
      commitment.writerPrincipalId,
      commitment.writerDeviceId,
      'owner',
    );
    requirePinnedKeyIfPresent(trust, replacement);
    requireUsableDeviceAt(replacement, commitment.timestamp, 'writer-inactive');
    requireNotDenied(registry, replacement, 'writer-inactive');
    const recoveryEvent = manifest.history.events.find(
      (event) => event.operationId === commitment.operationId,
    );
    if (
      recoveryEvent?.eventType !== 'owner-recovery' ||
      recoveryEvent.actorPrincipalId !== replacement.principalId ||
      recoveryEvent.actorDeviceId !== replacement.deviceId ||
      recoveryEvent.targetPrincipalId !== replacement.principalId
    ) {
      throw failure('writer-unauthorized');
    }
    await verifyManifestEnvelopeSignaturesByWriter(manifest, replacement);
  } else {
    const signer = requirePinnedDevice(
      trust,
      transition.transitionSignature.signerPrincipalId,
      transition.transitionSignature.signerDeviceId,
    );
    requireUsableDeviceAt(signer, commitment.timestamp, 'writer-inactive');
    requireNotDenied(registry, signer, 'writer-inactive');
    if (
      !(await verifyAuthorizationTransitionOwner(transition, signer.signingPublicKey))
    ) {
      throw failure('signature-invalid');
    }
  }
  if (Date.parse(now) < Date.parse(document.createdAt)) {
    throw failure('trust-mismatch');
  }
}

async function verifyGenesisTip(
  document: CollaborativeVaultDocument,
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): Promise<void> {
  const delegation = trust.delegation;
  const link = document.currentMutationLink;
  const commitment = link.commitment;
  const transition = requireAuthorizationTransition(link);
  const owner = manifest.memberships.find(
    (membership) =>
      membership.principalId === delegation.initialOwnerPrincipalId &&
      membership.state === 'active' &&
      membership.role === 'owner',
  );
  const device = owner?.devices.find(
    (candidate) =>
      candidate.deviceId === delegation.initialOwnerDeviceId &&
      candidate.state === 'active',
  );
  if (
    owner === undefined ||
    device === undefined ||
    commitment.operationType !== 'genesis-migration' ||
    commitment.operationId !== delegation.genesisOperationId ||
    commitment.writerPrincipalId !== owner.principalId ||
    commitment.writerDeviceId !== device.deviceId ||
    commitment.previousDocumentRevision !== 0 ||
    commitment.previousMembershipRevision !== 0 ||
    commitment.previousPolicyRevision !== 0 ||
    commitment.previousKeyEpoch !== 1 ||
    commitment.previousHeadDigest !== COLLABORATION_GENESIS_HEAD_DIGEST ||
    document.previousHeadDigest !== COLLABORATION_GENESIS_HEAD_DIGEST ||
    document.headDigest !== delegation.genesisHeadDigest ||
    canonicalJson(tupleOfDocument(document)) !==
      canonicalJson(delegation.genesisTuple) ||
    computePublicKeyFingerprint(owner.rootSigningPublicKey, 'ed25519') !==
      delegation.initialOwnerRootKeyFingerprint ||
    computePublicKeyFingerprint(device.signingPublicKey, 'ed25519') !==
      delegation.initialOwnerDeviceSigningKeyFingerprint ||
    computePublicKeyFingerprint(device.encryptionPublicKey, 'x25519') !==
      delegation.initialOwnerDeviceEncryptionKeyFingerprint ||
    transition.transitionSignature.signerKind !== 'owner-device' ||
    transition.transitionSignature.signerPrincipalId !== owner.principalId ||
    transition.transitionSignature.signerDeviceId !== device.deviceId
  ) {
    throw failure('writer-unauthorized');
  }
  requireNotDenied(registry, device, 'writer-inactive');
  const revision = validateRevisionTransition({
    operationType: 'genesis-migration',
    prior: transition.previousTuple,
    next: transition.nextTuple,
    authorizationTransitionDigest: transition.transitionDigest,
  });
  if (
    !revision.valid ||
    !(await verifyAuthorizationTransitionOwner(transition, device.signingPublicKey)) ||
    !(await verifyFinalizedMutationLink(link, device.signingPublicKey))
  ) {
    throw failure('signature-invalid');
  }
  const event = manifest.history.events[0];
  if (
    event?.eventType !== 'genesis-created' ||
    event.operationId !== commitment.operationId ||
    event.actorPrincipalId !== owner.principalId ||
    event.actorDeviceId !== device.deviceId ||
    event.previousDocumentRevision !== 0 ||
    event.newDocumentRevision !== 1 ||
    event.previousMembershipRevision !== 0 ||
    event.newMembershipRevision !== 1 ||
    event.previousPolicyRevision !== 0 ||
    event.newPolicyRevision !== 1 ||
    event.previousAuthorizationStateDigest !==
      commitment.previousAuthorizationStateDigest ||
    event.newAuthorizationStateDigest !== commitment.authorizationStateDigest ||
    event.previousHeadDigest !== COLLABORATION_GENESIS_HEAD_DIGEST
  ) {
    throw failure('writer-unauthorized');
  }
}

function requireDelegationGenesisWriter(
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): DeviceCertificate {
  const delegation = trust.delegation;
  const owner = manifest.memberships.find(
    (membership) =>
      membership.principalId === delegation.initialOwnerPrincipalId &&
      membership.state === 'active' &&
      membership.role === 'owner',
  );
  const device = owner?.devices.find(
    (candidate) =>
      candidate.deviceId === delegation.initialOwnerDeviceId &&
      candidate.state === 'active',
  );
  if (
    owner === undefined ||
    device === undefined ||
    !sameStrings(manifest.ownerPrincipalIds, [owner.principalId]) ||
    computePublicKeyFingerprint(owner.rootSigningPublicKey, 'ed25519') !==
      delegation.initialOwnerRootKeyFingerprint ||
    computePublicKeyFingerprint(device.signingPublicKey, 'ed25519') !==
      delegation.initialOwnerDeviceSigningKeyFingerprint ||
    computePublicKeyFingerprint(device.encryptionPublicKey, 'x25519') !==
      delegation.initialOwnerDeviceEncryptionKeyFingerprint
  ) {
    throw failure('trust-mismatch');
  }
  requirePinnedKeyIfPresent(trust, device);
  requireNotDenied(registry, device, 'writer-inactive');
  return device;
}

function verifyReceiptAgainstManifest(
  receipt: EnrollmentReceipt,
  checkpoint: CollaborationAuthorizationCheckpoint,
  manifest: CollaborativeMembershipManifest,
  discoveryRecords: readonly CollaborationDiscoveryRecord[],
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
  link?: CollaborationFinalizedMutationLink,
): void {
  if (
    canonicalJson(tupleOfManifest(manifest)) !==
      canonicalJson(tupleOfReceipt(receipt)) ||
    manifest.authorizationStateDigest !== receipt.authorizationStateDigest
  ) {
    throw failure('trust-mismatch');
  }
  const owner = manifest.memberships.find(
    (membership) =>
      membership.principalId === receipt.ownerPrincipalId &&
      membership.role === 'owner' &&
      membership.state === 'active',
  );
  const ownerDevice = owner?.devices.find(
    (device) =>
      device.deviceId === receipt.ownerDeviceCertificate.deviceId &&
      device.state === 'active',
  );
  const recipient = manifest.memberships.find(
    (membership) =>
      membership.principalId === receipt.recipientPrincipalId &&
      membership.state === 'active',
  );
  const recipientDevice = recipient?.devices.find(
    (device) =>
      device.deviceId === receipt.recipientDeviceId && device.state === 'active',
  );
  if (
    owner === undefined ||
    ownerDevice === undefined ||
    recipient === undefined ||
    recipientDevice === undefined ||
    canonicalJson(ownerDevice) !== canonicalJson(receipt.ownerDeviceCertificate) ||
    recipient.membershipId !== receipt.membershipId ||
    recipient.role !== receipt.role ||
    recipient.principalFingerprint !== receipt.recipientPrincipalFingerprint ||
    checkpoint.signerPrincipalId !== owner.principalId ||
    checkpoint.signerDeviceId !== ownerDevice.deviceId
  ) {
    throw failure('trust-mismatch');
  }
  verifyReceiptOrigin(receipt, manifest, link);
  requireNotDenied(registry, ownerDevice, 'writer-inactive');
  requireNotDenied(registry, recipientDevice, 'recipient-inactive');
  const discovery = selectRecipientDiscovery(
    discoveryRecords,
    tupleOfManifest(manifest),
    {
      databaseId: receipt.databaseId,
      vaultId: receipt.vaultId,
      principalId: receipt.recipientPrincipalId,
      deviceId: receipt.recipientDeviceId,
    },
    trust,
  );
  if (
    discovery.discoveryRecordDigest !== receipt.discoveryRecordDigest ||
    discovery.encryptedMemberKeyEnvelope.envelopeDigest !==
      receipt.memberKeyEnvelopeDigest
  ) {
    throw failure('trust-mismatch');
  }
}

function verifyReceiptOrigin(
  receipt: EnrollmentReceipt,
  manifest: CollaborativeMembershipManifest,
  link: CollaborationFinalizedMutationLink | undefined,
): void {
  const matchingEvents = manifest.history.events.filter(
    (event) => event.newDocumentRevision === receipt.documentRevision,
  );
  const event = matchingEvents[0];
  const expectedEventType =
    receipt.operationType === 'add-member' ? 'member-added' : 'device-added';
  if (matchingEvents.length !== 1 || event === undefined) {
    throw failure('trust-mismatch');
  }
  if (
    event.eventType !== expectedEventType ||
    event.targetPrincipalId !== receipt.recipientPrincipalId ||
    event.targetDeviceId !==
      (receipt.operationType === 'add-device'
        ? receipt.recipientDeviceId
        : undefined) ||
    event.newMembershipRevision !== receipt.membershipRevision ||
    event.newPolicyRevision !== receipt.policyRevision ||
    event.newKeyEpoch !== receipt.keyEpoch ||
    event.newAuthorityEpoch !== receipt.authorityEpoch ||
    event.newDatabaseDeviceGeneration !== receipt.databaseDeviceGeneration ||
    event.newDatabaseDeviceRegistryDigest !== receipt.databaseDeviceRegistryDigest ||
    event.newAuthorizationStateDigest !== receipt.authorizationStateDigest ||
    Date.parse(event.timestamp) > Date.parse(receipt.issuedAt)
  ) {
    throw failure('trust-mismatch');
  }
  if (link === undefined) return;
  if (
    computeFinalizedMutationLinkDigest(link) !== receipt.finalizedMutationLinkDigest ||
    link.commitment.operationType !== receipt.operationType ||
    link.authorizationTransition?.operationType !== receipt.operationType ||
    link.commitment.operationId !== event.operationId ||
    link.resultingHeadDigest !== receipt.headDigest ||
    canonicalJson(nextTupleOfLink(link)) !== canonicalJson(tupleOfReceipt(receipt))
  ) {
    throw failure('trust-mismatch');
  }
}

function verifyExactBasePlaintextBindings(
  base: ProofBase,
  document: CollaborativeVaultDocument,
  membershipDigest: Sha256Digest,
  policyDigest: Sha256Digest,
): void {
  if (
    (base.membershipDigest !== undefined &&
      base.membershipDigest !== membershipDigest) ||
    (base.policyDigest !== undefined && base.policyDigest !== policyDigest) ||
    (base.encryptedPayloadDigest !== undefined &&
      base.encryptedPayloadDigest !== document.encryptedPayloadDigest)
  ) {
    throw failure('fork');
  }
}

function requireFinalizationTime(link: CollaborationFinalizedMutationLink): void {
  const commitment = link.commitment;
  if (
    Date.parse(link.finalizedAt) < Date.parse(commitment.timestamp) ||
    (commitment.expiresAt !== undefined &&
      Date.parse(link.finalizedAt) >= Date.parse(commitment.expiresAt))
  ) {
    throw failure('proof-invalid');
  }
}

function requireAuthorizationTransition(
  link: CollaborationFinalizedMutationLink,
): CollaborationAuthorizationTransition {
  const transition = link.authorizationTransition;
  if (
    transition === undefined ||
    transition.transitionDigest !== link.commitment.authorizationTransitionDigest ||
    computeAuthorizationTransitionDigest(transition) !== transition.transitionDigest
  ) {
    throw failure('proof-invalid');
  }
  return transition;
}

function requireActiveDevice(
  manifest: CollaborativeMembershipManifest,
  principalId: string,
  deviceId: string,
  requiredRole: CollaborationMembership['role'],
): DeviceCertificate {
  const membership = manifest.memberships.find(
    (candidate) =>
      candidate.principalId === principalId &&
      candidate.state === 'active' &&
      candidate.role === requiredRole,
  );
  const device = membership?.devices.find(
    (candidate) => candidate.deviceId === deviceId && candidate.state === 'active',
  );
  if (device === undefined) throw failure('writer-unauthorized');
  return device;
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
  if (device === undefined) throw failure('writer-inactive');
  return device;
}

function requirePinnedKeyIfPresent(
  trust: TrustContext,
  device: DeviceCertificate,
): void {
  const pinned = trust.principals
    .get(device.principalId)
    ?.pinnedDevices.get(device.deviceId);
  if (
    pinned !== undefined &&
    (pinned.deviceGeneration !== device.deviceGeneration ||
      pinned.signingPublicKey !== device.signingPublicKey ||
      pinned.encryptionPublicKey !== device.encryptionPublicKey)
  ) {
    throw failure('trust-mismatch');
  }
}

function requirePinnedDevice(
  trust: TrustContext,
  principalId: string,
  deviceId: string,
): DeviceCertificate {
  const device = trust.principals.get(principalId)?.pinnedDevices.get(deviceId);
  if (device === undefined) throw failure('trust-required');
  return device;
}

function requirePinnedWriterForLink(
  trust: TrustContext,
  link: CollaborationFinalizedMutationLink,
  registry: CollaborationDatabaseDeviceRegistry,
): DeviceCertificate {
  const writer = requirePinnedDevice(
    trust,
    link.commitment.writerPrincipalId,
    link.commitment.writerDeviceId,
  );
  requireUsableDeviceAt(writer, link.commitment.timestamp, 'writer-inactive');
  requireNotDenied(registry, writer, 'writer-inactive');
  return writer;
}

function requireManifestWriterForLink(
  manifest: CollaborativeMembershipManifest,
  link: CollaborationFinalizedMutationLink,
  registry: CollaborationDatabaseDeviceRegistry,
  trust: TrustContext,
): DeviceCertificate {
  const membership = manifest.memberships.find(
    (candidate) =>
      candidate.principalId === link.commitment.writerPrincipalId &&
      candidate.state === 'active',
  );
  const writer = membership?.devices.find(
    (candidate) =>
      candidate.deviceId === link.commitment.writerDeviceId &&
      candidate.state === 'active',
  );
  if (writer === undefined) throw failure('writer-unauthorized');
  requirePinnedKeyIfPresent(trust, writer);
  requireUsableDeviceAt(writer, link.commitment.timestamp, 'writer-inactive');
  requireNotDenied(registry, writer, 'writer-inactive');
  return writer;
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
  const signingFingerprint = computePublicKeyFingerprint(
    device.signingPublicKey,
    'ed25519',
  );
  return registry.deniedDevices.some(
    (denial) =>
      (denial.principalId === device.principalId &&
        denial.deviceId === device.deviceId) ||
      denial.signingKeyFingerprint === signingFingerprint,
  );
}

function isDeniedAt(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
  at: number,
): boolean {
  const signingFingerprint = computePublicKeyFingerprint(
    device.signingPublicKey,
    'ed25519',
  );
  return registry.deniedDevices.some(
    (denial) =>
      Date.parse(denial.deniedAt) <= at &&
      ((denial.principalId === device.principalId &&
        denial.deviceId === device.deviceId) ||
        denial.signingKeyFingerprint === signingFingerprint),
  );
}

function requireNotDenied(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
  kind: 'recipient-inactive' | 'writer-inactive',
): void {
  if (isDenied(registry, device)) throw failure(kind);
}

function requirePinnedRecipientDevice(
  trust: TrustContext,
  scope: ParsedScope,
): DeviceCertificate {
  const device = trust.principals
    .get(scope.principalId)
    ?.pinnedDevices.get(scope.deviceId);
  if (device === undefined) throw failure('trust-required');
  return device;
}

function parseManifestPlaintext(
  plaintext: Uint8Array,
): CollaborativeMembershipManifest {
  try {
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    return collaborativeMembershipManifestSchema.parse(JSON.parse(decoded));
  } catch {
    throw failure('decryption-failed');
  }
}

function expectedAad(
  tuple: CollaborationRevisionTuple,
  databaseId: ReturnType<typeof databaseIdSchema.parse>,
  vaultId: ReturnType<typeof vaultIdSchema.parse>,
  entityType: 'membership-manifest' | 'vault-payload',
): CollaborationAad {
  const metadata = collaborationAadMetadataSchema.parse({
    protocolVersion: 1,
    databaseId,
    vaultId,
    authorityEpoch: tuple.authorityEpoch,
    entityType,
    entityId: vaultId,
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

function tupleOfDocument(
  document: CollaborativeVaultDocument,
): CollaborationRevisionTuple {
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

function tupleOfReceipt(receipt: EnrollmentReceipt): CollaborationRevisionTuple {
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: receipt.authorityEpoch,
    documentRevision: receipt.documentRevision,
    membershipRevision: receipt.membershipRevision,
    policyRevision: receipt.policyRevision,
    keyEpoch: receipt.keyEpoch,
    databaseDeviceGeneration: receipt.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: receipt.databaseDeviceRegistryDigest,
    authorizationStateDigest: receipt.authorizationStateDigest,
  });
}

function previousTupleOfLink(
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

function nextTupleOfLink(
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

function journalSuccessorAnchor(
  step: VerifiedProofStep,
  scope: ParsedScope,
  candidateAnchor: RecipientRollbackAnchor,
  tipUpdatedAt: Timestamp | undefined,
): RecipientRollbackAnchor {
  const tuple = nextTupleOfLink(step.link);
  const core = authorizationCore(step.manifest);
  return recipientRollbackAnchorSchema.parse({
    format: candidateAnchor.format,
    protocolVersion: step.link.protocolVersion,
    databaseId: scope.databaseId,
    vaultId: scope.vaultId,
    principalId: scope.principalId,
    deviceId: scope.deviceId,
    authorityEpoch: tuple.authorityEpoch,
    authorityDelegationDigest: step.link.authorityDelegationDigest,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    membershipRevision: tuple.membershipRevision,
    membershipDigest: computeMembershipStateDigest(core),
    policyRevision: tuple.policyRevision,
    policyDigest: computePolicyStateDigest(step.manifest.policy),
    keyEpoch: tuple.keyEpoch,
    documentRevision: tuple.documentRevision,
    encryptedPayloadDigest: step.link.commitment.encryptedPayloadDigest,
    headDigest: step.link.resultingHeadDigest,
    authorizationStateDigest: tuple.authorizationStateDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(step.link),
    updatedAt:
      step.link.resultingHeadDigest === candidateAnchor.headDigest
        ? candidateAnchor.updatedAt
        : (tipUpdatedAt ?? step.link.finalizedAt),
  });
}

function journalSuccessorAuthorityAnchor(
  step: VerifiedProofStep,
  candidateAnchor: RecipientRollbackAnchor,
  tipUpdatedAt: Timestamp | undefined,
): CollaborationAuthorityRollbackAnchor {
  const tuple = nextTupleOfLink(step.link);
  const core = authorizationCore(step.manifest);
  return collaborationAuthorityRollbackAnchorSchema.parse({
    format: COLLABORATION_AUTHORITY_ROLLBACK_ANCHOR_FORMAT,
    protocolVersion: step.link.protocolVersion,
    databaseId: step.link.databaseId,
    vaultId: step.link.vaultId,
    authorityEpoch: tuple.authorityEpoch,
    authorityDelegationDigest: step.link.authorityDelegationDigest,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    membershipRevision: tuple.membershipRevision,
    membershipDigest: computeMembershipStateDigest(core),
    policyRevision: tuple.policyRevision,
    policyDigest: computePolicyStateDigest(step.manifest.policy),
    keyEpoch: tuple.keyEpoch,
    documentRevision: tuple.documentRevision,
    encryptedPayloadDigest: step.link.commitment.encryptedPayloadDigest,
    headDigest: step.link.resultingHeadDigest,
    authorizationStateDigest: tuple.authorizationStateDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(step.link),
    updatedAt:
      step.link.resultingHeadDigest === candidateAnchor.headDigest
        ? candidateAnchor.updatedAt
        : (tipUpdatedAt ?? step.link.finalizedAt),
  });
}

function withoutMetadataDigest(aad: CollaborationAad): Record<string, unknown> {
  const metadata = { ...aad };
  Reflect.deleteProperty(metadata, 'metadataDigest');
  return metadata;
}

function parseScope(scope: RecipientRollbackAnchorScope): ParsedScope {
  return {
    databaseId: databaseIdSchema.parse(scope.databaseId),
    vaultId: vaultIdSchema.parse(scope.vaultId),
    principalId: principalIdSchema.parse(scope.principalId),
    deviceId: deviceIdSchema.parse(scope.deviceId),
  };
}

function parseNow(now: Timestamp | undefined): Timestamp {
  return timestampSchema.parse(now ?? new Date().toISOString());
}

function copySecret(value: Uint8Array, exactBytes: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== exactBytes) {
    throw failure('invalid-input');
  }
  return Uint8Array.from(value);
}

function requireReceipt(trust: TrustContext): EnrollmentReceipt {
  if (trust.receipt === undefined) throw failure('trust-required');
  return trust.receipt;
}

function requireCheckpoint(trust: TrustContext): CollaborationAuthorizationCheckpoint {
  if (trust.checkpoint === undefined) throw failure('trust-required');
  return trust.checkpoint;
}

function requireUsableDeviceAt(
  device: DeviceCertificate,
  at: Timestamp,
  kind: CollaborationStateVerificationFailureKind,
): void {
  if (
    device.state !== 'active' ||
    Date.parse(at) < Date.parse(device.createdAt) ||
    Date.parse(at) < Date.parse(device.stateChangedAt) ||
    (device.expiresAt !== undefined && Date.parse(at) >= Date.parse(device.expiresAt))
  ) {
    throw failure(kind);
  }
}

function requireTimeInside(
  value: Timestamp,
  start: Timestamp,
  end: Timestamp,
  kind: CollaborationStateVerificationFailureKind,
): void {
  if (Date.parse(value) < Date.parse(start) || Date.parse(value) >= Date.parse(end)) {
    throw failure(kind);
  }
}

function addTrustedPrincipal(
  principals: Map<string, TrustedPrincipal>,
  principal: TrustedPrincipal,
): void {
  const existing = principals.get(principal.principalId);
  if (
    existing !== undefined &&
    (existing.fingerprint !== principal.fingerprint ||
      existing.rootSigningPublicKey !== principal.rootSigningPublicKey)
  ) {
    throw failure('trust-mismatch');
  }
  if (existing === undefined) {
    principals.set(principal.principalId, principal);
    return;
  }
  const devices = new Map(existing.pinnedDevices);
  for (const [deviceId, device] of principal.pinnedDevices) {
    const previous = devices.get(deviceId);
    if (previous !== undefined && canonicalJson(previous) !== canonicalJson(device)) {
      throw failure('trust-mismatch');
    }
    devices.set(deviceId, device);
  }
  principals.set(principal.principalId, { ...existing, pinnedDevices: devices });
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length && left.every((value, index) => value === right[index])
  );
}

function failure(
  kind: CollaborationStateVerificationFailureKind,
): CollaborationStateVerificationError {
  return new CollaborationStateVerificationError(kind);
}

function mapFailure(
  error: unknown,
  fallback: CollaborationStateVerificationFailureKind,
): CollaborationStateVerificationError {
  return error instanceof CollaborationStateVerificationError
    ? error
    : failure(fallback);
}
