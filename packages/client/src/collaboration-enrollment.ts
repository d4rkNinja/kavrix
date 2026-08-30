import {
  COLLABORATION_DOMAINS,
  computeAadMetadataDigest,
  computeAuthorityDelegationDigest,
  computeAuthorityRecoveryEnvelopeDigest,
  computeAuthorizationCheckpointDigest,
  computeAuthorizationStateDigest,
  computeDeviceCertificateFingerprint,
  computeDeviceRegistryDigest,
  computeDiscoveryRecordDigest,
  computeDiscoveryTag,
  computeEncryptedMembershipDigest,
  computeFinalizedMutationLinkDigest,
  computeKeyEnvelopeDigest,
  computeKeyEnvelopeSetDigest,
  computeMembershipHistoryDigest,
  computeMembershipManifestDigest,
  computeMutationHead,
  computeMutationRequestDigest,
  computePolicyDigest,
  computePublicKeyFingerprint,
  signAuthorizationCheckpoint,
  signEnrollmentReceipt,
  verifyAuthorityDelegation,
  verifyAuthorizationCheckpoint,
  verifyAuthorizationTransitionOwner,
  verifyCollaborationRecord,
  verifyDiscoveryRecord,
  verifyEnrollmentReceipt,
  verifyFinalizedMutationLink,
  zeroize,
  type DeviceSigningPrivateKey,
} from '@kavrix/crypto';
import { verifyPublicIdentityExport } from '@kavrix/key-files';
import {
  COLLABORATION_PROTOCOL_VERSION,
  COLLABORATIVE_AUTHORIZATION_CHECKPOINT_FORMAT,
  COLLABORATIVE_ENROLLMENT_RECEIPT_FORMAT,
  canonicalJson,
  collaborationAuthorizationCheckpointSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationKeyEnvelopeSchema,
  collaborationMutationProofEntrySchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  deviceCertificateSchema,
  enrollmentReceiptSchema,
  historyIdSchema,
  membershipHistoryCheckpointSchema,
  membershipHistoryEventSchema,
  principalIdSchema,
  publicIdentityExportSchema,
  timestampSchema,
  deviceIdSchema,
  type CollaborationAuthorizationCheckpoint,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationDiscoveryRecord,
  type CollaborationMembership,
  type CollaborationRevisionTuple,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DeviceCertificate,
  type EnrollmentReceipt,
  type PublicIdentityExport,
} from '@kavrix/schemas';

import { requireExactDatabaseAuthorityRecoveryEnvelope } from './collaboration-recovery-envelope-binding.js';

const PLACEHOLDER_DIGEST = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PLACEHOLDER_SIGNATURE =
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ED25519_PRIVATE_KEY_BYTES = 64;
const SAFE_MESSAGE = 'Collaboration enrollment artifact creation failed.';

export class CollaborationEnrollmentError extends Error {
  public constructor() {
    super(SAFE_MESSAGE);
    this.name = 'CollaborationEnrollmentError';
  }
}

export type BuildCollaborationEnrollmentArtifactsInput = Readonly<{
  candidate: unknown;
  proofEntry: unknown;
  resultingManifest: unknown;
  ownerPublicIdentity: unknown;
  ownerPrincipalId: unknown;
  ownerDeviceId: unknown;
  recipientPublicIdentity: unknown;
  recipientDeviceId: unknown;
  ownerDeviceSigningPrivateKey: DeviceSigningPrivateKey | Uint8Array;
  checkpointId: unknown;
  issuedAt: unknown;
  expiresAt: unknown;
  now?: unknown;
}>;

export type CollaborationEnrollmentArtifacts = Readonly<{
  checkpoint: CollaborationAuthorizationCheckpoint;
  receipt: EnrollmentReceipt;
}>;

/**
 * Builds the two owner-authenticated artifacts used for a recipient's first
 * collaboration read. Every input is treated as untrusted until it is bound to
 * the exact finalized add-member/add-device candidate and its authenticated
 * manifest.
 */
export async function buildCollaborationEnrollmentArtifacts(
  input: BuildCollaborationEnrollmentArtifactsInput,
): Promise<CollaborationEnrollmentArtifacts> {
  let privateKey: Uint8Array | undefined;
  try {
    privateKey = copySigningPrivateKey(input.ownerDeviceSigningPrivateKey);
    const candidate = collaborativeVaultDocumentSchema.parse(input.candidate);
    const proofEntry = collaborationMutationProofEntrySchema.parse(input.proofEntry);
    const manifest = collaborativeMembershipManifestSchema.parse(
      input.resultingManifest,
    );
    const ownerIdentity = publicIdentityExportSchema.parse(input.ownerPublicIdentity);
    const recipientIdentity = publicIdentityExportSchema.parse(
      input.recipientPublicIdentity,
    );
    const ownerPrincipalId = principalIdSchema.parse(input.ownerPrincipalId);
    const ownerDeviceId = deviceIdSchema.parse(input.ownerDeviceId);
    const recipientDeviceId = deviceIdSchema.parse(input.recipientDeviceId);
    const checkpointId = historyIdSchema.parse(input.checkpointId);
    const issuedAt = timestampSchema.parse(input.issuedAt);
    const expiresAt = timestampSchema.parse(input.expiresAt);
    const now = timestampSchema.parse(input.now ?? new Date().toISOString());

    requireUsableReceiptInterval(issuedAt, expiresAt, now);
    const verified = await verifyPreparedEnrollmentState(
      candidate,
      proofEntry,
      manifest,
      ownerIdentity,
      recipientIdentity,
      ownerPrincipalId,
      ownerDeviceId,
      recipientDeviceId,
      issuedAt,
      now,
    );

    const checkpointBase = collaborationAuthorizationCheckpointSchema.parse({
      format: COLLABORATIVE_AUTHORIZATION_CHECKPOINT_FORMAT,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      checkpointId,
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      authorityDelegationDigest: candidate.authorityDelegationDigest,
      tuple: tupleOf(candidate),
      headDigest: candidate.headDigest,
      authorizationStateDigest: candidate.authorizationStateDigest,
      finalizedMutationLinkDigest: verified.finalizedMutationLinkDigest,
      compactedThroughDocumentRevision: candidate.documentRevision,
      checkpointDigest: PLACEHOLDER_DIGEST,
      signerPrincipalId: ownerPrincipalId,
      signerDeviceId: ownerDeviceId,
      createdAt: issuedAt,
      ownerSignature: PLACEHOLDER_SIGNATURE,
    });
    const checkpointWithDigest = collaborationAuthorizationCheckpointSchema.parse({
      ...checkpointBase,
      checkpointDigest: computeAuthorizationCheckpointDigest(checkpointBase),
    });
    const checkpoint = collaborationAuthorizationCheckpointSchema.parse({
      ...checkpointWithDigest,
      ownerSignature: await signAuthorizationCheckpoint(
        checkpointWithDigest,
        privateKey,
      ),
    });
    if (
      !(await verifyAuthorizationCheckpoint(
        checkpoint,
        verified.ownerDevice.signingPublicKey,
      ))
    ) {
      fail();
    }

    const receiptBase = enrollmentReceiptSchema.parse({
      format: COLLABORATIVE_ENROLLMENT_RECEIPT_FORMAT,
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      operationType: verified.operationType,
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      authorityEpoch: candidate.authorityEpoch,
      authorityDelegation: candidate.authorityDelegation,
      authorityDelegationDigest: candidate.authorityDelegationDigest,
      ownerPrincipalId,
      ownerPrincipalFingerprint: verified.ownerMembership.principalFingerprint,
      ownerRootSigningPublicKey: verified.ownerMembership.rootSigningPublicKey,
      ownerDeviceCertificate: verified.ownerDevice,
      recipientPrincipalId: verified.recipientMembership.principalId,
      recipientPrincipalFingerprint: verified.recipientMembership.principalFingerprint,
      recipientPublicIdentity: recipientIdentity,
      recipientDeviceId,
      recipientDeviceFingerprints: verified.recipientDeviceFingerprints,
      membershipId: verified.recipientMembership.membershipId,
      role: verified.recipientMembership.role,
      discoveryTag: verified.selectedDiscovery.discoveryTag,
      discoveryRecordDigest: verified.selectedDiscovery.discoveryRecordDigest,
      memberKeyEnvelopeDigest:
        verified.selectedDiscovery.encryptedMemberKeyEnvelope.envelopeDigest,
      databaseDeviceGeneration: candidate.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
      documentRevision: candidate.documentRevision,
      membershipRevision: candidate.membershipRevision,
      policyRevision: candidate.policyRevision,
      keyEpoch: candidate.keyEpoch,
      headDigest: candidate.headDigest,
      authorizationStateDigest: candidate.authorizationStateDigest,
      finalizedMutationLinkDigest: verified.finalizedMutationLinkDigest,
      authorizationCheckpointDigest: checkpoint.checkpointDigest,
      issuedAt,
      expiresAt,
      ownerSignature: PLACEHOLDER_SIGNATURE,
    });
    const receipt = enrollmentReceiptSchema.parse({
      ...receiptBase,
      ownerSignature: await signEnrollmentReceipt(receiptBase, privateKey),
    });
    if (
      !(await verifyEnrollmentReceipt(receipt, verified.ownerDevice.signingPublicKey))
    ) {
      fail();
    }

    deepFreeze(checkpoint);
    deepFreeze(receipt);
    return Object.freeze({ checkpoint, receipt });
  } catch {
    throw new CollaborationEnrollmentError();
  } finally {
    zeroize(privateKey);
  }
}

type VerifiedEnrollmentState = Readonly<{
  operationType: EnrollmentReceipt['operationType'];
  ownerMembership: CollaborationMembership;
  ownerDevice: DeviceCertificate;
  recipientMembership: CollaborationMembership;
  recipientDeviceFingerprints: readonly ReturnType<
    typeof computeDeviceCertificateFingerprint
  >[];
  selectedDiscovery: CollaborationDiscoveryRecord;
  finalizedMutationLinkDigest: ReturnType<typeof computeFinalizedMutationLinkDigest>;
}>;

async function verifyPreparedEnrollmentState(
  candidate: CollaborativeVaultDocument,
  proofEntry: ReturnType<typeof collaborationMutationProofEntrySchema.parse>,
  manifest: CollaborativeMembershipManifest,
  ownerIdentity: PublicIdentityExport,
  recipientIdentity: PublicIdentityExport,
  ownerPrincipalId: ReturnType<typeof principalIdSchema.parse>,
  ownerDeviceId: ReturnType<typeof deviceIdSchema.parse>,
  recipientDeviceId: ReturnType<typeof deviceIdSchema.parse>,
  issuedAt: ReturnType<typeof timestampSchema.parse>,
  now: ReturnType<typeof timestampSchema.parse>,
): Promise<VerifiedEnrollmentState> {
  const link = candidate.currentMutationLink;
  const commitment = link.commitment;
  const witness = proofEntry.authorizationWitness;
  const operationType = enrollmentOperation(commitment.operationType);
  requireExactDatabaseAuthorityRecoveryEnvelope(candidate, manifest);
  if (
    link.authorizationTransition?.operationType !== operationType ||
    witness === undefined ||
    canonicalJson(proofEntry.link) !== canonicalJson(link) ||
    canonicalJson(witness.encryptedMembershipManifest) !==
      canonicalJson(candidate.encryptedMembershipManifest) ||
    canonicalJson(witness.discoveryRecords) !==
      canonicalJson(candidate.discoveryRecords)
  ) {
    fail();
  }
  requireExactDatabaseAuthorityRecoveryEnvelope(witness, manifest);

  const delegation = candidate.authorityDelegation;
  const delegationDigest = computeAuthorityDelegationDigest(delegation);
  if (
    delegationDigest !== candidate.authorityDelegationDigest ||
    delegation.databaseId !== candidate.databaseId ||
    delegation.vaultId !== candidate.vaultId ||
    delegation.authorityEpoch !== candidate.authorityEpoch ||
    witness.databaseAuthorityRecoveryEnvelope.authorityRecoveryKeyFingerprint !==
      delegation.authorityRecoveryKeyFingerprint ||
    Date.parse(delegation.issuedAt) > Date.parse(commitment.timestamp) ||
    !(await verifyAuthorityDelegation(delegation, delegation.authoritySigningPublicKey))
  ) {
    fail();
  }

  const registry = collaborationDatabaseDeviceRegistrySchema.parse(
    witness.databaseDeviceRegistry,
  );
  await verifyRegistry(registry, candidate);
  verifyManifestBindings(candidate, manifest, witness);
  await verifyManifestTrust(candidate, manifest, registry);

  const ownerMembership = requireActiveMembership(manifest, ownerPrincipalId, 'owner');
  const recipientMembership = requireRecipientMembership(
    manifest,
    recipientIdentity,
    candidate,
    operationType,
    recipientDeviceId,
  );
  if (
    operationType === 'add-member' &&
    ownerMembership.principalId === recipientMembership.principalId
  ) {
    fail();
  }

  const verifiedOwnerIdentity = await verifyIdentity(ownerIdentity, issuedAt);
  const verifiedRecipientIdentity = await verifyIdentity(recipientIdentity, issuedAt);
  await verifyIdentity(ownerIdentity, now);
  await verifyIdentity(recipientIdentity, now);
  requireMembershipMatchesIdentity(ownerMembership, verifiedOwnerIdentity);
  requireMembershipMatchesIdentity(recipientMembership, verifiedRecipientIdentity);

  const ownerDevice = requireActiveDevice(ownerMembership, ownerDeviceId);
  requireExactCertificate(ownerDevice, ownerIdentity, ownerDeviceId);
  requireNotDenied(registry, ownerDevice);
  const selectedRecipientDevice = requireActiveDevice(
    recipientMembership,
    recipientDeviceId,
  );
  requireExactCertificate(
    selectedRecipientDevice,
    recipientIdentity,
    recipientDeviceId,
  );
  requireNotDenied(registry, selectedRecipientDevice);

  const finalizedMutationLinkDigest = computeFinalizedMutationLinkDigest(link);
  const writerMembership = requireActiveMembership(
    manifest,
    commitment.writerPrincipalId,
    'owner',
  );
  const writerDevice = requireActiveDevice(writerMembership, commitment.writerDeviceId);
  requireNotDenied(registry, writerDevice);
  if (
    computeMutationHead(commitment) !== candidate.headDigest ||
    computeMutationRequestDigest(commitment) !== commitment.requestDigest ||
    finalizedMutationLinkDigest !== witness.finalizedMutationLinkDigest ||
    (operationType === 'add-member' &&
      commitment.writerPrincipalId === recipientMembership.principalId) ||
    Date.parse(link.finalizedAt) < Date.parse(commitment.timestamp) ||
    Date.parse(link.finalizedAt) > Date.parse(issuedAt) ||
    (commitment.expiresAt !== undefined &&
      Date.parse(issuedAt) >= Date.parse(commitment.expiresAt)) ||
    !(await verifyFinalizedMutationLink(link, writerDevice.signingPublicKey))
  ) {
    fail();
  }

  const transition = requireValue(link.authorizationTransition);
  if (transition.transitionSignature.signerKind !== 'owner-device') fail();
  if (
    operationType === 'add-member' &&
    transition.transitionSignature.signerPrincipalId === recipientMembership.principalId
  ) {
    fail();
  }
  const transitionOwner = requireActiveMembership(
    manifest,
    transition.transitionSignature.signerPrincipalId,
    'owner',
  );
  const transitionDevice = requireActiveDevice(
    transitionOwner,
    transition.transitionSignature.signerDeviceId,
  );
  requireNotDenied(registry, transitionDevice);
  if (
    Date.parse(transition.issuedAt) > Date.parse(link.finalizedAt) ||
    Date.parse(link.finalizedAt) >= Date.parse(transition.expiresAt) ||
    Date.parse(issuedAt) >= Date.parse(transition.expiresAt) ||
    !(await verifyAuthorizationTransitionOwner(
      transition,
      transitionDevice.signingPublicKey,
    ))
  ) {
    fail();
  }

  const selectedDiscovery = await verifyDiscoverySet(
    candidate,
    manifest,
    registry,
    writerDevice,
    recipientMembership,
    recipientDeviceId,
  );
  const recipientDeviceFingerprints = recipientIdentity.devices
    .filter((device) => device.state === 'active')
    .sort((left, right) => left.deviceId.localeCompare(right.deviceId))
    .map((device) => computeDeviceCertificateFingerprint(device));
  if (
    new Set(recipientDeviceFingerprints).size !== recipientDeviceFingerprints.length
  ) {
    fail();
  }

  return {
    operationType,
    ownerMembership,
    ownerDevice,
    recipientMembership,
    recipientDeviceFingerprints,
    selectedDiscovery,
    finalizedMutationLinkDigest,
  };
}

async function verifyRegistry(
  registry: CollaborationDatabaseDeviceRegistry,
  candidate: CollaborativeVaultDocument,
): Promise<void> {
  const delegation = candidate.authorityDelegation;
  if (
    registry.databaseId !== candidate.databaseId ||
    registry.authorityEpoch !== candidate.authorityEpoch ||
    registry.authorityFingerprint !== delegation.authoritySigningKeyFingerprint ||
    registry.generation !== candidate.databaseDeviceGeneration ||
    registry.registryDigest !== candidate.databaseDeviceRegistryDigest ||
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
}

function verifyManifestBindings(
  candidate: CollaborativeVaultDocument,
  manifest: CollaborativeMembershipManifest,
  witness: NonNullable<
    ReturnType<
      typeof collaborationMutationProofEntrySchema.parse
    >['authorizationWitness']
  >,
): void {
  const tuple = tupleOf(candidate);
  const manifestTuple = collaborationRevisionTupleSchema.parse({
    authorityEpoch: manifest.authorityEpoch,
    documentRevision: manifest.documentRevision,
    membershipRevision: manifest.membershipRevision,
    policyRevision: manifest.policyRevision,
    keyEpoch: manifest.keyEpoch,
    databaseDeviceGeneration: manifest.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: manifest.databaseDeviceRegistryDigest,
    authorizationStateDigest: manifest.authorizationStateDigest,
  });
  if (
    manifest.databaseId !== candidate.databaseId ||
    manifest.vaultId !== candidate.vaultId ||
    canonicalJson(manifestTuple) !== canonicalJson(tuple) ||
    canonicalJson(witness.tuple) !== canonicalJson(tuple) ||
    manifest.previousHeadDigest !== candidate.previousHeadDigest ||
    computeMembershipManifestDigest(manifest) !== manifest.membershipDigest ||
    computeMembershipHistoryDigest(manifest.history) !==
      manifest.history.currentHistoryDigest ||
    computeAadMetadataDigest(candidate.encryptedMembershipManifest.aad) !==
      candidate.encryptedMembershipManifest.aad.metadataDigest ||
    computeEncryptedMembershipDigest(candidate.encryptedMembershipManifest) !==
      candidate.encryptedMembershipDigest ||
    computeKeyEnvelopeSetDigest(manifest.keyEnvelopes) !==
      candidate.encryptedEnvelopesDigest ||
    computePolicyDigest(manifest.policy) !== candidate.policyDigest ||
    manifest.policy.policyDigest !== candidate.policyDigest ||
    computeAuthorizationStateDigest(authorizationCore(manifest)) !==
      candidate.authorizationStateDigest
  ) {
    fail();
  }
}

async function verifyManifestTrust(
  candidate: CollaborativeVaultDocument,
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
      if (membership.state === 'active' && device.state === 'active') {
        requireNotDenied(registry, device);
      }
    }
  }

  const policyDevice = requireAnyDevice(
    manifest,
    manifest.policy.changedByPrincipalId,
    manifest.policy.changedByDeviceId,
  );
  requireNotDenied(registry, policyDevice);
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
    const membership = requireMembership(manifest, event.actorPrincipalId);
    const device = requireAnyDevice(
      manifest,
      event.actorPrincipalId,
      event.actorDeviceId,
    );
    if (
      !wasHistoricalSignerEligibleAt(registry, membership, device, event.timestamp) ||
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

  // The current registry is a prospective authorization fence. Historical
  // signatures remain authenticity evidence when their certified key is later
  // denied; the exact current add-member event is separately bound to and
  // fenced with the finalized-link writer below.
  for (const checkpoint of manifest.history.checkpoints) {
    const membership = requireMembership(manifest, checkpoint.signerPrincipalId);
    const device = requireAnyDevice(
      manifest,
      checkpoint.signerPrincipalId,
      checkpoint.signerDeviceId,
    );
    if (
      !wasHistoricalSignerEligibleAt(
        registry,
        membership,
        device,
        checkpoint.createdAt,
      ) ||
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
        checkpoint,
        membershipHistoryCheckpointSchema,
        'signature',
        device.signingPublicKey,
      ))
    ) {
      fail();
    }
  }

  const owners = manifest.memberships
    .filter(
      (membership) => membership.state === 'active' && membership.role === 'owner',
    )
    .flatMap((membership) => membership.devices)
    .filter((device) => device.state === 'active' && !isDenied(registry, device));
  for (const envelope of manifest.keyEnvelopes) {
    const digest =
      'membershipId' in envelope
        ? computeKeyEnvelopeDigest(envelope)
        : computeAuthorityRecoveryEnvelopeDigest(envelope);
    if (digest !== envelope.envelopeDigest) fail();
    const signatures = await Promise.all(
      owners.map((owner) =>
        'membershipId' in envelope
          ? verifyCollaborationRecord(
              COLLABORATION_DOMAINS.keyEnvelopeSignature,
              envelope,
              collaborationKeyEnvelopeSchema,
              'ownerSignature',
              owner.signingPublicKey,
            )
          : verifyCollaborationRecord(
              COLLABORATION_DOMAINS.keyEnvelopeSignature,
              envelope,
              databaseAuthorityRecoveryEnvelopeSchema,
              'ownerSignature',
              owner.signingPublicKey,
            ),
      ),
    );
    if (!signatures.some(Boolean)) fail();
  }

  if (candidate.discoveryRecords.length !== memberEnvelopes(manifest).length) fail();
}

async function verifyIdentity(
  identity: PublicIdentityExport,
  at: ReturnType<typeof timestampSchema.parse>,
): Promise<PublicIdentityExport> {
  return verifyPublicIdentityExport(
    identity,
    {
      principalId: identity.principalId,
      rootSigningPublicKey: identity.rootSigningPublicKey,
    },
    { at },
  );
}

function requireMembershipMatchesIdentity(
  membership: CollaborationMembership,
  identity: PublicIdentityExport,
): void {
  const activeMembershipDevices = membership.devices
    .filter((device) => device.state === 'active')
    .sort((left, right) => left.deviceId.localeCompare(right.deviceId));
  const identityDevices = [...identity.devices].sort((left, right) =>
    left.deviceId.localeCompare(right.deviceId),
  );
  if (
    membership.principalId !== identity.principalId ||
    membership.rootSigningPublicKey !== identity.rootSigningPublicKey ||
    membership.principalFingerprint !==
      computePublicKeyFingerprint(identity.rootSigningPublicKey, 'ed25519') ||
    membership.identityGeneration !== identity.identityGeneration ||
    canonicalJson(activeMembershipDevices) !== canonicalJson(identityDevices)
  ) {
    fail();
  }
}

function requireRecipientMembership(
  manifest: CollaborativeMembershipManifest,
  identity: PublicIdentityExport,
  candidate: CollaborativeVaultDocument,
  operationType: EnrollmentReceipt['operationType'],
  recipientDeviceId: string,
): CollaborationMembership {
  const commitment = candidate.currentMutationLink.commitment;
  const membership = requireActiveMembership(manifest, identity.principalId);
  const event = unique(
    manifest.history.events.filter(
      (candidateEvent) => candidateEvent.operationId === commitment.operationId,
    ),
  );
  if (
    event.eventType !==
      (operationType === 'add-member' ? 'member-added' : 'device-added') ||
    event.targetPrincipalId !== membership.principalId ||
    event.targetDeviceId !==
      (operationType === 'add-device' ? recipientDeviceId : undefined) ||
    event.actorPrincipalId !== commitment.writerPrincipalId ||
    event.actorDeviceId !== commitment.writerDeviceId ||
    event.previousHeadDigest !== commitment.previousHeadDigest ||
    event.previousDocumentRevision !== commitment.previousDocumentRevision ||
    event.newDocumentRevision !== commitment.documentRevision ||
    event.previousMembershipRevision !== commitment.previousMembershipRevision ||
    event.newMembershipRevision !== commitment.membershipRevision ||
    event.previousPolicyRevision !== commitment.previousPolicyRevision ||
    event.newPolicyRevision !== commitment.policyRevision ||
    event.previousKeyEpoch !== commitment.previousKeyEpoch ||
    event.newKeyEpoch !== commitment.keyEpoch ||
    event.previousAuthorityEpoch !== commitment.previousAuthorityEpoch ||
    event.newAuthorityEpoch !== commitment.authorityEpoch ||
    event.previousDatabaseDeviceGeneration !==
      commitment.previousDatabaseDeviceGeneration ||
    event.newDatabaseDeviceGeneration !== commitment.databaseDeviceGeneration ||
    event.previousDatabaseDeviceRegistryDigest !==
      commitment.previousDatabaseDeviceRegistryDigest ||
    event.newDatabaseDeviceRegistryDigest !== commitment.databaseDeviceRegistryDigest ||
    event.previousAuthorizationStateDigest !==
      commitment.previousAuthorizationStateDigest ||
    event.newAuthorizationStateDigest !== commitment.authorizationStateDigest
  ) {
    fail();
  }
  return membership;
}

function enrollmentOperation(
  operationType: string,
): EnrollmentReceipt['operationType'] {
  if (operationType !== 'add-member' && operationType !== 'add-device') fail();
  return operationType;
}

async function verifyDiscoverySet(
  candidate: CollaborativeVaultDocument,
  manifest: CollaborativeMembershipManifest,
  registry: CollaborationDatabaseDeviceRegistry,
  writer: DeviceCertificate,
  recipient: CollaborationMembership,
  selectedDeviceId: string,
): Promise<CollaborationDiscoveryRecord> {
  const envelopes = memberEnvelopes(manifest);
  for (const record of candidate.discoveryRecords) {
    if (
      record.signerPrincipalId !== writer.principalId ||
      record.signerDeviceId !== writer.deviceId ||
      computeDiscoveryRecordDigest(record) !== record.discoveryRecordDigest ||
      !(await verifyDiscoveryRecord(record, writer.signingPublicKey))
    ) {
      fail();
    }
    const membership = unique(
      manifest.memberships.filter(
        (candidateMembership) =>
          candidateMembership.membershipId === record.membershipId,
      ),
    );
    const envelope = unique(
      envelopes.filter(
        (candidateEnvelope) =>
          candidateEnvelope.membershipId === record.membershipId &&
          candidateEnvelope.deviceId === record.encryptedMemberKeyEnvelope.deviceId,
      ),
    );
    if (
      membership.state !== 'active' ||
      record.membershipState !== 'active' ||
      record.discoveryTag !==
        computeDiscoveryTag(candidate.databaseId, membership.principalFingerprint) ||
      canonicalJson(record.encryptedMemberKeyEnvelope) !== canonicalJson(envelope)
    ) {
      fail();
    }
  }

  const expectedTag = computeDiscoveryTag(
    candidate.databaseId,
    recipient.principalFingerprint,
  );
  let selected: CollaborationDiscoveryRecord | undefined;
  for (const device of recipient.devices.filter(
    (candidateDevice) => candidateDevice.state === 'active',
  )) {
    const records = candidate.discoveryRecords.filter(
      (record) =>
        record.discoveryTag === expectedTag &&
        record.membershipId === recipient.membershipId &&
        record.encryptedMemberKeyEnvelope.principalId === recipient.principalId &&
        record.encryptedMemberKeyEnvelope.deviceId === device.deviceId,
    );
    const record = unique(records);
    if (device.deviceId === selectedDeviceId) selected = record;
  }
  if (selected === undefined) fail();
  requireNotDenied(registry, writer);
  return selected;
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

function memberEnvelopes(
  manifest: CollaborativeMembershipManifest,
): readonly Extract<
  CollaborativeMembershipManifest['keyEnvelopes'][number],
  { membershipId: string }
>[] {
  return manifest.keyEnvelopes.filter(
    (envelope): envelope is Extract<typeof envelope, { membershipId: string }> =>
      'membershipId' in envelope,
  );
}

function tupleOf(candidate: CollaborativeVaultDocument): CollaborationRevisionTuple {
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: candidate.authorityEpoch,
    documentRevision: candidate.documentRevision,
    membershipRevision: candidate.membershipRevision,
    policyRevision: candidate.policyRevision,
    keyEpoch: candidate.keyEpoch,
    databaseDeviceGeneration: candidate.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
    authorizationStateDigest: candidate.authorizationStateDigest,
  });
}

function requireActiveMembership(
  manifest: CollaborativeMembershipManifest,
  principalId: string,
  role?: CollaborationMembership['role'],
): CollaborationMembership {
  return unique(
    manifest.memberships.filter(
      (membership) =>
        membership.principalId === principalId &&
        membership.state === 'active' &&
        (role === undefined || membership.role === role),
    ),
  );
}

function requireActiveDevice(
  membership: CollaborationMembership,
  deviceId: string,
): DeviceCertificate {
  return unique(
    membership.devices.filter(
      (device) => device.deviceId === deviceId && device.state === 'active',
    ),
  );
}

function requireAnyDevice(
  manifest: CollaborativeMembershipManifest,
  principalId: string,
  deviceId: string,
): DeviceCertificate {
  const membership = requireMembership(manifest, principalId);
  return unique(
    membership.devices.filter((candidate) => candidate.deviceId === deviceId),
  );
}

function requireMembership(
  manifest: CollaborativeMembershipManifest,
  principalId: string,
): CollaborationMembership {
  return unique(
    manifest.memberships.filter((candidate) => candidate.principalId === principalId),
  );
}

function requireExactCertificate(
  certificate: DeviceCertificate,
  identity: PublicIdentityExport,
  deviceId: string,
): void {
  const identityCertificate = unique(
    identity.devices.filter((device) => device.deviceId === deviceId),
  );
  if (canonicalJson(certificate) !== canonicalJson(identityCertificate)) fail();
}

function requireNotDenied(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
): void {
  if (isDenied(registry, device)) fail();
}

function isDenied(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
): boolean {
  const signingFingerprint = computePublicKeyFingerprint(
    device.signingPublicKey,
    'ed25519',
  );
  return registry.deniedDevices.some((denial) =>
    denialMatchesDevice(denial, device, signingFingerprint),
  );
}

function wasHistoricalSignerEligibleAt(
  registry: CollaborationDatabaseDeviceRegistry,
  membership: CollaborationMembership,
  device: DeviceCertificate,
  at: string,
): boolean {
  const evaluated = Date.parse(at);
  const signingFingerprint = computePublicKeyFingerprint(
    device.signingPublicKey,
    'ed25519',
  );
  return (
    evaluated >= Date.parse(membership.createdAt) &&
    evaluated >= Date.parse(device.createdAt) &&
    (membership.removedAt === undefined ||
      evaluated < Date.parse(membership.removedAt)) &&
    (device.state === 'active'
      ? evaluated >= Date.parse(device.stateChangedAt)
      : evaluated < Date.parse(device.stateChangedAt)) &&
    (device.expiresAt === undefined || evaluated < Date.parse(device.expiresAt)) &&
    !registry.deniedDevices.some(
      (denial) =>
        denialMatchesDevice(denial, device, signingFingerprint) &&
        Date.parse(denial.deniedAt) <= evaluated,
    )
  );
}

function denialMatchesDevice(
  denial: CollaborationDatabaseDeviceRegistry['deniedDevices'][number],
  device: DeviceCertificate,
  signingFingerprint: ReturnType<typeof computePublicKeyFingerprint>,
): boolean {
  return (
    (denial.principalId === device.principalId &&
      denial.deviceId === device.deviceId) ||
    denial.signingKeyFingerprint === signingFingerprint
  );
}

function requireUsableReceiptInterval(
  issuedAt: ReturnType<typeof timestampSchema.parse>,
  expiresAt: ReturnType<typeof timestampSchema.parse>,
  now: ReturnType<typeof timestampSchema.parse>,
): void {
  const issued = Date.parse(issuedAt);
  const expires = Date.parse(expiresAt);
  const current = Date.parse(now);
  if (issued > current || current >= expires) fail();
}

function copySigningPrivateKey(value: Uint8Array): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength !== ED25519_PRIVATE_KEY_BYTES
  ) {
    fail();
  }
  return Uint8Array.from(value);
}

function unique<T>(values: readonly T[]): T {
  if (values.length !== 1 || values[0] === undefined) fail();
  return values[0];
}

function requireValue<T>(value: T | undefined): T {
  if (value === undefined) fail();
  return value;
}

function deepFreeze(value: unknown): void {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
}

function fail(): never {
  throw new CollaborationEnrollmentError();
}
