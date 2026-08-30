import {
  checkActiveOwnerInvariant,
  validateOwnerTransition,
  type CollaborationOperationType,
} from '@kavrix/core';
import {
  computeAdministrativeActionParametersDigest,
  computeApprovalRequestDigest,
  computeMembershipHistoryDigest,
  computeMembershipManifestDigest,
  computeTransferIntentDigest,
} from '@kavrix/crypto';
import {
  COLLABORATION_PROTOCOL_VERSION,
  approvalRequestSchema,
  canonicalJson,
  collaborationAuthorizationTransitionSchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationMembershipSchema,
  collaborativeMembershipManifestSchema,
  transferIntentSchema,
  type ApprovalRequest,
  type CollaborationAuthorizationTransition,
  type CollaborationFinalizedMutationLink,
  type CollaborationMembership,
  type CollaborationRevisionTuple,
  type CollaborativeMembershipManifest,
  type MembershipHistoryEvent,
  type Sha256Digest,
  type TransferIntent,
} from '@kavrix/schemas';

import { verifyMembershipHistoryAppendOrCompaction } from './collaboration-history.js';

const ADMINISTRATIVE_OPERATIONS = new Set<CollaborationOperationType>([
  'add-member',
  'add-device',
  'remove-member',
  'revoke-device',
  'change-role',
  'rotate-key',
  'change-policy',
  'transfer-owner',
  'recover-owner',
  'emergency-rekey',
]);

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

export type CollaborativeAdministrativeNextState = Readonly<{
  memberships: readonly CollaborationMembership[];
  ownerPrincipalIds: readonly CollaborationMembership['principalId'][];
  approvalPolicy: CollaborativeMembershipManifest['approvalPolicy'];
  historyEvent: CollaborativeAdministrativeHistoryEvent;
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

export type NormalizedApprovalEvidence = Readonly<{
  consumed: ApprovalRequest;
  quorumReached: ApprovalRequest;
}>;

export type NormalizedTransferEvidence = Readonly<{
  published: TransferIntent;
  recipientAccepted: TransferIntent;
}>;

export type VerifiedCollaborativeAdministrativeManifestTransition = Readonly<{
  operationType: CollaborativeAdministrativeOperationType;
  transition: CollaborationAuthorizationTransition;
  historyEvent: MembershipHistoryEvent;
  decryptAccessChanged: boolean;
  actionParameters: CollaborativeAdministrativeActionParameters;
  actionParametersDigest: Sha256Digest;
  approval?: NormalizedApprovalEvidence;
  transfer?: NormalizedTransferEvidence;
}>;

export type VerifyCollaborativeAdministrativeManifestTransitionInput = Readonly<{
  link: CollaborationFinalizedMutationLink;
  priorManifest: CollaborativeMembershipManifest;
  nextManifest: CollaborativeMembershipManifest;
}>;

/** Deterministically advances the non-secret manifest wrapper across an ordinary link. */
export function advanceCollaborativeManifestAcrossOrdinaryLink(
  inputManifest: CollaborativeMembershipManifest,
  inputLink: CollaborationFinalizedMutationLink,
): CollaborativeMembershipManifest {
  const prior = collaborativeMembershipManifestSchema.parse(inputManifest);
  const link = collaborationFinalizedMutationLinkSchema.parse(inputLink);
  if (
    link.commitment.operationType !== 'ordinary-write' ||
    link.authorizationTransition !== undefined ||
    !manifestMatchesTuple(prior, previousTuple(link))
  ) {
    fail();
  }
  const tuple = nextTuple(link);
  const historyInput = {
    ...prior.history,
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    previousHeadDigest: link.commitment.previousHeadDigest,
    previousHistoryDigest: prior.history.currentHistoryDigest,
    currentHistoryDigest: prior.history.currentHistoryDigest,
  };
  const history = {
    ...historyInput,
    currentHistoryDigest: computeMembershipHistoryDigest(historyInput),
  };
  const manifestInput = {
    ...prior,
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    documentRevision: tuple.documentRevision,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    authorizationStateDigest: tuple.authorizationStateDigest,
    history,
    previousMembershipDigest: prior.membershipDigest,
    previousHeadDigest: link.commitment.previousHeadDigest,
    updatedAt: link.commitment.timestamp,
    membershipDigest: prior.membershipDigest,
  };
  return collaborativeMembershipManifestSchema.parse({
    ...manifestInput,
    membershipDigest: computeMembershipManifestDigest(manifestInput),
  });
}

/** Canonical non-secret projection signed by an administrative approval workflow. */
export function projectCollaborativeAdministrativeActionParameters(
  input: CollaborativeAdministrativeActionParametersInput,
): CollaborativeAdministrativeActionParameters {
  if (
    !ADMINISTRATIVE_OPERATIONS.has(input.operationType) ||
    typeof input.decryptAccessChanged !== 'boolean'
  ) {
    fail();
  }
  const projection: CollaborativeAdministrativeActionParameters = {
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    operationType: input.operationType,
    memberships: input.next.memberships.map((membership) =>
      collaborationMembershipSchema.parse(membership),
    ),
    ownerPrincipalIds: [...input.next.ownerPrincipalIds],
    approvalPolicy: input.next.approvalPolicy,
    decryptAccessChanged: input.decryptAccessChanged,
    historyEvent: exactHistoryProjection(input.next.historyEvent),
  };
  return deepFreeze(projection);
}

/** Digest the complete canonical action projection used by approval evidence. */
export function computeCollaborativeAdministrativeActionParametersDigest(
  input: CollaborativeAdministrativeActionParametersInput,
): Sha256Digest {
  return computeAdministrativeActionParametersDigest(
    projectCollaborativeAdministrativeActionParameters(input),
  );
}

/**
 * Proves the exact semantic and append-only workflow/history transition for one
 * already authenticated administrative candidate. Cryptographic signature and
 * signer-trust validation deliberately remains at each acceptance boundary.
 */
export function verifyCollaborativeAdministrativeManifestTransition(
  input: VerifyCollaborativeAdministrativeManifestTransitionInput,
): VerifiedCollaborativeAdministrativeManifestTransition {
  const link = collaborationFinalizedMutationLinkSchema.parse(input.link);
  const prior = collaborativeMembershipManifestSchema.parse(input.priorManifest);
  const next = collaborativeMembershipManifestSchema.parse(input.nextManifest);
  const operationType = administrativeOperation(link.commitment.operationType);
  const transition = collaborationAuthorizationTransitionSchema.parse(
    link.authorizationTransition,
  );
  const commitment = link.commitment;

  if (
    transition.operationType !== operationType ||
    transition.operationId !== commitment.operationId ||
    transition.databaseId !== commitment.databaseId ||
    transition.vaultId !== commitment.vaultId ||
    transition.previousHeadDigest !== commitment.previousHeadDigest ||
    transition.issuedAt !== commitment.timestamp ||
    transition.expiresAt !== commitment.expiresAt ||
    transition.previousAuthorizationStateDigest !==
      commitment.previousAuthorizationStateDigest ||
    transition.authorizationStateDigest !== commitment.authorizationStateDigest ||
    transition.transitionDigest !== commitment.authorizationTransitionDigest ||
    !sameCanonical(transition.previousTuple, previousTuple(link)) ||
    !sameCanonical(transition.nextTuple, nextTuple(link)) ||
    !manifestMatchesTuple(prior, previousTuple(link)) ||
    !manifestMatchesTuple(next, nextTuple(link)) ||
    next.databaseId !== prior.databaseId ||
    next.vaultId !== prior.vaultId ||
    next.databaseId !== commitment.databaseId ||
    next.vaultId !== commitment.vaultId ||
    next.previousMembershipDigest !== prior.membershipDigest ||
    next.previousHeadDigest !== commitment.previousHeadDigest ||
    next.createdAt !== prior.createdAt ||
    next.updatedAt !== commitment.timestamp ||
    next.approvalPolicy !== next.policy.approvalPolicy ||
    !checkActiveOwnerInvariant({ memberships: next.memberships }).valid ||
    !exactOwnerIndex(next)
  ) {
    fail();
  }

  assertExactPolicyArtifact(operationType, link, prior, next);

  const ownerTransition = validateOwnerTransition({
    priorMemberships: prior.memberships,
    nextMemberships: next.memberships,
    authorityRecoveryRecorded: operationType === 'recover-owner',
  });
  if (!ownerTransition.valid) fail();

  const historyEvent = exactHistoryAppend(link, prior, next);
  const transfer = normalizeTransferAppend(operationType, transition, prior, next);
  const approval = normalizeApprovalAppend(
    operationType,
    transition,
    prior,
    next,
    transfer,
  );
  const expectedHistory = assertExactOperationSemantics(
    operationType,
    prior,
    next,
    transfer?.recipientAccepted,
  );
  if (!sameCanonical(historyProjection(historyEvent), expectedHistory)) fail();

  assertExactHistoryApprovalFields(historyEvent, approval, operationType);
  const decryptAccessChanged =
    canonicalJson(decryptAccessSet(prior.memberships)) !==
    canonicalJson(decryptAccessSet(next.memberships));
  const actionParameters = projectCollaborativeAdministrativeActionParameters({
    operationType,
    next: {
      memberships: next.memberships,
      ownerPrincipalIds: next.ownerPrincipalIds,
      approvalPolicy: next.approvalPolicy,
      historyEvent: historyProjection(historyEvent),
    },
    decryptAccessChanged,
  });
  const actionParametersDigest =
    computeAdministrativeActionParametersDigest(actionParameters);
  if (
    approval !== undefined &&
    approval.consumed.actionParametersDigest !== actionParametersDigest
  ) {
    fail();
  }

  return deepFreeze({
    operationType,
    transition,
    historyEvent,
    decryptAccessChanged,
    actionParameters,
    actionParametersDigest,
    ...(approval === undefined ? {} : { approval }),
    ...(transfer === undefined ? {} : { transfer }),
  });
}

function exactHistoryAppend(
  link: CollaborationFinalizedMutationLink,
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): MembershipHistoryEvent {
  try {
    return verifyMembershipHistoryAppendOrCompaction({
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId: link.commitment.databaseId,
      vaultId: link.commitment.vaultId,
      operationId: link.commitment.operationId,
      previousHeadDigest: link.commitment.previousHeadDigest,
      previousTuple: previousTuple(link),
      nextTuple: nextTuple(link),
      priorHistory: prior.history,
      nextHistory: next.history,
      actorPrincipalId: link.commitment.writerPrincipalId,
      actorDeviceId: link.commitment.writerDeviceId,
      timestamp: link.commitment.timestamp,
      ...(link.commitment.expiresAt === undefined
        ? {}
        : { expiresAt: link.commitment.expiresAt }),
    }).event;
  } catch {
    fail();
  }
}

function normalizeApprovalAppend(
  operationType: CollaborativeAdministrativeOperationType,
  transition: CollaborationAuthorizationTransition,
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
  transfer: NormalizedTransferEvidence | undefined,
): NormalizedApprovalEvidence | undefined {
  assertUniqueApprovalWorkflows(prior.pendingApprovals);
  assertUniqueApprovalWorkflows(next.pendingApprovals);
  if (!exactPrefix(prior.pendingApprovals, next.pendingApprovals)) fail();
  const appended = next.pendingApprovals.slice(prior.pendingApprovals.length);

  if (operationType === 'recover-owner') {
    if (transition.evidence.kind !== 'authority-recovery' || appended.length !== 0) {
      fail();
    }
    return undefined;
  }

  if (operationType === 'transfer-owner') {
    if (transfer === undefined) fail();
    if (prior.approvalPolicy === 'none') {
      if (
        transfer.recipientAccepted.approvalRequestId !== undefined ||
        appended.length !== 0
      ) {
        fail();
      }
      return undefined;
    }
    if (
      transfer.recipientAccepted.approvalRequestId === undefined ||
      appended.length !== 1
    ) {
      fail();
    }
    const normalized = normalizeConsumedApproval(appended[0], transition.issuedAt);
    if (
      normalized.consumed.approvalRequestId !==
      transfer.recipientAccepted.approvalRequestId
    ) {
      fail();
    }
    assertApprovalBindsTransition(normalized.consumed, transition, prior);
    return normalized;
  }

  if (prior.approvalPolicy === 'none') {
    if (transition.evidence.kind !== 'none' || appended.length !== 0) fail();
    return undefined;
  }
  if (transition.evidence.kind !== 'approval' || appended.length !== 1) {
    fail();
  }
  const normalized = normalizeConsumedApproval(appended[0], transition.issuedAt);
  if (transition.evidence.evidenceDigest !== normalized.consumed.requestDigest) {
    fail();
  }
  assertApprovalBindsTransition(normalized.consumed, transition, prior);
  return normalized;
}

function normalizeTransferAppend(
  operationType: CollaborativeAdministrativeOperationType,
  transition: CollaborationAuthorizationTransition,
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): NormalizedTransferEvidence | undefined {
  assertUniqueTransferWorkflows(prior.pendingTransfers);
  assertUniqueTransferWorkflows(next.pendingTransfers);
  if (!exactPrefix(prior.pendingTransfers, next.pendingTransfers)) fail();
  const appended = next.pendingTransfers.slice(prior.pendingTransfers.length);
  if (operationType !== 'transfer-owner') {
    if (appended.length !== 0) fail();
    return undefined;
  }
  if (transition.evidence.kind !== 'ownership-transfer' || appended.length !== 1) {
    fail();
  }
  const published = transferIntentSchema.parse(appended[0]);
  if (
    published.state !== 'published' ||
    published.publishedAt !== transition.issuedAt ||
    published.terminalAt !== undefined ||
    published.intentDigest !== transition.evidence.evidenceDigest ||
    computeTransferIntentDigest(published) !== published.intentDigest ||
    published.operationId !== transition.operationId ||
    published.databaseId !== transition.databaseId ||
    published.vaultId !== transition.vaultId ||
    published.authorityEpoch !== transition.previousTuple.authorityEpoch ||
    published.databaseDeviceGeneration !==
      transition.previousTuple.databaseDeviceGeneration ||
    published.databaseDeviceRegistryDigest !==
      transition.previousTuple.databaseDeviceRegistryDigest ||
    published.documentRevision !== transition.previousTuple.documentRevision ||
    published.membershipRevision !== transition.previousTuple.membershipRevision ||
    published.policyRevision !== transition.previousTuple.policyRevision ||
    published.keyEpoch !== transition.previousTuple.keyEpoch ||
    published.currentHeadDigest !== transition.previousHeadDigest ||
    published.authorizationStateDigest !==
      transition.previousTuple.authorizationStateDigest
  ) {
    fail();
  }
  const acceptedInput: Record<string, unknown> = {
    ...published,
    state: 'recipient-accepted',
  };
  delete acceptedInput['publishedAt'];
  const recipientAccepted = transferIntentSchema.parse(acceptedInput);
  const expectedPublished = transferIntentSchema.parse({
    ...recipientAccepted,
    state: 'published',
    publishedAt: transition.issuedAt,
  });
  if (!sameCanonical(expectedPublished, published)) fail();
  return deepFreeze({ published, recipientAccepted });
}

function normalizeConsumedApproval(
  input: ApprovalRequest | undefined,
  committedAt: string,
): NormalizedApprovalEvidence {
  const consumed = approvalRequestSchema.parse(input);
  if (
    consumed.state !== 'consumed' ||
    consumed.resolvedAt !== committedAt ||
    computeApprovalRequestDigest(consumed) !== consumed.requestDigest
  ) {
    fail();
  }
  const quorumInput: Record<string, unknown> = {
    ...consumed,
    state: 'quorum-reached',
  };
  delete quorumInput['resolvedAt'];
  const quorumReached = approvalRequestSchema.parse(quorumInput);
  const expectedConsumed = approvalRequestSchema.parse({
    ...quorumReached,
    state: 'consumed',
    resolvedAt: committedAt,
  });
  if (!sameCanonical(expectedConsumed, consumed)) fail();
  return deepFreeze({ consumed, quorumReached });
}

function assertApprovalBindsTransition(
  request: ApprovalRequest,
  transition: CollaborationAuthorizationTransition,
  prior: CollaborativeMembershipManifest,
): void {
  if (
    request.operationId !== transition.operationId ||
    request.operationType !== transition.operationType ||
    request.databaseId !== transition.databaseId ||
    request.vaultId !== transition.vaultId ||
    request.authorityEpoch !== transition.previousTuple.authorityEpoch ||
    request.databaseDeviceGeneration !==
      transition.previousTuple.databaseDeviceGeneration ||
    request.databaseDeviceRegistryDigest !==
      transition.previousTuple.databaseDeviceRegistryDigest ||
    request.documentRevision !== transition.previousTuple.documentRevision ||
    request.membershipRevision !== transition.previousTuple.membershipRevision ||
    request.policyRevision !== transition.previousTuple.policyRevision ||
    request.keyEpoch !== transition.previousTuple.keyEpoch ||
    request.priorHeadDigest !== transition.previousHeadDigest ||
    request.authorizationStateDigest !==
      transition.previousTuple.authorizationStateDigest ||
    request.requiredApprovalPolicy !== prior.approvalPolicy
  ) {
    fail();
  }
}

function assertExactHistoryApprovalFields(
  event: MembershipHistoryEvent,
  approval: NormalizedApprovalEvidence | undefined,
  operationType: CollaborativeAdministrativeOperationType,
): void {
  if (approval === undefined || operationType === 'transfer-owner') {
    if (
      event.approvalRequestId !== undefined ||
      event.approvalRequestDigest !== undefined
    ) {
      fail();
    }
    return;
  }
  if (
    event.approvalRequestId !== approval.consumed.approvalRequestId ||
    event.approvalRequestDigest !== approval.consumed.requestDigest
  ) {
    fail();
  }
}

function assertExactOperationSemantics(
  operationType: CollaborativeAdministrativeOperationType,
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
  transfer: TransferIntent | undefined,
): CollaborativeAdministrativeHistoryEvent {
  if (operationType === 'add-member') return assertAddMember(prior, next);
  if (operationType === 'add-device') return assertAddDevice(prior, next);
  if (operationType === 'remove-member') return assertRemoveMember(prior, next);
  if (operationType === 'revoke-device') return assertRevokeDevice(prior, next);
  if (operationType === 'change-role') return assertChangeRole(prior, next);
  if (operationType === 'transfer-owner') {
    if (transfer === undefined) fail();
    return assertTransferOwner(prior, next, transfer);
  }
  if (operationType === 'recover-owner') return assertRecoverOwner(prior, next);

  if (!sameCanonical(prior.memberships, next.memberships)) fail();
  if (!sameCanonical(prior.ownerPrincipalIds, next.ownerPrincipalIds)) fail();
  if (operationType === 'change-policy') {
    if (prior.approvalPolicy === next.approvalPolicy) fail();
    return { eventType: 'policy-changed' };
  }
  if (prior.approvalPolicy !== next.approvalPolicy) fail();
  return {
    eventType: operationType === 'rotate-key' ? 'key-rotated' : 'emergency-rekey',
  };
}

function assertAddMember(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): CollaborativeAdministrativeHistoryEvent {
  assertPolicyUnchanged(prior, next);
  if (
    next.memberships.length !== prior.memberships.length + 1 ||
    !exactPrefix(prior.memberships, next.memberships)
  ) {
    fail();
  }
  const added = next.memberships.at(-1);
  if (added?.state !== 'active') fail();
  return { eventType: 'member-added', targetPrincipalId: added.principalId };
}

function assertAddDevice(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): CollaborativeAdministrativeHistoryEvent {
  assertPolicyUnchanged(prior, next);
  const changed = exactSingleMembershipChange(prior, next);
  if (
    !sameCanonical(prior.ownerPrincipalIds, next.ownerPrincipalIds) ||
    changed.prior.state !== 'active' ||
    changed.next.state !== 'active' ||
    changed.next.identityGeneration <= changed.prior.identityGeneration ||
    !sameExcept(changed.prior, changed.next, [
      'devices',
      'identityGeneration',
      'updatedAt',
    ]) ||
    changed.next.devices.length !== changed.prior.devices.length + 1 ||
    !exactPrefix(changed.prior.devices, changed.next.devices)
  ) {
    fail();
  }
  const added = changed.next.devices.at(-1);
  const mutationTime = Date.parse(next.updatedAt);
  if (
    added?.state !== 'active' ||
    mutationTime < Date.parse(added.createdAt) ||
    mutationTime < Date.parse(added.stateChangedAt) ||
    (added.expiresAt !== undefined && mutationTime >= Date.parse(added.expiresAt))
  ) {
    fail();
  }
  return {
    eventType: 'device-added',
    targetPrincipalId: changed.next.principalId,
    targetDeviceId: added.deviceId,
  };
}

function assertRemoveMember(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): CollaborativeAdministrativeHistoryEvent {
  assertPolicyUnchanged(prior, next);
  const changed = exactSingleMembershipChange(prior, next);
  if (
    changed.prior.state !== 'active' ||
    changed.next.state === 'active' ||
    !sameExcept(changed.prior, changed.next, ['state', 'updatedAt', 'removedAt'])
  ) {
    fail();
  }
  return {
    eventType: 'member-removed',
    targetPrincipalId: changed.next.principalId,
    previousState: changed.prior.state,
    newState: changed.next.state,
  };
}

function assertRevokeDevice(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): CollaborativeAdministrativeHistoryEvent {
  assertPolicyUnchanged(prior, next);
  const membership = exactSingleMembershipChange(prior, next);
  if (
    !sameExcept(membership.prior, membership.next, ['devices', 'updatedAt']) ||
    membership.prior.devices.length !== membership.next.devices.length
  ) {
    fail();
  }
  const changedDevices = membership.prior.devices.flatMap((device, index) => {
    const nextDevice = membership.next.devices[index];
    return nextDevice !== undefined && !sameCanonical(device, nextDevice)
      ? [{ prior: device, next: nextDevice }]
      : [];
  });
  const changed = changedDevices[0];
  if (
    changedDevices.length !== 1 ||
    changed === undefined ||
    changed.prior.deviceId !== changed.next.deviceId ||
    changed.prior.state !== 'active' ||
    changed.next.state === 'active' ||
    !sameExcept(changed.prior, changed.next, [
      'state',
      'stateChangedAt',
      'revokedAt',
      'rootSignature',
    ])
  ) {
    fail();
  }
  return {
    eventType: 'device-revoked',
    targetPrincipalId: membership.next.principalId,
    targetDeviceId: changed.next.deviceId,
  };
}

function assertChangeRole(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): CollaborativeAdministrativeHistoryEvent {
  assertPolicyUnchanged(prior, next);
  const changed = exactSingleMembershipChange(prior, next);
  if (
    changed.prior.role === changed.next.role ||
    !sameExcept(changed.prior, changed.next, ['role', 'updatedAt'])
  ) {
    fail();
  }
  return {
    eventType: 'role-changed',
    targetPrincipalId: changed.next.principalId,
    previousRole: changed.prior.role,
    newRole: changed.next.role,
  };
}

function assertTransferOwner(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
  intent: TransferIntent,
): CollaborativeAdministrativeHistoryEvent {
  assertPolicyUnchanged(prior, next);
  assertSameMembershipLayout(prior, next);
  const initiatorIndex = prior.memberships.findIndex(
    (membership) => membership.principalId === intent.initiatorPrincipalId,
  );
  const recipientIndex = prior.memberships.findIndex(
    (membership) => membership.principalId === intent.recipientPrincipalId,
  );
  const priorInitiator = prior.memberships[initiatorIndex];
  const nextInitiator = next.memberships[initiatorIndex];
  const priorRecipient = prior.memberships[recipientIndex];
  const nextRecipient = next.memberships[recipientIndex];
  if (
    priorInitiator?.state !== 'active' ||
    priorInitiator.role !== 'owner' ||
    priorRecipient?.state !== 'active' ||
    priorRecipient.role === 'owner' ||
    nextInitiator === undefined ||
    nextRecipient?.state !== 'active' ||
    nextRecipient.role !== 'owner' ||
    !sameExcept(priorRecipient, nextRecipient, ['role', 'updatedAt'])
  ) {
    fail();
  }
  for (const [index, priorMembership] of prior.memberships.entries()) {
    if (index === initiatorIndex || index === recipientIndex) continue;
    if (!sameCanonical(priorMembership, next.memberships[index])) fail();
  }
  assertTransferDisposition(priorInitiator, nextInitiator, intent);
  return {
    eventType: 'owner-transfer',
    targetPrincipalId: intent.recipientPrincipalId,
    previousRole: priorRecipient.role,
    newRole: nextRecipient.role,
  };
}

function assertTransferDisposition(
  prior: CollaborationMembership,
  next: CollaborationMembership,
  intent: TransferIntent,
): void {
  if (!sameExcept(prior, next, ['role', 'state', 'updatedAt', 'removedAt'])) fail();
  switch (intent.originalOwnerDisposition) {
    case 'remain-owner':
      if (next.state !== 'active' || next.role !== 'owner') fail();
      break;
    case 'editor':
    case 'reader':
      if (next.state !== 'active' || next.role !== intent.originalOwnerDisposition) {
        fail();
      }
      break;
    case 'removed':
      if (next.state === 'active' || next.removedAt === undefined) fail();
      break;
  }
}

function assertRecoverOwner(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): CollaborativeAdministrativeHistoryEvent {
  assertPolicyUnchanged(prior, next);
  const priorByPrincipal = new Map(
    prior.memberships.map((membership) => [membership.principalId, membership]),
  );
  const nextByPrincipal = new Map(
    next.memberships.map((membership) => [membership.principalId, membership]),
  );
  const replacements = next.memberships.filter((membership) => {
    const previous = priorByPrincipal.get(membership.principalId);
    return (
      membership.state === 'active' &&
      membership.role === 'owner' &&
      (previous?.state !== 'active' || previous.role !== 'owner')
    );
  });
  const replacement = replacements[0];
  if (replacements.length !== 1 || replacement === undefined) fail();

  const addedMemberships = next.memberships.filter(
    (membership) => !priorByPrincipal.has(membership.principalId),
  );

  const previousReplacement = priorByPrincipal.get(replacement.principalId);
  if (previousReplacement === undefined) {
    if (
      addedMemberships.length !== 1 ||
      replacement.devices.filter((device) => device.state === 'active').length === 0
    ) {
      fail();
    }
  } else if (
    addedMemberships.length !== 0 ||
    previousReplacement.state !== 'active' ||
    previousReplacement.role === 'owner' ||
    !sameExcept(previousReplacement, replacement, ['role', 'updatedAt'])
  ) {
    fail();
  }

  let removedPriorOwners = 0;
  for (const previous of prior.memberships) {
    const current = nextByPrincipal.get(previous.principalId);
    if (current === undefined) fail();
    if (previous.principalId === replacement.principalId) continue;
    if (previous.state === 'active' && previous.role === 'owner') {
      if (current.state !== 'active') {
        removedPriorOwners += 1;
        if (
          current.removedAt === undefined ||
          !sameExcept(previous, current, ['state', 'updatedAt', 'removedAt'])
        ) {
          fail();
        }
        continue;
      }
    }
    if (!sameCanonical(previous, current)) fail();
  }
  if (removedPriorOwners === 0) fail();
  return {
    eventType: 'owner-recovery',
    targetPrincipalId: replacement.principalId,
  };
}

function assertExactPolicyArtifact(
  operationType: CollaborativeAdministrativeOperationType,
  link: CollaborationFinalizedMutationLink,
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): void {
  const registryAdvanced =
    next.databaseDeviceGeneration > prior.databaseDeviceGeneration;
  if (operationType !== 'change-policy' && !registryAdvanced) {
    if (!sameCanonical(prior.policy, next.policy)) fail();
    return;
  }
  if (
    next.policy.changedByPrincipalId !== link.commitment.writerPrincipalId ||
    next.policy.changedByDeviceId !== link.commitment.writerDeviceId ||
    next.policy.changedAt !== link.commitment.timestamp ||
    (operationType === 'change-policy'
      ? prior.approvalPolicy === next.approvalPolicy
      : prior.approvalPolicy !== next.approvalPolicy)
  ) {
    fail();
  }
}

function exactSingleMembershipChange(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): Readonly<{ prior: CollaborationMembership; next: CollaborationMembership }> {
  assertSameMembershipLayout(prior, next);
  const changes = prior.memberships.flatMap((membership, index) => {
    const nextMembership = next.memberships[index];
    return nextMembership !== undefined && !sameCanonical(membership, nextMembership)
      ? [{ prior: membership, next: nextMembership }]
      : [];
  });
  const changed = changes[0];
  if (changes.length !== 1 || changed === undefined) fail();
  return changed;
}

function assertSameMembershipLayout(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): void {
  if (
    prior.memberships.length !== next.memberships.length ||
    prior.memberships.some((membership, index) => {
      const nextMembership = next.memberships[index];
      return (
        membership.membershipId !== nextMembership?.membershipId ||
        membership.principalId !== nextMembership.principalId
      );
    })
  ) {
    fail();
  }
}

function assertPolicyUnchanged(
  prior: CollaborativeMembershipManifest,
  next: CollaborativeMembershipManifest,
): void {
  if (prior.approvalPolicy !== next.approvalPolicy) fail();
}

function exactOwnerIndex(manifest: CollaborativeMembershipManifest): boolean {
  return sameCanonical(
    [...manifest.ownerPrincipalIds].sort(),
    manifest.memberships
      .filter(
        (membership) => membership.state === 'active' && membership.role === 'owner',
      )
      .map((membership) => membership.principalId)
      .sort(),
  );
}

function exactHistoryProjection(
  input: CollaborativeAdministrativeHistoryEvent,
): CollaborativeAdministrativeHistoryEvent {
  const allowed = new Set([
    'eventType',
    'targetPrincipalId',
    'targetDeviceId',
    'previousRole',
    'newRole',
    'previousState',
    'newState',
  ]);
  if (Object.keys(input).some((key) => !allowed.has(key))) {
    fail();
  }
  return deepFreeze({
    eventType: input.eventType,
    ...(input.targetPrincipalId === undefined
      ? {}
      : { targetPrincipalId: input.targetPrincipalId }),
    ...(input.targetDeviceId === undefined
      ? {}
      : { targetDeviceId: input.targetDeviceId }),
    ...(input.previousRole === undefined ? {} : { previousRole: input.previousRole }),
    ...(input.newRole === undefined ? {} : { newRole: input.newRole }),
    ...(input.previousState === undefined
      ? {}
      : { previousState: input.previousState }),
    ...(input.newState === undefined ? {} : { newState: input.newState }),
  });
}

function historyProjection(
  event: MembershipHistoryEvent,
): CollaborativeAdministrativeHistoryEvent {
  return deepFreeze({
    eventType: event.eventType,
    ...(event.targetPrincipalId === undefined
      ? {}
      : { targetPrincipalId: event.targetPrincipalId }),
    ...(event.targetDeviceId === undefined
      ? {}
      : { targetDeviceId: event.targetDeviceId }),
    ...(event.previousRole === undefined ? {} : { previousRole: event.previousRole }),
    ...(event.newRole === undefined ? {} : { newRole: event.newRole }),
    ...(event.previousState === undefined
      ? {}
      : { previousState: event.previousState }),
    ...(event.newState === undefined ? {} : { newState: event.newState }),
  });
}

function decryptAccessSet(memberships: readonly CollaborationMembership[]): string[] {
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

function previousTuple(
  link: CollaborationFinalizedMutationLink,
): CollaborationRevisionTuple {
  const commitment = link.commitment;
  return {
    authorityEpoch: commitment.previousAuthorityEpoch,
    documentRevision: commitment.previousDocumentRevision,
    membershipRevision: commitment.previousMembershipRevision,
    policyRevision: commitment.previousPolicyRevision,
    keyEpoch: commitment.previousKeyEpoch,
    databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
    databaseDeviceRegistryDigest: commitment.previousDatabaseDeviceRegistryDigest,
    authorizationStateDigest: commitment.previousAuthorizationStateDigest,
  };
}

function nextTuple(
  link: CollaborationFinalizedMutationLink,
): CollaborationRevisionTuple {
  const commitment = link.commitment;
  return {
    authorityEpoch: commitment.authorityEpoch,
    documentRevision: commitment.documentRevision,
    membershipRevision: commitment.membershipRevision,
    policyRevision: commitment.policyRevision,
    keyEpoch: commitment.keyEpoch,
    databaseDeviceGeneration: commitment.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: commitment.databaseDeviceRegistryDigest,
    authorizationStateDigest: commitment.authorizationStateDigest,
  };
}

function manifestMatchesTuple(
  manifest: CollaborativeMembershipManifest,
  tuple: ReturnType<typeof previousTuple>,
): boolean {
  return (
    manifest.authorityEpoch === tuple.authorityEpoch &&
    manifest.documentRevision === tuple.documentRevision &&
    manifest.membershipRevision === tuple.membershipRevision &&
    manifest.policyRevision === tuple.policyRevision &&
    manifest.keyEpoch === tuple.keyEpoch &&
    manifest.databaseDeviceGeneration === tuple.databaseDeviceGeneration &&
    manifest.databaseDeviceRegistryDigest === tuple.databaseDeviceRegistryDigest &&
    manifest.authorizationStateDigest === tuple.authorizationStateDigest
  );
}

function administrativeOperation(
  operationType: CollaborationOperationType,
): CollaborativeAdministrativeOperationType {
  if (!ADMINISTRATIVE_OPERATIONS.has(operationType)) fail();
  return operationType as CollaborativeAdministrativeOperationType;
}

function assertUniqueApprovalWorkflows(requests: readonly ApprovalRequest[]): void {
  assertUnique(requests.map((request) => request.approvalRequestId));
  assertUnique(requests.map((request) => request.requestDigest));
}

function assertUniqueTransferWorkflows(intents: readonly TransferIntent[]): void {
  assertUnique(intents.map((intent) => intent.transferIntentId));
  assertUnique(intents.map((intent) => intent.intentDigest));
}

function assertUnique(values: readonly string[]): void {
  if (new Set(values).size !== values.length) fail();
}

function exactPrefix<T>(prior: readonly T[], next: readonly T[]): boolean {
  return (
    next.length >= prior.length &&
    prior.every((value, index) => sameCanonical(value, next[index]))
  );
}

function sameExcept(
  prior: Readonly<Record<string, unknown>>,
  next: Readonly<Record<string, unknown>>,
  allowed: readonly string[],
): boolean {
  const omissions = new Set(allowed);
  return sameCanonical(
    Object.fromEntries(Object.entries(prior).filter(([key]) => !omissions.has(key))),
    Object.fromEntries(Object.entries(next).filter(([key]) => !omissions.has(key))),
  );
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
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

function fail(): never {
  throw new Error('Invalid collaborative administrative manifest transition');
}
