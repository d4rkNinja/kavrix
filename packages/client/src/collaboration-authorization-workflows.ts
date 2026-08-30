import {
  validateApproval,
  validateOwnershipTransfer,
  type VerifiedApprovalSignature,
  type VerifiedRequesterSignature,
} from '@kavrix/core';
import {
  computeApprovalRequestDigest,
  computeAuthorizationStateDigest,
  computeMembershipManifestDigest,
  computeTransferIntentDigest,
  signApprovalEvidence,
  signApprovalRequest,
  signOwnershipTransferAcceptance,
  signTransferIntent,
  verifyApprovalEvidence,
  verifyApprovalRequest,
  verifyOwnershipTransferAcceptance,
  verifyTransferIntent,
  zeroize,
  type DeviceSigningPrivateKey,
} from '@kavrix/crypto';
import { verifyDeviceCertificate } from '@kavrix/key-files';
import {
  COLLABORATION_PROTOCOL_VERSION,
  canonicalJson,
  collaborationAuthorizationStateCoreSchema,
  collaborationMembershipSchema,
  collaborationRevisionTupleSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  deviceCertificateSchema,
  sha256DigestSchema,
  timestampSchema,
  transferIntentSchema,
  approvalRequestSchema,
  type ApprovalRequest,
  type CollaborationMembership,
  type CollaborationRevisionTuple,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DeviceCertificate,
  type Sha256Digest,
  type Timestamp,
  type TransferIntent,
} from '@kavrix/schemas';

const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');
const SAFE_MESSAGE = 'Collaborative authorization workflow failed.';

type ApprovalOperationType = Exclude<
  ApprovalRequest['operationType'],
  'genesis-migration' | 'ordinary-write' | 'recover-owner'
>;

type OpenApprovalState = Extract<
  ApprovalRequest['state'],
  'pending' | 'quorum-reached'
>;
type ApprovalResolution = Extract<
  ApprovalRequest['state'],
  'consumed' | 'expired' | 'cancelled' | 'conflicted'
>;
type TransferResolution = Extract<
  TransferIntent['state'],
  'published' | 'expired' | 'cancelled' | 'conflicted'
>;

export class CollaborationAuthorizationWorkflowError extends Error {
  constructor() {
    super(SAFE_MESSAGE);
    this.name = 'CollaborationAuthorizationWorkflowError';
  }
}

export type AuthenticatedAuthorizationPriorState = Readonly<{
  document: CollaborativeVaultDocument;
  manifest: CollaborativeMembershipManifest;
}>;

export type AuthorizationDeviceSigner = Readonly<{
  deviceCertificate: DeviceCertificate;
  deviceSigningPrivateKey: DeviceSigningPrivateKey | Uint8Array;
}>;

export type CreateApprovalRequestResult =
  | Readonly<{ kind: 'approval-not-required' }>
  | Readonly<{ kind: 'approval-required'; request: ApprovalRequest }>;

export type CreateApprovalRequestInput = Readonly<{
  prior: AuthenticatedAuthorizationPriorState;
  requester: AuthorizationDeviceSigner;
  operationType: ApprovalOperationType;
  operationId: ApprovalRequest['operationId'];
  approvalRequestId: ApprovalRequest['approvalRequestId'];
  actionParametersDigest: Sha256Digest;
  createdAt: Timestamp;
  expiresAt: Timestamp;
  nonce: ApprovalRequest['nonce'];
}>;

export type AddApprovalInput = Readonly<{
  prior: AuthenticatedAuthorizationPriorState;
  request: ApprovalRequest;
  approver: AuthorizationDeviceSigner;
  approvedAt: Timestamp;
}>;

export type ResolveApprovalInput = Readonly<{
  prior: AuthenticatedAuthorizationPriorState;
  request: ApprovalRequest;
  resolution: ApprovalResolution;
  resolvedAt: Timestamp;
}>;

export type CreateOwnershipTransferIntentInput = Readonly<{
  prior: AuthenticatedAuthorizationPriorState;
  initiator: AuthorizationDeviceSigner;
  recipientDeviceCertificate: DeviceCertificate;
  transferIntentId: TransferIntent['transferIntentId'];
  operationId: TransferIntent['operationId'];
  actionParametersDigest: Sha256Digest;
  originalOwnerDisposition: TransferIntent['originalOwnerDisposition'];
  createdAt: Timestamp;
  expiresAt: Timestamp;
  approvalRequest?: ApprovalRequest;
}>;

export type AcceptOwnershipTransferIntentInput = Readonly<{
  prior: AuthenticatedAuthorizationPriorState;
  intent: TransferIntent;
  recipient: AuthorizationDeviceSigner;
  acceptedAt: Timestamp;
  actionParametersDigest: Sha256Digest;
  approvalRequest?: ApprovalRequest;
}>;

export type ResolveOwnershipTransferIntentInput = Readonly<{
  prior: AuthenticatedAuthorizationPriorState;
  intent: TransferIntent;
  resolution: TransferResolution;
  resolvedAt: Timestamp;
  actionParametersDigest: Sha256Digest;
  approvalRequest?: ApprovalRequest;
  nextMemberships?: readonly CollaborationMembership[];
}>;

type ParsedPrior = Readonly<{
  document: CollaborativeVaultDocument;
  manifest: CollaborativeMembershipManifest;
  tuple: CollaborationRevisionTuple;
}>;

/** Create and requester-sign a pending request, or explicitly report policy `none`. */
export async function createApprovalRequest(
  input: CreateApprovalRequestInput,
): Promise<CreateApprovalRequestResult> {
  let signingKey: Uint8Array | undefined;
  try {
    const prior = parsePrior(input.prior);
    const createdAt = timestampSchema.parse(input.createdAt);
    const expiresAt = timestampSchema.parse(input.expiresAt);
    const actionParametersDigest = sha256DigestSchema.parse(
      input.actionParametersDigest,
    );
    const operationType: string = input.operationType;
    if (
      operationType === 'genesis-migration' ||
      operationType === 'ordinary-write' ||
      operationType === 'recover-owner'
    ) {
      fail();
    }
    const requester = await authenticateDevice(
      prior.manifest,
      input.requester.deviceCertificate,
      createdAt,
      'owner',
    );
    signingKey = copySigningKey(input.requester.deviceSigningPrivateKey);
    const unsigned = approvalRequestSchema.parse({
      format: 'kavrix-collaborative-approval-request',
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      approvalRequestId: input.approvalRequestId,
      operationId: input.operationId,
      operationType: input.operationType,
      databaseId: prior.document.databaseId,
      vaultId: prior.document.vaultId,
      requestDigest: PLACEHOLDER_DIGEST,
      actionParametersDigest,
      ...tupleFields(prior),
      priorHeadDigest: prior.document.headDigest,
      requestingPrincipalId: requester.principalId,
      requestingDeviceId: requester.deviceId,
      requiredApprovalPolicy: prior.manifest.approvalPolicy,
      state: 'pending',
      createdAt,
      expiresAt,
      nonce: input.nonce,
      requesterSignature: PLACEHOLDER_SIGNATURE,
      approvals: [],
    });
    const withDigest = approvalRequestSchema.parse({
      ...unsigned,
      requestDigest: computeApprovalRequestDigest(unsigned),
    });
    const request = approvalRequestSchema.parse({
      ...withDigest,
      requesterSignature: await signApprovalRequest(withDigest, signingKey),
    });
    if (!(await verifyApprovalRequest(request, requester.signingPublicKey))) fail();
    const validation = validateApproval({
      request,
      priorPolicy: prior.manifest.policy,
      priorTuple: prior.tuple,
      priorHeadDigest: prior.document.headDigest,
      activeMemberships: prior.manifest.memberships,
      now: createdAt,
      verifiedRequesterSignature: requesterFact(request),
      verifiedApprovalSignatures: [],
    });
    if (!validation.valid || validation.eligibleForConsumption) fail();
    if (prior.manifest.approvalPolicy === 'none') {
      return Object.freeze({ kind: 'approval-not-required' });
    }
    return Object.freeze({ kind: 'approval-required', request: freeze(request) });
  } catch {
    fail();
  } finally {
    zeroize(signingKey);
  }
}

/** Add the one distinct active-owner approval and advance pending to quorum. */
export async function addApproval(input: AddApprovalInput): Promise<ApprovalRequest> {
  let signingKey: Uint8Array | undefined;
  try {
    const prior = parsePrior(input.prior);
    const approvedAt = timestampSchema.parse(input.approvedAt);
    const request = approvalRequestSchema.parse(input.request);
    if (request.state !== 'pending' || request.approvals.length !== 0) fail();
    await verifyOpenApproval(prior, request, approvedAt);
    const approver = await authenticateDevice(
      prior.manifest,
      input.approver.deviceCertificate,
      approvedAt,
      'owner',
    );
    if (approver.principalId === request.requestingPrincipalId) fail();
    signingKey = copySigningKey(input.approver.deviceSigningPrivateKey);
    const evidenceBase = {
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      approvalRequestId: request.approvalRequestId,
      operationId: request.operationId,
      databaseId: request.databaseId,
      vaultId: request.vaultId,
      requestDigest: request.requestDigest,
      authorityEpoch: request.authorityEpoch,
      databaseDeviceGeneration: request.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: request.databaseDeviceRegistryDigest,
      documentRevision: request.documentRevision,
      membershipRevision: request.membershipRevision,
      policyRevision: request.policyRevision,
      keyEpoch: request.keyEpoch,
      priorHeadDigest: request.priorHeadDigest,
      authorizationStateDigest: request.authorizationStateDigest,
      requestingPrincipalId: request.requestingPrincipalId,
      approverPrincipalId: approver.principalId,
      approverDeviceId: approver.deviceId,
      approvedAt,
      signature: PLACEHOLDER_SIGNATURE,
    };
    const evidence = approvalRequestSchema.shape.approvals.element.parse({
      ...evidenceBase,
      signature: await signApprovalEvidence(evidenceBase, signingKey),
    });
    if (!(await verifyApprovalEvidence(evidence, approver.signingPublicKey))) fail();
    const advanced = approvalRequestSchema.parse({
      ...request,
      state: 'quorum-reached',
      approvals: [evidence],
    });
    await verifyOpenApproval(prior, advanced, approvedAt, true);
    return freeze(advanced);
  } catch {
    fail();
  } finally {
    zeroize(signingKey);
  }
}

/** Resolve an open approval through one legal monotonic terminal transition. */
export async function resolveApprovalRequest(
  input: ResolveApprovalInput,
): Promise<ApprovalRequest> {
  try {
    const prior = parsePrior(input.prior);
    const request = approvalRequestSchema.parse(input.request);
    const resolvedAt = timestampSchema.parse(input.resolvedAt);
    if (!isOpenApprovalState(request.state)) fail();
    const expired = Date.parse(resolvedAt) >= Date.parse(request.expiresAt);
    if (input.resolution === 'expired') {
      if (!expired) fail();
      await verifyOpenApproval(prior, request, approvalEvidenceTime(request));
    } else {
      if (expired || Date.parse(resolvedAt) < Date.parse(request.createdAt)) fail();
      const validation = await verifyOpenApproval(prior, request, resolvedAt);
      if (
        input.resolution === 'consumed' &&
        (request.state !== 'quorum-reached' || !validation.eligibleForConsumption)
      ) {
        fail();
      }
    }
    return freeze(
      approvalRequestSchema.parse({
        ...request,
        state: input.resolution,
        resolvedAt,
      }),
    );
  } catch {
    fail();
  }
}

/** Create an initiator-signed two-party ownership-transfer intent. */
export async function createOwnershipTransferIntent(
  input: CreateOwnershipTransferIntentInput,
): Promise<TransferIntent> {
  let signingKey: Uint8Array | undefined;
  try {
    const prior = parsePrior(input.prior);
    const createdAt = timestampSchema.parse(input.createdAt);
    const expiresAt = timestampSchema.parse(input.expiresAt);
    const actionParametersDigest = sha256DigestSchema.parse(
      input.actionParametersDigest,
    );
    const initiator = await authenticateDevice(
      prior.manifest,
      input.initiator.deviceCertificate,
      createdAt,
      'owner',
    );
    const recipient = await authenticateDevice(
      prior.manifest,
      input.recipientDeviceCertificate,
      createdAt,
    );
    if (recipient.principalId === initiator.principalId) fail();
    const approvalRequestId = await verifyOptionalTransferApproval(
      prior,
      input.approvalRequest,
      input.operationId,
      actionParametersDigest,
      createdAt,
    );
    signingKey = copySigningKey(input.initiator.deviceSigningPrivateKey);
    const base = transferIntentSchema.parse({
      format: 'kavrix-collaborative-transfer-intent',
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      transferIntentId: input.transferIntentId,
      operationId: input.operationId,
      databaseId: prior.document.databaseId,
      vaultId: prior.document.vaultId,
      initiatorPrincipalId: initiator.principalId,
      initiatorDeviceId: initiator.deviceId,
      recipientPrincipalId: recipient.principalId,
      recipientDeviceId: recipient.deviceId,
      targetRole: 'owner',
      originalOwnerDisposition: input.originalOwnerDisposition,
      ...tupleFields(prior),
      currentHeadDigest: prior.document.headDigest,
      intentDigest: PLACEHOLDER_DIGEST,
      ...(approvalRequestId === undefined ? {} : { approvalRequestId }),
      state: 'initiator-signed',
      createdAt,
      expiresAt,
      initiatorSignedAt: createdAt,
      initiatorSignature: PLACEHOLDER_SIGNATURE,
    });
    const withDigest = transferIntentSchema.parse({
      ...base,
      intentDigest: computeTransferIntentDigest(base),
    });
    const intent = transferIntentSchema.parse({
      ...withDigest,
      initiatorSignature: await signTransferIntent(withDigest, signingKey),
    });
    if (!(await verifyTransferIntent(intent, initiator.signingPublicKey))) fail();
    return freeze(intent);
  } catch {
    fail();
  } finally {
    zeroize(signingKey);
  }
}

/** Verify the exact live intent and add the named recipient device's acceptance. */
export async function acceptOwnershipTransferIntent(
  input: AcceptOwnershipTransferIntentInput,
): Promise<TransferIntent> {
  let signingKey: Uint8Array | undefined;
  try {
    const prior = parsePrior(input.prior);
    const acceptedAt = timestampSchema.parse(input.acceptedAt);
    const actionParametersDigest = sha256DigestSchema.parse(
      input.actionParametersDigest,
    );
    const intent = transferIntentSchema.parse(input.intent);
    if (intent.state !== 'initiator-signed' || intent.recipientAcceptance) fail();
    await verifyTransferIntentState(
      prior,
      intent,
      acceptedAt,
      actionParametersDigest,
      input.approvalRequest,
      false,
    );
    const recipient = await authenticateDevice(
      prior.manifest,
      input.recipient.deviceCertificate,
      acceptedAt,
    );
    if (
      recipient.principalId !== intent.recipientPrincipalId ||
      recipient.deviceId !== intent.recipientDeviceId
    ) {
      fail();
    }
    signingKey = copySigningKey(input.recipient.deviceSigningPrivateKey);
    const acceptanceBase = {
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      transferIntentId: intent.transferIntentId,
      operationId: intent.operationId,
      databaseId: intent.databaseId,
      vaultId: intent.vaultId,
      intentDigest: intent.intentDigest,
      authorityEpoch: intent.authorityEpoch,
      databaseDeviceGeneration: intent.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: intent.databaseDeviceRegistryDigest,
      authorizationStateDigest: intent.authorizationStateDigest,
      recipientPrincipalId: intent.recipientPrincipalId,
      recipientDeviceId: intent.recipientDeviceId,
      acceptedAt,
      signature: PLACEHOLDER_SIGNATURE,
    };
    const acceptance = transferIntentSchema.shape.recipientAcceptance.unwrap().parse({
      ...acceptanceBase,
      signature: await signOwnershipTransferAcceptance(acceptanceBase, signingKey),
    });
    if (
      !(await verifyOwnershipTransferAcceptance(acceptance, recipient.signingPublicKey))
    ) {
      fail();
    }
    return freeze(
      transferIntentSchema.parse({
        ...intent,
        state: 'recipient-accepted',
        recipientAcceptance: acceptance,
      }),
    );
  } catch {
    fail();
  } finally {
    zeroize(signingKey);
  }
}

/** Mark an accepted transfer published, or resolve an open transfer terminally. */
export async function resolveOwnershipTransferIntent(
  input: ResolveOwnershipTransferIntentInput,
): Promise<TransferIntent> {
  try {
    const prior = parsePrior(input.prior);
    const resolvedAt = timestampSchema.parse(input.resolvedAt);
    const actionParametersDigest = sha256DigestSchema.parse(
      input.actionParametersDigest,
    );
    const intent = transferIntentSchema.parse(input.intent);
    if (intent.state !== 'initiator-signed' && intent.state !== 'recipient-accepted') {
      fail();
    }
    const expired = Date.parse(resolvedAt) >= Date.parse(intent.expiresAt);
    if (input.resolution === 'expired') {
      if (!expired) fail();
      await verifyTransferIntentState(
        prior,
        intent,
        transferEvidenceTime(intent),
        actionParametersDigest,
        input.approvalRequest,
        intent.state === 'recipient-accepted',
      );
    } else {
      if (expired || Date.parse(resolvedAt) < Date.parse(intent.createdAt)) fail();
      await verifyTransferIntentState(
        prior,
        intent,
        resolvedAt,
        actionParametersDigest,
        input.approvalRequest,
        intent.state === 'recipient-accepted',
      );
    }
    if (input.resolution === 'published') {
      if (intent.state !== 'recipient-accepted' || !input.nextMemberships) fail();
      const nextMemberships = input.nextMemberships.map((membership) =>
        collaborationMembershipSchema.parse(membership),
      );
      assertExactTransferMembershipChange(
        intent,
        prior.manifest.memberships,
        nextMemberships,
      );
      const validation = validateOwnershipTransfer({
        intent,
        priorMemberships: prior.manifest.memberships,
        nextMemberships,
        priorTuple: prior.tuple,
        priorHeadDigest: prior.document.headDigest,
        now: resolvedAt,
        initiatorSignatureVerification: {
          signerPrincipalId: intent.initiatorPrincipalId,
          signerDeviceId: intent.initiatorDeviceId,
          signedIntentDigest: intent.intentDigest,
          signature: requireValue(intent.initiatorSignature),
        },
        recipientAcceptanceVerification: {
          signerPrincipalId: intent.recipientPrincipalId,
          signerDeviceId: intent.recipientDeviceId,
          signedIntentDigest: intent.intentDigest,
          signature: requireValue(intent.recipientAcceptance).signature,
        },
      });
      if (!validation.valid || !validation.complete) fail();
      return freeze(
        transferIntentSchema.parse({
          ...intent,
          state: 'published',
          publishedAt: resolvedAt,
        }),
      );
    }
    return freeze(
      transferIntentSchema.parse({
        ...intent,
        state: input.resolution,
        terminalAt: resolvedAt,
      }),
    );
  } catch {
    fail();
  }
}

async function verifyOpenApproval(
  prior: ParsedPrior,
  request: ApprovalRequest,
  now: Timestamp,
  requireQuorum = false,
): Promise<ReturnType<typeof validateApproval>> {
  if (!isOpenApprovalState(request.state)) fail();
  const requester = await authenticateDevice(
    prior.manifest,
    exactDevice(
      prior.manifest,
      request.requestingPrincipalId,
      request.requestingDeviceId,
    ),
    now,
    'owner',
  );
  if (
    computeApprovalRequestDigest(request) !== request.requestDigest ||
    !(await verifyApprovalRequest(request, requester.signingPublicKey))
  ) {
    fail();
  }
  const verified: VerifiedApprovalSignature[] = [];
  for (const evidence of request.approvals) {
    const approver = await authenticateDevice(
      prior.manifest,
      exactDevice(
        prior.manifest,
        evidence.approverPrincipalId,
        evidence.approverDeviceId,
      ),
      now,
      'owner',
    );
    if (!(await verifyApprovalEvidence(evidence, approver.signingPublicKey))) fail();
    verified.push({
      approvalRequestId: evidence.approvalRequestId,
      approverPrincipalId: evidence.approverPrincipalId,
      approverDeviceId: evidence.approverDeviceId,
      signedRequestDigest: request.requestDigest,
      signature: evidence.signature,
    });
  }
  const validation = validateApproval({
    request,
    priorPolicy: prior.manifest.policy,
    priorTuple: prior.tuple,
    priorHeadDigest: prior.document.headDigest,
    activeMemberships: prior.manifest.memberships,
    now,
    verifiedRequesterSignature: requesterFact(request),
    verifiedApprovalSignatures: verified,
  });
  if (!validation.valid || (requireQuorum && !validation.eligibleForConsumption)) {
    fail();
  }
  return validation;
}

async function verifyOptionalTransferApproval(
  prior: ParsedPrior,
  request: ApprovalRequest | undefined,
  operationId: TransferIntent['operationId'],
  actionParametersDigest: Sha256Digest,
  now: Timestamp,
): Promise<ApprovalRequest['approvalRequestId'] | undefined> {
  if (prior.manifest.approvalPolicy === 'none') {
    if (request !== undefined) fail();
    return undefined;
  }
  if (request === undefined) fail();
  const parsed = approvalRequestSchema.parse(request);
  if (
    parsed.state !== 'quorum-reached' ||
    parsed.operationType !== 'transfer-owner' ||
    parsed.operationId !== operationId ||
    parsed.actionParametersDigest !== actionParametersDigest
  ) {
    fail();
  }
  const validation = await verifyOpenApproval(prior, parsed, now, true);
  if (!validation.eligibleForConsumption) fail();
  return parsed.approvalRequestId;
}

async function verifyTransferIntentState(
  prior: ParsedPrior,
  intent: TransferIntent,
  now: Timestamp,
  actionParametersDigest: Sha256Digest,
  approvalRequest: ApprovalRequest | undefined,
  requireAcceptance: boolean,
): Promise<void> {
  assertTransferTuple(prior, intent);
  if (
    Date.parse(now) < Date.parse(intent.createdAt) ||
    Date.parse(now) >= Date.parse(intent.expiresAt)
  ) {
    fail();
  }
  const initiator = await authenticateDevice(
    prior.manifest,
    exactDevice(prior.manifest, intent.initiatorPrincipalId, intent.initiatorDeviceId),
    now,
    'owner',
  );
  const recipient = await authenticateDevice(
    prior.manifest,
    exactDevice(prior.manifest, intent.recipientPrincipalId, intent.recipientDeviceId),
    now,
  );
  if (
    intent.initiatorSignedAt === undefined ||
    Date.parse(intent.initiatorSignedAt) < Date.parse(intent.createdAt) ||
    Date.parse(intent.initiatorSignedAt) >= Date.parse(intent.expiresAt) ||
    Date.parse(intent.initiatorSignedAt) > Date.parse(now) ||
    computeTransferIntentDigest(intent) !== intent.intentDigest ||
    !(await verifyTransferIntent(intent, initiator.signingPublicKey))
  ) {
    fail();
  }
  const verifiedId = await verifyOptionalTransferApproval(
    prior,
    approvalRequest,
    intent.operationId,
    actionParametersDigest,
    now,
  );
  if (verifiedId !== intent.approvalRequestId) fail();
  const acceptance = intent.recipientAcceptance;
  if (requireAcceptance) {
    if (
      acceptance === undefined ||
      Date.parse(acceptance.acceptedAt) < Date.parse(intent.createdAt) ||
      Date.parse(acceptance.acceptedAt) >= Date.parse(intent.expiresAt) ||
      Date.parse(acceptance.acceptedAt) > Date.parse(now) ||
      !(await verifyOwnershipTransferAcceptance(acceptance, recipient.signingPublicKey))
    ) {
      fail();
    }
  } else if (acceptance !== undefined) {
    fail();
  }
}

function parsePrior(input: AuthenticatedAuthorizationPriorState): ParsedPrior {
  const document = collaborativeVaultDocumentSchema.parse(input.document);
  const manifest = collaborativeMembershipManifestSchema.parse(input.manifest);
  if (
    manifest.databaseId !== document.databaseId ||
    manifest.vaultId !== document.vaultId ||
    manifest.authorityEpoch !== document.authorityEpoch ||
    manifest.databaseDeviceGeneration !== document.databaseDeviceGeneration ||
    manifest.databaseDeviceRegistryDigest !== document.databaseDeviceRegistryDigest ||
    manifest.documentRevision !== document.documentRevision ||
    manifest.membershipRevision !== document.membershipRevision ||
    manifest.policyRevision !== document.policyRevision ||
    manifest.keyEpoch !== document.keyEpoch ||
    manifest.authorizationStateDigest !== document.authorizationStateDigest ||
    manifest.membershipDigest !== computeMembershipManifestDigest(manifest) ||
    document.authorizationStateDigest !==
      computeAuthorizationStateDigest(authorizationCore(manifest))
  ) {
    fail();
  }
  return {
    document,
    manifest,
    tuple: collaborationRevisionTupleSchema.parse({
      authorityEpoch: document.authorityEpoch,
      documentRevision: document.documentRevision,
      membershipRevision: document.membershipRevision,
      policyRevision: document.policyRevision,
      keyEpoch: document.keyEpoch,
      databaseDeviceGeneration: document.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: document.databaseDeviceRegistryDigest,
      authorizationStateDigest: document.authorizationStateDigest,
    }),
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
      devices: membership.devices.map(deviceAuthorizationCore),
      createdAt: membership.createdAt,
      updatedAt: membership.updatedAt,
      ...(membership.removedAt === undefined
        ? {}
        : { removedAt: membership.removedAt }),
    })),
    ownerPrincipalIds: manifest.ownerPrincipalIds,
    keyEnvelopes: manifest.keyEnvelopes.map(keyEnvelopeAuthorizationCore),
    approvalPolicy: manifest.approvalPolicy,
  });
}

async function authenticateDevice(
  manifest: CollaborativeMembershipManifest,
  certificateInput: DeviceCertificate,
  at: Timestamp,
  role?: CollaborationMembership['role'],
): Promise<DeviceCertificate> {
  const certificate = deviceCertificateSchema.parse(certificateInput);
  const membership = unique(
    manifest.memberships.filter(
      (candidate) =>
        candidate.principalId === certificate.principalId &&
        candidate.state === 'active' &&
        (role === undefined || candidate.role === role),
    ),
  );
  const pinned = unique(
    membership.devices.filter(
      (candidate) =>
        candidate.deviceId === certificate.deviceId && candidate.state === 'active',
    ),
  );
  if (canonicalJson(pinned) !== canonicalJson(certificate)) fail();
  return await verifyDeviceCertificate(
    certificate,
    {
      principalId: membership.principalId,
      rootSigningPublicKey: membership.rootSigningPublicKey,
    },
    { at },
  );
}

function exactDevice(
  manifest: CollaborativeMembershipManifest,
  principalId: string,
  deviceId: string,
): DeviceCertificate {
  const membership = unique(
    manifest.memberships.filter(
      (candidate) =>
        candidate.principalId === principalId && candidate.state === 'active',
    ),
  );
  return unique(
    membership.devices.filter(
      (candidate) => candidate.deviceId === deviceId && candidate.state === 'active',
    ),
  );
}

function tupleFields(prior: ParsedPrior): CollaborationRevisionTuple {
  return {
    authorityEpoch: prior.tuple.authorityEpoch,
    databaseDeviceGeneration: prior.tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: prior.tuple.databaseDeviceRegistryDigest,
    documentRevision: prior.tuple.documentRevision,
    membershipRevision: prior.tuple.membershipRevision,
    policyRevision: prior.tuple.policyRevision,
    keyEpoch: prior.tuple.keyEpoch,
    authorizationStateDigest: prior.tuple.authorizationStateDigest,
  };
}

function assertTransferTuple(prior: ParsedPrior, intent: TransferIntent): void {
  if (
    intent.databaseId !== prior.document.databaseId ||
    intent.vaultId !== prior.document.vaultId ||
    intent.currentHeadDigest !== prior.document.headDigest ||
    intent.authorityEpoch !== prior.tuple.authorityEpoch ||
    intent.databaseDeviceGeneration !== prior.tuple.databaseDeviceGeneration ||
    intent.databaseDeviceRegistryDigest !== prior.tuple.databaseDeviceRegistryDigest ||
    intent.documentRevision !== prior.tuple.documentRevision ||
    intent.membershipRevision !== prior.tuple.membershipRevision ||
    intent.policyRevision !== prior.tuple.policyRevision ||
    intent.keyEpoch !== prior.tuple.keyEpoch ||
    intent.authorizationStateDigest !== prior.tuple.authorizationStateDigest
  ) {
    fail();
  }
}

function assertExactTransferMembershipChange(
  intent: TransferIntent,
  priorMemberships: readonly CollaborationMembership[],
  nextMemberships: readonly CollaborationMembership[],
): void {
  if (priorMemberships.length !== nextMemberships.length) fail();
  const nextById = new Map(
    nextMemberships.map((membership) => [membership.membershipId, membership]),
  );
  if (
    nextById.size !== nextMemberships.length ||
    new Set(nextMemberships.map((membership) => membership.principalId)).size !==
      nextMemberships.length
  ) {
    fail();
  }
  for (const prior of priorMemberships) {
    const next = nextById.get(prior.membershipId);
    if (
      next?.principalId !== prior.principalId ||
      canonicalJson(membershipStableCore(next)) !==
        canonicalJson(membershipStableCore(prior))
    ) {
      fail();
    }
    if (prior.principalId === intent.recipientPrincipalId) {
      if (next.state !== 'active' || next.role !== 'owner') fail();
    } else if (prior.principalId === intent.initiatorPrincipalId) {
      const dispositionMatches =
        intent.originalOwnerDisposition === 'remain-owner'
          ? next.state === 'active' && next.role === 'owner'
          : intent.originalOwnerDisposition === 'editor'
            ? next.state === 'active' && next.role === 'editor'
            : intent.originalOwnerDisposition === 'reader'
              ? next.state === 'active' && next.role === 'reader'
              : next.state !== 'active';
      if (!dispositionMatches) fail();
    } else if (canonicalJson(next) !== canonicalJson(prior)) {
      fail();
    }
  }
}

function membershipStableCore(
  membership: CollaborationMembership,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...membership };
  Reflect.deleteProperty(result, 'role');
  Reflect.deleteProperty(result, 'state');
  Reflect.deleteProperty(result, 'updatedAt');
  Reflect.deleteProperty(result, 'removedAt');
  return result;
}

function requesterFact(request: ApprovalRequest): VerifiedRequesterSignature {
  return {
    approvalRequestId: request.approvalRequestId,
    requesterPrincipalId: request.requestingPrincipalId,
    requesterDeviceId: request.requestingDeviceId,
    signedRequestDigest: request.requestDigest,
    signature: request.requesterSignature,
  };
}

function deviceAuthorizationCore(
  device: DeviceCertificate,
): Omit<DeviceCertificate, 'rootSignature'> {
  const result = { ...device };
  Reflect.deleteProperty(result, 'rootSignature');
  return result;
}

function keyEnvelopeAuthorizationCore(
  envelope: CollaborativeMembershipManifest['keyEnvelopes'][number],
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...envelope };
  Reflect.deleteProperty(result, 'envelopeDigest');
  Reflect.deleteProperty(result, 'createdAt');
  Reflect.deleteProperty(result, 'ownerSignature');
  return result;
}

function copySigningKey(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== 64) fail();
  return Uint8Array.from(value);
}

function approvalEvidenceTime(request: ApprovalRequest): Timestamp {
  const latest = request.approvals.reduce(
    (value, evidence) => Math.max(value, Date.parse(evidence.approvedAt)),
    Date.parse(request.createdAt),
  );
  if (!Number.isFinite(latest) || latest >= Date.parse(request.expiresAt)) fail();
  return timestampSchema.parse(new Date(latest).toISOString());
}

function transferEvidenceTime(intent: TransferIntent): Timestamp {
  const latest = Math.max(
    Date.parse(requireValue(intent.initiatorSignedAt)),
    intent.recipientAcceptance === undefined
      ? Number.NEGATIVE_INFINITY
      : Date.parse(intent.recipientAcceptance.acceptedAt),
  );
  if (!Number.isFinite(latest) || latest >= Date.parse(intent.expiresAt)) fail();
  return timestampSchema.parse(new Date(latest).toISOString());
}

function isOpenApprovalState(
  value: ApprovalRequest['state'],
): value is OpenApprovalState {
  return value === 'pending' || value === 'quorum-reached';
}

function unique<T>(values: readonly T[]): T {
  if (values.length !== 1 || values[0] === undefined) fail();
  return values[0];
}

function requireValue<T>(value: T | undefined): T {
  if (value === undefined) fail();
  return value;
}

function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) {
      freeze(nested);
    }
    Object.freeze(value);
  }
  return value;
}

function fail(): never {
  throw new CollaborationAuthorizationWorkflowError();
}
