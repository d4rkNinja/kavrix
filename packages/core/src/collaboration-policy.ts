import type {
  ApprovalEvidence,
  ApprovalRequest,
  CollaborationDatabaseDeviceRegistry,
  CollaborationMembership,
  CollaborationPolicyState,
  CollaborationRevisionTuple,
  DeviceCertificate,
  Sha256Digest,
  Timestamp,
  TransferIntent,
} from '@kavrix/schemas';

/** The canonical operation union is owned by the schemas package. */
export type CollaborationOperationType = ApprovalRequest['operationType'];
export type CollaborationRole = CollaborationMembership['role'];

export type CollaborationPolicyErrorCode =
  | 'invalid-input'
  | 'operation-not-supported'
  | 'unauthorized-role'
  | 'inactive-actor'
  | 'approval-invalid'
  | 'approval-policy-stale'
  | 'approval-stale'
  | 'approval-expired'
  | 'approval-self'
  | 'approval-duplicate'
  | 'approval-already-consumed'
  | 'approval-quorum-invalid'
  | 'revision-advance-invalid'
  | 'key-rotation-required'
  | 'authority-epoch-change'
  | 'device-generation-stale'
  | 'device-generation-future'
  | 'device-denied'
  | 'device-registry-digest-mismatch'
  | 'rekey-required'
  | 'active-owner-required'
  | 'last-owner-protected'
  | 'owner-index-invalid'
  | 'transfer-invalid'
  | 'transfer-expired'
  | 'transfer-stale'
  | 'transfer-signature-required'
  | 'transfer-acceptance-invalid'
  | 'transfer-state-invalid';

/** A typed, non-secret policy failure. */
export class CollaborationPolicyError extends Error {
  readonly code: CollaborationPolicyErrorCode;

  constructor(code: CollaborationPolicyErrorCode, message: string) {
    super(message);
    this.name = 'CollaborationPolicyError';
    this.code = code;
  }
}

const OPERATION_TYPES: readonly CollaborationOperationType[] = [
  'ordinary-write',
  'add-member',
  'add-device',
  'remove-member',
  'revoke-device',
  'change-role',
  'rotate-key',
  'change-policy',
  'transfer-owner',
  'destroy-vault',
  'recover-owner',
  'emergency-rekey',
];

/**
 * Genesis is deliberately excluded from normal role authorization. It is
 * accepted only by the dedicated migration boundary, but it still uses the
 * exact tuple-transition rules once that boundary has authenticated it.
 */
const TRANSITION_OPERATION_TYPES: readonly CollaborationOperationType[] = [
  'genesis-migration',
  ...OPERATION_TYPES,
];

const MEMBERSHIP_OPERATIONS: ReadonlySet<CollaborationOperationType> = new Set([
  'add-member',
  'add-device',
  'remove-member',
  'revoke-device',
  'change-role',
  'transfer-owner',
  'recover-owner',
]);

const MANDATORY_ROTATION_OPERATIONS: ReadonlySet<CollaborationOperationType> = new Set([
  'add-member',
  'add-device',
  'remove-member',
  'revoke-device',
  'rotate-key',
  'recover-owner',
  'emergency-rekey',
]);

const GENERATION_CHANGE_OPERATIONS: ReadonlySet<CollaborationOperationType> = new Set([
  'revoke-device',
  'rotate-key',
  'emergency-rekey',
]);

function knownOperation(value: string): value is CollaborationOperationType {
  return OPERATION_TYPES.includes(value as CollaborationOperationType);
}

function knownTransitionOperation(value: string): value is CollaborationOperationType {
  return TRANSITION_OPERATION_TYPES.includes(value as CollaborationOperationType);
}

function error(
  code: CollaborationPolicyErrorCode,
  message: string,
): CollaborationPolicyError {
  return new CollaborationPolicyError(code, message);
}

function timestampMillis(value: string): number | undefined {
  const result = Date.parse(value);
  return Number.isFinite(result) ? result : undefined;
}

function atOrAfter(left: string, right: string): boolean {
  const leftMillis = timestampMillis(left);
  const rightMillis = timestampMillis(right);
  return (
    leftMillis !== undefined && rightMillis !== undefined && leftMillis >= rightMillis
  );
}

function before(left: string, right: string): boolean {
  const leftMillis = timestampMillis(left);
  const rightMillis = timestampMillis(right);
  return (
    leftMillis !== undefined && rightMillis !== undefined && leftMillis < rightMillis
  );
}

function atOrBefore(left: string, right: string): boolean {
  const leftMillis = timestampMillis(left);
  const rightMillis = timestampMillis(right);
  return (
    leftMillis !== undefined && rightMillis !== undefined && leftMillis <= rightMillis
  );
}

function intentTupleMatches(
  intent: TransferIntent,
  tuple: CollaborationRevisionTuple,
): boolean {
  return (
    intent.authorityEpoch === tuple.authorityEpoch &&
    intent.documentRevision === tuple.documentRevision &&
    intent.membershipRevision === tuple.membershipRevision &&
    intent.policyRevision === tuple.policyRevision &&
    intent.keyEpoch === tuple.keyEpoch &&
    intent.databaseDeviceGeneration === tuple.databaseDeviceGeneration &&
    intent.databaseDeviceRegistryDigest === tuple.databaseDeviceRegistryDigest &&
    intent.authorizationStateDigest === tuple.authorizationStateDigest
  );
}

/**
 * The database registry is an exceptional deny fence, not a positive
 * allowlist. A root-certified active member remains eligible when it is absent
 * from this list. A denial may bind the exact device identity or a verified
 * signing-key fingerprint.
 */
function registryDeniesDevice(
  registry: CollaborationDatabaseDeviceRegistry,
  device: DeviceCertificate,
  signingKeyFingerprint: Sha256Digest | undefined,
): boolean {
  return registry.deniedDevices.some(
    (denial) =>
      (denial.principalId === device.principalId &&
        denial.deviceId === device.deviceId) ||
      (signingKeyFingerprint !== undefined &&
        denial.signingKeyFingerprint === signingKeyFingerprint),
  );
}

function activeOwners(
  memberships: readonly CollaborationMembership[],
): readonly CollaborationMembership[] {
  return memberships.filter(
    (membership) => membership.state === 'active' && membership.role === 'owner',
  );
}

function activeOwnerIds(
  memberships: readonly CollaborationMembership[],
): readonly string[] {
  return activeOwners(memberships).map((membership) => membership.principalId);
}

function activeOwnerDevice(
  memberships: readonly CollaborationMembership[],
  principalId: string,
  deviceId: string,
): DeviceCertificate | undefined {
  const owner = activeOwners(memberships).find(
    (membership) => membership.principalId === principalId,
  );
  return owner?.devices.find(
    (device) => device.deviceId === deviceId && device.state === 'active',
  );
}

export interface OperationAuthorizationInput {
  readonly operationType: CollaborationOperationType;
  readonly membership: CollaborationMembership;
  readonly device: DeviceCertificate;
  /** An already-verified global deny/recovery fence, when available. */
  readonly authoritativeRegistry?: CollaborationDatabaseDeviceRegistry;
  /** Fingerprint computed by the crypto/verifier boundary for this device key. */
  readonly deviceSigningKeyFingerprint?: Sha256Digest;
}

export interface OperationAuthorizationResult {
  readonly authorized: boolean;
  readonly role: CollaborationRole;
  readonly error: CollaborationPolicyError | undefined;
}

/**
 * Authorize only the role/lifecycle portion of a mutation. Approval policy is
 * intentionally absent: accepted administrative mutations must pass the full
 * `validateApproval` check separately.
 */
export function authorizeOperation(
  input: OperationAuthorizationInput,
): OperationAuthorizationResult {
  const { operationType, membership, device } = input;
  const role = membership.role;
  if (!knownOperation(operationType)) {
    const failure = error(
      'operation-not-supported',
      'Unknown collaboration operation.',
    );
    return { authorized: false, role, error: failure };
  }
  if (
    membership.state !== 'active' ||
    device.state !== 'active' ||
    device.principalId !== membership.principalId ||
    !membership.devices.some(
      (candidate) =>
        candidate.deviceId === device.deviceId &&
        candidate.principalId === device.principalId &&
        candidate.state === 'active',
    )
  ) {
    const failure = error(
      'inactive-actor',
      'Only an active membership and one of its active devices may authorize a mutation.',
    );
    return { authorized: false, role, error: failure };
  }
  if (
    input.authoritativeRegistry !== undefined &&
    registryDeniesDevice(
      input.authoritativeRegistry,
      device,
      input.deviceSigningKeyFingerprint,
    )
  ) {
    const failure = error(
      'device-denied',
      'The device is explicitly denied by the authoritative database fence.',
    );
    return { authorized: false, role, error: failure };
  }
  const authorized =
    role === 'owner' || (role === 'editor' && operationType === 'ordinary-write');
  if (!authorized) {
    const failure = error(
      'unauthorized-role',
      role === 'reader'
        ? 'Readers may decrypt but cannot create accepted mutations.'
        : 'This role is not authorized for the requested operation.',
    );
    return { authorized: false, role, error: failure };
  }
  return { authorized: true, role, error: undefined };
}

export interface RevisionTransitionInput {
  readonly operationType: CollaborationOperationType;
  readonly prior: CollaborationRevisionTuple;
  readonly next: CollaborationRevisionTuple;
  /** Required only to opt transfer/recovery into a decrypt-access rotation. */
  readonly decryptAccessChanged?: boolean;
  /** Required when the candidate moves to a newer global registry generation. */
  readonly authoritativeRegistry?: CollaborationDatabaseDeviceRegistry;
  /** Present for every administrative/genesis transition; absent for ordinary writes. */
  readonly authorizationTransitionDigest?: Sha256Digest;
}

export interface RevisionTransitionResult {
  readonly valid: boolean;
  readonly documentRevisionDelta: number;
  readonly membershipRevisionDelta: number;
  readonly policyRevisionDelta: number;
  readonly keyEpochDelta: number;
  readonly databaseDeviceGenerationDelta: number;
  readonly keyRotationRequired: boolean;
  readonly error: CollaborationPolicyError | undefined;
}

function transitionResult(
  input: RevisionTransitionInput,
  keyRotationRequired: boolean,
  transitionError: CollaborationPolicyError | undefined,
): RevisionTransitionResult {
  const { prior, next } = input;
  return {
    valid: transitionError === undefined,
    documentRevisionDelta: next.documentRevision - prior.documentRevision,
    membershipRevisionDelta: next.membershipRevision - prior.membershipRevision,
    policyRevisionDelta: next.policyRevision - prior.policyRevision,
    keyEpochDelta: next.keyEpoch - prior.keyEpoch,
    databaseDeviceGenerationDelta:
      next.databaseDeviceGeneration - prior.databaseDeviceGeneration,
    keyRotationRequired,
    error: transitionError,
  };
}

/** Validate all exact monotonic tuple deltas for one accepted mutation. */
export function validateRevisionTransition(
  input: RevisionTransitionInput,
): RevisionTransitionResult {
  const { operationType, prior, next, authoritativeRegistry } = input;
  if (!knownTransitionOperation(operationType)) {
    return transitionResult(
      input,
      false,
      error('operation-not-supported', 'Unknown collaboration operation.'),
    );
  }
  const genesis = operationType === 'genesis-migration';
  const decryptAccessChanged = input.decryptAccessChanged === true;
  const keyRotationRequired =
    (!genesis && MANDATORY_ROTATION_OPERATIONS.has(operationType)) ||
    (operationType === 'transfer-owner' && decryptAccessChanged);
  const expectedMembershipDelta =
    genesis || MEMBERSHIP_OPERATIONS.has(operationType) ? 1 : 0;
  const expectedPolicyDelta = genesis || operationType === 'change-policy' ? 1 : 0;
  const expectedKeyDelta = keyRotationRequired ? 1 : 0;
  const documentDelta = next.documentRevision - prior.documentRevision;
  const membershipDelta = next.membershipRevision - prior.membershipRevision;
  const policyDelta = next.policyRevision - prior.policyRevision;
  const keyDelta = next.keyEpoch - prior.keyEpoch;
  const generationDelta =
    next.databaseDeviceGeneration - prior.databaseDeviceGeneration;

  let transitionError: CollaborationPolicyError | undefined;
  if (next.authorityEpoch !== prior.authorityEpoch) {
    transitionError = error(
      'authority-epoch-change',
      'Authority epoch replacement is outside ordinary collaboration transitions.',
    );
  } else if (
    documentDelta !== 1 ||
    membershipDelta !== expectedMembershipDelta ||
    policyDelta !== expectedPolicyDelta ||
    keyDelta !== expectedKeyDelta
  ) {
    transitionError = error(
      keyDelta !== expectedKeyDelta
        ? 'key-rotation-required'
        : 'revision-advance-invalid',
      'The mutation does not advance the exact protocol-defined tuple fields.',
    );
  } else if (
    operationType === 'ordinary-write' &&
    (next.authorizationStateDigest !== prior.authorizationStateDigest ||
      input.authorizationTransitionDigest !== undefined)
  ) {
    transitionError = error(
      'revision-advance-invalid',
      'Ordinary writes must retain the authorization-state digest and cannot carry an authorization transition.',
    );
  } else if (
    operationType === 'destroy-vault' &&
    (next.authorizationStateDigest !== prior.authorizationStateDigest ||
      input.authorizationTransitionDigest === undefined)
  ) {
    transitionError = error(
      'revision-advance-invalid',
      'Vault destruction must retain authorization state and carry its signed authorization transition.',
    );
  } else if (
    operationType !== 'ordinary-write' &&
    operationType !== 'destroy-vault' &&
    (next.authorizationStateDigest === prior.authorizationStateDigest ||
      input.authorizationTransitionDigest === undefined)
  ) {
    transitionError = error(
      'revision-advance-invalid',
      'Administrative and genesis transitions must change authorization state and carry a transition digest.',
    );
  } else if (generationDelta < 0) {
    transitionError = error(
      'device-generation-stale',
      'Database device generations cannot move backwards.',
    );
  } else if (
    generationDelta === 0 &&
    next.databaseDeviceRegistryDigest !== prior.databaseDeviceRegistryDigest
  ) {
    transitionError = error(
      'device-registry-digest-mismatch',
      'An unchanged database device generation must retain its registry digest.',
    );
  } else if (
    generationDelta > 0 &&
    next.databaseDeviceRegistryDigest === prior.databaseDeviceRegistryDigest
  ) {
    transitionError = error(
      'device-registry-digest-mismatch',
      'A changed database device generation requires a new registry digest.',
    );
  } else if (generationDelta > 0 && !GENERATION_CHANGE_OPERATIONS.has(operationType)) {
    transitionError = error(
      'rekey-required',
      'Only revoke, explicit rotation, or emergency rekey transitions may change the global device generation.',
    );
  } else if (generationDelta > 0 && keyDelta !== 1) {
    transitionError = error(
      'rekey-required',
      'A transition catching up to a newer device registry must rotate its VRK.',
    );
  } else if (
    authoritativeRegistry !== undefined &&
    (next.databaseDeviceGeneration !== authoritativeRegistry.generation ||
      next.databaseDeviceRegistryDigest !== authoritativeRegistry.registryDigest)
  ) {
    transitionError = error(
      'device-registry-digest-mismatch',
      'The candidate tuple must bind the explicitly supplied authoritative registry.',
    );
  } else if (generationDelta > 0 && authoritativeRegistry === undefined) {
    transitionError = error(
      'invalid-input',
      'An authoritative registry is required when the database device generation changes.',
    );
  }
  return transitionResult(input, keyRotationRequired, transitionError);
}

export interface DeviceFenceInput {
  readonly vault: CollaborationRevisionTuple;
  readonly authoritativeRegistry: CollaborationDatabaseDeviceRegistry;
  /** Optional active member device whose write is being fenced. */
  readonly actorDevice?: DeviceCertificate;
  /** Independently verified signing-key fingerprint for `actorDevice`. */
  readonly actorSigningKeyFingerprint?: Sha256Digest;
}

export type DeviceFenceStatus =
  | 'current'
  | 'rekey-required'
  | 'future-generation'
  | 'digest-mismatch'
  | 'device-denied';

export interface DeviceFenceResult {
  readonly canWrite: boolean;
  readonly rekeyRequired: boolean;
  readonly status: DeviceFenceStatus;
  readonly error: CollaborationPolicyError | undefined;
}

/** Compare a vault's referenced generation/digest to the signed global fence. */
export function evaluateDeviceFence(input: DeviceFenceInput): DeviceFenceResult {
  const { vault, authoritativeRegistry } = input;
  let status: DeviceFenceStatus;
  let fenceError: CollaborationPolicyError | undefined;
  let rekeyRequired = false;
  if (vault.databaseDeviceGeneration < authoritativeRegistry.generation) {
    status = 'rekey-required';
    rekeyRequired = true;
    fenceError = error(
      'rekey-required',
      'The vault references a pre-revocation database device generation and must be rekeyed.',
    );
  } else if (vault.databaseDeviceGeneration > authoritativeRegistry.generation) {
    status = 'future-generation';
    fenceError = error(
      'device-generation-future',
      'The vault references a generation newer than the authoritative registry.',
    );
  } else if (
    vault.databaseDeviceRegistryDigest !== authoritativeRegistry.registryDigest
  ) {
    status = 'digest-mismatch';
    fenceError = error(
      'device-registry-digest-mismatch',
      'The vault and authoritative registry disagree at the same generation.',
    );
  } else if (
    input.actorDevice !== undefined &&
    registryDeniesDevice(
      authoritativeRegistry,
      input.actorDevice,
      input.actorSigningKeyFingerprint,
    )
  ) {
    status = 'device-denied';
    fenceError = error(
      'device-denied',
      'The actor device is explicitly denied by the authoritative database fence.',
    );
  } else {
    status = 'current';
  }
  const current = status === 'current';
  return {
    canWrite: current,
    rekeyRequired,
    status,
    error: fenceError,
  };
}

export interface ActiveOwnerInvariantInput {
  readonly memberships: readonly CollaborationMembership[];
  readonly ownerPrincipalIds?: readonly string[];
  /** Audit fact only; recovery never permits an ownerless committed state. */
  readonly authorityRecoveryRecorded?: boolean;
}

export interface ActiveOwnerInvariantResult {
  readonly valid: boolean;
  readonly activeOwnerPrincipalIds: readonly string[];
  readonly ownerIndexMatches: boolean;
  readonly error: CollaborationPolicyError | undefined;
}

/** Check that active owners and the optional manifest owner index are coherent. */
export function checkActiveOwnerInvariant(
  input: ActiveOwnerInvariantInput,
): ActiveOwnerInvariantResult {
  const owners = activeOwners(input.memberships);
  const ownerIds = owners.map((owner) => owner.principalId);
  const uniqueOwnerIds = new Set<string>(ownerIds);
  const ownerIndexMatches =
    input.ownerPrincipalIds === undefined ||
    (input.ownerPrincipalIds.length === uniqueOwnerIds.size &&
      input.ownerPrincipalIds.every((principalId) => uniqueOwnerIds.has(principalId)));
  let invariantError: CollaborationPolicyError | undefined;
  if (uniqueOwnerIds.size !== ownerIds.length) {
    invariantError = error(
      'owner-index-invalid',
      'Active owner memberships must identify distinct principals.',
    );
  } else if (!ownerIndexMatches) {
    invariantError = error(
      'owner-index-invalid',
      'The owner index must enumerate exactly the active owner principals.',
    );
  } else if (owners.length === 0) {
    invariantError = error(
      'active-owner-required',
      'A collaborative vault must retain an active owner unless authority recovery is recorded.',
    );
  } else if (
    owners.some((owner) => !owner.devices.some((device) => device.state === 'active'))
  ) {
    invariantError = error(
      'active-owner-required',
      'Every active owner must retain an active device.',
    );
  }
  return {
    valid: invariantError === undefined,
    activeOwnerPrincipalIds: ownerIds,
    ownerIndexMatches,
    error: invariantError,
  };
}

export interface OwnerTransitionInput {
  readonly priorMemberships: readonly CollaborationMembership[];
  readonly nextMemberships: readonly CollaborationMembership[];
  readonly authorityRecoveryRecorded: boolean;
}

export interface OwnerTransitionResult extends ActiveOwnerInvariantResult {
  readonly priorActiveOwnerPrincipalIds: readonly string[];
  readonly appointedOwner: boolean;
}

/** Validate the owner invariant across one atomic membership transition. */
export function validateOwnerTransition(
  input: OwnerTransitionInput,
): OwnerTransitionResult {
  const priorOwnerIds = activeOwnerIds(input.priorMemberships);
  const nextResult = checkActiveOwnerInvariant({
    memberships: input.nextMemberships,
    authorityRecoveryRecorded: input.authorityRecoveryRecorded,
  });
  const appointedOwner = nextResult.activeOwnerPrincipalIds.some(
    (principalId) => !priorOwnerIds.includes(principalId),
  );
  const transitionError =
    priorOwnerIds.length === 1 && nextResult.activeOwnerPrincipalIds.length === 0
      ? error(
          'last-owner-protected',
          'The last active owner cannot be removed or demoted without an atomic replacement owner.',
        )
      : nextResult.error;
  return {
    ...nextResult,
    valid: transitionError === undefined,
    priorActiveOwnerPrincipalIds: priorOwnerIds,
    appointedOwner,
    error: transitionError,
  };
}

export interface ApprovalValidationInput {
  readonly request: ApprovalRequest;
  /** The policy committed before the request's operation. */
  readonly priorPolicy: CollaborationPolicyState;
  readonly priorTuple: CollaborationRevisionTuple;
  readonly priorHeadDigest: Sha256Digest;
  readonly activeMemberships: readonly CollaborationMembership[];
  readonly now: Timestamp;
  /** Opaque fact returned after verifying the requester signature. */
  readonly verifiedRequesterSignature: VerifiedRequesterSignature;
  /** Opaque facts returned by an Ed25519 verifier for each evidence item. */
  readonly verifiedApprovalSignatures: readonly VerifiedApprovalSignature[];
}

/** A verifier-produced fact bound to the immutable request signer and bytes. */
export interface VerifiedRequesterSignature {
  readonly approvalRequestId: ApprovalRequest['approvalRequestId'];
  readonly requesterPrincipalId: ApprovalRequest['requestingPrincipalId'];
  readonly requesterDeviceId: ApprovalRequest['requestingDeviceId'];
  readonly signedRequestDigest: Sha256Digest;
  readonly signature: ApprovalRequest['requesterSignature'];
}

/** A verifier-produced fact bound to one canonical approval evidence record. */
export interface VerifiedApprovalSignature {
  readonly approvalRequestId: ApprovalRequest['approvalRequestId'];
  readonly approverPrincipalId: ApprovalEvidence['approverPrincipalId'];
  readonly approverDeviceId: ApprovalEvidence['approverDeviceId'];
  readonly signedRequestDigest: Sha256Digest;
  readonly signature: ApprovalEvidence['signature'];
}

export interface ApprovalValidationResult {
  readonly valid: boolean;
  readonly eligibleForConsumption: boolean;
  readonly consumed: boolean;
  readonly error: CollaborationPolicyError | undefined;
}

function approvalTupleMatches(
  request: ApprovalRequest,
  tuple: CollaborationRevisionTuple,
): boolean {
  return (
    request.authorityEpoch === tuple.authorityEpoch &&
    request.documentRevision === tuple.documentRevision &&
    request.membershipRevision === tuple.membershipRevision &&
    request.policyRevision === tuple.policyRevision &&
    request.keyEpoch === tuple.keyEpoch &&
    request.databaseDeviceGeneration === tuple.databaseDeviceGeneration &&
    request.databaseDeviceRegistryDigest === tuple.databaseDeviceRegistryDigest &&
    request.authorizationStateDigest === tuple.authorizationStateDigest
  );
}

function approvalEvidenceMatches(
  request: ApprovalRequest,
  evidence: ApprovalEvidence,
): boolean {
  return (
    evidence.approvalRequestId === request.approvalRequestId &&
    evidence.operationId === request.operationId &&
    evidence.databaseId === request.databaseId &&
    evidence.vaultId === request.vaultId &&
    evidence.requestDigest === request.requestDigest &&
    evidence.authorityEpoch === request.authorityEpoch &&
    evidence.databaseDeviceGeneration === request.databaseDeviceGeneration &&
    evidence.databaseDeviceRegistryDigest === request.databaseDeviceRegistryDigest &&
    evidence.documentRevision === request.documentRevision &&
    evidence.membershipRevision === request.membershipRevision &&
    evidence.policyRevision === request.policyRevision &&
    evidence.keyEpoch === request.keyEpoch &&
    evidence.priorHeadDigest === request.priorHeadDigest &&
    evidence.authorizationStateDigest === request.authorizationStateDigest &&
    evidence.requestingPrincipalId === request.requestingPrincipalId
  );
}

/** Validate one exact approval request and report whether it may be consumed. */
export function validateApproval(
  input: ApprovalValidationInput,
): ApprovalValidationResult {
  const { request, priorPolicy, priorTuple, priorHeadDigest, activeMemberships, now } =
    input;
  let validationError: CollaborationPolicyError | undefined;
  if (!knownOperation(request.operationType)) {
    validationError = error(
      'operation-not-supported',
      'Genesis migration is authorized only by its dedicated migration boundary.',
    );
  } else if (request.requiredApprovalPolicy !== priorPolicy.approvalPolicy) {
    validationError = error(
      'approval-policy-stale',
      'Approval evidence must use the policy active before the mutation.',
    );
  } else if (
    request.databaseId !== priorPolicy.databaseId ||
    request.vaultId !== priorPolicy.vaultId ||
    request.authorityEpoch !== priorPolicy.authorityEpoch ||
    request.databaseDeviceGeneration !== priorPolicy.databaseDeviceGeneration ||
    request.databaseDeviceRegistryDigest !== priorPolicy.databaseDeviceRegistryDigest ||
    request.policyRevision !== priorPolicy.policyRevision
  ) {
    validationError = error(
      'approval-stale',
      'Approval policy metadata does not bind the exact prior state.',
    );
  } else if (
    !approvalTupleMatches(request, priorTuple) ||
    request.priorHeadDigest !== priorHeadDigest
  ) {
    validationError = error(
      'approval-stale',
      'Approval request does not bind the exact prior revision tuple and head.',
    );
  } else if (request.operationType === 'ordinary-write') {
    validationError = error(
      'approval-invalid',
      'Ordinary writes do not use administrative approval requests.',
    );
  } else if (!atOrAfter(now, request.createdAt) || !before(now, request.expiresAt)) {
    validationError = error(
      'approval-expired',
      'The approval request is not currently unexpired.',
    );
  }

  const requester = activeOwnerDevice(
    activeMemberships,
    request.requestingPrincipalId,
    request.requestingDeviceId,
  );
  if (validationError === undefined && requester === undefined) {
    validationError = error(
      'unauthorized-role',
      'Only an active owner device may request an owner-gated mutation.',
    );
  }
  if (
    validationError === undefined &&
    (input.verifiedRequesterSignature.approvalRequestId !== request.approvalRequestId ||
      input.verifiedRequesterSignature.requesterPrincipalId !==
        request.requestingPrincipalId ||
      input.verifiedRequesterSignature.requesterDeviceId !==
        request.requestingDeviceId ||
      input.verifiedRequesterSignature.signedRequestDigest !== request.requestDigest ||
      input.verifiedRequesterSignature.signature !== request.requesterSignature)
  ) {
    validationError = error(
      'approval-invalid',
      'The verifier fact must bind the requester device to the exact request digest and signature.',
    );
  }

  if (validationError === undefined && request.requiredApprovalPolicy === 'none') {
    if (request.approvals.length !== 0) {
      validationError = error(
        'approval-invalid',
        'An approval-free policy cannot carry approval evidence.',
      );
    } else if (request.state === 'consumed') {
      validationError = error(
        'approval-already-consumed',
        'A consumed approval request cannot be replayed.',
      );
    }
  }

  if (
    validationError === undefined &&
    request.requiredApprovalPolicy === 'one-additional-owner'
  ) {
    if (request.state === 'consumed') {
      validationError = error(
        'approval-already-consumed',
        'Approval evidence has already been consumed.',
      );
    } else if (
      (request.state === 'pending' && request.approvals.length !== 0) ||
      (request.state === 'quorum-reached' && request.approvals.length !== 1)
    ) {
      validationError = error(
        'approval-quorum-invalid',
        'The approval state and evidence count do not match the one-additional-owner policy.',
      );
    } else if (
      request.state === 'expired' ||
      request.state === 'cancelled' ||
      request.state === 'conflicted'
    ) {
      validationError = error(
        request.state === 'expired' ? 'approval-expired' : 'approval-invalid',
        'A terminal approval request cannot authorize a mutation.',
      );
    }
  }

  const approverPrincipals = new Set<string>();
  const approverDevices = new Set<string>();
  const verifiedSignatures = input.verifiedApprovalSignatures;
  if (verifiedSignatures.length !== request.approvals.length) {
    validationError ??= error(
      'approval-invalid',
      'Every approval evidence item requires a verifier-produced signature fact.',
    );
  }
  for (const evidence of request.approvals) {
    if (validationError !== undefined) break;
    if (evidence.requestingPrincipalId === evidence.approverPrincipalId) {
      validationError = error(
        'approval-self',
        'The requesting principal cannot approve its own request.',
      );
    } else if (
      approverPrincipals.has(evidence.approverPrincipalId) ||
      approverDevices.has(evidence.approverDeviceId)
    ) {
      validationError = error(
        'approval-duplicate',
        'Approval evidence must come from one distinct owner and device.',
      );
    } else if (!approvalEvidenceMatches(request, evidence)) {
      validationError = error(
        'approval-stale',
        'Approval evidence does not bind the exact approval request tuple.',
      );
    } else if (
      !atOrAfter(evidence.approvedAt, request.createdAt) ||
      !before(evidence.approvedAt, request.expiresAt) ||
      !atOrBefore(evidence.approvedAt, now)
    ) {
      validationError = error(
        'approval-expired',
        'Approval evidence must be created inside the unexpired request lifetime.',
      );
    } else if (
      activeOwnerDevice(
        activeMemberships,
        evidence.approverPrincipalId,
        evidence.approverDeviceId,
      ) === undefined
    ) {
      validationError = error(
        'approval-invalid',
        'The approver must be an active owner using an active owner device.',
      );
    } else if (
      !verifiedSignatures.some(
        (verification) =>
          verification.approvalRequestId === evidence.approvalRequestId &&
          verification.approverPrincipalId === evidence.approverPrincipalId &&
          verification.approverDeviceId === evidence.approverDeviceId &&
          verification.signedRequestDigest === request.requestDigest &&
          verification.signature === evidence.signature,
      )
    ) {
      validationError = error(
        'approval-invalid',
        'The verifier fact must bind the exact approval signer and request digest.',
      );
    }
    approverPrincipals.add(evidence.approverPrincipalId);
    approverDevices.add(evidence.approverDeviceId);
  }

  const valid = validationError === undefined;
  const eligibleForConsumption =
    valid &&
    request.requiredApprovalPolicy === 'one-additional-owner' &&
    request.state === 'quorum-reached' &&
    request.approvals.length === 1;
  return {
    valid,
    eligibleForConsumption,
    consumed: request.state === 'consumed',
    error: validationError,
  };
}

export interface OwnershipTransferValidationInput {
  readonly intent: TransferIntent;
  readonly priorMemberships: readonly CollaborationMembership[];
  readonly nextMemberships: readonly CollaborationMembership[];
  readonly priorTuple: CollaborationRevisionTuple;
  readonly priorHeadDigest: Sha256Digest;
  readonly now: Timestamp;
  /** Opaque fact returned after verifying the initiator signature. */
  readonly initiatorSignatureVerification: VerifiedTransferSignature;
  /** Opaque fact returned after verifying the recipient acceptance signature. */
  readonly recipientAcceptanceVerification: VerifiedTransferSignature;
}

/** A verifier-produced fact for one exact transfer signature. */
export interface VerifiedTransferSignature {
  readonly signerPrincipalId: TransferIntent['initiatorPrincipalId'];
  readonly signerDeviceId: TransferIntent['initiatorDeviceId'];
  readonly signedIntentDigest: Sha256Digest;
  readonly signature: ApprovalEvidence['signature'];
}

export interface OwnershipTransferValidationResult {
  readonly valid: boolean;
  readonly complete: boolean;
  readonly initiatorSignatureValid: boolean;
  readonly recipientAcceptanceValid: boolean;
  readonly initiatorRemainsOwner: boolean;
  readonly recipientAppointed: boolean;
  readonly error: CollaborationPolicyError | undefined;
}

/** Validate both parties' exact, unexpired ownership-transfer bindings. */
export function validateOwnershipTransfer(
  input: OwnershipTransferValidationInput,
): OwnershipTransferValidationResult {
  const {
    intent,
    priorMemberships,
    nextMemberships,
    priorTuple,
    priorHeadDigest,
    now,
  } = input;
  const initiatorRemainsOwner = intent.originalOwnerDisposition === 'remain-owner';
  let validationError: CollaborationPolicyError | undefined;
  let initiatorSignatureValid = false;
  let recipientAcceptanceValid = false;
  let recipientAppointed = false;
  if (intent.state !== 'recipient-accepted' && intent.state !== 'published') {
    validationError = error(
      'transfer-state-invalid',
      'Ownership transfer publication requires recipient-accepted or published state.',
    );
  } else if (!atOrAfter(now, intent.createdAt) || !before(now, intent.expiresAt)) {
    validationError = error(
      'transfer-expired',
      'The ownership-transfer intent is expired.',
    );
  } else {
    if (
      !intentTupleMatches(intent, priorTuple) ||
      intent.currentHeadDigest !== priorHeadDigest
    ) {
      validationError = error(
        'transfer-stale',
        'The transfer intent must bind the exact prior tuple and head.',
      );
    } else if (
      activeOwnerDevice(
        priorMemberships,
        intent.initiatorPrincipalId,
        intent.initiatorDeviceId,
      ) === undefined
    ) {
      validationError = error(
        'unauthorized-role',
        'Only an active owner device may initiate ownership transfer.',
      );
    } else {
      initiatorSignatureValid =
        intent.initiatorSignature !== undefined &&
        intent.initiatorSignedAt !== undefined &&
        atOrAfter(intent.initiatorSignedAt, intent.createdAt) &&
        before(intent.initiatorSignedAt, intent.expiresAt) &&
        atOrBefore(intent.initiatorSignedAt, now);
      initiatorSignatureValid =
        initiatorSignatureValid &&
        input.initiatorSignatureVerification.signerPrincipalId ===
          intent.initiatorPrincipalId &&
        input.initiatorSignatureVerification.signerDeviceId ===
          intent.initiatorDeviceId &&
        input.initiatorSignatureVerification.signedIntentDigest ===
          intent.intentDigest &&
        input.initiatorSignatureVerification.signature === intent.initiatorSignature;
      if (!initiatorSignatureValid) {
        validationError = error(
          'transfer-signature-required',
          'The initiator signature must be present inside the unexpired intent lifetime.',
        );
      }
    }
  }

  const acceptance = intent.recipientAcceptance;
  if (validationError === undefined) {
    recipientAcceptanceValid =
      acceptance?.transferIntentId === intent.transferIntentId &&
      acceptance.operationId === intent.operationId &&
      acceptance.databaseId === intent.databaseId &&
      acceptance.vaultId === intent.vaultId &&
      acceptance.intentDigest === intent.intentDigest &&
      acceptance.authorityEpoch === intent.authorityEpoch &&
      acceptance.databaseDeviceGeneration === intent.databaseDeviceGeneration &&
      acceptance.databaseDeviceRegistryDigest === intent.databaseDeviceRegistryDigest &&
      acceptance.authorizationStateDigest === intent.authorizationStateDigest &&
      acceptance.recipientPrincipalId === intent.recipientPrincipalId &&
      acceptance.recipientDeviceId === intent.recipientDeviceId &&
      atOrAfter(acceptance.acceptedAt, intent.createdAt) &&
      before(acceptance.acceptedAt, intent.expiresAt) &&
      atOrBefore(acceptance.acceptedAt, now);
    recipientAcceptanceValid =
      recipientAcceptanceValid &&
      input.recipientAcceptanceVerification.signerPrincipalId ===
        intent.recipientPrincipalId &&
      input.recipientAcceptanceVerification.signerDeviceId ===
        intent.recipientDeviceId &&
      input.recipientAcceptanceVerification.signedIntentDigest ===
        intent.intentDigest &&
      input.recipientAcceptanceVerification.signature === acceptance?.signature;
    if (!recipientAcceptanceValid) {
      validationError = error(
        'transfer-acceptance-invalid',
        'Recipient acceptance must bind the exact unexpired transfer intent.',
      );
    }
  }

  if (validationError === undefined) {
    const recipient = activeOwnerDevice(
      nextMemberships,
      intent.recipientPrincipalId,
      intent.recipientDeviceId,
    );
    recipientAppointed = recipient !== undefined;
    if (!recipientAppointed) {
      validationError = error(
        'transfer-invalid',
        'The accepted recipient must be appointed as an active owner in the same transition.',
      );
    }
  }
  if (validationError === undefined) {
    const ownerTransition = validateOwnerTransition({
      priorMemberships,
      nextMemberships,
      authorityRecoveryRecorded: false,
    });
    if (!ownerTransition.valid) {
      validationError =
        ownerTransition.error ??
        error(
          'last-owner-protected',
          'The transfer violates the active-owner invariant.',
        );
    }
  }
  if (validationError === undefined) {
    const initiatorNextMembership = nextMemberships.find(
      (membership) => membership.principalId === intent.initiatorPrincipalId,
    );
    const dispositionMatches =
      intent.originalOwnerDisposition === 'remain-owner'
        ? initiatorNextMembership?.state === 'active' &&
          initiatorNextMembership.role === 'owner'
        : intent.originalOwnerDisposition === 'editor'
          ? initiatorNextMembership?.state === 'active' &&
            initiatorNextMembership.role === 'editor'
          : intent.originalOwnerDisposition === 'reader'
            ? initiatorNextMembership?.state === 'active' &&
              initiatorNextMembership.role === 'reader'
            : initiatorNextMembership !== undefined &&
              initiatorNextMembership.state !== 'active';
    if (!dispositionMatches) {
      validationError = error(
        'transfer-invalid',
        'The candidate membership state does not implement the initiator disposition.',
      );
    }
  }
  if (validationError === undefined && intent.state === 'published') {
    if (
      intent.publishedAt === undefined ||
      !atOrAfter(intent.publishedAt, intent.createdAt) ||
      !before(intent.publishedAt, intent.expiresAt) ||
      !atOrBefore(intent.publishedAt, now)
    ) {
      validationError = error(
        'transfer-state-invalid',
        'A published transfer requires publication inside the exact intent lifetime.',
      );
    }
  }
  const valid = validationError === undefined;
  return {
    valid,
    complete: valid,
    initiatorSignatureValid,
    recipientAcceptanceValid,
    initiatorRemainsOwner,
    recipientAppointed,
    error: validationError,
  };
}
