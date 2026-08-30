import {
  COLLABORATION_DOMAINS,
  computeMembershipHistoryCompactionDigest,
  computeMembershipHistoryDigest,
  signCollaborationRecord,
  verifyCollaborationRecord,
  zeroize,
  type DeviceSigningPrivateKey,
} from '@kavrix/crypto';
import {
  canonicalJson,
  collaborationOperationIdSchema,
  collaborationPublicKeySchema,
  collaborationRevisionTupleSchema,
  COLLABORATION_PROTOCOL_VERSION,
  databaseIdSchema,
  deviceIdSchema,
  historyIdSchema,
  MAX_COLLABORATIVE_HISTORY_BYTES,
  MAX_COLLABORATIVE_HISTORY_EVENTS,
  membershipHistoryCheckpointSchema,
  membershipHistoryCompactionInputSchema,
  membershipHistoryEventSchema,
  membershipHistorySchema,
  principalIdSchema,
  sha256DigestSchema,
  timestampSchema,
  vaultIdSchema,
  type CollaborationOperationId,
  type CollaborationRevisionTuple,
  type DatabaseId,
  type DeviceId,
  type MembershipHistory,
  type MembershipHistoryCheckpoint,
  type MembershipHistoryEvent,
  type PrincipalId,
  type Sha256Digest,
  type Timestamp,
  type VaultId,
} from '@kavrix/schemas';

const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');

const INPUT_KEYS = [
  'protocolVersion',
  'databaseId',
  'vaultId',
  'operationId',
  'previousHeadDigest',
  'previousTuple',
  'nextTuple',
  'priorHistory',
  'actorPrincipalId',
  'actorDeviceId',
  'actorSigningPublicKey',
  'event',
  'deviceSigningPrivateKey',
] as const;

const VERIFICATION_INPUT_KEYS = [
  'protocolVersion',
  'databaseId',
  'vaultId',
  'operationId',
  'previousHeadDigest',
  'previousTuple',
  'nextTuple',
  'priorHistory',
  'nextHistory',
  'actorPrincipalId',
  'actorDeviceId',
  'timestamp',
] as const;

const EVENT_REQUIRED_KEYS = ['eventType', 'timestamp'] as const;
const EVENT_OPTIONAL_KEYS = [
  'targetPrincipalId',
  'targetDeviceId',
  'previousRole',
  'newRole',
  'previousState',
  'newState',
  'approvalRequestId',
  'approvalRequestDigest',
  'expiresAt',
] as const;

export type MembershipHistoryEventDetails = Readonly<
  Pick<MembershipHistoryEvent, 'eventType' | 'timestamp'> &
    Partial<
      Pick<
        MembershipHistoryEvent,
        | 'targetPrincipalId'
        | 'targetDeviceId'
        | 'previousRole'
        | 'newRole'
        | 'previousState'
        | 'newState'
        | 'approvalRequestId'
        | 'approvalRequestDigest'
        | 'expiresAt'
      >
    >
>;

export type AppendOrCompactMembershipHistoryInput = Readonly<{
  protocolVersion: typeof COLLABORATION_PROTOCOL_VERSION;
  databaseId: DatabaseId;
  vaultId: VaultId;
  operationId: CollaborationOperationId;
  previousHeadDigest: Sha256Digest;
  previousTuple: CollaborationRevisionTuple;
  nextTuple: CollaborationRevisionTuple;
  priorHistory: MembershipHistory;
  actorPrincipalId: PrincipalId;
  actorDeviceId: DeviceId;
  actorSigningPublicKey: string;
  event: MembershipHistoryEventDetails;
  deviceSigningPrivateKey: DeviceSigningPrivateKey | Uint8Array;
}>;

export type AppendOrCompactMembershipHistoryResult = Readonly<{
  compacted: boolean;
  history: MembershipHistory;
}>;

export type VerifyMembershipHistoryAppendOrCompactionInput = Readonly<{
  protocolVersion: typeof COLLABORATION_PROTOCOL_VERSION;
  databaseId: DatabaseId;
  vaultId: VaultId;
  operationId: CollaborationOperationId;
  previousHeadDigest: Sha256Digest;
  previousTuple: CollaborationRevisionTuple;
  nextTuple: CollaborationRevisionTuple;
  priorHistory: MembershipHistory;
  nextHistory: MembershipHistory;
  actorPrincipalId: PrincipalId;
  actorDeviceId: DeviceId;
  timestamp: Timestamp;
  expiresAt?: Timestamp;
}>;

export type VerifiedMembershipHistoryAppendOrCompaction = Readonly<{
  compacted: boolean;
  event: MembershipHistoryEvent;
  checkpoint?: MembershipHistoryCheckpoint;
}>;

/** Generic fail-closed error for malformed, inconsistent, or unauthenticated input. */
export class MembershipHistoryAppendError extends Error {
  public constructor() {
    super('Unable to append collaborative membership history');
    this.name = 'MembershipHistoryAppendError';
  }
}

type StrictRecord = Readonly<Record<string, unknown>>;

function fail(): never {
  throw new MembershipHistoryAppendError();
}

function strictDataRecord(value: unknown): StrictRecord {
  if (
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail();
  }
  const record = value as Record<string, unknown>;
  for (const key of Reflect.ownKeys(record)) {
    if (typeof key !== 'string') fail();
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !Object.prototype.hasOwnProperty.call(descriptor, 'value')
    ) {
      fail();
    }
  }
  return record;
}

function assertExactKeys(
  record: StrictRecord,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[] = [],
): void {
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  if (
    requiredKeys.some((key) => !Object.prototype.hasOwnProperty.call(record, key)) ||
    Object.keys(record).some((key) => !allowed.has(key))
  ) {
    fail();
  }
}

function optionalField(
  record: StrictRecord,
  key: (typeof EVENT_OPTIONAL_KEYS)[number],
): Record<string, unknown> {
  const value = record[key];
  return value === undefined ? {} : { [key]: value };
}

function canonicalByteLength(value: unknown): number {
  return Buffer.byteLength(canonicalJson(value), 'utf8');
}

function sameCanonical(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function historyDraft(
  scope: Readonly<{
    databaseId: DatabaseId;
    vaultId: VaultId;
    nextTuple: CollaborationRevisionTuple;
    previousHeadDigest: Sha256Digest;
    previousHistoryDigest: Sha256Digest;
  }>,
  events: MembershipHistory['events'],
  checkpoints: MembershipHistory['checkpoints'],
  compactedThroughRevision: MembershipHistory['compactedThroughRevision'],
  compactedHistoryDigest: Sha256Digest,
): Omit<MembershipHistory, 'currentHistoryDigest'> & {
  readonly currentHistoryDigest: Sha256Digest;
} {
  return {
    protocolVersion: COLLABORATION_PROTOCOL_VERSION,
    databaseId: scope.databaseId,
    vaultId: scope.vaultId,
    authorityEpoch: scope.nextTuple.authorityEpoch,
    databaseDeviceGeneration: scope.nextTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: scope.nextTuple.databaseDeviceRegistryDigest,
    events,
    checkpoints,
    compactedThroughRevision,
    compactedHistoryDigest,
    previousHeadDigest: scope.previousHeadDigest,
    previousHistoryDigest: scope.previousHistoryDigest,
    currentHistoryDigest: sha256DigestSchema.parse(PLACEHOLDER_DIGEST),
  };
}

function finalizeHistory(draft: ReturnType<typeof historyDraft>): MembershipHistory {
  return membershipHistorySchema.parse({
    ...draft,
    currentHistoryDigest: computeMembershipHistoryDigest(draft),
  });
}

function requiresCompaction(draft: ReturnType<typeof historyDraft>): boolean {
  return (
    draft.events.length > MAX_COLLABORATIVE_HISTORY_EVENTS ||
    canonicalByteLength(draft) > MAX_COLLABORATIVE_HISTORY_BYTES
  );
}

function assertEventPosition(
  event: MembershipHistoryEvent,
  input: Readonly<{
    operationId: CollaborationOperationId;
    previousHeadDigest: Sha256Digest;
    previousTuple: CollaborationRevisionTuple;
    nextTuple: CollaborationRevisionTuple;
    actorPrincipalId: PrincipalId;
    actorDeviceId: DeviceId;
    timestamp: Timestamp;
    expiresAt?: Timestamp;
  }>,
): void {
  if (
    event.operationId !== input.operationId ||
    event.actorPrincipalId !== input.actorPrincipalId ||
    event.actorDeviceId !== input.actorDeviceId ||
    event.previousHeadDigest !== input.previousHeadDigest ||
    event.previousDocumentRevision !== input.previousTuple.documentRevision ||
    event.newDocumentRevision !== input.nextTuple.documentRevision ||
    event.previousMembershipRevision !== input.previousTuple.membershipRevision ||
    event.newMembershipRevision !== input.nextTuple.membershipRevision ||
    event.previousPolicyRevision !== input.previousTuple.policyRevision ||
    event.newPolicyRevision !== input.nextTuple.policyRevision ||
    event.previousKeyEpoch !== input.previousTuple.keyEpoch ||
    event.newKeyEpoch !== input.nextTuple.keyEpoch ||
    event.previousAuthorityEpoch !== input.previousTuple.authorityEpoch ||
    event.newAuthorityEpoch !== input.nextTuple.authorityEpoch ||
    event.previousDatabaseDeviceGeneration !==
      input.previousTuple.databaseDeviceGeneration ||
    event.newDatabaseDeviceGeneration !== input.nextTuple.databaseDeviceGeneration ||
    event.previousDatabaseDeviceRegistryDigest !==
      input.previousTuple.databaseDeviceRegistryDigest ||
    event.newDatabaseDeviceRegistryDigest !==
      input.nextTuple.databaseDeviceRegistryDigest ||
    event.previousAuthorizationStateDigest !==
      input.previousTuple.authorizationStateDigest ||
    event.newAuthorizationStateDigest !== input.nextTuple.authorizationStateDigest ||
    event.timestamp !== input.timestamp ||
    event.expiresAt !== input.expiresAt
  ) {
    fail();
  }
}

/**
 * Verifies the exact structural append-or-compaction transition after the
 * caller has authenticated both manifests and the retained history signatures.
 * This deliberately does not resolve historical signers or verify signatures.
 */
export function verifyMembershipHistoryAppendOrCompaction(
  input: VerifyMembershipHistoryAppendOrCompactionInput,
): VerifiedMembershipHistoryAppendOrCompaction {
  try {
    const inputRecord = strictDataRecord(input);
    assertExactKeys(inputRecord, VERIFICATION_INPUT_KEYS, ['expiresAt']);
    if (inputRecord['protocolVersion'] !== COLLABORATION_PROTOCOL_VERSION) fail();

    const databaseId = databaseIdSchema.parse(inputRecord['databaseId']);
    const vaultId = vaultIdSchema.parse(inputRecord['vaultId']);
    const operationId = collaborationOperationIdSchema.parse(
      inputRecord['operationId'],
    );
    const previousHeadDigest = sha256DigestSchema.parse(
      inputRecord['previousHeadDigest'],
    );
    const previousTuple = collaborationRevisionTupleSchema.parse(
      inputRecord['previousTuple'],
    );
    const nextTuple = collaborationRevisionTupleSchema.parse(inputRecord['nextTuple']);
    const priorHistory = membershipHistorySchema.parse(inputRecord['priorHistory']);
    const nextHistory = membershipHistorySchema.parse(inputRecord['nextHistory']);
    const actorPrincipalId = principalIdSchema.parse(inputRecord['actorPrincipalId']);
    const actorDeviceId = deviceIdSchema.parse(inputRecord['actorDeviceId']);
    const timestamp = timestampSchema.parse(inputRecord['timestamp']);
    const expiresAt =
      inputRecord['expiresAt'] === undefined
        ? undefined
        : timestampSchema.parse(inputRecord['expiresAt']);

    if (
      computeMembershipHistoryDigest(priorHistory) !==
        priorHistory.currentHistoryDigest ||
      computeMembershipHistoryDigest(nextHistory) !==
        nextHistory.currentHistoryDigest ||
      priorHistory.events.some((entry) => entry.operationId === operationId)
    ) {
      fail();
    }

    const compactionInput = membershipHistoryCompactionInputSchema.parse({
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId,
      vaultId,
      authorityEpoch: previousTuple.authorityEpoch,
      compactingOperationId: operationId,
      previousHeadDigest,
      previousTuple,
      priorHistory,
    });
    if (priorHistory.compactedThroughRevision > previousTuple.membershipRevision) {
      fail();
    }

    const matchingEvents = nextHistory.events.filter(
      (event) => event.operationId === operationId,
    );
    const event = matchingEvents[0];
    if (matchingEvents.length !== 1 || event === undefined) fail();
    assertEventPosition(event, {
      operationId,
      previousHeadDigest,
      previousTuple,
      nextTuple,
      actorPrincipalId,
      actorDeviceId,
      timestamp,
      ...(expiresAt === undefined ? {} : { expiresAt }),
    });

    const scope = {
      databaseId,
      vaultId,
      nextTuple,
      previousHeadDigest,
      previousHistoryDigest: priorHistory.currentHistoryDigest,
    };
    const appendedDraft = historyDraft(
      scope,
      [...priorHistory.events, event],
      priorHistory.checkpoints,
      priorHistory.compactedThroughRevision,
      priorHistory.compactedHistoryDigest,
    );
    if (!requiresCompaction(appendedDraft)) {
      if (!sameCanonical(nextHistory, finalizeHistory(appendedDraft))) fail();
      return { compacted: false, event };
    }

    if (nextHistory.events.length !== 1 || nextHistory.checkpoints.length !== 1) {
      fail();
    }
    const checkpoint = nextHistory.checkpoints[0];
    if (checkpoint === undefined) fail();
    const compactedHistoryDigest =
      computeMembershipHistoryCompactionDigest(compactionInput);
    const expectedCheckpoint = membershipHistoryCheckpointSchema.parse({
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      checkpointId: historyIdSchema.parse(operationId),
      authorityEpoch: nextTuple.authorityEpoch,
      databaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
      membershipRevision: nextTuple.membershipRevision,
      documentRevision: nextTuple.documentRevision,
      policyRevision: nextTuple.policyRevision,
      keyEpoch: nextTuple.keyEpoch,
      previousHeadDigest,
      compactedThroughRevision: previousTuple.membershipRevision,
      compactedHistoryDigest,
      signerPrincipalId: actorPrincipalId,
      signerDeviceId: actorDeviceId,
      createdAt: timestamp,
      signature: checkpoint.signature,
    });
    if (!sameCanonical(checkpoint, expectedCheckpoint)) fail();

    const compactedDraft = historyDraft(
      scope,
      [event],
      [checkpoint],
      checkpoint.compactedThroughRevision,
      checkpoint.compactedHistoryDigest,
    );
    if (!sameCanonical(nextHistory, finalizeHistory(compactedDraft))) fail();
    return { compacted: true, event, checkpoint };
  } catch (error) {
    if (error instanceof MembershipHistoryAppendError) throw error;
    throw new MembershipHistoryAppendError();
  }
}

/**
 * Append one administrative history event, compacting only when that exact
 * append would cross the protocol's event-count or canonical-byte ceiling.
 *
 * The caller must first authenticate the prior manifest/history (including its
 * historical event and checkpoint signers) and authorize the administrative
 * transition. This helper rechecks the strict prior-history self-digest and
 * position bindings, but intentionally does not replace higher-level historical
 * signer or authorization verification. Persist the returned history atomically
 * with the administrative or terminal mutation that supplied `nextTuple`.
 */
export async function appendOrCompactMembershipHistory(
  input: AppendOrCompactMembershipHistoryInput,
): Promise<AppendOrCompactMembershipHistoryResult> {
  let privateKey: Uint8Array | undefined;
  try {
    const inputRecord = strictDataRecord(input);
    const suppliedPrivateKey = inputRecord['deviceSigningPrivateKey'];
    if (!(suppliedPrivateKey instanceof Uint8Array)) fail();
    privateKey = Uint8Array.from(suppliedPrivateKey);

    assertExactKeys(inputRecord, INPUT_KEYS);
    if (inputRecord['protocolVersion'] !== COLLABORATION_PROTOCOL_VERSION) fail();
    const databaseId = databaseIdSchema.parse(inputRecord['databaseId']);
    const vaultId = vaultIdSchema.parse(inputRecord['vaultId']);
    const operationId = collaborationOperationIdSchema.parse(
      inputRecord['operationId'],
    );
    const checkpointId = historyIdSchema.parse(operationId);
    const previousHeadDigest = sha256DigestSchema.parse(
      inputRecord['previousHeadDigest'],
    );
    const previousTuple = collaborationRevisionTupleSchema.parse(
      inputRecord['previousTuple'],
    );
    const nextTuple = collaborationRevisionTupleSchema.parse(inputRecord['nextTuple']);
    const priorHistory = membershipHistorySchema.parse(inputRecord['priorHistory']);
    const actorPrincipalId = principalIdSchema.parse(inputRecord['actorPrincipalId']);
    const actorDeviceId = deviceIdSchema.parse(inputRecord['actorDeviceId']);
    const actorSigningPublicKey = collaborationPublicKeySchema.parse(
      inputRecord['actorSigningPublicKey'],
    );

    if (
      computeMembershipHistoryDigest(priorHistory) !== priorHistory.currentHistoryDigest
    ) {
      fail();
    }

    const compactionInput = membershipHistoryCompactionInputSchema.parse({
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      databaseId,
      vaultId,
      authorityEpoch: previousTuple.authorityEpoch,
      compactingOperationId: operationId,
      previousHeadDigest,
      previousTuple,
      priorHistory,
    });
    if (priorHistory.compactedThroughRevision > previousTuple.membershipRevision) {
      fail();
    }

    const eventDetails = strictDataRecord(inputRecord['event']);
    assertExactKeys(eventDetails, EVENT_REQUIRED_KEYS, EVENT_OPTIONAL_KEYS);
    const eventInput = {
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      operationId,
      eventType: eventDetails['eventType'],
      actorPrincipalId,
      actorDeviceId,
      ...optionalField(eventDetails, 'targetPrincipalId'),
      ...optionalField(eventDetails, 'targetDeviceId'),
      ...optionalField(eventDetails, 'previousRole'),
      ...optionalField(eventDetails, 'newRole'),
      ...optionalField(eventDetails, 'previousState'),
      ...optionalField(eventDetails, 'newState'),
      previousDocumentRevision: previousTuple.documentRevision,
      newDocumentRevision: nextTuple.documentRevision,
      previousMembershipRevision: previousTuple.membershipRevision,
      newMembershipRevision: nextTuple.membershipRevision,
      previousPolicyRevision: previousTuple.policyRevision,
      newPolicyRevision: nextTuple.policyRevision,
      previousKeyEpoch: previousTuple.keyEpoch,
      newKeyEpoch: nextTuple.keyEpoch,
      previousAuthorityEpoch: previousTuple.authorityEpoch,
      newAuthorityEpoch: nextTuple.authorityEpoch,
      previousDatabaseDeviceGeneration: previousTuple.databaseDeviceGeneration,
      newDatabaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
      previousDatabaseDeviceRegistryDigest: previousTuple.databaseDeviceRegistryDigest,
      newDatabaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
      previousAuthorizationStateDigest: previousTuple.authorizationStateDigest,
      newAuthorizationStateDigest: nextTuple.authorizationStateDigest,
      previousHeadDigest,
      ...optionalField(eventDetails, 'approvalRequestId'),
      ...optionalField(eventDetails, 'approvalRequestDigest'),
      timestamp: eventDetails['timestamp'],
      ...optionalField(eventDetails, 'expiresAt'),
      signature: PLACEHOLDER_SIGNATURE,
    };
    membershipHistoryEventSchema.parse(eventInput);
    const signature = await signCollaborationRecord(
      COLLABORATION_DOMAINS.membershipHistorySignature,
      eventInput,
      membershipHistoryEventSchema,
      'signature',
      privateKey,
    );
    const event = membershipHistoryEventSchema.parse({ ...eventInput, signature });
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistorySignature,
        event,
        membershipHistoryEventSchema,
        'signature',
        actorSigningPublicKey,
      ))
    ) {
      fail();
    }
    if (priorHistory.events.some((entry) => entry.operationId === operationId)) {
      fail();
    }

    const scope = {
      databaseId,
      vaultId,
      nextTuple,
      previousHeadDigest,
      previousHistoryDigest: priorHistory.currentHistoryDigest,
    };
    const appendedDraft = historyDraft(
      scope,
      [...priorHistory.events, event],
      priorHistory.checkpoints,
      priorHistory.compactedThroughRevision,
      priorHistory.compactedHistoryDigest,
    );
    const compacted = requiresCompaction(appendedDraft);
    if (!compacted) {
      return { compacted: false, history: finalizeHistory(appendedDraft) };
    }

    const compactedHistoryDigest =
      computeMembershipHistoryCompactionDigest(compactionInput);
    const checkpointInput = {
      protocolVersion: COLLABORATION_PROTOCOL_VERSION,
      checkpointId,
      authorityEpoch: nextTuple.authorityEpoch,
      databaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
      membershipRevision: nextTuple.membershipRevision,
      documentRevision: nextTuple.documentRevision,
      policyRevision: nextTuple.policyRevision,
      keyEpoch: nextTuple.keyEpoch,
      previousHeadDigest,
      compactedThroughRevision: previousTuple.membershipRevision,
      compactedHistoryDigest,
      signerPrincipalId: actorPrincipalId,
      signerDeviceId: actorDeviceId,
      createdAt: event.timestamp,
      signature: PLACEHOLDER_SIGNATURE,
    };
    membershipHistoryCheckpointSchema.parse(checkpointInput);
    const checkpointSignature = await signCollaborationRecord(
      COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
      checkpointInput,
      membershipHistoryCheckpointSchema,
      'signature',
      privateKey,
    );
    const checkpoint = membershipHistoryCheckpointSchema.parse({
      ...checkpointInput,
      signature: checkpointSignature,
    });
    if (
      !(await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
        checkpoint,
        membershipHistoryCheckpointSchema,
        'signature',
        actorSigningPublicKey,
      ))
    ) {
      fail();
    }

    const compactedDraft = historyDraft(
      scope,
      [event],
      [checkpoint],
      checkpoint.compactedThroughRevision,
      checkpoint.compactedHistoryDigest,
    );
    return { compacted: true, history: finalizeHistory(compactedDraft) };
  } catch (error) {
    if (error instanceof MembershipHistoryAppendError) throw error;
    throw new MembershipHistoryAppendError();
  } finally {
    zeroize(privateKey);
  }
}
