import { canonicalJson, syncPulledChangeSchema } from '@kavrix/schemas';
import type {
  DeviceId,
  OpaqueMutation,
  OpaqueSyncRecord,
  OutboundObservation,
  ProtectedLocalDeviceState,
  Sha256Digest,
  RecordRevision,
  SyncPulledChange,
  SyncPullResponse,
  SyncPushRequest,
  SyncPushResponse,
  SyncCursor,
  SyncState,
  TemplateMigrationPublicationRequest,
  TemplateMigrationPublicationResponse,
  Timestamp,
  VaultId,
  VaultRevision,
} from '@kavrix/schemas';

export type PulledChange = SyncPulledChange;

export interface PullPageRequest {
  readonly vaultId: VaultId;
  readonly cursor: SyncCursor;
  readonly limit: number;
}

export type PullPageResponse = SyncPullResponse;
export type PushBatchRequest = SyncPushRequest;
export type AcceptedPushResult = Extract<
  SyncPushResponse['results'][number],
  { status: 'accepted' }
>;
export type ConflictingPushResult = Extract<
  SyncPushResponse['results'][number],
  { status: 'conflict' }
>;
export type PushMutationResult = SyncPushResponse['results'][number];
export type PushBatchResponse = SyncPushResponse;

export interface ActivePushBatch {
  readonly vaultId: VaultId;
  readonly batchIdempotencyKey: string;
  readonly mutationIdempotencyKeys: readonly string[];
}

export interface SyncConflict {
  readonly mutation: OpaqueMutation;
  readonly currentRevision: RecordRevision | VaultRevision;
  readonly current: OpaqueSyncRecord | null;
}

/** Redacted, durable conflict metadata safe for CLI projections. */
export interface SyncConflictMetadata {
  readonly vaultId: VaultId;
  readonly entityType: OpaqueMutation['entityType'];
  readonly entityId: string;
  readonly idempotencyKey: string;
  readonly expectedRevision: RecordRevision | VaultRevision | null;
  readonly currentRevision: RecordRevision | VaultRevision;
  readonly currentState: 'present' | 'deleted' | 'missing';
}

export type SyncConflictResolutionStrategy = 'keep-local' | 'accept-remote';

export interface ResolveSyncConflictInput {
  readonly vaultId: VaultId;
  readonly conflictId: string;
  readonly currentRevision: RecordRevision | VaultRevision;
  readonly strategy: SyncConflictResolutionStrategy;
  /** Fresh only for keep-local; accept-remote does not create a mutation. */
  readonly replacementIdempotencyKey: string | null;
  readonly resolvedAt: Timestamp;
}

export interface ResolveSyncConflictResult {
  readonly status: 'accepted-remote' | 'queued-local';
  readonly conflictId: string;
  readonly strategy: SyncConflictResolutionStrategy;
  readonly replacementIdempotencyKey: string | null;
}

interface SyncStatusBase {
  readonly state: SyncState;
  readonly vaultId: VaultId;
  readonly at: Timestamp;
}

export type SyncStatus =
  | (SyncStatusBase & {
      readonly state: 'synced';
      readonly cursor: SyncCursor;
    })
  | (SyncStatusBase & {
      readonly state: 'offline';
      readonly cursor: SyncCursor;
      readonly reason: 'network-unavailable';
    })
  | (SyncStatusBase & {
      readonly state: 'syncing';
      readonly cursor: SyncCursor;
      readonly phase: 'pull' | 'push';
    })
  | (SyncStatusBase & {
      readonly state: 'conflict';
      readonly cursor: SyncCursor;
      readonly conflicts: readonly SyncConflict[];
    })
  | (SyncStatusBase & {
      readonly state: 'error';
      readonly cursor: SyncCursor;
      readonly code: SyncFailureCode;
      readonly retryable: boolean;
    });

export type SyncFailureCode =
  | 'transport-timeout'
  | 'rate-limited'
  | 'service-unavailable'
  | 'authorization-failed'
  | 'device-revoked'
  | 'request-rejected'
  | 'protocol-invalid'
  | 'rollback-detected'
  | 'local-state-invalid'
  | 'atomic-publication-conflict'
  | 'unexpected';

export type RetryClassification =
  | {
      readonly state: 'offline';
      readonly code: 'network-unavailable';
      readonly retryable: true;
    }
  | {
      readonly state: 'error';
      readonly code: SyncFailureCode;
      readonly retryable: boolean;
      readonly retryAfterMs?: number;
    };

export interface SyncRunInput {
  readonly vaultId: VaultId;
  readonly deviceId: DeviceId;
}

export type SyncRunResult =
  | {
      readonly state: 'synced';
      readonly cursor: SyncCursor;
      readonly pulledChanges: number;
      readonly pushedMutations: number;
    }
  | {
      readonly state: 'conflict';
      readonly cursor: SyncCursor;
      readonly pulledChanges: number;
      readonly pushedMutations: number;
      readonly conflicts: readonly SyncConflict[];
    };

export interface ApplyPullPageInput {
  readonly vaultId: VaultId;
  readonly changes: readonly PulledChange[];
  readonly cursor: SyncCursor;
}

export interface CompletePushBatchInput {
  readonly vaultId: VaultId;
  readonly batchIdempotencyKey: string;
  readonly acknowledgedIdempotencyKeys: readonly string[];
}

export interface CompleteTemplateMigrationPublicationInput {
  readonly publication: TemplateMigrationPublicationRequest;
  readonly response: TemplateMigrationPublicationResponse;
}

export const MAX_OUTBOUND_RECONCILIATION_CHANGES = 500;
export const MAX_OUTBOUND_RECONCILIATION_BYTES = 32 * 1024 * 1024;

export function measureOutboundReconciliationChanges(
  changes: readonly PulledChange[],
): number {
  if (!Array.isArray(changes) || changes.length > MAX_OUTBOUND_RECONCILIATION_CHANGES) {
    throw new TypeError('Invalid outbound reconciliation range');
  }
  const parsedChanges = changes.map((change) => {
    const parsed = syncPulledChangeSchema.safeParse(change);
    if (!parsed.success) throw new TypeError('Invalid outbound reconciliation range');
    return parsed.data;
  });
  const bytes = Buffer.byteLength(canonicalJson(parsedChanges));
  if (bytes > MAX_OUTBOUND_RECONCILIATION_BYTES) {
    throw new TypeError('Invalid outbound reconciliation range');
  }
  return bytes;
}

export type OutboundReplayState = Readonly<{
  kind: OutboundObservation['kind'];
  vaultId: VaultId;
  batchIdempotencyKey: string;
  replayFromServerSequence: number | null;
}>;

export type EnsureOutboundReplayStartInput = Readonly<{
  kind: OutboundObservation['kind'];
  vaultId: VaultId;
  batchIdempotencyKey: string;
}>;

type ReconcileOutboundObservationBase = Readonly<{
  vaultId: VaultId;
  deviceId: DeviceId;
  observation: OutboundObservation;
  stagedChanges: readonly PulledChange[];
  stagedChangesBytes: number;
  finalCursor: SyncCursor;
}>;

export type ReconcileOutboundObservationInput =
  | (ReconcileOutboundObservationBase &
      Readonly<{
        kind: 'generic-push';
        request: PushBatchRequest;
        response: PushBatchResponse;
      }>)
  | (ReconcileOutboundObservationBase &
      Readonly<{
        kind: 'template-publication';
        request: TemplateMigrationPublicationRequest;
        response: TemplateMigrationPublicationResponse;
      }>);

type CompletedOutboundObservationBase = Readonly<{
  vaultId: VaultId;
  deviceId: DeviceId;
  observation: OutboundObservation;
  finalCursor: SyncCursor;
  serializedBytes: number;
}>;

export type CompletedOutboundObservation =
  | (CompletedOutboundObservationBase &
      Readonly<{
        kind: 'generic-push';
        request: PushBatchRequest;
        response: PushBatchResponse;
      }>)
  | (CompletedOutboundObservationBase &
      Readonly<{
        kind: 'template-publication';
        request: TemplateMigrationPublicationRequest;
        response: TemplateMigrationPublicationResponse;
      }>);

export type {
  OpaqueMutation,
  OpaqueSyncRecord,
  ProtectedLocalDeviceState,
  Sha256Digest,
  SyncCursor,
};
