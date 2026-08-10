import type {
  DeviceId,
  OpaqueMutation,
  OpaqueSyncRecord,
  ProtectedLocalDeviceState,
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

export type { OpaqueMutation, OpaqueSyncRecord, ProtectedLocalDeviceState, SyncCursor };
