import type {
  DeviceId,
  Sha256Digest,
  TemplateMigrationPublicationRequest,
  TemplateMigrationPublicationResponse,
  Timestamp,
  VaultId,
  VaultRevision,
} from '@kavrix/schemas';

import type {
  ActivePushBatch,
  ApplyPullPageInput,
  CompletePushBatchInput,
  CompleteTemplateMigrationPublicationInput,
  OpaqueMutation,
  ProtectedLocalDeviceState,
  PullPageRequest,
  PullPageResponse,
  PushBatchRequest,
  PushBatchResponse,
  SyncCursor,
  SyncStatus,
} from './types.js';

/** The transport boundary carries only canonical opaque records and public metadata. */
export interface SyncTransportPort {
  pull(request: PullPageRequest): Promise<PullPageResponse>;
  push(request: PushBatchRequest): Promise<PushBatchResponse>;
  publishTemplateMigration(
    request: TemplateMigrationPublicationRequest,
  ): Promise<TemplateMigrationPublicationResponse>;
}

export interface SyncLocalStorePort {
  loadCursor(vaultId: VaultId): Promise<SyncCursor | null>;
  /** Applies records and advances the cursor atomically. */
  applyPullPage(input: ApplyPullPageInput): Promise<void>;
  listPendingMutations(vaultId: VaultId): Promise<readonly OpaqueMutation[]>;
  loadActivePushBatch(vaultId: VaultId): Promise<ActivePushBatch | null>;
  /** Persists the batch before its first transport attempt. */
  saveActivePushBatch(batch: ActivePushBatch): Promise<void>;
  /** Acknowledges mutations and clears the matching active batch atomically. */
  completePushBatch(input: CompletePushBatchInput): Promise<void>;
  /** Loads the exact durable atomic publication; it must never be synthesized. */
  loadPendingTemplateMigrationPublication(
    vaultId: VaultId,
  ): Promise<TemplateMigrationPublicationRequest | null>;
  /**
   * Persists one canonical atomic publication before its first remote attempt.
   * Implementations must fail closed if generic pending work exists for the vault.
   */
  enqueueTemplateMigrationPublication(
    publication: TemplateMigrationPublicationRequest,
  ): Promise<void>;
  /** Promotes all acknowledged records and clears the publication atomically. */
  completeTemplateMigrationPublication(
    input: CompleteTemplateMigrationPublicationInput,
  ): Promise<void>;
}

/** Implementations must use protected local storage, separate from the sync server. */
export interface ProtectedSyncStatePort {
  load(vaultId: VaultId, deviceId: DeviceId): Promise<ProtectedLocalDeviceState | null>;
  save(state: ProtectedLocalDeviceState): Promise<void>;
  completeObservation(
    vaultId: VaultId,
    deviceId: DeviceId,
    expectedObservationId: Sha256Digest,
    candidateRevision: VaultRevision,
    updatedAt: Timestamp,
  ): Promise<void>;
}

export interface SyncStatusPort {
  set(status: SyncStatus): Promise<void>;
}

export interface SyncClockPort {
  now(): Date;
}

export interface SyncIdempotencyKeyPort {
  /** Returns a fresh, unpredictable key of 16-256 characters. */
  next(): string;
}
