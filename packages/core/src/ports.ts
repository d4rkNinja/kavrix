import type {
  AttachmentId,
  AttachmentStreamFinalizeInput,
  AttachmentStreamProgress,
  AttachmentStreamStartInput,
  DeviceUnlockSecret,
  EncryptedAttachmentRecord,
  EncryptedGroupRecord,
  EncryptedItemRecord,
  GroupId,
  ItemId,
  KeychainLocator,
  OpaqueMutation,
  PersistedAttachmentChunkRecord,
  PersistedAttachmentHeaderRecord,
  SessionCredentialLocator,
  SessionCredentialSecret,
  SyncCursor,
  SyncPullResponse,
  SyncPushRequest,
  SyncPushResponse,
  TemplateMigrationPublicationRequest,
  TemplateMigrationPublicationResponse,
  VaultId,
  VaultRecord,
} from '@kavrix/schemas';

export interface AttachmentStreamStagingSession {
  /** Canonical hidden progress loaded when this idempotent session was opened. */
  readonly progress: AttachmentStreamProgress;
  /**
   * Stages the next contiguous chunk. Repeating the most recently accepted
   * index with the same authenticated hash, size, and tag is idempotent; gaps,
   * replacements, and writes after the final tag fail closed.
   */
  writeChunk(record: PersistedAttachmentChunkRecord): Promise<AttachmentStreamProgress>;
  /**
   * Atomically publishes attachment metadata, its one header, and every staged
   * chunk. A retried finalize with the same idempotency key and input succeeds
   * idempotently; an incompatible reuse fails closed.
   */
  finalize(input: AttachmentStreamFinalizeInput): Promise<void>;
  /** Idempotently discards this session's unpublished staged records. */
  abort(): Promise<void>;
}

export interface ClockPort {
  now(): Date;
}

export interface IdGeneratorPort<TId extends string> {
  next(): TId;
}

export interface KeychainPort {
  load(
    locator: KeychainLocator,
    signal?: AbortSignal,
  ): Promise<DeviceUnlockSecret | null>;
  store(
    locator: KeychainLocator,
    secret: DeviceUnlockSecret,
    signal?: AbortSignal,
  ): Promise<void>;
  delete(locator: KeychainLocator, signal?: AbortSignal): Promise<void>;
}

/** Native secure storage for API session credentials, separate from VRK slots. */
export interface SessionCredentialPort {
  load(
    locator: SessionCredentialLocator,
    signal?: AbortSignal,
  ): Promise<SessionCredentialSecret | null>;
  store(
    locator: SessionCredentialLocator,
    secret: SessionCredentialSecret,
    signal?: AbortSignal,
  ): Promise<void>;
  delete(locator: SessionCredentialLocator, signal?: AbortSignal): Promise<void>;
}

export interface VaultStoragePort {
  getVault(vaultId: VaultId): Promise<VaultRecord | null>;
  /** Commits only non-attachment opaque entities. */
  commit(mutation: OpaqueMutation): Promise<void>;
  getGroup(vaultId: VaultId, groupId: GroupId): Promise<EncryptedGroupRecord | null>;
  listGroups(vaultId: VaultId): AsyncIterable<EncryptedGroupRecord>;
  getItem(vaultId: VaultId, itemId: ItemId): Promise<EncryptedItemRecord | null>;
  listItems(vaultId: VaultId, groupId: GroupId): AsyncIterable<EncryptedItemRecord>;
  getAttachment(
    vaultId: VaultId,
    attachmentId: AttachmentId,
  ): Promise<EncryptedAttachmentRecord | null>;
  /**
   * The sole attachment publication path. Opens or resumes hidden staging
   * identified by the input idempotency key.
   * Staged header/chunks remain invisible to every read and the change feed until
   * finalize atomically publishes them with the attachment record. Reusing a key
   * with a different start input fails closed. Aborted staging is never visible.
   */
  beginAttachmentStream(
    input: AttachmentStreamStartInput,
  ): Promise<AttachmentStreamStagingSession>;
  /**
   * Idempotently aborts the exact hidden staging operation identified by the
   * canonical start input. Incompatible idempotency-key reuse fails closed.
   */
  abortAttachmentStream(input: AttachmentStreamStartInput): Promise<void>;
  getAttachmentStreamHeader(
    vaultId: VaultId,
    attachmentId: AttachmentId,
  ): Promise<PersistedAttachmentHeaderRecord | null>;
  getAttachmentChunk(
    vaultId: VaultId,
    attachmentId: AttachmentId,
    chunkIndex: number,
  ): Promise<PersistedAttachmentChunkRecord | null>;
  /** Yields chunks in strictly ascending, contiguous index order. */
  listAttachmentChunks(
    vaultId: VaultId,
    attachmentId: AttachmentId,
    startIndex: number,
  ): AsyncIterable<PersistedAttachmentChunkRecord>;
  /** Returns one canonical, rollback-bound page with immutable opaque snapshots. */
  pullSyncPage(cursor: SyncCursor, limit: number): Promise<SyncPullResponse>;
  /** Applies and durably checkpoints one ordered, idempotent sync batch. */
  pushSyncBatch(batch: SyncPushRequest): Promise<SyncPushResponse>;
  /**
   * Atomically publishes one bounded opaque group-template migration. Exact
   * batch retries return the original canonical response.
   */
  publishTemplateMigration(
    batch: TemplateMigrationPublicationRequest,
  ): Promise<TemplateMigrationPublicationResponse>;
}
