export {
  openSqliteInitializationJournal,
  openSqliteJoinLifecycleJournal,
  openSqlitePortableKeyRotationJournal,
  SqliteInitializationJournal,
  SqliteJoinLifecycleJournal,
  SqlitePortableKeyRotationJournal,
  type SqliteJoinLifecycleJournalOptions,
  type SqliteLifecycleJournalOptions,
} from './lifecycle-journals.js';
export {
  acquireLocalWriterLease,
  recoverStaleLocalWriterLease,
  type LocalWriterLease,
  type StaleLocalWriterLeaseRecovery,
} from './local-writer-lease.js';
export {
  openSqliteSyncLocalStore,
  SqliteSyncLocalStore,
  type QueueMutationResult,
  type SqliteSyncLocalStoreOptions,
  type SyncEntityType,
} from './sqlite-local-store.js';
export {
  openSqliteVaultProfileStore,
  SqliteVaultProfileStore,
  type SqliteVaultProfileStoreOptions,
} from './vault-profile-store.js';
export type {
  InitializationJournalPort,
  InitializationJournalRecord,
  JoinJournalRecord,
  JoinLifecycleJournalPort,
  PortableKeyRotationJournalPort,
  PortableKeyRotationJournalRecord,
  LifecycleOperationId,
  VaultProfile,
  VaultProfileStorePort,
} from '@kavrix/client';
export type { OpaqueMutation, OpaqueSyncRecord, VaultId } from '@kavrix/schemas';
export type {
  ActivePushBatch,
  ApplyPullPageInput,
  CompletePushBatchInput,
  SyncCursor,
  SyncLocalStorePort,
} from '@kavrix/sync';
