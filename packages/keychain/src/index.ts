export { KeychainError, type KeychainErrorCode } from './errors.js';
export {
  createNativeJoinJournalSecrets,
  NativeJoinJournalSecrets,
} from './native-join-journal-secrets.js';
export {
  createNativeKeychain,
  createNativeProtectedSyncState,
  createNativeSessionCredentials,
  NativeKeychain,
  NativeProtectedSyncState,
  NativeSessionCredentials,
  loadNativeEntryFactory,
  tryLoadNativeEntryFactory,
  type NativeEntryFactory,
} from './native-keychain.js';
export type { JoinActiveJournalRecord, LifecycleOperationId } from '@kavrix/client';
export type {
  DeviceUnlockSecret,
  KeychainLocator,
  SessionCredentialLocator,
  SessionCredentialSecret,
} from '@kavrix/schemas';
export type { ProtectedSyncStatePort } from '@kavrix/sync';
