import { TextEncoder } from 'node:util';

import { sealedEntryFactory, SealedSecretStore } from '@kavrix/key-files';
import {
  NativeJoinJournalSecrets,
  NativeKeychain,
  NativeProtectedSyncState,
  NativeSessionCredentials,
  loadNativeEntryFactory,
  type NativeEntryFactory,
} from '@kavrix/keychain';

import type { SecretInputPort } from '../secret-input.js';
import type { CliDataPaths } from './paths.js';

export interface SecretBackend {
  readonly kind: 'native' | 'sealed-file';
  readonly keychain: NativeKeychain;
  readonly sessions: NativeSessionCredentials;
  readonly protectedSyncState: NativeProtectedSyncState;
  readonly joinJournalSecrets: NativeJoinJournalSecrets;
  close(): Promise<void>;
}

export type SecretBackendPolicy = SecretBackend['kind'];

export type SecretBackendDependencies = Readonly<{
  loadNativeEntryFactory: () => Promise<NativeEntryFactory>;
}>;

const DEFAULT_DEPENDENCIES: SecretBackendDependencies = {
  loadNativeEntryFactory,
};

/**
 * The user-chosen policy is explicit. Native mode fails closed when its adapter
 * is unavailable; sealed-file mode never probes native storage.
 */
export async function createSecretBackend(
  paths: CliDataPaths,
  secrets: SecretInputPort,
  policy: SecretBackendPolicy,
  dependencies: SecretBackendDependencies = DEFAULT_DEPENDENCIES,
): Promise<SecretBackend> {
  if (policy === 'native') {
    const native = await dependencies.loadNativeEntryFactory();
    return backend('native', native, () => Promise.resolve());
  }

  const store = new SealedSecretStore({
    directory: paths.sealedSecrets,
    passphrase: () => readSealedStorePassphrase(secrets),
  });
  return backend('sealed-file', sealedEntryFactory(store), () => store.close());
}

function backend(
  kind: SecretBackend['kind'],
  createEntry: NativeEntryFactory,
  close: () => Promise<void>,
): SecretBackend {
  return {
    kind,
    keychain: new NativeKeychain(createEntry),
    sessions: new NativeSessionCredentials(createEntry),
    protectedSyncState: new NativeProtectedSyncState(createEntry),
    joinJournalSecrets: new NativeJoinJournalSecrets(createEntry),
    close,
  };
}

/**
 * The sealed store derives its file key from this passphrase, so it is read
 * through the same masked-terminal path as every other secret and never from an
 * argument or environment variable.
 */
async function readSealedStorePassphrase(
  secrets: SecretInputPort,
): Promise<Uint8Array> {
  const passphrase = await secrets.read({ kind: 'passphrase', fromStdin: false });
  return new TextEncoder().encode(passphrase);
}
