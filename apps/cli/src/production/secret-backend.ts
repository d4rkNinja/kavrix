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
import { CliUsageError } from '../errors.js';
import type { CliDataPaths } from './paths.js';

export interface SecretBackend {
  readonly kind: 'native' | 'sealed-file';
  readonly keychain: NativeKeychain;
  readonly sessions: NativeSessionCredentials;
  readonly protectedSyncState: NativeProtectedSyncState;
  readonly joinJournalSecrets: NativeJoinJournalSecrets;
  close(): Promise<void>;
}

export type SecretBackendPolicy =
  | Readonly<{ kind: 'native' }>
  | Readonly<{
      kind: 'sealed-file';
      passphraseFromStdin: boolean;
    }>;

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
  const runtimePolicy = parsePolicy(policy);
  if (runtimePolicy.kind === 'native') {
    const native = await dependencies.loadNativeEntryFactory();
    return backend('native', native, () => Promise.resolve());
  }
  const store = new SealedSecretStore({
    directory: paths.sealedSecrets,
    passphrase: () =>
      readSealedStorePassphrase(secrets, runtimePolicy.passphraseFromStdin),
  });
  return backend('sealed-file', sealedEntryFactory(store), () => store.close());
}

/** Rejects missing, mistyped, and extra policy fields before backend effects. */
function parsePolicy(input: unknown): SecretBackendPolicy {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new CliUsageError('The protected secret backend policy is invalid.');
  }
  const policy = input as Record<string, unknown>;
  const keys = Object.keys(policy);
  if (policy['kind'] === 'native' && hasExactKeys(keys, ['kind'])) {
    return { kind: 'native' };
  }
  if (
    policy['kind'] === 'sealed-file' &&
    typeof policy['passphraseFromStdin'] === 'boolean' &&
    hasExactKeys(keys, ['kind', 'passphraseFromStdin'])
  ) {
    return {
      kind: 'sealed-file',
      passphraseFromStdin: policy['passphraseFromStdin'],
    };
  }
  throw new CliUsageError('The protected secret backend policy is invalid.');
}

function hasExactKeys(actual: readonly string[], expected: readonly string[]): boolean {
  return (
    actual.length === expected.length && expected.every((key) => actual.includes(key))
  );
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
  fromStdin: boolean,
): Promise<Uint8Array> {
  const passphrase = await secrets.read({ kind: 'passphrase', fromStdin });
  return new TextEncoder().encode(passphrase);
}
