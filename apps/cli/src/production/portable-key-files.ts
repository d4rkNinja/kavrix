import {
  formatPortableKey,
  zeroize,
  type PortableKeyFileBinding,
} from '@kavrix/crypto';
import { PortableKeyFileError, readPortableKeyFile } from '@kavrix/key-files';

import type { ProtectedPortableKeyFileReaderPort } from '../initialization.js';
import {
  acquiredSecretSchema,
  type AcquiredSecret,
  type SecretInputPort,
} from '../secret-input.js';

export interface ProductionPortableKeyFileReaderOptions {
  readonly secrets: SecretInputPort;
  readonly passphraseFromStdin: boolean;
}

export interface ProductionPortableKeyFileReaderDependencies {
  readonly readPortableKeyFile: typeof readPortableKeyFile;
  readonly formatPortableKey: typeof formatPortableKey;
}

const DEFAULT_DEPENDENCIES: ProductionPortableKeyFileReaderDependencies = {
  readPortableKeyFile,
  formatPortableKey,
};

/**
 * Reads a canonical portable-key file without exposing its raw bytes. An
 * ordinary file is tried first; only cryptographic parse failures fall through
 * to the protected form, while filesystem safety failures remain terminal.
 */
export function createProductionPortableKeyFileReader(
  options: ProductionPortableKeyFileReaderOptions,
  dependencies: ProductionPortableKeyFileReaderDependencies = DEFAULT_DEPENDENCIES,
): ProtectedPortableKeyFileReaderPort {
  return {
    readFormattedPortableKey: async (
      path,
      expectedBinding = { kind: 'unbound' },
      acquirePassphrase,
    ) => {
      let parsed: Awaited<ReturnType<typeof readPortableKeyFile>> | undefined;
      try {
        try {
          parsed = await dependencies.readPortableKeyFile(path, {
            kind: 'unprotected',
          });
          assertExpectedBinding(parsed, expectedBinding);
        } catch (error) {
          if (
            error instanceof PortableKeyFileError ||
            error instanceof PortableKeyBindingMismatch
          ) {
            throw error;
          }
          const passphrase = await readAcquiredPassphrase(options, acquirePassphrase);
          const passphraseBytes = new TextEncoder().encode(passphrase);
          try {
            parsed = await dependencies.readPortableKeyFile(path, {
              kind: 'passphrase',
              passphrase: passphraseBytes,
            });
            assertExpectedBinding(parsed, expectedBinding);
          } finally {
            zeroize(passphraseBytes);
          }
        }
        return dependencies.formatPortableKey(parsed.key);
      } finally {
        zeroize(parsed?.key);
      }
    },
  };
}

function assertExpectedBinding(
  parsed: {
    readonly kind: PortableKeyFileBinding['kind'];
    readonly vaultId?: string;
    readonly keySlotId?: string;
  },
  expected: PortableKeyFileBinding | undefined,
): void {
  if (
    expected === undefined ||
    (expected.kind === 'unbound' && parsed.kind === 'unbound') ||
    (expected.kind === 'bound' &&
      parsed.kind === 'bound' &&
      parsed.vaultId === expected.vaultId &&
      parsed.keySlotId === expected.keySlotId)
  ) {
    return;
  }
  throw new PortableKeyBindingMismatch();
}

class PortableKeyBindingMismatch extends Error {}

async function readAcquiredPassphrase(
  options: ProductionPortableKeyFileReaderOptions,
  acquirePassphrase: (() => Promise<AcquiredSecret>) | undefined,
): Promise<AcquiredSecret> {
  if (acquirePassphrase !== undefined) {
    return acquiredSecretSchema.parse(await acquirePassphrase());
  }
  return options.secrets.read({
    kind: 'passphrase',
    fromStdin: options.passphraseFromStdin,
  });
}
