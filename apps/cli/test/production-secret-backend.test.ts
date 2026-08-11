import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { deviceUnlockSecretSchema, keychainLocatorSchema } from '@kavrix/schemas';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { acquiredSecretSchema } from '../src/secret-input.js';
import type { SecretInputPort } from '../src/secret-input.js';
import { resolveCliDataPaths } from '../src/production/paths.js';
import { createSecretBackend } from '../src/production/secret-backend.js';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

describe('protected secret backend policy', () => {
  it('fails closed for native policy without creating a sealed directory', async () => {
    const resolvedPaths = await createPaths();
    const failure = new Error('native-unavailable');
    await expect(
      createSecretBackend(resolvedPaths, unusedSecrets(), 'native', {
        loadNativeEntryFactory: () => Promise.reject(failure),
      }),
    ).rejects.toBe(failure);
    await expect(access(resolvedPaths.sealedSecrets)).rejects.toBeDefined();
  });

  it('uses sealed-file only when explicitly selected and never probes native', async () => {
    const native = vi.fn(() => Promise.reject(new Error('must-not-probe')));
    const backend = await createSecretBackend(
      await createPaths(),
      unusedSecrets(),
      'sealed-file',
      { loadNativeEntryFactory: native },
    );

    expect(backend.kind).toBe('sealed-file');
    expect(native).not.toHaveBeenCalled();
    await backend.close();
  });

  it('requests a sealed-store passphrase only through the masked secret port', async () => {
    const read = vi.fn(() =>
      Promise.resolve(acquiredSecretSchema.parse('sealed-passphrase-canary')),
    );
    const resolvedPaths = await createPaths();
    const backend = await createSecretBackend(
      resolvedPaths,
      {
        read,
        readBatch: () => Promise.reject(new Error('unexpected secret batch read')),
      },
      'sealed-file',
    );
    const locator = keychainLocatorSchema.parse({
      version: 1,
      vaultId: 'vault.primary',
      deviceId: 'device.primary',
      keySlotId: 'slot.primary',
    });

    try {
      await backend.keychain.store(
        locator,
        deviceUnlockSecretSchema.parse(new Uint8Array(32).fill(7)),
      );
      expect(read).toHaveBeenCalledWith({
        kind: 'passphrase',
        fromStdin: false,
      });
    } finally {
      await backend.close();
    }
  });
});

async function createPaths(): Promise<ReturnType<typeof resolveCliDataPaths>> {
  const home = await mkdtemp(join(tmpdir(), 'kavrix-secret-backend-'));
  temporaryDirectories.push(home);
  return resolveCliDataPaths({ CREDS_HOME: home });
}

function unusedSecrets(): SecretInputPort {
  return {
    read: () => Promise.reject(new Error('unexpected secret read')),
    readBatch: () => Promise.reject(new Error('unexpected secret batch read')),
  };
}
