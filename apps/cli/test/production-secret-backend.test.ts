import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  deviceUnlockSecretSchema,
  keychainLocatorSchema,
  protectedLocalDeviceStateSchema,
} from '@kavrix/schemas';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { acquiredSecretSchema } from '../src/secret-input.js';
import type { SecretInputPort } from '../src/secret-input.js';
import { resolveCliDataPaths } from '../src/production/paths.js';
import { createSecretBackend } from '../src/production/secret-backend.js';
import type { SecretBackendPolicy } from '../src/production/secret-backend.js';

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
      createSecretBackend(
        resolvedPaths,
        unusedSecrets(),
        { kind: 'native' },
        {
          loadNativeEntryFactory: () => Promise.reject(failure),
        },
      ),
    ).rejects.toBe(failure);
    await expect(access(resolvedPaths.sealedSecrets)).rejects.toBeDefined();
  });

  it('uses sealed-file only when explicitly selected and never probes native', async () => {
    const native = vi.fn(() => Promise.reject(new Error('must-not-probe')));
    const backend = await createSecretBackend(
      await createPaths(),
      unusedSecrets(),
      { kind: 'sealed-file', passphraseFromStdin: false },
      { loadNativeEntryFactory: native },
    );

    expect(backend.kind).toBe('sealed-file');
    expect(native).not.toHaveBeenCalled();
    await backend.close();
  });

  it.each([
    ['masked', false],
    ['explicit stdin', true],
  ] as const)(
    'requests a sealed-store passphrase through %s input only',
    async (_label, passphraseFromStdin) => {
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
        { kind: 'sealed-file', passphraseFromStdin },
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
          fromStdin: passphraseFromStdin,
        });
      } finally {
        await backend.close();
      }
    },
  );

  it('rejects an unknown runtime policy before any backend side effect', async () => {
    const resolvedPaths = await createPaths();
    const native = vi.fn(() => Promise.reject(new Error('must-not-probe')));
    const secrets = unusedSecrets();
    const read = vi.spyOn(secrets, 'read');
    const malformedPolicies: unknown[] = [
      'automatic-fallback',
      null,
      {},
      { kind: 'native', passphraseFromStdin: false },
      { kind: 'native', extra: true },
      { kind: 'sealed-file' },
      { kind: 'sealed-file', passphraseFromStdin: 'yes' },
      { kind: 'sealed-file', passphraseFromStdin: false, extra: true },
      { kind: 'unknown' },
    ];

    for (const runtimePolicy of malformedPolicies) {
      await expect(
        createSecretBackend(
          resolvedPaths,
          secrets,
          runtimePolicy as SecretBackendPolicy,
          { loadNativeEntryFactory: native },
        ),
      ).rejects.toSatisfy(
        (error: unknown) =>
          error instanceof Error && !error.message.includes('automatic-fallback'),
      );
    }
    expect(native).not.toHaveBeenCalled();
    expect(read).not.toHaveBeenCalled();
    await expect(access(resolvedPaths.sealedSecrets)).rejects.toBeDefined();
  });

  it('keeps a wrong sealed passphrase generic and remains safely closable', async () => {
    const paths = await createPaths();
    const vaultId = 'vault.primary';
    const deviceId = 'device.primary';
    const state = protectedLocalDeviceStateSchema.parse({
      version: 2,
      vaultId,
      deviceId,
      highestSeenVaultRevision: 7,
      updatedAt: '2026-08-10T01:02:03.000Z',
    });
    const writer = await createSecretBackend(
      paths,
      secretValue('correct-passphrase-canary'),
      { kind: 'sealed-file', passphraseFromStdin: false },
    );
    await writer.protectedSyncState.save(state);
    await writer.close();

    const reader = await createSecretBackend(
      paths,
      secretValue('wrong-passphrase-canary'),
      { kind: 'sealed-file', passphraseFromStdin: true },
    );
    const close = vi.spyOn(reader, 'close');
    try {
      const operation = reader.protectedSyncState.load(state.vaultId, state.deviceId);
      await expect(operation).rejects.toBeDefined();
      await expect(operation).rejects.not.toThrow(/passphrase-canary/u);
    } finally {
      await reader.close();
    }
    expect(close).toHaveBeenCalledOnce();
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

function secretValue(value: string): SecretInputPort {
  return {
    read: () => Promise.resolve(acquiredSecretSchema.parse(value)),
    readBatch: () => Promise.reject(new Error('unexpected secret batch read')),
  };
}
