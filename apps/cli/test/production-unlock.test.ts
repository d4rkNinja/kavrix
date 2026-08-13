import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { vaultProfileSchema } from '@kavrix/client';
import { openSqliteVaultProfileStore } from '@kavrix/local-store';
import { deviceIdSchema, keySlotIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';

import { resolveCliDataPaths } from '../src/production/paths.js';
import { ensureDataDirectory } from '../src/production/runtime-adapters.js';
import {
  runProductionLock,
  runProductionUnlocked,
  unlockMethodSchema,
} from '../src/production/unlock.js';

describe('production unlocked command runner', () => {
  let tempHome: string;

  beforeEach(async () => {
    tempHome = join(
      tmpdir(),
      `kavrix-prod-unlock-test-${Math.random().toString(36).slice(2)}`,
    );
    await ensureDataDirectory(tempHome);
    const paths = resolveCliDataPaths({ CREDS_HOME: tempHome });
    const profileStore = await openSqliteVaultProfileStore({
      path: paths.profileStore,
    });
    const profile = vaultProfileSchema.parse({
      version: 1,
      serverUrl: 'https://vault.example/',
      vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
      deviceId: deviceIdSchema.parse('device.test00000000000000001'),
      deviceLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
        deviceId: deviceIdSchema.parse('device.test00000000000000001'),
        keySlotId: 'slot.device.001',
      },
      sessionLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse('vault.test000000000000000001'),
        deviceId: deviceIdSchema.parse('device.test00000000000000001'),
        purpose: 'api-session',
      },
    });
    await profileStore.store(profile);
    await profileStore.close();
  });

  afterEach(async () => {
    try {
      await rm(tempHome, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on temp teardown
    }
  });

  it('validates unlockMethod runtime contracts strictly', () => {
    expect(unlockMethodSchema.parse({ kind: 'remembered-device' })).toEqual({
      kind: 'remembered-device',
    });

    expect(
      unlockMethodSchema.parse({
        kind: 'portable',
        formattedKey: 'KAVRIX-PORTABLE-KEY-001',
      }),
    ).toEqual({
      kind: 'portable',
      formattedKey: 'KAVRIX-PORTABLE-KEY-001',
    });

    const slotId = keySlotIdSchema.parse('slot.passphrase.001');
    expect(
      unlockMethodSchema.parse({
        kind: 'passphrase',
        passphraseSlotId: slotId,
      }),
    ).toEqual({
      kind: 'passphrase',
      passphraseSlotId: slotId,
    });

    expect(() => unlockMethodSchema.parse({ kind: 'unknown' })).toThrow();
  });

  it('runs an operation within an unlocked environment lifecycle and closes resources', async () => {
    const mockSecretsInput = {
      read: vi.fn(),
      readBatch: vi.fn(),
      clear: vi.fn(),
    };

    const result = await runProductionUnlocked(
      {
        environment: { CREDS_HOME: tempHome },
        secrets: mockSecretsInput,
        backendPolicy: { kind: 'native' },
        unlockMethod: { kind: 'remembered-device' },
      },
      (context) => {
        expect(context.profile).toBeDefined();
        expect(context.ports).toBeDefined();
        return Promise.resolve('operation-result');
      },
    );

    expect(result).toBe('operation-result');
  });

  it('locks vault and clears managed clipboard state in production', async () => {
    const mockSecretsInput = {
      read: vi.fn(),
      readBatch: vi.fn(),
      clear: vi.fn(),
    };

    await expect(
      runProductionLock({
        environment: { CREDS_HOME: tempHome },
        secrets: mockSecretsInput,
        backendPolicy: { kind: 'native' },
      }),
    ).resolves.toBeUndefined();
  });

  it('surfaces aggregate error when operation and cleanup both fail', async () => {
    const mockSecretsInput = {
      read: vi.fn(),
      readBatch: vi.fn(),
      clear: vi.fn(),
    };

    const operationError = new Error('operation failed');

    await expect(
      runProductionUnlocked(
        {
          environment: { CREDS_HOME: tempHome },
          secrets: mockSecretsInput,
          backendPolicy: { kind: 'native' },
        },
        (context) => {
          vi.spyOn(context.environment, 'close').mockRejectedValueOnce(
            new Error('cleanup failed'),
          );
          return Promise.reject(operationError);
        },
      ),
    ).rejects.toThrow(AggregateError);
  });
});
