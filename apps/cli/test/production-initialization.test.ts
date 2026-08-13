import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  lifecycleOperationIdSchema,
  vaultProfileSchema,
  type VaultInitializationInput,
} from '@kavrix/client';
import { deviceIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

import { DEFAULT_VAULT_INITIALIZATION_INPUT } from '../src/initialization.js';
import type { CliVaultInitializationPort } from '../src/initialization.js';
import { createProductionInitializationPort } from '../src/production/initialize.js';
import { CliUsageError } from '../src/errors.js';

describe('production initialization adapter factory', () => {
  let tempHome: string;

  beforeEach(() => {
    tempHome = join(
      tmpdir(),
      `kavrix-prod-init-test-${Math.random().toString(36).slice(2)}`,
    );
  });

  afterEach(async () => {
    try {
      await rm(tempHome, { recursive: true, force: true });
    } catch {
      // Ignore directory cleanup error on temp teardown
    }
  });

  it('delegates begin, beginImportedPortable, resume, and cancel to coordinator', async () => {
    const mockSecrets = {
      kind: 'native' as const,
      keychain: {} as never,
      sessions: {} as never,
      protectedSyncState: {} as never,
      joinJournalSecrets: {} as never,
      close: () => Promise.resolve(),
    };
    const mockEnvironment = {
      profiles: {
        listProfiles: vi.fn().mockResolvedValue([]),
      } as never,
      initializationJournal: {} as never,
    };

    const beginFn = vi.fn().mockResolvedValue('begin-res');
    const beginImportedPortableFn = vi.fn().mockResolvedValue('begin-imported-res');
    const resumeFn = vi.fn().mockResolvedValue('resume-res');
    const cancelFn = vi.fn().mockResolvedValue('cancel-res');

    const mockCoordinator: CliVaultInitializationPort = {
      begin: beginFn,
      beginImportedPortable: beginImportedPortableFn,
      resume: resumeFn,
      cancel: cancelFn,
    };

    const port = createProductionInitializationPort({
      environment: mockEnvironment as never,
      secrets: mockSecrets,
      defaultServerUrl: 'https://vault.example/',
      coordinatorFactory: () => mockCoordinator,
    });

    const input: VaultInitializationInput = DEFAULT_VAULT_INITIALIZATION_INPUT;

    await expect(port.begin(input)).resolves.toBe('begin-res');
    expect(beginFn).toHaveBeenCalledWith(input, undefined);

    await expect(
      port.beginImportedPortable(input, 'KAVRIX-PORTABLE-KEY'),
    ).resolves.toBe('begin-imported-res');
    expect(beginImportedPortableFn).toHaveBeenCalledWith(
      input,
      'KAVRIX-PORTABLE-KEY',
      undefined,
    );

    const opId = lifecycleOperationIdSchema.parse('operation.cli.init.0001');
    await expect(port.resume(opId)).resolves.toBe('resume-res');
    expect(resumeFn).toHaveBeenCalledWith(opId, undefined);

    await expect(port.cancel(opId)).resolves.toBe('cancel-res');
    expect(cancelFn).toHaveBeenCalledWith(opId, undefined);
  });

  it('refuses initialization when an active profile already exists', async () => {
    const mockSecrets = {
      kind: 'native' as const,
      keychain: {} as never,
      sessions: {} as never,
      protectedSyncState: {} as never,
      joinJournalSecrets: {} as never,
      close: () => Promise.resolve(),
    };
    const mockProfile = vaultProfileSchema.parse({
      version: 1,
      serverUrl: 'https://vault.example/',
      vaultId: vaultIdSchema.parse('vault.existing'),
      deviceId: deviceIdSchema.parse('device.existing'),
      deviceLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse('vault.existing'),
        deviceId: deviceIdSchema.parse('device.existing'),
        keySlotId: 'slot.existing',
      },
      sessionLocator: {
        version: 1,
        vaultId: vaultIdSchema.parse('vault.existing'),
        deviceId: deviceIdSchema.parse('device.existing'),
        purpose: 'api-session',
      },
    });
    const mockEnvironment = {
      profiles: {
        listProfiles: vi.fn().mockResolvedValue([mockProfile]),
      } as never,
      initializationJournal: {} as never,
    };

    const port = createProductionInitializationPort({
      environment: mockEnvironment as never,
      secrets: mockSecrets,
      defaultServerUrl: 'https://vault.example/',
    });

    await expect(port.begin(DEFAULT_VAULT_INITIALIZATION_INPUT)).rejects.toThrow(
      CliUsageError,
    );
    await expect(
      port.beginImportedPortable(
        DEFAULT_VAULT_INITIALIZATION_INPUT,
        'KAVRIX-PORTABLE-KEY',
      ),
    ).rejects.toThrow(CliUsageError);
  });
});
