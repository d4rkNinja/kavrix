import {
  createDeviceKeySlot,
  encryptPayload,
  generateDeviceKey,
  generateVaultRootKey,
  zeroize,
} from '@kavrix/crypto';
import {
  associatedDataSchema,
  deviceIdSchema,
  keySlotIdSchema,
  sessionCredentialSecretSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type VaultRecord,
} from '@kavrix/schemas';
import type { SyncLocalStorePort } from '@kavrix/sync';
import { describe, expect, it, vi } from 'vitest';

import { CliUsageError } from '../src/errors.js';
import {
  connectExistingVault,
  executeProductionConnect,
  type ExistingVaultConnectBackend,
  type ExistingVaultConnectEnvironment,
} from '../src/production/connect.js';

const SERVER_URL = 'https://sync.example/';
const VAULT_ID = vaultIdSchema.parse('vault.connect.test0000000000000001');
const DEVICE_ID = deviceIdSchema.parse('device.connect.test000000000000001');
const SLOT_ID = keySlotIdSchema.parse('slot.connect.test000000000000001');
const SESSION_LOCATOR = {
  version: 1 as const,
  vaultId: VAULT_ID,
  deviceId: DEVICE_ID,
  purpose: 'api-session' as const,
};

describe('production existing-vault connect', () => {
  it('validates credentials, persists the exact profile, and bootstraps opaque sync', async () => {
    const fixture = await createFixture();
    const profiles = {
      listProfiles: vi.fn().mockResolvedValue([]),
      store: vi.fn().mockResolvedValue(undefined),
    };
    const local = {} as SyncLocalStorePort;
    const environment: ExistingVaultConnectEnvironment = {
      profiles,
      openSyncStore: vi.fn().mockResolvedValue(local),
    };
    const sessionSecret = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
    const backend = createBackend(sessionSecret, fixture.deviceKey);
    const getSession = vi.fn().mockResolvedValue({
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
      scopes: ['sync:read', 'sync:write'],
    });
    const fetchVault = vi.fn().mockResolvedValue(fixture.vault);
    const synchronize = vi.fn().mockResolvedValue({ state: 'synced' });
    const controlPlaneFactory = vi.fn(() => ({ getSession, fetchVault }));
    const syncEngineFactory = vi.fn(() => ({ synchronize }));

    const result = await connectExistingVault(
      {
        environment,
        backend,
        request: { serverUrl: SERVER_URL, vaultId: VAULT_ID, deviceId: DEVICE_ID },
      },
      { controlPlaneFactory, syncEngineFactory },
    );

    expect(result).toEqual({ vaultId: VAULT_ID, deviceId: DEVICE_ID });
    expect(getSession).toHaveBeenCalledWith(expect.any(String), VAULT_ID, DEVICE_ID);
    expect(fetchVault).toHaveBeenCalledWith(expect.any(String), VAULT_ID);
    expect(profiles.store).toHaveBeenCalledOnce();
    expect(profiles.store).toHaveBeenCalledWith({
      version: 1,
      serverUrl: SERVER_URL,
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
      deviceLocator: {
        version: 1,
        vaultId: VAULT_ID,
        deviceId: DEVICE_ID,
        keySlotId: SLOT_ID,
      },
      sessionLocator: SESSION_LOCATOR,
    });
    expect(syncEngineFactory).toHaveBeenCalledOnce();
    expect(synchronize).toHaveBeenCalledWith({
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
    });
    expect(sessionSecret.every((byte) => byte === 0)).toBe(true);
    expect(fixture.deviceKey.every((byte) => byte === 0)).toBe(true);
  });

  it('refuses an existing profile before protected credentials are loaded', async () => {
    const sessionLoad = vi.fn();
    const existingProfile = {
      version: 1 as const,
      serverUrl: SERVER_URL,
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
      deviceLocator: {
        version: 1 as const,
        vaultId: VAULT_ID,
        deviceId: DEVICE_ID,
        keySlotId: SLOT_ID,
      },
      sessionLocator: SESSION_LOCATOR,
    };
    const store = vi.fn();
    const environment: ExistingVaultConnectEnvironment = {
      profiles: {
        listProfiles: vi.fn().mockResolvedValue([existingProfile]),
        store,
      },
      openSyncStore: vi.fn(),
    };
    const backend = createBackend(sessionLoad, new Uint8Array(32));

    await expect(
      connectExistingVault({
        environment,
        backend,
        request: { serverUrl: SERVER_URL, vaultId: VAULT_ID, deviceId: DEVICE_ID },
      }),
    ).rejects.toBeInstanceOf(CliUsageError);
    expect(sessionLoad).not.toHaveBeenCalled();
  });

  it('fails closed for a missing or mismatched active device slot', async () => {
    const fixture = await createFixture();
    const environment = emptyEnvironment();
    const sessionSecret = new Uint8Array(32).fill(7);
    const backend = createBackend(sessionSecret, fixture.deviceKey);
    const controlPlaneFactory = vi.fn(() => ({
      getSession: vi.fn().mockResolvedValue({
        vaultId: VAULT_ID,
        deviceId: DEVICE_ID,
        scopes: ['sync:read', 'sync:write'],
      }),
      fetchVault: vi.fn().mockResolvedValue({
        ...fixture.vault,
        keySlots: fixture.vault.keySlots.map((slot) =>
          slot.type === 'device-key'
            ? { ...slot, deviceId: deviceIdSchema.parse('device.other') }
            : slot,
        ),
      }),
    }));

    await expect(
      connectExistingVault(
        {
          environment,
          backend,
          request: { serverUrl: SERVER_URL, vaultId: VAULT_ID, deviceId: DEVICE_ID },
        },
        { controlPlaneFactory, syncEngineFactory: vi.fn() },
      ),
    ).rejects.toMatchObject({ name: 'VaultLifecycleError' });
    expect(environment.openSyncStore).not.toHaveBeenCalled();
  });

  it('closes the environment after a sync failure and leaves the profile retryable', async () => {
    const fixture = await createFixture();
    const close = vi.fn().mockResolvedValue(undefined);
    const profiles = {
      listProfiles: vi.fn().mockResolvedValue([]),
      store: vi.fn().mockResolvedValue(undefined),
    };
    const environment = {
      profiles,
      openSyncStore: vi.fn().mockResolvedValue({}),
      close,
    };
    const sessionSecret = new Uint8Array(32).fill(9);
    const backend = createBackend(sessionSecret, fixture.deviceKey);
    const syncFailure = new Error('network unavailable');

    await expect(
      executeProductionConnect(
        {
          environment: { CREDS_HOME: 'C:\\kavrix-connect-test' },
          secrets: {} as never,
          backendPolicy: { kind: 'native' },
          request: { serverUrl: SERVER_URL, vaultId: VAULT_ID, deviceId: DEVICE_ID },
        },
        {
          resolvePaths: vi.fn().mockReturnValue({}),
          createBackend: vi.fn().mockResolvedValue(backend),
          openEnvironment: vi.fn().mockResolvedValue(environment),
          controlPlaneFactory: vi.fn(() => ({
            getSession: vi.fn().mockResolvedValue({
              vaultId: VAULT_ID,
              deviceId: DEVICE_ID,
              scopes: ['sync:read', 'sync:write'],
            }),
            fetchVault: vi.fn().mockResolvedValue(fixture.vault),
          })),
          syncEngineFactory: vi.fn(() => ({
            synchronize: vi.fn().mockRejectedValue(syncFailure),
          })),
        },
      ),
    ).rejects.toBe(syncFailure);
    expect(profiles.store).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
  });
});

async function createFixture(): Promise<{
  vault: VaultRecord;
  deviceKey: Uint8Array;
}> {
  const rootKey = generateVaultRootKey();
  const deviceKey = generateDeviceKey();
  try {
    const slot = await createDeviceKeySlot(
      {
        vaultId: VAULT_ID,
        deviceId: DEVICE_ID,
        slotId: SLOT_ID,
        schemaVersion: 1,
        keyVersion: 1,
        provider: 'test',
        createdAt: '2026-08-13T00:00:00.000Z',
      },
      deviceKey,
      rootKey,
    );
    const encryptedPreferences = await encryptPayload(
      new TextEncoder().encode('{}'),
      rootKey,
      associatedDataSchema.parse({
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId: VAULT_ID,
        entityType: 'vault-preferences',
        entityId: VAULT_ID,
        purpose: 'vault-preferences',
      }),
    );
    return {
      vault: vaultRecordSchema.parse({
        id: VAULT_ID,
        schemaVersion: 1,
        cryptographicVersion: 1,
        keySlots: [slot],
        currentKeyVersion: 1,
        revision: 0,
        encryptedPreferences,
        createdAt: '2026-08-13T00:00:00.000Z',
        updatedAt: '2026-08-13T00:00:00.000Z',
      }),
      deviceKey,
    };
  } finally {
    zeroize(rootKey);
  }
}

function createBackend(
  sessionSecret: Uint8Array | (() => unknown),
  deviceKey: Uint8Array,
): ExistingVaultConnectBackend {
  return {
    sessions: {
      load:
        typeof sessionSecret === 'function'
          ? sessionSecret
          : vi
              .fn()
              .mockResolvedValue(sessionCredentialSecretSchema.parse(sessionSecret)),
    } as never,
    keychain: {
      load: vi.fn().mockResolvedValue(deviceKey),
    } as never,
    protectedSyncState: {
      load: vi.fn(),
      save: vi.fn(),
      completeObservation: vi.fn(),
    } as never,
  };
}

function emptyEnvironment(): ExistingVaultConnectEnvironment {
  return {
    profiles: {
      listProfiles: vi.fn().mockResolvedValue([]),
      store: vi.fn().mockResolvedValue(undefined),
    },
    openSyncStore: vi.fn().mockResolvedValue({}),
  };
}
