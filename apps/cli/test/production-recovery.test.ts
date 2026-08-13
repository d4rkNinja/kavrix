import {
  createPortableKeySlot,
  encryptPayload,
  formatPortableKey,
  generatePortableKey,
  generateVaultRootKey,
  unlockDeviceKeySlot,
  zeroize,
} from '@kavrix/crypto';
import { lifecycleOperationIdSchema, type VaultProfile } from '@kavrix/client';
import {
  associatedDataSchema,
  deviceIdSchema,
  deviceUnlockSecretSchema,
  keySlotIdSchema,
  sessionCredentialSecretSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type DeviceId,
  type DeviceUnlockSecret,
  type KeySlotId,
  type SessionCredentialSecret,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import type { SyncLocalStorePort } from '@kavrix/sync';
import { describe, expect, it, vi } from 'vitest';

import { CliUsageError } from '../src/errors.js';
import {
  executeProductionRecovery,
  executeProductionRecoveryCancel,
  recoverExistingVault,
  type RecoveryBackend,
  type RecoveryControlPlane,
  type RecoveryEnvironment,
} from '../src/production/recovery.js';
import { acquiredSecretSchema, type SecretInputPort } from '../src/secret-input.js';
const SERVER_URL = 'https://sync.example/';
const VAULT_ID = vaultIdSchema.parse('vault.recover.test00000000000001');
const DEVICE_ID = deviceIdSchema.parse('device.recovered.test00000000001');
const PORTABLE_SLOT_ID = keySlotIdSchema.parse('slot.portable.recover.test0001');
const OPERATION_ID = lifecycleOperationIdSchema.parse('operation.recover.test.0001');
const INVITE_TOKEN = 'A'.repeat(43);

describe('production fresh-home recovery', () => {
  it('authenticates the portable slot locally, persists a fresh device slot and profile, then syncs', async () => {
    const fixture = await createFixture();
    const sessionSecret = sessionCredentialSecretSchema.parse(
      Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    );
    const storedDeviceSecrets: Uint8Array[] = [];
    const backend = createBackend(sessionSecret, storedDeviceSecrets);
    let storedProfile: VaultProfile | null = null;
    let remoteVault = fixture.vault;
    const profiles = {
      listProfiles: vi.fn().mockResolvedValue([]),
      store: vi.fn(async (profile: VaultProfile) => {
        storedProfile = structuredClone(profile);
      }),
      load: vi.fn(async () => storedProfile),
    };
    const local = {} as SyncLocalStorePort;
    const environment: RecoveryEnvironment = {
      profiles,
      joinJournal: {} as never,
      openSyncStore: vi.fn().mockResolvedValue(local),
    };
    const getSession = vi.fn().mockResolvedValue({
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
      scopes: ['sync:read', 'sync:write', 'device:manage'],
    });
    const fetchVault = vi.fn(async () => remoteVault);
    const publishKeySlot = vi.fn(
      async (
        _bearer: ApiBearerToken,
        _vaultId: VaultId,
        _slotId: KeySlotId,
        request: Readonly<{
          expectedVaultRevision: number;
          idempotencyKey: string;
          record: VaultRecord;
        }>,
      ) => {
        remoteVault = request.record;
      },
    );
    const controlPlane: RecoveryControlPlane = {
      getSession,
      fetchVault,
      publishKeySlot,
    };
    const begin = vi.fn().mockResolvedValue({
      operationId: OPERATION_ID,
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
    });
    const resume = vi.fn().mockResolvedValue({
      operationId: OPERATION_ID,
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
    });
    const coordinator = {
      begin,
      resume,
      cancel: vi.fn(),
    };
    const synchronize = vi.fn().mockResolvedValue({ state: 'synced' });
    const syncEngineFactory = vi.fn(() => ({ synchronize }));

    const result = await recoverExistingVault({
      environment,
      backend,
      controlPlane,
      coordinator,
      request: { serverUrl: SERVER_URL, vaultId: VAULT_ID },
      inviteToken: INVITE_TOKEN,
      portableKey: formatPortableKey(fixture.portableKey),
      syncEngineFactory,
    });

    expect(result).toEqual({
      operationId: OPERATION_ID,
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
    });
    expect(begin).toHaveBeenCalledWith({
      inviteBearer: INVITE_TOKEN,
      expectedVaultId: VAULT_ID,
    });
    expect(resume).toHaveBeenCalledWith(
      OPERATION_ID,
      formatPortableKey(fixture.portableKey),
    );
    expect(publishKeySlot).toHaveBeenCalledOnce();
    expect(publishKeySlot.mock.calls[0]?.[3].expectedVaultRevision).toBe(0);
    expect(publishKeySlot.mock.calls[0]?.[3].record.revision).toBe(1);
    expect(JSON.stringify(publishKeySlot.mock.calls[0]?.[3].record)).not.toContain(
      Buffer.from(fixture.rootKey).toString('base64url'),
    );
    expect(profiles.store).toHaveBeenCalledOnce();
    expect(storedProfile).toMatchObject({
      version: 1,
      serverUrl: SERVER_URL,
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
      deviceLocator: {
        version: 1,
        vaultId: VAULT_ID,
        deviceId: DEVICE_ID,
      },
    });
    expect(syncEngineFactory).toHaveBeenCalledOnce();
    expect(synchronize).toHaveBeenCalledWith({
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
    });
    expect(storedDeviceSecrets).toHaveLength(1);
    const publishedSlot = remoteVault.keySlots.find(
      (slot) => slot.type === 'device-key' && slot.deviceId === DEVICE_ID,
    );
    expect(publishedSlot).toBeDefined();
    const verifiedRoot = await unlockDeviceKeySlot(
      publishedSlot as Extract<VaultRecord['keySlots'][number], { type: 'device-key' }>,
      storedDeviceSecrets[0] as DeviceUnlockSecret,
      {
        vaultId: VAULT_ID,
        slotId: publishedSlot?.id as KeySlotId,
        schemaVersion: 1,
        keyVersion: 1,
      },
    );
    expect(Buffer.from(verifiedRoot).toString('hex')).toBe(
      Buffer.from(fixture.rootKey).toString('hex'),
    );
    zeroize(verifiedRoot);
    expect(sessionSecret.every((byte) => byte === 0)).toBe(true);
    expect(fixture.rootKey.every((byte) => byte === 0)).toBe(false);
    zeroize(fixture.rootKey);
    zeroize(fixture.portableKey);
  });

  it('rejects a non-empty local data home before loading protected credentials', async () => {
    const sessionLoad = vi.fn();
    const environment: RecoveryEnvironment = {
      profiles: {
        listProfiles: vi.fn().mockResolvedValue([{} as VaultProfile]),
        store: vi.fn(),
        load: vi.fn(),
      },
      joinJournal: {} as never,
      openSyncStore: vi.fn(),
    };

    await expect(
      recoverExistingVault({
        environment,
        backend: {
          sessions: {
            load: sessionLoad,
            store: vi.fn(),
            delete: vi.fn(),
          },
          keychain: {} as never,
          protectedSyncState: {} as never,
        },
        controlPlane: {} as RecoveryControlPlane,
        coordinator: {} as never,
        request: { serverUrl: SERVER_URL, vaultId: VAULT_ID },
        inviteToken: INVITE_TOKEN,
        portableKey: 'portable-key-canary',
      }),
    ).rejects.toBeInstanceOf(CliUsageError);
    expect(sessionLoad).not.toHaveBeenCalled();
  });

  it('preflights a portable-key path before opening the protected backend', async () => {
    const validateKeyFile = vi
      .fn()
      .mockRejectedValue(new CliUsageError('The portable key file is unsafe.'));
    const createBackend = vi.fn();

    await expect(
      executeProductionRecovery(
        {
          environment: { CREDS_HOME: 'C:\\kavrix-recovery-test' },
          secrets: {} as SecretInputPort,
          backendPolicy: { kind: 'native' },
          request: { serverUrl: SERVER_URL, vaultId: VAULT_ID },
          keyFilePath: 'unsafe.cvk',
        },
        {
          resolvePaths: vi.fn().mockReturnValue({}),
          validateKeyFile,
          createBackend,
        },
      ),
    ).rejects.toBeInstanceOf(CliUsageError);
    expect(validateKeyFile).toHaveBeenCalledWith('unsafe.cvk');
    expect(createBackend).not.toHaveBeenCalled();
  });

  it('consumes invite and protected-file passphrase as one exact stdin frame batch', async () => {
    const readBatch = vi
      .fn()
      .mockResolvedValue([
        acquiredSecretSchema.parse(INVITE_TOKEN),
        acquiredSecretSchema.parse('file-passphrase-canary'),
      ]);
    const readPassphrase = vi.fn();
    const close = vi.fn().mockResolvedValue(undefined);
    const environment = {
      profiles: {
        listProfiles: vi.fn().mockResolvedValue([]),
        store: vi.fn(),
        load: vi.fn(),
      },
      joinJournal: {} as never,
      openSyncStore: vi.fn(),
      close,
    };
    const coordinator = {
      begin: vi.fn().mockResolvedValue({
        operationId: OPERATION_ID,
        vaultId: VAULT_ID,
        deviceId: DEVICE_ID,
      }),
      resume: vi.fn().mockRejectedValue(new CliUsageError('stop after source read')),
      cancel: vi.fn(),
    };

    await expect(
      executeProductionRecovery(
        {
          environment: { CREDS_HOME: 'C:\\kavrix-recovery-framed' },
          secrets: {
            read: readPassphrase,
            readBatch,
          },
          backendPolicy: { kind: 'native' },
          request: { serverUrl: SERVER_URL, vaultId: VAULT_ID },
          inviteFromStdin: true,
          keyFilePath: 'protected.cvk',
          keyFilePassphraseFromStdin: true,
        },
        {
          resolvePaths: vi.fn().mockReturnValue({}),
          validateKeyFile: vi.fn().mockResolvedValue(undefined),
          createBackend: vi.fn().mockResolvedValue({}),
          openEnvironment: vi.fn().mockResolvedValue(environment),
          controlPlaneFactory: vi.fn(() => ({}) as RecoveryControlPlane),
          coordinatorFactory: vi.fn(() => coordinator),
          keyFileReaderFactory: vi.fn(({ secrets, passphraseFromStdin }) => {
            expect(passphraseFromStdin).toBe(true);
            return {
              readFormattedPortableKey: async () => {
                const passphrase = await secrets.read({
                  kind: 'passphrase',
                  fromStdin: true,
                });
                expect(passphrase).toBe('file-passphrase-canary');
                return 'cvk1_test';
              },
            };
          }),
        },
      ),
    ).rejects.toBeInstanceOf(CliUsageError);
    expect(readBatch).toHaveBeenCalledWith({
      kinds: ['invite', 'passphrase'],
      fromStdin: true,
      requireEnd: true,
    });
    expect(readPassphrase).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();
  });

  it('cancels a prepared recovery journal without reading secret input', async () => {
    const cancel = vi.fn().mockResolvedValue(undefined);
    const close = vi.fn().mockResolvedValue(undefined);
    const backend = createBackend(
      sessionCredentialSecretSchema.parse(new Uint8Array(32).fill(4)),
      [],
    );
    const environment = {
      profiles: {} as never,
      joinJournal: {} as never,
      openSyncStore: vi.fn(),
      close,
    };
    const secrets = {
      read: vi.fn(),
      readBatch: vi.fn(),
    } as unknown as SecretInputPort;

    await executeProductionRecoveryCancel(
      {
        environment: { CREDS_HOME: 'C:\\kavrix-recovery-cancel' },
        secrets,
        backendPolicy: { kind: 'native' },
        request: { serverUrl: SERVER_URL, vaultId: VAULT_ID },
        operationId: OPERATION_ID,
      },
      {
        resolvePaths: vi.fn().mockReturnValue({}),
        createBackend: vi.fn().mockResolvedValue(backend),
        openEnvironment: vi.fn().mockResolvedValue(environment),
        controlPlaneFactory: vi.fn(() => ({}) as RecoveryControlPlane),
        coordinatorFactory: vi.fn(() => ({
          begin: vi.fn(),
          resume: vi.fn(),
          cancel,
        })),
      },
    );

    expect(cancel).toHaveBeenCalledWith(OPERATION_ID);
    expect(secrets.read).not.toHaveBeenCalled();
    expect(secrets.readBatch).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();
  });
});

async function createFixture(): Promise<{
  vault: VaultRecord;
  portableKey: Uint8Array;
  rootKey: Uint8Array;
}> {
  const rootKey = generateVaultRootKey();
  const portableKey = generatePortableKey();
  try {
    const slot = await createPortableKeySlot(
      {
        vaultId: VAULT_ID,
        slotId: PORTABLE_SLOT_ID,
        schemaVersion: 1,
        keyVersion: 1,
        createdAt: '2026-08-13T00:00:00.000Z',
      },
      portableKey,
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
      portableKey,
      rootKey: Uint8Array.from(rootKey),
    };
  } finally {
    zeroize(rootKey);
  }
}

function createBackend(
  sessionSecret: SessionCredentialSecret,
  storedDeviceSecrets: Uint8Array[],
): RecoveryBackend {
  return {
    sessions: {
      load: vi.fn().mockResolvedValue(sessionSecret),
      store: vi.fn(),
      delete: vi.fn(),
    },
    keychain: {
      load: vi.fn(async () => {
        const value = storedDeviceSecrets[0];
        return value === undefined
          ? null
          : deviceUnlockSecretSchema.parse(Uint8Array.from(value));
      }),
      store: vi.fn(async (_locator, secret: DeviceUnlockSecret) => {
        storedDeviceSecrets.push(Uint8Array.from(secret));
      }),
      delete: vi.fn(),
    },
    protectedSyncState: {
      load: vi.fn().mockResolvedValue(null),
      save: vi.fn().mockResolvedValue(undefined),
      completeObservation: vi.fn().mockResolvedValue(undefined),
    },
  };
}
