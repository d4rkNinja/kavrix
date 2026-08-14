import {
  manageKeySlotOperation,
  type KeySlotLifecycleOptions,
} from '../src/production/slot-lifecycle.js';
import {
  ControlPlaneFailure,
  vaultProfileSchema,
  type VaultProfile,
} from '@kavrix/client';
import {
  createDeviceKeySlot,
  createPortableKeySlot,
  decryptPayload,
  encryptPayload,
  formatPortableKey,
  formatRecoveryKey,
  generateDeviceKey,
  generatePortableKey,
  generateRecoveryKey,
  generateVaultRootKey,
  zeroize,
} from '@kavrix/crypto';
import {
  associatedDataSchema,
  auditEventIdSchema,
  deviceIdSchema,
  deviceUnlockSecretSchema,
  encryptedAuditRecordSchema,
  keySlotIdSchema,
  keySlotAuditPayloadSchema,
  sessionCredentialSecretSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type DeviceUnlockSecret,
  type KeySlotId,
  type VaultRecord,
} from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

const VAULT_ID = vaultIdSchema.parse('vault.slot.lifecycle.test0000001');
const DEVICE_ID = deviceIdSchema.parse('device.slot.lifecycle.test0001');
const CURRENT_SLOT_ID = keySlotIdSchema.parse('slot.device.lifecycle.current');
const PORTABLE_SLOT_ID = keySlotIdSchema.parse('slot.portable.lifecycle.current');
const SERVER_URL = 'https://sync.example/';
const SESSION_LOCATOR = {
  version: 1 as const,
  vaultId: VAULT_ID,
  deviceId: DEVICE_ID,
  purpose: 'api-session' as const,
};

describe('production unlock-slot lifecycle', () => {
  it('lists safely and composes every documented slot creation path', async () => {
    const fixture = await createFixture();
    let remoteVault = fixture.vault;
    const publishedRequests: { record: VaultRecord; audit?: unknown }[] = [];
    const storedProfile = createProfile(CURRENT_SLOT_ID);
    const profiles = createProfiles(storedProfile);
    const backend = createBackend(fixture.deviceKey);
    const controlPlane = createControlPlane(
      () => remoteVault,
      (record) => {
        remoteVault = record;
      },
      undefined,
      (request) => {
        publishedRequests.push(request);
      },
    );
    const base = createOptions(
      profiles,
      backend,
      controlPlane,
      () => remoteVault,
      () => undefined,
      storedProfile,
      fixture,
    );

    const listed = await manageKeySlotOperation({
      ...base,
      operation: { kind: 'list' },
    });
    expect(listed).toEqual([
      expect.objectContaining({ id: PORTABLE_SLOT_ID, type: 'portable-key' }),
      expect.objectContaining({
        id: CURRENT_SLOT_ID,
        type: 'device-key',
        deviceId: DEVICE_ID,
      }),
    ]);
    expect(JSON.stringify(listed)).not.toContain('wrappedRootKey');
    expect(JSON.stringify(listed)).not.toContain('derivation');

    const passphraseSlot = keySlotIdSchema.parse('slot.passphrase.lifecycle.test');
    const passphraseResult = await manageKeySlotOperation({
      ...base,
      operation: {
        kind: 'create',
        slotType: 'passphrase',
        credential: { kind: 'passphrase', passphrase: 'slot-passphrase-canary' },
        reauthentication: {
          kind: 'portable-key',
          formattedKey: formatPortableKey(fixture.portableKey),
          slotId: PORTABLE_SLOT_ID,
        },
      },
      slotIds: { next: () => passphraseSlot },
    });
    expect(passphraseResult).toMatchObject({
      action: 'created',
      slot: { id: passphraseSlot, type: 'passphrase', state: 'active' },
    });
    expect(JSON.stringify(remoteVault)).not.toContain('slot-passphrase-canary');
    const passphrasePublication = publishedRequests.find((request) =>
      request.record.keySlots.some((slot) => slot.id === passphraseSlot),
    );
    const passphraseAudit = encryptedAuditRecordSchema.parse(
      passphrasePublication?.audit,
    );
    expect(passphraseAudit.encryptedPayload.ciphertext).not.toContain(
      'slot-passphrase-canary',
    );
    const auditPlaintext = await decryptPayload(
      passphraseAudit.encryptedPayload,
      fixture.rootKey,
      passphraseAudit.encryptedPayload.aad,
    );
    try {
      expect(
        keySlotAuditPayloadSchema.parse(
          JSON.parse(new TextDecoder().decode(auditPlaintext)),
        ),
      ).toMatchObject({
        action: 'create',
        slotId: passphraseSlot,
        slotType: 'passphrase',
      });
    } finally {
      zeroize(auditPlaintext);
    }

    const recoverySlot = keySlotIdSchema.parse('slot.recovery.lifecycle.test');
    const recoveryKey = generateRecoveryKey();
    {
      const recoveryResult = await manageKeySlotOperation({
        ...base,
        operation: {
          kind: 'create',
          slotType: 'recovery-key',
          credential: {
            kind: 'recovery-key',
            formattedKey: formatRecoveryKey(recoveryKey),
          },
          reauthentication: {
            kind: 'passphrase',
            passphrase: 'slot-passphrase-canary',
            slotId: passphraseSlot,
          },
        },
        slotIds: { next: () => recoverySlot },
      });
      expect(recoveryResult).toMatchObject({
        action: 'created',
        slot: { id: recoverySlot, type: 'recovery-key', state: 'active' },
      });
    }

    const portableReplacement = generatePortableKey();
    try {
      const replacementSlot = keySlotIdSchema.parse('slot.portable.lifecycle.new');
      const replacementResult = await manageKeySlotOperation({
        ...base,
        operation: {
          kind: 'create',
          slotType: 'portable-key',
          credential: {
            kind: 'portable-key',
            formattedKey: formatPortableKey(portableReplacement),
          },
          reauthentication: {
            kind: 'recovery-key',
            formattedKey: formatRecoveryKey(recoveryKey),
            slotId: recoverySlot,
          },
        },
        slotIds: { next: () => replacementSlot },
      });
      expect(replacementResult).toMatchObject({
        action: 'created',
        slot: { id: replacementSlot, type: 'portable-key', state: 'active' },
      });
    } finally {
      zeroize(portableReplacement);
      zeroize(recoveryKey);
    }

    const secondDeviceSlot = keySlotIdSchema.parse('slot.device.lifecycle.second');
    const deviceResult = await manageKeySlotOperation({
      ...base,
      operation: {
        kind: 'create',
        slotType: 'device-key',
        reauthentication: { kind: 'device-key', slotId: CURRENT_SLOT_ID },
        deviceProvider: 'test-provider',
      },
      slotIds: { next: () => secondDeviceSlot },
    });
    expect(deviceResult).toMatchObject({
      action: 'created',
      slot: { id: secondDeviceSlot, type: 'device-key', deviceId: DEVICE_ID },
    });
    const persistedProfile = profiles.lastStored();
    expect(persistedProfile?.deviceLocator.keySlotId).toBe(secondDeviceSlot);
    expect(JSON.stringify(remoteVault)).not.toContain('slot-passphrase-canary');
    cleanupFixture(fixture);
  });

  it('reconciles a response-loss publication and protects the last current slot', async () => {
    const fixture = await createFixture();
    let remoteVault = fixture.vault;
    const profile = createProfile(CURRENT_SLOT_ID);
    const profiles = createProfiles(profile);
    const backend = createBackend(fixture.deviceKey);
    const publish = vi.fn(
      (
        _bearer: ApiBearerToken,
        _vaultId: string,
        _slotId: KeySlotId,
        request: { record: VaultRecord },
      ) => {
        remoteVault = request.record;
        throw new ControlPlaneFailure('offline');
      },
    );
    const controlPlane = createControlPlane(
      () => remoteVault,
      (record) => {
        remoteVault = record;
      },
      publish,
    );
    const newSlot = keySlotIdSchema.parse('slot.passphrase.response-loss');
    const created = await manageKeySlotOperation({
      ...createOptions(
        profiles,
        backend,
        controlPlane,
        () => remoteVault,
        () => undefined,
        profile,
        fixture,
      ),
      operation: {
        kind: 'create',
        slotType: 'passphrase',
        credential: { kind: 'passphrase', passphrase: 'response-loss-passphrase' },
        reauthentication: { kind: 'device-key', slotId: CURRENT_SLOT_ID },
      },
      slotIds: { next: () => newSlot },
    });
    expect(created).toMatchObject({ action: 'created', slot: { id: newSlot } });
    expect(publish).toHaveBeenCalledOnce();

    const lastFixture = await createFixture();
    let lastRemoteVault = vaultRecordSchema.parse({
      ...lastFixture.vault,
      keySlots: lastFixture.vault.keySlots.map((slot) =>
        slot.id === PORTABLE_SLOT_ID
          ? { ...slot, state: 'revoked', revokedAt: '2026-08-13T00:30:00.000Z' }
          : slot,
      ),
    });
    const lastProfile = createProfile(CURRENT_SLOT_ID);
    const lastProfiles = createProfiles(lastProfile);
    const lastBackend = createBackend(lastFixture.deviceKey);
    const lastControlPlane = createControlPlane(
      () => lastRemoteVault,
      (record) => {
        lastRemoteVault = record;
      },
    );
    const lastSlotAttempt = manageKeySlotOperation({
      ...createOptions(
        lastProfiles,
        lastBackend,
        lastControlPlane,
        () => lastRemoteVault,
        () => undefined,
        lastProfile,
        lastFixture,
      ),
      operation: {
        kind: 'revoke',
        slotId: CURRENT_SLOT_ID,
        reauthentication: { kind: 'device-key', slotId: CURRENT_SLOT_ID },
      },
    });
    await expect(lastSlotAttempt).rejects.toMatchObject({ name: 'LastValidSlotError' });
    cleanupFixture(fixture);
    cleanupFixture(lastFixture);
  });

  it('moves the remembered profile before disabling or revoking its old device slot', async () => {
    const fixture = await createFixture();
    let remoteVault = fixture.vault;
    const oldProfile = createProfile(CURRENT_SLOT_ID);
    const profiles = createProfiles(oldProfile);
    const backend = createBackend(fixture.deviceKey);
    const controlPlane = createControlPlane(
      () => remoteVault,
      (record) => {
        remoteVault = record;
      },
    );
    const replacement = keySlotIdSchema.parse('slot.device.lifecycle.replacement');
    await manageKeySlotOperation({
      ...createOptions(
        profiles,
        backend,
        controlPlane,
        () => remoteVault,
        () => undefined,
        oldProfile,
        fixture,
      ),
      operation: {
        kind: 'create',
        slotType: 'device-key',
        reauthentication: { kind: 'device-key', slotId: CURRENT_SLOT_ID },
      },
      slotIds: { next: () => replacement },
    });
    const currentProfile = profiles.current();
    const revoked = await manageKeySlotOperation({
      ...createOptions(
        profiles,
        backend,
        controlPlane,
        () => remoteVault,
        () => undefined,
        currentProfile,
        fixture,
      ),
      operation: {
        kind: 'revoke',
        slotId: CURRENT_SLOT_ID,
        reauthentication: { kind: 'device-key', slotId: replacement },
      },
    });
    expect(revoked).toMatchObject({
      action: 'revoked',
      slot: { id: CURRENT_SLOT_ID, state: 'revoked' },
    });
    expect(profiles.current().deviceLocator.keySlotId).toBe(replacement);
    await expect(
      manageKeySlotOperation({
        ...createOptions(
          profiles,
          backend,
          controlPlane,
          () => remoteVault,
          () => undefined,
          profiles.current(),
          fixture,
        ),
        operation: {
          kind: 'disable',
          slotId: PORTABLE_SLOT_ID,
          reauthentication: { kind: 'device-key', slotId: replacement },
        },
      }),
    ).rejects.toMatchObject({ name: 'CliUsageError' });
    cleanupFixture(fixture);
  });
});

async function createFixture(): Promise<{
  vault: VaultRecord;
  rootKey: Uint8Array;
  portableKey: Uint8Array;
  deviceKey: Uint8Array;
}> {
  const rootKey = generateVaultRootKey();
  const portableKey = generatePortableKey();
  const deviceKey = generateDeviceKey();
  const portableSlot = await createPortableKeySlot(
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
  const deviceSlot = await createDeviceKeySlot(
    {
      vaultId: VAULT_ID,
      slotId: CURRENT_SLOT_ID,
      schemaVersion: 1,
      keyVersion: 1,
      createdAt: '2026-08-13T00:00:00.000Z',
      deviceId: DEVICE_ID,
      provider: 'test',
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
      keySlots: [portableSlot, deviceSlot],
      currentKeyVersion: 1,
      revision: 0,
      encryptedPreferences,
      createdAt: '2026-08-13T00:00:00.000Z',
      updatedAt: '2026-08-13T00:00:00.000Z',
    }),
    rootKey,
    portableKey,
    deviceKey,
  };
}

function createProfile(slotId: KeySlotId): VaultProfile {
  return vaultProfileSchema.parse({
    version: 1,
    serverUrl: SERVER_URL,
    vaultId: VAULT_ID,
    deviceId: DEVICE_ID,
    deviceLocator: {
      version: 1,
      vaultId: VAULT_ID,
      deviceId: DEVICE_ID,
      keySlotId: slotId,
    },
    sessionLocator: SESSION_LOCATOR,
  });
}

type TestProfiles = KeySlotLifecycleOptions['environment']['profiles'] & {
  listProfiles(): Promise<readonly VaultProfile[]>;
  current(): VaultProfile;
  lastStored(): VaultProfile | undefined;
};

function createProfiles(initial: VaultProfile): TestProfiles {
  let current = structuredClone(initial);
  let lastStored: VaultProfile | undefined;
  const store = vi.fn((profile: VaultProfile) => {
    current = structuredClone(profile);
    lastStored = structuredClone(profile);
    return Promise.resolve();
  });
  return {
    listProfiles: () => Promise.resolve([structuredClone(current)]),
    store,
    load: () => Promise.resolve(structuredClone(current)),
    current: () => structuredClone(current),
    lastStored: () =>
      lastStored === undefined ? undefined : structuredClone(lastStored),
  };
}

function createBackend(deviceKey: Uint8Array): KeySlotLifecycleOptions['backend'] {
  const session = sessionCredentialSecretSchema.parse(new Uint8Array(32).fill(7));
  const entries = new Map<string, Uint8Array>();
  entries.set(CURRENT_SLOT_ID, Uint8Array.from(deviceKey));
  return {
    sessions: {
      load: () => Promise.resolve(Uint8Array.from(session)),
    } as never,
    keychain: {
      load: (locator: { keySlotId: KeySlotId }) => {
        const value = entries.get(locator.keySlotId);
        return Promise.resolve(
          value === undefined
            ? null
            : deviceUnlockSecretSchema.parse(Uint8Array.from(value)),
        );
      },
      store: (locator: { keySlotId: KeySlotId }, secret: DeviceUnlockSecret) => {
        entries.set(locator.keySlotId, Uint8Array.from(secret));
        return Promise.resolve();
      },
      delete: (locator: { keySlotId: KeySlotId }) => {
        entries.delete(locator.keySlotId);
        return Promise.resolve();
      },
    } as never,
  };
}

function createControlPlane(
  getVault: () => VaultRecord,
  setVault: (record: VaultRecord) => void,
  publishKeySlot = vi.fn(
    (
      _bearer: ApiBearerToken,
      _vaultId: string,
      _slotId: KeySlotId,
      request: { record: VaultRecord; audit?: unknown },
    ) => {
      setVault(request.record);
      onPublish?.(request);
      return Promise.resolve();
    },
  ),
  onPublish?: (request: { record: VaultRecord; audit?: unknown }) => void,
): KeySlotLifecycleOptions['controlPlane'] {
  return {
    getSession: () =>
      Promise.resolve({
        vaultId: VAULT_ID,
        deviceId: DEVICE_ID,
        scopes: ['sync:read', 'sync:write', 'device:manage'],
      }),
    fetchVault: () => Promise.resolve(structuredClone(getVault())),
    publishKeySlot,
    revokeKeySlot: (_bearer, _vaultId, _slotId, request) => {
      setVault(request.record);
      return Promise.resolve();
    },
  };
}

function createOptions(
  profiles: ReturnType<typeof createProfiles>,
  backend: KeySlotLifecycleOptions['backend'],
  controlPlane: KeySlotLifecycleOptions['controlPlane'],
  _getVault: () => VaultRecord,
  _setVault: (record: VaultRecord) => void,
  profile: VaultProfile,
  _fixture: {
    vault: VaultRecord;
    rootKey: Uint8Array;
    portableKey: Uint8Array;
    deviceKey: Uint8Array;
  },
): Omit<KeySlotLifecycleOptions, 'operation' | 'slotIds'> & {
  slotIds: { next: () => KeySlotId };
} {
  void _fixture;
  return {
    environment: { profiles },
    backend,
    profile,
    controlPlane,
    clock: { now: () => new Date('2026-08-13T01:00:00.000Z') },
    slotIds: { next: () => keySlotIdSchema.parse('slot.unused.lifecycle.default') },
    idempotencyKeys: { next: () => 'slot-lifecycle-idempotency-0001' },
    auditIds: { next: () => auditEventIdSchema.parse('audit.slot.lifecycle.test') },
  };
}

function cleanupFixture(fixture: {
  rootKey: Uint8Array;
  portableKey: Uint8Array;
  deviceKey: Uint8Array;
}): void {
  zeroize(fixture.rootKey);
  zeroize(fixture.portableKey);
  zeroize(fixture.deviceKey);
}
