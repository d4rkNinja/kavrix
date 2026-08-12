import type { ServerResponse } from 'node:http';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type {
  ClipboardCopyOptions,
  ClipboardCopyReceipt,
  SecureClipboardPort,
} from '@kavrix/clipboard';
import type { KeychainPort, SessionCredentialPort } from '@kavrix/core';
import {
  createDeviceKeySlot,
  createPassphraseKeySlot,
  createPortableKeySlot,
  createRecoveryKeySlot,
  formatPortableKey,
  formatRecoveryKey,
  generateDeviceKey,
  generatePortableKey,
  generateRecoveryKey,
  zeroize,
  type SlotIdentity,
} from '@kavrix/crypto';
import {
  deviceIdSchema,
  deviceUnlockSecretSchema,
  fieldDefinitionSchema,
  itemPayloadSchema,
  keychainLocatorSchema,
  keySlotIdSchema,
  sessionCredentialLocatorSchema,
  sessionCredentialSecretSchema,
  timestampSchema,
  vaultRecordSchema,
  type DeviceUnlockSecret,
  type KeychainLocator,
  type OpaqueMutation,
  type ProtectedLocalDeviceState,
  type SessionCredentialLocator,
  type SessionCredentialSecret,
  type SyncCursor,
  type SyncPulledChange,
  type TemplateMigrationPublicationRequest,
  type VaultRecord,
} from '@kavrix/schemas';
import type {
  ActivePushBatch,
  ApplyPullPageInput,
  CompletedOutboundObservation,
  EnsureOutboundReplayStartInput,
  OutboundReplayState,
  ProtectedSyncStatePort,
  ReconcileOutboundObservationInput,
  SyncStatusPort,
  SyncEngineOptions,
} from '@kavrix/sync';

import {
  VaultClientSession,
  VaultClientSessionError,
  VaultReadSession,
  vaultProfileSchema,
  type VaultClientSessionOptions,
  type VaultProfile,
} from '../src/index.js';
import {
  MemoryReadSource,
  encryptedFixture,
  type EncryptedFixture,
} from './fixtures.js';
import {
  readRequest,
  startLoopbackServer,
  type LoopbackServer,
} from './loopback-server.js';

const NOW = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const DEVICE_ID = deviceIdSchema.parse('device.session');
const PORTABLE_SLOT = keySlotIdSchema.parse('slot.portable');
const RECOVERY_SLOT = keySlotIdSchema.parse('slot.recovery');
const PASSPHRASE_SLOT = keySlotIdSchema.parse('slot.passphrase');
const DEVICE_SLOT = keySlotIdSchema.parse('slot.device');
const PASSPHRASE = new TextEncoder().encode('correct horse battery staple');
const COPY_CANARY = 'SESSION-FACADE-COPY-CANARY';
const servers: LoopbackServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe('VaultClientSession', () => {
  it.each(['portable', 'recovery', 'passphrase', 'device'] as const)(
    'unlocks through the %s slot with exact online bindings and safe show/copy',
    async (mode) => {
      const material = await sessionFixture();
      const remote = await startRemote(material.fixture.vault);
      const store = new SessionStore(material.fixture);
      const sessions = new MemorySessions(material.sessionSecret);
      const keychain = new MemoryKeychain(material.deviceSecret);
      const clipboard = new RecordingClipboard();
      const session = buildSession(
        material,
        remote,
        store,
        sessions,
        keychain,
        clipboard,
      );

      await unlockByMode(session, material, mode);

      expect(session.status()).toEqual({
        state: 'unlocked',
        vaultId: material.fixture.vaultId,
        deviceId: DEVICE_ID,
      });
      const shown = await session.show('group.1', 'item.1.1');
      expect(shown.fields).toEqual([
        expect.objectContaining({ stableKey: 'password', value: '[REDACTED]' }),
      ]);
      expect(JSON.stringify(shown)).not.toContain(COPY_CANARY);
      await expect(session.show('Production', 'Primary')).resolves.toMatchObject({
        id: 'item.1.1',
      });
      const receipt = await session.copy('group.1', 'item.1.1', 'password');
      expect(receipt).toEqual({ label: 'Password', clearAfterSeconds: 30 });
      expect(JSON.stringify(receipt)).not.toContain(COPY_CANARY);
      expect(clipboard.observed).toEqual(new TextEncoder().encode(COPY_CANARY));
      expect(clipboard.reference?.every((byte) => byte === 0)).toBe(true);
      expect(remote.seen.map(({ path }) => path)).toEqual([
        '/v1/session',
        `/v1/vaults/${material.fixture.vaultId}`,
      ]);
      expect(
        remote.seen.every(({ authorization }) => authorization === remote.auth),
      ).toBe(true);
      expect(sessions.lastLoaded?.every((byte) => byte === 0)).toBe(true);
      if (mode === 'device') {
        expect(keychain.lastLoaded?.every((byte) => byte === 0)).toBe(true);
      }

      await session.lock();
      expect(session.locked).toBe(true);
      expect(session.status()).toMatchObject({ state: 'locked' });
      expect(clipboard.lockCalls).toBe(1);
      await expect(session.show('group.1', 'item.1.1')).rejects.toMatchObject({
        kind: 'locked',
      });
      material.dispose();
    },
  );

  it('rejects malformed profile and formatted material before network access', async () => {
    const material = await sessionFixture();
    const remote = await startRemote(material.fixture.vault);
    const dependencies = dependencySet(material);

    expect(
      vaultProfileSchema.parse(profile(material, 'https://vault.example.test/')),
    ).toMatchObject({ serverUrl: 'https://vault.example.test/' });
    expect(
      vaultProfileSchema.parse(profile(material, 'http://[::1]:8080/')),
    ).toMatchObject({ serverUrl: 'http://[::1]:8080/' });
    expect(() =>
      vaultProfileSchema.parse({
        ...profile(material, 'https://vault.example.test/'),
        deviceLocator: {
          ...material.profileLocators.device,
          deviceId: 'device.cross',
        },
      }),
    ).toThrow();
    expect(
      () =>
        new VaultClientSession({
          ...dependencies,
          profile: {
            ...profile(material, 'https://vault.example.test/'),
            serverUrl: 'not-a-url',
          },
        }),
    ).toThrow(VaultClientSessionError);

    expect(
      () =>
        new VaultClientSession({
          ...dependencies,
          profile: profile(material, remote.server.url),
        }),
    ).toThrow(VaultClientSessionError);
    expect(() =>
      vaultProfileSchema.parse({
        ...profile(material, `${remote.server.url}/`),
        serverUrl: `http://example.com/`,
      }),
    ).toThrow();
    const session = new VaultClientSession({
      ...dependencies,
      profile: profile(material, `${remote.server.url}/`),
      allowInsecureLoopbackDevelopment: true,
    });
    await expect(session.unlockPortable('portable-key-canary')).rejects.toMatchObject({
      kind: 'invalid-input',
    });
    await expect(session.unlockRecovery('recovery-key-canary')).rejects.toMatchObject({
      kind: 'invalid-input',
    });
    await expect(
      session.unlockPassphrase(new Uint8Array(), PASSPHRASE_SLOT),
    ).rejects.toMatchObject({ kind: 'invalid-input' });
    expect(remote.seen).toHaveLength(0);
    material.dispose();
  });

  it('fails closed for missing, wrong, tampered, cross-vault, and revoked inputs', async () => {
    const wrong = await sessionFixture();
    const remote = await startRemote(wrong.fixture.vault);
    const missingSessions = new MemorySessions(null);
    const missing = buildSession(
      wrong,
      remote,
      new SessionStore(wrong.fixture),
      missingSessions,
      new MemoryKeychain(wrong.deviceSecret),
      new RecordingClipboard(),
    );
    await expect(missing.unlockPortable(wrong.portableFormatted)).rejects.toMatchObject(
      {
        kind: 'authentication',
      },
    );
    expect(remote.seen).toHaveLength(0);

    const wrongKey = generatePortableKey();
    const wrongFormatted = formatPortableKey(wrongKey);
    zeroize(wrongKey);
    const wrongSession = buildSession(
      wrong,
      remote,
      new SessionStore(wrong.fixture),
      new MemorySessions(wrong.sessionSecret),
      new MemoryKeychain(wrong.deviceSecret),
      new RecordingClipboard(),
    );
    await expect(wrongSession.unlockPortable(wrongFormatted)).rejects.toMatchObject({
      kind: 'authentication',
    });

    const tamperedVault = structuredClone(wrong.fixture.vault);
    const portableIndex = tamperedVault.keySlots.findIndex(
      ({ id }) => id === PORTABLE_SLOT,
    );
    const portable = tamperedVault.keySlots[portableIndex];
    if (portable?.type !== 'portable-key') throw new Error();
    tamperedVault.keySlots[portableIndex] = {
      ...portable,
      wrappedRootKey: mutateEnvelope(portable.wrappedRootKey),
    };
    remote.vault = vaultRecordSchema.parse(tamperedVault);
    const tampered = buildSession(
      wrong,
      remote,
      new SessionStore(wrong.fixture),
      new MemorySessions(wrong.sessionSecret),
      new MemoryKeychain(wrong.deviceSecret),
      new RecordingClipboard(),
    );
    await expect(
      tampered.unlockPortable(wrong.portableFormatted),
    ).rejects.toMatchObject({
      kind: 'authentication',
    });

    remote.vault = { ...wrong.fixture.vault, id: 'vault.cross' } as VaultRecord;
    const crossed = buildSession(
      wrong,
      remote,
      new SessionStore(wrong.fixture),
      new MemorySessions(wrong.sessionSecret),
      new MemoryKeychain(wrong.deviceSecret),
      new RecordingClipboard(),
    );
    await expect(crossed.unlockPortable(wrong.portableFormatted)).rejects.toMatchObject(
      {
        kind: 'protocol',
      },
    );

    remote.vault = wrong.fixture.vault;
    const missingDevice = buildSession(
      wrong,
      remote,
      new SessionStore(wrong.fixture),
      new MemorySessions(wrong.sessionSecret),
      new MemoryKeychain(null),
      new RecordingClipboard(),
    );
    await expect(missingDevice.unlockRememberedDevice()).rejects.toMatchObject({
      kind: 'authentication',
    });

    remote.sessionStatus = 403;
    const sessions = new MemorySessions(wrong.sessionSecret);
    const keychain = new MemoryKeychain(wrong.deviceSecret);
    const revoked = buildSession(
      wrong,
      remote,
      new SessionStore(wrong.fixture),
      sessions,
      keychain,
      new RecordingClipboard(),
    );
    await expect(revoked.unlockRememberedDevice()).rejects.toMatchObject({
      kind: 'authentication',
    });
    expect(sessions.deleteCalls).toBe(0);
    expect(keychain.deleteCalls).toBe(0);
    expect(revoked.locked).toBe(true);
    wrong.dispose();
  });

  it('requires least-privilege sync scopes and accepts additional management scope', async () => {
    const material = await sessionFixture();
    const remote = await startRemote(material.fixture.vault);
    remote.scopes = ['sync:read'];
    const denied = buildDefaultSession(material, remote);
    await expect(
      denied.unlockPortable(material.portableFormatted),
    ).rejects.toMatchObject({
      kind: 'authentication',
    });
    expect(remote.seen.map(({ path }) => path)).toEqual(['/v1/session']);

    remote.scopes = ['sync:read', 'sync:write', 'device:manage'];
    const allowed = buildDefaultSession(material, remote);
    await expect(
      allowed.unlockPortable(material.portableFormatted),
    ).resolves.toBeUndefined();
    await allowed.lock();
    material.dispose();
  });

  it('preserves safe control-plane retry classification without server detail', async () => {
    const material = await sessionFixture();
    const remote = await startRemote(material.fixture.vault);
    remote.sessionStatus = 429;
    const limited = await rejected(
      buildDefaultSession(material, remote).unlockPortable(material.portableFormatted),
    );
    expect(limited).toMatchObject({
      kind: 'rate-limited',
      retryable: true,
      retryAfterMs: 2_000,
    });
    expect(JSON.stringify(limited)).not.toContain('denied-detail-canary');

    remote.sessionStatus = 500;
    await expect(
      buildDefaultSession(material, remote).unlockPortable(material.portableFormatted),
    ).rejects.toMatchObject({ kind: 'server-unavailable', retryable: true });

    const offline = new VaultClientSession({
      ...dependencySet(material),
      profile: profile(material, 'http://127.0.0.1:9/'),
      network: { timeoutMs: 250 },
      allowInsecureLoopbackDevelopment: true,
    });
    await expect(
      offline.unlockPortable(material.portableFormatted),
    ).rejects.toMatchObject({ kind: 'network-unavailable', retryable: true });
    material.dispose();
  });

  it('syncs exact profile bindings and terminally locks on rotation or authorization loss', async () => {
    const material = await sessionFixture();
    const remote = await startRemote(material.fixture.vault);
    const store = new SessionStore(material.fixture);
    const clipboard = new RecordingClipboard();
    const session = buildSession(
      material,
      remote,
      store,
      new MemorySessions(material.sessionSecret),
      new MemoryKeychain(material.deviceSecret),
      clipboard,
    );
    await session.unlockPortable(material.portableFormatted);
    await expect(session.synchronize()).resolves.toMatchObject({ state: 'synced' });
    expect(remote.seen.at(-1)?.path).toBe(
      `/v1/vaults/${material.fixture.vaultId}/sync`,
    );
    expect(remote.seen.at(-1)?.query).toMatchObject({
      serverSequence: '0',
      highestSeenVaultRevision: '0',
    });

    store.afterApply = () => {
      store.vault = {
        ...material.fixture.vault,
        currentKeyVersion: material.fixture.vault.currentKeyVersion + 1,
        revision: material.fixture.vault.revision + 1,
      } as VaultRecord;
    };
    await expect(session.synchronize()).rejects.toMatchObject({
      kind: 'terminal-sync',
    });
    expect(session.locked).toBe(true);
    expect(clipboard.lockCalls).toBe(1);

    const authStore = new SessionStore(material.fixture);
    const authSession = buildDefaultSession(material, remote, authStore);
    remote.syncStatus = 403;
    await authSession.unlockPortable(material.portableFormatted);
    await expect(authSession.synchronize()).rejects.toMatchObject({
      kind: 'authentication',
    });
    expect(authSession.locked).toBe(true);

    remote.syncStatus = 200;
    const rollback = buildDefaultSession(material, remote);
    await rollback.unlockPortable(material.portableFormatted);
    await rollback.synchronize();
    remote.vault = { ...material.fixture.vault, revision: 0 } as VaultRecord;
    await expect(rollback.synchronize()).rejects.toMatchObject({
      kind: 'terminal-sync',
    });
    expect(rollback.locked).toBe(true);
    material.dispose();
  });

  it('terminally locks and releases unlocked state on a loopback rollback response', async () => {
    const material = await sessionFixture();
    const remote = await startRemote(material.fixture.vault);
    const store = new SessionStore(material.fixture);
    const sessions = new MemorySessions(material.sessionSecret);
    const keychain = new MemoryKeychain(material.deviceSecret);
    const clipboard = new RecordingClipboard();
    const session = buildSession(
      material,
      remote,
      store,
      sessions,
      keychain,
      clipboard,
    );
    const bodyCanary = 'rollback-session-body-canary-a612';
    remote.syncStatus = 409;
    remote.syncErrorBody = {
      error: {
        code: 'SYNC_ROLLBACK_DETECTED',
        message: 'The sync cursor is not accepted',
        detail: bodyCanary,
      },
    };
    const readLock = vi.spyOn(VaultReadSession.prototype, 'lock');
    await session.unlockPortable(material.portableFormatted);

    const error = await rejected(session.synchronize());

    expect(error).toMatchObject({ kind: 'terminal-sync' });
    expect(error).not.toHaveProperty('cause');
    expect(String(error)).not.toContain(bodyCanary);
    expect(JSON.stringify(error)).not.toContain(bodyCanary);
    expect(session.locked).toBe(true);
    expect(session.status()).toMatchObject({ state: 'locked' });
    await expect(session.show('group.1', 'item.1.1')).rejects.toMatchObject({
      kind: 'locked',
    });
    expect(clipboard.lockCalls).toBe(1);
    expect(readLock).toHaveBeenCalledTimes(1);
    expect(sessions.lastLoaded?.every((byte) => byte === 0)).toBe(true);
    expect(keychain.lastLoaded).toBeUndefined();
    material.dispose();
  });

  it('terminally locks and hides a protected-state adapter canary', async () => {
    const material = await sessionFixture();
    const remote = await startRemote(material.fixture.vault);
    const store = new SessionStore(material.fixture);
    const sessions = new MemorySessions(material.sessionSecret);
    const keychain = new MemoryKeychain(material.deviceSecret);
    const clipboard = new RecordingClipboard();
    const canary = 'protected-load-session-canary-82f1';
    const protectedFailure = new Error('protected adapter failed', {
      cause: { canary },
    });
    Object.assign(protectedFailure, { canary });
    const base = syncOptions();
    const session = new VaultClientSession({
      ...dependencySet(material),
      profile: profile(material, `${remote.server.url}/`),
      sessions,
      keychain,
      store,
      sync: {
        ...base,
        protectedState: {
          ...base.protectedState,
          load: () => Promise.reject(protectedFailure),
        },
      },
      clipboard,
      interaction: { clearAfterMs: 30_000 },
      network: { timeoutMs: 2_000, maximumResponseBytes: 1024 * 1024 },
      allowInsecureLoopbackDevelopment: true,
    });
    const readLock = vi.spyOn(VaultReadSession.prototype, 'lock');
    await session.unlockPortable(material.portableFormatted);

    const error = await rejected(session.synchronize());

    expect(error).toMatchObject({ kind: 'terminal-sync' });
    expect(error).not.toHaveProperty('cause');
    expect(`${String(error)}${JSON.stringify(error)}`).not.toContain(canary);
    expect(session.locked).toBe(true);
    expect(clipboard.lockCalls).toBe(1);
    expect(readLock).toHaveBeenCalledTimes(1);
    expect(sessions.lastLoaded?.every((byte) => byte === 0)).toBe(true);
    material.dispose();
  });

  it('blocks concurrent operations and lock aborts an in-flight sync graph', async () => {
    const material = await sessionFixture();
    const remote = await startRemote(material.fixture.vault);
    const gate = deferred<true>();
    remote.syncGate = gate.promise;
    const session = buildDefaultSession(material, remote);
    await session.unlockPortable(material.portableFormatted);
    const syncing = session.synchronize();
    await remote.syncStarted.promise;
    await expect(session.show('group.1', 'item.1.1')).rejects.toMatchObject({
      kind: 'concurrency',
    });
    await session.lock();
    gate.resolve(true);
    await expect(syncing).rejects.toBeInstanceOf(Error);
    expect(session.locked).toBe(true);
    material.dispose();
  });

  it('keeps credential canaries out of network and generic failure surfaces', async () => {
    const material = await sessionFixture();
    const remote = await startRemote(material.fixture.vault);
    remote.vault = vaultRecordSchema.parse({
      ...material.fixture.vault,
      keySlots: material.fixture.vault.keySlots.map((slot) =>
        slot.id === PORTABLE_SLOT && slot.type === 'portable-key'
          ? { ...slot, wrappedRootKey: mutateEnvelope(slot.wrappedRootKey) }
          : slot,
      ),
    });
    const session = buildDefaultSession(material, remote);
    const error = await rejected(session.unlockPortable(material.portableFormatted));
    const wire = JSON.stringify(remote.seen);
    const localCanaries = [
      material.portableFormatted,
      material.recoveryFormatted,
      new TextDecoder().decode(PASSPHRASE),
      Buffer.from(material.deviceSecret).toString('base64url'),
      Buffer.from(material.fixture.rootKey).toString('base64url'),
      COPY_CANARY,
    ];
    for (const canary of localCanaries) {
      expect(String(error)).not.toContain(canary);
      expect(JSON.stringify(error)).not.toContain(canary);
      expect(wire).not.toContain(canary);
    }
    expect(
      remote.seen.every(({ body, url }) => body === '' && !url.includes('?token')),
    ).toBe(true);
    material.dispose();
  });

  it('fails generically when graph construction or clipboard clearing fails', async () => {
    const material = await sessionFixture();
    const remote = await startRemote(material.fixture.vault);
    const invalidGraph = new VaultClientSession({
      ...dependencySet(material),
      profile: profile(material, `${remote.server.url}/`),
      interaction: { clearAfterMs: 1 },
      allowInsecureLoopbackDevelopment: true,
    });
    await expect(
      invalidGraph.unlockPortable(material.portableFormatted),
    ).rejects.toMatchObject({ kind: 'protocol' });

    const clipboard = new RecordingClipboard();
    const session = buildSession(
      material,
      remote,
      new SessionStore(material.fixture),
      new MemorySessions(material.sessionSecret),
      new MemoryKeychain(material.deviceSecret),
      clipboard,
    );
    await session.unlockPortable(material.portableFormatted);
    clipboard.failLock = true;
    await expect(session.lock()).rejects.toMatchObject({ kind: 'clipboard' });
    expect(session.locked).toBe(true);
    material.dispose();
  });
});

type SessionMaterial = Readonly<{
  fixture: EncryptedFixture;
  portableFormatted: string;
  recoveryFormatted: string;
  deviceSecret: DeviceUnlockSecret;
  sessionSecret: SessionCredentialSecret;
  profileLocators: Readonly<{
    device: KeychainLocator;
    session: SessionCredentialLocator;
  }>;
  dispose: () => void;
}>;

async function sessionFixture(): Promise<SessionMaterial> {
  const passwordField = fieldDefinitionSchema.parse({
    id: 'field.password',
    stableKey: 'password',
    label: 'Password',
    type: 'secret',
    required: true,
    sensitive: true,
    repeatable: false,
    copyable: true,
    searchableLocally: false,
    showInPreview: false,
    copyPolicy: 'allowed',
    revealPolicy: 'timed',
    reauthenticationPolicy: 'after-lock',
    exportPolicy: 'guarded',
    sortOrder: 0,
    createdAt: NOW,
    updatedAt: NOW,
  });
  const fixture = await encryptedFixture({
    transformGroup: (group) => ({
      ...group,
      template: { ...group.template, fields: [passwordField] },
    }),
    transformItem: (item) =>
      itemPayloadSchema.parse({
        ...item,
        templateValues: [
          {
            fieldId: passwordField.id,
            stableKey: passwordField.stableKey,
            value: {
              version: 1,
              state: 'present',
              content: {
                cardinality: 'single',
                value: { kind: 'secret', value: COPY_CANARY },
              },
            },
            updatedAt: NOW,
          },
        ],
      }),
  });
  const portable = generatePortableKey();
  const recovery = generateRecoveryKey();
  const device = generateDeviceKey();
  const portableFormatted = formatPortableKey(portable);
  const recoveryFormatted = formatRecoveryKey(recovery);
  const identity = (slotId: typeof PORTABLE_SLOT): SlotIdentity => ({
    vaultId: fixture.vaultId,
    slotId,
    schemaVersion: fixture.vault.schemaVersion,
    keyVersion: fixture.vault.currentKeyVersion,
    createdAt: NOW,
  });
  const slots = [
    await createPortableKeySlot(identity(PORTABLE_SLOT), portable, fixture.rootKey),
    await createRecoveryKeySlot(identity(RECOVERY_SLOT), recovery, fixture.rootKey),
    await createPassphraseKeySlot(
      identity(PASSPHRASE_SLOT),
      PASSPHRASE,
      fixture.rootKey,
    ),
    await createDeviceKeySlot(
      { ...identity(DEVICE_SLOT), deviceId: DEVICE_ID, provider: 'test-native' },
      device,
      fixture.rootKey,
    ),
  ];
  const vault = vaultRecordSchema.parse({ ...fixture.vault, keySlots: slots });
  const completeFixture: EncryptedFixture = { ...fixture, vault };
  const sessionSecret = sessionCredentialSecretSchema.parse(
    Uint8Array.from(Buffer.alloc(32, 77)),
  );
  const deviceSecret = deviceUnlockSecretSchema.parse(Uint8Array.from(device));
  zeroize(portable);
  zeroize(recovery);
  zeroize(device);
  return {
    fixture: completeFixture,
    portableFormatted,
    recoveryFormatted,
    deviceSecret,
    sessionSecret,
    profileLocators: {
      device: keychainLocatorSchema.parse({
        version: 1,
        vaultId: fixture.vaultId,
        deviceId: DEVICE_ID,
        keySlotId: DEVICE_SLOT,
      }),
      session: sessionCredentialLocatorSchema.parse({
        version: 1,
        vaultId: fixture.vaultId,
        deviceId: DEVICE_ID,
        purpose: 'api-session',
      }),
    },
    dispose: () => {
      zeroize(fixture.rootKey);
      zeroize(deviceSecret);
      zeroize(sessionSecret);
    },
  };
}

class SessionStore extends MemoryReadSource {
  cursor: SyncCursor | null = null;
  afterApply: (() => void) | undefined;

  loadCursor(): Promise<SyncCursor | null> {
    return Promise.resolve(this.cursor);
  }

  applyPullPage(input: ApplyPullPageInput): Promise<void> {
    this.cursor = input.cursor;
    this.afterApply?.();
    return Promise.resolve();
  }

  listPendingMutations(): Promise<readonly OpaqueMutation[]> {
    return Promise.resolve([]);
  }

  loadActivePushBatch(): Promise<ActivePushBatch | null> {
    return Promise.resolve(null);
  }

  saveActivePushBatch(): Promise<void> {
    return Promise.resolve();
  }

  completePushBatch(): Promise<void> {
    return Promise.resolve();
  }

  loadPendingTemplateMigrationPublication(): Promise<TemplateMigrationPublicationRequest | null> {
    return Promise.resolve(null);
  }

  enqueueTemplateMigrationPublication(): Promise<void> {
    return Promise.resolve();
  }

  completeTemplateMigrationPublication(): Promise<void> {
    return Promise.resolve();
  }

  loadOutboundReplayState(
    vaultId: VaultRecord['id'],
    kind: OutboundReplayState['kind'],
  ): Promise<OutboundReplayState | null> {
    void vaultId;
    void kind;
    return Promise.resolve(null);
  }

  ensureOutboundReplayStart(input: EnsureOutboundReplayStartInput): Promise<number> {
    void input;
    return Promise.reject(new Error('Unexpected outbound replay binding'));
  }

  loadCompletedOutboundObservation(): Promise<CompletedOutboundObservation | null> {
    return Promise.resolve(null);
  }

  confirmCompletedOutboundObservation(): Promise<CompletedOutboundObservation> {
    return Promise.reject(new Error('Unexpected completed observation confirmation'));
  }

  releaseCompletedOutboundObservation(): Promise<void> {
    return Promise.resolve();
  }

  reconcileOutboundObservation(
    input: ReconcileOutboundObservationInput,
  ): Promise<CompletedOutboundObservation> {
    void input;
    return Promise.reject(new Error('Unexpected outbound reconciliation'));
  }
}

class MemorySessions implements SessionCredentialPort {
  readonly secret: SessionCredentialSecret | null;
  lastLoaded: SessionCredentialSecret | undefined;
  deleteCalls = 0;

  constructor(secret: SessionCredentialSecret | null) {
    this.secret = secret;
  }

  load(): Promise<SessionCredentialSecret | null> {
    this.lastLoaded =
      this.secret === null
        ? undefined
        : sessionCredentialSecretSchema.parse(Uint8Array.from(this.secret));
    return Promise.resolve(this.lastLoaded ?? null);
  }

  store(): Promise<void> {
    return Promise.resolve();
  }

  delete(): Promise<void> {
    this.deleteCalls += 1;
    return Promise.resolve();
  }
}

class MemoryKeychain implements KeychainPort {
  readonly secret: DeviceUnlockSecret | null;
  lastLoaded: DeviceUnlockSecret | undefined;
  deleteCalls = 0;

  constructor(secret: DeviceUnlockSecret | null) {
    this.secret = secret;
  }

  load(): Promise<DeviceUnlockSecret | null> {
    this.lastLoaded =
      this.secret === null
        ? undefined
        : deviceUnlockSecretSchema.parse(Uint8Array.from(this.secret));
    return Promise.resolve(this.lastLoaded ?? null);
  }

  store(): Promise<void> {
    return Promise.resolve();
  }

  delete(): Promise<void> {
    this.deleteCalls += 1;
    return Promise.resolve();
  }
}

class RecordingClipboard implements SecureClipboardPort {
  observed: Uint8Array | undefined;
  reference: Uint8Array | undefined;
  lockCalls = 0;
  failLock = false;

  copy(
    secret: Uint8Array,
    options: ClipboardCopyOptions,
  ): Promise<ClipboardCopyReceipt> {
    this.observed = Uint8Array.from(secret);
    this.reference = secret;
    return Promise.resolve({
      generation: 1,
      requestedClearAfterMs: options.clearAfterMs,
      cleanupRetryWindowMs: 700,
      clearAfterMs: options.clearAfterMs,
    });
  }

  lock(): Promise<boolean> {
    this.lockCalls += 1;
    if (this.failLock) return Promise.reject(new Error('clipboard failure'));
    return Promise.resolve(true);
  }

  dispose(): Promise<boolean> {
    return Promise.resolve(true);
  }

  takeBackgroundError(): Error | null {
    return null;
  }
}

type SeenRequest = Readonly<{
  path: string;
  url: string;
  query: Readonly<Record<string, string>>;
  authorization: string;
  body: string;
}>;

interface Remote {
  server: LoopbackServer;
  readonly auth: string;
  readonly seen: SeenRequest[];
  readonly syncStarted: Deferred<true>;
  vault: VaultRecord;
  scopes: string[];
  sessionStatus: number;
  syncStatus: number;
  syncErrorBody: unknown;
  syncGate: Promise<unknown> | undefined;
}

async function startRemote(initialVault: VaultRecord): Promise<Remote> {
  const auth = `Bearer ${Buffer.alloc(32, 77).toString('base64url')}`;
  const seen: SeenRequest[] = [];
  const syncStarted = deferred<true>();
  const remote = {
    auth,
    seen,
    syncStarted,
    vault: initialVault,
    scopes: ['sync:read', 'sync:write'],
    sessionStatus: 200,
    syncStatus: 200,
    syncErrorBody: { error: 'sync-denied-detail-canary' },
    syncGate: undefined,
  } as Remote;
  const server = await startLoopbackServer(async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://loopback');
    const body = await readRequest(request);
    seen.push({
      path: url.pathname,
      url: request.url ?? '',
      query: Object.fromEntries(url.searchParams),
      authorization: request.headers.authorization ?? '',
      body,
    });
    if (request.headers.authorization !== auth) {
      json(response, 401, { error: 'unauthorized' });
      return;
    }
    if (url.pathname === '/v1/session') {
      if (remote.sessionStatus !== 200) {
        if (remote.sessionStatus === 429) response.setHeader('retry-after', '2');
        json(response, remote.sessionStatus, { error: 'denied-detail-canary' });
        return;
      }
      json(response, 200, {
        vaultId: initialVault.id,
        deviceId: DEVICE_ID,
        scopes: remote.scopes,
      });
      return;
    }
    if (url.pathname === `/v1/vaults/${initialVault.id}`) {
      json(response, 200, remote.vault);
      return;
    }
    if (url.pathname === `/v1/vaults/${initialVault.id}/sync`) {
      remote.syncStarted.resolve(true);
      await remote.syncGate;
      if (remote.syncStatus !== 200) {
        json(response, remote.syncStatus, remote.syncErrorBody);
        return;
      }
      json(response, 200, {
        vaultId: initialVault.id,
        serverVaultRevision: remote.vault.revision,
        changes: [] satisfies SyncPulledChange[],
        nextCursor: {
          vaultId: initialVault.id,
          serverSequence: 0,
          highestSeenVaultRevision: remote.vault.revision,
        },
        hasMore: false,
      });
      return;
    }
    json(response, 404, { error: 'missing' });
  });
  remote.server = server;
  servers.push(server);
  return remote;
}

function buildDefaultSession(
  material: SessionMaterial,
  remote: Remote,
  store = new SessionStore(material.fixture),
): VaultClientSession {
  return buildSession(
    material,
    remote,
    store,
    new MemorySessions(material.sessionSecret),
    new MemoryKeychain(material.deviceSecret),
    new RecordingClipboard(),
  );
}

function dependencySet(
  material: SessionMaterial,
): Omit<
  VaultClientSessionOptions,
  'profile' | 'network' | 'allowInsecureLoopbackDevelopment'
> {
  return {
    sessions: new MemorySessions(material.sessionSecret),
    keychain: new MemoryKeychain(material.deviceSecret),
    store: new SessionStore(material.fixture),
    sync: syncOptions(),
    clipboard: new RecordingClipboard(),
    interaction: { clearAfterMs: 30_000 },
  } as const;
}

function buildSession(
  material: SessionMaterial,
  remote: Remote,
  store: SessionStore,
  sessions: MemorySessions,
  keychain: MemoryKeychain,
  clipboard: RecordingClipboard,
): VaultClientSession {
  return new VaultClientSession({
    profile: profile(material, `${remote.server.url}/`),
    sessions,
    keychain,
    store,
    sync: syncOptions(),
    clipboard,
    interaction: { clearAfterMs: 30_000 },
    network: { timeoutMs: 2_000, maximumResponseBytes: 1024 * 1024 },
    allowInsecureLoopbackDevelopment: true,
  });
}

function profile(material: SessionMaterial, serverUrl: string): VaultProfile {
  return {
    version: 1,
    serverUrl,
    vaultId: material.fixture.vaultId,
    deviceId: DEVICE_ID,
    deviceLocator: material.profileLocators.device,
    sessionLocator: material.profileLocators.session,
  };
}

function syncOptions(): Omit<SyncEngineOptions, 'transport' | 'local'> {
  const protectedState = new Map<string, ProtectedLocalDeviceState>();
  const protectedPort: ProtectedSyncStatePort = {
    load: (vaultId, deviceId) =>
      Promise.resolve(protectedState.get(`${vaultId}:${deviceId}`) ?? null),
    save: (state) => {
      protectedState.set(`${state.vaultId}:${state.deviceId}`, state);
      return Promise.resolve();
    },
    completeObservation: () =>
      Promise.reject(new Error('Unexpected observation completion')),
  };
  const status: SyncStatusPort = {
    set() {
      return Promise.resolve();
    },
  };
  return {
    protectedState: protectedPort,
    status,
    clock: { now: () => new Date(NOW) },
    idempotencyKeys: { next: () => 'session-sync-idempotency' },
  };
}

async function unlockByMode(
  session: VaultClientSession,
  material: SessionMaterial,
  mode: 'portable' | 'recovery' | 'passphrase' | 'device',
): Promise<void> {
  if (mode === 'portable') {
    await session.unlockPortable(material.portableFormatted, PORTABLE_SLOT);
  } else if (mode === 'recovery') {
    await session.unlockRecovery(material.recoveryFormatted, RECOVERY_SLOT);
  } else if (mode === 'passphrase') {
    await session.unlockPassphrase(PASSPHRASE, PASSPHRASE_SLOT);
  } else {
    await session.unlockRememberedDevice();
  }
}

function mutateEnvelope<Envelope extends { readonly ciphertext: string }>(
  envelope: Envelope,
): Envelope {
  const bytes = Buffer.from(envelope.ciphertext, 'base64url');
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  return { ...envelope, ciphertext: bytes.toString('base64url') };
}

function json(response: ServerResponse, status: number, value: unknown): void {
  response.statusCode = status;
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.end(JSON.stringify(value));
}

interface Deferred<Value> {
  readonly promise: Promise<Value>;
  readonly resolve: (value: Value | PromiseLike<Value>) => void;
}

function deferred<Value>(): Deferred<Value> {
  let resolve!: (value: Value | PromiseLike<Value>) => void;
  const promise = new Promise<Value>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}

async function rejected(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected rejection');
}
