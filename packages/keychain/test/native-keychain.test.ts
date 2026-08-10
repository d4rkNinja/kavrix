import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  deviceUnlockSecretSchema,
  keychainLocatorSchema,
  protectedLocalDeviceStateSchema,
  sessionCredentialLocatorSchema,
  sessionCredentialSecretSchema,
} from '@kavrix/schemas';
import type { DeviceUnlockSecret, SessionCredentialSecret } from '@kavrix/schemas';

import {
  createNativeKeychain,
  createNativeProtectedSyncState,
  createNativeSessionCredentials,
  KeychainError,
  NativeKeychain,
  NativeProtectedSyncState,
  NativeSessionCredentials,
} from '../src/index.js';
import type { NativeEntryFactory } from '../src/index.js';

const KEY = keychainLocatorSchema.parse({
  version: 1,
  vaultId: 'vault_01JTEST0000000000000000000',
  deviceId: 'device_01JTEST000000000000000000',
  keySlotId: 'slot_01JTEST00000000000000000000',
});
const SESSION_KEY = sessionCredentialLocatorSchema.parse({
  version: 1,
  vaultId: KEY.vaultId,
  deviceId: KEY.deviceId,
  purpose: 'api-session',
});
const PROTECTED_STATE = protectedLocalDeviceStateSchema.parse({
  vaultId: KEY.vaultId,
  deviceId: KEY.deviceId,
  highestSeenVaultRevision: 5,
  updatedAt: '2026-08-10T00:00:00.000Z',
});

function secret(fill: number): DeviceUnlockSecret {
  return deviceUnlockSecretSchema.parse(new Uint8Array(32).fill(fill));
}

function sessionSecret(fill: number): SessionCredentialSecret {
  return sessionCredentialSecretSchema.parse(new Uint8Array(32).fill(fill));
}

function memoryEntries(): {
  createEntry: NativeEntryFactory;
  values: Map<string, Uint8Array>;
} {
  const values = new Map<string, Uint8Array>();
  return {
    values,
    createEntry: (service, account) => {
      const lookup = `${service}/${account}`;
      return {
        setSecret(secret): Promise<void> {
          values.set(lookup, Uint8Array.from(secret));
          return Promise.resolve();
        },
        getSecret(): Promise<Uint8Array | undefined> {
          const value = values.get(lookup);
          return Promise.resolve(
            value === undefined ? undefined : Uint8Array.from(value),
          );
        },
        deleteCredential(): Promise<boolean> {
          return Promise.resolve(values.delete(lookup));
        },
      };
    },
  };
}

describe('NativeKeychain', () => {
  it('keeps session credentials distinct from device-unlock secrets in types', () => {
    expectTypeOf<SessionCredentialSecret>().not.toEqualTypeOf<DeviceUnlockSecret>();
  });

  it('keeps device-unlock and API-session entries in distinct native accounts', async () => {
    const memory = memoryEntries();
    const keychain = new NativeKeychain(memory.createEntry);
    const sessions = new NativeSessionCredentials(memory.createEntry);
    const collidingSlotName = keychainLocatorSchema.parse({
      ...KEY,
      keySlotId: 'api-session',
    });

    await keychain.store(collidingSlotName, secret(2));
    await sessions.store(SESSION_KEY, sessionSecret(8));

    expect(memory.values.size).toBe(2);
    expect(await keychain.load(collidingSlotName)).toEqual(secret(2));
    expect(await sessions.load(SESSION_KEY)).toEqual(sessionSecret(8));
    await sessions.delete(SESSION_KEY);
    expect(await keychain.load(collidingSlotName)).toEqual(secret(2));
  });

  it('isolates caller bytes and wipes adapter-owned copies after success or failure', async () => {
    let successfulCopy: Uint8Array | undefined;
    const keychain = new NativeKeychain(() => ({
      setSecret(value): Promise<void> {
        successfulCopy = value;
        value.fill(91);
        return Promise.resolve();
      },
      getSecret(): Promise<undefined> {
        return Promise.resolve(undefined);
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));
    const deviceSecret = secret(5);
    await keychain.store(KEY, deviceSecret);
    expect(deviceSecret).toEqual(secret(5));
    expect(successfulCopy).toEqual(new Uint8Array(32));

    let failedCopy: Uint8Array | undefined;
    const sessions = new NativeSessionCredentials(() => ({
      setSecret(value): Promise<never> {
        failedCopy = value;
        value.fill(92);
        return Promise.reject(new Error('native-canary'));
      },
      getSecret(): Promise<undefined> {
        return Promise.resolve(undefined);
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));
    const apiSecret = sessionSecret(6);
    await expect(sessions.store(SESSION_KEY, apiSecret)).rejects.toMatchObject({
      code: 'KEYCHAIN_OPERATION_FAILED',
    });
    expect(apiSecret).toEqual(sessionSecret(6));
    expect(failedCopy).toEqual(new Uint8Array(32));
  });

  it('validates session locators and fails closed on corrupted session bytes', async () => {
    const memory = memoryEntries();
    const sessions = new NativeSessionCredentials(memory.createEntry);
    await expect(
      sessions.store(SESSION_KEY, new Uint8Array(31) as never),
    ).rejects.toMatchObject({ code: 'KEYCHAIN_OPERATION_FAILED' });
    await expect(
      sessions.load({ ...SESSION_KEY, purpose: 'wrong' } as never),
    ).rejects.toMatchObject({ code: 'KEYCHAIN_OPERATION_FAILED' });

    const corrupt = new NativeSessionCredentials(() => ({
      setSecret(): Promise<void> {
        return Promise.resolve();
      },
      getSecret(): Promise<Uint8Array> {
        return Promise.resolve(new Uint8Array(7));
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));
    await expect(corrupt.load(SESSION_KEY)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });
  });

  it('stores independent bytes and returns a defensive copy', async () => {
    const memory = memoryEntries();
    const keychain = new NativeKeychain(memory.createEntry);
    const original = secret(7);

    await keychain.store(KEY, original);
    original.fill(0);

    const loaded = await keychain.load(KEY);
    expect(loaded).toEqual(secret(7));
    loaded?.fill(9);
    expect(await keychain.load(KEY)).toEqual(secret(7));
  });

  it('deletes only the requested secure-store entry idempotently', async () => {
    const memory = memoryEntries();
    const keychain = new NativeKeychain(memory.createEntry);
    await keychain.store(KEY, secret(3));

    await expect(keychain.delete(KEY)).resolves.toBeUndefined();
    await expect(keychain.delete(KEY)).resolves.toBeUndefined();
    await expect(keychain.load(KEY)).resolves.toBeNull();
  });

  it('rejects invalid identifiers before invoking the native store', async () => {
    const memory = memoryEntries();
    const keychain = new NativeKeychain(memory.createEntry);

    await expect(
      keychain.load({ ...KEY, vaultId: '../unsafe' } as never),
    ).rejects.toMatchObject({
      code: 'KEYCHAIN_OPERATION_FAILED',
    });
    expect(memory.values.size).toBe(0);
  });

  it('uses canonical opaque identifiers and classifies invalid services correctly', async () => {
    const memory = memoryEntries();
    const keychain = new NativeKeychain(memory.createEntry);
    const canonical = keychainLocatorSchema.parse({
      ...KEY,
      vaultId: 'vault~portable',
    });

    await expect(keychain.store(canonical, secret(4))).resolves.toBeUndefined();
    await expect(createNativeKeychain('../unsafe')).rejects.toMatchObject({
      code: 'KEYCHAIN_OPERATION_FAILED',
    });
  });

  it('rejects corrupted and unexpectedly sized stored material', async () => {
    const corrupt = new NativeKeychain(() => ({
      setSecret(): Promise<void> {
        return Promise.resolve();
      },
      getSecret(): Promise<string> {
        return Promise.resolve('plaintext');
      },
      deleteCredential(): Promise<boolean> {
        return Promise.resolve(false);
      },
    }));
    const short = new NativeKeychain(() => ({
      setSecret(): Promise<void> {
        return Promise.resolve();
      },
      getSecret(): Promise<Uint8Array> {
        return Promise.resolve(new Uint8Array(8));
      },
      deleteCredential(): Promise<boolean> {
        return Promise.resolve(false);
      },
    }));

    await expect(corrupt.load(KEY)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });
    await expect(short.load(KEY)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });
    await expect(short.store(KEY, new Uint8Array(31) as never)).rejects.toMatchObject({
      code: 'KEYCHAIN_OPERATION_FAILED',
    });
  });

  it('accepts native byte arrays, wipes their source, and rejects invalid arrays', async () => {
    const returned = new Array<number>(32).fill(6);
    const arrayBacked = new NativeKeychain(() => ({
      setSecret(): Promise<void> {
        return Promise.resolve();
      },
      getSecret(): Promise<number[]> {
        return Promise.resolve(returned);
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));
    const invalidArray = new NativeKeychain(() => ({
      setSecret(): Promise<void> {
        return Promise.resolve();
      },
      getSecret(): Promise<number[]> {
        return Promise.resolve([0, -1, 256]);
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));

    await expect(arrayBacked.load(KEY)).resolves.toEqual(secret(6));
    expect(returned).toEqual(new Array<number>(32).fill(0));
    await expect(invalidArray.load(KEY)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });
  });

  it('maps native failures to stable messages without leaking the cause', async () => {
    const keychain = new NativeKeychain(() => ({
      setSecret(): Promise<never> {
        return Promise.reject(
          Object.assign(new Error('secret-canary'), {
            code: 'AccessDenied',
          }),
        );
      },
      getSecret(): Promise<undefined> {
        return Promise.resolve(undefined);
      },
      deleteCredential(): Promise<boolean> {
        return Promise.resolve(false);
      },
    }));

    const operation = keychain.store(KEY, secret(0));
    await expect(operation).rejects.toMatchObject({
      code: 'KEYCHAIN_ACCESS_DENIED',
    });
    await expect(operation).rejects.not.toThrow(/secret-canary/u);
  });

  it('classifies cancellation, missing deletion, and generic native failures', async () => {
    const aborted = new NativeKeychain(() => ({
      setSecret(): Promise<void> {
        return Promise.resolve();
      },
      getSecret(): Promise<never> {
        return Promise.reject(Object.assign(new Error('hidden'), { code: 'Abort' }));
      },
      deleteCredential(): Promise<never> {
        return Promise.reject(
          Object.assign(new Error('hidden'), { code: 'NoEntryFound' }),
        );
      },
    }));
    const failed = new NativeKeychain(() => ({
      setSecret(): Promise<never> {
        return Promise.reject(new Error('hidden'));
      },
      getSecret(): Promise<never> {
        return Promise.reject(
          new KeychainError('KEYCHAIN_CORRUPTED', 'Stable safe message.'),
        );
      },
      deleteCredential(): Promise<never> {
        return Promise.reject(Object.assign(new Error('hidden'), { code: 'locked' }));
      },
    }));

    await expect(aborted.load(KEY)).rejects.toMatchObject({
      code: 'KEYCHAIN_ABORTED',
    });
    await expect(aborted.delete(KEY)).resolves.toBeUndefined();
    await expect(failed.store(KEY, secret(1))).rejects.toMatchObject({
      code: 'KEYCHAIN_OPERATION_FAILED',
    });
    await expect(failed.load(KEY)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });
    await expect(failed.delete(KEY)).rejects.toMatchObject({
      code: 'KEYCHAIN_ACCESS_DENIED',
    });
  });

  it('loads the supported native adapter without accessing stored credentials', async () => {
    await expect(createNativeKeychain()).resolves.toBeInstanceOf(NativeKeychain);
    await expect(createNativeSessionCredentials()).resolves.toBeInstanceOf(
      NativeSessionCredentials,
    );
    await expect(createNativeProtectedSyncState()).resolves.toBeInstanceOf(
      NativeProtectedSyncState,
    );
  });
});

describe('NativeProtectedSyncState', () => {
  it('round-trips compact binary state in a namespace distinct from other entries', async () => {
    const memory = memoryEntries();
    const protectedState = new NativeProtectedSyncState(memory.createEntry);
    const keychain = new NativeKeychain(memory.createEntry);
    const sessions = new NativeSessionCredentials(memory.createEntry);
    const collidingSlotName = keychainLocatorSchema.parse({
      ...KEY,
      keySlotId: 'protected-sync-state',
    });

    await keychain.store(collidingSlotName, secret(2));
    await sessions.store(SESSION_KEY, sessionSecret(3));
    await protectedState.save(PROTECTED_STATE);

    expect(memory.values.size).toBe(3);
    expect(await protectedState.load(KEY.vaultId, KEY.deviceId)).toEqual(
      PROTECTED_STATE,
    );
    const encoded = [...memory.values.entries()].find(([key]) =>
      key.includes('v1:protected-sync-state:'),
    )?.[1];
    expect(encoded?.subarray(0, 4)).toEqual(Uint8Array.of(0x4b, 0x53, 0x53, 0x54));
    expect(Buffer.from(encoded ?? new Uint8Array()).toString('utf8')).not.toContain(
      'highestSeenVaultRevision',
    );
  });

  it('rejects revision and timestamp rollback while allowing monotonic updates', async () => {
    const memory = memoryEntries();
    const protectedState = new NativeProtectedSyncState(memory.createEntry);
    await protectedState.save(PROTECTED_STATE);

    for (const candidate of [
      { ...PROTECTED_STATE, highestSeenVaultRevision: 4 },
      { ...PROTECTED_STATE, updatedAt: '2026-08-09T23:59:59.000Z' },
    ]) {
      await expect(protectedState.save(candidate as never)).rejects.toMatchObject({
        name: 'SyncLocalStateError',
      });
    }
    const advanced = protectedLocalDeviceStateSchema.parse({
      ...PROTECTED_STATE,
      highestSeenVaultRevision: 6,
      updatedAt: '2026-08-09T23:59:59.000Z',
    });
    await expect(protectedState.save(advanced)).resolves.toBeUndefined();
    expect(await protectedState.load(KEY.vaultId, KEY.deviceId)).toEqual(advanced);
  });

  it('serializes monotonic saves within one adapter instance', async () => {
    const memory = memoryEntries();
    const protectedState = new NativeProtectedSyncState(memory.createEntry);
    const higher = protectedLocalDeviceStateSchema.parse({
      ...PROTECTED_STATE,
      highestSeenVaultRevision: 8,
      updatedAt: '2026-08-10T00:00:02.000Z',
    });

    const [first, second] = await Promise.allSettled([
      protectedState.save(higher),
      protectedState.save(PROTECTED_STATE),
    ]);

    expect(first.status).toBe('fulfilled');
    expect(second).toMatchObject({
      status: 'rejected',
      reason: { name: 'SyncLocalStateError' },
    });
    expect(await protectedState.load(KEY.vaultId, KEY.deviceId)).toEqual(higher);
  });

  it('detects corrupt and cross-locator protected state', async () => {
    const memory = memoryEntries();
    const protectedState = new NativeProtectedSyncState(memory.createEntry);
    await protectedState.save(PROTECTED_STATE);
    const primaryEntry = [...memory.values.keys()].find((key) =>
      key.includes('v1:protected-sync-state:'),
    );
    expect(primaryEntry).toBeDefined();
    memory.values.set(primaryEntry ?? '', Uint8Array.of(0x4b, 0x53, 0x53, 0x54, 9));
    await expect(protectedState.load(KEY.vaultId, KEY.deviceId)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });

    const otherVault = 'vault.other';
    const otherState = protectedLocalDeviceStateSchema.parse({
      ...PROTECTED_STATE,
      vaultId: otherVault,
    });
    await protectedState.save(otherState);
    const otherEntry = [...memory.values.entries()].find(([key]) =>
      key.includes(`v1:protected-sync-state:${otherVault}:`),
    );
    memory.values.set(primaryEntry ?? '', Uint8Array.from(otherEntry?.[1] ?? []));
    await expect(protectedState.load(KEY.vaultId, KEY.deviceId)).rejects.toMatchObject({
      code: 'KEYCHAIN_CORRUPTED',
    });
  });

  it('isolates native mutations and wipes owned protected-state buffers', async () => {
    let successfulCopy: Uint8Array | undefined;
    const state = new NativeProtectedSyncState(() => ({
      setSecret(value): Promise<void> {
        successfulCopy = value;
        value.fill(91);
        return Promise.resolve();
      },
      getSecret(): Promise<undefined> {
        return Promise.resolve(undefined);
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));
    await state.save(PROTECTED_STATE);
    expect(successfulCopy?.every((value) => value === 0)).toBe(true);
    expect(PROTECTED_STATE.highestSeenVaultRevision).toBe(5);

    let failedCopy: Uint8Array | undefined;
    const failing = new NativeProtectedSyncState(() => ({
      setSecret(value): Promise<never> {
        failedCopy = value;
        value.fill(92);
        return Promise.reject(new Error('native-state-canary'));
      },
      getSecret(): Promise<undefined> {
        return Promise.resolve(undefined);
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));
    const operation = failing.save(PROTECTED_STATE);
    await expect(operation).rejects.toMatchObject({
      code: 'KEYCHAIN_OPERATION_FAILED',
    });
    await expect(operation).rejects.not.toThrow(/native-state-canary/u);
    expect(failedCopy?.every((value) => value === 0)).toBe(true);
  });

  it('wipes native load buffers after decoding', async () => {
    const memory = memoryEntries();
    const writer = new NativeProtectedSyncState(memory.createEntry);
    await writer.save(PROTECTED_STATE);
    const stored = [...memory.values.entries()].find(([key]) =>
      key.includes('v1:protected-sync-state:'),
    )?.[1];
    const returned = Uint8Array.from(stored ?? []);
    const reader = new NativeProtectedSyncState(() => ({
      setSecret(): Promise<void> {
        return Promise.resolve();
      },
      getSecret(): Promise<Uint8Array> {
        return Promise.resolve(returned);
      },
      deleteCredential(): Promise<void> {
        return Promise.resolve();
      },
    }));

    await expect(reader.load(KEY.vaultId, KEY.deviceId)).resolves.toEqual(
      PROTECTED_STATE,
    );
    expect(returned.every((value) => value === 0)).toBe(true);
  });
});
