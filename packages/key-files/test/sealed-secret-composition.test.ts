import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { SealedSecretStore, sealedEntryFactory } from '../src/sealed-secret-store.js';
import {
  NativeKeychain,
  NativeProtectedSyncState,
  NativeSessionCredentials,
} from '../../keychain/src/native-keychain.js';

it('satisfies the native keychain port contract over the sealed backend', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kavrix-compose-'));
  try {
    const store = new SealedSecretStore({
      directory: dir,
      passphrase: () => Promise.resolve(Buffer.from('pw', 'utf8')),
    });
    const factory = sealedEntryFactory(store) as never;
    const vaultId = 'vault-1';
    const deviceId = 'device-1';

    const sessions = new NativeSessionCredentials(factory);
    const sLoc = { version: 1, vaultId, deviceId, purpose: 'api-session' } as never;
    const secret = Uint8Array.from({ length: 32 }, (_, i) => i) as never;
    await sessions.store(sLoc, secret);
    expect(await sessions.load(sLoc)).toStrictEqual(new Uint8Array(secret));

    const keychain = new NativeKeychain(factory);
    const kLoc = { version: 1, vaultId, deviceId, keySlotId: 'slot-1' } as never;
    const device = Uint8Array.from({ length: 32 }, () => 9) as never;
    await keychain.store(kLoc, device);
    expect(await keychain.load(kLoc)).toStrictEqual(new Uint8Array(device));
    await keychain.delete(kLoc);
    expect(await keychain.load(kLoc)).toBeNull();

    const anchors = new NativeProtectedSyncState(factory);
    await anchors.save({
      version: 2,
      vaultId,
      deviceId,
      highestSeenVaultRevision: 7,
      updatedAt: new Date(0).toISOString(),
    } as never);
    const loaded = await anchors.load(vaultId as never, deviceId as never);
    expect(loaded?.highestSeenVaultRevision).toBe(7);

    await store.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 180_000);

it('preserves protected observation transitions across sealed-store reopen', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'kavrix-observation-compose-'));
  const vaultId = 'vault-1';
  const deviceId = 'device-1';
  const passphrase = (): Promise<Uint8Array> =>
    Promise.resolve(Buffer.from('pw', 'utf8'));
  const content = {
    version: 1,
    kind: 'generic-push',
    batchIdempotencyKey: 'batch-key-0000001',
    requestHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    responseHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    responseVaultRevision: 7,
    replayFromServerSequence: 3,
    requiredThroughServerSequence: 5,
  } as const;
  const observation = {
    ...content,
    observationId: 'cLY5-qRBq_DupwZ-KwYazMN1fGM7owLxwct2_ZyKF0c',
  } as const;
  const pending = {
    version: 2,
    vaultId,
    deviceId,
    highestSeenVaultRevision: 7,
    updatedAt: new Date(0).toISOString(),
    outboundObservation: observation,
  } as const;
  let store: SealedSecretStore | undefined;
  try {
    store = new SealedSecretStore({ directory: dir, passphrase });
    let anchors = new NativeProtectedSyncState(sealedEntryFactory(store));
    await anchors.save(pending as never);
    await store.close();

    store = new SealedSecretStore({ directory: dir, passphrase });
    anchors = new NativeProtectedSyncState(sealedEntryFactory(store));
    expect(await anchors.load(vaultId as never, deviceId as never)).toEqual(pending);
    await anchors.save({
      ...pending,
      highestSeenVaultRevision: 9,
      updatedAt: '1969-12-31T23:59:59.000Z',
    } as never);
    await store.close();

    store = new SealedSecretStore({ directory: dir, passphrase });
    anchors = new NativeProtectedSyncState(sealedEntryFactory(store));
    await anchors.completeObservation(
      vaultId as never,
      deviceId as never,
      observation.observationId as never,
      9 as never,
      '1969-12-31T23:59:59.000Z',
    );
    await store.close();

    store = new SealedSecretStore({ directory: dir, passphrase });
    anchors = new NativeProtectedSyncState(sealedEntryFactory(store));
    const completed = await anchors.load(vaultId as never, deviceId as never);
    expect(completed).toEqual({
      version: 2,
      vaultId,
      deviceId,
      highestSeenVaultRevision: 9,
      updatedAt: pending.updatedAt,
      lastCompletedObservationId: observation.observationId,
    });
    await expect(
      anchors.completeObservation(
        vaultId as never,
        deviceId as never,
        observation.observationId as never,
        9 as never,
        pending.updatedAt,
      ),
    ).resolves.toBeUndefined();
    await store.close();
  } finally {
    try {
      await store?.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
}, 180_000);
