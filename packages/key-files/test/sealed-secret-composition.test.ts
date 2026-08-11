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
