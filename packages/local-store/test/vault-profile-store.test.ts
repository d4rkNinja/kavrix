import { randomUUID } from 'node:crypto';
import { readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { vaultProfileSchema, type VaultProfile } from '@kavrix/client';
import { SyncLocalStateError } from '@kavrix/sync';
import { afterEach, describe, expect, it } from 'vitest';

import {
  openSqliteVaultProfileStore,
  type SqliteVaultProfileStore,
  type SqliteVaultProfileStoreOptions,
} from '../src/index.js';

const TEST_TMPDIR = await realpath(tmpdir());
const roots: string[] = [];
const stores: SqliteVaultProfileStore[] = [];

afterEach(async () => {
  await Promise.allSettled(stores.splice(0).map((store) => store.close()));
  await Promise.all(
    roots.splice(0).map(async (root) => {
      if (
        dirname(root) !== TEST_TMPDIR ||
        !root.startsWith(join(TEST_TMPDIR, 'kavrix-profile-store-'))
      ) {
        throw new Error('Refusing unsafe profile-store test cleanup');
      }
      await rm(root, { recursive: true, force: true });
    }),
  );
});

describe('SqliteVaultProfileStore', () => {
  it('durably stores an exact profile, returns fresh copies, and reopens', async () => {
    const fixture = profilePath();
    let store = await openStore(fixture.path);
    const profile = profileRecord();

    await store.store(profile);
    await store.store(profile);
    const first = await store.load(profile.vaultId, profile.deviceId);
    expect(first).toEqual(profile);
    expect(first).not.toBe(profile);
    expect(first?.deviceLocator).not.toBe(profile.deviceLocator);
    if (first === null) throw new Error('Missing profile fixture');
    (first as { serverUrl: string }).serverUrl = 'https://mutated.example/';
    expect(await store.load(profile.vaultId, profile.deviceId)).toEqual(profile);

    const database = new DatabaseSync(fixture.path, { readOnly: true });
    try {
      expect(
        database.prepare(`SELECT COUNT(*) AS count FROM vault_profiles`).get(),
      ).toEqual({ count: 1 });
      expect(database.prepare('PRAGMA user_version').get()).toEqual({
        user_version: 1,
      });
    } finally {
      database.close();
    }

    await store.close();
    stores.splice(stores.indexOf(store), 1);
    store = await openStore(fixture.path);
    expect(await store.load(profile.vaultId, profile.deviceId)).toEqual(profile);
  });

  it('rejects conflicting identity and protected-locator reuse', async () => {
    const store = await openStore(profilePath().path);
    const original = profileRecord();
    await store.store(original);

    await expect(
      store.store({ ...original, serverUrl: 'https://conflict.example/' }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    const conflictingLocator = vaultProfileSchema.parse({
      ...original,
      deviceLocator: { ...original.deviceLocator, keySlotId: 'slot.profile.other' },
    });
    await expect(store.store(conflictingLocator)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );

    const other = profileRecord(
      'vault.profile.2',
      'device.profile.2',
      'slot.profile.2',
    );
    for (const crossIdentity of [
      { ...other, deviceLocator: original.deviceLocator },
      { ...other, sessionLocator: original.sessionLocator },
    ]) {
      expect(vaultProfileSchema.safeParse(crossIdentity).success).toBe(false);
      await expect(store.store(crossIdentity as never)).rejects.toBeInstanceOf(
        SyncLocalStateError,
      );
    }
    expect(await store.load(original.vaultId, original.deviceId)).toEqual(original);
  });

  it('bounds profile count and aggregate canonical bytes transactionally', async () => {
    const countStore = await openStore(profilePath().path, { maxProfiles: 1 });
    const first = profileRecord();
    const second = profileRecord(
      'vault.profile.2',
      'device.profile.2',
      'slot.profile.2',
    );
    await countStore.store(first);
    await expect(countStore.store(second)).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(countStore.load(second.vaultId, second.deviceId)).resolves.toBeNull();

    const bytesFixture = profilePath();
    const byteStore = await openStore(bytesFixture.path, { maxSerializedBytes: 1_024 });
    const longHost = `${'a'.repeat(300)}.example`;
    const largeFirst = profileRecord(
      'vault.profile.bytes.1',
      'device.profile.bytes.1',
      'slot.profile.bytes.1',
      `https://${longHost}/`,
    );
    const largeSecond = profileRecord(
      'vault.profile.bytes.2',
      'device.profile.bytes.2',
      'slot.profile.bytes.2',
      `https://${longHost}/`,
    );
    expect(Buffer.byteLength(JSON.stringify(largeFirst))).toBeLessThan(1_024);
    expect(
      Buffer.byteLength(JSON.stringify(largeFirst)) +
        Buffer.byteLength(JSON.stringify(largeSecond)),
    ).toBeGreaterThan(1_024);
    await byteStore.store(largeFirst);
    await expect(byteStore.store(largeSecond)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    expect(await byteStore.load(largeFirst.vaultId, largeFirst.deviceId)).toEqual(
      largeFirst,
    );
  });

  it('rejects invalid options and canonical identifiers before access', async () => {
    const invalidOptions: unknown[] = [
      { path: 'relative.sqlite' },
      { path: profilePath().path, maxProfiles: 0 },
      { path: profilePath().path, maxProfiles: 257 },
      { path: profilePath().path, maxSerializedBytes: 1_023 },
      { path: profilePath().path, maxDatabaseBytes: 1_048_575 },
      { path: profilePath().path, unknown: true },
    ];
    for (const options of invalidOptions) {
      await expect(
        openSqliteVaultProfileStore(options as SqliteVaultProfileStoreOptions),
      ).rejects.toBeInstanceOf(SyncLocalStateError);
    }

    const store = await openStore(profilePath().path);
    await expect(
      store.load('bad id' as never, 'bad id' as never),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('rejects weakened schemas and canonical row corruption on reopen', async () => {
    const weakened = profilePath();
    let store = await openStore(weakened.path);
    await store.close();
    stores.splice(stores.indexOf(store), 1);
    const database = new DatabaseSync(weakened.path);
    database.exec(`
      DROP TABLE vault_profiles;
      CREATE TABLE vault_profiles (
        vault_id TEXT,
        device_id TEXT,
        profile_json TEXT,
        serialized_bytes INTEGER,
        device_locator_json TEXT,
        session_locator_json TEXT
      ) STRICT;
    `);
    database.close();
    await expect(
      openSqliteVaultProfileStore({ path: weakened.path }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);

    const corrupt = profilePath();
    store = await openStore(corrupt.path);
    await store.store(profileRecord());
    await store.close();
    stores.splice(stores.indexOf(store), 1);
    const tampered = new DatabaseSync(corrupt.path);
    tampered.prepare(`UPDATE vault_profiles SET vault_id = 'vault.crossed'`).run();
    tampered.close();
    await expect(
      openSqliteVaultProfileStore({ path: corrupt.path }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('never persists rejected unknown plaintext and exposes no delete operation', async () => {
    const fixture = profilePath();
    const store = await openStore(fixture.path);
    const canary = 'PROFILE-PLAINTEXT-CANARY-4f5c8f';
    await expect(
      store.store({ ...profileRecord(), plaintext: canary } as never),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect('delete' in store).toBe(false);
    expect(await sqliteBytes(fixture.path)).not.toContain(canary);
  });

  it('fails closed after explicit close', async () => {
    const store = await openStore(profilePath().path);
    const profile = profileRecord();
    await store.close();
    stores.splice(stores.indexOf(store), 1);
    await expect(store.store(profile)).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(store.load(profile.vaultId, profile.deviceId)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
  });
});

async function openStore(
  path: string,
  options: Omit<SqliteVaultProfileStoreOptions, 'path'> = {},
): Promise<SqliteVaultProfileStore> {
  const store = await openSqliteVaultProfileStore({ path, ...options });
  stores.push(store);
  return store;
}

function profilePath(): Readonly<{ root: string; path: string }> {
  const root = join(
    TEST_TMPDIR,
    `kavrix-profile-store-${randomUUID().replaceAll('-', '')}`,
  );
  roots.push(root);
  return { root, path: join(root, 'profiles.sqlite') };
}

function profileRecord(
  vaultId = 'vault.profile.1',
  deviceId = 'device.profile.1',
  keySlotId = 'slot.profile.1',
  serverUrl = 'https://vault.example/',
): VaultProfile {
  return vaultProfileSchema.parse({
    version: 1,
    serverUrl,
    vaultId,
    deviceId,
    deviceLocator: { version: 1, vaultId, deviceId, keySlotId },
    sessionLocator: { version: 1, vaultId, deviceId, purpose: 'api-session' },
  });
}

async function sqliteBytes(path: string): Promise<string> {
  const buffers: Buffer[] = [];
  for (const candidate of [path, `${path}-wal`, `${path}-shm`, `${path}-journal`]) {
    try {
      buffers.push(await readFile(candidate));
    } catch (error) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === 'ENOENT'
      ) {
        continue;
      }
      throw error;
    }
  }
  try {
    return Buffer.concat(buffers).toString('latin1');
  } finally {
    for (const buffer of buffers) buffer.fill(0);
  }
}
