import { readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';

import { FileEncryptedDatabaseStore } from '@kavrix/storage';
import { profileIdSchema, type DatastoreProfile } from '@kavrix/schemas';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import {
  DatabaseSession,
  setDatabaseSessionZeroizationObserverForTest,
} from '../src/database-session.js';
import { TuiVaultSession } from '../src/tui-vault-session.js';
import { createCliTuiBackend } from '../src/tui-session.js';
import { DatastoreProfileRegistry } from '../src/datastore-profiles.js';
import { putCredential } from '../src/credential-mutations.js';

const directories: string[] = [];
const passphrase = Buffer.from('tui-session-fixture-passphrase');
afterEach(async () => {
  setDatabaseSessionZeroizationObserverForTest(undefined);
  await Promise.all(
    directories.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture() {
  const dir = await createSecureTestDirectory(join(tmpdir(), 'kavrix-tui-lease-'));
  directories.push(dir);
  const keyFile = join(dir, 'owner.key');
  const dataFile = join(dir, 'database.kavrix');
  const store = await FileEncryptedDatabaseStore.open(dataFile);
  await DatabaseSession.initialize({
    store,
    keyFile,
    passphrase,
    label: 'test database',
  });
  const session = await DatabaseSession.open({ store, keyFile, passphrase });
  const vault = await session.createVault('test vault');
  const databaseId = session.databaseId;
  await session.close();
  const profile: DatastoreProfile = {
    id: profileIdSchema.parse('test'),
    datastore: 'file',
    keyFile,
    dataFile,
    databaseId,
    defaultVaultId: vault.id,
  };
  return { dir, profile, vaultId: vault.id };
}

describe('bounded authenticated TUI session', () => {
  it('reuses one unlock, releases file locks, observes external writes, and wipes keys on close', async () => {
    const { profile, vaultId } = await fixture();
    const open = vi.spyOn(DatabaseSession, 'open');
    let cleared = 0;
    setDatabaseSessionZeroizationObserverForTest(() => {
      cleared += 1;
    });
    const lease = new TuiVaultSession(async () => undefined);
    try {
      await lease.run(profile, vaultId, passphrase, undefined, async (session, id) => {
        await session.updateVault(id, (payload) =>
          putCredential(payload, 'first', 'plaintext-canary', true),
        );
      });
      // Another real opener must work between actions: no idle writer lock.
      const externalStore = await FileEncryptedDatabaseStore.open(profile.dataFile!);
      const external = await DatabaseSession.open({
        store: externalStore,
        keyFile: profile.keyFile,
        passphrase,
      });
      await external.updateVault(vaultId, (payload) =>
        putCredential(payload, 'second', 'other-canary', true),
      );
      await external.close();
      await lease.run(profile, vaultId, passphrase, undefined, async (session, id) => {
        await session.inspectVault(id, (payload) => {
          expect(Object.keys(payload.records)).toEqual(['first', 'second']);
        });
      });
      expect(open).toHaveBeenCalledTimes(2); // One lease unlock, one external unlock.
      expect(await readFile(profile.dataFile!, 'utf8')).not.toContain(
        'plaintext-canary',
      );
      await lease.close();
      expect(cleared).toBe(2);
    } finally {
      await lease.close();
    }
  });

  it('fails closed on changed key bytes and does not reuse keys after that failure', async () => {
    const { profile, vaultId } = await fixture();
    const lease = new TuiVaultSession(async () => undefined);
    try {
      await lease.run(profile, vaultId, passphrase, undefined, async () => undefined);
      const original = await readFile(profile.keyFile);
      await writeFile(profile.keyFile, Buffer.concat([original, Buffer.from(' ')]));
      const operation = vi.fn(async () => undefined);
      await expect(
        lease.run(profile, vaultId, passphrase, undefined, operation),
      ).rejects.toThrow('changed or expired');
      expect(operation).not.toHaveBeenCalled();
    } finally {
      await lease.close();
    }
  });

  it('expires idle keys and notifies the owner without another action', async () => {
    const { profile, vaultId } = await fixture();
    const expired = vi.fn(async () => undefined);
    const lease = new TuiVaultSession(expired, 50, 5_000);
    try {
      await lease.run(profile, vaultId, passphrase, undefined, async () => undefined);
      await vi.waitFor(() => expect(expired).toHaveBeenCalledOnce(), {
        timeout: 2_000,
      });
      await expect(
        lease.run(profile, vaultId, passphrase, undefined, async () => undefined),
      ).rejects.toThrow('expired');
    } finally {
      await lease.close();
    }
  });

  it('does not extend the maximum lifetime when actions keep the session busy', async () => {
    const { profile, vaultId } = await fixture();
    let now = 0;
    vi.spyOn(performance, 'now').mockImplementation(() => now);
    const lease = new TuiVaultSession(async () => undefined, 10_000, 1_000);
    try {
      await lease.run(profile, vaultId, passphrase, undefined, async () => undefined);
      now = 500;
      await lease.run(profile, vaultId, passphrase, undefined, async () => undefined);
      now = 1_000;
      const operation = vi.fn(async () => undefined);
      await expect(
        lease.run(profile, vaultId, passphrase, undefined, operation),
      ).rejects.toThrow('changed or expired');
      expect(operation).not.toHaveBeenCalled();
    } finally {
      await lease.close();
    }
  });

  it('rejects modified storage before delivering data and clears unlocked keys', async () => {
    const { profile, vaultId } = await fixture();
    let cleared = false;
    setDatabaseSessionZeroizationObserverForTest(() => {
      cleared = true;
    });
    const lease = new TuiVaultSession(async () => undefined);
    try {
      await lease.run(profile, vaultId, passphrase, undefined, async () => undefined);
      await writeFile(profile.dataFile!, '{malformed');
      const operation = vi.fn(async () => undefined);
      await expect(
        lease.run(profile, vaultId, passphrase, undefined, operation),
      ).rejects.toThrow();
      expect(operation).not.toHaveBeenCalled();
      expect(cleared).toBe(true);
    } finally {
      await lease.close();
    }
  });

  it('rejects an authenticated older vault snapshot against the current rollback anchor', async () => {
    const { profile, vaultId } = await fixture();
    const older = await readFile(profile.dataFile!);
    const lease = new TuiVaultSession(async () => undefined);
    try {
      await lease.run(profile, vaultId, passphrase, undefined, async (session, id) => {
        await session.updateVault(id, (payload) =>
          putCredential(payload, 'new', 'rollback-canary', true),
        );
      });
      await writeFile(profile.dataFile!, older);
      const operation = vi.fn(async () => undefined);
      await expect(
        lease.run(profile, vaultId, passphrase, undefined, operation),
      ).rejects.toMatchObject({ code: 'rollback' });
      expect(operation).not.toHaveBeenCalled();
    } finally {
      await lease.close();
    }
  });

  it('native backend unlocks once across CRUD, Browse and policy refresh and disposes on exit', async () => {
    const { dir, profile } = await fixture();
    const registry = await DatastoreProfileRegistry.open({ configDirectory: dir });
    await registry.add(profile);
    await registry.use(profile.id);
    const open = vi.spyOn(DatabaseSession, 'open');
    const backend = createCliTuiBackend({
      profileConfigDir: dir,
      kavrixArtifactDir: dir,
    });
    try {
      expect(
        (
          await backend.dispatch({
            type: 'unlock',
            passphrase: passphrase.toString('utf8'),
          })
        ).snapshot.home.unlocked,
      ).toBe(true);
      expect(
        (
          await backend.dispatch({
            type: 'put-credential',
            name: 'first',
            value: 'native-canary',
          })
        ).snapshot.noticeTone,
      ).toBe('success');
      expect(
        (
          await backend.dispatch({
            type: 'rename-credential',
            from: 'first',
            to: 'second',
          })
        ).snapshot.credentials[0]?.name,
      ).toBe('second');
      const browse = await backend.dispatch({ type: 'refresh-browse' });
      expect(browse.snapshot.browse.some((node) => node.label === 'second')).toBe(true);
      expect(JSON.stringify(browse.snapshot)).not.toContain('native-canary');
      expect(
        (await backend.dispatch({ type: 'refresh-policy' })).snapshot.noticeTone,
      ).toBe('success');
      expect(
        (await backend.dispatch({ type: 'remove-credential', name: 'second' })).snapshot
          .credentials,
      ).toEqual([]);
      expect(open).toHaveBeenCalledOnce();
    } finally {
      await backend.dispose();
    }
    expect((await backend.load()).home.unlocked).toBe(false);
    await expect(backend.dispatch({ type: 'refresh' })).rejects.toThrow('closed');
  });
});
