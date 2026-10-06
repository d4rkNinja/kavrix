import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { MongoClient } from 'mongodb';
import { readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { profileIdSchema } from '@kavrix/schemas';
import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { DatastoreProfileRegistry } from '../src/datastore-profiles.js';
import { createCliTuiBackend } from '../src/tui-session.js';

const directories: string[] = [];
const bin = resolve('apps/cli/dist/bin.js');
// Optional prior compiled executable: create fixtures using an installed release,
// then unlock them with this checkout. This path carries no secret material.
const previousBin = process.env['KAVRIX_TEST_PREVIOUS_BIN'] ?? bin;
const passphrase = 'compatibility-test-passphrase';

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function runCliSuccessfully(
  args: readonly string[],
  frames: readonly string[] = [passphrase, passphrase],
): Promise<void> {
  const child = spawn(process.execPath, [previousBin, ...args], {
    shell: false,
    timeout: 120_000,
    windowsHide: true,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  child.stdout.resume();
  child.stderr.resume();
  child.stdin.on('error', () => undefined);
  child.stdin.end(frames.map((frame) => `${frame}\n`).join(''));
  const exitCode = await new Promise<number | null>((resolveExit, reject) => {
    child.once('error', reject);
    child.once('close', resolveExit);
  });
  expect(exitCode).toBe(0);
}

describe('TUI compatibility with an existing legacy vault', () => {
  it('unlocks through the real bounded child without rewriting existing encrypted vault or key bytes', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-tui-compat-'),
    );
    directories.push(directory);
    const dataFile = join(directory, 'legacy.vault');
    const keyFile = join(directory, 'legacy.key');
    await runCliSuccessfully([
      'init',
      '--legacy',
      '--datastore',
      'file',
      '--data-file',
      dataFile,
      '--key-file',
      keyFile,
      '--passphrase-stdin',
    ]);
    await runCliSuccessfully(
      [
        'put',
        'legacy-token',
        '--datastore',
        'file',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
        '--passphrase-stdin',
        '--value-stdin',
      ],
      [passphrase, 'compatibility-credential-canary'],
    );
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: directory,
    });
    await registry.add({
      id: profileIdSchema.parse('legacy'),
      datastore: 'file',
      dataFile,
      keyFile,
    });
    await registry.use(profileIdSchema.parse('legacy'));
    const beforeVault = await readFile(dataFile);
    const beforeKey = await readFile(keyFile);
    const backend = createCliTuiBackend({
      profileConfigDir: directory,
      binPath: bin,
      ascii: true,
    });
    const startedAt = Date.now();
    const result = await backend.dispatch({ type: 'unlock', passphrase });
    expect(result.snapshot.noticeTone, result.snapshot.notice ?? '').toBe('success');
    expect(result.snapshot.home.unlocked).toBe(true);
    expect(result.snapshot.credentials.map((entry) => entry.name)).toEqual([
      'legacy-token',
    ]);
    console.info(`Legacy TUI unlock completed in ${String(Date.now() - startedAt)}ms`);
    await backend.dispatch({ type: 'lock' });
    expect(await readFile(dataFile)).toEqual(beforeVault);
    expect(await readFile(keyFile)).toEqual(beforeKey);
  });
});

describe.runIf(process.env['KAVRIX_TEST_LOCAL_MONGO'] === '1')(
  'TUI compatibility with an existing local MongoDB vault',
  () => {
    it('retains the stdin connection after unlock and keeps existing encrypted records intact', async () => {
      const directory = await createSecureTestDirectory(
        join(tmpdir(), 'kavrix-tui-mongo-compat-'),
      );
      directories.push(directory);
      const keyFile = join(directory, 'legacy.key');
      const database = `kavrix_tui_compat_${randomUUID().replaceAll('-', '')}`;
      const uri = 'mongodb://127.0.0.1:27017';
      const client = new MongoClient(uri, { serverSelectionTimeoutMS: 2000 });
      try {
        await client.connect();
        await runCliSuccessfully(
          [
            'init',
            '--legacy',
            '--datastore',
            'mongodb',
            '--database',
            database,
            '--key-file',
            keyFile,
            '--database-url-stdin',
            '--passphrase-stdin',
          ],
          [uri, passphrase, passphrase],
        );
        await runCliSuccessfully(
          [
            'put',
            'legacy-token',
            '--datastore',
            'mongodb',
            '--database',
            database,
            '--key-file',
            keyFile,
            '--database-url-stdin',
            '--passphrase-stdin',
            '--value-stdin',
          ],
          [uri, passphrase, 'compatibility-credential-canary'],
        );
        const registry = await DatastoreProfileRegistry.open({
          configDirectory: directory,
        });
        await registry.add({
          id: profileIdSchema.parse('legacy-mongo'),
          datastore: 'mongodb',
          database,
          databaseCollection: 'kavrix_databases',
          vaultCollection: 'kavrix_vaults',
          keyFile,
        });
        await registry.use(profileIdSchema.parse('legacy-mongo'));
        const beforeRecords = await client
          .db(database)
          .collection('kavrix_vaults')
          .find()
          .toArray();
        const beforeKey = await readFile(keyFile);
        const backend = createCliTuiBackend({
          profileConfigDir: directory,
          binPath: bin,
          ascii: true,
        });
        const startedAt = Date.now();
        const unlocked = await backend.dispatch({
          type: 'unlock',
          passphrase,
          databaseUrl: uri,
        });
        expect(unlocked.snapshot.noticeTone, unlocked.snapshot.notice ?? '').toBe(
          'success',
        );
        expect(unlocked.snapshot.credentials.map((entry) => entry.name)).toEqual([
          'legacy-token',
        ]);
        console.info(
          `MongoDB TUI unlock completed in ${String(Date.now() - startedAt)}ms`,
        );
        const refreshed = await backend.dispatch({ type: 'refresh' });
        expect(refreshed.snapshot.home.unlocked).toBe(true);
        expect(refreshed.snapshot.noticeTone).not.toBe('error');
        expect(refreshed.snapshot.credentials.map((entry) => entry.name)).toEqual([
          'legacy-token',
        ]);
        await backend.dispatch({ type: 'lock' });
        expect(await readFile(keyFile)).toEqual(beforeKey);
        expect(
          await client.db(database).collection('kavrix_vaults').find().toArray(),
        ).toEqual(beforeRecords);
      } finally {
        if (!/^kavrix_tui_compat_[a-f0-9]{32}$/u.test(database))
          throw new Error('Unsafe test database cleanup.');
        try {
          await client.db(database).dropDatabase();
        } finally {
          await client.close();
        }
      }
    });
  },
);
