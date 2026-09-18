import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  databaseIdSchema,
  profileIdSchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { afterEach, describe, expect, it } from 'vitest';

import { DatastoreProfileRegistry } from '../src/datastore-profiles.js';
import { createCliTuiBackend } from '../src/tui-session.js';

describe('CliTuiSession mutations (mocked spawn)', () => {
  const dirs: string[] = [];

  afterEach(async () => {
    await Promise.all(
      dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })),
    );
  });

  async function setupProfile(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'kavrix-tui-session-'));
    dirs.push(dir);
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: dir,
    });
    await registry.add({
      id: profileIdSchema.parse('smoke'),
      datastore: 'file',
      dataFile: join(dir, 'db.kavrix'),
      keyFile: join(dir, 'owner.key'),
      databaseId: databaseIdSchema.parse('db_smoke'),
      defaultVaultId: vaultIdSchema.parse('vault_smoke'),
    });
    await registry.use(profileIdSchema.parse('smoke'));
    return dir;
  }

  it('unlocks, puts, renames, removes via stdin frames only', async () => {
    const configDir = await setupProfile();
    const calls: Array<{ args: readonly string[]; frames: readonly string[] }> =
      [];
    let names = ['alpha'];

    const backend = createCliTuiBackend({
      profileConfigDir: configDir,
      ascii: true,
      commandRunner: async (args, frames) => {
        calls.push({ args: [...args], frames: [...frames] });
        if (args.includes('list')) {
          return JSON.stringify({ names: [...names] });
        }
        if (args.includes('put')) {
          const name = args[args.indexOf('put') + 1];
          if (typeof name === 'string' && !names.includes(name)) names.push(name);
          names = [...names].sort();
          return JSON.stringify({ saved: true, name, revision: 1 });
        }
        if (args.includes('rename')) {
          const from = args[args.indexOf('rename') + 1];
          const to = args[args.indexOf('rename') + 2];
          names = names.map((entry) => (entry === from ? String(to) : entry));
          return JSON.stringify({ renamed: true, from, to });
        }
        if (args.includes('remove')) {
          const name = args[args.indexOf('remove') + 1];
          names = names.filter((entry) => entry !== name);
          return JSON.stringify({ removed: true, name });
        }
        if (args.includes('recovery') && args.includes('status')) {
          return JSON.stringify({
            active: 1,
            revoked: 0,
            slots: [{ id: 'slot-1', state: 'active' }],
          });
        }
        return '{}';
      },
    });

    let result = await backend.dispatch({
      type: 'unlock',
      passphrase: 'correct horse battery staple',
    });
    expect(result.snapshot.home.unlocked).toBe(true);
    expect(result.snapshot.credentials.map((c) => c.name)).toEqual(['alpha']);

    const unlockCall = calls.find((call) => call.args.includes('list'));
    expect(unlockCall?.frames).toEqual(['correct horse battery staple']);
    expect(unlockCall?.args).toContain('--passphrase-stdin');
    expect(unlockCall?.args.join(' ')).not.toContain('correct horse');

    result = await backend.dispatch({
      type: 'put-credential',
      name: 'beta',
      value: 'secret-value',
    });
    expect(result.snapshot.noticeTone).toBe('success');
    expect(result.snapshot.credentials.map((c) => c.name)).toEqual([
      'alpha',
      'beta',
    ]);
    const putCall = calls.find((call) => call.args.includes('put'));
    expect(putCall?.frames).toEqual([
      'correct horse battery staple',
      'secret-value',
    ]);
    expect(putCall?.args).toEqual(
      expect.arrayContaining([
        'put',
        'beta',
        '--passphrase-stdin',
        '--value-stdin',
        '--overwrite',
      ]),
    );

    result = await backend.dispatch({
      type: 'rename-credential',
      from: 'beta',
      to: 'gamma',
    });
    expect(result.snapshot.credentials.map((c) => c.name)).toEqual([
      'alpha',
      'gamma',
    ]);
    const renameCall = calls.find((call) => call.args.includes('rename'));
    expect(renameCall?.frames).toEqual(['correct horse battery staple']);

    result = await backend.dispatch({
      type: 'remove-credential',
      name: 'gamma',
    });
    expect(result.snapshot.credentials.map((c) => c.name)).toEqual(['alpha']);

    result = await backend.dispatch({ type: 'recovery-status' });
    expect(result.snapshot.recovery[0]?.slotId).toBe('slot-1');
    expect(result.snapshot.recovery[0]?.status).toBe('active');
    const recoveryCall = calls.find(
      (call) => call.args.includes('db') && call.args.includes('recovery'),
    );
    expect(recoveryCall?.args).toEqual(
      expect.arrayContaining(['db', 'recovery', 'status', '--json']),
    );
  });
});
