import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { databaseIdSchema, profileIdSchema, vaultIdSchema } from '@kavrix/schemas';
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
    const calls: Array<{ args: readonly string[]; frames: readonly string[] }> = [];
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
    expect(result.snapshot.credentials.map((c) => c.name)).toEqual(['alpha', 'beta']);
    const putCall = calls.find((call) => call.args.includes('put'));
    expect(putCall?.frames).toEqual(['correct horse battery staple', 'secret-value']);
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
    expect(result.snapshot.credentials.map((c) => c.name)).toEqual(['alpha', 'gamma']);
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

  it('creates a file profile via documented CLI frames then unlocks', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kavrix-tui-create-'));
    dirs.push(dir);
    const calls: Array<{ args: readonly string[]; frames: readonly string[] }> = [];
    let vaultCreated = false;
    let recoveryCreated = false;
    let recoveryVerified = false;
    const recoveryFile = join(dir, 'fresh.recovery');

    const backend = createCliTuiBackend({
      profileConfigDir: dir,
      ascii: true,
      commandRunner: async (args, frames) => {
        calls.push({ args: [...args], frames: [...frames] });
        const joined = args.join(' ');
        if (args.includes('add') && args.includes('profile')) {
          const registry = await DatastoreProfileRegistry.open({
            configDirectory: dir,
          });
          await registry.add({
            id: profileIdSchema.parse('fresh'),
            datastore: 'file',
            dataFile: join(dir, 'db.kavrix'),
            keyFile: join(dir, 'owner.key'),
          });
          return '';
        }
        if (
          args.includes('use') &&
          args.includes('profile') &&
          !args.includes('vault')
        ) {
          const registry = await DatastoreProfileRegistry.open({
            configDirectory: dir,
          });
          await registry.use(profileIdSchema.parse('fresh'));
          return '';
        }
        if (args[0] === 'db' && args[1] === 'init') {
          expect(frames).toEqual([
            'fresh-db',
            'correct horse battery staple',
            'correct horse battery staple',
          ]);
          expect(args).toContain('--passphrase-stdin');
          expect(joined).not.toContain('correct horse');
          const registry = await DatastoreProfileRegistry.open({
            configDirectory: dir,
          });
          await registry.bindDatabaseIdForInitialization(
            profileIdSchema.parse('fresh'),
            databaseIdSchema.parse('db_fresh'),
          );
          return '';
        }
        if (args.includes('vault') && args.includes('create')) {
          expect(frames).toEqual(['correct horse battery staple', 'fresh-vault']);
          vaultCreated = true;
          return JSON.stringify({ vaultId: 'vault_fresh' });
        }
        if (args.includes('vault') && args.includes('use')) {
          expect(frames).toEqual(['correct horse battery staple']);
          expect(args).toContain('vault_fresh');
          return '';
        }
        if (args[0] === 'db' && args[1] === 'recovery' && args.includes('create')) {
          expect(args).toEqual(
            expect.arrayContaining(['--recovery-file', recoveryFile]),
          );
          expect(frames).toEqual([
            'correct horse battery staple',
            'recovery-secret-kit!!',
            'recovery-secret-kit!!',
          ]);
          expect(joined).not.toContain('recovery-secret');
          recoveryCreated = true;
          return '';
        }
        if (args[0] === 'db' && args[1] === 'recovery' && args.includes('verify')) {
          expect(args).toEqual(
            expect.arrayContaining(['--recovery-file', recoveryFile]),
          );
          expect(frames).toEqual([
            'correct horse battery staple',
            'recovery-secret-kit!!',
          ]);
          recoveryVerified = true;
          return '';
        }
        if (args[0] === 'db' && args[1] === 'recovery' && args.includes('status')) {
          return JSON.stringify({
            slots: [{ id: 'slot-onboard', state: 'active' }],
            active: 1,
            revoked: 0,
          });
        }
        if (args.includes('list')) {
          return JSON.stringify({ names: [] });
        }
        return '{}';
      },
    });

    const result = await backend.dispatch({
      type: 'create-file-profile',
      profileId: 'fresh',
      dataFile: join(dir, 'db.kavrix'),
      keyFile: join(dir, 'owner.key'),
      passphrase: 'correct horse battery staple',
      recoveryFile,
      recoveryPassphrase: 'recovery-secret-kit!!',
    });

    expect(vaultCreated).toBe(true);
    expect(recoveryCreated).toBe(true);
    expect(recoveryVerified).toBe(true);
    expect(result.snapshot.noticeTone).toBe('success');
    expect(result.snapshot.notice).toMatch(/recovery kit created and verified/i);
    expect(result.snapshot.home.profileId).toBe('fresh');
    expect(result.snapshot.home.vaultId).toBe('vault_fresh');
    expect(result.snapshot.home.unlocked).toBe(true);

    const addCall = calls.find(
      (call) => call.args.includes('add') && call.args.includes('profile'),
    );
    expect(addCall?.frames).toEqual([]);
    expect(addCall?.args).toEqual(
      expect.arrayContaining([
        'db',
        'profile',
        'add',
        'fresh',
        '--datastore',
        'file',
        '--data-file',
      ]),
    );
    const initCall = calls.find(
      (call) => call.args[0] === 'db' && call.args[1] === 'init',
    );
    expect(initCall?.frames).toHaveLength(3);
    const createCall = calls.find(
      (call) => call.args.includes('vault') && call.args.includes('create'),
    );
    expect(createCall?.args).toContain('--passphrase-stdin');
    // Secrets never appear on argv across the whole create sequence.
    for (const call of calls) {
      expect(call.args.join(' ')).not.toContain('correct horse');
      expect(call.args.join(' ')).not.toContain('recovery-secret');
    }
  });

  it('retains profile when recovery fails after vault create', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kavrix-tui-create-recfail-'));
    dirs.push(dir);
    let removed = false;
    const recoveryFile = join(dir, 'broken.recovery');

    const backend = createCliTuiBackend({
      profileConfigDir: dir,
      ascii: true,
      commandRunner: async (args, frames) => {
        if (args.includes('add') && args.includes('profile')) {
          const registry = await DatastoreProfileRegistry.open({
            configDirectory: dir,
          });
          await registry.add({
            id: profileIdSchema.parse('kept'),
            datastore: 'file',
            dataFile: join(dir, 'db.kavrix'),
            keyFile: join(dir, 'owner.key'),
          });
          return '';
        }
        if (
          args.includes('use') &&
          args.includes('profile') &&
          !args.includes('vault')
        ) {
          const registry = await DatastoreProfileRegistry.open({
            configDirectory: dir,
          });
          await registry.use(profileIdSchema.parse('kept'));
          return '';
        }
        if (args[0] === 'db' && args[1] === 'init') {
          const registry = await DatastoreProfileRegistry.open({
            configDirectory: dir,
          });
          await registry.bindDatabaseIdForInitialization(
            profileIdSchema.parse('kept'),
            databaseIdSchema.parse('db_kept'),
          );
          return '';
        }
        if (args.includes('vault') && args.includes('create')) {
          return JSON.stringify({ vaultId: 'vault_kept' });
        }
        if (args.includes('vault') && args.includes('use')) {
          return '';
        }
        if (args.includes('list')) {
          return JSON.stringify({ names: [] });
        }
        if (args[0] === 'db' && args[1] === 'recovery' && args.includes('create')) {
          throw new Error('simulated recovery create failure');
        }
        if (args.includes('remove') && args.includes('profile')) {
          removed = true;
          return '';
        }
        return '{}';
      },
    });

    const result = await backend.dispatch({
      type: 'create-file-profile',
      profileId: 'kept',
      dataFile: join(dir, 'db.kavrix'),
      keyFile: join(dir, 'owner.key'),
      passphrase: 'correct horse battery staple',
      recoveryFile,
      recoveryPassphrase: 'recovery-secret-kit!!',
    });

    expect(result.snapshot.noticeTone).toBe('error');
    expect(result.snapshot.notice).toMatch(/recovery kit setup failed/i);
    expect(result.snapshot.notice).toMatch(/Protected state was retained/i);
    expect(removed).toBe(false);
  });

  it('runs doctor, policy, grant, recovery, preview, and agent via real CLI frames', async () => {
    const configDir = await setupProfile();
    const calls: Array<{ args: readonly string[]; frames: readonly string[] }> = [];
    let policies: Array<Record<string, unknown>> = [];
    let grants: Array<Record<string, unknown>> = [];
    let slots: Array<Record<string, unknown>> = [];

    const backend = createCliTuiBackend({
      profileConfigDir: configDir,
      ascii: true,
      commandRunner: async (args, frames) => {
        calls.push({ args: [...args], frames: [...frames] });
        if (
          args.includes('list') &&
          args[0] !== 'policy' &&
          args[0] !== 'grant' &&
          args[0] !== 'context' &&
          args[0] !== 'service' &&
          args[0] !== 'item'
        ) {
          return JSON.stringify({ names: ['alpha'] });
        }
        if (args[0] === 'doctor' || (args[0] === 'db' && args[1] === 'doctor')) {
          return JSON.stringify({
            healthy: true,
            checks: [{ name: 'database-container', status: 'ok', detail: 'ok' }],
          });
        }
        if (args[0] === 'policy' && args[1] === 'list') {
          return JSON.stringify({ policies });
        }
        if (args[0] === 'policy' && args[1] === 'create') {
          const id = args[2];
          policies = [
            ...policies.filter((row) => row['id'] !== id),
            {
              id,
              secret: 'alpha',
              commands: ['true'],
              createdAt: '2026-01-01T00:00:00.000Z',
            },
          ];
          return JSON.stringify({ saved: true, id });
        }
        if (args[0] === 'policy' && args[1] === 'remove') {
          const id = args[2];
          policies = policies.filter((row) => row['id'] !== id);
          return JSON.stringify({ removed: true, id });
        }
        if (args[0] === 'grant' && args[1] === 'list') {
          return JSON.stringify({ grants });
        }
        if (args[0] === 'grant' && args[1] === 'create') {
          const grantId = 'grant_test_1';
          grants = [
            {
              grantId,
              secret: 'alpha',
              status: 'active',
              commands: ['true'],
              createdAt: '2026-01-01T00:00:00.000Z',
            },
          ];
          return JSON.stringify({ granted: true, grantId });
        }
        if (args[0] === 'grant' && args[1] === 'revoke') {
          const grantId = args[2];
          grants = grants.map((row) =>
            row['grantId'] === grantId ? { ...row, status: 'revoked' } : row,
          );
          return JSON.stringify({ revoked: true, grantId });
        }
        if (args[0] === 'audit') {
          return JSON.stringify({ total: 0, shown: 0, events: [] });
        }
        if (args.includes('recovery') && args.includes('create')) {
          slots = [{ id: 'slot-new', state: 'active' }];
          return JSON.stringify({ slotId: 'slot-new' });
        }
        if (args.includes('recovery') && args.includes('verify')) {
          return JSON.stringify({ verified: true, slotId: 'slot-new' });
        }
        if (args.includes('recovery') && args.includes('status')) {
          return JSON.stringify({
            active: slots.filter((slot) => slot['state'] === 'active').length,
            revoked: 0,
            slots,
          });
        }
        if (args[0] === 'run' && args.includes('--help')) {
          return 'Usage: kavrix run [options]';
        }
        if (args[0] === 'has') {
          const name = args[1];
          return JSON.stringify({ exists: name === 'alpha', name, revision: 1 });
        }
        if (args[0] === 'context' && args[1] === 'list') {
          return JSON.stringify({ contexts: [{ name: 'default' }] });
        }
        if (args[0] === 'service' && args[1] === 'list') {
          return JSON.stringify({ context: 'default', services: ['api'] });
        }
        if (args[0] === 'item' && args[1] === 'list') {
          return JSON.stringify({
            context: 'default',
            service: 'api',
            items: ['token'],
          });
        }
        if (args[0] === 'agent' && args.includes('--dry-run')) {
          return JSON.stringify({ dryRun: true, ok: true, agent: 'noop' });
        }
        return '{}';
      },
    });

    await backend.dispatch({
      type: 'unlock',
      passphrase: 'correct horse battery staple',
    });

    let result = await backend.dispatch({ type: 'run-doctor' });
    expect(
      result.snapshot.doctor.some((row) => row.name === 'database-container'),
    ).toBe(true);
    expect(result.snapshot.noticeTone).toBe('success');

    result = await backend.dispatch({
      type: 'policy-create',
      id: 'allow-true',
      secret: 'alpha',
      command: 'true',
    });
    expect(result.snapshot.noticeTone).toBe('success');
    expect(
      result.snapshot.policies.some(
        (row) => row.kind === 'policy' && row.id === 'allow-true',
      ),
    ).toBe(true);
    const policyCreate = calls.find(
      (call) => call.args[0] === 'policy' && call.args[1] === 'create',
    );
    expect(policyCreate?.frames).toEqual(['correct horse battery staple']);
    expect(policyCreate?.args.join(' ')).not.toContain('correct horse');

    result = await backend.dispatch({
      type: 'grant-create',
      secret: 'alpha',
      command: 'true',
      ttl: '15m',
    });
    expect(result.snapshot.noticeTone).toBe('success');
    expect(result.snapshot.policies.some((row) => row.kind === 'grant')).toBe(true);

    result = await backend.dispatch({
      type: 'grant-revoke',
      grantId: 'grant_test_1',
    });
    expect(result.snapshot.noticeTone).toBe('success');

    result = await backend.dispatch({
      type: 'policy-remove',
      id: 'allow-true',
    });
    expect(result.snapshot.noticeTone).toBe('success');
    expect(
      result.snapshot.policies.some(
        (row) => row.kind === 'policy' && row.id === 'allow-true',
      ),
    ).toBe(false);

    result = await backend.dispatch({
      type: 'recovery-create',
      recoveryFile: join(configDir, 'recovery.kit'),
      recoveryPassphrase: 'recovery-secret',
    });
    expect(result.snapshot.noticeTone).toBe('success');
    expect(result.snapshot.recovery.some((slot) => slot.slotId === 'slot-new')).toBe(
      true,
    );
    const recoveryCreate = calls.find(
      (call) => call.args.includes('recovery') && call.args.includes('create'),
    );
    expect(recoveryCreate?.frames).toEqual([
      'correct horse battery staple',
      'recovery-secret',
      'recovery-secret',
    ]);
    expect(recoveryCreate?.args.join(' ')).not.toContain('recovery-secret');

    result = await backend.dispatch({
      type: 'recovery-verify',
      recoveryFile: join(configDir, 'recovery.kit'),
      recoveryPassphrase: 'recovery-secret',
    });
    expect(result.snapshot.noticeTone).toBe('success');

    result = await backend.dispatch({
      type: 'preview-run',
      credentialNames: ['alpha'],
    });
    expect(result.snapshot.noticeTone).toBe('success');
    expect(result.snapshot.runPreview.toLowerCase()).toContain('validated');

    result = await backend.dispatch({
      type: 'agent-dry-run',
      configPath: join(configDir, 'agent.kavrix.json'),
      agentName: 'noop',
    });
    expect(result.snapshot.noticeTone).toBe('success');
    const agentCall = calls.find(
      (call) => call.args[0] === 'agent' && call.args.includes('--dry-run'),
    );
    expect(agentCall?.args).toEqual(
      expect.arrayContaining([
        'agent',
        'run',
        '--dry-run',
        '--json',
        '--agent',
        'noop',
      ]),
    );
    expect(result.snapshot.agentStatus.length).toBeGreaterThan(0);

    result = await backend.dispatch({ type: 'refresh-browse' });
    expect(result.snapshot.noticeTone).toBe('success');
    expect(result.snapshot.browse.some((node) => node.kind === 'context')).toBe(true);
    expect(result.snapshot.browse.some((node) => node.kind === 'service')).toBe(true);
    expect(result.snapshot.browse.some((node) => node.kind === 'item')).toBe(true);
    const hasCall = calls.find((call) => call.args[0] === 'has');
    expect(hasCall?.frames).toEqual(['correct horse battery staple']);
    expect(hasCall?.args.join(' ')).not.toContain('correct horse');
  });

  it('creates mongodb profile via db profile add/init frames with URL on stdin only', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kavrix-tui-mongo-'));
    dirs.push(dir);
    const calls: Array<{ args: readonly string[]; frames: readonly string[] }> = [];
    let vaultCreated = false;
    const mongoUrl = 'mongodb://127.0.0.1:27017/?replicaSet=rs0';
    const passphrase = 'correct horse battery staple';

    const backend = createCliTuiBackend({
      profileConfigDir: dir,
      ascii: true,
      commandRunner: async (args, frames) => {
        calls.push({ args: [...args], frames: [...frames] });
        const joined = args.join(' ');
        if (args[0] === 'db' && args[1] === 'profile' && args[2] === 'add') {
          expect(args).toEqual(
            expect.arrayContaining([
              'db',
              'profile',
              'add',
              'mongo',
              '--datastore',
              'mongodb',
              '--database',
              'credentials',
              '--key-file',
            ]),
          );
          expect(frames).toEqual([]);
          expect(joined).not.toContain(mongoUrl);
          const registry = await DatastoreProfileRegistry.open({
            configDirectory: dir,
          });
          await registry.add({
            id: profileIdSchema.parse('mongo'),
            datastore: 'mongodb',
            database: 'credentials',
            databaseCollection: 'kavrix_databases',
            vaultCollection: 'kavrix_vaults',
            keyFile: join(dir, 'owner.key'),
          });
          return '';
        }
        if (args[0] === 'db' && args[1] === 'profile' && args[2] === 'use') {
          const registry = await DatastoreProfileRegistry.open({
            configDirectory: dir,
          });
          await registry.use(profileIdSchema.parse('mongo'));
          return '';
        }
        if (args[0] === 'db' && args[1] === 'init') {
          expect(frames).toEqual([mongoUrl, 'mongo-db', passphrase, passphrase]);
          expect(args).toContain('--passphrase-stdin');
          expect(joined).not.toContain(mongoUrl);
          expect(joined).not.toContain(passphrase);
          const registry = await DatastoreProfileRegistry.open({
            configDirectory: dir,
          });
          await registry.bindDatabaseIdForInitialization(
            profileIdSchema.parse('mongo'),
            databaseIdSchema.parse('db_mongo'),
          );
          return '';
        }
        if (args.includes('vault') && args.includes('create')) {
          expect(frames).toEqual([mongoUrl, passphrase, 'mongo-vault']);
          vaultCreated = true;
          return JSON.stringify({ vaultId: 'vault_mongo' });
        }
        if (args.includes('vault') && args.includes('use')) {
          expect(frames).toEqual([mongoUrl, passphrase]);
          expect(args).toContain('vault_mongo');
          return '';
        }
        if (args.includes('list') && args[0] !== 'policy' && args[0] !== 'grant') {
          expect(frames[0]).toBe(mongoUrl);
          expect(frames[1]).toBe(passphrase);
          expect(args).toContain('--database-url-stdin');
          expect(joined).not.toContain(mongoUrl);
          return JSON.stringify({ names: [] });
        }
        return '{}';
      },
    });

    const result = await backend.dispatch({
      type: 'create-mongodb-profile',
      profileId: 'mongo',
      database: 'credentials',
      keyFile: join(dir, 'owner.key'),
      databaseUrl: mongoUrl,
      passphrase,
      databaseLabel: 'mongo-db',
      vaultLabel: 'mongo-vault',
    });

    expect(vaultCreated).toBe(true);
    expect(result.snapshot.noticeTone).toBe('success');
    expect(result.snapshot.home.profileId).toBe('mongo');
    expect(result.snapshot.home.datastore).toBe('mongodb');
    expect(result.snapshot.home.vaultId).toBe('vault_mongo');
    expect(result.snapshot.home.unlocked).toBe(true);
    expect(result.snapshot.agentStatus).toBe('');

    for (const call of calls) {
      expect(call.args.join(' ')).not.toContain(mongoUrl);
      expect(call.args.join(' ')).not.toContain(passphrase);
    }
  });

  it('rejects agent dry-run without agent name and does not invent noop', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kavrix-tui-agent-'));
    dirs.push(dir);
    const calls: Array<{ args: readonly string[]; frames: readonly string[] }> = [];
    const backend = createCliTuiBackend({
      profileConfigDir: dir,
      ascii: true,
      commandRunner: async (args, frames) => {
        calls.push({ args: [...args], frames: [...frames] });
        return '{}';
      },
    });
    const result = await backend.dispatch({ type: 'agent-dry-run' });
    expect(result.snapshot.noticeTone).toBe('error');
    expect(result.snapshot.agentStatus.toLowerCase()).toContain(
      'requires an agent name',
    );
    expect(result.snapshot.agentStatus.toLowerCase()).not.toContain('noop');
    expect(calls.some((call) => call.args[0] === 'agent')).toBe(false);
  });
});
