import { chmod, link, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { databaseIdSchema, profileIdSchema } from '@kavrix/schemas';
import { setWindowsUserOnlyAcl } from '@kavrix/key-files';
import { MongoLocalVaultStore } from '@kavrix/storage';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  DatastoreProfileRegistry,
  resolveDatastoreProfileRouting,
  resolveProfilePath,
  verifyDatastoreProfileDatabaseId,
} from '../src/datastore-profiles.js';
import { buildLocalCli } from '../src/local-vault-cli.js';
import { LocalSecretInput } from '../src/local-secrets.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';

let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-datastore-profiles-'));
});

afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

function registry(): Promise<DatastoreProfileRegistry> {
  return DatastoreProfileRegistry.open({ configDirectory: directory });
}

function mongoProfile(id = 'work') {
  return {
    id: profileIdSchema.parse(id),
    datastore: 'mongodb' as const,
    databaseId: databaseIdSchema.parse(`db_${id}`),
    database: 'credentials',
    databaseCollection: 'kavrix_databases',
    vaultCollection: 'kavrix_vaults',
    keyFile: '/protected/work.kavrix-db-key',
  };
}

function fileProfile(id = 'local') {
  return {
    id: profileIdSchema.parse(id),
    datastore: 'file' as const,
    databaseId: databaseIdSchema.parse(`db_${id}`),
    dataFile: '/protected/local.kavrix-db',
    keyFile: '/protected/local.kavrix-db-key',
  };
}

describe('datastore profiles', () => {
  it('executes every profile CLI command with stable sanitized output', async () => {
    const output: string[] = [];
    const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      output.push(String(chunk));
      return true;
    });
    const execute = async (...args: string[]): Promise<Record<string, unknown>> => {
      output.length = 0;
      await buildLocalCli().parseAsync(['node', 'kavrix', ...args]);
      const text = output.join('');
      expect(text).not.toContain('\u001b');
      expect(text).not.toMatch(/(?:uri|password|token)/iu);
      return JSON.parse(text) as Record<string, unknown>;
    };
    try {
      expect(
        await execute(
          'db',
          'profile',
          'add',
          'work',
          '--config-dir',
          directory,
          '--datastore',
          'mongodb',
          '--database',
          'credentials',
          '--key-file',
          '/protected/work.kavrix-db-key',
        ),
      ).toMatchObject({ added: true, profile: { id: 'work', datastore: 'mongodb' } });
      expect(
        await execute(
          'db',
          'profile',
          'add',
          'local',
          '--config-dir',
          directory,
          '--datastore',
          'file',
          '--data-file',
          '/protected/local.kavrix-db',
          '--key-file',
          '/protected/local.kavrix-db-key',
        ),
      ).toMatchObject({ added: true, profile: { id: 'local', datastore: 'file' } });
      expect(await execute('db', 'profile', 'list', '--config-dir', directory)).toEqual(
        {
          profiles: [
            {
              id: 'local',
              datastore: 'file',
              dataFile: '/protected/local.kavrix-db',
              keyFile: '/protected/local.kavrix-db-key',
            },
            {
              id: 'work',
              datastore: 'mongodb',
              database: 'credentials',
              databaseCollection: 'kavrix_databases',
              vaultCollection: 'kavrix_vaults',
              keyFile: '/protected/work.kavrix-db-key',
            },
          ],
        },
      );
      expect(
        await execute('db', 'profile', 'use', 'work', '--config-dir', directory),
      ).toMatchObject({
        selected: { id: 'work' },
      });
      expect(
        await execute('db', 'profile', 'status', '--config-dir', directory),
      ).toMatchObject({
        current: { id: 'work' },
      });
      expect(
        await execute('db', 'profile', 'remove', 'work', '--config-dir', directory),
      ).toMatchObject({
        removed: true,
        profile: { id: 'work' },
      });
      expect(
        await execute('db', 'profile', 'status', '--config-dir', directory),
      ).toEqual({
        current: null,
      });
      await expect(
        buildLocalCli().parseAsync([
          'node',
          'kavrix',
          'db',
          'profile',
          'add',
          'local',
          '--config-dir',
          directory,
          '--datastore',
          'file',
          '--data-file',
          '/protected/local.kavrix-db',
          '--key-file',
          '/protected/local.kavrix-db-key',
        ]),
      ).rejects.toThrow('already exists');
      await expect(
        buildLocalCli().parseAsync([
          'node',
          'kavrix',
          'db',
          'profile',
          'remove',
          'missing',
          '--config-dir',
          directory,
        ]),
      ).rejects.toThrow('was not found');
    } finally {
      write.mockRestore();
    }
  });

  it('stores strict canonical non-secret profiles and switches deterministically', async () => {
    const profiles = await registry();
    await profiles.add(mongoProfile());
    await profiles.add(fileProfile());

    expect(await profiles.list()).toEqual([fileProfile(), mongoProfile()]);
    expect(await profiles.current()).toBeNull();
    await profiles.use(profileIdSchema.parse('work'));
    expect(await profiles.current()).toEqual(mongoProfile());

    const serialized = await readFile(resolveProfilePath(directory), 'utf8');
    expect(serialized).toBe(
      '{"current":"work","profiles":[{"dataFile":"/protected/local.kavrix-db","databaseId":"db_local","datastore":"file","id":"local","keyFile":"/protected/local.kavrix-db-key"},{"database":"credentials","databaseCollection":"kavrix_databases","databaseId":"db_work","datastore":"mongodb","id":"work","keyFile":"/protected/work.kavrix-db-key","vaultCollection":"kavrix_vaults"}],"version":1}',
    );
    expect(serialized).not.toContain('mongodb://');
    expect(serialized).not.toContain('password');
    expect(serialized).not.toContain('token');

    await profiles.remove(profileIdSchema.parse('work'));
    expect(await profiles.current()).toBeNull();
    expect(await profiles.list()).toEqual([fileProfile()]);
  });

  it('rejects duplicate, missing, and current-profile removal ambiguity', async () => {
    const profiles = await registry();
    await profiles.add(mongoProfile());
    await expect(profiles.add(mongoProfile())).rejects.toThrow('already exists');
    await expect(profiles.use(profileIdSchema.parse('missing'))).rejects.toThrow(
      'was not found',
    );
    await expect(profiles.remove(profileIdSchema.parse('missing'))).rejects.toThrow(
      'was not found',
    );
    await profiles.use(profileIdSchema.parse('work'));
    await profiles.remove(profileIdSchema.parse('work'));
    expect(await profiles.current()).toBeNull();
  });

  it('handles a registry creation race without publishing duplicate aliases', async () => {
    const first = await registry();
    const second = await registry();
    const results = await Promise.allSettled([
      first.add(mongoProfile()),
      second.add(mongoProfile()),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    expect(await first.list()).toEqual([mongoProfile()]);
  });

  it('binds an initialized opaque database ID once without changing routing', async () => {
    const profiles = await registry();
    const { databaseId: _databaseId, ...unbound } = mongoProfile();
    await profiles.add(unbound);
    const bound = await profiles.bindDatabaseId(
      profileIdSchema.parse('work'),
      databaseIdSchema.parse('db_initialized'),
    );
    expect(bound).toEqual({
      ...mongoProfile(),
      databaseId: databaseIdSchema.parse('db_initialized'),
    });
    await expect(
      profiles.bindDatabaseId(
        profileIdSchema.parse('work'),
        databaseIdSchema.parse('db_other'),
      ),
    ).rejects.toThrow('invalid');
  });

  it('preserves a profile database binding while explicit routing overrides win', async () => {
    const profile = mongoProfile();
    expect(
      resolveDatastoreProfileRouting(profile, {
        database: 'overridden',
        vaultCollection: 'overridden_vaults',
      }),
    ).toEqual({
      ...profile,
      database: 'overridden',
      vaultCollection: 'overridden_vaults',
    });
    expect(() =>
      verifyDatastoreProfileDatabaseId(profile, databaseIdSchema.parse('db_other')),
    ).toThrow('invalid');
    expect(() =>
      verifyDatastoreProfileDatabaseId(profile, databaseIdSchema.parse('db_work')),
    ).not.toThrow();
  });

  it('composes an explicit profile into db ping and gives explicit routing precedence', async () => {
    const profiles = await registry();
    const { databaseId: _databaseId, ...unbound } = mongoProfile();
    await profiles.add(unbound);
    const ping = vi.fn(async () => undefined);
    const close = vi.fn(async () => undefined);
    const connect = vi
      .spyOn(MongoLocalVaultStore, 'connect')
      .mockResolvedValue({ ping, close } as never);
    vi.spyOn(LocalSecretInput.prototype, 'read').mockResolvedValue([
      'mongodb://localhost/ignored-by-explicit-routing',
    ]);
    const output: string[] = [];
    const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      output.push(String(chunk));
      return true;
    });
    try {
      await buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'db',
        'ping',
        '--profile',
        'work',
        '--profile-config-dir',
        directory,
        '--database',
        'explicit_database',
        '--collection',
        'explicit_collection',
      ]);
      expect(connect).toHaveBeenCalledWith(
        'mongodb://localhost/ignored-by-explicit-routing',
        'explicit_database',
        { collectionName: 'explicit_collection' },
      );
      expect(ping).toHaveBeenCalledOnce();
      expect(close).toHaveBeenCalledOnce();
      expect(JSON.parse(output.join(''))).toEqual({
        connected: true,
        profile: 'work',
        database: 'explicit_database',
        collection: 'explicit_collection',
      });
    } finally {
      write.mockRestore();
      vi.restoreAllMocks();
    }
  });

  it('uses the current unbound profile for db ping without creating absent profile state', async () => {
    const profiles = await registry();
    const { databaseId: _databaseId, ...unbound } = mongoProfile();
    await profiles.add(unbound);
    await profiles.use(profileIdSchema.parse('work'));
    const connect = vi.spyOn(MongoLocalVaultStore, 'connect').mockResolvedValue({
      ping: async () => undefined,
      close: async () => undefined,
    } as never);
    vi.spyOn(LocalSecretInput.prototype, 'read').mockResolvedValue([
      'mongodb://localhost/ignored-by-profile-routing',
    ]);
    const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      await buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'db',
        'ping',
        '--profile-config-dir',
        directory,
      ]);
      expect(connect).toHaveBeenCalledWith(
        'mongodb://localhost/ignored-by-profile-routing',
        'credentials',
        { collectionName: 'kavrix_vaults' },
      );
    } finally {
      write.mockRestore();
      vi.restoreAllMocks();
    }
  });

  it('fails closed before secret input when db ping receives a database-bound profile', async () => {
    const profiles = await registry();
    await profiles.add(mongoProfile());
    await expect(
      buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'db',
        'ping',
        '--profile',
        'work',
        '--profile-config-dir',
        directory,
      ]),
    ).rejects.toThrow('requires database container commands');
  });

  it('rejects unsafe registry filesystem state and preserves the last valid publication', async () => {
    const profiles = await registry();
    await profiles.add(mongoProfile());
    const path = resolveProfilePath(directory);
    const before = await readFile(path, 'utf8');

    if (process.platform !== 'win32') {
      await chmod(path, 0o644);
      await expect(profiles.list()).rejects.toThrow('safe');
      await chmod(path, 0o600);
      const linked = join(directory, 'linked.json');
      await link(path, linked);
      await expect(
        DatastoreProfileRegistry.open({
          configDirectory: directory,
          fileName: 'linked.json',
        }),
      ).rejects.toThrow('safe');
      await rm(linked);
      const target = join(directory, 'target.json');
      await writeFile(target, before, { mode: 0o600 });
      const symlinked = join(directory, 'symlinked.json');
      await symlink(target, symlinked);
      await expect(
        DatastoreProfileRegistry.open({
          configDirectory: directory,
          fileName: 'symlinked.json',
        }),
      ).rejects.toThrow('safe');
    }

    await expect(
      profiles.add({
        ...mongoProfile(),
        databaseId: databaseIdSchema.parse('db_other'),
      }),
    ).rejects.toThrow('already exists');
    expect(await readFile(path, 'utf8')).toBe(before);
  });

  it(
    'rejects control characters, forbidden keys at every depth, noncanonical JSON, and bounds',
    async () => {
      const profiles = await registry();
      await expect(
        profiles.add({ ...mongoProfile(), database: 'bad\u001bname' }),
      ).rejects.toThrow('invalid');
      await expect(
        profiles.add({ ...mongoProfile(), uri: 'mongodb://forbidden' } as never),
      ).rejects.toThrow('invalid');

      const path = resolveProfilePath(directory);
      await writeFile(
        path,
        '{"current":null,"profiles":[],"version":1,"nested":{"accessToken":"forbidden"}}',
        { mode: 0o600 },
      );
      if (process.platform === 'win32') await setWindowsUserOnlyAcl(path);
      await expect(profiles.list()).rejects.toThrow('invalid');

      await rm(path);
      for (let index = 0; index < 64; index += 1) {
        await profiles.add(fileProfile(`profile-${String(index)}`));
      }
      await expect(profiles.add(fileProfile('profile-64'))).rejects.toThrow('limited');
    },
    process.platform === 'win32' ? 180_000 : 60_000,
  );
});
