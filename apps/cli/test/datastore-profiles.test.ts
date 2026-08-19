import {
  chmod,
  link,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { databaseIdSchema, profileIdSchema } from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  DatastoreProfileRegistry,
  resolveProfilePath,
} from '../src/datastore-profiles.js';

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

  it('rejects control characters, forbidden keys at every depth, noncanonical JSON, and bounds', async () => {
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
    await expect(profiles.list()).rejects.toThrow('invalid');

    await rm(path);
    for (let index = 0; index < 64; index += 1) {
      await profiles.add(fileProfile(`profile-${String(index)}`));
    }
    await expect(profiles.add(fileProfile('profile-64'))).rejects.toThrow('limited');
  });
});
