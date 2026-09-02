import type * as FsPromises from 'node:fs/promises';

import { readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { databaseIdSchema, profileIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { validateDatastoreProfileBindingPublicationResult } from '../src/datastore-profiles.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';

type FaultPhase =
  | 'none'
  | 'pre-publication'
  | 'post-link'
  | 'post-rename'
  | 'final-verification'
  | 'directory-sync'
  | 'foreign-replacement';

const fault = vi.hoisted(() => ({
  phase: 'none' as FaultPhase,
  target: '',
  directory: '',
  renamed: false,
  fired: false,
  foreignContents: '',
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  const injected = (): NodeJS.ErrnoException => {
    const error = new Error(
      'profile publication credential canary',
    ) as NodeJS.ErrnoException;
    error.code = 'EIO';
    return error;
  };
  return {
    ...actual,
    link: async (existingPath: FsPromises.PathLike, newPath: FsPromises.PathLike) => {
      if (String(newPath) !== fault.target || fault.fired) {
        return actual.link(existingPath, newPath);
      }
      if (fault.phase === 'pre-publication') {
        fault.fired = true;
        throw injected();
      }
      await actual.link(existingPath, newPath);
      fault.renamed = true;
      if (fault.phase === 'post-link') {
        fault.fired = true;
        throw injected();
      }
    },
    rename: async (oldPath: FsPromises.PathLike, newPath: FsPromises.PathLike) => {
      if (String(newPath) !== fault.target || fault.fired) {
        return actual.rename(oldPath, newPath);
      }
      if (fault.phase === 'pre-publication') {
        fault.fired = true;
        throw injected();
      }
      await actual.rename(oldPath, newPath);
      fault.renamed = true;
      if (fault.phase === 'post-rename') {
        fault.fired = true;
        throw injected();
      }
      if (fault.phase === 'foreign-replacement') {
        await actual.unlink(newPath);
        await actual.writeFile(newPath, fault.foreignContents, { mode: 0o600 });
        if (process.platform === 'win32') {
          const { setWindowsUserOnlyAcl } =
            await import('@kavrix/key-files/windows-acl');
          await setWindowsUserOnlyAcl(String(newPath));
        }
        fault.fired = true;
        throw injected();
      }
    },
    lstat: async (path: FsPromises.PathLike, options?: unknown) => {
      const result = await actual.lstat(path, options as never);
      if (
        fault.phase === 'final-verification' &&
        String(path) === fault.target &&
        fault.renamed &&
        !fault.fired
      ) {
        fault.fired = true;
        throw injected();
      }
      return result;
    },
    open: async (
      path: FsPromises.PathLike,
      flags: string | number,
      mode?: FsPromises.Mode,
    ) => {
      const handle = await actual.open(path, flags, mode);
      if (
        fault.phase !== 'directory-sync' ||
        String(path) !== fault.directory ||
        !fault.renamed ||
        fault.fired
      ) {
        return handle;
      }
      return new Proxy(handle, {
        get(target, property) {
          if (property === 'sync') {
            return async () => {
              fault.fired = true;
              throw injected();
            };
          }
          const value: unknown = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
  };
});

import {
  DatastoreProfileRegistry,
  resolveProfilePath,
} from '../src/datastore-profiles.js';

let directory = '';

beforeEach(async () => {
  directory = await realpath(
    await mkdtemp(join(tmpdir(), 'kavrix-profile-publication-')),
  );
  resetFault();
});

afterEach(async () => {
  resetFault();
  await rm(directory, { force: true, recursive: true });
});

function resetFault(): void {
  fault.phase = 'none';
  fault.target = '';
  fault.directory = '';
  fault.renamed = false;
  fault.fired = false;
  fault.foreignContents = '';
}

function armFault(phase: Exclude<FaultPhase, 'none'>, foreignContents = ''): void {
  fault.phase = phase;
  fault.target = resolveProfilePath(directory);
  fault.directory = directory;
  fault.renamed = false;
  fault.fired = false;
  fault.foreignContents = foreignContents;
}

async function unboundRegistry(): Promise<DatastoreProfileRegistry> {
  const profiles = await DatastoreProfileRegistry.open({
    configDirectory: directory,
  });
  await profiles.add({
    id: profileIdSchema.parse('work'),
    datastore: 'file',
    dataFile: '/protected/database.kavrix',
    keyFile: '/protected/owner.kavrix-db-key',
  });
  return profiles;
}

describe('datastore profile binding publication', () => {
  it.each(['post-link', 'final-verification', 'directory-sync'] as const)(
    'reports uncertain initial route publication after create-mode %s failure',
    async (phase) => {
      const profiles = await DatastoreProfileRegistry.open({
        configDirectory: directory,
      });
      const expected = {
        id: profileIdSchema.parse('guided'),
        datastore: 'file' as const,
        dataFile: '/protected/guided-database.kavrix',
        keyFile: '/protected/guided-owner.key',
      };
      armFault(phase);

      const publication = await profiles.addForInitialization(expected);

      expect(publication).toMatchObject({
        status: 'publication-uncertain',
        error: { code: 'PROFILE_UNSAFE' },
      });
      expect(Object.isFrozen(publication)).toBe(true);
      expect(await profiles.get(expected.id)).toEqual(expected);
    },
  );

  it('reports uncertain initial route publication after existing-registry replacement', async () => {
    const profiles = await unboundRegistry();
    const expected = {
      id: profileIdSchema.parse('guided'),
      datastore: 'file' as const,
      dataFile: '/protected/guided-database.kavrix',
      keyFile: '/protected/guided-owner.key',
    };
    armFault('post-rename');

    const publication = await profiles.addForInitialization(expected);

    expect(publication).toMatchObject({
      status: 'publication-uncertain',
      error: { code: 'PROFILE_UNSAFE' },
    });
    expect(await profiles.get(expected.id)).toEqual(expected);
  });

  it('proves initial route non-publication before create-only publication', async () => {
    const profiles = await DatastoreProfileRegistry.open({
      configDirectory: directory,
    });
    const expected = {
      id: profileIdSchema.parse('guided'),
      datastore: 'file' as const,
      dataFile: '/protected/guided-database.kavrix',
      keyFile: '/protected/guided-owner.key',
    };
    armFault('pre-publication');

    const publication = await profiles.addForInitialization(expected);

    expect(publication).toMatchObject({
      status: 'not-published',
      error: { code: 'PROFILE_UNSAFE' },
    });
    await expect(profiles.get(expected.id)).rejects.toMatchObject({
      code: 'PROFILE_NOT_FOUND',
    });
  });

  it('returns published with an opaque capability and preserves bindDatabaseId behavior', async () => {
    const profiles = await unboundRegistry();
    const databaseId = databaseIdSchema.parse('db_initialized');

    const publication = await profiles.bindDatabaseIdForInitialization(
      profileIdSchema.parse('work'),
      databaseId,
    );

    expect(publication).toMatchObject({ status: 'published' });
    if (publication.status !== 'published') {
      throw new Error('Expected published profile binding');
    }
    expect(Object.isFrozen(publication)).toBe(true);
    const proof = validateDatastoreProfileBindingPublicationResult(publication);
    expect(proof).toEqual({ status: 'published' });
    expect(Object.isFrozen(proof)).toBe(true);
    expect(validateDatastoreProfileBindingPublicationResult(publication)).not.toBe(
      proof,
    );
    expect(Object.isFrozen(publication.publication)).toBe(true);
    expect(Reflect.ownKeys(publication.publication)).toEqual([]);
    expect(JSON.stringify(publication.publication)).toBe('{}');
    expect(await profiles.get(profileIdSchema.parse('work'))).toMatchObject({
      databaseId,
    });
    await expect(
      profiles.bindDatabaseId(profileIdSchema.parse('work'), databaseId),
    ).resolves.toMatchObject({ databaseId });
  });

  it('proves non-publication before rename and leaves the profile unbound', async () => {
    const profiles = await unboundRegistry();
    armFault('pre-publication');

    const publication = await profiles.bindDatabaseIdForInitialization(
      profileIdSchema.parse('work'),
      databaseIdSchema.parse('db_initialized'),
    );

    expect(publication).toMatchObject({
      status: 'not-published',
      error: { code: 'PROFILE_UNSAFE' },
    });
    expect(publication).not.toHaveProperty('publication');
    expect(Object.isFrozen(publication)).toBe(true);
    expect(validateDatastoreProfileBindingPublicationResult(publication)).toEqual({
      status: 'not-published',
      errorCategory: 'PROFILE_UNSAFE',
    });
    expect(await profiles.get(profileIdSchema.parse('work'))).not.toHaveProperty(
      'databaseId',
    );
  });

  it.each(['post-rename', 'final-verification', 'directory-sync'] as const)(
    'retains the exact binding and returns publication uncertainty after %s failure',
    async (phase) => {
      const profiles = await unboundRegistry();
      const databaseId = databaseIdSchema.parse(`db_${phase.replace('-', '_')}`);
      armFault(phase);

      const publication = await profiles.bindDatabaseIdForInitialization(
        profileIdSchema.parse('work'),
        databaseId,
      );

      expect(publication).toMatchObject({
        status: 'publication-uncertain',
        error: { code: 'PROFILE_UNSAFE' },
      });
      if (publication.status !== 'publication-uncertain') {
        throw new Error('Expected uncertain profile binding');
      }
      expect(Object.isFrozen(publication.publication)).toBe(true);
      expect(Object.isFrozen(publication)).toBe(true);
      expect(validateDatastoreProfileBindingPublicationResult(publication)).toEqual({
        status: 'publication-uncertain',
        errorCategory: 'PROFILE_UNSAFE',
      });
      expect(Reflect.ownKeys(publication.publication)).toEqual([]);
      const serialized = JSON.stringify(publication);
      expect(serialized).not.toContain(directory);
      expect(serialized).not.toContain('credential canary');
      expect(await profiles.get(profileIdSchema.parse('work'))).toMatchObject({
        databaseId,
      });
    },
  );

  it('fails closed without overwriting or deleting a foreign replacement', async () => {
    const profiles = await unboundRegistry();
    const foreign = '{"current":null,"profiles":[],"version":1}';
    armFault('foreign-replacement', foreign);

    const publication = await profiles.bindDatabaseIdForInitialization(
      profileIdSchema.parse('work'),
      databaseIdSchema.parse('db_initialized'),
    );

    expect(publication).toMatchObject({
      status: 'publication-uncertain',
      error: { code: 'PROFILE_UNSAFE' },
    });
    expect(await readFile(resolveProfilePath(directory), 'utf8')).toBe(foreign);
    expect(await profiles.list()).toEqual([]);
  });

  it('rejects an already-bound profile without rewriting the registry', async () => {
    const profiles = await unboundRegistry();
    await profiles.bindDatabaseId(
      profileIdSchema.parse('work'),
      databaseIdSchema.parse('db_existing'),
    );
    const before = await readFile(resolveProfilePath(directory), 'utf8');

    const publication = await profiles.bindDatabaseIdForInitialization(
      profileIdSchema.parse('work'),
      databaseIdSchema.parse('db_new'),
    );

    expect(publication).toMatchObject({
      status: 'not-published',
      error: { code: 'PROFILE_INVALID' },
    });
    expect(await readFile(resolveProfilePath(directory), 'utf8')).toBe(before);
  });

  it('returns closed non-publication for malformed initialization IDs', async () => {
    const profiles = await unboundRegistry();
    const before = await readFile(resolveProfilePath(directory), 'utf8');

    const publication = await profiles.bindDatabaseIdForInitialization(
      'bad\u001bid' as never,
      'bad database id' as never,
    );

    expect(publication).toMatchObject({
      status: 'not-published',
      error: { code: 'PROFILE_INVALID' },
    });
    expect(await readFile(resolveProfilePath(directory), 'utf8')).toBe(before);
  });

  it('fails closed when exact final selection publication is uncertain', async () => {
    const profiles = await DatastoreProfileRegistry.open({
      configDirectory: directory,
    });
    const prior = {
      id: profileIdSchema.parse('prior'),
      datastore: 'file' as const,
      dataFile: '/protected/prior-database.kavrix',
      keyFile: '/protected/prior-owner.key',
    };
    const expected = {
      id: profileIdSchema.parse('guided'),
      datastore: 'file' as const,
      dataFile: '/protected/guided-database.kavrix',
      keyFile: '/protected/guided-owner.key',
      databaseId: databaseIdSchema.parse('db_guided'),
      defaultVaultId: vaultIdSchema.parse('vault_guided'),
    };
    await profiles.add(prior);
    await profiles.add(expected);
    await profiles.use(prior.id);
    armFault('post-rename');

    await expect(profiles.useExpected(expected)).rejects.toMatchObject({
      code: 'PROFILE_UNSAFE',
    });

    expect(await profiles.current()).toEqual(expected);
  });
});
