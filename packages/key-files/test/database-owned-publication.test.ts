import type * as FsPromises from 'node:fs/promises';

import {
  lstat,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  generateDatabaseRootKey,
  generatePortableKey,
  generateRecoveryKey,
  zeroize,
} from '@kavrix/crypto';
import {
  databaseIdSchema,
  databaseRevisionSchema,
  keySlotIdSchema,
  sha256DigestSchema,
} from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  cleanupOwnedDatabaseKeyFile,
  cleanupOwnedDatabaseRecoveryKitFile,
  cleanupOwnedDatabaseRevisionAnchor,
  createOwnedDatabaseKeyFile,
  createOwnedDatabaseRecoveryKitFile,
  createOwnedDatabaseRevisionAnchor,
  PortableKeyFileError,
  type DatabaseRevisionAnchor,
} from '../src/index.js';

type FaultPhase =
  'none' | 'post-write' | 'final-verify' | 'directory-sync' | 'cleanup-race';

const fault = vi.hoisted(() => ({
  phase: 'none' as FaultPhase,
  target: '',
  directory: '',
  fired: false,
  recoveryPath: '',
  cleanupUnlinkCalls: 0,
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  const injected = (): NodeJS.ErrnoException => {
    const error = new Error('injected filesystem failure') as NodeJS.ErrnoException;
    error.code = 'EIO';
    return error;
  };
  return {
    ...actual,
    link: actual.link,
    lstat: async (path: FsPromises.PathLike, options?: unknown) => {
      const result = await actual.lstat(path, options as never);
      if (
        fault.phase === 'final-verify' &&
        String(path) === fault.target &&
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
      const candidatePath = String(path);
      if (
        fault.phase === 'post-write' &&
        candidatePath === fault.target &&
        !fault.fired &&
        (typeof flags !== 'number' || flags !== 0)
      ) {
        return new Proxy(handle, {
          get(target, property) {
            if (property === 'writeFile') {
              return async (
                ...args: Parameters<FsPromises.FileHandle['writeFile']>
              ) => {
                await target.writeFile(...args);
                fault.fired = true;
                throw injected();
              };
            }
            const value: unknown = Reflect.get(target, property, target);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        });
      }
      if (
        fault.phase !== 'directory-sync' ||
        candidatePath !== fault.directory ||
        fault.fired
      ) {
        return handle;
      }
      return new Proxy(handle, {
        get(target, property) {
          if (property === 'sync') {
            return async () => {
              fault.fired = true;
              await target.sync();
              throw injected();
            };
          }
          const value: unknown = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
    rename: async (oldPath: FsPromises.PathLike, newPath: FsPromises.PathLike) => {
      if (
        fault.phase === 'cleanup-race' &&
        String(oldPath) === fault.target &&
        String(newPath).endsWith('/owned') &&
        !fault.fired
      ) {
        fault.fired = true;
        fault.recoveryPath = String(newPath);
        await actual.unlink(oldPath);
        await actual.writeFile(oldPath, 'foreign-during-cleanup', { mode: 0o600 });
      }
      return actual.rename(oldPath, newPath);
    },
    unlink: async (path: FsPromises.PathLike) => {
      if (fault.phase === 'cleanup-race') fault.cleanupUnlinkCalls += 1;
      return actual.unlink(path);
    },
  };
});

let directory = '';
const databaseId = databaseIdSchema.parse('db_publication_test');
const keyBinding = {
  databaseId,
  keySlotId: keySlotIdSchema.parse('owner-slot'),
};
const recoveryBinding = {
  databaseId,
  recoverySlotId: keySlotIdSchema.parse('recovery-slot'),
};
const anchor: DatabaseRevisionAnchor = {
  databaseId,
  databaseRevision: databaseRevisionSchema.parse(0),
  catalogMetadataDigest: sha256DigestSchema.parse(
    Buffer.alloc(32, 1).toString('base64url'),
  ),
  vaultHeads: {},
};

beforeEach(async () => {
  directory = await realpath(
    await mkdtemp(join(tmpdir(), 'kavrix-owned-publication-')),
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
  fault.fired = false;
  fault.recoveryPath = '';
  fault.cleanupUnlinkCalls = 0;
}

function armFault(phase: Exclude<FaultPhase, 'none'>, target: string): void {
  fault.phase = phase;
  fault.target = target;
  fault.directory = directory;
  fault.fired = false;
}

async function expectNoLiveInternalArtifacts(): Promise<number> {
  const internal = (await readdir(directory, { withFileTypes: true })).filter((entry) =>
    entry.name.startsWith('.kavrix-'),
  );
  for (const entry of internal) {
    expect(entry.isDirectory()).toBe(true);
    expect(entry.name.startsWith('.kavrix-quarantine-')).toBe(true);
    const quarantineDirectory = join(directory, entry.name);
    expect(await readdir(quarantineDirectory)).toEqual(['owned']);
    const neutralizedPath = join(quarantineDirectory, 'owned');
    await expect(readFile(neutralizedPath)).resolves.toHaveLength(0);
    if (process.platform !== 'win32') {
      const getuid = process.getuid;
      if (getuid === undefined) throw new Error('Expected a Unix user identity');
      const directoryMetadata = await lstat(quarantineDirectory, { bigint: true });
      const fileMetadata = await lstat(neutralizedPath, { bigint: true });
      expect(directoryMetadata.uid).toBe(BigInt(getuid()));
      expect(directoryMetadata.mode & 0o777n).toBe(0o700n);
      expect(fileMetadata.uid).toBe(BigInt(getuid()));
      expect(fileMetadata.mode & 0o777n).toBe(0o600n);
      expect(fileMetadata.nlink).toBe(1n);
    }
  }
  return internal.length;
}

describe('owned database-file publication', () => {
  it.each(['post-write', 'final-verify', 'directory-sync'] as const)(
    'returns inspectable uncertainty after %s failure for every database file domain',
    async (phase) => {
      const portableKey = generatePortableKey();
      const recoveryKey = generateRecoveryKey();
      const drk = generateDatabaseRootKey();
      const passphrase = new TextEncoder().encode('owned-publication-passphrase');
      const domains = [
        {
          name: 'key',
          create: (file: string) =>
            createOwnedDatabaseKeyFile(file, portableKey, keyBinding, {
              protection: { kind: 'passphrase', passphrase },
            }),
          cleanup: (publication: unknown) =>
            cleanupOwnedDatabaseKeyFile(publication as never),
        },
        {
          name: 'recovery',
          create: (file: string) =>
            createOwnedDatabaseRecoveryKitFile(file, recoveryKey, recoveryBinding, {
              passphrase,
            }),
          cleanup: (publication: unknown) =>
            cleanupOwnedDatabaseRecoveryKitFile(publication as never),
        },
        {
          name: 'anchor',
          create: (file: string) =>
            createOwnedDatabaseRevisionAnchor(file, drk, anchor),
          cleanup: (publication: unknown) =>
            cleanupOwnedDatabaseRevisionAnchor(publication as never),
        },
      ];
      try {
        for (const domain of domains) {
          const file = join(directory, `${phase}-${domain.name}`);
          armFault(phase, file);
          const created = await domain.create(file);
          resetFault();
          expect(created.status).toBe('publication-uncertain');
          if (created.status !== 'publication-uncertain') {
            throw new Error('Expected an uncertain owned publication');
          }
          expect(created.error).toMatchObject({
            code: 'KEY_FILE_OPERATION_FAILED',
            message: 'The portable key file operation failed.',
          });
          expect(Object.hasOwn(created.error, 'cause')).toBe(false);
          await expect(readFile(file)).resolves.not.toHaveLength(0);
          expect(
            (await readdir(directory)).filter((name) => name.endsWith('.tmp')),
          ).toEqual([]);
          await domain.cleanup(created.publication);
          await expect(readFile(file)).rejects.toMatchObject({ code: 'ENOENT' });
          await expectNoLiveInternalArtifacts();
        }
      } finally {
        zeroize(portableKey);
        zeroize(recoveryKey);
        zeroize(drk);
        zeroize(passphrase);
      }
    },
  );

  it('reports definitely-not-published without an ownership token', async () => {
    const file = join(directory, 'existing-key');
    const key = generatePortableKey();
    const passphrase = new TextEncoder().encode('not-published-passphrase');
    try {
      await writeFile(file, 'foreign', { mode: 0o600 });
      const result = await createOwnedDatabaseKeyFile(file, key, keyBinding, {
        protection: { kind: 'passphrase', passphrase },
      });
      expect(result).toMatchObject({
        status: 'not-published',
        error: { code: 'KEY_FILE_ALREADY_EXISTS' },
      });
      expect(Object.hasOwn(result, 'publication')).toBe(false);
      await expect(readFile(file, 'utf8')).resolves.toBe('foreign');
      await expectNoLiveInternalArtifacts();
    } finally {
      zeroize(key);
      zeroize(passphrase);
    }
  });

  it('refuses foreign replacement and hardlink states without deleting any foreign file', async () => {
    const file = join(directory, 'replace-refusal');
    const key = generatePortableKey();
    const passphrase = new TextEncoder().encode('replacement-passphrase');
    try {
      const created = await createOwnedDatabaseKeyFile(file, key, keyBinding, {
        protection: { kind: 'passphrase', passphrase },
      });
      if (created.status !== 'published') throw new Error('Expected publication');
      await rm(file);
      await writeFile(file, 'foreign-canary', { mode: 0o600 });
      await expect(
        cleanupOwnedDatabaseKeyFile(created.publication),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(readFile(file, 'utf8')).resolves.toBe('foreign-canary');

      const linkedFile = join(directory, 'hardlink-refusal');
      const linked = await createOwnedDatabaseKeyFile(linkedFile, key, keyBinding, {
        protection: { kind: 'passphrase', passphrase },
      });
      if (linked.status !== 'published') throw new Error('Expected publication');
      const extraLink = join(directory, 'foreign-hardlink');
      const fs = await import('node:fs/promises');
      await fs.link(linkedFile, extraLink);
      await expect(
        cleanupOwnedDatabaseKeyFile(linked.publication),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(readFile(linkedFile)).resolves.not.toHaveLength(0);
      await expect(readFile(extraLink)).resolves.not.toHaveLength(0);
      await expectNoLiveInternalArtifacts();
    } finally {
      zeroize(key);
      zeroize(passphrase);
    }
  });

  it('restores a foreign file raced in after final validation instead of deleting it', async () => {
    const file = join(directory, 'cleanup-race');
    const key = generatePortableKey();
    const passphrase = new TextEncoder().encode('cleanup-race-passphrase');
    try {
      const created = await createOwnedDatabaseKeyFile(file, key, keyBinding, {
        protection: { kind: 'passphrase', passphrase },
      });
      if (created.status !== 'published') throw new Error('Expected publication');
      armFault('cleanup-race', file);
      let cleanupError: unknown;
      try {
        await cleanupOwnedDatabaseKeyFile(created.publication);
      } catch (error) {
        cleanupError = error;
      }
      const recoveryPath = fault.recoveryPath;
      expect(cleanupError).toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      expect(Object.hasOwn(cleanupError as object, 'cause')).toBe(false);
      expect(fault.cleanupUnlinkCalls).toBe(0);
      const publicForeign = await lstat(file, { bigint: true });
      const recoveryForeign = await lstat(recoveryPath, { bigint: true });
      expect({ dev: publicForeign.dev, ino: publicForeign.ino }).toEqual({
        dev: recoveryForeign.dev,
        ino: recoveryForeign.ino,
      });
      await expect(readFile(recoveryPath, 'utf8')).resolves.toBe(
        'foreign-during-cleanup',
      );
      await expect(
        cleanupOwnedDatabaseKeyFile(created.publication),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      expect(fault.cleanupUnlinkCalls).toBe(0);
      resetFault();
      await expect(readFile(file, 'utf8')).resolves.toBe('foreign-during-cleanup');
      await expect(readFile(recoveryPath, 'utf8')).resolves.toBe(
        'foreign-during-cleanup',
      );
    } finally {
      zeroize(key);
      zeroize(passphrase);
    }
  });

  it('rejects every pairwise cross-domain ownership capability substitution', async () => {
    const key = generatePortableKey();
    const recoveryKey = generateRecoveryKey();
    const drk = generateDatabaseRootKey();
    const passphrase = new TextEncoder().encode('cross-domain-passphrase');
    try {
      const keyResult = await createOwnedDatabaseKeyFile(
        join(directory, 'domain-key'),
        key,
        keyBinding,
        { protection: { kind: 'passphrase', passphrase } },
      );
      const recoveryResult = await createOwnedDatabaseRecoveryKitFile(
        join(directory, 'domain-recovery'),
        recoveryKey,
        recoveryBinding,
        { passphrase },
      );
      const anchorResult = await createOwnedDatabaseRevisionAnchor(
        join(directory, 'domain-anchor'),
        drk,
        anchor,
      );
      if (
        keyResult.status !== 'published' ||
        recoveryResult.status !== 'published' ||
        anchorResult.status !== 'published'
      ) {
        throw new Error('Expected all domain publications');
      }

      await expect(
        cleanupOwnedDatabaseRecoveryKitFile(keyResult.publication as never),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
      await expect(
        cleanupOwnedDatabaseRevisionAnchor(keyResult.publication as never),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
      await expect(
        cleanupOwnedDatabaseKeyFile(recoveryResult.publication as never),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
      await expect(
        cleanupOwnedDatabaseRevisionAnchor(recoveryResult.publication as never),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
      await expect(
        cleanupOwnedDatabaseKeyFile(anchorResult.publication as never),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
      await expect(
        cleanupOwnedDatabaseRecoveryKitFile(anchorResult.publication as never),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });

      await cleanupOwnedDatabaseKeyFile(keyResult.publication);
      await cleanupOwnedDatabaseRecoveryKitFile(recoveryResult.publication);
      await cleanupOwnedDatabaseRevisionAnchor(anchorResult.publication);
      expect(await expectNoLiveInternalArtifacts()).toBe(3);
    } finally {
      zeroize(key);
      zeroize(recoveryKey);
      zeroize(drk);
      zeroize(passphrase);
    }
  });

  it('returns a redacted cleanup error suitable for aggregation and permits an absent-file retry', async () => {
    const file = join(directory, 'cleanup-sync');
    const key = generatePortableKey();
    const passphrase = new TextEncoder().encode('cleanup-passphrase');
    try {
      const created = await createOwnedDatabaseKeyFile(file, key, keyBinding, {
        protection: { kind: 'passphrase', passphrase },
      });
      if (created.status !== 'published') throw new Error('Expected publication');
      armFault('directory-sync', file);
      let cleanupError: unknown;
      try {
        await cleanupOwnedDatabaseKeyFile(created.publication);
      } catch (error) {
        cleanupError = error;
      }
      resetFault();
      expect(cleanupError).toBeInstanceOf(PortableKeyFileError);
      expect(cleanupError).toMatchObject({
        code: 'KEY_FILE_OPERATION_FAILED',
        message: 'The portable key file operation failed.',
      });
      expect(Object.hasOwn(cleanupError as object, 'cause')).toBe(false);
      const aggregate = new AggregateError([
        new PortableKeyFileError('KEY_FILE_OPERATION_FAILED'),
        cleanupError,
      ]);
      expect(
        aggregate.errors.every((error) => error instanceof PortableKeyFileError),
      ).toBe(true);
      expect(String(aggregate.errors)).not.toContain(file);
      await expect(readFile(file)).rejects.toMatchObject({ code: 'ENOENT' });
      await cleanupOwnedDatabaseKeyFile(created.publication);
      await expect(
        cleanupOwnedDatabaseKeyFile(created.publication),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
      await expectNoLiveInternalArtifacts();
    } finally {
      zeroize(key);
      zeroize(passphrase);
    }
  });
});
