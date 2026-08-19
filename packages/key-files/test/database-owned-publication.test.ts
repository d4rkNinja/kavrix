import type * as FsPromises from 'node:fs/promises';

import { mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
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
  'none' | 'post-link' | 'final-verify' | 'directory-sync' | 'cleanup-race';

const fault = vi.hoisted(() => ({
  phase: 'none' as FaultPhase,
  target: '',
  directory: '',
  fired: false,
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
    link: async (existingPath: FsPromises.PathLike, newPath: FsPromises.PathLike) => {
      if (
        fault.phase === 'post-link' &&
        String(newPath) === fault.target &&
        !fault.fired
      ) {
        fault.fired = true;
        await actual.link(existingPath, newPath);
        throw injected();
      }
      return actual.link(existingPath, newPath);
    },
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
      if (
        fault.phase !== 'directory-sync' ||
        String(path) !== fault.directory ||
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
        !fault.fired
      ) {
        fault.fired = true;
        await actual.unlink(oldPath);
        await actual.writeFile(oldPath, 'foreign-during-cleanup', { mode: 0o600 });
      }
      return actual.rename(oldPath, newPath);
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
}

function armFault(phase: Exclude<FaultPhase, 'none'>, target: string): void {
  fault.phase = phase;
  fault.target = target;
  fault.directory = directory;
  fault.fired = false;
}

async function expectNoInternalArtifacts(): Promise<void> {
  expect(
    (await readdir(directory)).filter((name) => name.startsWith('.kavrix-')),
  ).toEqual([]);
}

describe('owned database-file publication', () => {
  it.each(['post-link', 'final-verify', 'directory-sync'] as const)(
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
          await domain.cleanup(created.publication);
          await expect(readFile(file)).rejects.toMatchObject({ code: 'ENOENT' });
          await expectNoInternalArtifacts();
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
      await expectNoInternalArtifacts();
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
      await expectNoInternalArtifacts();
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
      await expect(
        cleanupOwnedDatabaseKeyFile(created.publication),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      resetFault();
      await expect(readFile(file, 'utf8')).resolves.toBe('foreign-during-cleanup');
      await expectNoInternalArtifacts();
    } finally {
      zeroize(key);
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
      await expectNoInternalArtifacts();
    } finally {
      zeroize(key);
      zeroize(passphrase);
    }
  });
});
