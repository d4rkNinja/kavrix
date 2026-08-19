import type * as FsPromises from 'node:fs/promises';

import { constants } from 'node:fs';
import { lstat, readFile, readdir, realpath, rm } from 'node:fs/promises';
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
import {
  createSecureTestDirectory as mkdtemp,
  writeSecureTestFile as writeFile,
} from './secure-temporary-directory.js';

type FaultPhase =
  | 'none'
  | 'post-write'
  | 'final-verify'
  | 'directory-sync'
  | 'cleanup-before-truncate'
  | 'cleanup-during-truncate'
  | 'cleanup-sync-substitution'
  | 'cleanup-post-inspection'
  | 'cleanup-sync-failure';

const fault = vi.hoisted(() => ({
  phase: 'none' as FaultPhase,
  target: '',
  directory: '',
  fired: false,
  neutralized: false,
  ownedRecoveryPath: '',
  foreignDev: 0n,
  foreignIno: 0n,
  cleanupPathOperations: 0,
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  const injected = (): NodeJS.ErrnoException => {
    const error = new Error('injected filesystem failure') as NodeJS.ErrnoException;
    error.code = 'EIO';
    return error;
  };
  const isCleanupFault = (): boolean => fault.phase.startsWith('cleanup-');
  const substitutePublicPath = async (path: string): Promise<void> => {
    if (fault.fired) return;
    fault.fired = true;
    fault.ownedRecoveryPath = `${path}.owned-displaced`;
    await actual.rename(path, fault.ownedRecoveryPath);
    await actual.writeFile(path, `foreign-${fault.phase}`, { mode: 0o600 });
    const foreign = await actual.lstat(path, { bigint: true });
    fault.foreignDev = foreign.dev;
    fault.foreignIno = foreign.ino;
  };
  return {
    ...actual,
    link: actual.link,
    lstat: async (path: FsPromises.PathLike, options?: unknown) => {
      const result = await actual.lstat(path, options as never);
      if (
        fault.phase === 'cleanup-post-inspection' &&
        String(path) === fault.target &&
        fault.neutralized &&
        !fault.fired
      ) {
        await substitutePublicPath(String(path));
      }
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
      const isCreateOpen =
        typeof flags === 'number'
          ? (flags & constants.O_CREAT) !== 0
          : flags.includes('w') || flags.includes('a');
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
      if (isCleanupFault() && candidatePath === fault.target && !isCreateOpen) {
        return new Proxy(handle, {
          get(target, property) {
            if (property === 'truncate') {
              return async (length?: number) => {
                if (fault.phase === 'cleanup-before-truncate') {
                  await substitutePublicPath(candidatePath);
                }
                await target.truncate(length);
                fault.neutralized = true;
                if (fault.phase === 'cleanup-during-truncate') {
                  await substitutePublicPath(candidatePath);
                }
              };
            }
            if (property === 'sync') {
              return async () => {
                if (fault.phase === 'cleanup-sync-failure' && !fault.fired) {
                  fault.fired = true;
                  throw injected();
                }
                if (fault.phase === 'cleanup-sync-substitution') {
                  await substitutePublicPath(candidatePath);
                }
                await target.sync();
              };
            }
            const value: unknown = Reflect.get(target, property, target);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        });
      }
      if (isCreateOpen) {
        return new Proxy(handle, {
          get(target, property) {
            if (property === 'truncate') {
              return async (length?: number) => {
                if (
                  candidatePath === fault.target &&
                  fault.phase === 'cleanup-before-truncate'
                ) {
                  await substitutePublicPath(candidatePath);
                }
                await target.truncate(length);
                if (candidatePath === fault.target && isCleanupFault()) {
                  fault.neutralized = true;
                }
                if (
                  candidatePath === fault.target &&
                  fault.phase === 'cleanup-during-truncate'
                ) {
                  await substitutePublicPath(candidatePath);
                }
              };
            }
            if (property === 'sync') {
              return async () => {
                if (
                  candidatePath === fault.target &&
                  fault.phase === 'cleanup-sync-failure' &&
                  !fault.fired
                ) {
                  fault.fired = true;
                  throw injected();
                }
                if (
                  candidatePath === fault.target &&
                  fault.phase === 'cleanup-sync-substitution'
                ) {
                  await substitutePublicPath(candidatePath);
                }
                await target.sync();
              };
            }
            if (property === 'stat') {
              return async (...args: Parameters<FsPromises.FileHandle['stat']>) => {
                const result = await target.stat(...args);
                if (
                  candidatePath === fault.target &&
                  fault.phase === 'cleanup-post-inspection' &&
                  fault.neutralized &&
                  !fault.fired
                ) {
                  await substitutePublicPath(candidatePath);
                }
                return result;
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
              throw injected();
            };
          }
          const value: unknown = Reflect.get(target, property, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
    rename: async (oldPath: FsPromises.PathLike, newPath: FsPromises.PathLike) => {
      if (isCleanupFault()) fault.cleanupPathOperations += 1;
      return actual.rename(oldPath, newPath);
    },
    unlink: async (path: FsPromises.PathLike) => {
      if (isCleanupFault()) fault.cleanupPathOperations += 1;
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
  fault.neutralized = false;
  fault.ownedRecoveryPath = '';
  fault.foreignDev = 0n;
  fault.foreignIno = 0n;
  fault.cleanupPathOperations = 0;
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

async function expectProtectedZeroTombstone(path: string): Promise<void> {
  await expect(readFile(path)).resolves.toHaveLength(0);
  const metadata = await lstat(path, { bigint: true });
  expect(metadata.isFile()).toBe(true);
  expect(metadata.size).toBe(0n);
  expect(metadata.nlink).toBe(1n);
  if (process.platform !== 'win32') {
    const getuid = process.getuid;
    if (getuid === undefined) throw new Error('Expected a Unix user identity');
    expect(metadata.uid).toBe(BigInt(getuid()));
    expect(metadata.mode & 0o777n).toBe(0o600n);
  }
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
          await expectProtectedZeroTombstone(file);
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

  it.each([
    'cleanup-before-truncate',
    'cleanup-during-truncate',
    'cleanup-sync-substitution',
    'cleanup-post-inspection',
  ] as const)(
    'neutralizes only the owned descriptor when substitution occurs at %s',
    async (phase) => {
      const file = join(directory, phase);
      const key = generatePortableKey();
      const passphrase = new TextEncoder().encode('cleanup-race-passphrase');
      try {
        const created = await createOwnedDatabaseKeyFile(file, key, keyBinding, {
          protection: { kind: 'passphrase', passphrase },
        });
        if (created.status !== 'published') throw new Error('Expected publication');
        armFault(phase, file);
        await cleanupOwnedDatabaseKeyFile(created.publication);
        const ownedRecoveryPath = fault.ownedRecoveryPath;
        expect(fault.cleanupPathOperations).toBe(0);
        await expect(readFile(file, 'utf8')).resolves.toBe(`foreign-${phase}`);
        const foreignAfter = await lstat(file, { bigint: true });
        expect({ dev: foreignAfter.dev, ino: foreignAfter.ino }).toEqual({
          dev: fault.foreignDev,
          ino: fault.foreignIno,
        });
        await expect(readFile(ownedRecoveryPath)).resolves.toHaveLength(0);
        const reuse = cleanupOwnedDatabaseKeyFile(created.publication);
        await expect(reuse).rejects.toMatchObject({
          code: 'KEY_FILE_OPERATION_FAILED',
          message: 'The portable key file operation failed.',
        });
        await expect(reuse).rejects.not.toHaveProperty('cause');
        expect(fault.cleanupPathOperations).toBe(0);
        resetFault();
        await expect(readFile(file, 'utf8')).resolves.toBe(`foreign-${phase}`);
        await expect(readFile(ownedRecoveryPath)).resolves.toHaveLength(0);
        await expectNoInternalArtifacts();
      } finally {
        zeroize(key);
        zeroize(passphrase);
      }
    },
  );

  it('rejects every pairwise cross-domain ownership capability substitution', async () => {
    const key = generatePortableKey();
    const recoveryKey = generateRecoveryKey();
    const drk = generateDatabaseRootKey();
    const passphrase = new TextEncoder().encode('cross-domain-passphrase');
    try {
      const keyFile = join(directory, 'domain-key');
      const recoveryFile = join(directory, 'domain-recovery');
      const anchorFile = join(directory, 'domain-anchor');
      const keyResult = await createOwnedDatabaseKeyFile(keyFile, key, keyBinding, {
        protection: { kind: 'passphrase', passphrase },
      });
      const recoveryResult = await createOwnedDatabaseRecoveryKitFile(
        recoveryFile,
        recoveryKey,
        recoveryBinding,
        { passphrase },
      );
      const anchorResult = await createOwnedDatabaseRevisionAnchor(
        anchorFile,
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
      await expectProtectedZeroTombstone(keyFile);
      await expectProtectedZeroTombstone(recoveryFile);
      await expectProtectedZeroTombstone(anchorFile);
      await expectNoInternalArtifacts();
    } finally {
      zeroize(key);
      zeroize(recoveryKey);
      zeroize(drk);
      zeroize(passphrase);
    }
  });

  it('returns a redacted sync error and permits a zero-tombstone retry', async () => {
    const file = join(directory, 'cleanup-sync');
    const key = generatePortableKey();
    const passphrase = new TextEncoder().encode('cleanup-passphrase');
    try {
      const created = await createOwnedDatabaseKeyFile(file, key, keyBinding, {
        protection: { kind: 'passphrase', passphrase },
      });
      if (created.status !== 'published') throw new Error('Expected publication');
      armFault('cleanup-sync-failure', file);
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
      await expectProtectedZeroTombstone(file);
      await cleanupOwnedDatabaseKeyFile(created.publication);
      await expect(
        cleanupOwnedDatabaseKeyFile(created.publication),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
      await expectProtectedZeroTombstone(file);
      await expectNoInternalArtifacts();
    } finally {
      zeroize(key);
      zeroize(passphrase);
    }
  });
});
