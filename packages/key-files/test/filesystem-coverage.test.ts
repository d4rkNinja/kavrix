import {
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockedAcl = vi.hoisted(() => ({
  directoryVerify: vi.fn(),
  set: vi.fn(),
  verify: vi.fn(),
}));

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: mockedAcl.set,
  verifyWindowsDirectoryAcl: mockedAcl.directoryVerify,
  verifyWindowsUserOnlyAcl: mockedAcl.verify,
}));

import { PortableKeyFileError } from '../src/errors.js';
import {
  MAX_PORTABLE_KEY_FILE_BYTES,
  MAX_SECURE_STREAM_CHUNK_BYTES,
  MAX_SECURE_STREAM_FILE_BYTES,
  cleanupOwnedSecureFilePublication,
  createOwnedSecureFile,
  deleteSecureFile,
  ensureSecureDirectory,
  readSecureFile,
  readSecureFileWhileExclusive,
  releaseOwnedSecureFilePublication,
  replaceSecureFileWhileExclusive,
  validateSecureFileDestination,
  validateSecureFileSource,
  withExclusiveSecureFile,
  writeSecureFile,
  writeSecureStreamFile,
} from '../src/filesystem.js';

let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-filesystem-'));
  mockedAcl.directoryVerify.mockReset();
  mockedAcl.set.mockReset();
  mockedAcl.verify.mockReset();
});

afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

function target(name = 'protected.cvkx'): string {
  return join(directory, name);
}

function values<T>(items: readonly T[]): AsyncIterable<T> {
  return {
    async *[Symbol.asyncIterator](): AsyncGenerator<T> {
      await Promise.resolve();
      yield* items;
    },
  };
}

async function writeRegularFile(
  path: string,
  contents: Uint8Array,
  mode = 0o600,
): Promise<void> {
  await writeFile(path, contents, { mode });
}

describe('filesystem adapter branch coverage', () => {
  it('rejects malformed paths and non-directory parents before touching files', async () => {
    const invalidValues: readonly unknown[] = [
      undefined,
      null,
      42,
      '',
      'bad\nname',
      'bad\u007fname',
    ];
    for (const value of invalidValues) {
      await expect(validateSecureFileDestination(value as never)).rejects.toMatchObject(
        { code: 'KEY_FILE_INVALID_PATH' },
      );
    }

    const parentFile = target('parent-file');
    await writeRegularFile(parentFile, new Uint8Array([1]));
    await expect(
      validateSecureFileDestination(join(parentFile, 'child.cvkx')),
    ).rejects.toMatchObject({ code: 'KEY_FILE_INVALID_PATH' });
    await expect(
      validateSecureFileDestination(join(directory, 'missing', 'child.cvkx')),
    ).rejects.toMatchObject({ code: 'KEY_FILE_NOT_FOUND' });
  });

  it('distinguishes an existing regular file, directory, and symlink destination', async () => {
    const existing = target('existing.cvkx');
    const existingDirectory = target('existing-directory');
    const linkPath = target('existing-link.cvkx');
    const linkTarget = target('link-target');
    await writeRegularFile(existing, new Uint8Array([1]));
    await mkdir(existingDirectory);
    await mkdir(linkTarget);
    await symlink(
      linkTarget,
      linkPath,
      process.platform === 'win32' ? 'junction' : 'dir',
    );

    await expect(validateSecureFileDestination(existing)).rejects.toMatchObject({
      code: 'KEY_FILE_ALREADY_EXISTS',
    });
    await expect(
      validateSecureFileDestination(existingDirectory),
    ).rejects.toMatchObject({ code: 'KEY_FILE_ALREADY_EXISTS' });
    await expect(validateSecureFileDestination(linkPath)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
  });

  it('creates a strict directory once and verifies the existing identity on reuse', async () => {
    const child = target('vault');
    await ensureSecureDirectory(child);
    const canonicalChild = await realpath(child);
    await expect(ensureSecureDirectory(child)).resolves.toBe(canonicalChild);

    const metadata = await lstat(child, { bigint: true });
    expect(metadata.isDirectory()).toBe(true);
    if (process.platform !== 'win32') {
      expect(metadata.mode & 0o777n).toBe(0o700n);
    }
  });

  it('fails closed when a requested secure directory is a file or link', async () => {
    const filePath = target('not-a-directory');
    const linkPath = target('directory-link');
    const linkTarget = target('directory-target');
    await writeRegularFile(filePath, new Uint8Array([1]));
    await mkdir(linkTarget);
    await symlink(
      linkTarget,
      linkPath,
      process.platform === 'win32' ? 'junction' : 'dir',
    );

    await expect(ensureSecureDirectory(filePath)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    await expect(ensureSecureDirectory(linkPath)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
  });

  it('validates regular-file size, link count, and POSIX ownership/mode', async () => {
    const empty = target('empty.cvkx');
    const oversized = target('oversized.cvkx');
    const safe = target('safe.cvkx');
    const hardLink = target('safe-hard-link.cvkx');
    await writeRegularFile(empty, new Uint8Array());
    await writeRegularFile(oversized, new Uint8Array(8));
    await writeRegularFile(safe, new Uint8Array([1, 2, 3]));
    await link(safe, hardLink);

    await expect(readSecureFile(empty)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    await expect(readSecureFile(oversized, 4)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    await expect(validateSecureFileSource(hardLink)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });

    if (process.platform !== 'win32') {
      const unsafeMode = target('unsafe-mode.cvkx');
      await writeRegularFile(unsafeMode, new Uint8Array([9]), 0o644);
      await expect(readSecureFile(unsafeMode)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    }
  });

  it('rejects missing, directory, and link sources without reading them', async () => {
    const sourceDirectory = target('source-directory');
    const sourceLink = target('source-link.cvkx');
    await mkdir(sourceDirectory);
    await symlink(
      sourceDirectory,
      sourceLink,
      process.platform === 'win32' ? 'junction' : 'dir',
    );

    await expect(
      validateSecureFileSource(target('missing.cvkx')),
    ).rejects.toMatchObject({
      code: 'KEY_FILE_NOT_FOUND',
    });
    await expect(validateSecureFileSource(sourceDirectory)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    await expect(validateSecureFileSource(sourceLink)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
  });

  it('rejects invalid secure-file limits and write inputs before creating staging files', async () => {
    const invalidLimits = [
      0,
      -1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      MAX_SECURE_STREAM_FILE_BYTES + 1,
    ];
    for (const maximumBytes of invalidLimits) {
      await expect(readSecureFile(target(), maximumBytes)).rejects.toMatchObject({
        code: 'KEY_FILE_OPERATION_FAILED',
      });
      await expect(
        validateSecureFileSource(target(), maximumBytes),
      ).rejects.toMatchObject({
        code: 'KEY_FILE_OPERATION_FAILED',
      });
    }
    await expect(
      writeSecureFile(target(), new Uint8Array([1]), 'invalid' as never),
    ).rejects.toMatchObject({
      code: 'KEY_FILE_OPERATION_FAILED',
    });
    await expect(
      writeSecureFile(target(), new Uint8Array(), 'create'),
    ).rejects.toMatchObject({
      code: 'KEY_FILE_OPERATION_FAILED',
    });
    await expect(
      writeSecureFile(
        target(),
        new Uint8Array(MAX_PORTABLE_KEY_FILE_BYTES + 1),
        'create',
      ),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    expect(await readdir(directory)).toEqual([]);
  });

  it('cleans staging files for empty, invalid, and oversized stream chunks', async () => {
    const invalidChunk = { value: 1 } as never;
    const oversizedChunk = new Uint8Array(MAX_SECURE_STREAM_CHUNK_BYTES + 1);
    const cases: readonly [string, AsyncIterable<Uint8Array>][] = [
      ['empty', values([])],
      ['invalid', values([invalidChunk])],
      ['zero', values([new Uint8Array()])],
      ['oversized', values([oversizedChunk])],
    ];
    for (const [name, source] of cases) {
      await expect(
        writeSecureStreamFile(
          target(`${name}.cvkx`),
          source,
          MAX_SECURE_STREAM_FILE_BYTES,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    }
    expect(await readdir(directory)).toEqual([]);
    expect(oversizedChunk[0]).toBe(0);
    expect(oversizedChunk[oversizedChunk.byteLength - 1]).toBe(0);
  });

  it('deletes only a validated regular file and maps unsafe or absent targets', async () => {
    const absent = target('absent.cvkx');
    const sourceDirectory = target('delete-directory');
    const linkPath = target('delete-link.cvkx');
    const filePath = target('delete.cvkx');
    await mkdir(sourceDirectory);
    await symlink(
      sourceDirectory,
      linkPath,
      process.platform === 'win32' ? 'junction' : 'dir',
    );
    await writeRegularFile(filePath, new Uint8Array([1, 2]));

    await expect(deleteSecureFile(absent)).rejects.toMatchObject({
      code: 'KEY_FILE_NOT_FOUND',
    });
    await expect(deleteSecureFile(sourceDirectory)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    await expect(deleteSecureFile(linkPath)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    await expect(deleteSecureFile(filePath)).resolves.toBeUndefined();
    await expect(lstat(filePath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('runs an exclusive callback, exposes only the lock capability, and replaces safely', async () => {
    const path = target('exclusive.cvkx');
    await writeSecureFile(path, new Uint8Array([1]), 'create');

    await expect(
      withExclusiveSecureFile(path, 32, async (lock) => {
        expect(Object.keys(lock).sort()).toEqual([
          'directoryPath',
          'maximumBytes',
          'targetPath',
        ]);
        await expect(readSecureFileWhileExclusive(lock)).resolves.toEqual(
          Buffer.from([1]),
        );
        await replaceSecureFileWhileExclusive(lock, new Uint8Array([2, 3]));
        return 'replaced';
      }),
    ).resolves.toBe('replaced');
    await expect(readSecureFile(path, 32)).resolves.toEqual(Buffer.from([2, 3]));

    await expect(
      withExclusiveSecureFile(path, 32, async () => {
        throw 'non-error callback failure';
      }),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    await expect(
      withExclusiveSecureFile(path, 32, async () => {
        throw new Error('callback failure');
      }),
    ).rejects.toThrow('callback failure');
    await expect(
      withExclusiveSecureFile(path, 32, async (lock) =>
        replaceSecureFileWhileExclusive(lock, new Uint8Array()),
      ),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
  });

  it('maps an already-held exclusive lock to a busy error', async () => {
    const path = target('busy.cvkx');
    await writeSecureFile(path, new Uint8Array([1]), 'create');
    const canonicalTarget = await realpath(path);
    const digest = createHash('sha256').update(canonicalTarget, 'utf8').digest('hex');
    const lockPath = target(`.kavrix-${digest}.lock`);
    await writeRegularFile(lockPath, new Uint8Array());

    await expect(
      withExclusiveSecureFile(path, 32, async () => undefined),
    ).rejects.toMatchObject({ code: 'KEY_FILE_BUSY' });
  });

  it('returns opaque ownership outcomes and consumes cleanup/release capabilities', async () => {
    const missing = await createOwnedSecureFile(
      target('missing-parent/key.cvkx'),
      new Uint8Array([1]),
      'database-key-file',
    );
    expect(missing.status).toBe('not-published');
    if (missing.status === 'not-published') {
      expect(missing.error).toBeInstanceOf(PortableKeyFileError);
      expect(missing.error.code).toBe('KEY_FILE_NOT_FOUND');
    }

    const path = target('owned.cvkx');
    const created = await createOwnedSecureFile(
      path,
      new Uint8Array([4, 5]),
      'database-key-file',
      32,
    );
    expect(created.status).toBe('published');
    if (created.status !== 'published') return;

    await expect(
      cleanupOwnedSecureFilePublication(
        created.publication,
        'database-recovery-kit-file',
      ),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    await expect(
      releaseOwnedSecureFilePublication(created.publication, 'database-key-file'),
    ).resolves.toBeUndefined();
    await expect(
      releaseOwnedSecureFilePublication(created.publication, 'database-key-file'),
    ).resolves.toBeUndefined();
    await expect(
      cleanupOwnedSecureFilePublication(created.publication, 'database-key-file'),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    await expect(readFile(path)).resolves.toEqual(Buffer.from([4, 5]));
  });

  it('neutralizes an owned publication exactly once and rejects reuse', async () => {
    const path = target('owned-cleanup.cvkx');
    const created = await createOwnedSecureFile(
      path,
      new Uint8Array([8, 9]),
      'database-recovery-kit-file',
      32,
    );
    expect(created.status).toBe('published');
    if (created.status !== 'published') return;

    await expect(
      cleanupOwnedSecureFilePublication(
        created.publication,
        'database-recovery-kit-file',
      ),
    ).resolves.toBeUndefined();
    await expect(readFile(path)).resolves.toEqual(Buffer.alloc(0));
    await expect(
      cleanupOwnedSecureFilePublication(
        created.publication,
        'database-recovery-kit-file',
      ),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
  });
});
