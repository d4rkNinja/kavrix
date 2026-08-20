import {
  lstat,
  readFile,
  realpath,
  rename,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const aclMocks = vi.hoisted(() => ({
  set: vi.fn<(path: string) => Promise<void>>(),
  verifyDirectory: vi.fn<(path: string) => Promise<void>>(),
  verifyFile: vi.fn<(path: string) => Promise<void>>(),
}));
const filesystemMocks = vi.hoisted(() => ({ mkdir: vi.fn() }));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return { ...actual, mkdir: filesystemMocks.mkdir };
});

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: aclMocks.set,
  verifyWindowsDirectoryAcl: aclMocks.verifyDirectory,
  verifyWindowsUserOnlyAcl: aclMocks.verifyFile,
}));

import { PortableKeyFileError } from '../src/errors.js';
import { ensureSecureDirectory } from '../src/index.js';
import {
  validateSecureFileDestination,
  validateSecureFileSource,
  writeSecureFile,
} from '../src/filesystem.js';

let directory = '';
let actualFilesystem: typeof import('node:fs/promises');
const nativePlatform = process.platform;
const platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform');

beforeEach(async () => {
  actualFilesystem =
    await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
  directory = await actualFilesystem.mkdtemp(join(tmpdir(), 'kavrix-filesystem-acl-'));
  Object.defineProperty(process, 'platform', {
    configurable: true,
    value: 'win32',
  });
  filesystemMocks.mkdir.mockImplementation(actualFilesystem.mkdir);
  aclMocks.set.mockResolvedValue(undefined);
  aclMocks.verifyDirectory.mockResolvedValue(undefined);
  aclMocks.verifyFile.mockResolvedValue(undefined);
});

afterEach(async () => {
  if (platformDescriptor !== undefined) {
    Object.defineProperty(process, 'platform', platformDescriptor);
  }
  filesystemMocks.mkdir.mockReset();
  vi.clearAllMocks();
  await actualFilesystem.rm(directory, { force: true, recursive: true });
});

describe('protected filesystem parent ACL checks', () => {
  it('uses the read-only directory verifier for destination preflight', async () => {
    const target = join(directory, 'destination.cvk');
    const canonicalDirectory = await realpath(directory);

    await expect(validateSecureFileDestination(target)).resolves.toBeUndefined();

    expect(aclMocks.verifyDirectory).toHaveBeenCalledWith(canonicalDirectory);
    expect(aclMocks.verifyFile).not.toHaveBeenCalledWith(canonicalDirectory);
    expect(aclMocks.set).not.toHaveBeenCalledWith(canonicalDirectory);
  });

  it('maps an unsafe existing-parent ACL failure to KEY_FILE_UNSAFE', async () => {
    aclMocks.verifyDirectory.mockRejectedValueOnce(
      new PortableKeyFileError('KEY_FILE_UNSAFE'),
    );

    await expect(
      validateSecureFileDestination(join(directory, 'unsafe.cvk')),
    ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    expect(aclMocks.set).not.toHaveBeenCalled();
    expect(aclMocks.verifyFile).not.toHaveBeenCalled();
  });

  it('keeps strict ACL set/verify for created files while checking the parent read-only', async () => {
    const target = join(directory, 'created.cvk');
    const canonicalDirectory = await realpath(directory);
    const canonicalTarget = join(canonicalDirectory, 'created.cvk');

    await expect(
      writeSecureFile(target, new Uint8Array([1, 2, 3]), 'create'),
    ).resolves.toBeUndefined();
    expect(aclMocks.verifyDirectory).toHaveBeenCalledWith(canonicalDirectory);
    expect(aclMocks.verifyFile).toHaveBeenCalledWith(canonicalTarget);
    expect(aclMocks.set).not.toHaveBeenCalledWith(canonicalDirectory);
    expect(
      aclMocks.set.mock.calls.some(([path]) => String(path).includes('.tmp')),
    ).toBe(true);
    aclMocks.verifyDirectory.mockClear();
    aclMocks.verifyFile.mockClear();
    aclMocks.set.mockClear();

    await expect(validateSecureFileSource(target)).resolves.toBeUndefined();

    expect(aclMocks.verifyDirectory).toHaveBeenCalledWith(canonicalDirectory);
    expect(aclMocks.verifyFile).toHaveBeenCalledWith(canonicalTarget);
    expect(aclMocks.set).not.toHaveBeenCalledWith(canonicalDirectory);
  });
});

describe('one-level secure directory provisioning', () => {
  function target(name = 'kavrix'): string {
    return join(directory, name);
  }

  it('creates one child and applies strict protection without changing its parent', async () => {
    const child = target();
    const canonicalParent = await realpath(directory);
    const canonicalChild = join(canonicalParent, 'kavrix');

    await expect(ensureSecureDirectory(child)).resolves.toBe(canonicalChild);

    expect((await lstat(child)).isDirectory()).toBe(true);
    expect(aclMocks.verifyDirectory).toHaveBeenCalledWith(canonicalParent);
    expect(aclMocks.set).toHaveBeenCalledWith(canonicalChild);
    expect(aclMocks.verifyFile).toHaveBeenCalledWith(canonicalChild);
    expect(aclMocks.set).not.toHaveBeenCalledWith(canonicalParent);
    expect(aclMocks.verifyFile).not.toHaveBeenCalledWith(canonicalParent);
  });

  it('accepts an existing strict directory without mutating it', async () => {
    const child = target();
    await actualFilesystem.mkdir(child, { mode: 0o700 });
    const canonicalChild = await actualFilesystem.realpath(child);

    await expect(ensureSecureDirectory(child)).resolves.toBe(canonicalChild);

    expect(aclMocks.set).not.toHaveBeenCalled();
    expect(aclMocks.verifyFile).toHaveBeenCalledWith(canonicalChild);
  });

  it('rejects existing files, symlink directories, and unsafe directories without mutation', async () => {
    const file = target('file');
    await writeFile(file, 'not a directory');
    await expect(ensureSecureDirectory(file)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });

    const linkedTarget = target('linked-target');
    const linked = target('linked');
    await actualFilesystem.mkdir(linkedTarget, { mode: 0o700 });
    await symlink(
      linkedTarget,
      linked,
      nativePlatform === 'win32' ? 'junction' : 'dir',
    );
    await expect(ensureSecureDirectory(linked)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });

    const unsafe = target('unsafe');
    await actualFilesystem.mkdir(unsafe, { mode: 0o700 });
    aclMocks.verifyFile.mockRejectedValueOnce(
      new PortableKeyFileError('KEY_FILE_UNSAFE'),
    );
    await expect(ensureSecureDirectory(unsafe)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    expect(aclMocks.set).not.toHaveBeenCalled();
  });

  it('fails before mkdir or ACL mutation when the existing parent is unsafe', async () => {
    const child = target();
    aclMocks.verifyDirectory.mockRejectedValueOnce(
      new PortableKeyFileError('KEY_FILE_UNSAFE'),
    );

    await expect(ensureSecureDirectory(child)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });

    await expect(lstat(child)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(filesystemMocks.mkdir).not.toHaveBeenCalled();
    expect(aclMocks.set).not.toHaveBeenCalled();
  });

  it('verifies a concurrent EEXIST winner instead of changing it', async () => {
    const child = target();
    filesystemMocks.mkdir.mockImplementationOnce(async () => {
      await actualFilesystem.mkdir(child, { mode: 0o700 });
      const error = new Error('already exists') as NodeJS.ErrnoException;
      error.code = 'EEXIST';
      throw error;
    });

    const result = await ensureSecureDirectory(child);
    expect(result).toBe(await actualFilesystem.realpath(child));
    expect(aclMocks.verifyFile).toHaveBeenCalledWith(
      await actualFilesystem.realpath(child),
    );
    expect(aclMocks.set).not.toHaveBeenCalled();
  });

  it('does not invoke the ACL setter after the child changes during pre-set validation', async () => {
    const child = target();
    const replacement = target('replacement');
    const canonicalChild = await realpath(directory).then((parent) =>
      join(parent, 'kavrix'),
    );
    aclMocks.verifyDirectory.mockImplementation(async (path) => {
      if (path !== canonicalChild) return;
      await actualFilesystem.mkdir(replacement, { mode: 0o700 });
      await actualFilesystem.rmdir(child);
      await actualFilesystem.rename(replacement, child);
    });

    await expect(ensureSecureDirectory(child)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });

    expect(aclMocks.set).not.toHaveBeenCalled();
    expect((await lstat(child)).isDirectory()).toBe(true);
  });

  it('fails closed and preserves a child replaced while the Windows setter runs', async () => {
    const child = target();
    const replacement = target('replacement');
    aclMocks.set.mockImplementationOnce(async (path) => {
      await actualFilesystem.mkdir(replacement, { mode: 0o700 });
      await actualFilesystem.rmdir(path);
      await rename(replacement, path);
    });

    await expect(ensureSecureDirectory(child)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });

    expect((await lstat(child)).isDirectory()).toBe(true);
  });

  it('removes only its empty created child after protection fails', async () => {
    const child = target();
    aclMocks.set.mockRejectedValueOnce(new Error('ACL failed'));

    await expect(ensureSecureDirectory(child)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });

    await expect(lstat(child)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('leaves a nonempty created child intact during failed-cleanup recovery', async () => {
    const child = target();
    aclMocks.set.mockImplementationOnce(async (path) => {
      await actualFilesystem.writeFile(join(path, 'concurrent-entry'), 'x');
      throw new Error('ACL failed');
    });

    await expect(ensureSecureDirectory(child)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });

    expect((await lstat(child)).isDirectory()).toBe(true);
    await expect(readFile(join(child, 'concurrent-entry'), 'utf8')).resolves.toBe('x');
  });

  if (nativePlatform !== 'win32') {
    it('keeps POSIX owner and mode checks coherent for new and existing directories', async () => {
      if (platformDescriptor !== undefined) {
        Object.defineProperty(process, 'platform', platformDescriptor);
      }
      const child = target();
      const canonical = await ensureSecureDirectory(child);
      const created = await lstat(canonical, { bigint: true });
      const getuid = process.getuid;
      if (getuid === undefined) throw new Error('missing POSIX uid');
      expect(created.uid).toBe(BigInt(getuid()));
      expect(created.mode & 0o777n).toBe(0o700n);

      await expect(ensureSecureDirectory(child)).resolves.toBe(canonical);
      await actualFilesystem.chmod(child, 0o755);
      await expect(ensureSecureDirectory(child)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    });
  }
});
