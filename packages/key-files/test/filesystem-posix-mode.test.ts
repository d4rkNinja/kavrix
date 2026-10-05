import { constants, type BigIntStats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const ports = vi.hoisted(() => ({
  lstat: vi.fn<(path: string) => Promise<BigIntStats>>(),
  stat: vi.fn<() => Promise<BigIntStats>>(),
  open: vi.fn<() => Promise<FileHandle>>(),
  realpath: vi.fn<(path: string) => Promise<string>>(),
  mkdir: vi.fn(),
  link: vi.fn(),
  rename: vi.fn(),
  rmdir: vi.fn(),
  unlink: vi.fn(),
}));
vi.mock('node:fs/promises', () => ports);

import {
  readSecureFile,
  validateSecureFileDestination,
  validateSecureFileSource,
} from '../src/filesystem.js';

const platform = Object.getOwnPropertyDescriptor(process, 'platform');
const uid = Object.getOwnPropertyDescriptor(process, 'getuid');
const path = '/permission-model/portable.key';
const payload = Buffer.from([11, 22, 33]);
let file: BigIntStats;
let directory: BigIntStats;
const openedStat = vi.fn<() => Promise<BigIntStats>>();
const close = vi.fn<() => Promise<void>>();
const read =
  vi.fn<
    (
      buffer: Buffer,
      offset: number,
      length: number,
      position: number,
    ) => Promise<{ bytesRead: number; buffer: Buffer }>
  >();

function metadata(
  kind: 'file' | 'directory',
  patch: Partial<BigIntStats> = {},
): BigIntStats {
  return {
    dev: 1n,
    ino: kind === 'file' ? 20n : 10n,
    uid: 1000n,
    mode: kind === 'file' ? 0o600n : 0o700n,
    nlink: 1n,
    size: kind === 'file' ? BigInt(payload.length) : 0n,
    isFile: () => kind === 'file',
    isDirectory: () => kind === 'directory',
    isSymbolicLink: () => false,
    ...patch,
  } as BigIntStats;
}

beforeEach(() => {
  Object.defineProperty(process, 'platform', { configurable: true, value: 'linux' });
  Object.defineProperty(process, 'getuid', { configurable: true, value: () => 1000 });
  for (const port of Object.values(ports)) port.mockReset();
  openedStat.mockReset();
  close.mockReset();
  read.mockReset();
  file = metadata('file');
  directory = metadata('directory');
  ports.realpath.mockImplementation(async (value) => value);
  ports.stat.mockImplementation(async () => directory);
  ports.lstat.mockImplementation(async (value) =>
    value.endsWith('portable.key') ? file : directory,
  );
  openedStat.mockImplementation(async () => file);
  close.mockResolvedValue(undefined);
  read.mockImplementation(async (buffer, offset, length, position) => {
    const bytesRead = Math.min(length, Math.max(0, payload.length - position));
    payload.copy(buffer, offset, position, position + bytesRead);
    return { bytesRead, buffer };
  });
  ports.open.mockResolvedValue({
    stat: openedStat,
    close,
    read,
  } as unknown as FileHandle);
});

afterEach(() => {
  if (platform !== undefined) Object.defineProperty(process, 'platform', platform);
  if (uid === undefined) delete process.getuid;
  else Object.defineProperty(process, 'getuid', uid);
});

describe('portable POSIX permission decisions', () => {
  it('validates an owner-only file without reading or mutating its contents', async () => {
    await expect(validateSecureFileSource(path)).resolves.toBeUndefined();
    expect(read).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();
    expect(ports.open).toHaveBeenCalledWith(
      expect.any(String),
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    for (const mutation of [
      ports.mkdir,
      ports.link,
      ports.rename,
      ports.rmdir,
      ports.unlink,
    ]) {
      expect(mutation).not.toHaveBeenCalled();
    }
  });

  it.each([0o640n, 0o604n, 0o620n, 0o602n, 0o700n, 0o4600n, 0o2600n, 0o1600n])(
    'rejects shared, executable, or special file mode %s before reading',
    async (mode) => {
      file = metadata('file', { mode });
      await expect(readSecureFile(path)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      expect(read).not.toHaveBeenCalled();
      expect(close).toHaveBeenCalledOnce();
    },
  );

  it('rejects a foreign file owner even in owner-only mode', async () => {
    file = metadata('file', { uid: 1001n });
    await expect(readSecureFile(path)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    expect(read).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();
  });

  it('fails closed when the host cannot identify the current owner', async () => {
    Object.defineProperty(process, 'getuid', { configurable: true, value: undefined });
    await expect(validateSecureFileSource(path)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    expect(ports.open).not.toHaveBeenCalled();
    await expect(readSecureFile(path)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    expect(read).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();
  });

  it.each([0o775n, 0o777n, 0o733n, 0o1777n])(
    'rejects a writable parent mode %s before opening the key',
    async (mode) => {
      directory = metadata('directory', { mode });
      await expect(validateSecureFileSource(path)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      expect(ports.open).not.toHaveBeenCalled();
      expect(read).not.toHaveBeenCalled();
    },
  );

  it('rejects a foreign parent owner without creating the destination', async () => {
    directory = metadata('directory', { uid: 1001n });
    await expect(validateSecureFileDestination(path)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    expect(ports.open).not.toHaveBeenCalled();
    expect(ports.mkdir).not.toHaveBeenCalled();
  });

  it('permits an owned, non-writable shared parent and reads the protected file', async () => {
    directory = metadata('directory', { mode: 0o755n });
    await expect(validateSecureFileSource(path)).resolves.toBeUndefined();
    await expect(readSecureFile(path)).resolves.toEqual(payload);
    expect(close).toHaveBeenCalledTimes(2);
  });

  it('rejects an inode swap between pathname inspection and opening', async () => {
    openedStat.mockResolvedValue(metadata('file', { ino: 21n }));
    await expect(readSecureFile(path)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    expect(read).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();
  });

  it('rejects a target redirected after its descriptor is opened', async () => {
    let checks = 0;
    ports.lstat.mockImplementation(async (value) => {
      if (!value.endsWith('portable.key')) return directory;
      checks += 1;
      return checks === 1 ? file : metadata('file', { ino: 21n });
    });
    await expect(validateSecureFileSource(path)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    expect(read).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();
  });

  it('rejects growth beyond the bound and zeroizes the scratch buffer', async () => {
    file = metadata('file', { size: 1n });
    await expect(readSecureFile(path, 1)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    const scratch = read.mock.calls[0]?.[0];
    expect(scratch).toBeDefined();
    expect(scratch?.every((byte) => byte === 0)).toBe(true);
    expect(close).toHaveBeenCalledOnce();
  });

  it('rejects truncation after inspection without returning any bytes', async () => {
    read.mockImplementation(async (buffer) => ({ bytesRead: 0, buffer }));
    await expect(readSecureFile(path)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    expect(close).toHaveBeenCalledOnce();
  });

  it('rejects a changed size after reading and closes the retained descriptor', async () => {
    openedStat
      .mockResolvedValueOnce(file)
      .mockResolvedValueOnce(metadata('file', { size: 4n }));
    await expect(readSecureFile(path)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
    expect(close).toHaveBeenCalledOnce();
  });

  it('reports failed descriptor cleanup rather than ignoring it', async () => {
    file = metadata('file', { uid: 1001n });
    close.mockRejectedValueOnce(new Error('descriptor close failed'));
    await expect(readSecureFile(path)).rejects.toMatchObject({
      code: 'KEY_FILE_OPERATION_FAILED',
    });
    expect(read).not.toHaveBeenCalled();
  });
});
