import { link, mkdir, mkdtemp, readFile, readdir, rm, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockedAcl = vi.hoisted(() => ({
  set: vi.fn(),
  verify: vi.fn(),
}));

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: mockedAcl.set,
  verifyWindowsUserOnlyAcl: mockedAcl.verify,
}));

import {
  readSecureFile,
  validateSecureFileDestination,
  validateSecureFileSource,
  writeSecureStreamFile,
} from '../src/filesystem.js';

let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-secure-stream-'));
  mockedAcl.set.mockReset();
  mockedAcl.verify.mockReset();
});

afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

describe('protected streaming file publication', () => {
  it('writes bounded chunks to a hidden sibling and publishes one create-only target', async () => {
    const first = new Uint8Array([1, 2, 3]);
    const second = new Uint8Array([4, 5]);
    const path = join(directory, 'backup.cvkx');

    await expect(
      writeSecureStreamFile(path, values([first, second]), 32),
    ).resolves.toEqual({ bytes: 5 });
    await expect(readFile(path)).resolves.toEqual(Buffer.from([1, 2, 3, 4, 5]));
    expect(first).toEqual(new Uint8Array(3));
    expect(second).toEqual(new Uint8Array(2));
    expect(await readdir(directory)).toEqual(['backup.cvkx']);
  });

  it('removes only its hidden sibling when the source aborts or exceeds the bound', async () => {
    const aborted = {
      async *[Symbol.asyncIterator](): AsyncGenerator<Uint8Array> {
        await Promise.resolve();
        yield new Uint8Array([9, 8, 7]);
        throw new Error('source failure canary');
      },
    };
    await expect(
      writeSecureStreamFile(join(directory, 'aborted.cvkx'), aborted, 32),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    expect(await readdir(directory)).toEqual([]);

    const oversized = new Uint8Array([6, 5, 4]);
    await expect(
      writeSecureStreamFile(join(directory, 'oversized.cvkx'), values([oversized]), 2),
    ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    expect(oversized).toEqual(new Uint8Array(3));
    expect(await readdir(directory)).toEqual([]);
  });

  it('preflights links and refuses to replace an existing archive', async () => {
    const path = join(directory, 'backup.cvkx');
    await expect(validateSecureFileDestination(path)).resolves.toBeUndefined();
    await expect(
      writeSecureStreamFile(path, values([new Uint8Array([1])])),
    ).resolves.toEqual({
      bytes: 1,
    });
    await expect(validateSecureFileDestination(path)).rejects.toMatchObject({
      code: 'KEY_FILE_ALREADY_EXISTS',
    });
    await expect(
      writeSecureStreamFile(path, values([new Uint8Array([2])])),
    ).rejects.toMatchObject({
      code: 'KEY_FILE_ALREADY_EXISTS',
    });
    await expect(readFile(path)).resolves.toEqual(Buffer.from([1]));

    const linkPath = join(directory, 'link.cvkx');
    const linkTarget = join(directory, 'link-target');
    await mkdir(linkTarget);
    await symlink(linkTarget, linkPath, 'junction');
    await expect(validateSecureFileDestination(linkPath)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
  });

  it('preflights and reads an existing bounded archive without following links', async () => {
    const path = join(directory, 'source.cvkx');
    await writeSecureStreamFile(path, values([new Uint8Array([7, 6, 5])]), 32);
    await expect(validateSecureFileSource(path, 32)).resolves.toBeUndefined();
    await expect(readSecureFile(path, 32)).resolves.toEqual(Buffer.from([7, 6, 5]));
    await expect(validateSecureFileSource(path, 2)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });

    const hardLink = join(directory, 'source-link.cvkx');
    await link(path, hardLink);
    await expect(validateSecureFileSource(hardLink, 32)).rejects.toMatchObject({
      code: 'KEY_FILE_UNSAFE',
    });
  });
});

function values<T>(items: readonly T[]): AsyncIterable<T> {
  return {
    async *[Symbol.asyncIterator](): AsyncGenerator<T> {
      await Promise.resolve();
      yield* items;
    },
  };
}
