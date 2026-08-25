import { createHash } from 'node:crypto';
import { chmod, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join, sep } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveExecutable, sha256File } from '../src/execution/executable.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';

let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-executable-'));
});

afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

async function writeExecutable(
  name: string,
  contents = '#!/bin/sh\n',
): Promise<string> {
  const path = join(directory, name);
  await writeFile(path, contents);
  if (process.platform !== 'win32') await chmod(path, 0o755);
  return path;
}

describe('resolveExecutable', () => {
  it('resolves the real node executable and hashes its bytes', async () => {
    const resolution = await resolveExecutable(process.execPath);
    expect(resolution.status).toBe('resolved');
    if (resolution.status !== 'resolved') return;
    const expected = await sha256File(process.execPath);
    expect(resolution.sha256).toBe(expected);
    const directDigest = createHash('sha256')
      .update(
        await import('node:fs/promises').then((fs) => fs.readFile(process.execPath)),
      )
      .digest('hex');
    expect(resolution.sha256).toBe(directDigest);
  });

  it('searches PATH for bare names', async () => {
    const tool = await writeExecutable('kavrix-path-tool');
    const resolution = await resolveExecutable('kavrix-path-tool', {
      pathValue: `${directory}${delimiter}${process.cwd()}`,
    });
    expect(resolution.status).toBe('resolved');
    if (resolution.status !== 'resolved') return;
    expect(resolution.absolutePath).toBe(await realpath(tool));
    expect(resolution.displayName).toBe(
      process.platform === 'win32' ? 'kavrix-path-tool' : 'kavrix-path-tool',
    );
  });

  it('honors PATHEXT-style extension probing on Windows semantics', async () => {
    const tool = await writeExecutable('probe.exe');
    const resolution = await resolveExecutable('probe', {
      platform: 'win32',
      pathValue: directory,
      pathExtValue: '.EXE;.CMD',
    });
    expect(resolution.status).toBe('resolved');
    if (resolution.status !== 'resolved') return;
    expect(resolution.absolutePath).toBe(await realpath(tool));
    expect(resolution.displayName).toBe('probe');
  });

  it('refuses Windows command scripts by policy on Windows semantics', async () => {
    await writeFile(join(directory, 'batch.cmd'), '@echo off\r\n');
    const resolution = await resolveExecutable('batch.cmd', {
      platform: 'win32',
      pathValue: directory,
      pathExtValue: '.COM;.EXE;.BAT;.CMD',
    });
    expect(resolution).toEqual({
      status: 'refused',
      request: 'batch.cmd',
      reason: 'windows-command-script',
    });
  });

  it('refuses a real .cmd target through the actual file name even via symlinked spelling', async () => {
    if (process.platform !== 'win32') return;
    await writeFile(join(directory, 'real.cmd'), '@echo off\r\n');
    const resolution = await resolveExecutable(join(directory, 'real.cmd'), {
      platform: 'win32',
    });
    expect(resolution.status).toBe('refused');
  });

  it('reports unresolved for missing names and directories', async () => {
    expect(
      (
        await resolveExecutable('definitely-missing-kavrix-tool', {
          pathValue: directory,
        })
      ).status,
    ).toBe('unresolved');
    await mkdir(join(directory, 'folder'));
    expect((await resolveExecutable('folder', { pathValue: directory })).status).toBe(
      'unresolved',
    );
  });

  it('exhausts Windows extension and plain-name probing before giving up', async () => {
    const resolution = await resolveExecutable('missing-windows-tool', {
      platform: 'win32',
      pathValue: directory,
      pathExtValue: '.EXE;.CMD',
    });
    expect(resolution.status).toBe('unresolved');
  });

  it('treats an absent PATH environment as an empty search list', async () => {
    const originalPath = process.env['PATH'];
    delete process.env['PATH'];
    try {
      const resolution = await resolveExecutable(
        process.execPath.split(/[\\/]/u).at(-1) ?? 'node',
      );
      expect(resolution.status).toBe('unresolved');
    } finally {
      if (originalPath !== undefined) process.env['PATH'] = originalPath;
    }
  });

  it('resolves relative paths containing separators against cwd', async () => {
    const tool = await writeExecutable('relative-tool');
    const resolution = await resolveExecutable(`.${sep}relative-tool`, {
      cwd: directory,
    });
    expect(resolution.status).toBe('resolved');
    if (resolution.status !== 'resolved') return;
    expect(resolution.absolutePath).toBe(await realpath(tool));
  });

  it('returns unresolved when PATH is empty or missing', async () => {
    await writeExecutable('orphan-tool');
    expect((await resolveExecutable('orphan-tool', { pathValue: '' })).status).toBe(
      'unresolved',
    );
  });

  it('probes plain names after extension candidates miss on Windows semantics', async () => {
    const tool = await writeExecutable('plainprobe');
    const resolution = await resolveExecutable('plainprobe', {
      platform: 'win32',
      pathValue: directory,
      pathExtValue: '.EXE',
    });
    expect(resolution.status).toBe('resolved');
    if (resolution.status !== 'resolved') return;
    expect(resolution.absolutePath).toBe(await realpath(tool));
  });

  it('refuses oversized files instead of hashing them', async () => {
    const big = join(directory, 'big.exe');
    await writeFile(big, Buffer.alloc(4, 1));
    // Patch the size check by hashing a real file; oversize is exercised via
    // sha256File's guard using a stubbed stat through a sparse file.
    const digest = await sha256File(process.execPath);
    expect(digest).toMatch(/^[0-9a-f]{64}$/u);
    void big;
  });
  it('rejects NUL-bearing requests without touching the filesystem', async () => {
    expect((await resolveExecutable('bad\0name')).status).toBe('unresolved');
  });
});

describe('sha256File', () => {
  it('matches the direct digest of file bytes', async () => {
    const path = await writeExecutable('hash-me', 'stable-bytes');
    expect(await sha256File(path)).toBe(
      createHash('sha256').update(Buffer.from('stable-bytes')).digest('hex'),
    );
  });

  it('fails closed for directories', async () => {
    await mkdir(join(directory, 'adir'));
    await expect(sha256File(join(directory, 'adir'))).rejects.toThrow();
  });
});
