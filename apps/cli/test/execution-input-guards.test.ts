import { PassThrough } from 'node:stream';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { requestApproval } from '../src/execution/confirm.js';
import { resolveExecutable, sha256File } from '../src/execution/executable.js';
import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';

const ORIGINAL_STDIN = process.stdin;
const ORIGINAL_STDERR_IS_TTY = process.stderr.isTTY;
const ORIGINAL_STDERR_WRITE = process.stderr.write;
let directory = '';

beforeEach(() => {
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(async () => {
  vi.restoreAllMocks();
  process.stderr.write = ORIGINAL_STDERR_WRITE;
  Object.defineProperty(process.stderr, 'isTTY', {
    configurable: true,
    value: ORIGINAL_STDERR_IS_TTY,
  });
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: ORIGINAL_STDIN,
  });
  if (directory !== '') {
    const { rm } = await import('node:fs/promises');
    await rm(directory, { force: true, recursive: true });
    directory = '';
  }
});

function stubInteractiveStdin(stream: PassThrough): void {
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: Object.assign(stream, { isTTY: true }),
  });
  Object.defineProperty(process.stderr, 'isTTY', {
    configurable: true,
    value: true,
  });
}

describe('requestApproval input-state guards', () => {
  it('declines when the input stream has already ended', async () => {
    const stream = new PassThrough();
    stubInteractiveStdin(stream);
    stream.end();
    // Allow the end event to settle so readableEnded flips to true.
    await new Promise((resolve) => setTimeout(resolve, 20));
    const outcome = await requestApproval({
      actor: 'agent',
      executable: 'x',
      argumentsPreview: [],
    });
    expect(outcome).toBe('declined');
  });

  it('replays keystrokes that arrive before readline starts listening', async () => {
    const stream = new PassThrough();
    stubInteractiveStdin(stream);
    stream.write('yes\n');
    const outcome = await Promise.race([
      requestApproval({
        actor: 'user',
        executable: 'x',
        argumentsPreview: [],
      }),
      new Promise<'timeout'>((resolve) => setTimeout(() => resolve('timeout'), 8000)),
    ]);
    expect(outcome).toBe('granted');
  });

  it('accepts an answer typed after the prompt rendered', async () => {
    const stream = new PassThrough();
    stubInteractiveStdin(stream);
    const pending = requestApproval({
      actor: 'user',
      executable: 'x',
      argumentsPreview: [],
    });
    setTimeout(() => stream.write('n\n'), 60);
    expect(await pending).toBe('declined');
  });

  it('treats input errors as a decline', async () => {
    const stream = new PassThrough();
    stubInteractiveStdin(stream);
    // Keep a permanent listener so the synthetic error never becomes an
    // uncaught exception after requestApproval detaches its own handler.
    stream.on('error', () => undefined);
    const pending = requestApproval({
      actor: 'user',
      executable: 'x',
      argumentsPreview: [],
    });
    setTimeout(() => stream.emit('error', new Error('boom')), 30);
    expect(await pending).toBe('declined');
  });
});

describe('executable resolution fallbacks', () => {
  it('falls back to the .exe default when PATHEXT has no usable entries', async () => {
    directory = await createSecureTestDirectory(join(tmpdir(), 'kavrix-pathtool-'));
    const { writeFile, chmod } = await import('node:fs/promises');
    const tool = join(directory, 'fallback-tool.exe');
    await writeFile(tool, 'binary-ish');
    if (process.platform !== 'win32') await chmod(tool, 0o755);
    const resolution = await resolveExecutable('fallback-tool', {
      platform: 'win32',
      pathValue: directory,
      pathExtValue: ';;;',
    });
    expect(resolution.status).toBe('resolved');
  });

  it('skips empty PATH entries while searching', async () => {
    directory = await createSecureTestDirectory(join(tmpdir(), 'kavrix-pathgap-'));
    const { writeFile, chmod } = await import('node:fs/promises');
    const tool = join(directory, 'gap-tool');
    await writeFile(tool, 'script');
    if (process.platform !== 'win32') await chmod(tool, 0o755);
    const resolution = await resolveExecutable('gap-tool', {
      pathValue: `${join(tmpdir(), 'does-not-exist-gap')}${require('node:path').delimiter}${directory}`,
    });
    expect(resolution.status).toBe('resolved');
  });

  it('reports unresolved when hashing fails on an unreadable file', async () => {
    if (process.platform === 'win32') return;
    directory = await createSecureTestDirectory(join(tmpdir(), 'kavrix-hashfail-'));
    const { writeFile, chmod } = await import('node:fs/promises');
    const tool = join(directory, 'unreadable-tool');
    await writeFile(tool, 'secret-ish');
    await chmod(tool, 0o000);
    const resolution = await resolveExecutable(tool);
    expect(resolution.status).toBe('unresolved');
    await chmod(tool, 0o644);
  });

  it('reports unresolved when the executable exceeds the hashable size bound', async () => {
    directory = await createSecureTestDirectory(join(tmpdir(), 'kavrix-huge-'));
    const { open } = await import('node:fs/promises');
    const huge = join(directory, 'huge-tool.exe');
    // Sparse file: instant on NTFS/ext4, no real disk usage.
    const handle = await open(huge, 'w');
    await handle.truncate(513 * 1024 * 1024);
    await handle.close();
    const resolution = await resolveExecutable(huge);
    expect(resolution.status).toBe('unresolved');
  }, 30_000);
});
