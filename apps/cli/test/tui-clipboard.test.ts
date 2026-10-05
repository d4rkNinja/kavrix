import { afterEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';

const clipboardProcess = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock('node:child_process', () => ({ spawn: clipboardProcess.spawn }));

import { clipboardCopyNotice, copySecretToClipboard } from '../src/tui-clipboard.js';

describe('copySecretToClipboard', () => {
  it('reports a scheduled terminal clear honestly and never promises native automatic clearing', () => {
    expect(clipboardCopyNotice('osc52')).toContain('best-effort');
    expect(clipboardCopyNotice('osc52')).toContain('while Kavrix stays open');
    expect(clipboardCopyNotice('system')).toContain(
      'automatic clearing is unavailable',
    );
    expect(clipboardCopyNotice('system')).toContain('Clear it manually');
    expect(clipboardCopyNotice('system')).not.toContain('30s');
  });
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  afterEach(() => {
    if (platform !== undefined) Object.defineProperty(process, 'platform', platform);
    clipboardProcess.spawn.mockReset();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it.each(['win32', 'darwin', 'linux'])(
    'uses stdin for the %s system clipboard',
    async (os) => {
      Object.defineProperty(process, 'platform', { configurable: true, value: os });
      const end = vi.fn();
      clipboardProcess.spawn.mockImplementation(() => {
        const child = Object.assign(new EventEmitter(), { stdin: { end } });
        void Promise.resolve().then(() => child.emit('close', 0));
        return child;
      });
      const canary = 'clipboard-boundary-canary';
      const stdout = { isTTY: false, write: vi.fn() } as unknown as NodeJS.WriteStream;
      await expect(copySecretToClipboard(canary, { stdout })).resolves.toBe('system');
      expect(end).toHaveBeenCalledWith(canary, 'utf8');
      const [executable, args, options] = clipboardProcess.spawn.mock.calls[0] ?? [];
      expect(executable).toBe(
        os === 'win32' ? 'powershell.exe' : os === 'darwin' ? 'pbcopy' : 'wl-copy',
      );
      expect(JSON.stringify(args)).not.toContain(canary);
      expect(options).toMatchObject({ stdio: ['pipe', 'ignore', 'ignore'] });
      expect(stdout.write).not.toHaveBeenCalled();
    },
  );

  it('falls back through unavailable Linux tools without exposing the copied value', async () => {
    Object.defineProperty(process, 'platform', { configurable: true, value: 'linux' });
    const end = vi.fn();
    let attempt = 0;
    clipboardProcess.spawn.mockImplementation(() => {
      const child = Object.assign(new EventEmitter(), { stdin: { end } });
      attempt += 1;
      const result = attempt;
      void Promise.resolve().then(() => {
        if (result === 1) child.emit('error', new Error('tool unavailable'));
        else child.emit('close', result === 2 ? 1 : 0);
      });
      return child;
    });
    const stdout = { isTTY: false } as NodeJS.WriteStream;
    await expect(copySecretToClipboard('fallback-canary', { stdout })).resolves.toBe(
      'system',
    );
    expect(clipboardProcess.spawn.mock.calls.map(([name]) => name)).toEqual([
      'wl-copy',
      'xclip',
      'xsel',
    ]);
    expect(end).toHaveBeenCalledTimes(3);
  });

  it('reports exhausted backends and handles a null exit code', async () => {
    Object.defineProperty(process, 'platform', { configurable: true, value: 'linux' });
    clipboardProcess.spawn.mockImplementation(() => {
      const child = Object.assign(new EventEmitter(), { stdin: { end: vi.fn() } });
      void Promise.resolve().then(() => child.emit('close', null));
      return child;
    });
    await expect(
      copySecretToClipboard('failure-canary', {
        stdout: { isTTY: false } as NodeJS.WriteStream,
      }),
    ).rejects.toThrow(/No clipboard backend available.*xsel exited null/u);
  });

  it('falls back when terminal clipboard output is unavailable and settles only once', async () => {
    Object.defineProperty(process, 'platform', { configurable: true, value: 'darwin' });
    clipboardProcess.spawn.mockImplementation(() => {
      const child = Object.assign(new EventEmitter(), { stdin: { end: vi.fn() } });
      void Promise.resolve().then(() => {
        child.emit('close', 0);
        child.emit('error', new Error('late process error'));
        child.emit('close', 1);
      });
      return child;
    });
    const stdout = {
      isTTY: true,
      write: () => {
        throw new Error('closed terminal');
      },
    } as unknown as NodeJS.WriteStream;
    await expect(
      copySecretToClipboard('closed-terminal-canary', { stdout }),
    ).resolves.toBe('system');
    expect(clipboardProcess.spawn).toHaveBeenCalledTimes(1);
  });

  it('clears only the newest terminal copy and tolerates terminal shutdown', async () => {
    vi.useFakeTimers();
    const write = vi.fn(() => true);
    const stdout = { isTTY: true, write } as unknown as NodeJS.WriteStream;
    await copySecretToClipboard('old-copy-canary', { stdout, clearAfterMs: 20 });
    await copySecretToClipboard('new-copy-canary', { stdout, clearAfterMs: 40 });
    await vi.advanceTimersByTimeAsync(25);
    expect(write).toHaveBeenCalledTimes(2);
    write.mockImplementation(() => {
      throw new Error('terminal closed');
    });
    await vi.advanceTimersByTimeAsync(20);
    expect(write).toHaveBeenCalledTimes(3);
  });

  it('writes an OSC 52 sequence to stdout on TTY and schedules a clear', async () => {
    vi.useFakeTimers();
    const writes: string[] = [];
    const stdout = {
      isTTY: true,
      write: (chunk: string) => {
        writes.push(String(chunk));
        return true;
      },
    } as unknown as NodeJS.WriteStream;

    const secret = 'super-secret-value';
    await copySecretToClipboard(secret, { stdout, clearAfterMs: 25 });
    const payload = Buffer.from(secret, 'utf8').toString('base64');
    expect(writes.some((chunk) => chunk.includes(`]52;c;${payload}`))).toBe(true);

    await vi.advanceTimersByTimeAsync(30);
    expect(writes.some((chunk) => chunk.includes(']52;c;\u0007'))).toBe(true);
  });
});
