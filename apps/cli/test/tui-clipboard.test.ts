import { afterEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';

const clipboardProcess = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock('node:child_process', () => ({ spawn: clipboardProcess.spawn }));

function clipboardChild(end = vi.fn()) {
  return Object.assign(new EventEmitter(), {
    stdin: Object.assign(new EventEmitter(), { end, destroy: vi.fn() }),
    kill: vi.fn(),
  });
}

import { clipboardCopyNotice, copySecretToClipboard } from '../src/tui-clipboard.js';

describe('copySecretToClipboard', () => {
  it('reports a scheduled terminal clear honestly and never promises native automatic clearing', () => {
    expect(clipboardCopyNotice('osc52')).toContain('best-effort');
    expect(clipboardCopyNotice('osc52')).toContain('while Kavrix stays open');
    // Terminals that silently drop OSC 52 cannot be detected; the notice must
    // describe the mechanism without promising a verified copy.
    expect(clipboardCopyNotice('osc52')).toContain('terminal clipboard escape');
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
        const child = clipboardChild(end);
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
      if (os === 'win32') {
        expect(args.join(' ')).toContain('[Console]::InputEncoding');
        expect(args.join(' ')).toContain('UTF8Encoding');
      }
      expect(stdout.write).not.toHaveBeenCalled();
    },
  );

  it('falls back through unavailable Linux tools without exposing the copied value', async () => {
    Object.defineProperty(process, 'platform', { configurable: true, value: 'linux' });
    const end = vi.fn();
    let attempt = 0;
    clipboardProcess.spawn.mockImplementation(() => {
      const child = clipboardChild(end);
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
      const child = clipboardChild();
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
      const child = clipboardChild();
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

  it('clears the previous terminal copy immediately when a newer copy lands', async () => {
    vi.useFakeTimers();
    const writes: string[] = [];
    const stdout = {
      isTTY: true,
      write: (chunk: string) => {
        writes.push(String(chunk));
        return true;
      },
    } as unknown as NodeJS.WriteStream;
    await copySecretToClipboard('old-copy-canary', { stdout, clearAfterMs: 20 });
    await copySecretToClipboard('new-copy-canary', { stdout, clearAfterMs: 40 });
    const firstPayload = Buffer.from('old-copy-canary', 'utf8').toString('base64');
    const secondPayload = Buffer.from('new-copy-canary', 'utf8').toString('base64');
    // The first secret is evicted before the second payload lands: two quick
    // copies never leave the older secret resident until its own timer.
    expect(writes).toEqual([
      `\x1b]52;c;${firstPayload}\x07`,
      '\x1b]52;c;\x07',
      `\x1b]52;c;${secondPayload}\x07`,
    ]);
    // Only the newest copy's clear timer remains, and it still fires.
    await vi.advanceTimersByTimeAsync(45);
    expect(writes).toHaveLength(4);
    expect(writes[3]).toBe('\x1b]52;c;\x07');
  });

  it('tolerates a closed terminal during the scheduled clear', async () => {
    vi.useFakeTimers();
    const writes: string[] = [];
    const stdout = {
      isTTY: true,
      write: (chunk: string) => {
        writes.push(String(chunk));
        if (writes.length > 1) throw new Error('terminal closed');
        return true;
      },
    } as unknown as NodeJS.WriteStream;
    await expect(
      copySecretToClipboard('closed-terminal-canary', { stdout, clearAfterMs: 20 }),
    ).resolves.toBe('osc52');
    await vi.advanceTimersByTimeAsync(25);
    expect(writes).toHaveLength(2);
  });

  it('refuses oversized payloads instead of writing a truncatable sequence', async () => {
    const writes: string[] = [];
    const stdout = {
      isTTY: true,
      write: (chunk: string) => {
        writes.push(String(chunk));
        return true;
      },
    } as unknown as NodeJS.WriteStream;
    const oversized = 'x'.repeat(64 * 1024);
    await expect(copySecretToClipboard(oversized, { stdout })).rejects.toThrow(
      /size cap/u,
    );
    expect(writes).toEqual([]);
  });

  it('handles a broken stdin pipe and tries the next Linux backend', async () => {
    Object.defineProperty(process, 'platform', { configurable: true, value: 'linux' });
    const children: ReturnType<typeof clipboardChild>[] = [];
    clipboardProcess.spawn.mockImplementation(() => {
      const child = clipboardChild();
      children.push(child);
      void Promise.resolve().then(() => {
        if (children.length === 1) {
          child.stdin.emit('error', new Error('EPIPE-private-canary'));
          child.emit('close', 1);
        } else child.emit('close', 0);
      });
      return child;
    });
    await expect(
      copySecretToClipboard('copy-canary', {
        stdout: { isTTY: false } as NodeJS.WriteStream,
      }),
    ).resolves.toBe('system');
    expect(children[0]?.kill).toHaveBeenCalledWith('SIGKILL');
    expect(clipboardProcess.spawn.mock.calls.map(([name]) => name)).toEqual([
      'wl-copy',
      'xclip',
    ]);
  });

  it('kills a hung clipboard helper and rejects within a bounded time', async () => {
    vi.useFakeTimers();
    Object.defineProperty(process, 'platform', { configurable: true, value: 'darwin' });
    const child = clipboardChild();
    clipboardProcess.spawn.mockReturnValue(child);
    const pending = expect(
      copySecretToClipboard('hung-helper-canary', {
        stdout: { isTTY: false } as NodeJS.WriteStream,
      }),
    ).rejects.toThrow('pbcopy timed out');
    await vi.advanceTimersByTimeAsync(5_000);
    expect(child.kill).toHaveBeenCalledWith('SIGKILL');
    await pending;
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
