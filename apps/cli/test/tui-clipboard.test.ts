import { afterEach, describe, expect, it, vi } from 'vitest';

import { copySecretToClipboard } from '../src/tui-clipboard.js';

describe('copySecretToClipboard', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
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
