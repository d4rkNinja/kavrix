import { afterEach, describe, expect, it, vi } from 'vitest';

import { LocalCliError } from '../src/cli-error.js';
import { runInteractiveTui } from '../src/tui-command.js';

describe('runInteractiveTui', () => {
  const stdinDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  const stdoutDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');

  afterEach(() => {
    vi.restoreAllMocks();
    if (stdinDescriptor === undefined)
      delete (process.stdin as { isTTY?: boolean }).isTTY;
    else Object.defineProperty(process.stdin, 'isTTY', stdinDescriptor);
    if (stdoutDescriptor === undefined)
      delete (process.stdout as { isTTY?: boolean }).isTTY;
    else Object.defineProperty(process.stdout, 'isTTY', stdoutDescriptor);
  });

  it('rejects an unknown --theme id before the TTY check', async () => {
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: true });
    Object.defineProperty(process.stdout, 'isTTY', { configurable: true, value: true });
    await expect(runInteractiveTui({ theme: 'neon-rainbow' })).rejects.toThrow(
      /Unknown theme "neon-rainbow".*gold, ocean, magma, forest, violet/su,
    );
  });

  it('accepts every installed theme id past validation', async () => {
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: false });
    Object.defineProperty(process.stdout, 'isTTY', {
      configurable: true,
      value: false,
    });
    for (const theme of ['gold', 'ocean', 'magma', 'forest', 'violet'] as const) {
      // A valid theme passes validation and reaches the TTY gate instead.
      await expect(runInteractiveTui({ theme })).rejects.toThrow(
        /requires an interactive TTY/i,
      );
    }
  });

  it('rejects non-TTY sessions before loading the Ink app', async () => {
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: false });
    Object.defineProperty(process.stdout, 'isTTY', {
      configurable: true,
      value: false,
    });
    await expect(runInteractiveTui({})).rejects.toBeInstanceOf(LocalCliError);
    await expect(runInteractiveTui({})).rejects.toThrow(/requires an interactive TTY/i);
  });
});
