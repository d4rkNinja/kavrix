import { afterEach, describe, expect, it, vi } from 'vitest';

import { LocalCliError } from '../src/cli-error.js';
import {
  runInitTuiOnboarding,
  writeInitTuiOnboardingComplete,
} from '../src/init-tui-onboarding.js';

describe('init TUI onboarding helpers', () => {
  const stdinDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  const stdoutDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  const stderrDescriptor = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');

  afterEach(() => {
    vi.restoreAllMocks();
    for (const [stream, descriptor] of [
      [process.stdin, stdinDescriptor],
      [process.stdout, stdoutDescriptor],
      [process.stderr, stderrDescriptor],
    ] as const) {
      if (descriptor === undefined) delete (stream as { isTTY?: boolean }).isTTY;
      else Object.defineProperty(stream, 'isTTY', descriptor);
    }
  });

  it('rejects when any stdio stream is non-TTY', async () => {
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: true });
    Object.defineProperty(process.stdout, 'isTTY', { configurable: true, value: true });
    Object.defineProperty(process.stderr, 'isTTY', {
      configurable: true,
      value: false,
    });
    await expect(runInitTuiOnboarding({})).rejects.toBeInstanceOf(LocalCliError);
    await expect(runInitTuiOnboarding({})).rejects.toThrow(/Pass --no-tui/i);
  });

  it('writes a sanitized completion banner', () => {
    const lines: string[] = [];
    writeInitTuiOnboardingComplete({
      write: (text) => lines.push(text),
      profileId: 'work',
      datastore: 'file',
      color: false,
    });
    const text = lines.join('');
    expect(text).toContain('SETUP COMPLETE');
    expect(text).toContain('kavrix tui');
    expect(text).toContain('--profile work');
    expect(text).toContain('--no-tui');
  });
});
