import { Command } from 'commander';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LocalCliError } from '../src/cli-error.js';
import { registerTuiCommand, runInteractiveTui } from '../src/tui-command.js';

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

  it('registers the interactive command with a mouse switch that defaults on', () => {
    const program = new Command();
    registerTuiCommand(program);

    const tui = program.commands.find((entry) => entry.name() === 'tui');
    expect(tui).toBeDefined();
    expect(tui?.aliases()).toContain('ui');

    const mouse = tui?.options.find((option) => option.flags.includes('--no-mouse'));
    expect(mouse).toBeDefined();
    // Negatable, with no explicit default: Commander then reports `true` unless
    // `--no-mouse` is passed, which is what keeps mouse support on by default
    // while still letting the opt-out through as a real `false`.
    expect(mouse?.negate).toBe(true);
    expect(mouse?.defaultValue).toBeUndefined();
    expect(mouse?.description).toMatch(/keyboard navigation/u);

    const theme = tui?.options.find((option) => option.flags.includes('--theme'));
    expect(theme?.description).toMatch(/gold, ocean, magma, forest, violet/u);
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

  describe('mouse option forwarding', () => {
    interface MountOptions {
      readonly mouse?: boolean;
      readonly version?: string;
    }

    async function mountWith(
      options: Parameters<typeof runInteractiveTui>[0],
    ): Promise<MountOptions> {
      const seen: MountOptions[] = [];
      vi.doMock('@kavrix/tui', () => ({
        mountKavrixApp: (mountOptions: MountOptions) => {
          seen.push(mountOptions);
          return {
            waitUntilExit: () => Promise.resolve(),
            unmount: () => undefined,
          };
        },
      }));
      Object.defineProperty(process.stdin, 'isTTY', {
        configurable: true,
        value: true,
      });
      Object.defineProperty(process.stdout, 'isTTY', {
        configurable: true,
        value: true,
      });
      await runInteractiveTui(options);
      const captured = seen[0];
      if (captured === undefined) throw new Error('mountKavrixApp was never called');
      return captured;
    }

    afterEach(() => {
      vi.doUnmock('@kavrix/tui');
      vi.resetModules();
    });

    it('passes --no-mouse through as an explicit false', async () => {
      const captured = await mountWith({ mouse: false });
      // Commander's negatable flag yields `true` by default, so `--no-mouse` must
      // arrive as a real `false` and not be dropped as absent.
      expect(captured.mouse).toBe(false);
    });

    it('omits the key entirely when the caller supplies no preference', async () => {
      const captured = await mountWith({});
      // Absent means "decide from the environment"; an explicit undefined would
      // pin it and break the documented default.
      expect('mouse' in captured).toBe(false);
    });
  });
});
