import { afterEach, describe, expect, it, vi } from 'vitest';

import { LocalCliError } from '../src/cli-error.js';
import { CLI_VERSION } from '../src/version.js';
import {
  runInitTuiOnboarding,
  writeInitTuiOnboardingComplete,
  type InitTuiOnboardingOptions,
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

  it('rejects non-TTY even when --no-splash / --ascii options are set', async () => {
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: false });
    Object.defineProperty(process.stdout, 'isTTY', { configurable: true, value: true });
    Object.defineProperty(process.stderr, 'isTTY', { configurable: true, value: true });
    await expect(
      runInitTuiOnboarding({ splash: false, ascii: true, color: false }),
    ).rejects.toBeInstanceOf(LocalCliError);
  });

  it('writes a sanitized completion banner with recovery kit path', () => {
    const lines: string[] = [];
    writeInitTuiOnboardingComplete({
      write: (text) => lines.push(text),
      profileId: 'work',
      datastore: 'file',
      recoveryFile: '/home/user/.kavrix/work.recovery',
      color: false,
    });
    const text = lines.join('');
    expect(text).toContain('SETUP COMPLETE');
    expect(text).toContain('Recovery kit created and verified locally');
    expect(text).toContain('Recovery kit path: /home/user/.kavrix/work.recovery');
    expect(text).toContain('kavrix tui');
    expect(text).toContain('--profile work');
    expect(text).toContain('--no-tui');
    expect(text).toContain('separate secure locations');
  });

  describe('interactive host options and cleanup', () => {
    const platform = Object.getOwnPropertyDescriptor(process, 'platform');
    const argv = process.argv;
    const unmount = vi.fn();
    type Captured = InitTuiOnboardingOptions & { noSplash?: boolean; version?: string };

    afterEach(() => {
      if (platform !== undefined) Object.defineProperty(process, 'platform', platform);
      process.argv = argv;
      vi.doUnmock('@kavrix/tui');
      vi.resetModules();
      vi.unstubAllEnvs();
      unmount.mockReset();
    });

    async function mount(
      options: InitTuiOnboardingOptions = {},
      reject = false,
    ): Promise<Captured> {
      let captured: Captured | undefined;
      for (const stream of [process.stdin, process.stdout, process.stderr]) {
        Object.defineProperty(stream, 'isTTY', { configurable: true, value: true });
      }
      vi.doMock('@kavrix/tui', () => ({
        mountOnboardingApp: (passed: Captured) => {
          captured = passed;
          return {
            waitUntilExit: () =>
              reject
                ? Promise.reject(new Error('terminal host failed'))
                : Promise.resolve({ status: 'cancelled' }),
            unmount,
          };
        },
      }));
      if (reject)
        await expect(runInitTuiOnboarding(options)).rejects.toThrow(
          'terminal host failed',
        );
      else
        await expect(runInitTuiOnboarding(options)).resolves.toEqual({
          status: 'cancelled',
        });
      expect(unmount).toHaveBeenCalledTimes(1);
      if (captured === undefined) throw new Error('Setup did not mount');
      return captured;
    }

    it('keeps environment-controlled defaults and forwards the published version', async () => {
      Object.defineProperty(process, 'platform', {
        configurable: true,
        value: 'linux',
      });
      vi.stubEnv('TERM', 'xterm-256color');
      vi.stubEnv('NO_COLOR', undefined);
      vi.stubEnv('KAVRIX_TUI_NO_SPLASH', undefined);
      const result = await mount();
      expect(result.ascii).toBe(false);
      expect(result.version).toBe(CLI_VERSION);
      expect('mouse' in result).toBe(false);
      expect('noSplash' in result).toBe(false);
    });

    it('forwards keyboard-only, ASCII, color, and splash preferences', async () => {
      const result = await mount({
        mouse: false,
        ascii: true,
        color: false,
        splash: false,
      });
      expect(result).toMatchObject({
        mouse: false,
        ascii: true,
        color: false,
        noSplash: true,
      });
    });

    it('honors an explicit color preference over NO_COLOR', async () => {
      vi.stubEnv('NO_COLOR', '1');
      expect((await mount({ color: true, mouse: true })).color).toBe(true);
    });

    it.each(['1', 'true'])(
      'honors the %s splash opt-out environment value',
      async (value) => {
        vi.stubEnv('KAVRIX_TUI_NO_SPLASH', value);
        expect((await mount()).noSplash).toBe(true);
      },
    );

    it.each(['dumb', undefined])(
      'uses ASCII on a terminal with TERM=%s',
      async (term) => {
        Object.defineProperty(process, 'platform', {
          configurable: true,
          value: 'linux',
        });
        vi.stubEnv('TERM', term);
        expect((await mount()).ascii).toBe(true);
      },
    );

    it('uses the Windows presentation default and honors the argv color switch', async () => {
      Object.defineProperty(process, 'platform', {
        configurable: true,
        value: 'win32',
      });
      vi.stubEnv('NO_COLOR', undefined);
      process.argv = [...argv, '--no-color'];
      expect(await mount()).toMatchObject({ ascii: true, color: false });
    });

    it('unmounts a failed terminal host before propagating its failure', async () => {
      await mount({}, true);
    });
  });
});
