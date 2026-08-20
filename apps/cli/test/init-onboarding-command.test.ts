import { homedir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const readlineMocks = vi.hoisted(() => {
  const answers: string[] = [];
  const interface_ = {
    close: vi.fn(),
    off: vi.fn(),
    once: vi.fn(),
    question: vi.fn(async () => {
      const answer = answers.shift();
      if (answer === undefined) throw new Error('Missing onboarding answer.');
      return answer;
    }),
  };
  return { answers, createInterface: vi.fn(() => interface_), interface_ };
});
const secureDirectoryMocks = vi.hoisted(() => ({
  ensure: vi.fn<(path: string) => Promise<string>>(),
}));

vi.mock('node:readline/promises', () => ({
  createInterface: readlineMocks.createInterface,
}));
vi.mock('@kavrix/key-files', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@kavrix/key-files')>();
  return { ...actual, ensureSecureDirectory: secureDirectoryMocks.ensure };
});

import { InitOnboardingCancelledError } from '../src/init-onboarding.js';
import { buildLocalCli, runLocalCli } from '../src/local-vault-cli.js';

const stdinTtyDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
const stderrTtyDescriptor = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');
const originalExitCode = process.exitCode;

beforeEach(() => {
  readlineMocks.answers.splice(0);
  secureDirectoryMocks.ensure.mockReset();
  setTty(true);
});

afterEach(() => {
  vi.restoreAllMocks();
  readlineMocks.createInterface.mockClear();
  readlineMocks.interface_.close.mockClear();
  readlineMocks.interface_.off.mockClear();
  readlineMocks.interface_.once.mockClear();
  readlineMocks.interface_.question.mockClear();
  restoreProperty(process.stdin, 'isTTY', stdinTtyDescriptor);
  restoreProperty(process.stderr, 'isTTY', stderrTtyDescriptor);
  process.exitCode = originalExitCode;
});

describe('root init onboarding composition', () => {
  it('starts only the interactive no-option init flow and closes it on cancel', async () => {
    readlineMocks.answers.push('', 'q');
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(
      buildLocalCli().parseAsync(['node', 'kavrix', 'init']),
    ).rejects.toBeInstanceOf(InitOnboardingCancelledError);

    expect(readlineMocks.createInterface).toHaveBeenCalledTimes(1);
    expect(readlineMocks.interface_.close).toHaveBeenCalledTimes(1);
    expect(stderr.mock.calls.join('')).toContain('STEP 1 / WELCOME & SECURITY');
  });

  it('preserves explicit init behavior without starting the wizard', async () => {
    await expect(
      buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'init',
        '--key-file',
        'invalid\0key',
      ]),
    ).rejects.toMatchObject({ code: 'KEY_FILE_INVALID_PATH' });

    expect(readlineMocks.createInterface).not.toHaveBeenCalled();
  });

  it('places blank guided defaults in one protected Kavrix user directory', async () => {
    readlineMocks.answers.push('', '', '', '', '');
    const stop = new Error('stop after secure default resolution');
    secureDirectoryMocks.ensure.mockRejectedValueOnce(stop);
    vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(buildLocalCli().parseAsync(['node', 'kavrix', 'init'])).rejects.toBe(
      stop,
    );

    expect(secureDirectoryMocks.ensure).toHaveBeenCalledWith(
      join(homedir(), '.kavrix'),
    );
    expect(readlineMocks.interface_.close).toHaveBeenCalledTimes(1);
  });

  it('renders an actionable protected-file error instead of a generic failure', async () => {
    setTty(false);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await runLocalCli(['node', 'kavrix', 'init', '--key-file', 'invalid\0key']);

    const output = stderr.mock.calls.flat().join('');
    expect(output).toContain('portable key file path is invalid');
    expect(output).not.toContain('Kavrix command failed');
    expect(process.exitCode).toBe(1);
  });
});

function setTty(value: boolean): void {
  Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value });
  Object.defineProperty(process.stderr, 'isTTY', { configurable: true, value });
}

function restoreProperty(
  target: NodeJS.ReadStream | NodeJS.WriteStream,
  key: 'isTTY',
  descriptor: PropertyDescriptor | undefined,
): void {
  if (descriptor === undefined) delete (target as { isTTY?: boolean }).isTTY;
  else Object.defineProperty(target, key, descriptor);
}
