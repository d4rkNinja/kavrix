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

import { PortableKeyFileError } from '@kavrix/key-files';
import { EncryptedVaultStoreError } from '@kavrix/storage';

import { InitOnboardingCancelledError } from '../src/init-onboarding.js';
import {
  buildLocalCli,
  classifyInitDestinationError,
  runLocalCli,
} from '../src/local-vault-cli.js';

const stdinTtyDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
const stderrTtyDescriptor = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');
const originalExitCode = process.exitCode;

beforeEach(() => {
  readlineMocks.answers.splice(0);
  readlineMocks.createInterface.mockReset();
  readlineMocks.createInterface.mockReturnValue(readlineMocks.interface_);
  readlineMocks.interface_.off.mockReset();
  readlineMocks.interface_.once.mockReset();
  readlineMocks.interface_.question.mockReset();
  readlineMocks.interface_.question.mockImplementation(async () => {
    const answer = readlineMocks.answers.shift();
    if (answer === undefined) throw new Error('Missing onboarding answer.');
    return answer;
  });
  secureDirectoryMocks.ensure.mockReset();
  setTty(true);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
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
  it('classifies destination failures without relying on key-file display text', () => {
    const defaultCandidate = {
      datastore: 'file' as const,
      dataFile: './kavrix.vault',
      keyFile: './kavrix.key',
    };
    const customCandidate = {
      ...defaultCandidate,
      dataFile: 'private/vault',
      keyFile: 'private/key',
    };

    expect(
      classifyInitDestinationError(
        new PortableKeyFileError('KEY_FILE_UNSAFE'),
        defaultCandidate,
      ),
    ).toBe('unsafe-default-directory');
    expect(
      classifyInitDestinationError(
        new PortableKeyFileError('KEY_FILE_UNSAFE'),
        customCandidate,
      ),
    ).toBe('unsafe-key-file');
    expect(
      classifyInitDestinationError(
        new PortableKeyFileError('KEY_FILE_INVALID_PATH'),
        customCandidate,
      ),
    ).toBe('invalid-destination');
    expect(
      classifyInitDestinationError(
        new Error('MongoDB database name is invalid.'),
        defaultCandidate,
      ),
    ).toBe('invalid-database');
    expect(
      classifyInitDestinationError(
        new Error('MongoDB collection name is invalid.'),
        defaultCandidate,
      ),
    ).toBe('invalid-collection');
    expect(
      classifyInitDestinationError(
        new EncryptedVaultStoreError('invalid', 'static datastore failure'),
        defaultCandidate,
      ),
    ).toBe('invalid-destination');
    expect(classifyInitDestinationError({}, defaultCandidate)).toBeUndefined();

    expect(
      classifyInitDestinationError(new PortableKeyFileError('KEY_FILE_UNSAFE'), {
        datastore: 'file',
        dataFile: './kavrix.vault',
        keyFile: 'private/key',
      }),
    ).toBe('unsafe-default-directory');
  });

  it('starts only the interactive no-option init flow and closes it on cancel', async () => {
    readlineMocks.answers.push('', 'q');
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(
      buildLocalCli().parseAsync(['node', 'kavrix', 'init']),
    ).rejects.toBeInstanceOf(InitOnboardingCancelledError);

    expect(readlineMocks.createInterface).toHaveBeenCalledTimes(2);
    expectEveryInterfaceClosed();
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
    expectEveryInterfaceClosed();
  });

  it('resolves the MongoDB default key in the protected Kavrix user directory', async () => {
    readlineMocks.answers.push('', '2', '', '', '', '');
    const stop = new Error('stop after MongoDB default resolution');
    secureDirectoryMocks.ensure.mockRejectedValueOnce(stop);
    vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(buildLocalCli().parseAsync(['node', 'kavrix', 'init'])).rejects.toBe(
      stop,
    );

    expect(secureDirectoryMocks.ensure).toHaveBeenCalledWith(
      join(homedir(), '.kavrix'),
    );
    expectEveryInterfaceClosed();
  });

  it('preserves a Windows-style data path while resolving only the default key', async () => {
    const windowsDataPath = 'C:\\Users\\alice\\Vaults\\team.kavrix';
    readlineMocks.answers.push('', '1', windowsDataPath, '', '');
    const stop = new Error('stop after mixed destination resolution');
    secureDirectoryMocks.ensure.mockRejectedValueOnce(stop);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(buildLocalCli().parseAsync(['node', 'kavrix', 'init'])).rejects.toBe(
      stop,
    );

    expect(secureDirectoryMocks.ensure).toHaveBeenCalledTimes(1);
    expect(stderr.mock.calls.flat().join('')).not.toContain(windowsDataPath);
    expectEveryInterfaceClosed();
  });

  it('returns to the destination step after a protected-destination error without leaking input', async () => {
    const enteredDataPath = 'C:\\private\\vault.kavrix';
    readlineMocks.answers.push('', '1', enteredDataPath, '', '', 'q');
    secureDirectoryMocks.ensure.mockRejectedValueOnce(
      new PortableKeyFileError('KEY_FILE_UNSAFE'),
    );
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(
      buildLocalCli().parseAsync(['node', 'kavrix', 'init']),
    ).rejects.toBeInstanceOf(InitOnboardingCancelledError);

    const output = stderr.mock.calls.flat().join('');
    expect(output).toContain('could not safely use its protected default directory');
    expect(output).toContain('fail-closed vault/key-file policy');
    expect(output.match(/STEP 1 \/ WELCOME & SECURITY/gu)).toHaveLength(1);
    expect(output.match(/STEP 3 \/ LOCAL FILE DESTINATION/gu)).toHaveLength(2);
    expect(output).not.toContain(enteredDataPath);
    expectEveryInterfaceClosed();
  });

  it('closes the interface and preserves an Error rejected by readline', async () => {
    const failure = new Error('readline failed safely');
    readlineMocks.interface_.question.mockRejectedValueOnce(failure);
    vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(buildLocalCli().parseAsync(['node', 'kavrix', 'init'])).rejects.toBe(
      failure,
    );

    expect(readlineMocks.interface_.off).toHaveBeenCalledWith(
      'SIGINT',
      expect.any(Function),
    );
    expectEveryInterfaceClosed();
  });

  it('normalizes a non-Error readline rejection to a safe static message', async () => {
    const unsafeRejection = { input: 'private-readline-canary' };
    readlineMocks.interface_.question.mockRejectedValueOnce(unsafeRejection);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(
      buildLocalCli().parseAsync(['node', 'kavrix', 'init']),
    ).rejects.toThrow('Interactive onboarding input failed.');

    expect(stderr.mock.calls.flat().join('')).not.toContain(unsafeRejection.input);
    expectEveryInterfaceClosed();
  });

  it('turns readline SIGINT into dedicated cancellation and ignores late input', async () => {
    readlineMocks.interface_.once.mockImplementationOnce((_event, listener) => {
      listener();
      return readlineMocks.interface_;
    });
    readlineMocks.interface_.question.mockResolvedValueOnce('late-private-input');
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(
      buildLocalCli().parseAsync(['node', 'kavrix', 'init']),
    ).rejects.toBeInstanceOf(InitOnboardingCancelledError);

    expect(stderr.mock.calls.flat().join('')).not.toContain('late-private-input');
    expect(readlineMocks.interface_.off).toHaveBeenCalledTimes(1);
    expectEveryInterfaceClosed();
  });

  it('enables onboarding color only for an eligible terminal', async () => {
    vi.stubEnv('TERM', 'xterm-256color');
    vi.stubEnv('NO_COLOR', undefined);
    readlineMocks.answers.push('q');
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(
      buildLocalCli().parseAsync(['node', 'kavrix', 'init']),
    ).rejects.toBeInstanceOf(InitOnboardingCancelledError);

    expect(stderr.mock.calls.flat().join('')).toContain('\u001b[');
  });

  it('renders an actionable protected-file error instead of a generic failure', async () => {
    setTty(false);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await runLocalCli(['node', 'kavrix', 'init', '--key-file', 'invalid\0key']);

    const output = stderr.mock.calls.flat().join('');
    expect(output).toContain('portable key file path is invalid');
    expect(output).not.toContain('Kavrix command failed');
    // Invalid configuration input carries the documented stable exit code.
    expect(process.exitCode).toBe(14);
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

function expectEveryInterfaceClosed(): void {
  expect(readlineMocks.interface_.close).toHaveBeenCalledTimes(
    readlineMocks.createInterface.mock.calls.length,
  );
}
