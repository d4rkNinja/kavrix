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

const guidedMocks = vi.hoisted(() => ({
  preflight: vi.fn(),
  execute: vi.fn(),
}));

const configMocks = vi.hoisted(() => ({
  ensure: vi.fn(async () => join(homedir(), '.kavrix', 'config.toml')),
  path: vi.fn(() => join(homedir(), '.kavrix', 'config.toml')),
}));

vi.mock('node:readline/promises', () => ({
  createInterface: readlineMocks.createInterface,
}));

vi.mock('@kavrix/key-files', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@kavrix/key-files')>();
  return {
    ...actual,
    ensureSecureDirectory: secureDirectoryMocks.ensure,
  };
});

vi.mock('../src/local-database-onboarding.js', () => ({
  preflightGuidedLocalOnboarding: guidedMocks.preflight,
  executeGuidedLocalOnboarding: guidedMocks.execute,
}));

vi.mock('../src/kavrix-config.js', () => ({
  ensureKavrixConfig: configMocks.ensure,
  getKavrixConfigPath: configMocks.path,
}));

import { PortableKeyFileError } from '@kavrix/key-files';
import { EncryptedDatabaseStoreError, EncryptedVaultStoreError } from '@kavrix/storage';

import { DatabaseSessionError } from '../src/database-session.js';
import { DatastoreProfileError } from '../src/datastore-profiles.js';
import { InitOnboardingCancelledError } from '../src/init-onboarding.js';
import { LocalSecretInput } from '../src/local-secrets.js';
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
  readlineMocks.interface_.close.mockReset();
  readlineMocks.interface_.off.mockReset();
  readlineMocks.interface_.once.mockReset();
  readlineMocks.interface_.question.mockReset();
  readlineMocks.interface_.question.mockImplementation(async () => {
    const answer = readlineMocks.answers.shift();
    if (answer === undefined) throw new Error('Missing onboarding answer.');
    return answer;
  });
  secureDirectoryMocks.ensure.mockReset();
  secureDirectoryMocks.ensure.mockImplementation(async (path) => path);
  guidedMocks.preflight.mockReset();
  guidedMocks.preflight.mockResolvedValue(undefined);
  guidedMocks.execute.mockReset();
  configMocks.ensure.mockClear();
  configMocks.path.mockClear();
  setTty(true);
  vi.stubEnv('NO_COLOR', '1');
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  restoreProperty(process.stdin, 'isTTY', stdinTtyDescriptor);
  restoreProperty(process.stderr, 'isTTY', stderrTtyDescriptor);
  process.exitCode = originalExitCode;
});

describe('root init onboarding composition', () => {
  it('classifies destination failures without relying on display text', () => {
    const candidate = {
      profileId: 'default',
      dataFile: './kavrix.vault',
      keyFile: './kavrix.key',
      recoveryFile: './kavrix.recovery',
    };

    expect(
      classifyInitDestinationError(
        new PortableKeyFileError('KEY_FILE_UNSAFE'),
        candidate,
      ),
    ).toBe('unsafe-default-directory');
    expect(
      classifyInitDestinationError(
        new PortableKeyFileError('KEY_FILE_INVALID_PATH'),
        candidate,
      ),
    ).toBe('invalid-destination');
    expect(
      classifyInitDestinationError(
        new EncryptedDatabaseStoreError('invalid'),
        candidate,
      ),
    ).toBe('invalid-destination');
    expect(
      classifyInitDestinationError(
        new EncryptedVaultStoreError('invalid', 'static datastore failure'),
        candidate,
      ),
    ).toBe('invalid-destination');
    expect(
      classifyInitDestinationError(new DatabaseSessionError('invalid'), candidate),
    ).toBe('invalid-destination');
    expect(
      classifyInitDestinationError(
        new DatastoreProfileError('PROFILE_DUPLICATE'),
        candidate,
      ),
    ).toBe('invalid-destination');
    expect(classifyInitDestinationError({}, candidate)).toBeUndefined();
  });

  it('creates and selects a recoverable local database for eligible init', async () => {
    readlineMocks.answers.push('', '', '', '', '', '');
    const privateValues = [
      'database-label-canary',
      'owner correct horse battery staple',
      'owner correct horse battery staple',
      'vault-label-canary',
      'recovery correct horse battery staple',
      'recovery correct horse battery staple',
    ];
    const read = vi
      .spyOn(LocalSecretInput.prototype, 'read')
      .mockResolvedValue(privateValues);
    guidedMocks.execute.mockImplementation(async (request) => {
      expect(Buffer.from(request.ownerPassphrase).toString('utf8')).toBe(
        privateValues[1],
      );
      expect(Buffer.from(request.recoveryPassphrase).toString('utf8')).toBe(
        privateValues[4],
      );
      expect(request).toMatchObject({
        profileId: 'default',
        databaseLabel: privateValues[0],
        vaultLabel: privateValues[3],
      });
      return {
        profileId: 'default',
        databaseId: 'db_created',
        vaultId: 'vault_created',
        dataFile: request.dataFile,
        keyFile: request.keyFile,
        recoveryFile: request.recoveryFile,
        recoveryReady: true,
      };
    });
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await buildLocalCli().parseAsync(['node', 'kavrix', 'init']);

    const protectedDirectory = join(homedir(), '.kavrix');
    expect(guidedMocks.preflight).toHaveBeenCalledWith({
      profileId: 'default',
      dataFile: join(protectedDirectory, 'kavrix.vault'),
      keyFile: join(protectedDirectory, 'kavrix.key'),
      recoveryFile: join(protectedDirectory, 'kavrix.recovery'),
      reservedPaths: [join(protectedDirectory, 'config.toml')],
    });
    expect(configMocks.ensure).toHaveBeenCalledOnce();
    expect(read).toHaveBeenCalledWith(
      [
        'database-label',
        'new-passphrase',
        'new-passphrase',
        'vault-label',
        'recovery-passphrase',
        'recovery-passphrase',
      ],
      false,
    );
    expect(guidedMocks.execute).toHaveBeenCalledOnce();
    const output = stderr.mock.calls.flat().join('');
    expect(output).toContain('SETUP COMPLETE');
    expect(output).toContain('Recovery kit created and verified locally');
    expect(output).toContain('Protected datastore profile selected: default');
    for (const value of privateValues) expect(output).not.toContain(value);
    expectEveryInterfaceClosed();
  });

  it('cancels before protected input or mutation', async () => {
    readlineMocks.answers.push('q');
    const read = vi.spyOn(LocalSecretInput.prototype, 'read');
    vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await expect(
      buildLocalCli().parseAsync(['node', 'kavrix', 'init']),
    ).rejects.toBeInstanceOf(InitOnboardingCancelledError);

    expect(read).not.toHaveBeenCalled();
    expect(guidedMocks.preflight).not.toHaveBeenCalled();
    expect(guidedMocks.execute).not.toHaveBeenCalled();
    expect(configMocks.ensure).toHaveBeenCalledOnce();
    expectEveryInterfaceClosed();
  });

  it('preserves explicit legacy init behavior without starting onboarding', async () => {
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
    expect(guidedMocks.preflight).not.toHaveBeenCalled();
    expect(guidedMocks.execute).not.toHaveBeenCalled();
  });

  it.each([['--vault', 'custom'], ['--allow-insecure-transport']])(
    'does not enter guided setup when init receives explicit option %s',
    async (...explicitOptions) => {
      vi.spyOn(LocalSecretInput.prototype, 'read').mockRejectedValueOnce(
        new Error('legacy init reached protected input'),
      );

      await expect(
        buildLocalCli().parseAsync(['node', 'kavrix', 'init', ...explicitOptions]),
      ).rejects.toThrow();

      expect(readlineMocks.createInterface).not.toHaveBeenCalled();
      expect(guidedMocks.preflight).not.toHaveBeenCalled();
      expect(guidedMocks.execute).not.toHaveBeenCalled();
    },
  );

  it('renders an actionable protected-file error for explicit legacy init', async () => {
    setTty(false);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await runLocalCli(['node', 'kavrix', 'init', '--key-file', 'invalid\0key']);

    const output = stderr.mock.calls.flat().join('');
    expect(output).toContain('portable key file path is invalid');
    expect(output).not.toContain('Kavrix command failed');
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
