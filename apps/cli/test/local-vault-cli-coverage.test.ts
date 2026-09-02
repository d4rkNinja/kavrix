import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';

import * as keyFiles from '@kavrix/key-files';
import { PortableKeyFileError } from '@kavrix/key-files';
import {
  EncryptedVaultStoreError,
  FileEncryptedDatabaseStore,
  FileLocalVaultStore,
  MongoLocalVaultStore,
} from '@kavrix/storage';
import { afterEach, describe, expect, it, vi } from 'vitest';

const aclMocks = vi.hoisted(() => ({
  set: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
  verifyDirectory: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
  verify: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
}));
const readlineMocks = vi.hoisted(() => ({
  createInterface: vi.fn(() => ({
    close: vi.fn(),
    off: vi.fn(),
    once: vi.fn((_event: string, callback: () => void) => {
      queueMicrotask(callback);
    }),
    question: vi.fn(async () => ''),
  })),
}));

vi.mock('@kavrix/key-files/windows-acl', () => ({
  setWindowsUserOnlyAcl: aclMocks.set,
  verifyWindowsDirectoryAcl: aclMocks.verifyDirectory,
  verifyWindowsUserOnlyAcl: aclMocks.verify,
}));
vi.mock('@kavrix/key-files', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@kavrix/key-files')>();
  return {
    ...actual,
    setWindowsUserOnlyAcl: aclMocks.set,
    verifyWindowsUserOnlyAcl: aclMocks.verify,
  };
});
vi.mock('node:readline/promises', () => ({
  createInterface: readlineMocks.createInterface,
}));

import {
  buildLocalCli,
  renderSearchResult,
  renderVaultStats,
  renderVaultView,
  runLocalCli,
  sanitizeJsonValue,
} from '../src/local-vault-cli.js';
import { DatabaseSession, DatabaseSessionError } from '../src/database-session.js';
import { DatabaseMigrationError } from '../src/database-migration.js';
import * as migrationCommands from '../src/database-migration-command.js';

const PASSPHRASE = 'local-cli-coverage-passphrase';
const DIFFERENT_PASSPHRASE = 'local-cli-coverage-different-passphrase';
const NEW_PASSPHRASE = 'local-cli-coverage-new-passphrase';
const RECOVERY_PASSPHRASE = 'local-cli-coverage-recovery-passphrase';
const SECOND_RECOVERY_PASSPHRASE = 'local-cli-coverage-second-recovery-passphrase';
const RECOVERED_PASSPHRASE = 'local-cli-coverage-recovered-passphrase';
const ALPHA_VALUE = 'coverage-alpha-value';
const BETA_VALUE = 'coverage-beta-value';
const directories: string[] = [];

type Target = Readonly<{
  directory: string;
  data: string;
  key: string;
}>;

afterEach(async () => {
  vi.restoreAllMocks();
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

async function target(): Promise<Target> {
  const directory = await mkdtemp(join(tmpdir(), 'kavrix-local-cli-coverage-'));
  directories.push(directory);
  return {
    directory,
    data: join(directory, 'vault.data'),
    key: join(directory, 'vault.key'),
  };
}

function route(value: Target, keyFile = value.key): string[] {
  return [...databaseRoute(value), '--key-file', keyFile];
}

function databaseRoute(value: Target): string[] {
  return ['--datastore', 'file', '--data-file', value.data];
}

async function runCli(args: readonly string[], input = ''): Promise<string> {
  const originalStdin = process.stdin;
  const output: string[] = [];
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: Readable.from([input]),
  });
  const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    output.push(String(chunk));
    return true;
  });
  try {
    await buildLocalCli().parseAsync(['node', 'kavrix', ...args]);
    return output.join('');
  } catch (error) {
    throw error;
  } finally {
    write.mockRestore();
    Object.defineProperty(process, 'stdin', {
      configurable: true,
      value: originalStdin,
    });
    if (process.platform === 'win32') {
      await new Promise<void>((resolve) => setTimeout(resolve, 25));
    }
  }
}

async function initVault(value: Target): Promise<Record<string, unknown>> {
  const output = await runCli(
    ['init', ...route(value), '--passphrase-stdin'],
    `${PASSPHRASE}\n${PASSPHRASE}\n`,
  );
  return JSON.parse(output) as Record<string, unknown>;
}

async function put(
  value: Target,
  name: string,
  secret: string,
): Promise<Record<string, unknown>> {
  const output = await runCli(
    ['put', name, ...route(value), '--passphrase-stdin', '--value-stdin'],
    `${PASSPHRASE}\n${secret}\n`,
  );
  return JSON.parse(output) as Record<string, unknown>;
}

async function overwrite(
  value: Target,
  name: string,
  secret: string,
): Promise<Record<string, unknown>> {
  const output = await runCli(
    [
      'put',
      name,
      ...route(value),
      '--passphrase-stdin',
      '--value-stdin',
      '--overwrite',
    ],
    `${PASSPHRASE}\n${secret}\n`,
  );
  return JSON.parse(output) as Record<string, unknown>;
}

describe(
  'local vault CLI active coverage',
  { retry: process.platform === 'win32' ? 2 : 0 },
  () => {
    it('renders bare root help as a successful command without an error line', async () => {
      const originalExitCode = process.exitCode;
      const stdout: string[] = [];
      const stderr: string[] = [];
      const writeOut = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
        stdout.push(String(chunk));
        return true;
      });
      const writeErr = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
        stderr.push(String(chunk));
        return true;
      });
      try {
        process.exitCode = undefined;
        await runLocalCli(['node', 'kavrix']);
        expect(process.exitCode).toBe(0);
        expect(stdout.join('')).toBe('');
        expect(stderr.join('')).toContain('Usage: kavrix [options] [command]');
        expect(stderr.join('')).not.toContain('(outputHelp)');
      } finally {
        writeOut.mockRestore();
        writeErr.mockRestore();
        process.exitCode = originalExitCode;
      }
    });

    it('runs the local vault command lifecycle with safe machine-readable output', async () => {
      const value = await target();
      expect(await initVault(value)).toMatchObject({
        datastore: 'file',
        dataFile: value.data,
        keyFile: value.key,
      });
      const emptyStats = JSON.parse(
        await runCli(
          ['stats', ...route(value), '--passphrase-stdin', '--json'],
          `${PASSPHRASE}\n`,
        ),
      ) as {
        credentialCount: number;
        oldestCredentialAt: string | null;
        newestCredentialAt: string | null;
      };
      expect(emptyStats).toMatchObject({
        credentialCount: 0,
        oldestCredentialAt: null,
        newestCredentialAt: null,
      });
      expect(await put(value, 'alpha', ALPHA_VALUE)).toMatchObject({
        saved: true,
        name: 'alpha',
        revision: 1,
      });
      expect(await put(value, 'beta', BETA_VALUE)).toMatchObject({
        saved: true,
        name: 'beta',
        revision: 2,
      });

      const listed = JSON.parse(
        await runCli(
          ['list', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ) as { names: string[]; revision: number };
      expect(listed).toEqual({ names: ['alpha', 'beta'], revision: 2 });

      const masked = JSON.parse(
        await runCli(
          ['get', 'alpha', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ) as Record<string, unknown>;
      expect(masked).toMatchObject({ name: 'alpha', value: '[REDACTED]', revision: 2 });
      expect(JSON.stringify(masked)).not.toContain(ALPHA_VALUE);

      const revealed = await runCli(
        ['get', 'alpha', ...route(value), '--passphrase-stdin', '--reveal'],
        `${PASSPHRASE}\n`,
      );
      expect(revealed).toBe(`${ALPHA_VALUE}\n`);

      const viewed = JSON.parse(
        await runCli(
          ['view', ...route(value), '--passphrase-stdin', '--json'],
          `${PASSPHRASE}\n`,
        ),
      ) as { count: number; records: Array<{ name: string; value: string }> };
      expect(viewed.count).toBe(2);
      expect(viewed.records.map((record) => record.name)).toEqual(['alpha', 'beta']);
      expect(viewed.records.every((record) => record.value === '[REDACTED]')).toBe(
        true,
      );

      const searched = JSON.parse(
        await runCli(
          [
            'search',
            'A',
            ...route(value),
            '--passphrase-stdin',
            '--limit',
            '1',
            '--json',
          ],
          `${PASSPHRASE}\n`,
        ),
      ) as { count: number; truncated: boolean; matches: Array<{ name: string }> };
      expect(searched).toMatchObject({ count: 2, truncated: true });
      expect(searched.matches).toMatchObject([{ name: 'alpha' }]);

      const stats = JSON.parse(
        await runCli(
          ['stats', ...route(value), '--passphrase-stdin', '--json'],
          `${PASSPHRASE}\n`,
        ),
      ) as {
        credentialCount: number;
        oldestCredentialAt: string;
        newestCredentialAt: string;
      };
      expect(stats.credentialCount).toBe(2);
      expect(stats.oldestCredentialAt).toBeTruthy();
      expect(stats.newestCredentialAt).toBeTruthy();

      expect(
        JSON.parse(
          await runCli(
            ['has', 'alpha', ...route(value), '--passphrase-stdin'],
            `${PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({ exists: true, name: 'alpha', revision: 2 });
      expect(
        JSON.parse(
          await runCli(
            ['has', 'missing', ...route(value), '--passphrase-stdin'],
            `${PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({ exists: false, name: 'missing', revision: 2 });

      expect(
        await runCli(
          ['rename', 'alpha', 'renamed', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).toMatchObject(/"renamed":true/iu);
      expect(
        await runCli(
          ['remove', 'beta', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).toMatch(/"removed":true/iu);

      expect(
        JSON.parse(
          await runCli(
            ['doctor', ...route(value), '--passphrase-stdin'],
            `${PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({ healthy: true, credentialCount: 1, revision: 4 });
      expect(
        JSON.parse(
          await runCli(
            ['doctor', 'health', ...route(value), '--passphrase-stdin'],
            `${PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({ healthy: false, manualRecoveryRequired: expect.any(Array) });

      expect(
        JSON.parse(await runCli(['vault', 'list', ...databaseRoute(value)])),
      ).toEqual({ datastore: 'file', dataFile: value.data, vaults: ['default'] });
      expect(
        JSON.parse(await runCli(['vault', 'status', ...databaseRoute(value)])),
      ).toMatchObject({ vaultId: 'default', revision: 4, currentKeyVersion: 1 });

      const keyStatus = JSON.parse(
        await runCli(
          ['key', 'status', '--key-file', value.key, '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ) as Record<string, unknown>;
      expect(keyStatus).toMatchObject({ keyFile: value.key, protected: true });
    });

    it('resolves MongoDB routes and reports invalid connection-name combinations safely', async () => {
      const value = await target();
      await initVault(value);
      const document = JSON.parse(await readFile(value.data, 'utf8')) as Record<
        string,
        unknown
      >;
      const fakeStore = {
        ping: vi.fn(async () => undefined),
        get: vi.fn(async () => document),
        listVaultIds: vi.fn(async () => ['default']),
        create: vi.fn(async () => undefined),
        update: vi.fn(async () => undefined),
        delete: vi.fn(async () => undefined),
        close: vi.fn(async () => undefined),
      };
      const connect = vi
        .spyOn(MongoLocalVaultStore, 'connect')
        .mockResolvedValue(fakeStore as never);

      expect(
        JSON.parse(
          await runCli(
            [
              'db',
              'ping',
              '--datastore',
              'mongodb',
              '--database-url-stdin',
              '--database',
              'audit_db',
              '--profile-config-dir',
              value.directory,
            ],
            'mongodb://localhost\n',
          ),
        ),
      ).toMatchObject({ connected: true, database: 'audit_db' });
      expect(fakeStore.ping).toHaveBeenCalledTimes(1);

      expect(
        JSON.parse(
          await runCli(
            ['vault', 'list', '--datastore', 'mongodb', '--database-url-stdin'],
            'mongodb://localhost/from-uri\n',
          ),
        ),
      ).toEqual({
        database: 'from-uri',
        collection: 'kavrix_vaults',
        vaults: ['default'],
      });
      expect(
        JSON.parse(
          await runCli(
            [
              'vault',
              'status',
              '--datastore',
              'mongodb',
              '--database-url-stdin',
              '--database',
              'audit_db',
            ],
            'mongodb://localhost\n',
          ),
        ),
      ).toMatchObject({ database: 'audit_db', vaultId: 'default', revision: 0 });
      expect(connect).toHaveBeenCalledTimes(3);
      expect(fakeStore.close).toHaveBeenCalledTimes(3);

      await expect(
        runCli(
          ['vault', 'list', '--datastore', 'mongodb', '--database-url-stdin'],
          'not-a-mongodb-url\n',
        ),
      ).rejects.toThrow('MongoDB connection string is invalid.');
      await expect(
        runCli(
          ['vault', 'list', '--datastore', 'mongodb', '--database-url-stdin'],
          'mongodb://localhost\n',
        ),
      ).rejects.toThrow(
        'Specify --database when the MongoDB connection string has no database name.',
      );
      await expect(
        runCli(
          [
            'vault',
            'list',
            '--datastore',
            'mongodb',
            '--database-url-stdin',
            '--database',
            'invalid database',
          ],
          'mongodb://localhost\n',
        ),
      ).rejects.toThrow('MongoDB database name is invalid.');
    });

    it('reports bounded MongoDB health retries and fail-closed outages', async () => {
      const value = await target();
      await initVault(value);
      const document = JSON.parse(await readFile(value.data, 'utf8')) as Record<
        string,
        unknown
      >;
      const fakeStore = {
        ping: vi.fn<() => Promise<void>>(),
        get: vi.fn(async () => document),
        listVaultIds: vi.fn(async () => ['default']),
        create: vi.fn(async () => undefined),
        update: vi.fn(async () => undefined),
        delete: vi.fn(async () => undefined),
        close: vi.fn(async () => undefined),
      };
      const connect = vi
        .spyOn(MongoLocalVaultStore, 'connect')
        .mockResolvedValue(fakeStore as never);
      const mongoHealthArgs = [
        'doctor',
        'health',
        '--datastore',
        'mongodb',
        '--database-url-stdin',
        '--key-file',
        value.key,
        '--passphrase-stdin',
      ];

      fakeStore.ping
        .mockRejectedValueOnce(new Error('transient detail'))
        .mockResolvedValueOnce(undefined);
      const retried = JSON.parse(
        await runCli(mongoHealthArgs, `mongodb://localhost/healthdb\n${PASSPHRASE}\n`),
      ) as { autoHealed: string[]; checks: Array<{ name: string }> };
      expect(retried.autoHealed).toContain('datastore-retry');
      expect(retried.checks.map((check) => check.name)).toContain('database');

      fakeStore.ping.mockReset().mockRejectedValue(new Error('persistent detail'));
      const unavailable = JSON.parse(
        await runCli(mongoHealthArgs, `mongodb://localhost/healthdb\n${PASSPHRASE}\n`),
      ) as { healthy: boolean; manualRecoveryRequired: string[] };
      expect(unavailable.healthy).toBe(false);
      expect(unavailable.manualRecoveryRequired.join(' ')).toContain(
        'datastore is unavailable',
      );

      connect.mockRejectedValueOnce(new Error('connection detail'));
      const unopened = JSON.parse(
        await runCli(mongoHealthArgs, `mongodb://localhost/healthdb\n${PASSPHRASE}\n`),
      ) as { healthy: boolean; manualRecoveryRequired: string[] };
      expect(unopened.healthy).toBe(false);
      expect(unopened.manualRecoveryRequired.join(' ')).toContain(
        'could not be opened safely',
      );
    });

    it('rejects incompatible datastore options before reading protected input', async () => {
      const value = await target();
      await expect(
        runCli(
          [
            'init',
            '--datastore',
            'file',
            '--data-file',
            value.data,
            '--key-file',
            value.key,
            '--database-url-stdin',
          ],
          '',
        ),
      ).rejects.toThrow(
        'MongoDB connection options cannot be used with --datastore file.',
      );
      await expect(
        runCli(
          [
            'init',
            '--datastore',
            'mongodb',
            '--data-file',
            value.data,
            '--key-file',
            value.key,
          ],
          '',
        ),
      ).rejects.toThrow('--data-file requires --datastore file.');
      await expect(
        runCli(['db', 'ping', '--datastore', 'file', '--data-file', value.data]),
      ).rejects.toThrow('db ping supports only the MongoDB datastore.');
      await expect(
        runCli(['list', '--datastore', 'unsupported', '--data-file', value.data]),
      ).rejects.toThrow('--datastore must be mongodb or file.');
    });

    it('preserves the primary command error when closing a file store also fails', async () => {
      const value = await target();
      await initVault(value);
      const originalClose = FileLocalVaultStore.prototype.close;
      vi.spyOn(FileLocalVaultStore.prototype, 'close').mockImplementationOnce(
        async function (this: FileLocalVaultStore): Promise<void> {
          await originalClose.call(this);
          throw new Error('injected close detail');
        },
      );

      let failure: unknown;
      try {
        await runCli(
          ['get', 'missing', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        );
      } catch (error) {
        failure = error;
      }
      expect(failure).toBeInstanceOf(Error);
      expect(failure).toHaveProperty('message', 'Credential was not found.');
      expect(failure).toHaveProperty('cause');
      expect((failure as Error & { cause?: unknown }).cause).toBeInstanceOf(
        AggregateError,
      );
    });

    it.each([
      'busy',
      'closed',
      'conflict',
      'exists',
      'invalid',
      'connection',
      'operation',
    ] as const)(
      'classifies a %s datastore publication failure without leaking details',
      async (code) => {
        const value = await target();
        vi.spyOn(FileLocalVaultStore.prototype, 'create').mockRejectedValueOnce(
          new EncryptedVaultStoreError(code, 'internal datastore detail'),
        );

        await expect(
          runCli(
            ['init', ...route(value), '--passphrase-stdin'],
            `${PASSPHRASE}\n${PASSPHRASE}\n`,
          ),
        ).rejects.toThrow(
          'The vault operation may have committed; protected local artifacts were retained.',
        );
      },
    );

    it('keeps a protected artifact failure generic and pre-commit', async () => {
      const value = await target();
      vi.spyOn(keyFiles, 'writePortableKeyFile').mockRejectedValueOnce(
        new PortableKeyFileError('KEY_FILE_ALREADY_EXISTS'),
      );

      await expect(
        runCli(
          ['init', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n${PASSPHRASE}\n`,
        ),
      ).rejects.toMatchObject({
        name: 'PortableKeyFileError',
        code: 'KEY_FILE_ALREADY_EXISTS',
      });
    });

    it('rejects invalid input before decrypting or mutating the local vault', async () => {
      const value = await target();
      await initVault(value);
      await put(value, 'existing', ALPHA_VALUE);

      await expect(
        runCli(
          [
            'put',
            'constructor',
            ...route(value),
            '--passphrase-stdin',
            '--value-stdin',
          ],
          `${PASSPHRASE}\nvalue\n`,
        ),
      ).rejects.toThrow('That credential name is reserved.');
      await expect(
        runCli(
          ['put', 'existing', ...route(value), '--passphrase-stdin', '--value-stdin'],
          `${PASSPHRASE}\nreplacement\n`,
        ),
      ).rejects.toThrow('Credential already exists.');
      expect(await overwrite(value, 'existing', BETA_VALUE)).toMatchObject({
        saved: true,
        revision: 2,
      });
      expect(await put(value, 'other', 'coverage-other-value')).toMatchObject({
        saved: true,
        revision: 3,
      });

      await expect(
        runCli(
          ['search', '   ', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('A search pattern is required.');
      await expect(
        runCli(
          ['search', 'x'.repeat(129), ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('Search patterns are limited to 128 characters.');
      await expect(
        runCli(
          ['search', 'x', ...route(value), '--passphrase-stdin', '--limit', '0'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('--limit must be a whole number between 1 and 200.');
      await expect(
        runCli(
          ['search', 'x', ...route(value), '--passphrase-stdin', '--limit', '201'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('--limit must be a whole number between 1 and 200.');
      await expect(
        runCli(['view', 'existing', '--reveal', ...route(value)]),
      ).rejects.toThrow('view --reveal requires an interactive terminal;');
      await expect(
        runCli(['view', 'existing', '--reveal', '--json', ...route(value)]),
      ).rejects.toThrow('view --reveal cannot be combined with --json.');
      await expect(
        runCli(
          [
            'init',
            '--datastore',
            'mongodb',
            '--database',
            'bad database name',
            '--key-file',
            join(value.directory, 'invalid-database.key'),
            '--database-url-stdin',
            '--passphrase-stdin',
          ],
          'mongodb://localhost/kavrix\npass\npass\n',
        ),
      ).rejects.toThrow('MongoDB database name is invalid.');
      await expect(
        runCli(
          [
            'init',
            '--datastore',
            'mongodb',
            '--collection',
            'bad collection name',
            '--key-file',
            join(value.directory, 'invalid-collection.key'),
            '--database-url-stdin',
            '--passphrase-stdin',
          ],
          'mongodb://localhost/kavrix\npass\npass\n',
        ),
      ).rejects.toThrow('MongoDB collection name is invalid.');

      await expect(
        runCli(
          ['get', 'missing', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('Credential was not found.');
      await expect(
        runCli(
          ['view', ...route(value), '--passphrase-stdin', '--reveal'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('Choose one credential before using view --reveal.');
      await expect(
        runCli(
          [
            'view',
            'existing',
            ...route(value),
            '--passphrase-stdin',
            '--reveal',
            '--json',
          ],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('view --reveal cannot be combined with --json.');
      await expect(
        runCli(
          ['view', 'existing', ...route(value), '--passphrase-stdin', '--reveal'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('view --reveal requires an interactive terminal;');

      await expect(
        runCli(
          ['rename', 'existing', 'existing', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('Credential names must be different.');
      await expect(
        runCli(
          ['rename', 'existing', 'other', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow(/destination credential already exists/u);
      await expect(
        runCli(
          ['rename', 'missing', 'new-name', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('Credential was not found.');
      await expect(
        runCli(
          ['put', 'later', ...route(value), '--passphrase-stdin', '--value-stdin'],
          `${PASSPHRASE}\nlater\n`,
        ),
      ).resolves.toContain('"saved":true');
      await expect(
        runCli(
          ['put', 'mixed', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('Use stdin flags for every secret in a command,');

      await expect(
        runCli(
          [
            'init',
            ...route({ ...value, key: join(value.directory, 'other.key') }),
            '--passphrase-stdin',
          ],
          `${PASSPHRASE}\n${DIFFERENT_PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('Passphrases do not match.');
      await expect(
        runCli(
          [
            'key',
            'rewrap',
            '--key-file',
            value.key,
            '--passphrase-stdin',
            '--new-passphrase-stdin',
          ],
          `${PASSPHRASE}\n${NEW_PASSPHRASE}\n${DIFFERENT_PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('New passphrases do not match.');
      await expect(
        runCli(
          [
            'key',
            'copy',
            '--source',
            value.key,
            '--passphrase-stdin',
            '--new-passphrase-stdin',
          ],
          '',
        ),
      ).rejects.toThrow('--destination is required.');
      await expect(
        runCli(
          [
            'recovery',
            'create',
            ...route(value),
            '--passphrase-stdin',
            '--recovery-passphrase-stdin',
          ],
          `${PASSPHRASE}\n${RECOVERY_PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('--recovery-file is required.');
    });

    it('creates, verifies, revokes, and consumes protected recovery artifacts', async () => {
      const value = await target();
      await initVault(value);
      const firstRecovery = join(value.directory, 'first.recovery');
      const secondRecovery = join(value.directory, 'second.recovery');
      const recoveredRecovery = join(value.directory, 'recovered.recovery');
      const recoveredKey = join(value.directory, 'recovered.key');

      const first = JSON.parse(
        await runCli(
          [
            'recovery',
            'create',
            ...route(value),
            '--recovery-file',
            firstRecovery,
            '--passphrase-stdin',
            '--recovery-passphrase-stdin',
          ],
          `${PASSPHRASE}\n${RECOVERY_PASSPHRASE}\n`,
        ),
      ) as { recoverySlotId: string };
      expect(first.recoverySlotId).toMatch(/^[0-9a-f-]{36}$/u);
      const activeHealth = JSON.parse(
        await runCli(
          ['doctor', 'health', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ) as {
        checks: Array<{ name: string; status: string; detail?: string }>;
      };
      expect(activeHealth.checks).toContainEqual(
        expect.objectContaining({
          name: 'recovery-slots',
          status: 'ok',
          detail: 'At least one recovery slot is active.',
        }),
      );
      expect(
        JSON.parse(
          await runCli(['recovery', 'status', ...databaseRoute(value), '--json']),
        ),
      ).toMatchObject({ totalKits: 1, activeKits: 1, revokedKits: 0 });
      expect(
        JSON.parse(
          await runCli(
            [
              'recovery',
              'verify',
              ...route(value),
              '--recovery-file',
              firstRecovery,
              '--recovery-passphrase-stdin',
            ],
            `${RECOVERY_PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({ valid: true, recoverySlotId: first.recoverySlotId });
      await expect(
        runCli(
          [
            'recovery',
            'revoke',
            first.recoverySlotId,
            ...route(value),
            '--passphrase-stdin',
          ],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('last active kit.');
      await expect(
        runCli(
          ['recovery', 'revoke', 'not a slot', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('Recovery slot ID is invalid.');

      const second = JSON.parse(
        await runCli(
          [
            'recovery',
            'create',
            ...route(value),
            '--recovery-file',
            secondRecovery,
            '--passphrase-stdin',
            '--recovery-passphrase-stdin',
          ],
          `${PASSPHRASE}\n${SECOND_RECOVERY_PASSPHRASE}\n`,
        ),
      ) as { recoverySlotId: string };
      expect(
        JSON.parse(
          await runCli(
            [
              'recovery',
              'revoke',
              first.recoverySlotId,
              ...route(value),
              '--passphrase-stdin',
            ],
            `${PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({ revoked: true, slotId: first.recoverySlotId });
      await expect(
        runCli(
          [
            'recovery',
            'verify',
            ...route(value),
            '--recovery-file',
            firstRecovery,
            '--recovery-passphrase-stdin',
          ],
          `${RECOVERY_PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('Recovery verification failed.');

      await expect(
        runCli(
          [
            'recovery',
            'revoke',
            first.recoverySlotId,
            ...route(value),
            '--passphrase-stdin',
          ],
          `${PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('not found or is already revoked.');
      await expect(
        runCli(
          [
            'recovery',
            'use',
            ...route(value),
            '--recovery-file',
            secondRecovery,
            '--output-recovery-file',
            recoveredRecovery,
            '--output-key-file',
            recoveredKey,
            '--overwrite',
          ],
          '',
        ),
      ).rejects.toThrow('Recovery outputs cannot be overwritten.');
      await expect(
        runCli(
          [
            'recovery',
            'use',
            ...route(value),
            '--recovery-file',
            secondRecovery,
            '--output-recovery-file',
            recoveredRecovery,
            '--output-key-file',
            secondRecovery,
          ],
          '',
        ),
      ).rejects.toThrow('Recovery-kit and key-file paths must be different.');
      await expect(
        runCli(
          [
            'recovery',
            'use',
            ...route(value),
            '--recovery-file',
            secondRecovery,
            '--output-recovery-file',
            secondRecovery,
            '--output-key-file',
            recoveredKey,
          ],
          '',
        ),
      ).rejects.toThrow('source and destination recovery-kit paths must be different.');
      const mismatchRecovery = join(value.directory, 'mismatch.recovery');
      const mismatchKey = join(value.directory, 'mismatch.key');
      await expect(
        runCli(
          [
            'recovery',
            'use',
            ...route(value),
            '--recovery-file',
            secondRecovery,
            '--output-recovery-file',
            mismatchRecovery,
            '--output-key-file',
            mismatchKey,
            '--recovery-passphrase-stdin',
            '--new-passphrase-stdin',
          ],
          `${SECOND_RECOVERY_PASSPHRASE}\n${NEW_PASSPHRASE}\n${DIFFERENT_PASSPHRASE}\n`,
        ),
      ).rejects.toThrow('New passphrases do not match.');

      expect(
        JSON.parse(
          await runCli(
            [
              'recovery',
              'use',
              ...route(value),
              '--recovery-file',
              secondRecovery,
              '--output-recovery-file',
              recoveredRecovery,
              '--output-key-file',
              recoveredKey,
              '--recovery-passphrase-stdin',
              '--new-passphrase-stdin',
            ],
            `${SECOND_RECOVERY_PASSPHRASE}\n${RECOVERED_PASSPHRASE}\n${RECOVERED_PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({
        recovered: true,
        keyFile: recoveredKey,
        recoveryFile: recoveredRecovery,
      });
      expect(
        JSON.parse(
          await runCli(
            ['doctor', ...route(value, recoveredKey), '--passphrase-stdin'],
            `${RECOVERED_PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({ healthy: true, revision: 4, credentialCount: 0 });

      const copiedKey = join(value.directory, 'copied.key');
      expect(
        JSON.parse(
          await runCli(
            [
              'key',
              'copy',
              '--source',
              recoveredKey,
              '--destination',
              copiedKey,
              '--passphrase-stdin',
              '--new-passphrase-stdin',
            ],
            `${RECOVERED_PASSPHRASE}\n${NEW_PASSPHRASE}\n${NEW_PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({ copied: true, destination: copiedKey });
      expect(
        JSON.parse(
          await runCli(
            ['key', 'status', '--key-file', copiedKey, '--passphrase-stdin'],
            `${NEW_PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({ keyFile: copiedKey, protected: true });
      expect(
        JSON.parse(
          await runCli(
            [
              'key',
              'rewrap',
              '--key-file',
              copiedKey,
              '--passphrase-stdin',
              '--new-passphrase-stdin',
            ],
            `${NEW_PASSPHRASE}\n${RECOVERY_PASSPHRASE}\n${RECOVERY_PASSPHRASE}\n`,
          ),
        ),
      ).toMatchObject({ rewrapped: true, keyFile: copiedKey });

      expect(await access(firstRecovery)).toBeUndefined();
      expect(await access(secondRecovery)).toBeUndefined();
      expect((await readFile(recoveredKey)).byteLength).toBeGreaterThan(0);
      expect((await readFile(recoveredRecovery)).byteLength).toBeGreaterThan(0);
      expect(second.recoverySlotId).not.toBe(first.recoverySlotId);
    });

    it('reports missing anchors and can initialize one only with explicit acceptance', async () => {
      const value = await target();
      await initVault(value);
      await rm(`${value.key}.anchor`);

      const missing = JSON.parse(
        await runCli(
          ['doctor', 'health', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ) as { healthy: boolean; manualRecoveryRequired: string[] };
      expect(missing.healthy).toBe(false);
      expect(missing.manualRecoveryRequired.join(' ')).toContain('revision anchor');

      const accepted = JSON.parse(
        await runCli(
          [
            'doctor',
            'health',
            ...route(value),
            '--passphrase-stdin',
            '--accept-current',
          ],
          `${PASSPHRASE}\n`,
        ),
      ) as { healthy: boolean; autoHealed: string[] };
      expect(accepted.healthy).toBe(false);
      expect(accepted.autoHealed).toContain('revision-anchor-initialized');
      expect(await access(`${value.key}.anchor`)).toBeUndefined();
    });

    it('renders empty statistics, truncated search results, and rejects circular JSON', () => {
      const emptyStats = renderVaultStats({
        vaultId: 'empty',
        revision: 0,
        currentKeyVersion: 1,
        credentialCount: 0,
        oldestCredentialAt: null,
        newestCredentialAt: null,
        updatedAt: '2026-08-20T00:00:00.000Z',
      });
      expect(emptyStats).toContain('Oldest credential:  (none)');
      expect(emptyStats).toContain('Newest credential:  (none)');

      const truncated = renderSearchResult({
        vaultId: 'empty',
        revision: 0,
        pattern: 'credential',
        count: 2,
        truncated: true,
        matches: [{ name: 'one', updatedAt: '2026-08-20T00:00:00.000Z' }],
      });
      expect(truncated).toContain('Results were limited.');

      const circular: Record<string, unknown> = {};
      circular['self'] = circular;
      expect(() => sanitizeJsonValue(circular)).toThrow(
        'Cannot serialize circular JSON output.',
      );
    });

    it('renders every dashboard shape and sanitizes structured JSON safely', () => {
      const stdoutTty = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
      vi.stubEnv('NO_COLOR', undefined);
      vi.stubEnv('TERM', 'xterm-256color');
      Object.defineProperty(process.stdout, 'isTTY', {
        configurable: true,
        value: true,
      });
      try {
        const emptyView = renderVaultView(
          { id: 'empty', revision: 0, updatedAt: '2026-08-21T00:00:00Z' },
          [],
          false,
        );
        expect(emptyView).toContain('No credentials stored');
        expect(emptyView).toContain('\u001b[');

        const revealed = renderVaultView(
          { id: 'vault', revision: 1, updatedAt: '2026-08-21T00:00:00.000Z' },
          [
            [
              'credential',
              {
                value: 'v'.repeat(90),
                updatedAt: '2026-08-21T00:00:00.000Z',
              },
            ],
          ],
          true,
        );
        expect(revealed).toContain('Credential: credential');
        expect(revealed).toContain('...');

        const table = renderVaultView(
          { id: 'vault', revision: 2, updatedAt: '2026-08-21T00:00:00.000Z' },
          [
            [
              'n'.repeat(40),
              { value: 'secret', updatedAt: '2026-08-21T00:00:00.000Z' },
            ],
            ['second', { value: 'secret', updatedAt: '2026-08-21T00:00:00.000Z' }],
          ],
          false,
        );
        expect(table).toContain('[REDACTED]');
        expect(table).not.toContain('secret');

        expect(
          renderSearchResult({
            vaultId: 'vault',
            revision: 2,
            pattern: 'missing',
            count: 0,
            truncated: false,
            matches: [],
          }),
        ).toContain('No credential names matched');
        expect(
          renderSearchResult({
            vaultId: 'vault',
            revision: 2,
            pattern: 'found',
            count: 1,
            truncated: false,
            matches: [{ name: 'n'.repeat(40), updatedAt: '2026-08-21T00:00:00.000Z' }],
          }),
        ).not.toContain('Results were limited');
      } finally {
        vi.unstubAllEnvs();
        restoreProperty(process.stdout, 'isTTY', stdoutTty);
      }

      expect(sanitizeJsonValue(null)).toBeNull();
      expect(sanitizeJsonValue(3)).toBe(3);
      expect(sanitizeJsonValue(['safe', { nested: 'value' }])).toEqual([
        'safe',
        { nested: 'value' },
      ]);
      expect(() => sanitizeJsonValue({ 'name\u0000': 1, 'name[CONTROL]': 2 })).toThrow(
        'JSON output contains colliding sanitized keys.',
      );
    });

    it('renders interactive local-vault commands and keeps revealed output terminal-safe', async () => {
      const value = await target();
      await initVault(value);
      await put(value, 'interactive', 'value\u001b[31m-canary');
      const stdoutTty = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
      Object.defineProperty(process.stdout, 'isTTY', {
        configurable: true,
        value: true,
      });
      try {
        const dashboard = await runCli(
          ['view', ...route(value), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        );
        expect(dashboard).toContain('KAVRIX / VAULT VIEW');
        expect(dashboard).toContain('[REDACTED]');

        const card = await runCli(
          ['view', 'interactive', ...route(value), '--passphrase-stdin', '--reveal'],
          `${PASSPHRASE}\n`,
        );
        expect(card).toContain('Credential: interactive');
        expect(card).toContain('[CONTROL][31m-canary');

        const revealed = await runCli(
          ['get', 'interactive', ...route(value), '--passphrase-stdin', '--reveal'],
          `${PASSPHRASE}\n`,
        );
        expect(revealed).toContain('[CONTROL][31m-canary');
        expect(revealed).not.toContain('\u001b[31m-canary');

        expect(
          await runCli(
            ['search', 'inter', ...route(value), '--passphrase-stdin'],
            `${PASSPHRASE}\n`,
          ),
        ).toContain('KAVRIX / SEARCH');
        expect(
          await runCli(
            ['stats', ...route(value), '--passphrase-stdin'],
            `${PASSPHRASE}\n`,
          ),
        ).toContain('KAVRIX / VAULT STATS');

        await expect(
          runCli(
            ['view', 'missing', ...route(value), '--passphrase-stdin'],
            `${PASSPHRASE}\n`,
          ),
        ).rejects.toThrow('Credential was not found.');
        await expect(
          runCli(
            ['remove', 'missing', ...route(value), '--passphrase-stdin'],
            `${PASSPHRASE}\n`,
          ),
        ).rejects.toThrow('Credential was not found.');
      } finally {
        restoreProperty(process.stdout, 'isTTY', stdoutTty);
      }
    });

    it('runs every datastore-profile CLI shape and rejects incompatible routing', async () => {
      const value = await target();
      const config = join(value.directory, 'profiles');

      expect(
        JSON.parse(await runCli(['db', 'profile', 'status', '--config-dir', config])),
      ).toEqual({ current: null });

      const fileAdded = JSON.parse(
        await runCli([
          'db',
          'profile',
          'add',
          'local',
          '--config-dir',
          config,
          '--datastore',
          'file',
          '--database-id',
          'db_local',
          '--data-file',
          join(value.directory, 'database.data'),
          '--key-file',
          join(value.directory, 'database.key'),
        ]),
      ) as { profile: { datastore: string; databaseId: string } };
      expect(fileAdded.profile).toMatchObject({
        datastore: 'file',
        databaseId: 'db_local',
      });

      const mongoAdded = JSON.parse(
        await runCli([
          'db',
          'profile',
          'add',
          'work',
          '--config-dir',
          config,
          '--datastore',
          'mongodb',
          '--database-id',
          'db_work',
          '--database',
          'credentials',
          '--database-collection',
          'database_docs',
          '--vault-collection',
          'vault_docs',
          '--key-file',
          join(value.directory, 'mongo.key'),
        ]),
      ) as { profile: { datastore: string; databaseId: string } };
      expect(mongoAdded.profile).toMatchObject({
        datastore: 'mongodb',
        databaseId: 'db_work',
      });

      vi.spyOn(MongoLocalVaultStore, 'connect').mockResolvedValueOnce({
        ping: vi.fn(async () => undefined),
        close: vi.fn(async () => undefined),
      } as never);
      expect(
        JSON.parse(
          await runCli(
            ['db', 'ping', '--profile-config-dir', config, '--database-url-stdin'],
            'mongodb://localhost/kavrix\n',
          ),
        ),
      ).toMatchObject({ connected: true, database: 'kavrix' });

      const defaultedMongo = JSON.parse(
        await runCli([
          'db',
          'profile',
          'add',
          'defaulted',
          '--config-dir',
          config,
          '--datastore',
          'mongodb',
          '--database',
          'credentials',
          '--key-file',
          join(value.directory, 'defaulted.key'),
        ]),
      ) as { profile: Record<string, unknown> };
      expect(defaultedMongo.profile).toMatchObject({
        datastore: 'mongodb',
        database: 'credentials',
        databaseCollection: 'kavrix_databases',
        vaultCollection: 'kavrix_vaults',
      });
      expect(defaultedMongo.profile.databaseId).toBeUndefined();
      vi.spyOn(MongoLocalVaultStore, 'connect').mockResolvedValueOnce({
        ping: vi.fn(async () => undefined),
        close: vi.fn(async () => undefined),
      } as never);
      expect(
        JSON.parse(
          await runCli(
            [
              'db',
              'ping',
              '--datastore',
              'mongodb',
              '--profile',
              'defaulted',
              '--profile-config-dir',
              config,
              '--collection',
              'custom_vaults',
              '--database-url-stdin',
            ],
            'mongodb://localhost/kavrix\n',
          ),
        ),
      ).toMatchObject({
        connected: true,
        database: 'credentials',
        collection: 'custom_vaults',
      });

      expect(
        JSON.parse(await runCli(['db', 'profile', 'list', '--config-dir', config])),
      ).toMatchObject({
        profiles: [{ id: 'defaulted' }, { id: 'local' }, { id: 'work' }],
      });
      expect(
        await runReported([
          'db',
          'ping',
          '--profile',
          'defaulted',
          '--profile-config-dir',
          config,
          '--data-file',
          'wrong.data',
        ]),
      ).toContain('--data-file requires --datastore file.');
      expect(
        JSON.parse(
          await runCli(['db', 'profile', 'use', 'work', '--config-dir', config]),
        ),
      ).toMatchObject({ selected: { id: 'work', datastore: 'mongodb' } });
      expect(
        JSON.parse(await runCli(['db', 'profile', 'status', '--config-dir', config])),
      ).toMatchObject({ current: { id: 'work', databaseId: 'db_work' } });
      expect(
        JSON.parse(
          await runCli(['db', 'profile', 'remove', 'work', '--config-dir', config]),
        ),
      ).toMatchObject({ removed: true, profile: { id: 'work' } });

      await expect(
        runCli([
          'db',
          'profile',
          'add',
          'bad-mongo',
          '--config-dir',
          config,
          '--datastore',
          'mongodb',
          '--database',
          'credentials',
          '--data-file',
          'wrong.data',
          '--key-file',
          'wrong.key',
        ]),
      ).rejects.toThrow('--data-file requires --datastore file.');
      await expect(
        runCli([
          'db',
          'profile',
          'add',
          'bad-file',
          '--config-dir',
          config,
          '--datastore',
          'file',
          '--database',
          'wrong',
          '--data-file',
          'wrong.data',
          '--key-file',
          'wrong.key',
        ]),
      ).rejects.toThrow('MongoDB routing options require --datastore mongodb.');
      await expect(
        runCli([
          'db',
          'profile',
          'add',
          'bad-kind',
          '--config-dir',
          config,
          '--datastore',
          'other',
          '--key-file',
          'wrong.key',
        ]),
      ).rejects.toThrow('--datastore must be mongodb or file.');
    });

    it('maps command failures to safe, stable stderr output', async () => {
      expect(
        await runReported([
          'search',
          '   ',
          '--datastore',
          'file',
          '--data-file',
          'vault.data',
          '--key-file',
          'vault.key',
        ]),
      ).toContain('A search pattern is required.');
      expect(
        await runReported([
          'get',
          'missing',
          '--datastore',
          'file',
          '--data-file',
          'vault.data',
          '--key-file',
          'vault.key',
          '--passphrase-stdin',
        ]),
      ).toContain('Secret input contains the wrong number of values.');
      const config = join((await target()).directory, 'empty');
      expect(
        await runReported([
          'db',
          'profile',
          'remove',
          'missing',
          '--config-dir',
          config,
        ]),
      ).toContain('profile was not found');
      expect(
        await runReported([
          'migrate',
          'database',
          '--source-profile',
          'same',
          '--destination-profile',
          'same',
          '--source-vault',
          'vault_default',
        ]),
      ).toContain('Migration source and destination profiles must differ.');
      // Unknown commands are usage errors with the documented exit code 2
      // and commander's sanitized message, not a generic failure.
      expect(await runReported(['unknown-command'])).toContain(
        "unknown command 'unknown-command'",
      );
      vi.spyOn(
        migrationCommands,
        'executeDatabaseMigrationCommand',
      ).mockRejectedValueOnce(new DatabaseMigrationError('invalid'));
      expect(
        await runReported([
          'migrate',
          'database',
          '--source-profile',
          'source',
          '--destination-profile',
          'destination',
          '--source-vault',
          'vault_default',
        ]),
      ).toContain('The migration request is invalid.');
      const stdinTty = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
      const stderrTty = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');
      Object.defineProperty(process.stdin, 'isTTY', {
        configurable: true,
        value: true,
      });
      Object.defineProperty(process.stderr, 'isTTY', {
        configurable: true,
        value: true,
      });
      try {
        const reported = await runReported(['init'], '', true);
        expect(reported).toContain('STEP 1 / LOCAL RECOVERABLE SETUP');
        expect(reported).toContain('Setup cancelled. No vault was created.');
      } finally {
        restoreProperty(process.stdin, 'isTTY', stdinTty);
        restoreProperty(process.stderr, 'isTTY', stderrTty);
      }
      expect(
        await runReported([
          'list',
          '--datastore',
          'unsupported',
          '--data-file',
          'vault.data',
        ]),
      ).toContain('--datastore must be mongodb or file.');

      const portableTarget = await target();
      vi.spyOn(keyFiles, 'writePortableKeyFile').mockRejectedValueOnce(
        new PortableKeyFileError('KEY_FILE_ALREADY_EXISTS'),
      );
      expect(
        await runReported(
          ['init', ...route(portableTarget), '--passphrase-stdin'],
          `${PASSPHRASE}\n${PASSPHRASE}\n`,
        ),
      ).toContain('portable key file already exists');

      const aggregateTarget = await target();
      vi.spyOn(FileLocalVaultStore, 'open').mockRejectedValueOnce(
        new AggregateError([new Error('opaque')], 'aggregate failure'),
      );
      expect(
        await runReported(
          ['list', ...route(aggregateTarget), '--passphrase-stdin'],
          `${PASSPHRASE}\n`,
        ),
      ).toContain('aggregate failure');

      vi.spyOn(MongoLocalVaultStore, 'connect').mockRejectedValueOnce(
        new EncryptedVaultStoreError('operation', 'private store detail'),
      );
      expect(
        await runReported(
          [
            'list',
            '--datastore',
            'mongodb',
            '--database-url-stdin',
            '--passphrase-stdin',
          ],
          'mongodb://localhost/kavrix\ncorrect horse battery staple\n',
        ),
      ).toContain('private store detail');

      const pingProfileConfig = join((await target()).directory, 'missing-profile');
      vi.spyOn(MongoLocalVaultStore, 'connect').mockResolvedValueOnce({
        ping: vi.fn(async () => undefined),
        close: vi.fn(async () => undefined),
      } as never);
      expect(
        JSON.parse(
          await runCli(
            [
              'db',
              'ping',
              '--profile-config-dir',
              pingProfileConfig,
              '--database-url-stdin',
            ],
            'mongodb://localhost/kavrix\n',
          ),
        ),
      ).toMatchObject({ connected: true, database: 'kavrix' });

      const value = await target();
      const boundConfig = join(value.directory, 'bound-profile');
      await runCli([
        'db',
        'profile',
        'add',
        'local',
        '--config-dir',
        boundConfig,
        '--datastore',
        'file',
        '--database-id',
        'db_bound',
        '--data-file',
        join(value.directory, 'database.data'),
        '--key-file',
        join(value.directory, 'database.key'),
      ]);
      expect(
        await runReported(
          [
            'get',
            'missing',
            '--profile',
            'local',
            '--profile-config-dir',
            boundConfig,
            '--passphrase-stdin',
          ],
          'correct horse battery staple\n',
        ),
      ).toContain('kavrix db vault use');
      expect(
        await runReported([
          'get',
          'missing',
          '--profile',
          'local',
          '--profile-config-dir',
          boundConfig,
          '--vault',
          'default',
        ]),
      ).toContain('Vault ID is invalid.');

      vi.spyOn(FileEncryptedDatabaseStore, 'open').mockResolvedValueOnce({
        close: vi.fn(async () => undefined),
      } as never);
      vi.spyOn(DatabaseSession, 'open').mockRejectedValueOnce(
        new DatabaseSessionError('operation'),
      );
      expect(
        await runReported(
          [
            'get',
            'missing',
            '--profile',
            'local',
            '--profile-config-dir',
            boundConfig,
            '--vault',
            'vault_example',
            '--passphrase-stdin',
          ],
          'correct horse battery staple\n',
        ),
      ).toContain('The database operation failed.');
    });

    it('parses every MongoDB destruction secret frame before opening the datastore', async () => {
      vi.spyOn(MongoLocalVaultStore, 'connect').mockRejectedValueOnce(
        new EncryptedVaultStoreError('operation', 'destroy datastore unavailable'),
      );
      expect(
        await runReported(
          [
            'destroy',
            '--datastore',
            'mongodb',
            '--database',
            'credentials',
            '--database-url-stdin',
            '--passphrase-stdin',
            '--confirmation-stdin',
          ],
          `mongodb://localhost/credentials\n${PASSPHRASE}\nfirst confirmation\nsecond confirmation\n`,
        ),
      ).toContain('destroy datastore unavailable');
    });

    it('keeps explicit standalone routing out of an ambient database-bound profile', async () => {
      const value = await target();
      const ambientConfig = join(value.directory, 'ambient-profile');
      await runCli([
        'db',
        'profile',
        'add',
        'ambient',
        '--config-dir',
        ambientConfig,
        '--datastore',
        'file',
        '--database-id',
        'db_ambient',
        '--data-file',
        join(value.directory, 'ambient.database'),
        '--key-file',
        join(value.directory, 'ambient.key'),
      ]);
      await runCli(['db', 'profile', 'use', 'ambient', '--config-dir', ambientConfig]);
      await initVault(value);
      expect(await put(value, 'standalone', ALPHA_VALUE)).toMatchObject({
        saved: true,
        name: 'standalone',
        revision: 1,
      });
    });
  },
);

function restoreProperty(
  target: object,
  key: PropertyKey,
  descriptor: PropertyDescriptor | undefined,
): void {
  if (descriptor === undefined) Reflect.deleteProperty(target, key);
  else Object.defineProperty(target, key, descriptor);
}

async function runReported(
  args: readonly string[],
  input = '',
  stdinTty = false,
): Promise<string> {
  const originalStdin = process.stdin;
  const originalExitCode = process.exitCode;
  const output: string[] = [];
  const stdin = Readable.from([input]);
  if (stdinTty)
    Object.defineProperty(stdin, 'isTTY', { configurable: true, value: true });
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: stdin,
  });
  const write = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    output.push(String(chunk));
    return true;
  });
  try {
    await runLocalCli(['node', 'kavrix', ...args]);
    return output.join('');
  } finally {
    write.mockRestore();
    Object.defineProperty(process, 'stdin', {
      configurable: true,
      value: originalStdin,
    });
    process.exitCode = originalExitCode;
  }
}
