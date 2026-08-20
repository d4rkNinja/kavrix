import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

const aclMocks = vi.hoisted(() => ({
  set: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
  verifyDirectory: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
  verify: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
}));

vi.mock('@kavrix/key-files/windows-acl', () => ({
  setWindowsUserOnlyAcl: aclMocks.set,
  verifyWindowsDirectoryAcl: aclMocks.verifyDirectory,
  verifyWindowsUserOnlyAcl: aclMocks.verify,
}));

import { buildLocalCli } from '../src/local-vault-cli.js';

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
  } finally {
    write.mockRestore();
    Object.defineProperty(process, 'stdin', {
      configurable: true,
      value: originalStdin,
    });
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

describe('local vault CLI active coverage', () => {
  it('runs the local vault command lifecycle with safe machine-readable output', async () => {
    const value = await target();
    expect(await initVault(value)).toMatchObject({
      datastore: 'file',
      dataFile: value.data,
      keyFile: value.key,
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
      await runCli(['list', ...route(value), '--passphrase-stdin'], `${PASSPHRASE}\n`),
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
    expect(viewed.records.every((record) => record.value === '[REDACTED]')).toBe(true);

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

  it('rejects invalid input before decrypting or mutating the local vault', async () => {
    const value = await target();
    await initVault(value);
    await put(value, 'existing', ALPHA_VALUE);

    await expect(
      runCli(
        ['put', 'constructor', ...route(value), '--passphrase-stdin', '--value-stdin'],
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
        ['doctor', 'health', ...route(value), '--passphrase-stdin', '--accept-current'],
        `${PASSPHRASE}\n`,
      ),
    ) as { healthy: boolean; autoHealed: string[] };
    expect(accepted.healthy).toBe(false);
    expect(accepted.autoHealed).toContain('revision-anchor-initialized');
    expect(await access(`${value.key}.anchor`)).toBeUndefined();
  });
});
