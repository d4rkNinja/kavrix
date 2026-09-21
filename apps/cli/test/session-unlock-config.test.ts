import { chmod, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

const directories: string[] = [];

afterEach(async () => {
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) =>
      rm(directory, { force: true, recursive: true }).catch(() => undefined),
    ),
  );
});

import { databaseIdSchema, profileIdSchema, vaultIdSchema } from '@kavrix/schemas';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { runCli } from './execution-helpers.js';
import { classifyCliFailure } from '../src/cli-errors.js';
import { DatastoreProfileRegistry } from '../src/datastore-profiles.js';
import { SessionUnlockError } from '../src/session-unlock.js';
import { ensureKavrixConfig, getKavrixConfigDir } from '../src/kavrix-config.js';

describe('session unlock error classification', () => {
  it('maps session unlock failure codes to stable exit codes', () => {
    const cases: ReadonlyArray<{
      readonly code: SessionUnlockError['code'];
      readonly exitCode: number;
    }> = [
      { code: 'unavailable', exitCode: 14 },
      { code: 'expired', exitCode: 14 },
      { code: 'keychain-unavailable', exitCode: 15 },
      { code: 'tampered', exitCode: 16 },
    ];
    for (const { code, exitCode } of cases) {
      const result = classifyCliFailure(
        new SessionUnlockError(code, `session: ${code}.`),
      );
      expect(result.exitCode, code).toBe(exitCode);
      expect(result.message).toContain(code);
    }
  });
});

describe('--session passphrase resolution fail-closed paths', () => {
  it('list --session on a profile without a session fails with the enable hint', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-session-miss-'),
    );
    directories.push(directory);
    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    await registry.add({
      id: profileIdSchema.parse('default'),
      datastore: 'file',
      dataFile: join(directory, 'data.vault'),
      keyFile: join(directory, 'owner.key'),
      databaseId: databaseIdSchema.parse('db_sessionmiss'),
      defaultVaultId: vaultIdSchema.parse('vault_sessionmiss'),
    });
    await registry.use(profileIdSchema.parse('default'));

    const result = await runCli(
      [
        'list',
        '--profile',
        'default',
        '--profile-config-dir',
        configDir,
        '--session',
        '--json',
      ],
      '',
    );
    expect(result.code).not.toBe(0);
    // Linux CI without secret-tool reports the store as unavailable;
    // Windows reports no-session. Both fail closed with guidance.
    expect(result.stderr).toMatch(/no session unlock|credential store is unavailable/i);
  });
});

describe('ensureKavrixConfig self-heal', () => {
  it('session enable rejects an out-of-range TTL without touching the keychain', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-session-ttl-'),
    );
    directories.push(directory);
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: join(directory, 'config'),
    });
    await registry.add({
      id: profileIdSchema.parse('default'),
      datastore: 'file',
      dataFile: join(directory, 'data.vault'),
      keyFile: join(directory, 'owner.key'),
    });
    await registry.use(profileIdSchema.parse('default'));

    const result = await runCli(
      [
        'session',
        'enable',
        '--profile',
        'default',
        '--profile-config-dir',
        join(directory, 'config'),
        '--ttl-hours',
        '0',
        '--passphrase-stdin',
        '--json',
      ],
      ['anything'],
    );
    expect(result.code).not.toBe(0);
    expect(result.stderr).toMatch(/--ttl-hours/i);
  });

  it('session status with an unknown profile fails with guidance', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-session-unknown-'),
    );
    directories.push(directory);
    const result = await runCli(
      [
        'session',
        'status',
        '--profile',
        'nope',
        '--profile-config-dir',
        join(directory, 'config'),
        '--json',
      ],
      '',
    );
    expect(result.code).not.toBe(0);
    expect(result.stderr.length).toBeGreaterThan(0);
  });

  it('mongodb list --session fails closed when no session exists', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-session-mongo-'),
    );
    directories.push(directory);
    const configDir = join(directory, 'config');
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: configDir,
    });
    await registry.add({
      id: profileIdSchema.parse('mongo'),
      datastore: 'mongodb',
      database: 'kavrix_qa',
      databaseCollection: 'kavrix_databases',
      vaultCollection: 'kavrix_vaults',
      keyFile: join(directory, 'mongo.key'),
      databaseId: databaseIdSchema.parse('db_mongoqa'),
      defaultVaultId: vaultIdSchema.parse('vault_mongoqa'),
    });
    await registry.use(profileIdSchema.parse('mongo'));

    // Fails at session resolution before any MongoDB connection is attempted.
    const result = await runCli(
      [
        'list',
        '--profile',
        'mongo',
        '--profile-config-dir',
        configDir,
        '--session',
        '--json',
      ],
      '',
    );
    expect(result.code).not.toBe(0);
    expect(result.stderr).toMatch(/no session unlock|credential store is unavailable/i);
  });

  it('session status without any profile fails with guidance', async () => {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), 'kavrix-session-noprofile-'),
    );
    directories.push(directory);
    const result = await runCli(
      [
        'session',
        'status',
        '--profile-config-dir',
        join(directory, 'config'),
        '--json',
      ],
      '',
    );
    expect(result.code).not.toBe(0);
    expect(result.stderr).toMatch(/no datastore profile is selected/i);
  });

  afterEach(async () => {
    // Leave the worker's isolated kavrix home hardened for later tests.
    const { hardenExistingSecureDirectory } = await import('@kavrix/key-files');
    await hardenExistingSecureDirectory(getKavrixConfigDir()).catch(() => undefined);
  });

  it('hardens an existing unsafe kavrix home and config reference', async () => {
    // The vitest isolated-home setup redirects HOME/USERPROFILE per worker,
    // so getKavrixConfigDir() is a hermetic per-run directory.
    const kavrixHome = getKavrixConfigDir();
    await mkdir(kavrixHome, { recursive: true, mode: 0o755 });
    if (process.platform !== 'win32') {
      await chmod(kavrixHome, 0o755);
    }
    const configPath = join(kavrixHome, 'config.toml');
    await writeFile(configPath, '# stale unsafe reference\n', { mode: 0o644 });
    if (process.platform !== 'win32') {
      await chmod(configPath, 0o644);
    }

    const path = await ensureKavrixConfig();
    expect(path).toContain('.kavrix');
    if (process.platform !== 'win32') {
      expect((await stat(kavrixHome)).mode & 0o777).toBe(0o700);
      expect((await stat(configPath)).mode & 0o777).toBe(0o600);
    }
  });

  it('succeeds on a fresh home and creates the onboarding reference', async () => {
    const kavrixHome = getKavrixConfigDir();
    await rm(kavrixHome, { force: true, recursive: true }).catch(() => undefined);

    const path = await ensureKavrixConfig();
    expect(path.endsWith('config.toml')).toBe(true);
    const content = await readFile(path, 'utf8');
    expect(content).toMatch(/Kavrix/);
  });
});
