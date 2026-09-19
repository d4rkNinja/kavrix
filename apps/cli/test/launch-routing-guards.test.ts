import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { LocalCliError } from '../src/cli-error.js';
import {
  CONFLICTING_PROFILE_CONFIG_DIR_MESSAGE,
  resolveProfileConfigDirectory,
} from '../src/profile-config-directory.js';
import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  passphraseFrame,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';

const PASSPHRASE = `${EXEC_PASSPHRASE}\n`;

describe('resolveProfileConfigDirectory', () => {
  it('accepts either spelling alone', () => {
    expect(resolveProfileConfigDirectory('/a', undefined)).toBe('/a');
    expect(resolveProfileConfigDirectory(undefined, '/b')).toBe('/b');
    expect(resolveProfileConfigDirectory(undefined, undefined)).toBeUndefined();
  });

  it('rejects when both spellings are supplied', () => {
    expect(() => resolveProfileConfigDirectory('/a', '/b')).toThrow(LocalCliError);
    expect(() => resolveProfileConfigDirectory('/same', '/same')).toThrow(
      CONFLICTING_PROFILE_CONFIG_DIR_MESSAGE,
    );
  });
});

describe('launch routing guards', () => {
  let fixture: ExecutionFixture | undefined;

  afterEach(async () => {
    if (fixture !== undefined) {
      await destroyFixture(fixture);
      fixture = undefined;
    }
  });

  it('rejects conflicting --config-dir and --profile-config-dir on put', async () => {
    fixture = await createExecutionFixture({ 'demo/token': 'value' });
    const left = await mkdtemp(join(tmpdir(), 'kavrix-cfg-a-'));
    const right = await mkdtemp(join(tmpdir(), 'kavrix-cfg-b-'));
    const result = await runCli(
      [
        'put',
        'demo/token',
        ...fixture.routingArgs,
        '--config-dir',
        left,
        '--profile-config-dir',
        right,
        '--passphrase-stdin',
        '--value-stdin',
        '--json',
      ],
      `${passphraseFrame()}replacement\n`,
    );
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain(CONFLICTING_PROFILE_CONFIG_DIR_MESSAGE);
  });

  it('refuses init --legacy with --config-dir', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-legacy-cfg-'));
    const data = join(directory, 'vault.data');
    const key = join(directory, 'vault.key');
    const configDir = join(directory, 'profiles');
    await mkdir(configDir, { recursive: true });
    const result = await runCli(
      [
        'init',
        '--legacy',
        '--datastore',
        'file',
        '--data-file',
        data,
        '--key-file',
        key,
        '--config-dir',
        configDir,
        '--passphrase-stdin',
      ],
      `${PASSPHRASE}${PASSPHRASE}`,
    );
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain('Legacy init (--legacy) does not create or bind a datastore profile');
    expect(result.stderr).toContain('--config-dir');
  });

  it('refuses bare db ping without --datastore mongodb', async () => {
    const result = await runCli(['db', 'ping', '--database-url-stdin'], 'mongodb://127.0.0.1/x\n');
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain('db ping requires --datastore mongodb');
  });

  it('rejects explicit --datastore mongodb when an ambient bound file profile is current', async () => {
    fixture = await createExecutionFixture({ 'demo/token': 'value' });
    const configDirIndex = fixture.routingArgs.indexOf('--profile-config-dir');
    expect(configDirIndex).toBeGreaterThanOrEqual(0);
    const configDir = fixture.routingArgs[configDirIndex + 1]!;
    // Select ambient current profile, then omit --profile on the put.
    const use = await runCli(
      ['db', 'profile', 'use', 'exec', '--profile-config-dir', configDir],
      '',
    );
    expect(use.exitCode).toBe(0);

    const result = await runCli(
      [
        'put',
        'demo/token',
        '--profile-config-dir',
        configDir,
        '--datastore',
        'mongodb',
        '--passphrase-stdin',
        '--value-stdin',
        '--json',
      ],
      `${passphraseFrame()}x\n`,
    );
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toMatch(/Explicit --datastore mongodb conflicts with the current bound profile/u);
  });
});

describe('run --no-config help', () => {
  it('documents skipping project configuration', async () => {
    const result = await runCli(['run', '--help'], '');
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('--no-config');
    expect(result.stdout.toLowerCase()).toMatch(/skip project configuration|ignore any project/u);
  });
});
