import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';

const PASSPHRASE = `${EXEC_PASSPHRASE}\n`;

describe('launch P1 follow-ups', () => {
  let fixture: ExecutionFixture | undefined;
  const directories: string[] = [];

  afterEach(async () => {
    if (fixture !== undefined) {
      await destroyFixture(fixture);
      fixture = undefined;
    }
    const pending = directories.splice(0);
    await Promise.all(
      pending.map((directory) => rm(directory, { force: true, recursive: true })),
    );
  });

  async function scratch(label: string): Promise<string> {
    const directory = await createSecureTestDirectory(
      join(tmpdir(), `kavrix-p1-${label}-`),
    );
    directories.push(directory);
    return directory;
  }

  it('documents db ping as mongodb-only without a file default in help', async () => {
    const help = await runCli(['db', 'ping', '--help'], '');
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toMatch(/must be mongodb/i);
    expect(help.stdout).not.toMatch(/\(default:\s*"file"\)/u);
  });

  it('emits JSON healthy:false exit 15 from root doctor health on auth fail', async () => {
    fixture = await createExecutionFixture({});
    const result = await runCli(
      ['doctor', 'health', '--passphrase-stdin', '--json', ...fixture.routingArgs],
      'wrong-passphrase!!!!\n',
    );
    expect(result.exitCode).toBe(15);
    const report = JSON.parse(result.stdout) as {
      healthy: boolean;
      manualRecoveryRequired: string[];
    };
    expect(report.healthy).toBe(false);
    expect(report.manualRecoveryRequired.join(' ')).toMatch(/authentication failed/i);
  });

  it('treats missing recovery as warning-only for legacy doctor health', async () => {
    const directory = await scratch('legacy-health');
    const data = join(directory, 'legacy.vault');
    const key = join(directory, 'legacy.key');
    const init = await runCli(
      [
        'init',
        '--legacy',
        '--json',
        '--passphrase-stdin',
        '--datastore',
        'file',
        '--data-file',
        data,
        '--key-file',
        key,
      ],
      `${PASSPHRASE}${PASSPHRASE}`,
    );
    expect(init.exitCode).toBe(0);
    const health = await runCli(
      [
        'doctor',
        'health',
        '--passphrase-stdin',
        '--json',
        '--datastore',
        'file',
        '--data-file',
        data,
        '--key-file',
        key,
      ],
      PASSPHRASE,
    );
    expect(health.exitCode).toBe(0);
    const report = JSON.parse(health.stdout) as {
      healthy: boolean;
      checks: Array<{ name: string; status: string }>;
    };
    expect(report.healthy).toBe(true);
    expect(report.checks).toContainEqual(
      expect.objectContaining({ name: 'recovery-slots', status: 'warning' }),
    );
  });

  it('aligns unbound list/put messages with run (exit 14)', async () => {
    const directory = await scratch('unbound');
    const data = join(directory, 'x.v');
    const key = join(directory, 'x.k');
    const configDir = join(directory, 'config');
    const add = await runCli(
      [
        'db',
        'profile',
        'add',
        'work',
        '--datastore',
        'file',
        '--data-file',
        data,
        '--key-file',
        key,
        '--profile-config-dir',
        configDir,
      ],
      '',
    );
    expect(add.exitCode).toBe(0);
    expect(
      (
        await runCli(
          ['db', 'profile', 'use', 'work', '--profile-config-dir', configDir],
          '',
        )
      ).exitCode,
    ).toBe(0);
    const list = await runCli(
      ['list', '--passphrase-stdin', '--profile-config-dir', configDir],
      PASSPHRASE,
    );
    expect(list.exitCode).toBe(14);
    expect(list.stderr).toContain('not bound to a database');
    expect(list.stderr).toContain('db init');
    const put = await runCli(
      [
        'put',
        'X',
        '--passphrase-stdin',
        '--value-stdin',
        '--profile-config-dir',
        configDir,
      ],
      `${PASSPHRASE}value\n`,
    );
    expect(put.exitCode).toBe(14);
    expect(put.stderr).toContain('not bound to a database');
  });

  it.skipIf(process.platform === 'win32')(
    'rolls back stuck default profile after EACCES init so retry succeeds',
    async () => {
      const directory = await scratch('eacces');
      const configDir = join(directory, 'config');
      const readonly = await mkdtemp(join(tmpdir(), 'kavrix-p1-ro-'));
      directories.push(readonly);
      await chmod(readonly, 0o555);
      const failed = await runCli(
        [
          'init',
          '--json',
          '--passphrase-stdin',
          '--data-file',
          join(readonly, 'v'),
          '--key-file',
          join(readonly, 'k'),
          '--profile-config-dir',
          configDir,
        ],
        `${PASSPHRASE}${PASSPHRASE}`,
      );
      expect(failed.exitCode).not.toBe(0);
      expect(failed.stderr).toMatch(/removed so you can retry/i);
      const listed = await runCli(
        ['db', 'profile', 'list', '--profile-config-dir', configDir],
        '',
      );
      expect(listed.stdout).toContain('"profiles":[]');
      const retry = await runCli(
        [
          'init',
          '--json',
          '--passphrase-stdin',
          '--data-file',
          join(directory, 'ok.v'),
          '--key-file',
          join(directory, 'ok.k'),
          '--profile-config-dir',
          configDir,
        ],
        `${PASSPHRASE}${PASSPHRASE}`,
      );
      expect(retry.exitCode).toBe(0);
      await chmod(readonly, 0o755);
    },
  );

  it('rejects empty secrets at run with a clear message', async () => {
    fixture = await createExecutionFixture({});
    const put = await runCli(
      [
        'put',
        'EMPTY',
        '--passphrase-stdin',
        '--value-stdin-base64',
        ...fixture.routingArgs,
      ],
      `${PASSPHRASE}\n`,
    );
    expect(put.exitCode).toBe(0);
    const run = await runCli(
      [
        'run',
        '--passphrase-stdin',
        '--secret',
        'X=EMPTY',
        ...fixture.routingArgs,
        '--',
        'true',
      ],
      PASSPHRASE,
    );
    expect(run.exitCode).toBe(14);
    expect(run.stderr).toContain('empty value');
    expect(run.stderr).not.toContain('protected runtime variable');
  });

  it('points top-level recovery at db recovery for database-container profiles', async () => {
    fixture = await createExecutionFixture({});
    const status = await runCli(
      ['recovery', 'status', '--json', ...fixture.routingArgs],
      '',
    );
    expect(status.exitCode).toBe(1);
    expect(status.stderr).toContain('db recovery');
    expect(status.stderr).not.toContain('Vault is not initialized');
  });

  it('documents --database-url-stdin in frames put', async () => {
    const frames = await runCli(['frames', 'put'], '');
    expect(frames.exitCode).toBe(0);
    expect(frames.stdout).toContain('--database-url-stdin');
  });
});
