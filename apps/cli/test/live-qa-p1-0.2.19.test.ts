import { chmod, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { runCli } from './execution-helpers.js';

const directories: string[] = [];
const PASS = 'LiveQaPassphrase16+!';

afterEach(async () => {
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

async function scratch(label: string): Promise<string> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), `kavrix-0219-${label}-`),
  );
  directories.push(directory);
  return directory;
}

describe('0.2.19 live-qa P1: vault list/status --profile routing', () => {
  it('routes vault list/status through a legacy file profile paths', async () => {
    const directory = await scratch('vault-profile');
    const configDir = join(directory, 'config');
    const dataFile = join(directory, 'legacy.vault');
    const keyFile = join(directory, 'legacy.key');

    const init = await runCli(
      [
        'init',
        '--legacy',
        '--passphrase-stdin',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
      ],
      `${PASS}\n${PASS}\n`,
    );
    expect(init.exitCode).toBe(0);

    const put = await runCli(
      [
        'put',
        'demo/secret',
        '--passphrase-stdin',
        '--value-stdin',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
      ],
      `${PASS}\ncanary\n`,
    );
    expect(put.exitCode).toBe(0);

    const add = await runCli(
      [
        'db',
        'profile',
        'add',
        'legacy-file',
        '--config-dir',
        configDir,
        '--datastore',
        'file',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
      ],
      '',
    );
    expect(add.exitCode).toBe(0);

    const listed = await runCli(
      ['vault', 'list', '--profile', 'legacy-file', '--config-dir', configDir],
      '',
    );
    expect(listed.exitCode).toBe(0);
    const listBody = JSON.parse(listed.stdout) as {
      dataFile: string;
      vaults: string[];
    };
    expect(listBody.dataFile).toBe(dataFile);
    expect(listBody.vaults).toEqual(['default']);
    expect(listBody.dataFile).not.toBe('./kavrix.vault');

    const status = await runCli(
      ['vault', 'status', '--profile', 'legacy-file', '--config-dir', configDir],
      '',
    );
    expect(status.exitCode).toBe(0);
    const statusBody = JSON.parse(status.stdout) as {
      dataFile: string;
      vaultId: string;
    };
    expect(statusBody.dataFile).toBe(dataFile);
    expect(statusBody.vaultId).toBe('default');
  });

  it('still redirects top-level vault list on database-container profiles', async () => {
    const directory = await scratch('vault-redirect');
    const configDir = join(directory, 'config');
    const dataFile = join(directory, 'db.vault');
    const keyFile = join(directory, 'db.key');
    const init = await runCli(
      [
        'init',
        '--json',
        '--passphrase-stdin',
        '--no-tui',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
        '--profile-config-dir',
        configDir,
      ],
      `${PASS}\n${PASS}\n`,
    );
    expect(init.exitCode).toBe(0);
    const listed = await runCli(
      ['vault', 'list', '--profile-config-dir', configDir],
      '',
    );
    expect(listed.exitCode).not.toBe(0);
    expect(listed.stderr).toMatch(/db vault list/i);
  });
});

describe('0.2.19 live-qa P1: doctor --heal --dry-run fail-closed', () => {
  it('does not report healthy dry-run when explicit vault target is invalid', async () => {
    const directory = await scratch('dry-run-false');
    const dataFile = join(directory, 'not-a-vault.vault');
    const keyFile = join(directory, 'not-a-key.key');
    await writeFile(dataFile, 'corrupt-not-a-vault\n', { mode: 0o600 });
    await writeFile(keyFile, 'corrupt-not-a-key\n', { mode: 0o600 });
    await chmod(dataFile, 0o600);
    await chmod(keyFile, 0o600);

    const dryRun = await runCli(
      [
        'doctor',
        '--heal',
        '--dry-run',
        '--passphrase-stdin',
        '--json',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
      ],
      `${PASS}\n`,
    );
    expect(dryRun.exitCode).not.toBe(0);
    if (dryRun.stdout.trim().length > 0) {
      const body = JSON.parse(dryRun.stdout) as { healthy?: boolean };
      expect(body.healthy).not.toBe(true);
    } else {
      expect(dryRun.stderr.toLowerCase()).toMatch(/invalid|unsafe|not initialized/);
    }

    const apply = await runCli(
      [
        'doctor',
        '--heal',
        '--passphrase-stdin',
        '--json',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
      ],
      `${PASS}\n`,
    );
    expect(apply.exitCode).not.toBe(0);
  });
});

describe('0.2.19 live-qa P1: run --secret protected destination help/error', () => {
  it('documents a safe destination example and names protected ENV', async () => {
    const help = await runCli(['run', '--help'], '');
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toMatch(/MYSECRET/);
    expect(help.stdout).not.toMatch(/--secret ENV=/);
    expect(help.stdout).not.toMatch(/ENV=NAME/);

    const directory = await scratch('run-env');
    const configDir = join(directory, 'config');
    const dataFile = join(directory, 'vault.db');
    const keyFile = join(directory, 'owner.key');
    const init = await runCli(
      [
        'init',
        '--json',
        '--passphrase-stdin',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
        '--profile-config-dir',
        configDir,
      ],
      `${PASS}\n${PASS}\n`,
    );
    expect(init.exitCode).toBe(0);
    const put = await runCli(
      [
        'put',
        'demo',
        '--passphrase-stdin',
        '--value-stdin',
        '--profile-config-dir',
        configDir,
      ],
      `${PASS}\ncanary\n`,
    );
    expect(put.exitCode).toBe(0);

    const denied = await runCli(
      [
        'run',
        '--passphrase-stdin',
        '--profile-config-dir',
        configDir,
        '--secret',
        'ENV=demo',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      `${PASS}\n`,
    );
    expect(denied.exitCode).toBe(14);
    expect(denied.stderr).toMatch(/ENV/);
    expect(denied.stderr).toMatch(/protected/i);
  });
});

describe('0.2.19 live-qa Jr P2: matching bound-profile path overrides', () => {
  it('accepts absolute path overrides that match the bound profile', async () => {
    const directory = await scratch('bound-match');
    const configDir = join(directory, 'config');
    const dataFile = join(directory, 'rel.vault');
    const keyFile = join(directory, 'rel.key');
    const init = await runCli(
      [
        'init',
        '--json',
        '--passphrase-stdin',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
        '--profile-config-dir',
        configDir,
      ],
      `${PASS}\n${PASS}\n`,
    );
    expect(init.exitCode).toBe(0);

    const put = await runCli(
      [
        'put',
        'x',
        '--passphrase-stdin',
        '--value-stdin',
        '--profile-config-dir',
        configDir,
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
      ],
      `${PASS}\nval\n`,
    );
    expect(put.exitCode).toBe(0);
    expect(JSON.parse(put.stdout)).toMatchObject({ saved: true, name: 'x' });
  });

  it('rejects non-matching path overrides with a clear bound-profile error', async () => {
    const directory = await scratch('bound-mismatch');
    const configDir = join(directory, 'config');
    const dataFile = join(directory, 'rel.vault');
    const keyFile = join(directory, 'rel.key');
    const other = join(directory, 'other.vault');
    await writeFile(other, 'x', { mode: 0o600 });
    const init = await runCli(
      [
        'init',
        '--json',
        '--passphrase-stdin',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
        '--profile-config-dir',
        configDir,
      ],
      `${PASS}\n${PASS}\n`,
    );
    expect(init.exitCode).toBe(0);

    const put = await runCli(
      [
        'put',
        'x',
        '--passphrase-stdin',
        '--value-stdin',
        '--profile-config-dir',
        configDir,
        '--data-file',
        other,
        '--key-file',
        keyFile,
      ],
      `${PASS}\nval\n`,
    );
    expect(put.exitCode).not.toBe(0);
    expect(put.stderr).toMatch(
      /Omit (?:path overrides|those flags)|bound(?: database-container)? profile/i,
    );
    expect(put.stderr).not.toMatch(/invalid or unsafe/i);
  });
});
