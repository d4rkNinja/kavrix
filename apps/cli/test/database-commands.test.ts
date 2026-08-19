import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { buildLocalCli } from '../src/local-vault-cli.js';
import { LocalSecretInput, type LocalSecretKind } from '../src/local-secrets.js';

afterEach(() => vi.restoreAllMocks());

describe('database owner command composition', () => {
  it('registers the database and multi-vault owner surface without delete or secret arguments', () => {
    const program = buildLocalCli();
    const db = program.commands.find((command) => command.name() === 'db');
    const vault = program.commands.find((command) => command.name() === 'vault');
    expect(db?.commands.map((command) => command.name())).toEqual(
      expect.arrayContaining(['init', 'status', 'recovery']),
    );
    expect(
      db?.commands
        .find((command) => command.name() === 'recovery')
        ?.commands.map((command) => command.name()),
    ).toEqual(expect.arrayContaining(['create', 'verify', 'status', 'revoke', 'use']));
    expect(vault?.commands.map((command) => command.name())).toEqual(
      expect.arrayContaining(['create', 'list', 'status', 'rename']),
    );
    expect(vault?.commands.map((command) => command.name())).not.toContain('delete');
    expect(program.helpInformation()).not.toMatch(/--(?:passphrase|database-url)\s+</u);
  });

  it('executes file database, vault, and recovery commands through exact secret requests', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-database-commands-'));
    const dataFile = join(directory, 'database.kavrix');
    const keyFile = join(directory, 'owner.kavrix-db-key');
    const firstRecovery = join(directory, 'first.kavrix-db-recovery');
    const secondRecovery = join(directory, 'second.kavrix-db-recovery');
    const recoveredKey = join(directory, 'recovered.kavrix-db-key');
    const otherDataFile = join(directory, 'other-database.kavrix');
    const otherKeyFile = join(directory, 'other-owner.kavrix-db-key');
    const passphrase = 'correct horse battery staple';
    const requests: LocalSecretKind[][] = [];
    const queued: string[][] = [];
    const allArgv: string[][] = [];
    vi.spyOn(LocalSecretInput.prototype, 'read').mockImplementation(async (kinds) => {
      requests.push([...kinds]);
      const next = queued.shift();
      if (next === undefined) throw new Error('missing secret fixture');
      return next;
    });
    const output: string[] = [];
    const allOutput: string[] = [];
    const errors: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      output.push(String(chunk));
      allOutput.push(String(chunk));
      return true;
    });
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      errors.push(String(chunk));
      return true;
    });
    const execute = async (frames: string[], ...args: string[]) => {
      queued.push(frames);
      allArgv.push(['node', 'kavrix', ...args]);
      output.length = 0;
      await buildLocalCli().parseAsync(['node', 'kavrix', ...args]);
      return JSON.parse(output.join('')) as Record<string, unknown>;
    };
    output.length = 0;
    await buildLocalCli().parseAsync([
      'node',
      'kavrix',
      'db',
      'profile',
      'add',
      'local',
      '--config-dir',
      directory,
      '--datastore',
      'file',
      '--data-file',
      dataFile,
      '--key-file',
      keyFile,
    ]);
    const route = [
      '--profile',
      'local',
      '--profile-config-dir',
      directory,
      '--secrets-stdin',
    ];

    const initialized = await execute(
      ['private-database-label', passphrase, passphrase],
      'db',
      'init',
      ...route,
    );
    expect(initialized).toMatchObject({ initialized: true });
    const secretRequestsBeforeExistingInit = requests.length;
    await expect(
      buildLocalCli().parseAsync(['node', 'kavrix', 'db', 'init', ...route]),
    ).rejects.toMatchObject({ code: 'KEY_FILE_ALREADY_EXISTS' });
    expect(requests).toHaveLength(secretRequestsBeforeExistingInit);
    await execute(
      ['other-private-database-label', passphrase, passphrase],
      'db',
      'init',
      '--datastore',
      'file',
      '--data-file',
      otherDataFile,
      '--key-file',
      otherKeyFile,
      '--secrets-stdin',
    );
    const secretRequestsBeforeMismatch = requests.length;
    await expect(
      buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'db',
        'status',
        ...route,
        '--data-file',
        otherDataFile,
      ]),
    ).rejects.toMatchObject({ code: 'binding' });
    expect(requests).toHaveLength(secretRequestsBeforeMismatch);
    expect(await execute([passphrase], 'db', 'status', ...route)).toMatchObject({
      vaultCount: 0,
    });
    const created = await execute(
      [passphrase, 'private-project-label'],
      'vault',
      'create',
      ...route,
    );
    const vaultId = (created['created'] as { id: string }).id;
    expect(vaultId).toMatch(/^vault_/u);
    expect(await execute([passphrase], 'vault', 'list', ...route)).toMatchObject({
      vaults: [{ id: vaultId, label: '[REDACTED]' }],
    });
    expect(
      await execute([passphrase], 'vault', 'status', vaultId, ...route),
    ).toMatchObject({
      vaultId,
      revision: 0,
    });
    expect(
      await execute(
        [passphrase, 'renamed-project-label'],
        'vault',
        'rename',
        vaultId,
        ...route,
      ),
    ).toEqual({ renamed: true, vaultId });

    const first = await execute(
      [passphrase, passphrase, passphrase],
      'db',
      'recovery',
      'create',
      ...route,
      '--recovery-file',
      firstRecovery,
    );
    const secretRequestsBeforeExistingRecovery = requests.length;
    await expect(
      buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'db',
        'recovery',
        'create',
        ...route,
        '--recovery-file',
        firstRecovery,
      ]),
    ).rejects.toMatchObject({ code: 'KEY_FILE_ALREADY_EXISTS' });
    expect(requests).toHaveLength(secretRequestsBeforeExistingRecovery);
    const second = await execute(
      [passphrase, passphrase, passphrase],
      'db',
      'recovery',
      'create',
      ...route,
      '--recovery-file',
      secondRecovery,
    );
    expect(await execute([passphrase], 'db', 'recovery', 'status', ...route)).toEqual({
      active: 2,
      revoked: 0,
    });
    expect(
      await execute(
        [passphrase, passphrase],
        'db',
        'recovery',
        'verify',
        ...route,
        '--recovery-file',
        secondRecovery,
      ),
    ).toMatchObject({ valid: true, slotId: second['slotId'] });
    expect(
      await execute(
        [passphrase],
        'db',
        'recovery',
        'revoke',
        String(first['slotId']),
        ...route,
      ),
    ).toMatchObject({ revoked: true });
    const secretRequestsBeforeRecoveryMismatch = requests.length;
    await expect(
      buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'db',
        'recovery',
        'use',
        ...route,
        '--data-file',
        otherDataFile,
        '--recovery-file',
        secondRecovery,
        '--output-key-file',
        join(directory, 'mismatched-recovered-key'),
      ]),
    ).rejects.toMatchObject({ code: 'binding' });
    expect(requests).toHaveLength(secretRequestsBeforeRecoveryMismatch);
    expect(
      await execute(
        [passphrase, passphrase, passphrase],
        'db',
        'recovery',
        'use',
        ...route,
        '--recovery-file',
        secondRecovery,
        '--output-key-file',
        recoveredKey,
      ),
    ).toMatchObject({ keyFile: recoveredKey });
    expect(
      await execute([passphrase], 'db', 'status', ...route, '--key-file', recoveredKey),
    ).toMatchObject({ vaultCount: 1, activeRecoverySlots: 1 });

    expect(requests).toContainEqual(['label', 'new-passphrase', 'new-passphrase']);
    expect(requests).toContainEqual(['passphrase', 'label']);
    expect(requests).toContainEqual([
      'passphrase',
      'recovery-passphrase',
      'recovery-passphrase',
    ]);
    expect(requests).toContainEqual([
      'recovery-passphrase',
      'new-passphrase',
      'new-passphrase',
    ]);
    for (const path of [
      dataFile,
      keyFile,
      keyFile + '.database-anchor',
      firstRecovery,
      firstRecovery + '.database-anchor',
      secondRecovery,
      secondRecovery + '.database-anchor',
      recoveredKey,
      recoveredKey + '.database-anchor',
      otherDataFile,
      otherKeyFile,
      otherKeyFile + '.database-anchor',
      join(directory, 'datastore-profiles.json'),
    ]) {
      const serialized = await readFile(path, 'utf8');
      expect(serialized).not.toContain(passphrase);
      expect(serialized).not.toContain('private-database-label');
      expect(serialized).not.toContain('private-project-label');
      expect(serialized).not.toContain('renamed-project-label');
      expect(serialized).not.toContain('other-private-database-label');
    }
    expect(JSON.stringify(allArgv)).not.toContain(passphrase);
    expect(JSON.stringify(allArgv)).not.toContain('private-database-label');
    expect(JSON.stringify(allArgv)).not.toContain('private-project-label');
    expect(JSON.stringify(allArgv)).not.toContain('renamed-project-label');
    expect(JSON.stringify(allArgv)).not.toContain('other-private-database-label');
    expect(allOutput.join('')).not.toContain(passphrase);
    expect(allOutput.join('')).not.toContain('private-database-label');
    expect(allOutput.join('')).not.toContain('private-project-label');
    expect(allOutput.join('')).not.toContain('renamed-project-label');
    expect(allOutput.join('')).not.toContain('other-private-database-label');
    expect(errors.join('')).not.toContain(passphrase);
    expect(errors.join('')).not.toContain('private-database-label');
    expect(errors.join('')).not.toContain('private-project-label');
    expect(errors.join('')).not.toContain('renamed-project-label');
    expect(errors.join('')).not.toContain('other-private-database-label');
  });
});
