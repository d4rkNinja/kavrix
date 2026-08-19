import { access, mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readDatabaseKeyFileBinding } from '@kavrix/key-files';
import { FileEncryptedDatabaseStore, MongoLocalVaultStore } from '@kavrix/storage';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { buildLocalCli } from '../src/local-vault-cli.js';
import { DatastoreProfileRegistry } from '../src/datastore-profiles.js';
import { DatabaseSession } from '../src/database-session.js';
import { LocalSecretInput, type LocalSecretKind } from '../src/local-secrets.js';

afterEach(() => vi.restoreAllMocks());

describe('database owner command composition', () => {
  it('registers the database and multi-vault owner surface without delete or secret arguments', () => {
    const program = buildLocalCli();
    const db = program.commands.find((command) => command.name() === 'db');
    const vault = program.commands.find((command) => command.name() === 'vault');
    const databaseVault = db?.commands.find((command) => command.name() === 'vault');
    expect(db?.commands.map((command) => command.name())).toEqual(
      expect.arrayContaining(['init', 'status', 'recovery', 'vault']),
    );
    expect(
      db?.commands
        .find((command) => command.name() === 'recovery')
        ?.commands.map((command) => command.name()),
    ).toEqual(expect.arrayContaining(['create', 'verify', 'status', 'revoke', 'use']));
    expect(databaseVault?.commands.map((command) => command.name())).toEqual(
      expect.arrayContaining(['create', 'list', 'status', 'rename']),
    );
    expect(databaseVault?.commands.map((command) => command.name())).not.toContain(
      'delete',
    );
    expect(vault?.commands.map((command) => command.name())).toEqual([
      'list',
      'status',
    ]);
    expect(
      vault?.commands.find((command) => command.name() === 'status')?.usage(),
    ).toBe('[options]');
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
    ).rejects.toMatchObject({ code: 'binding' });
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
      'db',
      'vault',
      'create',
      ...route,
    );
    const vaultId = (created['created'] as { id: string }).id;
    expect(vaultId).toMatch(/^vault_/u);
    const restoreTty = setStdoutTty(true);
    try {
      expect(
        await execute([passphrase], 'db', 'vault', 'list', ...route),
      ).toMatchObject({
        vaults: [{ id: vaultId, label: '[REDACTED]' }],
      });
      expect(
        await execute([passphrase], 'db', 'vault', 'status', vaultId, ...route),
      ).toMatchObject({
        vaultId,
        label: '[REDACTED]',
        revision: 0,
      });
    } finally {
      restoreTty();
    }
    expect(
      await execute(
        [passphrase, 'renamed-project-label'],
        'db',
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

  it('rolls back database artifacts when initial profile binding publication fails', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-profile-publish-'));
    const dataFile = join(directory, 'database.kavrix');
    const keyFile = join(directory, 'owner.kavrix-db-key');
    const passphrase = 'correct horse battery staple';
    vi.spyOn(LocalSecretInput.prototype, 'read').mockResolvedValue([
      'private-profile-label',
      passphrase,
      passphrase,
    ]);
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    await buildLocalCli().parseAsync([
      'node',
      'kavrix',
      'db',
      'profile',
      'add',
      'failing',
      '--config-dir',
      directory,
      '--datastore',
      'file',
      '--data-file',
      dataFile,
      '--key-file',
      keyFile,
    ]);
    vi.spyOn(
      DatastoreProfileRegistry.prototype,
      'bindDatabaseIdForInitialization',
    ).mockResolvedValue({
      status: 'not-published',
      error: new Error('profile-publication-secret-canary'),
    } as never);
    let thrown: unknown;
    try {
      await buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'db',
        'init',
        '--profile',
        'failing',
        '--profile-config-dir',
        directory,
        '--secrets-stdin',
      ]);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ code: 'authentication' });
    expect(serializeThrown(thrown)).not.toContain('profile-publication-secret-canary');
    for (const path of [dataFile, keyFile, keyFile + '.database-anchor']) {
      await expect(access(path)).rejects.toMatchObject({ code: 'ENOENT' });
    }
  });

  it('retains and reopens database artifacts when profile publication is uncertain', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-profile-uncertain-'));
    const dataFile = join(directory, 'database.kavrix');
    const keyFile = join(directory, 'owner.kavrix-db-key');
    const passphrase = 'correct horse battery staple';
    vi.spyOn(LocalSecretInput.prototype, 'read').mockResolvedValue([
      'private-profile-label',
      passphrase,
      passphrase,
    ]);
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    await buildLocalCli().parseAsync([
      'node',
      'kavrix',
      'db',
      'profile',
      'add',
      'uncertain',
      '--config-dir',
      directory,
      '--datastore',
      'file',
      '--data-file',
      dataFile,
      '--key-file',
      keyFile,
    ]);
    vi.spyOn(
      DatastoreProfileRegistry.prototype,
      'bindDatabaseIdForInitialization',
    ).mockResolvedValue({
      status: 'publication-uncertain',
      publication: Object.freeze({}),
      error: new Error('profile-uncertain-secret-canary'),
    } as never);
    let thrown: unknown;
    try {
      await buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'db',
        'init',
        '--profile',
        'uncertain',
        '--profile-config-dir',
        directory,
        '--secrets-stdin',
      ]);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ code: 'ambiguous-commit' });
    expect(serializeThrown(thrown)).not.toContain('profile-uncertain-secret-canary');
    for (const path of [dataFile, keyFile, keyFile + '.database-anchor']) {
      await expect(access(path)).resolves.toBeUndefined();
    }
    const binding = await readDatabaseKeyFileBinding(keyFile);
    const store = await FileEncryptedDatabaseStore.open(dataFile);
    const reopened = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: new TextEncoder().encode(passphrase),
      expectedDatabaseId: binding.databaseId,
    });
    expect(reopened.databaseId).toBe(binding.databaseId);
    await reopened.close();
  });

  it('preserves executable legacy vault list and status output contracts', async () => {
    vi.spyOn(LocalSecretInput.prototype, 'read').mockResolvedValue([
      'mongodb://localhost/legacy',
    ]);
    const close = vi.fn(async () => undefined);
    const store = {
      listVaultIds: vi.fn(async () => ['legacy']),
      get: vi.fn(async () => ({
        id: 'legacy',
        revision: 4,
        currentKeyVersion: 2,
        keySlot: {
          id: 'slot',
          type: 'portable-key',
          state: 'active',
          keyVersion: 2,
          createdAt: '2026-08-19T00:00:00.000Z',
        },
        recoverySlots: [],
        createdAt: '2026-08-19T00:00:00.000Z',
        updatedAt: '2026-08-19T01:00:00.000Z',
      })),
      close,
    };
    vi.spyOn(MongoLocalVaultStore, 'connect').mockResolvedValue(
      store as unknown as MongoLocalVaultStore,
    );
    const output: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      output.push(String(chunk));
      return true;
    });
    const execute = async (...args: string[]) => {
      output.length = 0;
      await buildLocalCli().parseAsync(['node', 'kavrix', ...args]);
      return JSON.parse(output.join('')) as Record<string, unknown>;
    };
    await expect(
      execute('vault', 'list', '--database-url-stdin', '--database', 'legacy'),
    ).resolves.toEqual({
      database: 'legacy',
      collection: 'kavrix_vaults',
      vaults: ['legacy'],
    });
    await expect(
      execute(
        'vault',
        'status',
        '--vault',
        'legacy',
        '--database-url-stdin',
        '--database',
        'legacy',
      ),
    ).resolves.toEqual({
      database: 'legacy',
      collection: 'kavrix_vaults',
      vaultId: 'legacy',
      revision: 4,
      currentKeyVersion: 2,
      keySlot: {
        id: 'slot',
        type: 'portable-key',
        state: 'active',
        keyVersion: 2,
        createdAt: '2026-08-19T00:00:00.000Z',
      },
      recoverySlots: { total: 0, active: 0, revoked: 0 },
      createdAt: '2026-08-19T00:00:00.000Z',
      updatedAt: '2026-08-19T01:00:00.000Z',
    });
    expect(close).toHaveBeenCalledTimes(2);
  });
});

function serializeThrown(value: unknown, seen = new Set<unknown>()): string {
  if (value === null || typeof value !== 'object') return String(value);
  if (seen.has(value)) return '[cycle]';
  seen.add(value);
  return Reflect.ownKeys(value)
    .map((key) => {
      const label = typeof key === 'symbol' ? (key.description ?? 'symbol') : key;
      return `${label}:${serializeThrown(Reflect.get(value, key), seen)}`;
    })
    .join('|');
}

function setStdoutTty(value: boolean): () => void {
  const descriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  Object.defineProperty(process.stdout, 'isTTY', { configurable: true, value });
  return () => {
    if (descriptor === undefined) delete (process.stdout as { isTTY?: boolean }).isTTY;
    else Object.defineProperty(process.stdout, 'isTTY', descriptor);
  };
}
