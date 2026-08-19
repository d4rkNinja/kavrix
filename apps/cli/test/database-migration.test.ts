import { createHash } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, rename, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  encryptPayload,
  unlockPortableKeySlotBytes,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  databaseRevisionAnchorPath,
  deleteSecureFile,
  readPortableKeyFile,
  writeRevisionAnchor,
} from '@kavrix/key-files';
import {
  FileEncryptedDatabaseStore,
  FileLocalVaultStore,
  MongoEncryptedDatabaseStore,
  EncryptedDatabaseStoreError,
  type CreateVaultInput,
  type DeleteVaultInput,
  type EncryptedDatabaseStore,
  type UpdateVaultInput,
} from '@kavrix/storage';
import {
  associatedDataSchema,
  canonicalJson,
  localVaultDocumentSchema,
  localVaultPayloadSchema,
  sha256DigestSchema,
  vaultRevisionSchema,
  type DatabaseVaultDocument,
  type EncryptedDatabaseDocument,
  type LocalVaultDocument,
  type VaultId,
} from '@kavrix/schemas';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  DatabaseMigrationError,
  migrateLegacyVaultToDatabase,
} from '../src/database-migration.js';
import { databaseMigrationSecretKinds } from '../src/database-migration-command.js';
import { DatabaseSession } from '../src/database-session.js';
import { DatastoreProfileRegistry } from '../src/datastore-profiles.js';
import { buildLocalCli } from '../src/local-vault-cli.js';
import { LocalSecretInput } from '../src/local-secrets.js';

const SOURCE_PASSPHRASE = 'legacy passphrase';
const DESTINATION_PASSPHRASE = Buffer.from('database passphrase', 'utf8');

afterEach(() => vi.restoreAllMocks());

describe('legacy version 2 database migration', () => {
  it('constructs exactly the seven-frame widest migration request', () => {
    expect(databaseMigrationSecretKinds('mongodb', 'mongodb', true)).toEqual([
      'database-url',
      'database-url',
      'passphrase',
      'new-passphrase',
      'new-passphrase',
      'label',
      'label',
    ]);
  });

  it('routes an existing mocked Mongo destination through the explicit command', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-migrate-mongo-'));
    const sourceDataFile = join(directory, 'source.vault');
    const sourceKeyFile = join(directory, 'source.key');
    const destinationKeyFile = join(directory, 'destination.key');
    await createLegacySource(sourceDataFile, sourceKeyFile, {
      mongo: { value: 'mocked-mongo-canary', updatedAt: '' },
    });
    vi.restoreAllMocks();
    const backend = new MemoryDatabaseBackend();
    const initialized = await DatabaseSession.initialize({
      store: backend.open(),
      keyFile: destinationKeyFile,
      passphrase: DESTINATION_PASSPHRASE,
      label: 'mongo destination',
    });
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: directory,
    });
    await registry.add({
      id: 'legacy' as never,
      datastore: 'file',
      dataFile: sourceDataFile,
      keyFile: sourceKeyFile,
    });
    await registry.add({
      id: 'mongo' as never,
      datastore: 'mongodb',
      databaseId: initialized.databaseId,
      database: 'kavrix',
      databaseCollection: 'databases',
      vaultCollection: 'vaults',
      keyFile: destinationKeyFile,
    });
    vi.spyOn(MongoEncryptedDatabaseStore, 'connect').mockImplementation(
      async () => backend.open() as never,
    );
    vi.spyOn(LocalSecretInput.prototype, 'read').mockResolvedValue([
      'mongodb://user:password@example.invalid/kavrix',
      SOURCE_PASSPHRASE,
      DESTINATION_PASSPHRASE.toString('utf8'),
      'mongo migrated vault',
    ]);
    const output: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      output.push(String(chunk));
      return true;
    });
    const migrationArgv = [
      'node',
      'kavrix',
      'migrate',
      'database',
      '--source-profile',
      'legacy',
      '--destination-profile',
      'mongo',
      '--source-vault',
      'legacy',
      '--profile-config-dir',
      directory,
      '--secrets-stdin',
    ];
    await buildLocalCli().parseAsync(migrationArgv);
    expect(JSON.parse(output.join(''))).toMatchObject({
      migrated: true,
      recordCount: 1,
    });
    expect(JSON.stringify([...backend.vaults.values()])).not.toContain(
      'mocked-mongo-canary',
    );
  });

  it('rejects explicit Mongo initialization before reading any secret frame', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-migrate-mongo-init-'));
    const sourceDataFile = join(directory, 'source.vault');
    const sourceKeyFile = join(directory, 'source.key');
    await createLegacySource(sourceDataFile, sourceKeyFile, {});
    vi.restoreAllMocks();
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: directory,
    });
    await registry.add({
      id: 'legacy' as never,
      datastore: 'file',
      dataFile: sourceDataFile,
      keyFile: sourceKeyFile,
    });
    await registry.add({
      id: 'mongo' as never,
      datastore: 'mongodb',
      database: 'kavrix',
      databaseCollection: 'databases',
      vaultCollection: 'vaults',
      keyFile: join(directory, 'mongo.key'),
    });
    const read = vi.spyOn(LocalSecretInput.prototype, 'read');
    await expect(
      buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'migrate',
        'database',
        '--source-profile',
        'legacy',
        '--destination-profile',
        'mongo',
        '--source-vault',
        'legacy',
        '--profile-config-dir',
        directory,
        '--initialize',
        '--secrets-stdin',
      ]),
    ).rejects.toThrow(
      'MongoDB destination initialization is unavailable without ownership-bound cleanup.',
    );
    expect(read).not.toHaveBeenCalled();
  });

  it('executes explicit file migration initialization, binds the profile, and verifies through flat list', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-migrate-command-'));
    const sourceDataFile = join(directory, 'source.vault');
    const sourceKeyFile = join(directory, 'source.key');
    const destinationDataFile = join(directory, 'destination.database');
    const destinationKeyFile = join(directory, 'destination.key');
    await createLegacySource(sourceDataFile, sourceKeyFile, {
      'command-🔐': { value: 'command-value-canary', updatedAt: '' },
    });
    vi.restoreAllMocks();
    const cli = buildLocalCli();
    await cli.parseAsync([
      'node',
      'kavrix',
      'db',
      'profile',
      'add',
      'legacy',
      '--config-dir',
      directory,
      '--datastore',
      'file',
      '--data-file',
      sourceDataFile,
      '--key-file',
      sourceKeyFile,
    ]);
    await buildLocalCli().parseAsync([
      'node',
      'kavrix',
      'db',
      'profile',
      'add',
      'destination',
      '--config-dir',
      directory,
      '--datastore',
      'file',
      '--data-file',
      destinationDataFile,
      '--key-file',
      destinationKeyFile,
    ]);
    const frames = [
      [
        SOURCE_PASSPHRASE,
        'new database passphrase',
        'new database passphrase',
        'private database label',
        'private migrated vault label',
      ],
      ['new database passphrase'],
    ];
    const requests: string[][] = [];
    vi.spyOn(LocalSecretInput.prototype, 'read').mockImplementation(async (kinds) => {
      requests.push([...kinds]);
      const next = frames.shift();
      if (next === undefined) throw new Error('missing migration frame');
      return next;
    });
    const output: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      output.push(String(chunk));
      return true;
    });
    const migrationArgv = [
      'node',
      'kavrix',
      'migrate',
      'database',
      '--source-profile',
      'legacy',
      '--destination-profile',
      'destination',
      '--source-vault',
      'legacy',
      '--profile-config-dir',
      directory,
      '--initialize',
      '--secrets-stdin',
    ];
    await buildLocalCli().parseAsync(migrationArgv);
    const migrated = JSON.parse(output.join('')) as {
      migrated: boolean;
      vaultId: string;
      recordCount: number;
    };
    expect(migrated).toMatchObject({ migrated: true, recordCount: 1 });
    expect(requests[0]).toEqual([
      'passphrase',
      'new-passphrase',
      'new-passphrase',
      'label',
      'label',
    ]);
    const bound = await (
      await DatastoreProfileRegistry.open({ configDirectory: directory })
    ).get('destination' as never);
    expect(bound.databaseId).toMatch(/^db_/u);

    output.length = 0;
    await buildLocalCli().parseAsync([
      'node',
      'kavrix',
      'list',
      '--profile',
      'destination',
      '--profile-config-dir',
      directory,
      '--vault',
      migrated.vaultId,
      '--passphrase-stdin',
    ]);
    expect(JSON.parse(output.join(''))).toMatchObject({ names: ['command-🔐'] });
    expect(await readFile(destinationDataFile, 'utf8')).not.toContain(
      'command-value-canary',
    );
    expect(output.join('')).not.toContain('command-value-canary');
    expect(migrationArgv.join('\0')).not.toContain('command-value-canary');
    for (const protectedOrPublicPath of [
      sourceDataFile,
      sourceKeyFile,
      sourceKeyFile + '.anchor',
      destinationKeyFile,
      destinationKeyFile + '.database-anchor',
      join(directory, 'datastore-profiles.json'),
    ]) {
      expect(await readFile(protectedOrPublicPath, 'utf8')).not.toContain(
        'command-value-canary',
      );
    }
  });

  it('routes every flat credential and doctor command through an explicitly selected database vault', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-flat-database-'));
    const dataFile = join(directory, 'database.kavrix');
    const keyFile = join(directory, 'database.key');
    const passphrase = 'database passphrase';
    const queued: string[][] = [];
    let reads = 0;
    vi.spyOn(LocalSecretInput.prototype, 'read').mockImplementation(async () => {
      reads += 1;
      const next = queued.shift();
      if (next === undefined) throw new Error('missing secret frame');
      return next;
    });
    const output: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      output.push(String(chunk));
      return true;
    });
    const run = async (frames: string[], ...args: string[]) => {
      queued.push(frames);
      output.length = 0;
      await buildLocalCli().parseAsync(['node', 'kavrix', ...args]);
      return JSON.parse(output.join('')) as Record<string, unknown>;
    };
    await buildLocalCli().parseAsync([
      'node',
      'kavrix',
      'db',
      'profile',
      'add',
      'database',
      '--config-dir',
      directory,
      '--datastore',
      'file',
      '--data-file',
      dataFile,
      '--key-file',
      keyFile,
    ]);
    const route = ['--profile', 'database', '--profile-config-dir', directory];
    await run(
      ['private database', passphrase, passphrase],
      'db',
      'init',
      ...route,
      '--secrets-stdin',
    );
    const created = await run(
      [passphrase, 'private vault'],
      'db',
      'vault',
      'create',
      ...route,
      '--secrets-stdin',
    );
    const vaultId = (created['created'] as { id: string }).id;
    const readsBeforeAmbiguous = reads;
    await expect(
      buildLocalCli().parseAsync([
        'node',
        'kavrix',
        'list',
        ...route,
        '--passphrase-stdin',
      ]),
    ).rejects.toThrow(/Select one database vault explicitly/u);
    expect(reads).toBe(readsBeforeAmbiguous);
    const flatRoute = [...route, '--vault', vaultId, '--passphrase-stdin'];

    expect(
      await run(
        [passphrase, 'flat-command-canary'],
        'put',
        'alpha',
        ...flatRoute,
        '--value-stdin',
      ),
    ).toMatchObject({ saved: true, name: 'alpha' });
    expect(await run([passphrase], 'get', 'alpha', ...flatRoute)).toMatchObject({
      value: '[REDACTED]',
    });
    expect(await run([passphrase], 'list', ...flatRoute)).toMatchObject({
      names: ['alpha'],
    });
    expect(await run([passphrase], 'view', ...flatRoute, '--json')).toMatchObject({
      count: 1,
    });
    expect(
      await run([passphrase], 'search', 'alp', ...flatRoute, '--json'),
    ).toMatchObject({ count: 1 });
    expect(await run([passphrase], 'stats', ...flatRoute, '--json')).toMatchObject({
      credentialCount: 1,
    });
    expect(await run([passphrase], 'has', 'alpha', ...flatRoute)).toMatchObject({
      exists: true,
    });
    expect(
      await run([passphrase], 'rename', 'alpha', 'beta', ...flatRoute),
    ).toMatchObject({ renamed: true });
    expect(await run([passphrase], 'doctor', ...flatRoute)).toMatchObject({
      healthy: true,
      credentialCount: 1,
    });
    expect(await run([passphrase], 'doctor', 'health', ...flatRoute)).toMatchObject({
      healthy: true,
      manualRecoveryRequired: [],
    });
    expect(await run([passphrase], 'remove', 'beta', ...flatRoute)).toMatchObject({
      removed: true,
    });
    expect(await run([passphrase], 'has', 'beta', ...flatRoute)).toMatchObject({
      exists: false,
    });
    expect(JSON.stringify(await readFile(dataFile, 'utf8'))).not.toContain(
      'flat-command-canary',
    );
  });

  it('copies Unicode, maximum-length, and empty values exactly and preserves the source', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-migration-'));
    const sourceDataFile = join(directory, 'source.vault');
    const sourceKeyFile = join(directory, 'source.key');
    const destinationKeyFile = join(directory, 'destination.key');
    const source = await createLegacySource(sourceDataFile, sourceKeyFile, {
      'emoji-🔐': { value: '値🌍', updatedAt: '2026-08-18T09:20:30.000Z' },
      ['x'.repeat(256)]: { value: '', updatedAt: '2026-08-18T10:20:30.000Z' },
    });
    const sourceBytes = await Promise.all([
      readFile(sourceDataFile),
      readFile(sourceKeyFile),
      readFile(sourceKeyFile + '.anchor'),
    ]);
    const backend = new MemoryDatabaseBackend();
    await DatabaseSession.initialize({
      store: backend.open(),
      keyFile: destinationKeyFile,
      passphrase: DESTINATION_PASSPHRASE,
      label: 'destination',
    });
    let sourceReads = 0;
    let destinationReads = 0;

    const result = await migrateLegacyVaultToDatabase({
      source: {
        document: source,
        keyFile: sourceKeyFile,
        readPassphrase: async () => {
          sourceReads += 1;
          return Buffer.from(SOURCE_PASSPHRASE, 'utf8');
        },
      },
      destination: {
        openStore: async () => backend.open(),
        keyFile: destinationKeyFile,
        vaultLabel: 'migrated vault',
        readPassphrase: async () => {
          destinationReads += 1;
          return Uint8Array.from(DESTINATION_PASSPHRASE);
        },
      },
    });

    expect(result.recordCount).toBe(2);
    expect(sourceReads).toBe(1);
    expect(destinationReads).toBe(1);
    expect(backend.createVaultCalls).toBe(1);
    expect(backend.updateVaultCalls).toBe(0);
    expect(backend.getVaultCalls).toBe(1);
    expect(
      await Promise.all([
        readFile(sourceDataFile),
        readFile(sourceKeyFile),
        readFile(sourceKeyFile + '.anchor'),
      ]),
    ).toEqual(sourceBytes);
    const reopened = await DatabaseSession.open({
      store: backend.open(),
      keyFile: destinationKeyFile,
      passphrase: DESTINATION_PASSPHRASE,
    });
    let observed: unknown;
    await reopened.inspectVault(result.vaultId, (payload) => {
      observed = payload;
    });
    expect(observed).toEqual({ records: sourceRecords() });
    await reopened.close();
    const publicBoundary = JSON.stringify({
      database: backend.database,
      vaults: [...backend.vaults.values()],
    });
    expect(publicBoundary).not.toContain('値🌍');
    expect(publicBoundary).not.toContain('emoji-🔐');
  });

  it('copies an empty source vault and verifies an exact zero-record destination', async () => {
    const fixture = await migrationFixture({});
    const result = await migrateLegacyVaultToDatabase(fixture.options);
    expect(result.recordCount).toBe(0);
    const reopened = await DatabaseSession.open({
      store: fixture.backend.open(),
      keyFile: fixture.options.destination.keyFile,
      passphrase: DESTINATION_PASSPHRASE,
    });
    let observed: unknown;
    await reopened.inspectVault(result.vaultId, (payload) => {
      observed = payload;
    });
    expect(observed).toEqual({ records: {} });
    await reopened.close();
  });

  it('rejects a wrong source key without creating a destination vault', async () => {
    const fixture = await migrationFixture({
      secret: { value: 'canary', updatedAt: '' },
    });
    await expect(
      migrateLegacyVaultToDatabase({
        ...fixture.options,
        source: {
          ...fixture.options.source,
          readPassphrase: async () => Buffer.from('wrong passphrase', 'utf8'),
        },
      }),
    ).rejects.toMatchObject({ code: 'authentication' });
    expect(fixture.backend.vaults.size).toBe(0);
  });

  it('rejects duplicate labels without altering the first migrated vault', async () => {
    const fixture = await migrationFixture({});
    await migrateLegacyVaultToDatabase(fixture.options);
    await expect(migrateLegacyVaultToDatabase(fixture.options)).rejects.toMatchObject({
      code: 'conflict',
    });
    expect(fixture.backend.vaults.size).toBe(1);
  });

  it('leaves no vault or anchor head after a proven pre-publication conflict', async () => {
    const fixture = await migrationFixture({
      secret: { value: 'canary', updatedAt: '' },
    });
    fixture.backend.createVaultFailure = 'before';
    await expect(migrateLegacyVaultToDatabase(fixture.options)).rejects.toMatchObject({
      code: 'conflict',
    });
    expect(fixture.backend.vaults.size).toBe(0);
  });

  it('retains recovery artifacts and reports ambiguity after an uncertain store result', async () => {
    const fixture = await migrationFixture({
      secret: { value: 'canary', updatedAt: '' },
    });
    fixture.backend.createVaultFailure = 'after';
    await expect(migrateLegacyVaultToDatabase(fixture.options)).rejects.toMatchObject({
      code: 'ambiguous-commit',
    });
    expect(fixture.backend.vaults.size).toBe(1);
  });

  it('retains the published destination and reports ambiguity after verification mismatch', async () => {
    const fixture = await migrationFixture({
      secret: { value: 'verification-canary', updatedAt: '' },
    });
    const originalInspect = DatabaseSession.prototype.inspectVault;
    vi.spyOn(DatabaseSession.prototype, 'inspectVault').mockImplementation(
      async function (id, inspect) {
        return await originalInspect.call(this, id, async (payload) => {
          await inspect({
            records: {
              ...payload.records,
              mismatch: {
                value: 'mismatch',
                updatedAt: '2026-08-19T00:00:00.000Z',
              },
            },
          });
        });
      },
    );
    await expect(migrateLegacyVaultToDatabase(fixture.options)).rejects.toMatchObject({
      code: 'ambiguous-commit',
    });
    expect(fixture.backend.vaults.size).toBe(1);
  });

  it('retains a published vault and reports ambiguity when the post-create read fails', async () => {
    const fixture = await migrationFixture({
      secret: {
        value: 'post-create-read-canary',
        updatedAt: '2026-08-18T00:00:00.000Z',
      },
    });
    fixture.backend.failNextVaultReadAfterCreate = true;
    await expect(migrateLegacyVaultToDatabase(fixture.options)).rejects.toMatchObject({
      code: 'ambiguous-commit',
    });
    expect(fixture.backend.vaults.size).toBe(1);
    expect(fixture.backend.updateVaultCalls).toBe(0);
  });

  it('retains a published vault and reports ambiguity when anchor publication fails', async () => {
    const fixture = await migrationFixture({
      secret: {
        value: 'post-create-anchor-canary',
        updatedAt: '2026-08-18T00:00:00.000Z',
      },
    });
    const anchorFile = databaseRevisionAnchorPath(fixture.options.destination.keyFile);
    const savedAnchor = anchorFile + '.saved';
    fixture.backend.afterVaultCreate = async () => {
      await rename(anchorFile, savedAnchor);
      await mkdir(anchorFile);
    };
    try {
      await expect(migrateLegacyVaultToDatabase(fixture.options)).rejects.toMatchObject(
        {
          code: 'ambiguous-commit',
        },
      );
      expect(fixture.backend.vaults.size).toBe(1);
    } finally {
      await rm(anchorFile, { recursive: true });
      await rename(savedAnchor, anchorFile);
    }
  });

  it('retains initialized recovery artifacts when profile publication is ambiguous', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-migration-profile-'));
    const sourceDataFile = join(directory, 'source.vault');
    const sourceKeyFile = join(directory, 'source.key');
    const destinationKeyFile = join(directory, 'destination.key');
    const source = await createLegacySource(sourceDataFile, sourceKeyFile, {});
    const backend = new MemoryDatabaseBackend();
    let thrown: unknown;
    try {
      await migrateLegacyVaultToDatabase({
        source: {
          document: source,
          keyFile: sourceKeyFile,
          readPassphrase: async () => Buffer.from(SOURCE_PASSPHRASE, 'utf8'),
        },
        destination: {
          openStore: async () => backend.open(),
          keyFile: destinationKeyFile,
          vaultLabel: 'migrated',
          readPassphrase: async () => Uint8Array.from(DESTINATION_PASSPHRASE),
          initialize: {
            databaseLabel: 'new database',
            rollbackDatabase: async () => backend.clear(),
            publishBinding: async () => {
              throw new Error('profile-publication-secret-canary');
            },
          },
        },
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ code: 'ambiguous-commit' });
    expect(String((thrown as Error).message)).not.toContain(
      'profile-publication-secret-canary',
    );
    expect(backend.database).not.toBeNull();
    expect(backend.vaults.size).toBe(1);
    expect((await readFile(destinationKeyFile)).byteLength).toBeGreaterThan(0);
    expect(
      (await readFile(destinationKeyFile + '.database-anchor')).byteLength,
    ).toBeGreaterThan(0);
  });

  it('rolls back the exact initialized file destination after authentic profile non-publication', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-migration-profile-'));
    const sourceDataFile = join(directory, 'source.vault');
    const sourceKeyFile = join(directory, 'source.key');
    const destinationDataFile = join(directory, 'destination.database');
    const destinationKeyFile = join(directory, 'destination.key');
    const source = await createLegacySource(sourceDataFile, sourceKeyFile, {
      exact: {
        value: 'profile-non-publication-source-canary',
        updatedAt: '2026-08-18T02:03:04.000Z',
      },
    });
    const sourceBytes = await Promise.all([
      readFile(sourceDataFile),
      readFile(sourceKeyFile),
      readFile(sourceKeyFile + '.anchor'),
    ]);
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: directory,
    });
    await registry.add({
      id: 'destination' as never,
      datastore: 'file',
      dataFile: destinationDataFile,
      keyFile: destinationKeyFile,
    });
    const createVault = vi.spyOn(FileEncryptedDatabaseStore.prototype, 'createVault');

    await expect(
      migrateLegacyVaultToDatabase({
        source: {
          document: source,
          keyFile: sourceKeyFile,
          readPassphrase: async () => Buffer.from(SOURCE_PASSPHRASE, 'utf8'),
        },
        destination: {
          openStore: async () => FileEncryptedDatabaseStore.open(destinationDataFile),
          keyFile: destinationKeyFile,
          vaultLabel: 'migrated',
          readPassphrase: async () => Uint8Array.from(DESTINATION_PASSPHRASE),
          initialize: {
            databaseLabel: 'new database',
            rollbackDatabase: async () => deleteSecureFile(destinationDataFile),
            publishBinding: async () =>
              registry.bindDatabaseIdForInitialization(
                'destination' as never,
                'invalid database id' as never,
              ),
          },
        },
      }),
    ).rejects.toMatchObject({ code: 'invalid' });

    expect(createVault).toHaveBeenCalledTimes(1);
    await expect(access(destinationDataFile)).rejects.toMatchObject({ code: 'ENOENT' });
    for (const path of [destinationKeyFile, destinationKeyFile + '.database-anchor']) {
      expect(await readFile(path)).toHaveLength(0);
      if (process.platform !== 'win32') {
        expect((await stat(path)).mode & 0o077).toBe(0);
      }
    }
    expect((await registry.get('destination' as never)).databaseId).toBeUndefined();
    expect(
      await Promise.all([
        readFile(sourceDataFile),
        readFile(sourceKeyFile),
        readFile(sourceKeyFile + '.anchor'),
      ]),
    ).toEqual(sourceBytes);
  });

  it('aggregates only redacted errors when authentic non-publication cleanup fails', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-migration-profile-'));
    const sourceDataFile = join(directory, 'source.vault');
    const sourceKeyFile = join(directory, 'source.key');
    const destinationDataFile = join(directory, 'destination.database');
    const destinationKeyFile = join(directory, 'destination.key');
    const source = await createLegacySource(sourceDataFile, sourceKeyFile, {});
    const registry = await DatastoreProfileRegistry.open({
      configDirectory: directory,
    });
    await registry.add({
      id: 'destination' as never,
      datastore: 'file',
      dataFile: destinationDataFile,
      keyFile: destinationKeyFile,
    });
    let thrown: unknown;
    try {
      await migrateLegacyVaultToDatabase({
        source: {
          document: source,
          keyFile: sourceKeyFile,
          readPassphrase: async () => Buffer.from(SOURCE_PASSPHRASE, 'utf8'),
        },
        destination: {
          openStore: async () => FileEncryptedDatabaseStore.open(destinationDataFile),
          keyFile: destinationKeyFile,
          vaultLabel: 'migrated',
          readPassphrase: async () => Uint8Array.from(DESTINATION_PASSPHRASE),
          initialize: {
            databaseLabel: 'new database',
            rollbackDatabase: async () => {
              throw new Error('profile-cleanup-secret-canary');
            },
            publishBinding: async () =>
              registry.bindDatabaseIdForInitialization(
                'destination' as never,
                'invalid database id' as never,
              ),
          },
        },
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(AggregateError);
    expect(serializeThrown(thrown)).not.toContain('profile-cleanup-secret-canary');
    const aggregate = thrown as AggregateError;
    expect(aggregate.errors).toEqual([
      expect.objectContaining({ code: 'invalid' }),
      expect.objectContaining({ code: 'ambiguous-commit' }),
    ]);
    expect(aggregate.errors).toSatisfy((errors: unknown[]) =>
      errors.every((error) => error instanceof DatabaseMigrationError),
    );
    expect((await registry.get('destination' as never)).databaseId).toBeUndefined();
    await expect(access(destinationDataFile)).resolves.toBeUndefined();
    expect((await readFile(destinationKeyFile)).byteLength).toBeGreaterThan(0);
    expect(
      (await readFile(destinationKeyFile + '.database-anchor')).byteLength,
    ).toBeGreaterThan(0);
  });

  it('rolls back an explicitly initialized destination after a proven create conflict', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-migration-init-'));
    const sourceDataFile = join(directory, 'source.vault');
    const sourceKeyFile = join(directory, 'source.key');
    const destinationKeyFile = join(directory, 'destination.key');
    const source = await createLegacySource(sourceDataFile, sourceKeyFile, {
      secret: { value: 'verify-canary', updatedAt: '' },
    });
    const backend = new MemoryDatabaseBackend();
    backend.createVaultFailure = 'before';
    await expect(
      migrateLegacyVaultToDatabase({
        source: {
          document: source,
          keyFile: sourceKeyFile,
          readPassphrase: async () => Buffer.from(SOURCE_PASSPHRASE, 'utf8'),
        },
        destination: {
          openStore: async () => backend.open(),
          keyFile: destinationKeyFile,
          vaultLabel: 'migrated',
          readPassphrase: async () => Uint8Array.from(DESTINATION_PASSPHRASE),
          initialize: {
            databaseLabel: 'new database',
            rollbackDatabase: async () => backend.clear(),
          },
        },
      }),
    ).rejects.toMatchObject({ code: 'conflict' });
    expect(backend.database).toBeNull();
    expect(backend.vaults.size).toBe(0);
    expect(await readFile(destinationKeyFile)).toHaveLength(0);
    expect(await readFile(destinationKeyFile + '.database-anchor')).toHaveLength(0);
  });
});

async function migrationFixture(
  records: Readonly<Record<string, Readonly<{ value: string; updatedAt: string }>>>,
) {
  const directory = await mkdtemp(join(tmpdir(), 'kavrix-migration-case-'));
  const sourceDataFile = join(directory, 'source.vault');
  const sourceKeyFile = join(directory, 'source.key');
  const destinationKeyFile = join(directory, 'destination.key');
  const source = await createLegacySource(sourceDataFile, sourceKeyFile, records);
  const backend = new MemoryDatabaseBackend();
  await DatabaseSession.initialize({
    store: backend.open(),
    keyFile: destinationKeyFile,
    passphrase: DESTINATION_PASSPHRASE,
    label: 'destination',
  });
  return {
    backend,
    options: {
      source: {
        document: source,
        keyFile: sourceKeyFile,
        readPassphrase: async () => Buffer.from(SOURCE_PASSPHRASE, 'utf8'),
      },
      destination: {
        openStore: async () => backend.open(),
        keyFile: destinationKeyFile,
        vaultLabel: 'migrated vault',
        readPassphrase: async () => Uint8Array.from(DESTINATION_PASSPHRASE),
      },
    },
  };
}

async function createLegacySource(
  dataFile: string,
  keyFile: string,
  records: Readonly<Record<string, Readonly<{ value: string; updatedAt: string }>>>,
) {
  const frames = [[SOURCE_PASSPHRASE, SOURCE_PASSPHRASE]];
  vi.spyOn(LocalSecretInput.prototype, 'read').mockImplementation(async () => {
    const frame = frames.shift();
    if (frame === undefined) throw new Error('missing secret frame');
    return frame;
  });
  await buildLocalCli().parseAsync([
    'node',
    'kavrix',
    'init',
    '--datastore',
    'file',
    '--data-file',
    dataFile,
    '--key-file',
    keyFile,
    '--vault',
    'legacy',
    '--passphrase-stdin',
  ]);
  const store = await FileLocalVaultStore.open(dataFile);
  let portable: Awaited<ReturnType<typeof readPortableKeyFile>> | undefined;
  let root: VaultRootKey | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    const document = await store.get('legacy');
    if (document === null) throw new Error('legacy fixture missing');
    const passphrase = Buffer.from(SOURCE_PASSPHRASE, 'utf8');
    try {
      portable = await readPortableKeyFile(
        keyFile,
        { kind: 'passphrase', passphrase },
        {
          kind: 'bound',
          vaultId: document.id,
          keySlotId: document.keySlot.id,
        },
      );
    } finally {
      zeroize(passphrase);
    }
    root = await unlockPortableKeySlotBytes(document.keySlot, portable.key, {
      vaultId: document.id,
      slotId: document.keySlot.id,
      schemaVersion: document.schemaVersion,
      keyVersion: document.currentKeyVersion,
    });
    const payload = localVaultPayloadSchema.parse({
      records: Object.fromEntries(
        Object.entries(records).map(([name, record]) => [
          name,
          {
            ...record,
            updatedAt:
              record.updatedAt === '' ? '2026-08-18T00:00:00.000Z' : record.updatedAt,
          },
        ]),
      ),
    });
    const updatedMetadata = {
      ...document,
      revision: vaultRevisionSchema.parse(document.revision + 1),
      updatedAt: '2026-08-18T11:20:30.000Z',
    };
    const metadataDigest = legacyMetadataDigest(updatedMetadata);
    plaintext = new TextEncoder().encode(canonicalJson(payload));
    const encryptedPayload = await encryptPayload(
      plaintext,
      root,
      associatedDataSchema.parse({
        version: 1,
        vaultId: document.id,
        entityType: 'vault-preferences',
        entityId: document.id,
        purpose: 'vault-preferences',
        schemaVersion: document.schemaVersion,
        keyVersion: document.currentKeyVersion,
        revision: updatedMetadata.revision,
        metadataDigest,
      }),
    );
    const updated = localVaultDocumentSchema.parse({
      ...updatedMetadata,
      encryptedPayload,
    });
    await store.update(updated, document.revision);
    await writeRevisionAnchor(
      keyFile + '.anchor',
      root,
      {
        vaultId: updated.id,
        keySlotId: updated.keySlot.id,
        revision: updated.revision,
        metadataDigest,
      },
      'replace',
    );
    return updated;
  } finally {
    await store.close();
    zeroize(plaintext);
    zeroize(root);
    zeroize(portable?.key);
  }
}

function legacyMetadataDigest(document: LocalVaultDocument) {
  const metadata = {
    format: document.format,
    version: document.version,
    id: document.id,
    schemaVersion: document.schemaVersion,
    cryptographicVersion: document.cryptographicVersion,
    currentKeyVersion: document.currentKeyVersion,
    keySlot: document.keySlot,
    recoverySlots: document.recoverySlots,
    revision: document.revision,
    createdAt: document.createdAt,
    updatedAt: document.updatedAt,
  };
  return sha256DigestSchema.parse(
    createHash('sha256')
      .update('kavrix/local-vault-metadata/v1\0', 'utf8')
      .update(canonicalJson(metadata), 'utf8')
      .digest('base64url'),
  );
}

function sourceRecords(): unknown {
  return {
    'emoji-🔐': { value: '値🌍', updatedAt: '2026-08-18T09:20:30.000Z' },
    ['x'.repeat(256)]: { value: '', updatedAt: '2026-08-18T10:20:30.000Z' },
  };
}

class MemoryDatabaseBackend {
  database: EncryptedDatabaseDocument | null = null;
  readonly vaults = new Map<VaultId, DatabaseVaultDocument>();
  createVaultFailure: 'before' | 'after' | null = null;
  failNextVaultReadAfterCreate = false;
  afterVaultCreate: (() => Promise<void>) | undefined;
  createVaultCalls = 0;
  getVaultCalls = 0;
  updateVaultCalls = 0;

  clear(): void {
    this.database = null;
    this.vaults.clear();
  }

  open(): EncryptedDatabaseStore {
    const backend = this;
    return {
      async ping() {},
      async getDatabase(id) {
        return backend.database?.id === id ? structuredClone(backend.database) : null;
      },
      async createDatabase(document) {
        if (backend.database !== null) throw new Error('exists');
        backend.database = structuredClone(document);
      },
      async updateDatabase(document, expectedRevision) {
        if (backend.database?.revision !== expectedRevision)
          throw new Error('conflict');
        backend.database = structuredClone(document);
      },
      async listVaults(databaseId) {
        return [...backend.vaults.values()]
          .filter((vault) => vault.databaseId === databaseId)
          .map((vault) => structuredClone(vault));
      },
      async getVault(databaseId, vaultId) {
        backend.getVaultCalls += 1;
        if (backend.failNextVaultReadAfterCreate && backend.vaults.size > 0) {
          backend.failNextVaultReadAfterCreate = false;
          throw new EncryptedDatabaseStoreError('operation');
        }
        const vault = backend.vaults.get(vaultId);
        return vault?.databaseId === databaseId ? structuredClone(vault) : null;
      },
      async createVault(input: CreateVaultInput) {
        backend.createVaultCalls += 1;
        if (backend.createVaultFailure === 'before') {
          backend.createVaultFailure = null;
          throw new EncryptedDatabaseStoreError('conflict');
        }
        backend.database = structuredClone(input.database);
        backend.vaults.set(input.vault.id, structuredClone(input.vault));
        if (backend.createVaultFailure === 'after') {
          backend.createVaultFailure = null;
          throw new EncryptedDatabaseStoreError('operation');
        }
        await backend.afterVaultCreate?.();
      },
      async updateVault(input: UpdateVaultInput) {
        backend.updateVaultCalls += 1;
        backend.vaults.set(input.vault.id, structuredClone(input.vault));
      },
      async deleteVault(input: DeleteVaultInput) {
        backend.database = structuredClone(input.database);
        backend.vaults.delete(input.vaultId);
      },
      async close() {},
    };
  }
}

function serializeThrown(value: unknown, seen = new Set<unknown>()): string {
  if (value === null || typeof value !== 'object') return String(value);
  if (seen.has(value)) return '[cycle]';
  seen.add(value);
  const entries = Reflect.ownKeys(value).map((key) => {
    const label = typeof key === 'symbol' ? (key.description ?? 'symbol') : key;
    return `${label}:${serializeThrown(Reflect.get(value, key), seen)}`;
  });
  return entries.join('|');
}
