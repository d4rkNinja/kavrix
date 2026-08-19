import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  databaseIdSchema,
  databaseRevisionSchema,
  databaseVaultDocumentSchema,
  encryptedDatabaseDocumentSchema,
  type DatabaseId,
  type DatabaseRevision,
  type DatabaseVaultDocument,
  type EncryptedDatabaseDocument,
  type VaultId,
} from '@kavrix/schemas';
import { afterEach, describe, expect, it, vi } from 'vitest';

const aclMocks = vi.hoisted(() => ({
  set: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
  verify: vi.fn<(path: string) => Promise<void>>(() => Promise.resolve()),
}));
const fileSystemMocks = vi.hoisted(() => ({ rename: vi.fn() }));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  fileSystemMocks.rename.mockImplementation(actual.rename);
  return { ...actual, rename: fileSystemMocks.rename };
});

vi.mock('@kavrix/key-files/windows-acl', () => ({
  setWindowsUserOnlyAcl: aclMocks.set,
  verifyWindowsUserOnlyAcl: aclMocks.verify,
}));

import { defineEncryptedDatabaseStoreContractTests } from './encrypted-database-store-contract.test.js';
import {
  __fileEncryptedDatabaseTestEffects,
  FileEncryptedDatabaseStore,
  MAX_FILE_ENCRYPTED_DATABASE_BYTES,
} from '../src/file-encrypted-database.js';

const directories: string[] = [];
const timestamp = '2026-08-19T00:00:00.000Z';
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const nonce = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const tag = 'AAAAAAAAAAAAAAAAAAAAAA';
const ciphertext = 'AQID';

afterEach(async () => {
  __fileEncryptedDatabaseTestEffects.reset();
  vi.clearAllMocks();
  for (const directory of directories.splice(0))
    await rm(directory, { force: true, recursive: true });
});

defineEncryptedDatabaseStoreContractTests(
  'FileEncryptedDatabaseStore contract',
  async () => FileEncryptedDatabaseStore.open(await targetPath()),
);

describe('FileEncryptedDatabaseStore', () => {
  it('publishes a canonical, restrictive two-vault container without plaintext', async () => {
    const target = await targetPath();
    const databaseId = dbId('db_01JFILEDATABASE');
    const store = await FileEncryptedDatabaseStore.open(target);
    await store.createDatabase(database(databaseId, 0));
    await store.createVault({
      database: database(databaseId, 1),
      expectedDatabaseRevision: revision(0),
      vault: vault(databaseId, vaultId('vault_01JZULU'), 1, 0),
    });
    await store.createVault({
      database: database(databaseId, 2),
      expectedDatabaseRevision: revision(1),
      vault: vault(databaseId, vaultId('vault_01JALPHA'), 2, 0),
    });
    const contents = await readFile(target, 'utf8');
    expect(contents).toBe(`${JSON.stringify(JSON.parse(contents))}\n`);
    expect(contents).not.toContain('plaintext-canary');
    expect((await store.listVaults(databaseId)).map((entry) => entry.id)).toEqual([
      'vault_01JALPHA',
      'vault_01JZULU',
    ]);
    const metadata = await lstat(target, { bigint: true });
    expect(metadata.nlink).toBe(1n);
    if (process.platform !== 'win32') expect(metadata.mode & 0o777n).toBe(0o600n);
    await store.close();
  });

  it('holds a sibling lock and rejects malformed, noncanonical, oversized, and unsafe targets', async () => {
    const target = await targetPath();
    const first = await FileEncryptedDatabaseStore.open(target);
    await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
      code: 'busy',
    });
    await first.close();
    await writeRestricted(target, '{"format":"bad"}\n');
    await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
      code: 'invalid',
    });
    await writeRestricted(target, 'x');
    const handle = await import('node:fs/promises');
    await handle.truncate(target, MAX_FILE_ENCRYPTED_DATABASE_BYTES + 1);
    await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
      code: 'invalid',
    });
  });

  it.skipIf(process.platform === 'win32')(
    'rejects group writable directories before creating a lock',
    async () => {
      const directory = await temporaryDirectory();
      await chmod(directory, 0o770);
      await expect(
        FileEncryptedDatabaseStore.open(join(directory, 'database.json')),
      ).rejects.toMatchObject({ code: 'invalid' });
      expect(await readdir(directory)).toEqual([]);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'rejects unsafe existing sibling locks instead of reporting busy',
    async () => {
      const target = await targetPath();
      const source = `${target}.source`;
      await writeRestricted(source, 'lock');
      await symlink(source, `${target}.lock`);
      await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
        code: 'invalid',
      });
      await unlink(`${target}.lock`);
      await link(source, `${target}.lock`);
      await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
        code: 'invalid',
      });
      await unlink(`${target}.lock`);
      await mkdir(`${target}.lock`, { mode: 0o700 });
      await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
        code: 'invalid',
      });
    },
  );

  it.skipIf(process.platform === 'win32')(
    'rejects symlinked and hard-linked database targets through open and validatePath',
    async () => {
      const target = await targetPath();
      const source = `${target}.source`;
      await writeRestricted(source, '{}\n');
      await symlink(source, target);
      await expect(
        FileEncryptedDatabaseStore.validatePath(target),
      ).rejects.toMatchObject({
        code: 'invalid',
      });
      await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
        code: 'invalid',
      });
      await unlink(target);
      await link(source, target);
      await expect(
        FileEncryptedDatabaseStore.validatePath(target),
      ).rejects.toMatchObject({
        code: 'invalid',
      });
      await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
        code: 'invalid',
      });
    },
  );

  it.skipIf(process.platform === 'win32')(
    'fails closed when its lock or containing directory is replaced',
    async () => {
      const target = await targetPath();
      const store = await FileEncryptedDatabaseStore.open(target);
      await unlink(`${target}.lock`);
      await writeRestricted(`${target}.lock`, 'replacement');
      await expect(store.ping()).rejects.toMatchObject({ code: 'invalid' });
      await expect(store.close()).rejects.toMatchObject({ code: 'operation' });

      const directory = await temporaryDirectory();
      const directoryTarget = join(directory, 'database.json');
      const directoryStore = await FileEncryptedDatabaseStore.open(directoryTarget);
      const movedDirectory = `${directory}.moved`;
      await rename(directory, movedDirectory);
      await mkdir(directory, { mode: 0o700 });
      await expect(directoryStore.ping()).rejects.toMatchObject({ code: 'invalid' });
      await expect(directoryStore.close()).rejects.toMatchObject({ code: 'operation' });
      await rm(movedDirectory, { force: true, recursive: true });
    },
  );

  it('rejects a valid but noncanonical container and validates absent safe paths', async () => {
    const target = await targetPath();
    await FileEncryptedDatabaseStore.validatePath(target);
    const databaseId = dbId('db_01JNONCANONICAL');
    const store = await FileEncryptedDatabaseStore.open(target);
    await store.createDatabase(database(databaseId, 0));
    await store.close();
    const parsed = JSON.parse(await readFile(target, 'utf8'));
    await writeRestricted(target, `${JSON.stringify(parsed, null, 2)}\n`);
    await expect(FileEncryptedDatabaseStore.validatePath(target)).rejects.toMatchObject(
      {
        code: 'invalid',
      },
    );
  });

  it('preserves prior bytes and removes temporary files when an atomic replace fails', async () => {
    const target = await targetPath();
    const databaseId = dbId('db_01JATOMICFAILURE');
    const store = await FileEncryptedDatabaseStore.open(target);
    await store.createDatabase(database(databaseId, 0));
    const before = await readFile(target, 'utf8');
    fileSystemMocks.rename.mockRejectedValueOnce(
      Object.assign(new Error(), { code: 'EIO' }),
    );
    await expect(
      store.updateDatabase(database(databaseId, 1), revision(0)),
    ).rejects.toMatchObject({
      code: 'operation',
    });
    expect(await readFile(target, 'utf8')).toBe(before);
    expect(
      (await readdir(dirname(target))).filter((name) => name.endsWith('.tmp')),
    ).toEqual([]);
    await store.close();
  });

  it('rolls back a post-publication replace failure and retains its lock', async () => {
    const target = await targetPath();
    const databaseId = dbId('db_01JROLLBACKREPLACE');
    const store = await FileEncryptedDatabaseStore.open(target);
    await store.createDatabase(database(databaseId, 0));
    const before = await readFile(target, 'utf8');
    let failed = false;
    __fileEncryptedDatabaseTestEffects.replace({
      syncDirectory: async () => {
        if (!failed) {
          failed = true;
          throw new Error('injected directory sync');
        }
      },
    });
    await expect(
      store.updateDatabase(database(databaseId, 1), revision(0)),
    ).rejects.toMatchObject({ code: 'operation' });
    __fileEncryptedDatabaseTestEffects.reset();
    expect(await readFile(target, 'utf8')).toBe(before);
    expect(
      (await readdir(dirname(target))).filter(
        (name) => name.endsWith('.tmp') || name.endsWith('.bak'),
      ),
    ).toEqual([]);
    await store.ping();
    await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
      code: 'busy',
    });
    await store.close();
  });

  it('fails closed and cleans publication artifacts for injected pre-publication phases', async () => {
    const phases = ['write', 'sync', 'chmod', 'link', 'rename'] as const;
    for (const phase of phases) {
      const target = await targetPath();
      const databaseId = dbId(`db_01JFAULT${phase.toUpperCase()}`);
      const store = await FileEncryptedDatabaseStore.open(target);
      await store.createDatabase(database(databaseId, 0));
      const before = await readFile(target, 'utf8');
      const injected = new Error(`injected ${phase}`);
      __fileEncryptedDatabaseTestEffects.replace({
        [phase]: async () => Promise.reject(injected),
      } as Parameters<typeof __fileEncryptedDatabaseTestEffects.replace>[0]);
      await expect(
        store.updateDatabase(database(databaseId, 1), revision(0)),
      ).rejects.toMatchObject({ code: 'operation' });
      __fileEncryptedDatabaseTestEffects.reset();
      expect(await readFile(target, 'utf8')).toBe(before);
      expect(
        (await readdir(dirname(target))).filter(
          (name) => name.endsWith('.tmp') || name.endsWith('.bak'),
        ),
      ).toEqual([]);
      await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
        code: 'busy',
      });
      await store.close();
    }
  });

  it('redacts deterministic temporary-close and final-read failures without losing the held lock', async () => {
    const rows = [
      {
        name: 'temporary close',
        effects: {
          close: async (handle: { close(): Promise<void> }) => {
            await handle.close();
            throw new Error('injected close');
          },
        },
      },
      {
        name: 'final canonical read',
        effects: {
          readFinal: async () => {
            throw new Error('injected final read');
          },
        },
      },
    ] as const;
    for (const row of rows) {
      const target = await targetPath();
      const databaseId = dbId(`db_01J${row.name.replaceAll(' ', '').toUpperCase()}`);
      const store = await FileEncryptedDatabaseStore.open(target);
      await store.createDatabase(database(databaseId, 0));
      const before = await readFile(target, 'utf8');
      __fileEncryptedDatabaseTestEffects.replace(
        row.effects as Parameters<typeof __fileEncryptedDatabaseTestEffects.replace>[0],
      );
      await expect(
        store.updateDatabase(database(databaseId, 1), revision(0)),
      ).rejects.toMatchObject({ code: 'operation' });
      __fileEncryptedDatabaseTestEffects.reset();
      expect(await readFile(target, 'utf8')).toBe(before);
      expect(
        (await readdir(dirname(target))).filter(
          (name) => name.endsWith('.tmp') || name.endsWith('.bak'),
        ),
      ).toEqual([]);
      await expect(FileEncryptedDatabaseStore.open(target)).rejects.toMatchObject({
        code: 'busy',
      });
      await store.close();
    }
  });

  it('accepts exactly one thousand vaults and preserves bytes when rejecting 1,001', async () => {
    const target = await targetPath();
    const databaseId = dbId('db_01JVAULTBOUNDARY');
    const vaults: Record<string, DatabaseVaultDocument> = {};
    for (let index = 1; index <= 1_000; index += 1) {
      const id = vaultId(`vault_01JBOUNDARY${String(index).padStart(4, '0')}`);
      vaults[id] = vault(databaseId, id, 0, 0);
    }
    await writeRestricted(
      target,
      `${JSON.stringify({
        format: 'kavrix-file-database-container',
        version: 1,
        database: database(databaseId, 0),
        vaults,
      })}\n`,
    );
    const store = await FileEncryptedDatabaseStore.open(target);
    expect((await store.listVaults(databaseId)).length).toBe(1_000);
    const before = await readFile(target, 'utf8');
    await expect(
      store.createVault({
        database: database(databaseId, 1),
        expectedDatabaseRevision: revision(0),
        vault: vault(databaseId, vaultId('vault_01JBOUNDARY1001'), 1, 0),
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
    expect(await readFile(target, 'utf8')).toBe(before);
    await store.close();
  });

  it('sets and verifies Windows ACLs for the exact final path after publication', async () => {
    const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
    let store: FileEncryptedDatabaseStore | undefined;
    try {
      Object.defineProperty(process, 'platform', {
        configurable: true,
        value: 'win32',
      });
      const target = await targetPath();
      const canonicalTarget = join(await realpath(dirname(target)), 'database.json');
      store = await FileEncryptedDatabaseStore.open(target);
      await store.createDatabase(database(dbId('db_01JWINDOWSFINAL'), 0));
      expect(aclMocks.set).toHaveBeenCalledWith(canonicalTarget);
      expect(aclMocks.verify).toHaveBeenCalledWith(canonicalTarget);
    } finally {
      await store?.close();
      if (descriptor !== undefined)
        Object.defineProperty(process, 'platform', descriptor);
    }
  });
});

async function targetPath(): Promise<string> {
  return join(await temporaryDirectory(), 'database.json');
}
async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'kavrix-file-database-'));
  directories.push(directory);
  if (process.platform !== 'win32') await chmod(directory, 0o700);
  return directory;
}
async function writeRestricted(path: string, contents: string): Promise<void> {
  await writeFile(path, contents, { mode: 0o600 });
  if (process.platform !== 'win32') await chmod(path, 0o600);
}
function dbId(value: string): DatabaseId {
  return databaseIdSchema.parse(value);
}
function vaultId(value: string): VaultId {
  return awaitableVaultId(value);
}
function awaitableVaultId(value: string): VaultId {
  return databaseVaultDocumentSchema.shape.id.parse(value);
}
function revision(value: number): DatabaseRevision {
  return databaseRevisionSchema.parse(value);
}
function database(id: DatabaseId, value: number): EncryptedDatabaseDocument {
  const current = revision(value);
  return encryptedDatabaseDocumentSchema.parse({
    format: 'kavrix-encrypted-database',
    version: 1,
    id,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    keySlot: {
      slotVersion: 1,
      id: 'slot.database-owner',
      type: 'portable-key',
      state: 'active',
      keyVersion: 1,
      derivation: {
        algorithm: 'hkdf-sha256',
        version: 1,
        salt: digest,
        context: 'kavrix/database-root-wrap/v1',
        outputLength: 32,
      },
      wrappedDatabaseRoot: envelope(
        id,
        'wrapped-database-root',
        'slot.database-owner',
        'database-root',
        0,
      ),
      createdAt: timestamp,
    },
    recoverySlots: [],
    revision: current,
    encryptedCatalog: envelope(id, 'database-catalog', id, 'catalog', value),
    catalogMetadataDigest: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}
function vault(
  databaseId: DatabaseId,
  id: VaultId,
  databaseRevision: number,
  value: number,
): DatabaseVaultDocument {
  return databaseVaultDocumentSchema.parse({
    databaseId,
    id,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    databaseRevision: revision(databaseRevision),
    revision: value,
    wrappedVaultRoot: envelope(
      databaseId,
      'wrapped-vault-root',
      id,
      'vault-root',
      databaseRevision,
      id,
    ),
    encryptedPayload: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce,
      ciphertext,
      authenticationTag: tag,
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId: id,
        entityType: 'vault-preferences',
        entityId: id,
        purpose: 'vault-preferences',
        revision: value,
        metadataDigest: digest,
      },
      keyVersion: 1,
    },
    payloadMetadataDigest: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}
function envelope(
  databaseId: DatabaseId,
  entityType: 'database-catalog' | 'wrapped-database-root' | 'wrapped-vault-root',
  entityId: DatabaseId | VaultId | 'slot.database-owner',
  purpose: 'catalog' | 'database-root' | 'vault-root',
  value: number,
  vault?: VaultId,
): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce,
    ciphertext,
    authenticationTag: tag,
    aad: {
      version: 1,
      databaseId,
      entityType,
      entityId,
      purpose,
      schemaVersion: 1,
      keyVersion: 1,
      revision: value,
      ...(vault === undefined ? {} : { vaultId: vault }),
      metadataDigest: digest,
    },
    keyVersion: 1,
  };
}
