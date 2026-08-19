import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
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
import { afterEach, describe, expect, it } from 'vitest';

import { defineEncryptedDatabaseStoreContractTests } from './encrypted-database-store-contract.test.js';
import {
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
