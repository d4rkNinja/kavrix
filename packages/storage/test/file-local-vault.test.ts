import {
  chmod,
  link,
  lstat,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  truncate,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  localVaultDocumentSchema,
  vaultRevisionSchema,
  type LocalVaultDocument,
} from '@kavrix/schemas';
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

import {
  EncryptedVaultStoreError,
  FileLocalVaultError,
  FileLocalVaultStore,
  MAX_FILE_LOCAL_VAULT_BYTES,
  type EncryptedVaultStore,
} from '../src/index.js';

const temporaryDirectories: string[] = [];
const timestamp = '2026-08-19T00:00:00.000Z';

afterEach(async () => {
  vi.clearAllMocks();
  const directories = temporaryDirectories.splice(0);
  for (const directory of directories) {
    await rm(directory, { force: true, recursive: true });
  }
});

describe('FileLocalVaultStore', () => {
  it('creates, canonically reads, revision-CAS updates, and revision-CAS deletes', async () => {
    const target = await targetPath();
    const store: EncryptedVaultStore = await FileLocalVaultStore.open(target);
    expect(await store.listVaultIds()).toEqual([]);
    expect(await store.get('vault.one')).toBeNull();

    const initial = document();
    await store.create(initial);
    expect(await store.get('vault.one')).toEqual(initial);
    expect(await store.listVaultIds()).toEqual(['vault.one']);
    await expect(store.create(initial)).rejects.toMatchObject({ code: 'exists' });

    const updated = document(1);
    await expect(store.update(updated, revision(1))).rejects.toMatchObject({
      code: 'invalid',
    });
    await expect(store.update(document(5), revision(4))).rejects.toMatchObject({
      code: 'conflict',
    });
    await store.update(updated, revision(0));
    expect((await store.get('vault.one'))?.revision).toBe(1);

    await expect(store.delete('vault.one', revision(0))).rejects.toMatchObject({
      code: 'conflict',
    });
    await expect(store.delete('vault.two', revision(1))).rejects.toMatchObject({
      code: 'conflict',
    });
    await store.delete('vault.one', revision(1));
    expect(await store.listVaultIds()).toEqual([]);
    await store.close();

    await expect(lstat(`${target}.lock`)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(lstat(target)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('publishes restrictive canonical files atomically and leaves no staging files', async () => {
    const target = await targetPath();
    const store = await FileLocalVaultStore.open(target);
    const initial = document();
    await store.create(initial);

    const contents = await readFile(target, 'utf8');
    expect(contents).toBe(`${JSON.stringify(initial)}\n`);
    const metadata = await lstat(target, { bigint: true });
    expect(metadata.isFile()).toBe(true);
    expect(metadata.nlink).toBe(1n);
    if (process.platform !== 'win32') expect(metadata.mode & 0o777n).toBe(0o600n);
    expect(
      (await readdir(dirname(target))).filter((name) => name.endsWith('.tmp')),
    ).toEqual([]);
    await store.close();
  });

  it('holds an exclusive process-lifetime sibling lock', async () => {
    const target = await targetPath();
    const first = await FileLocalVaultStore.open(target);
    await expect(FileLocalVaultStore.open(target)).rejects.toBeInstanceOf(
      FileLocalVaultError,
    );
    await expect(FileLocalVaultStore.open(target)).rejects.toMatchObject({
      code: 'busy',
    });
    await first.close();
    const reopened = await FileLocalVaultStore.open(target);
    await reopened.close();
  });

  it('verifies inherited Windows directory ACLs and protects every owned file', async () => {
    const platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform');
    let store: FileLocalVaultStore | undefined;
    try {
      Object.defineProperty(process, 'platform', {
        configurable: true,
        value: 'win32',
      });
      const target = await targetPath();
      const canonicalDirectory = await realpath(dirname(target));
      const canonicalTarget = join(canonicalDirectory, 'vault.json');
      store = await FileLocalVaultStore.open(target);
      await store.create(document());
      await store.update(document(1), revision(0));
      await store.close();
      store = undefined;

      expect(aclMocks.verifyDirectory).toHaveBeenCalledWith(canonicalDirectory);
      expect(aclMocks.set).not.toHaveBeenCalledWith(canonicalDirectory);
      expect(aclMocks.set).toHaveBeenCalledWith(`${canonicalTarget}.lock`);
      expect(
        aclMocks.set.mock.calls.some(([path]) =>
          String(path).includes('.vault.json.kavrix-'),
        ),
      ).toBe(true);
      expect(aclMocks.verify).toHaveBeenCalledWith(`${canonicalTarget}.lock`);
      expect(aclMocks.verify).toHaveBeenCalledWith(canonicalTarget);
    } finally {
      await store?.close();
      if (platformDescriptor !== undefined) {
        Object.defineProperty(process, 'platform', platformDescriptor);
      }
    }
  });

  it('validates an existing Windows parent without mutating its ACL', async () => {
    const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
    try {
      Object.defineProperty(process, 'platform', {
        configurable: true,
        value: 'win32',
      });
      const target = await targetPath();
      const canonicalDirectory = await realpath(dirname(target));
      await expect(FileLocalVaultStore.validatePath(target)).resolves.toBeUndefined();
      expect(aclMocks.verifyDirectory).toHaveBeenCalledWith(canonicalDirectory);
      expect(aclMocks.set).not.toHaveBeenCalledWith(canonicalDirectory);
    } finally {
      if (descriptor !== undefined)
        Object.defineProperty(process, 'platform', descriptor);
    }
  });

  it('fails closed after close and allows idempotent close', async () => {
    const target = await targetPath();
    const store = await FileLocalVaultStore.open(target);
    await store.close();
    await store.close();
    await expect(store.ping()).rejects.toMatchObject({ code: 'closed' });
    await expect(store.get('vault.one')).rejects.toBeInstanceOf(
      EncryptedVaultStoreError,
    );
  });

  it('rejects malformed, noncanonical, and oversized document files', async () => {
    const malformedTarget = await targetPath();
    await writeRestricted(malformedTarget, '{"format":"not-a-vault"}\n');
    await expect(FileLocalVaultStore.open(malformedTarget)).rejects.toMatchObject({
      code: 'invalid',
    });

    const noncanonicalTarget = await targetPath();
    await writeRestricted(
      noncanonicalTarget,
      `${JSON.stringify(document(), null, 2)}\n`,
    );
    await expect(FileLocalVaultStore.open(noncanonicalTarget)).rejects.toMatchObject({
      code: 'invalid',
    });

    const oversizedTarget = await targetPath();
    await writeRestricted(oversizedTarget, 'x');
    await truncate(oversizedTarget, MAX_FILE_LOCAL_VAULT_BYTES + 1);
    await expect(FileLocalVaultStore.open(oversizedTarget)).rejects.toMatchObject({
      code: 'invalid',
    });
  });

  it.skipIf(process.platform === 'win32')(
    'rejects unsafe file permissions, symlinks, and hardlinks',
    async () => {
      const broadTarget = await targetPath();
      await writeFile(broadTarget, `${JSON.stringify(document())}\n`, { mode: 0o644 });
      await chmod(broadTarget, 0o644);
      await expect(FileLocalVaultStore.open(broadTarget)).rejects.toMatchObject({
        code: 'invalid',
      });

      const symlinkTarget = await targetPath();
      const symlinkSource = `${symlinkTarget}.source`;
      await writeRestricted(symlinkSource, `${JSON.stringify(document())}\n`);
      await symlink(symlinkSource, symlinkTarget);
      await expect(FileLocalVaultStore.open(symlinkTarget)).rejects.toMatchObject({
        code: 'invalid',
      });

      const hardlinkTarget = await targetPath();
      const hardlinkSource = `${hardlinkTarget}.source`;
      await writeRestricted(hardlinkSource, `${JSON.stringify(document())}\n`);
      await link(hardlinkSource, hardlinkTarget);
      await expect(FileLocalVaultStore.open(hardlinkTarget)).rejects.toMatchObject({
        code: 'invalid',
      });
    },
  );

  it.skipIf(process.platform === 'win32')(
    'rejects a group-writable containing directory before creating artifacts',
    async () => {
      const directory = await temporaryDirectory();
      await chmod(directory, 0o770);
      const target = join(directory, 'vault.json');
      await expect(FileLocalVaultStore.open(target)).rejects.toMatchObject({
        code: 'invalid',
      });
      expect(await readdir(directory)).toEqual([]);
    },
  );
});

async function targetPath(): Promise<string> {
  return join(await temporaryDirectory(), 'vault.json');
}

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'kavrix-file-store-'));
  temporaryDirectories.push(directory);
  if (process.platform !== 'win32') await chmod(directory, 0o700);
  return directory;
}

async function writeRestricted(path: string, contents: string): Promise<void> {
  await writeFile(path, contents, { mode: 0o600 });
  if (process.platform !== 'win32') await chmod(path, 0o600);
}

function document(revision = 0): LocalVaultDocument {
  const vaultId = 'vault.one';
  const slotId = 'slot.one';
  const metadataDigest = Buffer.alloc(32).toString('base64url');
  const nonce = Buffer.alloc(24).toString('base64url');
  const authenticationTag = Buffer.alloc(16).toString('base64url');
  const wrappedRootKey = {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce,
    ciphertext: Buffer.alloc(32).toString('base64url'),
    authenticationTag,
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType: 'wrapped-root-key',
      entityId: slotId,
      purpose: 'vrk-slot',
    },
    keyVersion: 1,
  };
  return localVaultDocumentSchema.parse({
    format: 'kavrix-local-vault',
    version: 2,
    id: vaultId,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    keySlot: {
      slotVersion: 1,
      id: slotId,
      state: 'active',
      keyVersion: 1,
      wrappedRootKey,
      createdAt: timestamp,
      type: 'portable-key',
      derivation: {
        algorithm: 'hkdf-sha256',
        version: 1,
        salt: Buffer.alloc(32).toString('base64url'),
        context: 'credvault/v1/portable-key-wrap',
        outputLength: 32,
      },
    },
    recoverySlots: [],
    revision,
    encryptedPayload: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce,
      ciphertext: Buffer.from('opaque-ciphertext').toString('base64url'),
      authenticationTag,
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId,
        revision,
        metadataDigest,
        entityType: 'vault-preferences',
        entityId: vaultId,
        purpose: 'vault-preferences',
      },
      keyVersion: 1,
    },
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

function revision(value: number): LocalVaultDocument['revision'] {
  return vaultRevisionSchema.parse(value);
}
