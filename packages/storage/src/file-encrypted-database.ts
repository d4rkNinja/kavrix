import { randomBytes } from 'node:crypto';
import type { BigIntStats } from 'node:fs';
import {
  constants,
  link,
  lstat,
  open,
  realpath,
  rename,
  stat,
  unlink,
  type FileHandle,
} from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

import {
  databaseIdSchema,
  databaseRevisionSchema,
  databaseVaultDocumentSchema,
  encryptedDatabaseDocumentSchema,
  fileDatabaseContainerSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type DatabaseId,
  type DatabaseRevision,
  type DatabaseVaultDocument,
  type EncryptedDatabaseDocument,
  type FileDatabaseContainer,
  type VaultId,
  type VaultRevision,
} from '@kavrix/schemas';
// ACL-only platform boundary; this subpath does not expose key or crypto APIs.
// eslint-disable-next-line no-restricted-imports
import {
  setWindowsUserOnlyAcl,
  verifyWindowsUserOnlyAcl,
} from '@kavrix/key-files/windows-acl';

import {
  EncryptedDatabaseStoreError,
  type CreateVaultInput,
  type DeleteVaultInput,
  type EncryptedDatabaseStore,
  type UpdateVaultInput,
} from './encrypted-database-store.js';

/** The exact maximum serialized UTF-8 size of a local encrypted database. */
export const MAX_FILE_ENCRYPTED_DATABASE_BYTES = 32 * 1024 * 1024;

type FileIdentity = Readonly<{ dev: bigint; ino: bigint }>;
type ResolvedFileTarget = Readonly<{
  directoryPath: string;
  targetPath: string;
  lockPath: string;
}>;
type ReadContainerResult = Readonly<{
  container: FileDatabaseContainer;
  identity: FileIdentity;
}>;

/**
 * Opaque encrypted-database storage backed by one protected, canonical local
 * file. The adapter never decrypts or interprets encrypted fields.
 */
export class FileEncryptedDatabaseStore implements EncryptedDatabaseStore {
  readonly #directoryPath: string;
  readonly #targetPath: string;
  readonly #lockPath: string;
  readonly #lockHandle: FileHandle;
  readonly #lockIdentity: FileIdentity;
  #closed = false;

  private constructor(
    target: ResolvedFileTarget,
    lockHandle: FileHandle,
    lockIdentity: FileIdentity,
  ) {
    this.#directoryPath = target.directoryPath;
    this.#targetPath = target.targetPath;
    this.#lockPath = target.lockPath;
    this.#lockHandle = lockHandle;
    this.#lockIdentity = lockIdentity;
  }

  static async validatePath(path: string): Promise<void> {
    const target = await resolveTarget(path);
    await readContainerIfPresent(target.targetPath);
  }

  static async open(path: string): Promise<FileEncryptedDatabaseStore> {
    const target = await resolveTarget(path);
    const acquired = await acquireLock(target.lockPath);
    try {
      const store = new FileEncryptedDatabaseStore(
        target,
        acquired.handle,
        acquired.identity,
      );
      await store.ping();
      return store;
    } catch (error) {
      await releaseLock(acquired.handle, target.lockPath, acquired.identity).catch(
        () => undefined,
      );
      if (error instanceof EncryptedDatabaseStoreError) throw error;
      throw new EncryptedDatabaseStoreError('operation');
    }
  }

  async ping(): Promise<void> {
    this.#assertOpen();
    await readContainerIfPresent(this.#targetPath);
  }

  async getDatabase(databaseId: DatabaseId): Promise<EncryptedDatabaseDocument | null> {
    this.#assertOpen();
    const id = parseDatabaseId(databaseId);
    const current = await readContainerIfPresent(this.#targetPath);
    if (current?.container.database.id !== id) return null;
    return parseDatabaseDocument(current.container.database);
  }

  async createDatabase(document: EncryptedDatabaseDocument): Promise<void> {
    this.#assertOpen();
    const database = parseDatabaseDocument(document);
    if ((await readContainerIfPresent(this.#targetPath)) !== null) {
      throw new EncryptedDatabaseStoreError('exists');
    }
    await publishContainer(
      this.#directoryPath,
      this.#targetPath,
      canonicalizeContainer({
        format: 'kavrix-file-database-container',
        version: 1,
        database,
        vaults: {},
      }),
      'create',
    );
  }

  async updateDatabase(
    document: EncryptedDatabaseDocument,
    expectedRevision: DatabaseRevision,
  ): Promise<void> {
    this.#assertOpen();
    const database = parseDatabaseDocument(document);
    const expected = parseDatabaseRevision(expectedRevision);
    assertNextRevision(database.revision, expected);
    const current = await readContainerIfPresent(this.#targetPath);
    if (
      current?.container.database.id !== database.id ||
      current.container.database.revision !== expected
    ) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    await publishContainer(
      this.#directoryPath,
      this.#targetPath,
      canonicalizeContainer({ ...current.container, database }),
      'replace',
      current.identity,
    );
  }

  async listVaults(databaseId: DatabaseId): Promise<readonly DatabaseVaultDocument[]> {
    this.#assertOpen();
    const id = parseDatabaseId(databaseId);
    const current = await readContainerIfPresent(this.#targetPath);
    if (current?.container.database.id !== id) return [];
    return Object.values(current.container.vaults)
      .sort((left, right) => compareOpaqueIds(left.id, right.id))
      .map((vault) => parseVaultDocument(vault));
  }

  async getVault(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<DatabaseVaultDocument | null> {
    this.#assertOpen();
    const database = parseDatabaseId(databaseId);
    const id = parseVaultId(vaultId);
    const current = await readContainerIfPresent(this.#targetPath);
    if (current?.container.database.id !== database) return null;
    const vault = current.container.vaults[id];
    return vault === undefined ? null : parseVaultDocument(vault);
  }

  async createVault(input: CreateVaultInput): Promise<void> {
    this.#assertOpen();
    const { database, expectedDatabaseRevision, vault } = parseCreateVaultInput(input);
    assertNextRevision(database.revision, expectedDatabaseRevision);
    if (
      vault.databaseId !== database.id ||
      vault.databaseRevision !== database.revision
    ) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    const current = await readContainerIfPresent(this.#targetPath);
    if (
      current?.container.database.id !== database.id ||
      current.container.database.revision !== expectedDatabaseRevision
    ) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    if (current.container.vaults[vault.id] !== undefined) {
      throw new EncryptedDatabaseStoreError('exists');
    }
    await publishContainer(
      this.#directoryPath,
      this.#targetPath,
      canonicalizeContainer({
        ...current.container,
        database,
        vaults: { ...current.container.vaults, [vault.id]: vault },
      }),
      'replace',
      current.identity,
    );
  }

  async updateVault(input: UpdateVaultInput): Promise<void> {
    this.#assertOpen();
    const { vault, expectedVaultRevision } = parseUpdateVaultInput(input);
    assertNextRevision(vault.revision, expectedVaultRevision);
    const current = await readContainerIfPresent(this.#targetPath);
    if (current?.container.database.id !== vault.databaseId) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    const existing = current.container.vaults[vault.id];
    if (existing?.revision !== expectedVaultRevision)
      throw new EncryptedDatabaseStoreError('conflict');
    await publishContainer(
      this.#directoryPath,
      this.#targetPath,
      canonicalizeContainer({
        ...current.container,
        vaults: { ...current.container.vaults, [vault.id]: vault },
      }),
      'replace',
      current.identity,
    );
  }

  async deleteVault(input: DeleteVaultInput): Promise<void> {
    this.#assertOpen();
    const { database, expectedDatabaseRevision, vaultId, expectedVaultRevision } =
      parseDeleteVaultInput(input);
    assertNextRevision(database.revision, expectedDatabaseRevision);
    const current = await readContainerIfPresent(this.#targetPath);
    if (
      current?.container.database.id !== database.id ||
      current.container.database.revision !== expectedDatabaseRevision
    ) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    const existing = current.container.vaults[vaultId];
    if (existing?.revision !== expectedVaultRevision)
      throw new EncryptedDatabaseStoreError('conflict');
    const { [vaultId]: deletedVault, ...vaults } = current.container.vaults;
    void deletedVault;
    await publishContainer(
      this.#directoryPath,
      this.#targetPath,
      canonicalizeContainer({ ...current.container, database, vaults }),
      'replace',
      current.identity,
    );
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    try {
      await releaseLock(this.#lockHandle, this.#lockPath, this.#lockIdentity);
      await syncDirectory(this.#directoryPath);
    } catch {
      throw new EncryptedDatabaseStoreError('operation');
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new EncryptedDatabaseStoreError('closed');
  }
}

function parseDatabaseId(value: unknown): DatabaseId {
  try {
    return databaseIdSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseVaultId(value: unknown): VaultId {
  try {
    return vaultIdSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseDatabaseRevision(value: unknown): DatabaseRevision {
  try {
    return databaseRevisionSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseVaultRevision(value: unknown): VaultRevision {
  try {
    return vaultRevisionSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseDatabaseDocument(value: unknown): EncryptedDatabaseDocument {
  try {
    return encryptedDatabaseDocumentSchema.parse(structuredClone(value));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseVaultDocument(value: unknown): DatabaseVaultDocument {
  try {
    return databaseVaultDocumentSchema.parse(structuredClone(value));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseCreateVaultInput(input: unknown): Readonly<{
  database: EncryptedDatabaseDocument;
  expectedDatabaseRevision: DatabaseRevision;
  vault: DatabaseVaultDocument;
}> {
  const fields = parseInputRecord(input);
  return {
    database: parseDatabaseDocument(fields['database']),
    expectedDatabaseRevision: parseDatabaseRevision(fields['expectedDatabaseRevision']),
    vault: parseVaultDocument(fields['vault']),
  };
}

function parseUpdateVaultInput(input: unknown): Readonly<{
  expectedVaultRevision: VaultRevision;
  vault: DatabaseVaultDocument;
}> {
  const fields = parseInputRecord(input);
  return {
    vault: parseVaultDocument(fields['vault']),
    expectedVaultRevision: parseVaultRevision(fields['expectedVaultRevision']),
  };
}

function parseDeleteVaultInput(input: unknown): Readonly<{
  database: EncryptedDatabaseDocument;
  expectedDatabaseRevision: DatabaseRevision;
  expectedVaultRevision: VaultRevision;
  vaultId: VaultId;
}> {
  const fields = parseInputRecord(input);
  return {
    database: parseDatabaseDocument(fields['database']),
    expectedDatabaseRevision: parseDatabaseRevision(fields['expectedDatabaseRevision']),
    expectedVaultRevision: parseVaultRevision(fields['expectedVaultRevision']),
    vaultId: parseVaultId(fields['vaultId']),
  };
}

function parseInputRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  return value as Record<string, unknown>;
}

function assertNextRevision(actual: number, expected: number): void {
  if (actual !== expected + 1) throw new EncryptedDatabaseStoreError('invalid');
}

function canonicalizeContainer(value: FileDatabaseContainer): FileDatabaseContainer {
  const vaults: Record<string, DatabaseVaultDocument> = {};
  for (const rawId of Object.keys(value.vaults).sort(compareOpaqueIds)) {
    const id = parseVaultId(rawId);
    const vault = value.vaults[id];
    if (vault === undefined) throw new EncryptedDatabaseStoreError('invalid');
    vaults[id] = parseVaultDocument(vault);
  }
  try {
    return fileDatabaseContainerSchema.parse({
      format: value.format,
      version: value.version,
      database: parseDatabaseDocument(value.database),
      vaults,
    });
  } catch (error) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

async function resolveTarget(inputPath: string): Promise<ResolvedFileTarget> {
  if (
    typeof inputPath !== 'string' ||
    inputPath.length === 0 ||
    hasControlCharacter(inputPath)
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  try {
    const absolutePath = isAbsolute(inputPath) ? inputPath : resolve(inputPath);
    const targetName = basename(absolutePath);
    validateBasename(targetName);
    const directoryPath = await realpath(dirname(absolutePath));
    const directory = await stat(directoryPath, { bigint: true });
    if (!directory.isDirectory()) throw new EncryptedDatabaseStoreError('invalid');
    if (process.platform === 'win32') await setWindowsUserOnlyAcl(directoryPath);
    await assertOwnedPermissions(directory, directoryPath, false);
    const targetPath = join(directoryPath, targetName);
    return { directoryPath, targetPath, lockPath: `${targetPath}.lock` };
  } catch (error) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function validateBasename(value: string): void {
  if (
    value.length === 0 ||
    value === '.' ||
    value === '..' ||
    hasControlCharacter(value)
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  if (
    process.platform === 'win32' &&
    (value.includes(':') ||
      value.endsWith('.') ||
      value.endsWith(' ') ||
      /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu.test(value))
  ) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function hasControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });
}

async function acquireLock(
  lockPath: string,
): Promise<Readonly<{ handle: FileHandle; identity: FileIdentity }>> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      lockPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR,
      0o600,
    );
    await setAndVerifyCreatedFile(lockPath, handle);
    await handle.sync();
    const metadata = await handle.stat({ bigint: true });
    return { handle, identity: identityOf(metadata) };
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (handle !== undefined) await unlink(lockPath).catch(() => undefined);
    if (fileErrorCode(error) === 'EEXIST')
      throw new EncryptedDatabaseStoreError('busy');
    throw new EncryptedDatabaseStoreError('operation');
  }
}

async function releaseLock(
  handle: FileHandle,
  lockPath: string,
  identity: FileIdentity,
): Promise<void> {
  let failure = false;
  try {
    await assertPathIdentity(lockPath, identity);
  } catch {
    failure = true;
  }
  try {
    await handle.close();
  } catch {
    failure = true;
  }
  if (!failure) {
    try {
      await unlink(lockPath);
    } catch {
      failure = true;
    }
  }
  if (failure) throw new EncryptedDatabaseStoreError('operation');
}

async function readContainerIfPresent(
  path: string,
): Promise<ReadContainerResult | null> {
  let before: BigIntStats;
  try {
    before = await lstat(path, { bigint: true });
  } catch (error) {
    if (fileErrorCode(error) === 'ENOENT') return null;
    throw new EncryptedDatabaseStoreError('operation');
  }
  await assertOwnedPermissions(before, path, true);
  const identity = identityOf(before);
  let handle: FileHandle | undefined;
  let contents: Buffer | undefined;
  try {
    handle = await open(path, noFollowReadFlags());
    const opened = await handle.stat({ bigint: true });
    await assertOwnedPermissions(opened, path, true);
    if (!sameIdentity(identity, identityOf(opened)))
      throw new EncryptedDatabaseStoreError('invalid');
    const size = Number(opened.size);
    if (
      !Number.isSafeInteger(size) ||
      size < 2 ||
      size > MAX_FILE_ENCRYPTED_DATABASE_BYTES
    ) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    contents = Buffer.alloc(size + 1);
    let offset = 0;
    while (offset < contents.byteLength) {
      const result = await handle.read(
        contents,
        offset,
        contents.byteLength - offset,
        offset,
      );
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (
      offset !== size ||
      after.size !== opened.size ||
      !sameIdentity(identity, identityOf(after))
    ) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    await assertPathIdentity(path, identity);
    const text = contents.subarray(0, size).toString('utf8');
    const container = canonicalizeContainer(
      fileDatabaseContainerSchema.parse(JSON.parse(text) as unknown),
    );
    if (text !== serializeContainer(container))
      throw new EncryptedDatabaseStoreError('invalid');
    return { container, identity };
  } catch (error) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('invalid');
  } finally {
    contents?.fill(0);
    await handle?.close().catch(() => undefined);
  }
}

async function publishContainer(
  directoryPath: string,
  targetPath: string,
  container: FileDatabaseContainer,
  mode: 'create' | 'replace',
  expectedIdentity?: FileIdentity,
): Promise<void> {
  const contents = Buffer.from(serializeContainer(container), 'utf8');
  if (contents.byteLength > MAX_FILE_ENCRYPTED_DATABASE_BYTES) {
    contents.fill(0);
    throw new EncryptedDatabaseStoreError('invalid');
  }
  const temporaryPath = join(
    directoryPath,
    `.${basename(targetPath)}.kavrix-${String(process.pid)}-${randomBytes(16).toString('hex')}.tmp`,
  );
  let handle: FileHandle | undefined;
  let published = false;
  try {
    handle = await open(
      temporaryPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR,
      0o600,
    );
    await setAndVerifyCreatedFile(temporaryPath, handle);
    await handle.writeFile(contents);
    await handle.sync();
    const staged = await handle.stat({ bigint: true });
    await assertOwnedPermissions(staged, temporaryPath, true);
    if (staged.size !== BigInt(contents.byteLength))
      throw new EncryptedDatabaseStoreError('operation');
    const stagedIdentity = identityOf(staged);
    await handle.close();
    handle = undefined;
    await assertPathIdentity(temporaryPath, stagedIdentity);
    if (mode === 'create') {
      try {
        await link(temporaryPath, targetPath);
      } catch (error) {
        if (fileErrorCode(error) === 'EEXIST')
          throw new EncryptedDatabaseStoreError('exists');
        throw error;
      }
      await unlink(temporaryPath);
    } else {
      if (expectedIdentity === undefined)
        throw new EncryptedDatabaseStoreError('operation');
      await assertPathIdentity(targetPath, expectedIdentity);
      await rename(temporaryPath, targetPath);
    }
    const final = await readContainerIfPresent(targetPath);
    if (
      final === null ||
      serializeContainer(final.container) !== contents.toString('utf8')
    ) {
      throw new EncryptedDatabaseStoreError('operation');
    }
    await syncDirectory(directoryPath);
    published = true;
  } catch (error) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('operation');
  } finally {
    contents.fill(0);
    await handle?.close().catch(() => undefined);
    if (!published) await unlink(temporaryPath).catch(() => undefined);
  }
}

function serializeContainer(container: FileDatabaseContainer): string {
  return `${JSON.stringify(canonicalizeContainer(container))}\n`;
}

async function setAndVerifyCreatedFile(
  targetPath: string,
  handle: FileHandle,
): Promise<void> {
  if (process.platform === 'win32') await setWindowsUserOnlyAcl(targetPath);
  else await handle.chmod(0o600);
  const metadata = await handle.stat({ bigint: true });
  await assertOwnedPermissions(metadata, targetPath, true);
}

async function assertOwnedPermissions(
  metadata: BigIntStats,
  path: string,
  requireFile: boolean,
): Promise<void> {
  if (requireFile) {
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1n) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
  } else if (!metadata.isDirectory()) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  if (process.platform === 'win32') {
    try {
      await verifyWindowsUserOnlyAcl(path);
      return;
    } catch {
      throw new EncryptedDatabaseStoreError('invalid');
    }
  }
  const getuid = process.getuid;
  if (getuid === undefined || metadata.uid !== BigInt(getuid())) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  if (requireFile) {
    if ((metadata.mode & 0o777n) !== 0o600n)
      throw new EncryptedDatabaseStoreError('invalid');
  } else if ((metadata.mode & 0o022n) !== 0n) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

async function assertPathIdentity(path: string, expected: FileIdentity): Promise<void> {
  try {
    const metadata = await lstat(path, { bigint: true });
    await assertOwnedPermissions(metadata, path, true);
    if (!sameIdentity(identityOf(metadata), expected)) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
  } catch (error) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('operation');
  }
}

async function syncDirectory(path: string): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, constants.O_RDONLY);
    await handle.sync();
  } catch (error) {
    const code = fileErrorCode(error);
    if (
      process.platform !== 'win32' ||
      (code !== 'EPERM' && code !== 'EACCES' && code !== 'EINVAL')
    ) {
      throw new EncryptedDatabaseStoreError('operation');
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function noFollowReadFlags(): number {
  return constants.O_RDONLY | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW);
}

function identityOf(value: {
  readonly dev: bigint;
  readonly ino: bigint;
}): FileIdentity {
  return { dev: value.dev, ino: value.ino };
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function compareOpaqueIds(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function fileErrorCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String(error.code)
    : undefined;
}
