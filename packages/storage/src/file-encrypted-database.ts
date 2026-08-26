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
  verifyWindowsDirectoryAcl,
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
  directoryIdentity: FileIdentity;
  targetPath: string;
  lockPath: string;
}>;
type ReadContainerResult = Readonly<{
  container: FileDatabaseContainer;
  identity: FileIdentity;
}>;
type RetainedFile = Readonly<{
  handle: FileHandle;
  identity: FileIdentity;
}>;
type OwnedInitialization = Readonly<{
  databaseId: DatabaseId;
  retained: RetainedFile;
}>;

/**
 * Opaque encrypted-database storage backed by one protected, canonical local
 * file. The adapter never decrypts or interprets encrypted fields.
 */
export class FileEncryptedDatabaseStore implements EncryptedDatabaseStore {
  readonly #directoryPath: string;
  readonly #targetPath: string;
  readonly #lockPath: string;
  readonly #directoryIdentity: FileIdentity;
  readonly #lockHandle: FileHandle;
  readonly #lockIdentity: FileIdentity;
  #ownedInitialization: OwnedInitialization | undefined;
  readonly #retiredInitializationHandles = new Set<FileHandle>();
  #closed = false;

  private constructor(
    target: ResolvedFileTarget,
    lockHandle: FileHandle,
    lockIdentity: FileIdentity,
  ) {
    this.#directoryPath = target.directoryPath;
    this.#directoryIdentity = target.directoryIdentity;
    this.#targetPath = target.targetPath;
    this.#lockPath = target.lockPath;
    this.#lockHandle = lockHandle;
    this.#lockIdentity = lockIdentity;
  }

  static async validatePath(path: string): Promise<void> {
    const target = await resolveTarget(path);
    await assertDirectoryIdentity(target);
    await readContainerIfPresent(target.targetPath);
    await assertDirectoryIdentity(target);
  }

  static async open(path: string): Promise<FileEncryptedDatabaseStore> {
    const target = await resolveTarget(path);
    const acquired = await acquireLock(target);
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
    await this.#readContainer();
  }

  async getDatabase(databaseId: DatabaseId): Promise<EncryptedDatabaseDocument | null> {
    this.#assertOpen();
    const id = parseDatabaseId(databaseId);
    const current = await this.#readContainer();
    if (current?.container.database.id !== id) return null;
    return parseDatabaseDocument(current.container.database);
  }

  async createDatabase(document: EncryptedDatabaseDocument): Promise<void> {
    this.#assertOpen();
    const database = parseDatabaseDocument(document);
    if ((await this.#readContainer()) !== null) {
      throw new EncryptedDatabaseStoreError('exists');
    }
    const retained = await publishContainer(
      this.#target(),
      this.#lockIdentity,
      canonicalizeContainer({
        format: 'kavrix-file-database-container',
        version: 1,
        database,
        vaults: {},
      }),
      'create',
    );
    await this.#adoptPublishedHandle(database.id, retained, true);
  }

  /**
   * Rolls back the database created by this store through its retained exact
   * file object. The pathname is never used as an ownership capability.
   */
  async rollbackOwnedInitialization(databaseId: DatabaseId): Promise<void> {
    this.#assertOpen();
    const id = parseDatabaseId(databaseId);
    const owned = this.#ownedInitialization;
    if (owned?.databaseId !== id) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    this.#ownedInitialization = undefined;
    let failure = false;
    let truncate = false;
    try {
      await assertTrustedPublicationState(
        this.#target(),
        this.#lockPath,
        this.#lockIdentity,
      );
      const metadata = await owned.retained.handle.stat({ bigint: true });
      assertRetainedFileMetadata(metadata);
      if (metadata.nlink > 1n) throw new EncryptedDatabaseStoreError('invalid');
      const current = await lstat(this.#targetPath, { bigint: true }).catch(
        (error: unknown) => {
          if (fileErrorCode(error) === 'ENOENT') return undefined;
          throw error;
        },
      );
      if (
        current !== undefined &&
        sameIdentity(identityOf(current), owned.retained.identity)
      ) {
        await assertOwnedPermissions(current, this.#targetPath, true);
        if (current.nlink !== 1n) throw new EncryptedDatabaseStoreError('invalid');
      }
      truncate = true;
    } catch {
      failure = true;
    }
    if (truncate) {
      try {
        await fileEncryptedDatabaseEffects.truncate(owned.retained.handle);
        await fileEncryptedDatabaseEffects.sync(owned.retained.handle);
        await assertTrustedPublicationState(
          this.#target(),
          this.#lockPath,
          this.#lockIdentity,
        );
      } catch {
        failure = true;
      }
    }
    try {
      await fileEncryptedDatabaseEffects.closeOwned(owned.retained.handle);
    } catch {
      failure = true;
    }
    for (const handle of this.#retireInitializationHandles()) {
      try {
        await fileEncryptedDatabaseEffects.closeOwned(handle);
      } catch {
        failure = true;
      }
    }
    if (!failure && truncate) {
      try {
        await assertTrustedPublicationState(
          this.#target(),
          this.#lockPath,
          this.#lockIdentity,
        );
        const current = await lstat(this.#targetPath, { bigint: true }).catch(
          (error: unknown) => {
            if (fileErrorCode(error) === 'ENOENT') return undefined;
            throw error;
          },
        );
        if (
          current !== undefined &&
          sameIdentity(identityOf(current), owned.retained.identity)
        ) {
          await assertOwnedPermissions(current, this.#targetPath, true);
          if (current.nlink !== 1n || current.size !== 0n) {
            throw new EncryptedDatabaseStoreError('operation');
          }
        }
        await assertTrustedPublicationState(
          this.#target(),
          this.#lockPath,
          this.#lockIdentity,
        );
      } catch {
        failure = true;
      }
    }
    if (failure) throw new EncryptedDatabaseStoreError('operation');
  }

  async updateDatabase(
    document: EncryptedDatabaseDocument,
    expectedRevision: DatabaseRevision,
  ): Promise<void> {
    this.#assertOpen();
    const database = parseDatabaseDocument(document);
    const expected = parseDatabaseRevision(expectedRevision);
    assertNextRevision(database.revision, expected);
    const current = await this.#readContainer();
    if (
      current?.container.database.id !== database.id ||
      current.container.database.revision !== expected
    ) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    await this.#publishAndAdopt(
      database.id,
      canonicalizeContainer({ ...current.container, database }),
      'replace',
      current.identity,
    );
  }

  async listVaults(databaseId: DatabaseId): Promise<readonly DatabaseVaultDocument[]> {
    this.#assertOpen();
    const id = parseDatabaseId(databaseId);
    const current = await this.#readContainer();
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
    const current = await this.#readContainer();
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
    const current = await this.#readContainer();
    if (
      current?.container.database.id !== database.id ||
      current.container.database.revision !== expectedDatabaseRevision
    ) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    if (current.container.vaults[vault.id] !== undefined) {
      throw new EncryptedDatabaseStoreError('exists');
    }
    await this.#publishAndAdopt(
      database.id,
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
    const current = await this.#readContainer();
    if (current?.container.database.id !== vault.databaseId) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    const existing = current.container.vaults[vault.id];
    if (existing?.revision !== expectedVaultRevision)
      throw new EncryptedDatabaseStoreError('conflict');
    await this.#publishAndAdopt(
      vault.databaseId,
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
    const current = await this.#readContainer();
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
    await this.#publishAndAdopt(
      database.id,
      canonicalizeContainer({ ...current.container, database, vaults }),
      'replace',
      current.identity,
    );
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    let failure = false;
    for (const handle of this.#takeInitializationHandles()) {
      try {
        await fileEncryptedDatabaseEffects.closeOwned(handle);
      } catch {
        failure = true;
      }
    }
    try {
      await this.#assertTrusted();
    } catch {
      failure = true;
    }
    try {
      await releaseLock(this.#lockHandle, this.#lockPath, this.#lockIdentity);
    } catch {
      failure = true;
    }
    try {
      await syncDirectory(this.#directoryPath);
    } catch {
      failure = true;
    }
    if (failure) throw new EncryptedDatabaseStoreError('operation');
  }

  #assertOpen(): void {
    if (this.#closed) throw new EncryptedDatabaseStoreError('closed');
  }

  #target(): ResolvedFileTarget {
    return {
      directoryPath: this.#directoryPath,
      directoryIdentity: this.#directoryIdentity,
      targetPath: this.#targetPath,
      lockPath: this.#lockPath,
    };
  }

  async #assertTrusted(): Promise<void> {
    await assertDirectoryIdentity(this.#target());
    await assertPathIdentity(this.#lockPath, this.#lockIdentity);
  }

  async #adoptPublishedHandle(
    databaseId: DatabaseId,
    retained: RetainedFile,
    initialize = false,
  ): Promise<void> {
    const existing = this.#ownedInitialization;
    if (initialize) {
      if (existing !== undefined) {
        await fileEncryptedDatabaseEffects
          .closeOwned(retained.handle)
          .catch(() => undefined);
        throw new EncryptedDatabaseStoreError('operation');
      }
      this.#ownedInitialization = { databaseId, retained };
      return;
    }
    if (existing === undefined) {
      try {
        await fileEncryptedDatabaseEffects.closeOwned(retained.handle);
      } catch {
        throw new EncryptedDatabaseStoreError('operation');
      }
      return;
    }
    if (existing.databaseId !== databaseId) {
      await fileEncryptedDatabaseEffects
        .closeOwned(retained.handle)
        .catch(() => undefined);
      throw new EncryptedDatabaseStoreError('invalid');
    }
    this.#ownedInitialization = { databaseId, retained };
    try {
      await fileEncryptedDatabaseEffects.closeOwned(existing.retained.handle);
    } catch {
      this.#retiredInitializationHandles.add(existing.retained.handle);
      throw new EncryptedDatabaseStoreError('operation');
    }
  }

  async #publishAndAdopt(
    databaseId: DatabaseId,
    container: FileDatabaseContainer,
    mode: 'create' | 'replace',
    expectedIdentity: FileIdentity,
  ): Promise<void> {
    const detached =
      process.platform === 'win32'
        ? await this.#detachInitializationForReplace()
        : undefined;
    try {
      const retained = await publishContainer(
        this.#target(),
        this.#lockIdentity,
        container,
        mode,
        expectedIdentity,
      );
      await this.#adoptPublishedHandle(databaseId, retained, detached !== undefined);
    } catch (error) {
      if (detached !== undefined) {
        try {
          const restored = await openRetainedFile(
            this.#targetPath,
            detached.retained.identity,
          );
          this.#ownedInitialization = {
            databaseId: detached.databaseId,
            retained: restored,
          };
        } catch {
          throw new EncryptedDatabaseStoreError('operation');
        }
      }
      throw error;
    }
  }

  async #detachInitializationForReplace(): Promise<OwnedInitialization | undefined> {
    const existing = this.#ownedInitialization;
    if (existing === undefined) return undefined;
    this.#ownedInitialization = undefined;
    try {
      await fileEncryptedDatabaseEffects.closeOwned(existing.retained.handle);
    } catch {
      this.#ownedInitialization = existing;
      throw new EncryptedDatabaseStoreError('operation');
    }
    return existing;
  }

  #takeInitializationHandles(): FileHandle[] {
    const handles = [...this.#retireInitializationHandles()];
    const active = this.#ownedInitialization?.retained.handle;
    this.#ownedInitialization = undefined;
    if (active !== undefined) handles.unshift(active);
    return handles;
  }

  #retireInitializationHandles(): Set<FileHandle> {
    const handles = new Set(this.#retiredInitializationHandles);
    this.#retiredInitializationHandles.clear();
    return handles;
  }

  async #readContainer(): Promise<ReadContainerResult | null> {
    await this.#assertTrusted();
    const current = await readContainerIfPresent(this.#targetPath);
    await this.#assertTrusted();
    return current;
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
    if (process.platform === 'win32') await verifyWindowsDirectoryAcl(directoryPath);
    await assertOwnedPermissions(directory, directoryPath, false);
    const targetPath = join(directoryPath, targetName);
    return {
      directoryPath,
      directoryIdentity: identityOf(directory),
      targetPath,
      lockPath: `${targetPath}.lock`,
    };
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

const LOCK_METADATA_FORMAT = 'kavrix-database-lock';
const MAX_LOCK_METADATA_BYTES = 256;
const STALE_LOCK_RECOVERY_ATTEMPTS = 3;

type LockMetadata = Readonly<{ format: string; version: 1; pid: number }>;

/**
 * Reports whether the process that owns a surviving lock file is still
 * addressable. `EPERM` means a live process the caller cannot signal;
 * every other failure means no such process exists.
 */
function isProcessLive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return fileErrorCode(error) === 'EPERM';
  }
}

async function writeLockMetadata(handle: FileHandle, pid: number): Promise<void> {
  const metadata: LockMetadata = {
    format: LOCK_METADATA_FORMAT,
    version: 1,
    pid,
  };
  // The payload is non-secret routing metadata bounded well below the
  // container limits; it lets a later invocation distinguish a dead owner
  // from a live one instead of bricking on a hard kill.
  const payload = Buffer.from(JSON.stringify(metadata), 'utf8');
  if (payload.byteLength > MAX_LOCK_METADATA_BYTES) {
    throw new EncryptedDatabaseStoreError('operation');
  }
  await handle.write(payload, 0, payload.byteLength, 0);
}

/**
 * Reads the recorded owner of an existing lock without trusting its content.
 * Returns `undefined` for any foreign, malformed, or oversized payload so the
 * caller treats the lock as live evidence and refuses normally.
 */
async function readLockOwner(lockPath: string): Promise<number | undefined> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(lockPath, constants.O_RDONLY);
    const size = (await handle.stat()).size;
    if (!Number.isInteger(size) || size <= 0 || size > MAX_LOCK_METADATA_BYTES) {
      return undefined;
    }
    const contents = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const read = await handle.read(contents, offset, size - offset, offset);
      if (read.bytesRead === 0) break;
      offset += read.bytesRead;
    }
    if (offset !== size) return undefined;
    const parsed: unknown = JSON.parse(contents.toString('utf8'));
    if (typeof parsed !== 'object' || parsed === null) return undefined;
    const record = parsed as Record<string, unknown>;
    if (
      record['format'] !== LOCK_METADATA_FORMAT ||
      record['version'] !== 1 ||
      typeof record['pid'] !== 'number'
    ) {
      return undefined;
    }
    return record['pid'];
  } catch {
    return undefined;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function acquireLock(
  target: ResolvedFileTarget,
): Promise<Readonly<{ handle: FileHandle; identity: FileIdentity }>> {
  const { lockPath } = target;
  for (let attempt = 0; ; attempt += 1) {
    let handle: FileHandle | undefined;
    try {
      await assertDirectoryIdentity(target);
      handle = await open(
        lockPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_RDWR,
        0o600,
      );
      await setAndVerifyCreatedFile(lockPath, handle, 'lock');
      await writeLockMetadata(handle, process.pid);
      await fileEncryptedDatabaseEffects.sync(handle);
      const metadata = await handle.stat({ bigint: true });
      await assertDirectoryIdentity(target);
      return { handle, identity: identityOf(metadata) };
    } catch (error) {
      if (handle !== undefined)
        await fileEncryptedDatabaseEffects.close(handle, 'lock').catch(() => undefined);
      if (handle !== undefined)
        await fileEncryptedDatabaseEffects
          .unlink(lockPath, 'lock-acquire-cleanup')
          .catch(() => undefined);
      if (fileErrorCode(error) !== 'EEXIST') {
        throw new EncryptedDatabaseStoreError('operation');
      }
      // An existing lock is only removable when it provably belongs to a
      // process that no longer exists. Live owners, foreign shapes, and
      // unreadable payloads all keep the fail-closed busy response.
      await inspectExistingLock(lockPath);
      const ownerPid = await readLockOwner(lockPath);
      if (
        ownerPid !== undefined &&
        !isProcessLive(ownerPid) &&
        attempt + 1 < STALE_LOCK_RECOVERY_ATTEMPTS &&
        (await removeStaleLock(lockPath, ownerPid))
      ) {
        continue;
      }
      throw new EncryptedDatabaseStoreError('busy');
    }
  }
}

/**
 * Removes one proven-dead owner's lock only while an opened handle, the current
 * pathname, and the re-read owner metadata still identify the same file.
 * Any observed replacement keeps the lock in place and reports refusal.
 */
async function removeStaleLock(lockPath: string, deadPid: number): Promise<boolean> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(lockPath, noFollowReadFlags());
    const metadata = await handle.stat({ bigint: true });
    await assertOwnedPermissions(metadata, lockPath, true);
    const currentPid = await readLockOwner(lockPath);
    if (
      currentPid !== deadPid ||
      isProcessLive(currentPid) ||
      !sameIdentity(
        identityOf(metadata),
        identityOf(await lstat(lockPath, { bigint: true })),
      )
    )
      return false;
    await fileEncryptedDatabaseEffects.unlink(lockPath, 'lock-release');
    return true;
  } catch {
    return false;
  } finally {
    await handle?.close().catch(() => undefined);
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
    await fileEncryptedDatabaseEffects.close(handle, 'lock');
  } catch {
    failure = true;
  }
  if (!failure) {
    try {
      await fileEncryptedDatabaseEffects.unlink(lockPath, 'lock-release');
    } catch {
      failure = true;
    }
  }
  if (failure) throw new EncryptedDatabaseStoreError('operation');
}

/**
 * An existing sibling lock is only evidence of an active owner when it is the
 * same protected regular-file shape we create ourselves. Never turn hostile
 * filesystem objects into a misleading normal `busy` response.
 */
async function inspectExistingLock(lockPath: string): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    const before = await lstat(lockPath, { bigint: true });
    await assertOwnedPermissions(before, lockPath, true);
    const identity = identityOf(before);
    handle = await open(lockPath, noFollowReadFlags());
    const opened = await handle.stat({ bigint: true });
    await assertOwnedPermissions(opened, lockPath, true);
    if (!sameIdentity(identity, identityOf(opened))) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    await assertPathIdentity(lockPath, identity);
  } catch (error) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('invalid');
  } finally {
    await handle?.close().catch(() => undefined);
  }
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
  target: ResolvedFileTarget,
  lockIdentity: FileIdentity,
  container: FileDatabaseContainer,
  mode: 'create' | 'replace',
  expectedIdentity?: FileIdentity,
): Promise<RetainedFile> {
  const { directoryPath, targetPath, lockPath } = target;
  await assertTrustedPublicationState(target, lockPath, lockIdentity);
  const contents = Buffer.from(serializeContainer(container), 'utf8');
  if (contents.byteLength > MAX_FILE_ENCRYPTED_DATABASE_BYTES) {
    contents.fill(0);
    throw new EncryptedDatabaseStoreError('invalid');
  }
  const temporaryPath = join(
    directoryPath,
    `.${basename(targetPath)}.kavrix-${String(process.pid)}-${randomBytes(16).toString('hex')}.tmp`,
  );
  const backupPath = join(
    directoryPath,
    `.${basename(targetPath)}.kavrix-${String(process.pid)}-${randomBytes(16).toString('hex')}.bak`,
  );
  let handle: FileHandle | undefined;
  let published = false;
  let publishedIdentity: FileIdentity | undefined;
  let backupIdentity: FileIdentity | undefined;
  try {
    handle = await open(
      temporaryPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR,
      0o600,
    );
    await setAndVerifyCreatedFile(temporaryPath, handle, 'temporary');
    await fileEncryptedDatabaseEffects.write(handle, contents);
    await fileEncryptedDatabaseEffects.sync(handle);
    const staged = await handle.stat({ bigint: true });
    await assertOwnedPermissions(staged, temporaryPath, true);
    if (staged.size !== BigInt(contents.byteLength))
      throw new EncryptedDatabaseStoreError('operation');
    const stagedIdentity = identityOf(staged);
    await fileEncryptedDatabaseEffects.close(handle, 'temporary');
    handle = undefined;
    await assertPathIdentity(temporaryPath, stagedIdentity);
    await assertTrustedPublicationState(target, lockPath, lockIdentity);
    await fileEncryptedDatabaseEffects.syncDirectory(directoryPath, 'pre-publish');
    await assertTrustedPublicationState(target, lockPath, lockIdentity);
    if (mode === 'create') {
      try {
        await fileEncryptedDatabaseEffects.link(
          temporaryPath,
          targetPath,
          'publish-create',
        );
      } catch (error) {
        if (fileErrorCode(error) === 'EEXIST')
          throw new EncryptedDatabaseStoreError('exists');
        throw error;
      }
      // The target exists before temporary cleanup; establish a trusted
      // rollback identity now so a failed temporary unlink cannot leave a
      // successful-looking create behind.
      publishedIdentity = stagedIdentity;
      await assertLinkedPublicationIdentity(targetPath, stagedIdentity);
      await fileEncryptedDatabaseEffects.unlink(
        temporaryPath,
        'temporary-after-create',
      );
    } else {
      if (expectedIdentity === undefined)
        throw new EncryptedDatabaseStoreError('operation');
      await assertPathIdentity(targetPath, expectedIdentity);
      await assertTrustedPublicationState(target, lockPath, lockIdentity);
      await fileEncryptedDatabaseEffects.link(targetPath, backupPath, 'backup');
      backupIdentity = await assertBackupIdentity(backupPath, expectedIdentity);
      await fileEncryptedDatabaseEffects.rename(temporaryPath, targetPath, 'publish');
      publishedIdentity = stagedIdentity;
      await assertPathIdentity(targetPath, stagedIdentity);
    }
    await assertTrustedPublicationState(target, lockPath, lockIdentity);
    const finalMetadata = await lstat(targetPath, { bigint: true });
    await assertOwnedPermissions(finalMetadata, targetPath, true, false);
    const finalIdentity = identityOf(finalMetadata);
    if (!sameIdentity(finalIdentity, stagedIdentity)) {
      throw new EncryptedDatabaseStoreError('operation');
    }
    if (process.platform === 'win32') {
      await fileEncryptedDatabaseEffects.setAcl(targetPath, 'final');
      await fileEncryptedDatabaseEffects.verifyAcl(targetPath, 'final');
      await assertPathIdentity(targetPath, finalIdentity);
    }
    await fileEncryptedDatabaseEffects.verifyFinalIdentity(targetPath, finalIdentity);
    const final = await fileEncryptedDatabaseEffects.readFinal(targetPath);
    if (
      final === null ||
      serializeContainer(final.container) !== contents.toString('utf8')
    ) {
      throw new EncryptedDatabaseStoreError('operation');
    }
    await assertTrustedPublicationState(target, lockPath, lockIdentity);
    await fileEncryptedDatabaseEffects.syncDirectory(directoryPath, 'post-publish');
    await assertTrustedPublicationState(target, lockPath, lockIdentity);
    if (backupIdentity !== undefined) {
      await assertPathIdentity(backupPath, backupIdentity);
      await fileEncryptedDatabaseEffects.unlink(backupPath, 'backup-cleanup');
      backupIdentity = undefined;
    }
    const retained = await openRetainedFile(targetPath, publishedIdentity);
    published = true;
    return retained;
  } catch (error) {
    if (publishedIdentity !== undefined) {
      try {
        await rollbackPublishedContainer(
          mode,
          target,
          lockIdentity,
          publishedIdentity,
          backupPath,
          backupIdentity,
        );
        backupIdentity = undefined;
      } catch {
        throw new EncryptedDatabaseStoreError('operation');
      }
      throw new EncryptedDatabaseStoreError('operation');
    }
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('operation');
  } finally {
    contents.fill(0);
    if (handle !== undefined)
      await fileEncryptedDatabaseEffects
        .close(handle, 'temporary')
        .catch(() => undefined);
    if (!published)
      await fileEncryptedDatabaseEffects
        .unlink(temporaryPath, 'temporary-cleanup')
        .catch(() => undefined);
    if (!published && publishedIdentity === undefined && backupIdentity !== undefined)
      await fileEncryptedDatabaseEffects
        .unlink(backupPath, 'backup-cleanup')
        .catch(() => undefined);
    if (published && backupIdentity !== undefined)
      await fileEncryptedDatabaseEffects
        .unlink(backupPath, 'backup-cleanup')
        .catch(() => undefined);
  }
}

async function assertBackupIdentity(
  path: string,
  expected: FileIdentity,
): Promise<FileIdentity> {
  try {
    const metadata = await lstat(path, { bigint: true });
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 2n) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    if (!sameIdentity(identityOf(metadata), expected)) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    if (process.platform === 'win32') await verifyWindowsUserOnlyAcl(path);
    else if ((metadata.mode & 0o777n) !== 0o600n) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    return identityOf(metadata);
  } catch (error) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('operation');
  }
}

async function assertLinkedPublicationIdentity(
  path: string,
  expected: FileIdentity,
): Promise<void> {
  try {
    const metadata = await lstat(path, { bigint: true });
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 2n) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    if (!sameIdentity(identityOf(metadata), expected)) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    if (process.platform === 'win32') await verifyWindowsUserOnlyAcl(path);
    else if ((metadata.mode & 0o777n) !== 0o600n) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
  } catch (error) {
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('operation');
  }
}

async function openRetainedFile(
  path: string,
  expected: FileIdentity,
): Promise<RetainedFile> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, noFollowReadWriteFlags());
    const metadata = await handle.stat({ bigint: true });
    await assertOwnedPermissions(metadata, path, true);
    if (!sameIdentity(identityOf(metadata), expected)) {
      throw new EncryptedDatabaseStoreError('operation');
    }
    await assertPathIdentity(path, expected);
    return { handle, identity: expected };
  } catch (error) {
    await handle?.close().catch(() => undefined);
    if (error instanceof EncryptedDatabaseStoreError) throw error;
    throw new EncryptedDatabaseStoreError('operation');
  }
}

async function rollbackPublishedContainer(
  mode: 'create' | 'replace',
  target: ResolvedFileTarget,
  lockIdentity: FileIdentity,
  publishedIdentity: FileIdentity,
  backupPath: string,
  backupIdentity: FileIdentity | undefined,
): Promise<void> {
  const { directoryPath, lockPath, targetPath } = target;
  await assertTrustedPublicationState(target, lockPath, lockIdentity);
  if (mode === 'create')
    await assertLinkedPublicationIdentity(targetPath, publishedIdentity);
  else await assertPathIdentity(targetPath, publishedIdentity);
  await assertTrustedPublicationState(target, lockPath, lockIdentity);
  if (mode === 'create') {
    await assertTrustedPublicationState(target, lockPath, lockIdentity);
    try {
      await fileEncryptedDatabaseEffects.unlink(targetPath, 'rollback-create');
    } catch {
      await assertTrustedPublicationState(target, lockPath, lockIdentity);
      await assertLinkedPublicationIdentity(targetPath, publishedIdentity);
      await fileEncryptedDatabaseEffects.unlink(targetPath, 'rollback-create');
    }
  } else {
    if (backupIdentity === undefined)
      throw new EncryptedDatabaseStoreError('operation');
    await assertPathIdentity(backupPath, backupIdentity);
    await assertTrustedPublicationState(target, lockPath, lockIdentity);
    try {
      await fileEncryptedDatabaseEffects.rename(backupPath, targetPath, 'rollback');
    } catch {
      await assertTrustedPublicationState(target, lockPath, lockIdentity);
      await assertPathIdentity(targetPath, publishedIdentity);
      await assertPathIdentity(backupPath, backupIdentity);
      await fileEncryptedDatabaseEffects.rename(backupPath, targetPath, 'rollback');
    }
    await assertPathIdentity(targetPath, backupIdentity);
  }
  try {
    await fileEncryptedDatabaseEffects.syncDirectory(directoryPath, 'rollback');
  } catch {
    await assertTrustedPublicationState(target, lockPath, lockIdentity);
    if (mode === 'replace' && backupIdentity !== undefined) {
      await assertPathIdentity(targetPath, backupIdentity);
      await fileEncryptedDatabaseEffects.link(targetPath, backupPath, 'recovery');
      await assertBackupIdentity(backupPath, backupIdentity);
    }
    throw new EncryptedDatabaseStoreError('operation');
  }
  await assertTrustedPublicationState(target, lockPath, lockIdentity);
}

async function assertTrustedPublicationState(
  target: ResolvedFileTarget,
  lockPath: string,
  lockIdentity: FileIdentity,
): Promise<void> {
  await assertDirectoryIdentity(target);
  await assertPathIdentity(lockPath, lockIdentity);
}

function serializeContainer(container: FileDatabaseContainer): string {
  return `${JSON.stringify(canonicalizeContainer(container))}\n`;
}

async function setAndVerifyCreatedFile(
  targetPath: string,
  handle: FileHandle,
  role: 'lock' | 'temporary',
): Promise<void> {
  if (process.platform === 'win32')
    await fileEncryptedDatabaseEffects.setAcl(targetPath, role);
  else await fileEncryptedDatabaseEffects.chmod(handle, 0o600);
  const metadata = await handle.stat({ bigint: true });
  await assertOwnedPermissions(metadata, targetPath, true, false);
  if (process.platform === 'win32')
    await fileEncryptedDatabaseEffects.verifyAcl(targetPath, role);
}

async function assertOwnedPermissions(
  metadata: BigIntStats,
  path: string,
  requireFile: boolean,
  verifyAcl = true,
): Promise<void> {
  if (requireFile) {
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1n) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
  } else if (!metadata.isDirectory()) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  if (process.platform === 'win32') {
    if (!verifyAcl) return;
    try {
      if (requireFile) await verifyWindowsUserOnlyAcl(path);
      else await verifyWindowsDirectoryAcl(path);
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

function assertRetainedFileMetadata(metadata: BigIntStats): void {
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink > 1n) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  if (process.platform === 'win32') return;
  const getuid = process.getuid;
  if (getuid === undefined || metadata.uid !== BigInt(getuid())) {
    throw new EncryptedDatabaseStoreError('invalid');
  }
  if ((metadata.mode & 0o777n) !== 0o600n) {
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

async function assertDirectoryIdentity(target: ResolvedFileTarget): Promise<void> {
  try {
    const resolved = await realpath(dirname(target.targetPath));
    if (resolved !== target.directoryPath)
      throw new EncryptedDatabaseStoreError('invalid');
    const metadata = await stat(resolved, { bigint: true });
    await assertOwnedPermissions(metadata, resolved, false);
    if (!sameIdentity(identityOf(metadata), target.directoryIdentity)) {
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

function noFollowReadWriteFlags(): number {
  return constants.O_RDWR | (process.platform === 'win32' ? 0 : constants.O_NOFOLLOW);
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

type FileEffectFileRole = 'lock' | 'temporary' | 'final';
type FileEffectLinkPhase = 'backup' | 'publish-create' | 'recovery';
type FileEffectRenamePhase = 'publish' | 'rollback';
type FileEffectUnlinkPhase =
  | 'backup-cleanup'
  | 'lock-acquire-cleanup'
  | 'lock-release'
  | 'rollback-create'
  | 'temporary-after-create'
  | 'temporary-cleanup';
type FileEffectDirectorySyncPhase =
  'close' | 'post-publish' | 'pre-publish' | 'rollback';

type FileEncryptedDatabaseEffects = Readonly<{
  chmod: (handle: FileHandle, mode: number) => Promise<void>;
  close: (handle: FileHandle, role: 'lock' | 'temporary') => Promise<void>;
  closeOwned: (handle: FileHandle) => Promise<void>;
  link: (
    existingPath: string,
    newPath: string,
    phase: FileEffectLinkPhase,
  ) => Promise<void>;
  rename: (
    oldPath: string,
    newPath: string,
    phase: FileEffectRenamePhase,
  ) => Promise<void>;
  setAcl: (path: string, role: FileEffectFileRole) => Promise<void>;
  verifyAcl: (path: string, role: FileEffectFileRole) => Promise<void>;
  sync: (handle: FileHandle) => Promise<void>;
  truncate: (handle: FileHandle) => Promise<void>;
  unlink: (path: string, phase: FileEffectUnlinkPhase) => Promise<void>;
  write: (handle: FileHandle, contents: Buffer) => Promise<void>;
  readFinal: typeof readContainerIfPresent;
  verifyFinalIdentity: typeof assertPathIdentity;
  syncDirectory: (path: string, phase: FileEffectDirectorySyncPhase) => Promise<void>;
}>;

const defaultFileEncryptedDatabaseEffects: FileEncryptedDatabaseEffects = {
  chmod: (handle, mode) => handle.chmod(mode),
  close: (handle) => handle.close(),
  closeOwned: (handle) => handle.close(),
  link: (existingPath, newPath) => link(existingPath, newPath),
  rename: (oldPath, newPath) => rename(oldPath, newPath),
  setAcl: (path) => setWindowsUserOnlyAcl(path),
  verifyAcl: (path) => verifyWindowsUserOnlyAcl(path),
  sync: (handle) => handle.sync(),
  truncate: (handle) => handle.truncate(0),
  unlink: (path) => unlink(path),
  write: (handle, contents) => handle.writeFile(contents),
  readFinal: readContainerIfPresent,
  verifyFinalIdentity: assertPathIdentity,
  syncDirectory: (path) => syncDirectory(path),
};

let fileEncryptedDatabaseEffects = defaultFileEncryptedDatabaseEffects;

/**
 * Test-only package-internal fault seam. It is deliberately absent from the
 * storage package barrel, so production consumers cannot configure filesystem
 * behavior. Each replacement is reset after a test.
 */
export const __fileEncryptedDatabaseTestEffects = {
  replace(overrides: Partial<FileEncryptedDatabaseEffects>): void {
    fileEncryptedDatabaseEffects = {
      ...defaultFileEncryptedDatabaseEffects,
      ...overrides,
    };
  },
  reset(): void {
    fileEncryptedDatabaseEffects = defaultFileEncryptedDatabaseEffects;
  },
};
