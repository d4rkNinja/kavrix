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
  localVaultDocumentSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type LocalVaultDocument,
} from '@kavrix/schemas';
// ACL-only platform boundary; this subpath does not expose key or crypto APIs.
// eslint-disable-next-line no-restricted-imports
import {
  setWindowsUserOnlyAcl,
  verifyWindowsDirectoryAcl,
  verifyWindowsUserOnlyAcl,
} from '@kavrix/key-files/windows-acl';

import {
  EncryptedVaultStoreError,
  type EncryptedVaultStore,
} from './encrypted-vault-store.js';

export const MAX_FILE_LOCAL_VAULT_BYTES = 32 * 1024 * 1024;

export type FileLocalVaultErrorCode =
  'busy' | 'closed' | 'conflict' | 'exists' | 'invalid' | 'operation';

export class FileLocalVaultError extends EncryptedVaultStoreError {
  constructor(code: FileLocalVaultErrorCode) {
    const message =
      code === 'busy'
        ? 'The local vault file is in use.'
        : code === 'closed'
          ? 'The local vault store is closed.'
          : code === 'conflict'
            ? 'The vault changed while this command was running.'
            : code === 'exists'
              ? 'A vault already exists in this local file.'
              : code === 'invalid'
                ? 'The local vault file is invalid or unsafe.'
                : 'The local vault file operation failed.';
    super(code, message);
    this.name = 'FileLocalVaultError';
  }
}

type ResolvedFileTarget = Readonly<{
  directoryPath: string;
  targetPath: string;
  lockPath: string;
}>;

type FileIdentity = Readonly<{ dev: bigint; ino: bigint }>;

/**
 * A filesystem metadata snapshot strong enough to prove "same bytes on disk we
 * already verified": inode identity plus size, mode, link count, and
 * nanosecond mtime/ctime. In-place writes, truncation, permission changes, and
 * link swaps all change at least one field, so a matching snapshot against a
 * fully verified path is evidence the verified state still holds.
 */
type TrustedSnapshot = Readonly<{
  dev: bigint;
  ino: bigint;
  size: bigint;
  mode: bigint;
  nlink: bigint;
  mtimeNs: bigint;
  ctimeNs: bigint;
}>;

/**
 * Paths whose full identity and permission verification is being reused. The
 * map is owned by one store and holds only paths that were fully verified at
 * least once.
 */
type TrustCache = Map<string, TrustedSnapshot>;

type ReadDocumentResult = Readonly<{
  document: LocalVaultDocument;
  identity: FileIdentity;
  /** The exact on-disk bytes the document was parsed from. */
  text: string;
}>;

export class FileLocalVaultStore implements EncryptedVaultStore {
  readonly #directoryPath: string;
  readonly #targetPath: string;
  readonly #lockPath: string;
  readonly #lockHandle: FileHandle;
  readonly #lockIdentity: FileIdentity;
  /**
   * Full identity+permission verification results per path, reusable while the
   * path's metadata snapshot is unchanged. The store holds the exclusive lock
   * for its whole lifetime; every check still re-`lstat`s and falls back to
   * full verification on any snapshot change.
   */
  readonly #trustCache: TrustCache = new Map();
  /**
   * The most recently read-and-verified document with its file snapshot, or
   * the document this store last published. Repeat reads are served from this
   * entry while a fresh `lstat` proves the file bytes are unchanged.
   */
  #documentCache:
    Readonly<{ snapshot: TrustedSnapshot; document: LocalVaultDocument }> | undefined;
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
    await readDocumentIfPresent(target.targetPath);
  }

  static async open(path: string): Promise<FileLocalVaultStore> {
    const target = await resolveTarget(path);
    const acquired = await acquireLock(target.lockPath);
    try {
      const store = new FileLocalVaultStore(target, acquired.handle, acquired.identity);
      await store.ping();
      return store;
    } catch (error) {
      await releaseLock(acquired.handle, target.lockPath, acquired.identity).catch(
        () => undefined,
      );
      if (error instanceof FileLocalVaultError) throw error;
      throw new FileLocalVaultError('operation');
    }
  }

  async ping(): Promise<void> {
    this.#assertOpen();
    await this.#readDocument();
  }

  /**
   * Reads the document, serving repeat reads from the verified snapshot while
   * a fresh `lstat` proves the file is unchanged.
   *
   * The store holds the exclusive writer lock for its whole lifetime, so while
   * the snapshot matches, the bytes on disk are exactly the bytes this store
   * already parsed and validated. Any snapshot change falls through to the
   * full verification path, so nothing trusted is ever served without the
   * evidence that it is unchanged.
   */
  async #readDocument(): Promise<ReadDocumentResult | null> {
    let currentStats: BigIntStats | undefined;
    try {
      currentStats = await lstat(this.#targetPath, { bigint: true });
    } catch {
      currentStats = undefined;
    }
    if (currentStats === undefined) {
      this.#documentCache = undefined;
      return null;
    }
    const snapshot = snapshotOf(currentStats);
    const cached = this.#documentCache;
    if (cached !== undefined && sameSnapshot(cached.snapshot, snapshot)) {
      return {
        document: cached.document,
        identity: identityOf(currentStats),
        text: '',
      };
    }
    const current = await readDocumentIfPresent(this.#targetPath, this.#trustCache);
    if (current === null) {
      this.#documentCache = undefined;
      return null;
    }
    this.#documentCache = { snapshot, document: current.document };
    return current;
  }

  async get(vaultId: string): Promise<LocalVaultDocument | null> {
    this.#assertOpen();
    const id = parseVaultId(vaultId);
    const current = await this.#readDocument();
    return current?.document.id === id ? current.document : null;
  }

  async listVaultIds(): Promise<string[]> {
    this.#assertOpen();
    const current = await this.#readDocument();
    return current === null ? [] : [current.document.id];
  }

  async create(document: LocalVaultDocument): Promise<void> {
    this.#assertOpen();
    const parsed = parseDocument(document);
    if ((await this.#readDocument()) !== null) {
      throw new FileLocalVaultError('exists');
    }
    await publishDocument(
      this.#directoryPath,
      this.#targetPath,
      parsed,
      'create',
      undefined,
      this.#trustCache,
    );
    await this.#notePublishedDocument(parsed);
  }

  async update(
    document: LocalVaultDocument,
    expectedRevision: LocalVaultDocument['revision'],
  ): Promise<void> {
    this.#assertOpen();
    const parsed = parseDocument(document);
    const expected = parseRevision(expectedRevision);
    if (parsed.revision !== expected + 1) throw new FileLocalVaultError('invalid');
    const current = await this.#readDocument();
    if (current?.document.id !== parsed.id || current.document.revision !== expected) {
      throw new FileLocalVaultError('conflict');
    }
    await publishDocument(
      this.#directoryPath,
      this.#targetPath,
      parsed,
      'replace',
      current.identity,
      this.#trustCache,
    );
    await this.#notePublishedDocument(parsed);
  }

  async delete(
    vaultId: string,
    expectedRevision: LocalVaultDocument['revision'],
  ): Promise<void> {
    this.#assertOpen();
    const id = parseVaultId(vaultId);
    const expected = parseRevision(expectedRevision);
    const current = await this.#readDocument();
    if (current?.document.id !== id || current.document.revision !== expected) {
      throw new FileLocalVaultError('conflict');
    }
    await assertPathIdentityCached(
      this.#targetPath,
      current.identity,
      this.#trustCache,
    );
    try {
      await unlink(this.#targetPath);
      await syncDirectory(this.#directoryPath);
    } catch {
      throw new FileLocalVaultError('operation');
    }
    this.#documentCache = undefined;
    this.#trustCache.delete(this.#targetPath);
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    try {
      await releaseLock(this.#lockHandle, this.#lockPath, this.#lockIdentity);
      await syncDirectory(this.#directoryPath);
    } catch {
      throw new FileLocalVaultError('operation');
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new FileLocalVaultError('closed');
  }

  /**
   * Records the exact document this store just published, so subsequent reads
   * are served from verified memory after one confirming `lstat`.
   */
  async #notePublishedDocument(document: LocalVaultDocument): Promise<void> {
    try {
      const metadata = await lstat(this.#targetPath, { bigint: true });
      this.#documentCache = { snapshot: snapshotOf(metadata), document };
    } catch {
      this.#documentCache = undefined;
    }
  }
}

function parseVaultId(value: unknown): LocalVaultDocument['id'] {
  try {
    return vaultIdSchema.parse(value);
  } catch {
    throw new FileLocalVaultError('invalid');
  }
}

function parseRevision(value: unknown): LocalVaultDocument['revision'] {
  try {
    return vaultRevisionSchema.parse(value);
  } catch {
    throw new FileLocalVaultError('invalid');
  }
}

function parseDocument(value: unknown): LocalVaultDocument {
  try {
    return localVaultDocumentSchema.parse(value);
  } catch {
    throw new FileLocalVaultError('invalid');
  }
}

async function resolveTarget(inputPath: string): Promise<ResolvedFileTarget> {
  if (
    typeof inputPath !== 'string' ||
    inputPath.length === 0 ||
    hasControlCharacter(inputPath)
  ) {
    throw new FileLocalVaultError('invalid');
  }
  try {
    const absolutePath = isAbsolute(inputPath) ? inputPath : resolve(inputPath);
    const targetName = basename(absolutePath);
    if (targetName.length === 0 || targetName === '.' || targetName === '..') {
      throw new FileLocalVaultError('invalid');
    }
    const directoryPath = await realpath(dirname(absolutePath));
    const directory = await stat(directoryPath, { bigint: true });
    if (!directory.isDirectory()) throw new FileLocalVaultError('invalid');
    if (process.platform === 'win32') await verifyWindowsDirectoryAcl(directoryPath);
    await assertOwnedPermissions(directory, directoryPath, false);
    const targetPath = join(directoryPath, targetName);
    return { directoryPath, targetPath, lockPath: `${targetPath}.lock` };
  } catch (error) {
    if (error instanceof FileLocalVaultError) throw error;
    throw new FileLocalVaultError('invalid');
  }
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 31 || codeUnit === 127) return true;
  }
  return false;
}

const LOCK_METADATA_FORMAT = 'kavrix-local-vault-lock';
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
  const metadata: LockMetadata = { format: LOCK_METADATA_FORMAT, version: 1, pid };
  const payload = Buffer.from(JSON.stringify(metadata), 'utf8');
  if (payload.byteLength > MAX_LOCK_METADATA_BYTES) {
    throw new FileLocalVaultError('operation');
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
    await unlink(lockPath);
    return true;
  } catch {
    return false;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function acquireLock(
  lockPath: string,
): Promise<Readonly<{ handle: FileHandle; identity: FileIdentity }>> {
  for (let attempt = 0; ; attempt += 1) {
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        lockPath,
        constants.O_CREAT | constants.O_EXCL | constants.O_RDWR,
        0o600,
      );
      if (process.platform === 'win32') await setWindowsUserOnlyAcl(lockPath);
      else await handle.chmod(0o600);
      await writeLockMetadata(handle, process.pid);
      await handle.sync();
      const metadata = await handle.stat({ bigint: true });
      await assertOwnedPermissions(metadata, lockPath, true);
      return { handle, identity: identityOf(metadata) };
    } catch (error) {
      if (handle !== undefined) await handle.close().catch(() => undefined);
      if (handle !== undefined) await unlink(lockPath).catch(() => undefined);
      if (fileErrorCode(error) !== 'EEXIST') throw new FileLocalVaultError('operation');
      // Only a provably dead owner's lock may be removed; see the database
      // store for the full fail-closed stale-recovery contract.
      const ownerPid = await inspectExistingLockOwner(lockPath);
      if (
        ownerPid !== undefined &&
        !isProcessLive(ownerPid) &&
        attempt + 1 < STALE_LOCK_RECOVERY_ATTEMPTS &&
        (await removeStaleLock(lockPath, ownerPid))
      ) {
        continue;
      }
      throw new FileLocalVaultError('busy');
    }
  }
}

/** Verifies the hostile-shape guards before any staleness consideration. */
async function inspectExistingLockOwner(lockPath: string): Promise<number | undefined> {
  try {
    const before = await lstat(lockPath, { bigint: true });
    await assertOwnedPermissions(before, lockPath, true);
    const identity = identityOf(before);
    const openedHandle = await open(lockPath, noFollowReadFlags());
    try {
      const opened = await openedHandle.stat({ bigint: true });
      await assertOwnedPermissions(opened, lockPath, true);
      if (!sameIdentity(identity, identityOf(opened))) return undefined;
    } finally {
      await openedHandle.close().catch(() => undefined);
    }
    return await readLockOwner(lockPath);
  } catch {
    return undefined;
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
  if (failure) throw new FileLocalVaultError('operation');
}

async function readDocumentIfPresent(
  path: string,
  trust?: TrustCache,
): Promise<ReadDocumentResult | null> {
  let before;
  try {
    before = await lstat(path, { bigint: true });
  } catch (error) {
    if (fileErrorCode(error) === 'ENOENT') return null;
    throw new FileLocalVaultError('operation');
  }
  await assertOwnedPermissionsCached(before, path, true, trust);
  const identity = identityOf(before);
  let handle: FileHandle | undefined;
  let contents: Buffer | undefined;
  try {
    handle = await open(path, noFollowReadFlags());
    const opened = await handle.stat({ bigint: true });
    await assertOwnedPermissionsCached(opened, path, true, trust);
    if (!sameIdentity(identity, identityOf(opened)))
      throw new FileLocalVaultError('invalid');
    const size = Number(opened.size);
    if (!Number.isSafeInteger(size) || size < 2 || size > MAX_FILE_LOCAL_VAULT_BYTES) {
      throw new FileLocalVaultError('invalid');
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
      throw new FileLocalVaultError('invalid');
    }
    await assertPathIdentityCached(path, identity, trust);
    const text = contents.subarray(0, size).toString('utf8');
    const parsed = parseDocument(JSON.parse(text) as unknown);
    if (text !== `${JSON.stringify(parsed)}\n`)
      throw new FileLocalVaultError('invalid');
    return { document: parsed, identity, text };
  } catch (error) {
    if (error instanceof FileLocalVaultError) throw error;
    throw new FileLocalVaultError('invalid');
  } finally {
    contents?.fill(0);
    await handle?.close().catch(() => undefined);
  }
}

async function publishDocument(
  directoryPath: string,
  targetPath: string,
  document: LocalVaultDocument,
  mode: 'create' | 'replace',
  expectedIdentity?: FileIdentity,
  trust?: TrustCache,
): Promise<void> {
  const contents = Buffer.from(`${JSON.stringify(document)}\n`, 'utf8');
  if (contents.byteLength > MAX_FILE_LOCAL_VAULT_BYTES) {
    contents.fill(0);
    throw new FileLocalVaultError('invalid');
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
    if (process.platform === 'win32') await setWindowsUserOnlyAcl(temporaryPath);
    else await handle.chmod(0o600);
    await handle.writeFile(contents);
    await handle.sync();
    const staged = await handle.stat({ bigint: true });
    await assertOwnedPermissionsCached(staged, temporaryPath, true, trust);
    if (staged.size !== BigInt(contents.byteLength)) {
      throw new FileLocalVaultError('operation');
    }
    await handle.close();
    handle = undefined;
    if (mode === 'create') {
      try {
        await link(temporaryPath, targetPath);
      } catch (error) {
        if (fileErrorCode(error) === 'EEXIST') throw new FileLocalVaultError('exists');
        throw error;
      }
      await unlink(temporaryPath);
    } else {
      if (expectedIdentity === undefined) throw new FileLocalVaultError('operation');
      await assertPathIdentityCached(targetPath, expectedIdentity, trust);
      await rename(temporaryPath, targetPath);
    }
    published = true;
    const finalMetadata = await lstat(targetPath, { bigint: true });
    await assertOwnedPermissions(finalMetadata, targetPath, true);
    await syncDirectory(directoryPath);
  } catch (error) {
    if (error instanceof FileLocalVaultError) throw error;
    throw new FileLocalVaultError('operation');
  } finally {
    contents.fill(0);
    await handle?.close().catch(() => undefined);
    if (!published) await unlink(temporaryPath).catch(() => undefined);
  }
}

async function assertOwnedPermissions(
  metadata: BigIntStats,
  path: string,
  requireFile: boolean,
): Promise<void> {
  if (requireFile) {
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1n) {
      throw new FileLocalVaultError('invalid');
    }
  } else if (!metadata.isDirectory()) {
    throw new FileLocalVaultError('invalid');
  }
  if (process.platform === 'win32') {
    try {
      if (requireFile) await verifyWindowsUserOnlyAcl(path);
      else await verifyWindowsDirectoryAcl(path);
      return;
    } catch {
      throw new FileLocalVaultError('invalid');
    }
  }
  const getuid = process.getuid;
  if (getuid === undefined || metadata.uid !== BigInt(getuid())) {
    throw new FileLocalVaultError('invalid');
  }
  if (requireFile) {
    if ((metadata.mode & 0o777n) !== 0o600n) throw new FileLocalVaultError('invalid');
  } else if ((metadata.mode & 0o022n) !== 0n) {
    throw new FileLocalVaultError('invalid');
  }
}

async function assertPathIdentity(path: string, expected: FileIdentity): Promise<void> {
  try {
    const metadata = await lstat(path, { bigint: true });
    await assertOwnedPermissions(metadata, path, true);
    if (!sameIdentity(identityOf(metadata), expected))
      throw new FileLocalVaultError('invalid');
  } catch (error) {
    if (error instanceof FileLocalVaultError) throw error;
    throw new FileLocalVaultError('operation');
  }
}

/**
 * Same contract as `assertOwnedPermissions`, reusing a prior full verification
 * of `path` while the metadata snapshot is unchanged. The snapshot includes
 * change time, so permission changes are never silently accepted.
 */
async function assertOwnedPermissionsCached(
  metadata: BigIntStats,
  path: string,
  requireFile: boolean,
  trust?: TrustCache,
): Promise<void> {
  if (trust === undefined) return assertOwnedPermissions(metadata, path, requireFile);
  const snapshot = snapshotOf(metadata);
  const cached = trust.get(path);
  if (cached !== undefined && sameSnapshot(cached, snapshot)) return;
  await assertOwnedPermissions(metadata, path, requireFile);
  trust.set(path, snapshot);
}

/**
 * Same contract as `assertPathIdentity`, reusing a prior full verification
 * while the metadata snapshot is unchanged.
 */
async function assertPathIdentityCached(
  path: string,
  expected: FileIdentity,
  trust?: TrustCache,
): Promise<void> {
  if (trust === undefined) return assertPathIdentity(path, expected);
  let metadata: BigIntStats;
  try {
    metadata = await lstat(path, { bigint: true });
  } catch {
    throw new FileLocalVaultError('operation');
  }
  const snapshot = snapshotOf(metadata);
  const cached = trust.get(path);
  if (cached !== undefined && sameSnapshot(cached, snapshot)) return;
  await assertOwnedPermissions(metadata, path, true);
  if (!sameIdentity(identityOf(metadata), expected)) {
    throw new FileLocalVaultError('invalid');
  }
  trust.set(path, snapshot);
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
      throw new FileLocalVaultError('operation');
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

function snapshotOf(value: BigIntStats): TrustedSnapshot {
  return {
    dev: value.dev,
    ino: value.ino,
    size: value.size,
    mode: value.mode,
    nlink: value.nlink,
    mtimeNs: value.mtimeNs,
    ctimeNs: value.ctimeNs,
  };
}

function sameSnapshot(left: TrustedSnapshot, right: TrustedSnapshot): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function fileErrorCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String(error.code)
    : undefined;
}
