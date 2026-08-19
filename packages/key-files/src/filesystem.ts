import { randomBytes, createHash } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import {
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

import { PortableKeyFileError } from './errors.js';
import { setWindowsUserOnlyAcl, verifyWindowsUserOnlyAcl } from './windows-acl.js';

export const MAX_PORTABLE_KEY_FILE_BYTES = 16_384;
export const MAX_SECURE_STREAM_FILE_BYTES = 128 * 1024 * 1024;
export const MAX_SECURE_STREAM_CHUNK_BYTES = 32 * 1024 * 1024;
const TEMP_FILE_BYTES = 12;
const WINDOWS_RESERVED_BASENAME = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu;

type FileIdentity = Readonly<{
  dev: bigint;
  ino: bigint;
}>;

export type OwnedSecureFileKind =
  'database-key-file' | 'database-recovery-kit-file' | 'database-revision-anchor';

const ownedSecureFilePublicationBrand = Symbol('ownedSecureFilePublication');
export type OwnedSecureFilePublication = Readonly<{
  readonly [ownedSecureFilePublicationBrand]: true;
}>;

export type OwnedSecureFileCreateResult =
  | Readonly<{
      status: 'not-published';
      error: PortableKeyFileError;
    }>
  | Readonly<{
      status: 'published';
      publication: OwnedSecureFilePublication;
    }>
  | Readonly<{
      status: 'publication-uncertain';
      publication: OwnedSecureFilePublication;
      error: PortableKeyFileError;
    }>;

type OwnedSecureFileState = Readonly<{
  kind: OwnedSecureFileKind;
  directoryPath: string;
  targetPath: string;
  identity: FileIdentity;
  maximumBytes: number;
}>;

const ownedSecureFileStates = new WeakMap<object, OwnedSecureFileState>();

type ResolvedTarget = Readonly<{
  directoryPath: string;
  targetPath: string;
}>;

const exclusiveSecureFileLockBrand = Symbol('exclusiveSecureFileLock');
export type ExclusiveSecureFileLock = Readonly<{
  readonly [exclusiveSecureFileLockBrand]: true;
  readonly targetPath: string;
  readonly directoryPath: string;
  readonly maximumBytes: number;
}>;

export type SecureFileStreamWriteResult = Readonly<{
  bytes: number;
}>;

function fileErrorCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String(error.code)
    : undefined;
}

function isWriteMode(value: unknown): value is 'create' | 'replace' {
  return value === 'create' || value === 'replace';
}

function mappedFileError(
  error: unknown,
  fallback: 'KEY_FILE_INVALID_PATH' | 'KEY_FILE_OPERATION_FAILED' | 'KEY_FILE_UNSAFE',
): PortableKeyFileError {
  if (error instanceof PortableKeyFileError) return error;
  const code = fileErrorCode(error);
  if (code === 'ENOENT') return new PortableKeyFileError('KEY_FILE_NOT_FOUND');
  if (code === 'EEXIST') {
    return new PortableKeyFileError('KEY_FILE_ALREADY_EXISTS');
  }
  if (code === 'ELOOP') return new PortableKeyFileError('KEY_FILE_UNSAFE');
  return new PortableKeyFileError(fallback);
}

function assertSecureFileMaximum(maximumBytes: number): void {
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > MAX_SECURE_STREAM_FILE_BYTES
  ) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
}

function validateBasename(value: string): void {
  if (
    value.length === 0 ||
    value === '.' ||
    value === '..' ||
    value.includes('\0') ||
    Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0);
      return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
    })
  ) {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
  if (
    process.platform === 'win32' &&
    (value.includes(':') ||
      value.endsWith('.') ||
      value.endsWith(' ') ||
      WINDOWS_RESERVED_BASENAME.test(value))
  ) {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
}

async function resolveTarget(inputPath: string): Promise<ResolvedTarget> {
  if (typeof inputPath !== 'string' || inputPath.length === 0) {
    throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
  }
  try {
    const absolutePath = isAbsolute(inputPath) ? inputPath : resolve(inputPath);
    const targetName = basename(absolutePath);
    validateBasename(targetName);
    const directoryPath = await realpath(dirname(absolutePath));
    const directory = await stat(directoryPath, { bigint: true });
    if (!directory.isDirectory()) {
      throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
    }
    return { directoryPath, targetPath: join(directoryPath, targetName) };
  } catch (error) {
    throw mappedFileError(error, 'KEY_FILE_INVALID_PATH');
  }
}

async function validateWriteDirectory(directoryPath: string): Promise<void> {
  try {
    const metadata = await lstat(directoryPath, { bigint: true });
    if (!metadata.isDirectory()) {
      throw new PortableKeyFileError('KEY_FILE_INVALID_PATH');
    }
    if (process.platform === 'win32') {
      await verifyWindowsUserOnlyAcl(directoryPath);
    } else {
      const getuid = process.getuid;
      if (
        getuid === undefined ||
        metadata.uid !== BigInt(getuid()) ||
        (metadata.mode & 0o022n) !== 0n
      ) {
        throw new PortableKeyFileError('KEY_FILE_UNSAFE');
      }
    }
  } catch (error) {
    throw mappedFileError(error, 'KEY_FILE_UNSAFE');
  }
}

function identityOf(value: {
  readonly dev: bigint;
  readonly ino: bigint;
}): FileIdentity {
  return { dev: value.dev, ino: value.ino };
}

function sameIdentity(
  left: { readonly dev: bigint; readonly ino: bigint },
  right: { readonly dev: bigint; readonly ino: bigint },
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function validateRegularFile(
  targetPath: string,
  metadata: BigIntStats,
  maximumBytes = MAX_PORTABLE_KEY_FILE_BYTES,
  allowEmpty = false,
): Promise<void> {
  if (
    !metadata.isFile() ||
    metadata.size < (allowEmpty ? 0n : 1n) ||
    metadata.size > BigInt(maximumBytes) ||
    metadata.nlink !== 1n
  ) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }

  if (process.platform === 'win32') {
    await verifyWindowsUserOnlyAcl(targetPath);
    return;
  }

  const getuid = process.getuid;
  if (getuid === undefined || metadata.uid !== BigInt(getuid())) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
  if ((metadata.mode & 0o7177n) !== 0n) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
}

function noFollowReadFlags(): number {
  const noFollow = constants.O_NOFOLLOW;
  return constants.O_RDONLY | (process.platform === 'win32' ? 0 : noFollow);
}

function noFollowReadWriteFlags(): number {
  const noFollow = constants.O_NOFOLLOW;
  return constants.O_RDWR | (process.platform === 'win32' ? 0 : noFollow);
}

async function lstatRegularIdentity(targetPath: string): Promise<FileIdentity> {
  const metadata = await lstat(targetPath, { bigint: true });
  if (!metadata.isFile()) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
  return identityOf(metadata);
}

async function verifyPathStillNamesFile(
  targetPath: string,
  identity: FileIdentity,
): Promise<void> {
  const after = await lstat(targetPath, { bigint: true });
  if (!after.isFile() || !sameIdentity(after, identity)) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
}

async function verifyPathStillNamesDirectory(
  targetPath: string,
  identity: FileIdentity,
): Promise<void> {
  const after = await lstat(targetPath, { bigint: true });
  if (!after.isDirectory() || !sameIdentity(after, identity)) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
}

async function readBounded(handle: FileHandle, maximumBytes: number): Promise<Buffer> {
  const output = Buffer.alloc(maximumBytes + 1);
  let offset = 0;
  while (offset < output.byteLength) {
    const result = await handle.read(
      output,
      offset,
      output.byteLength - offset,
      offset,
    );
    if (result.bytesRead === 0) break;
    offset += result.bytesRead;
  }
  if (offset === 0 || offset > maximumBytes) {
    output.fill(0);
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
  const result = Buffer.from(output.subarray(0, offset));
  output.fill(0);
  return result;
}

export async function readSecureFile(
  inputPath: string,
  maximumBytes = MAX_PORTABLE_KEY_FILE_BYTES,
): Promise<Buffer> {
  assertSecureFileMaximum(maximumBytes);
  const { targetPath } = await resolveTarget(inputPath);
  let handle: FileHandle | undefined;
  let contents: Buffer | undefined;
  try {
    const before = await lstatRegularIdentity(targetPath);
    handle = await open(targetPath, noFollowReadFlags());
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(before, opened)) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await validateRegularFile(targetPath, opened, maximumBytes);
    await verifyPathStillNamesFile(targetPath, before);
    contents = await readBounded(handle, maximumBytes);
    const afterRead = await handle.stat({ bigint: true });
    if (
      !sameIdentity(opened, afterRead) ||
      afterRead.size !== BigInt(contents.length)
    ) {
      contents.fill(0);
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await verifyPathStillNamesFile(targetPath, before);
    await handle.close();
    handle = undefined;
    const result = contents;
    contents = undefined;
    return result;
  } catch (error) {
    contents?.fill(0);
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
      }
    }
    throw mappedFileError(error, 'KEY_FILE_UNSAFE');
  }
}

async function setAndVerifyCreatedFile(
  targetPath: string,
  handle: FileHandle,
): Promise<void> {
  if (process.platform === 'win32') {
    await setWindowsUserOnlyAcl(targetPath);
  } else {
    await handle.chmod(0o600);
  }
  const metadata = await handle.stat({ bigint: true });
  if (!metadata.isFile() || metadata.nlink !== 1n) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
  if (process.platform !== 'win32') {
    const getuid = process.getuid;
    if (
      getuid === undefined ||
      metadata.uid !== BigInt(getuid()) ||
      (metadata.mode & 0o777n) !== 0o600n
    ) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
  }
}

async function createSecureEmptyFile(targetPath: string): Promise<FileHandle> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      targetPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR,
      0o600,
    );
    await setAndVerifyCreatedFile(targetPath, handle);
    return handle;
  } catch (error) {
    let cleanupFailed = false;
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        cleanupFailed = true;
      }
      try {
        await unlink(targetPath);
      } catch (cleanupError) {
        if (fileErrorCode(cleanupError) !== 'ENOENT') {
          cleanupFailed = true;
        }
      }
    }
    if (cleanupFailed) {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
    throw mappedFileError(error, 'KEY_FILE_OPERATION_FAILED');
  }
}

async function removeIfPresent(targetPath: string): Promise<void> {
  try {
    await unlink(targetPath);
  } catch (error) {
    if (fileErrorCode(error) !== 'ENOENT') {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
  }
}

/**
 * Checks a create-only destination without creating a file or touching any
 * secret-bearing resource. Callers use this before unlocking so a known bad
 * target cannot prompt for protected input.
 */
export async function validateSecureFileDestination(inputPath: string): Promise<void> {
  const { directoryPath, targetPath } = await resolveTarget(inputPath);
  await validateWriteDirectory(directoryPath);
  try {
    const metadata = await lstat(targetPath, { bigint: true });
    if (metadata.isSymbolicLink()) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    throw new PortableKeyFileError('KEY_FILE_ALREADY_EXISTS');
  } catch (error) {
    if (fileErrorCode(error) === 'ENOENT') return;
    throw mappedFileError(error, 'KEY_FILE_UNSAFE');
  }
}

/**
 * Checks an existing protected regular file before callers acquire unlock
 * material. This does not read file contents or mutate the path.
 */
export async function validateSecureFileSource(
  inputPath: string,
  maximumBytes = MAX_SECURE_STREAM_FILE_BYTES,
): Promise<void> {
  assertSecureFileMaximum(maximumBytes);
  const { directoryPath, targetPath } = await resolveTarget(inputPath);
  await validateWriteDirectory(directoryPath);
  let handle: FileHandle | undefined;
  try {
    const before = await lstatRegularIdentity(targetPath);
    handle = await open(targetPath, noFollowReadFlags());
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(before, opened)) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await validateRegularFile(targetPath, opened, maximumBytes);
    await verifyPathStillNamesFile(targetPath, before);
    await handle.close();
    handle = undefined;
  } catch (error) {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
      }
    }
    throw mappedFileError(error, 'KEY_FILE_UNSAFE');
  }
}

/**
 * Removes one already-protected Kavrix file without following links. The file is
 * first moved to a random same-directory quarantine name and its identity is
 * rechecked before unlink, preventing path replacement from widening deletion.
 */
export async function deleteSecureFile(
  inputPath: string,
  maximumBytes = MAX_SECURE_STREAM_FILE_BYTES,
): Promise<void> {
  assertSecureFileMaximum(maximumBytes);
  const { directoryPath, targetPath } = await resolveTarget(inputPath);
  let handle: FileHandle | undefined;
  let quarantinePath: string | undefined;
  let originalIdentity: FileIdentity | undefined;
  try {
    await validateWriteDirectory(directoryPath);
    const before = await lstatRegularIdentity(targetPath);
    originalIdentity = before;
    handle = await open(targetPath, noFollowReadFlags());
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(before, opened)) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await validateRegularFile(targetPath, opened, maximumBytes);
    await handle.close();
    handle = undefined;
    await verifyPathStillNamesFile(targetPath, before);
    quarantinePath = join(
      directoryPath,
      `.kavrix-delete-${String(process.pid)}-${randomBytes(TEMP_FILE_BYTES).toString('hex')}.tmp`,
    );
    await rename(targetPath, quarantinePath);
    const quarantined = await lstat(quarantinePath, { bigint: true });
    if (!quarantined.isFile() || !sameIdentity(before, quarantined)) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await unlink(quarantinePath);
    quarantinePath = undefined;
    await syncDirectory(directoryPath);
  } catch (error) {
    throw mappedFileError(error, 'KEY_FILE_OPERATION_FAILED');
  } finally {
    await handle?.close().catch(() => undefined);
    if (quarantinePath !== undefined && originalIdentity !== undefined) {
      const cleanupPath = quarantinePath;
      const cleanupIdentity = originalIdentity;
      await lstat(cleanupPath, { bigint: true })
        .then(async (candidate) => {
          if (candidate.isFile() && sameIdentity(cleanupIdentity, candidate)) {
            await unlink(cleanupPath);
          }
        })
        .catch(() => undefined);
    }
  }
}

async function syncDirectory(directoryPath: string): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(directoryPath, constants.O_RDONLY);
    await handle.sync();
  } catch (error) {
    const code = fileErrorCode(error);
    if (
      process.platform !== 'win32' ||
      (code !== 'EPERM' && code !== 'EACCES' && code !== 'EINVAL')
    ) {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
  } finally {
    await handle?.close();
  }
}

function temporaryPath(directoryPath: string): string {
  return join(
    directoryPath,
    `.kavrix-${String(process.pid)}-${randomBytes(TEMP_FILE_BYTES).toString('hex')}.tmp`,
  );
}

function lockPath(directoryPath: string, targetPath: string): string {
  const digest = createHash('sha256').update(targetPath, 'utf8').digest('hex');
  return join(directoryPath, `.kavrix-${digest}.lock`);
}

async function writeTemporaryFile(
  directoryPath: string,
  contents: Uint8Array,
): Promise<Readonly<{ path: string; identity: FileIdentity }>> {
  const path = temporaryPath(directoryPath);
  const handle = await createSecureEmptyFile(path);
  let identity: FileIdentity;
  try {
    await handle.writeFile(contents);
    await handle.sync();
    const metadata = await handle.stat({ bigint: true });
    if (metadata.size !== BigInt(contents.byteLength)) {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
    identity = identityOf(metadata);
  } catch (error) {
    let cleanupFailed = false;
    try {
      await handle.close();
    } catch {
      cleanupFailed = true;
    }
    try {
      await removeIfPresent(path);
    } catch {
      cleanupFailed = true;
    }
    if (cleanupFailed) {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
    throw mappedFileError(error, 'KEY_FILE_OPERATION_FAILED');
  }
  try {
    await handle.close();
  } catch {
    await removeIfPresent(path);
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  return { path, identity };
}

async function writeTemporaryStreamFile(
  directoryPath: string,
  source: AsyncIterable<Uint8Array>,
  maximumBytes: number,
): Promise<Readonly<{ path: string; bytes: number }>> {
  const path = temporaryPath(directoryPath);
  const handle = await createSecureEmptyFile(path);
  let bytes = 0;
  try {
    for await (const chunk of source) {
      if (
        !(chunk instanceof Uint8Array) ||
        chunk.byteLength === 0 ||
        chunk.byteLength > MAX_SECURE_STREAM_CHUNK_BYTES
      ) {
        throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
      }
      const next = bytes + chunk.byteLength;
      if (!Number.isSafeInteger(next) || next > maximumBytes) {
        chunk.fill(0);
        throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
      }
      try {
        let offset = 0;
        while (offset < chunk.byteLength) {
          const result = await handle.write(chunk, offset, chunk.byteLength - offset);
          if (result.bytesWritten <= 0) {
            throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
          }
          offset += result.bytesWritten;
        }
      } finally {
        chunk.fill(0);
      }
      bytes = next;
    }
    if (bytes === 0) {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
    await handle.sync();
    const metadata = await handle.stat({ bigint: true });
    if (metadata.size !== BigInt(bytes)) {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
  } catch (error) {
    let cleanupFailed = false;
    try {
      await handle.close();
    } catch {
      cleanupFailed = true;
    }
    try {
      await removeIfPresent(path);
    } catch {
      cleanupFailed = true;
    }
    if (cleanupFailed) {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
    throw mappedFileError(error, 'KEY_FILE_OPERATION_FAILED');
  }
  try {
    await handle.close();
  } catch {
    await removeIfPresent(path);
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  return { path, bytes };
}

async function publishCreateNew(
  directoryPath: string,
  targetPath: string,
  temporaryFile: string,
  maximumBytes = MAX_PORTABLE_KEY_FILE_BYTES,
): Promise<void> {
  try {
    await link(temporaryFile, targetPath);
    await removeIfPresent(temporaryFile);
    const published = await lstat(targetPath, { bigint: true });
    await validateRegularFile(targetPath, published, maximumBytes);
    await syncDirectory(directoryPath);
  } catch (error) {
    // Once the create-only link exists, publication may have reached durable
    // storage even when verification or directory sync reports failure. Never
    // remove that public path on an uncertain outcome.
    throw mappedFileError(error, 'KEY_FILE_OPERATION_FAILED');
  }
}

function newOwnedSecureFilePublication(
  state: OwnedSecureFileState,
): OwnedSecureFilePublication {
  const publication = Object.freeze({
    [ownedSecureFilePublicationBrand]: true as const,
  });
  ownedSecureFileStates.set(publication, state);
  return publication;
}

/**
 * Internal create-only publisher used by the database domain wrappers. It
 * returns an opaque ownership capability whenever publication may have
 * occurred, while keeping paths and filesystem identity private.
 */
export async function createOwnedSecureFile(
  inputPath: string,
  contents: Uint8Array,
  kind: OwnedSecureFileKind,
  maximumBytes = MAX_PORTABLE_KEY_FILE_BYTES,
): Promise<OwnedSecureFileCreateResult> {
  let resolved: ResolvedTarget;
  try {
    assertSecureFileMaximum(maximumBytes);
    if (contents.byteLength === 0 || contents.byteLength > maximumBytes) {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
    resolved = await resolveTarget(inputPath);
    await validateWriteDirectory(resolved.directoryPath);
  } catch (error) {
    return {
      status: 'not-published',
      error: mappedFileError(error, 'KEY_FILE_OPERATION_FAILED'),
    };
  }

  let handle: FileHandle;
  try {
    handle = await open(
      resolved.targetPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR,
      0o600,
    );
  } catch (error) {
    return {
      status: 'not-published',
      error: mappedFileError(error, 'KEY_FILE_OPERATION_FAILED'),
    };
  }

  let identity: FileIdentity;
  try {
    identity = identityOf(await handle.stat({ bigint: true }));
  } catch (error) {
    await handle.close().catch(() => undefined);
    return {
      status: 'publication-uncertain',
      publication: newOwnedSecureFilePublication({
        kind,
        directoryPath: resolved.directoryPath,
        targetPath: resolved.targetPath,
        identity: { dev: -1n, ino: -1n },
        maximumBytes,
      }),
      error: mappedFileError(error, 'KEY_FILE_OPERATION_FAILED'),
    };
  }
  const publication = newOwnedSecureFilePublication({
    kind,
    directoryPath: resolved.directoryPath,
    targetPath: resolved.targetPath,
    identity,
    maximumBytes,
  });
  try {
    await setAndVerifyCreatedFile(resolved.targetPath, handle);
    await handle.writeFile(contents);
    await handle.sync();
    const written = await handle.stat({ bigint: true });
    if (
      !sameIdentity(written, identity) ||
      written.size !== BigInt(contents.byteLength)
    ) {
      throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
    }
    const published = await lstat(resolved.targetPath, { bigint: true });
    if (!sameIdentity(published, identity)) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await validateRegularFile(resolved.targetPath, published, maximumBytes);
    await syncDirectory(resolved.directoryPath);
    await handle.close();
    return { status: 'published', publication };
  } catch (error) {
    await handle.close().catch(() => undefined);
    return {
      status: 'publication-uncertain',
      publication,
      error: mappedFileError(error, 'KEY_FILE_OPERATION_FAILED'),
    };
  }
}

async function neutralizeHeldFile(
  handle: FileHandle,
  identity: FileIdentity,
): Promise<void> {
  const before = await handle.stat({ bigint: true });
  if (!before.isFile() || !sameIdentity(before, identity)) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
  await handle.truncate(0);
  await handle.sync();
  const after = await handle.stat({ bigint: true });
  if (!after.isFile() || !sameIdentity(after, identity) || after.size !== 0n) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
}

/**
 * Neutralizes only the exact protected file represented by an opaque
 * publication capability. Node has no portable unlink-by-handle operation;
 * cleanup therefore truncates and flushes the inode solely through a retained
 * descriptor. The public name is never mutated. It either remains as a
 * protected zero-byte tombstone or is observed as absent/replaced after the
 * owned inode is already neutralized. Forged, reused, and cross-domain
 * capabilities fail closed.
 */
export async function cleanupOwnedSecureFilePublication(
  publication: OwnedSecureFilePublication,
  expectedKind: OwnedSecureFileKind,
): Promise<void> {
  const state = ownedSecureFileStates.get(publication);
  if (state?.kind !== expectedKind) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }

  let handle: FileHandle | undefined;
  let directoryHandle: FileHandle | undefined;
  try {
    const resolved = await resolveTarget(state.targetPath);
    if (
      resolved.directoryPath !== state.directoryPath ||
      resolved.targetPath !== state.targetPath
    ) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await validateWriteDirectory(state.directoryPath);

    let before: BigIntStats;
    try {
      before = await lstat(state.targetPath, { bigint: true });
    } catch (error) {
      if (fileErrorCode(error) === 'ENOENT') {
        throw new PortableKeyFileError('KEY_FILE_UNSAFE');
      }
      throw error;
    }
    if (!before.isFile() || !sameIdentity(before, state.identity)) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    handle = await open(state.targetPath, noFollowReadWriteFlags());
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(opened, state.identity)) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await validateRegularFile(state.targetPath, opened, state.maximumBytes, true);
    await verifyPathStillNamesFile(state.targetPath, state.identity);

    const directoryBefore = await lstat(state.directoryPath, { bigint: true });
    if (!directoryBefore.isDirectory()) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    directoryHandle = await open(state.directoryPath, constants.O_RDONLY);
    const openedDirectory = await directoryHandle.stat({ bigint: true });
    if (
      !openedDirectory.isDirectory() ||
      !sameIdentity(openedDirectory, directoryBefore)
    ) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await verifyPathStillNamesDirectory(
      state.directoryPath,
      identityOf(openedDirectory),
    );

    await neutralizeHeldFile(handle, state.identity);

    try {
      const publicPath = await lstat(state.targetPath, { bigint: true });
      if (sameIdentity(publicPath, state.identity) && publicPath.size !== 0n) {
        await neutralizeHeldFile(handle, state.identity);
      }
    } catch {
      // Namespace inspection is observational only. The held inode is already
      // zero and no pathname is mutated based on this result.
    }

    await neutralizeHeldFile(handle, state.identity);
    ownedSecureFileStates.delete(publication);
  } catch (error) {
    throw mappedFileError(error, 'KEY_FILE_OPERATION_FAILED');
  } finally {
    await handle?.close().catch(() => undefined);
    await directoryHandle?.close().catch(() => undefined);
  }
}

async function acquireReplacementLock(path: string): Promise<FileHandle> {
  try {
    return await createSecureEmptyFile(path);
  } catch (error) {
    if (
      error instanceof PortableKeyFileError &&
      error.code === 'KEY_FILE_ALREADY_EXISTS'
    ) {
      throw new PortableKeyFileError('KEY_FILE_BUSY');
    }
    throw error;
  }
}

async function validateReplacementTarget(
  targetPath: string,
  maximumBytes = MAX_PORTABLE_KEY_FILE_BYTES,
): Promise<FileIdentity> {
  const identity = await lstatRegularIdentity(targetPath);
  const handle = await open(targetPath, noFollowReadFlags());
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(identity, opened)) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await validateRegularFile(targetPath, opened, maximumBytes);
    await verifyPathStillNamesFile(targetPath, identity);
    return identity;
  } finally {
    await handle.close();
  }
}

async function publishReplacement(
  directoryPath: string,
  targetPath: string,
  temporaryFile: string,
  maximumBytes = MAX_PORTABLE_KEY_FILE_BYTES,
): Promise<void> {
  let canonicalExistingTarget: string;
  try {
    canonicalExistingTarget = await realpath(targetPath);
  } catch (error) {
    throw mappedFileError(error, 'KEY_FILE_UNSAFE');
  }
  const replacementLockPath = lockPath(directoryPath, canonicalExistingTarget);
  const lock = await acquireReplacementLock(replacementLockPath);
  let operationError: PortableKeyFileError | undefined;
  try {
    const expected = await validateReplacementTarget(targetPath, maximumBytes);
    await verifyPathStillNamesFile(targetPath, expected);
    await rename(temporaryFile, targetPath);
    const published = await lstat(targetPath, { bigint: true });
    await validateRegularFile(targetPath, published, maximumBytes);
    await syncDirectory(directoryPath);
  } catch (error) {
    operationError = mappedFileError(error, 'KEY_FILE_OPERATION_FAILED');
  }
  let cleanupFailed = false;
  try {
    await lock.close();
  } catch {
    cleanupFailed = true;
  }
  try {
    await removeIfPresent(replacementLockPath);
  } catch {
    cleanupFailed = true;
  }
  if (cleanupFailed) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  if (operationError !== undefined) {
    throw operationError;
  }
}

export async function writeSecureFile(
  inputPath: string,
  contents: Uint8Array,
  mode: 'create' | 'replace',
  maximumBytes = MAX_PORTABLE_KEY_FILE_BYTES,
): Promise<void> {
  if (!isWriteMode(mode)) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  assertSecureFileMaximum(maximumBytes);
  if (contents.byteLength === 0 || contents.byteLength > maximumBytes) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  const { directoryPath, targetPath } = await resolveTarget(inputPath);
  await validateWriteDirectory(directoryPath);
  let temporaryFile: string | undefined;
  try {
    temporaryFile = (await writeTemporaryFile(directoryPath, contents)).path;
    if (mode === 'create') {
      await publishCreateNew(directoryPath, targetPath, temporaryFile, maximumBytes);
    } else {
      await publishReplacement(directoryPath, targetPath, temporaryFile, maximumBytes);
    }
    temporaryFile = undefined;
  } finally {
    if (temporaryFile !== undefined) await removeIfPresent(temporaryFile);
  }
}

/** Internal primitive for a higher-level protected state transition. It is not
 * re-exported from this package: callers receive no filesystem paths or handles. */
export async function withExclusiveSecureFile<T>(
  inputPath: string,
  maximumBytes: number,
  callback: (lock: ExclusiveSecureFileLock) => Promise<T>,
): Promise<T> {
  assertSecureFileMaximum(maximumBytes);
  const { directoryPath, targetPath } = await resolveTarget(inputPath);
  await validateWriteDirectory(directoryPath);
  await validateReplacementTarget(targetPath, maximumBytes);
  const canonicalTarget = await realpath(targetPath);
  const replacementLockPath = lockPath(directoryPath, canonicalTarget);
  const handle = await acquireReplacementLock(replacementLockPath);
  let callbackError: unknown;
  let result: T | undefined;
  try {
    await validateReplacementTarget(targetPath, maximumBytes);
    result = await callback({
      [exclusiveSecureFileLockBrand]: true,
      targetPath,
      directoryPath,
      maximumBytes,
    });
  } catch (error) {
    callbackError = error;
  }
  let cleanupError: unknown;
  try {
    await handle.close();
  } catch (error) {
    cleanupError = error;
  }
  try {
    await removeIfPresent(replacementLockPath);
  } catch (error) {
    cleanupError ??= error;
  }
  if (cleanupError !== undefined) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  if (callbackError !== undefined) {
    if (callbackError instanceof Error) throw callbackError;
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  return result as T;
}

export async function readSecureFileWhileExclusive(
  lock: ExclusiveSecureFileLock,
): Promise<Buffer> {
  return readSecureFile(lock.targetPath, lock.maximumBytes);
}

export async function replaceSecureFileWhileExclusive(
  lock: ExclusiveSecureFileLock,
  contents: Uint8Array,
): Promise<void> {
  if (contents.byteLength === 0 || contents.byteLength > lock.maximumBytes) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  await validateWriteDirectory(lock.directoryPath);
  let temporaryFile: string | undefined;
  try {
    temporaryFile = (await writeTemporaryFile(lock.directoryPath, contents)).path;
    const expected = await validateReplacementTarget(
      lock.targetPath,
      lock.maximumBytes,
    );
    await verifyPathStillNamesFile(lock.targetPath, expected);
    await rename(temporaryFile, lock.targetPath);
    const published = await lstat(lock.targetPath, { bigint: true });
    await validateRegularFile(lock.targetPath, published, lock.maximumBytes);
    await syncDirectory(lock.directoryPath);
    temporaryFile = undefined;
  } finally {
    if (temporaryFile !== undefined) await removeIfPresent(temporaryFile);
  }
}

/**
 * Replaces the exact file named by an opaque ownership capability and returns
 * ownership of the replacement inode. The prior capability is consumed only
 * after the replacement is fully verified.
 */
export async function replaceOwnedSecureFileWhileExclusive(
  lock: ExclusiveSecureFileLock,
  contents: Uint8Array,
  publication: OwnedSecureFilePublication,
  expectedKind: OwnedSecureFileKind,
): Promise<OwnedSecureFilePublication> {
  const state = ownedSecureFileStates.get(publication);
  if (
    state?.kind !== expectedKind ||
    state.directoryPath !== lock.directoryPath ||
    state.targetPath !== lock.targetPath ||
    state.maximumBytes !== lock.maximumBytes
  ) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  const before = await lstat(state.targetPath, { bigint: true });
  if (!sameIdentity(before, state.identity)) {
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
  await replaceSecureFileWhileExclusive(lock, contents);
  const after = await lstat(state.targetPath, { bigint: true });
  await validateRegularFile(state.targetPath, after, state.maximumBytes);
  const next = newOwnedSecureFilePublication({
    ...state,
    identity: identityOf(after),
  });
  ownedSecureFileStates.delete(publication);
  return next;
}

/**
 * Streams bounded contents to a hidden, restrictive sibling and publishes it
 * with create-only semantics. The destination is never replaced.
 */
export async function writeSecureStreamFile(
  inputPath: string,
  source: AsyncIterable<Uint8Array>,
  maximumBytes = MAX_SECURE_STREAM_FILE_BYTES,
): Promise<SecureFileStreamWriteResult> {
  assertSecureFileMaximum(maximumBytes);
  const { directoryPath, targetPath } = await resolveTarget(inputPath);
  await validateWriteDirectory(directoryPath);
  let temporaryFile: string | undefined;
  try {
    const written = await writeTemporaryStreamFile(directoryPath, source, maximumBytes);
    temporaryFile = written.path;
    await publishCreateNew(directoryPath, targetPath, temporaryFile, maximumBytes);
    temporaryFile = undefined;
    return { bytes: written.bytes };
  } finally {
    if (temporaryFile !== undefined) await removeIfPresent(temporaryFile);
  }
}
