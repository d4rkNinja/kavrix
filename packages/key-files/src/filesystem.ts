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

type ResolvedTarget = Readonly<{
  directoryPath: string;
  targetPath: string;
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
): Promise<void> {
  if (
    !metadata.isFile() ||
    metadata.size <= 0 ||
    metadata.size > MAX_PORTABLE_KEY_FILE_BYTES ||
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

async function readBounded(handle: FileHandle): Promise<Buffer> {
  const output = Buffer.alloc(MAX_PORTABLE_KEY_FILE_BYTES + 1);
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
  if (offset === 0 || offset > MAX_PORTABLE_KEY_FILE_BYTES) {
    output.fill(0);
    throw new PortableKeyFileError('KEY_FILE_UNSAFE');
  }
  const result = Buffer.from(output.subarray(0, offset));
  output.fill(0);
  return result;
}

export async function readSecureFile(inputPath: string): Promise<Buffer> {
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
    await validateRegularFile(targetPath, opened);
    await verifyPathStillNamesFile(targetPath, before);
    contents = await readBounded(handle);
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
): Promise<string> {
  const path = temporaryPath(directoryPath);
  const handle = await createSecureEmptyFile(path);
  try {
    await handle.writeFile(contents);
    await handle.sync();
    const metadata = await handle.stat({ bigint: true });
    if (metadata.size !== BigInt(contents.byteLength)) {
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
  return path;
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
): Promise<void> {
  try {
    await link(temporaryFile, targetPath);
    await removeIfPresent(temporaryFile);
    const published = await lstat(targetPath, { bigint: true });
    await validateRegularFile(targetPath, published);
    await syncDirectory(directoryPath);
  } catch (error) {
    // Once the create-only link exists, publication may have reached durable
    // storage even when verification or directory sync reports failure. Never
    // remove that public path on an uncertain outcome.
    throw mappedFileError(error, 'KEY_FILE_OPERATION_FAILED');
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

async function validateReplacementTarget(targetPath: string): Promise<FileIdentity> {
  const identity = await lstatRegularIdentity(targetPath);
  const handle = await open(targetPath, noFollowReadFlags());
  try {
    const opened = await handle.stat({ bigint: true });
    if (!sameIdentity(identity, opened)) {
      throw new PortableKeyFileError('KEY_FILE_UNSAFE');
    }
    await validateRegularFile(targetPath, opened);
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
    const expected = await validateReplacementTarget(targetPath);
    await verifyPathStillNamesFile(targetPath, expected);
    await rename(temporaryFile, targetPath);
    const published = await lstat(targetPath, { bigint: true });
    await validateRegularFile(targetPath, published);
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
): Promise<void> {
  if (!isWriteMode(mode)) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  if (contents.byteLength === 0 || contents.byteLength > MAX_PORTABLE_KEY_FILE_BYTES) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  const { directoryPath, targetPath } = await resolveTarget(inputPath);
  await validateWriteDirectory(directoryPath);
  let temporaryFile: string | undefined;
  try {
    temporaryFile = await writeTemporaryFile(directoryPath, contents);
    if (mode === 'create') {
      await publishCreateNew(directoryPath, targetPath, temporaryFile);
    } else {
      await publishReplacement(directoryPath, targetPath, temporaryFile);
    }
    temporaryFile = undefined;
  } finally {
    if (temporaryFile !== undefined) await removeIfPresent(temporaryFile);
  }
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
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > MAX_SECURE_STREAM_FILE_BYTES
  ) {
    throw new PortableKeyFileError('KEY_FILE_OPERATION_FAILED');
  }
  const { directoryPath, targetPath } = await resolveTarget(inputPath);
  await validateWriteDirectory(directoryPath);
  let temporaryFile: string | undefined;
  try {
    const written = await writeTemporaryStreamFile(directoryPath, source, maximumBytes);
    temporaryFile = written.path;
    await publishCreateNew(directoryPath, targetPath, temporaryFile);
    temporaryFile = undefined;
    return { bytes: written.bytes };
  } finally {
    if (temporaryFile !== undefined) await removeIfPresent(temporaryFile);
  }
}
