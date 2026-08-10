import { randomBytes } from 'node:crypto';
import type { FileHandle } from 'node:fs/promises';
import { lstat, open, unlink } from 'node:fs/promises';

import { SyncLocalStateError } from '@kavrix/sync';

import {
  prepareSecureLeafParent,
  secureNewLeaf,
  verifySecureLeaf,
} from './path-security.js';

export interface LocalWriterLease {
  readonly path: string;
  release(): Promise<void>;
}

export type StaleLocalWriterLeaseRecovery = 'absent' | 'recovered';

const MAX_METADATA_BYTES = 256;
const NONCE_BYTES = 16;

type FileIdentity = Readonly<{
  dev: number | bigint;
  ino: number | bigint;
}>;

class ExclusiveLocalWriterLease implements LocalWriterLease {
  readonly path: string;
  readonly #handle: FileHandle;
  readonly #identity: FileIdentity;
  #released = false;

  public constructor(path: string, handle: FileHandle, identity: FileIdentity) {
    this.path = path;
    this.#handle = handle;
    this.#identity = identity;
  }

  public async release(): Promise<void> {
    if (this.#released) return;
    this.#released = true;
    let failure: unknown;
    try {
      const pathStats = await verifySecureLeaf(this.path);
      const handleStats = await this.#handle.stat();
      if (
        !sameIdentity(pathStats, this.#identity) ||
        !sameIdentity(handleStats, this.#identity) ||
        pathStats.nlink !== 1 ||
        handleStats.nlink !== 1
      ) {
        throw invalidState();
      }
      await unlink(this.path);
    } catch (error) {
      failure = error;
    }
    try {
      await this.#handle.close();
    } catch (error) {
      failure ??= error;
    }
    if (failure !== undefined) throw invalidState();
  }
}

/**
 * Acquires a process-lifetime writer exclusion file with `O_EXCL`. This call
 * never removes an existing lease; guarded dead-owner recovery is an explicit
 * separate operation.
 */
export async function acquireLocalWriterLease(
  pathInput: string,
): Promise<LocalWriterLease> {
  const path = await prepareSecureLeafParent(pathInput);
  let handle: FileHandle;
  try {
    handle = await open(path, 'wx', 0o600);
  } catch {
    throw invalidState();
  }
  try {
    await secureNewLeaf(path);
    await writeOwnerMetadata(handle);
    const handleStats = await handle.stat();
    const pathStats = await verifySecureLeaf(path);
    if (
      handleStats.nlink !== 1 ||
      pathStats.nlink !== 1 ||
      !sameIdentity(handleStats, pathStats)
    ) {
      throw invalidState();
    }
    return new ExclusiveLocalWriterLease(path, handle, {
      dev: handleStats.dev,
      ino: handleStats.ino,
    });
  } catch {
    try {
      const pathStats = await verifySecureLeaf(path);
      const handleStats = await handle.stat();
      if (sameIdentity(pathStats, handleStats)) await unlink(path);
    } catch {
      // The path is no longer identity-bound, so removing it would be unsafe.
    }
    try {
      await handle.close();
    } catch {
      // Acquisition already fails closed.
    }
    throw invalidState();
  }
}

/**
 * Removes only an identity-bound, owner-only lease whose recorded PID is no
 * longer live. Malformed metadata, a live/reused PID, or any path race fails
 * closed. Callers must retry `acquireLocalWriterLease` after recovery.
 */
export async function recoverStaleLocalWriterLease(
  pathInput: string,
): Promise<StaleLocalWriterLeaseRecovery> {
  const path = await prepareSecureLeafParent(pathInput);
  if (!(await exists(path))) return 'absent';
  const pathStats = await verifySecureLeaf(path);
  let handle: FileHandle;
  try {
    handle = await open(path, 'r');
  } catch {
    throw invalidState();
  }
  let failed = false;
  try {
    const handleStats = await handle.stat();
    if (
      pathStats.nlink !== 1 ||
      handleStats.nlink !== 1 ||
      !sameIdentity(pathStats, handleStats)
    ) {
      throw invalidState();
    }
    const first = await readOwnerMetadata(handle);
    if (ownerPidIsLive(first.pid)) throw invalidState();
    const second = await readOwnerMetadata(handle);
    const currentPathStats = await verifySecureLeaf(path);
    const currentHandleStats = await handle.stat();
    if (
      JSON.stringify(first) !== JSON.stringify(second) ||
      currentPathStats.nlink !== 1 ||
      currentHandleStats.nlink !== 1 ||
      !sameIdentity(currentPathStats, pathStats) ||
      !sameIdentity(currentHandleStats, pathStats)
    ) {
      throw invalidState();
    }
    await unlink(path);
  } catch {
    failed = true;
  }
  try {
    await handle.close();
  } catch {
    failed = true;
  }
  if (failed) throw invalidState();
  return 'recovered';
}

async function writeOwnerMetadata(handle: FileHandle): Promise<void> {
  const nonceBytes = randomBytes(NONCE_BYTES);
  const metadata = Buffer.from(
    JSON.stringify({
      version: 1,
      pid: process.pid,
      nonce: nonceBytes.toString('base64url'),
    }),
    'utf8',
  );
  try {
    if (metadata.byteLength < 1 || metadata.byteLength > MAX_METADATA_BYTES) {
      throw invalidState();
    }
    const result = await handle.write(metadata, 0, metadata.byteLength, 0);
    if (result.bytesWritten !== metadata.byteLength) throw invalidState();
    await handle.sync();
  } catch {
    throw invalidState();
  } finally {
    nonceBytes.fill(0);
    metadata.fill(0);
  }
}

async function readOwnerMetadata(
  handle: FileHandle,
): Promise<Readonly<{ version: 1; pid: number; nonce: string }>> {
  const stats = await handle.stat();
  if (
    !Number.isSafeInteger(stats.size) ||
    stats.size < 1 ||
    stats.size > MAX_METADATA_BYTES
  ) {
    throw invalidState();
  }
  const encoded = new Uint8Array(stats.size);
  try {
    const result = await handle.read(encoded, 0, encoded.byteLength, 0);
    if (result.bytesRead !== encoded.byteLength) throw invalidState();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(encoded);
    const value = JSON.parse(text) as unknown;
    if (
      typeof value !== 'object' ||
      value === null ||
      Array.isArray(value) ||
      Object.keys(value).length !== 3 ||
      !('version' in value) ||
      value.version !== 1 ||
      !('pid' in value) ||
      !Number.isSafeInteger(value.pid) ||
      (value.pid as number) < 1 ||
      !('nonce' in value) ||
      typeof value.nonce !== 'string' ||
      !/^[A-Za-z0-9_-]{22}$/u.test(value.nonce)
    ) {
      throw invalidState();
    }
    const parsed = {
      version: 1 as const,
      pid: value.pid as number,
      nonce: value.nonce,
    };
    if (JSON.stringify(parsed) !== text) throw invalidState();
    return parsed;
  } catch {
    throw invalidState();
  } finally {
    encoded.fill(0);
  }
}

function ownerPidIsLive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      error.code === 'ESRCH'
    ) {
      return false;
    }
    if (
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      error.code === 'EPERM'
    ) {
      return true;
    }
    throw invalidState();
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      error.code === 'ENOENT'
    ) {
      return false;
    }
    throw invalidState();
  }
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function invalidState(): SyncLocalStateError {
  return new SyncLocalStateError();
}
