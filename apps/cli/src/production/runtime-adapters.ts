import { mkdir } from 'node:fs/promises';
import { randomUUID, webcrypto } from 'node:crypto';

import { createSecureClipboard } from '@kavrix/clipboard';
import type { ClockPort, IdGeneratorPort } from '@kavrix/core';
import { setWindowsUserOnlyAcl } from '@kavrix/key-files';

const CLOCK: ClockPort = { now: () => new Date() };

/** Directory permissions must be user-only before any store file is created. */
export async function ensureDataDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  if (process.platform === 'win32') {
    await setWindowsUserOnlyAcl(directory);
  }
}

export function productionClock(): ClockPort {
  return CLOCK;
}

/**
 * Identifiers must be unpredictable and satisfy the opaque-ID grammar
 * (`[A-Za-z0-9][A-Za-z0-9._~-]*`). Lifecycle operation IDs additionally require
 * at least sixteen characters, which the 32-character hex form always meets.
 */
export function randomIdGenerator<TId extends string>(): IdGeneratorPort<TId> {
  return {
    next: () => randomHex(16) as TId,
  };
}

/** Sync idempotency keys have the same unpredictability requirement. */
export function randomIdempotencyKeys(): { next(): string } {
  return { next: () => randomHex(16) };
}

export function secureClipboard(): ReturnType<typeof createSecureClipboard> {
  return createSecureClipboard();
}

function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  webcrypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export { randomUUID };
