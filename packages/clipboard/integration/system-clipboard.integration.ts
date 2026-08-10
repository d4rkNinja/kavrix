import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { detectClipboardBackend } from '../src/backends.js';
import { createNodeClipboardRuntime } from '../src/node-runtime.js';
import { SecureClipboard } from '../src/secure-clipboard.js';

const explicitlyEnabled =
  process.env['KAVRIX_CLIPBOARD_INTEGRATION'] === '1' &&
  process.env['KAVRIX_CLIPBOARD_EXCLUSIVE_SESSION'] === '1';

describe.runIf(explicitlyEnabled)('real system clipboard', () => {
  it('temporarily copies, guarded-clears, and restores an exclusively held snapshot', async () => {
    const runtime = createNodeClipboardRuntime();
    const backend = await detectClipboardBackend(runtime);
    const clipboard = new SecureClipboard(runtime);
    const snapshot = await backend.read();
    const snapshotHash = digest(snapshot);
    const canary = new TextEncoder().encode(
      `kavrix-integration-${randomBytes(16).toString('base64url')}`,
    );
    const canaryHash = digest(canary);
    const emptyHash = digest(new Uint8Array());
    let restored = false;

    try {
      await clipboard.copy(canary, { clearAfterMs: 30_000 });
      await expect(clipboard.lock()).resolves.toBe(true);
    } finally {
      let current: Uint8Array = new Uint8Array();
      let currentHash: Uint8Array = new Uint8Array();
      try {
        current = await backend.read();
        currentHash = digest(current);
        if (
          equalDigest(currentHash, snapshotHash) ||
          equalDigest(currentHash, canaryHash) ||
          equalDigest(currentHash, emptyHash)
        ) {
          if (snapshot.byteLength === 0) await backend.clear();
          else await backend.write(snapshot);
          restored = true;
        }
      } finally {
        current.fill(0);
        currentHash.fill(0);
        snapshot.fill(0);
        snapshotHash.fill(0);
        canary.fill(0);
        canaryHash.fill(0);
        emptyHash.fill(0);
      }
    }

    expect(restored).toBe(true);
  });
});

function digest(value: Uint8Array): Uint8Array {
  const hash = createHash('sha256').update(value).digest();
  try {
    return Uint8Array.from(hash);
  } finally {
    hash.fill(0);
  }
}

function equalDigest(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}
