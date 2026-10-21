import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import sodium from 'libsodium-wrappers';
import { describe, expect, it } from 'vitest';

/**
 * `secretstream.ts` wipes WASM stream state through libsodium's private
 * `libsodium.HEAPU8`, `_free`, and state-size exports. Those are not public
 * API, so this suite pins the exact reviewed version and proves the private
 * surface still behaves. A dependency bump must fail here, loudly, before it
 * can silently turn state cleanup into a runtime error or a no-op.
 */
const REVIEWED_LIBSODIUM_WRAPPERS_VERSION = '0.8.4';
const SECRETSTREAM_STATE_BYTES = 52;

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(here, '../../..');

interface RawSodiumRuntime {
  readonly HEAPU8: Uint8Array;
  readonly _crypto_secretstream_xchacha20poly1305_statebytes: () => number;
  readonly _free: (address: number) => void;
}

function rawRuntime(): RawSodiumRuntime {
  const runtime = (sodium as unknown as { readonly libsodium?: RawSodiumRuntime })
    .libsodium;
  if (runtime === undefined) throw new Error('libsodium runtime is not exposed');
  return runtime;
}

describe('libsodium private runtime contract', () => {
  it('uses exactly the reviewed libsodium-wrappers version', () => {
    // The package's `exports` map hides package.json, so read the installed
    // manifest through the crypto package's own dependency link.
    const manifest = JSON.parse(
      readFileSync(
        resolve(
          repositoryRoot,
          'packages/crypto/node_modules/libsodium-wrappers/package.json',
        ),
        'utf8',
      ),
    ) as { version?: unknown };
    expect(manifest.version).toBe(REVIEWED_LIBSODIUM_WRAPPERS_VERSION);
    const workspace = readFileSync(
      resolve(repositoryRoot, 'pnpm-workspace.yaml'),
      'utf8',
    );
    expect(workspace).toMatch(
      new RegExp(
        `^\\s+libsodium-wrappers: ${REVIEWED_LIBSODIUM_WRAPPERS_VERSION.replaceAll('.', '\\.')}$`,
        'mu',
      ),
    );
  });

  it('exposes the private exports secretstream cleanup depends on', async () => {
    await sodium.ready;
    const runtime = rawRuntime();
    expect(runtime.HEAPU8).toBeInstanceOf(Uint8Array);
    expect(typeof runtime._free).toBe('function');
    expect(typeof runtime._crypto_secretstream_xchacha20poly1305_statebytes).toBe(
      'function',
    );
    expect(runtime._crypto_secretstream_xchacha20poly1305_statebytes()).toBe(
      SECRETSTREAM_STATE_BYTES,
    );
  });

  it('represents stream state as a heap address that can be wiped in place', async () => {
    await sodium.ready;
    const runtime = rawRuntime();
    const key = sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const { state } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    const address = state as unknown as number;
    expect(Number.isSafeInteger(address)).toBe(true);
    const end = address + SECRETSTREAM_STATE_BYTES;
    expect(end).toBeLessThanOrEqual(runtime.HEAPU8.byteLength);
    expect(runtime.HEAPU8.subarray(address, end).some((byte) => byte !== 0)).toBe(true);
    runtime.HEAPU8.fill(0, address, end);
    expect(runtime.HEAPU8.subarray(address, end).every((byte) => byte === 0)).toBe(
      true,
    );
    runtime._free(address);
    key.fill(0);
  });
});
