/**
 * Measures the pure serialization and authenticated-encryption hot paths.
 *
 * Every digest Kavrix persists goes through `canonicalJson`, and every
 * protected document read/write goes through it twice. The AEAD measurements
 * use freshly generated random keys and non-secret synthetic plaintext; nothing
 * here touches a vault, a key file, or a real passphrase.
 */
import { createHash, randomBytes } from 'node:crypto';

import { encryptAead } from '../../packages/crypto/src/aead.ts';
import { canonicalJson } from '../../packages/schemas/src/content-hash.ts';

import { parseArgs, timeRepeatedly, throughput } from './harness.mjs';

const iterations = Number.parseInt(parseArgs(process.argv).iterations ?? '3000', 10);

const smallDocument = buildDocument(6);
const largeDocument = buildDocument(400);
const associatedData = {
  version: 1,
  schemaVersion: 1,
  keyVersion: 1,
  vaultId: 'vault.00000000-0000-4000-8000-000000000000',
  entityType: 'item',
  entityId: 'item.00000000-0000-4000-8000-000000000000',
  purpose: 'item-payload',
  revision: 1,
  groupId: 'group.00000000-0000-4000-8000-000000000000',
  metadataDigest: Buffer.alloc(32).toString('base64url'),
};
const aeadKey = randomBytes(32);
const aeadPlaintext = randomBytes(1024);

const results = {
  iterations,
  canonicalJsonSmall: await timeRepeatedly(() => canonicalJson(smallDocument), {
    iterations,
    warmup: Math.floor(iterations / 4),
  }),
  canonicalJsonLarge: await timeRepeatedly(() => canonicalJson(largeDocument), {
    iterations: Math.floor(iterations / 4),
    warmup: Math.floor(iterations / 8),
  }),
  canonicalizeLargeBytes: await throughput(
    () => Buffer.byteLength(canonicalJson(largeDocument), 'utf8'),
    { iterations: Math.floor(iterations / 4), warmup: Math.floor(iterations / 8) },
  ),
  sha256OverCanonicalLarge: await throughput(
    () => {
      createHash('sha256')
        .update(canonicalJson(largeDocument), 'utf8')
        .digest('base64url');
    },
    { iterations: Math.floor(iterations / 4), warmup: Math.floor(iterations / 8) },
  ),
  aeadEncrypt1KiB: await timeRepeatedly(
    () => encryptAead(aeadPlaintext, aeadKey, associatedData),
    {
      iterations: 400,
      warmup: 100,
    },
  ),
};

console.log(JSON.stringify(results, null, 2));

/**
 * A nested, key-sorted, digest-bearing document shaped like the payloads
 * `canonicalJson` actually canonicalizes in production.
 */
function buildDocument(width) {
  const leaf = (index) => ({
    id: `entity.${String(index).padStart(6, '0')}`,
    revision: index,
    createdAt: '2026-08-19T00:00:00.000Z',
    ciphertextHash: 'x'.repeat(43),
    payload: {
      nonce: 'A'.repeat(22),
      ciphertext: 'A'.repeat(Math.max(32, width * 2)),
      authenticationTag: 'A'.repeat(22),
      keyVersion: 1,
    },
    metadata: { owner: 'synthetic', environment: 'production', tags: ['a', 'b', 'c'] },
  });
  const vaults = {};
  for (let index = 0; index < width; index += 1) vaults[`vault-${index}`] = leaf(index);
  return { format: 'kavrix-benchmark', version: 1, vaults };
}
