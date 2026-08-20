import { describe, expect, it } from 'vitest';

import { MAX_TEXT_BYTES, localVaultValueSchema, utf8ByteLength } from '../src/index.js';

const updatedAt = '2026-08-10T00:00:00.000Z';

describe('local vault value text byte limits', () => {
  it('uses the shared UTF-8 byte limit at the exact boundary', () => {
    const euroCount = Math.floor(MAX_TEXT_BYTES / 3);
    const atLimit = `${'€'.repeat(euroCount)}a`;
    const overLimit = `${atLimit}€`;

    expect(utf8ByteLength(atLimit)).toBe(MAX_TEXT_BYTES);
    expect(localVaultValueSchema.parse({ value: atLimit, updatedAt }).value).toBe(
      atLimit,
    );
    expect(
      localVaultValueSchema.safeParse({ value: overLimit, updatedAt }).success,
    ).toBe(false);
  });

  it('rejects the oversized multi-byte reproduction', () => {
    const oversized = '€'.repeat(600_000);

    expect(
      localVaultValueSchema.safeParse({ value: oversized, updatedAt }).success,
    ).toBe(false);
  });
});
