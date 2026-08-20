import { describe, expect, it } from 'vitest';

import {
  MAX_TEXT_BYTES,
  encryptedTextSchema,
  secretValueSchema,
  utf8ByteLength,
} from '../src/index.js';

describe('UTF-8 text byte limits', () => {
  it('accepts ASCII exactly at the byte limit and rejects over-limit ASCII', () => {
    const atLimit = 'a'.repeat(MAX_TEXT_BYTES);
    const overLimit = `${atLimit}a`;

    expect(utf8ByteLength(atLimit)).toBe(MAX_TEXT_BYTES);
    expect(encryptedTextSchema.safeParse(atLimit).success).toBe(true);
    expect(secretValueSchema.safeParse(atLimit).success).toBe(true);
    expect(encryptedTextSchema.safeParse(overLimit).success).toBe(false);
    expect(secretValueSchema.safeParse(overLimit).success).toBe(false);
  });

  it('accepts multi-byte UTF-8 text exactly at the limit and rejects a larger code point', () => {
    const euroCount = Math.floor(MAX_TEXT_BYTES / 3);
    const atLimit = `${'€'.repeat(euroCount)}a`;
    const overLimit = `${atLimit}€`;

    expect(utf8ByteLength(atLimit)).toBe(MAX_TEXT_BYTES);
    expect(encryptedTextSchema.safeParse(atLimit).success).toBe(true);
    expect(secretValueSchema.safeParse(atLimit).success).toBe(true);
    expect(utf8ByteLength(overLimit)).toBeGreaterThan(MAX_TEXT_BYTES);
    expect(encryptedTextSchema.safeParse(overLimit).success).toBe(false);
    expect(secretValueSchema.safeParse(overLimit).success).toBe(false);
  });

  it('rejects the 600,000-euro reproduction while preserving ordinary Unicode', () => {
    const oversized = '€'.repeat(600_000);
    expect(utf8ByteLength(oversized)).toBe(1_800_000);
    expect(encryptedTextSchema.safeParse(oversized).success).toBe(false);
    expect(secretValueSchema.safeParse(oversized).success).toBe(false);

    for (const value of ['é', 'e\u0301', '秘密の手順', '🔐\nمرحبا']) {
      expect(secretValueSchema.parse(value)).toBe(value);
      expect(encryptedTextSchema.parse(value)).toBe(value);
    }
  });

  it('retains the too-big issue contract for byte-limit failures', () => {
    const result = encryptedTextSchema.safeParse('a'.repeat(MAX_TEXT_BYTES + 1));

    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.error.issues).toEqual([
      {
        code: 'too_big',
        origin: 'string',
        maximum: MAX_TEXT_BYTES,
        inclusive: true,
        message: `Too big: expected string to have <=${String(MAX_TEXT_BYTES)} bytes`,
        path: [],
      },
    ]);
  });
});
