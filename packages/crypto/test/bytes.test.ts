import { describe, expect, it } from 'vitest';

import {
  CryptoInputError,
  constantTimeEqual,
  copyBytes,
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from '../src/index.js';

describe('byte handling', () => {
  it('round-trips only canonical unpadded base64url', () => {
    const bytes = Uint8Array.of(0, 127, 128, 255);
    expect(decodeBase64Url(encodeBase64Url(bytes))).toEqual(bytes);
    for (const malformed of ['', 'A', 'AA==', 'AA+', 'AA/']) {
      expect(() => decodeBase64Url(malformed)).toThrow(CryptoInputError);
    }
    expect(() => decodeBase64Url('AAAA', { exactBytes: 2 })).toThrow(CryptoInputError);
    expect(() => decodeBase64Url('AAAA', { maximumBytes: 2 })).toThrow(
      CryptoInputError,
    );
  });

  it('compares equal and differently sized values without prefix equality', () => {
    expect(constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2))).toBe(true);
    expect(constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3))).toBe(false);
    expect(constantTimeEqual(Uint8Array.of(1), Uint8Array.of(1, 0))).toBe(false);
  });

  it('copies and best-effort zeroizes mutable arrays', () => {
    const original = Uint8Array.of(1, 2, 3);
    const copy = copyBytes(original);
    zeroize(original);
    expect(original).toEqual(Uint8Array.of(0, 0, 0));
    expect(copy).toEqual(Uint8Array.of(1, 2, 3));
    expect(() => {
      requireByteLength(copy, 2);
    }).toThrow(CryptoInputError);
  });
});
