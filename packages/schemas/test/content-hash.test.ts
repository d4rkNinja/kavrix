import { describe, expect, it } from 'vitest';

import { canonicalJson } from '../src/index.js';

describe('canonical JSON', () => {
  it('sorts object keys recursively while preserving array order', () => {
    expect(
      canonicalJson({ z: true, a: [{ y: 2, x: 1 }, null], omitted: undefined }),
    ).toBe('{"a":[{"x":1,"y":2},null],"z":true}');
  });

  it('rejects values outside the JSON wire domain', () => {
    expect(() => canonicalJson(Number.POSITIVE_INFINITY)).toThrow(TypeError);
    expect(() => canonicalJson(undefined)).toThrow(TypeError);
    expect(() => canonicalJson(new Date('2026-08-10T00:00:00.000Z'))).toThrow(
      TypeError,
    );
  });
});
