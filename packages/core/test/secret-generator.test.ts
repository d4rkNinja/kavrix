import { randomFillSync } from 'node:crypto';

import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import {
  generateSecret,
  secretCharacterClasses,
  type RandomFill,
} from '../src/index.js';
import type { SecretGenerationRequest } from '@kavrix/schemas';

const csprng: RandomFill = (target) => {
  randomFillSync(target);
};

function request(
  overrides: Partial<SecretGenerationRequest> = {},
): SecretGenerationRequest {
  return {
    format: 'password',
    length: 32,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false,
    ...overrides,
  };
}

describe('generateSecret', () => {
  it('honours length and includes every selected class', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 8, max: 256 }),
        fc.boolean(),
        fc.boolean(),
        fc.boolean(),
        fc.boolean(),
        fc.boolean(),
        (length, lowercase, uppercase, digits, symbols, excludeAmbiguous) => {
          fc.pre(lowercase || uppercase || digits || symbols);
          const input = request({
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            excludeAmbiguous,
          });
          const classes = secretCharacterClasses(input);
          const generated = generateSecret(input, csprng);
          const characters = Array.from(generated.value);
          expect(characters).toHaveLength(length);
          const alphabet = new Set(classes.join(''));
          expect(characters.every((character) => alphabet.has(character))).toBe(true);
          for (const characterClass of classes) {
            expect(
              characters.some((character) => characterClass.includes(character)),
            ).toBe(true);
          }
          if (excludeAmbiguous) {
            expect(generated.value).not.toMatch(/[Il1O0o|]/u);
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  it('never emits shell- or env-hostile characters', () => {
    for (let run = 0; run < 50; run += 1) {
      const { value } = generateSecret(request({ length: 256 }), csprng);
      expect(value).not.toMatch(/["'`\\$\s]/u);
    }
  });

  it('produces hex and base64url alphabets', () => {
    expect(
      generateSecret(request({ format: 'hex', length: 64 }), csprng).value,
    ).toMatch(/^[0-9a-f]{64}$/u);
    expect(
      generateSecret(request({ format: 'base64url', length: 43 }), csprng).value,
    ).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  });

  it('reports a conservative entropy estimate', () => {
    const hex = generateSecret(request({ format: 'hex', length: 64 }), csprng);
    expect(hex.alphabetSize).toBe(16);
    expect(hex.entropyBits).toBe(256);
    const password = generateSecret(request({ length: 20 }), csprng);
    expect(password.entropyBits).toBeLessThanOrEqual(
      Math.floor(20 * Math.log2(password.alphabetSize)),
    );
    expect(password.entropyBits).toBeGreaterThan(100);
  });

  it('rejects biased samples instead of reducing them modulo the alphabet', () => {
    // 2^32 - 1 is above the largest multiple of 10 below 2^32, so the first
    // sample must be discarded; the second (zero) selects index 0.
    let calls = 0;
    const fill: RandomFill = (target) => {
      calls += 1;
      target.fill(calls % 2 === 1 ? 0xff : 0x00);
    };
    const { value } = generateSecret(
      request({ lowercase: false, uppercase: false, symbols: false, length: 8 }),
      fill,
    );
    expect(value).toBe('00000000');
    expect(calls).toBeGreaterThan(8);
  });

  it('fails closed when the random source never yields a usable sample', () => {
    const stuck: RandomFill = (target) => {
      target.fill(0xff);
    };
    expect(() =>
      generateSecret(
        request({ lowercase: false, uppercase: false, symbols: false }),
        stuck,
      ),
    ).toThrow('random source');
  });

  it('distributes characters close to uniformly', () => {
    const counts = new Map<string, number>();
    const draws = 40;
    for (let run = 0; run < draws; run += 1) {
      for (const character of generateSecret(
        request({ format: 'hex', length: 1024 }),
        csprng,
      ).value) {
        counts.set(character, (counts.get(character) ?? 0) + 1);
      }
    }
    const expected = (draws * 1024) / 16;
    const chiSquare = [...counts.values()].reduce(
      (total, count) => total + (count - expected) ** 2 / expected,
      0,
    );
    expect(counts.size).toBe(16);
    // 15 degrees of freedom; 50 is far beyond the 0.9999 quantile (~42.6).
    expect(chiSquare).toBeLessThan(50);
  });

  it('rejects malformed requests before drawing randomness', () => {
    let calls = 0;
    const counting: RandomFill = (target) => {
      calls += 1;
      randomFillSync(target);
    };
    for (const invalid of [
      request({ length: 7 }),
      request({ length: 1025 }),
      request({ length: 12.5 }),
      request({ lowercase: false, uppercase: false, digits: false, symbols: false }),
      { ...request(), extra: true } as unknown as SecretGenerationRequest,
    ]) {
      expect(() => generateSecret(invalid, counting)).toThrow();
    }
    expect(calls).toBe(0);
  });
});
