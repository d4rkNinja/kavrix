import { describe, expect, expectTypeOf, it, vi } from 'vitest';
import * as fc from 'fast-check';

import type { SecretValue } from '@kavrix/schemas';

import {
  calculatePassphraseEntropyBits,
  calculatePassphraseSearchSpace,
  generatePassphrase,
  MAX_PASSPHRASE_WORD_COUNT,
  MIN_PASSPHRASE_ENTROPY_BITS,
  MIN_PASSPHRASE_WORD_COUNT,
  PASSPHRASE_WORD_LIST_SIZE,
  SAFE_PASSPHRASE_SEPARATORS,
  ValidationError,
  type PassphraseGeneratorPolicy,
} from '../src/index.js';
import {
  generatePassphraseWithRandomFill,
  type PassphraseRandomFill,
} from '../src/passphrase-generator.js';
import { PASSPHRASE_WORD_LIST } from '../src/passphrase-word-list.js';

describe('passphrase generator', () => {
  it('uses a compact strong default and returns only a branded secret', () => {
    const spies = [
      vi.spyOn(console, 'log').mockImplementation(() => undefined),
      vi.spyOn(console, 'info').mockImplementation(() => undefined),
      vi.spyOn(console, 'warn').mockImplementation(() => undefined),
      vi.spyOn(console, 'error').mockImplementation(() => undefined),
    ];
    const generated = generatePassphrase();

    expectTypeOf(generated).toEqualTypeOf<SecretValue>();
    expect(generated.length).toBeGreaterThan(23);
    expect(hasUnsafeControl(generated)).toBe(false);
    expect(calculatePassphraseEntropyBits()).toBeGreaterThan(82);
    expect(calculatePassphraseSearchSpace()).toBe(1_296n ** 8n);
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });

  it('uses rejection sampling and wipes the owned random buffer', () => {
    const source = queuedUint32([0xffff_ffff, ...new Array<number>(8).fill(0)]);
    const generated = generatePassphraseWithRandomFill(undefined, source.fill);

    expect(generated).toBe('acid-acid-acid-acid-acid-acid-acid-acid' as SecretValue);
    expect(source.calls()).toBe(9);
    expect(source.buffer()?.every((value) => value === 0)).toBe(true);
  });

  it('applies exclusions, one random capitalization, and a random number', () => {
    const source = queuedUint32(new Array<number>(9).fill(0));
    const generated = generatePassphraseWithRandomFill(
      {
        wordCount: 6,
        separator: '_',
        capitalize: true,
        includeNumber: true,
        excludedWords: ['acid'],
      },
      source.fill,
    );

    expect(generated).toBe('Acorn_acorn_acorn_acorn_acorn_acorn_0' as SecretValue);
    expect(generated).not.toContain('acid');
    expect(source.calls()).toBe(8);
  });

  it('matches exact search-space and entropy math across dynamic policies', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 64 }),
        fc.integer({ min: 7, max: MAX_PASSPHRASE_WORD_COUNT }),
        fc.boolean(),
        fc.boolean(),
        (excludedCount, wordCount, capitalize, includeNumber) => {
          const policy = {
            wordCount,
            capitalize,
            includeNumber,
            excludedWords: PASSPHRASE_WORD_LIST.slice(0, excludedCount),
          } satisfies PassphraseGeneratorPolicy;
          const available = PASSPHRASE_WORD_LIST_SIZE - excludedCount;
          const expected =
            BigInt(available) ** BigInt(wordCount) *
            BigInt(capitalize ? wordCount : 1) *
            BigInt(includeNumber ? 10 : 1);
          const expectedBits =
            Math.log2(available) * wordCount +
            (capitalize ? Math.log2(wordCount) : 0) +
            (includeNumber ? Math.log2(10) : 0);

          expect(calculatePassphraseSearchSpace(policy)).toBe(expected);
          expect(calculatePassphraseEntropyBits(policy)).toBeCloseTo(expectedBits, 12);
        },
      ),
      { numRuns: 250 },
    );
  });

  it('satisfies bounded property-generated policies without control characters', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 7, max: MAX_PASSPHRASE_WORD_COUNT }),
        fc.constantFrom(
          '_' as const,
          '.' as const,
          ':' as const,
          '+' as const,
          '=' as const,
        ),
        fc.boolean(),
        fc.boolean(),
        fc.integer({ min: 0, max: 32 }),
        fc.integer({ min: 0, max: 0xffff_ffff }),
        (wordCount, separator, capitalize, includeNumber, excludedCount, seed) => {
          const excludedWords = PASSPHRASE_WORD_LIST.slice(0, excludedCount);
          const generated = generatePassphraseWithRandomFill(
            {
              wordCount,
              separator,
              capitalize,
              includeNumber,
              excludedWords,
            },
            deterministicFill(seed),
          );
          const tokens = generated.split(separator);
          const words = includeNumber ? tokens.slice(0, -1) : tokens;

          expect(words).toHaveLength(wordCount);
          expect(hasUnsafeControl(generated)).toBe(false);
          expect(
            words.every((word) => !excludedWords.includes(word.toLowerCase())),
          ).toBe(true);
          expect(words.filter((word) => /^[A-Z]/u.test(word))).toHaveLength(
            capitalize ? 1 : 0,
          );
          if (includeNumber) expect(tokens.at(-1)).toMatch(/^\d$/u);
        },
      ),
      { numRuns: 250 },
    );
  });

  it('fails generically when a random source never yields an accepted value', () => {
    const source = queuedUint32(new Array<number>(128).fill(0xffff_ffff));
    expect(() => generatePassphraseWithRandomFill(undefined, source.fill)).toThrow(
      'Cryptographic random selection failed.',
    );
    expect(source.calls()).toBe(128);
    expect(source.buffer()?.every((value) => value === 0)).toBe(true);
  });

  it('wipes the owned random buffer when the injected test source fails', () => {
    let observed: Uint8Array | undefined;
    const failing: PassphraseRandomFill = (target) => {
      observed = target;
      target.fill(77);
      throw new Error('random-source-canary');
    };
    const operation = (): SecretValue =>
      generatePassphraseWithRandomFill(undefined, failing);

    expect(operation).toThrow('Cryptographic random selection failed.');
    expect(operation).not.toThrow('random-source-canary');
    expect(observed?.every((value) => value === 0)).toBe(true);
    expect(() => generatePassphraseWithRandomFill(undefined, null as never)).toThrow(
      'Cryptographic random selection failed.',
    );
  });

  it.each(SAFE_PASSPHRASE_SEPARATORS)(
    'accepts only the fixed visible separator %s',
    (separator) => {
      const generated = generatePassphraseWithRandomFill(
        { separator },
        queuedUint32(new Array<number>(8).fill(0)).fill,
      );
      expect(generated).toBe(new Array<string>(8).fill('acid').join(separator));
      expect(hasUnsafeControl(generated)).toBe(false);
    },
  );

  it.each([
    null,
    [],
    { unexpected: true },
    { wordCount: MIN_PASSPHRASE_WORD_COUNT - 1 },
    { wordCount: MAX_PASSPHRASE_WORD_COUNT + 1 },
    { wordCount: Number.NaN },
    { separator: ' ' },
    { separator: '\n' },
    { capitalize: 'yes' },
    { includeNumber: 1 },
    { excludedWords: 'acid' },
    { excludedWords: ['missing'] },
    { excludedWords: ['acid', 'acid'] },
    { excludedWords: PASSPHRASE_WORD_LIST.slice(0, 1_290) },
    { excludedWords: new Array(PASSPHRASE_WORD_LIST_SIZE).fill('acid') },
  ])('rejects invalid or insufficient policy %#', (policy) => {
    expect(() => generatePassphrase(policy as never)).toThrow(ValidationError);
  });

  it('embeds the reviewed canonical list with no unsafe characters', () => {
    expect(SAFE_PASSPHRASE_SEPARATORS).toEqual(['-', '_', '.', ':', '+', '=']);
    expect(PASSPHRASE_WORD_LIST).toHaveLength(PASSPHRASE_WORD_LIST_SIZE);
    expect(new Set(PASSPHRASE_WORD_LIST).size).toBe(PASSPHRASE_WORD_LIST_SIZE);
    expect(
      PASSPHRASE_WORD_LIST.every((word) => /^[a-z]+(?:-[a-z]+)?$/u.test(word)),
    ).toBe(true);
    expect(calculatePassphraseEntropyBits()).toBeGreaterThanOrEqual(
      MIN_PASSPHRASE_ENTROPY_BITS,
    );
  });
});

function queuedUint32(values: readonly number[]): Readonly<{
  fill: PassphraseRandomFill;
  calls: () => number;
  buffer: () => Uint8Array | undefined;
}> {
  let callCount = 0;
  let observed: Uint8Array | undefined;
  return {
    fill(target): void {
      observed = target;
      const value = values[callCount];
      if (value === undefined) throw new Error('Test random queue exhausted');
      new DataView(target.buffer, target.byteOffset, target.byteLength).setUint32(
        0,
        value,
        false,
      );
      callCount += 1;
    },
    calls: () => callCount,
    buffer: () => observed,
  };
}

function deterministicFill(initialSeed: number): PassphraseRandomFill {
  let state = initialSeed >>> 0;
  return (target) => {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    new DataView(target.buffer, target.byteOffset, target.byteLength).setUint32(
      0,
      state,
      false,
    );
  };
}

function hasUnsafeControl(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0);
    return (
      codePoint === undefined ||
      codePoint < 0x20 ||
      (codePoint >= 0x7f && codePoint <= 0x9f)
    );
  });
}
