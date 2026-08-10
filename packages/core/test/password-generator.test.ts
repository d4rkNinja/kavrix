import { describe, expect, expectTypeOf, it } from 'vitest';
import * as fc from 'fast-check';

import type { SecretValue } from '@kavrix/schemas';

import {
  MAX_GENERATED_PASSWORD_LENGTH,
  MIN_GENERATED_PASSWORD_LENGTH,
  ValidationError,
  generatePassword,
  type PasswordGeneratorPolicy,
} from '../src/index.js';

const strongPolicy = {
  length: 32,
  classes: [
    { name: 'lowercase', alphabet: 'abcdefghijkmnopqrstuvwxyz', minimum: 4 },
    { name: 'uppercase', alphabet: 'ABCDEFGHJKLMNPQRSTUVWXYZ', minimum: 4 },
    { name: 'digits', alphabet: '23456789', minimum: 4 },
    { name: 'symbols', alphabet: '!@#$%^&*', minimum: 2 },
  ],
} as const satisfies PasswordGeneratorPolicy;

describe('password generator', () => {
  it('returns a branded secret satisfying every explicit class rule', () => {
    const generated = generatePassword(strongPolicy);
    expectTypeOf(generated).toEqualTypeOf<SecretValue>();
    expect(generated).toHaveLength(32);
    expect(
      generated.match(/[abcdefghijkmnopqrstuvwxyz]/g)?.length ?? 0,
    ).toBeGreaterThanOrEqual(4);
    expect(
      generated.match(/[ABCDEFGHJKLMNPQRSTUVWXYZ]/g)?.length ?? 0,
    ).toBeGreaterThanOrEqual(4);
    expect(generated.match(/[23456789]/g)?.length ?? 0).toBeGreaterThanOrEqual(4);
    expect(generated.match(/[!@#$%^&*]/g)?.length ?? 0).toBeGreaterThanOrEqual(2);
  });

  it('applies exclusions before generation without weakening a class minimum', () => {
    const generated = generatePassword({
      ...strongPolicy,
      excludedCharacters: 'aA2!',
    });
    expect(generated).not.toMatch(/[aA2!]/);
    expect(generated).toHaveLength(strongPolicy.length);
  });

  it('satisfies bounded policies across property-generated lengths and minima', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: MIN_GENERATED_PASSWORD_LENGTH, max: 128 }),
        fc.integer({ min: 1, max: 4 }),
        (length, requestedMinimum) => {
          const minimum = Math.min(requestedMinimum, Math.floor(length / 2));
          const generated = generatePassword({
            length,
            classes: [
              { name: 'letters', alphabet: 'abcdef', minimum },
              { name: 'digits', alphabet: '012345', minimum },
            ],
          });
          expect(generated).toHaveLength(length);
          expect(generated.match(/[a-f]/g)?.length ?? 0).toBeGreaterThanOrEqual(
            minimum,
          );
          expect(generated.match(/[0-5]/g)?.length ?? 0).toBeGreaterThanOrEqual(
            minimum,
          );
        },
      ),
      { numRuns: 200 },
    );
  });

  it.each([
    {
      length: MIN_GENERATED_PASSWORD_LENGTH - 1,
      classes: [{ name: 'letters', alphabet: 'abc', minimum: 1 }],
    },
    {
      length: MAX_GENERATED_PASSWORD_LENGTH + 1,
      classes: [{ name: 'letters', alphabet: 'abc', minimum: 1 }],
    },
    { length: 16, classes: [] },
    {
      length: 16,
      classes: [{ name: 'Letters', alphabet: 'abc', minimum: 1 }],
    },
    {
      length: 16,
      classes: [
        { name: 'letters', alphabet: 'abc', minimum: 1 },
        { name: 'letters', alphabet: 'XYZ', minimum: 1 },
      ],
    },
    {
      length: 16,
      classes: [{ name: 'letters', alphabet: 'aac', minimum: 1 }],
    },
    {
      length: 16,
      classes: [{ name: 'letters', alphabet: 'a c', minimum: 1 }],
    },
    {
      length: 16,
      classes: [{ name: 'letters', alphabet: 'abc', minimum: 0 }],
    },
    {
      length: 16,
      classes: [
        { name: 'letters', alphabet: 'abc', minimum: 1 },
        { name: 'overlap', alphabet: 'cde', minimum: 1 },
      ],
    },
    {
      length: 8,
      classes: [
        { name: 'letters', alphabet: 'abc', minimum: 5 },
        { name: 'digits', alphabet: '123', minimum: 4 },
      ],
    },
    {
      length: 16,
      classes: [{ name: 'letters', alphabet: 'abc', minimum: 1 }],
      excludedCharacters: 'abc',
    },
  ] satisfies readonly PasswordGeneratorPolicy[])(
    'rejects impossible policy %#',
    (policy) => {
      expect(() => generatePassword(policy)).toThrow(ValidationError);
    },
  );
});
