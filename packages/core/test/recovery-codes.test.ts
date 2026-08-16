import {
  fieldDefinitionSchema,
  fieldValueSchema,
  secretValueSchema,
  type FieldDefinition,
  type FieldType,
  type FieldValue,
  type FieldValueElement,
  type Timestamp,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import { AmbiguousNameError, NotFoundError, ValidationError } from '../src/errors.js';
import {
  assertRecoveryCodeField,
  listRecoveryCodes,
  planRecoveryCodeUse,
  readRecoveryCodeElements,
  selectRecoveryCode,
  summarizeRecoveryCodes,
} from '../src/policies/recovery-codes.js';

const CREATED_AT = '2026-08-10T00:00:00.000Z';
const USED_AT = '2026-08-16T12:00:00.000Z' as Timestamp;

function definition(type: FieldType = 'recovery-code-list'): FieldDefinition {
  return fieldDefinitionSchema.parse({
    id: 'field.recovery',
    stableKey: 'recovery-codes',
    label: 'Recovery codes',
    type,
    required: false,
    sensitive: true,
    repeatable: false,
    copyable: true,
    searchableLocally: false,
    showInPreview: false,
    copyPolicy: 'allowed',
    revealPolicy: 'timed',
    reauthenticationPolicy: 'after-lock',
    exportPolicy: 'guarded',
    sortOrder: 0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
}

/** Builds a stored code list. `usedAt` present marks that element consumed. */
function codes(
  entries: readonly (readonly [id: string, code: string, usedAt?: string])[],
): FieldValue {
  return fieldValueSchema.parse({
    version: 1,
    state: 'present',
    content: {
      cardinality: 'multiple',
      elements: entries.map(([id, code, usedAt]) => ({
        id,
        value: { kind: 'secret', value: secretValueSchema.parse(code) },
        lifecycle:
          usedAt === undefined
            ? { version: 1, status: 'available' }
            : { version: 1, status: 'used', usedAt },
      })),
    },
  });
}

function elementsOf(value: FieldValue): readonly FieldValueElement[] {
  return readRecoveryCodeElements(definition(), value);
}

describe('recovery code field guard', () => {
  it('accepts only the field type whose elements may be marked used', () => {
    expect(() => {
      assertRecoveryCodeField(definition());
    }).not.toThrow();

    for (const type of ['tags', 'secret', 'text', 'environment-map'] as const) {
      expect(() => {
        assertRecoveryCodeField(definition(type));
      }).toThrow(ValidationError);
    }
  });

  it('refuses every stored state that is not a readable code list', () => {
    const field = definition();
    const cases: readonly (readonly [FieldValue | undefined, RegExp])[] = [
      [undefined, /no recovery codes yet/u],
      [
        fieldValueSchema.parse({ version: 1, state: 'missing' }),
        /no recovery codes yet/u,
      ],
      [fieldValueSchema.parse({ version: 1, state: 'empty' }), /is empty/u],
      [
        fieldValueSchema.parse({ version: 1, state: 'inapplicable' }),
        /marked inapplicable/u,
      ],
      [
        fieldValueSchema.parse({
          version: 1,
          state: 'unreadable',
          reason: 'decryption-failed',
        }),
        /cannot be read/u,
      ],
      [
        fieldValueSchema.parse({
          version: 1,
          state: 'orphaned',
          originalValue: { version: 1, state: 'empty' },
        }),
        /archived/u,
      ],
      [
        fieldValueSchema.parse({
          version: 1,
          state: 'present',
          content: {
            cardinality: 'single',
            value: { kind: 'secret', value: secretValueSchema.parse('lonely') },
          },
        }),
        /single value/u,
      ],
    ];

    for (const [value, message] of cases) {
      expect(() => readRecoveryCodeElements(field, value)).toThrow(ValidationError);
      expect(() => readRecoveryCodeElements(field, value)).toThrow(message);
    }
  });

  it('never treats an unreadable code list as an empty one', () => {
    // Reporting "no codes" here would invite a caller to overwrite codes that
    // are still stored but temporarily unreadable.
    expect(() =>
      readRecoveryCodeElements(
        definition(),
        fieldValueSchema.parse({
          version: 1,
          state: 'unreadable',
          reason: 'decryption-failed',
        }),
      ),
    ).toThrow(/cannot be read/u);
  });
});

describe('recovery code listing', () => {
  it('projects identity and lifecycle without exposing any code material', () => {
    const value = codes([
      ['code.a', 'aaaa-1111'],
      ['code.b', 'bbbb-2222', USED_AT],
    ]);

    const listed = listRecoveryCodes(elementsOf(value));

    expect(listed).toEqual([
      { id: 'code.a', status: 'available', usedAt: undefined },
      { id: 'code.b', status: 'used', usedAt: USED_AT },
    ]);
    const rendered = JSON.stringify(listed);
    expect(rendered).not.toContain('aaaa-1111');
    expect(rendered).not.toContain('bbbb-2222');
  });

  it('counts available and used codes', () => {
    const inventory = summarizeRecoveryCodes(
      elementsOf(
        codes([
          ['code.a', 'aaaa-1111'],
          ['code.b', 'bbbb-2222', USED_AT],
          ['code.c', 'cccc-3333', USED_AT],
        ]),
      ),
    );

    expect(inventory).toEqual({ total: 3, available: 1, used: 2 });
  });
});

describe('recovery code selection', () => {
  const value = codes([
    ['code.alpha', 'aaaa-1111'],
    ['code.alphabet', 'bbbb-2222'],
    ['code.beta', 'cccc-3333'],
  ]);

  it('selects by exact stable identifier even when it prefixes another', () => {
    expect(selectRecoveryCode(elementsOf(value), 'code.alpha').id).toBe('code.alpha');
  });

  it('accepts an unambiguous prefix', () => {
    expect(selectRecoveryCode(elementsOf(value), 'code.b').id).toBe('code.beta');
  });

  it('refuses an ambiguous prefix instead of guessing', () => {
    let thrown: unknown;
    try {
      selectRecoveryCode(elementsOf(value), 'code.alp');
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(AmbiguousNameError);
    expect((thrown as AmbiguousNameError).candidateIds).toEqual([
      'code.alpha',
      'code.alphabet',
    ]);
  });

  it('refuses an unknown identifier, an empty query, and a differently cased one', () => {
    expect(() => selectRecoveryCode(elementsOf(value), 'code.zeta')).toThrow(
      NotFoundError,
    );
    expect(() => selectRecoveryCode(elementsOf(value), '   ')).toThrow(ValidationError);
    expect(() => selectRecoveryCode(elementsOf(value), 'CODE.ALPHA')).toThrow(
      NotFoundError,
    );
  });

  it('never resolves a code by its own value', () => {
    // Matching on the value would compare a command argument against decrypted
    // code material, turning a typo into an oracle.
    expect(() => selectRecoveryCode(elementsOf(value), 'aaaa-1111')).toThrow(
      NotFoundError,
    );
  });

  it('does not select positionally', () => {
    expect(() => selectRecoveryCode(elementsOf(value), '1')).toThrow(NotFoundError);
    expect(() => selectRecoveryCode(elementsOf(value), '0')).toThrow(NotFoundError);
  });
});

describe('recovery code consumption plan', () => {
  const stored = codes([
    ['code.a', 'aaaa-1111'],
    ['code.b', 'bbbb-2222'],
    ['code.c', 'cccc-3333', '2026-08-15T00:00:00.000Z'],
  ]);

  it('marks exactly one code used and preserves every other element verbatim', () => {
    const before = elementsOf(stored);
    const plan = planRecoveryCodeUse(definition(), stored, 'code.b', USED_AT);

    expect(plan.element.id).toBe('code.b');
    expect(plan.element.lifecycle).toEqual({
      version: 1,
      status: 'used',
      usedAt: USED_AT,
    });
    expect(plan.value.content.cardinality).toBe('multiple');
    const after =
      plan.value.content.cardinality === 'multiple' ? plan.value.content.elements : [];
    expect(after.map(({ id }) => id)).toEqual(before.map(({ id }) => id));
    expect(after[0]).toEqual(before[0]);
    expect(after[2]).toEqual(before[2]);
    expect(after[1]?.value).toEqual(before[1]?.value);
    expect(plan.inventory).toEqual({ total: 3, available: 1, used: 2 });
  });

  it('leaves the stored value untouched so nothing is consumed before the write', () => {
    planRecoveryCodeUse(definition(), stored, 'code.a', USED_AT);

    expect(listRecoveryCodes(elementsOf(stored))).toEqual([
      { id: 'code.a', status: 'available', usedAt: undefined },
      { id: 'code.b', status: 'available', usedAt: undefined },
      { id: 'code.c', status: 'used', usedAt: '2026-08-15T00:00:00.000Z' },
    ]);
  });

  it('refuses a code that is already used rather than restamping it', () => {
    expect(() => planRecoveryCodeUse(definition(), stored, 'code.c', USED_AT)).toThrow(
      /already been used/u,
    );
  });

  it('produces a value its own field definition accepts', () => {
    const plan = planRecoveryCodeUse(definition(), stored, 'code.b', USED_AT);

    expect(() => fieldValueSchema.parse(plan.value)).not.toThrow();
  });

  it('refuses to plan a consume on a field that cannot hold a used state', () => {
    const repeatableText = fieldDefinitionSchema.parse({
      ...definition('text'),
      repeatable: true,
    });

    expect(() =>
      planRecoveryCodeUse(repeatableText, stored, 'code.b', USED_AT),
    ).toThrow(ValidationError);
  });
});
