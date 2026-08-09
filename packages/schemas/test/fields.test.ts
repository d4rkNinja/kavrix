import { describe, expect, expectTypeOf, it } from 'vitest';
import * as fc from 'fast-check';

import {
  fieldDefinitionSchema,
  fieldValueMatchesDefinition,
  fieldValueElementLifecycleSchema,
  fieldValueSchema,
  groupTemplateSchema,
  isSensitiveFieldType,
  itemIdSchema,
  itemPayloadSchema,
  matchesNamedValidation,
  noteSchema,
  secretValueSchema,
  validationRulesSchema,
  type FieldDefinition,
  type FieldScalarValue,
  type FieldType,
  type FieldValue,
  type ItemId,
  type SecretValue,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';

function field(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'field.password',
    stableKey: 'password',
    label: 'Password',
    type: 'secret',
    required: true,
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
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  };
}

function singleValue(value: FieldScalarValue): FieldValue {
  return fieldValueSchema.parse({
    version: 1,
    state: 'present',
    content: { cardinality: 'single', value },
  });
}

function textValue(value: string, secret = false): FieldValue {
  return singleValue(
    secret
      ? { kind: 'secret', value: secretValueSchema.parse(value) }
      : { kind: 'text', value },
  );
}

function repeatedValue(values: readonly FieldScalarValue[]): FieldValue {
  return fieldValueSchema.parse({
    version: 1,
    state: 'present',
    content: {
      cardinality: 'multiple',
      elements: values.map((value, index) => ({
        id: `element.${String(index)}`,
        value,
        lifecycle: { version: 1, status: 'available' },
      })),
    },
  });
}

describe('dynamic field schemas', () => {
  it('forbids secret defaults and non-sensitive secret field types', async () => {
    const schemaExports = await import('../src/index.js');
    expect(Object.hasOwn(schemaExports, 'sensitiveFieldTypes')).toBe(false);
    expect(
      fieldDefinitionSchema.safeParse(
        field({ defaultValue: textValue('unsafe', true) }),
      ).success,
    ).toBe(false);
    expect(fieldDefinitionSchema.safeParse(field({ sensitive: false })).success).toBe(
      false,
    );
    expect(
      fieldDefinitionSchema.safeParse(field({ copyable: false, copyPolicy: 'allowed' }))
        .success,
    ).toBe(false);
    expect(
      fieldDefinitionSchema.safeParse(field({ showInPreview: true })).success,
    ).toBe(false);
  });

  it('keeps stable keys independent from editable labels', () => {
    const original = fieldDefinitionSchema.parse(field());
    const renamed = fieldDefinitionSchema.parse(
      field({ label: 'Application password' }),
    );
    expect(renamed.id).toBe(original.id);
    expect(renamed.stableKey).toBe('password');
  });

  it('rejects duplicate field IDs, stable keys, and sort orders', () => {
    expect(
      groupTemplateSchema.safeParse({
        id: 'template.email',
        name: 'Email',
        version: 1,
        fields: [field(), field({ label: 'Again' })],
        createdAt: timestamp,
        updatedAt: timestamp,
      }).success,
    ).toBe(false);
  });

  it('accepts generated dynamic labels while preserving stable keys', () => {
    fc.assert(
      fc.property(
        fc
          .string({ minLength: 1, maxLength: 256 })
          .filter((label) => label.trim().length > 0),
        fc.integer({ min: 0, max: 10_000 }),
        (label, index) => {
          const stableKey = `property_${String(index)}`;
          const parsed = fieldDefinitionSchema.parse(
            field({
              id: `field.property.${String(index)}`,
              stableKey,
              label,
            }),
          );
          expect(parsed.stableKey).toBe(stableKey);
        },
      ),
      { numRuns: 250 },
    );
  });

  it('rejects contradictory ranges and all free-form regular expressions', () => {
    for (const rules of [
      { minLength: 4, maxLength: 3 },
      { min: 2, max: 1 },
      { pattern: '[' },
      { pattern: '^(a+)+$' },
      { customValidator: 'consumer-code' },
    ]) {
      expect(validationRulesSchema.safeParse(rules).success).toBe(false);
    }
    expect(
      validationRulesSchema.safeParse({
        minLength: 1,
        maxLength: 2,
        namedValidation: 'lowercase-ascii',
      }).success,
    ).toBe(true);
  });

  it('evaluates safe named validations at their boundaries', () => {
    expect(matchesNamedValidation('hostname', `${'a'.repeat(63)}.example`)).toBe(true);
    expect(matchesNamedValidation('hostname', `${'a'.repeat(64)}.example`)).toBe(false);
    expect(matchesNamedValidation('ipv4', '255.255.255.255')).toBe(true);
    expect(matchesNamedValidation('ipv4', '256.0.0.1')).toBe(false);
    expect(matchesNamedValidation('base64url', 'Abc_123-Z')).toBe(true);
    expect(matchesNamedValidation('base64url', 'Abc=')).toBe(false);
  });

  it('enforces canonical select, preview, reveal, and copy policy combinations', () => {
    const publicField = {
      type: 'text',
      sensitive: false,
      revealPolicy: 'never',
      reauthenticationPolicy: 'never',
      exportPolicy: 'encrypted-only',
    };
    const invalid = [
      field({ ...publicField, copyable: true, copyPolicy: 'never' }),
      field({ ...publicField, revealPolicy: 'timed' }),
      field({ type: 'secret', reauthenticationPolicy: 'never' }),
      field({ ...publicField, type: 'select' }),
      field({ ...publicField, selectOptions: [{ value: 'x', label: 'X' }] }),
    ];
    for (const candidate of invalid) {
      expect(fieldDefinitionSchema.safeParse(candidate).success).toBe(false);
    }
    expect(
      fieldDefinitionSchema.safeParse(
        field({
          type: 'select',
          sensitive: false,
          revealPolicy: 'never',
          reauthenticationPolicy: 'never',
          exportPolicy: 'encrypted-only',
          selectOptions: [{ value: 'production', label: 'Production' }],
        }),
      ).success,
    ).toBe(true);
  });
});

function matchingField(
  type: FieldType,
  overrides: Record<string, unknown> = {},
): FieldDefinition {
  const sensitive = isSensitiveFieldType(type);
  return fieldDefinitionSchema.parse(
    field({
      type,
      sensitive,
      required: false,
      repeatable: false,
      searchableLocally: !sensitive,
      showInPreview: !sensitive,
      revealPolicy: sensitive ? 'timed' : 'never',
      reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
      exportPolicy: sensitive ? 'guarded' : 'encrypted-only',
      ...overrides,
    }),
  );
}

describe('field value semantics', () => {
  it('matches every structured type and rejects malformed contextual values', () => {
    const cases: readonly (readonly [
      FieldType,
      FieldValue,
      FieldValue,
      Record<string, unknown>?,
    ])[] = [
      ['number', singleValue({ kind: 'number', value: 1.5 }), textValue('1.5')],
      [
        'port',
        singleValue({ kind: 'number', value: 443 }),
        singleValue({ kind: 'number', value: 65_536 }),
      ],
      ['boolean', singleValue({ kind: 'boolean', value: true }), textValue('true')],
      [
        'tags',
        repeatedValue([
          { kind: 'text', value: 'one' },
          { kind: 'text', value: 'two' },
        ]),
        repeatedValue([{ kind: 'number', value: 2 }]),
      ],
      [
        'recovery-code-list',
        repeatedValue([{ kind: 'secret', value: secretValueSchema.parse('one') }]),
        textValue('one', true),
      ],
      [
        'environment-map',
        repeatedValue([
          {
            kind: 'environment-entry',
            key: 'PROD',
            value: { classification: 'text', value: 'secret' },
          },
        ]),
        repeatedValue([{ kind: 'text', value: 'secret' }]),
      ],
      ['json', textValue('{"valid":true}'), textValue('{invalid')],
      [
        'select',
        textValue('prod'),
        textValue('unknown'),
        { selectOptions: [{ value: 'prod', label: 'Production' }] },
      ],
      [
        'multi-select',
        repeatedValue([{ kind: 'text', value: 'prod' }]),
        repeatedValue([{ kind: 'text', value: 'unknown' }]),
        { selectOptions: [{ value: 'prod', label: 'Production' }] },
      ],
      ['email', textValue('person@example.test'), textValue('not-an-email')],
      [
        'url',
        textValue('https://example.test'),
        textValue('ftp://example.test'),
        { validationRules: { allowedSchemes: ['https'] } },
      ],
      ['text', textValue('value'), singleValue({ kind: 'number', value: 1 })],
    ];
    for (const [type, valid, invalid, overrides = {}] of cases) {
      const definition = matchingField(type, overrides);
      expect(fieldValueMatchesDefinition(definition, valid), type).toBe(true);
      expect(fieldValueMatchesDefinition(definition, invalid), type).toBe(false);
    }
  });

  it('applies repeatability and safe text and number rules per element', () => {
    const repeated = matchingField('text', {
      repeatable: true,
      validationRules: {
        minLength: 2,
        maxLength: 4,
        namedValidation: 'lowercase-ascii',
      },
    });
    expect(
      fieldValueMatchesDefinition(
        repeated,
        repeatedValue([
          { kind: 'text', value: 'ab' },
          { kind: 'text', value: 'test' },
        ]),
      ),
    ).toBe(true);
    expect(fieldValueMatchesDefinition(repeated, textValue('ab'))).toBe(false);
    expect(
      fieldValueMatchesDefinition(
        repeated,
        repeatedValue([{ kind: 'text', value: 'a' }]),
      ),
    ).toBe(false);
    expect(
      fieldValueMatchesDefinition(
        repeated,
        repeatedValue([{ kind: 'text', value: 'AB' }]),
      ),
    ).toBe(false);

    const bounded = matchingField('number', { validationRules: { min: 2, max: 4 } });
    expect(
      fieldValueMatchesDefinition(bounded, singleValue({ kind: 'number', value: 3 })),
    ).toBe(true);
    expect(
      fieldValueMatchesDefinition(bounded, singleValue({ kind: 'number', value: 1 })),
    ).toBe(false);
    expect(
      fieldValueMatchesDefinition(bounded, singleValue({ kind: 'number', value: 5 })),
    ).toBe(false);
  });

  it('distinguishes all states, brands secrets, and rejects positional repeats', () => {
    for (const state of ['missing', 'empty'] as const) {
      expect(fieldValueSchema.safeParse({ version: 1, state }).success).toBe(true);
    }
    expect(
      fieldValueSchema.safeParse({
        version: 1,
        state: 'inapplicable',
        reason: 'Not used by this provider',
      }).success,
    ).toBe(true);
    expect(
      fieldValueSchema.safeParse({
        version: 1,
        state: 'unreadable',
        reason: 'unsupported-version',
      }).success,
    ).toBe(true);
    const secret = textValue('classified', true);
    if (secret.state !== 'present' || secret.content.cardinality !== 'single') {
      throw new Error('Expected a scalar secret fixture');
    }
    if (secret.content.value.kind !== 'secret') {
      throw new Error('Expected a branded secret fixture');
    }
    expectTypeOf(secret.content.value.value).toEqualTypeOf<SecretValue>();
    expect(fieldValueSchema.safeParse(['one', 'two']).success).toBe(false);
    expect(
      fieldValueSchema.safeParse({
        version: 1,
        state: 'present',
        content: {
          cardinality: 'multiple',
          elements: [
            {
              id: 'element.same',
              value: { kind: 'text', value: 'one' },
              lifecycle: { version: 1, status: 'available' },
            },
            {
              id: 'element.same',
              value: { kind: 'text', value: 'two' },
              lifecycle: { version: 1, status: 'available' },
            },
          ],
        },
      }).success,
    ).toBe(false);
  });

  it('brands sensitive environment values and rejects ordinary strings', () => {
    const sensitiveEnvironment = matchingField('environment-map', {
      sensitive: true,
      searchableLocally: false,
      showInPreview: false,
      revealPolicy: 'timed',
      reauthenticationPolicy: 'after-lock',
      exportPolicy: 'guarded',
    });
    const secretEnvironment = repeatedValue([
      {
        kind: 'environment-entry',
        key: 'TOKEN',
        value: {
          classification: 'secret',
          value: secretValueSchema.parse('classified'),
        },
      },
    ]);
    const plainEnvironment = repeatedValue([
      {
        kind: 'environment-entry',
        key: 'TOKEN',
        value: { classification: 'text', value: 'classified' },
      },
    ]);
    expect(fieldValueMatchesDefinition(sensitiveEnvironment, secretEnvironment)).toBe(
      true,
    );
    expect(fieldValueMatchesDefinition(sensitiveEnvironment, plainEnvironment)).toBe(
      false,
    );
    expect(
      fieldValueMatchesDefinition(matchingField('environment-map'), plainEnvironment),
    ).toBe(true);
  });

  it('enforces recovery-code element lifecycle without leaking it to other lists', () => {
    expect(
      fieldValueElementLifecycleSchema.safeParse({
        version: 1,
        status: 'available',
        usedAt: timestamp,
      }).success,
    ).toBe(false);
    expect(
      fieldValueElementLifecycleSchema.safeParse({
        version: 1,
        status: 'used',
      }).success,
    ).toBe(false);
    const usedRecoveryCodes = fieldValueSchema.parse({
      version: 1,
      state: 'present',
      content: {
        cardinality: 'multiple',
        elements: [
          {
            id: 'recovery-code.1',
            value: {
              kind: 'secret',
              value: secretValueSchema.parse('recovery-code'),
            },
            lifecycle: { version: 1, status: 'used', usedAt: timestamp },
          },
        ],
      },
    });
    expect(
      fieldValueMatchesDefinition(
        matchingField('recovery-code-list'),
        usedRecoveryCodes,
      ),
    ).toBe(true);
    expect(
      fieldValueMatchesDefinition(
        matchingField('text', { repeatable: true }),
        fieldValueSchema.parse({
          version: 1,
          state: 'present',
          content: {
            cardinality: 'multiple',
            elements: [
              {
                id: 'ordinary.1',
                value: { kind: 'text', value: 'ordinary' },
                lifecycle: { version: 1, status: 'used', usedAt: timestamp },
              },
            ],
          },
        }),
      ),
    ).toBe(false);
  });

  it('enforces aggregate serialized size', () => {
    expect(
      fieldValueSchema.safeParse({
        version: 1,
        state: 'present',
        content: {
          cardinality: 'multiple',
          elements: Array.from({ length: 5 }, (_, index) => ({
            id: `element.large.${String(index)}`,
            value: { kind: 'text', value: 'x'.repeat(1_000_000) },
            lifecycle: { version: 1, status: 'available' },
          })),
        },
      }).success,
    ).toBe(false);
  });
});

describe('aggregate item field contracts', () => {
  it('rejects unbound, mistyped, missing, and active-plus-orphaned values', () => {
    const customField = fieldDefinitionSchema.parse(
      field({
        id: 'field.custom_port',
        stableKey: 'custom_port',
        label: 'Custom port',
        type: 'port',
        sensitive: false,
        required: true,
        revealPolicy: 'never',
        reauthenticationPolicy: 'never',
        exportPolicy: 'encrypted-only',
      }),
    );
    const base = {
      version: 1,
      id: 'item.1',
      vaultId: 'vault.1',
      groupId: 'group.1',
      templateId: 'template.1',
      title: 'Item',
      aliases: ['Primary account'],
      templateVersion: 1,
      templateValues: [],
      itemFields: [customField],
      itemValues: [
        {
          fieldId: customField.id,
          stableKey: customField.stableKey,
          value: singleValue({ kind: 'number', value: 5432 }),
          updatedAt: timestamp,
        },
      ],
      archivedFieldValues: [],
      notes: [],
      tags: [],
      favorite: false,
      productionSensitive: false,
      relatedItemIds: [],
      attachmentIds: [],
      copySequences: [],
      revision: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    };

    expect(itemPayloadSchema.safeParse(base).success).toBe(true);
    expect(itemPayloadSchema.safeParse({ ...base, itemValues: [] }).success).toBe(
      false,
    );
    expect(
      itemPayloadSchema.safeParse({
        ...base,
        itemValues: [{ ...base.itemValues[0], value: textValue('not-a-port') }],
      }).success,
    ).toBe(false);
    expect(
      itemPayloadSchema.safeParse({
        ...base,
        archivedFieldValues: [
          {
            definition: customField,
            value: {
              version: 1,
              state: 'orphaned',
              originalValue: {
                version: 1,
                state: 'present',
                content: {
                  cardinality: 'single',
                  value: { kind: 'number', value: 1234 },
                },
              },
            },
            sourceTemplateId: 'template.1',
            sourceTemplateVersion: 1,
            archivedAt: timestamp,
            reason: 'user-archived',
          },
        ],
      }).success,
    ).toBe(false);
  });

  it('binds field references and copy sequences to declared opaque IDs and keys', () => {
    const referenceField = field({
      id: 'field.related',
      stableKey: 'related',
      type: 'item-reference',
      required: false,
    });
    const referenceValue = singleValue({
      kind: 'item-reference',
      itemId: itemIdSchema.parse('item.2'),
    });
    if (
      referenceValue.state !== 'present' ||
      referenceValue.content.cardinality !== 'single' ||
      referenceValue.content.value.kind !== 'item-reference'
    ) {
      throw new Error('Expected an item reference fixture');
    }
    expectTypeOf(referenceValue.content.value.itemId).toEqualTypeOf<ItemId>();
    const base = {
      version: 1,
      id: 'item.1',
      vaultId: 'vault.1',
      groupId: 'group.1',
      templateId: 'template.1',
      title: 'Item',
      aliases: [],
      templateVersion: 1,
      templateValues: [],
      itemFields: [referenceField],
      itemValues: [
        {
          fieldId: 'field.related',
          stableKey: 'related',
          value: referenceValue,
          updatedAt: timestamp,
        },
      ],
      archivedFieldValues: [],
      notes: [],
      tags: [],
      favorite: false,
      owner: 'Platform team',
      purpose: 'Production deployment credential',
      productionSensitive: true,
      lastVerifiedAt: timestamp,
      relatedItemIds: ['item.2'],
      attachmentIds: [],
      copySequences: [{ id: 'sequence.login', name: 'Login', fieldKeys: ['related'] }],
      revision: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    expect(itemPayloadSchema.safeParse(base).success).toBe(true);
    expect(itemPayloadSchema.safeParse({ ...base, relatedItemIds: [] }).success).toBe(
      false,
    );
    expect(
      itemPayloadSchema.safeParse({
        ...base,
        copySequences: [
          { id: 'sequence.login', name: 'Login', fieldKeys: ['unknown'] },
        ],
      }).success,
    ).toBe(false);
  });
});

describe('Unicode note schema properties', () => {
  it('round-trips representative arbitrary Unicode without normalization', () => {
    const values = ['é', 'e\u0301', '秘密の手順', '🔐\nمرحبا', '\u202Evisible'];
    for (const [index, content] of values.entries()) {
      const parsed = noteSchema.parse({
        id: `note.${String(index)}`,
        title: `Note ${String(index)}`,
        content: secretValueSchema.parse(content),
        isSensitive: index % 2 === 0,
        isPinned: false,
        tags: [],
        sortOrder: index,
        createdAt: timestamp,
        updatedAt: timestamp,
      });
      expect(parsed.content).toBe(content);
    }
  });

  it('preserves arbitrary bounded note content', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 4_096 }), (content) => {
        const parsed = noteSchema.parse({
          id: 'note.property',
          title: 'Property note',
          content: secretValueSchema.parse(content),
          isSensitive: true,
          isPinned: false,
          tags: [],
          sortOrder: 0,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
        expect(parsed.content).toBe(content);
      }),
      { numRuns: 200 },
    );
  });
});
