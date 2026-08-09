import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';

import {
  auditEventIdSchema,
  activeFieldValueSchema,
  fieldDefinitionSchema,
  fieldValueSchema,
  groupTemplateSchema,
  itemPayloadSchema,
  templateMigrationIdSchema,
  type ActiveFieldValue,
  type FieldDefinition,
  type GroupTemplate,
  type ItemPayload,
  type TemplateMigrationPlan,
} from '@kavrix/schemas';

import {
  SchemaMigrationError,
  applyTemplateMigrationBatch,
  planTemplateMigration,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';
const later = '2026-08-10T00:01:00.000Z';

function secretFieldValue(value: string): ActiveFieldValue {
  return activeFieldValueSchema.parse({
    version: 1,
    state: 'present',
    content: {
      cardinality: 'single',
      value: { kind: 'secret', value },
    },
  });
}

function scalarText(value: unknown): string | undefined {
  const parsed = fieldValueSchema.safeParse(value);
  if (
    !parsed.success ||
    parsed.data.state !== 'present' ||
    parsed.data.content.cardinality !== 'single'
  ) {
    return undefined;
  }
  const scalar = parsed.data.content.value;
  return scalar.kind === 'text' || scalar.kind === 'secret' ? scalar.value : undefined;
}

function field(overrides: Record<string, unknown> = {}): FieldDefinition {
  return fieldDefinitionSchema.parse({
    id: 'field.support_pin',
    stableKey: 'support_pin',
    label: 'Support PIN',
    type: 'secret',
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
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  });
}

function template(version: number, fields: readonly FieldDefinition[]): GroupTemplate {
  return groupTemplateSchema.parse({
    id: 'template.email',
    name: 'Email',
    version,
    fields,
    createdAt: timestamp,
    updatedAt: version === 1 ? timestamp : later,
  });
}

function item(activeField: FieldDefinition): ItemPayload {
  return itemPayloadSchema.parse({
    version: 1,
    id: 'item.gmail',
    vaultId: 'vault.1',
    groupId: 'group.email',
    title: 'Gmail',
    aliases: [],
    templateId: 'template.email',
    templateVersion: 1,
    templateValues: [
      {
        fieldId: activeField.id,
        stableKey: activeField.stableKey,
        value: secretFieldValue('123456'),
        updatedAt: timestamp,
      },
    ],
    itemFields: [],
    itemValues: [],
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
  });
}

function itemWithValue(
  activeField: FieldDefinition,
  value: ActiveFieldValue,
  id = 'item.gmail',
): ItemPayload {
  return itemPayloadSchema.parse({
    ...item(activeField),
    id,
    templateValues: [
      {
        fieldId: activeField.id,
        stableKey: activeField.stableKey,
        value,
        updatedAt: timestamp,
      },
    ],
  });
}

function plan(
  fromTemplate: GroupTemplate,
  toTemplate: GroupTemplate,
  items: readonly ItemPayload[],
): TemplateMigrationPlan {
  return planTemplateMigration({
    migrationId: templateMigrationIdSchema.parse('migration.1'),
    auditEventId: auditEventIdSchema.parse('audit.1'),
    fromTemplate,
    toTemplate,
    items,
    timestamp,
  });
}

describe('safe template migrations', () => {
  it('renames labels without changing stable keys or values', () => {
    const original = field();
    const renamed = field({ label: 'Provider Support PIN', updatedAt: later });
    const migration = plan(template(1, [original]), template(2, [renamed]), [
      item(original),
    ]);

    expect(migration.steps).toContainEqual(
      expect.objectContaining({ kind: 'rename-label', requiresConfirmation: false }),
    );
    const result = applyTemplateMigrationBatch(migration, [item(original)], 1, later);
    expect(result.items[0]?.templateValues[0]?.stableKey).toBe('support_pin');
    expect(scalarText(result.items[0]?.templateValues[0]?.value)).toBe('123456');
  });

  it('preserves stable recovery-code IDs and lifecycle during migration', () => {
    const recovery = field({ type: 'recovery-code-list' });
    const renamed = field({
      type: 'recovery-code-list',
      label: 'Recovery codes',
      updatedAt: later,
    });
    const value = activeFieldValueSchema.parse({
      version: 1,
      state: 'present',
      content: {
        cardinality: 'multiple',
        elements: [
          {
            id: 'code.1',
            value: { kind: 'secret', value: 'first' },
            lifecycle: { version: 1, status: 'used', usedAt: timestamp },
          },
          {
            id: 'code.2',
            value: { kind: 'secret', value: 'second' },
            lifecycle: { version: 1, status: 'available' },
          },
        ],
      },
    });
    const source = itemWithValue(recovery, value);
    const migration = plan(template(1, [recovery]), template(2, [renamed]), [source]);
    const migrated = applyTemplateMigrationBatch(migration, [source], 1, later);
    expect(migrated.items[0]?.templateValues[0]?.value).toEqual(value);
  });

  it('archives removed field values and restores them in a later migration', () => {
    const original = field();
    const sourceItem = item(original);
    const removal = plan(template(1, [original]), template(2, []), [sourceItem]);
    expect(() => applyTemplateMigrationBatch(removal, [sourceItem], 1, later)).toThrow(
      SchemaMigrationError,
    );

    const removed = applyTemplateMigrationBatch(removal, [sourceItem], 1, later, true);
    expect(removed.items[0]?.templateValues).toHaveLength(0);
    expect(removed.items[0]?.archivedFieldValues[0]?.value.state).toBe('orphaned');

    const restoredField = field({ updatedAt: later });
    const restoration = plan(
      template(2, []),
      template(3, [restoredField]),
      removed.items,
    );
    const restored = applyTemplateMigrationBatch(restoration, removed.items, 1, later);
    expect(scalarText(restored.items[0]?.templateValues[0]?.value)).toBe('123456');
    expect(restored.items[0]?.archivedFieldValues).toHaveLength(0);
  });

  it('round-trips every active value state through archive and restore exactly', () => {
    const original = field();
    const states: readonly ActiveFieldValue[] = [
      { version: 1, state: 'missing' },
      { version: 1, state: 'empty' },
      secretFieldValue('123456'),
      { version: 1, state: 'inapplicable', reason: 'Provider does not use it' },
      { version: 1, state: 'unreadable', reason: 'unsupported-version' },
    ];

    for (const [index, state] of states.entries()) {
      const source = itemWithValue(original, state, `item.state.${String(index)}`);
      const removal = plan(template(1, [original]), template(2, []), [source]);
      const removed = applyTemplateMigrationBatch(removal, [source], 1, later, true);
      expect(removed.items[0]?.archivedFieldValues[0]?.value.originalValue).toEqual(
        state,
      );

      const restoration = plan(
        template(2, []),
        template(3, [field({ updatedAt: later })]),
        removed.items,
      );
      const restored = applyTemplateMigrationBatch(
        restoration,
        removed.items,
        1,
        later,
      );
      expect(restored.items[0]?.templateValues[0]?.value).toEqual(state);
      expect(restored.items[0]?.archivedFieldValues).toHaveLength(0);
    }
  });

  it('preserves all states across interrupted removal and conversion batches', () => {
    const original = field();
    const states: readonly ActiveFieldValue[] = [
      { version: 1, state: 'missing' },
      { version: 1, state: 'empty' },
      secretFieldValue('not-a-boolean'),
      { version: 1, state: 'inapplicable' },
      { version: 1, state: 'unreadable', reason: 'invalid-encoding' },
    ];
    const items = states.map((state, index) =>
      itemWithValue(original, state, `item.batch.${String(index)}`),
    );
    const removal = plan(template(1, [original]), template(2, []), items);
    const partial = applyTemplateMigrationBatch(removal, items, 2, later, true);
    const completed = applyTemplateMigrationBatch(
      partial.plan,
      partial.items,
      states.length,
      later,
      true,
    );
    expect(
      completed.items.map(
        (candidate) => candidate.archivedFieldValues[0]?.value.originalValue,
      ),
    ).toEqual(states);

    const booleanField = field({ type: 'boolean', updatedAt: later });
    const conversion = plan(
      template(1, [original]),
      template(2, [booleanField]),
      items,
    );
    const convertedPartial = applyTemplateMigrationBatch(
      conversion,
      items,
      2,
      later,
      true,
    );
    const converted = applyTemplateMigrationBatch(
      convertedPartial.plan,
      convertedPartial.items,
      states.length,
      later,
      true,
    );
    expect(converted.items[0]?.templateValues[0]?.value).toEqual(states[0]);
    expect(converted.items[1]?.templateValues[0]?.value).toEqual(states[1]);
    expect(converted.items[2]?.archivedFieldValues[0]?.value.originalValue).toEqual(
      states[2],
    );
    expect(converted.items[3]?.templateValues[0]?.value).toEqual(states[3]);
    expect(converted.items[4]?.templateValues[0]?.value).toEqual(states[4]);
  });

  it('rejects restoring an archived ID under a different key or type', () => {
    const original = field();
    const source = item(original);
    const removal = plan(template(1, [original]), template(2, []), [source]);
    const removed = applyTemplateMigrationBatch(removal, [source], 1, later, true);
    const replacement = field({
      stableKey: 'api_token',
      label: 'API token',
      type: 'api-key',
      updatedAt: later,
    });

    expect(() =>
      plan(template(2, []), template(3, [replacement]), removed.items),
    ).toThrow(SchemaMigrationError);
    const reassignedKey = field({
      id: 'field.replacement',
      stableKey: original.stableKey,
      updatedAt: later,
    });
    expect(() =>
      plan(template(2, []), template(3, [reassignedKey]), removed.items),
    ).toThrow(SchemaMigrationError);
  });

  it('uses checkpoints so interrupted batches resume at the next item', () => {
    const original = field();
    const first = item(original);
    const second = itemPayloadSchema.parse({ ...first, id: 'item.outlook' });
    const migration = plan(template(1, [original]), template(2, []), [first, second]);

    const partial = applyTemplateMigrationBatch(
      migration,
      [first, second],
      1,
      later,
      true,
    );
    expect(partial.plan.status).toBe('running');
    expect(partial.plan.nextItemIndex).toBe(1);
    expect(partial.items[0]?.archivedFieldValues).toHaveLength(1);
    expect(partial.items[1]?.archivedFieldValues).toHaveLength(0);

    const completed = applyTemplateMigrationBatch(
      partial.plan,
      partial.items,
      1,
      later,
      true,
    );
    expect(completed.plan.status).toBe('completed');
    expect(
      completed.items.every((candidate) => candidate.archivedFieldValues.length === 1),
    ).toBe(true);
  });

  it('rejects reordered or replaced items when a migration resumes', () => {
    const original = field();
    const first = item(original);
    const second = itemPayloadSchema.parse({ ...first, id: 'item.outlook' });
    const migration = plan(template(1, [original]), template(2, []), [first, second]);
    const partial = applyTemplateMigrationBatch(
      migration,
      [first, second],
      1,
      later,
      true,
    );
    const migratedFirst = partial.items[0];
    const pendingSecond = partial.items[1];
    if (migratedFirst === undefined || pendingSecond === undefined) {
      throw new Error('Expected two migration fixtures');
    }

    expect(() =>
      applyTemplateMigrationBatch(
        partial.plan,
        [pendingSecond, migratedFirst],
        1,
        later,
        true,
      ),
    ).toThrow(SchemaMigrationError);
  });

  it('cannot complete while a newly required field is absent', () => {
    const required = field({
      id: 'field.required',
      stableKey: 'required_value',
      label: 'Required value',
      type: 'text',
      sensitive: false,
      required: true,
      revealPolicy: 'never',
      reauthenticationPolicy: 'never',
      exportPolicy: 'encrypted-only',
    });
    const source = itemPayloadSchema.parse({
      ...item(field()),
      templateValues: [],
    });
    const migration = plan(template(1, []), template(2, [required]), [source]);

    expect(() =>
      applyTemplateMigrationBatch(migration, [source], 1, later, true),
    ).toThrow(SchemaMigrationError);
  });

  it('archives conversions that violate target select rules', () => {
    const original = field();
    const select = field({
      type: 'select',
      selectOptions: [{ value: 'allowed', label: 'Allowed' }],
      updatedAt: later,
    });
    const source = item(original);
    const migration = plan(template(1, [original]), template(2, [select]), [source]);
    const result = applyTemplateMigrationBatch(migration, [source], 1, later, true);

    expect(result.items[0]?.templateValues).toHaveLength(0);
    expect(result.items[0]?.archivedFieldValues[0]?.reason).toBe('type-conversion');
  });

  it('requires confirmation for every protection-policy downgrade', () => {
    const original = field({
      copyPolicy: 'confirm',
      revealPolicy: 'confirm',
      reauthenticationPolicy: 'always',
      exportPolicy: 'never',
    });
    const relaxed = field({
      copyPolicy: 'allowed',
      revealPolicy: 'timed',
      reauthenticationPolicy: 'after-lock',
      exportPolicy: 'guarded',
      searchableLocally: true,
      environmentVariableName: 'SECRET_VALUE',
      updatedAt: later,
    });
    const migration = plan(template(1, [original]), template(2, [relaxed]), [
      item(original),
    ]);

    expect(migration.steps).toContainEqual(
      expect.objectContaining({
        kind: 'update-field-policy',
        requiresConfirmation: true,
      }),
    );
    expect(() =>
      applyTemplateMigrationBatch(migration, [item(original)], 1, later),
    ).toThrow(SchemaMigrationError);
  });

  it('reclassifies nested environment values in both sensitivity directions', () => {
    const plain = field({
      type: 'environment-map',
      sensitive: false,
      repeatable: true,
      revealPolicy: 'never',
      reauthenticationPolicy: 'never',
    });
    const secret = field({
      type: 'environment-map',
      sensitive: true,
      repeatable: true,
      updatedAt: later,
    });
    const plainValue = activeFieldValueSchema.parse({
      version: 1,
      state: 'present',
      content: {
        cardinality: 'multiple',
        elements: [
          {
            id: 'element.env.1',
            value: {
              kind: 'environment-entry',
              key: 'API_TOKEN',
              value: { classification: 'text', value: 'token-value' },
            },
            lifecycle: { version: 1, status: 'available' },
          },
        ],
      },
    });
    const sourceItem = itemWithValue(plain, plainValue);
    const protect = plan(template(1, [plain]), template(2, [secret]), [sourceItem]);
    expect(protect.steps).toContainEqual(
      expect.objectContaining({
        kind: 'update-field-policy',
        requiresConfirmation: false,
      }),
    );
    const protectedItem = applyTemplateMigrationBatch(protect, [sourceItem], 1, later)
      .items[0];
    if (protectedItem === undefined) {
      throw new Error('Expected a protected migrated item');
    }
    const protectedValue = protectedItem.templateValues[0]?.value;
    expect(protectedValue?.state).toBe('present');
    if (
      protectedValue?.state !== 'present' ||
      protectedValue.content.cardinality !== 'multiple'
    ) {
      throw new Error('Expected a protected environment map');
    }
    const protectedEntry = protectedValue.content.elements[0]?.value;
    expect(protectedEntry?.kind).toBe('environment-entry');
    if (protectedEntry?.kind !== 'environment-entry') {
      throw new Error('Expected an environment entry');
    }
    expect(protectedEntry.value).toEqual({
      classification: 'secret',
      value: 'token-value',
    });

    const unprotected = field({
      type: 'environment-map',
      sensitive: false,
      repeatable: true,
      revealPolicy: 'never',
      reauthenticationPolicy: 'never',
      updatedAt: later,
    });
    const expose = plan(template(2, [secret]), template(3, [unprotected]), [
      protectedItem,
    ]);
    expect(expose.steps).toContainEqual(
      expect.objectContaining({
        kind: 'update-field-policy',
        requiresConfirmation: true,
      }),
    );
    expect(() =>
      applyTemplateMigrationBatch(expose, [protectedItem], 1, later),
    ).toThrow(SchemaMigrationError);
    const exposedItem = applyTemplateMigrationBatch(
      expose,
      [protectedItem],
      1,
      later,
      true,
    ).items[0];
    const exposedValue = exposedItem?.templateValues[0]?.value;
    expect(exposedValue?.state).toBe('present');
    if (
      exposedValue?.state !== 'present' ||
      exposedValue.content.cardinality !== 'multiple'
    ) {
      throw new Error('Expected an exposed environment map');
    }
    const exposedEntry = exposedValue.content.elements[0]?.value;
    expect(exposedEntry?.kind).toBe('environment-entry');
    if (exposedEntry?.kind !== 'environment-entry') {
      throw new Error('Expected an environment entry');
    }
    expect(exposedEntry.value).toEqual({
      classification: 'text',
      value: 'token-value',
    });
  });

  it('rejects stable-key reassignment across random migration sequences', () => {
    const keys = ['email', 'password', 'support_pin', 'tenant_id', 'unicode_e'];
    for (const [index, key] of keys.entries()) {
      const original = field({ id: `field.old.${String(index)}`, stableKey: key });
      const replacement = field({
        id: `field.new.${String(index)}`,
        stableKey: key,
        updatedAt: later,
      });
      expect(() =>
        plan(template(1, [original]), template(2, [replacement]), []),
      ).toThrow(SchemaMigrationError);
    }
  });

  it('preserves every generated value when removing a populated field', () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ minLength: 1, maxLength: 128 }), { maxLength: 30 }),
        (values) => {
          const original = field();
          const items = values.map((value, index) =>
            itemPayloadSchema.parse({
              ...item(original),
              id: `item.property.${String(index)}`,
              templateValues: [
                {
                  fieldId: original.id,
                  stableKey: original.stableKey,
                  value: secretFieldValue(value),
                  updatedAt: timestamp,
                },
              ],
            }),
          );
          const migration = plan(template(1, [original]), template(2, []), items);
          const result = applyTemplateMigrationBatch(
            migration,
            items,
            Math.max(1, items.length),
            later,
            true,
          );
          expect(
            result.items.map((candidate) => {
              const archived = candidate.archivedFieldValues[0]?.value;
              if (
                archived?.state !== 'orphaned' ||
                archived.originalValue.state !== 'present' ||
                archived.originalValue.content.cardinality !== 'single'
              ) {
                return undefined;
              }
              const scalar = archived.originalValue.content.value;
              return scalar.kind === 'text' || scalar.kind === 'secret'
                ? scalar.value
                : undefined;
            }),
          ).toEqual(values);
        },
      ),
      { numRuns: 100 },
    );
  });
});
