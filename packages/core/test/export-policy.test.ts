import { describe, expect, it } from 'vitest';

import {
  fieldDefinitionSchema,
  groupTemplateSchema,
  itemPayloadSchema,
  type FieldDefinition,
  type GroupTemplate,
  type ItemPayload,
} from '@kavrix/schemas';

import {
  ValidationError,
  fieldValueMayBeExported,
  projectItemForTransfer,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';

function definition(overrides: Record<string, unknown>): FieldDefinition {
  return fieldDefinitionSchema.parse({
    id: 'field.hostname',
    stableKey: 'hostname',
    label: 'Hostname',
    type: 'text',
    required: false,
    sensitive: false,
    repeatable: false,
    copyable: true,
    searchableLocally: true,
    showInPreview: true,
    copyPolicy: 'allowed',
    revealPolicy: 'never',
    reauthenticationPolicy: 'never',
    exportPolicy: 'encrypted-only',
    sortOrder: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...overrides,
  });
}

function template(fields: readonly FieldDefinition[]): GroupTemplate {
  return groupTemplateSchema.parse({
    id: 'template.database',
    name: 'Database',
    version: 1,
    fields,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

function storedValue(
  field: FieldDefinition,
  content: Record<string, unknown>,
): Record<string, unknown> {
  return {
    fieldId: field.id,
    stableKey: field.stableKey,
    value: { version: 1, state: 'present', content },
    updatedAt: timestamp,
  };
}

function textContent(value: string): Record<string, unknown> {
  return { cardinality: 'single', value: { kind: 'text', value } };
}

function item(overrides: Record<string, unknown>): ItemPayload {
  return itemPayloadSchema.parse({
    version: 1,
    id: 'item.1',
    vaultId: 'vault.1',
    groupId: 'group.1',
    templateId: 'template.database',
    templateVersion: 1,
    title: 'Primary DB',
    aliases: [],
    templateValues: [],
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
    ...overrides,
  });
}

describe('transfer export policy', () => {
  it('classifies each export policy without consulting any other field flag', () => {
    expect(fieldValueMayBeExported(definition({ exportPolicy: 'guarded' }))).toBe(true);
    expect(
      fieldValueMayBeExported(definition({ exportPolicy: 'encrypted-only' })),
    ).toBe(true);
    // A sensitive, unreadable, non-copyable field is still exportable when its
    // export policy permits it; only `never` withholds.
    expect(
      fieldValueMayBeExported(
        definition({
          exportPolicy: 'never',
          sensitive: true,
          showInPreview: false,
          reauthenticationPolicy: 'after-lock',
          copyable: false,
          copyPolicy: 'never',
        }),
      ),
    ).toBe(false);
  });

  it('carries a policy-permitted item unchanged and withholds nothing', () => {
    const hostname = definition({});
    const source = item({
      templateValues: [storedValue(hostname, textContent('db.internal.invalid'))],
    });

    const projection = projectItemForTransfer(source, template([hostname]), {
      exportedItemIds: new Set(['item.1']),
    });

    expect(projection.withheld).toEqual([]);
    expect(projection.item).toStrictEqual(source);
  });

  it('withholds an export-forbidden value and names it in the manifest', () => {
    const hostname = definition({});
    const secret = definition({
      id: 'field.master_key',
      stableKey: 'master_key',
      label: 'Master key',
      type: 'secret',
      sensitive: true,
      showInPreview: false,
      revealPolicy: 'timed',
      reauthenticationPolicy: 'after-lock',
      exportPolicy: 'never',
      sortOrder: 1,
    });
    const source = item({
      templateValues: [
        storedValue(hostname, textContent('db.internal.invalid')),
        storedValue(secret, {
          cardinality: 'single',
          value: { kind: 'secret', value: 'never-leaves-the-vault' },
        }),
      ],
    });

    const projection = projectItemForTransfer(source, template([hostname, secret]), {
      exportedItemIds: new Set(['item.1']),
    });

    expect(projection.withheld).toEqual([
      { stableKey: 'master_key', scope: 'template', reason: 'export-policy' },
    ]);
    expect(projection.item.templateValues).toHaveLength(1);
    expect(projection.item.templateValues[0]?.stableKey).toBe('hostname');
    // The withheld secret must not survive anywhere in the projected document.
    expect(JSON.stringify(projection.item)).not.toContain('never-leaves-the-vault');
  });

  it('refuses the projection when a required value would have to be withheld', () => {
    const required = definition({ required: true, exportPolicy: 'never' });
    const source = item({
      templateValues: [storedValue(required, textContent('db.internal.invalid'))],
    });

    expect(() =>
      projectItemForTransfer(source, template([required]), {
        exportedItemIds: new Set(['item.1']),
      }),
    ).toThrow(ValidationError);
  });

  it('drops copy sequences that name a withheld template field', () => {
    const hostname = definition({});
    const secret = definition({
      id: 'field.master_key',
      stableKey: 'master_key',
      label: 'Master key',
      type: 'secret',
      sensitive: true,
      showInPreview: false,
      revealPolicy: 'timed',
      reauthenticationPolicy: 'after-lock',
      exportPolicy: 'never',
      sortOrder: 1,
    });
    const source = item({
      templateValues: [
        storedValue(hostname, textContent('db.internal.invalid')),
        storedValue(secret, {
          cardinality: 'single',
          value: { kind: 'secret', value: 'sequence-secret' },
        }),
      ],
      copySequences: [
        { id: 'sequence.login', name: 'Login', fieldKeys: ['hostname', 'master_key'] },
        { id: 'sequence.host', name: 'Host only', fieldKeys: ['hostname'] },
      ],
    });

    const projection = projectItemForTransfer(source, template([hostname, secret]), {
      exportedItemIds: new Set(['item.1']),
    });

    expect(projection.item.copySequences.map((sequence) => sequence.id)).toEqual([
      'sequence.host',
    ]);
  });

  it('withholds attachment references because a transfer carries no content', () => {
    const attachment = definition({
      id: 'field.contract',
      stableKey: 'contract',
      label: 'Contract',
      type: 'attachment',
    });
    const source = item({
      itemFields: [attachment],
      itemValues: [
        storedValue(attachment, {
          cardinality: 'single',
          value: { kind: 'attachment-reference', attachmentId: 'attachment.1' },
        }),
      ],
      attachmentIds: ['attachment.1'],
    });

    const projection = projectItemForTransfer(source, template([]), {
      exportedItemIds: new Set(['item.1']),
    });

    expect(projection.withheld).toEqual([
      { stableKey: 'contract', scope: 'item', reason: 'attachment-unsupported' },
    ]);
    expect(projection.item.attachmentIds).toEqual([]);
    expect(projection.item.itemValues).toEqual([]);
    // The definition survives so the reader still sees the field exists.
    expect(projection.item.itemFields).toHaveLength(1);
  });

  it('withholds a reference to an item outside the exported set', () => {
    const reference = definition({
      id: 'field.depends_on',
      stableKey: 'depends_on',
      label: 'Depends on',
      type: 'item-reference',
    });
    const source = item({
      itemFields: [reference],
      itemValues: [
        storedValue(reference, {
          cardinality: 'single',
          value: { kind: 'item-reference', itemId: 'item.2' },
        }),
      ],
      relatedItemIds: ['item.2', 'item.3'],
    });

    const withoutTarget = projectItemForTransfer(source, template([]), {
      exportedItemIds: new Set(['item.1']),
    });
    expect(withoutTarget.withheld).toEqual([
      { stableKey: 'depends_on', scope: 'item', reason: 'unresolved-reference' },
    ]);
    expect(withoutTarget.item.relatedItemIds).toEqual([]);

    const withTarget = projectItemForTransfer(source, template([]), {
      exportedItemIds: new Set(['item.1', 'item.2']),
    });
    expect(withTarget.withheld).toEqual([]);
    expect(withTarget.item.relatedItemIds).toEqual(['item.2']);
  });

  it('rejects an item bound to a different template', () => {
    const other = groupTemplateSchema.parse({
      id: 'template.other',
      name: 'Other',
      version: 1,
      fields: [],
      createdAt: timestamp,
      updatedAt: timestamp,
    });

    expect(() =>
      projectItemForTransfer(item({}), other, { exportedItemIds: new Set(['item.1']) }),
    ).toThrow();
  });
});
