import { describe, expect, expectTypeOf, it } from 'vitest';

import {
  changeRecordSchema,
  deviceRecordSchema,
  fieldDefinitionSchema,
  groupTemplateSchema,
  itemPayloadSchema,
  noteCollectionSchema,
  noteSchema,
  templateMigrationPlanSchema,
  templateMigrationStepSchema,
  tombstoneRecordSchema,
  type AttachmentId,
  type ChangeRecord,
  type ChangeSequence,
  type DeviceRecord,
  type GroupId,
  type GroupTemplate,
  type ItemId,
  type ItemPayload,
  type KeyVersion,
  type RecordRevision,
  type SchemaVersion,
  type TemplateVersion,
  type TombstoneRecord,
  type TokenVersion,
  type VaultId,
  type VaultRecord,
  type VaultRevision,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function textValue(value: string): object {
  return {
    version: 1,
    state: 'present',
    content: { cardinality: 'single', value: { kind: 'text', value } },
  };
}

function numberValue(value: number): object {
  return {
    version: 1,
    state: 'present',
    content: { cardinality: 'single', value: { kind: 'number', value } },
  };
}

function field(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'field.name',
    stableKey: 'name',
    label: 'Name',
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
  };
}

function template(version: number, fields: readonly unknown[] = []): object {
  return {
    id: 'template.1',
    name: 'Template',
    version,
    fields,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function item(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    id: 'item.1',
    vaultId: 'vault.1',
    groupId: 'group.1',
    templateId: 'template.1',
    title: 'Item',
    aliases: [],
    templateVersion: 1,
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
  };
}

function note(id: string): Record<string, unknown> {
  return {
    id,
    title: 'Note',
    content: 'content',
    isSensitive: true,
    isPinned: false,
    tags: [],
    sortOrder: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

describe('template and item aggregates', () => {
  it('identifies each independent template field collision', () => {
    const original = field();
    const collisions = [
      field({ stableKey: 'second', sortOrder: 1 }),
      field({ id: 'field.second', sortOrder: 1 }),
      field({ id: 'field.second', stableKey: 'second' }),
    ];
    for (const duplicate of collisions) {
      expect(
        groupTemplateSchema.safeParse(template(1, [original, duplicate])).success,
      ).toBe(false);
    }
  });

  it('rejects active value collisions and item definitions shadowing template values', () => {
    const value = {
      fieldId: 'field.template',
      stableKey: 'template_key',
      value: textValue('value'),
      updatedAt: timestamp,
    };
    const duplicateValues = item({
      templateValues: [value],
      itemValues: [{ ...value }],
    });
    const shadowedDefinition = item({
      templateValues: [value],
      itemFields: [field({ id: value.fieldId, stableKey: 'custom' })],
    });
    expect(itemPayloadSchema.safeParse(duplicateValues).success).toBe(false);
    expect(itemPayloadSchema.safeParse(shadowedDefinition).success).toBe(false);
  });

  it('requires unique, type-compatible item-only values and required values', () => {
    const definition = field({
      id: 'field.port',
      stableKey: 'port',
      label: 'Port',
      type: 'port',
      required: true,
    });
    const value = {
      fieldId: 'field.port',
      stableKey: 'port',
      value: numberValue(443),
      updatedAt: timestamp,
    };
    expect(
      itemPayloadSchema.safeParse(
        item({ itemFields: [definition], itemValues: [value] }),
      ).success,
    ).toBe(true);
    for (const itemValues of [
      [],
      [{ ...value, stableKey: 'wrong' }],
      [{ ...value, value: numberValue(70_000) }],
      [value, value],
    ]) {
      expect(
        itemPayloadSchema.safeParse(item({ itemFields: [definition], itemValues }))
          .success,
      ).toBe(false);
    }
  });

  it('keeps archived definitions unique and disjoint from active values', () => {
    const definition = field({ id: 'field.old', stableKey: 'old' });
    const archived = {
      definition,
      value: {
        version: 1,
        state: 'orphaned',
        originalValue: {
          version: 1,
          state: 'present',
          content: {
            cardinality: 'single',
            value: { kind: 'text', value: 'old value' },
          },
        },
      },
      sourceTemplateId: 'template.1',
      sourceTemplateVersion: 1,
      archivedAt: timestamp,
      reason: 'template-field-removed',
    };
    expect(
      itemPayloadSchema.safeParse(item({ archivedFieldValues: [archived, archived] }))
        .success,
    ).toBe(false);
    expect(
      itemPayloadSchema.safeParse(
        item({
          templateValues: [
            {
              fieldId: 'field.old',
              stableKey: 'old',
              value: textValue('active'),
              updatedAt: timestamp,
            },
          ],
          archivedFieldValues: [archived],
        }),
      ).success,
    ).toBe(false);
    expect(
      itemPayloadSchema.safeParse(
        item({
          templateValues: [
            {
              fieldId: 'field.replacement',
              stableKey: 'old',
              value: textValue('replacement'),
              updatedAt: timestamp,
            },
          ],
          archivedFieldValues: [archived],
        }),
      ).success,
    ).toBe(false);
    expect(
      itemPayloadSchema.safeParse(
        item({
          archivedFieldValues: [
            archived,
            {
              ...archived,
              definition: field({ id: 'field.other', stableKey: 'old' }),
            },
          ],
        }),
      ).success,
    ).toBe(false);
  });
});

describe('notes and migration persistence schemas', () => {
  it('rejects duplicate note identities while preserving distinct notes', () => {
    const first = noteSchema.parse(note('note.1'));
    expect(noteCollectionSchema.safeParse([first]).success).toBe(true);
    expect(noteCollectionSchema.safeParse([first, first]).success).toBe(false);
  });

  it('accepts every persisted migration step variant', () => {
    const fromField = fieldDefinitionSchema.parse(field());
    const toField = fieldDefinitionSchema.parse(field({ label: 'Renamed' }));
    const base = { affectedItemCount: 1, requiresConfirmation: false };
    const steps = [
      { ...base, kind: 'add-field', field: fromField },
      { ...base, kind: 'restore-field', field: fromField },
      {
        ...base,
        kind: 'rename-label',
        fieldId: fromField.id,
        fromLabel: 'Name',
        toLabel: 'Renamed',
      },
      {
        ...base,
        kind: 'reorder-field',
        fieldId: fromField.id,
        fromSortOrder: 0,
        toSortOrder: 1,
      },
      {
        ...base,
        kind: 'change-required',
        fieldId: fromField.id,
        fromRequired: false,
        toRequired: true,
        missingValueCount: 1,
      },
      {
        ...base,
        kind: 'update-field-policy',
        fieldId: fromField.id,
        fromField,
        toField,
      },
      {
        ...base,
        kind: 'convert-type',
        fieldId: fromField.id,
        fromField,
        toField,
        fromType: 'text',
        toType: 'text',
        strategy: 'identity',
        incompatibleValueCount: 0,
      },
      { ...base, kind: 'archive-field', field: fromField },
    ];
    expect(
      steps.every((step) => templateMigrationStepSchema.safeParse(step).success),
    ).toBe(true);
  });

  it('rejects inconsistent versions, identities, snapshots, and checkpoints', () => {
    const base = {
      id: 'migration.1',
      fromVersion: 1,
      toVersion: 2,
      sourceTemplate: template(1),
      targetTemplate: template(2),
      itemSnapshots: [{ itemId: 'item.1', revision: 1 }],
      steps: [],
      status: 'pending',
      nextItemIndex: 0,
      totalItems: 1,
      auditEventId: 'audit.1',
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    expect(templateMigrationPlanSchema.safeParse(base).success).toBe(true);
    const invalid = [
      { ...base, toVersion: 1 },
      { ...base, targetTemplate: template(3) },
      { ...base, sourceTemplate: template(2) },
      { ...base, targetTemplate: { ...template(2), id: 'template.other' } },
      { ...base, totalItems: 2 },
      { ...base, itemSnapshots: [base.itemSnapshots[0], base.itemSnapshots[0]] },
      { ...base, nextItemIndex: 2 },
      { ...base, status: 'completed', nextItemIndex: 0 },
    ];
    for (const candidate of invalid) {
      expect(templateMigrationPlanSchema.safeParse(candidate).success).toBe(false);
    }
    expect(
      templateMigrationPlanSchema.safeParse({
        ...base,
        status: 'completed',
        nextItemIndex: 1,
      }).success,
    ).toBe(true);
  });
});

describe('sync metadata invariants', () => {
  it('keeps semantic versions and revision types distinct', () => {
    expectTypeOf<SchemaVersion>().not.toEqualTypeOf<KeyVersion>();
    expectTypeOf<TemplateVersion>().not.toEqualTypeOf<RecordRevision>();
    expectTypeOf<VaultRevision>().not.toEqualTypeOf<ChangeSequence>();
    expectTypeOf<VaultRecord['schemaVersion']>().toEqualTypeOf<SchemaVersion>();
    expectTypeOf<VaultRecord['revision']>().toEqualTypeOf<VaultRevision>();
    expectTypeOf<GroupTemplate['version']>().toEqualTypeOf<TemplateVersion>();
    expectTypeOf<ItemPayload['revision']>().toEqualTypeOf<RecordRevision>();
    expectTypeOf<DeviceRecord['tokenVersion']>().toEqualTypeOf<TokenVersion>();
  });
  it('requires hashes for every non-purge change', () => {
    const base = {
      id: 'change.1',
      vaultId: 'vault.1',
      serverSequence: 1,
      entityType: 'item',
      entityId: 'item.1',
      recordRevision: 1,
      createdAt: timestamp,
    };
    expect(changeRecordSchema.safeParse({ ...base, operation: 'upsert' }).success).toBe(
      false,
    );
    expect(
      changeRecordSchema.safeParse({
        ...base,
        operation: 'upsert',
        ciphertextHash: digest,
      }).success,
    ).toBe(true);
    expect(
      changeRecordSchema.safeParse({ ...base, operation: 'tombstone' }).success,
    ).toBe(false);
    expect(
      changeRecordSchema.safeParse({
        ...base,
        operation: 'tombstone',
        ciphertextHash: digest,
      }).success,
    ).toBe(true);
    expect(changeRecordSchema.safeParse({ ...base, operation: 'purge' }).success).toBe(
      true,
    );
  });

  it('pairs each sync discriminator with its branded ID and binds vault identity', () => {
    expectTypeOf<
      Extract<ChangeRecord, { entityType: 'vault' }>['entityId']
    >().toEqualTypeOf<VaultId>();
    expectTypeOf<
      Extract<ChangeRecord, { entityType: 'group' }>['entityId']
    >().toEqualTypeOf<GroupId>();
    expectTypeOf<
      Extract<ChangeRecord, { entityType: 'item' }>['entityId']
    >().toEqualTypeOf<ItemId>();
    expectTypeOf<
      Extract<ChangeRecord, { entityType: 'attachment' }>['entityId']
    >().toEqualTypeOf<AttachmentId>();
    expectTypeOf<
      Extract<TombstoneRecord, { entityType: 'item' }>['entityId']
    >().toEqualTypeOf<ItemId>();
    expectTypeOf<ChangeRecord['serverSequence']>().toEqualTypeOf<ChangeSequence>();
    expectTypeOf<ChangeRecord['recordRevision']>().toEqualTypeOf<RecordRevision>();

    const commonChange = {
      id: 'change.vault',
      vaultId: 'vault.1',
      serverSequence: 1,
      recordRevision: 0,
      operation: 'tombstone',
      ciphertextHash: digest,
      createdAt: timestamp,
    };
    expect(
      changeRecordSchema.safeParse({
        ...commonChange,
        entityType: 'vault',
        entityId: 'vault.1',
      }).success,
    ).toBe(true);
    expect(
      changeRecordSchema.safeParse({
        ...commonChange,
        entityType: 'vault',
        entityId: 'vault.other',
      }).success,
    ).toBe(false);
    expect(
      changeRecordSchema.safeParse({
        ...commonChange,
        entityType: 'attachment-chunk',
        entityId: 'attachment.1',
        chunkIndex: 0,
      }).success,
    ).toBe(false);
    expect(
      changeRecordSchema.safeParse({
        ...commonChange,
        entityType: 'history',
        entityId: 'history.1',
      }).success,
    ).toBe(false);

    const commonTombstone = {
      vaultId: 'vault.1',
      state: 'deleted',
      tombstoneRevision: 3,
      lastRecordRevision: 2,
      lastCiphertextHash: digest,
      deletedAt: timestamp,
    };
    expect(
      tombstoneRecordSchema.safeParse({
        ...commonTombstone,
        entityType: 'attachment',
        entityId: 'attachment.1',
      }).success,
    ).toBe(true);
    expect(
      tombstoneRecordSchema.safeParse({
        ...commonTombstone,
        entityType: 'vault',
        entityId: 'item.1',
      }).success,
    ).toBe(false);
    for (const tombstoneRevision of [2, 1]) {
      expect(
        tombstoneRecordSchema.safeParse({
          ...commonTombstone,
          tombstoneRevision,
          entityType: 'item',
          entityId: 'item.1',
        }).success,
      ).toBe(false);
    }
    expect(
      tombstoneRecordSchema.safeParse({
        ...commonTombstone,
        entityType: 'item',
        entityId: 'item.1',
        state: 'restored',
      }).success,
    ).toBe(false);
    expect(
      tombstoneRecordSchema.safeParse({
        ...commonTombstone,
        entityType: 'item',
        entityId: 'item.1',
        state: 'restored',
        restoredAt: timestamp,
      }).success,
    ).toBe(true);
    expect(
      tombstoneRecordSchema.safeParse({
        ...commonTombstone,
        entityType: 'item',
        entityId: 'item.1',
        state: 'restored',
        restoredAt: timestamp,
        purgeAfter: timestamp,
      }).success,
    ).toBe(false);
  });

  it('binds optional encrypted device labels to device, vault, and schema', () => {
    const envelope = {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      ciphertext: 'AQID',
      authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId: 'vault.1',
        entityType: 'device-label',
        entityId: 'device.1',
        purpose: 'device-label',
      },
      keyVersion: 1,
    };
    const base = {
      id: 'device.1',
      vaultId: 'vault.1',
      schemaVersion: 1,
      tokenHash: digest,
      tokenVersion: 1,
      scopes: ['sync:read'],
      createdAt: timestamp,
    };
    expect(deviceRecordSchema.safeParse(base).success).toBe(true);
    expect(
      deviceRecordSchema.safeParse({ ...base, encryptedLabel: envelope }).success,
    ).toBe(true);
    for (const changed of [
      { vaultId: 'vault.other' },
      { schemaVersion: 2 },
      { entityType: 'audit-event', purpose: 'audit-event' },
      { entityId: 'device.other' },
    ]) {
      expect(
        deviceRecordSchema.safeParse({
          ...base,
          encryptedLabel: { ...envelope, aad: { ...envelope.aad, ...changed } },
        }).success,
      ).toBe(false);
    }
  });
});
