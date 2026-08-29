import {
  encryptedAttachmentRecordSchema,
  encryptedHistoryRecordSchema,
  itemPayloadSchema,
  localVaultPayloadSchema,
  structuredVaultPayloadSchema,
  vaultIdSchema,
  type ItemPayload,
  type LocalVaultPayload,
  type StructuredVaultPayload,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  DEFAULT_PROJECT_CONTEXT_ID,
  DEFAULT_SERVICE_ID,
  DEFAULT_VALUE_FIELD_KEY,
  StructuredVaultProjectionError,
  applyFlatVaultPayload,
  createEmptyStructuredVaultPayload,
  isStructuredVaultPayload,
  projectFlatVaultPayload,
  upgradeLegacyVaultPayload,
} from '../src/structured-vault-projection.js';

const vaultId = vaultIdSchema.parse('vault.projection');
const createdAt = '2026-08-10T00:00:00.000Z';
const changedAt = '2026-08-11T00:00:00.000Z';
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function flat(
  records: Record<string, { value: string; updatedAt: string }>,
): LocalVaultPayload {
  return localVaultPayloadSchema.parse({ records });
}

function defaultStructured(
  records: Record<string, { value: string; updatedAt: string }> = {},
): StructuredVaultPayload {
  return upgradeLegacyVaultPayload(flat(records), vaultId, createdAt);
}

function envelope(
  entityType: 'attachment' | 'wrapped-attachment-key' | 'history',
  entityId: string,
  itemId: string,
  groupId: string,
): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType,
      entityId,
      groupId,
      parentId: itemId,
      purpose:
        entityType === 'attachment'
          ? 'attachment-metadata'
          : entityType === 'history'
            ? 'history-event'
            : 'attachment-key',
    },
    keyVersion: 1,
  };
}

function withOwnedRecords(value: StructuredVaultPayload): StructuredVaultPayload {
  const item = value.items[0];
  if (item === undefined) throw new Error('fixture requires an item');
  const attachment = encryptedAttachmentRecordSchema.parse({
    id: 'attachment.projection',
    vaultId,
    groupId: item.groupId,
    itemId: item.id,
    schemaVersion: 1,
    wrappedAttachmentKey: envelope(
      'wrapped-attachment-key',
      'attachment.projection',
      item.id,
      item.groupId,
    ),
    encryptedManifest: envelope(
      'attachment',
      'attachment.projection',
      item.id,
      item.groupId,
    ),
    chunkCount: 1,
    recordRevision: 1,
    createdAt,
    updatedAt: createdAt,
  });
  const history = encryptedHistoryRecordSchema.parse({
    id: 'history.projection',
    vaultId,
    groupId: item.groupId,
    itemId: item.id,
    schemaVersion: 1,
    encryptedPayload: envelope('history', 'history.projection', item.id, item.groupId),
    itemRecordRevision: item.revision,
    ciphertextHash: digest,
    createdAt,
  });
  return structuredVaultPayloadSchema.parse({
    ...value,
    items: [itemPayloadSchema.parse({ ...item, attachmentIds: [attachment.id] })],
    attachments: [attachment],
    history: [history],
  });
}

function addNonDefaultEntities(value: StructuredVaultPayload): StructuredVaultPayload {
  const service = value.groups[0];
  if (service === undefined) throw new Error('fixture requires a service');
  const otherContext = {
    id: 'project.other',
    name: 'Other project',
    environment: 'staging',
    revision: 0,
    createdAt,
    updatedAt: createdAt,
  };
  const otherService = {
    ...service,
    id: 'service.other',
    projectContextId: otherContext.id,
  };
  const otherItem = itemPayloadSchema.parse({
    ...value.items[0],
    id: 'item.other',
    groupId: otherService.id,
    title: 'Other credential',
    itemFields: [],
    itemValues: [],
    attachmentIds: [],
  });
  return structuredVaultPayloadSchema.parse({
    ...value,
    projectContexts: [...value.projectContexts, otherContext],
    groups: [...value.groups, otherService],
    items: [...value.items, otherItem],
  });
}

describe('structured vault flat compatibility projection', () => {
  it('creates a validated empty hierarchy with stable default identities', () => {
    const value = createEmptyStructuredVaultPayload(vaultId, createdAt);

    expect(isStructuredVaultPayload(value)).toBe(true);
    expect(value.vaultId).toBe(vaultId);
    expect(value.projectContexts).toHaveLength(1);
    expect(value.projectContexts[0]?.id).toBe(DEFAULT_PROJECT_CONTEXT_ID);
    expect(value.groups[0]?.id).toBe(DEFAULT_SERVICE_ID);
    expect(value.items).toEqual([]);
    expect(projectFlatVaultPayload(value)).toEqual({ records: {} });
  });

  it('round-trips legacy records without splitting path-like names', () => {
    const source = flat({
      'production/database/main': { value: 'secret', updatedAt: createdAt },
      'ssh host/name': { value: 'another-secret', updatedAt: changedAt },
    });
    const upgraded = upgradeLegacyVaultPayload(source, vaultId, changedAt);

    expect(projectFlatVaultPayload(upgraded)).toEqual(source);
    expect(upgraded.items.map(({ title }) => title)).toEqual([
      'production/database/main',
      'ssh host/name',
    ]);
    expect(upgraded.items[0]?.itemFields[0]?.stableKey).toBe(DEFAULT_VALUE_FIELD_KEY);
    expect(upgraded.items[0]?.itemValues[0]?.updatedAt).toBe(createdAt);
  });

  it('preserves empty values through upgrade, projection, and overwrite', () => {
    const source = flat({
      empty: { value: '', updatedAt: createdAt },
      filled: { value: 'secret', updatedAt: createdAt },
    });
    const upgraded = upgradeLegacyVaultPayload(source, vaultId, changedAt);

    expect(projectFlatVaultPayload(upgraded)).toEqual(source);
    const next = flat({
      empty: { value: 'now-filled', updatedAt: changedAt },
      filled: { value: '', updatedAt: changedAt },
    });
    const updated = applyFlatVaultPayload(upgraded, source, next, changedAt);

    expect(projectFlatVaultPayload(updated)).toEqual(next);
  });

  it('preserves item identity and extra fields on overwrite', () => {
    const source = defaultStructured({ main: { value: 'old', updatedAt: createdAt } });
    const before = source.items[0];
    if (before === undefined) throw new Error('fixture requires an item');
    const extra = itemPayloadSchema.parse({
      ...before,
      itemFields: [
        ...before.itemFields,
        {
          id: 'field.extra',
          stableKey: 'username',
          label: 'Username',
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
          sortOrder: 1,
          createdAt,
          updatedAt: createdAt,
        },
      ],
      itemValues: [
        ...before.itemValues,
        {
          fieldId: 'field.extra',
          stableKey: 'username',
          value: {
            version: 1,
            state: 'present',
            content: {
              cardinality: 'single',
              value: { kind: 'text', value: 'alice' },
            },
          },
          updatedAt: createdAt,
        },
      ],
    });
    const structured = structuredVaultPayloadSchema.parse({
      ...source,
      items: [extra],
    });
    const next = flat({ main: { value: 'new', updatedAt: changedAt } });
    const updated = applyFlatVaultPayload(
      structured,
      flat({ main: { value: 'old', updatedAt: createdAt } }),
      next,
      changedAt,
    );
    const after = updated.items[0];
    if (after === undefined) throw new Error('fixture requires an item');

    expect(after.id).toBe(before.id);
    expect(after.itemFields).toEqual(
      before.itemFields.concat(extra.itemFields.slice(1)),
    );
    expect(after.itemValues[1]).toEqual(extra.itemValues[1]);
    expect(projectFlatVaultPayload(updated)).toEqual(next);
  });

  it('preserves item identity on a one-to-one exact-content rename', () => {
    const source = defaultStructured({ old: { value: 'same', updatedAt: createdAt } });
    const before = source.items[0];
    if (before === undefined) throw new Error('fixture requires an item');
    const next = flat({ renamed: { value: 'same', updatedAt: createdAt } });
    const updated = applyFlatVaultPayload(
      source,
      flat({ old: { value: 'same', updatedAt: createdAt } }),
      next,
      changedAt,
    );

    expect(updated.items[0]?.id).toBe(before.id);
    expect(updated.items[0]?.title).toBe('renamed');
    expect(projectFlatVaultPayload(updated)).toEqual(next);
  });

  it('removes the deleted item and only its owned attachment/history records', () => {
    const source = withOwnedRecords(
      defaultStructured({ main: { value: 'secret', updatedAt: createdAt } }),
    );
    const updated = applyFlatVaultPayload(
      source,
      projectFlatVaultPayload(source),
      { records: {} },
      changedAt,
    );

    expect(updated.items).toEqual([]);
    expect(updated.attachments).toEqual([]);
    expect(updated.history).toEqual([]);
    expect(updated.projectContexts).toEqual(source.projectContexts);
    expect(updated.groups).toEqual(source.groups);
  });

  it('keeps non-default contexts, services, and items out of the flat view and unchanged', () => {
    const source = addNonDefaultEntities(
      defaultStructured({ main: { value: 'secret', updatedAt: createdAt } }),
    );
    const otherContext = source.projectContexts[1];
    const otherService = source.groups[1];
    const otherItem = source.items[1];
    if (
      otherContext === undefined ||
      otherService === undefined ||
      otherItem === undefined
    ) {
      throw new Error('fixture requires non-default entities');
    }
    const next = flat({ main: { value: 'changed', updatedAt: changedAt } });
    const updated = applyFlatVaultPayload(
      source,
      projectFlatVaultPayload(source),
      next,
      changedAt,
    );

    expect(projectFlatVaultPayload(updated)).toEqual(next);
    expect(updated.projectContexts.find(({ id }) => id === otherContext.id)).toEqual(
      otherContext,
    );
    expect(updated.groups.find(({ id }) => id === otherService.id)).toEqual(
      otherService,
    );
    expect(updated.items.find(({ id }) => id === otherItem.id)).toEqual(otherItem);
  });

  it('refuses reserved default context and service identity collisions', () => {
    const source = createEmptyStructuredVaultPayload(vaultId, createdAt);
    const context = source.projectContexts[0];
    const service = source.groups[0];
    if (context === undefined || service === undefined) {
      throw new Error('fixture requires default identities');
    }

    const renamedContext = structuredVaultPayloadSchema.parse({
      ...source,
      projectContexts: [{ ...context, name: 'User project' }],
    });
    expect(() => projectFlatVaultPayload(renamedContext)).toThrow(
      StructuredVaultProjectionError,
    );

    const changedEnvironment = structuredVaultPayloadSchema.parse({
      ...source,
      projectContexts: [{ ...context, environment: 'production' }],
    });
    expect(() => projectFlatVaultPayload(changedEnvironment)).toThrow(
      StructuredVaultProjectionError,
    );

    const renamedService = structuredVaultPayloadSchema.parse({
      ...source,
      groups: [{ ...service, name: 'User service' }],
    });
    expect(() => projectFlatVaultPayload(renamedService)).toThrow(
      StructuredVaultProjectionError,
    );

    const changedTemplate = structuredVaultPayloadSchema.parse({
      ...source,
      groups: [
        {
          ...service,
          template: { ...service.template, name: 'User template' },
        },
      ],
    });
    expect(() => projectFlatVaultPayload(changedTemplate)).toThrow(
      StructuredVaultProjectionError,
    );
  });

  it('rejects malformed or missing canonical values and stale flat snapshots', () => {
    const source = defaultStructured({
      main: { value: 'secret', updatedAt: createdAt },
    });
    const item = source.items[0];
    if (item === undefined) throw new Error('fixture requires an item');
    const missing = structuredVaultPayloadSchema.parse({
      ...source,
      items: [itemPayloadSchema.parse({ ...item, itemFields: [], itemValues: [] })],
    });

    expect(() => projectFlatVaultPayload(missing)).toThrow(
      StructuredVaultProjectionError,
    );
    expect(() =>
      applyFlatVaultPayload(
        source,
        { records: {} },
        projectFlatVaultPayload(source),
        changedAt,
      ),
    ).toThrow(StructuredVaultProjectionError);
    expect(isStructuredVaultPayload({ ...source, version: 2 })).toBe(false);
  });

  it('refuses ambiguous delete-plus-create transitions', () => {
    const source = defaultStructured({ old: { value: 'old', updatedAt: createdAt } });
    const current = flat({ old: { value: 'old', updatedAt: createdAt } });
    const next = flat({ added: { value: 'new', updatedAt: changedAt } });

    expect(() => applyFlatVaultPayload(source, current, next, changedAt)).toThrow(
      StructuredVaultProjectionError,
    );
  });

  it('returns legacy payloads unchanged unless upgrade is explicitly requested', () => {
    const source = flat({ legacy: { value: 'secret', updatedAt: createdAt } });
    const projected = projectFlatVaultPayload(source);

    expect(projected).toEqual(source);
    expect(projected).not.toBe(source);
    expect(isStructuredVaultPayload(source)).toBe(false);
  });
});
