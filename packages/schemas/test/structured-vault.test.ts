import { describe, expect, it } from 'vitest';

import {
  databaseVaultPayloadSchema,
  encryptedAttachmentRecordSchema,
  encryptedHistoryRecordSchema,
  structuredGroupPayloadSchema,
  structuredVaultPayloadSchema,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function envelope(
  entityType: 'attachment' | 'wrapped-attachment-key' | 'history',
  entityId: string,
  vaultId = 'vault.1',
  groupId = 'group.1',
  parentId = 'item.1',
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
      parentId,
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

function context(id = 'context.1', name = 'Project'): Record<string, unknown> {
  return {
    id,
    name,
    environment: 'production',
    revision: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function group(
  id = 'group.1',
  projectContextId = 'context.1',
  vaultId = 'vault.1',
  name = 'Database',
): Record<string, unknown> {
  return {
    id,
    vaultId,
    projectContextId,
    name,
    aliases: [],
    tags: [],
    notes: [],
    template: {
      id: 'template.database',
      name: 'Database',
      version: 1,
      fields: [],
      createdAt: timestamp,
      updatedAt: timestamp,
    },
    sortOrder: 0,
    revision: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function item(
  id = 'item.1',
  groupId = 'group.1',
  vaultId = 'vault.1',
  attachmentIds: string[] = [],
  title = 'Primary',
  deletedAt?: string,
): Record<string, unknown> {
  return {
    version: 1,
    id,
    vaultId,
    groupId,
    templateId: 'template.database',
    title,
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
    attachmentIds,
    copySequences: [],
    revision: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
    ...(deletedAt === undefined ? {} : { deletedAt }),
  };
}

function attachment(
  id = 'attachment.1',
  vaultId = 'vault.1',
  groupId = 'group.1',
  itemId = 'item.1',
): Record<string, unknown> {
  return {
    id,
    vaultId,
    groupId,
    itemId,
    schemaVersion: 1,
    wrappedAttachmentKey: envelope(
      'wrapped-attachment-key',
      id,
      vaultId,
      groupId,
      itemId,
    ),
    encryptedManifest: envelope('attachment', id, vaultId, groupId, itemId),
    chunkCount: 1,
    recordRevision: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function history(
  id = 'history.1',
  vaultId = 'vault.1',
  groupId = 'group.1',
  itemId = 'item.1',
): Record<string, unknown> {
  return {
    id,
    vaultId,
    groupId,
    itemId,
    schemaVersion: 1,
    encryptedPayload: envelope('history', id, vaultId, groupId, itemId),
    itemRecordRevision: 1,
    ciphertextHash: digest,
    createdAt: timestamp,
  };
}

function validPayload(
  overrides: Partial<{
    projectContexts: unknown[];
    groups: unknown[];
    items: unknown[];
    attachments: unknown[];
    history: unknown[];
  }> = {},
): Record<string, unknown> {
  return {
    version: 1,
    vaultId: 'vault.1',
    projectContexts: [context()],
    groups: [group()],
    items: [item()],
    attachments: [],
    history: [],
    ...overrides,
  };
}

describe('structured database-vault payloads', () => {
  it('accepts the valid hierarchy and legacy flat payload through the database union', () => {
    expect(structuredVaultPayloadSchema.safeParse(validPayload()).success).toBe(true);
    expect(
      databaseVaultPayloadSchema.safeParse({
        records: { 'credential.1': { value: 'secret', updatedAt: timestamp } },
      }).success,
    ).toBe(true);
  });

  it('reuses strict canonical group and encrypted record contracts', () => {
    expect(structuredGroupPayloadSchema.safeParse(group()).success).toBe(true);
    expect(encryptedAttachmentRecordSchema.safeParse(attachment()).success).toBe(true);
    expect(encryptedHistoryRecordSchema.safeParse(history()).success).toBe(true);
    expect(
      structuredVaultPayloadSchema.safeParse({ ...validPayload(), version: 2 }).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse({ ...validPayload(), unexpected: true })
        .success,
    ).toBe(false);
  });

  it('rejects duplicate identities and duplicate names in their hierarchy scopes', () => {
    expect(
      structuredVaultPayloadSchema.safeParse(
        validPayload({ projectContexts: [context(), context('context.2', 'Project')] }),
      ).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse(
        validPayload({
          groups: [group(), group('group.2', 'context.1', 'vault.1', 'Database')],
        }),
      ).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse(
        validPayload({ items: [item(), item('item.2')] }),
      ).success,
    ).toBe(false);
  });

  it('rejects dangling, cross-vault, and mismatched parent references', () => {
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...validPayload(),
        vaultId: 'vault.other',
      }).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse(
        validPayload({ groups: [group('group.1', 'context.missing')] }),
      ).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse(
        validPayload({ items: [item('item.1', 'group.missing')] }),
      ).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse(
        validPayload({ items: [item('item.1', 'group.1', 'vault.other')] }),
      ).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse(
        validPayload({
          items: [{ ...item(), templateId: 'template.other' }],
        }),
      ).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse(
        validPayload({
          items: [{ ...item(), relatedItemIds: ['item.missing'] }],
        }),
      ).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...validPayload({
          items: [item('item.1', 'group.1', 'vault.1', ['attachment.1'])],
        }),
        attachments: [attachment('attachment.1', 'vault.1', 'group.other')],
      }).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...validPayload(),
        history: [history('history.1', 'vault.1', 'group.other')],
      }).success,
    ).toBe(false);
  });

  it('requires item attachment lists and records to agree exactly', () => {
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...validPayload({
          items: [item('item.1', 'group.1', 'vault.1', ['attachment.1'])],
        }),
        attachments: [],
      }).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...validPayload(),
        attachments: [attachment()],
      }).success,
    ).toBe(false);
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...validPayload({
          items: [item('item.1', 'group.1', 'vault.1', ['attachment.1'])],
        }),
        attachments: [attachment()],
      }).success,
    ).toBe(true);
  });

  it('allows archived item titles to be reused while active titles remain unique', () => {
    expect(
      structuredVaultPayloadSchema.safeParse({
        ...validPayload({
          items: [
            item(),
            item('item.2', 'group.1', 'vault.1', [], 'Primary', timestamp),
          ],
        }),
      }).success,
    ).toBe(true);
  });
});
