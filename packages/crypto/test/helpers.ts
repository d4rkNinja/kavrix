import {
  associatedDataSchema,
  groupIdSchema,
  itemIdSchema,
  keySlotIdSchema,
  vaultIdSchema,
  type AssociatedData,
} from '@kavrix/schemas';

import { decodeBase64Url, encodeBase64Url } from '../src/index.js';

export const vaultId = vaultIdSchema.parse('vault-1');
export const otherVaultId = vaultIdSchema.parse('vault-2');
export const groupId = groupIdSchema.parse('group-1');
export const otherGroupId = groupIdSchema.parse('group-2');
export const itemId = itemIdSchema.parse('item-1');
export const otherItemId = itemIdSchema.parse('item-2');
export const slotId = keySlotIdSchema.parse('slot-1');
export const otherSlotId = keySlotIdSchema.parse('slot-2');

export function itemPayloadAad(
  overrides: Readonly<Record<string, unknown>> = {},
): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId,
    entityType: 'item',
    entityId: itemId,
    groupId,
    purpose: 'item-payload',
    ...overrides,
  });
}

export function itemKeyAad(
  overrides: Readonly<Record<string, unknown>> = {},
): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId,
    entityType: 'wrapped-item-key',
    entityId: itemId,
    groupId,
    purpose: 'item-key',
    ...overrides,
  });
}

export function groupKeyAad(
  overrides: Readonly<Record<string, unknown>> = {},
): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId,
    entityType: 'wrapped-group-key',
    entityId: groupId,
    purpose: 'group-key',
    ...overrides,
  });
}

export function attachmentChunkAad(
  overrides: Readonly<Record<string, unknown>> = {},
): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId,
    entityType: 'attachment-chunk',
    entityId: 'attachment-1',
    groupId,
    parentId: itemId,
    purpose: 'attachment-chunk',
    ...overrides,
  });
}

export function mutateBase64Url(value: string): string {
  const bytes = decodeBase64Url(value);
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  return encodeBase64Url(bytes);
}
