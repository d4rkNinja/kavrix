import { createHash } from 'node:crypto';

import type { VaultReadSourcePort } from '../src/index.js';
import {
  createPortableKeySlot,
  encryptPayload,
  generateGroupKey,
  generateItemKey,
  generatePortableKey,
  generateVaultRootKey,
  wrapGroupKey,
  wrapItemKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  associatedDataSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  groupIdSchema,
  groupPayloadSchema,
  itemIdSchema,
  itemPayloadSchema,
  keySlotIdSchema,
  templateIdSchema,
  timestampSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type GroupPayload,
  type ItemPayload,
  type GroupTemplate,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';

const timestamp = timestampSchema.parse('2026-08-10T00:00:00.000Z');

export type EncryptedFixture = Readonly<{
  vaultId: VaultId;
  rootKey: VaultRootKey;
  vault: VaultRecord;
  groups: readonly EncryptedGroupRecord[];
  items: ReadonlyMap<string, readonly EncryptedItemRecord[]>;
  groupPayloads: readonly GroupPayload[];
  itemPayloads: readonly ItemPayload[];
}>;

export class MemoryReadSource implements VaultReadSourcePort {
  vault: VaultRecord | null;
  groups: readonly EncryptedGroupRecord[];
  items: ReadonlyMap<string, readonly EncryptedItemRecord[]>;
  readonly calls = {
    getVault: 0,
    getGroup: 0,
    listGroups: 0,
    getItem: 0,
    listItems: 0,
  };

  constructor(fixture: EncryptedFixture) {
    this.vault = fixture.vault;
    this.groups = fixture.groups;
    this.items = fixture.items;
  }

  getVault(vaultId: VaultId): Promise<VaultRecord | null> {
    this.calls.getVault += 1;
    return Promise.resolve(this.vault?.id === vaultId ? this.vault : null);
  }

  getGroup(
    vaultId: VaultId,
    groupId: ReturnType<typeof groupIdSchema.parse>,
  ): Promise<EncryptedGroupRecord | null> {
    this.calls.getGroup += 1;
    return Promise.resolve(
      this.groups.find(
        (candidate) => candidate.vaultId === vaultId && candidate.id === groupId,
      ) ?? null,
    );
  }

  async *listGroups(vaultId: VaultId): AsyncIterable<EncryptedGroupRecord> {
    this.calls.listGroups += 1;
    for (const group of this.groups) {
      if (group.vaultId === vaultId) yield await Promise.resolve(group);
    }
  }

  getItem(
    vaultId: VaultId,
    itemId: ReturnType<typeof itemIdSchema.parse>,
  ): Promise<EncryptedItemRecord | null> {
    this.calls.getItem += 1;
    for (const candidates of this.items.values()) {
      const item = candidates.find(
        (candidate) => candidate.vaultId === vaultId && candidate.id === itemId,
      );
      if (item !== undefined) return Promise.resolve(item);
    }
    return Promise.resolve(null);
  }

  async *listItems(
    vaultId: VaultId,
    groupId: ReturnType<typeof groupIdSchema.parse>,
  ): AsyncIterable<EncryptedItemRecord> {
    this.calls.listItems += 1;
    for (const item of this.items.get(groupId) ?? []) {
      if (item.vaultId === vaultId) yield await Promise.resolve(item);
    }
  }
}

export async function encryptedFixture(
  options: {
    readonly groupNames?: readonly string[];
    readonly itemTitles?: readonly string[];
    readonly plaintextCanary?: string;
    readonly keyVersion?: number;
    readonly recordKeyVersion?: number;
    readonly itemTemplateId?: string;
    readonly nonCanonicalItem?: boolean;
    readonly nonCanonicalGroup?: boolean;
    readonly portableKey?: Uint8Array;
    readonly transformItem?: (
      item: ItemPayload,
      template: GroupTemplate,
    ) => ItemPayload;
    readonly transformGroup?: (group: GroupPayload) => GroupPayload;
  } = {},
): Promise<EncryptedFixture> {
  const vaultId = vaultIdSchema.parse('vault.client');
  const rootKey = generateVaultRootKey();
  const keyVersion = options.keyVersion ?? 1;
  const recordKeyVersion = options.recordKeyVersion ?? keyVersion;
  const schemaVersion = 1;
  const groupNames = options.groupNames ?? ['Production'];
  const itemTitles = options.itemTitles ?? ['Primary'];
  const groups: EncryptedGroupRecord[] = [];
  const itemRecords = new Map<string, EncryptedItemRecord[]>();
  const groupPayloads: GroupPayload[] = [];
  const itemPayloads: ItemPayload[] = [];

  for (const [groupIndex, groupName] of groupNames.entries()) {
    const groupId = groupIdSchema.parse(`group.${String(groupIndex + 1)}`);
    const templateId = templateIdSchema.parse(`template.${String(groupIndex + 1)}`);
    const baseGroupPayload = groupPayloadSchema.parse({
      id: groupId,
      vaultId,
      name: groupName,
      slug: `group-${String(groupIndex + 1)}`,
      aliases: [`g${String(groupIndex + 1)}`],
      tags: [],
      notes: [],
      template: {
        id: templateId,
        name: 'Custom',
        version: 1,
        fields: [],
        createdAt: timestamp,
        updatedAt: timestamp,
      },
      sortOrder: groupIndex,
      revision: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    const groupPayload = groupPayloadSchema.parse(
      options.transformGroup?.(baseGroupPayload) ?? baseGroupPayload,
    );
    const groupKey = generateGroupKey();
    const groupKeyContext = associatedDataSchema.parse({
      version: 1,
      schemaVersion,
      keyVersion: recordKeyVersion,
      vaultId,
      entityType: 'wrapped-group-key',
      entityId: groupId,
      purpose: 'group-key',
    });
    const groupPayloadContext = associatedDataSchema.parse({
      version: 1,
      schemaVersion,
      keyVersion: recordKeyVersion,
      vaultId,
      entityType: 'group',
      entityId: groupId,
      purpose: 'group-payload',
    });
    const groupRecord = encryptedGroupRecordSchema.parse({
      id: groupId,
      vaultId,
      schemaVersion,
      wrappedGroupKey: await wrapGroupKey(groupKey, rootKey, groupKeyContext),
      encryptedPayload: await encryptPayload(
        Buffer.from(
          JSON.stringify(groupPayload).concat(
            options.nonCanonicalGroup === true ? ' ' : '',
          ),
          'utf8',
        ),
        groupKey,
        groupPayloadContext,
      ),
      templateVersion: groupPayload.template.version,
      recordRevision: groupPayload.revision,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    groups.push(groupRecord);
    groupPayloads.push(groupPayload);

    const encryptedItems: EncryptedItemRecord[] = [];
    for (const [itemIndex, itemTitle] of itemTitles.entries()) {
      const itemId = itemIdSchema.parse(
        `item.${String(groupIndex + 1)}.${String(itemIndex + 1)}`,
      );
      const baseItemPayload = itemPayloadSchema.parse({
        version: 1,
        id: itemId,
        vaultId,
        groupId,
        templateId: templateIdSchema.parse(options.itemTemplateId ?? templateId),
        title: itemTitle,
        slug: `item-${String(itemIndex + 1)}`,
        aliases: [`i${String(itemIndex + 1)}`],
        ...(options.plaintextCanary === undefined
          ? {}
          : { subtitle: options.plaintextCanary }),
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
      });
      const itemPayload = itemPayloadSchema.parse(
        options.transformItem?.(baseItemPayload, groupPayload.template) ??
          baseItemPayload,
      );
      const itemKey = generateItemKey();
      const itemKeyContext = associatedDataSchema.parse({
        version: 1,
        schemaVersion,
        keyVersion: recordKeyVersion,
        vaultId,
        entityType: 'wrapped-item-key',
        entityId: itemId,
        groupId,
        purpose: 'item-key',
      });
      const itemPayloadContext = associatedDataSchema.parse({
        version: 1,
        schemaVersion,
        keyVersion: recordKeyVersion,
        vaultId,
        entityType: 'item',
        entityId: itemId,
        groupId,
        purpose: 'item-payload',
      });
      const serialized = JSON.stringify(itemPayload).concat(
        options.nonCanonicalItem === true ? ' ' : '',
      );
      const encryptedPayload = await encryptPayload(
        Buffer.from(serialized, 'utf8'),
        itemKey,
        itemPayloadContext,
      );
      encryptedItems.push(
        encryptedItemRecordSchema.parse({
          id: itemId,
          vaultId,
          groupId,
          schemaVersion,
          wrappedItemKey: await wrapItemKey(itemKey, groupKey, itemKeyContext),
          encryptedPayload,
          recordRevision: itemPayload.revision,
          ciphertextHash: createHash('sha256')
            .update(Buffer.from(encryptedPayload.ciphertext, 'base64url'))
            .digest('base64url'),
          createdAt: timestamp,
          updatedAt: timestamp,
        }),
      );
      itemPayloads.push(itemPayload);
    }
    itemRecords.set(groupId, encryptedItems);
    groupKey.fill(0);
  }

  const portableKey =
    options.portableKey === undefined
      ? generatePortableKey()
      : Uint8Array.from(options.portableKey);
  const slotId = keySlotIdSchema.parse('slot.client');
  const slot = await createPortableKeySlot(
    {
      vaultId,
      slotId,
      schemaVersion,
      keyVersion,
      createdAt: timestamp,
    },
    portableKey,
    rootKey,
  );
  portableKey.fill(0);
  const preferencesContext = associatedDataSchema.parse({
    version: 1,
    schemaVersion,
    keyVersion,
    vaultId,
    entityType: 'vault-preferences',
    entityId: vaultId,
    purpose: 'vault-preferences',
  });
  const vault = vaultRecordSchema.parse({
    id: vaultId,
    schemaVersion,
    cryptographicVersion: 1,
    keySlots: [slot],
    currentKeyVersion: keyVersion,
    revision: 1,
    encryptedPreferences: await encryptPayload(
      Buffer.from('{"productLabel":"CredVault"}', 'utf8'),
      rootKey,
      preferencesContext,
    ),
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  return {
    vaultId,
    rootKey,
    vault,
    groups,
    items: itemRecords,
    groupPayloads,
    itemPayloads,
  };
}

export function mutateCiphertext(record: EncryptedItemRecord): EncryptedItemRecord {
  const bytes = Buffer.from(record.encryptedPayload.ciphertext, 'base64url');
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  return {
    ...record,
    encryptedPayload: {
      ...record.encryptedPayload,
      ciphertext: bytes.toString('base64url'),
    },
  };
}
