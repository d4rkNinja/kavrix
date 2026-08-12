import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { CryptoAuthenticationError } from '@kavrix/core';
import { zeroize } from '@kavrix/crypto';
import {
  contentHashForRecord,
  recordRevisionSchema,
  sha256DigestSchema,
  timestampSchema,
  tombstoneRecordSchema,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type TombstoneRecord,
} from '@kavrix/schemas';

import {
  assertGroupTombstoneRelation,
  assertItemTombstoneRelation,
} from '../src/vault-mutation-deleted-state.js';
import {
  encryptGroupRecord,
  encryptItemRecord,
  openGroupRecord,
  openGroupRecordForState,
  openItemRecord,
  openItemRecordForState,
  type OpenGroup,
  type OpenItem,
} from '../src/vault-mutation-records.js';
import { MemoryReadSource, encryptedFixture } from './fixtures.js';
import { VaultReadSession } from '../src/vault-read-session.js';

const deletedAt = timestampSchema.parse('2026-08-11T00:00:00.000Z');
const restoredAt = timestampSchema.parse('2026-08-12T00:00:00.000Z');

describe('restore record openers', () => {
  it('opens active and explicitly deleted group/item records and keeps wrappers active-only', async () => {
    const fixture = await encryptedFixture();
    const vault = activeVault(fixture);
    let activeGroup: OpenGroup | undefined;
    let deletedGroup: OpenGroup | undefined;
    let activeItem: OpenItem | undefined;
    let deletedItem: OpenItem | undefined;
    try {
      activeGroup = await openGroupRecord(
        required(fixture.groups[0]),
        fixture.vaultId,
        vault,
        fixture.rootKey,
      );
      activeItem = await openItemRecord(firstItem(fixture), activeGroup, vault);
      const deletedGroupRecord = await encryptGroupRecord(
        {
          ...activeGroup.payload,
          revision: recordRevisionSchema.parse(2),
          updatedAt: deletedAt,
          deletedAt,
        },
        activeGroup.key,
        fixture.rootKey,
        vault,
        activeGroup.record.wrappedGroupKey,
        deletedAt,
      );
      const deletedItemRecord = await encryptItemRecord(
        {
          ...activeItem.payload,
          revision: recordRevisionSchema.parse(2),
          updatedAt: deletedAt,
          deletedAt,
        },
        activeItem.key,
        activeGroup.key,
        vault,
        activeItem.record.wrappedItemKey,
        deletedAt,
      );
      deletedGroup = await openGroupRecordForState(
        deletedGroupRecord,
        fixture.vaultId,
        vault,
        fixture.rootKey,
        'deleted',
      );
      deletedItem = await openItemRecordForState(
        deletedItemRecord,
        deletedGroup,
        vault,
        'deleted',
      );
      expect(deletedGroup.deleted).toBe(true);
      expect(deletedItem.deleted).toBe(true);
      await expect(
        openGroupRecord(deletedGroupRecord, fixture.vaultId, vault, fixture.rootKey),
      ).rejects.toBeInstanceOf(CryptoAuthenticationError);
      await expect(
        openItemRecord(deletedItemRecord, deletedGroup, vault),
      ).rejects.toBeInstanceOf(CryptoAuthenticationError);

      const read = new VaultReadSession(
        new MemoryReadSource({
          ...fixture,
          groups: [deletedGroupRecord],
          items: new Map(),
        }),
        fixture.vaultId,
      );
      await read.unlock(fixture.rootKey);
      await expect(read.listGroups()).rejects.toBeInstanceOf(CryptoAuthenticationError);
      read.lock();
      const itemRead = new VaultReadSession(
        new MemoryReadSource({
          ...fixture,
          items: new Map([[activeGroup.record.id, [deletedItemRecord]]]),
        }),
        fixture.vaultId,
      );
      await itemRead.unlock(fixture.rootKey);
      await expect(itemRead.listItems(activeGroup.record.id)).rejects.toBeInstanceOf(
        CryptoAuthenticationError,
      );
      itemRead.lock();
    } finally {
      zeroize(deletedItem?.key);
      zeroize(activeItem?.key);
      zeroize(deletedGroup?.key);
      zeroize(activeGroup?.key);
      zeroize(fixture.rootKey);
    }
  });

  it('authenticates deleted and restored group/item tombstone relations', async () => {
    const fixture = await encryptedFixture();
    const vault = activeVault(fixture);
    let group: OpenGroup | undefined;
    let item: OpenItem | undefined;
    let deletedGroup: OpenGroup | undefined;
    let deletedItem: OpenItem | undefined;
    let restoredGroup: OpenGroup | undefined;
    let restoredItem: OpenItem | undefined;
    try {
      group = await openGroupRecord(
        required(fixture.groups[0]),
        fixture.vaultId,
        vault,
        fixture.rootKey,
      );
      item = await openItemRecord(firstItem(fixture), group, vault);
      deletedGroup = await openGroupRecordForState(
        await encryptGroupRecord(
          {
            ...group.payload,
            revision: recordRevisionSchema.parse(2),
            updatedAt: deletedAt,
            deletedAt,
          },
          group.key,
          fixture.rootKey,
          vault,
          group.record.wrappedGroupKey,
          deletedAt,
        ),
        fixture.vaultId,
        vault,
        fixture.rootKey,
        'deleted',
      );
      deletedItem = await openItemRecordForState(
        await encryptItemRecord(
          {
            ...item.payload,
            revision: recordRevisionSchema.parse(2),
            updatedAt: deletedAt,
            deletedAt,
          },
          item.key,
          group.key,
          vault,
          item.record.wrappedItemKey,
          deletedAt,
        ),
        deletedGroup,
        vault,
        'deleted',
      );
      const groupDeleted = tombstoneRecordSchema.parse({
        vaultId: fixture.vaultId,
        entityType: 'group',
        entityId: group.record.id,
        state: 'deleted',
        tombstoneRevision: 2,
        lastRecordRevision: 1,
        lastCiphertextHash: contentHashForRecord(group.record),
        deletedAt,
      }) as Extract<TombstoneRecord, { entityType: 'group' }>;
      const itemDeleted = tombstoneRecordSchema.parse({
        vaultId: fixture.vaultId,
        entityType: 'item',
        entityId: item.record.id,
        state: 'deleted',
        tombstoneRevision: 2,
        lastRecordRevision: 1,
        lastCiphertextHash: contentHashForRecord(item.record),
        deletedAt,
      }) as Extract<TombstoneRecord, { entityType: 'item' }>;
      const authenticatedDeletedGroup = deletedGroup;
      const authenticatedDeletedItem = deletedItem;
      expect(() => {
        assertGroupTombstoneRelation(authenticatedDeletedGroup, groupDeleted, group);
      }).not.toThrow();
      expect(() => {
        assertItemTombstoneRelation(authenticatedDeletedItem, itemDeleted, item);
      }).not.toThrow();
      expect(() => {
        assertGroupTombstoneRelation(authenticatedDeletedGroup, groupDeleted);
      }).toThrow(CryptoAuthenticationError);
      expect(() => {
        assertItemTombstoneRelation(authenticatedDeletedItem, itemDeleted);
      }).toThrow(CryptoAuthenticationError);
      for (const badCurrent of [
        { ...authenticatedDeletedGroup, deleted: false },
        {
          ...authenticatedDeletedGroup,
          record: {
            ...authenticatedDeletedGroup.record,
            recordRevision: recordRevisionSchema.parse(1),
          },
        },
        {
          ...authenticatedDeletedGroup,
          payload: { ...authenticatedDeletedGroup.payload, deletedAt: restoredAt },
        },
      ]) {
        expect(() => {
          assertGroupTombstoneRelation(badCurrent, groupDeleted, group);
        }).toThrow(CryptoAuthenticationError);
      }
      for (const badPredecessor of [
        { ...group, deleted: true },
        { ...group, record: { ...group.record, id: 'group.other' } },
        {
          ...group,
          record: { ...group.record, recordRevision: recordRevisionSchema.parse(2) },
        },
      ]) {
        expect(() => {
          assertGroupTombstoneRelation(
            authenticatedDeletedGroup,
            groupDeleted,
            badPredecessor as OpenGroup,
          );
        }).toThrow(CryptoAuthenticationError);
      }
      expect(() => {
        assertGroupTombstoneRelation(
          authenticatedDeletedGroup,
          {
            ...groupDeleted,
            lastCiphertextHash: sha256DigestSchema.parse(
              createHash('sha256').update('wrong').digest('base64url'),
            ),
          },
          group,
        );
      }).toThrow(CryptoAuthenticationError);
      for (const badCurrent of [
        {
          ...authenticatedDeletedItem,
          record: { ...authenticatedDeletedItem.record, groupId: 'group.other' },
        },
        {
          ...authenticatedDeletedItem,
          payload: { ...authenticatedDeletedItem.payload, id: 'item.other' },
        },
      ]) {
        expect(() => {
          assertItemTombstoneRelation(badCurrent as OpenItem, itemDeleted, item);
        }).toThrow(CryptoAuthenticationError);
      }
      for (const badPredecessor of [
        { ...item, record: { ...item.record, groupId: 'group.other' } },
        { ...item, payload: { ...item.payload, id: 'item.other' } },
      ]) {
        expect(() => {
          assertItemTombstoneRelation(
            authenticatedDeletedItem,
            itemDeleted,
            badPredecessor as OpenItem,
          );
        }).toThrow(CryptoAuthenticationError);
      }
      for (const badTombstone of [
        { ...groupDeleted, vaultId: 'vault.other' },
        { ...groupDeleted, entityId: 'group.other' },
        { ...groupDeleted, tombstoneRevision: recordRevisionSchema.parse(3) },
        { ...groupDeleted, deletedAt: restoredAt },
      ]) {
        expect(() => {
          assertGroupTombstoneRelation(
            authenticatedDeletedGroup,
            badTombstone as never,
            group,
          );
        }).toThrow(CryptoAuthenticationError);
      }

      restoredGroup = await openGroupRecord(
        await encryptGroupRecord(
          {
            ...group.payload,
            revision: recordRevisionSchema.parse(2),
            updatedAt: restoredAt,
          },
          group.key,
          fixture.rootKey,
          vault,
          group.record.wrappedGroupKey,
        ),
        fixture.vaultId,
        vault,
        fixture.rootKey,
      );
      restoredItem = await openItemRecord(
        await encryptItemRecord(
          {
            ...item.payload,
            revision: recordRevisionSchema.parse(2),
            updatedAt: restoredAt,
          },
          item.key,
          group.key,
          vault,
          item.record.wrappedItemKey,
        ),
        restoredGroup,
        vault,
      );
      const groupRestored = tombstoneRecordSchema.parse({
        ...groupDeleted,
        state: 'restored',
        restoredAt,
      }) as Extract<TombstoneRecord, { entityType: 'group' }>;
      const itemRestored = tombstoneRecordSchema.parse({
        ...itemDeleted,
        state: 'restored',
        restoredAt,
      }) as Extract<TombstoneRecord, { entityType: 'item' }>;
      const authenticatedRestoredGroup = restoredGroup;
      const authenticatedRestoredItem = restoredItem;
      expect(() => {
        assertGroupTombstoneRelation(authenticatedRestoredGroup, groupRestored);
      }).not.toThrow();
      expect(() => {
        assertItemTombstoneRelation(authenticatedRestoredItem, itemRestored);
      }).not.toThrow();
      expect(() => {
        assertGroupTombstoneRelation(authenticatedRestoredGroup, groupRestored, group);
      }).toThrow(CryptoAuthenticationError);
      expect(() => {
        assertItemTombstoneRelation(authenticatedRestoredItem, itemRestored, item);
      }).toThrow(CryptoAuthenticationError);
      for (const badCurrent of [
        { ...authenticatedRestoredGroup, deleted: true },
        {
          ...authenticatedRestoredGroup,
          record: {
            ...authenticatedRestoredGroup.record,
            recordRevision: recordRevisionSchema.parse(1),
          },
        },
        {
          ...authenticatedRestoredGroup,
          payload: { ...authenticatedRestoredGroup.payload, updatedAt: deletedAt },
        },
      ]) {
        expect(() => {
          assertGroupTombstoneRelation(badCurrent, groupRestored);
        }).toThrow(CryptoAuthenticationError);
      }
      for (const badTombstone of [
        { ...groupRestored, vaultId: 'vault.other' },
        { ...groupRestored, entityId: 'group.other' },
        { ...groupRestored, tombstoneRevision: recordRevisionSchema.parse(3) },
        { ...groupRestored, restoredAt: deletedAt },
      ]) {
        expect(() => {
          assertGroupTombstoneRelation(
            authenticatedRestoredGroup,
            badTombstone as never,
          );
        }).toThrow(CryptoAuthenticationError);
      }
    } finally {
      for (const opened of [
        restoredItem,
        deletedItem,
        item,
        restoredGroup,
        deletedGroup,
        group,
      ])
        zeroize(opened?.key);
      zeroize(fixture.rootKey);
    }
  });

  it.each([
    [
      'vault identity',
      (record: EncryptedGroupRecord) => ({ ...record, vaultId: 'vault.other' }),
    ],
    ['identity', (record: EncryptedGroupRecord) => ({ ...record, id: 'group.other' })],
    [
      'schema version',
      (record: EncryptedGroupRecord) => ({ ...record, schemaVersion: 2 }),
    ],
    [
      'record revision',
      (record: EncryptedGroupRecord) => ({ ...record, recordRevision: 2 }),
    ],
    [
      'template version',
      (record: EncryptedGroupRecord) => ({ ...record, templateVersion: 2 }),
    ],
    [
      'created time',
      (record: EncryptedGroupRecord) => ({ ...record, createdAt: deletedAt }),
    ],
    [
      'updated time',
      (record: EncryptedGroupRecord) => ({ ...record, updatedAt: deletedAt }),
    ],
    [
      'wrapped-key AAD',
      (record: EncryptedGroupRecord) => ({
        ...record,
        wrappedGroupKey: {
          ...record.wrappedGroupKey,
          aad: { ...record.wrappedGroupKey.aad, entityId: 'group.other' },
        },
      }),
    ],
    [
      'wrapped-key version',
      (record: EncryptedGroupRecord) => ({
        ...record,
        wrappedGroupKey: { ...record.wrappedGroupKey, keyVersion: 2 },
      }),
    ],
    [
      'payload AAD',
      (record: EncryptedGroupRecord) => ({
        ...record,
        encryptedPayload: {
          ...record.encryptedPayload,
          aad: { ...record.encryptedPayload.aad, entityId: 'group.other' },
        },
      }),
    ],
    [
      'payload version',
      (record: EncryptedGroupRecord) => ({
        ...record,
        encryptedPayload: { ...record.encryptedPayload, keyVersion: 2 },
      }),
    ],
  ])('rejects group %s mismatches generically', async (_name, mutate) => {
    const fixture = await encryptedFixture();
    try {
      await expect(
        openGroupRecord(
          mutate(required(fixture.groups[0])) as never,
          fixture.vaultId,
          activeVault(fixture),
          fixture.rootKey,
        ),
      ).rejects.toMatchObject({
        name: 'CryptoAuthenticationError',
        message: 'Encrypted data could not be authenticated.',
      });
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('rejects noncanonical group plaintext and mismatched deletion time', async () => {
    const noncanonical = await encryptedFixture({ nonCanonicalGroup: true });
    const fixture = await encryptedFixture();
    let group: OpenGroup | undefined;
    try {
      await expect(
        openGroupRecord(
          required(noncanonical.groups[0]),
          noncanonical.vaultId,
          activeVault(noncanonical),
          noncanonical.rootKey,
        ),
      ).rejects.toBeInstanceOf(CryptoAuthenticationError);
      group = await openGroupRecord(
        required(fixture.groups[0]),
        fixture.vaultId,
        activeVault(fixture),
        fixture.rootKey,
      );
      const mismatch = await encryptGroupRecord(
        {
          ...group.payload,
          revision: recordRevisionSchema.parse(2),
          updatedAt: deletedAt,
          deletedAt,
        },
        group.key,
        fixture.rootKey,
        activeVault(fixture),
        group.record.wrappedGroupKey,
        restoredAt,
      );
      await expect(
        openGroupRecordForState(
          mismatch,
          fixture.vaultId,
          activeVault(fixture),
          fixture.rootKey,
          'deleted',
        ),
      ).rejects.toBeInstanceOf(CryptoAuthenticationError);
    } finally {
      zeroize(group?.key);
      zeroize(fixture.rootKey);
      zeroize(noncanonical.rootKey);
    }
  });

  it.each([
    ['identity', (record: EncryptedItemRecord) => ({ ...record, id: 'item.other' })],
    [
      'vault identity',
      (record: EncryptedItemRecord) => ({ ...record, vaultId: 'vault.other' }),
    ],
    [
      'parent',
      (record: EncryptedItemRecord) => ({ ...record, groupId: 'group.other' }),
    ],
    [
      'schema version',
      (record: EncryptedItemRecord) => ({ ...record, schemaVersion: 2 }),
    ],
    ['revision', (record: EncryptedItemRecord) => ({ ...record, recordRevision: 2 })],
    [
      'created time',
      (record: EncryptedItemRecord) => ({ ...record, createdAt: deletedAt }),
    ],
    [
      'updated time',
      (record: EncryptedItemRecord) => ({ ...record, updatedAt: deletedAt }),
    ],
    [
      'key version',
      (record: EncryptedItemRecord) => ({
        ...record,
        wrappedItemKey: { ...record.wrappedItemKey, keyVersion: 2 },
      }),
    ],
    [
      'wrapped-key AAD',
      (record: EncryptedItemRecord) => ({
        ...record,
        wrappedItemKey: {
          ...record.wrappedItemKey,
          aad: { ...record.wrappedItemKey.aad, entityId: 'item.other' },
        },
      }),
    ],
    [
      'payload AAD',
      (record: EncryptedItemRecord) => ({
        ...record,
        encryptedPayload: {
          ...record.encryptedPayload,
          aad: { ...record.encryptedPayload.aad, groupId: 'group.other' },
        },
      }),
    ],
    [
      'payload key version',
      (record: EncryptedItemRecord) => ({
        ...record,
        encryptedPayload: { ...record.encryptedPayload, keyVersion: 2 },
      }),
    ],
    [
      'ciphertext hash',
      (record: EncryptedItemRecord) => ({
        ...record,
        ciphertextHash: sha256DigestSchema.parse(
          createHash('sha256').update('wrong').digest('base64url'),
        ),
      }),
    ],
  ])('rejects item %s mismatches generically', async (_name, mutate) => {
    const fixture = await encryptedFixture();
    let group: OpenGroup | undefined;
    try {
      group = await openGroupRecord(
        required(fixture.groups[0]),
        fixture.vaultId,
        activeVault(fixture),
        fixture.rootKey,
      );
      await expect(
        openItemRecord(
          mutate(firstItem(fixture)) as never,
          group,
          activeVault(fixture),
        ),
      ).rejects.toMatchObject({
        name: 'CryptoAuthenticationError',
        message: 'Encrypted data could not be authenticated.',
      });
    } finally {
      zeroize(group?.key);
      zeroize(fixture.rootKey);
    }
  });

  it('rejects deleted item timestamp and template bindings', async () => {
    const fixture = await encryptedFixture();
    let group: OpenGroup | undefined;
    let item: OpenItem | undefined;
    try {
      group = await openGroupRecord(
        required(fixture.groups[0]),
        fixture.vaultId,
        activeVault(fixture),
        fixture.rootKey,
      );
      item = await openItemRecord(firstItem(fixture), group, activeVault(fixture));
      const deletedMismatch = await encryptItemRecord(
        {
          ...item.payload,
          revision: recordRevisionSchema.parse(2),
          updatedAt: deletedAt,
          deletedAt,
        },
        item.key,
        group.key,
        activeVault(fixture),
        item.record.wrappedItemKey,
        restoredAt,
      );
      await expect(
        openItemRecordForState(deletedMismatch, group, activeVault(fixture), 'deleted'),
      ).rejects.toBeInstanceOf(CryptoAuthenticationError);
      for (const payload of [
        { ...item.payload, templateId: 'template.other' },
        { ...item.payload, templateVersion: 2 },
      ]) {
        const record = await encryptItemRecord(
          payload as never,
          item.key,
          group.key,
          activeVault(fixture),
          item.record.wrappedItemKey,
        );
        await expect(
          openItemRecord(record, group, activeVault(fixture)),
        ).rejects.toBeInstanceOf(CryptoAuthenticationError);
      }
    } finally {
      zeroize(item?.key);
      zeroize(group?.key);
      zeroize(fixture.rootKey);
    }
  });

  it('fails closed for runtime-invalid explicit record states', async () => {
    const fixture = await encryptedFixture();
    let group: OpenGroup | undefined;
    try {
      await expect(
        openGroupRecordForState(
          required(fixture.groups[0]),
          fixture.vaultId,
          activeVault(fixture),
          fixture.rootKey,
          'bogus' as never,
        ),
      ).rejects.toBeInstanceOf(CryptoAuthenticationError);
      group = await openGroupRecord(
        required(fixture.groups[0]),
        fixture.vaultId,
        activeVault(fixture),
        fixture.rootKey,
      );
      await expect(
        openItemRecordForState(
          firstItem(fixture),
          group,
          activeVault(fixture),
          'bogus' as never,
        ),
      ).rejects.toBeInstanceOf(CryptoAuthenticationError);
    } finally {
      zeroize(group?.key);
      zeroize(fixture.rootKey);
    }
  });

  it('rejects noncanonical item plaintext through the shared read opener', async () => {
    const fixture = await encryptedFixture({ nonCanonicalItem: true });
    let group: OpenGroup | undefined;
    try {
      group = await openGroupRecord(
        required(fixture.groups[0]),
        fixture.vaultId,
        activeVault(fixture),
        fixture.rootKey,
      );
      await expect(
        openItemRecord(firstItem(fixture), group, activeVault(fixture)),
      ).rejects.toBeInstanceOf(CryptoAuthenticationError);
    } finally {
      zeroize(group?.key);
      zeroize(fixture.rootKey);
    }
  });
});

function activeVault(fixture: Awaited<ReturnType<typeof encryptedFixture>>): Readonly<{
  schemaVersion: typeof fixture.vault.schemaVersion;
  keyVersion: typeof fixture.vault.currentKeyVersion;
}> {
  return {
    schemaVersion: fixture.vault.schemaVersion,
    keyVersion: fixture.vault.currentKeyVersion,
  };
}

function firstItem(
  fixture: Awaited<ReturnType<typeof encryptedFixture>>,
): EncryptedItemRecord {
  return required(required(fixture.items.values().next().value)[0]);
}

function required<T>(value: T | null | undefined): T {
  if (value === null || value === undefined) throw new Error('Missing fixture value');
  return value;
}
