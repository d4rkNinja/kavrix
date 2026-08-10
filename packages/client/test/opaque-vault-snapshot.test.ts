import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  contentHashForRecord,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  syncPullResponseSchema,
  timestampSchema,
  type SyncPullResponse,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
} from '@kavrix/schemas';
import { SyncProtocolError, type SyncTransportPort } from '@kavrix/sync';

import {
  OpaqueSnapshotCapacityError,
  OpaqueVaultSnapshot,
  VaultReadSession,
} from '../src/index.js';
import { encryptedFixture } from './fixtures.js';

const timestamp = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const digest = createHash('sha256').update('snapshot').digest('base64url');

describe('OpaqueVaultSnapshot', () => {
  it('feeds the read session from canonical ciphertext-only sync pages', async () => {
    const fixture = await encryptedFixture();
    const page = fixturePage(fixture);
    const snapshot = new OpaqueVaultSnapshot(fixture.vaultId);
    snapshot.applyPullPage(page);

    expect(snapshot.recordCount).toBe(3);
    expect(snapshot.totalBytes).toBeGreaterThan(0);
    expect(snapshot.cursor.serverSequence).toBe(3);
    await expect(snapshot.getVault(fixture.vaultId)).resolves.toMatchObject({
      id: fixture.vaultId,
    });
    await expect(
      snapshot.getGroup(fixture.vaultId, required(fixture.groupPayloads[0]).id),
    ).resolves.toMatchObject({ id: 'group.1' });
    await expect(
      snapshot.getItem(fixture.vaultId, required(fixture.itemPayloads[0]).id),
    ).resolves.toMatchObject({ id: 'item.1.1' });

    const session = new VaultReadSession(snapshot, fixture.vaultId);
    await session.unlock(fixture.rootKey);
    await expect(session.show('Production', 'Primary')).resolves.toMatchObject({
      item: { id: 'item.1.1' },
      template: { id: 'template.1' },
    });
  });

  it('retains bounded hidden ciphertext and activates exact current restore records', async () => {
    const fixture = await encryptedFixture();
    const snapshot = new OpaqueVaultSnapshot(fixture.vaultId);
    snapshot.applyPullPage(fixturePage(fixture));
    const item = required(fixture.itemPayloads[0]);
    const storedItem = required(fixture.items.get(item.groupId)?.[0]);
    snapshot.applyPullPage(
      tombstonePage(fixture.vaultId, {
        entityType: 'item',
        entityId: item.id,
        sequence: 4,
        serverVaultRevision: 2,
        tombstoneRevision: 2,
        lastRecordRevision: storedItem.recordRevision,
        lastCiphertextHash: contentHashForRecord(storedItem),
      }),
    );
    await expect(snapshot.getItem(fixture.vaultId, item.id)).resolves.toBeNull();
    expect(snapshot.recordCount).toBe(3);

    const restored = restoredItemRecord(storedItem, 3, 'current-restored-item');
    snapshot.applyPullPage(
      currentRecordPage(fixture.vaultId, restored, 'restore', 5, 3),
    );
    await expect(snapshot.getItem(fixture.vaultId, item.id)).resolves.toEqual(restored);

    snapshot.clear();
    expect(snapshot.recordCount).toBe(0);
    expect(snapshot.totalBytes).toBe(0);
    expect(snapshot.cursor.serverSequence).toBe(0);
  });

  it('hides group descendants without losing their independent deletion state', async () => {
    const fixture = await encryptedFixture();
    const snapshot = new OpaqueVaultSnapshot(fixture.vaultId);
    snapshot.applyPullPage(fixturePage(fixture));
    const group = required(fixture.groups[0]);
    const item = required(fixture.items.get(group.id)?.[0]);
    snapshot.applyPullPage(
      tombstonePage(fixture.vaultId, {
        entityType: 'group',
        entityId: group.id,
        sequence: 4,
        serverVaultRevision: 2,
        tombstoneRevision: 2,
        lastRecordRevision: group.recordRevision,
        lastCiphertextHash: contentHashForRecord(group),
      }),
    );
    await expect(snapshot.getGroup(fixture.vaultId, group.id)).resolves.toBeNull();
    await expect(snapshot.getItem(fixture.vaultId, item.id)).resolves.toBeNull();
    expect(snapshot.recordCount).toBe(3);

    const restoredGroup = restoredGroupRecord(group, 3, 'current-restored-group');
    snapshot.applyPullPage(
      currentRecordPage(fixture.vaultId, restoredGroup, 'restore', 5, 3),
    );
    await expect(snapshot.getGroup(fixture.vaultId, group.id)).resolves.toEqual(
      restoredGroup,
    );
    await expect(snapshot.getItem(fixture.vaultId, item.id)).resolves.toMatchObject({
      id: item.id,
    });
  });

  it('rejects missing or tampered hidden restore state atomically', async () => {
    const fixture = await encryptedFixture();
    const item = required(fixture.itemPayloads[0]);
    const storedItem = required(fixture.items.get(item.groupId)?.[0]);
    const restored = restoredItemRecord(storedItem, 3, 'missing-prior-restore');
    const missing = new OpaqueVaultSnapshot(fixture.vaultId);
    expect(() => {
      missing.applyPullPage(
        currentRecordPage(fixture.vaultId, restored, 'restore', 1, 1),
      );
    }).toThrow(SyncProtocolError);
    expect(missing.recordCount).toBe(0);

    const active = new OpaqueVaultSnapshot(fixture.vaultId);
    active.applyPullPage(fixturePage(fixture));
    expect(() => {
      active.applyPullPage(
        currentRecordPage(fixture.vaultId, restored, 'restore', 4, 2),
      );
    }).toThrow(SyncProtocolError);

    const restoredTombstone = {
      ...tombstonePage(fixture.vaultId, {
        entityType: 'item' as const,
        entityId: item.id,
        sequence: 4,
        serverVaultRevision: 2,
        tombstoneRevision: 2,
        lastRecordRevision: 1,
        lastCiphertextHash: contentHashForRecord(storedItem),
      }),
      changes: [
        {
          change: {
            ...tombstonePage(fixture.vaultId, {
              entityType: 'item' as const,
              entityId: item.id,
              sequence: 4,
              serverVaultRevision: 2,
              tombstoneRevision: 2,
              lastRecordRevision: 1,
              lastCiphertextHash: contentHashForRecord(storedItem),
            }).changes[0]?.change,
            operation: 'restore',
          },
          record: {
            vaultId: fixture.vaultId,
            entityType: 'item',
            entityId: item.id,
            state: 'restored',
            tombstoneRevision: 2,
            lastRecordRevision: 1,
            lastCiphertextHash: contentHashForRecord(storedItem),
            deletedAt: timestamp,
            restoredAt: timestamp,
          },
        },
      ],
    } as never;
    expect(() => {
      active.applyPullPage(restoredTombstone);
    }).toThrow(SyncProtocolError);

    const tampered = new OpaqueVaultSnapshot(fixture.vaultId);
    tampered.applyPullPage(fixturePage(fixture));
    tampered.applyPullPage(
      tombstonePage(fixture.vaultId, {
        entityType: 'item',
        entityId: item.id,
        sequence: 4,
        serverVaultRevision: 2,
        tombstoneRevision: 2,
        lastRecordRevision: 1,
        lastCiphertextHash: contentHashForRecord(storedItem),
      }),
    );
    const stale = restoredItemRecord(storedItem, 2, 'stale-restored-item');
    expect(() => {
      tampered.applyPullPage(
        currentRecordPage(fixture.vaultId, stale, 'restore', 5, 3),
      );
    }).toThrow(SyncProtocolError);
    const wrongHash = createHash('sha256').update('wrong').digest('base64url');
    expect(() => {
      tampered.applyPullPage(
        currentRecordPage(fixture.vaultId, restored, 'restore', 5, 3, wrongHash),
      );
    }).toThrow(SyncProtocolError);
    expect(tampered.cursor.serverSequence).toBe(4);
    await expect(tampered.getItem(fixture.vaultId, item.id)).resolves.toBeNull();
  });

  it('permanently purges opaque records and their descendants', async () => {
    const fixture = await encryptedFixture();
    const group = required(fixture.groups[0]);
    const item = required(fixture.items.get(group.id)?.[0]);

    const itemSnapshot = new OpaqueVaultSnapshot(fixture.vaultId);
    itemSnapshot.applyPullPage(fixturePage(fixture));
    itemSnapshot.applyPullPage(purgePage(fixture.vaultId, 'item', item.id, 4));
    expect(itemSnapshot.recordCount).toBe(2);

    const groupSnapshot = new OpaqueVaultSnapshot(fixture.vaultId);
    groupSnapshot.applyPullPage(fixturePage(fixture));
    groupSnapshot.applyPullPage(purgePage(fixture.vaultId, 'group', group.id, 4));
    expect(groupSnapshot.recordCount).toBe(1);

    const vaultSnapshot = new OpaqueVaultSnapshot(fixture.vaultId);
    vaultSnapshot.applyPullPage(fixturePage(fixture));
    vaultSnapshot.applyPullPage(
      purgePage(fixture.vaultId, 'vault', fixture.vaultId, 4),
    );
    expect(vaultSnapshot.recordCount).toBe(0);
    expect(vaultSnapshot.totalBytes).toBe(0);
  });

  it('rejects rollback, sequence gaps, invalid bounds, and capacity atomically', async () => {
    const fixture = await encryptedFixture();
    expect(
      () => new OpaqueVaultSnapshot(fixture.vaultId, { maximumRecords: 0 }),
    ).toThrow(TypeError);
    expect(
      () =>
        new OpaqueVaultSnapshot(fixture.vaultId, {
          maximumBytes: 1024 * 1024 * 1024 + 1,
        }),
    ).toThrow(TypeError);
    const constrained = new OpaqueVaultSnapshot(fixture.vaultId, {
      maximumRecords: 2,
    });
    expect(() => {
      constrained.applyPullPage(fixturePage(fixture));
    }).toThrow(OpaqueSnapshotCapacityError);
    expect(constrained.recordCount).toBe(0);
    expect(constrained.cursor.serverSequence).toBe(0);

    const snapshot = new OpaqueVaultSnapshot(fixture.vaultId);
    snapshot.applyPullPage(fixturePage(fixture));
    expect(() => {
      snapshot.applyPullPage(fixturePage(fixture));
    }).toThrow(SyncProtocolError);
    const valid = fixturePage(fixture);
    const gap = {
      ...valid,
      nextCursor: { ...valid.nextCursor, serverSequence: 4 },
    } as never;
    expect(() => {
      new OpaqueVaultSnapshot(fixture.vaultId).applyPullPage(gap);
    }).toThrow(SyncProtocolError);
  });

  it('refreshes through the canonical transport port with bounded page size', async () => {
    const fixture = await encryptedFixture();
    const page = fixturePage(fixture);
    const requests: unknown[] = [];
    const transport: SyncTransportPort = {
      pull: (request) => {
        requests.push(request);
        return Promise.resolve(page);
      },
      push: () => Promise.reject(new Error('push is not part of this test')),
      publishTemplateMigration: () =>
        Promise.reject(new Error('template migration is not part of this test')),
    };
    const snapshot = new OpaqueVaultSnapshot(fixture.vaultId);
    await expect(snapshot.refresh(transport, 25)).resolves.toBe(3);
    expect(requests).toHaveLength(1);
    await expect(snapshot.refresh(transport, 0)).rejects.toBeInstanceOf(
      SyncProtocolError,
    );
  });
});

function fixturePage(
  fixture: Awaited<ReturnType<typeof encryptedFixture>>,
): SyncPullResponse {
  const group = required(fixture.groups[0]);
  const item = required(fixture.items.get(group.id)?.[0]);
  return syncPullResponseSchema.parse({
    vaultId: fixture.vaultId,
    serverVaultRevision: 1,
    changes: [
      {
        change: {
          id: 'change.vault.1',
          vaultId: fixture.vaultId,
          serverSequence: 1,
          recordRevision: fixture.vault.revision,
          operation: 'upsert',
          ciphertextHash: contentHashForRecord(fixture.vault),
          createdAt: timestamp,
          entityType: 'vault',
          entityId: fixture.vaultId,
        },
        record: fixture.vault,
      },
      {
        change: {
          id: 'change.group.1',
          vaultId: fixture.vaultId,
          serverSequence: 2,
          recordRevision: group.recordRevision,
          operation: 'upsert',
          ciphertextHash: contentHashForRecord(group),
          createdAt: timestamp,
          entityType: 'group',
          entityId: group.id,
        },
        record: group,
      },
      {
        change: {
          id: 'change.item.1',
          vaultId: fixture.vaultId,
          serverSequence: 3,
          recordRevision: item.recordRevision,
          operation: 'upsert',
          ciphertextHash: contentHashForRecord(item),
          createdAt: timestamp,
          entityType: 'item',
          entityId: item.id,
        },
        record: item,
      },
    ],
    nextCursor: {
      vaultId: fixture.vaultId,
      serverSequence: 3,
      highestSeenVaultRevision: 1,
    },
    hasMore: false,
  });
}

function tombstonePage(
  vaultId: Awaited<ReturnType<typeof encryptedFixture>>['vaultId'],
  input: Readonly<{
    entityType: 'group' | 'item';
    entityId: string;
    sequence: number;
    serverVaultRevision: number;
    tombstoneRevision: number;
    lastRecordRevision: number;
    lastCiphertextHash: string;
  }>,
): SyncPullResponse {
  return syncPullResponseSchema.parse({
    vaultId,
    serverVaultRevision: input.serverVaultRevision,
    changes: [
      {
        change: {
          id: `change.${input.entityType}.deleted.${String(input.sequence)}`,
          vaultId,
          serverSequence: input.sequence,
          recordRevision: input.tombstoneRevision,
          operation: 'tombstone',
          ciphertextHash: digest,
          createdAt: timestamp,
          entityType: input.entityType,
          entityId: input.entityId,
        },
        record: {
          vaultId,
          entityType: input.entityType,
          entityId: input.entityId,
          state: 'deleted',
          tombstoneRevision: input.tombstoneRevision,
          lastRecordRevision: input.lastRecordRevision,
          lastCiphertextHash: input.lastCiphertextHash,
          deletedAt: timestamp,
        },
      },
    ],
    nextCursor: {
      vaultId,
      serverSequence: input.sequence,
      highestSeenVaultRevision: input.serverVaultRevision,
    },
    hasMore: false,
  });
}

function currentRecordPage(
  vaultId: Awaited<ReturnType<typeof encryptedFixture>>['vaultId'],
  record: EncryptedGroupRecord | EncryptedItemRecord,
  operation: 'upsert' | 'restore',
  sequence: number,
  serverVaultRevision: number,
  contentHash: string = contentHashForRecord(record),
): SyncPullResponse {
  const entityType = 'groupId' in record ? 'item' : 'group';
  return syncPullResponseSchema.parse({
    vaultId,
    serverVaultRevision,
    changes: [
      {
        change: {
          id: `change.${entityType}.${operation}.${String(sequence)}`,
          vaultId,
          serverSequence: sequence,
          recordRevision: record.recordRevision,
          operation,
          ciphertextHash: contentHash,
          createdAt: record.updatedAt,
          entityType,
          entityId: record.id,
        },
        record,
      },
    ],
    nextCursor: {
      vaultId,
      serverSequence: sequence,
      highestSeenVaultRevision: serverVaultRevision,
    },
    hasMore: false,
  });
}

function restoredItemRecord(
  previous: EncryptedItemRecord,
  revision: number,
  ciphertext: string,
): EncryptedItemRecord {
  return encryptedItemRecordSchema.parse({
    ...previous,
    encryptedPayload: {
      ...previous.encryptedPayload,
      ciphertext: Buffer.from(ciphertext, 'utf8').toString('base64url'),
    },
    recordRevision: revision,
    ciphertextHash: Buffer.alloc(32, revision).toString('base64url'),
    updatedAt: '2026-08-10T00:02:00.000Z',
  });
}

function restoredGroupRecord(
  previous: EncryptedGroupRecord,
  revision: number,
  ciphertext: string,
): EncryptedGroupRecord {
  return encryptedGroupRecordSchema.parse({
    ...previous,
    encryptedPayload: {
      ...previous.encryptedPayload,
      ciphertext: Buffer.from(ciphertext, 'utf8').toString('base64url'),
    },
    recordRevision: revision,
    updatedAt: '2026-08-10T00:02:00.000Z',
  });
}

function purgePage(
  vaultId: Awaited<ReturnType<typeof encryptedFixture>>['vaultId'],
  entityType: 'vault' | 'group' | 'item',
  entityId: string,
  sequence: number,
): SyncPullResponse {
  return syncPullResponseSchema.parse({
    vaultId,
    serverVaultRevision: 2,
    changes: [
      {
        change: {
          id: `change.${entityType}.purge.${String(sequence)}`,
          vaultId,
          serverSequence: sequence,
          recordRevision: 2,
          operation: 'purge',
          createdAt: timestamp,
          entityType,
          entityId,
        },
        record: null,
      },
    ],
    nextCursor: {
      vaultId,
      serverSequence: sequence,
      highestSeenVaultRevision: 2,
    },
    hasMore: false,
  });
}

function required<TValue>(value: TValue | undefined): TValue {
  if (value === undefined) throw new Error('The test fixture is incomplete.');
  return value;
}
