import { createHash, randomUUID } from 'node:crypto';
import { realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { OpaqueMutationDurabilityUnknownError } from '@kavrix/client';
import {
  changeRecordSchema,
  contentHashForRecord,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  opaqueMutationSchema,
  syncCursorSchema,
  syncPulledChangeSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  tombstoneRecordSchema,
  vaultRecordSchema,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type SyncPulledChange,
  type TemplateMigrationPublicationRequest,
  type TemplateMigrationPublicationResponse,
  type VaultRecord,
} from '@kavrix/schemas';
import { SyncLocalStateError, type ApplyPullPageInput } from '@kavrix/sync';
import { afterEach, describe, expect, it } from 'vitest';

import { openSqliteSyncLocalStore, type SqliteSyncLocalStore } from '../src/index.js';
import { digest, groupRecord, otherVaultId, timestamp, vaultId } from './fixtures.js';
import {
  grantWindowsEveryoneFullControl,
  removeWindowsEveryoneGrant,
} from './windows-acl-fixture.js';

const TEST_TMPDIR = await realpath(tmpdir());
const WRONG_DIGEST = createHash('sha256')
  .update('wrong-hash-fixture')
  .digest('base64url');
const roots: string[] = [];
const stores: SqliteSyncLocalStore[] = [];

afterEach(async () => {
  for (const store of stores.splice(0)) {
    try {
      store.close();
    } catch {
      // Security-failure tests intentionally force the adapter closed.
    }
  }
  for (const root of roots.splice(0)) {
    if (
      dirname(root) !== TEST_TMPDIR ||
      !root.startsWith(join(TEST_TMPDIR, 'kavrix-vault-adapter-test-'))
    ) {
      throw new Error('Refusing to remove an unverified test directory');
    }
    await rm(root, { force: true, recursive: true });
  }
});

describe('SqliteSyncLocalStore client adapters', () => {
  it('reads active records with pending overlays and group deletion cascade', async () => {
    const fixture = await createStore();
    const vault = vaultRecord();
    const group = groupRecord();
    const item = itemRecord();
    await enqueueAndComplete(fixture.store, [
      vaultMutation('vault-key-active-0001', vault),
      groupMutation('group-key-active-0001', group),
      itemMutation('item-key-active-00001', item),
    ]);

    expect(await fixture.store.getVault(vaultId)).toEqual(vault);
    expect(await fixture.store.getGroup(vaultId, group.id)).toEqual(group);
    expect(await collect(fixture.store.listGroups(vaultId))).toEqual([group]);
    expect(await fixture.store.getItem(vaultId, item.id)).toEqual(item);
    expect(await collect(fixture.store.listItems(vaultId, group.id))).toEqual([item]);

    const deletion = deletedGroupRecord(group, 1);
    await fixture.store.enqueueBatch([
      groupMutation('group-key-delete-0001', deletion, 0),
    ]);
    expect(await fixture.store.getGroup(vaultId, group.id)).toBeNull();
    expect(await collect(fixture.store.listGroups(vaultId))).toEqual([]);
    expect(await fixture.store.getItem(vaultId, item.id)).toBeNull();
    expect(await collect(fixture.store.listItems(vaultId, group.id))).toEqual([]);

    const deleted = await fixture.store.getCurrentGroup(vaultId, group.id);
    expect(deleted).toEqual({
      state: 'deleted',
      tombstone: tombstoneRecordSchema.parse({
        vaultId,
        entityType: 'group',
        entityId: group.id,
        state: 'deleted',
        tombstoneRevision: 1,
        lastRecordRevision: 0,
        lastCiphertextHash: contentHashForRecord(group),
        deletedAt: timestamp,
      }),
      predecessor: group,
    });
    await expect(
      fixture.store.getCurrentGroup(otherVaultId, group.id),
    ).resolves.toBeNull();
  });

  it('persists delete then restore overlays before sync and across reopen', async () => {
    const fixture = await createStore();
    const group = groupRecord();
    await enqueueAndComplete(fixture.store, [
      groupMutation('group-key-seed-000001', group),
    ]);
    const deletion = deletedGroupRecord(group, 1);
    const restored = encryptedGroupRecordSchema.parse({
      ...group,
      recordRevision: 2,
      updatedAt: '2026-08-10T00:00:02.000Z',
    });
    const mutations = [
      groupMutation('group-key-offline-delete', deletion, 0),
      groupMutation('group-key-offline-restor', restored, 1),
    ] as const;
    await fixture.store.enqueueBatch(mutations);

    expect(await fixture.store.getCurrentGroup(vaultId, group.id)).toEqual({
      state: 'active',
      record: restored,
    });
    const reopened = await openSqliteSyncLocalStore({ path: fixture.path });
    stores.push(reopened);
    expect(await reopened.getCurrentGroup(vaultId, group.id)).toEqual({
      state: 'active',
      record: restored,
    });
    expect(await reopened.getGroup(vaultId, group.id)).toEqual(restored);

    await completeExisting(reopened, 'batch-offline-restore-0001', mutations);
    expect(await reopened.loadOpaqueRecord(vaultId, 'group', group.id)).toEqual(
      restored,
    );
    await expect(reopened.enqueueBatch(mutations)).resolves.toBeUndefined();
    const incompatible = groupMutation(
      mutations[0].idempotencyKey,
      encryptedGroupRecordSchema.parse({
        ...deletion,
        updatedAt: '2026-08-11T00:00:00.000Z',
      }),
      0,
    );
    await expect(reopened.enqueueBatch([incompatible])).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
  });

  it('enqueues a whole batch atomically and rejects mixed or cross-vault replay', async () => {
    const fixture = await createStore({ maxPendingMutations: 2 });
    const first = groupMutation('batch-atomic-key-00001', groupRecord('group.1'));
    const second = groupMutation('batch-atomic-key-00002', groupRecord('group.2'));
    await fixture.store.enqueueBatch([first, second]);
    await expect(fixture.store.enqueueBatch([first, second])).resolves.toBeUndefined();
    expect(await fixture.store.listPendingMutations(vaultId)).toEqual([first, second]);

    const third = groupMutation('batch-atomic-key-00003', groupRecord('group.3'));
    await expect(fixture.store.enqueueBatch([first, third])).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    expect(await fixture.store.listPendingMutations(vaultId)).toEqual([first, second]);
    await expect(
      fixture.store.enqueueBatch([
        third,
        groupMutation(
          'batch-atomic-key-00004',
          groupRecord('group.4', 0, otherVaultId),
        ),
      ]),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('exposes exact pending item deletion state through item overlays', async () => {
    const fixture = await createStore();
    const group = groupRecord();
    const item = itemRecord();
    await enqueueAndComplete(fixture.store, [
      groupMutation('item-delete-seed-group1', group),
      itemMutation('item-delete-seed-item01', item),
    ]);
    expect(await collect(fixture.store.listCurrentItems(vaultId, group.id))).toEqual([
      { state: 'active', record: item },
    ]);

    const deleted = deletedItemRecord(item, 1);
    await fixture.store.enqueueBatch([
      itemMutation('item-delete-pending-001', deleted, 0),
    ]);
    const expected = {
      state: 'deleted',
      tombstone: tombstoneRecordSchema.parse({
        vaultId,
        entityType: 'item',
        entityId: item.id,
        state: 'deleted',
        tombstoneRevision: 1,
        lastRecordRevision: 0,
        lastCiphertextHash: contentHashForRecord(item),
        deletedAt: timestamp,
      }),
      predecessor: item,
    } as const;
    expect(await fixture.store.getCurrentItem(vaultId, item.id)).toEqual(expected);
    expect(await collect(fixture.store.listCurrentItems(vaultId, group.id))).toEqual([
      expected,
    ]);
    expect(await fixture.store.getItem(vaultId, item.id)).toBeNull();
  });

  it('fails closed on malformed active-read and whole-batch inputs', async () => {
    const fixture = await createStore();
    await expect(fixture.store.getVault('' as never)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(fixture.store.getGroup(vaultId, '' as never)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(collect(fixture.store.listGroups('' as never))).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(fixture.store.getItem(vaultId, '' as never)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(
      collect(fixture.store.listItems(vaultId, '' as never)),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      fixture.store.getCurrentGroup(vaultId, '' as never),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      fixture.store.getCurrentItem(vaultId, '' as never),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      collect(fixture.store.listCurrentItems(vaultId, '' as never)),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      fixture.store.loadPendingTemplateMigrationPublication('' as never),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(fixture.store.enqueueBatch([])).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );

    const duplicate = groupMutation('duplicate-within-batch-01', groupRecord());
    await expect(
      fixture.store.enqueueBatch([duplicate, duplicate]),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      fixture.store.enqueueBatch(Array.from({ length: 101 }, () => duplicate)),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(await fixture.store.listPendingMutations(vaultId)).toEqual([]);
  });

  it('preserves pulled tombstone predecessors, restores exactly, and purges both', async () => {
    const fixture = await createStore();
    const active = groupRecord();
    await fixture.store.applyPullPage(page(1, 'upsert', active));
    const tombstone = tombstoneRecordSchema.parse({
      vaultId,
      entityType: 'group',
      entityId: active.id,
      state: 'deleted',
      tombstoneRevision: 1,
      lastRecordRevision: 0,
      lastCiphertextHash: contentHashForRecord(active),
      deletedAt: timestamp,
    });
    await fixture.store.applyPullPage(page(2, 'tombstone', tombstone));
    expect(await fixture.store.getCurrentGroup(vaultId, active.id)).toEqual({
      state: 'deleted',
      tombstone,
      predecessor: active,
    });

    const restored = encryptedGroupRecordSchema.parse({
      ...active,
      recordRevision: 2,
      updatedAt: '2026-08-10T00:00:02.000Z',
    });
    await fixture.store.applyPullPage(page(3, 'restore', restored));
    expect(await fixture.store.getCurrentGroup(vaultId, active.id)).toEqual({
      state: 'active',
      record: restored,
    });
    await fixture.store.applyPullPage(page(4, 'purge', null, 'group', active.id, 3));
    expect(await fixture.store.getCurrentGroup(vaultId, active.id)).toBeNull();

    const raw = new DatabaseSync(fixture.path, { readOnly: true });
    try {
      expect(
        raw.prepare(`SELECT COUNT(*) AS value FROM deletion_predecessors`).get(),
      ).toEqual({ value: 0 });
    } finally {
      raw.close();
    }
  });

  it('rejects a wrong current-record hash without advancing cursor or records', async () => {
    const fixture = await createStore();
    const input = page(1, 'upsert', groupRecord());
    const change = input.changes[0];
    if (change === undefined) throw new Error('fixture');
    const wrong: ApplyPullPageInput = {
      ...input,
      changes: [
        syncPulledChangeSchema.parse({
          ...change,
          change: { ...change.change, ciphertextHash: digest },
        }),
      ],
    };
    await expect(fixture.store.applyPullPage(wrong)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    expect(await fixture.store.loadCursor(vaultId)).toBeNull();
    expect(await fixture.store.listOpaqueRecords(vaultId)).toEqual([]);
  });

  it('rejects corruption in hidden predecessors and durable queue receipts', async () => {
    const fixture = await createStore();
    const group = groupRecord();
    await enqueueAndComplete(fixture.store, [
      groupMutation('corruption-seed-group-01', group),
    ]);
    const deletion = groupMutation(
      'corruption-delete-key-01',
      deletedGroupRecord(group, 1),
      0,
    );
    await fixture.store.enqueueBatch([deletion]);
    const raw = new DatabaseSync(fixture.path);
    try {
      raw.exec(
        `UPDATE deletion_predecessors
            SET serialized_bytes = serialized_bytes + 1
          WHERE owner_key = 'corruption-delete-key-01'`,
      );
      await expect(
        fixture.store.getCurrentGroup(vaultId, group.id),
      ).rejects.toBeInstanceOf(SyncLocalStateError);
      raw.exec(
        `UPDATE deletion_predecessors
            SET serialized_bytes = serialized_bytes - 1
          WHERE owner_key = 'corruption-delete-key-01'`,
      );
    } finally {
      raw.close();
    }

    await completeExisting(fixture.store, 'corruption-delete-batch', [deletion]);
    const completed = new DatabaseSync(fixture.path);
    try {
      completed.exec(
        `UPDATE completed_mutation_receipts
            SET queue_kind = 'template-migration'
          WHERE idempotency_key = 'corruption-delete-key-01'`,
      );
      await expect(fixture.store.enqueueBatch([deletion])).rejects.toBeInstanceOf(
        SyncLocalStateError,
      );
      completed.exec(
        `UPDATE completed_mutation_receipts
            SET queue_kind = 'generic'
          WHERE idempotency_key = 'corruption-delete-key-01'`,
      );
    } finally {
      completed.close();
    }
    await expect(fixture.store.enqueueBatch([deletion])).resolves.toBeUndefined();

    const activeGroup = groupRecord('group.2');
    const activeItem = itemRecord('item.2', activeGroup.id);
    await enqueueAndComplete(fixture.store, [
      groupMutation('corruption-pub-group-01', activeGroup),
      itemMutation('corruption-pub-item-001', activeItem),
    ]);
    const publication = migrationPublication(activeGroup, activeItem, 1);
    await fixture.store.enqueueTemplateMigrationPublication(publication);
    const pending = new DatabaseSync(fixture.path);
    try {
      pending
        .prepare(
          `UPDATE pending_template_migrations
            SET serialized_bytes = serialized_bytes + 1
          WHERE batch_key = ?`,
        )
        .run(publication.batchIdempotencyKey);
      await expect(
        fixture.store.loadPendingTemplateMigrationPublication(vaultId),
      ).rejects.toBeInstanceOf(SyncLocalStateError);
      pending
        .prepare(
          `UPDATE pending_template_migrations
            SET serialized_bytes = serialized_bytes - 1
          WHERE batch_key = ?`,
        )
        .run(publication.batchIdempotencyKey);
    } finally {
      pending.close();
    }
    expect(
      await fixture.store.loadPendingTemplateMigrationPublication(vaultId),
    ).toEqual(publication);
  });

  it('persists and atomically completes one template migration publication', async () => {
    const fixture = await createStore();
    const group = groupRecord();
    const item = itemRecord();
    await enqueueAndComplete(fixture.store, [
      groupMutation('template-seed-group-001', group),
      itemMutation('template-seed-item-0001', item),
    ]);
    const publication = migrationPublication(group, item, 1);
    await fixture.store.enqueueTemplateMigrationPublication(publication);
    await expect(
      fixture.store.enqueueTemplateMigrationPublication(publication),
    ).resolves.toBeUndefined();
    await expect(
      fixture.store.enqueueTemplateMigrationPublication(
        templateMigrationPublicationRequestSchema.parse({
          ...publication,
          batchIdempotencyKey: 'template-migration-collision-key',
        }),
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(
      await fixture.store.loadPendingTemplateMigrationPublication(vaultId),
    ).toEqual(publication);
    expect((await fixture.store.getGroup(vaultId, group.id))?.recordRevision).toBe(1);

    const response = migrationResponse(publication, 10);
    const wrongHash = templateMigrationPublicationResponseSchema.parse({
      ...response,
      results: response.results.map((result, index) =>
        index === 0
          ? {
              ...result,
              change: { ...result.change, ciphertextHash: WRONG_DIGEST },
            }
          : result,
      ),
    });
    await expect(
      fixture.store.completeTemplateMigrationPublication({
        publication,
        response: wrongHash,
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(await fixture.store.loadOpaqueRecord(vaultId, 'group', group.id)).toEqual(
      group,
    );

    await fixture.store.completeTemplateMigrationPublication({ publication, response });
    await expect(
      fixture.store.completeTemplateMigrationPublication({ publication, response }),
    ).resolves.toBeUndefined();
    await expect(
      fixture.store.completeTemplateMigrationPublication({
        publication,
        response: templateMigrationPublicationResponseSchema.parse({
          ...response,
          serverVaultRevision: response.serverVaultRevision + 1,
        }),
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(
      await fixture.store.loadPendingTemplateMigrationPublication(vaultId),
    ).toBeNull();
    expect(
      (
        (await fixture.store.loadOpaqueRecord(
          vaultId,
          'group',
          group.id,
        )) as EncryptedGroupRecord
      ).recordRevision,
    ).toBe(1);
    expect(await fixture.store.listPendingMutations(vaultId)).toEqual([]);
  });

  it('rejects generic/publication coexistence and prunes old receipts transactionally', async () => {
    const firstGroup = groupRecord('group.1');
    const firstItem = itemRecord('item.1', 'group.1');
    const firstPublication = migrationPublication(firstGroup, firstItem, 1);
    const firstResponse = migrationResponse(firstPublication, 20);
    const firstBytes =
      Buffer.byteLength(JSON.stringify(firstPublication)) +
      Buffer.byteLength(JSON.stringify(firstResponse));
    const fixture = await createStore({
      maxCompletedBatches: 10,
      maxCompletedPublicationBytes: firstBytes + 64,
    });
    await enqueueAndComplete(fixture.store, [
      groupMutation('receipt-seed-group-001', firstGroup),
      itemMutation('receipt-seed-item-0001', firstItem),
    ]);
    await fixture.store.enqueueTemplateMigrationPublication(firstPublication);
    await expect(
      fixture.store.enqueueBatch([
        groupMutation('blocked-generic-key-01', groupRecord('group.blocked')),
      ]),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    const claimedKey = firstPublication.mutations[0]?.idempotencyKey;
    if (claimedKey === undefined) throw new Error('fixture');
    await expect(
      fixture.store.enqueueBatch([
        groupMutation(claimedKey, groupRecord('group.cross-vault', 0, otherVaultId)),
      ]),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await fixture.store.completeTemplateMigrationPublication({
      publication: firstPublication,
      response: firstResponse,
    });

    const secondPublication = migrationPublication(
      firstPublication.mutations.at(-1)?.record as EncryptedGroupRecord,
      firstPublication.mutations[0]?.record as EncryptedItemRecord,
      2,
    );
    const secondResponse = migrationResponse(secondPublication, 30);
    await fixture.store.enqueueTemplateMigrationPublication(secondPublication);
    await fixture.store.completeTemplateMigrationPublication({
      publication: secondPublication,
      response: secondResponse,
    });
    await expect(
      fixture.store.completeTemplateMigrationPublication({
        publication: secondPublication,
        response: secondResponse,
      }),
    ).resolves.toBeUndefined();

    const raw = new DatabaseSync(fixture.path, { readOnly: true });
    try {
      const bounds = raw
        .prepare(
          `SELECT COUNT(*) AS row_count,
                  COALESCE(SUM(serialized_bytes), 0) AS total_bytes
             FROM completed_template_migrations`,
        )
        .get() as { row_count: number; total_bytes: number };
      expect(bounds.row_count).toBe(1);
      expect(bounds.total_bytes).toBeLessThanOrEqual(firstBytes + 64);
    } finally {
      raw.close();
    }
  });

  it('bounds completed mutation receipts while retaining latest exact replay', async () => {
    const fixture = await createStore({ maxCompletedMutations: 1 });
    const first = groupMutation('receipt-generic-key-001', groupRecord('group.1'));
    const second = groupMutation('receipt-generic-key-002', groupRecord('group.2'));
    await enqueueAndComplete(fixture.store, [first], 'generic-receipt-batch-1');
    await enqueueAndComplete(fixture.store, [second], 'generic-receipt-batch-2');
    await expect(fixture.store.enqueueBatch([second])).resolves.toBeUndefined();
    const raw = new DatabaseSync(fixture.path, { readOnly: true });
    try {
      expect(
        raw.prepare(`SELECT COUNT(*) AS value FROM completed_mutation_receipts`).get(),
      ).toEqual({ value: 1 });
    } finally {
      raw.close();
    }
  });

  it('prunes completed push batches by aggregate bytes and retains current replay', async () => {
    const limits = {
      maxCompletedBatches: 10,
      maxCompletedPushBatchBytes: 1_024,
    } as const;
    const fixture = await createStore(limits);
    const first = [1, 2, 3].map((index) =>
      groupMutation(longKey('first', index), groupRecord(`group.${String(index)}`)),
    );
    const second = [4, 5, 6].map((index) =>
      groupMutation(longKey('second', index), groupRecord(`group.${String(index)}`)),
    );
    await enqueueAndComplete(fixture.store, first, 'completed-push-batch-first');
    await enqueueAndComplete(fixture.store, second, 'completed-push-batch-current');

    fixture.store.close();
    const reopened = await openSqliteSyncLocalStore({ path: fixture.path, ...limits });
    stores.push(reopened);
    const exact = {
      vaultId,
      batchIdempotencyKey: 'completed-push-batch-current',
      acknowledgedIdempotencyKeys: second.map((mutation) => mutation.idempotencyKey),
    } as const;
    await expect(reopened.completePushBatch(exact)).resolves.toBeUndefined();
    await expect(
      reopened.completePushBatch({
        ...exact,
        acknowledgedIdempotencyKeys: [],
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      reopened.completePushBatch({
        vaultId,
        batchIdempotencyKey: 'completed-push-batch-first',
        acknowledgedIdempotencyKeys: first.map((mutation) => mutation.idempotencyKey),
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);

    const raw = new DatabaseSync(fixture.path, { readOnly: true });
    try {
      expect(
        raw
          .prepare(
            `SELECT COUNT(*) AS row_count,
                    COALESCE(SUM(serialized_bytes), 0) AS total_bytes
               FROM completed_push_batches`,
          )
          .get(),
      ).toEqual({
        row_count: 1,
        total_bytes: Buffer.byteLength(
          JSON.stringify(exact.acknowledgedIdempotencyKeys),
        ),
      });
    } finally {
      raw.close();
    }
  });

  it.runIf(process.platform === 'win32')(
    'reports after-commit durability uncertainty and exact retry after ACL repair',
    async () => {
      const fixture = await createStore();
      const mutation = groupMutation(
        'durability-unknown-key-1',
        groupRecord('group.uncertain'),
      );
      await grantWindowsEveryoneFullControl(fixture.path);
      await expect(fixture.store.enqueueBatch([mutation])).rejects.toBeInstanceOf(
        OpaqueMutationDurabilityUnknownError,
      );
      await removeWindowsEveryoneGrant(fixture.path);
      const reopened = await openSqliteSyncLocalStore({ path: fixture.path });
      stores.push(reopened);
      await expect(reopened.enqueueBatch([mutation])).resolves.toBeUndefined();
      expect(await reopened.listPendingMutations(vaultId)).toEqual([mutation]);
    },
  );
});

async function createStore(
  limits: Readonly<{
    maxPendingMutations?: number;
    maxCompletedBatches?: number;
    maxCompletedPushBatchBytes?: number;
    maxCompletedMutations?: number;
    maxCompletedPublicationBytes?: number;
  }> = {},
): Promise<Readonly<{ path: string; store: SqliteSyncLocalStore }>> {
  const root = join(
    TEST_TMPDIR,
    `kavrix-vault-adapter-test-${randomUUID().replaceAll('-', '')}`,
  );
  roots.push(root);
  const path = join(root, 'state.sqlite');
  const store = await openSqliteSyncLocalStore({ path, ...limits });
  stores.push(store);
  return { path, store };
}

function longKey(prefix: string, index: number): string {
  return `${prefix}-${String(index)}-${'x'.repeat(230)}`;
}

async function enqueueAndComplete(
  store: SqliteSyncLocalStore,
  mutations: readonly OpaqueMutation[],
  batchKey = `batch-${randomUUID()}`,
): Promise<void> {
  await store.enqueueBatch(mutations);
  await completeExisting(store, batchKey, mutations);
}

async function completeExisting(
  store: SqliteSyncLocalStore,
  batchKey: string,
  mutations: readonly OpaqueMutation[],
): Promise<void> {
  await store.saveActivePushBatch({
    vaultId,
    batchIdempotencyKey: batchKey,
    mutationIdempotencyKeys: mutations.map((mutation) => mutation.idempotencyKey),
  });
  await store.completePushBatch({
    vaultId,
    batchIdempotencyKey: batchKey,
    acknowledgedIdempotencyKeys: mutations.map((mutation) => mutation.idempotencyKey),
  });
}

function vaultMutation(key: string, record: VaultRecord): OpaqueMutation {
  return opaqueMutationSchema.parse({
    entityType: 'vault',
    expectedVaultRevision: null,
    idempotencyKey: key,
    record,
  });
}

function groupMutation(
  key: string,
  record: EncryptedGroupRecord,
  expectedRecordRevision: number | null = null,
): OpaqueMutation {
  return opaqueMutationSchema.parse({
    entityType: 'group',
    expectedRecordRevision,
    idempotencyKey: key,
    record,
  });
}

function itemMutation(
  key: string,
  record: EncryptedItemRecord,
  expectedRecordRevision: number | null = null,
): OpaqueMutation {
  return opaqueMutationSchema.parse({
    entityType: 'item',
    expectedRecordRevision,
    idempotencyKey: key,
    record,
  });
}

function deletedGroupRecord(
  record: EncryptedGroupRecord,
  revision: number,
): EncryptedGroupRecord {
  return encryptedGroupRecordSchema.parse({
    ...record,
    recordRevision: revision,
    updatedAt: timestamp,
    tombstonedAt: timestamp,
  });
}

function deletedItemRecord(
  record: EncryptedItemRecord,
  revision: number,
): EncryptedItemRecord {
  return encryptedItemRecordSchema.parse({
    ...record,
    recordRevision: revision,
    updatedAt: timestamp,
    tombstonedAt: timestamp,
  });
}

function vaultRecord(): VaultRecord {
  return vaultRecordSchema.parse({
    id: vaultId,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [
      {
        slotVersion: 1,
        id: 'slot.1',
        type: 'device-key',
        state: 'active',
        keyVersion: 1,
        derivation: {
          algorithm: 'hkdf-sha256',
          version: 1,
          salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          context: 'credvault/v1/device-key-wrap',
          outputLength: 32,
          provider: 'test-provider',
        },
        wrappedRootKey: envelope('wrapped-root-key', 'vrk-slot', 'slot.1', undefined),
        createdAt: timestamp,
        deviceId: 'device.1',
      },
    ],
    currentKeyVersion: 1,
    revision: 0,
    encryptedPreferences: envelope(
      'vault-preferences',
      'vault-preferences',
      vaultId,
      undefined,
    ),
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

function itemRecord(
  id = 'item.1',
  groupId = 'group.1',
  revision = 0,
): EncryptedItemRecord {
  return encryptedItemRecordSchema.parse({
    id,
    vaultId,
    groupId,
    schemaVersion: 1,
    wrappedItemKey: envelope('wrapped-item-key', 'item-key', id, groupId),
    encryptedPayload: envelope('item', 'item-payload', id, groupId),
    recordRevision: revision,
    ciphertextHash: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

function envelope(
  entityType: 'item' | 'vault-preferences' | 'wrapped-item-key' | 'wrapped-root-key',
  purpose: 'item-key' | 'item-payload' | 'vault-preferences' | 'vrk-slot',
  entityId: string,
  groupId: string | undefined,
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
      purpose,
      ...(groupId === undefined ? {} : { groupId }),
    },
    keyVersion: 1,
  };
}

function page(
  serverSequence: number,
  operation: 'purge' | 'restore' | 'tombstone' | 'upsert',
  record: OpaqueSyncRecord | null,
  entityType: 'group' | 'item' | 'vault' = recordType(record),
  entityId = recordId(record),
  recordRevision = recordRevisionOf(record),
): ApplyPullPageInput {
  const change = changeRecordSchema.parse({
    id: `change.adapter.${String(serverSequence)}`,
    vaultId,
    serverSequence,
    entityType,
    entityId,
    recordRevision,
    operation,
    ...(operation === 'purge'
      ? {}
      : {
          ciphertextHash:
            record !== null && !('state' in record)
              ? contentHashForRecord(record)
              : record !== null && 'state' in record
                ? record.lastCiphertextHash
                : digest,
        }),
    createdAt: timestamp,
  });
  return {
    vaultId,
    changes: [{ change, record }] as readonly SyncPulledChange[],
    cursor: syncCursorSchema.parse({
      vaultId,
      serverSequence,
      highestSeenVaultRevision: serverSequence,
    }),
  };
}

function recordType(record: OpaqueSyncRecord | null): 'group' | 'item' | 'vault' {
  if (record === null) return 'group';
  if ('state' in record) return record.entityType as 'group' | 'item' | 'vault';
  if ('revision' in record) return 'vault';
  return 'groupId' in record ? 'item' : 'group';
}

function recordId(record: OpaqueSyncRecord | null): string {
  if (record === null) return 'group.1';
  return 'state' in record ? record.entityId : record.id;
}

function recordRevisionOf(record: OpaqueSyncRecord | null): number {
  if (record === null) return 0;
  if ('state' in record) return record.tombstoneRevision;
  return 'revision' in record ? record.revision : record.recordRevision;
}

function migrationPublication(
  group: EncryptedGroupRecord,
  item: EncryptedItemRecord,
  nextRevision: number,
): TemplateMigrationPublicationRequest {
  const migratedItem = encryptedItemRecordSchema.parse({
    ...item,
    recordRevision: nextRevision,
    updatedAt: `2026-08-10T00:00:0${String(nextRevision)}.000Z`,
  });
  const migratedGroup = encryptedGroupRecordSchema.parse({
    ...group,
    recordRevision: nextRevision,
    updatedAt: `2026-08-10T00:00:0${String(nextRevision)}.000Z`,
  });
  return templateMigrationPublicationRequestSchema.parse({
    vaultId,
    batchIdempotencyKey: `migration-batch-key-${String(nextRevision).padStart(4, '0')}`,
    mutations: [
      itemMutation(
        `migration-item-key-${String(nextRevision).padStart(5, '0')}`,
        migratedItem,
        nextRevision - 1,
      ),
      groupMutation(
        `migration-group-key-${String(nextRevision).padStart(4, '0')}`,
        migratedGroup,
        nextRevision - 1,
      ),
    ],
  });
}

function migrationResponse(
  publication: TemplateMigrationPublicationRequest,
  firstSequence: number,
): TemplateMigrationPublicationResponse {
  return templateMigrationPublicationResponseSchema.parse({
    vaultId,
    batchIdempotencyKey: publication.batchIdempotencyKey,
    serverVaultRevision: firstSequence + publication.mutations.length,
    results: publication.mutations.map((mutation, index) => ({
      idempotencyKey: mutation.idempotencyKey,
      change: {
        id: `change.migration.${String(firstSequence + index)}`,
        vaultId,
        serverSequence: firstSequence + index,
        entityType: mutation.entityType,
        entityId: mutation.record.id,
        recordRevision:
          'revision' in mutation.record
            ? mutation.record.revision
            : mutation.record.recordRevision,
        operation: 'upsert',
        ciphertextHash: contentHashForRecord(mutation.record),
        createdAt: timestamp,
      },
    })),
  });
}

async function collect<Value>(values: AsyncIterable<Value>): Promise<Value[]> {
  const result: Value[] = [];
  for await (const value of values) result.push(value);
  return result;
}
