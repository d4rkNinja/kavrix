import { randomUUID } from 'node:crypto';
import { realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  encryptedGroupRecordSchema,
  recordRevisionSchema,
  syncCursorSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
  type DeviceId,
  type OpaqueMutation,
} from '@kavrix/schemas';
import {
  createOutboundObservation,
  measureOutboundReconciliationChanges,
} from '@kavrix/sync';
import { afterEach, describe, expect, it } from 'vitest';

import { openSqliteSyncLocalStore, type SqliteSyncLocalStore } from '../src/index.js';
import {
  groupRecord,
  mutation,
  plaintextCanary,
  pullPage,
  timestamp,
  vaultId,
} from './fixtures.js';

const TEST_TMPDIR = await realpath(tmpdir());
const deviceId = 'device.1' as DeviceId;
const roots: string[] = [];
const stores: SqliteSyncLocalStore[] = [];

afterEach(async () => {
  for (const store of stores.splice(0)) store.close();
  for (const root of roots.splice(0)) {
    if (
      dirname(root) !== TEST_TMPDIR ||
      !root.startsWith(join(TEST_TMPDIR, 'kavrix-conflict-test-'))
    ) {
      throw new Error('Refusing to remove an unverified test directory');
    }
    await rm(root, { recursive: true, force: true });
  }
});

describe('durable SQLite sync conflicts', () => {
  it('persists redacted metadata, rejects stale resolution, and retries accept-remote', async () => {
    const fixture = await createStore();
    const queued = await reconcileConflict(fixture.store, 'conflict-accept-0001');

    const listed = await fixture.store.listConflicts(vaultId);
    expect(listed).toEqual([
      {
        vaultId,
        entityType: 'group',
        entityId: queued.record.id,
        idempotencyKey: queued.idempotencyKey,
        expectedRevision: 0,
        currentRevision: 2,
        currentState: 'present',
      },
    ]);
    expect(JSON.stringify(listed)).not.toContain(plaintextCanary);
    fixture.store.close();
    const reopened = await openSqliteSyncLocalStore({ path: fixture.path });
    stores.push(reopened);
    expect(await reopened.listConflicts(vaultId)).toEqual(listed);
    expect(await reopened.listPendingMutations(vaultId)).toEqual([queued]);
    await expect(
      reopened.resolveConflict({
        vaultId,
        conflictId: queued.idempotencyKey,
        currentRevision: recordRevisionSchema.parse(1),
        strategy: 'accept-remote',
        replacementIdempotencyKey: null,
        resolvedAt: timestamp,
      }),
    ).rejects.toThrow();

    const request = {
      vaultId,
      conflictId: queued.idempotencyKey,
      currentRevision: recordRevisionSchema.parse(2),
      strategy: 'accept-remote' as const,
      replacementIdempotencyKey: null,
      resolvedAt: timestamp,
    };
    await expect(reopened.resolveConflict(request)).resolves.toEqual({
      status: 'accepted-remote',
      conflictId: queued.idempotencyKey,
      strategy: 'accept-remote',
      replacementIdempotencyKey: null,
    });
    expect(await reopened.listConflicts(vaultId)).toEqual([]);
    expect(await reopened.listPendingMutations(vaultId)).toEqual([]);
    expect(await reopened.getGroup(vaultId, queued.record.id)).toEqual(
      groupRecord(queued.record.id, 2),
    );
    await expect(reopened.resolveConflict(request)).resolves.toEqual({
      status: 'accepted-remote',
      conflictId: queued.idempotencyKey,
      strategy: 'accept-remote',
      replacementIdempotencyKey: null,
    });
  });

  it('rebases an opaque keep-local mutation to the exact remote revision across restart', async () => {
    const fixture = await createStore();
    const queued = await reconcileConflict(fixture.store, 'conflict-keep-0001');
    const replacementKey = 'conflict-replacement-0001';
    const request = {
      vaultId,
      conflictId: queued.idempotencyKey,
      currentRevision: recordRevisionSchema.parse(2),
      strategy: 'keep-local' as const,
      replacementIdempotencyKey: replacementKey,
      resolvedAt: timestamp,
    };

    const result = await fixture.store.resolveConflict(request);
    expect(result).toEqual({
      status: 'queued-local',
      conflictId: queued.idempotencyKey,
      strategy: 'keep-local',
      replacementIdempotencyKey: replacementKey,
    });
    expect(await fixture.store.listConflicts(vaultId)).toEqual([]);
    const pending = await fixture.store.listPendingMutations(vaultId);
    expect(pending).toHaveLength(1);
    expect(pending[0]).toMatchObject({
      entityType: 'group',
      expectedRecordRevision: 2,
      idempotencyKey: replacementKey,
      record: { recordRevision: 3 },
    });

    fixture.store.close();
    const reopened = await openSqliteSyncLocalStore({ path: fixture.path });
    stores.push(reopened);
    expect(await reopened.listConflicts(vaultId)).toEqual([]);
    expect(await reopened.listPendingMutations(vaultId)).toEqual(pending);
    await expect(reopened.resolveConflict(request)).resolves.toEqual({
      status: 'queued-local',
      conflictId: queued.idempotencyKey,
      strategy: 'keep-local',
      replacementIdempotencyKey: replacementKey,
    });
  });
});

async function createStore(): Promise<
  Readonly<{ path: string; store: SqliteSyncLocalStore }>
> {
  const root = join(
    TEST_TMPDIR,
    `kavrix-conflict-test-${randomUUID().replaceAll('-', '')}`,
  );
  roots.push(root);
  const path = join(root, 'state.sqlite');
  const store = await openSqliteSyncLocalStore({ path });
  stores.push(store);
  return { path, store };
}

async function reconcileConflict(
  store: SqliteSyncLocalStore,
  key: string,
): Promise<OpaqueMutation & { entityType: 'group' }> {
  const base = groupRecord(`group.${key}`);
  await store.applyPullPage(pullPage([base]));
  const queued = mutation(key, groupRecord(base.id, 1), 0);
  await store.enqueueBatch([queued]);
  const request = syncPushRequestSchema.parse({
    vaultId,
    batchIdempotencyKey: `${key}-batch`,
    mutations: [queued],
  });
  await store.saveActivePushBatch({
    vaultId,
    batchIdempotencyKey: request.batchIdempotencyKey,
    mutationIdempotencyKeys: [queued.idempotencyKey],
  });
  const current = encryptedGroupRecordSchema.parse({
    ...base,
    recordRevision: 2,
  });
  const cursor = await store.loadCursor(vaultId);
  if (cursor === null) throw new Error('fixture cursor');
  const finalCursor = syncCursorSchema.parse({
    ...cursor,
    highestSeenVaultRevision: 2,
  });
  const response = syncPushResponseSchema.parse({
    vaultId,
    batchIdempotencyKey: request.batchIdempotencyKey,
    serverVaultRevision: 2,
    results: [
      {
        status: 'conflict',
        idempotencyKey: queued.idempotencyKey,
        currentRevision: recordRevisionSchema.parse(2),
        current,
      },
    ],
  });
  const observation = createOutboundObservation({
    kind: 'generic-push',
    vaultId,
    deviceId,
    request,
    response,
    replayFromServerSequence: cursor.serverSequence,
  });
  await store.reconcileOutboundObservation({
    kind: 'generic-push',
    vaultId,
    deviceId,
    observation,
    request,
    response,
    stagedChanges: [],
    stagedChangesBytes: measureOutboundReconciliationChanges([]),
    finalCursor,
  });
  return queued as OpaqueMutation & { entityType: 'group' };
}
