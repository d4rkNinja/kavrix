import { randomUUID } from 'node:crypto';
import { realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  canonicalJson,
  changeRecordSchema,
  contentHashForRecord,
  encryptedGroupRecordSchema,
  syncCursorSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  type DeviceId,
  type Sha256Digest,
  type SyncPulledChange,
} from '@kavrix/schemas';
import {
  createOutboundObservation,
  MAX_OUTBOUND_RECONCILIATION_BYTES,
  measureOutboundReconciliationChanges,
  type CompletedOutboundObservation,
} from '@kavrix/sync';
import { afterEach, describe, expect, it } from 'vitest';

import { openSqliteSyncLocalStore, type SqliteSyncLocalStore } from '../src/index.js';
import { groupRecord, mutation, otherVaultId, pullPage, vaultId } from './fixtures.js';

const TEST_TMPDIR = await realpath(tmpdir());
const deviceId = 'device.1' as DeviceId;
const roots: string[] = [];
const stores: SqliteSyncLocalStore[] = [];

afterEach(async () => {
  for (const store of stores.splice(0)) store.close();
  for (const root of roots.splice(0)) {
    if (
      dirname(root) !== TEST_TMPDIR ||
      !root.startsWith(join(TEST_TMPDIR, 'kavrix-reconcile-test-'))
    ) {
      throw new Error('Refusing to remove an unverified test directory');
    }
    await rm(root, { recursive: true, force: true });
  }
});

describe('atomic outbound reconciliation', () => {
  it('enforces the shared canonical aggregate at exact row and byte boundaries', () => {
    const canonical = pullPage([groupRecord()]).changes[0];
    if (canonical === undefined) throw new Error('fixture');
    expect(
      measureOutboundReconciliationChanges(
        Array.from({ length: 500 }, () => canonical),
      ),
    ).toBeGreaterThan(0);
    expect(() =>
      measureOutboundReconciliationChanges(
        Array.from({ length: 501 }, () => canonical),
      ),
    ).toThrow();
    expect(() =>
      measureOutboundReconciliationChanges([
        { ...canonical, unexpected: true } as never,
      ]),
    ).toThrow();

    const minimal = largePulledChange(2);
    expect(measureOutboundReconciliationChanges([])).toBe(2);
    const strictPair = [minimal, minimal];
    const independentPairBytes = Buffer.byteLength(canonicalJson(strictPair));
    expect(measureOutboundReconciliationChanges(strictPair)).toBe(independentPairBytes);
    const arrayOverhead = independentPairBytes - 4;
    const totalCiphertextLength = MAX_OUTBOUND_RECONCILIATION_BYTES - arrayOverhead;
    const firstLength = Math.min(22_369_632, totalCiphertextLength - 2);
    const secondLength = totalCiphertextLength - firstLength;
    expect(firstLength % 4).not.toBe(1);
    expect(secondLength % 4).not.toBe(1);
    const exact = [largePulledChange(firstLength), largePulledChange(secondLength)];
    expect(Buffer.byteLength(canonicalJson(exact))).toBe(
      MAX_OUTBOUND_RECONCILIATION_BYTES,
    );
    expect(measureOutboundReconciliationChanges(exact)).toBe(
      MAX_OUTBOUND_RECONCILIATION_BYTES,
    );
    expect(() =>
      measureOutboundReconciliationChanges([
        largePulledChange(firstLength),
        largePulledChange(secondLength + 1),
      ]),
    ).toThrow();
  });

  it('binds replay starts exactly for both outbound kinds and rejects mismatches', async () => {
    const generic = await createStore();
    const queued = mutation('replay-generic-key-1');
    await generic.enqueueBatch([queued]);
    await generic.saveActivePushBatch({
      vaultId,
      batchIdempotencyKey: 'replay-generic-batch-1',
      mutationIdempotencyKeys: [queued.idempotencyKey],
    });
    await expect(
      generic.ensureOutboundReplayStart({
        kind: 'generic-push',
        vaultId,
        batchIdempotencyKey: 'replay-generic-batch-1',
      }),
    ).resolves.toBe(0);
    await expect(
      generic.ensureOutboundReplayStart({
        kind: 'template-publication',
        vaultId,
        batchIdempotencyKey: 'replay-generic-batch-1',
      }),
    ).rejects.toThrow();
    await expect(
      generic.ensureOutboundReplayStart({
        kind: 'generic-push',
        vaultId,
        batchIdempotencyKey: 'wrong-replay-batch',
      }),
    ).rejects.toThrow();

    const publicationStore = await createStore();
    const publicationBase = groupRecord('group.replay-template', 0);
    await publicationStore.applyPullPage(pullPage([publicationBase]));
    const publication = templateMigrationPublicationRequestSchema.parse({
      vaultId,
      batchIdempotencyKey: 'replay-template-batch-1',
      mutations: [
        mutation('replay-template-key-1', groupRecord(publicationBase.id, 1), 0),
      ],
    });
    await publicationStore.enqueueTemplateMigrationPublication(publication);
    await expect(
      publicationStore.ensureOutboundReplayStart({
        kind: 'template-publication',
        vaultId,
        batchIdempotencyKey: publication.batchIdempotencyKey,
      }),
    ).resolves.toBe(1);
    expect(
      await publicationStore.loadOutboundReplayState(vaultId, 'template-publication'),
    ).toMatchObject({ replayFromServerSequence: 1 });
  });
  it('applies the exact generic feed and finalizes the request in one idempotent transaction', async () => {
    const store = await createStore();
    const record = groupRecord();
    const queued = mutation('mutation-key-0001', record);
    const request = syncPushRequestSchema.parse({
      vaultId,
      batchIdempotencyKey: 'batch-key-0000001',
      mutations: [queued],
    });
    if (queued.entityType !== 'group') throw new Error('fixture');
    const page = pullPage([queued.record]);
    const acceptedChange = page.changes[0]?.change;
    if (acceptedChange === undefined) throw new Error('fixture');
    const response = syncPushResponseSchema.parse({
      vaultId,
      batchIdempotencyKey: request.batchIdempotencyKey,
      serverVaultRevision: 1,
      results: [
        {
          status: 'accepted',
          disposition: 'committed',
          idempotencyKey: queued.idempotencyKey,
          change: acceptedChange,
        },
      ],
    });
    const observation = createOutboundObservation({
      kind: 'generic-push',
      vaultId,
      deviceId,
      request,
      response,
      replayFromServerSequence: 0,
    });

    await store.enqueueBatch([queued]);
    await store.saveActivePushBatch({
      vaultId,
      batchIdempotencyKey: request.batchIdempotencyKey,
      mutationIdempotencyKeys: [queued.idempotencyKey],
    });
    const input = {
      kind: 'generic-push',
      vaultId,
      deviceId,
      observation,
      request,
      response,
      stagedChanges: page.changes,
      stagedChangesBytes: measureOutboundReconciliationChanges(page.changes),
      finalCursor: page.cursor,
    } as const;

    const first = await store.reconcileOutboundObservation(input);
    const replay = await store.reconcileOutboundObservation(input);

    expect(first).toEqual(replay);
    expect(first.observation.observationId).toBe(observation.observationId);
    const canonicalReceipt = {
      kind: first.kind,
      vaultId: first.vaultId,
      deviceId: first.deviceId,
      observation: first.observation,
      request: first.request,
      response: first.response,
      finalCursor: first.finalCursor,
    };
    expect(first.serializedBytes).toBe(
      Buffer.byteLength(canonicalJson(canonicalReceipt)),
    );
    expect(
      await store.loadCompletedOutboundObservation(vaultId, observation.observationId),
    ).toEqual(first);
    await expect(
      store.confirmCompletedOutboundObservation(
        vaultId,
        'device.other' as DeviceId,
        observation,
      ),
    ).rejects.toThrow();
    await expect(
      store.loadCompletedOutboundObservation(otherVaultId, observation.observationId),
    ).rejects.toThrow();
    expect(await store.loadCursor(vaultId)).toEqual(page.cursor);
    expect(await store.loadActivePushBatch(vaultId)).toBeNull();
    expect(await store.listPendingMutations(vaultId)).toEqual([]);
    expect(await store.loadOpaqueRecord(vaultId, 'group', queued.record.id)).toEqual(
      queued.record,
    );
  });

  it('acknowledges an accepted historical sequence at C without downgrading base state', async () => {
    const store = await createStore();
    const record = groupRecord();
    const queued = mutation('historical-key-0001', record);
    const page = pullPage([record]);
    await store.enqueueBatch([queued]);
    await store.applyPullPage(page);
    const request = syncPushRequestSchema.parse({
      vaultId,
      batchIdempotencyKey: 'historical-batch-001',
      mutations: [queued],
    });
    await store.saveActivePushBatch({
      vaultId,
      batchIdempotencyKey: request.batchIdempotencyKey,
      mutationIdempotencyKeys: [queued.idempotencyKey],
    });
    const change = page.changes[0]?.change;
    if (change === undefined) throw new Error('fixture');
    const response = syncPushResponseSchema.parse({
      vaultId,
      batchIdempotencyKey: request.batchIdempotencyKey,
      serverVaultRevision: 1,
      results: [
        {
          status: 'accepted',
          disposition: 'committed',
          idempotencyKey: queued.idempotencyKey,
          change,
        },
      ],
    });
    const observation = createOutboundObservation({
      kind: 'generic-push',
      vaultId,
      deviceId,
      request,
      response,
      replayFromServerSequence: 1,
    });
    const input = {
      kind: 'generic-push',
      vaultId,
      deviceId,
      observation,
      request,
      response,
      stagedChanges: [],
      stagedChangesBytes: measureOutboundReconciliationChanges([]),
      finalCursor: page.cursor,
    } as const;

    await expect(store.reconcileOutboundObservation(input)).resolves.toMatchObject({
      observation,
      finalCursor: page.cursor,
    });
    expect(await store.loadOpaqueRecord(vaultId, 'group', record.id)).toEqual(record);
    expect(await store.listPendingMutations(vaultId)).toEqual([]);
  });

  it('reconciles an exact template publication and validates every child row', async () => {
    const store = await createStore();
    const base = groupRecord();
    const initial = pullPage([base]);
    await store.applyPullPage(initial);
    const updated = groupRecord(base.id, 1);
    const publication = templateMigrationPublicationRequestSchema.parse({
      vaultId,
      batchIdempotencyKey: 'template-batch-key-001',
      mutations: [mutation('template-mutation-001', updated, 0)],
    });
    await store.enqueueTemplateMigrationPublication(publication);
    const change = changeRecordSchema.parse({
      id: 'change.2',
      vaultId,
      serverSequence: 2,
      entityType: 'group',
      entityId: updated.id,
      recordRevision: 1,
      operation: 'upsert',
      ciphertextHash: contentHashForRecord(updated),
      createdAt: '2026-08-10T00:00:00.000Z',
    });
    const response = templateMigrationPublicationResponseSchema.parse({
      vaultId,
      batchIdempotencyKey: publication.batchIdempotencyKey,
      serverVaultRevision: 2,
      results: [{ idempotencyKey: publication.mutations[0]?.idempotencyKey, change }],
    });
    const observation = createOutboundObservation({
      kind: 'template-publication',
      vaultId,
      deviceId,
      request: publication,
      response,
      replayFromServerSequence: 1,
    });
    const stagedChanges = [{ change, record: updated }] as const;
    const finalCursor = syncCursorSchema.parse({
      vaultId,
      serverSequence: 2,
      highestSeenVaultRevision: 2,
    });
    const receipt = await store.reconcileOutboundObservation({
      kind: 'template-publication',
      vaultId,
      deviceId,
      observation,
      request: publication,
      response,
      stagedChanges,
      stagedChangesBytes: measureOutboundReconciliationChanges(stagedChanges),
      finalCursor,
    });

    expect(receipt.kind).toBe('template-publication');
    expect(await store.loadPendingTemplateMigrationPublication(vaultId)).toBeNull();
    expect(await store.loadOpaqueRecord(vaultId, 'group', updated.id)).toEqual(updated);
    await expect(
      store.enqueueTemplateMigrationPublication(publication),
    ).resolves.toBeUndefined();
    await expect(
      store.confirmCompletedOutboundObservation(vaultId, deviceId, observation),
    ).resolves.toEqual(receipt);
  });

  it('rejects a supplied aggregate-byte mismatch without changing cursor or active work', async () => {
    const store = await createStore();
    const record = groupRecord();
    const queued = mutation('byte-mismatch-key-1', record);
    const request = syncPushRequestSchema.parse({
      vaultId,
      batchIdempotencyKey: 'byte-mismatch-batch-1',
      mutations: [queued],
    });
    const page = pullPage([record]);
    const change = page.changes[0]?.change;
    if (change === undefined) throw new Error('fixture');
    const response = syncPushResponseSchema.parse({
      vaultId,
      batchIdempotencyKey: request.batchIdempotencyKey,
      serverVaultRevision: 1,
      results: [
        {
          status: 'accepted',
          disposition: 'committed',
          idempotencyKey: queued.idempotencyKey,
          change,
        },
      ],
    });
    const observation = createOutboundObservation({
      kind: 'generic-push',
      vaultId,
      deviceId,
      request,
      response,
      replayFromServerSequence: 0,
    });
    await store.enqueueBatch([queued]);
    await store.saveActivePushBatch({
      vaultId,
      batchIdempotencyKey: request.batchIdempotencyKey,
      mutationIdempotencyKeys: [queued.idempotencyKey],
    });

    await expect(
      store.reconcileOutboundObservation({
        kind: 'generic-push',
        vaultId,
        deviceId,
        observation,
        request,
        response,
        stagedChanges: page.changes,
        stagedChangesBytes: measureOutboundReconciliationChanges(page.changes) + 1,
        finalCursor: page.cursor,
      }),
    ).rejects.toThrow();
    expect(await store.loadCursor(vaultId)).toBeNull();
    expect(await store.loadActivePushBatch(vaultId)).not.toBeNull();
    expect(await store.listPendingMutations(vaultId)).toEqual([queued]);
  });

  it('rolls back an earlier staged write when a later same-entity revision is invalid', async () => {
    const store = await createStore();
    const acceptedRecord = groupRecord('group.rollback', 0);
    const queued = mutation('rollback-key-0001', acceptedRecord);
    const request = syncPushRequestSchema.parse({
      vaultId,
      batchIdempotencyKey: 'rollback-batch-0001',
      mutations: [queued],
    });
    await store.enqueueBatch([queued]);
    await store.saveActivePushBatch({
      vaultId,
      batchIdempotencyKey: request.batchIdempotencyKey,
      mutationIdempotencyKeys: [queued.idempotencyKey],
    });
    const externalRecord = groupRecord('group.rollback', 5);
    const external = pullPage([externalRecord]).changes[0];
    if (external === undefined) throw new Error('fixture');
    const acceptedChange = changeRecordSchema.parse({
      id: 'change.2',
      vaultId,
      serverSequence: 2,
      entityType: 'group',
      entityId: acceptedRecord.id,
      recordRevision: acceptedRecord.recordRevision,
      operation: 'upsert',
      ciphertextHash: contentHashForRecord(acceptedRecord),
      createdAt: '2026-08-10T00:00:00.000Z',
    });
    const response = syncPushResponseSchema.parse({
      vaultId,
      batchIdempotencyKey: request.batchIdempotencyKey,
      serverVaultRevision: 5,
      results: [
        {
          status: 'accepted',
          disposition: 'committed',
          idempotencyKey: queued.idempotencyKey,
          change: acceptedChange,
        },
      ],
    });
    const observation = createOutboundObservation({
      kind: 'generic-push',
      vaultId,
      deviceId,
      request,
      response,
      replayFromServerSequence: 0,
    });
    const stagedChanges = [
      external,
      { change: acceptedChange, record: acceptedRecord },
    ];
    const finalCursor = syncCursorSchema.parse({
      vaultId,
      serverSequence: 2,
      highestSeenVaultRevision: 5,
    });
    await expect(
      store.reconcileOutboundObservation({
        kind: 'generic-push',
        vaultId,
        deviceId,
        observation,
        request,
        response,
        stagedChanges,
        stagedChangesBytes: measureOutboundReconciliationChanges(stagedChanges),
        finalCursor,
      }),
    ).rejects.toThrow();
    expect(await store.loadCursor(vaultId)).toBeNull();
    expect(
      await store.loadOpaqueRecord(vaultId, 'group', externalRecord.id),
    ).toBeNull();
    expect(await store.listPendingMutations(vaultId)).toEqual([queued]);
    expect(await store.loadActivePushBatch(vaultId)).not.toBeNull();
    expect(
      await store.loadCompletedOutboundObservation(vaultId, observation.observationId),
    ).toBeNull();
  });

  it('fails closed rather than pruning another vault unresolved receipt', async () => {
    const store = await createStore({
      maxCompletedBatches: 1,
      maxCompletedMutations: 1,
    });
    const retained = await reconcileSingleGeneric(store, otherVaultId, 'other-vault');

    await expect(
      reconcileSingleGeneric(store, vaultId, 'current-vault'),
    ).rejects.toThrow();

    expect(
      await store.loadCompletedOutboundObservation(
        otherVaultId,
        retained.observation.observationId,
      ),
    ).toEqual(retained);
    expect(await store.loadCursor(vaultId)).toBeNull();
    expect(await store.loadActivePushBatch(vaultId)).not.toBeNull();
    expect(await store.listPendingMutations(vaultId)).toHaveLength(1);
  });

  it('persists the exact pin across reopen and releases only the bound tuple', async () => {
    const fixture = await createStoreFixture();
    const receipt = await reconcileSingleGeneric(fixture.store, vaultId, 'reopen-pin');
    fixture.store.close();
    const reopened = await openSqliteSyncLocalStore({ path: fixture.path });
    stores.push(reopened);

    await expect(
      reopened.confirmCompletedOutboundObservation(
        vaultId,
        deviceId,
        receipt.observation,
      ),
    ).resolves.toEqual(receipt);
    await expect(
      reopened.releaseCompletedOutboundObservation(
        vaultId,
        'device.other' as DeviceId,
        receipt.observation.observationId,
      ),
    ).rejects.toThrow();
    await expect(
      reopened.confirmCompletedOutboundObservation(
        vaultId,
        deviceId,
        receipt.observation,
      ),
    ).resolves.toEqual(receipt);
    await expect(
      reopened.releaseCompletedOutboundObservation(
        vaultId,
        deviceId,
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as Sha256Digest,
      ),
    ).rejects.toThrow();
    await expect(
      reopened.confirmCompletedOutboundObservation(
        vaultId,
        deviceId,
        receipt.observation,
      ),
    ).resolves.toEqual(receipt);
    await expect(
      reopened.releaseCompletedOutboundObservation(
        otherVaultId,
        deviceId,
        receipt.observation.observationId,
      ),
    ).rejects.toThrow();
    await expect(
      reopened.confirmCompletedOutboundObservation(
        vaultId,
        deviceId,
        receipt.observation,
      ),
    ).resolves.toEqual(receipt);
    await expect(
      reopened.releaseCompletedOutboundObservation(
        vaultId,
        deviceId,
        receipt.observation.observationId,
      ),
    ).resolves.toBeUndefined();
    reopened.close();
    const released = await openSqliteSyncLocalStore({ path: fixture.path });
    stores.push(released);
    await expect(
      released.releaseCompletedOutboundObservation(
        vaultId,
        deviceId,
        receipt.observation.observationId,
      ),
    ).resolves.toBeUndefined();
    await expect(
      released.confirmCompletedOutboundObservation(
        vaultId,
        deviceId,
        receipt.observation,
      ),
    ).rejects.toThrow();
  });

  it('rolls back newer same-vault work while an older exact receipt stays pinned', async () => {
    const fixture = await createStoreFixture({
      maxCompletedBatches: 1,
      maxCompletedMutations: 1,
    });
    const retained = await reconcileSingleGeneric(
      fixture.store,
      vaultId,
      'same-vault-old',
    );

    await expect(
      reconcileSingleGeneric(fixture.store, vaultId, 'same-vault-new'),
    ).rejects.toThrow();
    expect(await fixture.store.loadCursor(vaultId)).toEqual(retained.finalCursor);
    expect(await fixture.store.loadActivePushBatch(vaultId)).not.toBeNull();
    expect(await fixture.store.listPendingMutations(vaultId)).toHaveLength(1);
    fixture.store.close();

    const reopened = await openSqliteSyncLocalStore({ path: fixture.path });
    stores.push(reopened);
    await expect(
      reopened.confirmCompletedOutboundObservation(
        vaultId,
        deviceId,
        retained.observation,
      ),
    ).resolves.toEqual(retained);
  });

  it('prunes released receipts across vaults and replaces only a released pin', async () => {
    const store = await createStore({
      maxCompletedBatches: 1,
      maxCompletedMutations: 1,
    });
    const first = await reconcileSingleGeneric(store, otherVaultId, 'released-old');
    await store.releaseCompletedOutboundObservation(
      otherVaultId,
      deviceId,
      first.observation.observationId,
    );

    const current = await reconcileSingleGeneric(store, vaultId, 'released-new');
    expect(
      await store.loadCompletedOutboundObservation(
        otherVaultId,
        first.observation.observationId,
      ),
    ).toBeNull();
    await expect(
      store.releaseCompletedOutboundObservation(
        otherVaultId,
        deviceId,
        first.observation.observationId,
      ),
    ).resolves.toBeUndefined();
    await expect(
      store.confirmCompletedOutboundObservation(vaultId, deviceId, current.observation),
    ).resolves.toEqual(current);
    await store.releaseCompletedOutboundObservation(
      vaultId,
      deviceId,
      current.observation.observationId,
    );
    const replacement = await reconcileSingleGeneric(
      store,
      vaultId,
      'released-replacement',
    );
    expect(
      await store.loadCompletedOutboundObservation(
        vaultId,
        current.observation.observationId,
      ),
    ).toBeNull();
    await expect(
      store.confirmCompletedOutboundObservation(
        vaultId,
        deviceId,
        replacement.observation,
      ),
    ).resolves.toEqual(replacement);
  });

  it('rejects a tampered mutation claim while its exact observation is pinned', async () => {
    const fixture = await createStoreFixture();
    await reconcileSingleGeneric(fixture.store, vaultId, 'tampered-claim');
    fixture.store.close();

    const raw = new DatabaseSync(fixture.path);
    try {
      raw
        .prepare(
          `UPDATE completed_mutation_receipts
              SET queue_kind = 'template-migration'
            WHERE vault_id = ?`,
        )
        .run(vaultId);
    } finally {
      raw.close();
    }

    await expect(openSqliteSyncLocalStore({ path: fixture.path })).rejects.toThrow();
  });
});

async function createStore(
  limits: Readonly<{
    maxCompletedBatches?: number;
    maxCompletedMutations?: number;
  }> = {},
): Promise<SqliteSyncLocalStore> {
  return (await createStoreFixture(limits)).store;
}

async function createStoreFixture(
  limits: Readonly<{
    maxCompletedBatches?: number;
    maxCompletedMutations?: number;
  }> = {},
): Promise<Readonly<{ path: string; store: SqliteSyncLocalStore }>> {
  const root = join(
    TEST_TMPDIR,
    `kavrix-reconcile-test-${randomUUID().replaceAll('-', '')}`,
  );
  roots.push(root);
  const path = join(root, 'state.sqlite');
  const store = await openSqliteSyncLocalStore({
    path,
    ...limits,
  });
  stores.push(store);
  return { path, store };
}

async function reconcileSingleGeneric(
  store: SqliteSyncLocalStore,
  recordVaultId: typeof vaultId,
  suffix: string,
): Promise<CompletedOutboundObservation> {
  const cursor = await store.loadCursor(recordVaultId);
  const replayFromServerSequence = cursor?.serverSequence ?? 0;
  const highestSeenVaultRevision = cursor?.highestSeenVaultRevision ?? 0;
  const record = groupRecord(`group.${suffix}`, 0, recordVaultId);
  const queued = mutation(`mutation-${suffix}-0001`, record);
  const request = syncPushRequestSchema.parse({
    vaultId: recordVaultId,
    batchIdempotencyKey: `batch-${suffix}-0001`,
    mutations: [queued],
  });
  const change = changeRecordSchema.parse({
    id: `change.${suffix}`,
    vaultId: recordVaultId,
    serverSequence: replayFromServerSequence + 1,
    entityType: 'group',
    entityId: record.id,
    recordRevision: record.recordRevision,
    operation: 'upsert',
    ciphertextHash: contentHashForRecord(record),
    createdAt: '2026-08-10T00:00:00.000Z',
  });
  const finalCursor = syncCursorSchema.parse({
    vaultId: recordVaultId,
    serverSequence: replayFromServerSequence + 1,
    highestSeenVaultRevision: Math.max(
      highestSeenVaultRevision,
      replayFromServerSequence + 1,
    ),
  });
  const response = syncPushResponseSchema.parse({
    vaultId: recordVaultId,
    batchIdempotencyKey: request.batchIdempotencyKey,
    serverVaultRevision: finalCursor.highestSeenVaultRevision,
    results: [
      {
        status: 'accepted',
        disposition: 'committed',
        idempotencyKey: queued.idempotencyKey,
        change,
      },
    ],
  });
  const observation = createOutboundObservation({
    kind: 'generic-push',
    vaultId: recordVaultId,
    deviceId,
    request,
    response,
    replayFromServerSequence,
  });
  await store.enqueueBatch([queued]);
  await store.saveActivePushBatch({
    vaultId: recordVaultId,
    batchIdempotencyKey: request.batchIdempotencyKey,
    mutationIdempotencyKeys: [queued.idempotencyKey],
  });
  return store.reconcileOutboundObservation({
    kind: 'generic-push',
    vaultId: recordVaultId,
    deviceId,
    observation,
    request,
    response,
    stagedChanges: [{ change, record }],
    stagedChangesBytes: measureOutboundReconciliationChanges([{ change, record }]),
    finalCursor,
  });
}

function largePulledChange(ciphertextLength: number): SyncPulledChange {
  const record = encryptedGroupRecordSchema.parse({
    ...groupRecord(),
    encryptedPayload: {
      ...groupRecord().encryptedPayload,
      ciphertext: 'A'.repeat(ciphertextLength),
    },
  });
  const change = pullPage([record]).changes[0];
  if (change === undefined) throw new Error('fixture');
  return change;
}
