import { randomUUID } from 'node:crypto';
import { realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  protectedLocalDeviceStateSchema,
  syncPushResponseSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  type DeviceId,
  type ProtectedLocalDeviceState,
  type Sha256Digest,
  type TemplateMigrationPublicationResponse,
  type TemplateMigrationPublicationRequest,
} from '@kavrix/schemas';
import {
  SyncEngine,
  SyncLocalStateError,
  type ProtectedSyncStatePort,
  type PullPageRequest,
  type PullPageResponse,
  type PushBatchRequest,
  type PushBatchResponse,
  type ReconcileOutboundObservationInput,
  type SyncLocalStorePort,
  type SyncStatus,
  type SyncTransportPort,
} from '../../sync/src/index.js';
import { afterEach, describe, expect, it } from 'vitest';

import { openSqliteSyncLocalStore, type SqliteSyncLocalStore } from '../src/index.js';
import { groupRecord, mutation, pullPage, timestamp, vaultId } from './fixtures.js';

const TEST_TMPDIR = await realpath(tmpdir());
const deviceId = 'device.1' as DeviceId;
const roots: string[] = [];
const stores: SqliteSyncLocalStore[] = [];

afterEach(async () => {
  for (const store of stores.splice(0)) store.close();
  for (const root of roots.splice(0)) {
    if (
      dirname(root) !== TEST_TMPDIR ||
      !root.startsWith(join(TEST_TMPDIR, 'kavrix-rollback-recovery-'))
    ) {
      throw new Error('Refusing to remove an unverified test directory');
    }
    await rm(root, { recursive: true, force: true });
  }
});

describe('rollback anchor crash recovery with real SQLite', () => {
  it('reopens after reconcile commits then throws and confirms the exact receipt without network', async () => {
    const root = join(
      TEST_TMPDIR,
      `kavrix-rollback-recovery-${randomUUID().replaceAll('-', '')}`,
    );
    roots.push(root);
    const path = join(root, 'state.sqlite');
    const initial = await openSqliteSyncLocalStore({ path });
    stores.push(initial);
    const queued = mutation('rollback-reopen-mutation-0001');
    if (queued.entityType !== 'group') throw new Error('fixture');
    await initial.enqueueBatch([queued]);
    const response = acceptedResponse(queued, 'rollback-reopen-batch-0001');
    const feed = pullPage([queued.record]);
    const transport = new ScriptedTransport(
      [emptyPage(0, 0), pullResponse(feed)],
      [response],
    );
    const protectedState = new DeterministicProtectedState();
    const failAfter = failAfterReconcile(initial);

    await expect(
      engine(failAfter, transport, protectedState).synchronize({
        vaultId,
        deviceId,
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(protectedState.value?.outboundObservation).toBeDefined();
    initial.close();

    const reopened = await openSqliteSyncLocalStore({ path });
    stores.push(reopened);
    const pendingObservation = protectedState.value?.outboundObservation;
    if (pendingObservation === undefined) throw new Error('fixture');
    expect(await reopened.loadCursor(vaultId)).toMatchObject({
      serverSequence: 1,
      highestSeenVaultRevision: 1,
    });
    expect(await reopened.loadActivePushBatch(vaultId)).toBeNull();
    expect(await reopened.listPendingMutations(vaultId)).toEqual([]);
    await expect(
      reopened.confirmCompletedOutboundObservation(
        vaultId,
        deviceId,
        pendingObservation,
      ),
    ).resolves.toMatchObject({
      observation: pendingObservation,
      finalCursor: { serverSequence: 1, highestSeenVaultRevision: 1 },
    });
    const replayTransport = new ScriptedTransport([emptyPage(1, 1)]);
    await expect(
      engine(reopened, replayTransport, protectedState).synchronize({
        vaultId,
        deviceId,
      }),
    ).resolves.toMatchObject({ state: 'synced', pushedMutations: 1 });

    expect(replayTransport.pushRequests).toHaveLength(0);
    expect(await reopened.loadCursor(vaultId)).toMatchObject({
      serverSequence: 1,
      highestSeenVaultRevision: 1,
    });
    expect(await reopened.loadActivePushBatch(vaultId)).toBeNull();
    expect(await reopened.listPendingMutations(vaultId)).toEqual([]);
    expect(protectedState.value?.outboundObservation).toBeUndefined();
    expect(protectedState.value?.lastCompletedObservationId).toBeDefined();
  });

  it('reopens after protected clear commits then throws and releases the exact pin before pull', async () => {
    const root = join(
      TEST_TMPDIR,
      `kavrix-rollback-recovery-${randomUUID().replaceAll('-', '')}`,
    );
    roots.push(root);
    const path = join(root, 'state.sqlite');
    const initial = await openSqliteSyncLocalStore({ path });
    stores.push(initial);
    const queued = mutation('rollback-clear-mutation-0001');
    if (queued.entityType !== 'group') throw new Error('fixture');
    await initial.enqueueBatch([queued]);
    const response = acceptedResponse(queued, 'rollback-reopen-batch-0001');
    const feed = pullPage([queued.record]);
    const transport = new ScriptedTransport(
      [emptyPage(0, 0), pullResponse(feed)],
      [response],
    );
    const protectedState = new DeterministicProtectedState();
    protectedState.failAfterComplete = true;

    await expect(
      engine(initial, transport, protectedState).synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(protectedState.value?.outboundObservation).toBeUndefined();
    const completedId = protectedState.value?.lastCompletedObservationId;
    expect(completedId).toBeDefined();
    initial.close();

    const reopened = await openSqliteSyncLocalStore({ path });
    stores.push(reopened);
    expect(await reopened.loadCursor(vaultId)).toMatchObject({ serverSequence: 1 });
    if (completedId === undefined) throw new Error('fixture');
    expect(
      await reopened.loadCompletedOutboundObservation(vaultId, completedId),
    ).not.toBeNull();
    const replayTransport = new ScriptedTransport([emptyPage(1, 1)]);
    await expect(
      engine(reopened, replayTransport, protectedState).synchronize({
        vaultId,
        deviceId,
      }),
    ).resolves.toMatchObject({ state: 'synced' });
    expect(replayTransport.pushRequests).toHaveLength(0);
    await expect(
      reopened.releaseCompletedOutboundObservation(vaultId, deviceId, completedId),
    ).resolves.toBeUndefined();
  });

  it('reopens a template publication after reconcile commits then throws without replaying the publication', async () => {
    const root = join(
      TEST_TMPDIR,
      `kavrix-rollback-recovery-${randomUUID().replaceAll('-', '')}`,
    );
    roots.push(root);
    const path = join(root, 'state.sqlite');
    const initial = await openSqliteSyncLocalStore({ path });
    stores.push(initial);
    const base = groupRecord('group.template-recovery', 0);
    await initial.applyPullPage(pullPage([base]));
    const updated = groupRecord(base.id, 1);
    const queued = mutation('template-recovery-key-0001', updated, 0);
    const publication = templateMigrationPublicationRequestSchema.parse({
      vaultId,
      batchIdempotencyKey: 'template-recovery-batch-0001',
      mutations: [queued],
    });
    await initial.enqueueTemplateMigrationPublication(publication);
    const page = pullPage([base, updated], 2);
    const templateChange = page.changes[1]?.change;
    if (templateChange === undefined) throw new Error('fixture');
    const response = templateMigrationPublicationResponseSchema.parse({
      vaultId,
      batchIdempotencyKey: publication.batchIdempotencyKey,
      serverVaultRevision: 2,
      results: [{ idempotencyKey: queued.idempotencyKey, change: templateChange }],
    });
    const transport = new ScriptedTransport(
      [pullResponseFrom(2, 2, page.changes.slice(1))],
      [],
      [response],
    );
    const protectedState = new DeterministicProtectedState();

    await expect(
      engine(failAfterReconcile(initial), transport, protectedState).synchronize({
        vaultId,
        deviceId,
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    initial.close();
    const reopened = await openSqliteSyncLocalStore({ path });
    stores.push(reopened);
    expect(await reopened.loadCursor(vaultId)).toMatchObject({ serverSequence: 2 });
    expect(await reopened.loadPendingTemplateMigrationPublication(vaultId)).toBeNull();
    const replayTransport = new ScriptedTransport([emptyPage(2, 2)]);
    await expect(
      engine(reopened, replayTransport, protectedState).synchronize({
        vaultId,
        deviceId,
      }),
    ).resolves.toMatchObject({
      state: 'synced',
      pulledChanges: 1,
      pushedMutations: 1,
    });
    expect(replayTransport.publicationRequests).toHaveLength(0);
  });
});

function engine(
  local: SyncLocalStorePort,
  transport: SyncTransportPort,
  protectedState: ProtectedSyncStatePort,
): SyncEngine {
  let keyIndex = 0;
  return new SyncEngine({
    local,
    transport,
    protectedState,
    status: {
      set: (status: SyncStatus) => {
        void status;
        return Promise.resolve();
      },
    },
    clock: { now: () => new Date(timestamp) },
    idempotencyKeys: {
      next: () => {
        keyIndex += 1;
        return keyIndex === 1
          ? 'rollback-reopen-batch-0001'
          : `rollback-reopen-batch-${String(keyIndex).padStart(4, '0')}`;
      },
    },
  });
}

function failAfterReconcile(store: SqliteSyncLocalStore): SyncLocalStorePort {
  const wrapper = new Proxy(Object.create(null) as object, {
    get(target, property) {
      void target;
      if (property === 'reconcileOutboundObservation') {
        return async (input: ReconcileOutboundObservationInput) => {
          await store.reconcileOutboundObservation(input);
          throw new Error('ambiguous-local-commit-canary');
        };
      }
      const value: unknown = Reflect.get(store, property, store);
      if (typeof value !== 'function') return value;
      const method = value as (...args: unknown[]) => unknown;
      return (...args: unknown[]) => Reflect.apply(method, store, args);
    },
  });
  return wrapper as SyncLocalStorePort;
}

class DeterministicProtectedState implements ProtectedSyncStatePort {
  value: ProtectedLocalDeviceState | null = null;
  failAfterComplete = false;

  load(): Promise<ProtectedLocalDeviceState | null> {
    return Promise.resolve(this.value);
  }

  save(state: ProtectedLocalDeviceState): Promise<void> {
    this.value = protectedLocalDeviceStateSchema.parse(state);
    return Promise.resolve();
  }

  completeObservation(
    _vaultId: typeof vaultId,
    _deviceId: DeviceId,
    expectedObservationId: Sha256Digest,
    candidateRevision: ProtectedLocalDeviceState['highestSeenVaultRevision'],
    updatedAt: ProtectedLocalDeviceState['updatedAt'],
  ): Promise<void> {
    if (this.value?.outboundObservation?.observationId !== expectedObservationId) {
      return Promise.reject(new Error('protected observation mismatch'));
    }
    this.value = protectedLocalDeviceStateSchema.parse({
      version: 2,
      vaultId,
      deviceId,
      highestSeenVaultRevision: candidateRevision,
      updatedAt,
      lastCompletedObservationId: expectedObservationId,
    });
    if (this.failAfterComplete) {
      this.failAfterComplete = false;
      return Promise.reject(new Error('ambiguous-protected-clear-canary'));
    }
    return Promise.resolve();
  }
}

class ScriptedTransport implements SyncTransportPort {
  readonly pushRequests: PushBatchRequest[] = [];
  readonly publicationRequests: TemplateMigrationPublicationRequest[] = [];
  readonly #pull: PullPageResponse[];
  readonly #push: PushBatchResponse[];
  readonly #publications: TemplateMigrationPublicationResponse[];

  constructor(
    pull: PullPageResponse[],
    push: PushBatchResponse[] = [],
    publications: TemplateMigrationPublicationResponse[] = [],
  ) {
    this.#pull = pull;
    this.#push = push;
    this.#publications = publications;
  }

  pull(request: PullPageRequest): Promise<PullPageResponse> {
    void request;
    const page = this.#pull.shift();
    return page === undefined
      ? Promise.reject(new Error('unexpected pull'))
      : Promise.resolve(page);
  }

  push(request: PushBatchRequest): Promise<PushBatchResponse> {
    this.pushRequests.push(structuredClone(request));
    const response = this.#push.shift();
    return response === undefined
      ? Promise.reject(new Error('unexpected push'))
      : Promise.resolve(response);
  }

  publishTemplateMigration(
    request: TemplateMigrationPublicationRequest,
  ): Promise<TemplateMigrationPublicationResponse> {
    this.publicationRequests.push(structuredClone(request));
    const response = this.#publications.shift();
    return response === undefined
      ? Promise.reject(new Error('unexpected template publication'))
      : Promise.resolve(response);
  }
}

function acceptedResponse(
  queued: ReturnType<typeof mutation>,
  batchIdempotencyKey: string,
): PushBatchResponse {
  if (queued.entityType !== 'group') throw new Error('fixture');
  const page = pullPage([queued.record]);
  const change = page.changes[0]?.change;
  if (change === undefined) throw new Error('fixture');
  return syncPushResponseSchema.parse({
    vaultId,
    serverVaultRevision: 1,
    batchIdempotencyKey,
    results: [
      {
        status: 'accepted',
        disposition: 'committed',
        idempotencyKey: queued.idempotencyKey,
        change,
      },
    ],
  });
}

function pullResponse(page: ReturnType<typeof pullPage>): PullPageResponse {
  return {
    vaultId,
    serverVaultRevision: page.cursor.highestSeenVaultRevision,
    changes: [...page.changes],
    nextCursor: page.cursor,
    hasMore: false,
  };
}

function emptyPage(revision: number, sequence: number): PullPageResponse {
  return {
    vaultId,
    serverVaultRevision: revision as PullPageResponse['serverVaultRevision'],
    changes: [],
    nextCursor: {
      vaultId,
      serverSequence: sequence as PullPageResponse['nextCursor']['serverSequence'],
      highestSeenVaultRevision:
        revision as PullPageResponse['nextCursor']['highestSeenVaultRevision'],
    },
    hasMore: false,
  };
}

function pullResponseFrom(
  revision: number,
  sequence: number,
  changes: readonly PullPageResponse['changes'][number][],
): PullPageResponse {
  return {
    ...emptyPage(revision, sequence),
    changes: [...changes],
  };
}
