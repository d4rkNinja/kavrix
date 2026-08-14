import { realpath, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  OpaqueMutationDurabilityUnknownError,
  type OpaqueMutationQueuePort,
} from '@kavrix/client';
import {
  createPortableKeySlot,
  encryptPayload,
  generatePortableKey,
  generateVaultRootKey,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import { NativeProtectedSyncState, type NativeEntryFactory } from '@kavrix/keychain';
import {
  openSqliteSyncLocalStore,
  type SqliteSyncLocalStore,
} from '@kavrix/local-store';
import {
  associatedDataSchema,
  changeRecordSchema,
  contentHashForRecord,
  encryptedGroupRecordSchema,
  keySlotIdSchema,
  opaqueMutationSchema,
  recordRevisionSchema,
  syncCursorSchema,
  syncPullResponseSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
  timestampSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type ChangeRecord,
  type DeviceId,
  type EncryptedGroupRecord,
  type OpaqueMutation,
  type ProtectedLocalDeviceState,
  type Sha256Digest,
  type Timestamp,
  type VaultId,
  type VaultRevision,
} from '@kavrix/schemas';
import {
  SyncEngine,
  SyncLocalStateError,
  SyncTransportFailure,
  type ProtectedSyncStatePort,
  type PullPageRequest,
  type PullPageResponse,
  type PushBatchRequest,
  type PushBatchResponse,
  type SyncLocalStorePort,
  type SyncTransportPort,
} from '@kavrix/sync';
import { afterEach, describe, expect, it } from 'vitest';

import { executeProductionCreateGroup } from '../src/production/mutations.js';

const TIMESTAMP = timestampSchema.parse('2026-08-14T00:00:00.000Z');
const TEST_TMPDIR = await realpath(tmpdir());
const VAULT_ID = vaultIdSchema.parse('vault.issue46.acceptance');
const DEVICE_ID = 'device.issue46.acceptance' as DeviceId;
const PLAINTEXT_CANARY = 'issue-46-plaintext-canary';
const TEST_ROOTS: string[] = [];
const OPEN_STORES = new Set<SqliteSyncLocalStore>();
const TEST_TRANSPORTS = new Set<OpaqueSyncServer>();
const TEST_PROTECTED_STORES = new Set<PersistentProtectedState>();

afterEach(async () => {
  for (const store of OPEN_STORES) {
    store.close();
  }
  OPEN_STORES.clear();
  for (const transport of TEST_TRANSPORTS) assertOpaqueTransport(transport);
  TEST_TRANSPORTS.clear();
  for (const protectedState of TEST_PROTECTED_STORES) protectedState.dispose();
  TEST_PROTECTED_STORES.clear();
  for (const root of TEST_ROOTS.splice(0)) {
    if (!root.startsWith(join(TEST_TMPDIR, 'kavrix-issue-46-'))) {
      throw new Error('Refusing to remove an unverified test directory');
    }
    await rm(root, { recursive: true, force: true });
  }
});

describe('interruption and recovery acceptance', () => {
  it('retries an ambiguous local mutation acknowledgement with the exact batch', async () => {
    const rootKey = generateVaultRootKey();
    try {
      const fixture = await createStore('mutation');
      await seedVaultRecord(fixture.store, rootKey);
      const queue = new AmbiguousMutationQueue(fixture.store);

      const result = await executeProductionCreateGroup(
        {
          source: fixture.store,
          queue,
          vaultId: VAULT_ID,
          rootKey,
        },
        {
          name: 'Recovered group',
          description: PLAINTEXT_CANARY,
        },
      );

      expect(queue.batches).toHaveLength(2);
      expect(queue.batches[1]).toEqual(queue.batches[0]);
      expect(result.groupId).toBe(queue.batches[0]?.[0]?.record.id);
      const pending = await fixture.store.listPendingMutations(VAULT_ID);
      expect(pending).toHaveLength(1);
      expect(pending[0]?.record.id).toBe(result.groupId);
      expect(JSON.stringify(pending)).not.toContain(PLAINTEXT_CANARY);

      closeStore(fixture.store);
      const reopened = await reopenStore(fixture.path);
      const reopenedPending = await reopened.listPendingMutations(VAULT_ID);
      expect(reopenedPending).toEqual(pending);
      expect(await reopened.getCurrentGroup(VAULT_ID, result.groupId)).toMatchObject({
        state: 'active',
        record: { id: result.groupId },
      });
    } finally {
      zeroize(rootKey);
    }
  });

  it('keeps the offline queue and resumes after reopening the real SQLite store', async () => {
    const fixture = await createStore('offline');
    const mutation = opaqueGroupMutation('mutation.issue46.offline');
    await fixture.store.enqueueBatch([mutation]);
    const transport = new OpaqueSyncServer();
    transport.failNextPull = true;
    const protectedState = new PersistentProtectedState();

    await expect(
      sync(fixture.store, protectedState.current(), transport, 'batch.issue46.offline'),
    ).rejects.toMatchObject({ kind: 'offline' });
    expect(await fixture.store.listPendingMutations(VAULT_ID)).toEqual([mutation]);

    closeStore(fixture.store);
    const reopened = await reopenStore(fixture.path);
    await expect(
      sync(reopened, protectedState.reopen(), transport, 'batch.issue46.offline'),
    ).resolves.toMatchObject({ state: 'synced', pushedMutations: 1 });
    expect(await reopened.listPendingMutations(VAULT_ID)).toEqual([]);
    expect(transport.acceptedMutations).toBe(1);
    expect(transport.pushRequests).toHaveLength(1);
    assertOpaqueTransport(transport);
  });

  it('resumes the exact durable batch after active-batch persistence interruption', async () => {
    const fixture = await createStore('active-batch');
    const mutation = opaqueGroupMutation('mutation.issue46.active');
    await fixture.store.enqueueBatch([mutation]);
    const transport = new OpaqueSyncServer();
    const protectedState = new PersistentProtectedState();
    const interrupted = faultAfterLocalMethod(fixture.store, 'saveActivePushBatch');

    await expect(
      sync(interrupted, protectedState.current(), transport, 'batch.issue46.active'),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    const active = await fixture.store.loadActivePushBatch(VAULT_ID);
    expect(active).toMatchObject({
      batchIdempotencyKey: 'batch.issue46.active',
      mutationIdempotencyKeys: [mutation.idempotencyKey],
    });

    closeStore(fixture.store);
    const reopened = await reopenStore(fixture.path);
    await expect(
      sync(reopened, protectedState.reopen(), transport, 'batch.issue46.active'),
    ).resolves.toMatchObject({ state: 'synced', pushedMutations: 1 });
    expect(transport.pushRequests[0]?.batchIdempotencyKey).toBe('batch.issue46.active');
    expect(await reopened.loadActivePushBatch(VAULT_ID)).toBeNull();
    expect(await reopened.listPendingMutations(VAULT_ID)).toEqual([]);
  });

  it('replays a committed response-loss batch once and clears it after reopen', async () => {
    const fixture = await createStore('response-loss');
    const mutation = opaqueGroupMutation('mutation.issue46.response');
    await fixture.store.enqueueBatch([mutation]);
    const transport = new OpaqueSyncServer();
    transport.loseNextPushResponse = true;
    const protectedState = new PersistentProtectedState();

    await expect(
      sync(
        fixture.store,
        protectedState.current(),
        transport,
        'batch.issue46.response',
      ),
    ).rejects.toMatchObject({ kind: 'offline' });
    expect(transport.acceptedMutations).toBe(1);
    expect(await fixture.store.loadActivePushBatch(VAULT_ID)).toMatchObject({
      batchIdempotencyKey: 'batch.issue46.response',
    });

    closeStore(fixture.store);
    const reopened = await reopenStore(fixture.path);
    await expect(
      sync(reopened, protectedState.reopen(), transport, 'batch.issue46.response'),
    ).resolves.toMatchObject({ state: 'synced', pushedMutations: 1 });
    expect(transport.pushRequests).toHaveLength(2);
    expect(transport.pushRequests[1]).toEqual(transport.pushRequests[0]);
    expect(transport.acceptedMutations).toBe(1);
    expect(await reopened.listPendingMutations(VAULT_ID)).toEqual([]);
  });

  it('recovers after reconciliation committed before its acknowledgement returned', async () => {
    const fixture = await createStore('reconcile');
    const mutation = opaqueGroupMutation('mutation.issue46.reconcile');
    await fixture.store.enqueueBatch([mutation]);
    const transport = new OpaqueSyncServer();
    const protectedState = new PersistentProtectedState();
    const interrupted = faultAfterLocalMethod(
      fixture.store,
      'reconcileOutboundObservation',
    );

    await expect(
      sync(interrupted, protectedState.current(), transport, 'batch.issue46.reconcile'),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(await fixture.store.listPendingMutations(VAULT_ID)).toEqual([]);
    expect(await fixture.store.loadActivePushBatch(VAULT_ID)).toBeNull();
    expect(
      (await protectedState.current().load(VAULT_ID, DEVICE_ID))?.outboundObservation,
    ).toBeDefined();

    closeStore(fixture.store);
    const reopened = await reopenStore(fixture.path);
    await expect(
      sync(reopened, protectedState.reopen(), transport, 'batch.issue46.reconcile'),
    ).resolves.toMatchObject({ state: 'synced', pushedMutations: 1 });
    expect(transport.pushRequests).toHaveLength(1);
    expect(await reopened.listPendingMutations(VAULT_ID)).toEqual([]);
    expect(
      (await protectedState.current().load(VAULT_ID, DEVICE_ID))?.outboundObservation,
    ).toBeUndefined();
  });

  it('releases a completed protected observation after the clear acknowledgement is lost', async () => {
    const fixture = await createStore('protected-complete');
    const mutation = opaqueGroupMutation('mutation.issue46.protected');
    await fixture.store.enqueueBatch([mutation]);
    const transport = new OpaqueSyncServer();
    const baseProtectedState = new PersistentProtectedState();
    const interrupted = new FaultingProtectedState(baseProtectedState.current());

    await expect(
      sync(fixture.store, interrupted, transport, 'batch.issue46.protected'),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    const protectedAfter = await baseProtectedState.current().load(VAULT_ID, DEVICE_ID);
    expect(protectedAfter?.lastCompletedObservationId).toBeDefined();

    closeStore(fixture.store);
    const reopened = await reopenStore(fixture.path);
    await expect(
      sync(reopened, baseProtectedState.reopen(), transport, 'batch.issue46.protected'),
    ).resolves.toMatchObject({ state: 'synced', pushedMutations: 0 });
    expect(transport.pushRequests).toHaveLength(1);
    expect(await reopened.listPendingMutations(VAULT_ID)).toEqual([]);
  });

  it('keeps a monotonic cursor after pull apply commits before acknowledgement', async () => {
    const fixture = await createStore('pull-apply');
    const record = opaqueGroupRecord('group.issue46.pull');
    const transport = new OpaqueSyncServer([record]);
    const protectedState = new PersistentProtectedState();
    const interrupted = faultAfterLocalMethod(fixture.store, 'applyPullPage');

    await expect(
      sync(interrupted, protectedState.current(), transport, 'batch.issue46.pull'),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(await fixture.store.loadCursor(VAULT_ID)).toMatchObject({
      serverSequence: 1,
    });

    closeStore(fixture.store);
    const reopened = await reopenStore(fixture.path);
    await expect(
      sync(reopened, protectedState.reopen(), transport, 'batch.issue46.pull'),
    ).resolves.toMatchObject({ state: 'synced', pulledChanges: 0 });
    expect(
      transport.pullRequests.map((request) => request.cursor.serverSequence),
    ).toEqual([0, 1]);
    expect(await reopened.getGroup(VAULT_ID, record.id)).toEqual(record);
    expect(JSON.stringify(await reopened.getGroup(VAULT_ID, record.id))).not.toContain(
      PLAINTEXT_CANARY,
    );
  });

  it('retains and resolves an explicit conflict through the reopened SQLite ledger', async () => {
    const current = opaqueGroupRecord('group.issue46.conflict', 2);
    const local = opaqueGroupMutation(
      'mutation.issue46.conflict',
      opaqueGroupRecord(current.id, 1),
      0,
    );
    const fixture = await createStore('conflict');
    const localBase = opaqueGroupRecord(current.id, 0);
    await fixture.store.applyPullPage({
      vaultId: VAULT_ID,
      changes: [{ change: changeFor(localBase, 1), record: localBase }],
      cursor: syncCursorSchema.parse({
        vaultId: VAULT_ID,
        serverSequence: 1,
        highestSeenVaultRevision: 0,
      }),
    });
    await fixture.store.enqueueBatch([local]);
    const transport = new OpaqueSyncServer([current]);
    const protectedState = new PersistentProtectedState();

    const result = await sync(
      fixture.store,
      protectedState.current(),
      transport,
      'batch.issue46.conflict',
    );
    expect(result).toMatchObject({ state: 'conflict', pushedMutations: 0 });
    const listed = await fixture.store.listConflicts(VAULT_ID);
    expect(listed).toEqual([
      expect.objectContaining({
        entityId: current.id,
        idempotencyKey: local.idempotencyKey,
        currentRevision: 2,
      }),
    ]);
    expect(JSON.stringify(listed)).not.toContain(PLAINTEXT_CANARY);

    closeStore(fixture.store);
    const reopened = await reopenStore(fixture.path);
    const reopenedConflicts = await reopened.listConflicts(VAULT_ID);
    const conflict = reopenedConflicts[0];
    if (conflict === undefined) throw new Error('Missing durable conflict');
    await expect(
      reopened.resolveConflict({
        vaultId: VAULT_ID,
        conflictId: conflict.idempotencyKey,
        currentRevision: recordRevisionSchema.parse(conflict.currentRevision),
        strategy: 'accept-remote',
        replacementIdempotencyKey: null,
        resolvedAt: TIMESTAMP,
      }),
    ).resolves.toMatchObject({ status: 'accepted-remote' });
    expect(await reopened.listConflicts(VAULT_ID)).toEqual([]);
    expect(await reopened.listPendingMutations(VAULT_ID)).toEqual([]);
  });
});

class AmbiguousMutationQueue implements OpaqueMutationQueuePort {
  readonly batches: OpaqueMutation[][] = [];
  #first = true;

  constructor(private readonly store: SqliteSyncLocalStore) {}

  async enqueueBatch(mutations: readonly OpaqueMutation[]): Promise<void> {
    this.batches.push(mutations.map((mutation) => structuredClone(mutation)));
    await this.store.enqueueBatch(mutations);
    if (this.#first) {
      this.#first = false;
      throw new OpaqueMutationDurabilityUnknownError();
    }
  }

  enqueueTemplateMigrationPublication(
    publication: Parameters<
      OpaqueMutationQueuePort['enqueueTemplateMigrationPublication']
    >[0],
  ): Promise<void> {
    return this.store.enqueueTemplateMigrationPublication(publication);
  }
}

class PersistentProtectedState {
  readonly #entries = new Map<string, Uint8Array>();
  readonly #service = 'kavrix-issue-46';
  readonly #factory: NativeEntryFactory = (service, account) => {
    const key = `${service}\u0000${account}`;
    return {
      setSecret: (secret) => {
        this.#entries.get(key)?.fill(0);
        this.#entries.set(key, Uint8Array.from(secret));
        return Promise.resolve();
      },
      getSecret: () => {
        const secret = this.#entries.get(key);
        return Promise.resolve(secret === undefined ? null : Uint8Array.from(secret));
      },
      deleteCredential: () => {
        this.#entries.get(key)?.fill(0);
        this.#entries.delete(key);
        return Promise.resolve();
      },
    };
  };

  constructor() {
    TEST_PROTECTED_STORES.add(this);
  }

  current(): NativeProtectedSyncState {
    return new NativeProtectedSyncState(this.#factory, this.#service);
  }

  reopen(): NativeProtectedSyncState {
    return this.current();
  }

  dispose(): void {
    for (const value of this.#entries.values()) value.fill(0);
    this.#entries.clear();
  }
}

class FaultingProtectedState implements ProtectedSyncStatePort {
  constructor(private readonly delegate: ProtectedSyncStatePort) {}

  load(
    vaultId: VaultId,
    deviceId: DeviceId,
  ): Promise<ProtectedLocalDeviceState | null> {
    return this.delegate.load(vaultId, deviceId);
  }

  save(state: ProtectedLocalDeviceState): Promise<void> {
    return this.delegate.save(state);
  }

  async completeObservation(
    vaultId: VaultId,
    deviceId: DeviceId,
    expectedObservationId: Sha256Digest,
    candidateRevision: VaultRevision,
    updatedAt: Timestamp,
  ): Promise<void> {
    await this.delegate.completeObservation(
      vaultId,
      deviceId,
      expectedObservationId,
      candidateRevision,
      updatedAt,
    );
    throw new Error('issue-46-protected-acknowledgement-interrupted');
  }
}

class OpaqueSyncServer implements SyncTransportPort {
  readonly pullRequests: PullPageRequest[] = [];
  readonly pushRequests: PushBatchRequest[] = [];
  readonly #batches = new Map<string, PushBatchResponse>();
  readonly #mutations = new Map<string, string>();
  readonly #active = new Map<string, EncryptedGroupRecord>();
  readonly #changes: { change: ChangeRecord; record: EncryptedGroupRecord }[] = [];
  #serverRevision = 0;
  #accepted = 0;
  failNextPull = false;
  loseNextPushResponse = false;

  constructor(initial: readonly EncryptedGroupRecord[] = []) {
    TEST_TRANSPORTS.add(this);
    for (const [index, record] of initial.entries()) {
      this.#active.set(this.key(record.id), record);
      this.#changes.push({
        change: changeFor(record, index + 1),
        record,
      });
      this.#serverRevision = Math.max(this.#serverRevision, record.recordRevision);
    }
  }

  get acceptedMutations(): number {
    return this.#accepted;
  }

  pull(request: PullPageRequest): Promise<PullPageResponse> {
    this.pullRequests.push(structuredClone(request));
    if (this.failNextPull) {
      this.failNextPull = false;
      return Promise.reject(new SyncTransportFailure('offline'));
    }
    const cursor = syncCursorSchema.parse(request.cursor);
    const changes = this.#changes
      .filter(({ change }) => change.serverSequence > cursor.serverSequence)
      .slice(0, request.limit);
    const serverSequence =
      changes.at(-1)?.change.serverSequence ?? cursor.serverSequence;
    return Promise.resolve(
      syncPullResponseSchema.parse({
        vaultId: VAULT_ID,
        serverVaultRevision: this.#serverRevision,
        changes,
        nextCursor: syncCursorSchema.parse({
          vaultId: VAULT_ID,
          serverSequence,
          highestSeenVaultRevision: Math.max(
            cursor.highestSeenVaultRevision,
            this.#serverRevision,
          ),
        }),
        hasMore: this.#changes.some(
          ({ change }) => change.serverSequence > serverSequence,
        ),
      }),
    );
  }

  push(request: PushBatchRequest): Promise<PushBatchResponse> {
    const batch = syncPushRequestSchema.parse(request);
    this.pushRequests.push(structuredClone(batch));
    const prior = this.#batches.get(batch.batchIdempotencyKey);
    if (prior !== undefined) return Promise.resolve(structuredClone(prior));

    const results: PushBatchResponse['results'][number][] = [];
    for (const mutation of batch.mutations) {
      if (mutation.entityType !== 'group') throw new Error('Unexpected entity.');
      const record = encryptedGroupRecordSchema.parse(mutation.record);
      const body = JSON.stringify(mutation);
      const priorMutation = this.#mutations.get(mutation.idempotencyKey);
      if (priorMutation !== undefined) {
        if (priorMutation !== body) throw new Error('Mutation key reused.');
        const existing = this.#changes.find(
          ({ change }) => change.entityId === mutation.record.id,
        );
        if (existing === undefined) throw new Error('Missing accepted change.');
        results.push({
          status: 'accepted',
          idempotencyKey: mutation.idempotencyKey,
          disposition: 'duplicate',
          change: existing.change,
        });
        continue;
      }

      const current = this.#active.get(this.key(record.id));
      const expected = current?.recordRevision ?? null;
      if (mutation.expectedRecordRevision !== expected) {
        results.push({
          status: 'conflict',
          idempotencyKey: mutation.idempotencyKey,
          currentRevision: recordRevisionSchema.parse(current?.recordRevision ?? 0),
          current: current ?? null,
        });
        continue;
      }

      const change = changeFor(record, this.#changes.length + 1);
      this.#active.set(this.key(record.id), record);
      this.#changes.push({ change, record });
      this.#serverRevision = Math.max(this.#serverRevision + 1, record.recordRevision);
      this.#mutations.set(mutation.idempotencyKey, body);
      this.#accepted += 1;
      results.push({
        status: 'accepted',
        idempotencyKey: mutation.idempotencyKey,
        disposition: 'committed',
        change,
      });
    }

    const response = syncPushResponseSchema.parse({
      vaultId: VAULT_ID,
      serverVaultRevision: this.#serverRevision,
      batchIdempotencyKey: batch.batchIdempotencyKey,
      results,
    });
    this.#batches.set(batch.batchIdempotencyKey, response);
    if (this.loseNextPushResponse) {
      this.loseNextPushResponse = false;
      return Promise.reject(new SyncTransportFailure('offline'));
    }
    return Promise.resolve(structuredClone(response));
  }

  publishTemplateMigration(): Promise<never> {
    return Promise.reject(new Error('Template migration is out of scope.'));
  }

  private key(entityId: string): string {
    return `group:${entityId}`;
  }
}

function sync(
  local: SyncLocalStorePort,
  protectedState: ProtectedSyncStatePort,
  transport: SyncTransportPort,
  batchKey: string,
): Promise<unknown> {
  return new SyncEngine({
    local,
    protectedState,
    transport,
    status: { set: () => Promise.resolve() },
    clock: { now: () => new Date(TIMESTAMP) },
    idempotencyKeys: { next: () => batchKey },
  }).synchronize({ vaultId: VAULT_ID, deviceId: DEVICE_ID });
}

function faultAfterLocalMethod(
  store: SqliteSyncLocalStore,
  methodName: 'applyPullPage' | 'saveActivePushBatch' | 'reconcileOutboundObservation',
): SyncLocalStorePort {
  return new Proxy(Object.create(null) as object, {
    get(target, property) {
      void target;
      if (property === methodName) {
        return async (...args: unknown[]) => {
          const value: unknown = Reflect.get(store, property, store);
          if (typeof value !== 'function') {
            throw new Error('Missing local store method.');
          }
          const method = value as (...values: unknown[]) => Promise<unknown>;
          await method.apply(store, args);
          throw new Error('issue-46-local-acknowledgement-interrupted');
        };
      }
      const value: unknown = Reflect.get(store, property, store);
      if (typeof value !== 'function') return value;
      const method = value as (...args: unknown[]) => unknown;
      return (...args: unknown[]) => method.apply(store, args);
    },
  }) as SyncLocalStorePort;
}

function assertOpaqueTransport(transport: OpaqueSyncServer): void {
  const serialized = JSON.stringify({
    pull: transport.pullRequests,
    push: transport.pushRequests,
  });
  expect(serialized).not.toContain(PLAINTEXT_CANARY);
}

async function createStore(
  label: string,
): Promise<Readonly<{ path: string; store: SqliteSyncLocalStore }>> {
  const root = join(
    TEST_TMPDIR,
    `kavrix-issue-46-${label}-${randomUUID().replaceAll('-', '')}`,
  );
  TEST_ROOTS.push(root);
  const path = join(root, 'state.sqlite');
  const store = await openSqliteSyncLocalStore({ path });
  OPEN_STORES.add(store);
  return { path, store };
}

async function reopenStore(path: string): Promise<SqliteSyncLocalStore> {
  const store = await openSqliteSyncLocalStore({ path });
  OPEN_STORES.add(store);
  return store;
}

function closeStore(store: SqliteSyncLocalStore): void {
  if (!OPEN_STORES.delete(store)) return;
  store.close();
}

async function seedVaultRecord(
  store: SqliteSyncLocalStore,
  rootKey: VaultRootKey,
): Promise<void> {
  const portableKey = generatePortableKey();
  let slot: Awaited<ReturnType<typeof createPortableKeySlot>> | undefined;
  try {
    slot = await createPortableKeySlot(
      {
        vaultId: VAULT_ID,
        slotId: keySlotIdSchema.parse('slot.issue46.portable'),
        schemaVersion: 1,
        keyVersion: 1,
        createdAt: TIMESTAMP,
      },
      portableKey,
      rootKey,
    );
  } finally {
    zeroize(portableKey);
  }

  const context = associatedDataSchema.parse({
    version: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId: VAULT_ID,
    entityType: 'vault-preferences',
    entityId: VAULT_ID,
    purpose: 'vault-preferences',
  });
  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      productLabel: 'CredVault',
      executableName: 'creds',
      clipboardClearSeconds: 30,
      revealHideSeconds: 30,
      historyRetentionDays: 365,
      telemetryEnabled: false,
    }),
  );
  let encryptedPreferences;
  try {
    encryptedPreferences = await encryptPayload(plaintext, rootKey, context);
  } finally {
    zeroize(plaintext);
  }
  const vault = vaultRecordSchema.parse({
    id: VAULT_ID,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [slot],
    currentKeyVersion: 1,
    revision: 1,
    encryptedPreferences,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
  const change = changeRecordSchema.parse({
    id: 'change.issue46.vault',
    vaultId: VAULT_ID,
    serverSequence: 1,
    entityType: 'vault',
    entityId: VAULT_ID,
    recordRevision: 1,
    operation: 'upsert',
    ciphertextHash: contentHashForRecord(vault),
    createdAt: TIMESTAMP,
  });
  await store.applyPullPage({
    vaultId: VAULT_ID,
    changes: [{ change, record: vault }],
    cursor: syncCursorSchema.parse({
      vaultId: VAULT_ID,
      serverSequence: 1,
      highestSeenVaultRevision: 1,
    }),
  });
}

function opaqueGroupMutation(
  key: string,
  record = opaqueGroupRecord(`group.${key}`),
  expectedRecordRevision: number | null = null,
): OpaqueMutation {
  return opaqueMutationSchema.parse({
    entityType: 'group',
    expectedRecordRevision,
    idempotencyKey: key,
    record,
  });
}

function opaqueGroupRecord(
  id: string,
  revision = 0,
  vaultId: VaultId = VAULT_ID,
): EncryptedGroupRecord {
  return encryptedGroupRecordSchema.parse({
    id,
    vaultId,
    schemaVersion: 1,
    wrappedGroupKey: envelope('wrapped-group-key', 'group-key', id, vaultId),
    encryptedPayload: envelope(
      'group',
      'group-payload',
      id,
      vaultId,
      Buffer.from(PLAINTEXT_CANARY).toString('base64url'),
    ),
    templateVersion: 1,
    recordRevision: revision,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
}

function envelope(
  entityType: 'group' | 'wrapped-group-key',
  purpose: 'group-key' | 'group-payload',
  entityId: string,
  vaultId: VaultId,
  ciphertext = 'AQID',
): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext,
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType,
      entityId,
      purpose,
    },
    keyVersion: 1,
  };
}

function changeFor(record: EncryptedGroupRecord, serverSequence: number): ChangeRecord {
  return changeRecordSchema.parse({
    id: `change.issue46.${String(serverSequence)}`,
    vaultId: record.vaultId,
    serverSequence,
    entityType: 'group',
    entityId: record.id,
    recordRevision: record.recordRevision,
    operation: 'upsert',
    ciphertextHash: contentHashForRecord(record),
    createdAt: TIMESTAMP,
  });
}
