import { randomBytes } from 'node:crypto';

import {
  changeRecordSchema,
  contentHashForRecord,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  opaqueMutationSchema,
  protectedLocalDeviceStateSchema,
  syncCursorSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
} from '@kavrix/schemas';
import type {
  ChangeRecord,
  DeviceId,
  EncryptedGroupRecord,
  EncryptedItemRecord,
  OpaqueMutation,
  ProtectedLocalDeviceState,
  SyncCursor,
  TemplateMigrationPublicationRequest,
  TemplateMigrationPublicationResponse,
  VaultId,
  Sha256Digest,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  classifySyncFailure,
  createOutboundObservation,
  SyncEngine,
  SyncLocalStateError,
  SyncProtocolError,
  SyncRollbackError,
  SyncTransportFailure,
} from '../src/index.js';
import type {
  ActivePushBatch,
  ApplyPullPageInput,
  CompletePushBatchInput,
  CompleteTemplateMigrationPublicationInput,
  CompletedOutboundObservation,
  EnsureOutboundReplayStartInput,
  OutboundReplayState,
  ProtectedSyncStatePort,
  PullPageRequest,
  PullPageResponse,
  PushBatchRequest,
  PushBatchResponse,
  ReconcileOutboundObservationInput,
  SyncClockPort,
  SyncIdempotencyKeyPort,
  SyncLocalStorePort,
  SyncStatus,
  SyncStatusPort,
  SyncTransportPort,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const wrongDigest = Buffer.alloc(32, 1).toString('base64url');
const vaultId = 'vault.1' as VaultId;
const deviceId = 'device.1' as DeviceId;

describe('SyncEngine pull', () => {
  it('protects a validated pull revision before publishing it locally', async () => {
    const events: string[] = [];
    const change = purgeChange(1, 'group.1', 1);
    const local = new FakeLocalStore([], null, events);
    const protectedState = new FakeProtectedState(events);
    protectedState.failNextSave = true;
    const harness = makeHarness({
      local,
      protectedState,
      transport: new FakeTransport(
        [pullPage(1, 1, [{ change, record: null }], false)],
        [],
        [],
        events,
      ),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(events).toEqual(['transport.pull', 'protected.save']);
    expect(local.cursor).toBeNull();
    expect(local.applied).toHaveLength(0);
  });

  it('sanitizes protected adapter failures and status cannot mask them', async () => {
    const canary = { message: 'enumerable-protected-canary', secret: 'nested' };
    const protectedState = new FakeProtectedState();
    protectedState.loadFailure = canary;
    const status = new FakeStatus();
    status.failNext = true;
    const harness = makeHarness({
      protectedState,
      status,
      transport: new FakeTransport([]),
    });

    let thrown: unknown;
    try {
      await harness.engine.synchronize({ vaultId, deviceId });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(SyncLocalStateError);
    expect(thrown).not.toBe(canary);
    expect(Object.prototype.hasOwnProperty.call(thrown, 'cause')).toBe(false);
    const serialized = `${String(thrown)}${JSON.stringify(thrown)}${JSON.stringify(
      status.values,
    )}`;
    expect(serialized).not.toContain(canary.message);
    expect(serialized).not.toContain(canary.secret);
  });

  it('pulls every ordered page and advances cursor and protected revision', async () => {
    const firstChange = purgeChange(1, 'group.1', 1);
    const secondChange = purgeChange(2, 'group.2', 1);
    const transport = new FakeTransport([
      pullPage(1, 1, [{ change: firstChange, record: null }], true),
      pullPage(2, 2, [{ change: secondChange, record: null }], false),
    ]);
    const harness = makeHarness({ transport, pullPageSize: 1 });

    const result = await harness.engine.synchronize({ vaultId, deviceId });

    expect(result).toMatchObject({
      state: 'synced',
      pulledChanges: 2,
      pushedMutations: 0,
    });
    expect(
      transport.pullRequests.map((request) => request.cursor.serverSequence),
    ).toEqual([0, 1]);
    expect(harness.local.applied).toHaveLength(2);
    expect(harness.protectedState.value?.highestSeenVaultRevision).toBe(2);
    expect(harness.status.values.map(({ state }) => state)).toEqual([
      'syncing',
      'syncing',
      'synced',
    ]);
  });

  it('resumes from the last atomically committed cursor after interruption', async () => {
    const change = purgeChange(1, 'group.1', 1);
    const page = pullPage(1, 1, [{ change, record: null }], false);
    const transport = new FakeTransport([page, page]);
    const harness = makeHarness({ transport });
    harness.local.failNextApply = true;

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(harness.local.cursor).toBeNull();

    const result = await harness.engine.synchronize({ vaultId, deviceId });

    expect(result.state).toBe('synced');
    expect(
      transport.pullRequests.map((request) => request.cursor.serverSequence),
    ).toEqual([0, 0]);
    expect(harness.local.cursor?.serverSequence).toBe(1);
  });

  it('rejects rollback below protected highest-seen vault revision', async () => {
    const protectedState = new FakeProtectedState();
    protectedState.value = protectedLocalDeviceStateSchema.parse({
      version: 2,
      vaultId,
      deviceId,
      highestSeenVaultRevision: 5,
      updatedAt: timestamp,
    });
    const harness = makeHarness({
      transport: new FakeTransport([pullPage(4, 0, [], false)]),
      protectedState,
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncRollbackError);
    expect(harness.local.applied).toHaveLength(0);
    expect(harness.status.values.at(-1)).toMatchObject({
      state: 'error',
      code: 'rollback-detected',
      retryable: false,
    });
  });

  it('rejects cross-vault and malformed pages without applying them', async () => {
    const crossVault = {
      ...pullPage(0, 0, [], false),
      vaultId: 'vault.other',
    } as unknown as PullPageResponse;
    const malformed = {
      ...pullPage(1, 2, [], false),
      changes: [
        {
          change: { ...purgeChange(2, 'group.1', 1), serverSequence: 2 },
          record: null,
        },
      ],
    } as unknown as PullPageResponse;

    for (const page of [crossVault, malformed]) {
      const harness = makeHarness({ transport: new FakeTransport([page]) });
      await expect(
        harness.engine.synchronize({ vaultId, deviceId }),
      ).rejects.toBeInstanceOf(SyncProtocolError);
      expect(harness.local.applied).toHaveLength(0);
      expect(harness.status.values.at(-1)).toMatchObject({
        state: 'error',
        code: 'protocol-invalid',
      });
    }
  });

  it('rejects a current pulled record whose canonical content hash is wrong', async () => {
    const record = groupRecord(1);
    const change = changeRecordSchema.parse({
      id: 'change.wrong-hash.1',
      vaultId,
      serverSequence: 1,
      entityType: 'group',
      entityId: record.id,
      recordRevision: record.recordRevision,
      operation: 'upsert',
      ciphertextHash: wrongDigest,
      createdAt: timestamp,
    });
    expect(change.ciphertextHash).not.toBe(contentHashForRecord(record));
    const harness = makeHarness({
      transport: new FakeTransport([pullPage(1, 1, [{ change, record }], false)]),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    expect(harness.local.applied).toHaveLength(0);
  });
});

describe('SyncEngine push', () => {
  it('publishes success only after reconcile, protected clear, and pin release', async () => {
    const events: string[] = [];
    const mutation = groupMutation(0, null, 'barrier-mutation-key-0001');
    const response = acceptedPushResponse(
      mutation,
      'batch-key-0000001',
      'committed',
      1,
    );
    const local = new FakeLocalStore([mutation], null, events);
    const protectedState = new FakeProtectedState(events);
    const status = new FakeStatus(events);
    const harness = makeHarness({
      local,
      protectedState,
      status,
      transport: new FakeTransport(
        [
          pullPage(0, 0, [], false),
          acceptedFeedPage(response, [mutation]),
          pullPage(1, 1, [], false),
        ],
        [response],
        [],
        events,
      ),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).resolves.toMatchObject({
      state: 'synced',
      pushedMutations: 1,
      pulledChanges: 1,
    });
    expect(events.indexOf('local.reconcile')).toBeLessThan(
      events.indexOf('protected.complete'),
    );
    expect(events.indexOf('protected.complete')).toBeLessThan(
      events.indexOf('local.release'),
    );
    expect(events.indexOf('local.release')).toBeLessThan(
      events.indexOf('status.synced'),
    );
  });

  it('recovers a committed receipt without network before exact clear', async () => {
    const mutation = groupMutation(0, null, 'receipt-recovery-key-0001');
    const response = acceptedPushResponse(
      mutation,
      'batch-key-0000001',
      'committed',
      1,
    );
    const local = new FakeLocalStore([mutation]);
    const protectedState = new FakeProtectedState();
    protectedState.failNextComplete = true;
    const transport = new FakeTransport(
      [
        pullPage(0, 0, [], false),
        acceptedFeedPage(response, [mutation]),
        pullPage(1, 1, [], false),
      ],
      [response],
    );
    const harness = makeHarness({ local, protectedState, transport });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(local.active).toBeNull();
    expect(local.pending).toHaveLength(0);
    expect(protectedState.value?.outboundObservation).toBeDefined();
    expect(transport.pushRequests).toHaveLength(1);

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).resolves.toMatchObject({
      state: 'synced',
      pushedMutations: 1,
      pulledChanges: 1,
    });
    expect(transport.pushRequests).toHaveLength(1);
    expect(protectedState.value?.outboundObservation).toBeUndefined();
  });

  it('keeps descriptor and publication barrier closed when clear fails', async () => {
    const mutation = groupMutation(0, null, 'clear-failure-key-0001');
    const response = acceptedPushResponse(
      mutation,
      'batch-key-0000001',
      'committed',
      1,
    );
    const events: string[] = [];
    const local = new FakeLocalStore([mutation], null, events);
    const protectedState = new FakeProtectedState(events);
    protectedState.failNextComplete = true;
    const status = new FakeStatus(events);
    const harness = makeHarness({
      local,
      protectedState,
      status,
      transport: new FakeTransport(
        [pullPage(0, 0, [], false), acceptedFeedPage(response, [mutation])],
        [response],
        [],
        events,
      ),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(protectedState.value?.outboundObservation).toBeDefined();
    expect(events).toContain('local.reconcile');
    expect(events).toContain('protected.complete');
    expect(events).not.toContain('local.release');
    expect(events).not.toContain('status.synced');
  });

  it('rejects a cursor/replay mismatch before transport or protected mutation', async () => {
    const mutation = groupMutation(1, 0, 'cursor-mismatch-key-0001');
    const local = new FakeLocalStore([mutation]);
    local.cursor = syncCursorSchema.parse({
      vaultId,
      serverSequence: 2,
      highestSeenVaultRevision: 2,
    });
    local.active = {
      vaultId,
      batchIdempotencyKey: 'cursor-mismatch-batch-0001',
      mutationIdempotencyKeys: [mutation.idempotencyKey],
    };
    local.replayStart = 1;
    const protectedState = new FakeProtectedState();
    const transport = new FakeTransport([]);
    const harness = makeHarness({ local, protectedState, transport });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(transport.pushRequests).toHaveLength(0);
    expect(transport.pullRequests).toHaveLength(0);
    expect(protectedState.value).toBeNull();
  });

  it('rejects a changed staged accepted entry and keeps descriptor/work durable', async () => {
    const mutation = groupMutation(0, null, 'changed-feed-key-0001');
    const response = acceptedPushResponse(
      mutation,
      'batch-key-0000001',
      'committed',
      1,
    );
    const changed = acceptedFeedPage(response, [mutation]);
    const original = changed.changes[0];
    if (original === undefined) throw new Error('fixture');
    changed.changes[0] = {
      ...original,
      change: { ...original.change, id: 'change.changed-feed' },
    } as PullPageResponse['changes'][number];
    const local = new FakeLocalStore([mutation]);
    const protectedState = new FakeProtectedState();
    const harness = makeHarness({
      local,
      protectedState,
      transport: new FakeTransport([pullPage(0, 0, [], false), changed], [response]),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    expect(protectedState.value?.outboundObservation).toBeDefined();
    expect(local.active).not.toBeNull();
    expect(local.pending).toEqual([mutation]);
    expect(local.cursor?.serverSequence).toBe(0);
  });

  it('rejects a premature terminal recovery page without local reconciliation', async () => {
    const mutation = groupMutation(0, null, 'premature-feed-key-0001');
    const response = acceptedPushResponse(
      mutation,
      'batch-key-0000001',
      'committed',
      1,
    );
    const local = new FakeLocalStore([mutation]);
    const harness = makeHarness({
      local,
      transport: new FakeTransport(
        [pullPage(0, 0, [], false), pullPage(1, 0, [], false)],
        [response],
      ),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    expect(local.active).not.toBeNull();
    expect(local.cursor?.serverSequence).toBe(0);
  });

  it('rejects an unprotected historical accepted receipt before staging', async () => {
    const mutation = groupMutation(1, 0, 'historical-mutation-key-0001');
    const response = acceptedPushResponse(
      mutation,
      'historical-batch-key-0001',
      'duplicate',
      2,
    );
    const local = new FakeLocalStore([mutation]);
    local.cursor = syncCursorSchema.parse({
      vaultId,
      serverSequence: 1,
      highestSeenVaultRevision: 2,
    });
    local.active = {
      vaultId,
      batchIdempotencyKey: response.batchIdempotencyKey,
      mutationIdempotencyKeys: [mutation.idempotencyKey],
    };
    local.replayStart = 1;
    const harness = makeHarness({
      local,
      transport: new FakeTransport([], [response]),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncRollbackError);
    expect(harness.local.cursor?.serverSequence).toBe(1);
  });

  it('resolves an exact protected receipt before loading durable work', async () => {
    const mutation = groupMutation(0, null, 'receipt-mutation-key-0001');
    const request: PushBatchRequest = {
      vaultId,
      batchIdempotencyKey: 'receipt-batch-key-0001',
      mutations: [mutation],
    };
    const response = acceptedPushResponse(
      mutation,
      request.batchIdempotencyKey,
      'committed',
      1,
    );
    const observation = createOutboundObservation({
      kind: 'generic-push',
      vaultId,
      deviceId,
      request,
      response,
      replayFromServerSequence: 0,
    });
    const finalCursor = syncCursorSchema.parse({
      vaultId,
      serverSequence: 1,
      highestSeenVaultRevision: 1,
    });
    const receipt = {
      kind: 'generic-push',
      vaultId,
      deviceId,
      observation,
      request,
      response,
      finalCursor,
      serializedBytes: 1,
    } as const;
    const local = new FakeLocalStore();
    local.cursor = finalCursor;
    local.completed.set(observation.observationId, receipt);
    local.failIfDurableWorkLoads = true;
    const protectedState = new FakeProtectedState();
    protectedState.value = protectedLocalDeviceStateSchema.parse({
      version: 2,
      vaultId,
      deviceId,
      highestSeenVaultRevision: 1,
      updatedAt: timestamp,
      outboundObservation: observation,
    });
    const harness = makeHarness({
      local,
      protectedState,
      transport: new FakeTransport([pullPage(1, 1, [], false)]),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).resolves.toMatchObject({ state: 'synced', pushedMutations: 1 });
    expect(harness.protectedState.value?.outboundObservation).toBeUndefined();
  });

  it('retries an interrupted batch with the exact stored response and real feed', async () => {
    const mutation = groupMutation(0, null, 'mutation-key-0001');
    const accepted = acceptedPushResponse(
      mutation,
      'batch-key-0000001',
      'committed',
      1,
    );
    const feed = acceptedFeedPage(accepted, [mutation]);
    const transport = new FakeTransport(
      [pullPage(0, 0, [], false), feed, feed, pullPage(1, 1, [], false)],
      [accepted, accepted],
    );
    const local = new FakeLocalStore([mutation]);
    local.failNextReconcile = true;
    const harness = makeHarness({ transport, local });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(local.active?.batchIdempotencyKey).toBe('batch-key-0000001');
    expect(local.pending).toHaveLength(1);

    const result = await harness.engine.synchronize({ vaultId, deviceId });

    expect(result).toMatchObject({ state: 'synced', pushedMutations: 1 });
    expect(transport.pushRequests).toHaveLength(2);
    expect(transport.pushRequests[1]).toEqual(transport.pushRequests[0]);
    expect(local.pending).toHaveLength(0);
    expect(local.active).toBeNull();
  });

  it('returns an explicit conflict and never acknowledges the conflicting mutation', async () => {
    const mutation = groupMutation(1, 0, 'mutation-key-0002');
    const current = groupRecord(2);
    const response: PushBatchResponse = {
      vaultId,
      serverVaultRevision: 3 as PushBatchResponse['serverVaultRevision'],
      batchIdempotencyKey: 'batch-key-0000001',
      results: [
        {
          status: 'conflict',
          idempotencyKey: mutation.idempotencyKey,
          currentRevision: current.recordRevision,
          current,
        },
      ],
    };
    const local = new FakeLocalStore([mutation]);
    const harness = makeHarness({
      transport: new FakeTransport([pullPage(0, 0, [], false)], [response]),
      local,
    });

    const result = await harness.engine.synchronize({ vaultId, deviceId });

    expect(result).toMatchObject({ state: 'conflict', pushedMutations: 0 });
    if (result.state !== 'conflict') throw new Error('Expected conflict');
    expect(result.conflicts).toHaveLength(1);
    expect(result.conflicts[0]?.mutation).toEqual(mutation);
    expect(result.conflicts[0]?.current).toEqual(current);
    expect(local.pending).toEqual([mutation]);
    expect(harness.status.values.at(-1)?.state).toBe('conflict');
  });

  it('rejects a cross-vault conflict record', async () => {
    const mutation = groupMutation(1, 0, 'mutation-key-0003');
    const response = {
      vaultId,
      serverVaultRevision: 2,
      batchIdempotencyKey: 'batch-key-0000001',
      results: [
        {
          status: 'conflict',
          idempotencyKey: mutation.idempotencyKey,
          currentRevision: 1,
          current: groupRecord(1, 'vault.other'),
        },
      ],
    } as unknown as PushBatchResponse;
    const harness = makeHarness({
      transport: new FakeTransport([pullPage(0, 0, [], false)], [response]),
      local: new FakeLocalStore([mutation]),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncProtocolError);
  });

  it('rejects an accepted generic mutation with the wrong content hash', async () => {
    const mutation = groupMutation(1, 0, 'mutation-key-wrong-hash-0001');
    const valid = acceptedPushResponse(mutation, 'batch-key-0000001', 'committed', 1);
    const response = {
      ...valid,
      results: valid.results.map((result) =>
        result.status === 'accepted'
          ? {
              ...result,
              change: { ...result.change, ciphertextHash: wrongDigest },
            }
          : result,
      ),
    } as PushBatchResponse;
    expect(response.results[0]?.status).toBe('accepted');
    const local = new FakeLocalStore([mutation]);
    const harness = makeHarness({
      local,
      transport: new FakeTransport([pullPage(0, 0, [], false)], [response]),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    expect(local.pending).toEqual([mutation]);
  });

  it('sends only opaque mutation data and public synchronization metadata', async () => {
    const canaries = Array.from({ length: 10 }, () =>
      randomBytes(24).toString('base64url'),
    );
    const mutation = groupMutation(0, null, 'mutation-key-0004');
    const transport = new FakeTransport(
      [
        pullPage(0, 0, [], false),
        acceptedFeedPage(
          acceptedPushResponse(mutation, 'batch-key-0000001', 'committed', 1),
          [mutation],
        ),
        pullPage(1, 1, [], false),
      ],
      [acceptedPushResponse(mutation, 'batch-key-0000001', 'committed', 1)],
    );
    const harness = makeHarness({
      transport,
      local: new FakeLocalStore([mutation]),
    });

    await harness.engine.synchronize({ vaultId, deviceId });

    const request = transport.pushRequests[0];
    expect(request).toBeDefined();
    expect(Object.keys(request ?? {}).sort()).toEqual([
      'batchIdempotencyKey',
      'mutations',
      'vaultId',
    ]);
    const wire = JSON.stringify(request);
    for (const canary of canaries) expect(wire).not.toContain(canary);
    expect(wire).not.toMatch(
      /portableKey|passphrase|recoveryKey|deviceToken|rootKey|decrypted|plaintext/i,
    );
    expect(request?.mutations[0]).toEqual(opaqueMutationSchema.parse(mutation));
  });
});

describe('SyncEngine atomic template migration publication', () => {
  it('retries a lost response with the exact durable request and never uses generic push', async () => {
    const publication = templateMigrationPublication();
    const response = templateMigrationResponse(publication, 3);
    const local = new FakeLocalStore([], publication);
    const transport = new FakeTransport(
      [templateFeedPage(publication, response), pullPage(3, 3, [], false)],
      [],
      [new SyncTransportFailure('timeout'), response],
    );
    const harness = makeHarness({ transport, local });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toMatchObject({ kind: 'timeout' });
    expect(local.pendingPublication).toEqual(publication);
    expect(local.promotedPublications).toHaveLength(0);

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).resolves.toMatchObject({ state: 'synced', pushedMutations: 3 });
    expect(transport.publicationRequests).toEqual([publication, publication]);
    expect(transport.pushRequests).toHaveLength(0);
    expect(local.pendingPublication).toBeNull();
    expect(local.promotedPublications).toEqual([]);
    expect(publication.mutations.map((mutation) => mutation.entityType)).toEqual([
      'item',
      'item',
      'group',
    ]);
    expect(publication.mutations.slice(0, 2).map(({ record }) => record.id)).toEqual([
      'item.1',
      'item.2',
    ]);
  });

  it('rejects malformed and cross-vault acknowledgements before local promotion', async () => {
    const publication = templateMigrationPublication();
    const valid = templateMigrationResponse(publication, 3);
    const invalidResponses = [
      { ...valid, vaultId: 'vault.other' },
      { ...valid, batchIdempotencyKey: 'wrong-template-batch-key-0001' },
      { ...valid, results: valid.results.slice(1) },
      {
        ...valid,
        results: valid.results.map((result, index) =>
          index === 0 ? { ...result, idempotencyKey: 'wrong-result-key-0001' } : result,
        ),
      },
      {
        ...valid,
        results: valid.results.map((result, index) =>
          index === 0
            ? {
                ...result,
                change: { ...result.change, ciphertextHash: wrongDigest },
              }
            : result,
        ),
      },
      {
        ...valid,
        results: valid.results.map((result, index) =>
          index === 0
            ? { ...result, change: { ...result.change, entityId: 'item.other' } }
            : result,
        ),
      },
      {
        ...valid,
        results: valid.results.map((result, index) =>
          index === 0
            ? { ...result, change: { ...result.change, recordRevision: 2 } }
            : result,
        ),
      },
    ];
    for (const invalid of invalidResponses) {
      const local = new FakeLocalStore([], publication);
      const harness = makeHarness({
        local,
        transport: new FakeTransport(
          [pullPage(0, 0, [], false)],
          [],
          [invalid as never],
        ),
      });
      await expect(
        harness.engine.synchronize({ vaultId, deviceId }),
      ).rejects.toBeInstanceOf(SyncProtocolError);
      expect(local.pendingPublication).toEqual(publication);
      expect(local.promotedPublications).toHaveLength(0);
    }
  });

  it('keeps conflict and authorization terminal without clearing the publication', async () => {
    const publication = templateMigrationPublication();
    for (const [failure, code] of [
      [new SyncTransportFailure('conflict'), 'atomic-publication-conflict'],
      [new SyncTransportFailure('unauthorized'), 'authorization-failed'],
    ] as const) {
      const local = new FakeLocalStore([], publication);
      const harness = makeHarness({
        local,
        transport: new FakeTransport([pullPage(0, 0, [], false)], [], [failure]),
      });
      await expect(harness.engine.synchronize({ vaultId, deviceId })).rejects.toBe(
        failure,
      );
      expect(local.pendingPublication).toEqual(publication);
      expect(harness.status.values.at(-1)).toMatchObject({
        state: 'error',
        code,
        retryable: false,
      });
    }
  });

  it('rejects a rollback response before promoting or removing the publication', async () => {
    const publication = templateMigrationPublication();
    const local = new FakeLocalStore([], publication);
    const protectedState = new FakeProtectedState();
    protectedState.value = protectedLocalDeviceStateSchema.parse({
      version: 2,
      vaultId,
      deviceId,
      highestSeenVaultRevision: 4,
      updatedAt: timestamp,
    });
    const harness = makeHarness({
      local,
      protectedState,
      transport: new FakeTransport(
        [pullPage(4, 0, [], false)],
        [],
        [templateMigrationResponse(publication, 3)],
      ),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncRollbackError);
    expect(local.pendingPublication).toEqual(publication);
    expect(local.promotedPublications).toHaveLength(0);
  });
});

describe('retry classification and terminal states', () => {
  it('classifies only transient transport failures as retryable', () => {
    expect(classifySyncFailure(new SyncTransportFailure('offline'))).toEqual({
      state: 'offline',
      code: 'network-unavailable',
      retryable: true,
    });
    expect(classifySyncFailure(new SyncTransportFailure('server'))).toEqual({
      state: 'error',
      code: 'service-unavailable',
      retryable: true,
    });
    expect(classifySyncFailure(new SyncTransportFailure('device-revoked'))).toEqual({
      state: 'error',
      code: 'device-revoked',
      retryable: false,
    });
    expect(classifySyncFailure(new SyncTransportFailure('rate-limited'))).toEqual({
      state: 'error',
      code: 'rate-limited',
      retryable: true,
    });
    expect(classifySyncFailure(new SyncTransportFailure('client'))).toEqual({
      state: 'error',
      code: 'request-rejected',
      retryable: false,
    });
    expect(classifySyncFailure(new SyncLocalStateError())).toEqual({
      state: 'error',
      code: 'local-state-invalid',
      retryable: false,
    });
    expect(classifySyncFailure(new Error('unknown'))).toEqual({
      state: 'error',
      code: 'unexpected',
      retryable: false,
    });
  });

  it('transitions from syncing to offline for unavailable transport', async () => {
    const harness = makeHarness({
      transport: new FakeTransport([new SyncTransportFailure('offline')]),
    });

    await expect(
      harness.engine.synchronize({ vaultId, deviceId }),
    ).rejects.toBeInstanceOf(SyncTransportFailure);
    expect(harness.status.values.map(({ state }) => state)).toEqual([
      'syncing',
      'offline',
    ]);
  });

  it('rejects concurrent runs on one engine before transport state can race', async () => {
    let releasePull: (() => void) | undefined;
    const waitForRelease = new Promise<void>((resolve) => {
      releasePull = resolve;
    });
    const page = pullPage(0, 0, [], false);
    const transport: SyncTransportPort = {
      async pull(): Promise<PullPageResponse> {
        await waitForRelease;
        return page;
      },
      push(): Promise<PushBatchResponse> {
        return Promise.reject(new Error('Unexpected push'));
      },
      publishTemplateMigration(): Promise<TemplateMigrationPublicationResponse> {
        return Promise.reject(new Error('Unexpected template migration'));
      },
    };
    const local = new FakeLocalStore();
    const protectedState = new FakeProtectedState();
    const status = new FakeStatus();
    const engine = new SyncEngine({
      transport,
      local,
      protectedState,
      status,
      clock: new FixedClock(),
      idempotencyKeys: new SequenceKeys(),
    });

    const first = engine.synchronize({ vaultId, deviceId });
    await expect(engine.synchronize({ vaultId, deviceId })).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    releasePull?.();
    await expect(first).resolves.toMatchObject({ state: 'synced' });
  });
});

class FakeTransport implements SyncTransportPort {
  readonly pullRequests: PullPageRequest[] = [];
  readonly pushRequests: PushBatchRequest[] = [];
  readonly publicationRequests: TemplateMigrationPublicationRequest[] = [];
  readonly #pull: (PullPageResponse | Error)[];
  readonly #push: (PushBatchResponse | Error)[];
  readonly #publications: (TemplateMigrationPublicationResponse | Error)[];
  readonly #events: string[] | undefined;

  constructor(
    pull: (PullPageResponse | Error)[],
    push: (PushBatchResponse | Error)[] = [],
    publications: (TemplateMigrationPublicationResponse | Error)[] = [],
    events?: string[],
  ) {
    this.#pull = pull;
    this.#push = push;
    this.#publications = publications;
    this.#events = events;
  }

  pull(request: PullPageRequest): Promise<PullPageResponse> {
    this.#events?.push('transport.pull');
    this.pullRequests.push(structuredClone(request));
    const next = this.#pull.shift();
    if (next === undefined) return Promise.reject(new Error('Unexpected pull'));
    if (next instanceof Error) return Promise.reject(next);
    return Promise.resolve(next);
  }

  push(request: PushBatchRequest): Promise<PushBatchResponse> {
    this.#events?.push('transport.push');
    this.pushRequests.push(structuredClone(request));
    const next = this.#push.shift();
    if (next === undefined) return Promise.reject(new Error('Unexpected push'));
    if (next instanceof Error) return Promise.reject(next);
    return Promise.resolve(next);
  }

  publishTemplateMigration(
    request: TemplateMigrationPublicationRequest,
  ): Promise<TemplateMigrationPublicationResponse> {
    this.publicationRequests.push(structuredClone(request));
    const next = this.#publications.shift();
    if (next === undefined) {
      return Promise.reject(new Error('Unexpected template migration'));
    }
    if (next instanceof Error) return Promise.reject(next);
    return Promise.resolve(next);
  }
}

class FakeLocalStore implements SyncLocalStorePort {
  cursor: SyncCursor | null = null;
  pending: OpaqueMutation[];
  active: ActivePushBatch | null = null;
  readonly applied: ApplyPullPageInput[] = [];
  failNextApply = false;
  failNextComplete = false;
  failNextReconcile = false;
  failIfDurableWorkLoads = false;
  pendingPublication: TemplateMigrationPublicationRequest | null;
  readonly promotedPublications: CompleteTemplateMigrationPublicationInput[] = [];
  readonly #events: string[] | undefined;
  readonly completed = new Map<string, CompletedOutboundObservation>();
  replayStart: number | null = null;

  constructor(
    pending: OpaqueMutation[] = [],
    pendingPublication: TemplateMigrationPublicationRequest | null = null,
    events?: string[],
  ) {
    this.pending = pending;
    this.pendingPublication = pendingPublication;
    this.#events = events;
  }

  loadCursor(): Promise<SyncCursor | null> {
    return Promise.resolve(this.cursor);
  }

  applyPullPage(input: ApplyPullPageInput): Promise<void> {
    this.#events?.push('local.apply');
    if (this.failNextApply) {
      this.failNextApply = false;
      return Promise.reject(new Error('interrupted apply'));
    }
    this.applied.push(input);
    this.cursor = input.cursor;
    return Promise.resolve();
  }

  listPendingMutations(): Promise<readonly OpaqueMutation[]> {
    return Promise.resolve(this.pending);
  }

  loadActivePushBatch(): Promise<ActivePushBatch | null> {
    if (this.failIfDurableWorkLoads) {
      return Promise.reject(new Error('durable-work-load-canary'));
    }
    return Promise.resolve(this.active);
  }

  saveActivePushBatch(batch: ActivePushBatch): Promise<void> {
    this.active = batch;
    this.replayStart = this.cursor?.serverSequence ?? 0;
    return Promise.resolve();
  }

  completePushBatch(input: CompletePushBatchInput): Promise<void> {
    if (this.failNextComplete) {
      this.failNextComplete = false;
      return Promise.reject(new Error('interrupted completion'));
    }
    if (this.active?.batchIdempotencyKey !== input.batchIdempotencyKey) {
      return Promise.reject(new Error('Wrong active batch'));
    }
    const acknowledged = new Set(input.acknowledgedIdempotencyKeys);
    this.pending = this.pending.filter(
      (mutation) => !acknowledged.has(mutation.idempotencyKey),
    );
    this.active = null;
    return Promise.resolve();
  }

  loadPendingTemplateMigrationPublication(): Promise<TemplateMigrationPublicationRequest | null> {
    return Promise.resolve(this.pendingPublication);
  }

  enqueueTemplateMigrationPublication(
    publication: TemplateMigrationPublicationRequest,
  ): Promise<void> {
    this.pendingPublication = publication;
    this.replayStart = this.cursor?.serverSequence ?? 0;
    return Promise.resolve();
  }

  completeTemplateMigrationPublication(
    input: CompleteTemplateMigrationPublicationInput,
  ): Promise<void> {
    if (
      this.pendingPublication?.batchIdempotencyKey !==
      input.publication.batchIdempotencyKey
    ) {
      return Promise.reject(new Error('Wrong template migration publication'));
    }
    this.promotedPublications.push(input);
    this.pendingPublication = null;
    return Promise.resolve();
  }

  loadOutboundReplayState(
    _vaultId: VaultId,
    kind: OutboundReplayState['kind'],
  ): Promise<OutboundReplayState | null> {
    const key =
      kind === 'generic-push'
        ? this.active?.batchIdempotencyKey
        : this.pendingPublication?.batchIdempotencyKey;
    return Promise.resolve(
      key === undefined
        ? null
        : {
            kind,
            vaultId,
            batchIdempotencyKey: key,
            replayFromServerSequence: this.replayStart,
          },
    );
  }

  ensureOutboundReplayStart(input: EnsureOutboundReplayStartInput): Promise<number> {
    const expected =
      input.kind === 'generic-push'
        ? this.active?.batchIdempotencyKey
        : this.pendingPublication?.batchIdempotencyKey;
    if (expected !== input.batchIdempotencyKey) {
      return Promise.reject(new Error('Wrong replay work'));
    }
    this.replayStart ??= this.cursor?.serverSequence ?? 0;
    return Promise.resolve(this.replayStart);
  }

  loadCompletedOutboundObservation(
    _vaultId: VaultId,
    observationId: Sha256Digest,
  ): Promise<CompletedOutboundObservation | null> {
    return Promise.resolve(this.completed.get(observationId) ?? null);
  }

  confirmCompletedOutboundObservation(
    _vaultId: VaultId,
    _deviceId: DeviceId,
    observation: ReconcileOutboundObservationInput['observation'],
  ): Promise<CompletedOutboundObservation> {
    const receipt = this.completed.get(observation.observationId);
    return receipt === undefined
      ? Promise.reject(new Error('Missing receipt'))
      : Promise.resolve(receipt);
  }

  releaseCompletedOutboundObservation(): Promise<void> {
    this.#events?.push('local.release');
    return Promise.resolve();
  }

  reconcileOutboundObservation(
    input: ReconcileOutboundObservationInput,
  ): Promise<CompletedOutboundObservation> {
    this.#events?.push('local.reconcile');
    if (this.failNextReconcile) {
      this.failNextReconcile = false;
      return Promise.reject(new Error('interrupted reconciliation'));
    }
    this.cursor = input.finalCursor;
    if (input.kind === 'generic-push') {
      const accepted = new Set(
        input.response.results
          .filter((result) => result.status === 'accepted')
          .map((result) => result.idempotencyKey),
      );
      this.pending = this.pending.filter(
        (mutation) => !accepted.has(mutation.idempotencyKey),
      );
      this.active = null;
    } else {
      this.pendingPublication = null;
    }
    const receipt = {
      kind: input.kind,
      vaultId: input.vaultId,
      deviceId: input.deviceId,
      observation: input.observation,
      request: input.request,
      response: input.response,
      finalCursor: input.finalCursor,
      serializedBytes: 1,
    } as CompletedOutboundObservation;
    this.completed.set(input.observation.observationId, receipt);
    return Promise.resolve(receipt);
  }
}

class FakeProtectedState implements ProtectedSyncStatePort {
  value: ProtectedLocalDeviceState | null = null;
  failNextSave = false;
  failNextComplete = false;
  loadFailure: unknown;
  readonly #events: string[] | undefined;

  constructor(events?: string[]) {
    this.#events = events;
  }

  load(): Promise<ProtectedLocalDeviceState | null> {
    if (this.loadFailure !== undefined) {
      return Promise.reject(
        this.loadFailure instanceof Error
          ? this.loadFailure
          : new Error('Protected state load failed'),
      );
    }
    return Promise.resolve(this.value);
  }

  save(state: ProtectedLocalDeviceState): Promise<void> {
    this.#events?.push('protected.save');
    if (this.failNextSave) {
      this.failNextSave = false;
      return Promise.reject(new Error('protected-save-canary'));
    }
    this.value = state;
    return Promise.resolve();
  }

  completeObservation(
    _vaultId: VaultId,
    _deviceId: DeviceId,
    expectedObservationId: Sha256Digest,
    candidateRevision: ProtectedLocalDeviceState['highestSeenVaultRevision'],
    updatedAt: ProtectedLocalDeviceState['updatedAt'],
  ): Promise<void> {
    this.#events?.push('protected.complete');
    if (this.failNextComplete) {
      this.failNextComplete = false;
      return Promise.reject(new Error('protected-complete-canary'));
    }
    if (this.value?.outboundObservation?.observationId !== expectedObservationId) {
      return Promise.reject(new Error('Wrong observation completion'));
    }
    this.value = protectedLocalDeviceStateSchema.parse({
      version: 2,
      vaultId,
      deviceId,
      highestSeenVaultRevision: candidateRevision,
      updatedAt,
      lastCompletedObservationId: expectedObservationId,
    });
    return Promise.resolve();
  }
}

class FakeStatus implements SyncStatusPort {
  readonly values: SyncStatus[] = [];
  failNext = false;
  readonly #events: string[] | undefined;

  constructor(events?: string[]) {
    this.#events = events;
  }

  set(status: SyncStatus): Promise<void> {
    this.#events?.push(`status.${status.state}`);
    this.values.push(status);
    if (this.failNext) {
      this.failNext = false;
      return Promise.reject(new Error('status-sink-canary'));
    }
    return Promise.resolve();
  }
}

class FixedClock implements SyncClockPort {
  now(): Date {
    return new Date(timestamp);
  }
}

class SequenceKeys implements SyncIdempotencyKeyPort {
  #index = 0;

  next(): string {
    this.#index += 1;
    return `batch-key-${String(this.#index).padStart(7, '0')}`;
  }
}

function makeHarness(options: {
  transport: FakeTransport;
  local?: FakeLocalStore;
  protectedState?: FakeProtectedState;
  status?: FakeStatus;
  pullPageSize?: number;
}): {
  engine: SyncEngine;
  local: FakeLocalStore;
  protectedState: FakeProtectedState;
  status: FakeStatus;
} {
  const local = options.local ?? new FakeLocalStore();
  const protectedState = options.protectedState ?? new FakeProtectedState();
  const status = options.status ?? new FakeStatus();
  return {
    engine: new SyncEngine({
      transport: options.transport,
      local,
      protectedState,
      status,
      clock: new FixedClock(),
      idempotencyKeys: new SequenceKeys(),
      ...(options.pullPageSize === undefined
        ? {}
        : { pullPageSize: options.pullPageSize }),
    }),
    local,
    protectedState,
    status,
  };
}

function pullPage(
  vaultRevision: number,
  sequence: number,
  changes: PullPageResponse['changes'],
  hasMore: boolean,
): PullPageResponse {
  const cursor = syncCursorSchema.parse({
    vaultId,
    serverSequence: sequence,
    highestSeenVaultRevision: vaultRevision,
  });
  return {
    vaultId,
    serverVaultRevision: cursor.highestSeenVaultRevision,
    changes,
    nextCursor: cursor,
    hasMore,
  };
}

function purgeChange(
  sequence: number,
  entityId: string,
  revision: number,
): ChangeRecord {
  return changeRecordSchema.parse({
    id: `change.${String(sequence)}`,
    vaultId,
    serverSequence: sequence,
    entityType: 'group',
    entityId,
    recordRevision: revision,
    operation: 'purge',
    createdAt: timestamp,
  });
}

function groupRecord(
  revision: number,
  recordVaultId = 'vault.1',
): EncryptedGroupRecord {
  return encryptedGroupRecordSchema.parse({
    id: 'group.1',
    vaultId: recordVaultId,
    schemaVersion: 1,
    wrappedGroupKey: envelope('wrapped-group-key', 'group.1', recordVaultId),
    encryptedPayload: envelope('group', 'group.1', recordVaultId),
    templateVersion: 1,
    recordRevision: revision,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

function groupMutation(
  revision: number,
  expected: number | null,
  idempotencyKey: string,
): OpaqueMutation {
  return opaqueMutationSchema.parse({
    entityType: 'group',
    expectedRecordRevision: expected,
    idempotencyKey,
    record: groupRecord(revision),
  });
}

function acceptedPushResponse(
  mutation: OpaqueMutation,
  batchIdempotencyKey: string,
  disposition: 'committed' | 'duplicate',
  serverVaultRevision: number,
): PushBatchResponse {
  if (mutation.entityType !== 'group') throw new Error('Expected group mutation');
  const change = changeRecordSchema.parse({
    id: 'change.push.1',
    vaultId,
    serverSequence: 1,
    entityType: 'group',
    entityId: mutation.record.id,
    recordRevision: mutation.record.recordRevision,
    operation: 'upsert',
    ciphertextHash: contentHashForRecord(mutation.record),
    createdAt: timestamp,
  });
  return {
    vaultId,
    serverVaultRevision:
      serverVaultRevision as PushBatchResponse['serverVaultRevision'],
    batchIdempotencyKey,
    results: [
      {
        status: 'accepted',
        idempotencyKey: mutation.idempotencyKey,
        disposition,
        change,
      },
    ],
  };
}

function acceptedFeedPage(
  response: PushBatchResponse,
  mutations: readonly OpaqueMutation[],
): PullPageResponse {
  const changes = response.results.flatMap((result, index) => {
    if (result.status !== 'accepted') return [];
    const mutation = mutations[index];
    if (mutation === undefined) throw new Error('Missing mutation fixture');
    return [{ change: result.change, record: mutation.record }];
  });
  const sequence = Math.max(0, ...changes.map(({ change }) => change.serverSequence));
  return pullPage(response.serverVaultRevision, sequence, changes, false);
}

function templateFeedPage(
  publication: TemplateMigrationPublicationRequest,
  response: TemplateMigrationPublicationResponse,
): PullPageResponse {
  const changes = response.results.map((result, index) => {
    const mutation = publication.mutations[index];
    if (mutation === undefined) throw new Error('Missing publication fixture');
    return { change: result.change, record: mutation.record };
  });
  return pullPage(response.serverVaultRevision, changes.length, changes, false);
}

function templateMigrationPublication(): TemplateMigrationPublicationRequest {
  const first = itemRecord('item.1', 1);
  const second = itemRecord('item.2', 1);
  const group = encryptedGroupRecordSchema.parse({
    ...groupRecord(1),
    templateVersion: 2,
  });
  return templateMigrationPublicationRequestSchema.parse({
    vaultId,
    batchIdempotencyKey: 'template-batch-key-0001',
    mutations: [
      opaqueMutationSchema.parse({
        entityType: 'item',
        expectedRecordRevision: 0,
        idempotencyKey: 'template-item-key-0001',
        record: first,
      }),
      opaqueMutationSchema.parse({
        entityType: 'item',
        expectedRecordRevision: 0,
        idempotencyKey: 'template-item-key-0002',
        record: second,
      }),
      opaqueMutationSchema.parse({
        entityType: 'group',
        expectedRecordRevision: 0,
        idempotencyKey: 'template-group-key-0001',
        record: group,
      }),
    ],
  });
}

function templateMigrationResponse(
  publication: TemplateMigrationPublicationRequest,
  serverVaultRevision: number,
): TemplateMigrationPublicationResponse {
  return templateMigrationPublicationResponseSchema.parse({
    vaultId: publication.vaultId,
    batchIdempotencyKey: publication.batchIdempotencyKey,
    serverVaultRevision,
    results: publication.mutations.map((mutation, index) => ({
      idempotencyKey: mutation.idempotencyKey,
      change: changeRecordSchema.parse({
        id: `change.template.${String(index + 1)}`,
        vaultId: publication.vaultId,
        serverSequence: index + 1,
        entityType: mutation.entityType,
        entityId: mutation.record.id,
        recordRevision:
          'revision' in mutation.record
            ? mutation.record.revision
            : mutation.record.recordRevision,
        operation: 'upsert',
        ciphertextHash: contentHashForRecord(mutation.record),
        createdAt: timestamp,
      }),
    })),
  });
}

function itemRecord(id: string, revision: number): EncryptedItemRecord {
  return encryptedItemRecordSchema.parse({
    id,
    vaultId,
    groupId: 'group.1',
    schemaVersion: 1,
    wrappedItemKey: envelope('wrapped-item-key', id, vaultId, 'group.1'),
    encryptedPayload: envelope('item', id, vaultId, 'group.1'),
    recordRevision: revision,
    ciphertextHash: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

function envelope(
  entityType: 'group' | 'wrapped-group-key' | 'item' | 'wrapped-item-key',
  entityId: string,
  id: string,
  groupId?: string,
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
      vaultId: id,
      entityType,
      entityId,
      purpose:
        entityType === 'group'
          ? 'group-payload'
          : entityType === 'wrapped-group-key'
            ? 'group-key'
            : entityType === 'item'
              ? 'item-payload'
              : 'item-key',
      ...(groupId === undefined ? {} : { groupId }),
    },
    keyVersion: 1,
  };
}
