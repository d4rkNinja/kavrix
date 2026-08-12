import {
  canonicalJson,
  protectedLocalDeviceStateSchema,
  syncCursorSchema,
  timestampSchema,
} from '@kavrix/schemas';
import type {
  OutboundObservation,
  ProtectedLocalDeviceState,
  SyncCursor,
  TemplateMigrationPublicationRequest,
  TemplateMigrationPublicationResponse,
  Timestamp,
  VaultRevision,
} from '@kavrix/schemas';

import {
  classifySyncFailure,
  SyncLocalStateError,
  SyncProtocolError,
  SyncRollbackError,
} from './errors.js';
import type {
  ProtectedSyncStatePort,
  SyncClockPort,
  SyncIdempotencyKeyPort,
  SyncLocalStorePort,
  SyncStatusPort,
  SyncTransportPort,
} from './ports.js';
import type {
  ActivePushBatch,
  CompletedOutboundObservation,
  OpaqueMutation,
  PulledChange,
  PushBatchRequest,
  PushBatchResponse,
  SyncConflict,
  SyncRunInput,
  SyncRunResult,
  SyncStatus,
} from './types.js';
import {
  MAX_OUTBOUND_RECONCILIATION_CHANGES,
  measureOutboundReconciliationChanges,
} from './types.js';
import {
  createOutboundObservation,
  hashOutboundObservationRequest,
  hashOutboundObservationResponse,
  validateOutboundObservationBinding,
} from './outbound-observation.js';
import {
  parseCursor,
  parsePullPage,
  parsePushResponse,
  parseTemplateMigrationPublicationResponse,
  validateActiveBatch,
  validateGeneratedIdempotencyKey,
  validatePendingMutations,
  validatePendingTemplateMigrationPublication,
  validateOutboundStagedRange,
} from './validation.js';

export interface SyncEngineOptions {
  readonly transport: SyncTransportPort;
  readonly local: SyncLocalStorePort;
  readonly protectedState: ProtectedSyncStatePort;
  readonly status: SyncStatusPort;
  readonly clock: SyncClockPort;
  readonly idempotencyKeys: SyncIdempotencyKeyPort;
  readonly pullPageSize?: number;
  readonly pushBatchSize?: number;
}

type DurableOutboundWork =
  | Readonly<{
      kind: 'generic-push';
      request: PushBatchRequest;
      replayFromServerSequence: number;
    }>
  | Readonly<{
      kind: 'template-publication';
      request: TemplateMigrationPublicationRequest;
      replayFromServerSequence: number;
    }>;

interface RunState {
  cursor: SyncCursor;
  protectedState: ProtectedLocalDeviceState;
}

type ResolvedOutbound = Readonly<{
  conflicts: readonly SyncConflict[];
  accepted: number;
  pulled: number;
}>;

export class SyncEngine {
  readonly #transport: SyncTransportPort;
  readonly #local: SyncLocalStorePort;
  readonly #protectedState: ProtectedSyncStatePort;
  readonly #status: SyncStatusPort;
  readonly #clock: SyncClockPort;
  readonly #idempotencyKeys: SyncIdempotencyKeyPort;
  readonly #pullPageSize: number;
  readonly #pushBatchSize: number;
  #running = false;

  constructor(options: SyncEngineOptions) {
    this.#transport = options.transport;
    this.#local = options.local;
    this.#protectedState = options.protectedState;
    this.#status = options.status;
    this.#clock = options.clock;
    this.#idempotencyKeys = options.idempotencyKeys;
    this.#pullPageSize = boundedInteger(
      options.pullPageSize ?? 100,
      500,
      'Sync pull page size',
    );
    this.#pushBatchSize = boundedInteger(
      options.pushBatchSize ?? 50,
      100,
      'Sync push batch size',
    );
  }

  async synchronize(input: SyncRunInput): Promise<SyncRunResult> {
    if (this.#running) throw new SyncLocalStateError();
    let visibleCursor = syncCursorSchema.parse({
      vaultId: input.vaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 0,
    });
    this.#running = true;
    let pulledChanges = 0;
    let pushedMutations = 0;

    try {
      const state = await this.#loadState(input);
      visibleCursor = state.cursor;
      await this.#setStatus({
        state: 'syncing',
        vaultId: input.vaultId,
        cursor: state.cursor,
        phase: 'pull',
        at: this.#now(),
      });

      await this.#releaseCompletedPinAtStartup(input, state);

      const protectedObservation = state.protectedState.outboundObservation;
      if (protectedObservation !== undefined) {
        const recovered = await this.#recoverProtectedObservation(
          input,
          state,
          protectedObservation,
        );
        pushedMutations += recovered.accepted;
        pulledChanges += recovered.pulled;
        visibleCursor = state.cursor;
      } else {
        const durableWork = await this.#loadDurableOutboundWork(input.vaultId);
        if (durableWork !== null) {
          // Work durable at run start is recovered history. Its conflict payload is
          // suppressed and any remaining mutation is retried in a fresh batch.
          const recovered = await this.#observeAndResolve(
            input,
            state,
            durableWork,
            true,
          );
          pushedMutations += recovered.accepted;
          pulledChanges += recovered.pulled;
          visibleCursor = state.cursor;
        }
      }

      pulledChanges += await this.#pullOrdinaryPages(input, state);
      visibleCursor = state.cursor;

      await this.#setStatus({
        state: 'syncing',
        vaultId: input.vaultId,
        cursor: state.cursor,
        phase: 'push',
        at: this.#now(),
      });

      // A writer lease excludes a concurrent enqueue. Seeing work here means a
      // local adapter violated the state snapshot used above.
      const latePublication = await this.#localBoundary(() =>
        this.#local.loadPendingTemplateMigrationPublication(input.vaultId),
      );
      if (latePublication !== null) {
        throw new SyncLocalStateError();
      }

      const conflicts: SyncConflict[] = [];
      const acknowledgedThisRun = new Set<string>();
      for (;;) {
        const pending = validatePendingMutations(
          await this.#localBoundary(() =>
            this.#local.listPendingMutations(input.vaultId),
          ),
          input.vaultId,
        );
        if (pending.length === 0) break;
        if (
          pending.some((mutation) => acknowledgedThisRun.has(mutation.idempotencyKey))
        ) {
          throw new SyncLocalStateError();
        }
        const work = await this.#loadOrCreateBatch(input.vaultId, pending);
        const resolved = await this.#observeAndResolve(input, state, work, false);
        visibleCursor = state.cursor;
        pushedMutations += resolved.accepted;
        pulledChanges += resolved.pulled;
        for (const conflict of resolved.conflicts) {
          conflicts.push(conflict);
        }
        for (const mutation of work.request.mutations) {
          if (
            resolved.conflicts.every(
              (conflict) =>
                conflict.mutation.idempotencyKey !== mutation.idempotencyKey,
            )
          ) {
            acknowledgedThisRun.add(mutation.idempotencyKey);
          }
        }
        if (resolved.conflicts.length > 0) break;
      }

      if (conflicts.length > 0) {
        await this.#setStatus({
          state: 'conflict',
          vaultId: input.vaultId,
          cursor: state.cursor,
          conflicts,
          at: this.#now(),
        });
        return {
          state: 'conflict',
          cursor: state.cursor,
          pulledChanges,
          pushedMutations,
          conflicts,
        };
      }

      await this.#setStatus({
        state: 'synced',
        vaultId: input.vaultId,
        cursor: state.cursor,
        at: this.#now(),
      });
      return {
        state: 'synced',
        cursor: state.cursor,
        pulledChanges,
        pushedMutations,
      };
    } catch (error) {
      const classification = classifySyncFailure(error);
      const terminal: SyncStatus =
        classification.state === 'offline'
          ? {
              state: 'offline',
              vaultId: input.vaultId,
              cursor: visibleCursor,
              reason: 'network-unavailable',
              at: this.#now(),
            }
          : {
              state: 'error',
              vaultId: input.vaultId,
              cursor: visibleCursor,
              code: classification.code,
              retryable: classification.retryable,
              at: this.#now(),
            };
      try {
        await this.#setStatus(terminal);
      } catch {
        // Status reporting is advisory and must not mask the classified failure.
      }
      throw error;
    } finally {
      this.#running = false;
    }
  }

  async #loadState(input: SyncRunInput): Promise<RunState> {
    const rawProtected = await this.#protectedBoundary(() =>
      this.#protectedState.load(input.vaultId, input.deviceId),
    );
    const protectedState =
      rawProtected === null
        ? protectedLocalDeviceStateSchema.parse({
            version: 2,
            vaultId: input.vaultId,
            deviceId: input.deviceId,
            highestSeenVaultRevision: 0,
            updatedAt: this.#now(),
          })
        : this.#parseProtected(rawProtected, input);
    const rawCursor = await this.#localBoundary(() =>
      this.#local.loadCursor(input.vaultId),
    );
    const cursor =
      rawCursor === null
        ? syncCursorSchema.parse({
            vaultId: input.vaultId,
            serverSequence: 0,
            highestSeenVaultRevision: protectedState.highestSeenVaultRevision,
          })
        : parseCursor(rawCursor, input.vaultId);
    const highest = maxRevision(
      cursor.highestSeenVaultRevision,
      protectedState.highestSeenVaultRevision,
    );
    return {
      protectedState,
      cursor: syncCursorSchema.parse({ ...cursor, highestSeenVaultRevision: highest }),
    };
  }

  #parseProtected(value: unknown, input: SyncRunInput): ProtectedLocalDeviceState {
    try {
      const state = validateOutboundObservationBinding(value);
      if (state.vaultId !== input.vaultId || state.deviceId !== input.deviceId) {
        throw new SyncLocalStateError();
      }
      return state;
    } catch {
      throw new SyncLocalStateError();
    }
  }

  async #releaseCompletedPinAtStartup(
    input: SyncRunInput,
    state: RunState,
  ): Promise<void> {
    if (
      state.protectedState.outboundObservation !== undefined ||
      state.protectedState.lastCompletedObservationId === undefined
    ) {
      return;
    }
    const completedObservationId = state.protectedState.lastCompletedObservationId;
    await this.#localBoundary(() =>
      this.#local.releaseCompletedOutboundObservation(
        input.vaultId,
        input.deviceId,
        completedObservationId,
      ),
    );
  }

  async #loadDurableOutboundWork(
    vaultId: SyncRunInput['vaultId'],
  ): Promise<DurableOutboundWork | null> {
    const [rawPublication, rawActive] = await Promise.all([
      this.#localBoundary(() =>
        this.#local.loadPendingTemplateMigrationPublication(vaultId),
      ),
      this.#localBoundary(() => this.#local.loadActivePushBatch(vaultId)),
    ]);
    if (rawPublication !== null && rawActive !== null) {
      throw new SyncLocalStateError();
    }
    if (rawPublication !== null) {
      const request = validatePendingTemplateMigrationPublication(
        rawPublication,
        vaultId,
      );
      const replayFromServerSequence = await this.#exactReplayStart(
        'template-publication',
        vaultId,
        request.batchIdempotencyKey,
      );
      return { kind: 'template-publication', request, replayFromServerSequence };
    }
    if (rawActive !== null) {
      const active = validateActiveBatch(rawActive, vaultId);
      const pending = validatePendingMutations(
        await this.#localBoundary(() => this.#local.listPendingMutations(vaultId)),
        vaultId,
      );
      const pendingByKey = new Map(
        pending.map((mutation) => [mutation.idempotencyKey, mutation]),
      );
      const mutations = active.mutationIdempotencyKeys.map((key) => {
        const mutation = pendingByKey.get(key);
        if (mutation === undefined) throw new SyncLocalStateError();
        return mutation;
      });
      const request: PushBatchRequest = {
        vaultId,
        batchIdempotencyKey: active.batchIdempotencyKey,
        mutations: [...mutations],
      };
      const replayFromServerSequence = await this.#exactReplayStart(
        'generic-push',
        vaultId,
        active.batchIdempotencyKey,
      );
      return { kind: 'generic-push', request, replayFromServerSequence };
    }
    const [genericReplay, templateReplay] = await Promise.all([
      this.#localBoundary(() =>
        this.#local.loadOutboundReplayState(vaultId, 'generic-push'),
      ),
      this.#localBoundary(() =>
        this.#local.loadOutboundReplayState(vaultId, 'template-publication'),
      ),
    ]);
    if (genericReplay !== null || templateReplay !== null) {
      throw new SyncLocalStateError();
    }
    return null;
  }

  async #exactReplayStart(
    kind: DurableOutboundWork['kind'],
    vaultId: SyncRunInput['vaultId'],
    batchIdempotencyKey: string,
  ): Promise<number> {
    const replay = await this.#localBoundary(() =>
      this.#local.loadOutboundReplayState(vaultId, kind),
    );
    if (
      replay?.kind !== kind ||
      replay.vaultId !== vaultId ||
      replay.batchIdempotencyKey !== batchIdempotencyKey
    ) {
      throw new SyncLocalStateError();
    }
    const bound = await this.#localBoundary(() =>
      this.#local.ensureOutboundReplayStart({
        kind,
        vaultId,
        batchIdempotencyKey,
      }),
    );
    if (
      !Number.isSafeInteger(bound) ||
      bound < 0 ||
      (replay.replayFromServerSequence !== null &&
        replay.replayFromServerSequence !== bound)
    ) {
      throw new SyncLocalStateError();
    }
    return bound;
  }

  async #recoverProtectedObservation(
    input: SyncRunInput,
    state: RunState,
    observation: OutboundObservation,
  ): Promise<ResolvedOutbound> {
    const receipt = await this.#localBoundary(() =>
      this.#local.loadCompletedOutboundObservation(
        input.vaultId,
        observation.observationId,
      ),
    );
    if (receipt !== null) {
      this.#assertExactReceipt(
        receipt,
        input,
        observation,
        state.protectedState.highestSeenVaultRevision,
      );
      if (canonicalJson(state.cursor) !== canonicalJson(receipt.finalCursor)) {
        throw new SyncLocalStateError();
      }
      const confirmed = await this.#localBoundary(() =>
        this.#local.confirmCompletedOutboundObservation(
          input.vaultId,
          input.deviceId,
          observation,
        ),
      );
      this.#assertExactReceipt(
        confirmed,
        input,
        observation,
        state.protectedState.highestSeenVaultRevision,
      );
      this.#assertEqualLocalReceipts(confirmed, receipt);
      await this.#completeAndRelease(input, state, observation, confirmed.finalCursor);
      return this.#resultFromReceipt(confirmed);
    }
    const durableWork = await this.#loadDurableOutboundWork(input.vaultId);
    if (durableWork === null) throw new SyncLocalStateError();
    this.#assertExactWorkObservation(durableWork, observation);
    this.#assertReplayCursor(state, observation.replayFromServerSequence);
    const response = await this.#sendAndParse(durableWork);
    if (
      hashOutboundObservationResponse(durableWork.kind, response) !==
      observation.responseHash
    ) {
      throw new SyncProtocolError();
    }
    return this.#resolveObservation(input, state, durableWork, response, observation);
  }

  #resultFromReceipt(receipt: CompletedOutboundObservation): ResolvedOutbound {
    if (receipt.kind === 'template-publication') {
      return {
        conflicts: [],
        accepted: receipt.request.mutations.length,
        pulled:
          receipt.observation.requiredThroughServerSequence -
          receipt.observation.replayFromServerSequence,
      };
    }
    const conflicts: SyncConflict[] = [];
    let accepted = 0;
    for (const [index, result] of receipt.response.results.entries()) {
      const mutation = receipt.request.mutations[index];
      if (mutation === undefined) throw new SyncLocalStateError();
      if (result.status === 'accepted') accepted += 1;
      else {
        conflicts.push({
          mutation,
          currentRevision: result.currentRevision,
          current: result.current,
        });
      }
    }
    return {
      conflicts: [],
      accepted,
      pulled:
        receipt.observation.requiredThroughServerSequence -
        receipt.observation.replayFromServerSequence,
    };
  }

  #assertExactWorkObservation(
    work: DurableOutboundWork,
    observation: OutboundObservation,
  ): void {
    try {
      if (
        work.kind !== observation.kind ||
        work.request.batchIdempotencyKey !== observation.batchIdempotencyKey ||
        work.replayFromServerSequence !== observation.replayFromServerSequence ||
        hashOutboundObservationRequest(work.kind, work.request) !==
          observation.requestHash
      ) {
        throw new SyncLocalStateError();
      }
    } catch {
      throw new SyncLocalStateError();
    }
  }

  #assertExactReceipt(
    receipt: CompletedOutboundObservation,
    input: SyncRunInput,
    observation: OutboundObservation,
    protectedRevision: VaultRevision,
  ): void {
    try {
      if (
        !hasExactObjectKeys(receipt, [
          'kind',
          'vaultId',
          'deviceId',
          'observation',
          'request',
          'response',
          'finalCursor',
          'serializedBytes',
        ]) ||
        receipt.vaultId !== input.vaultId ||
        receipt.deviceId !== input.deviceId ||
        receipt.kind !== observation.kind ||
        canonicalJson(receipt.observation) !== canonicalJson(observation) ||
        receipt.request.batchIdempotencyKey !== observation.batchIdempotencyKey ||
        !Number.isSafeInteger(receipt.serializedBytes) ||
        receipt.serializedBytes <= 0 ||
        hashOutboundObservationRequest(receipt.kind, receipt.request) !==
          observation.requestHash ||
        hashOutboundObservationResponse(receipt.kind, receipt.response) !==
          observation.responseHash ||
        receipt.finalCursor.serverSequence !==
          observation.requiredThroughServerSequence ||
        receipt.finalCursor.highestSeenVaultRevision !== protectedRevision
      ) {
        throw new SyncLocalStateError();
      }
      parseCursor(receipt.finalCursor, input.vaultId);
    } catch {
      throw new SyncLocalStateError();
    }
  }

  #assertEqualLocalReceipts(
    left: CompletedOutboundObservation,
    right: CompletedOutboundObservation,
  ): void {
    try {
      if (canonicalJson(left) !== canonicalJson(right)) {
        throw new SyncLocalStateError();
      }
    } catch {
      throw new SyncLocalStateError();
    }
  }

  async #observeAndResolve(
    input: SyncRunInput,
    state: RunState,
    work: DurableOutboundWork,
    recoveredHistory: boolean,
  ): Promise<ResolvedOutbound> {
    this.#assertReplayCursor(state, work.replayFromServerSequence);
    const response = await this.#sendAndParse(work);
    if (work.kind === 'generic-push') {
      const genericResponse = response as PushBatchResponse;
      if (
        genericResponse.results.some(
          (result) =>
            result.status === 'accepted' &&
            result.change.serverSequence <= work.replayFromServerSequence,
        )
      ) {
        throw new SyncRollbackError();
      }
    } else {
      const publicationResponse = response as TemplateMigrationPublicationResponse;
      if (
        publicationResponse.results.some(
          (result) => result.change.serverSequence <= work.replayFromServerSequence,
        )
      ) {
        throw new SyncRollbackError();
      }
    }
    this.#assertFresh(
      response.serverVaultRevision,
      state.protectedState.highestSeenVaultRevision,
    );
    const observation = createOutboundObservation({
      kind: work.kind,
      vaultId: input.vaultId,
      deviceId: input.deviceId,
      request: work.request,
      response,
      replayFromServerSequence: work.replayFromServerSequence,
    });
    await this.#protectState(
      input,
      state,
      maxRevision(
        state.protectedState.highestSeenVaultRevision,
        response.serverVaultRevision,
      ),
      observation,
    );
    const resolved = await this.#resolveObservation(
      input,
      state,
      work,
      response,
      observation,
    );
    return recoveredHistory
      ? { conflicts: [], accepted: resolved.accepted, pulled: resolved.pulled }
      : resolved;
  }

  async #sendAndParse(
    work: DurableOutboundWork,
  ): Promise<PushBatchResponse | TemplateMigrationPublicationResponse> {
    if (work.kind === 'generic-push') {
      const raw: unknown = await this.#transport.push(work.request);
      return parsePushResponse(
        raw,
        work.request.vaultId,
        work.request.batchIdempotencyKey,
        work.request.mutations,
      );
    }
    const raw: unknown = await this.#transport.publishTemplateMigration(work.request);
    return parseTemplateMigrationPublicationResponse(raw, work.request);
  }

  async #resolveObservation(
    input: SyncRunInput,
    state: RunState,
    work: DurableOutboundWork,
    response: PushBatchResponse | TemplateMigrationPublicationResponse,
    observation: OutboundObservation,
  ): Promise<ResolvedOutbound> {
    this.#assertReplayCursor(state, observation.replayFromServerSequence);
    const staged = await this.#stageObservationRange(input, state, observation);
    const reconciliation =
      work.kind === 'generic-push'
        ? ({
            kind: work.kind,
            vaultId: input.vaultId,
            deviceId: input.deviceId,
            observation,
            request: work.request,
            response: response as PushBatchResponse,
            stagedChanges: staged.changes,
            stagedChangesBytes: staged.bytes,
            finalCursor: staged.finalCursor,
          } as const)
        : ({
            kind: work.kind,
            vaultId: input.vaultId,
            deviceId: input.deviceId,
            observation,
            request: work.request,
            response: response as TemplateMigrationPublicationResponse,
            stagedChanges: staged.changes,
            stagedChangesBytes: staged.bytes,
            finalCursor: staged.finalCursor,
          } as const);
    validateOutboundStagedRange(reconciliation);
    await this.#protectState(
      input,
      state,
      staged.finalCursor.highestSeenVaultRevision,
      observation,
    );
    const receipt = await this.#localBoundary(() =>
      this.#local.reconcileOutboundObservation(reconciliation),
    );
    this.#assertExactReceipt(
      receipt,
      input,
      observation,
      state.protectedState.highestSeenVaultRevision,
    );
    await this.#completeAndRelease(input, state, observation, receipt.finalCursor);

    if (work.kind === 'template-publication') {
      return {
        conflicts: [],
        accepted: work.request.mutations.length,
        pulled: staged.changes.length,
      };
    }
    const conflicts: SyncConflict[] = [];
    let accepted = 0;
    for (const [index, result] of (response as PushBatchResponse).results.entries()) {
      const mutation = work.request.mutations[index];
      if (mutation === undefined) throw new SyncLocalStateError();
      if (result.status === 'accepted') {
        accepted += 1;
      } else {
        conflicts.push({
          mutation,
          currentRevision: result.currentRevision,
          current: result.current,
        });
      }
    }
    return { conflicts, accepted, pulled: staged.changes.length };
  }

  async #stageObservationRange(
    input: SyncRunInput,
    state: RunState,
    observation: OutboundObservation,
  ): Promise<
    Readonly<{
      changes: readonly PulledChange[];
      bytes: number;
      finalCursor: SyncCursor;
    }>
  > {
    const required = observation.requiredThroughServerSequence;
    const replayFrom = observation.replayFromServerSequence;
    if (required - replayFrom > MAX_OUTBOUND_RECONCILIATION_CHANGES) {
      throw new SyncProtocolError();
    }
    const changes: PulledChange[] = [];
    let cursor = syncCursorSchema.parse({
      vaultId: input.vaultId,
      serverSequence: replayFrom,
      highestSeenVaultRevision: state.protectedState.highestSeenVaultRevision,
    });
    let bytes = 2;
    while (cursor.serverSequence < required) {
      const limit = Math.min(this.#pullPageSize, required - cursor.serverSequence);
      const raw: unknown = await this.#transport.pull({
        vaultId: input.vaultId,
        cursor,
        limit,
      });
      const page = parsePullPage(raw, input.vaultId, cursor, limit);
      this.#assertFresh(page.serverVaultRevision, cursor.highestSeenVaultRevision);
      if (
        page.nextCursor.serverSequence <= cursor.serverSequence ||
        page.nextCursor.serverSequence > required ||
        (!page.hasMore && page.nextCursor.serverSequence < required)
      ) {
        throw new SyncProtocolError();
      }
      changes.push(...page.changes);
      try {
        bytes = measureOutboundReconciliationChanges(changes);
      } catch {
        throw new SyncProtocolError();
      }
      cursor = page.nextCursor;
    }
    const finalCursor = syncCursorSchema.parse({
      ...cursor,
      highestSeenVaultRevision: maxRevision(
        cursor.highestSeenVaultRevision,
        state.protectedState.highestSeenVaultRevision,
      ),
    });
    return { changes, bytes, finalCursor };
  }

  async #completeAndRelease(
    input: SyncRunInput,
    state: RunState,
    observation: OutboundObservation,
    finalCursorInput: SyncCursor,
  ): Promise<void> {
    const finalCursor = parseCursor(finalCursorInput, input.vaultId);
    const candidateRevision = maxRevision(
      state.protectedState.highestSeenVaultRevision,
      finalCursor.highestSeenVaultRevision,
    );
    const updatedAt = this.#now();
    await this.#protectedBoundary(() =>
      this.#protectedState.completeObservation(
        input.vaultId,
        input.deviceId,
        observation.observationId,
        candidateRevision,
        updatedAt,
      ),
    );
    state.protectedState = protectedLocalDeviceStateSchema.parse({
      version: 2,
      vaultId: input.vaultId,
      deviceId: input.deviceId,
      highestSeenVaultRevision: candidateRevision,
      updatedAt,
      lastCompletedObservationId: observation.observationId,
    });
    await this.#localBoundary(() =>
      this.#local.releaseCompletedOutboundObservation(
        input.vaultId,
        input.deviceId,
        observation.observationId,
      ),
    );
    state.cursor = syncCursorSchema.parse({
      ...finalCursor,
      highestSeenVaultRevision: candidateRevision,
    });
  }

  async #pullOrdinaryPages(input: SyncRunInput, state: RunState): Promise<number> {
    let pulled = 0;
    let hasMore: boolean;
    do {
      const raw: unknown = await this.#transport.pull({
        vaultId: input.vaultId,
        cursor: state.cursor,
        limit: this.#pullPageSize,
      });
      const page = parsePullPage(raw, input.vaultId, state.cursor, this.#pullPageSize);
      this.#assertFresh(
        page.serverVaultRevision,
        state.protectedState.highestSeenVaultRevision,
      );
      await this.#protectState(input, state, page.nextCursor.highestSeenVaultRevision);
      await this.#localBoundary(() =>
        this.#local.applyPullPage({
          vaultId: input.vaultId,
          changes: page.changes,
          cursor: page.nextCursor,
        }),
      );
      state.cursor = page.nextCursor;
      pulled += page.changes.length;
      hasMore = page.hasMore;
    } while (hasMore);
    return pulled;
  }

  async #loadOrCreateBatch(
    vaultId: SyncRunInput['vaultId'],
    pending: readonly OpaqueMutation[],
  ): Promise<Extract<DurableOutboundWork, { kind: 'generic-push' }>> {
    const rawActive = await this.#localBoundary(() =>
      this.#local.loadActivePushBatch(vaultId),
    );
    let active: ActivePushBatch;
    let mutations: readonly OpaqueMutation[];
    if (rawActive !== null) {
      active = validateActiveBatch(rawActive, vaultId);
      const pendingByKey = new Map(
        pending.map((mutation) => [mutation.idempotencyKey, mutation]),
      );
      mutations = active.mutationIdempotencyKeys.map((key) => {
        const mutation = pendingByKey.get(key);
        if (mutation === undefined) throw new SyncLocalStateError();
        return mutation;
      });
    } else {
      mutations = pending.slice(0, this.#pushBatchSize);
      active = {
        vaultId,
        batchIdempotencyKey: validateGeneratedIdempotencyKey(
          this.#idempotencyKeys.next(),
        ),
        mutationIdempotencyKeys: mutations.map((mutation) => mutation.idempotencyKey),
      };
      await this.#localBoundary(() => this.#local.saveActivePushBatch(active));
    }
    const replayFromServerSequence = await this.#exactReplayStart(
      'generic-push',
      vaultId,
      active.batchIdempotencyKey,
    );
    return {
      kind: 'generic-push',
      request: {
        vaultId,
        batchIdempotencyKey: active.batchIdempotencyKey,
        mutations: [...mutations],
      },
      replayFromServerSequence,
    };
  }

  #assertFresh(server: VaultRevision, local: VaultRevision): void {
    if (server < local) throw new SyncRollbackError();
  }

  #assertReplayCursor(state: RunState, replayFromServerSequence: number): void {
    if (state.cursor.serverSequence !== replayFromServerSequence) {
      throw new SyncLocalStateError();
    }
  }

  async #protectState(
    input: SyncRunInput,
    state: RunState,
    revision: VaultRevision,
    observation: OutboundObservation | undefined = state.protectedState
      .outboundObservation,
  ): Promise<void> {
    const candidate = protectedLocalDeviceStateSchema.parse({
      version: 2,
      vaultId: input.vaultId,
      deviceId: input.deviceId,
      highestSeenVaultRevision: maxRevision(
        state.protectedState.highestSeenVaultRevision,
        revision,
      ),
      updatedAt: this.#now(),
      ...(observation === undefined ? {} : { outboundObservation: observation }),
      ...(state.protectedState.lastCompletedObservationId === undefined
        ? {}
        : {
            lastCompletedObservationId: state.protectedState.lastCompletedObservationId,
          }),
    });
    validateOutboundObservationBinding(candidate);
    await this.#protectedBoundary(() => this.#protectedState.save(candidate));
    state.protectedState = candidate;
  }

  async #protectedBoundary<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch {
      throw new SyncLocalStateError();
    }
  }

  async #localBoundary<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch {
      throw new SyncLocalStateError();
    }
  }

  async #setStatus(status: SyncStatus): Promise<void> {
    await this.#status.set(status);
  }

  #now(): Timestamp {
    return timestampSchema.parse(this.#clock.now().toISOString());
  }
}

function boundedInteger(value: number, maximum: number, label: string): number {
  if (!Number.isInteger(value) || value <= 0 || value > maximum) {
    throw new RangeError(
      `${label} must be an integer between 1 and ${String(maximum)}.`,
    );
  }
  return value;
}

function maxRevision(left: VaultRevision, right: VaultRevision): VaultRevision {
  return left >= right ? left : right;
}

function hasExactObjectKeys(value: unknown, expected: readonly string[]): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => key in value);
}
