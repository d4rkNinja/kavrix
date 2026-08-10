import {
  protectedLocalDeviceStateSchema,
  syncCursorSchema,
  timestampSchema,
} from '@kavrix/schemas';
import type {
  ProtectedLocalDeviceState,
  SyncCursor,
  Timestamp,
  VaultRevision,
} from '@kavrix/schemas';

import {
  classifySyncFailure,
  SyncLocalStateError,
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
  OpaqueMutation,
  SyncConflict,
  SyncRunInput,
  SyncRunResult,
  SyncStatus,
} from './types.js';
import {
  asVaultRevision,
  parseCursor,
  parsePullPage,
  parsePushResponse,
  parseTemplateMigrationPublicationResponse,
  validateActiveBatch,
  validateGeneratedIdempotencyKey,
  validatePendingMutations,
  validatePendingTemplateMigrationPublication,
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
    let cursor = syncCursorSchema.parse({
      vaultId: input.vaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 0,
    });
    this.#running = true;
    let pulledChanges = 0;
    let pushedMutations = 0;

    try {
      cursor = await this.#loadCursor(input);
      await this.#setStatus({
        state: 'syncing',
        vaultId: input.vaultId,
        cursor,
        phase: 'pull',
        at: this.#now(),
      });

      let hasMore: boolean;
      do {
        const rawPage: unknown = await this.#transport.pull({
          vaultId: input.vaultId,
          cursor,
          limit: this.#pullPageSize,
        });
        const page = parsePullPage(rawPage, input.vaultId, cursor, this.#pullPageSize);
        this.#assertFresh(page.serverVaultRevision, cursor.highestSeenVaultRevision);
        await this.#local.applyPullPage({
          vaultId: input.vaultId,
          changes: page.changes,
          cursor: page.nextCursor,
        });
        cursor = page.nextCursor;
        pulledChanges += page.changes.length;
        await this.#saveProtected(input, cursor.highestSeenVaultRevision);
        hasMore = page.hasMore;
      } while (hasMore);

      await this.#setStatus({
        state: 'syncing',
        vaultId: input.vaultId,
        cursor,
        phase: 'push',
        at: this.#now(),
      });

      const completedPublications = new Set<string>();
      for (;;) {
        const rawPublication =
          await this.#local.loadPendingTemplateMigrationPublication(input.vaultId);
        if (rawPublication === null) break;
        const publication = validatePendingTemplateMigrationPublication(
          rawPublication,
          input.vaultId,
        );
        if (completedPublications.has(publication.batchIdempotencyKey)) {
          throw new SyncLocalStateError();
        }
        const rawResponse: unknown =
          await this.#transport.publishTemplateMigration(publication);
        const response = parseTemplateMigrationPublicationResponse(
          rawResponse,
          publication,
        );
        this.#assertFresh(
          response.serverVaultRevision,
          cursor.highestSeenVaultRevision,
        );
        await this.#local.completeTemplateMigrationPublication({
          publication,
          response,
        });
        completedPublications.add(publication.batchIdempotencyKey);
        pushedMutations += publication.mutations.length;
        const highest = maxRevision(
          cursor.highestSeenVaultRevision,
          response.serverVaultRevision,
        );
        cursor = syncCursorSchema.parse({
          ...cursor,
          highestSeenVaultRevision: highest,
        });
        await this.#saveProtected(input, highest);
      }

      const conflicts: SyncConflict[] = [];
      const acknowledgedThisRun = new Set<string>();
      for (;;) {
        const pending = validatePendingMutations(
          await this.#local.listPendingMutations(input.vaultId),
          input.vaultId,
        );
        if (pending.length === 0) break;
        if (
          pending.some((mutation) => acknowledgedThisRun.has(mutation.idempotencyKey))
        ) {
          throw new SyncLocalStateError();
        }
        const { batch, mutations } = await this.#loadOrCreateBatch(
          input.vaultId,
          pending,
        );
        const rawResponse: unknown = await this.#transport.push({
          vaultId: input.vaultId,
          batchIdempotencyKey: batch.batchIdempotencyKey,
          mutations,
        });
        const response = parsePushResponse(
          rawResponse,
          input.vaultId,
          batch.batchIdempotencyKey,
          mutations,
        );
        this.#assertFresh(
          response.serverVaultRevision,
          cursor.highestSeenVaultRevision,
        );
        const acknowledged: string[] = [];
        for (const [index, result] of response.results.entries()) {
          const mutation = mutations[index];
          if (mutation === undefined) throw new SyncLocalStateError();
          if (result.status === 'accepted') {
            acknowledged.push(result.idempotencyKey);
            acknowledgedThisRun.add(result.idempotencyKey);
            pushedMutations += 1;
          } else {
            conflicts.push({
              mutation,
              currentRevision: result.currentRevision,
              current: result.current,
            });
          }
        }
        await this.#local.completePushBatch({
          vaultId: input.vaultId,
          batchIdempotencyKey: batch.batchIdempotencyKey,
          acknowledgedIdempotencyKeys: acknowledged,
        });
        const highest = maxRevision(
          cursor.highestSeenVaultRevision,
          response.serverVaultRevision,
        );
        cursor = syncCursorSchema.parse({
          ...cursor,
          highestSeenVaultRevision: highest,
        });
        await this.#saveProtected(input, highest);
        if (conflicts.length > 0) break;
      }

      if (conflicts.length > 0) {
        await this.#setStatus({
          state: 'conflict',
          vaultId: input.vaultId,
          cursor,
          conflicts,
          at: this.#now(),
        });
        return {
          state: 'conflict',
          cursor,
          pulledChanges,
          pushedMutations,
          conflicts,
        };
      }

      await this.#setStatus({
        state: 'synced',
        vaultId: input.vaultId,
        cursor,
        at: this.#now(),
      });
      return { state: 'synced', cursor, pulledChanges, pushedMutations };
    } catch (error) {
      const classification = classifySyncFailure(error);
      const terminal: SyncStatus =
        classification.state === 'offline'
          ? {
              state: 'offline',
              vaultId: input.vaultId,
              cursor,
              reason: 'network-unavailable',
              at: this.#now(),
            }
          : {
              state: 'error',
              vaultId: input.vaultId,
              cursor,
              code: classification.code,
              retryable: classification.retryable,
              at: this.#now(),
            };
      await this.#setStatus(terminal);
      throw error;
    } finally {
      this.#running = false;
    }
  }

  async #loadCursor(input: SyncRunInput): Promise<SyncCursor> {
    const rawProtected = await this.#protectedState.load(input.vaultId, input.deviceId);
    let protectedState: ProtectedLocalDeviceState | null = null;
    if (rawProtected !== null) {
      const result = protectedLocalDeviceStateSchema.safeParse(rawProtected);
      if (
        !result.success ||
        result.data.vaultId !== input.vaultId ||
        result.data.deviceId !== input.deviceId
      ) {
        throw new SyncLocalStateError();
      }
      protectedState = result.data;
    }
    const rawCursor = await this.#local.loadCursor(input.vaultId);
    const cursor =
      rawCursor === null
        ? syncCursorSchema.parse({
            vaultId: input.vaultId,
            serverSequence: 0,
            highestSeenVaultRevision: protectedState?.highestSeenVaultRevision ?? 0,
          })
        : parseCursor(rawCursor, input.vaultId);
    const highest = maxRevision(
      cursor.highestSeenVaultRevision,
      protectedState?.highestSeenVaultRevision ?? asVaultRevision(0),
    );
    return syncCursorSchema.parse({ ...cursor, highestSeenVaultRevision: highest });
  }

  async #loadOrCreateBatch(
    vaultId: SyncRunInput['vaultId'],
    pending: readonly OpaqueMutation[],
  ): Promise<{ batch: ActivePushBatch; mutations: OpaqueMutation[] }> {
    const rawActive = await this.#local.loadActivePushBatch(vaultId);
    if (rawActive !== null) {
      const active = validateActiveBatch(rawActive, vaultId);
      const pendingByKey = new Map(
        pending.map((mutation) => [mutation.idempotencyKey, mutation]),
      );
      const mutations = active.mutationIdempotencyKeys.map((key) => {
        const mutation = pendingByKey.get(key);
        if (mutation === undefined) throw new SyncLocalStateError();
        return mutation;
      });
      return { batch: active, mutations };
    }
    const mutations = pending.slice(0, this.#pushBatchSize);
    const batch: ActivePushBatch = {
      vaultId,
      batchIdempotencyKey: validateGeneratedIdempotencyKey(
        this.#idempotencyKeys.next(),
      ),
      mutationIdempotencyKeys: mutations.map((mutation) => mutation.idempotencyKey),
    };
    await this.#local.saveActivePushBatch(batch);
    return { batch, mutations };
  }

  #assertFresh(server: VaultRevision, local: VaultRevision): void {
    if (server < local) throw new SyncRollbackError();
  }

  async #saveProtected(input: SyncRunInput, revision: VaultRevision): Promise<void> {
    await this.#protectedState.save(
      protectedLocalDeviceStateSchema.parse({
        vaultId: input.vaultId,
        deviceId: input.deviceId,
        highestSeenVaultRevision: revision,
        updatedAt: this.#now(),
      }),
    );
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
