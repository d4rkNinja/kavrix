import { DatabaseSync } from 'node:sqlite';

import {
  OpaqueMutationDurabilityUnknownError,
  type GroupMutationState,
  type ItemMutationState,
  type OpaqueMutationQueuePort,
  type VaultMutationStatePort,
  type VaultSyncStorePort,
} from '@kavrix/client';
import {
  groupIdSchema,
  itemIdSchema,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type GroupId,
  type ItemId,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type TemplateMigrationPublicationRequest,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import type {
  ActivePushBatch,
  ApplyPullPageInput,
  CompletePushBatchInput,
  CompleteTemplateMigrationPublicationInput,
  SyncCursor,
  SyncLocalStorePort,
} from '@kavrix/sync';

import {
  assertBatchPending,
  encodeBounded,
  parseActiveBatch,
  parseApplyPullPage,
  parseBatchRow,
  parseCompletion,
  parseCursorRow,
  parseEntityId,
  parseEntityType,
  parseMutation,
  parseMutationRow,
  parseRecordRow,
  parseVaultId,
  validateCursorAdvance,
  type BatchRow,
  type CursorRow,
  type MutationRow,
  type RecordRow,
  type SyncEntityType,
} from './sqlite-local-codecs.js';
import {
  assertPhysicalSize,
  assertRowCount,
  initializeDatabase,
  parseOptions,
  pruneCompletedPushBatches,
  requireNonnegativeInteger,
  verifyDatabase,
  withTransaction,
  type SqliteSyncLocalStoreOptions,
  type StoreLimits,
} from './sqlite-local-database.js';
import { invalidState, normalizeFailure } from './sqlite-local-errors.js';
import { prepareSecureDatabasePath, secureSqliteFiles } from './path-security.js';
import { SqliteVaultState } from './sqlite-vault-state.js';

export type { SqliteSyncLocalStoreOptions } from './sqlite-local-database.js';
export type { SyncEntityType } from './sqlite-local-codecs.js';

export type QueueMutationResult = 'duplicate' | 'queued';

export class SqliteSyncLocalStore
  implements
    SyncLocalStorePort,
    VaultSyncStorePort,
    VaultMutationStatePort,
    OpaqueMutationQueuePort
{
  readonly #database: DatabaseSync;
  readonly #databasePath: string;
  readonly #limits: StoreLimits;
  readonly #vaultState: SqliteVaultState;
  #closed = false;

  private constructor(
    database: DatabaseSync,
    databasePath: string,
    limits: StoreLimits,
  ) {
    this.#database = database;
    this.#databasePath = databasePath;
    this.#limits = limits;
    this.#vaultState = new SqliteVaultState(database, limits);
  }

  public static async open(
    options: SqliteSyncLocalStoreOptions,
  ): Promise<SqliteSyncLocalStore> {
    const limits = parseOptions(options);
    const databasePath = await prepareSecureDatabasePath(options.path);
    let database: DatabaseSync | undefined;
    try {
      database = new DatabaseSync(databasePath, {
        allowExtension: false,
        enableDoubleQuotedStringLiterals: false,
        enableForeignKeyConstraints: true,
        timeout: 5_000,
      });
      initializeDatabase(database, limits);
      database.enableDefensive(true);
      verifyDatabase(database, limits);
      await secureSqliteFiles(databasePath, true);
    } catch (error) {
      if (database !== undefined) {
        try {
          database.close();
        } catch {
          throw invalidState();
        }
      }
      throw normalizeFailure(error);
    }
    return new SqliteSyncLocalStore(database, databasePath, limits);
  }

  public loadCursor(vaultIdInput: VaultId): Promise<SyncCursor | null> {
    try {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const row = this.#database
        .prepare(
          `SELECT vault_id, server_sequence, highest_revision, cursor_json,
                  last_page_hash
             FROM sync_cursors WHERE vault_id = ?`,
        )
        .get(vaultId) as CursorRow | undefined;
      return Promise.resolve(
        row === undefined ? null : parseCursorRow(row, vaultId).cursor,
      );
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public async applyPullPage(input: ApplyPullPageInput): Promise<void> {
    try {
      this.#assertOpen();
      const page = parseApplyPullPage(input, this.#limits.maxSerializedRowBytes);
      withTransaction(this.#database, () => {
        const existingRow = this.#database
          .prepare(
            `SELECT vault_id, server_sequence, highest_revision, cursor_json,
                    last_page_hash
               FROM sync_cursors WHERE vault_id = ?`,
          )
          .get(page.vaultId) as CursorRow | undefined;
        const existing =
          existingRow === undefined ? null : parseCursorRow(existingRow, page.vaultId);
        const disposition = validateCursorAdvance(existing, page);
        if (disposition === 'duplicate') return;

        const pageRevisions = new Map<string, number>();
        for (const pulled of page.changes) {
          const identity = `${pulled.change.entityType}:${pulled.change.entityId}`;
          const previousRevision = pageRevisions.get(identity);
          if (
            previousRevision !== undefined &&
            pulled.change.recordRevision <= previousRevision
          ) {
            throw invalidState();
          }
          pageRevisions.set(identity, pulled.change.recordRevision);
          this.#vaultState.applyPulledChange(pulled, page.vaultId);
        }
        this.#vaultState.assertBounds();
        this.#database
          .prepare(
            `INSERT INTO sync_cursors
               (vault_id, server_sequence, highest_revision, cursor_json,
                last_page_hash)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(vault_id) DO UPDATE SET
               server_sequence = excluded.server_sequence,
               highest_revision = excluded.highest_revision,
               cursor_json = excluded.cursor_json,
               last_page_hash = excluded.last_page_hash`,
          )
          .run(
            page.vaultId,
            page.cursor.serverSequence,
            page.cursor.highestSeenVaultRevision,
            page.cursorJson,
            page.pageHash,
          );
        assertRowCount(this.#database, 'sync_cursors', this.#limits.maxVaults);
      });
      await this.#afterWrite();
    } catch (error) {
      throw normalizeFailure(error);
    }
  }

  public listPendingMutations(
    vaultIdInput: VaultId,
  ): Promise<readonly OpaqueMutation[]> {
    try {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const rows = this.#database
        .prepare(
          `SELECT vault_id, entity_type, entity_id, idempotency_key,
                  mutation_json, serialized_bytes
             FROM pending_mutations WHERE vault_id = ? ORDER BY sequence ASC`,
        )
        .all(vaultId) as unknown as MutationRow[];
      if (rows.length > this.#limits.maxPendingMutations) throw invalidState();
      return Promise.resolve(rows.map((row) => parseMutationRow(row, vaultId)));
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public async enqueueMutation(
    vaultIdInput: VaultId,
    mutationInput: OpaqueMutation,
  ): Promise<QueueMutationResult> {
    try {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const mutation = parseMutation(mutationInput, vaultId);
      const disposition = withTransaction(this.#database, () =>
        this.#vaultState.enqueueBatch([mutation]),
      );
      await this.#afterWrite();
      return disposition;
    } catch (error) {
      throw normalizeFailure(error);
    }
  }

  public async enqueueBatch(mutations: readonly OpaqueMutation[]): Promise<void> {
    let committed = false;
    try {
      this.#assertOpen();
      withTransaction(this.#database, () => this.#vaultState.enqueueBatch(mutations));
      committed = true;
      await this.#afterWrite();
    } catch (error) {
      if (committed) {
        throw new OpaqueMutationDurabilityUnknownError({
          cause: normalizeFailure(error),
        });
      }
      throw normalizeFailure(error);
    }
  }

  public loadActivePushBatch(vaultIdInput: VaultId): Promise<ActivePushBatch | null> {
    try {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const row = this.#database
        .prepare(
          `SELECT vault_id, batch_key, batch_json, serialized_bytes
             FROM active_push_batches WHERE vault_id = ?`,
        )
        .get(vaultId) as BatchRow | undefined;
      if (row === undefined) return Promise.resolve(null);
      const batch = parseBatchRow(row, vaultId);
      assertBatchPending(this.#database, batch);
      return Promise.resolve(batch);
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public async saveActivePushBatch(batchInput: ActivePushBatch): Promise<void> {
    try {
      this.#assertOpen();
      const batch = parseActiveBatch(batchInput);
      const encoded = encodeBounded(batch, this.#limits.maxSerializedRowBytes);
      withTransaction(this.#database, () => {
        if (this.#vaultState.loadPendingPublication(batch.vaultId) !== null) {
          throw invalidState();
        }
        const completed = this.#database
          .prepare(`SELECT vault_id FROM completed_push_batches WHERE batch_key = ?`)
          .get(batch.batchIdempotencyKey);
        if (completed !== undefined) throw invalidState();
        const existing = this.#database
          .prepare(
            `SELECT vault_id, batch_key, batch_json, serialized_bytes
               FROM active_push_batches WHERE vault_id = ? OR batch_key = ?`,
          )
          .all(batch.vaultId, batch.batchIdempotencyKey) as unknown as BatchRow[];
        if (existing.length > 0) {
          const first = existing.at(0);
          if (
            existing.length === 1 &&
            first?.vault_id === batch.vaultId &&
            first.batch_key === batch.batchIdempotencyKey &&
            first.batch_json === encoded.json
          ) {
            parseBatchRow(first, batch.vaultId);
            assertBatchPending(this.#database, batch);
            return;
          }
          throw invalidState();
        }
        assertBatchPending(this.#database, batch);
        this.#database
          .prepare(
            `INSERT INTO active_push_batches
               (vault_id, batch_key, batch_json, serialized_bytes)
             VALUES (?, ?, ?, ?)`,
          )
          .run(batch.vaultId, batch.batchIdempotencyKey, encoded.json, encoded.bytes);
        assertRowCount(this.#database, 'active_push_batches', this.#limits.maxVaults);
      });
      await this.#afterWrite();
    } catch (error) {
      throw normalizeFailure(error);
    }
  }

  public async completePushBatch(input: CompletePushBatchInput): Promise<void> {
    try {
      this.#assertOpen();
      const completion = parseCompletion(input);
      const acknowledgementJson = JSON.stringify(
        completion.acknowledgedIdempotencyKeys,
      );
      withTransaction(this.#database, () => {
        const row = this.#database
          .prepare(
            `SELECT vault_id, batch_key, batch_json, serialized_bytes
               FROM active_push_batches WHERE vault_id = ?`,
          )
          .get(completion.vaultId) as BatchRow | undefined;
        if (row === undefined) {
          const completed = this.#database
            .prepare(
              `SELECT vault_id, acknowledged_json AS value_json,
                      serialized_bytes
                 FROM completed_push_batches WHERE batch_key = ?`,
            )
            .get(completion.batchIdempotencyKey) as
            | {
                vault_id: unknown;
                value_json: unknown;
                serialized_bytes: unknown;
              }
            | undefined;
          if (
            completed?.vault_id === completion.vaultId &&
            completed.value_json === acknowledgementJson &&
            requireNonnegativeInteger(completed.serialized_bytes) ===
              Buffer.byteLength(acknowledgementJson)
          ) {
            return;
          }
          throw invalidState();
        }
        const batch = parseBatchRow(row, completion.vaultId);
        if (batch.batchIdempotencyKey !== completion.batchIdempotencyKey) {
          throw invalidState();
        }
        assertBatchPending(this.#database, batch);
        const batchKeys = new Set(batch.mutationIdempotencyKeys);
        if (completion.acknowledgedIdempotencyKeys.some((key) => !batchKeys.has(key))) {
          throw invalidState();
        }
        const findMutation = this.#database.prepare(
          `SELECT vault_id, entity_type, entity_id, idempotency_key,
                  mutation_json, serialized_bytes
             FROM pending_mutations
            WHERE idempotency_key = ?`,
        );
        const deleteMutation = this.#database.prepare(
          `DELETE FROM pending_mutations
            WHERE vault_id = ? AND idempotency_key = ?`,
        );
        for (const key of completion.acknowledgedIdempotencyKeys) {
          const pending = findMutation.get(key) as MutationRow | undefined;
          if (pending?.vault_id !== completion.vaultId) throw invalidState();
          const mutation = parseMutationRow(pending, completion.vaultId);
          this.#vaultState.promoteMutation(mutation);
          this.#vaultState.recordCompletedMutation(mutation, 'generic');
          deleteMutation.run(completion.vaultId, key);
        }
        this.#vaultState.pruneCompletedMutationReceipts(
          completion.acknowledgedIdempotencyKeys,
        );
        this.#database
          .prepare(`DELETE FROM active_push_batches WHERE vault_id = ?`)
          .run(completion.vaultId);
        this.#database
          .prepare(
            `INSERT INTO completed_push_batches
               (vault_id, batch_key, acknowledged_json, serialized_bytes)
             VALUES (?, ?, ?, ?)`,
          )
          .run(
            completion.vaultId,
            completion.batchIdempotencyKey,
            acknowledgementJson,
            Buffer.byteLength(acknowledgementJson),
          );
        pruneCompletedPushBatches(
          this.#database,
          this.#limits,
          completion.batchIdempotencyKey,
        );
      });
      await this.#afterWrite();
    } catch (error) {
      throw normalizeFailure(error);
    }
  }

  public getVault(vaultIdInput: VaultId): Promise<VaultRecord | null> {
    try {
      this.#assertOpen();
      return Promise.resolve(this.#vaultState.getVault(parseVaultId(vaultIdInput)));
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public getGroup(
    vaultIdInput: VaultId,
    groupIdInput: GroupId,
  ): Promise<EncryptedGroupRecord | null> {
    try {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const groupId = groupIdSchema.safeParse(groupIdInput);
      if (!groupId.success) throw invalidState();
      return Promise.resolve(this.#vaultState.getGroup(vaultId, groupId.data));
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public listGroups(vaultIdInput: VaultId): AsyncIterable<EncryptedGroupRecord> {
    return deferredAsyncIterable(() => {
      this.#assertOpen();
      return this.#vaultState.listGroups(parseVaultId(vaultIdInput));
    });
  }

  public getItem(
    vaultIdInput: VaultId,
    itemIdInput: ItemId,
  ): Promise<EncryptedItemRecord | null> {
    try {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const itemId = itemIdSchema.safeParse(itemIdInput);
      if (!itemId.success) throw invalidState();
      return Promise.resolve(this.#vaultState.getItem(vaultId, itemId.data));
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public listItems(
    vaultIdInput: VaultId,
    groupIdInput: GroupId,
  ): AsyncIterable<EncryptedItemRecord> {
    return deferredAsyncIterable(() => {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const groupId = groupIdSchema.safeParse(groupIdInput);
      if (!groupId.success) throw invalidState();
      return this.#vaultState.listItems(vaultId, groupId.data);
    });
  }

  public getCurrentGroup(
    vaultIdInput: VaultId,
    groupIdInput: GroupId,
  ): Promise<GroupMutationState | null> {
    try {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const groupId = groupIdSchema.safeParse(groupIdInput);
      if (!groupId.success) throw invalidState();
      return Promise.resolve(this.#vaultState.getCurrentGroup(vaultId, groupId.data));
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public getCurrentItem(
    vaultIdInput: VaultId,
    itemIdInput: ItemId,
  ): Promise<ItemMutationState | null> {
    try {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const itemId = itemIdSchema.safeParse(itemIdInput);
      if (!itemId.success) throw invalidState();
      return Promise.resolve(this.#vaultState.getCurrentItem(vaultId, itemId.data));
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public listCurrentItems(
    vaultIdInput: VaultId,
    groupIdInput: GroupId,
  ): AsyncIterable<ItemMutationState> {
    return deferredAsyncIterable(() => {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const groupId = groupIdSchema.safeParse(groupIdInput);
      if (!groupId.success) throw invalidState();
      return this.#vaultState.listCurrentItems(vaultId, groupId.data);
    });
  }

  public loadPendingTemplateMigrationPublication(
    vaultIdInput: VaultId,
  ): Promise<TemplateMigrationPublicationRequest | null> {
    try {
      this.#assertOpen();
      return Promise.resolve(
        this.#vaultState.loadPendingPublication(parseVaultId(vaultIdInput)),
      );
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public async enqueueTemplateMigrationPublication(
    publication: TemplateMigrationPublicationRequest,
  ): Promise<void> {
    let committed = false;
    try {
      this.#assertOpen();
      withTransaction(this.#database, () => {
        this.#vaultState.enqueuePublication(publication);
      });
      committed = true;
      await this.#afterWrite();
    } catch (error) {
      if (committed) {
        throw new OpaqueMutationDurabilityUnknownError({
          cause: normalizeFailure(error),
        });
      }
      throw normalizeFailure(error);
    }
  }

  public async completeTemplateMigrationPublication(
    input: CompleteTemplateMigrationPublicationInput,
  ): Promise<void> {
    try {
      this.#assertOpen();
      withTransaction(this.#database, () => {
        this.#vaultState.completePublication(input);
      });
      await this.#afterWrite();
    } catch (error) {
      throw normalizeFailure(error);
    }
  }

  public loadOpaqueRecord(
    vaultIdInput: VaultId,
    entityTypeInput: SyncEntityType,
    entityIdInput: string,
  ): Promise<OpaqueSyncRecord | null> {
    try {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const entityType = parseEntityType(entityTypeInput);
      const entityId = parseEntityId(entityType, entityIdInput);
      const row = this.#database
        .prepare(
          `SELECT vault_id, entity_type, entity_id, revision, record_json,
                  serialized_bytes
             FROM opaque_records
            WHERE vault_id = ? AND entity_type = ? AND entity_id = ?`,
        )
        .get(vaultId, entityType, entityId) as RecordRow | undefined;
      return Promise.resolve(row === undefined ? null : parseRecordRow(row, vaultId));
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public listOpaqueRecords(
    vaultIdInput: VaultId,
  ): Promise<readonly OpaqueSyncRecord[]> {
    try {
      this.#assertOpen();
      const vaultId = parseVaultId(vaultIdInput);
      const rows = this.#database
        .prepare(
          `SELECT vault_id, entity_type, entity_id, revision, record_json,
                  serialized_bytes
             FROM opaque_records WHERE vault_id = ?
            ORDER BY entity_type ASC, entity_id ASC`,
        )
        .all(vaultId) as unknown as RecordRow[];
      if (rows.length > this.#limits.maxRecords) throw invalidState();
      return Promise.resolve(rows.map((row) => parseRecordRow(row, vaultId)));
    } catch (error) {
      return Promise.reject(normalizeFailure(error));
    }
  }

  public close(): void {
    if (this.#closed) return;
    let failed = false;
    try {
      this.#database.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch {
      failed = true;
    }
    try {
      this.#database.close();
    } catch {
      failed = true;
    }
    this.#closed = true;
    if (failed) throw invalidState();
  }

  async #afterWrite(): Promise<void> {
    try {
      verifyDatabase(this.#database, this.#limits, false);
      await secureSqliteFiles(this.#databasePath, true);
      await assertPhysicalSize(this.#databasePath, this.#limits.maxDatabaseBytes);
    } catch {
      try {
        this.#database.close();
      } catch {
        this.#closed = true;
        throw invalidState();
      }
      this.#closed = true;
      throw invalidState();
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw invalidState();
  }
}

export async function openSqliteSyncLocalStore(
  options: SqliteSyncLocalStoreOptions,
): Promise<SqliteSyncLocalStore> {
  return SqliteSyncLocalStore.open(options);
}

function deferredAsyncIterable<Value>(
  load: () => readonly Value[],
): AsyncIterable<Value> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Value> {
      let values: readonly Value[] | undefined;
      let index = 0;
      return {
        next(): Promise<IteratorResult<Value>> {
          try {
            values ??= load();
            const value = values[index];
            if (value === undefined) {
              return Promise.resolve({ done: true, value: undefined });
            }
            index += 1;
            return Promise.resolve({ done: false, value });
          } catch (error) {
            return Promise.reject(normalizeFailure(error));
          }
        },
      };
    },
  };
}
