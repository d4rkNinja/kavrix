import type { DatabaseSync } from 'node:sqlite';

import {
  lifecycleOperationIdListSchema,
  type JoinCommittedJournalRecord,
  type JoinJournalRecord,
  type JoinLifecycleJournalPort,
  type JoinPreparedJournalRecord,
  type LifecycleOperationId,
} from '@kavrix/client';
import { NativeJoinJournalSecrets } from '@kavrix/keychain';

import {
  copyPrepared,
  encodeJoinMirror,
  matchesMirror,
  parseCommittedJoin,
  parseJoinRow,
  parseOperationId,
  sameJoinRecord,
  verifyJoinCapacity,
  verifyJoinDatabaseRows,
  wipeJoinRecord,
  type JoinRow,
  type ParsedJoinRow,
} from './lifecycle-journal-codecs.js';
import {
  JOIN_APPLICATION_ID,
  JOIN_SCHEMA,
  SqliteLifecycleJournalBase,
  invalidState,
  normalizeFailure,
  openLifecycleDatabase,
  parseLifecycleOptions,
  required,
  withTransaction,
  type LifecycleJournalLimits,
  type SqliteLifecycleJournalOptions,
} from './lifecycle-journal-db.js';
import type { LocalWriterLease } from './local-writer-lease.js';

export interface SqliteJoinLifecycleJournalOptions extends SqliteLifecycleJournalOptions {
  readonly protectedSecrets: NativeJoinJournalSecrets;
}

export class SqliteJoinLifecycleJournal
  extends SqliteLifecycleJournalBase
  implements JoinLifecycleJournalPort
{
  readonly #protectedSecrets: NativeJoinJournalSecrets;

  private constructor(
    database: DatabaseSync,
    databasePath: string,
    limits: LifecycleJournalLimits,
    lease: LocalWriterLease,
    protectedSecrets: NativeJoinJournalSecrets,
  ) {
    super(database, databasePath, limits, lease);
    this.#protectedSecrets = protectedSecrets;
  }

  public static async open(
    options: SqliteJoinLifecycleJournalOptions,
  ): Promise<SqliteJoinLifecycleJournal> {
    if (!(options.protectedSecrets instanceof NativeJoinJournalSecrets)) {
      throw invalidState();
    }
    const limits = parseLifecycleOptions(options, ['protectedSecrets']);
    const opened = await openLifecycleDatabase(
      options,
      limits,
      JOIN_APPLICATION_ID,
      'kavrix-join-journal-v1',
      JOIN_SCHEMA,
      verifyJoinDatabaseRows,
    );
    const journal = new SqliteJoinLifecycleJournal(
      opened.database,
      opened.path,
      limits,
      opened.lease,
      options.protectedSecrets,
    );
    try {
      await journal.reconcileAll();
      return journal;
    } catch (error) {
      try {
        await journal.close();
      } catch {
        throw invalidState();
      }
      throw normalizeFailure(error);
    }
  }

  public createPrepared(recordInput: JoinPreparedJournalRecord): Promise<void> {
    const owned = copyPrepared(recordInput);
    return this.exclusive(async () => {
      try {
        const prior = await this.reconcileOne(owned.operationId);
        if (prior !== null) {
          if (prior.state === 'committed') throw invalidState();
          const existing = await this.#protectedSecrets.load(owned.operationId);
          if (existing === null) throw invalidState();
          try {
            if (!sameJoinRecord(existing, owned)) throw invalidState();
            return;
          } finally {
            wipeJoinRecord(existing);
          }
        }
        const mirror = encodeJoinMirror(owned);
        withTransaction(this.database, () => {
          this.database
            .prepare(
              `INSERT INTO join_journal
                 (operation_id, phase, state, target_state, expected_vault_id,
                  device_id, session_locator_json, committed_json, serialized_bytes)
               VALUES (?, 'reserving', 'prepared', NULL, ?, ?, ?, NULL, ?)`,
            )
            .run(
              owned.operationId,
              owned.expectedVaultId,
              owned.deviceId,
              mirror.sessionLocatorJson,
              mirror.serializedBytes,
            );
          verifyJoinCapacity(this.database, this.limits);
        });
        await this.durableFlush();
        await this.#protectedSecrets.store(owned);
        withTransaction(this.database, () => {
          const changed = this.database
            .prepare(
              `UPDATE join_journal SET phase = 'stable'
                WHERE operation_id = ? AND phase = 'reserving' AND state = 'prepared'`,
            )
            .run(owned.operationId);
          if (changed.changes !== 1) throw invalidState();
        });
        await this.durableFlush();
      } finally {
        wipeJoinRecord(owned);
      }
    });
  }

  public listOperationIds(): Promise<readonly LifecycleOperationId[]> {
    return this.exclusive(async () => {
      await this.reconcileAllInternal();
      const rows = this.database
        .prepare(
          `SELECT operation_id FROM join_journal
            ORDER BY operation_id ASC LIMIT 257`,
        )
        .all() as unknown as { operation_id?: unknown }[];
      return lifecycleOperationIdListSchema.parse(rows.map((row) => row.operation_id));
    });
  }

  public load(
    operationIdInput: LifecycleOperationId,
  ): Promise<JoinJournalRecord | null> {
    return this.exclusive(async () => {
      const operationId = parseOperationId(operationIdInput);
      const row = await this.reconcileOne(operationId);
      if (row === null) return null;
      if (row.state === 'committed') return required(row.committed);
      const active = await this.#protectedSecrets.load(operationId);
      if (active === null || !matchesMirror(active, row)) {
        wipeJoinRecord(active ?? undefined);
        throw invalidState();
      }
      return active;
    });
  }

  public markRedeemAttempted(operationIdInput: LifecycleOperationId): Promise<void> {
    return this.transition(operationIdInput, 'prepared', 'redeem-attempted');
  }

  public markCompletionAttempted(
    operationIdInput: LifecycleOperationId,
  ): Promise<void> {
    return this.transition(
      operationIdInput,
      'redeem-attempted',
      'completion-attempted',
    );
  }

  public commit(
    operationIdInput: LifecycleOperationId,
    vaultId: JoinCommittedJournalRecord['vaultId'],
    deviceId: JoinCommittedJournalRecord['deviceId'],
    committedAt: JoinCommittedJournalRecord['committedAt'],
  ): Promise<void> {
    return this.exclusive(async () => {
      const operationId = parseOperationId(operationIdInput);
      const committed = parseCommittedJoin({
        version: 1,
        kind: 'vault-join',
        operationId,
        state: 'committed',
        vaultId,
        deviceId,
        committedAt,
      });
      const committedJson = JSON.stringify(committed);
      const row = required(await this.reconcileOne(operationId));
      if (row.state === 'committed') {
        if (JSON.stringify(row.committed) !== committedJson) throw invalidState();
        return;
      }
      if (
        row.state !== 'completion-attempted' ||
        row.expectedVaultId !== committed.vaultId ||
        row.deviceId !== committed.deviceId
      ) {
        throw invalidState();
      }
      const committedBytes = Buffer.byteLength(committedJson);
      if (committedBytes > this.limits.maxSerializedBytes) throw invalidState();
      withTransaction(this.database, () => {
        const changed = this.database
          .prepare(
            `UPDATE join_journal
                SET phase = 'committing', committed_json = ?, serialized_bytes = ?
              WHERE operation_id = ? AND phase = 'stable'
                AND state = 'completion-attempted'`,
          )
          .run(committedJson, committedBytes, operationId);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
      await this.#protectedSecrets.delete(operationId);
      withTransaction(this.database, () => {
        const changed = this.database
          .prepare(
            `UPDATE join_journal
                SET phase = 'stable', state = 'committed'
              WHERE operation_id = ? AND phase = 'committing'
                AND state = 'completion-attempted' AND committed_json = ?`,
          )
          .run(operationId, committedJson);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
    });
  }

  public deletePrepared(operationIdInput: LifecycleOperationId): Promise<void> {
    return this.exclusive(async () => {
      const operationId = parseOperationId(operationIdInput);
      const row = required(await this.reconcileOne(operationId));
      if (row.state !== 'prepared') throw invalidState();
      withTransaction(this.database, () => {
        const changed = this.database
          .prepare(
            `UPDATE join_journal SET phase = 'deleting'
              WHERE operation_id = ? AND phase = 'stable' AND state = 'prepared'`,
          )
          .run(operationId);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
      await this.#protectedSecrets.delete(operationId);
      withTransaction(this.database, () => {
        const changed = this.database
          .prepare(
            `DELETE FROM join_journal
              WHERE operation_id = ? AND phase = 'deleting' AND state = 'prepared'`,
          )
          .run(operationId);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
    });
  }

  private transition(
    operationIdInput: LifecycleOperationId,
    sourceState: 'prepared' | 'redeem-attempted',
    targetState: 'redeem-attempted' | 'completion-attempted',
  ): Promise<void> {
    return this.exclusive(async () => {
      const operationId = parseOperationId(operationIdInput);
      const row = required(await this.reconcileOne(operationId));
      if (row.state === targetState) return;
      if (row.state !== sourceState || row.phase !== 'stable') throw invalidState();
      withTransaction(this.database, () => {
        const changed = this.database
          .prepare(
            `UPDATE join_journal SET phase = 'transitioning', target_state = ?
              WHERE operation_id = ? AND phase = 'stable' AND state = ?`,
          )
          .run(targetState, operationId, sourceState);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
      const active = await this.#protectedSecrets.load(operationId);
      if (active?.state !== sourceState || !matchesMirror(active, row)) {
        wipeJoinRecord(active ?? undefined);
        throw invalidState();
      }
      try {
        await this.#protectedSecrets.store({ ...active, state: targetState });
      } finally {
        wipeJoinRecord(active);
      }
      withTransaction(this.database, () => {
        const changed = this.database
          .prepare(
            `UPDATE join_journal
                SET phase = 'stable', state = ?, target_state = NULL
              WHERE operation_id = ? AND phase = 'transitioning'
                AND state = ? AND target_state = ?`,
          )
          .run(targetState, operationId, sourceState, targetState);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
    });
  }

  private reconcileAll(): Promise<void> {
    return this.exclusive(() => this.reconcileAllInternal());
  }

  private async reconcileAllInternal(): Promise<void> {
    const rows = this.database
      .prepare(`SELECT operation_id FROM join_journal ORDER BY operation_id ASC`)
      .all() as unknown as { operation_id?: unknown }[];
    if (rows.length > this.limits.maxOperations) throw invalidState();
    for (const value of rows) {
      await this.reconcileOne(parseOperationId(value.operation_id));
    }
  }

  private async reconcileOne(
    operationId: LifecycleOperationId,
  ): Promise<ParsedJoinRow | null> {
    let row = this.readRow(operationId);
    if (row === null) return null;
    if (row.phase === 'stable') {
      if (row.state === 'committed') return row;
      const active = await this.#protectedSecrets.load(operationId);
      if (active === null || !matchesMirror(active, row)) {
        wipeJoinRecord(active ?? undefined);
        throw invalidState();
      }
      wipeJoinRecord(active);
      return row;
    }
    if (row.phase === 'reserving') {
      const active = await this.#protectedSecrets.load(operationId);
      if (active === null) {
        withTransaction(this.database, () => {
          this.database
            .prepare(
              `DELETE FROM join_journal
                WHERE operation_id = ? AND phase = 'reserving'`,
            )
            .run(operationId);
        });
        await this.durableFlush();
        return null;
      }
      try {
        if (active.state !== 'prepared' || !matchesMirror(active, row)) {
          throw invalidState();
        }
      } finally {
        wipeJoinRecord(active);
      }
      withTransaction(this.database, () => {
        const changed = this.database
          .prepare(
            `UPDATE join_journal SET phase = 'stable'
              WHERE operation_id = ? AND phase = 'reserving' AND state = 'prepared'`,
          )
          .run(operationId);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
      return required(this.readRow(operationId));
    }
    if (row.phase === 'transitioning') {
      const target = required(row.targetState);
      const active = await this.#protectedSecrets.load(operationId);
      if (active === null || !matchesMirror(active, row)) {
        wipeJoinRecord(active ?? undefined);
        throw invalidState();
      }
      try {
        if (active.state === row.state) {
          await this.#protectedSecrets.store({ ...active, state: target });
        } else if (active.state !== target) {
          throw invalidState();
        }
      } finally {
        wipeJoinRecord(active);
      }
      withTransaction(this.database, () => {
        const changed = this.database
          .prepare(
            `UPDATE join_journal
                SET phase = 'stable', state = target_state, target_state = NULL
              WHERE operation_id = ? AND phase = 'transitioning'`,
          )
          .run(operationId);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
      return required(this.readRow(operationId));
    }
    if (row.phase === 'deleting') {
      await this.#protectedSecrets.delete(operationId);
      withTransaction(this.database, () => {
        this.database
          .prepare(
            `DELETE FROM join_journal
              WHERE operation_id = ? AND phase = 'deleting'`,
          )
          .run(operationId);
      });
      await this.durableFlush();
      return null;
    }
    if (row.committed === null) throw invalidState();
    await this.#protectedSecrets.delete(operationId);
    withTransaction(this.database, () => {
      const changed = this.database
        .prepare(
          `UPDATE join_journal SET phase = 'stable', state = 'committed'
            WHERE operation_id = ? AND phase = 'committing'`,
        )
        .run(operationId);
      if (changed.changes !== 1) throw invalidState();
    });
    await this.durableFlush();
    row = required(this.readRow(operationId));
    return row;
  }

  private readRow(operationId: LifecycleOperationId): ParsedJoinRow | null {
    const row = this.database
      .prepare(
        `SELECT operation_id, phase, state, target_state, expected_vault_id,
                device_id, session_locator_json, committed_json, serialized_bytes
           FROM join_journal WHERE operation_id = ?`,
      )
      .get(operationId) as JoinRow | undefined;
    return row === undefined ? null : parseJoinRow(row, this.limits);
  }
}

export async function openSqliteJoinLifecycleJournal(
  options: SqliteJoinLifecycleJournalOptions,
): Promise<SqliteJoinLifecycleJournal> {
  return SqliteJoinLifecycleJournal.open(options);
}
