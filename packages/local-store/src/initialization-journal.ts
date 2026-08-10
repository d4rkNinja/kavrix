import type { DatabaseSync } from 'node:sqlite';

import {
  lifecycleOperationIdListSchema,
  type InitializationActiveJournalRecord,
  type InitializationCommittedJournalRecord,
  type InitializationJournalPort,
  type InitializationJournalRecord,
  type LifecycleOperationId,
} from '@kavrix/client';

import {
  encodeBounded,
  parseInitialization,
  parseInitializationRow,
  parseOperationId,
  verifyInitializationCapacity,
  verifyInitializationDatabaseRows,
  type InitializationRow,
} from './lifecycle-journal-codecs.js';
import {
  INIT_SCHEMA,
  INITIALIZATION_APPLICATION_ID,
  SqliteLifecycleJournalBase,
  invalidState,
  openLifecycleDatabase,
  parseLifecycleOptions,
  required,
  withTransaction,
  type LifecycleJournalLimits,
  type SqliteLifecycleJournalOptions,
} from './lifecycle-journal-db.js';
import type { LocalWriterLease } from './local-writer-lease.js';

export class SqliteInitializationJournal
  extends SqliteLifecycleJournalBase
  implements InitializationJournalPort
{
  private constructor(
    database: DatabaseSync,
    databasePath: string,
    limits: LifecycleJournalLimits,
    lease: LocalWriterLease,
  ) {
    super(database, databasePath, limits, lease);
  }

  public static async open(
    options: SqliteLifecycleJournalOptions,
  ): Promise<SqliteInitializationJournal> {
    const limits = parseLifecycleOptions(options);
    const opened = await openLifecycleDatabase(
      options,
      limits,
      INITIALIZATION_APPLICATION_ID,
      'kavrix-initialization-journal-v1',
      INIT_SCHEMA,
      verifyInitializationDatabaseRows,
    );
    return new SqliteInitializationJournal(
      opened.database,
      opened.path,
      limits,
      opened.lease,
    );
  }

  public createPrepared(recordInput: InitializationActiveJournalRecord): Promise<void> {
    return this.exclusive(async () => {
      const record = parseInitialization(recordInput);
      if (record.state !== 'prepared') throw invalidState();
      const encoded = encodeBounded(record, this.limits.maxSerializedBytes);
      const deviceLocator = JSON.stringify(record.deviceLocator);
      const sessionLocator = JSON.stringify(record.sessionLocator);
      withTransaction(this.database, () => {
        const existing = this.read(record.operationId);
        if (existing !== null) {
          if (JSON.stringify(existing) === encoded.json) return;
          throw invalidState();
        }
        this.database
          .prepare(
            `INSERT INTO initialization_journal
               (operation_id, state, record_json, serialized_bytes,
                device_locator_json, session_locator_json)
             VALUES (?, 'prepared', ?, ?, ?, ?)`,
          )
          .run(
            record.operationId,
            encoded.json,
            encoded.bytes,
            deviceLocator,
            sessionLocator,
          );
        verifyInitializationCapacity(this.database, this.limits);
      });
      await this.durableFlush();
    });
  }

  public listOperationIds(): Promise<readonly LifecycleOperationId[]> {
    return this.exclusive(() => {
      const rows = this.database
        .prepare(
          `SELECT operation_id FROM initialization_journal
            ORDER BY operation_id ASC LIMIT 257`,
        )
        .all() as unknown as { operation_id?: unknown }[];
      return Promise.resolve(
        lifecycleOperationIdListSchema.parse(rows.map((row) => row.operation_id)),
      );
    });
  }

  public load(
    operationIdInput: LifecycleOperationId,
  ): Promise<InitializationJournalRecord | null> {
    return this.exclusive(() =>
      Promise.resolve(this.read(parseOperationId(operationIdInput))),
    );
  }

  public markNetworkAttempted(operationIdInput: LifecycleOperationId): Promise<void> {
    return this.exclusive(async () => {
      const operationId = parseOperationId(operationIdInput);
      withTransaction(this.database, () => {
        const record = required(this.read(operationId));
        if (record.state === 'network-attempted') return;
        if (record.state !== 'prepared') throw invalidState();
        const target = parseInitialization({ ...record, state: 'network-attempted' });
        const encoded = encodeBounded(target, this.limits.maxSerializedBytes);
        const changed = this.database
          .prepare(
            `UPDATE initialization_journal
                SET state = 'network-attempted', record_json = ?, serialized_bytes = ?
              WHERE operation_id = ? AND state = 'prepared'`,
          )
          .run(encoded.json, encoded.bytes, operationId);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
    });
  }

  public commit(
    operationIdInput: LifecycleOperationId,
    receipt: InitializationCommittedJournalRecord['receipt'],
    committedAt: InitializationCommittedJournalRecord['committedAt'],
  ): Promise<void> {
    return this.exclusive(async () => {
      const operationId = parseOperationId(operationIdInput);
      const committed = parseInitialization({
        version: 1,
        kind: 'vault-initialization',
        operationId,
        state: 'committed',
        receipt,
        committedAt,
      });
      const encoded = encodeBounded(committed, this.limits.maxSerializedBytes);
      withTransaction(this.database, () => {
        const existing = required(this.read(operationId));
        if (existing.state === 'committed') {
          if (JSON.stringify(existing) === encoded.json) return;
          throw invalidState();
        }
        if (existing.state !== 'network-attempted') {
          throw invalidState();
        }
        const changed = this.database
          .prepare(
            `UPDATE initialization_journal
                SET state = 'committed', record_json = ?, serialized_bytes = ?,
                    device_locator_json = NULL, session_locator_json = NULL
              WHERE operation_id = ? AND state = 'network-attempted'`,
          )
          .run(encoded.json, encoded.bytes, operationId);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
    });
  }

  public deletePrepared(operationIdInput: LifecycleOperationId): Promise<void> {
    return this.exclusive(async () => {
      const operationId = parseOperationId(operationIdInput);
      withTransaction(this.database, () => {
        const existing = required(this.read(operationId));
        if (existing.state !== 'prepared') throw invalidState();
        const changed = this.database
          .prepare(
            `DELETE FROM initialization_journal
              WHERE operation_id = ? AND state = 'prepared'`,
          )
          .run(operationId);
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
    });
  }

  private read(operationId: LifecycleOperationId): InitializationJournalRecord | null {
    const row = this.database
      .prepare(
        `SELECT operation_id, state, record_json, serialized_bytes,
                device_locator_json, session_locator_json
           FROM initialization_journal WHERE operation_id = ?`,
      )
      .get(operationId) as InitializationRow | undefined;
    return row === undefined
      ? null
      : parseInitializationRow(row, this.limits.maxSerializedBytes);
  }
}

export async function openSqliteInitializationJournal(
  options: SqliteLifecycleJournalOptions,
): Promise<SqliteInitializationJournal> {
  return SqliteInitializationJournal.open(options);
}
