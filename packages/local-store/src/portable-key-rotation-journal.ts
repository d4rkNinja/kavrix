import type { DatabaseSync } from 'node:sqlite';

import {
  lifecycleOperationIdListSchema,
  parsePortableKeyRotationJournalRecord,
  portableKeyRotationJournalSerializedBytes,
  portableKeyRotationOperationId,
  type LifecycleOperationId,
  type PortableKeyRotationJournalPort,
  type PortableKeyRotationJournalRecord,
} from '@kavrix/client';
import {
  PORTABLE_KEY_ROTATION_JOURNAL_MAX_SERIALIZED_BYTES,
  type PortableKeyRotationCheckpoint,
  type Timestamp,
} from '@kavrix/schemas';

import {
  PORTABLE_KEY_ROTATION_APPLICATION_ID,
  PORTABLE_KEY_ROTATION_SCHEMA,
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

type RotationRow = Readonly<{
  operation_id: unknown;
  state: unknown;
  record_json: unknown;
  serialized_bytes: unknown;
}>;

export class SqlitePortableKeyRotationJournal
  extends SqliteLifecycleJournalBase
  implements PortableKeyRotationJournalPort
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
  ): Promise<SqlitePortableKeyRotationJournal> {
    const limits = parseLifecycleOptions(options);
    const opened = await openLifecycleDatabase(
      options,
      limits,
      PORTABLE_KEY_ROTATION_APPLICATION_ID,
      'kavrix-portable-key-rotation-journal-v1',
      PORTABLE_KEY_ROTATION_SCHEMA,
      verifyRotationDatabaseRows,
    );
    const journal = new SqlitePortableKeyRotationJournal(
      opened.database,
      opened.path,
      limits,
      opened.lease,
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

  public createPrepared(recordInput: PortableKeyRotationJournalRecord): Promise<void> {
    const owned = copyRecord(recordInput);
    if (owned.state !== 'prepared') throw invalidState();
    return this.exclusive(async () => {
      const serialized = encodeRecord(owned, this.limits.maxSerializedBytes);
      const prior = this.readRow(owned.operationId);
      if (prior !== null) {
        if (prior.recordJson !== serialized.json) throw invalidState();
        return;
      }
      withTransaction(this.database, () => {
        this.database
          .prepare(
            `INSERT INTO portable_key_rotation_journal
                 (operation_id, state, record_json, serialized_bytes)
               VALUES (?, ?, ?, ?)`,
          )
          .run(owned.operationId, owned.state, serialized.json, serialized.bytes);
        verifyRotationCapacity(this.database, this.limits);
      });
      await this.durableFlush();
    });
  }

  public listOperationIds(): Promise<readonly LifecycleOperationId[]> {
    return this.exclusive(() => {
      const rows = this.database
        .prepare(
          `SELECT operation_id FROM portable_key_rotation_journal
            ORDER BY operation_id ASC LIMIT 257`,
        )
        .all() as unknown as { operation_id?: unknown }[];
      return Promise.resolve(
        lifecycleOperationIdListSchema.parse(
          rows.map((row) => portableKeyRotationOperationId(row.operation_id)),
        ),
      );
    });
  }

  public load(
    operationIdInput: LifecycleOperationId,
  ): Promise<PortableKeyRotationJournalRecord | null> {
    return this.exclusive(() => {
      const operationId = portableKeyRotationOperationId(operationIdInput);
      const row = this.readRow(operationId);
      return Promise.resolve(
        row === null
          ? null
          : parsePortableKeyRotationJournalRecord(parseJson(row.recordJson)),
      );
    });
  }

  public markPendingPublished(
    operationIdInput: LifecycleOperationId,
    updatedAt: Timestamp,
    checkpoint: PortableKeyRotationCheckpoint,
  ): Promise<void> {
    return this.transition(
      operationIdInput,
      'prepared',
      'pending-published',
      updatedAt,
      checkpoint,
    );
  }

  public markActivePublished(
    operationIdInput: LifecycleOperationId,
    updatedAt: Timestamp,
    checkpoint: PortableKeyRotationCheckpoint,
  ): Promise<void> {
    return this.transition(
      operationIdInput,
      'pending-published',
      'active-published',
      updatedAt,
      checkpoint,
    );
  }

  public complete(
    operationIdInput: LifecycleOperationId,
    completedAt: Timestamp,
    checkpoint: PortableKeyRotationCheckpoint,
  ): Promise<void> {
    return this.transition(
      operationIdInput,
      'active-published',
      'completed',
      completedAt,
      checkpoint,
    );
  }

  private transition(
    operationIdInput: LifecycleOperationId,
    sourceState: PortableKeyRotationJournalRecord['state'],
    targetState: Exclude<PortableKeyRotationJournalRecord['state'], 'prepared'>,
    updatedAt: Timestamp,
    checkpoint: PortableKeyRotationCheckpoint,
  ): Promise<void> {
    return this.exclusive(async () => {
      const operationId = portableKeyRotationOperationId(operationIdInput);
      const current = required(this.readRow(operationId));
      const record = parsePortableKeyRotationJournalRecord(
        parseJson(current.recordJson),
      );
      if (record.state === targetState) {
        const expected = nextRecord(record, targetState, updatedAt, checkpoint);
        if (
          encodeRecord(expected, this.limits.maxSerializedBytes).json !==
          current.recordJson
        ) {
          throw invalidState();
        }
        return;
      }
      if (record.state !== sourceState) throw invalidState();
      const next = nextRecord(record, targetState, updatedAt, checkpoint);
      const serialized = encodeRecord(next, this.limits.maxSerializedBytes);
      withTransaction(this.database, () => {
        const changed = this.database
          .prepare(
            `UPDATE portable_key_rotation_journal
                SET state = ?, record_json = ?, serialized_bytes = ?
              WHERE operation_id = ? AND state = ? AND record_json = ?`,
          )
          .run(
            targetState,
            serialized.json,
            serialized.bytes,
            operationId,
            sourceState,
            current.recordJson,
          );
        if (changed.changes !== 1) throw invalidState();
      });
      await this.durableFlush();
    });
  }

  private reconcileAll(): Promise<void> {
    const rows = this.database
      .prepare(
        `SELECT operation_id, state, record_json, serialized_bytes
           FROM portable_key_rotation_journal`,
      )
      .all() as unknown as RotationRow[];
    verifyRotationCapacity(this.database, this.limits);
    for (const row of rows) parseRotationRow(row, this.limits.maxSerializedBytes);
    return Promise.resolve();
  }

  private readRow(operationId: LifecycleOperationId): ParsedRotationRow | null {
    const row = this.database
      .prepare(
        `SELECT operation_id, state, record_json, serialized_bytes
           FROM portable_key_rotation_journal WHERE operation_id = ?`,
      )
      .get(operationId) as RotationRow | undefined;
    return row === undefined
      ? null
      : parseRotationRow(row, this.limits.maxSerializedBytes);
  }
}

type ParsedRotationRow = Readonly<{
  operationId: LifecycleOperationId;
  state: PortableKeyRotationJournalRecord['state'];
  recordJson: string;
  serializedBytes: number;
}>;

function copyRecord(
  input: PortableKeyRotationJournalRecord,
): PortableKeyRotationJournalRecord {
  return parsePortableKeyRotationJournalRecord(structuredClone(input));
}

function nextRecord(
  record: PortableKeyRotationJournalRecord,
  state: Exclude<PortableKeyRotationJournalRecord['state'], 'prepared'>,
  updatedAt: Timestamp,
  checkpoint: PortableKeyRotationCheckpoint,
): PortableKeyRotationJournalRecord {
  return parsePortableKeyRotationJournalRecord({
    ...record,
    state,
    updatedAt,
    checkpoint,
    replacementSlot:
      state === 'active-published' || state === 'completed'
        ? { ...record.replacementSlot, state: 'active' }
        : record.replacementSlot,
  });
}

function encodeRecord(
  record: PortableKeyRotationJournalRecord,
  maxSerializedBytes: number,
): Readonly<{ json: string; bytes: number }> {
  const parsed = parsePortableKeyRotationJournalRecord(record);
  const bytes = portableKeyRotationJournalSerializedBytes(parsed);
  if (
    bytes > maxSerializedBytes ||
    bytes > PORTABLE_KEY_ROTATION_JOURNAL_MAX_SERIALIZED_BYTES
  ) {
    throw invalidState();
  }
  const json = JSON.stringify(parsed);
  return { json, bytes };
}

function parseRotationRow(
  row: RotationRow,
  maxSerializedBytes: number,
): ParsedRotationRow {
  const operationId = portableKeyRotationOperationId(row.operation_id);
  if (
    typeof row.state !== 'string' ||
    typeof row.record_json !== 'string' ||
    !Number.isSafeInteger(row.serialized_bytes) ||
    row.serialized_bytes !== Buffer.byteLength(row.record_json, 'utf8') ||
    row.serialized_bytes > maxSerializedBytes ||
    row.serialized_bytes > PORTABLE_KEY_ROTATION_JOURNAL_MAX_SERIALIZED_BYTES
  ) {
    throw invalidState();
  }
  const record = parsePortableKeyRotationJournalRecord(parseJson(row.record_json));
  if (
    record.operationId !== operationId ||
    record.state !== row.state ||
    JSON.stringify(record) !== row.record_json
  ) {
    throw invalidState();
  }
  return {
    operationId,
    state: record.state,
    recordJson: row.record_json,
    serializedBytes: row.serialized_bytes,
  };
}

function verifyRotationDatabaseRows(
  database: DatabaseSync,
  limits: LifecycleJournalLimits,
): void {
  verifyRotationCapacity(database, limits);
  const rows = database
    .prepare(
      `SELECT operation_id, state, record_json, serialized_bytes
         FROM portable_key_rotation_journal`,
    )
    .all() as unknown as RotationRow[];
  for (const row of rows) parseRotationRow(row, limits.maxSerializedBytes);
}

function verifyRotationCapacity(
  database: DatabaseSync,
  limits: LifecycleJournalLimits,
): void {
  const row = database
    .prepare(
      `SELECT COUNT(*) AS row_count,
              COALESCE(SUM(serialized_bytes), 0) AS total_bytes
         FROM portable_key_rotation_journal`,
    )
    .get() as { row_count?: unknown; total_bytes?: unknown } | undefined;
  if (
    row === undefined ||
    !Number.isSafeInteger(row.row_count) ||
    !Number.isSafeInteger(row.total_bytes) ||
    (row.row_count as number) > limits.maxOperations ||
    (row.total_bytes as number) > limits.maxSerializedBytes
  ) {
    throw invalidState();
  }
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw invalidState();
  }
}

export async function openSqlitePortableKeyRotationJournal(
  options: SqliteLifecycleJournalOptions,
): Promise<SqlitePortableKeyRotationJournal> {
  return SqlitePortableKeyRotationJournal.open(options);
}
