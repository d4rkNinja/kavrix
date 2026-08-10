import { stat } from 'node:fs/promises';
import type { DatabaseSync } from 'node:sqlite';

import { invalidState, normalizeFailure } from './sqlite-local-errors.js';
import {
  SqliteVaultState,
  VAULT_STATE_SCHEMA_DEFINITIONS,
} from './sqlite-vault-state.js';

const APPLICATION_ID = 0x4b565258;
const SCHEMA_VERSION = 2;
const DEFAULT_LIMITS = {
  maxVaults: 128,
  maxRecords: 100_000,
  maxRecordBytes: 256 * 1024 * 1024,
  maxPendingMutations: 10_000,
  maxPendingBytes: 64 * 1024 * 1024,
  maxCompletedBatches: 10_000,
  maxCompletedPushBatchBytes: 64 * 1024 * 1024,
  maxCompletedMutations: 100_000,
  maxCompletedMutationBytes: 64 * 1024 * 1024,
  maxCompletedPublicationBytes: 64 * 1024 * 1024,
  maxSerializedRowBytes: 8 * 1024 * 1024,
  maxDatabaseBytes: 512 * 1024 * 1024,
} as const;
const SCHEMA_DEFINITIONS = {
  store_metadata: `CREATE TABLE store_metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
  ) STRICT, WITHOUT ROWID`,
  sync_cursors: `CREATE TABLE sync_cursors (
    vault_id TEXT PRIMARY KEY NOT NULL,
    server_sequence INTEGER NOT NULL CHECK(server_sequence >= 0),
    highest_revision INTEGER NOT NULL CHECK(highest_revision >= 0),
    cursor_json TEXT NOT NULL,
    last_page_hash TEXT NOT NULL CHECK(length(last_page_hash) = 43)
  ) STRICT, WITHOUT ROWID`,
  opaque_records: `CREATE TABLE opaque_records (
    vault_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('vault','group','item','attachment')),
    entity_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 0),
    record_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2),
    PRIMARY KEY(vault_id, entity_type, entity_id)
  ) STRICT, WITHOUT ROWID`,
  pending_mutations: `CREATE TABLE pending_mutations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK(entity_type IN ('vault','group','item')),
    entity_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    mutation_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2)
  ) STRICT`,
  pending_mutations_vault_sequence: `CREATE INDEX pending_mutations_vault_sequence
    ON pending_mutations(vault_id, sequence)`,
  pending_mutations_entity_sequence: `CREATE INDEX pending_mutations_entity_sequence
    ON pending_mutations(vault_id, entity_type, entity_id, sequence)`,
  active_push_batches: `CREATE TABLE active_push_batches (
    vault_id TEXT PRIMARY KEY NOT NULL,
    batch_key TEXT NOT NULL UNIQUE,
    batch_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2)
  ) STRICT, WITHOUT ROWID`,
  completed_push_batches: `CREATE TABLE completed_push_batches (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id TEXT NOT NULL,
    batch_key TEXT NOT NULL UNIQUE,
    acknowledged_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2)
  ) STRICT`,
  ...VAULT_STATE_SCHEMA_DEFINITIONS,
} as const;
const SCHEMA_DEFINITION_SQL = `${Object.values(SCHEMA_DEFINITIONS).join(';\n')};`;

export interface SqliteSyncLocalStoreOptions {
  readonly path: string;
  readonly maxVaults?: number;
  readonly maxRecords?: number;
  readonly maxRecordBytes?: number;
  readonly maxPendingMutations?: number;
  readonly maxPendingBytes?: number;
  readonly maxCompletedBatches?: number;
  readonly maxCompletedPushBatchBytes?: number;
  readonly maxCompletedMutations?: number;
  readonly maxCompletedMutationBytes?: number;
  readonly maxCompletedPublicationBytes?: number;
  readonly maxSerializedRowBytes?: number;
  readonly maxDatabaseBytes?: number;
}

export interface StoreLimits {
  readonly maxVaults: number;
  readonly maxRecords: number;
  readonly maxRecordBytes: number;
  readonly maxPendingMutations: number;
  readonly maxPendingBytes: number;
  readonly maxCompletedBatches: number;
  readonly maxCompletedPushBatchBytes: number;
  readonly maxCompletedMutations: number;
  readonly maxCompletedMutationBytes: number;
  readonly maxCompletedPublicationBytes: number;
  readonly maxSerializedRowBytes: number;
  readonly maxDatabaseBytes: number;
}

interface CountBytesRow {
  readonly row_count: unknown;
  readonly total_bytes: unknown;
}

export function initializeDatabase(database: DatabaseSync, limits: StoreLimits): void {
  database.exec(`
    PRAGMA trusted_schema = OFF;
    PRAGMA foreign_keys = ON;
    PRAGMA temp_store = MEMORY;
    PRAGMA secure_delete = ON;
    PRAGMA synchronous = FULL;
    PRAGMA fullfsync = ON;
    PRAGMA checkpoint_fullfsync = ON;
    PRAGMA wal_autocheckpoint = 64;
    PRAGMA journal_size_limit = 16777216;
  `);
  const applicationId = getIntegerPragma(
    database,
    'PRAGMA application_id',
    'application_id',
  );
  const userVersion = getIntegerPragma(database, 'PRAGMA user_version', 'user_version');
  if (applicationId === 0 && userVersion === 0) {
    const tableCount = getInteger(
      database
        .prepare(
          `SELECT COUNT(*) AS value FROM sqlite_schema
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`,
        )
        .get(),
      'value',
    );
    if (tableCount !== 0) throw invalidState();
    withTransaction(database, () => {
      database.exec(`
        ${SCHEMA_DEFINITION_SQL}
        INSERT INTO store_metadata(key, value)
          VALUES ('format', 'kavrix-local-sync-v2');
        PRAGMA application_id = ${String(APPLICATION_ID)};
        PRAGMA user_version = ${String(SCHEMA_VERSION)};
      `);
    });
  } else if (applicationId !== APPLICATION_ID || userVersion !== SCHEMA_VERSION) {
    throw invalidState();
  }
  const mode = getStringPragma(database, 'PRAGMA journal_mode = WAL', 'journal_mode');
  if (mode.toLowerCase() !== 'wal') throw invalidState();
  const pageSize = getIntegerPragma(database, 'PRAGMA page_size', 'page_size');
  const maxPages = Math.floor(limits.maxDatabaseBytes / pageSize);
  if (maxPages < 1) throw invalidState();
  database.exec(`PRAGMA max_page_count = ${String(maxPages)}`);
}

export function verifyDatabase(
  database: DatabaseSync,
  limits: StoreLimits,
  includeIntegrityCheck = true,
): void {
  if (
    getIntegerPragma(database, 'PRAGMA application_id', 'application_id') !==
      APPLICATION_ID ||
    getIntegerPragma(database, 'PRAGMA user_version', 'user_version') !== SCHEMA_VERSION
  ) {
    throw invalidState();
  }
  const format = database
    .prepare(`SELECT value FROM store_metadata WHERE key = 'format'`)
    .get() as { value?: unknown } | undefined;
  if (format?.value !== 'kavrix-local-sync-v2') throw invalidState();
  verifySchemaObjects(database);
  if (includeIntegrityCheck) {
    const rows = database.prepare('PRAGMA integrity_check').all() as unknown as {
      integrity_check?: unknown;
    }[];
    if (rows.length !== 1 || rows[0]?.integrity_check !== 'ok') {
      throw invalidState();
    }
    if (database.prepare('PRAGMA foreign_key_check').all().length !== 0) {
      throw invalidState();
    }
  }
  const pageCount = getIntegerPragma(database, 'PRAGMA page_count', 'page_count');
  const pageSize = getIntegerPragma(database, 'PRAGMA page_size', 'page_size');
  if (pageCount * pageSize > limits.maxDatabaseBytes) throw invalidState();
  assertRowCount(database, 'sync_cursors', limits.maxVaults);
  assertTableBounds(
    database,
    'opaque_records',
    limits.maxRecords,
    limits.maxRecordBytes,
  );
  assertTableBounds(
    database,
    'pending_mutations',
    limits.maxPendingMutations,
    limits.maxPendingBytes,
  );
  assertRowCount(database, 'active_push_batches', limits.maxVaults);
  assertTableBounds(
    database,
    'completed_push_batches',
    limits.maxCompletedBatches,
    limits.maxCompletedPushBatchBytes,
  );
  const vaultState = new SqliteVaultState(database, limits);
  vaultState.assertNoQueueCoexistence();
  vaultState.assertBounds();
}

function verifySchemaObjects(database: DatabaseSync): void {
  const rows = database
    .prepare(
      `SELECT type, name, sql FROM sqlite_schema
        WHERE name NOT LIKE 'sqlite_%' ORDER BY type ASC, name ASC`,
    )
    .all() as unknown as { name?: unknown; sql?: unknown; type?: unknown }[];
  const objects = rows.map((row) => {
    if (
      typeof row.name !== 'string' ||
      typeof row.type !== 'string' ||
      typeof row.sql !== 'string'
    ) {
      throw invalidState();
    }
    return {
      identity: `${row.type}:${row.name}`,
      sql: normalizeSql(row.sql),
    };
  });
  const expected = Object.entries(SCHEMA_DEFINITIONS)
    .map(([name, sql]) => ({
      identity: `${/^CREATE (?:UNIQUE )?INDEX\b/u.test(sql) ? 'index' : 'table'}:${name}`,
      sql: normalizeSql(sql),
    }))
    .sort((left, right) => left.identity.localeCompare(right.identity));
  if (
    objects.length !== expected.length ||
    JSON.stringify(objects) !== JSON.stringify(expected)
  ) {
    throw invalidState();
  }
}

function normalizeSql(value: string): string {
  return value.replace(/\s+/gu, ' ').trim();
}

export function parseOptions(options: SqliteSyncLocalStoreOptions): StoreLimits {
  if (!hasOnlyKeys(options, ['path', ...Object.keys(DEFAULT_LIMITS)])) {
    throw invalidState();
  }
  const parsed: StoreLimits = {
    maxVaults: boundedOption(options.maxVaults, DEFAULT_LIMITS.maxVaults, 1, 10_000),
    maxRecords: boundedOption(
      options.maxRecords,
      DEFAULT_LIMITS.maxRecords,
      1,
      1_000_000,
    ),
    maxRecordBytes: boundedOption(
      options.maxRecordBytes,
      DEFAULT_LIMITS.maxRecordBytes,
      1_024,
      2_147_483_647,
    ),
    maxPendingMutations: boundedOption(
      options.maxPendingMutations,
      DEFAULT_LIMITS.maxPendingMutations,
      1,
      100_000,
    ),
    maxPendingBytes: boundedOption(
      options.maxPendingBytes,
      DEFAULT_LIMITS.maxPendingBytes,
      1_024,
      2_147_483_647,
    ),
    maxCompletedBatches: boundedOption(
      options.maxCompletedBatches,
      DEFAULT_LIMITS.maxCompletedBatches,
      1,
      100_000,
    ),
    maxCompletedPushBatchBytes: boundedOption(
      options.maxCompletedPushBatchBytes,
      DEFAULT_LIMITS.maxCompletedPushBatchBytes,
      1_024,
      2_147_483_647,
    ),
    maxCompletedMutations: boundedOption(
      options.maxCompletedMutations,
      DEFAULT_LIMITS.maxCompletedMutations,
      1,
      1_000_000,
    ),
    maxCompletedMutationBytes: boundedOption(
      options.maxCompletedMutationBytes,
      DEFAULT_LIMITS.maxCompletedMutationBytes,
      1_024,
      2_147_483_647,
    ),
    maxCompletedPublicationBytes: boundedOption(
      options.maxCompletedPublicationBytes,
      DEFAULT_LIMITS.maxCompletedPublicationBytes,
      1_024,
      2_147_483_647,
    ),
    maxSerializedRowBytes: boundedOption(
      options.maxSerializedRowBytes,
      DEFAULT_LIMITS.maxSerializedRowBytes,
      1_024,
      64 * 1024 * 1024,
    ),
    maxDatabaseBytes: boundedOption(
      options.maxDatabaseBytes,
      DEFAULT_LIMITS.maxDatabaseBytes,
      1024 * 1024,
      2_147_483_647,
    ),
  };
  if (
    parsed.maxSerializedRowBytes > parsed.maxRecordBytes ||
    parsed.maxSerializedRowBytes > parsed.maxPendingBytes ||
    parsed.maxSerializedRowBytes > parsed.maxCompletedMutationBytes
  ) {
    throw invalidState();
  }
  return parsed;
}

export function withTransaction<Result>(
  database: DatabaseSync,
  task: () => Result,
): Result {
  database.exec('BEGIN IMMEDIATE');
  try {
    const result = task();
    database.exec('COMMIT');
    return result;
  } catch (error) {
    try {
      database.exec('ROLLBACK');
    } catch {
      throw invalidState();
    }
    throw error;
  }
}

function assertTableBounds(
  database: DatabaseSync,
  table: 'completed_push_batches' | 'opaque_records' | 'pending_mutations',
  maxRows: number,
  maxBytes: number,
): void {
  const row = database
    .prepare(
      `SELECT COUNT(*) AS row_count,
              COALESCE(SUM(serialized_bytes), 0) AS total_bytes
         FROM ${table}`,
    )
    .get() as CountBytesRow | undefined;
  if (
    row === undefined ||
    requireNonnegativeInteger(row.row_count) > maxRows ||
    requireNonnegativeInteger(row.total_bytes) > maxBytes
  ) {
    throw invalidState();
  }
}

export function assertRowCount(
  database: DatabaseSync,
  table: 'active_push_batches' | 'sync_cursors',
  maxRows: number,
): void {
  const row = database.prepare(`SELECT COUNT(*) AS value FROM ${table}`).get();
  if (getInteger(row, 'value') > maxRows) throw invalidState();
}

export function pruneCompletedPushBatches(
  database: DatabaseSync,
  limits: Pick<StoreLimits, 'maxCompletedBatches' | 'maxCompletedPushBatchBytes'>,
  protectedBatchKey: string,
): void {
  for (;;) {
    const row = database
      .prepare(
        `SELECT COUNT(*) AS row_count,
                COALESCE(SUM(serialized_bytes), 0) AS total_bytes
           FROM completed_push_batches`,
      )
      .get() as CountBytesRow | undefined;
    if (row === undefined) throw invalidState();
    if (
      requireNonnegativeInteger(row.row_count) <= limits.maxCompletedBatches &&
      requireNonnegativeInteger(row.total_bytes) <= limits.maxCompletedPushBatchBytes
    ) {
      return;
    }
    const changed = database
      .prepare(
        `DELETE FROM completed_push_batches
          WHERE sequence = (
            SELECT sequence FROM completed_push_batches
             WHERE batch_key <> ? ORDER BY sequence ASC LIMIT 1
          )`,
      )
      .run(protectedBatchKey);
    if (changed.changes !== 1) throw invalidState();
  }
}

function getIntegerPragma(database: DatabaseSync, sql: string, key: string): number {
  return getInteger(database.prepare(sql).get(), key);
}

function getStringPragma(database: DatabaseSync, sql: string, key: string): string {
  const row = database.prepare(sql).get();
  if (row === undefined || typeof row[key] !== 'string') {
    throw invalidState();
  }
  return row[key];
}

function getInteger(row: unknown, key: string): number {
  if (typeof row !== 'object' || row === null || !(key in row)) {
    throw invalidState();
  }
  return requireNonnegativeInteger((row as Record<string, unknown>)[key]);
}

export function requireNonnegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw invalidState();
  return value as number;
}

function boundedOption(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const candidate = value ?? fallback;
  if (!Number.isSafeInteger(candidate) || candidate < minimum || candidate > maximum) {
    throw invalidState();
  }
  return candidate;
}

function hasOnlyKeys(value: unknown, keys: readonly string[]): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return (
    actual.length === keys.filter((key) => key in value).length &&
    actual.every((key) => keys.includes(key))
  );
}

export async function assertPhysicalSize(
  path: string,
  maxDatabaseBytes: number,
): Promise<void> {
  let total = 0;
  for (const candidate of [path, `${path}-wal`, `${path}-shm`, `${path}-journal`]) {
    try {
      const value = await stat(candidate);
      if (!value.isFile()) throw invalidState();
      total += value.size;
    } catch (error) {
      if (isMissing(error)) continue;
      throw normalizeFailure(error);
    }
  }
  if (total > maxDatabaseBytes + 32 * 1024 * 1024) throw invalidState();
}

function isMissing(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
}
