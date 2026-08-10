import { stat } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';

import { SyncLocalStateError } from '@kavrix/sync';

import {
  acquireLocalWriterLease,
  recoverStaleLocalWriterLease,
  type LocalWriterLease,
} from './local-writer-lease.js';
import { prepareSecureDatabasePath, secureSqliteFiles } from './path-security.js';

const SCHEMA_VERSION = 1;
const MAX_OPERATION_LIMIT = 256;
const DEFAULT_MAX_SERIALIZED_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_DATABASE_BYTES = 64 * 1024 * 1024;
const MAX_CONFIGURED_DATABASE_BYTES = 512 * 1024 * 1024;

export const INITIALIZATION_APPLICATION_ID = 0x4b4a4931;
export const JOIN_APPLICATION_ID = 0x4b4a4a31;
export const INIT_SCHEMA = {
  lifecycle_metadata: `CREATE TABLE lifecycle_metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
  ) STRICT, WITHOUT ROWID`,
  initialization_journal: `CREATE TABLE initialization_journal (
    operation_id TEXT PRIMARY KEY NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('prepared','network-attempted','committed')),
    record_json TEXT NOT NULL,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2),
    device_locator_json TEXT UNIQUE,
    session_locator_json TEXT UNIQUE,
    CHECK((state = 'committed' AND device_locator_json IS NULL AND session_locator_json IS NULL)
       OR (state != 'committed' AND device_locator_json IS NOT NULL AND session_locator_json IS NOT NULL))
  ) STRICT, WITHOUT ROWID`,
} as const;
export const JOIN_SCHEMA = {
  lifecycle_metadata: `CREATE TABLE lifecycle_metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
  ) STRICT, WITHOUT ROWID`,
  join_journal: `CREATE TABLE join_journal (
    operation_id TEXT PRIMARY KEY NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('reserving','stable','transitioning','deleting','committing')),
    state TEXT NOT NULL CHECK(state IN ('prepared','redeem-attempted','completion-attempted','committed')),
    target_state TEXT CHECK(target_state IN ('redeem-attempted','completion-attempted')),
    expected_vault_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    session_locator_json TEXT NOT NULL UNIQUE,
    committed_json TEXT,
    serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2),
    CHECK((phase = 'transitioning' AND target_state IS NOT NULL) OR
          (phase != 'transitioning' AND target_state IS NULL)),
    CHECK((state = 'committed' AND phase = 'stable' AND committed_json IS NOT NULL) OR
          (state != 'committed')),
    CHECK((phase = 'committing' AND committed_json IS NOT NULL) OR
          (phase != 'committing'))
  ) STRICT, WITHOUT ROWID`,
} as const;

export interface SqliteLifecycleJournalOptions {
  readonly path: string;
  readonly leasePath?: string;
  readonly maxOperations?: number;
  readonly maxSerializedBytes?: number;
  readonly maxDatabaseBytes?: number;
}

export type LifecycleJournalLimits = Readonly<{
  maxOperations: number;
  maxSerializedBytes: number;
  maxDatabaseBytes: number;
}>;

export abstract class SqliteLifecycleJournalBase {
  protected readonly database: DatabaseSync;
  protected readonly databasePath: string;
  protected readonly limits: LifecycleJournalLimits;
  readonly #lease: LocalWriterLease;
  #closed = false;
  #leaseReleased = false;
  #tail: Promise<void> = Promise.resolve();

  protected constructor(
    database: DatabaseSync,
    databasePath: string,
    limits: LifecycleJournalLimits,
    lease: LocalWriterLease,
  ) {
    this.database = database;
    this.databasePath = databasePath;
    this.limits = limits;
    this.#lease = lease;
  }

  public close(): Promise<void> {
    const predecessor = this.#tail;
    let releaseQueue: (() => void) | undefined;
    this.#tail = new Promise((resolve) => {
      releaseQueue = resolve;
    });
    return predecessor
      .then(async () => {
        let failed = false;
        if (!this.#closed) {
          try {
            this.database.exec('PRAGMA wal_checkpoint(TRUNCATE)');
          } catch {
            failed = true;
          }
          try {
            this.database.close();
          } catch {
            failed = true;
          }
          this.#closed = true;
        }
        if (!this.#leaseReleased) {
          try {
            await this.#lease.release();
            this.#leaseReleased = true;
          } catch {
            failed = true;
          }
        }
        if (failed) throw invalidState();
      })
      .finally(() => releaseQueue?.());
  }

  protected exclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
    const predecessor = this.#tail;
    let release: (() => void) | undefined;
    this.#tail = new Promise((resolve) => {
      release = resolve;
    });
    return predecessor
      .then(async () => {
        if (this.#closed) throw invalidState();
        return operation();
      })
      .catch((error: unknown) => {
        throw normalizeFailure(error);
      })
      .finally(() => release?.());
  }

  protected async durableFlush(): Promise<void> {
    try {
      this.database.exec('PRAGMA wal_checkpoint(FULL)');
      await secureSqliteFiles(this.databasePath, true);
      await assertPhysicalSize(this.databasePath, this.limits.maxDatabaseBytes);
    } catch {
      this.failClosed();
      throw invalidState();
    }
  }

  private failClosed(): void {
    if (this.#closed) return;
    try {
      this.database.close();
    } catch {
      // The adapter stays permanently closed if native close reports failure.
    }
    this.#closed = true;
  }
}

export async function openLifecycleDatabase(
  options: SqliteLifecycleJournalOptions,
  limits: LifecycleJournalLimits,
  applicationId: number,
  format: string,
  schema: Readonly<Record<string, string>>,
  verifyRows: (database: DatabaseSync, limits: LifecycleJournalLimits) => void,
): Promise<
  Readonly<{ database: DatabaseSync; path: string; lease: LocalWriterLease }>
> {
  const leasePath = options.leasePath ?? `${options.path}.writer.lock`;
  let lease: LocalWriterLease;
  try {
    lease = await acquireLocalWriterLease(leasePath);
  } catch {
    const recovered = await recoverStaleLocalWriterLease(leasePath);
    if (recovered !== 'recovered') throw invalidState();
    lease = await acquireLocalWriterLease(leasePath);
  }
  let database: DatabaseSync | undefined;
  try {
    const path = await prepareSecureDatabasePath(options.path);
    database = new DatabaseSync(path, {
      allowExtension: false,
      enableDoubleQuotedStringLiterals: false,
      enableForeignKeyConstraints: true,
      timeout: 5_000,
    });
    initializeDatabase(database, limits, applicationId, format, schema);
    database.enableDefensive(true);
    verifyDatabase(database, limits, applicationId, format, schema, verifyRows);
    await secureSqliteFiles(path, true);
    await assertPhysicalSize(path, limits.maxDatabaseBytes);
    return { database, path, lease };
  } catch (error) {
    if (database !== undefined) {
      try {
        database.close();
      } catch {
        throw invalidState();
      }
    }
    try {
      await lease.release();
    } catch {
      throw invalidState();
    }
    throw normalizeFailure(error);
  }
}

export function parseLifecycleOptions(
  options: SqliteLifecycleJournalOptions,
  additionalKeys: readonly string[] = [],
): LifecycleJournalLimits {
  const permitted = [
    'path',
    'leasePath',
    'maxOperations',
    'maxSerializedBytes',
    'maxDatabaseBytes',
    ...additionalKeys,
  ];
  if (
    Object.keys(options).some((key) => !permitted.includes(key)) ||
    typeof options.path !== 'string'
  ) {
    throw invalidState();
  }
  return {
    maxOperations: bounded(
      options.maxOperations,
      MAX_OPERATION_LIMIT,
      1,
      MAX_OPERATION_LIMIT,
    ),
    maxSerializedBytes: bounded(
      options.maxSerializedBytes,
      DEFAULT_MAX_SERIALIZED_BYTES,
      1_024,
      32 * 1024 * 1024,
    ),
    maxDatabaseBytes: bounded(
      options.maxDatabaseBytes,
      DEFAULT_MAX_DATABASE_BYTES,
      1024 * 1024,
      MAX_CONFIGURED_DATABASE_BYTES,
    ),
  };
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

export function required<Value>(value: Value | null | undefined): Value {
  if (value === null || value === undefined) throw invalidState();
  return value;
}

export function normalizeFailure(error: unknown): SyncLocalStateError {
  return error instanceof SyncLocalStateError ? error : invalidState();
}

export function invalidState(): SyncLocalStateError {
  return new SyncLocalStateError();
}

function initializeDatabase(
  database: DatabaseSync,
  limits: LifecycleJournalLimits,
  applicationId: number,
  format: string,
  schema: Readonly<Record<string, string>>,
): void {
  database.exec(`
    PRAGMA trusted_schema = OFF;
    PRAGMA foreign_keys = ON;
    PRAGMA temp_store = MEMORY;
    PRAGMA secure_delete = ON;
    PRAGMA synchronous = FULL;
    PRAGMA fullfsync = ON;
    PRAGMA checkpoint_fullfsync = ON;
    PRAGMA wal_autocheckpoint = 32;
    PRAGMA journal_size_limit = 8388608;
  `);
  const currentApplicationId = integerPragma(
    database,
    'PRAGMA application_id',
    'application_id',
  );
  const currentVersion = integerPragma(database, 'PRAGMA user_version', 'user_version');
  if (currentApplicationId === 0 && currentVersion === 0) {
    const objects = getInteger(
      database
        .prepare(
          `SELECT COUNT(*) AS value FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'`,
        )
        .get(),
      'value',
    );
    if (objects !== 0) throw invalidState();
    withTransaction(database, () => {
      database.exec(`${Object.values(schema).join(';\n')};`);
      database
        .prepare(`INSERT INTO lifecycle_metadata(key, value) VALUES ('format', ?)`)
        .run(format);
      database.exec(`PRAGMA application_id = ${String(applicationId)}`);
      database.exec(`PRAGMA user_version = ${String(SCHEMA_VERSION)}`);
    });
  } else if (
    currentApplicationId !== applicationId ||
    currentVersion !== SCHEMA_VERSION
  ) {
    throw invalidState();
  }
  const mode = stringPragma(database, 'PRAGMA journal_mode = WAL', 'journal_mode');
  if (mode.toLowerCase() !== 'wal') throw invalidState();
  const pageSize = integerPragma(database, 'PRAGMA page_size', 'page_size');
  database.exec(
    `PRAGMA max_page_count = ${String(Math.floor(limits.maxDatabaseBytes / pageSize))}`,
  );
}

function verifyDatabase(
  database: DatabaseSync,
  limits: LifecycleJournalLimits,
  applicationId: number,
  format: string,
  schema: Readonly<Record<string, string>>,
  verifyRows: (database: DatabaseSync, limits: LifecycleJournalLimits) => void,
): void {
  if (
    integerPragma(database, 'PRAGMA application_id', 'application_id') !==
      applicationId ||
    integerPragma(database, 'PRAGMA user_version', 'user_version') !== SCHEMA_VERSION
  ) {
    throw invalidState();
  }
  const marker = database
    .prepare(`SELECT value FROM lifecycle_metadata WHERE key = 'format'`)
    .get() as { value?: unknown } | undefined;
  if (marker?.value !== format) throw invalidState();
  verifySchema(database, schema);
  const integrity = database.prepare('PRAGMA integrity_check').all() as unknown as {
    integrity_check?: unknown;
  }[];
  if (integrity.length !== 1 || integrity[0]?.integrity_check !== 'ok') {
    throw invalidState();
  }
  const pages = integerPragma(database, 'PRAGMA page_count', 'page_count');
  const pageSize = integerPragma(database, 'PRAGMA page_size', 'page_size');
  if (pages * pageSize > limits.maxDatabaseBytes) throw invalidState();
  verifyRows(database, limits);
}

function verifySchema(
  database: DatabaseSync,
  schema: Readonly<Record<string, string>>,
): void {
  const actual = database
    .prepare(
      `SELECT type, name, sql FROM sqlite_schema
        WHERE name NOT LIKE 'sqlite_%' ORDER BY type ASC, name ASC`,
    )
    .all() as unknown as { type?: unknown; name?: unknown; sql?: unknown }[];
  const parsed = actual.map((row) => {
    if (
      row.type !== 'table' ||
      typeof row.name !== 'string' ||
      typeof row.sql !== 'string'
    ) {
      throw invalidState();
    }
    return { name: row.name, sql: normalizeSql(row.sql) };
  });
  const expected = Object.entries(schema)
    .map(([name, sql]) => ({ name, sql: normalizeSql(sql) }))
    .sort((left, right) => left.name.localeCompare(right.name));
  if (JSON.stringify(parsed) !== JSON.stringify(expected)) throw invalidState();
}

function integerPragma(database: DatabaseSync, sql: string, key: string): number {
  return getInteger(database.prepare(sql).get(), key);
}

function stringPragma(database: DatabaseSync, sql: string, key: string): string {
  const row = database.prepare(sql).get();
  if (row === undefined || typeof row[key] !== 'string') throw invalidState();
  return row[key];
}

function getInteger(row: unknown, key: string): number {
  if (typeof row !== 'object' || row === null || !(key in row)) throw invalidState();
  return requireInteger((row as Record<string, unknown>)[key]);
}

function requireInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw invalidState();
  return value as number;
}

function bounded(
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

function normalizeSql(value: string): string {
  return value.replace(/\s+/gu, ' ').trim();
}

async function assertPhysicalSize(
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
      throw invalidState();
    }
  }
  if (total > maxDatabaseBytes + 16 * 1024 * 1024) throw invalidState();
}

function isMissing(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
}
