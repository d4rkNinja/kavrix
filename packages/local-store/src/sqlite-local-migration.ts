import type { DatabaseSync } from 'node:sqlite';

import { invalidState } from './sqlite-local-errors.js';

const LEGACY_COMPLETION_TABLES = [
  'completed_push_batches',
  'completed_template_migrations',
  'completed_mutation_receipts',
] as const;

export function migrateLegacyV2Database(
  database: DatabaseSync,
  addedSchemaDefinitions: readonly string[],
  formatMarker: string,
  schemaVersion: number,
  verifyLegacyState: () => void,
): void {
  database.exec('BEGIN IMMEDIATE');
  try {
    verifyLegacyState();
    for (const table of LEGACY_COMPLETION_TABLES) {
      const row = database.prepare(`SELECT COUNT(*) AS value FROM ${table}`).get();
      if (typeof row !== 'object' || !('value' in row) || row['value'] !== 0) {
        throw invalidState();
      }
    }
    database.exec(`
      ALTER TABLE active_push_batches
        ADD COLUMN replay_from_server_sequence INTEGER
          CHECK(replay_from_server_sequence >= 0);
      ALTER TABLE pending_template_migrations
        ADD COLUMN replay_from_server_sequence INTEGER
          CHECK(replay_from_server_sequence >= 0);
      ${addedSchemaDefinitions.join(';\n')};
    `);
    const changed = database
      .prepare(`UPDATE store_metadata SET value = ? WHERE key = 'format'`)
      .run(formatMarker);
    if (changed.changes !== 1) throw invalidState();
    database.exec(`PRAGMA user_version = ${String(schemaVersion)}`);
    database.exec('COMMIT');
  } catch (error) {
    try {
      database.exec('ROLLBACK');
    } catch {
      throw invalidState();
    }
    throw error;
  }
}

export function migrateSchemaV3Database(
  database: DatabaseSync,
  addedSchemaDefinitions: readonly string[],
  formatMarker: string,
  schemaVersion: number,
  verifyPreviousState: () => void,
): void {
  database.exec('BEGIN IMMEDIATE');
  try {
    verifyPreviousState();
    database.exec(`
      ${addedSchemaDefinitions.join(';\n')};
    `);
    const changed = database
      .prepare(`UPDATE store_metadata SET value = ? WHERE key = 'format'`)
      .run(formatMarker);
    if (changed.changes !== 1) throw invalidState();
    database.exec(`PRAGMA user_version = ${String(schemaVersion)}`);
    database.exec('COMMIT');
  } catch (error) {
    try {
      database.exec('ROLLBACK');
    } catch {
      throw invalidState();
    }
    throw error;
  }
}
