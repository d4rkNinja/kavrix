import { createHash, randomUUID } from 'node:crypto';
import { readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { constants as sqliteConstants, DatabaseSync } from 'node:sqlite';

import {
  encryptedGroupRecordSchema,
  opaqueMutationSchema,
  templateMigrationPublicationRequestSchema,
} from '@kavrix/schemas';
import { SyncLocalStateError } from '@kavrix/sync';
import { afterEach, describe, expect, it } from 'vitest';

import { openSqliteSyncLocalStore } from '../src/index.js';
import { initializeDatabase, parseOptions } from '../src/sqlite-local-database.js';
import { groupRecord, mutation, pullPage, timestamp, vaultId } from './fixtures.js';

const TEST_TMPDIR = await realpath(tmpdir());
const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) {
    if (
      dirname(root) !== TEST_TMPDIR ||
      !root.startsWith(join(TEST_TMPDIR, 'kavrix-sqlite-v3-test-'))
    ) {
      throw new Error('Refusing to remove an unverified test directory');
    }
    await rm(root, { recursive: true, force: true });
  }
});

describe('SQLite local format v3', () => {
  it('creates and reopens the exact v3 marker and user version', async () => {
    const path = databasePath();
    const store = await openSqliteSyncLocalStore({ path });
    store.close();

    const reopened = await openSqliteSyncLocalStore({ path });
    reopened.close();

    const raw = new DatabaseSync(path, { readOnly: true });
    try {
      expect(raw.prepare('PRAGMA user_version').get()).toEqual({ user_version: 3 });
      expect(
        raw.prepare(`SELECT value FROM store_metadata WHERE key = 'format'`).get(),
      ).toEqual({ value: 'kavrix-local-sync-v3' });
      expect(
        raw
          .prepare(
            `SELECT COUNT(*) AS value FROM sqlite_schema
              WHERE type = 'table' AND name = 'completed_outbound_observations'`,
          )
          .get(),
      ).toEqual({ value: 1 });
      expect(
        raw
          .prepare(
            `SELECT COUNT(*) AS value FROM sqlite_schema
              WHERE type = 'table' AND name = 'outbound_observation_pins'`,
          )
          .get(),
      ).toEqual({ value: 1 });
    } finally {
      raw.close();
    }
  });

  it('fails closed for a tampered v3 marker without rewriting it', async () => {
    const path = databasePath();
    const store = await openSqliteSyncLocalStore({ path });
    store.close();
    const raw = new DatabaseSync(path);
    raw
      .prepare(`UPDATE store_metadata SET value = 'tampered' WHERE key = 'format'`)
      .run();
    raw.close();

    await expect(openSqliteSyncLocalStore({ path })).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    const check = new DatabaseSync(path, { readOnly: true });
    try {
      expect(
        check.prepare(`SELECT value FROM store_metadata WHERE key = 'format'`).get(),
      ).toEqual({ value: 'tampered' });
    } finally {
      check.close();
    }
  });

  it('migrates an exact empty-completion v2 while preserving cursor, base, active work, and delete predecessor', async () => {
    const path = databasePath();
    const store = await openSqliteSyncLocalStore({ path });
    const base = groupRecord();
    const deletion = opaqueMutationSchema.parse({
      entityType: 'group',
      expectedRecordRevision: 0,
      idempotencyKey: 'pending-delete-key-001',
      record: encryptedGroupRecordSchema.parse({
        ...groupRecord(base.id, 1),
        tombstonedAt: timestamp,
      }),
    });
    const page = pullPage([base]);
    await store.applyPullPage(page);
    await store.enqueueBatch([deletion]);
    await store.saveActivePushBatch({
      vaultId,
      batchIdempotencyKey: 'active-v2-batch-key-01',
      mutationIdempotencyKeys: [deletion.idempotencyKey],
    });
    store.close();
    downgradeToV2(path);

    const migrated = await openSqliteSyncLocalStore({ path });
    expect(await migrated.loadCursor(vaultId)).toEqual(page.cursor);
    expect(await migrated.loadOpaqueRecord(vaultId, 'group', base.id)).toEqual(base);
    expect(await migrated.listPendingMutations(vaultId)).toEqual([deletion]);
    expect(await migrated.loadActivePushBatch(vaultId)).toEqual({
      vaultId,
      batchIdempotencyKey: 'active-v2-batch-key-01',
      mutationIdempotencyKeys: [deletion.idempotencyKey],
    });
    expect(await migrated.loadOutboundReplayState(vaultId, 'generic-push')).toEqual({
      kind: 'generic-push',
      vaultId,
      batchIdempotencyKey: 'active-v2-batch-key-01',
      replayFromServerSequence: null,
    });
    await expect(
      migrated.ensureOutboundReplayStart({
        kind: 'template-publication',
        vaultId,
        batchIdempotencyKey: 'active-v2-batch-key-01',
      }),
    ).rejects.toThrow();
    expect(
      await migrated.loadOutboundReplayState(vaultId, 'generic-push'),
    ).toMatchObject({ replayFromServerSequence: null });
    await expect(
      migrated.ensureOutboundReplayStart({
        kind: 'generic-push',
        vaultId,
        batchIdempotencyKey: 'active-v2-batch-key-01',
      }),
    ).resolves.toBe(1);
    expect((await migrated.getCurrentGroup(vaultId, base.id))?.state).toBe('deleted');
    migrated.close();

    const rebound = await openSqliteSyncLocalStore({ path });
    expect(
      await rebound.loadOutboundReplayState(vaultId, 'generic-push'),
    ).toMatchObject({
      replayFromServerSequence: 1,
    });
    rebound.close();

    const check = new DatabaseSync(path, { readOnly: true });
    try {
      expect(check.prepare('PRAGMA user_version').get()).toEqual({ user_version: 3 });
      expect(
        check.prepare(`SELECT value FROM store_metadata WHERE key = 'format'`).get(),
      ).toEqual({ value: 'kavrix-local-sync-v3' });
    } finally {
      check.close();
    }
  });

  it('refuses each nonempty legacy completion family without changing logical state', async () => {
    for (const family of [
      'completed_push_batches',
      'completed_template_migrations',
      'completed_mutation_receipts',
    ] as const) {
      const path = databasePath();
      const store = await openSqliteSyncLocalStore({ path });
      store.close();
      downgradeToV2(path);
      const raw = new DatabaseSync(path);
      try {
        if (family === 'completed_push_batches') {
          raw
            .prepare(
              `INSERT INTO completed_push_batches
                 (vault_id, batch_key, acknowledged_json, serialized_bytes)
               VALUES (?, ?, '[]', 2)`,
            )
            .run(vaultId, 'legacy-completed-batch-1');
        } else if (family === 'completed_template_migrations') {
          raw
            .prepare(
              `INSERT INTO completed_template_migrations
                 (vault_id, batch_key, publication_json, response_json,
                  serialized_bytes)
               VALUES (?, ?, '{}', '{}', 4)`,
            )
            .run(vaultId, 'legacy-template-batch-1');
        } else {
          const completed = mutation('legacy-mutation-key-1');
          const json = JSON.stringify(completed);
          raw
            .prepare(
              `INSERT INTO completed_mutation_receipts
                 (vault_id, idempotency_key, queue_kind, mutation_json,
                  serialized_bytes)
               VALUES (?, ?, 'generic', ?, ?)`,
            )
            .run(vaultId, completed.idempotencyKey, json, Buffer.byteLength(json));
        }
      } finally {
        raw.close();
      }
      const before = await snapshotV2(path, family);
      await expect(openSqliteSyncLocalStore({ path })).rejects.toBeInstanceOf(
        SyncLocalStateError,
      );
      expect(await snapshotV2(path, family)).toEqual(before);
    }
  });

  it('rolls back real migration DDL when the final marker update is denied', async () => {
    const path = databasePath();
    const store = await openSqliteSyncLocalStore({ path });
    store.close();
    downgradeToV2(path);
    const raw = new DatabaseSync(path);
    raw.setAuthorizer((action, arg1) =>
      action === sqliteConstants.SQLITE_UPDATE && arg1 === 'store_metadata'
        ? sqliteConstants.SQLITE_DENY
        : sqliteConstants.SQLITE_OK,
    );
    expect(() => {
      initializeDatabase(raw, parseOptions({ path }));
    }).toThrow();
    raw.setAuthorizer(null);
    expect(raw.prepare('PRAGMA user_version').get()).toEqual({ user_version: 2 });
    expect(
      raw.prepare(`SELECT value FROM store_metadata WHERE key = 'format'`).get(),
    ).toEqual({ value: 'kavrix-local-sync-v2' });
    expect(
      raw
        .prepare(
          `SELECT COUNT(*) AS value FROM sqlite_schema
            WHERE name = 'completed_outbound_observations'`,
        )
        .get(),
    ).toEqual({ value: 0 });
    expect(
      raw
        .prepare(
          `SELECT COUNT(*) AS value FROM pragma_table_info('active_push_batches')
            WHERE name = 'replay_from_server_sequence'`,
        )
        .get(),
    ).toEqual({ value: 0 });
    raw.close();
  });

  it('preserves an exact pending template publication with a nullable replay start', async () => {
    const path = databasePath();
    const store = await openSqliteSyncLocalStore({ path });
    const base = groupRecord();
    await store.applyPullPage(pullPage([base]));
    const publication = templateMigrationPublicationRequestSchema.parse({
      vaultId,
      batchIdempotencyKey: 'pending-v2-template-1',
      mutations: [mutation('pending-template-key-1', groupRecord(base.id, 1), 0)],
    });
    await store.enqueueTemplateMigrationPublication(publication);
    store.close();
    downgradeToV2(path);

    const migrated = await openSqliteSyncLocalStore({ path });
    expect(await migrated.loadPendingTemplateMigrationPublication(vaultId)).toEqual(
      publication,
    );
    expect(
      await migrated.loadOutboundReplayState(vaultId, 'template-publication'),
    ).toEqual({
      kind: 'template-publication',
      vaultId,
      batchIdempotencyKey: publication.batchIdempotencyKey,
      replayFromServerSequence: null,
    });
    await expect(
      migrated.ensureOutboundReplayStart({
        kind: 'template-publication',
        vaultId,
        batchIdempotencyKey: publication.batchIdempotencyKey,
      }),
    ).resolves.toBe(1);
    await expect(
      migrated.ensureOutboundReplayStart({
        kind: 'template-publication',
        vaultId,
        batchIdempotencyKey: publication.batchIdempotencyKey,
      }),
    ).resolves.toBe(1);
    migrated.close();
  });

  it('rejects tampered v2 predecessor and template-position state without modifying the file', async () => {
    for (const tamper of ['predecessor', 'template-position'] as const) {
      const path = databasePath();
      const store = await openSqliteSyncLocalStore({ path });
      const base = groupRecord();
      await store.applyPullPage(pullPage([base]));
      if (tamper === 'predecessor') {
        const deletion = opaqueMutationSchema.parse({
          entityType: 'group',
          expectedRecordRevision: 0,
          idempotencyKey: 'tampered-delete-key-1',
          record: encryptedGroupRecordSchema.parse({
            ...groupRecord(base.id, 1),
            tombstonedAt: timestamp,
          }),
        });
        await store.enqueueBatch([deletion]);
      } else {
        await store.enqueueTemplateMigrationPublication(
          templateMigrationPublicationRequestSchema.parse({
            vaultId,
            batchIdempotencyKey: 'tampered-position-batch',
            mutations: [mutation('tampered-position-key', groupRecord(base.id, 1), 0)],
          }),
        );
      }
      store.close();
      downgradeToV2(path);
      const raw = new DatabaseSync(path);
      if (tamper === 'predecessor') {
        raw
          .prepare(
            `UPDATE deletion_predecessors
                SET entity_id = 'group.orphan'
              WHERE owner_key = 'tampered-delete-key-1'`,
          )
          .run();
      } else {
        raw
          .prepare(`UPDATE pending_template_migration_mutations SET position = 1`)
          .run();
      }
      raw.close();
      const before = await fileDigest(path);
      await expect(openSqliteSyncLocalStore({ path })).rejects.toBeInstanceOf(
        SyncLocalStateError,
      );
      expect(await fileDigest(path)).toBe(before);
      const check = new DatabaseSync(path, { readOnly: true });
      expect(check.prepare('PRAGMA user_version').get()).toEqual({ user_version: 2 });
      check.close();
    }
  });
});

function databasePath(): string {
  const root = join(
    TEST_TMPDIR,
    `kavrix-sqlite-v3-test-${randomUUID().replaceAll('-', '')}`,
  );
  roots.push(root);
  return join(root, 'state.sqlite');
}

function downgradeToV2(path: string): void {
  const raw = new DatabaseSync(path);
  try {
    raw.exec(`PRAGMA foreign_keys = OFF`);
    raw.exec(`
      BEGIN IMMEDIATE;
      DROP TABLE outbound_observation_pins;
      DROP TABLE completed_outbound_observations;
      CREATE TEMP TABLE migrate_template_children AS
        SELECT batch_key, position, vault_id, entity_type, entity_id,
               idempotency_key, mutation_json, serialized_bytes
          FROM pending_template_migration_mutations;
      CREATE TEMP TABLE migrate_template_parents AS
        SELECT vault_id, batch_key, publication_json, serialized_bytes
          FROM pending_template_migrations;
      DROP TABLE pending_template_migration_mutations;
      DROP TABLE pending_template_migrations;
      CREATE TABLE pending_template_migrations (
        vault_id TEXT PRIMARY KEY NOT NULL,
        batch_key TEXT NOT NULL UNIQUE,
        publication_json TEXT NOT NULL,
        serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2)
      ) STRICT, WITHOUT ROWID;
      INSERT INTO pending_template_migrations
        (vault_id, batch_key, publication_json, serialized_bytes)
        SELECT vault_id, batch_key, publication_json, serialized_bytes
          FROM migrate_template_parents;
      CREATE TABLE pending_template_migration_mutations (
        batch_key TEXT NOT NULL,
        position INTEGER NOT NULL CHECK(position >= 0 AND position < 100),
        vault_id TEXT NOT NULL,
        entity_type TEXT NOT NULL CHECK(entity_type IN ('group','item')),
        entity_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        mutation_json TEXT NOT NULL,
        serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2),
        PRIMARY KEY(batch_key, position),
        FOREIGN KEY(batch_key) REFERENCES pending_template_migrations(batch_key) ON DELETE CASCADE
      ) STRICT, WITHOUT ROWID;
      CREATE INDEX pending_template_migration_entity
        ON pending_template_migration_mutations(vault_id, entity_type, entity_id, position);
      INSERT INTO pending_template_migration_mutations
        (batch_key, position, vault_id, entity_type, entity_id,
         idempotency_key, mutation_json, serialized_bytes)
        SELECT batch_key, position, vault_id, entity_type, entity_id,
               idempotency_key, mutation_json, serialized_bytes
          FROM migrate_template_children;
      DROP TABLE migrate_template_children;
      DROP TABLE migrate_template_parents;
      ALTER TABLE active_push_batches RENAME TO active_push_batches_v3;
      CREATE TABLE active_push_batches (
        vault_id TEXT PRIMARY KEY NOT NULL,
        batch_key TEXT NOT NULL UNIQUE,
        batch_json TEXT NOT NULL,
        serialized_bytes INTEGER NOT NULL CHECK(serialized_bytes >= 2)
      ) STRICT, WITHOUT ROWID;
      INSERT INTO active_push_batches
        (vault_id, batch_key, batch_json, serialized_bytes)
        SELECT vault_id, batch_key, batch_json, serialized_bytes
          FROM active_push_batches_v3;
      DROP TABLE active_push_batches_v3;
      UPDATE store_metadata SET value = 'kavrix-local-sync-v2' WHERE key = 'format';
      PRAGMA user_version = 2;
      COMMIT;
    `);
    raw.exec(`PRAGMA foreign_keys = ON`);
  } finally {
    raw.close();
  }
}

async function snapshotV2(
  path: string,
  family:
    | 'completed_push_batches'
    | 'completed_template_migrations'
    | 'completed_mutation_receipts',
): Promise<unknown> {
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    const logical = {
      version: raw.prepare('PRAGMA user_version').get(),
      marker: raw
        .prepare(`SELECT value FROM store_metadata WHERE key = 'format'`)
        .get(),
      receipt: raw.prepare(`SELECT * FROM ${family}`).all(),
      schema: raw
        .prepare(
          `SELECT type, name, sql FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`,
        )
        .all(),
    };
    const bytes = await readFile(path);
    try {
      return {
        logical,
        fileDigest: createHash('sha256').update(bytes).digest('base64url'),
      };
    } finally {
      bytes.fill(0);
    }
  } finally {
    raw.close();
  }
}

async function fileDigest(path: string): Promise<string> {
  const bytes = await readFile(path);
  try {
    return createHash('sha256').update(bytes).digest('base64url');
  } finally {
    bytes.fill(0);
  }
}
