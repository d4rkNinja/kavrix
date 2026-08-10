import type { DatabaseSync } from 'node:sqlite';

import type { OpaqueMutation, VaultId } from '@kavrix/schemas';

import type { SqliteRecordState } from './sqlite-record-state.js';
import {
  encodeBounded,
  getInteger,
  invalidState,
  isDeleteMutation,
  mutationVaultId,
  parseMutationInput,
  required,
} from './sqlite-vault-codecs.js';
import type { VaultStateLimits } from './sqlite-vault-schema.js';

type ClaimedMutation = Readonly<{
  kind: 'generic' | 'template-migration';
  mutationJson: string;
}>;

export class SqliteMutationQueue {
  readonly #database: DatabaseSync;
  readonly #limits: VaultStateLimits;
  readonly #records: SqliteRecordState;

  constructor(
    database: DatabaseSync,
    limits: VaultStateLimits,
    records: SqliteRecordState,
  ) {
    this.#database = database;
    this.#limits = limits;
    this.#records = records;
  }

  enqueue(mutationsInput: readonly OpaqueMutation[]): 'duplicate' | 'queued' {
    if (
      !Array.isArray(mutationsInput) ||
      mutationsInput.length === 0 ||
      mutationsInput.length > 100
    ) {
      throw invalidState();
    }
    const mutations = mutationsInput.map(parseMutationInput);
    const vaultId = mutationVaultId(required(mutations[0]));
    if (
      mutations.some((mutation) => mutationVaultId(mutation) !== vaultId) ||
      new Set(mutations.map((mutation) => mutation.idempotencyKey)).size !==
        mutations.length ||
      this.hasPendingPublication(vaultId)
    ) {
      throw invalidState();
    }

    const existing = mutations.map((mutation) =>
      this.findClaim(mutation.idempotencyKey),
    );
    const existingCount = existing.filter((row) => row !== null).length;
    if (existingCount > 0) {
      if (
        existingCount !== mutations.length ||
        existing.some((row, index) => {
          const mutation = mutations[index];
          return (
            row === null ||
            mutation === undefined ||
            row.kind !== 'generic' ||
            row.mutationJson !== JSON.stringify(mutation)
          );
        })
      ) {
        throw invalidState();
      }
      return 'duplicate';
    }

    for (const mutation of mutations) {
      const current = this.#records.effective(
        vaultId,
        mutation.entityType,
        mutation.record.id,
      );
      this.#records.assertMutationApplies(current, mutation);
      if (isDeleteMutation(mutation)) {
        if (current === null) throw invalidState();
        this.#records.storePendingDeletePredecessor(mutation, current);
      }
      const encoded = encodeBounded(mutation, this.#limits.maxSerializedRowBytes);
      this.#database
        .prepare(
          `INSERT INTO pending_mutations
             (vault_id, entity_type, entity_id, idempotency_key, mutation_json,
              serialized_bytes)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(
          vaultId,
          mutation.entityType,
          mutation.record.id,
          mutation.idempotencyKey,
          encoded.json,
          encoded.bytes,
        );
    }
    this.assertBounds();
    this.#records.assertBounds();
    return 'queued';
  }

  recordCompleted(
    mutationInput: OpaqueMutation,
    queueKind: 'generic' | 'template-migration',
  ): void {
    const mutation = parseMutationInput(mutationInput);
    const encoded = encodeBounded(mutation, this.#limits.maxSerializedRowBytes);
    const existing = this.#database
      .prepare(
        `SELECT vault_id, queue_kind, mutation_json, serialized_bytes
           FROM completed_mutation_receipts WHERE idempotency_key = ?`,
      )
      .get(mutation.idempotencyKey) as
      | {
          vault_id?: unknown;
          queue_kind?: unknown;
          mutation_json?: unknown;
          serialized_bytes?: unknown;
        }
      | undefined;
    if (existing !== undefined) {
      if (
        existing.vault_id !== mutationVaultId(mutation) ||
        existing.queue_kind !== queueKind ||
        existing.mutation_json !== encoded.json ||
        getInteger(existing, 'serialized_bytes') !== encoded.bytes
      ) {
        throw invalidState();
      }
      return;
    }
    this.#database
      .prepare(
        `INSERT INTO completed_mutation_receipts
           (vault_id, idempotency_key, queue_kind, mutation_json,
            serialized_bytes)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        mutationVaultId(mutation),
        mutation.idempotencyKey,
        queueKind,
        encoded.json,
        encoded.bytes,
      );
  }

  pruneCompleted(protectedKeys: readonly string[]): void {
    const protectedSet = new Set(protectedKeys);
    for (;;) {
      const bounds = this.#completedBounds();
      if (
        bounds.rows <= this.#limits.maxCompletedMutations &&
        bounds.bytes <= this.#limits.maxCompletedMutationBytes
      ) {
        return;
      }
      const candidates = this.#database
        .prepare(
          `SELECT sequence, idempotency_key FROM completed_mutation_receipts
            ORDER BY sequence ASC`,
        )
        .all() as unknown as { sequence?: unknown; idempotency_key?: unknown }[];
      const candidate = candidates.find(
        (row) =>
          typeof row.idempotency_key === 'string' &&
          !protectedSet.has(row.idempotency_key),
      );
      if (candidate === undefined) throw invalidState();
      const changed = this.#database
        .prepare(`DELETE FROM completed_mutation_receipts WHERE sequence = ?`)
        .run(getInteger(candidate, 'sequence'));
      if (changed.changes !== 1) throw invalidState();
    }
  }

  findClaim(key: string): ClaimedMutation | null {
    const generic = this.#database
      .prepare(`SELECT mutation_json FROM pending_mutations WHERE idempotency_key = ?`)
      .get(key) as { mutation_json?: unknown } | undefined;
    const migration = this.#database
      .prepare(
        `SELECT mutation_json FROM pending_template_migration_mutations
          WHERE idempotency_key = ?`,
      )
      .get(key) as { mutation_json?: unknown } | undefined;
    const completed = this.#database
      .prepare(
        `SELECT queue_kind, mutation_json FROM completed_mutation_receipts
          WHERE idempotency_key = ?`,
      )
      .get(key) as { queue_kind?: unknown; mutation_json?: unknown } | undefined;
    if (
      [generic, migration, completed].filter((value) => value !== undefined).length > 1
    ) {
      throw invalidState();
    }
    if (generic !== undefined) {
      if (typeof generic.mutation_json !== 'string') throw invalidState();
      return { kind: 'generic', mutationJson: generic.mutation_json };
    }
    if (migration !== undefined) {
      if (typeof migration.mutation_json !== 'string') throw invalidState();
      return { kind: 'template-migration', mutationJson: migration.mutation_json };
    }
    if (completed !== undefined) {
      if (
        (completed.queue_kind !== 'generic' &&
          completed.queue_kind !== 'template-migration') ||
        typeof completed.mutation_json !== 'string'
      ) {
        throw invalidState();
      }
      return {
        kind: completed.queue_kind,
        mutationJson: completed.mutation_json,
      };
    }
    return null;
  }

  hasPendingPublication(vaultId: VaultId): boolean {
    return (
      this.#database
        .prepare(`SELECT 1 FROM pending_template_migrations WHERE vault_id = ?`)
        .get(vaultId) !== undefined
    );
  }

  assertBounds(): void {
    const queueBounds = this.#database
      .prepare(
        `SELECT
           (SELECT COUNT(*) FROM pending_mutations) +
           (SELECT COUNT(*) FROM pending_template_migration_mutations)
             AS row_count,
           (SELECT COALESCE(SUM(serialized_bytes), 0) FROM pending_mutations) +
           (SELECT COALESCE(SUM(serialized_bytes), 0)
              FROM pending_template_migration_mutations) +
           (SELECT COALESCE(SUM(serialized_bytes), 0)
              FROM pending_template_migrations) AS total_bytes`,
      )
      .get();
    if (
      getInteger(queueBounds, 'row_count') > this.#limits.maxPendingMutations ||
      getInteger(queueBounds, 'total_bytes') > this.#limits.maxPendingBytes
    ) {
      throw invalidState();
    }
    const completion = this.#completedBounds();
    if (
      completion.rows > this.#limits.maxCompletedMutations ||
      completion.bytes > this.#limits.maxCompletedMutationBytes
    ) {
      throw invalidState();
    }
  }

  #completedBounds(): Readonly<{ rows: number; bytes: number }> {
    const row = this.#database
      .prepare(
        `SELECT COUNT(*) AS row_count,
                COALESCE(SUM(serialized_bytes), 0) AS total_bytes
           FROM completed_mutation_receipts`,
      )
      .get();
    return {
      rows: getInteger(row, 'row_count'),
      bytes: getInteger(row, 'total_bytes'),
    };
  }
}
