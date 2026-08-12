import type { DatabaseSync } from 'node:sqlite';

import {
  canonicalJson,
  type TemplateMigrationPublicationRequest,
  type VaultId,
} from '@kavrix/schemas';
import type { CompleteTemplateMigrationPublicationInput } from '@kavrix/sync';

import type { SqliteMutationQueue } from './sqlite-mutation-queue.js';
import type { SqliteRecordState } from './sqlite-record-state.js';
import {
  countRows,
  encodeBounded,
  getInteger,
  invalidState,
  parseJson,
  parseMutationRow,
  parsePublication,
  parsePublicationResponse,
  parsePublicationRow,
} from './sqlite-vault-codecs.js';
import type {
  PersistedCompletionRow,
  PersistedMutationRow,
  PersistedPublicationRow,
  VaultStateLimits,
} from './sqlite-vault-schema.js';

export class SqliteTemplatePublications {
  readonly #database: DatabaseSync;
  readonly #limits: VaultStateLimits;
  readonly #records: SqliteRecordState;
  readonly #queue: SqliteMutationQueue;

  constructor(
    database: DatabaseSync,
    limits: VaultStateLimits,
    records: SqliteRecordState,
    queue: SqliteMutationQueue,
  ) {
    this.#database = database;
    this.#limits = limits;
    this.#records = records;
    this.#queue = queue;
  }

  load(vaultId: VaultId): TemplateMigrationPublicationRequest | null {
    const row = this.#database
      .prepare(
        `SELECT vault_id, batch_key, publication_json, serialized_bytes
           FROM pending_template_migrations WHERE vault_id = ?`,
      )
      .get(vaultId) as PersistedPublicationRow | undefined;
    return row === undefined ? null : parsePublicationRow(row, vaultId);
  }

  assertExactPending(publication: TemplateMigrationPublicationRequest): void {
    const pending = this.load(publication.vaultId);
    if (pending === null || canonicalJson(pending) !== canonicalJson(publication)) {
      throw invalidState();
    }
    const rows = this.#database
      .prepare(
        `SELECT batch_key, position, vault_id, entity_type, entity_id,
                idempotency_key, mutation_json, serialized_bytes
           FROM pending_template_migration_mutations
          WHERE batch_key = ? ORDER BY position ASC`,
      )
      .all(publication.batchIdempotencyKey) as unknown as (PersistedMutationRow & {
      batch_key?: unknown;
      position?: unknown;
    })[];
    if (rows.length !== publication.mutations.length) throw invalidState();
    for (const [index, row] of rows.entries()) {
      const expected = publication.mutations[index];
      if (
        expected === undefined ||
        row.batch_key !== publication.batchIdempotencyKey ||
        getInteger(row, 'position') !== index ||
        typeof row.entity_type !== 'string' ||
        typeof row.entity_id !== 'string'
      ) {
        throw invalidState();
      }
      const mutation = parseMutationRow(
        row,
        publication.vaultId,
        expected.entityType,
        expected.record.id,
      );
      if (canonicalJson(mutation) !== canonicalJson(expected)) throw invalidState();
    }
  }

  assertCanonicalState(): void {
    const rows = this.#database
      .prepare(
        `SELECT vault_id, batch_key, publication_json, serialized_bytes
           FROM pending_template_migrations`,
      )
      .all() as unknown as PersistedPublicationRow[];
    for (const row of rows) {
      if (typeof row.vault_id !== 'string') throw invalidState();
      const publication = parsePublicationRow(row, row.vault_id as VaultId);
      this.assertExactPending(publication);
    }
  }

  enqueue(publicationInput: TemplateMigrationPublicationRequest): void {
    const publication = parsePublication(publicationInput);
    const encoded = encodeBounded(publication, this.#limits.maxPendingBytes);
    const pending = this.#database
      .prepare(
        `SELECT vault_id, batch_key, publication_json, serialized_bytes
           FROM pending_template_migrations
          WHERE vault_id = ? OR batch_key = ?`,
      )
      .all(
        publication.vaultId,
        publication.batchIdempotencyKey,
      ) as unknown as PersistedPublicationRow[];
    if (pending.length > 0) {
      if (
        pending.length === 1 &&
        pending[0]?.vault_id === publication.vaultId &&
        pending[0].batch_key === publication.batchIdempotencyKey &&
        pending[0].publication_json === encoded.json
      ) {
        parsePublicationRow(pending[0], publication.vaultId);
        return;
      }
      throw invalidState();
    }
    const completed = this.#completed(publication.batchIdempotencyKey);
    if (completed !== null) {
      if (completed.publicationJson === encoded.json) return;
      throw invalidState();
    }
    if (
      countRows(this.#database, 'pending_mutations', publication.vaultId) !== 0 ||
      countRows(this.#database, 'active_push_batches', publication.vaultId) !== 0
    ) {
      throw invalidState();
    }
    for (const mutation of publication.mutations) {
      if (this.#queue.findClaim(mutation.idempotencyKey) !== null) throw invalidState();
      this.#records.assertMutationApplies(
        this.#records.effective(
          publication.vaultId,
          mutation.entityType,
          mutation.record.id,
        ),
        mutation,
      );
    }
    this.#database
      .prepare(
        `INSERT INTO pending_template_migrations
           (vault_id, batch_key, publication_json, serialized_bytes,
            replay_from_server_sequence)
         VALUES (?, ?, ?, ?, COALESCE((
           SELECT server_sequence FROM sync_cursors WHERE vault_id = ?
         ), 0))`,
      )
      .run(
        publication.vaultId,
        publication.batchIdempotencyKey,
        encoded.json,
        encoded.bytes,
        publication.vaultId,
      );
    const insert = this.#database.prepare(
      `INSERT INTO pending_template_migration_mutations
         (batch_key, position, vault_id, entity_type, entity_id,
          idempotency_key, mutation_json, serialized_bytes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const [position, mutation] of publication.mutations.entries()) {
      const mutationEncoded = encodeBounded(
        mutation,
        this.#limits.maxSerializedRowBytes,
      );
      insert.run(
        publication.batchIdempotencyKey,
        position,
        publication.vaultId,
        mutation.entityType,
        mutation.record.id,
        mutation.idempotencyKey,
        mutationEncoded.json,
        mutationEncoded.bytes,
      );
    }
    this.#queue.assertBounds();
  }

  complete(input: CompleteTemplateMigrationPublicationInput): void {
    const publication = parsePublication(input.publication);
    const response = parsePublicationResponse(input.response, publication);
    const publicationJson = JSON.stringify(publication);
    const responseJson = JSON.stringify(response);
    const pending = this.load(publication.vaultId);
    if (pending === null) {
      const completed = this.#completed(publication.batchIdempotencyKey);
      if (
        completed?.vaultId === publication.vaultId &&
        completed.publicationJson === publicationJson &&
        completed.responseJson === responseJson
      ) {
        return;
      }
      throw invalidState();
    }
    if (JSON.stringify(pending) !== publicationJson) throw invalidState();
    for (const mutation of publication.mutations) {
      this.#records.promote(mutation);
      this.#queue.recordCompleted(mutation, 'template-migration');
    }
    this.#queue.pruneCompleted(
      publication.mutations.map((mutation) => mutation.idempotencyKey),
    );
    this.#database
      .prepare(`DELETE FROM pending_template_migrations WHERE batch_key = ?`)
      .run(publication.batchIdempotencyKey);
    const totalBytes =
      Buffer.byteLength(publicationJson) + Buffer.byteLength(responseJson);
    if (totalBytes > this.#limits.maxCompletedPublicationBytes) throw invalidState();
    this.#database
      .prepare(
        `INSERT INTO completed_template_migrations
           (vault_id, batch_key, publication_json, response_json, serialized_bytes)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        publication.vaultId,
        publication.batchIdempotencyKey,
        publicationJson,
        responseJson,
        totalBytes,
      );
    this.#prune(publication.batchIdempotencyKey);
    this.assertBounds();
  }

  completeReconciled(input: CompleteTemplateMigrationPublicationInput): void {
    const publication = parsePublication(input.publication);
    const response = parsePublicationResponse(input.response, publication);
    const publicationJson = JSON.stringify(publication);
    const responseJson = JSON.stringify(response);
    this.assertExactPending(publication);
    const totalBytes =
      Buffer.byteLength(publicationJson) + Buffer.byteLength(responseJson);
    if (totalBytes > this.#limits.maxCompletedPublicationBytes) throw invalidState();
    const removed = this.#database
      .prepare(
        `DELETE FROM pending_template_migrations
          WHERE vault_id = ? AND batch_key = ?`,
      )
      .run(publication.vaultId, publication.batchIdempotencyKey);
    if (removed.changes !== 1) throw invalidState();
    this.#database
      .prepare(
        `INSERT INTO completed_template_migrations
           (vault_id, batch_key, publication_json, response_json, serialized_bytes)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        publication.vaultId,
        publication.batchIdempotencyKey,
        publicationJson,
        responseJson,
        totalBytes,
      );
    this.#prune(publication.batchIdempotencyKey);
  }

  assertNoQueueCoexistence(): void {
    const row = this.#database
      .prepare(
        `SELECT COUNT(*) AS value
           FROM pending_template_migrations AS publication
          WHERE EXISTS (
            SELECT 1 FROM pending_mutations AS mutation
             WHERE mutation.vault_id = publication.vault_id
          ) OR EXISTS (
            SELECT 1 FROM active_push_batches AS batch
             WHERE batch.vault_id = publication.vault_id
          )`,
      )
      .get();
    if (getInteger(row, 'value') !== 0) throw invalidState();
  }

  assertBounds(): void {
    const row = this.#database
      .prepare(
        `SELECT COUNT(*) AS row_count,
                COALESCE(SUM(serialized_bytes), 0) AS total_bytes
           FROM completed_template_migrations`,
      )
      .get();
    if (
      getInteger(row, 'row_count') > this.#limits.maxCompletedBatches ||
      getInteger(row, 'total_bytes') > this.#limits.maxCompletedPublicationBytes
    ) {
      throw invalidState();
    }
  }

  #completed(batchKey: string): Readonly<{
    vaultId: VaultId;
    publicationJson: string;
    responseJson: string;
  }> | null {
    const row = this.#database
      .prepare(
        `SELECT vault_id, batch_key, publication_json, response_json,
                serialized_bytes
           FROM completed_template_migrations WHERE batch_key = ?`,
      )
      .get(batchKey) as PersistedCompletionRow | undefined;
    if (row === undefined) return null;
    if (
      typeof row.vault_id !== 'string' ||
      row.batch_key !== batchKey ||
      typeof row.publication_json !== 'string' ||
      typeof row.response_json !== 'string' ||
      getInteger(row, 'serialized_bytes') !==
        Buffer.byteLength(row.publication_json) + Buffer.byteLength(row.response_json)
    ) {
      throw invalidState();
    }
    const publication = parsePublication(parseJson(row.publication_json));
    const response = parsePublicationResponse(
      parseJson(row.response_json),
      publication,
    );
    if (
      publication.vaultId !== row.vault_id ||
      publication.batchIdempotencyKey !== batchKey ||
      JSON.stringify(publication) !== row.publication_json ||
      JSON.stringify(response) !== row.response_json
    ) {
      throw invalidState();
    }
    return {
      vaultId: publication.vaultId,
      publicationJson: row.publication_json,
      responseJson: row.response_json,
    };
  }

  #prune(currentBatchKey: string): void {
    for (;;) {
      const row = this.#database
        .prepare(
          `SELECT COUNT(*) AS row_count,
                  COALESCE(SUM(serialized_bytes), 0) AS total_bytes
             FROM completed_template_migrations`,
        )
        .get();
      if (
        getInteger(row, 'row_count') <= this.#limits.maxCompletedBatches &&
        getInteger(row, 'total_bytes') <= this.#limits.maxCompletedPublicationBytes
      ) {
        return;
      }
      const changed = this.#database
        .prepare(
          `DELETE FROM completed_template_migrations
            WHERE sequence = (
              SELECT completion.sequence
                FROM completed_template_migrations AS completion
               WHERE completion.batch_key <> ? AND NOT EXISTS (
                 SELECT 1 FROM outbound_observation_pins AS pin
                  WHERE pin.state = 'pinned'
                    AND pin.kind = 'template-publication'
                    AND pin.observation_id = (
                      SELECT receipt.observation_id
                        FROM completed_outbound_observations AS receipt
                       WHERE receipt.kind = 'template-publication'
                         AND receipt.batch_key = completion.batch_key
                    )
               )
               ORDER BY completion.sequence ASC LIMIT 1
            )`,
        )
        .run(currentBatchKey);
      if (changed.changes !== 1) throw invalidState();
    }
  }
}
