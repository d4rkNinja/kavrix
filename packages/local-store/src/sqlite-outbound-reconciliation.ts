import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import {
  canonicalJson,
  deviceIdSchema,
  outboundObservationSchema,
  sha256DigestSchema,
  syncCursorSchema,
  syncPulledChangeSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  vaultIdSchema,
  type OpaqueMutation,
  type OutboundObservation,
  type Sha256Digest,
  type SyncPulledChange,
  type VaultId,
} from '@kavrix/schemas';
import {
  createOutboundObservation,
  measureOutboundReconciliationChanges,
  type CompletedOutboundObservation,
  type EnsureOutboundReplayStartInput,
  type OutboundReplayState,
  type ReconcileOutboundObservationInput,
  type SyncCursor,
} from '@kavrix/sync';

import {
  assertBatchPending,
  parseBatchRow,
  parseCursorRow,
  parseMutationRow,
  validateCursorAdvance,
  type BatchRow,
  type CursorRow,
  type MutationRow,
} from './sqlite-local-codecs.js';
import { invalidState } from './sqlite-local-errors.js';
import {
  SqliteOutboundPins,
  type OutboundObservationPin,
} from './sqlite-outbound-pins.js';
import type { SqliteVaultState } from './sqlite-vault-state.js';
import {
  getInteger,
  parseMutationInput,
  parsePublicationRow,
} from './sqlite-vault-codecs.js';
import type {
  PersistedOutboundObservationRow,
  PersistedPublicationRow,
  VaultStateLimits,
} from './sqlite-vault-schema.js';
import { SqliteSyncConflicts } from './sqlite-conflicts.js';

type ParsedReconciliation = ReconcileOutboundObservationInput &
  Readonly<{
    stagedChanges: readonly SyncPulledChange[];
    finalCursor: SyncCursor;
    receiptBytes: number;
    requestJson: string;
    responseJson: string;
    finalCursorJson: string;
  }>;

export class SqliteOutboundReconciliation {
  readonly #database: DatabaseSync;
  readonly #limits: VaultStateLimits;
  readonly #vaultState: SqliteVaultState;
  readonly #conflicts: SqliteSyncConflicts;
  readonly #pins: SqliteOutboundPins;

  constructor(
    database: DatabaseSync,
    limits: VaultStateLimits,
    vaultState: SqliteVaultState,
    conflicts?: SqliteSyncConflicts,
  ) {
    this.#database = database;
    this.#limits = limits;
    this.#vaultState = vaultState;
    this.#conflicts =
      conflicts ?? new SqliteSyncConflicts(database, limits, vaultState);
    this.#pins = new SqliteOutboundPins(database, limits);
  }

  loadReplayState(
    vaultIdInput: VaultId,
    kind: OutboundReplayState['kind'],
  ): OutboundReplayState | null {
    const vaultId = parseVaultId(vaultIdInput);
    if (kind === 'generic-push') {
      const row = this.#database
        .prepare(
          `SELECT vault_id, batch_key, batch_json, serialized_bytes,
                  replay_from_server_sequence
             FROM active_push_batches WHERE vault_id = ?`,
        )
        .get(vaultId) as
        (BatchRow & { replay_from_server_sequence: unknown }) | undefined;
      if (row === undefined) return null;
      const batch = parseBatchRow(row, vaultId);
      assertBatchPending(this.#database, batch);
      return {
        kind,
        vaultId,
        batchIdempotencyKey: batch.batchIdempotencyKey,
        replayFromServerSequence: parseNullableSequence(
          row.replay_from_server_sequence,
        ),
      };
    }
    const untrustedKind: unknown = kind;
    if (untrustedKind !== 'template-publication') throw invalidState();
    const row = this.#database
      .prepare(
        `SELECT vault_id, batch_key, publication_json, serialized_bytes,
                replay_from_server_sequence
           FROM pending_template_migrations WHERE vault_id = ?`,
      )
      .get(vaultId) as PersistedPublicationRow | undefined;
    if (row === undefined) return null;
    const publication = parsePublicationRow(row, vaultId);
    return {
      kind,
      vaultId,
      batchIdempotencyKey: publication.batchIdempotencyKey,
      replayFromServerSequence: parseNullableSequence(row.replay_from_server_sequence),
    };
  }

  ensureReplayStart(input: EnsureOutboundReplayStartInput): number {
    if (!hasExactKeys(input, ['kind', 'vaultId', 'batchIdempotencyKey'])) {
      throw invalidState();
    }
    const vaultId = parseVaultId(input.vaultId);
    const current = this.loadReplayState(vaultId, input.kind);
    if (current?.batchIdempotencyKey !== input.batchIdempotencyKey) {
      throw invalidState();
    }
    if (current.replayFromServerSequence !== null) {
      return current.replayFromServerSequence;
    }
    const replayFromServerSequence = this.#currentCursor(vaultId).cursor.serverSequence;
    const table =
      input.kind === 'generic-push'
        ? 'active_push_batches'
        : 'pending_template_migrations';
    const changed = this.#database
      .prepare(
        `UPDATE ${table}
            SET replay_from_server_sequence = ?
          WHERE vault_id = ? AND batch_key = ?
            AND replay_from_server_sequence IS NULL`,
      )
      .run(replayFromServerSequence, vaultId, input.batchIdempotencyKey);
    if (changed.changes !== 1) throw invalidState();
    return replayFromServerSequence;
  }

  loadCompleted(
    vaultIdInput: VaultId,
    observationIdInput: Sha256Digest,
  ): CompletedOutboundObservation | null {
    const vaultId = parseVaultId(vaultIdInput);
    const observationId = sha256DigestSchema.safeParse(observationIdInput);
    if (!observationId.success) throw invalidState();
    const row = this.#database
      .prepare(
        `SELECT sequence, vault_id, device_id, kind, batch_key, observation_id,
                request_hash, response_hash, response_vault_revision,
                replay_from_server_sequence, required_through_server_sequence,
                request_json, response_json, final_cursor_json, serialized_bytes
           FROM completed_outbound_observations
          WHERE observation_id = ?`,
      )
      .get(observationId.data) as PersistedOutboundObservationRow | undefined;
    return row === undefined ? null : parseReceiptRow(row, vaultId);
  }

  confirmCompleted(
    vaultId: VaultId,
    deviceId: ReconcileOutboundObservationInput['deviceId'],
    observation: OutboundObservation,
  ): CompletedOutboundObservation {
    const parsedObservation = outboundObservationSchema.safeParse(observation);
    const parsedDeviceId = deviceIdSchema.safeParse(deviceId);
    if (!parsedObservation.success || !parsedDeviceId.success) throw invalidState();
    const receipt = this.loadCompleted(vaultId, parsedObservation.data.observationId);
    if (
      receipt?.deviceId !== parsedDeviceId.data ||
      canonicalJson(receipt.observation) !== canonicalJson(parsedObservation.data)
    ) {
      throw invalidState();
    }
    this.#pins.requirePinned(
      receipt.vaultId,
      receipt.deviceId,
      receipt.observation,
      acceptedKeysFor(receipt),
    );
    return receipt;
  }

  releaseCompleted(
    vaultIdInput: VaultId,
    deviceId: ReconcileOutboundObservationInput['deviceId'],
    observationId: Sha256Digest,
  ): void {
    const vaultId = parseVaultId(vaultIdInput);
    const receipt = this.loadCompleted(vaultId, observationId);
    const pin = this.#pins.load(vaultId);
    if (pin?.deviceId !== deviceId || pin.observationId !== observationId) {
      throw invalidState();
    }
    if (pin.state === 'pinned') {
      if (
        receipt?.deviceId !== deviceId ||
        receipt.observation.observationId !== observationId ||
        receipt.kind !== pin.kind ||
        canonicalJson(acceptedKeysFor(receipt)) !== canonicalJson(pin.acceptedKeys)
      ) {
        throw invalidState();
      }
    }
    this.#pins.release(vaultId, deviceId, observationId);
  }

  reconcile(input: ReconcileOutboundObservationInput): CompletedOutboundObservation {
    const parsed = parseReconciliation(input);
    if (parsed.receiptBytes > this.#limits.maxSerializedRowBytes) {
      throw invalidState();
    }
    const existing = this.loadCompleted(
      parsed.vaultId,
      parsed.observation.observationId,
    );
    if (existing !== null) {
      if (!sameReceiptInput(existing, parsed)) throw invalidState();
      this.#pins.requirePinned(
        existing.vaultId,
        existing.deviceId,
        existing.observation,
        acceptedKeysFor(existing),
      );
      return existing;
    }

    const currentCursor = this.#currentCursor(parsed.vaultId);
    if (
      currentCursor.cursor.serverSequence !==
        parsed.observation.replayFromServerSequence ||
      parsed.finalCursor.highestSeenVaultRevision <
        currentCursor.cursor.highestSeenVaultRevision
    ) {
      throw invalidState();
    }
    const page = reconciliationPage(parsed);
    validateCursorAdvance(currentCursor.persisted, page);

    this.#assertExpectedFeed(parsed);
    this.#assertExactDurableRequest(parsed);
    const pageRevisions = new Map<string, number>();
    for (const pulled of parsed.stagedChanges) {
      const identity = `${pulled.change.entityType}:${pulled.change.entityId}`;
      const previousRevision = pageRevisions.get(identity);
      if (
        previousRevision !== undefined &&
        pulled.change.recordRevision <= previousRevision
      ) {
        throw invalidState();
      }
      pageRevisions.set(identity, pulled.change.recordRevision);
      this.#vaultState.applyPulledChange(pulled, parsed.vaultId);
    }
    const acceptedMutations = this.#finalizeOutbound(parsed);
    this.#storeCursor(parsed.vaultId, page);
    this.#insertReceipt(parsed);
    this.#pins.pin(
      parsed.vaultId,
      parsed.deviceId,
      parsed.observation,
      acceptedMutations.map((mutation) => mutation.idempotencyKey),
    );
    this.#vaultState.pruneCompletedMutationReceipts([]);
    this.#pruneReceipts(parsed.kind);
    this.#vaultState.assertBounds();
    return this.confirmCompleted(parsed.vaultId, parsed.deviceId, parsed.observation);
  }

  assertBounds(): void {
    for (const kind of ['generic-push', 'template-publication'] as const) {
      const bounds = this.#receiptBounds(kind);
      const maxBytes =
        kind === 'generic-push'
          ? this.#limits.maxCompletedPushBatchBytes
          : this.#limits.maxCompletedPublicationBytes;
      if (bounds.rows > this.#limits.maxCompletedBatches || bounds.bytes > maxBytes) {
        throw invalidState();
      }
    }
    this.#pins.assertBounds();
  }

  assertCanonicalRows(): void {
    const rows = this.#database
      .prepare(
        `SELECT sequence, vault_id, device_id, kind, batch_key, observation_id,
                request_hash, response_hash, response_vault_revision,
                replay_from_server_sequence, required_through_server_sequence,
                request_json, response_json, final_cursor_json, serialized_bytes
           FROM completed_outbound_observations ORDER BY sequence ASC`,
      )
      .all() as unknown as PersistedOutboundObservationRow[];
    for (const row of rows) {
      if (!Number.isSafeInteger(row.sequence) || (row.sequence as number) < 1) {
        throw invalidState();
      }
      parseReceiptRow(row, parseVaultId(row.vault_id));
    }
    this.#pins.assertCanonicalRows();
    for (const pin of this.#pinnedRows()) {
      const receipt = this.loadCompleted(pin.vaultId, pin.observationId);
      if (
        receipt?.deviceId !== pin.deviceId ||
        receipt.kind !== pin.kind ||
        canonicalJson(acceptedKeysFor(receipt)) !== canonicalJson(pin.acceptedKeys)
      ) {
        throw invalidState();
      }
      const expectedMutations = new Map(
        acceptedMutationsFor(receipt).map((mutation) => [
          mutation.idempotencyKey,
          mutation,
        ]),
      );
      for (const key of pin.acceptedKeys) {
        const row = this.#database
          .prepare(
            `SELECT vault_id, queue_kind, mutation_json, serialized_bytes
               FROM completed_mutation_receipts
              WHERE idempotency_key = ?`,
          )
          .get(key) as
          | {
              vault_id?: unknown;
              queue_kind?: unknown;
              mutation_json?: unknown;
              serialized_bytes?: unknown;
            }
          | undefined;
        const expected = expectedMutations.get(key);
        const expectedQueueKind =
          receipt.kind === 'generic-push' ? 'generic' : 'template-migration';
        if (
          row?.vault_id !== pin.vaultId ||
          row.queue_kind !== expectedQueueKind ||
          typeof row.mutation_json !== 'string' ||
          expected === undefined ||
          getInteger(row, 'serialized_bytes') !== Buffer.byteLength(row.mutation_json)
        ) {
          throw invalidState();
        }
        const mutation = parseMutationInput(parseJson(row.mutation_json));
        if (
          JSON.stringify(mutation) !== row.mutation_json ||
          canonicalJson(mutation) !== canonicalJson(expected)
        ) {
          throw invalidState();
        }
      }
    }
    const genericVaults = this.#database
      .prepare(`SELECT vault_id FROM active_push_batches`)
      .all() as unknown as { vault_id?: unknown }[];
    for (const row of genericVaults) {
      this.loadReplayState(parseVaultId(row.vault_id), 'generic-push');
    }
    const publicationVaults = this.#database
      .prepare(`SELECT vault_id FROM pending_template_migrations`)
      .all() as unknown as { vault_id?: unknown }[];
    for (const row of publicationVaults) {
      this.loadReplayState(parseVaultId(row.vault_id), 'template-publication');
    }
    this.assertBounds();
  }

  #assertExpectedFeed(parsed: ParsedReconciliation): void {
    const replayFrom = parsed.observation.replayFromServerSequence;
    const requiredThrough = parsed.observation.requiredThroughServerSequence;
    if (
      parsed.finalCursor.serverSequence !== requiredThrough ||
      parsed.finalCursor.highestSeenVaultRevision <
        parsed.observation.responseVaultRevision ||
      parsed.stagedChanges.length !== requiredThrough - replayFrom
    ) {
      throw invalidState();
    }
    let expectedSequence = replayFrom + 1;
    for (const pulled of parsed.stagedChanges) {
      if (pulled.change.serverSequence !== expectedSequence) throw invalidState();
      expectedSequence += 1;
    }

    const results = parsed.response.results;
    const mutations = parsed.request.mutations;
    for (const [index, result] of results.entries()) {
      if ('status' in result && result.status === 'conflict') continue;
      const mutation = mutations[index];
      if (mutation === undefined) throw invalidState();
      const sequence = result.change.serverSequence;
      if (sequence <= replayFrom) continue;
      const pulled = parsed.stagedChanges[sequence - replayFrom - 1];
      if (
        pulled === undefined ||
        canonicalJson(pulled.change) !== canonicalJson(result.change)
      ) {
        throw invalidState();
      }
      if (
        (result.change.operation === 'upsert' ||
          result.change.operation === 'restore') &&
        (pulled.record === null ||
          canonicalJson(pulled.record) !== canonicalJson(mutation.record))
      ) {
        throw invalidState();
      }
    }
  }

  #assertExactDurableRequest(parsed: ParsedReconciliation): void {
    if (parsed.kind === 'generic-push') {
      const replay = this.loadReplayState(parsed.vaultId, parsed.kind);
      if (
        replay?.batchIdempotencyKey !== parsed.request.batchIdempotencyKey ||
        replay.replayFromServerSequence !== parsed.observation.replayFromServerSequence
      ) {
        throw invalidState();
      }
      const active = this.#database
        .prepare(
          `SELECT vault_id, batch_key, batch_json, serialized_bytes
             FROM active_push_batches WHERE vault_id = ?`,
        )
        .get(parsed.vaultId) as BatchRow | undefined;
      if (active === undefined) throw invalidState();
      const batch = parseBatchRow(active, parsed.vaultId);
      if (
        canonicalJson(batch.mutationIdempotencyKeys) !==
        canonicalJson(
          parsed.request.mutations.map((mutation) => mutation.idempotencyKey),
        )
      ) {
        throw invalidState();
      }
      const lookup = this.#database.prepare(
        `SELECT vault_id, entity_type, entity_id, idempotency_key,
                mutation_json, serialized_bytes
           FROM pending_mutations WHERE idempotency_key = ?`,
      );
      for (const mutation of parsed.request.mutations) {
        const row = lookup.get(mutation.idempotencyKey) as MutationRow | undefined;
        if (
          row === undefined ||
          canonicalJson(parseMutationRow(row, parsed.vaultId)) !==
            canonicalJson(mutation)
        ) {
          throw invalidState();
        }
      }
      return;
    }
    const replay = this.loadReplayState(parsed.vaultId, parsed.kind);
    if (
      replay?.batchIdempotencyKey !== parsed.request.batchIdempotencyKey ||
      replay.replayFromServerSequence !== parsed.observation.replayFromServerSequence
    ) {
      throw invalidState();
    }
    this.#vaultState.assertExactPendingPublication(parsed.request);
  }

  #finalizeOutbound(parsed: ParsedReconciliation): readonly OpaqueMutation[] {
    const accepted: OpaqueMutation[] = [];
    if (parsed.kind === 'generic-push') {
      const deletePending = this.#database.prepare(
        `DELETE FROM pending_mutations
          WHERE vault_id = ? AND idempotency_key = ?`,
      );
      const deletePredecessor = this.#database.prepare(
        `DELETE FROM deletion_predecessors WHERE owner_key = ?`,
      );
      for (const [index, result] of parsed.response.results.entries()) {
        const mutation = parsed.request.mutations[index];
        if (mutation === undefined) throw invalidState();
        if (result.status === 'conflict') {
          this.#conflicts.record(
            parsed.vaultId,
            mutation,
            result.currentRevision,
            result.current,
          );
          continue;
        }
        this.#vaultState.recordCompletedMutation(mutation, 'generic');
        if (deletePending.run(parsed.vaultId, mutation.idempotencyKey).changes !== 1) {
          throw invalidState();
        }
        deletePredecessor.run(mutation.idempotencyKey);
        accepted.push(mutation);
      }
      const removed = this.#database
        .prepare(
          `DELETE FROM active_push_batches
            WHERE vault_id = ? AND batch_key = ?`,
        )
        .run(parsed.vaultId, parsed.request.batchIdempotencyKey);
      if (removed.changes !== 1) throw invalidState();
      return accepted;
    }
    for (const mutation of parsed.request.mutations) {
      this.#vaultState.recordCompletedMutation(mutation, 'template-migration');
      accepted.push(mutation);
    }
    this.#vaultState.completeReconciledPublication({
      publication: parsed.request,
      response: parsed.response,
    });
    return accepted;
  }

  #storeCursor(vaultId: VaultId, page: ReturnType<typeof reconciliationPage>): void {
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
        vaultId,
        page.cursor.serverSequence,
        page.cursor.highestSeenVaultRevision,
        page.cursorJson,
        page.pageHash,
      );
    const count = this.#database
      .prepare(`SELECT COUNT(*) AS value FROM sync_cursors`)
      .get();
    if (getInteger(count, 'value') > this.#limits.maxVaults) throw invalidState();
  }

  #insertReceipt(parsed: ParsedReconciliation): void {
    this.#database
      .prepare(
        `INSERT INTO completed_outbound_observations
           (vault_id, device_id, kind, batch_key, observation_id, request_hash,
            response_hash, response_vault_revision, replay_from_server_sequence,
            required_through_server_sequence, request_json, response_json,
            final_cursor_json, serialized_bytes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        parsed.vaultId,
        parsed.deviceId,
        parsed.kind,
        parsed.observation.batchIdempotencyKey,
        parsed.observation.observationId,
        parsed.observation.requestHash,
        parsed.observation.responseHash,
        parsed.observation.responseVaultRevision,
        parsed.observation.replayFromServerSequence,
        parsed.observation.requiredThroughServerSequence,
        parsed.requestJson,
        parsed.responseJson,
        parsed.finalCursorJson,
        parsed.receiptBytes,
      );
  }

  #pruneReceipts(kind: CompletedOutboundObservation['kind']): void {
    const maxBytes =
      kind === 'generic-push'
        ? this.#limits.maxCompletedPushBatchBytes
        : this.#limits.maxCompletedPublicationBytes;
    for (;;) {
      const bounds = this.#receiptBounds(kind);
      if (bounds.rows <= this.#limits.maxCompletedBatches && bounds.bytes <= maxBytes) {
        return;
      }
      const changed = this.#database
        .prepare(
          `DELETE FROM completed_outbound_observations
            WHERE sequence = (
              SELECT receipt.sequence FROM completed_outbound_observations AS receipt
               WHERE receipt.kind = ? AND NOT EXISTS (
                 SELECT 1 FROM outbound_observation_pins AS pin
                  WHERE pin.state = 'pinned'
                    AND pin.observation_id = receipt.observation_id
               )
               ORDER BY sequence ASC LIMIT 1
            )`,
        )
        .run(kind);
      if (changed.changes !== 1) throw invalidState();
    }
  }

  #receiptBounds(
    kind: CompletedOutboundObservation['kind'],
  ): Readonly<{ rows: number; bytes: number }> {
    const row = this.#database
      .prepare(
        `SELECT COUNT(*) AS row_count,
                COALESCE(SUM(serialized_bytes), 0) AS total_bytes
           FROM completed_outbound_observations WHERE kind = ?`,
      )
      .get(kind);
    return {
      rows: getInteger(row, 'row_count'),
      bytes: getInteger(row, 'total_bytes'),
    };
  }

  #pinnedRows(): readonly OutboundObservationPin[] {
    const rows = this.#database
      .prepare(
        `SELECT vault_id FROM outbound_observation_pins
          WHERE state = 'pinned' ORDER BY vault_id ASC`,
      )
      .all() as unknown as { vault_id?: unknown }[];
    return rows.map((row) => {
      const pin = this.#pins.load(parseVaultId(row.vault_id));
      if (pin?.state !== 'pinned') throw invalidState();
      return pin;
    });
  }

  #currentCursor(vaultId: VaultId): Readonly<{
    cursor: SyncCursor;
    persisted: ReturnType<typeof parseCursorRow> | null;
  }> {
    const row = this.#database
      .prepare(
        `SELECT vault_id, server_sequence, highest_revision, cursor_json,
                last_page_hash
           FROM sync_cursors WHERE vault_id = ?`,
      )
      .get(vaultId) as CursorRow | undefined;
    if (row === undefined) {
      return {
        cursor: syncCursorSchema.parse({
          vaultId,
          serverSequence: 0,
          highestSeenVaultRevision: 0,
        }),
        persisted: null,
      };
    }
    const persisted = parseCursorRow(row, vaultId);
    return { cursor: persisted.cursor, persisted };
  }
}

function parseReconciliation(
  input: ReconcileOutboundObservationInput,
): ParsedReconciliation {
  if (
    !hasExactKeys(input, [
      'kind',
      'vaultId',
      'deviceId',
      'observation',
      'request',
      'response',
      'stagedChanges',
      'stagedChangesBytes',
      'finalCursor',
    ])
  ) {
    throw invalidState();
  }
  const vaultId = vaultIdSchema.safeParse(input.vaultId);
  const deviceId = deviceIdSchema.safeParse(input.deviceId);
  const observation = outboundObservationSchema.safeParse(input.observation);
  const finalCursor = syncCursorSchema.safeParse(input.finalCursor);
  if (
    !vaultId.success ||
    !deviceId.success ||
    !observation.success ||
    !finalCursor.success ||
    finalCursor.data.vaultId !== vaultId.data ||
    observation.data.kind !== input.kind
  ) {
    throw invalidState();
  }
  const request =
    input.kind === 'generic-push'
      ? syncPushRequestSchema.safeParse(input.request)
      : templateMigrationPublicationRequestSchema.safeParse(input.request);
  const response =
    input.kind === 'generic-push'
      ? syncPushResponseSchema.safeParse(input.response)
      : templateMigrationPublicationResponseSchema.safeParse(input.response);
  if (!request.success || !response.success) throw invalidState();
  const recreated = createOutboundObservation({
    kind: input.kind,
    vaultId: vaultId.data,
    deviceId: deviceId.data,
    request: request.data,
    response: response.data,
    replayFromServerSequence: observation.data.replayFromServerSequence,
  });
  if (canonicalJson(recreated) !== canonicalJson(observation.data)) {
    throw invalidState();
  }
  if (!Array.isArray(input.stagedChanges)) throw invalidState();
  const stagedChanges = input.stagedChanges.map((value) => {
    const parsed = syncPulledChangeSchema.safeParse(value);
    if (!parsed.success || parsed.data.change.vaultId !== vaultId.data) {
      throw invalidState();
    }
    return parsed.data;
  });
  let stagedChangesBytes: number;
  try {
    stagedChangesBytes = measureOutboundReconciliationChanges(stagedChanges);
  } catch {
    throw invalidState();
  }
  if (
    !Number.isSafeInteger(input.stagedChangesBytes) ||
    input.stagedChangesBytes !== stagedChangesBytes
  ) {
    throw invalidState();
  }
  const requestJson = canonicalJson(request.data);
  const responseJson = canonicalJson(response.data);
  const finalCursorJson = canonicalJson(finalCursor.data);
  const receiptBytes = receiptSerializedBytes({
    kind: input.kind,
    vaultId: vaultId.data,
    deviceId: deviceId.data,
    observation: observation.data,
    request: request.data,
    response: response.data,
    finalCursor: finalCursor.data,
  });
  return {
    kind: input.kind,
    vaultId: vaultId.data,
    deviceId: deviceId.data,
    observation: observation.data,
    request: request.data,
    response: response.data,
    stagedChanges,
    stagedChangesBytes,
    finalCursor: finalCursor.data,
    receiptBytes,
    requestJson,
    responseJson,
    finalCursorJson,
  } as ParsedReconciliation;
}

function reconciliationPage(parsed: ParsedReconciliation): Readonly<{
  cursor: SyncCursor;
  changes: readonly SyncPulledChange[];
  cursorJson: string;
  pageHash: string;
}> {
  const cursorJson = JSON.stringify(parsed.finalCursor);
  const pageJson = JSON.stringify({
    vaultId: parsed.vaultId,
    changes: parsed.stagedChanges,
    cursor: parsed.finalCursor,
  });
  const digest = createHash('sha256').update(pageJson, 'utf8').digest();
  try {
    return {
      cursor: parsed.finalCursor,
      changes: parsed.stagedChanges,
      cursorJson,
      pageHash: digest.toString('base64url'),
    };
  } finally {
    digest.fill(0);
  }
}

function parseReceiptRow(
  row: PersistedOutboundObservationRow,
  expectedVaultId: VaultId,
): CompletedOutboundObservation {
  const deviceId = deviceIdSchema.safeParse(row.device_id);
  const observationId = sha256DigestSchema.safeParse(row.observation_id);
  if (
    row.vault_id !== expectedVaultId ||
    !deviceId.success ||
    !observationId.success ||
    (row.kind !== 'generic-push' && row.kind !== 'template-publication') ||
    typeof row.request_json !== 'string' ||
    typeof row.response_json !== 'string' ||
    typeof row.final_cursor_json !== 'string'
  ) {
    throw invalidState();
  }
  const requestValue = parseJson(row.request_json);
  const responseValue = parseJson(row.response_json);
  const cursor = syncCursorSchema.safeParse(parseJson(row.final_cursor_json));
  const request =
    row.kind === 'generic-push'
      ? syncPushRequestSchema.safeParse(requestValue)
      : templateMigrationPublicationRequestSchema.safeParse(requestValue);
  const response =
    row.kind === 'generic-push'
      ? syncPushResponseSchema.safeParse(responseValue)
      : templateMigrationPublicationResponseSchema.safeParse(responseValue);
  if (
    !request.success ||
    !response.success ||
    !cursor.success ||
    request.data.vaultId !== expectedVaultId ||
    request.data.batchIdempotencyKey !== row.batch_key ||
    cursor.data.vaultId !== expectedVaultId ||
    canonicalJson(request.data) !== row.request_json ||
    canonicalJson(response.data) !== row.response_json ||
    canonicalJson(cursor.data) !== row.final_cursor_json
  ) {
    throw invalidState();
  }
  const observation = createOutboundObservation({
    kind: row.kind,
    vaultId: expectedVaultId,
    deviceId: deviceId.data,
    request: request.data,
    response: response.data,
    replayFromServerSequence: getInteger(row, 'replay_from_server_sequence'),
  });
  if (
    observation.observationId !== observationId.data ||
    observation.requestHash !== row.request_hash ||
    observation.responseHash !== row.response_hash ||
    observation.responseVaultRevision !== getInteger(row, 'response_vault_revision') ||
    observation.requiredThroughServerSequence !==
      getInteger(row, 'required_through_server_sequence') ||
    cursor.data.serverSequence !== observation.requiredThroughServerSequence
  ) {
    throw invalidState();
  }
  const serializedBytes = receiptSerializedBytes({
    kind: row.kind,
    vaultId: expectedVaultId,
    deviceId: deviceId.data,
    observation,
    request: request.data,
    response: response.data,
    finalCursor: cursor.data,
  });
  if (getInteger(row, 'serialized_bytes') !== serializedBytes) throw invalidState();
  return {
    kind: row.kind,
    vaultId: expectedVaultId,
    deviceId: deviceId.data,
    observation,
    request: request.data,
    response: response.data,
    finalCursor: cursor.data,
    serializedBytes,
  } as CompletedOutboundObservation;
}

function receiptSerializedBytes(
  receipt: Omit<CompletedOutboundObservation, 'serializedBytes'>,
): number {
  return Buffer.byteLength(canonicalJson(receipt));
}

function acceptedKeysFor(
  receipt: CompletedOutboundObservation | ParsedReconciliation,
): readonly string[] {
  return acceptedMutationsFor(receipt).map((mutation) => mutation.idempotencyKey);
}

function acceptedMutationsFor(
  receipt: CompletedOutboundObservation | ParsedReconciliation,
): readonly OpaqueMutation[] {
  if (receipt.kind === 'template-publication') {
    return receipt.request.mutations;
  }
  const accepted: OpaqueMutation[] = [];
  for (const [index, result] of receipt.response.results.entries()) {
    if (result.status !== 'accepted') continue;
    const mutation = receipt.request.mutations[index];
    if (mutation === undefined) throw invalidState();
    accepted.push(mutation);
  }
  return accepted;
}

function sameReceiptInput(
  receipt: CompletedOutboundObservation,
  input: ParsedReconciliation,
): boolean {
  return (
    receipt.kind === input.kind &&
    receipt.vaultId === input.vaultId &&
    receipt.deviceId === input.deviceId &&
    canonicalJson(receipt.observation) === canonicalJson(input.observation) &&
    canonicalJson(receipt.request) === canonicalJson(input.request) &&
    canonicalJson(receipt.response) === canonicalJson(input.response) &&
    canonicalJson(receipt.finalCursor) === canonicalJson(input.finalCursor)
  );
}

function parseNullableSequence(value: unknown): number | null {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw invalidState();
  return value as number;
}

function parseVaultId(value: unknown): VaultId {
  const parsed = vaultIdSchema.safeParse(value);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw invalidState();
  }
}

function hasExactKeys(value: unknown, keys: readonly string[]): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.length && actual.every((key) => keys.includes(key));
}
