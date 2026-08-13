import type { DatabaseSync } from 'node:sqlite';

import {
  canonicalJson,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  opaqueMutationSchema,
  opaqueSyncRecordSchema,
  recordRevisionSchema,
  timestampSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type VaultId,
} from '@kavrix/schemas';
import type {
  ResolveSyncConflictInput,
  ResolveSyncConflictResult,
  SyncConflictMetadata,
  SyncConflictResolutionStrategy,
} from '@kavrix/sync';

import {
  conflictResolutionSchema,
  resolutionFromInput,
  type ConflictResolution,
  type PersistedConflictRow,
} from './sqlite-conflict-schema.js';
import { parseMutationRow } from './sqlite-local-codecs.js';
import {
  encodeBounded,
  getInteger,
  invalidState,
  mutationVaultId,
  parseJson,
  parseMutationInput,
  recordEntityType,
  recordIdentity,
  recordVaultId,
  syncRecordRevision,
} from './sqlite-vault-codecs.js';
import type { CurrentState, VaultStateLimits } from './sqlite-vault-schema.js';
import type { SqliteVaultState } from './sqlite-vault-state.js';

const MIN_IDEMPOTENCY_KEY_LENGTH = 16;
const MAX_IDEMPOTENCY_KEY_LENGTH = 256;

type ParsedConflict = Readonly<{
  sequence: number;
  vaultId: VaultId;
  mutation: OpaqueMutation;
  currentRevision: number;
  current: OpaqueSyncRecord | null;
  resolution: ConflictResolution | null;
  serializedBytes: number;
}>;

export class SqliteSyncConflicts {
  readonly #database: DatabaseSync;
  readonly #limits: VaultStateLimits;
  readonly #vaultState: SqliteVaultState;

  constructor(
    database: DatabaseSync,
    limits: VaultStateLimits,
    vaultState: SqliteVaultState,
  ) {
    this.#database = database;
    this.#limits = limits;
    this.#vaultState = vaultState;
  }

  record(
    vaultIdInput: VaultId,
    mutationInput: OpaqueMutation,
    currentRevisionInput: number,
    currentInput: OpaqueSyncRecord | null,
  ): void {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const mutation = parseMutationInput(mutationInput);
    const currentRevision = recordRevisionSchema.parse(currentRevisionInput);
    const current =
      currentInput === null ? null : opaqueSyncRecordSchema.parse(currentInput);
    assertConflictBinding(vaultId, mutation, currentRevision, current);

    const mutationJson = encodeBounded(
      mutation,
      this.#limits.maxSerializedRowBytes,
    ).json;
    const currentJson =
      current === null
        ? null
        : encodeBounded(current, this.#limits.maxSerializedRowBytes).json;
    const existing = this.#loadRow(vaultId, mutation.idempotencyKey);
    if (existing !== undefined) {
      const parsed = parseConflictRow(existing, vaultId);
      if (
        parsed.resolution !== null ||
        canonicalJson(parsed.mutation) !== canonicalJson(mutation)
      ) {
        throw invalidState();
      }
      this.#updateConflict(
        vaultId,
        mutation.idempotencyKey,
        mutationJson,
        currentRevision,
        currentJson,
        null,
      );
    } else {
      this.#database
        .prepare(
          `INSERT INTO sync_conflicts
             (vault_id, entity_type, entity_id, idempotency_key, mutation_json,
              current_revision, current_json, resolution_json, serialized_bytes)
           VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
        )
        .run(
          vaultId,
          mutation.entityType,
          mutation.record.id,
          mutation.idempotencyKey,
          mutationJson,
          currentRevision,
          currentJson,
          conflictBytes(mutationJson, currentJson, null),
        );
    }
    this.assertBounds();
  }

  list(vaultIdInput: VaultId): readonly SyncConflictMetadata[] {
    const vaultId = vaultIdSchema.parse(vaultIdInput);
    const rows = this.#database
      .prepare(
        `SELECT sequence, vault_id, entity_type, entity_id, idempotency_key,
                mutation_json, current_revision, current_json, resolution_json,
                serialized_bytes
           FROM sync_conflicts
          WHERE vault_id = ? AND resolution_json IS NULL
          ORDER BY sequence ASC`,
      )
      .all(vaultId) as unknown as PersistedConflictRow[];
    if (rows.length > this.#limits.maxCompletedMutations) throw invalidState();
    return rows.map((row) => {
      const parsed = parseConflictRow(row, vaultId);
      if (parsed.resolution !== null) throw invalidState();
      return {
        vaultId,
        entityType: parsed.mutation.entityType,
        entityId: parsed.mutation.record.id,
        idempotencyKey: parsed.mutation.idempotencyKey,
        expectedRevision:
          parsed.mutation.entityType === 'vault'
            ? parsed.mutation.expectedVaultRevision
            : parsed.mutation.expectedRecordRevision,
        currentRevision: recordRevisionSchema.parse(parsed.currentRevision),
        currentState:
          parsed.current === null
            ? ('missing' as const)
            : 'state' in parsed.current
              ? ('deleted' as const)
              : ('present' as const),
      };
    });
  }

  resolve(input: ResolveSyncConflictInput): ResolveSyncConflictResult {
    const parsedInput = parseResolutionInput(input);
    const row = this.#loadRow(parsedInput.vaultId, parsedInput.conflictId);
    if (row === undefined) throw invalidState();
    const conflict = parseConflictRow(row, parsedInput.vaultId);
    if (conflict.resolution !== null) {
      if (
        conflict.resolution.strategy !== parsedInput.strategy ||
        conflict.resolution.currentRevision !== parsedInput.currentRevision
      ) {
        throw invalidState();
      }
      return resultFromResolution(parsedInput.conflictId, conflict.resolution);
    }
    if (conflict.currentRevision !== parsedInput.currentRevision) {
      throw invalidState();
    }

    const pendingRow = this.#database
      .prepare(
        `SELECT sequence, vault_id, entity_type, entity_id, idempotency_key,
                mutation_json, serialized_bytes
           FROM pending_mutations
          WHERE vault_id = ? AND idempotency_key = ?`,
      )
      .get(parsedInput.vaultId, parsedInput.conflictId) as
      | {
          sequence?: unknown;
          vault_id: unknown;
          entity_type: unknown;
          entity_id: unknown;
          idempotency_key: unknown;
          mutation_json: unknown;
          serialized_bytes: unknown;
        }
      | undefined;
    if (pendingRow === undefined) throw invalidState();
    const pending = parseMutationRow(pendingRow, parsedInput.vaultId);
    if (canonicalJson(pending) !== canonicalJson(conflict.mutation)) {
      throw invalidState();
    }
    if (this.#hasLaterPending(pendingRow.sequence, pending)) throw invalidState();

    let result: ResolveSyncConflictResult;
    if (parsedInput.strategy === 'accept-remote') {
      if (parsedInput.replacementIdempotencyKey !== null) throw invalidState();
      this.#vaultState.removePendingMutation(parsedInput.vaultId, pending);
      this.#vaultState.applyConflictCurrent(
        parsedInput.vaultId,
        pending.entityType,
        pending.record.id,
        conflict.currentRevision,
        conflict.current,
      );
      result = {
        status: 'accepted-remote',
        conflictId: parsedInput.conflictId,
        strategy: parsedInput.strategy,
        replacementIdempotencyKey: null,
      };
    } else {
      const replacementKey = parsedInput.replacementIdempotencyKey;
      if (replacementKey === null) throw invalidState();
      this.#vaultState.applyConflictCurrent(
        parsedInput.vaultId,
        pending.entityType,
        pending.record.id,
        conflict.currentRevision,
        conflict.current,
      );
      const current = this.#vaultState.baseState(
        parsedInput.vaultId,
        pending.entityType,
        pending.record.id,
      );
      const replacement = rebaseMutation(
        pending,
        current,
        parsedInput.currentRevision,
        parsedInput.resolvedAt,
        replacementKey,
      );
      this.#vaultState.replacePendingMutation(
        parsedInput.vaultId,
        pending,
        replacement,
        current,
      );
      result = {
        status: 'queued-local',
        conflictId: parsedInput.conflictId,
        strategy: parsedInput.strategy,
        replacementIdempotencyKey: replacementKey,
      };
    }

    const resolution = resolutionFromInput({
      ...parsedInput,
      replacementIdempotencyKey: result.replacementIdempotencyKey,
    });
    this.#markResolved(conflict, resolution);
    return result;
  }

  assertBounds(): void {
    const row = this.#database
      .prepare(
        `SELECT COUNT(*) AS row_count,
                COALESCE(SUM(serialized_bytes), 0) AS total_bytes
           FROM sync_conflicts`,
      )
      .get();
    if (
      getInteger(row, 'row_count') > this.#limits.maxCompletedMutations ||
      getInteger(row, 'total_bytes') > this.#limits.maxCompletedMutationBytes
    ) {
      throw invalidState();
    }
  }

  assertCanonicalRows(): void {
    const rows = this.#database
      .prepare(
        `SELECT sequence, vault_id, entity_type, entity_id, idempotency_key,
                mutation_json, current_revision, current_json, resolution_json,
                serialized_bytes
           FROM sync_conflicts ORDER BY sequence ASC`,
      )
      .all() as unknown as PersistedConflictRow[];
    for (const row of rows) {
      const vaultId = vaultIdSchema.safeParse(row.vault_id);
      if (!vaultId.success) throw invalidState();
      const parsed = parseConflictRow(row, vaultId.data);
      const pending = this.#database
        .prepare(
          `SELECT sequence, vault_id, entity_type, entity_id, idempotency_key,
                  mutation_json, serialized_bytes
             FROM pending_mutations WHERE vault_id = ? AND idempotency_key = ?`,
        )
        .get(vaultId.data, parsed.mutation.idempotencyKey) as
        | {
            sequence?: unknown;
            vault_id: unknown;
            entity_type: unknown;
            entity_id: unknown;
            idempotency_key: unknown;
            mutation_json: unknown;
            serialized_bytes: unknown;
          }
        | undefined;
      if (parsed.resolution === null) {
        if (pending === undefined) throw invalidState();
        if (
          canonicalJson(parseMutationRow(pending, vaultId.data)) !==
          canonicalJson(parsed.mutation)
        ) {
          throw invalidState();
        }
      } else if (pending !== undefined) {
        throw invalidState();
      } else if (parsed.resolution.strategy === 'keep-local') {
        const replacementKey = parsed.resolution.replacementIdempotencyKey;
        if (replacementKey === null) throw invalidState();
        const replacement = this.#database
          .prepare(
            `SELECT sequence, vault_id, entity_type, entity_id, idempotency_key,
                    mutation_json, serialized_bytes
               FROM pending_mutations WHERE vault_id = ? AND idempotency_key = ?`,
          )
          .get(vaultId.data, replacementKey) as
          | {
              sequence?: unknown;
              vault_id: unknown;
              entity_type: unknown;
              entity_id: unknown;
              idempotency_key: unknown;
              mutation_json: unknown;
              serialized_bytes: unknown;
            }
          | undefined;
        if (replacement === undefined) throw invalidState();
        const replacementMutation = parseMutationRow(replacement, vaultId.data);
        if (
          replacementMutation.entityType !== parsed.mutation.entityType ||
          replacementMutation.record.id !== parsed.mutation.record.id
        ) {
          throw invalidState();
        }
      } else if (parsed.resolution.replacementIdempotencyKey !== null) {
        throw invalidState();
      }
    }
    this.assertBounds();
  }

  #loadRow(vaultId: VaultId, conflictId: string): PersistedConflictRow | undefined {
    return this.#database
      .prepare(
        `SELECT sequence, vault_id, entity_type, entity_id, idempotency_key,
                mutation_json, current_revision, current_json, resolution_json,
                serialized_bytes
           FROM sync_conflicts
          WHERE vault_id = ? AND idempotency_key = ?`,
      )
      .get(vaultId, conflictId) as PersistedConflictRow | undefined;
  }

  #updateConflict(
    vaultId: VaultId,
    conflictId: string,
    mutationJson: string,
    currentRevision: number,
    currentJson: string | null,
    resolutionJson: string | null,
  ): void {
    const changed = this.#database
      .prepare(
        `UPDATE sync_conflicts
            SET mutation_json = ?, current_revision = ?, current_json = ?,
                resolution_json = ?, serialized_bytes = ?
          WHERE vault_id = ? AND idempotency_key = ?`,
      )
      .run(
        mutationJson,
        currentRevision,
        currentJson,
        resolutionJson,
        conflictBytes(mutationJson, currentJson, resolutionJson),
        vaultId,
        conflictId,
      );
    if (changed.changes !== 1) throw invalidState();
  }

  #markResolved(conflict: ParsedConflict, resolution: ConflictResolution): void {
    const resolutionJson = encodeBounded(
      resolution,
      this.#limits.maxSerializedRowBytes,
    ).json;
    this.#updateConflict(
      conflict.vaultId,
      conflict.mutation.idempotencyKey,
      JSON.stringify(conflict.mutation),
      conflict.currentRevision,
      conflict.current === null ? null : JSON.stringify(conflict.current),
      resolutionJson,
    );
  }

  #hasLaterPending(sequence: unknown, mutation: OpaqueMutation): boolean {
    if (!Number.isSafeInteger(sequence)) throw invalidState();
    return (
      this.#database
        .prepare(
          `SELECT 1 FROM pending_mutations
            WHERE vault_id = ? AND entity_type = ? AND entity_id = ?
              AND sequence > ? LIMIT 1`,
        )
        .get(
          mutationVaultId(mutation),
          mutation.entityType,
          mutation.record.id,
          sequence as number,
        ) !== undefined
    );
  }
}

function parseConflictRow(
  row: PersistedConflictRow,
  expectedVaultId: VaultId,
): ParsedConflict {
  if (
    typeof row.vault_id !== 'string' ||
    row.vault_id !== expectedVaultId ||
    typeof row.entity_type !== 'string' ||
    typeof row.entity_id !== 'string' ||
    typeof row.idempotency_key !== 'string' ||
    typeof row.mutation_json !== 'string' ||
    (row.current_json !== null && typeof row.current_json !== 'string') ||
    (row.resolution_json !== null && typeof row.resolution_json !== 'string') ||
    getInteger(row, 'serialized_bytes') < 2
  ) {
    throw invalidState();
  }
  const mutation = parseMutationInput(parseJson(row.mutation_json));
  const currentRevision = recordRevisionSchema.safeParse(row.current_revision);
  if (
    !currentRevision.success ||
    mutationVaultId(mutation) !== expectedVaultId ||
    mutation.entityType !== row.entity_type ||
    mutation.record.id !== row.entity_id ||
    mutation.idempotencyKey !== row.idempotency_key
  ) {
    throw invalidState();
  }
  const current =
    row.current_json === null
      ? null
      : opaqueSyncRecordSchema.safeParse(parseJson(row.current_json));
  if (current !== null && !current.success) throw invalidState();
  const parsedCurrent = current === null ? null : current.data;
  assertConflictBinding(expectedVaultId, mutation, currentRevision.data, parsedCurrent);
  const resolution =
    row.resolution_json === null
      ? null
      : conflictResolutionSchema.safeParse(parseJson(row.resolution_json));
  if (resolution !== null && !resolution.success) throw invalidState();
  const parsedResolution = resolution === null ? null : resolution.data;
  if (
    JSON.stringify(mutation) !== row.mutation_json ||
    (parsedCurrent === null
      ? row.current_json !== null
      : JSON.stringify(parsedCurrent) !== row.current_json) ||
    (parsedResolution === null
      ? row.resolution_json !== null
      : JSON.stringify(parsedResolution) !== row.resolution_json) ||
    getInteger(row, 'serialized_bytes') !==
      conflictBytes(row.mutation_json, row.current_json, row.resolution_json)
  ) {
    throw invalidState();
  }
  if (!Number.isSafeInteger(row.sequence) || (row.sequence as number) < 1) {
    throw invalidState();
  }
  return {
    sequence: row.sequence as number,
    vaultId: expectedVaultId,
    mutation,
    currentRevision: currentRevision.data,
    current: parsedCurrent,
    resolution: parsedResolution,
    serializedBytes: getInteger(row, 'serialized_bytes'),
  };
}

function assertConflictBinding(
  vaultId: VaultId,
  mutation: OpaqueMutation,
  currentRevision: number,
  current: OpaqueSyncRecord | null,
): void {
  if (current === null) {
    if (currentRevision !== 0) throw invalidState();
    return;
  }
  if (
    recordVaultId(current) !== vaultId ||
    recordEntityType(current) !== mutation.entityType ||
    recordIdentity(current) !== mutation.record.id ||
    syncRecordRevision(current) !== currentRevision
  ) {
    throw invalidState();
  }
}

function rebaseMutation(
  mutation: OpaqueMutation,
  current: CurrentState | null,
  currentRevision: number,
  resolvedAt: string,
  replacementIdempotencyKey: string,
): OpaqueMutation {
  if (currentRevision >= Number.MAX_SAFE_INTEGER) throw invalidState();
  const predecessor =
    current === null
      ? null
      : current.state === 'active'
        ? current.record
        : current.predecessor;
  if (predecessor !== null && mutation.record.createdAt !== predecessor.createdAt) {
    throw invalidState();
  }
  const updatedAt = maxTimestamp(
    mutation.record.updatedAt,
    predecessor?.updatedAt,
    resolvedAt,
  );
  const revision = recordRevisionSchema.parse(currentRevision + 1);
  const record =
    mutation.entityType === 'vault'
      ? vaultRecordSchema.parse({
          ...mutation.record,
          revision,
          updatedAt,
        })
      : mutation.entityType === 'group'
        ? encryptedGroupRecordSchema.parse({
            ...mutation.record,
            recordRevision: revision,
            updatedAt,
          })
        : encryptedItemRecordSchema.parse({
            ...mutation.record,
            recordRevision: revision,
            updatedAt,
          });
  return opaqueMutationSchema.parse({
    ...mutation,
    idempotencyKey: replacementIdempotencyKey,
    ...(mutation.entityType === 'vault'
      ? { expectedVaultRevision: recordRevisionSchema.parse(currentRevision) }
      : { expectedRecordRevision: recordRevisionSchema.parse(currentRevision) }),
    record,
  });
}

function parseResolutionInput(
  input: ResolveSyncConflictInput,
): ResolveSyncConflictInput {
  if (
    !isRecord(input) ||
    !hasExactKeys(input, [
      'vaultId',
      'conflictId',
      'currentRevision',
      'strategy',
      'replacementIdempotencyKey',
      'resolvedAt',
    ])
  ) {
    throw invalidState();
  }
  const vaultId = vaultIdSchema.parse(input.vaultId);
  const conflictId = parseIdempotencyKey(input.conflictId);
  const currentRevision = recordRevisionSchema.parse(input.currentRevision);
  const strategy = parseStrategy(input.strategy);
  const replacementIdempotencyKey =
    input.replacementIdempotencyKey === null
      ? null
      : parseIdempotencyKey(input.replacementIdempotencyKey);
  const resolvedAt = timestampSchema.parse(input.resolvedAt);
  return {
    vaultId,
    conflictId,
    currentRevision,
    strategy,
    replacementIdempotencyKey,
    resolvedAt,
  };
}

function resultFromResolution(
  conflictId: string,
  resolution: ConflictResolution,
): ResolveSyncConflictResult {
  return {
    status:
      resolution.strategy === 'accept-remote' ? 'accepted-remote' : 'queued-local',
    conflictId,
    strategy: resolution.strategy,
    replacementIdempotencyKey: resolution.replacementIdempotencyKey,
  };
}

function parseIdempotencyKey(value: unknown): string {
  if (
    typeof value !== 'string' ||
    value.length < MIN_IDEMPOTENCY_KEY_LENGTH ||
    value.length > MAX_IDEMPOTENCY_KEY_LENGTH
  ) {
    throw invalidState();
  }
  return value;
}

function parseStrategy(value: unknown): SyncConflictResolutionStrategy {
  if (value !== 'keep-local' && value !== 'accept-remote') throw invalidState();
  return value;
}

function conflictBytes(
  mutationJson: string,
  currentJson: string | null,
  resolutionJson: string | null,
): number {
  return (
    Buffer.byteLength(mutationJson) +
    Buffer.byteLength(currentJson ?? 'null') +
    Buffer.byteLength(resolutionJson ?? 'null')
  );
}

function maxTimestamp(...values: readonly (string | undefined)[]): string {
  const candidates = values.filter((value): value is string => value !== undefined);
  const latest = candidates.reduce(
    (current, candidate) => (candidate > current ? candidate : current),
    '0000-01-01T00:00:00.000Z',
  );
  return timestampSchema.parse(latest);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return JSON.stringify(actual) === JSON.stringify(expected);
}
