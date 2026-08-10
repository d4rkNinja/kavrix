import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import {
  attachmentIdSchema,
  groupIdSchema,
  itemIdSchema,
  opaqueMutationSchema,
  opaqueSyncRecordSchema,
  syncCursorSchema,
  syncEntityTypeSchema,
  syncPulledChangeSchema,
  vaultIdSchema,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type SyncPulledChange,
  type VaultId,
} from '@kavrix/schemas';
import type {
  ActivePushBatch,
  ApplyPullPageInput,
  CompletePushBatchInput,
  SyncCursor,
} from '@kavrix/sync';

import { requireNonnegativeInteger } from './sqlite-local-database.js';
import { invalidState } from './sqlite-local-errors.js';

const MAX_PULL_PAGE_CHANGES = 500;
const MAX_PULL_PAGE_BYTES = 32 * 1024 * 1024;
const MAX_BATCH_MUTATIONS = 100;
const MIN_IDEMPOTENCY_KEY_LENGTH = 16;
const MAX_IDEMPOTENCY_KEY_LENGTH = 256;

export type SyncEntityType = SyncPulledChange['change']['entityType'];

export interface CursorRow {
  readonly vault_id: unknown;
  readonly server_sequence: unknown;
  readonly highest_revision: unknown;
  readonly cursor_json: unknown;
  readonly last_page_hash: unknown;
}

export interface MutationRow {
  readonly vault_id: unknown;
  readonly entity_type: unknown;
  readonly entity_id: unknown;
  readonly idempotency_key: unknown;
  readonly mutation_json: unknown;
  readonly serialized_bytes: unknown;
}

export interface RecordRow {
  readonly vault_id: unknown;
  readonly entity_type: unknown;
  readonly entity_id: unknown;
  readonly revision: unknown;
  readonly record_json: unknown;
  readonly serialized_bytes: unknown;
}

export interface BatchRow {
  readonly vault_id: unknown;
  readonly batch_key: unknown;
  readonly batch_json: unknown;
  readonly serialized_bytes: unknown;
}

export function parseApplyPullPage(
  input: ApplyPullPageInput,
  maxSerializedRowBytes: number,
): Readonly<{
  vaultId: VaultId;
  changes: readonly SyncPulledChange[];
  cursor: SyncCursor;
  cursorJson: string;
  pageHash: string;
}> {
  if (!hasExactKeys(input, ['vaultId', 'changes', 'cursor'])) throw invalidState();
  const vaultId = parseVaultId(input.vaultId);
  const parsedCursor = syncCursorSchema.safeParse(input.cursor);
  if (!parsedCursor.success || parsedCursor.data.vaultId !== vaultId) {
    throw invalidState();
  }
  if (!Array.isArray(input.changes) || input.changes.length > MAX_PULL_PAGE_CHANGES) {
    throw invalidState();
  }
  const changes = input.changes.map((value) => {
    const parsed = syncPulledChangeSchema.safeParse(value);
    if (!parsed.success || parsed.data.change.vaultId !== vaultId) {
      throw invalidState();
    }
    return parsed.data;
  });
  const cursorJson = encodeBounded(parsedCursor.data, maxSerializedRowBytes).json;
  const pageJson = encodeBounded(
    { vaultId, changes, cursor: parsedCursor.data },
    Math.min(
      MAX_PULL_PAGE_BYTES,
      maxSerializedRowBytes * Math.max(1, changes.length + 1),
    ),
  ).json;
  return {
    vaultId,
    changes,
    cursor: parsedCursor.data,
    cursorJson,
    pageHash: digest(pageJson),
  };
}

export function validateCursorAdvance(
  existing: Readonly<{ cursor: SyncCursor; pageHash: string }> | null,
  page: Readonly<{
    cursor: SyncCursor;
    changes: readonly SyncPulledChange[];
    pageHash: string;
  }>,
): 'advance' | 'duplicate' {
  const previousSequence = existing?.cursor.serverSequence ?? 0;
  const previousRevision = existing?.cursor.highestSeenVaultRevision ?? 0;
  if (
    page.cursor.serverSequence < previousSequence ||
    page.cursor.highestSeenVaultRevision < previousRevision
  ) {
    throw invalidState();
  }
  if (page.cursor.serverSequence === previousSequence) {
    if (
      existing !== null &&
      page.cursor.highestSeenVaultRevision === previousRevision &&
      page.pageHash === existing.pageHash
    ) {
      return 'duplicate';
    }
    if (page.changes.length !== 0) throw invalidState();
    return 'advance';
  }
  if (page.changes.length === 0) throw invalidState();
  let expected = previousSequence + 1;
  for (const pulled of page.changes) {
    if (pulled.change.serverSequence !== expected) throw invalidState();
    expected += 1;
  }
  if (page.cursor.serverSequence !== expected - 1) throw invalidState();
  return 'advance';
}

export function parseCursorRow(
  row: CursorRow,
  expectedVaultId: string,
): Readonly<{ cursor: SyncCursor; pageHash: string }> {
  if (
    row.vault_id !== expectedVaultId ||
    typeof row.cursor_json !== 'string' ||
    typeof row.last_page_hash !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/u.test(row.last_page_hash)
  ) {
    throw invalidState();
  }
  const parsed = parseJson(row.cursor_json);
  const cursor = syncCursorSchema.safeParse(parsed);
  if (
    !cursor.success ||
    cursor.data.vaultId !== expectedVaultId ||
    cursor.data.serverSequence !== row.server_sequence ||
    cursor.data.highestSeenVaultRevision !== row.highest_revision ||
    JSON.stringify(cursor.data) !== row.cursor_json
  ) {
    throw invalidState();
  }
  return { cursor: cursor.data, pageHash: row.last_page_hash };
}

export function parseMutation(
  input: OpaqueMutation,
  expectedVaultId: string,
): OpaqueMutation {
  const parsed = opaqueMutationSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  const mutation = parsed.data;
  const revision =
    mutation.entityType === 'vault'
      ? mutation.record.revision
      : mutation.record.recordRevision;
  const expected =
    mutation.entityType === 'vault'
      ? mutation.expectedVaultRevision
      : mutation.expectedRecordRevision;
  if (
    mutationVaultId(mutation) !== expectedVaultId ||
    revision !== (expected === null ? 0 : expected + 1)
  ) {
    throw invalidState();
  }
  return mutation;
}

export function parseMutationRow(
  row: MutationRow,
  expectedVaultId: string,
): OpaqueMutation {
  if (
    row.vault_id !== expectedVaultId ||
    typeof row.entity_type !== 'string' ||
    typeof row.entity_id !== 'string' ||
    typeof row.idempotency_key !== 'string' ||
    typeof row.mutation_json !== 'string' ||
    requireNonnegativeInteger(row.serialized_bytes) !==
      Buffer.byteLength(row.mutation_json)
  ) {
    throw invalidState();
  }
  const mutation = parseMutation(
    parseJson(row.mutation_json) as never,
    expectedVaultId,
  );
  if (
    mutation.idempotencyKey !== row.idempotency_key ||
    mutation.entityType !== row.entity_type ||
    recordIdentity(mutation.record) !== row.entity_id ||
    JSON.stringify(mutation) !== row.mutation_json
  ) {
    throw invalidState();
  }
  return mutation;
}

export function parseActiveBatch(input: ActivePushBatch): ActivePushBatch {
  if (
    !hasExactKeys(input, ['vaultId', 'batchIdempotencyKey', 'mutationIdempotencyKeys'])
  ) {
    throw invalidState();
  }
  const vaultId = parseVaultId(input.vaultId);
  const mutationIdempotencyKeys = parseIdempotencyKeys(
    input.mutationIdempotencyKeys,
    false,
  );
  if (!isIdempotencyKey(input.batchIdempotencyKey)) {
    throw invalidState();
  }
  return {
    vaultId,
    batchIdempotencyKey: input.batchIdempotencyKey,
    mutationIdempotencyKeys,
  };
}

export function parseBatchRow(row: BatchRow, expectedVaultId: string): ActivePushBatch {
  if (
    row.vault_id !== expectedVaultId ||
    typeof row.batch_key !== 'string' ||
    typeof row.batch_json !== 'string' ||
    requireNonnegativeInteger(row.serialized_bytes) !==
      Buffer.byteLength(row.batch_json)
  ) {
    throw invalidState();
  }
  const batch = parseActiveBatch(parseJson(row.batch_json) as never);
  if (
    batch.vaultId !== expectedVaultId ||
    batch.batchIdempotencyKey !== row.batch_key ||
    JSON.stringify(batch) !== row.batch_json
  ) {
    throw invalidState();
  }
  return batch;
}

export function assertBatchPending(
  database: DatabaseSync,
  batch: ActivePushBatch,
): void {
  const lookup = database.prepare(
    `SELECT vault_id FROM pending_mutations WHERE idempotency_key = ?`,
  );
  for (const key of batch.mutationIdempotencyKeys) {
    const row = lookup.get(key) as { vault_id: unknown } | undefined;
    if (row?.vault_id !== batch.vaultId) throw invalidState();
  }
}

export function parseCompletion(input: CompletePushBatchInput): CompletePushBatchInput {
  if (
    !hasExactKeys(input, [
      'vaultId',
      'batchIdempotencyKey',
      'acknowledgedIdempotencyKeys',
    ])
  ) {
    throw invalidState();
  }
  const vaultId = parseVaultId(input.vaultId);
  const acknowledgedIdempotencyKeys = parseIdempotencyKeys(
    input.acknowledgedIdempotencyKeys,
    true,
  );
  if (!isIdempotencyKey(input.batchIdempotencyKey)) {
    throw invalidState();
  }
  return {
    vaultId,
    batchIdempotencyKey: input.batchIdempotencyKey,
    acknowledgedIdempotencyKeys,
  };
}

export function parseRecordRow(
  row: RecordRow,
  expectedVaultId: string,
): OpaqueSyncRecord {
  if (
    row.vault_id !== expectedVaultId ||
    typeof row.entity_type !== 'string' ||
    typeof row.entity_id !== 'string' ||
    typeof row.record_json !== 'string' ||
    requireNonnegativeInteger(row.serialized_bytes) !==
      Buffer.byteLength(row.record_json)
  ) {
    throw invalidState();
  }
  const result = opaqueSyncRecordSchema.safeParse(parseJson(row.record_json));
  if (!result.success) throw invalidState();
  const record = result.data;
  if (
    recordVaultId(record) !== expectedVaultId ||
    recordEntityType(record) !== row.entity_type ||
    recordIdentity(record) !== row.entity_id ||
    recordRevision(record) !== row.revision ||
    JSON.stringify(record) !== row.record_json
  ) {
    throw invalidState();
  }
  return record;
}

export function parseVaultId(input: unknown): VaultId {
  const parsed = vaultIdSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

export function parseEntityType(input: unknown): SyncEntityType {
  const parsed = syncEntityTypeSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

export function parseEntityId(entityType: SyncEntityType, input: unknown): string {
  const schema =
    entityType === 'vault'
      ? vaultIdSchema
      : entityType === 'group'
        ? groupIdSchema
        : entityType === 'item'
          ? itemIdSchema
          : attachmentIdSchema;
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

function mutationVaultId(mutation: OpaqueMutation): VaultId {
  return mutation.entityType === 'vault' ? mutation.record.id : mutation.record.vaultId;
}

function recordVaultId(record: OpaqueSyncRecord): VaultId {
  return 'vaultId' in record ? record.vaultId : record.id;
}

function recordIdentity(record: OpaqueSyncRecord): string {
  return 'state' in record ? record.entityId : record.id;
}

function recordEntityType(record: OpaqueSyncRecord): SyncEntityType {
  if ('state' in record) return record.entityType;
  if ('revision' in record) return 'vault';
  if ('itemId' in record) return 'attachment';
  if ('groupId' in record) return 'item';
  return 'group';
}

function recordRevision(record: OpaqueSyncRecord): number {
  if ('state' in record) return record.tombstoneRevision;
  return 'revision' in record ? record.revision : record.recordRevision;
}

function isIdempotencyKey(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= MIN_IDEMPOTENCY_KEY_LENGTH &&
    value.length <= MAX_IDEMPOTENCY_KEY_LENGTH
  );
}

function parseIdempotencyKeys(value: unknown, allowEmpty: boolean): string[] {
  if (!Array.isArray(value)) throw invalidState();
  const candidates = value as unknown[];
  if (
    (!allowEmpty && candidates.length === 0) ||
    candidates.length > MAX_BATCH_MUTATIONS
  ) {
    throw invalidState();
  }
  const result: string[] = [];
  for (const candidate of candidates) {
    if (!isIdempotencyKey(candidate)) throw invalidState();
    result.push(candidate);
  }
  if (new Set(result).size !== result.length) throw invalidState();
  return result;
}

export function encodeBounded(
  value: unknown,
  maxBytes: number,
): Readonly<{ json: string; bytes: number }> {
  const json = JSON.stringify(value);
  if (typeof json !== 'string') throw invalidState();
  const bytes = Buffer.byteLength(json);
  if (bytes < 2 || bytes > maxBytes) throw invalidState();
  return { json, bytes };
}

function digest(value: string): string {
  const hash = createHash('sha256').update(value, 'utf8').digest();
  try {
    return hash.toString('base64url');
  } finally {
    hash.fill(0);
  }
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
  return (
    actual.length === keys.length &&
    keys.every((key) => key in value) &&
    actual.every((key) => keys.includes(key))
  );
}
