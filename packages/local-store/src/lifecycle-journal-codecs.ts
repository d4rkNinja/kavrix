import { timingSafeEqual } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import {
  initializationJournalRecordSchema,
  joinJournalRecordSchema,
  joinPreparedJournalRecordSchema,
  lifecycleOperationIdSchema,
  type InitializationJournalRecord,
  type JoinActiveJournalRecord,
  type JoinCommittedJournalRecord,
  type JoinJournalRecord,
  type JoinPreparedJournalRecord,
  type LifecycleOperationId,
} from '@kavrix/client';
import {
  deviceIdSchema,
  sessionCredentialLocatorSchema,
  vaultIdSchema,
} from '@kavrix/schemas';

import { invalidState, type LifecycleJournalLimits } from './lifecycle-journal-db.js';

export type InitializationRow = Readonly<{
  operation_id: unknown;
  state: unknown;
  record_json: unknown;
  serialized_bytes: unknown;
  device_locator_json: unknown;
  session_locator_json: unknown;
}>;

export type JoinRow = Readonly<{
  operation_id: unknown;
  phase: unknown;
  state: unknown;
  target_state: unknown;
  expected_vault_id: unknown;
  device_id: unknown;
  session_locator_json: unknown;
  committed_json: unknown;
  serialized_bytes: unknown;
}>;

export type ParsedJoinRow = Readonly<{
  operationId: LifecycleOperationId;
  phase: 'reserving' | 'stable' | 'transitioning' | 'deleting' | 'committing';
  state: JoinJournalRecord['state'];
  targetState: 'redeem-attempted' | 'completion-attempted' | null;
  expectedVaultId: string;
  deviceId: string;
  sessionLocatorJson: string;
  committed: JoinCommittedJournalRecord | null;
  serializedBytes: number;
}>;

export function verifyInitializationDatabaseRows(
  database: DatabaseSync,
  limits: LifecycleJournalLimits,
): void {
  verifyInitializationCapacity(database, limits);
  for (const row of database
    .prepare(
      `SELECT operation_id, state, record_json, serialized_bytes,
              device_locator_json, session_locator_json
         FROM initialization_journal`,
    )
    .all() as unknown as InitializationRow[]) {
    parseInitializationRow(row, limits.maxSerializedBytes);
  }
}

export function verifyJoinDatabaseRows(
  database: DatabaseSync,
  limits: LifecycleJournalLimits,
): void {
  verifyJoinCapacity(database, limits);
  for (const row of database
    .prepare(
      `SELECT operation_id, phase, state, target_state, expected_vault_id,
              device_id, session_locator_json, committed_json, serialized_bytes
         FROM join_journal`,
    )
    .all() as unknown as JoinRow[]) {
    parseJoinRow(row, limits);
  }
}

export function parseInitializationRow(
  row: InitializationRow,
  maxSerializedBytes: number,
): InitializationJournalRecord {
  if (
    typeof row.operation_id !== 'string' ||
    typeof row.state !== 'string' ||
    typeof row.record_json !== 'string' ||
    requireInteger(row.serialized_bytes) !== Buffer.byteLength(row.record_json) ||
    Buffer.byteLength(row.record_json) > maxSerializedBytes
  ) {
    throw invalidState();
  }
  const record = parseInitialization(parseJson(row.record_json));
  if (
    record.operationId !== row.operation_id ||
    record.state !== row.state ||
    JSON.stringify(record) !== row.record_json
  ) {
    throw invalidState();
  }
  if (record.state === 'committed') {
    if (row.device_locator_json !== null || row.session_locator_json !== null) {
      throw invalidState();
    }
  } else if (
    row.device_locator_json !== JSON.stringify(record.deviceLocator) ||
    row.session_locator_json !== JSON.stringify(record.sessionLocator)
  ) {
    throw invalidState();
  }
  return record;
}

export function parseJoinRow(
  row: JoinRow,
  limits: LifecycleJournalLimits,
): ParsedJoinRow {
  const operationId = parseOperationId(row.operation_id);
  const phases = [
    'reserving',
    'stable',
    'transitioning',
    'deleting',
    'committing',
  ] as const;
  const states = [
    'prepared',
    'redeem-attempted',
    'completion-attempted',
    'committed',
  ] as const;
  if (
    !phases.some((value) => value === row.phase) ||
    !states.some((value) => value === row.state) ||
    typeof row.expected_vault_id !== 'string' ||
    typeof row.device_id !== 'string' ||
    typeof row.session_locator_json !== 'string'
  ) {
    throw invalidState();
  }
  const phase = row.phase as ParsedJoinRow['phase'];
  const state = row.state as ParsedJoinRow['state'];
  const vaultId = vaultIdSchema.safeParse(row.expected_vault_id);
  const deviceId = deviceIdSchema.safeParse(row.device_id);
  const sessionLocator = sessionCredentialLocatorSchema.safeParse(
    parseJson(row.session_locator_json),
  );
  if (
    !vaultId.success ||
    !deviceId.success ||
    !sessionLocator.success ||
    sessionLocator.data.vaultId !== vaultId.data ||
    sessionLocator.data.deviceId !== deviceId.data ||
    JSON.stringify(sessionLocator.data) !== row.session_locator_json
  ) {
    throw invalidState();
  }
  const targetState =
    row.target_state === null
      ? null
      : row.target_state === 'redeem-attempted' ||
          row.target_state === 'completion-attempted'
        ? row.target_state
        : invalidStateNever();
  const committed =
    row.committed_json === null
      ? null
      : typeof row.committed_json === 'string'
        ? parseCommittedJoin(parseJson(row.committed_json))
        : invalidStateNever();
  const bytes = requireInteger(row.serialized_bytes);
  const isCommittedPhase = phase === 'committing' || state === 'committed';
  const validTransition =
    phase !== 'transitioning' ||
    (state === 'prepared' && targetState === 'redeem-attempted') ||
    (state === 'redeem-attempted' && targetState === 'completion-attempted');
  if (
    bytes > limits.maxSerializedBytes ||
    (committed === null
      ? bytes !== Buffer.byteLength(row.session_locator_json)
      : bytes !== Buffer.byteLength(row.committed_json as string)) ||
    (committed !== null &&
      (committed.operationId !== operationId ||
        committed.vaultId !== vaultId.data ||
        committed.deviceId !== deviceId.data ||
        JSON.stringify(committed) !== row.committed_json)) ||
    isCommittedPhase !== (committed !== null) ||
    (state === 'committed' && phase !== 'stable') ||
    (phase === 'committing' && state !== 'completion-attempted') ||
    (phase === 'reserving' && state !== 'prepared') ||
    (phase === 'deleting' && state !== 'prepared') ||
    !validTransition
  ) {
    throw invalidState();
  }
  return {
    operationId,
    phase,
    state,
    targetState,
    expectedVaultId: vaultId.data,
    deviceId: deviceId.data,
    sessionLocatorJson: row.session_locator_json,
    committed,
    serializedBytes: bytes,
  };
}

export function matchesMirror(
  active: JoinActiveJournalRecord,
  row: ParsedJoinRow,
): boolean {
  return (
    active.operationId === row.operationId &&
    active.expectedVaultId === row.expectedVaultId &&
    active.deviceId === row.deviceId &&
    JSON.stringify(active.sessionLocator) === row.sessionLocatorJson &&
    (row.phase === 'transitioning'
      ? active.state === row.state || active.state === row.targetState
      : active.state === row.state)
  );
}

export function sameJoinRecord(
  left: JoinActiveJournalRecord,
  right: JoinActiveJournalRecord,
): boolean {
  const leftPublic = JSON.stringify({
    ...left,
    inviteBearer: undefined,
    enrollmentSuccessor: undefined,
    sessionSuccessor: undefined,
  });
  const rightPublic = JSON.stringify({
    ...right,
    inviteBearer: undefined,
    enrollmentSuccessor: undefined,
    sessionSuccessor: undefined,
  });
  return (
    leftPublic === rightPublic &&
    safeEqual(left.inviteBearer, right.inviteBearer) &&
    safeEqual(left.enrollmentSuccessor, right.enrollmentSuccessor) &&
    safeEqual(left.sessionSuccessor, right.sessionSuccessor)
  );
}

export function copyPrepared(
  input: JoinPreparedJournalRecord,
): JoinPreparedJournalRecord {
  const parsed = joinPreparedJournalRecordSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return joinPreparedJournalRecordSchema.parse({
    ...parsed.data,
    inviteBearer: Uint8Array.from(parsed.data.inviteBearer),
    enrollmentSuccessor: Uint8Array.from(parsed.data.enrollmentSuccessor),
    sessionSuccessor: Uint8Array.from(parsed.data.sessionSuccessor),
  });
}

export function wipeJoinRecord(record: JoinActiveJournalRecord | undefined): void {
  record?.inviteBearer.fill(0);
  record?.enrollmentSuccessor.fill(0);
  record?.sessionSuccessor.fill(0);
}

export function encodeJoinMirror(record: JoinPreparedJournalRecord): Readonly<{
  sessionLocatorJson: string;
  serializedBytes: number;
}> {
  const sessionLocatorJson = JSON.stringify(record.sessionLocator);
  return {
    sessionLocatorJson,
    serializedBytes: Buffer.byteLength(sessionLocatorJson),
  };
}

export function parseInitialization(input: unknown): InitializationJournalRecord {
  const parsed = initializationJournalRecordSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

export function parseCommittedJoin(input: unknown): JoinCommittedJournalRecord {
  const parsed = joinJournalRecordSchema.safeParse(input);
  if (!parsed.success || parsed.data.state !== 'committed') throw invalidState();
  return parsed.data;
}

export function parseOperationId(input: unknown): LifecycleOperationId {
  const parsed = lifecycleOperationIdSchema.safeParse(input);
  if (!parsed.success) throw invalidState();
  return parsed.data;
}

export function verifyInitializationCapacity(
  database: DatabaseSync,
  limits: LifecycleJournalLimits,
): void {
  verifyCapacity(database, 'initialization_journal', limits);
}

export function verifyJoinCapacity(
  database: DatabaseSync,
  limits: LifecycleJournalLimits,
): void {
  verifyCapacity(database, 'join_journal', limits);
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

function verifyCapacity(
  database: DatabaseSync,
  table: 'initialization_journal' | 'join_journal',
  limits: LifecycleJournalLimits,
): void {
  const row = database
    .prepare(
      `SELECT COUNT(*) AS row_count,
              COALESCE(SUM(serialized_bytes), 0) AS total_bytes FROM ${table}`,
    )
    .get() as { row_count?: unknown; total_bytes?: unknown } | undefined;
  if (
    row === undefined ||
    requireInteger(row.row_count) > limits.maxOperations ||
    requireInteger(row.total_bytes) > limits.maxSerializedBytes
  ) {
    throw invalidState();
  }
}

function safeEqual(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

function requireInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw invalidState();
  return value as number;
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw invalidState();
  }
}

function invalidStateNever(): never {
  throw invalidState();
}
