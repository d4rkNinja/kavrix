import { describe, expect, it } from 'vitest';

import {
  changeRecordSchema,
  contentHashForRecord,
  encryptedGroupRecordSchema,
  MAX_CIPHERTEXT_CHARS,
  opaqueMutationSchema,
  syncCursorSchema,
  type DeviceId,
  type VaultId,
} from '@kavrix/schemas';

import { SyncProtocolError } from '../src/errors.js';
import { createOutboundObservation } from '../src/outbound-observation.js';
import {
  MAX_OUTBOUND_RECONCILIATION_CHANGES,
  measureOutboundReconciliationChanges,
  type OpaqueMutation,
  type PulledChange,
  type PushBatchRequest,
  type PushBatchResponse,
  type ReconcileOutboundObservationInput,
} from '../src/types.js';
import { validateOutboundStagedRange } from '../src/validation.js';

const timestamp = '2026-08-10T00:00:00.000Z';
const vaultId = 'vault.recovery.matrix' as VaultId;
const deviceId = 'device.recovery.matrix' as DeviceId;

describe('outbound reconciliation recovery matrix', () => {
  it('accepts the exact complete staged range', () => {
    expect(() => {
      validateOutboundStagedRange(validInput());
    }).not.toThrow();
  });

  it.each([
    [
      'missing entry',
      (input: ReconcileOutboundObservationInput) => ({
        ...input,
        stagedChanges: [],
        stagedChangesBytes: measureOutboundReconciliationChanges([]),
      }),
    ],
    [
      'sequence gap',
      (input: ReconcileOutboundObservationInput) => ({
        ...input,
        stagedChanges: input.stagedChanges.map((pulled) => ({
          ...pulled,
          change: { ...pulled.change, serverSequence: 2 },
        })),
        stagedChangesBytes: 0,
      }),
    ],
    [
      'duplicate sequence',
      (input: ReconcileOutboundObservationInput) => ({
        ...input,
        stagedChanges: [...input.stagedChanges, ...input.stagedChanges],
        stagedChangesBytes: measureOutboundReconciliationChanges([
          ...input.stagedChanges,
          ...input.stagedChanges,
        ]),
      }),
    ],
    [
      'request record mismatch',
      (input: ReconcileOutboundObservationInput) => {
        const changed = groupMutation(0, 'group.changed', 'mutation-key-0000001');
        const changedPulled = {
          change: changeRecordSchema.parse({
            id: 'change.changed.1',
            vaultId,
            serverSequence: 1,
            entityType: 'group',
            entityId: changed.record.id,
            recordRevision: changed.record.recordRevision,
            operation: 'upsert',
            ciphertextHash: contentHashForRecord(changed.record),
            createdAt: timestamp,
          }),
          record: changed.record,
        };
        return {
          ...input,
          stagedChanges: [changedPulled],
          stagedChangesBytes: measureOutboundReconciliationChanges([changedPulled]),
        };
      },
    ],
    [
      'declared byte mismatch',
      (input: ReconcileOutboundObservationInput) => ({
        ...input,
        stagedChangesBytes: input.stagedChangesBytes + 1,
      }),
    ],
    [
      'terminal cursor below required range',
      (input: ReconcileOutboundObservationInput) => ({
        ...input,
        finalCursor: syncCursorSchema.parse({
          ...input.finalCursor,
          serverSequence: 0,
        }),
      }),
    ],
  ])('rejects %s before reconciliation', (_name, mutate) => {
    expect(() => {
      validateOutboundStagedRange(mutate(validInput()) as never);
    }).toThrow(SyncProtocolError);
  });

  it('rejects a descriptor required-range mismatch', () => {
    const input = validInput();
    expect(() => {
      validateOutboundStagedRange({
        ...input,
        observation: { ...input.observation, requiredThroughServerSequence: 2 },
      } as never);
    }).toThrow(SyncProtocolError);
  });

  it('rejects 501 staged changes before canonical byte accounting', () => {
    const pulled = required(validInput().stagedChanges[0]);
    const excessive = Array.from(
      { length: MAX_OUTBOUND_RECONCILIATION_CHANGES + 1 },
      () => pulled,
    );
    expect(() => measureOutboundReconciliationChanges(excessive)).toThrow(
      'Invalid outbound reconciliation range',
    );
  });

  it('rejects a canonical aggregate above 32 MiB using individually valid records', () => {
    const first = largeValidPulledChange('group.large.1', 1, MAX_CIPHERTEXT_CHARS);
    const second = largeValidPulledChange('group.large.2', 2, 32 * 1024 * 1024);
    expect(() => measureOutboundReconciliationChanges([first, second])).toThrow(
      'Invalid outbound reconciliation range',
    );
  });
});

function validInput(): ReconcileOutboundObservationInput {
  const mutation = groupMutation(0, 'group.1', 'mutation-key-0000001');
  const request: PushBatchRequest = {
    vaultId,
    batchIdempotencyKey: 'batch-key-0000001',
    mutations: [mutation],
  };
  const change = changeRecordSchema.parse({
    id: 'change.push.1',
    vaultId,
    serverSequence: 1,
    entityType: 'group',
    entityId: mutation.record.id,
    recordRevision: mutation.record.recordRevision,
    operation: 'upsert',
    ciphertextHash: contentHashForRecord(mutation.record),
    createdAt: timestamp,
  });
  const response: PushBatchResponse = {
    vaultId,
    serverVaultRevision: 1 as PushBatchResponse['serverVaultRevision'],
    batchIdempotencyKey: request.batchIdempotencyKey,
    results: [
      {
        status: 'accepted',
        idempotencyKey: mutation.idempotencyKey,
        disposition: 'committed',
        change,
      },
    ],
  };
  const observation = createOutboundObservation({
    kind: 'generic-push',
    vaultId,
    deviceId,
    request,
    response,
    replayFromServerSequence: 0,
  });
  const stagedChanges = [{ change, record: mutation.record }] as const;
  return {
    kind: 'generic-push',
    vaultId,
    deviceId,
    observation,
    request,
    response,
    stagedChanges,
    stagedChangesBytes: measureOutboundReconciliationChanges(stagedChanges),
    finalCursor: syncCursorSchema.parse({
      vaultId,
      serverSequence: 1,
      highestSeenVaultRevision: 1,
    }),
  };
}

function groupMutation(
  revision: number,
  id: string,
  idempotencyKey: string,
): Extract<OpaqueMutation, { entityType: 'group' }> {
  const record = encryptedGroupRecordSchema.parse({
    id,
    vaultId,
    schemaVersion: 1,
    wrappedGroupKey: envelope('wrapped-group-key', id),
    encryptedPayload: envelope('group', id),
    templateVersion: 1,
    recordRevision: revision,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  return opaqueMutationSchema.parse({
    entityType: 'group',
    expectedRecordRevision: null,
    idempotencyKey,
    record,
  }) as Extract<OpaqueMutation, { entityType: 'group' }>;
}

function envelope(
  entityType: 'group' | 'wrapped-group-key',
  entityId: string,
): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType,
      entityId,
      purpose: entityType === 'group' ? 'group-payload' : 'group-key',
    },
    keyVersion: 1,
  };
}

function largeValidPulledChange(
  id: string,
  serverSequence: number,
  targetAggregateContribution: number,
): PulledChange {
  const ciphertextLength = Math.min(MAX_CIPHERTEXT_CHARS, targetAggregateContribution);
  const mutation = groupMutation(
    0,
    id,
    `large-key-${String(serverSequence).padStart(8, '0')}`,
  );
  const record = encryptedGroupRecordSchema.parse({
    ...mutation.record,
    encryptedPayload: {
      ...mutation.record.encryptedPayload,
      ciphertext: 'A'.repeat(ciphertextLength),
    },
  });
  return {
    change: changeRecordSchema.parse({
      id: `change.large.${String(serverSequence)}`,
      vaultId,
      serverSequence,
      entityType: 'group',
      entityId: record.id,
      recordRevision: record.recordRevision,
      operation: 'upsert',
      ciphertextHash: contentHashForRecord(record),
      createdAt: timestamp,
    }),
    record,
  };
}

function required<T>(value: T | null | undefined): T {
  if (value === null || value === undefined) throw new Error('Missing fixture');
  return value;
}
