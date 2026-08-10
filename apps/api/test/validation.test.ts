import { describe, expect, it } from 'vitest';

import {
  changeRecordSchema,
  syncCursorSchema,
  syncPullResponseSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
} from '@kavrix/schemas';

import { buildApi } from '../src/app.js';
import { rejectSecretFields } from '../src/boundary.js';
import { NodeInviteIdPort } from '../src/invite-id.js';
import { validatePullPage, validatePushBatch } from '../src/sync-validation.js';
import {
  createTestPorts,
  digest,
  nowIso,
  otherVaultId,
  vaultFixture,
  vaultId,
} from './helpers.js';

describe('adapter and configuration boundaries', () => {
  it('generates distinct canonical opaque invite identifiers', () => {
    const ids = new NodeInviteIdPort();
    expect(ids.next()).not.toBe(ids.next());
  });

  it('rejects non-contiguous, rollback, cross-vault, and oversized pull pages', () => {
    const cursor = syncCursorSchema.parse({
      vaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 1,
    });
    const empty = syncPullResponseSchema.parse({
      vaultId,
      serverVaultRevision: 1,
      changes: [],
      nextCursor: cursor,
      hasMore: false,
    });
    expect(validatePullPage(empty, vaultId, cursor, 1)).toEqual(empty);

    const otherCursor = syncCursorSchema.parse({
      vaultId: otherVaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 1,
    });
    expect(() =>
      validatePullPage(
        { ...empty, vaultId: otherVaultId, nextCursor: otherCursor },
        vaultId,
        cursor,
        1,
      ),
    ).toThrow('boundary');
    expect(() =>
      validatePullPage(
        {
          ...empty,
          serverVaultRevision: 0,
          nextCursor: { ...cursor, highestSeenVaultRevision: 0 },
        },
        vaultId,
        cursor,
        1,
      ),
    ).toThrow('boundary');

    const gapChange = changeRecordSchema.parse({
      id: 'change-gap-2',
      vaultId,
      serverSequence: 2,
      recordRevision: 2,
      operation: 'purge',
      createdAt: nowIso,
      entityType: 'group',
      entityId: 'group-gap',
    });
    const gapPage = syncPullResponseSchema.parse({
      vaultId,
      serverVaultRevision: 1,
      changes: [{ change: gapChange, record: null }],
      nextCursor: { ...cursor, serverSequence: 2 },
      hasMore: false,
    });
    expect(() => validatePullPage(gapPage, vaultId, cursor, 1)).toThrow(
      'non-contiguous',
    );
    expect(() => validatePullPage(gapPage, vaultId, cursor, 0)).toThrow('boundary');
    expect(() =>
      validatePullPage(
        { ...empty, nextCursor: { ...cursor, serverSequence: 1 } },
        vaultId,
        cursor,
        1,
      ),
    ).toThrow('next sync cursor');
  });

  it('rejects reordered, cross-batch, misacknowledged, and cross-vault push results', () => {
    const request = syncPushRequestSchema.parse({
      vaultId,
      batchIdempotencyKey: 'batch-validation-0001',
      mutations: [
        {
          entityType: 'vault',
          expectedVaultRevision: 1,
          idempotencyKey: 'mutation-validation-01',
          record: vaultFixture(vaultId, 2),
        },
      ],
    });
    const change = changeRecordSchema.parse({
      id: 'change-validation-1',
      vaultId,
      serverSequence: 1,
      recordRevision: 2,
      operation: 'upsert',
      ciphertextHash: digest('validation'),
      createdAt: nowIso,
      entityType: 'vault',
      entityId: vaultId,
    });
    const accepted = syncPushResponseSchema.parse({
      vaultId,
      serverVaultRevision: 2,
      batchIdempotencyKey: request.batchIdempotencyKey,
      results: [
        {
          status: 'accepted',
          idempotencyKey: request.mutations[0]?.idempotencyKey,
          disposition: 'committed',
          change,
        },
      ],
    });
    expect(validatePushBatch(accepted, request)).toEqual(accepted);
    expect(() =>
      validatePushBatch({ ...accepted, vaultId: otherVaultId }, request),
    ).toThrow('boundary');
    expect(() =>
      validatePushBatch(
        { ...accepted, batchIdempotencyKey: 'batch-validation-other' },
        request,
      ),
    ).toThrow('boundary');
    expect(() =>
      validatePushBatch(
        {
          ...accepted,
          results: [
            { ...accepted.results[0], idempotencyKey: 'mutation-validation-02' },
          ],
        },
        request,
      ),
    ).toThrow('order');
    expect(() =>
      validatePushBatch(
        {
          ...accepted,
          results: [
            {
              ...accepted.results[0],
              change: { ...change, operation: 'restore' },
            },
          ],
        },
        request,
      ),
    ).toThrow('different mutation');

    const conflict = syncPushResponseSchema.parse({
      ...accepted,
      results: [
        {
          status: 'conflict',
          idempotencyKey: request.mutations[0]?.idempotencyKey,
          currentRevision: 1,
          current: vaultFixture(otherVaultId),
        },
      ],
    });
    expect(() => validatePushBatch(conflict, request)).toThrow('different record');
  });

  it('fails closed on unsafe local configuration and pathological bodies', async () => {
    const fixture = await createTestPorts();
    expect(() =>
      buildApi({ ports: fixture.ports, environment: 'test', bodyLimit: 0 }),
    ).toThrow('body limit');
    expect(() =>
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        authenticatedRatePolicy: { limit: 0, windowSeconds: 60 },
      }),
    ).toThrow('rate limit');
    expect(() =>
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        enrollmentLifetimeSeconds: 1,
      }),
    ).toThrow('Enrollment lifetime');
    expect(() => {
      rejectSecretFields(new Array(100_001).fill(null));
    }).toThrow();
  });
});
