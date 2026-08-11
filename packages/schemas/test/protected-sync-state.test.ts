import { describe, expect, it } from 'vitest';

import {
  outboundObservationSchema,
  protectedLocalDeviceStateSchema,
} from '../src/index.js';

const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const observation = {
  version: 1,
  observationId: digest,
  kind: 'generic-push',
  batchIdempotencyKey: 'batch-key-0000001',
  requestHash: digest,
  responseHash: digest,
  responseVaultRevision: 7,
  replayFromServerSequence: 3,
  requiredThroughServerSequence: 5,
} as const;

const state = {
  version: 2,
  vaultId: 'vault.1',
  deviceId: 'device.1',
  highestSeenVaultRevision: 7,
  updatedAt: '2026-08-12T00:00:00.000Z',
  outboundObservation: observation,
  lastCompletedObservationId: digest,
} as const;

describe('protectedLocalDeviceStateSchema', () => {
  it('accepts the exact strict v2 state and observation fields', () => {
    expect(protectedLocalDeviceStateSchema.parse(state)).toEqual(state);
    expect(
      outboundObservationSchema.parse({
        ...observation,
        kind: 'template-publication',
      }),
    ).toMatchObject({ kind: 'template-publication' });
  });

  it.each([
    { ...state, version: 1 },
    { ...state, version: undefined },
    { ...state, extra: true },
    { ...state, outboundObservation: { ...observation, extra: true } },
    { ...state, outboundObservation: { ...observation, version: 2 } },
    { ...state, outboundObservation: { ...observation, kind: 'generic' } },
    { ...state, outboundObservation: { ...observation, requestHash: `${digest}A` } },
    {
      ...state,
      outboundObservation: { ...observation, responseHash: digest.slice(1) },
    },
    {
      ...state,
      outboundObservation: { ...observation, observationId: '*'.repeat(43) },
    },
    {
      ...state,
      outboundObservation: {
        ...observation,
        requestHash: `${digest.slice(0, -1)}B`,
      },
    },
    { ...state, highestSeenVaultRevision: 6 },
    {
      ...state,
      outboundObservation: {
        ...observation,
        replayFromServerSequence: 6,
        requiredThroughServerSequence: 5,
      },
    },
  ])('rejects malformed, non-v2, extra, and cross-bound state %#', (candidate) => {
    expect(protectedLocalDeviceStateSchema.safeParse(candidate).success).toBe(false);
  });
});
