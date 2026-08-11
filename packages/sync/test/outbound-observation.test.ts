import {
  changeRecordSchema,
  contentHashForRecord,
  encryptedGroupRecordSchema,
  opaqueMutationSchema,
  syncPushRequestSchema,
  syncPushResponseSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  type DeviceId,
  type VaultId,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  computeOutboundObservationId,
  createOutboundObservation,
  hashOutboundObservationRequest,
  hashOutboundObservationResponse,
  validateOutboundObservationBinding,
} from '../src/index.js';

const vaultId = 'vault.1' as VaultId;
const deviceId = 'device.1' as DeviceId;
const timestamp = '2026-08-12T00:00:00.000Z';

const record = encryptedGroupRecordSchema.parse({
  id: 'group.1',
  vaultId,
  schemaVersion: 1,
  wrappedGroupKey: envelope('wrapped-group-key', 'group-key'),
  encryptedPayload: envelope('group', 'group-payload'),
  templateVersion: 2,
  recordRevision: 1,
  createdAt: timestamp,
  updatedAt: timestamp,
});
const mutation = opaqueMutationSchema.parse({
  entityType: 'group',
  expectedRecordRevision: 0,
  idempotencyKey: 'mutation-key-0001',
  record,
});
const change = changeRecordSchema.parse({
  id: 'change.1',
  vaultId,
  serverSequence: 5,
  entityType: 'group',
  entityId: record.id,
  recordRevision: record.recordRevision,
  operation: 'upsert',
  ciphertextHash: contentHashForRecord(record),
  createdAt: timestamp,
});
const genericRequest = syncPushRequestSchema.parse({
  vaultId,
  batchIdempotencyKey: 'batch-key-0000001',
  mutations: [mutation],
});
const genericResponse = syncPushResponseSchema.parse({
  vaultId,
  serverVaultRevision: 7,
  batchIdempotencyKey: genericRequest.batchIdempotencyKey,
  results: [
    {
      status: 'accepted',
      idempotencyKey: mutation.idempotencyKey,
      disposition: 'committed',
      change,
    },
  ],
});
const templateRequest = templateMigrationPublicationRequestSchema.parse({
  ...genericRequest,
  batchIdempotencyKey: 'template-batch-key-0001',
});
const templateResponse = templateMigrationPublicationResponseSchema.parse({
  vaultId,
  serverVaultRevision: 7,
  batchIdempotencyKey: templateRequest.batchIdempotencyKey,
  results: [{ idempotencyKey: mutation.idempotencyKey, change }],
});

describe('outbound observation digests', () => {
  it('matches golden request, response, and descriptor hashes for generic push', () => {
    expect(hashOutboundObservationRequest('generic-push', genericRequest)).toBe(
      'VdJnac477P4fLiBXe4-_W6TefHRx7pcmqnNaOxBSy3k',
    );
    expect(hashOutboundObservationResponse('generic-push', genericResponse)).toBe(
      'fWthhN941k7yKYu33dSXCjvjn64DwOQzknS3K3S2YuM',
    );
    expect(
      createOutboundObservation({
        kind: 'generic-push',
        vaultId,
        deviceId,
        request: genericRequest,
        response: genericResponse,
        replayFromServerSequence: 3,
      }).observationId,
    ).toBe('w0PKfWTT7NWMq6du2HIhrEUXkPyteyx51z9ZFyYDU1k');
  });

  it('matches golden request, response, and descriptor hashes for template publication', () => {
    expect(
      hashOutboundObservationRequest('template-publication', templateRequest),
    ).toBe('EOeyKDRTAjZ-o398VdE1WkaqP80OEpdj8uzuVdY5Y98');
    expect(
      hashOutboundObservationResponse('template-publication', templateResponse),
    ).toBe('6hLwe4BFqrGLxTKFw8emJRCMwIWou8a0xxgfJ5GHrZo');
    expect(
      createOutboundObservation({
        kind: 'template-publication',
        vaultId,
        deviceId,
        request: templateRequest,
        response: templateResponse,
        replayFromServerSequence: 3,
      }).observationId,
    ).toBe('_j0tz4WA3TokGlg1saqsDgNunoIfQCGbJ9nkAkZSQWQ');
  });

  it('derives every scalar except replayFrom from parsed request/response data', () => {
    const observation = createOutboundObservation({
      kind: 'generic-push',
      vaultId,
      deviceId,
      request: genericRequest,
      response: genericResponse,
      replayFromServerSequence: 3,
    });

    expect(observation).toMatchObject({
      version: 1,
      kind: 'generic-push',
      batchIdempotencyKey: genericRequest.batchIdempotencyKey,
      responseVaultRevision: genericResponse.serverVaultRevision,
      replayFromServerSequence: 3,
      requiredThroughServerSequence: 5,
    });
  });

  it('keeps required-through at replay start for conflict-only or historical results', () => {
    const conflictResponse = syncPushResponseSchema.parse({
      ...genericResponse,
      results: [
        {
          status: 'conflict',
          idempotencyKey: mutation.idempotencyKey,
          currentRevision: record.recordRevision,
          current: record,
        },
      ],
    });
    expect(
      createOutboundObservation({
        kind: 'generic-push',
        vaultId,
        deviceId,
        request: genericRequest,
        response: conflictResponse,
        replayFromServerSequence: 3,
      }).requiredThroughServerSequence,
    ).toBe(3);
    expect(
      createOutboundObservation({
        kind: 'generic-push',
        vaultId,
        deviceId,
        request: genericRequest,
        response: genericResponse,
        replayFromServerSequence: 6,
      }).requiredThroughServerSequence,
    ).toBe(6);
    expect(
      createOutboundObservation({
        kind: 'template-publication',
        vaultId,
        deviceId,
        request: templateRequest,
        response: templateResponse,
        replayFromServerSequence: 6,
      }).requiredThroughServerSequence,
    ).toBe(6);
  });

  it('binds each descriptor field independently into the observation ID', () => {
    const baseline = createOutboundObservation({
      kind: 'generic-push',
      vaultId,
      deviceId,
      request: genericRequest,
      response: genericResponse,
      replayFromServerSequence: 3,
    });
    const { observationId: baselineId, ...content } = baseline;
    const alternateHash = Buffer.alloc(32, 1).toString('base64url');
    const variants = [
      computeOutboundObservationId(vaultId, deviceId, {
        ...content,
        kind: 'template-publication',
      }),
      computeOutboundObservationId('vault.2', deviceId, content),
      computeOutboundObservationId(vaultId, 'device.2', content),
      computeOutboundObservationId(vaultId, deviceId, {
        ...content,
        batchIdempotencyKey: 'batch-key-0000002',
      }),
      computeOutboundObservationId(vaultId, deviceId, {
        ...content,
        responseVaultRevision: 8,
      }),
      computeOutboundObservationId(vaultId, deviceId, {
        ...content,
        replayFromServerSequence: 2,
      }),
      computeOutboundObservationId(vaultId, deviceId, {
        ...content,
        requiredThroughServerSequence: 6,
      }),
      computeOutboundObservationId(vaultId, deviceId, {
        ...content,
        requestHash: alternateHash,
      }),
      computeOutboundObservationId(vaultId, deviceId, {
        ...content,
        responseHash: alternateHash,
      }),
    ];

    expect(new Set(variants)).not.toContain(baselineId);
    expect(new Set(variants).size).toBe(variants.length);
  });

  it('changes request and response hashes when one canonical field changes', () => {
    expect(
      hashOutboundObservationRequest('generic-push', {
        ...genericRequest,
        mutations: [{ ...mutation, idempotencyKey: 'mutation-key-0002' }],
      }),
    ).not.toBe(hashOutboundObservationRequest('generic-push', genericRequest));
    expect(
      hashOutboundObservationResponse('generic-push', {
        ...genericResponse,
        results: [{ ...genericResponse.results[0], disposition: 'duplicate' }],
      }),
    ).not.toBe(hashOutboundObservationResponse('generic-push', genericResponse));
  });

  it('rejects unknown fields, kind/schema mismatch, and response binding mismatch', () => {
    expect(() =>
      hashOutboundObservationRequest('generic-push', {
        ...genericRequest,
        unknown: true,
      }),
    ).toThrow();
    expect(() =>
      hashOutboundObservationRequest('unknown-kind' as never, genericRequest),
    ).toThrow();
    expect(() =>
      hashOutboundObservationResponse('generic-push', {
        ...genericResponse,
        unknown: true,
      }),
    ).toThrow();
    expect(() =>
      createOutboundObservation({
        kind: 'template-publication',
        vaultId,
        deviceId,
        request: genericRequest,
        response: genericResponse,
        replayFromServerSequence: 3,
      }),
    ).toThrow();
    expect(() =>
      createOutboundObservation({
        kind: 'generic-push',
        vaultId,
        deviceId,
        request: genericRequest,
        response: { ...genericResponse, batchIdempotencyKey: 'wrong-batch-key-0001' },
        replayFromServerSequence: 3,
      }),
    ).toThrow();
  });

  it('recomputes and rejects a protected descriptor with any changed bound field', () => {
    const observation = createOutboundObservation({
      kind: 'generic-push',
      vaultId,
      deviceId,
      request: genericRequest,
      response: genericResponse,
      replayFromServerSequence: 3,
    });
    const protectedState = {
      version: 2,
      vaultId,
      deviceId,
      highestSeenVaultRevision: 7,
      updatedAt: timestamp,
      outboundObservation: observation,
    } as const;

    expect(validateOutboundObservationBinding(protectedState)).toEqual(protectedState);
    expect(() =>
      validateOutboundObservationBinding({
        ...protectedState,
        outboundObservation: { ...observation, responseVaultRevision: 8 },
      }),
    ).toThrow();
    expect(() =>
      validateOutboundObservationBinding({
        ...protectedState,
        outboundObservation: {
          ...observation,
          observationId: Buffer.alloc(32, 2).toString('base64url'),
        },
      }),
    ).toThrow();
    expect(() =>
      validateOutboundObservationBinding({
        ...protectedState,
        vaultId: 'vault.2',
      }),
    ).toThrow();
    expect(() =>
      validateOutboundObservationBinding({
        ...protectedState,
        deviceId: 'device.2',
      }),
    ).toThrow();
  });
});

function envelope(
  entityType: 'group' | 'wrapped-group-key',
  label: string,
): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: Buffer.from(label, 'utf8').toString('base64url'),
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType,
      entityId: recordId(entityType),
      purpose: entityType === 'group' ? 'group-payload' : 'group-key',
    },
    keyVersion: 1,
  };
}

function recordId(entityType: 'group' | 'wrapped-group-key'): string {
  return entityType === 'group' ? 'group.1' : 'group.1';
}
