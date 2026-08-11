import { describe, expect, it } from 'vitest';

import {
  aeadEnvelopeSchema,
  apiBearerTokenSchema,
  canonicalJson,
  changeRecordSchema,
  CONTROL_LIST_CURSOR_VERSION,
  controlListCursorPayloadSchema,
  controlListCursorSchema,
  controlListPageQuerySchema,
  decodeControlListCursor,
  DEFAULT_CONTROL_LIST_PAGE_SIZE,
  deviceListPageResponseSchema,
  deviceListResponseSchema,
  encodeControlListCursor,
  enrollmentCompleteRequestSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  healthResponseSchema,
  inviteIssueRequestSchema,
  inviteIssueResponseSchema,
  inviteListPageResponseSchema,
  inviteRedeemResponseSchema,
  MAX_CONTROL_LIST_CURSOR_CHARS,
  MAX_CONTROL_LIST_PAGE_SIZE,
  publicDeviceRecordSchema,
  publicInviteRecordSchema,
  opaqueMutationSchema,
  syncPullQuerySchema,
  syncPullResponseSchema,
  syncPulledChangeSchema,
  syncCursorSchema,
  timestampSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  vaultBootstrapRequestSchema,
  vaultIdSchema,
  vaultRecordSchema,
} from '../src/index.js';

const inviteCursorGolden =
  'eyJjcmVhdGVkQXQiOiIyMDI2LTA4LTExVDAwOjAwOjAwLjAwMFoiLCJpZCI6Imludml0ZS4xIiwicmVzb3VyY2UiOiJpbnZpdGVzIiwidmF1bHRJZCI6InZhdWx0LjEiLCJ2ZXJzaW9uIjoxfQ';

function publicInvite(
  index: number,
  vaultId = 'vault.1',
): ReturnType<typeof publicInviteRecordSchema.parse> {
  return publicInviteRecordSchema.parse({
    id: `invite.${String(index)}`,
    vaultId,
    issuedByDeviceId: 'device.issuer',
    scopes: ['sync:read'],
    state: 'active',
    createdAt: '2026-08-11T00:00:00.000Z',
    expiresAt: '2026-08-12T00:00:00.000Z',
  });
}

function publicDevice(
  index: number,
  vaultId = 'vault.1',
): ReturnType<typeof publicDeviceRecordSchema.parse> {
  return publicDeviceRecordSchema.parse({
    id: `device.${String(index)}`,
    vaultId,
    schemaVersion: 1,
    tokenVersion: 1,
    scopes: ['sync:read'],
    createdAt: '2026-08-11T00:00:00.000Z',
  });
}

function rawJsonCursor(json: string): string {
  return Buffer.from(json, 'utf8').toString('base64url');
}

function deviceLabelEnvelope(
  vaultId: string,
  deviceId: string,
  schemaVersion = 1,
): Readonly<Record<string, unknown>> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion,
      keyVersion: 1,
      vaultId,
      entityType: 'device-label',
      entityId: deviceId,
      purpose: 'device-label',
    },
    keyVersion: 1,
  } as const;
}

describe('API wire contracts', () => {
  it('uses one strict health response contract', () => {
    expect(healthResponseSchema.parse({ status: 'ok' })).toEqual({ status: 'ok' });
    expect(
      healthResponseSchema.safeParse({ status: 'ok', detail: 'internal' }).success,
    ).toBe(false);
  });

  it('accepts only canonical 256-bit bearer tokens', () => {
    const token = Buffer.alloc(32, 7).toString('base64url');
    expect(apiBearerTokenSchema.parse(token)).toBe(token);
    for (const malformed of ['', `${token}=`, token.slice(1), 'a'.repeat(43)]) {
      expect(apiBearerTokenSchema.safeParse(malformed).success).toBe(false);
    }
  });

  it('requires unique bounded invite scopes', () => {
    expect(
      inviteIssueRequestSchema.safeParse({
        scopes: ['sync:read', 'sync:write'],
        expiresInSeconds: 600,
      }).success,
    ).toBe(true);
    expect(
      inviteIssueRequestSchema.safeParse({
        scopes: ['sync:read', 'sync:read'],
        expiresInSeconds: 600,
      }).success,
    ).toBe(false);
  });

  it('exposes opaque invite identity and lifecycle without token hashes', () => {
    const token = apiBearerTokenSchema.parse(Buffer.alloc(32, 9).toString('base64url'));
    expect(
      inviteIssueResponseSchema.parse({
        inviteId: 'invite-1',
        inviteToken: token,
        expiresAt: '2026-08-10T00:10:00.000Z',
      }),
    ).toMatchObject({ inviteId: 'invite-1' });
    const active = publicInviteRecordSchema.parse({
      id: 'invite-1',
      vaultId: 'vault-1',
      issuedByDeviceId: 'device-1',
      scopes: ['sync:read'],
      state: 'active',
      createdAt: '2026-08-10T00:00:00.000Z',
      expiresAt: '2026-08-10T00:10:00.000Z',
    });
    expect(JSON.stringify(active)).not.toContain('tokenHash');
    expect(
      publicInviteRecordSchema.safeParse({
        ...active,
        state: 'revoked',
      }).success,
    ).toBe(false);
  });

  it('binds the redeemed public vault to the invite vault', () => {
    const vault = currentVaultRecord('vault-redeemed');
    expect(
      inviteRedeemResponseSchema.parse({
        vaultId: vault.id,
        expiresAt: '2026-08-10T00:10:00.000Z',
        vault,
      }),
    ).toMatchObject({ vaultId: vault.id, vault });
    expect(
      inviteRedeemResponseSchema.safeParse({
        vaultId: 'vault-other',
        expiresAt: '2026-08-10T00:10:00.000Z',
        vault,
      }).success,
    ).toBe(false);
  });

  it('parses the actual hash-free public device wire shape', () => {
    const device = {
      id: 'device-public-wire',
      vaultId: 'vault-public-wire',
      schemaVersion: 1,
      tokenVersion: 1,
      scopes: ['sync:read'] as const,
      createdAt: '2026-08-10T00:00:00.000Z',
    };
    expect(deviceListResponseSchema.parse({ devices: [device] })).toEqual({
      devices: [device],
    });
    expect(
      deviceListResponseSchema.safeParse({
        devices: [
          {
            ...device,
            tokenHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          },
        ],
      }).success,
    ).toBe(false);
  });

  it('pins enrollment and first-device bootstrap inputs to current schema labels', () => {
    const label = deviceLabelEnvelope('vault.bootstrap', 'device.bootstrap');
    const enrollment = {
      vaultId: 'vault.bootstrap',
      deviceId: 'device.bootstrap',
      schemaVersion: 1,
      encryptedLabel: label,
    };
    const initialVault = vaultRecordSchema.parse({
      ...currentVaultRecord('vault.bootstrap'),
      revision: 0,
    });
    const bootstrap = {
      vault: initialVault,
      device: {
        id: 'device.bootstrap',
        schemaVersion: 1,
        encryptedLabel: label,
      },
    };

    expect(enrollmentCompleteRequestSchema.safeParse(enrollment).success).toBe(true);
    expect(
      enrollmentCompleteRequestSchema.safeParse({
        ...enrollment,
        schemaVersion: 2,
      }).success,
    ).toBe(false);
    expect(vaultBootstrapRequestSchema.safeParse(bootstrap).success).toBe(true);
    expect(
      vaultBootstrapRequestSchema.safeParse({
        ...bootstrap,
        device: { ...bootstrap.device, schemaVersion: 2 },
      }).success,
    ).toBe(false);
    for (const schema of [
      enrollmentCompleteRequestSchema,
      vaultBootstrapRequestSchema,
    ]) {
      const oversizedLabel = { ...label, ciphertext: 'A'.repeat(4_098) };
      const candidate =
        schema === enrollmentCompleteRequestSchema
          ? { ...enrollment, encryptedLabel: oversizedLabel }
          : {
              ...bootstrap,
              device: { ...bootstrap.device, encryptedLabel: oversizedLabel },
            };
      expect(schema.safeParse(candidate).success).toBe(false);
    }
  });

  it.each([
    ['vaultId', deviceLabelEnvelope('vault.label-other', 'device.label-binding')],
    ['entityId', deviceLabelEnvelope('vault.label-binding', 'device.label-other')],
    [
      'schemaVersion',
      deviceLabelEnvelope('vault.label-binding', 'device.label-binding', 2),
    ],
  ])('rejects enrollment labels with unbound %s AAD', (_dimension, encryptedLabel) => {
    expect(
      enrollmentCompleteRequestSchema.safeParse({
        vaultId: 'vault.label-binding',
        deviceId: 'device.label-binding',
        schemaVersion: 1,
        encryptedLabel,
      }).success,
    ).toBe(false);
  });

  it.each([
    ['vaultId', deviceLabelEnvelope('vault.label-other', 'device.label-binding')],
    ['entityId', deviceLabelEnvelope('vault.label-binding', 'device.label-other')],
    [
      'schemaVersion',
      deviceLabelEnvelope('vault.label-binding', 'device.label-binding', 2),
    ],
  ])('rejects bootstrap labels with unbound %s AAD', (_dimension, encryptedLabel) => {
    const vault = vaultRecordSchema.parse({
      ...currentVaultRecord('vault.label-binding'),
      revision: 0,
    });
    expect(
      vaultBootstrapRequestSchema.safeParse({
        vault,
        device: {
          id: 'device.label-binding',
          schemaVersion: 1,
          encryptedLabel,
        },
      }).success,
    ).toBe(false);
  });

  it('strictly parses bounded control-list query strings', () => {
    expect(controlListPageQuerySchema.parse({})).toEqual({
      limit: DEFAULT_CONTROL_LIST_PAGE_SIZE,
    });
    expect(controlListPageQuerySchema.parse({ limit: '1' })).toEqual({ limit: 1 });
    expect(controlListPageQuerySchema.parse({ limit: '200' })).toEqual({ limit: 200 });
    expect(CONTROL_LIST_CURSOR_VERSION).toBe(1);
    expect(MAX_CONTROL_LIST_PAGE_SIZE).toBe(200);
    expect(MAX_CONTROL_LIST_CURSOR_CHARS).toBe(512);

    for (const limit of [
      '0',
      '201',
      '01',
      '+1',
      '-1',
      ' 1',
      '1 ',
      '1.0',
      '1e2',
      '',
      1,
    ]) {
      expect(controlListPageQuerySchema.safeParse({ limit }).success).toBe(false);
    }
    expect(controlListPageQuerySchema.safeParse({ cursor: '' }).success).toBe(false);
    expect(controlListPageQuerySchema.safeParse({ cursor: 'AA' }).success).toBe(false);
    expect(
      controlListPageQuerySchema.safeParse({ limit: '1', unexpected: 'value' }).success,
    ).toBe(false);

    const maximumCursor = encodeControlListCursor({
      version: 1,
      resource: 'invites',
      vaultId: `v${'a'.repeat(127)}`,
      createdAt: `2026-08-11T00:00:00.${'0'.repeat(37)}Z`,
      id: `i${'a'.repeat(127)}`,
    });
    expect(maximumCursor).toHaveLength(MAX_CONTROL_LIST_CURSOR_CHARS);
    expect(controlListCursorSchema.safeParse(maximumCursor).success).toBe(true);
    expect(controlListPageQuerySchema.parse({ cursor: maximumCursor })).toEqual({
      limit: DEFAULT_CONTROL_LIST_PAGE_SIZE,
      cursor: maximumCursor,
    });
    expect(() =>
      encodeControlListCursor({
        version: 1,
        resource: 'invites',
        vaultId: `v${'a'.repeat(127)}`,
        createdAt: `2026-08-11T00:00:00.${'0'.repeat(38)}Z`,
        id: `i${'a'.repeat(127)}`,
      }),
    ).toThrow();
  });

  it('round-trips deterministic invite and device cursors with a literal golden', () => {
    const invitePayload = controlListCursorPayloadSchema.parse({
      version: CONTROL_LIST_CURSOR_VERSION,
      resource: 'invites',
      vaultId: 'vault.1',
      createdAt: '2026-08-11T00:00:00.000Z',
      id: 'invite.1',
    });
    const inviteCursor = encodeControlListCursor(invitePayload);

    expect(inviteCursor).toBe(inviteCursorGolden);
    expect(decodeControlListCursor(inviteCursor)).toEqual(invitePayload);
    expect(encodeControlListCursor(decodeControlListCursor(inviteCursor))).toBe(
      inviteCursor,
    );

    const devicePayload = controlListCursorPayloadSchema.parse({
      version: CONTROL_LIST_CURSOR_VERSION,
      resource: 'devices',
      vaultId: 'vault.1',
      createdAt: '2026-08-11T00:00:00.000Z',
      id: 'device.1',
    });
    const deviceCursor = encodeControlListCursor(devicePayload);
    expect(decodeControlListCursor(deviceCursor)).toEqual(devicePayload);
    expect(encodeControlListCursor(devicePayload)).toBe(deviceCursor);
  });

  it('rejects malformed, unsupported, and noncanonical cursor payloads', () => {
    const canonicalPayload = {
      version: 1,
      resource: 'invites',
      vaultId: 'vault.1',
      createdAt: '2026-08-11T00:00:00.000Z',
      id: 'invite.1',
    };
    const canonicalText = Buffer.from(inviteCursorGolden, 'base64url').toString('utf8');
    const invalidCursors = [
      `${inviteCursorGolden}=`,
      rawJsonCursor(` ${canonicalText}`),
      rawJsonCursor(JSON.stringify(canonicalPayload)),
      rawJsonCursor(
        '{"createdAt":"2026-08-11T00:00:00.000Z","id":"invite.1","resource":"invites","vaultId":"vault.1","version":1,"version":1}',
      ),
      rawJsonCursor(canonicalJson({ ...canonicalPayload, extra: true })),
      rawJsonCursor(canonicalJson({ ...canonicalPayload, version: 2 })),
      rawJsonCursor(canonicalJson({ ...canonicalPayload, resource: 'groups' })),
      rawJsonCursor('{'),
      Buffer.from([0xc3, 0x28]).toString('base64url'),
      'AB',
    ];

    for (const cursor of invalidCursors) {
      expect(() => decodeControlListCursor(cursor)).toThrow();
      expect(() => controlListCursorSchema.safeParse(cursor)).not.toThrow();
      expect(controlListCursorSchema.safeParse(cursor).success).toBe(false);
    }

    const canary = 'cursor-error-canary-7f9d';
    const canaryCursor = rawJsonCursor(
      canonicalJson({ ...canonicalPayload, unexpected: canary }),
    );
    let caught: unknown;
    try {
      decodeControlListCursor(canaryCursor);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(TypeError);
    if (!(caught instanceof TypeError)) {
      throw new Error('Expected a generic cursor TypeError');
    }
    expect(caught.message).toBe('Invalid control-list cursor');
    expect(caught.message).not.toContain(canary);
    expect(caught.message).not.toContain(canaryCursor);
    expect(Object.hasOwn(caught, 'cause')).toBe(false);
  });

  it('bounds additive invite and device page response sizes', () => {
    for (const size of [0, 1, MAX_CONTROL_LIST_PAGE_SIZE]) {
      expect(
        inviteListPageResponseSchema.safeParse({
          invites: Array.from({ length: size }, (_, index) => publicInvite(index)),
          nextCursor: null,
        }).success,
      ).toBe(true);
      expect(
        deviceListPageResponseSchema.safeParse({
          devices: Array.from({ length: size }, (_, index) => publicDevice(index)),
          nextCursor: null,
        }).success,
      ).toBe(true);
    }
    expect(
      inviteListPageResponseSchema.safeParse({
        invites: Array.from({ length: MAX_CONTROL_LIST_PAGE_SIZE + 1 }, (_, index) =>
          publicInvite(index),
        ),
        nextCursor: null,
      }).success,
    ).toBe(false);
    expect(
      deviceListPageResponseSchema.safeParse({
        devices: Array.from({ length: MAX_CONTROL_LIST_PAGE_SIZE + 1 }, (_, index) =>
          publicDevice(index),
        ),
        nextCursor: null,
      }).success,
    ).toBe(false);
  });

  it('binds page cursors to the final row resource, vault, time, and ID', () => {
    const invites = [publicInvite(1), publicInvite(2)];
    const devices = [publicDevice(1), publicDevice(2)];
    const firstInvite = invites[0];
    const finalInvite = invites.at(-1);
    const finalDevice = devices.at(-1);
    if (
      firstInvite === undefined ||
      finalInvite === undefined ||
      finalDevice === undefined
    ) {
      throw new Error('Expected nonempty control-list fixtures');
    }
    const inviteCursor = encodeControlListCursor(
      controlListCursorPayloadSchema.parse({
        version: 1,
        resource: 'invites',
        vaultId: finalInvite.vaultId,
        createdAt: finalInvite.createdAt,
        id: finalInvite.id,
      }),
    );
    const deviceCursor = encodeControlListCursor(
      controlListCursorPayloadSchema.parse({
        version: 1,
        resource: 'devices',
        vaultId: finalDevice.vaultId,
        createdAt: finalDevice.createdAt,
        id: finalDevice.id,
      }),
    );
    const cursorForFirstInvite = encodeControlListCursor(
      controlListCursorPayloadSchema.parse({
        version: 1,
        resource: 'invites',
        vaultId: firstInvite.vaultId,
        createdAt: firstInvite.createdAt,
        id: firstInvite.id,
      }),
    );

    expect(
      inviteListPageResponseSchema.safeParse({ invites, nextCursor: inviteCursor })
        .success,
    ).toBe(true);
    expect(
      deviceListPageResponseSchema.safeParse({ devices, nextCursor: deviceCursor })
        .success,
    ).toBe(true);
    expect(inviteListPageResponseSchema.safeParse({ invites }).success).toBe(false);
    expect(
      inviteListPageResponseSchema.safeParse({
        invites,
        nextCursor: null,
        unexpected: true,
      }).success,
    ).toBe(false);
    expect(
      inviteListPageResponseSchema.safeParse({ invites, nextCursor: 'AA' }).success,
    ).toBe(false);
    expect(
      inviteListPageResponseSchema.safeParse({
        invites,
        nextCursor: cursorForFirstInvite,
      }).success,
    ).toBe(false);
    expect(
      inviteListPageResponseSchema.safeParse({ invites, nextCursor: deviceCursor })
        .success,
    ).toBe(false);
    for (const mismatch of [
      { vaultId: 'vault.other' },
      { createdAt: '2026-08-11T00:00:00Z' },
    ]) {
      const mismatchedCursor = encodeControlListCursor({
        version: 1,
        resource: 'invites',
        vaultId: finalInvite.vaultId,
        createdAt: finalInvite.createdAt,
        id: finalInvite.id,
        ...mismatch,
      });
      expect(
        inviteListPageResponseSchema.safeParse({
          invites,
          nextCursor: mismatchedCursor,
        }).success,
      ).toBe(false);
    }
    expect(
      deviceListPageResponseSchema.safeParse({ devices, nextCursor: inviteCursor })
        .success,
    ).toBe(false);
    expect(
      inviteListPageResponseSchema.safeParse({
        invites: [invites[0], publicInvite(2, 'vault.other')],
        nextCursor: null,
      }).success,
    ).toBe(false);
    expect(
      inviteListPageResponseSchema.safeParse({
        invites: [],
        nextCursor: inviteCursor,
      }).success,
    ).toBe(false);
  });

  it('strictly parses bounded sync query strings', () => {
    expect(
      syncPullQuerySchema.parse({
        serverSequence: '0',
        highestSeenVaultRevision: '2',
        limit: '50',
      }),
    ).toMatchObject({
      serverSequence: 0,
      highestSeenVaultRevision: 2,
      limit: 50,
    });
    expect(
      syncPullQuerySchema.safeParse({
        serverSequence: '0',
        highestSeenVaultRevision: '2',
        limit: '501',
      }).success,
    ).toBe(false);
  });

  it('binds paginated purge records and cursors to one vault', () => {
    const vaultId = vaultIdSchema.parse('vault-api-contract');
    const change = changeRecordSchema.parse({
      id: 'change-api-contract',
      vaultId,
      serverSequence: 1,
      recordRevision: 1,
      operation: 'purge',
      createdAt: timestampSchema.parse('2026-08-10T00:00:00.000Z'),
      entityType: 'group',
      entityId: 'group-api-contract',
    });
    const nextCursor = syncCursorSchema.parse({
      vaultId,
      serverSequence: 1,
      highestSeenVaultRevision: 2,
    });
    expect(
      syncPullResponseSchema.parse({
        vaultId,
        serverVaultRevision: 2,
        changes: [{ change, record: null }],
        nextCursor,
        hasMore: false,
      }),
    ).toMatchObject({ vaultId, nextCursor });
    expect(
      syncPullResponseSchema.safeParse({
        vaultId,
        serverVaultRevision: 1,
        changes: [{ change, record: null }],
        nextCursor,
        hasMore: false,
      }).success,
    ).toBe(false);
  });

  it('requires current encrypted records for upsert and restore changes', () => {
    const current = currentGroupRecord();
    const baseChange = {
      id: 'change-current-record',
      vaultId: current.vaultId,
      serverSequence: 1,
      recordRevision: current.recordRevision,
      ciphertextHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      createdAt: current.updatedAt,
      entityType: 'group' as const,
      entityId: current.id,
    };
    for (const operation of ['upsert', 'restore'] as const) {
      expect(
        syncPulledChangeSchema.safeParse({
          change: { ...baseChange, operation },
          record: current,
        }).success,
      ).toBe(true);
      expect(
        syncPulledChangeSchema.safeParse({
          change: { ...baseChange, operation },
          record: { ...current, tombstonedAt: current.updatedAt },
        }).success,
      ).toBe(false);
    }

    const restoredTombstone = {
      vaultId: current.vaultId,
      entityType: 'group',
      entityId: current.id,
      state: 'restored',
      tombstoneRevision: current.recordRevision,
      lastRecordRevision: current.recordRevision - 1,
      lastCiphertextHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      deletedAt: current.createdAt,
      restoredAt: current.updatedAt,
    };
    expect(
      syncPulledChangeSchema.safeParse({
        change: { ...baseChange, operation: 'restore' },
        record: restoredTombstone,
      }).success,
    ).toBe(false);
    expect(
      syncPulledChangeSchema.safeParse({
        change: { ...baseChange, operation: 'tombstone' },
        record: { ...restoredTombstone, state: 'deleted', restoredAt: undefined },
      }).success,
    ).toBe(true);
  });

  it('strictly binds one ordered opaque template migration and its response', () => {
    const currentGroup = currentGroupRecord();
    const currentItem = currentItemRecord(currentGroup);
    const itemMutation = opaqueMutationSchema.parse({
      entityType: 'item',
      expectedRecordRevision: currentItem.recordRevision,
      idempotencyKey: 'migration-item-key-0001',
      record: encryptedItemRecordSchema.parse({
        ...currentItem,
        recordRevision: currentItem.recordRevision + 1,
        updatedAt: '2026-08-10T00:02:00.000Z',
      }),
    });
    const groupMutation = opaqueMutationSchema.parse({
      entityType: 'group',
      expectedRecordRevision: currentGroup.recordRevision,
      idempotencyKey: 'migration-group-key-001',
      record: encryptedGroupRecordSchema.parse({
        ...currentGroup,
        templateVersion: currentGroup.templateVersion + 1,
        recordRevision: currentGroup.recordRevision + 1,
        updatedAt: '2026-08-10T00:02:00.000Z',
      }),
    });
    if (itemMutation.entityType !== 'item' || groupMutation.entityType !== 'group') {
      throw new Error('Expected canonical item and group mutations');
    }
    const request = templateMigrationPublicationRequestSchema.parse({
      vaultId: currentGroup.vaultId,
      batchIdempotencyKey: 'migration-batch-key-001',
      mutations: [itemMutation, groupMutation],
    });
    expect(request.mutations.map(({ entityType }) => entityType)).toEqual([
      'item',
      'group',
    ]);
    for (const mutations of [
      [groupMutation, itemMutation],
      [itemMutation],
      [itemMutation, itemMutation, groupMutation],
      [
        {
          ...itemMutation,
          record: {
            ...itemMutation.record,
            tombstonedAt: itemMutation.record.updatedAt,
          },
        },
        groupMutation,
      ],
    ]) {
      expect(
        templateMigrationPublicationRequestSchema.safeParse({
          ...request,
          mutations,
        }).success,
      ).toBe(false);
    }

    const itemChange = changeRecordSchema.parse({
      id: 'change-template-item',
      vaultId: request.vaultId,
      serverSequence: 8,
      entityType: 'item',
      entityId: itemMutation.record.id,
      recordRevision: itemMutation.record.recordRevision,
      operation: 'upsert',
      ciphertextHash: itemMutation.record.ciphertextHash,
      createdAt: itemMutation.record.updatedAt,
    });
    const groupChange = changeRecordSchema.parse({
      id: 'change-template-group',
      vaultId: request.vaultId,
      serverSequence: 9,
      entityType: 'group',
      entityId: groupMutation.record.id,
      recordRevision: groupMutation.record.recordRevision,
      operation: 'upsert',
      ciphertextHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      createdAt: groupMutation.record.updatedAt,
    });
    expect(
      templateMigrationPublicationResponseSchema.parse({
        vaultId: request.vaultId,
        batchIdempotencyKey: request.batchIdempotencyKey,
        serverVaultRevision: 9,
        results: [
          { idempotencyKey: itemMutation.idempotencyKey, change: itemChange },
          { idempotencyKey: groupMutation.idempotencyKey, change: groupChange },
        ],
      }),
    ).toMatchObject({ serverVaultRevision: 9 });
  });
});

function currentItemRecord(
  group: ReturnType<typeof encryptedGroupRecordSchema.parse>,
): ReturnType<typeof encryptedItemRecordSchema.parse> {
  const itemId = 'item-current-record';
  const envelope = (
    entityType: 'item' | 'wrapped-item-key',
    purpose: 'item-payload' | 'item-key',
  ): ReturnType<typeof aeadEnvelopeSchema.parse> =>
    aeadEnvelopeSchema.parse({
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      ciphertext: 'AQID',
      authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId: group.vaultId,
        entityType,
        entityId: itemId,
        groupId: group.id,
        purpose,
      },
      keyVersion: 1,
    });
  return encryptedItemRecordSchema.parse({
    id: itemId,
    vaultId: group.vaultId,
    groupId: group.id,
    schemaVersion: 1,
    wrappedItemKey: envelope('wrapped-item-key', 'item-key'),
    encryptedPayload: envelope('item', 'item-payload'),
    recordRevision: 2,
    ciphertextHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    createdAt: '2026-08-10T00:00:00.000Z',
    updatedAt: '2026-08-10T00:01:00.000Z',
  });
}

function currentGroupRecord(): ReturnType<typeof encryptedGroupRecordSchema.parse> {
  const vaultId = vaultIdSchema.parse('vault-current-record');
  const groupId = 'group-current-record';
  const updatedAt = timestampSchema.parse('2026-08-10T00:01:00.000Z');
  const envelope = (
    entityType: 'group' | 'wrapped-group-key',
    purpose: 'group-payload' | 'group-key',
  ): ReturnType<typeof aeadEnvelopeSchema.parse> =>
    aeadEnvelopeSchema.parse({
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
        entityId: groupId,
        purpose,
      },
      keyVersion: 1,
    });
  return encryptedGroupRecordSchema.parse({
    id: groupId,
    vaultId,
    schemaVersion: 1,
    wrappedGroupKey: envelope('wrapped-group-key', 'group-key'),
    encryptedPayload: envelope('group', 'group-payload'),
    templateVersion: 1,
    recordRevision: 2,
    createdAt: '2026-08-10T00:00:00.000Z',
    updatedAt,
  });
}

function currentVaultRecord(id: string): ReturnType<typeof vaultRecordSchema.parse> {
  const vaultId = vaultIdSchema.parse(id);
  const slotId = 'slot-redeemed';
  return vaultRecordSchema.parse({
    id: vaultId,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [
      {
        slotVersion: 1,
        id: slotId,
        type: 'portable-key',
        state: 'active',
        keyVersion: 1,
        derivation: {
          algorithm: 'hkdf-sha256',
          version: 1,
          salt: Buffer.alloc(32).toString('base64url'),
          context: 'credvault/v1/portable-key-wrap',
          outputLength: 32,
        },
        wrappedRootKey: aeadEnvelopeSchema.parse({
          version: 1,
          algorithm: 'xchacha20-poly1305-ietf',
          nonce: Buffer.alloc(24).toString('base64url'),
          ciphertext: 'AQID',
          authenticationTag: Buffer.alloc(16).toString('base64url'),
          aad: {
            version: 1,
            schemaVersion: 1,
            keyVersion: 1,
            vaultId,
            entityType: 'wrapped-root-key',
            entityId: slotId,
            purpose: 'vrk-slot',
          },
          keyVersion: 1,
        }),
        createdAt: '2026-08-10T00:00:00.000Z',
      },
    ],
    currentKeyVersion: 1,
    revision: 1,
    encryptedPreferences: aeadEnvelopeSchema.parse({
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: Buffer.alloc(24).toString('base64url'),
      ciphertext: 'AQID',
      authenticationTag: Buffer.alloc(16).toString('base64url'),
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId,
        entityType: 'vault-preferences',
        entityId: vaultId,
        purpose: 'vault-preferences',
      },
      keyVersion: 1,
    }),
    createdAt: '2026-08-10T00:00:00.000Z',
    updatedAt: '2026-08-10T00:00:00.000Z',
  });
}
