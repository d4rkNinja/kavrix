import { describe, expect, expectTypeOf, it } from 'vitest';

import {
  aeadEnvelopeSchema,
  encryptedAttachmentRecordSchema,
  encryptedAuditRecordSchema,
  encryptedGroupRecordSchema,
  encryptedHistoryRecordSchema,
  encryptedItemRecordSchema,
  encryptedRecordSchema,
  keySlotSchema,
  vaultRecordSchema,
  type AssociatedData,
  type AttachmentId,
  type AuditEventId,
  type DeviceId,
  type GroupId,
  type HistoryId,
  type ItemId,
  type KeySlotId,
  type VaultId,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const purposeByEntity = {
  'vault-preferences': 'vault-preferences',
  group: 'group-payload',
  item: 'item-payload',
  attachment: 'attachment-metadata',
  'attachment-chunk': 'attachment-chunk',
  'audit-event': 'audit-event',
  history: 'history-event',
  'device-label': 'device-label',
  'wrapped-root-key': 'vrk-slot',
  'wrapped-group-key': 'group-key',
  'wrapped-item-key': 'item-key',
  'wrapped-attachment-key': 'attachment-key',
} as const;

type EntityType = keyof typeof purposeByEntity;

function envelope(
  entityType: EntityType,
  entityId: string,
  options: {
    vaultId?: string;
    schemaVersion?: number;
    keyVersion?: number;
    groupId?: string;
    parentId?: string;
  } = {},
): Record<string, unknown> {
  const keyVersion = options.keyVersion ?? 1;
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: options.schemaVersion ?? 1,
      keyVersion,
      vaultId: options.vaultId ?? 'vault.1',
      entityType,
      entityId,
      ...(options.groupId === undefined ? {} : { groupId: options.groupId }),
      ...(options.parentId === undefined ? {} : { parentId: options.parentId }),
      purpose: purposeByEntity[entityType],
    },
    keyVersion,
  };
}

function slot(
  id: string,
  state: 'pending' | 'active' | 'superseded' | 'revoked' = 'active',
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id,
    slotVersion: 1,
    type: 'portable-key',
    state,
    keyVersion: 1,
    derivation: {
      algorithm: 'hkdf-sha256',
      version: 1,
      salt: digest,
      context: 'credvault/v1/portable-key-wrap',
      outputLength: 32,
    },
    wrappedRootKey: envelope('wrapped-root-key', id),
    createdAt: timestamp,
    ...(state === 'superseded' ? { supersededAt: timestamp } : {}),
    ...(state === 'revoked' ? { revokedAt: timestamp } : {}),
    ...overrides,
  };
}

describe('authenticated envelope contracts', () => {
  it('brands every associated-data identity role by discriminator', () => {
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'vault-preferences' }>['entityId']
    >().toEqualTypeOf<VaultId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'group' }>['entityId']
    >().toEqualTypeOf<GroupId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'item' }>['entityId']
    >().toEqualTypeOf<ItemId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'attachment' }>['entityId']
    >().toEqualTypeOf<AttachmentId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'attachment' }>['parentId']
    >().toEqualTypeOf<ItemId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'attachment-chunk' }>['entityId']
    >().toEqualTypeOf<AttachmentId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'attachment-chunk' }>['parentId']
    >().toEqualTypeOf<ItemId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'audit-event' }>['entityId']
    >().toEqualTypeOf<AuditEventId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'history' }>['entityId']
    >().toEqualTypeOf<HistoryId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'device-label' }>['entityId']
    >().toEqualTypeOf<DeviceId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'wrapped-root-key' }>['entityId']
    >().toEqualTypeOf<KeySlotId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'wrapped-group-key' }>['entityId']
    >().toEqualTypeOf<GroupId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'wrapped-item-key' }>['entityId']
    >().toEqualTypeOf<ItemId>();
    expectTypeOf<
      Extract<AssociatedData, { entityType: 'wrapped-attachment-key' }>['entityId']
    >().toEqualTypeOf<AttachmentId>();
  });
  it('accepts every closed associated-data binding shape', () => {
    const cases: readonly (readonly [EntityType, string, object?])[] = [
      ['vault-preferences', 'vault.1'],
      ['group', 'group.1'],
      ['item', 'item.1', { groupId: 'group.1' }],
      ['attachment', 'attachment.1', { groupId: 'group.1', parentId: 'item.1' }],
      ['attachment-chunk', 'attachment.1', { groupId: 'group.1', parentId: 'item.1' }],
      ['audit-event', 'audit.1'],
      ['history', 'history.1', { groupId: 'group.1', parentId: 'item.1' }],
      ['device-label', 'device.1'],
      ['wrapped-root-key', 'slot.1'],
      ['wrapped-group-key', 'group.1'],
      ['wrapped-item-key', 'item.1', { groupId: 'group.1' }],
      [
        'wrapped-attachment-key',
        'attachment.1',
        { groupId: 'group.1', parentId: 'item.1' },
      ],
    ];
    for (const [type, id, options = {}] of cases) {
      expect(aeadEnvelopeSchema.safeParse(envelope(type, id, options)).success).toBe(
        true,
      );
    }
  });

  it('rejects malformed cryptographic lengths and unauthenticated key versions', () => {
    const valid = envelope('group', 'group.1');
    for (const candidate of [
      { ...valid, nonce: 'short' },
      { ...valid, authenticationTag: 'short' },
      { ...valid, keyVersion: 2 },
    ]) {
      expect(aeadEnvelopeSchema.safeParse(candidate).success).toBe(false);
    }
  });
});

describe('unlock-slot state bindings', () => {
  it('accepts every derivation type with its required metadata', () => {
    const cases = [
      slot('slot.portable'),
      slot('slot.passphrase', 'active', {
        type: 'passphrase',
        derivation: {
          algorithm: 'argon2id',
          version: 1,
          salt: 'AAAAAAAAAAAAAAAAAAAAAA',
          memoryKiB: 65_536,
          passes: 3,
          parallelism: 4,
          outputLength: 32,
        },
        wrappedRootKey: envelope('wrapped-root-key', 'slot.passphrase'),
      }),
      slot('slot.recovery', 'active', {
        type: 'recovery-key',
        derivation: {
          algorithm: 'hkdf-sha256',
          version: 1,
          salt: digest,
          context: 'credvault/v1/recovery-key-wrap',
          outputLength: 32,
        },
        wrappedRootKey: envelope('wrapped-root-key', 'slot.recovery'),
      }),
      slot('slot.device', 'active', {
        type: 'device-key',
        deviceId: 'device.1',
        derivation: {
          algorithm: 'hkdf-sha256',
          version: 1,
          salt: digest,
          context: 'credvault/v1/device-key-wrap',
          outputLength: 32,
          provider: 'native-keychain',
        },
        wrappedRootKey: envelope('wrapped-root-key', 'slot.device'),
      }),
    ];
    expect(cases.every((candidate) => keySlotSchema.safeParse(candidate).success)).toBe(
      true,
    );
  });

  it('requires timestamps to agree exactly with terminal slot states', () => {
    const invalid = [
      slot('slot.revoked', 'revoked', { revokedAt: undefined }),
      slot('slot.active-revoked', 'active', { revokedAt: timestamp }),
      slot('slot.superseded', 'superseded', { supersededAt: undefined }),
      slot('slot.active-superseded', 'active', { supersededAt: timestamp }),
      slot('slot.wrong-type', 'active', {
        wrappedRootKey: envelope('group', 'slot.wrong-type'),
      }),
      slot('slot.wrong-version', 'active', {
        wrappedRootKey: envelope('wrapped-root-key', 'slot.wrong-version', {
          keyVersion: 2,
        }),
      }),
    ];
    for (const candidate of invalid) {
      expect(keySlotSchema.safeParse(candidate).success).toBe(false);
    }
    expect(keySlotSchema.safeParse(slot('slot.revoked', 'revoked')).success).toBe(true);
    expect(keySlotSchema.safeParse(slot('slot.superseded', 'superseded')).success).toBe(
      true,
    );
  });
});

describe('vault and opaque record bindings', () => {
  const vault = {
    id: 'vault.1',
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [slot('slot.1')],
    currentKeyVersion: 1,
    revision: 0,
    encryptedPreferences: envelope('vault-preferences', 'vault.1'),
    createdAt: timestamp,
    updatedAt: timestamp,
  };

  it('rejects duplicate, inactive, stale, cross-vault, and cross-schema slots', () => {
    const invalid = [
      { ...vault, keySlots: [slot('slot.1'), slot('slot.1')] },
      { ...vault, keySlots: [slot('slot.1', 'revoked')] },
      { ...vault, currentKeyVersion: 2 },
      {
        ...vault,
        keySlots: [
          slot('slot.1', 'active', {
            wrappedRootKey: envelope('wrapped-root-key', 'slot.1', {
              vaultId: 'vault.other',
            }),
          }),
        ],
      },
      {
        ...vault,
        keySlots: [
          slot('slot.1', 'active', {
            wrappedRootKey: envelope('wrapped-root-key', 'slot.1', {
              schemaVersion: 2,
            }),
          }),
        ],
      },
    ];
    expect(vaultRecordSchema.safeParse(vault).success).toBe(true);
    for (const candidate of invalid) {
      expect(vaultRecordSchema.safeParse(candidate).success).toBe(false);
    }
  });

  it('authenticates every preferences identity component', () => {
    for (const encryptedPreferences of [
      envelope('vault-preferences', 'vault.other'),
      envelope('vault-preferences', 'vault.1', { vaultId: 'vault.other' }),
      envelope('vault-preferences', 'vault.1', { schemaVersion: 2 }),
      envelope('group', 'vault.1'),
    ]) {
      expect(
        vaultRecordSchema.safeParse({ ...vault, encryptedPreferences }).success,
      ).toBe(false);
    }
  });

  it('rejects fully coordinated unsupported vault formats and crypto versions', () => {
    const futureVault = {
      ...vault,
      schemaVersion: 2,
      keySlots: [
        slot('slot.1', 'active', {
          wrappedRootKey: envelope('wrapped-root-key', 'slot.1', {
            schemaVersion: 2,
          }),
        }),
      ],
      encryptedPreferences: envelope('vault-preferences', 'vault.1', {
        schemaVersion: 2,
      }),
    };

    expect(vaultRecordSchema.safeParse(futureVault).success).toBe(false);
    expect(
      vaultRecordSchema.safeParse({ ...vault, cryptographicVersion: 2 }).success,
    ).toBe(false);
  });

  it('accepts each opaque record and rejects a binding changed at any level', () => {
    const recordCases = (schemaVersion: number) =>
      [
        {
          schema: encryptedGroupRecordSchema,
          value: {
            id: 'group.1',
            vaultId: 'vault.1',
            schemaVersion,
            wrappedGroupKey: envelope('wrapped-group-key', 'group.1', {
              schemaVersion,
            }),
            encryptedPayload: envelope('group', 'group.1', { schemaVersion }),
            templateVersion: 1,
            recordRevision: 1,
            createdAt: timestamp,
            updatedAt: timestamp,
          },
        },
        {
          schema: encryptedItemRecordSchema,
          value: {
            id: 'item.1',
            vaultId: 'vault.1',
            groupId: 'group.1',
            schemaVersion,
            wrappedItemKey: envelope('wrapped-item-key', 'item.1', {
              schemaVersion,
              groupId: 'group.1',
            }),
            encryptedPayload: envelope('item', 'item.1', {
              schemaVersion,
              groupId: 'group.1',
            }),
            recordRevision: 1,
            ciphertextHash: digest,
            createdAt: timestamp,
            updatedAt: timestamp,
          },
        },
        {
          schema: encryptedAttachmentRecordSchema,
          value: {
            id: 'attachment.1',
            vaultId: 'vault.1',
            groupId: 'group.1',
            itemId: 'item.1',
            schemaVersion,
            wrappedAttachmentKey: envelope('wrapped-attachment-key', 'attachment.1', {
              schemaVersion,
              groupId: 'group.1',
              parentId: 'item.1',
            }),
            encryptedManifest: envelope('attachment', 'attachment.1', {
              schemaVersion,
              groupId: 'group.1',
              parentId: 'item.1',
            }),
            chunkCount: 1,
            recordRevision: 1,
            createdAt: timestamp,
            updatedAt: timestamp,
          },
        },
        {
          schema: encryptedAuditRecordSchema,
          value: {
            id: 'audit.1',
            vaultId: 'vault.1',
            schemaVersion,
            encryptedPayload: envelope('audit-event', 'audit.1', { schemaVersion }),
            recordRevision: 1,
            createdAt: timestamp,
          },
        },
        {
          schema: encryptedHistoryRecordSchema,
          value: {
            id: 'history.1',
            vaultId: 'vault.1',
            groupId: 'group.1',
            itemId: 'item.1',
            schemaVersion,
            encryptedPayload: envelope('history', 'history.1', {
              schemaVersion,
              groupId: 'group.1',
              parentId: 'item.1',
            }),
            itemRecordRevision: 1,
            ciphertextHash: digest,
            createdAt: timestamp,
          },
        },
      ] as const;

    const records = recordCases(1);

    for (const { schema, value } of records) {
      expect(schema.safeParse(value).success).toBe(true);
      expect(encryptedRecordSchema.safeParse(value).success).toBe(true);
      expect(schema.safeParse({ ...value, vaultId: 'vault.other' }).success).toBe(
        false,
      );
      expect(schema.safeParse({ ...value, schemaVersion: 2 }).success).toBe(false);
    }
    for (const { schema, value } of recordCases(2)) {
      expect(schema.safeParse(value).success).toBe(false);
    }
  });
});
