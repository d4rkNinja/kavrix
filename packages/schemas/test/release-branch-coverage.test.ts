import { describe, expect, it } from 'vitest';

import {
  DEFAULT_IDLE_TIMEOUT_MS,
  DEFAULT_INVOCATION_TIMEOUT_MS,
  DEFAULT_MAX_TRANSFER_DOCUMENTS,
  DEFAULT_REAUTHENTICATION_WINDOW_MS,
  DEFAULT_SESSION_LIFETIME_POLICY,
  MAX_SESSION_TIMEOUT_MS,
  MAX_SUPPORTED_TRANSFER_BYTES,
  MIN_SESSION_TIMEOUT_MS,
  deviceUnlockSecretSchema,
  encryptedTransferEntrySchema,
  encryptedTransferFooterSchema,
  encryptedTransferHeaderSchema,
  keychainLocatorSchema,
  portableKeyRotationCheckpointPayloadSchema,
  portableKeyRotationCheckpointSchema,
  portableKeyRotationJournalRecordSchema,
  portableKeyRotationJournalSerializedBytes,
  portableKeyRotationSourceKindSchema,
  sessionCredentialLocatorSchema,
  sessionCredentialSecretSchema,
  sessionExpiryReasonSchema,
  sessionLifetimePolicySchema,
  transferAuthenticationTagSchema,
  transferCollisionStrategySchema,
  transferImportSummarySchema,
  transferKeySaltSchema,
  transferLimitsSchema,
  transferProtectionSchema,
  transferWithholdingReasonSchema,
  transferWithholdingSchema,
  transferWithholdingsSchema,
  type PortableKeyRotationState,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';
const digest = 'A'.repeat(43);
const transferSalt = 'A'.repeat(43);
const passphraseSalt = 'A'.repeat(22);

type RotationState = PortableKeyRotationState;

const rotationOffsets: Record<RotationState, number> = {
  prepared: 0,
  'pending-published': 1,
  'active-published': 2,
  completed: 3,
};

function rotationEnvelope(entityType: string, entityId: string): object {
  const purposeByEntity: Record<string, string> = {
    'wrapped-root-key': 'vrk-slot',
  };
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'A'.repeat(32),
    ciphertext: 'AQID',
    authenticationTag: 'A'.repeat(22),
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: 'vault.rotation',
      entityType,
      entityId,
      purpose: purposeByEntity[entityType],
    },
    keyVersion: 1,
  };
}

function rotationSlot(
  id: string,
  state: 'pending' | 'active' | 'superseded' | 'revoked',
  type: 'portable-key' | 'passphrase' = 'portable-key',
): Record<string, unknown> {
  return {
    id,
    slotVersion: 1,
    type,
    state,
    keyVersion: 1,
    derivation:
      type === 'portable-key'
        ? {
            algorithm: 'hkdf-sha256',
            version: 1,
            salt: digest,
            context: 'credvault/v1/portable-key-wrap',
            outputLength: 32,
          }
        : {
            algorithm: 'argon2id',
            version: 1,
            salt: passphraseSalt,
            memoryKiB: 65_536,
            passes: 3,
            parallelism: 4,
            outputLength: 32,
          },
    wrappedRootKey: rotationEnvelope('wrapped-root-key', id),
    createdAt: timestamp,
    ...(state === 'superseded' ? { supersededAt: timestamp } : {}),
    ...(state === 'revoked' ? { revokedAt: timestamp } : {}),
  };
}

function rotationCheckpoint(
  state: RotationState,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const payload = {
    version: 1,
    vaultId: 'vault.rotation',
    operationId: 'operation.rotation.0001',
    sourceSlotId: 'slot.rotation.source',
    replacementSlotId: 'slot.rotation.replacement',
    sourceRevision: 10,
    remoteRevision: 10 + rotationOffsets[state],
    sourceSlotDigest: digest,
    replacementSlotDigest: digest,
    transcriptDigest: digest,
    state,
    ...overrides,
  };
  return {
    payload,
    authenticationTag: digest,
  };
}

function rotationJournal(
  state: RotationState,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const replacementState =
    state === 'prepared' || state === 'pending-published' ? 'pending' : 'active';
  return {
    version: 1,
    kind: 'portable-key-rotation',
    operationId: 'operation.rotation.0001',
    vaultId: 'vault.rotation',
    deviceId: 'device.rotation',
    state,
    sourceKind: 'generated-file',
    sourceSlot: rotationSlot('slot.rotation.source', 'active'),
    replacementSlot: rotationSlot('slot.rotation.replacement', replacementState),
    sourceRevision: 10,
    createdAt: timestamp,
    updatedAt: timestamp,
    checkpoint: rotationCheckpoint(state),
    ...overrides,
  };
}

function transferEnvelope(
  entityType: 'group' | 'item',
  entityId: string,
  groupId?: string,
): object {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'A'.repeat(32),
    ciphertext: 'AQID',
    authenticationTag: 'A'.repeat(22),
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: 'vault.transfer',
      entityType,
      entityId,
      ...(groupId === undefined ? {} : { groupId }),
      purpose: entityType === 'group' ? 'group-payload' : 'item-payload',
    },
    keyVersion: 1,
  };
}

function transferProtection(): object {
  return {
    algorithm: 'argon2id+hkdf-sha256+xchacha20-poly1305-ietf',
    derivation: {
      algorithm: 'argon2id',
      version: 1,
      salt: passphraseSalt,
      memoryKiB: 65_536,
      passes: 3,
      parallelism: 4,
      outputLength: 32,
    },
    expansionSalt: transferSalt,
  };
}

function transferHeader(): Record<string, unknown> {
  return {
    type: 'header',
    format: 'kavrix-encrypted-transfer',
    version: 1,
    vaultId: 'vault.transfer',
    schemaVersion: 1,
    createdAt: timestamp,
    protection: transferProtection(),
  };
}

describe('release branch coverage for rotation schemas', () => {
  it('accepts every checkpoint lifecycle and source kind', () => {
    for (const state of [
      'prepared',
      'pending-published',
      'active-published',
      'completed',
    ] as const) {
      expect(
        portableKeyRotationCheckpointPayloadSchema.safeParse(
          rotationCheckpoint(state)['payload'],
        ).success,
      ).toBe(true);
      expect(
        portableKeyRotationCheckpointSchema.safeParse(rotationCheckpoint(state))
          .success,
      ).toBe(true);
      expect(
        portableKeyRotationJournalRecordSchema.safeParse(rotationJournal(state))
          .success,
      ).toBe(true);
    }
    for (const sourceKind of ['generated-file', 'imported-file'] as const) {
      expect(portableKeyRotationSourceKindSchema.safeParse(sourceKind).success).toBe(
        true,
      );
      expect(
        portableKeyRotationJournalRecordSchema.safeParse(
          rotationJournal('prepared', { sourceKind }),
        ).success,
      ).toBe(true);
    }
  });

  it('rejects checkpoint identity and lifecycle inconsistencies', () => {
    const valid = rotationCheckpoint('prepared');
    const payload = valid['payload'] as Record<string, unknown>;
    for (const invalid of [
      { ...payload, sourceSlotId: payload['replacementSlotId'] },
      { ...payload, remoteRevision: 11 },
      { ...payload, operationId: 'x'.repeat(15) },
      { ...payload, operationId: 'operation with spaces' },
      { ...payload, unexpected: true },
    ]) {
      expect(
        portableKeyRotationCheckpointPayloadSchema.safeParse(invalid).success,
      ).toBe(false);
    }

    const mismatches = [
      {
        sourceSlot: rotationSlot('slot.rotation.source', 'pending'),
      },
      {
        replacementSlot: rotationSlot('slot.rotation.replacement', 'active'),
      },
      {
        replacementSlot: rotationSlot('slot.rotation.source', 'pending'),
      },
      {
        replacementSlot: {
          ...rotationSlot('slot.rotation.replacement', 'pending'),
          keyVersion: 2,
        },
      },
      { sourceRevision: 11 },
      {
        checkpoint: rotationCheckpoint('prepared', { vaultId: 'vault.other' }),
      },
      {
        checkpoint: rotationCheckpoint('prepared', {
          operationId: 'operation.other.0001',
        }),
      },
      {
        checkpoint: rotationCheckpoint('prepared', {
          sourceSlotId: 'slot.other.source',
        }),
      },
      {
        checkpoint: rotationCheckpoint('prepared', {
          replacementSlotId: 'slot.other.replacement',
        }),
      },
      {
        checkpoint: rotationCheckpoint('pending-published'),
      },
      {
        replacementSlot: rotationSlot(
          'slot.rotation.replacement',
          'pending',
          'passphrase',
        ),
      },
    ];
    for (const mismatch of mismatches) {
      expect(
        portableKeyRotationJournalRecordSchema.safeParse({
          ...rotationJournal('prepared'),
          ...mismatch,
        }).success,
      ).toBe(false);
    }
  });

  it('serializes only canonical journal records and exposes the size bound', () => {
    const record = portableKeyRotationJournalRecordSchema.parse(
      rotationJournal('completed'),
    );
    const serializedBytes = portableKeyRotationJournalSerializedBytes(record);
    expect(serializedBytes).toBe(Buffer.byteLength(JSON.stringify(record), 'utf8'));
    expect(serializedBytes).toBeGreaterThan(0);
    expect(() =>
      portableKeyRotationJournalSerializedBytes({
        ...record,
        state: 'invalid',
      } as never),
    ).toThrow();
  });
});

describe('release branch coverage for session lifetime schemas', () => {
  it('accepts policy boundaries, defaults, and every terminal expiry reason', () => {
    expect(DEFAULT_SESSION_LIFETIME_POLICY).toEqual({
      invocationTimeoutMs: DEFAULT_INVOCATION_TIMEOUT_MS,
      idleTimeoutMs: DEFAULT_IDLE_TIMEOUT_MS,
      reauthenticationWindowMs: DEFAULT_REAUTHENTICATION_WINDOW_MS,
    });
    for (const timeout of [MIN_SESSION_TIMEOUT_MS, MAX_SESSION_TIMEOUT_MS]) {
      expect(
        sessionLifetimePolicySchema.safeParse({
          invocationTimeoutMs: timeout,
          idleTimeoutMs: timeout,
          reauthenticationWindowMs: timeout,
        }).success,
      ).toBe(true);
    }
    for (const reason of [
      'invocation-timeout',
      'idle-timeout',
      'interrupted',
      'terminated',
      'hangup',
      'clock-regression',
    ] as const) {
      expect(sessionExpiryReasonSchema.safeParse(reason).success).toBe(true);
    }
  });

  it('rejects out-of-range, non-integral, strict, and cross-limit policies', () => {
    const valid = {
      invocationTimeoutMs: DEFAULT_INVOCATION_TIMEOUT_MS,
      idleTimeoutMs: DEFAULT_IDLE_TIMEOUT_MS,
      reauthenticationWindowMs: DEFAULT_REAUTHENTICATION_WINDOW_MS,
    };
    for (const invalid of [
      { ...valid, invocationTimeoutMs: MIN_SESSION_TIMEOUT_MS - 1 },
      { ...valid, invocationTimeoutMs: MAX_SESSION_TIMEOUT_MS + 1 },
      { ...valid, idleTimeoutMs: 1_000.5 },
      { ...valid, reauthenticationWindowMs: 0 },
      { ...valid, extra: true },
      { ...valid, idleTimeoutMs: DEFAULT_INVOCATION_TIMEOUT_MS + 1 },
      {
        ...valid,
        reauthenticationWindowMs: DEFAULT_INVOCATION_TIMEOUT_MS + 1,
      },
      {
        ...valid,
        idleTimeoutMs: DEFAULT_INVOCATION_TIMEOUT_MS + 1,
        reauthenticationWindowMs: DEFAULT_INVOCATION_TIMEOUT_MS + 1,
      },
    ]) {
      expect(sessionLifetimePolicySchema.safeParse(invalid).success).toBe(false);
    }
    expect(sessionExpiryReasonSchema.safeParse('expired').success).toBe(false);
  });
});

describe('release branch coverage for encrypted transfer schemas', () => {
  it('accepts canonical protection, header, entries, footer, and limits', () => {
    expect(transferKeySaltSchema.safeParse(transferSalt).success).toBe(true);
    expect(transferAuthenticationTagSchema.safeParse(digest).success).toBe(true);
    expect(transferProtectionSchema.safeParse(transferProtection()).success).toBe(true);
    expect(encryptedTransferHeaderSchema.safeParse(transferHeader()).success).toBe(
      true,
    );

    expect(
      encryptedTransferEntrySchema.safeParse({
        kind: 'group',
        groupId: 'group.transfer',
        envelope: transferEnvelope('group', 'group.transfer'),
      }).success,
    ).toBe(true);
    expect(
      encryptedTransferEntrySchema.safeParse({
        kind: 'item',
        groupId: 'group.transfer',
        itemId: 'item.transfer',
        envelope: transferEnvelope('item', 'item.transfer', 'group.transfer'),
        withheld: [],
      }).success,
    ).toBe(true);

    const withheld = transferWithholdingSchema.parse({
      stableKey: 'username',
      scope: 'template',
      reason: 'export-policy',
    });
    expect(transferWithholdingReasonSchema.safeParse('export-policy').success).toBe(
      true,
    );
    expect(
      transferWithholdingsSchema.safeParse([
        withheld,
        { ...withheld, scope: 'item', reason: 'unresolved-reference' },
      ]).success,
    ).toBe(true);
    expect(
      transferWithholdingsSchema.safeParse([
        withheld,
        { ...withheld, reason: 'attachment-unsupported' },
      ]).success,
    ).toBe(false);

    expect(
      encryptedTransferFooterSchema.safeParse({
        type: 'footer',
        version: 1,
        groupCount: 0,
        itemCount: DEFAULT_MAX_TRANSFER_DOCUMENTS,
        transcriptSha256: digest,
        authenticationTag: digest,
      }).success,
    ).toBe(true);
    expect(
      transferLimitsSchema.safeParse({
        maximumBytes: MAX_SUPPORTED_TRANSFER_BYTES,
        maximumDocuments: DEFAULT_MAX_TRANSFER_DOCUMENTS,
      }).success,
    ).toBe(true);
    for (const strategy of ['fail', 'skip', 'rename'] as const) {
      expect(transferCollisionStrategySchema.safeParse(strategy).success).toBe(true);
    }
    expect(
      transferImportSummarySchema.safeParse({
        vaultId: 'vault.transfer',
        createdAt: timestamp,
        groupsCreated: 0,
        groupsSkipped: 1,
        itemsCreated: 2,
        withheldValues: 3,
      }).success,
    ).toBe(true);
  });

  it('rejects malformed canonical bytes, duplicate withholdings, and bounds', () => {
    for (const invalid of ['', 'A'.repeat(42), 'A'.repeat(44), '!'.repeat(43)]) {
      expect(transferKeySaltSchema.safeParse(invalid).success).toBe(false);
      expect(transferAuthenticationTagSchema.safeParse(invalid).success).toBe(false);
    }
    expect(transferWithholdingReasonSchema.safeParse('omitted').success).toBe(false);

    const withholding = {
      stableKey: 'username',
      scope: 'item',
      reason: 'export-policy',
    } as const;
    expect(
      transferWithholdingsSchema.safeParse([withholding, withholding]).success,
    ).toBe(false);
    expect(
      transferWithholdingsSchema.safeParse([{ ...withholding, stableKey: 'not valid' }])
        .success,
    ).toBe(false);
    expect(
      encryptedTransferEntrySchema.safeParse({
        kind: 'unknown',
        groupId: 'group.transfer',
        envelope: transferEnvelope('group', 'group.transfer'),
      }).success,
    ).toBe(false);

    const header = transferHeader();
    for (const invalid of [
      { ...header, version: 2 },
      { ...header, unexpected: true },
      {
        ...header,
        protection: { ...transferProtection(), expansionSalt: 'A'.repeat(42) },
      },
    ]) {
      expect(encryptedTransferHeaderSchema.safeParse(invalid).success).toBe(false);
    }
    for (const invalid of [
      { maximumBytes: 0, maximumDocuments: 1 },
      { maximumBytes: MAX_SUPPORTED_TRANSFER_BYTES + 1, maximumDocuments: 1 },
      { maximumBytes: 1, maximumDocuments: DEFAULT_MAX_TRANSFER_DOCUMENTS + 1 },
      { maximumBytes: 1.5, maximumDocuments: 1 },
    ]) {
      expect(transferLimitsSchema.safeParse(invalid).success).toBe(false);
    }
    expect(transferCollisionStrategySchema.safeParse('merge').success).toBe(false);
    expect(
      encryptedTransferFooterSchema.safeParse({
        type: 'footer',
        version: 1,
        groupCount: -1,
        itemCount: 0,
        transcriptSha256: digest,
        authenticationTag: digest,
      }).success,
    ).toBe(false);
  });
});

describe('release branch coverage for keychain schemas', () => {
  it('accepts exact secret byte lengths and strict device/session locators', () => {
    expect(deviceUnlockSecretSchema.safeParse(new Uint8Array(32)).success).toBe(true);
    expect(sessionCredentialSecretSchema.safeParse(new Uint8Array(32)).success).toBe(
      true,
    );
    expect(
      keychainLocatorSchema.safeParse({
        version: 1,
        vaultId: 'vault.keychain',
        deviceId: 'device.keychain',
        keySlotId: 'slot.keychain',
      }).success,
    ).toBe(true);
    expect(
      sessionCredentialLocatorSchema.safeParse({
        version: 1,
        vaultId: 'vault.keychain',
        deviceId: 'device.keychain',
        purpose: 'api-session',
      }).success,
    ).toBe(true);
  });

  it('rejects non-Uint8Array, wrong byte sizes, wrong versions, and extra locator fields', () => {
    for (const value of [
      new Uint8Array(0),
      new Uint8Array(31),
      new Uint8Array(33),
      new ArrayBuffer(32),
    ]) {
      expect(deviceUnlockSecretSchema.safeParse(value).success).toBe(false);
      expect(sessionCredentialSecretSchema.safeParse(value).success).toBe(false);
    }
    expect(deviceUnlockSecretSchema.safeParse('secret').success).toBe(false);
    expect(sessionCredentialSecretSchema.safeParse([0, 1, 2]).success).toBe(false);

    const locator = {
      version: 1,
      vaultId: 'vault.keychain',
      deviceId: 'device.keychain',
      keySlotId: 'slot.keychain',
    };
    expect(keychainLocatorSchema.safeParse({ ...locator, version: 2 }).success).toBe(
      false,
    );
    expect(keychainLocatorSchema.safeParse({ ...locator, extra: true }).success).toBe(
      false,
    );
    expect(keychainLocatorSchema.safeParse({ ...locator, vaultId: '' }).success).toBe(
      false,
    );

    const sessionLocator = {
      version: 1,
      vaultId: 'vault.keychain',
      deviceId: 'device.keychain',
      purpose: 'api-session',
    };
    expect(
      sessionCredentialLocatorSchema.safeParse({ ...sessionLocator, purpose: 'device' })
        .success,
    ).toBe(false);
    expect(
      sessionCredentialLocatorSchema.safeParse({ ...sessionLocator, extra: true })
        .success,
    ).toBe(false);
    expect(
      sessionCredentialLocatorSchema.safeParse({ ...sessionLocator, deviceId: '_bad' })
        .success,
    ).toBe(false);
  });
});
