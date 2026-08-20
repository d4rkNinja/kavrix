import { describe, expect, it } from 'vitest';

import {
  CURRENT_CRYPTOGRAPHIC_VERSION,
  CURRENT_SCHEMA_VERSION,
  CURRENT_LOCAL_VAULT_VERSION,
  MAX_LOCAL_RECOVERY_SLOTS,
  MAX_TEXT_BYTES,
  localRecoveryKeySlotSchema,
  localVaultDocumentSchema,
  localVaultFormatSchema,
  localVaultPayloadSchema,
  localVaultValueSchema,
  localVaultVersionSchema,
  utf8ByteLength,
} from '../src/index.js';

const updatedAt = '2026-08-10T00:00:00.000Z';
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function rootKeyEnvelope(
  slotId: string,
  options: { vaultId?: string; schemaVersion?: number; keyVersion?: number } = {},
): Record<string, unknown> {
  const vaultId = options.vaultId ?? 'vault.1';
  const schemaVersion = options.schemaVersion ?? CURRENT_SCHEMA_VERSION;
  const keyVersion = options.keyVersion ?? 1;
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion,
      keyVersion,
      vaultId,
      entityType: 'wrapped-root-key',
      entityId: slotId,
      purpose: 'vrk-slot',
    },
    keyVersion,
  };
}

function portableSlot(
  id: string,
  options: {
    vaultId?: string;
    schemaVersion?: number;
    keyVersion?: number;
    state?: 'pending' | 'active' | 'superseded' | 'revoked';
  } = {},
): Record<string, unknown> {
  const state = options.state ?? 'active';
  return {
    slotVersion: 1,
    id,
    type: 'portable-key',
    state,
    keyVersion: options.keyVersion ?? 1,
    derivation: {
      algorithm: 'hkdf-sha256',
      version: 1,
      salt: digest,
      context: 'credvault/v1/portable-key-wrap',
      outputLength: 32,
    },
    wrappedRootKey: rootKeyEnvelope(id, options),
    createdAt: updatedAt,
    ...(state === 'superseded' ? { supersededAt: updatedAt } : {}),
    ...(state === 'revoked' ? { revokedAt: updatedAt } : {}),
  };
}

function recoverySlot(
  id: string,
  options: {
    vaultId?: string;
    schemaVersion?: number;
    keyVersion?: number;
    state?: 'pending' | 'active' | 'superseded' | 'revoked';
  } = {},
): Record<string, unknown> {
  return {
    ...portableSlot(id, options),
    type: 'recovery-key',
    derivation: {
      algorithm: 'hkdf-sha256',
      version: 1,
      salt: digest,
      context: 'credvault/v1/recovery-key-wrap',
      outputLength: 32,
    },
  };
}

function passphraseSlot(id: string): Record<string, unknown> {
  return {
    ...portableSlot(id),
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
  };
}

function payloadEnvelope(
  options: {
    vaultId?: string;
    entityId?: string;
    schemaVersion?: number;
    keyVersion?: number;
    revision?: number;
    metadataDigest?: string;
  } = {},
): Record<string, unknown> {
  const vaultId = options.vaultId ?? 'vault.1';
  const schemaVersion = options.schemaVersion ?? CURRENT_SCHEMA_VERSION;
  const keyVersion = options.keyVersion ?? 1;
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion,
      keyVersion,
      vaultId,
      entityType: 'vault-preferences',
      entityId: options.entityId ?? vaultId,
      purpose: 'vault-preferences',
      ...(options.revision === undefined ? {} : { revision: options.revision }),
      ...(options.metadataDigest === undefined
        ? {}
        : { metadataDigest: options.metadataDigest }),
    },
    keyVersion,
  };
}

function validDocument(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const id = typeof overrides['id'] === 'string' ? overrides['id'] : 'vault.1';
  const revision =
    typeof overrides['revision'] === 'number' ? overrides['revision'] : 0;
  const currentKeyVersion =
    typeof overrides['currentKeyVersion'] === 'number'
      ? overrides['currentKeyVersion']
      : 1;
  return {
    format: 'kavrix-local-vault',
    version: CURRENT_LOCAL_VAULT_VERSION,
    id,
    schemaVersion: CURRENT_SCHEMA_VERSION,
    cryptographicVersion: CURRENT_CRYPTOGRAPHIC_VERSION,
    currentKeyVersion,
    keySlot:
      overrides['keySlot'] ??
      portableSlot('slot.portable', { vaultId: id, keyVersion: currentKeyVersion }),
    ...(overrides['recoverySlots'] === undefined
      ? {}
      : { recoverySlots: overrides['recoverySlots'] }),
    revision,
    encryptedPayload:
      overrides['encryptedPayload'] ??
      payloadEnvelope({
        vaultId: id,
        keyVersion: currentKeyVersion,
        revision,
        metadataDigest: digest,
      }),
    createdAt: updatedAt,
    updatedAt,
    ...overrides,
  };
}

function expectInvalid(candidate: unknown): void {
  expect(localVaultDocumentSchema.safeParse(candidate).success).toBe(false);
}

describe('local vault value text byte limits', () => {
  it('uses the shared UTF-8 byte limit at the exact boundary', () => {
    const euroCount = Math.floor(MAX_TEXT_BYTES / 3);
    const atLimit = `${'€'.repeat(euroCount)}a`;
    const overLimit = `${atLimit}€`;

    expect(utf8ByteLength(atLimit)).toBe(MAX_TEXT_BYTES);
    expect(localVaultValueSchema.parse({ value: atLimit, updatedAt }).value).toBe(
      atLimit,
    );
    expect(
      localVaultValueSchema.safeParse({ value: overLimit, updatedAt }).success,
    ).toBe(false);
  });

  it('rejects the oversized multi-byte reproduction', () => {
    const oversized = '€'.repeat(600_000);

    expect(
      localVaultValueSchema.safeParse({ value: oversized, updatedAt }).success,
    ).toBe(false);
  });

  it('keeps the value object strict and timestamped', () => {
    expect(
      localVaultValueSchema.safeParse({ value: 'token', updatedAt, extra: 'field' })
        .success,
    ).toBe(false);
    expect(
      localVaultValueSchema.safeParse({ value: 'token', updatedAt: 'not-a-timestamp' })
        .success,
    ).toBe(false);
  });
});

describe('local vault primitive and payload schemas', () => {
  it('accepts only the canonical local vault format and version', () => {
    expect(localVaultFormatSchema.parse('kavrix-local-vault')).toBe(
      'kavrix-local-vault',
    );
    expect(localVaultVersionSchema.parse(CURRENT_LOCAL_VAULT_VERSION)).toBe(
      CURRENT_LOCAL_VAULT_VERSION,
    );
    expect(localVaultFormatSchema.safeParse('other-vault').success).toBe(false);
    expect(
      localVaultVersionSchema.safeParse(CURRENT_LOCAL_VAULT_VERSION + 1).success,
    ).toBe(false);
  });

  it('validates record values, strict payloads, and the record-count bound', () => {
    const parsed = localVaultPayloadSchema.parse({
      records: {
        'credential.1': { value: 'token', updatedAt },
      },
    });
    expect(parsed.records['credential.1']?.value).toBe('token');

    expect(
      localVaultPayloadSchema.safeParse({
        records: { 'credential.1': { value: 'token', updatedAt } },
        extra: true,
      }).success,
    ).toBe(false);
    expect(
      localVaultPayloadSchema.safeParse({
        records: { 'credential.1': { value: 'token', updatedAt, extra: true } },
      }).success,
    ).toBe(false);

    const tooManyRecords = Object.fromEntries(
      Array.from({ length: 10_001 }, (_, index) => [
        `credential.${String(index)}`,
        { value: 'x', updatedAt },
      ]),
    );
    expect(localVaultPayloadSchema.safeParse({ records: tooManyRecords }).success).toBe(
      false,
    );
  });

  it('accepts recovery-key material and rejects other unlock material', () => {
    expect(localRecoveryKeySlotSchema.parse(recoverySlot('recovery.1')).type).toBe(
      'recovery-key',
    );
    expect(
      localRecoveryKeySlotSchema.safeParse(portableSlot('portable.1')).success,
    ).toBe(false);
  });
});

describe('local vault document invariants', () => {
  it('accepts a canonical document and defaults recovery slots to an empty list', () => {
    const parsed = localVaultDocumentSchema.parse(validDocument());

    expect(parsed.format).toBe('kavrix-local-vault');
    expect(parsed.version).toBe(CURRENT_LOCAL_VAULT_VERSION);
    expect(parsed.recoverySlots).toEqual([]);
    expect(parsed.encryptedPayload.aad.revision).toBe(0);
    expect(parsed.encryptedPayload.aad.metadataDigest).toBe(digest);
  });

  it('accepts active and revoked recovery slots within the limit', () => {
    const recoverySlots = [
      recoverySlot('recovery.active'),
      recoverySlot('recovery.revoked', { state: 'revoked' }),
    ];
    const parsed = localVaultDocumentSchema.parse(validDocument({ recoverySlots }));

    expect(parsed.recoverySlots.map((slot) => slot.state)).toEqual([
      'active',
      'revoked',
    ]);
  });

  it('rejects more than the supported number of recovery slots', () => {
    const recoverySlots = Array.from(
      { length: MAX_LOCAL_RECOVERY_SLOTS + 1 },
      (_, index) => recoverySlot(`recovery.${String(index)}`),
    );

    expectInvalid(validDocument({ recoverySlots }));
  });

  it('rejects a non-portable, inactive, mismatched, or foreign unlock slot', () => {
    expectInvalid(validDocument({ keySlot: passphraseSlot('slot.passphrase') }));
    expectInvalid(
      validDocument({
        keySlot: portableSlot('slot.pending', { state: 'pending' }),
      }),
    );
    expectInvalid(
      validDocument({
        keySlot: portableSlot('slot.version', { keyVersion: 2 }),
      }),
    );
    expectInvalid(
      validDocument({
        keySlot: portableSlot('slot.foreign', { vaultId: 'vault.other' }),
      }),
    );
  });

  it('rejects duplicate, stale, foreign, and pending recovery slots', () => {
    expectInvalid(
      validDocument({
        recoverySlots: [recoverySlot('slot.portable')],
      }),
    );
    expectInvalid(
      validDocument({
        recoverySlots: [recoverySlot('recovery.version', { keyVersion: 2 })],
      }),
    );
    expectInvalid(
      validDocument({
        recoverySlots: [recoverySlot('recovery.foreign', { vaultId: 'vault.other' })],
      }),
    );
    expectInvalid(
      validDocument({
        recoverySlots: [recoverySlot('recovery.pending', { state: 'pending' })],
      }),
    );
  });

  it('rejects unsupported top-level versions and strict document fields', () => {
    expectInvalid(
      validDocument({
        schemaVersion: CURRENT_SCHEMA_VERSION + 1,
        recoverySlots: [recoverySlot('recovery.schema')],
      }),
    );
    expectInvalid(
      validDocument({ cryptographicVersion: CURRENT_CRYPTOGRAPHIC_VERSION + 1 }),
    );
    expectInvalid(validDocument({ extra: 'unexpected' }));
    expectInvalid(validDocument({ updatedAt: 'not-a-timestamp' }));
  });

  it('requires payload revision and metadata digest binding', () => {
    expectInvalid(
      validDocument({
        encryptedPayload: payloadEnvelope({ metadataDigest: digest }),
      }),
    );
    expectInvalid(
      validDocument({
        encryptedPayload: payloadEnvelope({ revision: 0 }),
      }),
    );
    expectInvalid(
      validDocument({
        encryptedPayload: payloadEnvelope({
          revision: 1,
          metadataDigest: digest,
        }),
      }),
    );
  });

  it('requires payload associated data to match the document', () => {
    expectInvalid(
      validDocument({
        encryptedPayload: payloadEnvelope({
          vaultId: 'vault.other',
          revision: 0,
          metadataDigest: digest,
        }),
      }),
    );
    expectInvalid(
      validDocument({
        encryptedPayload: payloadEnvelope({
          entityId: 'vault.other',
          revision: 0,
          metadataDigest: digest,
        }),
      }),
    );
    expectInvalid(
      validDocument({
        encryptedPayload: payloadEnvelope({
          keyVersion: 2,
          revision: 0,
          metadataDigest: digest,
        }),
      }),
    );
  });
});
