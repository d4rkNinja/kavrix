import {
  AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS,
  AEAD_NONCE_BASE64URL_CHARS,
  API_SCOPE_VALUES,
  ARGON2ID_SALT_BASE64URL_CHARS,
  CANONICAL_BASE64URL_PATTERN_SOURCE,
  CANONICAL_TIMESTAMP_CHARS,
  CANONICAL_TIMESTAMP_PATTERN_SOURCE,
  HKDF_SALT_BASE64URL_CHARS,
  KEY_DERIVATION_OUTPUT_BYTES,
  MAX_API_SCOPES,
  MAX_ARGON2_MEMORY_KIB,
  MAX_ARGON2_PARALLELISM,
  MAX_ARGON2_PASSES,
  MAX_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
  MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
  MAX_ATTACHMENT_CHUNKS,
  MAX_CIPHERTEXT_CHARS,
  MAX_DEVICE_KEY_PROVIDER_CHARS,
  MAX_ENCRYPTED_DEVICE_LABEL_CIPHERTEXT_CHARS,
  MAX_OPAQUE_ID_CHARS,
  MAX_SEMANTIC_REVISION,
  MAX_SEMANTIC_VERSION,
  MIN_API_SCOPES,
  MIN_ARGON2_MEMORY_KIB,
  MIN_ARGON2_PARALLELISM,
  MIN_ARGON2_PASSES,
  MIN_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
  MIN_OPAQUE_ID_CHARS,
  OPAQUE_ID_PATTERN_SOURCE,
  SECRETSTREAM_HEADER_BASE64URL_CHARS,
  SHA256_DIGEST_BASE64URL_CHARS,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  associatedDataVersionFragment,
  aeadAuthenticationTagFragment,
  aeadEnvelopeFragment,
  aeadNonceFragment,
  apiScopesFragment,
  argon2idSaltFragment,
  associatedDataFragment,
  attachmentChunkCiphertextFragment,
  attachmentSecretStreamChunkRecordFragment,
  attachmentSecretStreamHeaderRecordFragment,
  canonicalBase64UrlFragment,
  canonicalTimestampFragment,
  deviceKeyDerivationFragment,
  encryptedDeviceLabelFragment,
  envelopeVersionFragment,
  hkdfSaltFragment,
  keyDerivationFragment,
  keySlotFragment,
  keySlotVersionFragment,
  nonnegativeSemanticRevisionFragment,
  opaqueIdentifierFragment,
  passphraseDerivationFragment,
  persistedAttachmentChunkFragment,
  persistedAttachmentHeaderFragment,
  portableKeyDerivationFragment,
  recoveryKeyDerivationFragment,
  safeInteger,
  secretStreamHeaderFragment,
  sha256DigestFragment,
  strictObject,
  supportedCryptographicVersionFragment,
  supportedSchemaVersionFragment,
  supportedTokenVersionFragment,
  type MongoJsonSchema,
} from '../src/mongo-validator-fragments.js';
import { aeadEnvelopeFragment as indexedAeadEnvelopeFragment } from '../src/index.js';

function branches(fragment: MongoJsonSchema): readonly MongoJsonSchema[] {
  expect(fragment.oneOf).toBeDefined();
  return fragment.oneOf ?? [];
}

function properties(
  fragment: MongoJsonSchema,
): Readonly<Record<string, MongoJsonSchema>> {
  expect(fragment.properties).toBeDefined();
  return fragment.properties ?? {};
}

function enumValue(fragment: MongoJsonSchema): string | number | boolean | null {
  expect(fragment.enum).toHaveLength(1);
  const value = fragment.enum?.[0];
  expect(value).toBeDefined();
  return value ?? null;
}

function property(fragment: MongoJsonSchema, name: string): MongoJsonSchema {
  const value = properties(fragment)[name];
  expect(value).toBeDefined();
  return value ?? {};
}

function firstBranch(fragment: MongoJsonSchema): MongoJsonSchema {
  const value = branches(fragment)[0];
  expect(value).toBeDefined();
  return value ?? {};
}

function schemaKeywords(value: unknown): readonly string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => schemaKeywords(entry));
  }
  if (value === null || typeof value !== 'object') return [];
  const record = value as Readonly<Record<string, unknown>>;
  return Object.entries(record).flatMap(([key, entry]) => [
    key,
    ...schemaKeywords(entry),
  ]);
}

describe('shared Mongo validator fragments', () => {
  it('is exported through the storage package root', () => {
    expect(indexedAeadEnvelopeFragment).toBe(aeadEnvelopeFragment);
  });

  it('builds strict objects and bounded BSON-safe integers without Decimal128', () => {
    const integer = safeInteger({ minimum: 0, maximum: MAX_SEMANTIC_REVISION });
    expect(integer).toEqual({
      bsonType: ['int', 'long', 'double'],
      multipleOf: 1,
      minimum: 0,
      maximum: Number.MAX_SAFE_INTEGER,
    });
    expect(JSON.stringify(integer)).not.toContain('decimal');
    expect(
      safeInteger({
        minimum: -Number.MAX_SAFE_INTEGER,
        maximum: Number.MAX_SAFE_INTEGER,
      }),
    ).toMatchObject({
      minimum: -Number.MAX_SAFE_INTEGER,
      maximum: Number.MAX_SAFE_INTEGER,
    });
    expect(() =>
      safeInteger({ minimum: Number.MIN_SAFE_INTEGER - 1, maximum: 0 }),
    ).toThrow(RangeError);

    expect(strictObject(['value'], { value: integer })).toEqual({
      bsonType: 'object',
      required: ['value'],
      additionalProperties: false,
      properties: { value: integer },
    });
  });

  it('represents supported and structural versions as exact BSON-safe enums', () => {
    for (const fragment of [
      supportedSchemaVersionFragment,
      supportedCryptographicVersionFragment,
      supportedTokenVersionFragment,
    ]) {
      expect(fragment).toEqual({
        bsonType: ['int', 'long', 'double'],
        multipleOf: 1,
        minimum: 1,
        maximum: MAX_SEMANTIC_VERSION,
        enum: [1],
      });
    }
    for (const fragment of [
      envelopeVersionFragment,
      associatedDataVersionFragment,
      keySlotVersionFragment,
    ]) {
      expect(fragment).toEqual({
        bsonType: ['int', 'long', 'double'],
        multipleOf: 1,
        minimum: 1,
        maximum: 1,
        enum: [1],
      });
    }
    expect(nonnegativeSemanticRevisionFragment).toMatchObject({
      bsonType: ['int', 'long', 'double'],
      multipleOf: 1,
      minimum: 0,
      maximum: MAX_SEMANTIC_REVISION,
    });
  });

  it('uses canonical identifier, timestamp, and base64url constraints', () => {
    expect(opaqueIdentifierFragment).toEqual({
      bsonType: 'string',
      minLength: MIN_OPAQUE_ID_CHARS,
      maxLength: MAX_OPAQUE_ID_CHARS,
      pattern: OPAQUE_ID_PATTERN_SOURCE,
    });
    expect(canonicalTimestampFragment).toEqual({
      bsonType: 'string',
      minLength: CANONICAL_TIMESTAMP_CHARS,
      maxLength: CANONICAL_TIMESTAMP_CHARS,
      pattern: CANONICAL_TIMESTAMP_PATTERN_SOURCE,
    });
    expect(canonicalBase64UrlFragment).toEqual({
      bsonType: 'string',
      minLength: 1,
      maxLength: MAX_CIPHERTEXT_CHARS,
      pattern: CANONICAL_BASE64URL_PATTERN_SOURCE,
    });

    for (const [fragment, length] of [
      [aeadAuthenticationTagFragment, AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS],
      [aeadNonceFragment, AEAD_NONCE_BASE64URL_CHARS],
      [secretStreamHeaderFragment, SECRETSTREAM_HEADER_BASE64URL_CHARS],
      [argon2idSaltFragment, ARGON2ID_SALT_BASE64URL_CHARS],
      [hkdfSaltFragment, HKDF_SALT_BASE64URL_CHARS],
      [sha256DigestFragment, SHA256_DIGEST_BASE64URL_CHARS],
    ] as const) {
      expect(fragment).toMatchObject({
        bsonType: 'string',
        minLength: length,
        maxLength: length,
        pattern: CANONICAL_BASE64URL_PATTERN_SOURCE,
      });
    }
    expect(sha256DigestFragment.pattern).toContain('[AEIMQUYcgkosw048]');
    expect(attachmentChunkCiphertextFragment).toMatchObject({
      minLength: MIN_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
      maxLength: MAX_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
      pattern: CANONICAL_BASE64URL_PATTERN_SOURCE,
    });
  });

  it('defines one strict, bounded, unique API-scope array', () => {
    expect(apiScopesFragment).toEqual({
      bsonType: 'array',
      minItems: MIN_API_SCOPES,
      maxItems: MAX_API_SCOPES,
      uniqueItems: true,
      items: { bsonType: 'string', enum: [...API_SCOPE_VALUES] },
    });
  });

  it('generates all 12 exact associated-data branches from the canonical matrix', () => {
    const expected = [
      ['vault-preferences', 'vault-preferences', false, false],
      ['group', 'group-payload', false, false],
      ['item', 'item-payload', true, false],
      ['attachment', 'attachment-metadata', true, true],
      ['attachment-chunk', 'attachment-chunk', true, true],
      ['audit-event', 'audit-event', false, false],
      ['history', 'history-event', true, true],
      ['device-label', 'device-label', false, false],
      ['wrapped-root-key', 'vrk-slot', false, false],
      ['wrapped-group-key', 'group-key', false, false],
      ['wrapped-item-key', 'item-key', true, false],
      ['wrapped-attachment-key', 'attachment-key', true, true],
    ] as const;
    const actual = branches(associatedDataFragment);
    expect(actual).toHaveLength(expected.length);

    expected.forEach(([entityType, purpose, hasGroupId, hasParentId], index) => {
      const branch = actual[index];
      expect(branch).toBeDefined();
      if (branch === undefined) return;
      const branchProperties = properties(branch);
      expect(branch.additionalProperties).toBe(false);
      expect(Object.keys(branchProperties)).toEqual(branch.required);
      expect(enumValue(property(branch, 'entityType'))).toBe(entityType);
      expect(enumValue(property(branch, 'purpose'))).toBe(purpose);
      expect('groupId' in branchProperties).toBe(hasGroupId);
      expect('parentId' in branchProperties).toBe(hasParentId);
      expect(branch.required).toEqual([
        'version',
        'schemaVersion',
        'keyVersion',
        'vaultId',
        'entityType',
        'entityId',
        'purpose',
        ...(hasGroupId ? ['groupId'] : []),
        ...(hasParentId ? ['parentId'] : []),
      ]);
    });
  });

  it('defines exact AEAD and encrypted device-label envelopes', () => {
    expect(aeadEnvelopeFragment.additionalProperties).toBe(false);
    expect(Object.keys(properties(aeadEnvelopeFragment))).toEqual(
      aeadEnvelopeFragment.required,
    );
    expect(enumValue(property(aeadEnvelopeFragment, 'version'))).toBe(1);
    expect(enumValue(property(aeadEnvelopeFragment, 'algorithm'))).toBe(
      'xchacha20-poly1305-ietf',
    );
    expect(property(aeadEnvelopeFragment, 'ciphertext')).toEqual(
      canonicalBase64UrlFragment,
    );
    expect(branches(property(aeadEnvelopeFragment, 'aad'))).toHaveLength(12);

    expect(property(encryptedDeviceLabelFragment, 'ciphertext')).toMatchObject({
      minLength: 1,
      maxLength: MAX_ENCRYPTED_DEVICE_LABEL_CIPHERTEXT_CHARS,
    });
    expect(Object.keys(properties(encryptedDeviceLabelFragment))).toEqual(
      encryptedDeviceLabelFragment.required,
    );
    const labelAad = branches(property(encryptedDeviceLabelFragment, 'aad'));
    expect(labelAad).toHaveLength(1);
    expect(
      enumValue(
        property(
          firstBranch(property(encryptedDeviceLabelFragment, 'aad')),
          'entityType',
        ),
      ),
    ).toBe('device-label');
  });

  it('defines four exact derivation branches and their numeric bounds', () => {
    expect(branches(keyDerivationFragment)).toEqual([
      portableKeyDerivationFragment,
      passphraseDerivationFragment,
      recoveryKeyDerivationFragment,
      deviceKeyDerivationFragment,
    ]);

    const contexts = [
      [portableKeyDerivationFragment, 'credvault/v1/portable-key-wrap', false],
      [recoveryKeyDerivationFragment, 'credvault/v1/recovery-key-wrap', false],
      [deviceKeyDerivationFragment, 'credvault/v1/device-key-wrap', true],
    ] as const;
    for (const [fragment, context, hasProvider] of contexts) {
      const branchProperties = properties(fragment);
      expect(Object.keys(branchProperties)).toEqual(fragment.required);
      expect(enumValue(property(fragment, 'algorithm'))).toBe('hkdf-sha256');
      expect(enumValue(property(fragment, 'version'))).toBe(1);
      expect(enumValue(property(fragment, 'context'))).toBe(context);
      expect(enumValue(property(fragment, 'outputLength'))).toBe(
        KEY_DERIVATION_OUTPUT_BYTES,
      );
      expect(property(fragment, 'salt')).toEqual(hkdfSaltFragment);
      expect('provider' in branchProperties).toBe(hasProvider);
    }
    expect(property(deviceKeyDerivationFragment, 'provider')).toMatchObject({
      minLength: 1,
      maxLength: MAX_DEVICE_KEY_PROVIDER_CHARS,
    });

    expect(enumValue(property(passphraseDerivationFragment, 'algorithm'))).toBe(
      'argon2id',
    );
    expect(enumValue(property(passphraseDerivationFragment, 'version'))).toBe(1);
    expect(enumValue(property(passphraseDerivationFragment, 'outputLength'))).toBe(
      KEY_DERIVATION_OUTPUT_BYTES,
    );
    expect(property(passphraseDerivationFragment, 'salt')).toEqual(
      argon2idSaltFragment,
    );
    expect(property(passphraseDerivationFragment, 'memoryKiB')).toMatchObject({
      minimum: MIN_ARGON2_MEMORY_KIB,
      maximum: MAX_ARGON2_MEMORY_KIB,
    });
    expect(property(passphraseDerivationFragment, 'passes')).toMatchObject({
      minimum: MIN_ARGON2_PASSES,
      maximum: MAX_ARGON2_PASSES,
    });
    expect(property(passphraseDerivationFragment, 'parallelism')).toMatchObject({
      minimum: MIN_ARGON2_PARALLELISM,
      maximum: MAX_ARGON2_PARALLELISM,
    });
    expect(Object.keys(properties(passphraseDerivationFragment))).toEqual(
      passphraseDerivationFragment.required,
    );
  });

  it('generates four slot types across four strict lifecycle states', () => {
    const slotBranches = branches(keySlotFragment);
    expect(slotBranches).toHaveLength(16);
    const combinations = new Set<string>();

    for (const branch of slotBranches) {
      expect(branch.additionalProperties).toBe(false);
      const branchProperties = properties(branch);
      expect(Object.keys(branchProperties)).toEqual(branch.required);
      const type = String(enumValue(property(branch, 'type')));
      const state = String(enumValue(property(branch, 'state')));
      combinations.add(`${type}:${state}`);

      const requiresDevice = type === 'device-key';
      expect('deviceId' in branchProperties).toBe(requiresDevice);
      expect(branch.required?.includes('deviceId')).toBe(requiresDevice);

      const requiresSupersededAt = state === 'superseded';
      const requiresRevokedAt = state === 'revoked';
      expect('supersededAt' in branchProperties).toBe(requiresSupersededAt);
      expect('revokedAt' in branchProperties).toBe(requiresRevokedAt);
      expect(branch.required?.includes('supersededAt')).toBe(requiresSupersededAt);
      expect(branch.required?.includes('revokedAt')).toBe(requiresRevokedAt);

      const expectedDerivation = {
        'portable-key': portableKeyDerivationFragment,
        passphrase: passphraseDerivationFragment,
        'recovery-key': recoveryKeyDerivationFragment,
        'device-key': deviceKeyDerivationFragment,
      }[type];
      expect(expectedDerivation).toBeDefined();
      expect(property(branch, 'derivation')).toEqual(expectedDerivation);

      const wrappedRootAad = branches(
        property(property(branch, 'wrappedRootKey'), 'aad'),
      );
      expect(wrappedRootAad).toHaveLength(1);
      expect(
        enumValue(
          property(
            firstBranch(property(property(branch, 'wrappedRootKey'), 'aad')),
            'entityType',
          ),
        ),
      ).toBe('wrapped-root-key');
    }
    expect(combinations.size).toBe(16);
  });

  it('bounds strict secretstream header/chunk and persisted record shapes', () => {
    for (const fragment of [
      attachmentSecretStreamHeaderRecordFragment,
      attachmentSecretStreamChunkRecordFragment,
      persistedAttachmentHeaderFragment,
      persistedAttachmentChunkFragment,
    ]) {
      expect(fragment.additionalProperties).toBe(false);
      expect(Object.keys(properties(fragment))).toEqual(fragment.required);
    }
    expect(
      enumValue(property(attachmentSecretStreamHeaderRecordFragment, 'version')),
    ).toBe(1);
    expect(
      enumValue(property(attachmentSecretStreamHeaderRecordFragment, 'streamVersion')),
    ).toBe(1);
    expect(property(attachmentSecretStreamHeaderRecordFragment, 'header')).toEqual(
      secretStreamHeaderFragment,
    );

    expect(property(attachmentSecretStreamChunkRecordFragment, 'index')).toMatchObject({
      minimum: 0,
      maximum: MAX_ATTACHMENT_CHUNKS - 1,
    });
    expect(property(attachmentSecretStreamChunkRecordFragment, 'ciphertext')).toEqual(
      attachmentChunkCiphertextFragment,
    );

    expect(property(persistedAttachmentHeaderFragment, 'record')).toEqual(
      attachmentSecretStreamHeaderRecordFragment,
    );
    expect(property(persistedAttachmentHeaderFragment, 'contentHash')).toEqual(
      sha256DigestFragment,
    );

    expect(property(persistedAttachmentChunkFragment, 'record')).toEqual(
      attachmentSecretStreamChunkRecordFragment,
    );
    expect(property(persistedAttachmentChunkFragment, 'plaintextBytes')).toMatchObject({
      minimum: 0,
      maximum: MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
    });
    expect(property(persistedAttachmentChunkFragment, 'recordRevision')).toMatchObject({
      minimum: 0,
      maximum: MAX_SEMANTIC_REVISION,
    });
  });

  it('emits only Mongo-supported structural keywords and no plaintext fields', () => {
    const allFragments = {
      associatedDataFragment,
      aeadEnvelopeFragment,
      encryptedDeviceLabelFragment,
      keyDerivationFragment,
      keySlotFragment,
      persistedAttachmentChunkFragment,
    };
    const keywords = schemaKeywords(allFragments);
    for (const forbidden of ['$ref', '$schema', 'default', 'definitions', 'format']) {
      expect(keywords).not.toContain(forbidden);
    }
    const serialized = JSON.stringify(allFragments);
    expect(serialized).not.toContain('"integer"');
    expect(serialized).not.toContain('"decimal"');
    expect(serialized).not.toContain('"password"');
    expect(serialized).not.toContain('"secretValue"');
    expect(serialized).not.toContain('"decrypted"');
    expect(serialized).toContain('"maximum":' + String(MAX_SEMANTIC_VERSION));
  });
});
