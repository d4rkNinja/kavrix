import { describe, expect, it } from 'vitest';

import {
  AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS,
  AEAD_NONCE_BASE64URL_CHARS,
  aeadEnvelopeSchema,
  ARGON2ID_SALT_BASE64URL_CHARS,
  associatedDataSchema,
  attachmentChunkCiphertextSchema,
  attachmentHeaderContentHash,
  attachmentSecretStreamManifestSchema,
  attachmentSecretStreamRecordSchema,
  attachmentStreamFinalizeInputSchema,
  attachmentStreamProgressSchema,
  attachmentStreamStartInputSchema,
  base64UrlSchema,
  CANONICAL_BASE64URL_PATTERN_SOURCE,
  deviceRecordSchema,
  deviceKeyDerivationSchema,
  encryptedBackupHeaderSchema,
  encryptedDeviceLabelSchema,
  encryptedAttachmentRecordSchema,
  encryptedItemRecordSchema,
  HKDF_SALT_BASE64URL_CHARS,
  KEY_DERIVATION_OUTPUT_BYTES,
  keySlotSchema,
  MAX_ARGON2_MEMORY_KIB,
  MAX_ARGON2_PARALLELISM,
  MAX_ARGON2_PASSES,
  MAX_ATTACHMENT_CHUNK_CIPHERTEXT_BYTES,
  MAX_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
  MAX_DEVICE_KEY_PROVIDER_CHARS,
  MAX_ENCRYPTED_DEVICE_LABEL_CIPHERTEXT_CHARS,
  MAX_OPAQUE_ID_CHARS,
  MIN_ARGON2_MEMORY_KIB,
  MIN_ARGON2_PARALLELISM,
  MIN_ARGON2_PASSES,
  MIN_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
  MIN_OPAQUE_ID_CHARS,
  OPAQUE_ID_PATTERN_SOURCE,
  opaqueMutationSchema,
  passphraseDerivationSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  positiveVersionSchema,
  protectedLocalDeviceStateSchema,
  SECRETSTREAM_HEADER_BASE64URL_CHARS,
  SHA256_DIGEST_BASE64URL_CHARS,
  sha256DigestSchema,
  timestampSchema,
  vaultIdSchema,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const purposeByEntity: Readonly<Record<string, string>> = {
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
};

function envelope(
  entityType: string,
  entityId: string,
  groupId?: string,
  parentId?: string,
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
      vaultId: 'vault.1',
      entityType,
      entityId,
      ...(groupId === undefined ? {} : { groupId }),
      ...(parentId === undefined ? {} : { parentId }),
      purpose: purposeByEntity[entityType],
    },
    keyVersion: 1,
  };
}

describe('opaque persisted records', () => {
  it('exports exact Mongo-independent identifier and cryptographic bounds', () => {
    expect({
      MIN_OPAQUE_ID_CHARS,
      MAX_OPAQUE_ID_CHARS,
      OPAQUE_ID_PATTERN_SOURCE,
      SHA256_DIGEST_BASE64URL_CHARS,
      AEAD_NONCE_BASE64URL_CHARS,
      AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS,
      SECRETSTREAM_HEADER_BASE64URL_CHARS,
      MIN_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
      MAX_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS,
      HKDF_SALT_BASE64URL_CHARS,
      ARGON2ID_SALT_BASE64URL_CHARS,
      KEY_DERIVATION_OUTPUT_BYTES,
      MIN_ARGON2_MEMORY_KIB,
      MAX_ARGON2_MEMORY_KIB,
      MIN_ARGON2_PASSES,
      MAX_ARGON2_PASSES,
      MIN_ARGON2_PARALLELISM,
      MAX_ARGON2_PARALLELISM,
      MAX_DEVICE_KEY_PROVIDER_CHARS,
    }).toEqual({
      MIN_OPAQUE_ID_CHARS: 1,
      MAX_OPAQUE_ID_CHARS: 128,
      OPAQUE_ID_PATTERN_SOURCE: '^[A-Za-z0-9][A-Za-z0-9._~-]*$',
      SHA256_DIGEST_BASE64URL_CHARS: 43,
      AEAD_NONCE_BASE64URL_CHARS: 32,
      AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS: 22,
      SECRETSTREAM_HEADER_BASE64URL_CHARS: 32,
      MIN_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS: 23,
      MAX_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS: 11_184_834,
      HKDF_SALT_BASE64URL_CHARS: 43,
      ARGON2ID_SALT_BASE64URL_CHARS: 22,
      KEY_DERIVATION_OUTPUT_BYTES: 32,
      MIN_ARGON2_MEMORY_KIB: 65_536,
      MAX_ARGON2_MEMORY_KIB: 1_048_576,
      MIN_ARGON2_PASSES: 3,
      MAX_ARGON2_PASSES: 64,
      MIN_ARGON2_PARALLELISM: 4,
      MAX_ARGON2_PARALLELISM: 32,
      MAX_DEVICE_KEY_PROVIDER_CHARS: 128,
    });
  });

  it('applies the exported opaque-ID and fixed encoded-length boundaries', () => {
    expect(vaultIdSchema.safeParse('a'.repeat(MIN_OPAQUE_ID_CHARS)).success).toBe(true);
    expect(vaultIdSchema.safeParse('a'.repeat(MAX_OPAQUE_ID_CHARS)).success).toBe(true);
    for (const invalid of [
      '',
      'a'.repeat(MAX_OPAQUE_ID_CHARS + 1),
      '_not-leading-alphanumeric',
    ]) {
      expect(vaultIdSchema.safeParse(invalid).success).toBe(false);
    }

    const validEnvelope = envelope('group', 'group.1');
    expect(
      aeadEnvelopeSchema.safeParse({
        ...validEnvelope,
        nonce: 'A'.repeat(AEAD_NONCE_BASE64URL_CHARS),
        authenticationTag: 'A'.repeat(AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS),
      }).success,
    ).toBe(true);
    expect(
      aeadEnvelopeSchema.safeParse({
        ...validEnvelope,
        nonce: 'A'.repeat(AEAD_NONCE_BASE64URL_CHARS - 1),
      }).success,
    ).toBe(false);
    expect(
      aeadEnvelopeSchema.safeParse({
        ...validEnvelope,
        authenticationTag: 'A'.repeat(AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS + 2),
      }).success,
    ).toBe(false);

    const streamHeader = {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: 'vault.1',
      groupId: 'group.1',
      itemId: 'item.1',
      attachmentId: 'attachment.1',
      recordType: 'header',
    };
    expect(
      attachmentSecretStreamRecordSchema.safeParse({
        ...streamHeader,
        header: 'A'.repeat(SECRETSTREAM_HEADER_BASE64URL_CHARS),
      }).success,
    ).toBe(true);
    expect(
      attachmentSecretStreamRecordSchema.safeParse({
        ...streamHeader,
        header: 'A'.repeat(SECRETSTREAM_HEADER_BASE64URL_CHARS - 1),
      }).success,
    ).toBe(false);
  });

  it('bounds versions to canonical unsigned 32-bit integers', () => {
    expect(positiveVersionSchema.parse(0xff_ff_ff_ff)).toBe(0xff_ff_ff_ff);
    expect(() => positiveVersionSchema.parse(0x1_0000_0000)).toThrow();
  });

  it('defines incremental hidden attachment staging inputs and records', () => {
    const identity = {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: 'vault.1',
      groupId: 'group.1',
      itemId: 'item.1',
      attachmentId: 'attachment.1',
    } as const;
    const header = attachmentSecretStreamRecordSchema.parse({
      ...identity,
      recordType: 'header',
      header: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    });
    const chunk = attachmentSecretStreamRecordSchema.parse({
      ...identity,
      recordType: 'chunk',
      index: 0,
      ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAA',
      tag: 'final',
    });
    expect(header).toBeDefined();
    expect(chunk).toBeDefined();
    const initialPersistedHeader = persistedAttachmentHeaderRecordSchema.parse({
      entityType: 'attachment-header',
      record: header,
      recordRevision: 0,
      contentHash: digest,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    const persistedHeader = persistedAttachmentHeaderRecordSchema.parse({
      ...initialPersistedHeader,
      contentHash: attachmentHeaderContentHash(initialPersistedHeader),
    });
    const persistedChunk = persistedAttachmentChunkRecordSchema.parse({
      entityType: 'attachment-chunk',
      record: chunk,
      plaintextBytes: 0,
      recordRevision: 0,
      ciphertextHash: digest,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    expect(persistedChunk.plaintextBytes).toBe(0);
    expect(
      opaqueMutationSchema.safeParse({
        entityType: 'attachment-header',
        expectedRecordRevision: null,
        idempotencyKey: 'idempotency-key-1',
        record: persistedHeader,
      }).success,
    ).toBe(false);
    expect(
      opaqueMutationSchema.safeParse({
        entityType: 'attachment',
        expectedRecordRevision: null,
        idempotencyKey: 'idempotency-key-3',
        record: {
          id: 'attachment.1',
          vaultId: 'vault.1',
          groupId: 'group.1',
          itemId: 'item.1',
          schemaVersion: 1,
          wrappedAttachmentKey: envelope(
            'wrapped-attachment-key',
            'attachment.1',
            'group.1',
            'item.1',
          ),
          encryptedManifest: envelope(
            'attachment',
            'attachment.1',
            'group.1',
            'item.1',
          ),
          chunkCount: 1,
          recordRevision: 0,
          createdAt: timestamp,
          updatedAt: timestamp,
        },
      }).success,
    ).toBe(false);
    expect(
      opaqueMutationSchema.safeParse({
        entityType: 'attachment-chunk',
        expectedRecordRevision: null,
        idempotencyKey: 'idempotency-key-2',
        record: persistedChunk,
      }).success,
    ).toBe(false);
    expect(
      attachmentStreamStartInputSchema.safeParse({
        version: 1,
        idempotencyKey: 'attachment-stream-1',
        expectedAttachmentRevision: null,
        header: persistedHeader,
      }).success,
    ).toBe(true);
    expect(
      attachmentStreamStartInputSchema.safeParse({
        version: 1,
        idempotencyKey: 'attachment-stream-1',
        expectedAttachmentRevision: 0,
        header: persistedHeader,
      }).success,
    ).toBe(false);
    expect(
      attachmentStreamProgressSchema.safeParse({
        version: 1,
        state: 'ready-to-finalize',
        nextChunkIndex: 1,
        totalPlaintextBytes: 0,
        totalCiphertextBytes: 17,
        lastChunkIndex: 0,
        lastChunkCiphertextHash: digest,
        lastChunkPlaintextBytes: 0,
      }).success,
    ).toBe(true);
    expect(
      attachmentStreamProgressSchema.safeParse({
        version: 1,
        state: 'writing',
        nextChunkIndex: 1,
        totalPlaintextBytes: 0,
        totalCiphertextBytes: 18,
        lastChunkIndex: 0,
        lastChunkCiphertextHash: digest,
        lastChunkPlaintextBytes: 0,
      }).success,
    ).toBe(false);
    expect(
      attachmentStreamFinalizeInputSchema.safeParse({
        version: 1,
        record: {
          id: 'attachment.1',
          vaultId: 'vault.1',
          groupId: 'group.1',
          itemId: 'item.1',
          schemaVersion: 1,
          wrappedAttachmentKey: envelope(
            'wrapped-attachment-key',
            'attachment.1',
            'group.1',
            'item.1',
          ),
          encryptedManifest: envelope(
            'attachment',
            'attachment.1',
            'group.1',
            'item.1',
          ),
          chunkCount: 1,
          recordRevision: 0,
          createdAt: timestamp,
          updatedAt: timestamp,
        },
      }).success,
    ).toBe(true);
    expect(
      attachmentSecretStreamRecordSchema.parse({
        ...identity,
        recordType: 'header',
        header: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      }),
    ).toBeDefined();
    expect(
      attachmentSecretStreamManifestSchema.parse({
        ...identity,
        manifestVersion: 1,
        header: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        chunkCount: 1,
        totalPlaintextBytes: 0,
        plaintextSha256: digest,
      }),
    ).toBeDefined();
    expect(() =>
      attachmentSecretStreamRecordSchema.parse({
        ...identity,
        recordType: 'chunk',
        index: 1_000_000,
        ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAA',
        tag: 'final',
      }),
    ).toThrow();
  });

  it('bounds decoded attachment ciphertext to 8 MiB plus stream overhead', () => {
    const minimum = Buffer.alloc(17).toString('base64url');
    const maximum = Buffer.alloc(MAX_ATTACHMENT_CHUNK_CIPHERTEXT_BYTES).toString(
      'base64url',
    );
    const oversized = Buffer.alloc(MAX_ATTACHMENT_CHUNK_CIPHERTEXT_BYTES + 1).toString(
      'base64url',
    );
    expect(minimum).toHaveLength(MIN_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS);
    expect(maximum).toHaveLength(MAX_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS);
    expect(attachmentChunkCiphertextSchema.safeParse(minimum).success).toBe(true);
    expect(attachmentChunkCiphertextSchema.safeParse(maximum).success).toBe(true);
    expect(attachmentChunkCiphertextSchema.safeParse(oversized).success).toBe(false);
    expect(attachmentChunkCiphertextSchema.safeParse('AQID').success).toBe(false);
  });
  it('rejects ciphertext associated with another item', () => {
    const parsed = encryptedItemRecordSchema.safeParse({
      id: 'item.1',
      vaultId: 'vault.1',
      groupId: 'group.1',
      schemaVersion: 1,
      wrappedItemKey: envelope('wrapped-item-key', 'item.1', 'group.1'),
      encryptedPayload: envelope('item', 'item.2', 'group.1'),
      recordRevision: 1,
      ciphertextHash: digest,
      createdAt: timestamp,
      updatedAt: timestamp,
    });

    expect(parsed.success).toBe(false);
  });

  it('contains no plaintext content fields', () => {
    const persisted = encryptedItemRecordSchema.parse({
      id: 'item.1',
      vaultId: 'vault.1',
      groupId: 'group.1',
      schemaVersion: 1,
      wrappedItemKey: envelope('wrapped-item-key', 'item.1', 'group.1'),
      encryptedPayload: envelope('item', 'item.1', 'group.1'),
      recordRevision: 1,
      ciphertextHash: digest,
      createdAt: timestamp,
      updatedAt: timestamp,
    });

    expect(Object.keys(persisted)).not.toContain('title');
    expect(JSON.stringify(persisted)).not.toContain('canary-plaintext-value');
  });

  it('binds wrapped root keys to their slot ID', () => {
    const parsed = keySlotSchema.safeParse({
      id: 'slot.1',
      slotVersion: 1,
      type: 'portable-key',
      state: 'active',
      keyVersion: 1,
      derivation: {
        algorithm: 'hkdf-sha256',
        version: 1,
        salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        context: 'credvault/v1/portable-key-wrap',
        outputLength: 32,
      },
      wrappedRootKey: envelope('wrapped-root-key', 'slot.other'),
      createdAt: timestamp,
    });

    expect(parsed.success).toBe(false);
  });

  it('versions the complete key-slot shape and requires an exact HKDF salt', () => {
    const slot = {
      id: 'slot.1',
      slotVersion: 1,
      type: 'portable-key',
      state: 'active',
      keyVersion: 1,
      derivation: {
        algorithm: 'hkdf-sha256',
        version: 1,
        salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        context: 'credvault/v1/portable-key-wrap',
        outputLength: 32,
      },
      wrappedRootKey: envelope('wrapped-root-key', 'slot.1'),
      createdAt: timestamp,
    };

    expect(keySlotSchema.safeParse(slot).success).toBe(true);
    expect(keySlotSchema.safeParse({ ...slot, slotVersion: 2 }).success).toBe(false);
    expect(
      keySlotSchema.safeParse({
        ...slot,
        derivation: { ...slot.derivation, salt: 'AAAAAAAAAAAAAAAAAAAAAA' },
      }).success,
    ).toBe(false);
  });

  it('binds attachments to their vault, group, item, and attachment IDs', () => {
    const base = {
      id: 'attachment.1',
      vaultId: 'vault.1',
      groupId: 'group.1',
      itemId: 'item.1',
      schemaVersion: 1,
      wrappedAttachmentKey: envelope(
        'wrapped-attachment-key',
        'attachment.1',
        'group.1',
        'item.1',
      ),
      encryptedManifest: envelope('attachment', 'attachment.1', 'group.1', 'item.1'),
      chunkCount: 1,
      recordRevision: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    };

    expect(encryptedAttachmentRecordSchema.safeParse(base).success).toBe(true);
    for (const encryptedManifest of [
      envelope('attachment', 'attachment.other', 'group.1', 'item.1'),
      envelope('attachment', 'attachment.1', 'group.other', 'item.1'),
      envelope('attachment', 'attachment.1', 'group.1', 'item.other'),
    ]) {
      expect(
        encryptedAttachmentRecordSchema.safeParse({
          ...base,
          encryptedManifest,
        }).success,
      ).toBe(false);
    }
  });

  it('provides a distinct closed purpose for attachment chunks', () => {
    expect(
      aeadEnvelopeSchema.safeParse(
        envelope('attachment-chunk', 'attachment.1', 'group.1', 'item.1'),
      ).success,
    ).toBe(true);
    expect(
      aeadEnvelopeSchema.safeParse({
        ...envelope('attachment-chunk', 'attachment.1', 'group.1', 'item.1'),
        aad: {
          ...(envelope('attachment-chunk', 'attachment.1', 'group.1', 'item.1')[
            'aad'
          ] as Record<string, unknown>),
          purpose: 'attachment-metadata',
        },
      }).success,
    ).toBe(false);
  });

  it('authenticates schema and key versions inside every envelope', () => {
    const valid = envelope('group', 'group.1');
    expect(aeadEnvelopeSchema.safeParse(valid).success).toBe(true);
    expect(aeadEnvelopeSchema.safeParse({ ...valid, keyVersion: 2 }).success).toBe(
      false,
    );
    expect(
      aeadEnvelopeSchema.safeParse({
        ...valid,
        aad: { ...(valid['aad'] as Record<string, unknown>), schemaVersion: 0 },
      }).success,
    ).toBe(false);
  });

  it('keeps standalone AAD values broad while current envelopes fail closed', () => {
    const futureEnvelope = envelope('group', 'group.1');
    const futureAad = {
      ...(futureEnvelope['aad'] as Record<string, unknown>),
      schemaVersion: 2,
    };

    expect(associatedDataSchema.safeParse(futureAad).success).toBe(true);
    expect(
      aeadEnvelopeSchema.safeParse({ ...futureEnvelope, aad: futureAad }).success,
    ).toBe(false);
  });

  it('bounds only encrypted device-label ciphertexts to 4,096 characters', () => {
    const label = envelope('device-label', 'device.1');
    const maximum = 'A'.repeat(MAX_ENCRYPTED_DEVICE_LABEL_CIPHERTEXT_CHARS);
    const nextCanonicalLength = 'A'.repeat(
      MAX_ENCRYPTED_DEVICE_LABEL_CIPHERTEXT_CHARS + 2,
    );

    expect(
      encryptedDeviceLabelSchema.safeParse({ ...label, ciphertext: maximum }).success,
    ).toBe(true);
    expect(
      encryptedDeviceLabelSchema.safeParse({
        ...label,
        ciphertext: nextCanonicalLength,
      }).success,
    ).toBe(false);
    expect(
      aeadEnvelopeSchema.safeParse({ ...label, ciphertext: nextCanonicalLength })
        .success,
    ).toBe(true);
    expect(
      encryptedDeviceLabelSchema.safeParse(envelope('group', 'group.1')).success,
    ).toBe(false);
    expect(
      encryptedDeviceLabelSchema.safeParse({
        ...label,
        aad: {
          ...(label['aad'] as Record<string, unknown>),
          purpose: 'audit-event',
        },
      }).success,
    ).toBe(false);
  });

  it('rejects unknown algorithms and mismatched payload purposes', () => {
    const valid = envelope('group', 'group.1');
    expect(
      aeadEnvelopeSchema.safeParse({ ...valid, algorithm: 'aes-256-gcm' }).success,
    ).toBe(false);
    expect(
      aeadEnvelopeSchema.safeParse({
        ...valid,
        aad: { ...(valid['aad'] as Record<string, unknown>), purpose: 'item-payload' },
      }).success,
    ).toBe(false);
  });
});

describe('canonical public encodings', () => {
  it('rejects non-canonical base64url and non-UTC timestamps', () => {
    expect(CANONICAL_BASE64URL_PATTERN_SOURCE).toBe(
      '^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$',
    );
    expect(base64UrlSchema.safeParse('AA').success).toBe(true);
    expect(base64UrlSchema.safeParse('AB').success).toBe(false);
    expect(base64UrlSchema.safeParse('AAA').success).toBe(true);
    expect(base64UrlSchema.safeParse('AAB').success).toBe(false);
    expect(sha256DigestSchema.safeParse(digest).success).toBe(true);
    expect(digest).toHaveLength(SHA256_DIGEST_BASE64URL_CHARS);
    expect(sha256DigestSchema.safeParse(`${digest.slice(0, -1)}B`).success).toBe(false);
    expect(timestampSchema.safeParse(timestamp).success).toBe(true);
    expect(timestampSchema.safeParse('2026-08-10T05:30:00.000+05:30').success).toBe(
      false,
    );
  });

  it('keeps rollback state out of the server device record', () => {
    const serverRecord = {
      id: 'device.1',
      vaultId: 'vault.1',
      schemaVersion: 1,
      tokenHash: digest,
      tokenVersion: 1,
      scopes: ['sync:read'],
      createdAt: timestamp,
    };
    expect(deviceRecordSchema.safeParse(serverRecord).success).toBe(true);
    expect(
      deviceRecordSchema.safeParse({ ...serverRecord, highestSeenVaultRevision: 5 })
        .success,
    ).toBe(false);
    expect(
      protectedLocalDeviceStateSchema.safeParse({
        version: 2,
        vaultId: 'vault.1',
        deviceId: 'device.1',
        highestSeenVaultRevision: 5,
        updatedAt: timestamp,
      }).success,
    ).toBe(true);
  });

  it('rejects unknown backup and persisted attachment-stream schema versions', () => {
    const header = {
      type: 'header',
      format: 'kavrix-encrypted-backup',
      version: 1,
      vaultId: 'vault.1',
      schemaVersion: 1,
      createdAt: timestamp,
      authentication: {
        algorithm: 'hkdf-sha256+hmac-sha256',
        salt: digest,
      },
    };
    const streamHeader = {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: 'vault.1',
      groupId: 'group.1',
      itemId: 'item.1',
      attachmentId: 'attachment.1',
      recordType: 'header',
      header: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    };
    const streamChunk = {
      version: streamHeader.version,
      algorithm: streamHeader.algorithm,
      streamVersion: streamHeader.streamVersion,
      schemaVersion: streamHeader.schemaVersion,
      keyVersion: streamHeader.keyVersion,
      vaultId: streamHeader.vaultId,
      groupId: streamHeader.groupId,
      itemId: streamHeader.itemId,
      attachmentId: streamHeader.attachmentId,
      recordType: 'chunk',
      index: 0,
      ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAA',
      tag: 'final',
    };
    const streamManifest = {
      version: streamHeader.version,
      algorithm: streamHeader.algorithm,
      streamVersion: streamHeader.streamVersion,
      schemaVersion: streamHeader.schemaVersion,
      keyVersion: streamHeader.keyVersion,
      vaultId: streamHeader.vaultId,
      groupId: streamHeader.groupId,
      itemId: streamHeader.itemId,
      attachmentId: streamHeader.attachmentId,
      manifestVersion: 1,
      header: streamHeader.header,
      chunkCount: 1,
      totalPlaintextBytes: 0,
      plaintextSha256: digest,
    };
    const persistedHeader = {
      entityType: 'attachment-header',
      record: streamHeader,
      recordRevision: 0,
      contentHash: digest,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    const persistedChunk = {
      entityType: 'attachment-chunk',
      record: streamChunk,
      plaintextBytes: 0,
      recordRevision: 0,
      ciphertextHash: digest,
      createdAt: timestamp,
      updatedAt: timestamp,
    };

    expect(encryptedBackupHeaderSchema.safeParse(header).success).toBe(true);
    expect(
      encryptedBackupHeaderSchema.safeParse({ ...header, schemaVersion: 2 }).success,
    ).toBe(false);
    expect(attachmentSecretStreamRecordSchema.safeParse(streamHeader).success).toBe(
      true,
    );
    expect(
      attachmentSecretStreamRecordSchema.safeParse({
        ...streamHeader,
        schemaVersion: 2,
      }).success,
    ).toBe(false);
    expect(attachmentSecretStreamRecordSchema.safeParse(streamChunk).success).toBe(
      true,
    );
    expect(
      attachmentSecretStreamRecordSchema.safeParse({
        ...streamChunk,
        schemaVersion: 2,
      }).success,
    ).toBe(false);
    expect(attachmentSecretStreamManifestSchema.safeParse(streamManifest).success).toBe(
      true,
    );
    expect(
      attachmentSecretStreamManifestSchema.safeParse({
        ...streamManifest,
        schemaVersion: 2,
      }).success,
    ).toBe(false);
    expect(
      persistedAttachmentHeaderRecordSchema.safeParse(persistedHeader).success,
    ).toBe(true);
    expect(
      persistedAttachmentHeaderRecordSchema.safeParse({
        ...persistedHeader,
        record: { ...streamHeader, schemaVersion: 2 },
      }).success,
    ).toBe(false);
    expect(persistedAttachmentChunkRecordSchema.safeParse(persistedChunk).success).toBe(
      true,
    );
    expect(
      persistedAttachmentChunkRecordSchema.safeParse({
        ...persistedChunk,
        record: { ...streamChunk, schemaVersion: 2 },
      }).success,
    ).toBe(false);
  });
});

describe('Argon2id metadata', () => {
  it('uses canonical passes metadata and enforces the parallelism floor', () => {
    const metadata = {
      algorithm: 'argon2id',
      version: 1,
      salt: 'AAAAAAAAAAAAAAAAAAAAAA',
      memoryKiB: 65_536,
      passes: 3,
      parallelism: 4,
      outputLength: 32,
    };

    expect(passphraseDerivationSchema.safeParse(metadata).success).toBe(true);
    // Profile v1 pins Argon2 v=0x13 semantics; 0x13 is not a profile number.
    for (const unsupportedProfileVersion of [2, 0x13]) {
      expect(
        passphraseDerivationSchema.safeParse({
          ...metadata,
          version: unsupportedProfileVersion,
        }).success,
      ).toBe(false);
    }
    expect(
      passphraseDerivationSchema.safeParse({
        ...metadata,
        salt: 'A'.repeat(ARGON2ID_SALT_BASE64URL_CHARS),
        memoryKiB: MAX_ARGON2_MEMORY_KIB,
        passes: MAX_ARGON2_PASSES,
        parallelism: MAX_ARGON2_PARALLELISM,
        outputLength: KEY_DERIVATION_OUTPUT_BYTES,
      }).success,
    ).toBe(true);
    // Profile v1 pins Argon2 v=0x13 semantics; 0x13 is not a profile number.
    for (const unsupportedProfileVersion of [2, 0x13]) {
      expect(
        passphraseDerivationSchema.safeParse({
          ...metadata,
          version: unsupportedProfileVersion,
        }).success,
      ).toBe(false);
    }
    for (const changed of [
      { memoryKiB: MIN_ARGON2_MEMORY_KIB - 1 },
      { memoryKiB: MAX_ARGON2_MEMORY_KIB + 1 },
      { passes: MIN_ARGON2_PASSES - 1 },
      { passes: MAX_ARGON2_PASSES + 1 },
      { parallelism: MIN_ARGON2_PARALLELISM - 1 },
      { parallelism: MAX_ARGON2_PARALLELISM + 1 },
      { outputLength: KEY_DERIVATION_OUTPUT_BYTES + 1 },
    ]) {
      expect(
        passphraseDerivationSchema.safeParse({ ...metadata, ...changed }).success,
      ).toBe(false);
    }
    expect(
      passphraseDerivationSchema.safeParse({
        ...metadata,
        salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      }).success,
    ).toBe(false);
    expect(
      passphraseDerivationSchema.safeParse({
        ...metadata,
        passes: undefined,
        iterations: 3,
      }).success,
    ).toBe(false);
  });
});

describe('device-key derivation metadata', () => {
  it('serializes the per-slot HKDF salt and canonical context', () => {
    const metadata = {
      algorithm: 'hkdf-sha256',
      version: 1,
      salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      context: 'credvault/v1/device-key-wrap',
      outputLength: 32,
      provider: 'os-keychain',
    };

    expect(deviceKeyDerivationSchema.safeParse(metadata).success).toBe(true);
    expect(
      deviceKeyDerivationSchema.safeParse({
        ...metadata,
        salt: 'A'.repeat(HKDF_SALT_BASE64URL_CHARS),
        outputLength: KEY_DERIVATION_OUTPUT_BYTES,
        provider: 'p'.repeat(MAX_DEVICE_KEY_PROVIDER_CHARS),
      }).success,
    ).toBe(true);
    expect(
      deviceKeyDerivationSchema.safeParse({ ...metadata, algorithm: 'device-key' })
        .success,
    ).toBe(false);
    expect(
      deviceKeyDerivationSchema.safeParse({
        ...metadata,
        salt: 'AAAAAAAAAAAAAAAAAAAAAA',
      }).success,
    ).toBe(false);
    expect(
      deviceKeyDerivationSchema.safeParse({
        ...metadata,
        provider: 'p'.repeat(MAX_DEVICE_KEY_PROVIDER_CHARS + 1),
      }).success,
    ).toBe(false);
  });
});
