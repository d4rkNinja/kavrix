import { describe, expect, it } from 'vitest';

import {
  aeadEnvelopeSchema,
  attachmentChunkCiphertextSchema,
  attachmentSecretStreamManifestSchema,
  attachmentSecretStreamRecordSchema,
  attachmentStreamFinalizeInputSchema,
  attachmentStreamProgressSchema,
  attachmentStreamStartInputSchema,
  base64UrlSchema,
  deviceRecordSchema,
  deviceKeyDerivationSchema,
  encryptedAttachmentRecordSchema,
  encryptedItemRecordSchema,
  keySlotSchema,
  MAX_ATTACHMENT_CHUNK_CIPHERTEXT_BYTES,
  opaqueMutationSchema,
  passphraseDerivationSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  positiveVersionSchema,
  protectedLocalDeviceStateSchema,
  sha256DigestSchema,
  timestampSchema,
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
    const persistedHeader = persistedAttachmentHeaderRecordSchema.parse({
      entityType: 'attachment-header',
      record: header,
      recordRevision: 0,
      contentHash: digest,
      createdAt: timestamp,
      updatedAt: timestamp,
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
    const maximum = Buffer.alloc(MAX_ATTACHMENT_CHUNK_CIPHERTEXT_BYTES).toString(
      'base64url',
    );
    const oversized = Buffer.alloc(MAX_ATTACHMENT_CHUNK_CIPHERTEXT_BYTES + 1).toString(
      'base64url',
    );
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
    expect(base64UrlSchema.safeParse('AA').success).toBe(true);
    expect(base64UrlSchema.safeParse('AB').success).toBe(false);
    expect(sha256DigestSchema.safeParse(digest).success).toBe(true);
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
        vaultId: 'vault.1',
        deviceId: 'device.1',
        highestSeenVaultRevision: 5,
        updatedAt: timestamp,
      }).success,
    ).toBe(true);
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
    expect(
      passphraseDerivationSchema.safeParse({
        ...metadata,
        parallelism: 1,
      }).success,
    ).toBe(false);
    expect(
      passphraseDerivationSchema.safeParse({
        ...metadata,
        memoryKiB: 1_048_577,
      }).success,
    ).toBe(false);
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
      deviceKeyDerivationSchema.safeParse({ ...metadata, algorithm: 'device-key' })
        .success,
    ).toBe(false);
    expect(
      deviceKeyDerivationSchema.safeParse({
        ...metadata,
        salt: 'AAAAAAAAAAAAAAAAAAAAAA',
      }).success,
    ).toBe(false);
  });
});
