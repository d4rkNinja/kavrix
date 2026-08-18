import { z } from 'zod';

import {
  attachmentIdSchema,
  auditEventIdSchema,
  deviceIdSchema,
  groupIdSchema,
  historyIdSchema,
  itemIdSchema,
  keySlotIdSchema,
  vaultIdSchema,
} from './identifiers.js';
import {
  base64UrlSchema,
  associatedDataVersionSchema,
  keyVersionSchema,
  keySlotVersionSchema,
  recordRevisionSchema,
  schemaVersionSchema,
  sha256DigestSchema,
  supportedCryptographicVersionSchema,
  supportedSchemaVersionSchema,
  templateVersionSchema,
  timestampSchema,
  vaultRevisionSchema,
  envelopeVersionSchema,
} from './primitives.js';

export const encryptedEntityTypeSchema = z.enum([
  'vault-preferences',
  'group',
  'item',
  'attachment',
  'attachment-chunk',
  'audit-event',
  'history',
  'device-label',
  'wrapped-root-key',
  'wrapped-group-key',
  'wrapped-item-key',
  'wrapped-attachment-key',
]);

export const encryptedPayloadPurposeSchema = z.enum([
  'vault-preferences',
  'group-payload',
  'item-payload',
  'attachment-metadata',
  'attachment-chunk',
  'audit-event',
  'history-event',
  'device-label',
  'vrk-slot',
  'group-key',
  'item-key',
  'attachment-key',
]);

export const AEAD_NONCE_BASE64URL_CHARS = 32;
export const AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS = 22;

const associatedDataBaseSchema = z
  .object({
    version: associatedDataVersionSchema,
    schemaVersion: schemaVersionSchema,
    keyVersion: keyVersionSchema,
    vaultId: vaultIdSchema,
    revision: vaultRevisionSchema.optional(),
    metadataDigest: sha256DigestSchema.optional(),
  })
  .strict();

const unboundAssociatedData = {
  groupId: z.undefined().optional(),
  parentId: z.undefined().optional(),
};

/**
 * Standalone AAD encoding/migration primitive. Its broad schema-version value
 * is not permission to decrypt, persist, or overwrite an unknown record format.
 */
export const associatedDataSchema = z.discriminatedUnion('entityType', [
  associatedDataBaseSchema.extend({
    entityType: z.literal('vault-preferences'),
    entityId: vaultIdSchema,
    purpose: z.literal('vault-preferences'),
    ...unboundAssociatedData,
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('group'),
    entityId: groupIdSchema,
    purpose: z.literal('group-payload'),
    ...unboundAssociatedData,
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('item'),
    entityId: itemIdSchema,
    purpose: z.literal('item-payload'),
    groupId: groupIdSchema,
    parentId: z.undefined().optional(),
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('attachment'),
    entityId: attachmentIdSchema,
    purpose: z.literal('attachment-metadata'),
    groupId: groupIdSchema,
    parentId: itemIdSchema,
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('attachment-chunk'),
    entityId: attachmentIdSchema,
    purpose: z.literal('attachment-chunk'),
    groupId: groupIdSchema,
    parentId: itemIdSchema,
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('audit-event'),
    entityId: auditEventIdSchema,
    purpose: z.literal('audit-event'),
    ...unboundAssociatedData,
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('history'),
    entityId: historyIdSchema,
    purpose: z.literal('history-event'),
    groupId: groupIdSchema,
    parentId: itemIdSchema,
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('device-label'),
    entityId: deviceIdSchema,
    purpose: z.literal('device-label'),
    ...unboundAssociatedData,
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('wrapped-root-key'),
    entityId: keySlotIdSchema,
    purpose: z.literal('vrk-slot'),
    ...unboundAssociatedData,
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('wrapped-group-key'),
    entityId: groupIdSchema,
    purpose: z.literal('group-key'),
    ...unboundAssociatedData,
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('wrapped-item-key'),
    entityId: itemIdSchema,
    purpose: z.literal('item-key'),
    groupId: groupIdSchema,
    parentId: z.undefined().optional(),
  }),
  associatedDataBaseSchema.extend({
    entityType: z.literal('wrapped-attachment-key'),
    entityId: attachmentIdSchema,
    purpose: z.literal('attachment-key'),
    groupId: groupIdSchema,
    parentId: itemIdSchema,
  }),
]);

const currentAssociatedDataSchema = associatedDataSchema.superRefine(
  (associatedData, context) => {
    if (!supportedSchemaVersionSchema.safeParse(associatedData.schemaVersion).success) {
      context.addIssue({
        code: 'custom',
        message: 'Current envelopes require a supported schema version',
        path: ['schemaVersion'],
      });
    }
  },
);

export const aeadEnvelopeSchema = z
  .object({
    version: envelopeVersionSchema,
    algorithm: z.literal('xchacha20-poly1305-ietf'),
    nonce: base64UrlSchema,
    ciphertext: base64UrlSchema,
    authenticationTag: base64UrlSchema,
    aad: currentAssociatedDataSchema,
    keyVersion: keyVersionSchema,
  })
  .strict()
  .superRefine((envelope, context) => {
    if (envelope.nonce.length !== AEAD_NONCE_BASE64URL_CHARS) {
      context.addIssue({
        code: 'custom',
        message: 'Nonce length does not match the authenticated-encryption algorithm',
        path: ['nonce'],
      });
    }
    if (envelope.authenticationTag.length !== AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS) {
      context.addIssue({
        code: 'custom',
        message: 'Authentication tag must encode 16 bytes',
        path: ['authenticationTag'],
      });
    }
    if (envelope.keyVersion !== envelope.aad.keyVersion) {
      context.addIssue({
        code: 'custom',
        message: 'Envelope key version must be authenticated in associated data',
        path: ['keyVersion'],
      });
    }
  });

export const MAX_ENCRYPTED_DEVICE_LABEL_CIPHERTEXT_CHARS = 4_096;

export const encryptedDeviceLabelSchema = aeadEnvelopeSchema.superRefine(
  (envelope, context) => {
    if (envelope.ciphertext.length > MAX_ENCRYPTED_DEVICE_LABEL_CIPHERTEXT_CHARS) {
      context.addIssue({
        code: 'custom',
        message: 'Encrypted device-label ciphertext exceeds the canonical bound',
        path: ['ciphertext'],
      });
    }
    if (envelope.aad.entityType !== 'device-label') {
      context.addIssue({
        code: 'custom',
        message: 'Encrypted device labels require device-label associated data',
        path: ['aad'],
      });
    }
  },
);

export const MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES = 8 * 1024 * 1024;
export const SECRETSTREAM_CHUNK_OVERHEAD_BYTES = 17;
export const MAX_ATTACHMENT_CHUNKS = 1_000_000;
export const MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES = 4 * 1024 * 1024 * 1024;
export const MAX_ATTACHMENT_CHUNK_CIPHERTEXT_BYTES =
  MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES + SECRETSTREAM_CHUNK_OVERHEAD_BYTES;
export const MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES =
  MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES +
  MAX_ATTACHMENT_CHUNKS * SECRETSTREAM_CHUNK_OVERHEAD_BYTES;
export const SECRETSTREAM_HEADER_BASE64URL_CHARS = 32;
export const MIN_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS = Math.ceil(
  (SECRETSTREAM_CHUNK_OVERHEAD_BYTES * 4) / 3,
);
export const MAX_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS = Math.ceil(
  (MAX_ATTACHMENT_CHUNK_CIPHERTEXT_BYTES * 4) / 3,
);

const secretStreamHeaderSchema = base64UrlSchema
  .length(SECRETSTREAM_HEADER_BASE64URL_CHARS)
  .refine((value) => Buffer.from(value, 'base64url').byteLength === 24, {
    error: 'Secretstream headers must canonically encode exactly 24 bytes',
  });
export const attachmentChunkCiphertextSchema = base64UrlSchema
  .min(MIN_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS)
  .max(MAX_ATTACHMENT_CHUNK_CIPHERTEXT_CHARS)
  .refine(
    (value) => {
      const byteLength = Buffer.from(value, 'base64url').byteLength;
      return (
        byteLength >= SECRETSTREAM_CHUNK_OVERHEAD_BYTES &&
        byteLength <= MAX_ATTACHMENT_CHUNK_CIPHERTEXT_BYTES
      );
    },
    { error: 'Attachment chunk ciphertext is outside the canonical byte bounds' },
  )
  .brand<'AttachmentChunkCiphertext'>();

const attachmentSecretStreamIdentitySchema = z.object({
  version: z.literal(1),
  algorithm: z.literal('secretstream-xchacha20-poly1305'),
  streamVersion: z.literal(1),
  schemaVersion: supportedSchemaVersionSchema,
  keyVersion: keyVersionSchema,
  vaultId: vaultIdSchema,
  groupId: groupIdSchema,
  itemId: itemIdSchema,
  attachmentId: attachmentIdSchema,
});

export const attachmentSecretStreamHeaderRecordSchema =
  attachmentSecretStreamIdentitySchema
    .extend({
      recordType: z.literal('header'),
      header: secretStreamHeaderSchema,
    })
    .strict();

export const attachmentSecretStreamChunkRecordSchema =
  attachmentSecretStreamIdentitySchema
    .extend({
      recordType: z.literal('chunk'),
      index: z
        .number()
        .int()
        .nonnegative()
        .max(MAX_ATTACHMENT_CHUNKS - 1),
      ciphertext: attachmentChunkCiphertextSchema,
      tag: z.enum(['message', 'final']),
    })
    .strict();

export const attachmentSecretStreamRecordSchema = z.discriminatedUnion('recordType', [
  attachmentSecretStreamHeaderRecordSchema,
  attachmentSecretStreamChunkRecordSchema,
]);

export const persistedAttachmentHeaderRecordSchema = z
  .object({
    entityType: z.literal('attachment-header'),
    record: attachmentSecretStreamHeaderRecordSchema,
    recordRevision: recordRevisionSchema,
    contentHash: sha256DigestSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const persistedAttachmentChunkRecordSchema = z
  .object({
    entityType: z.literal('attachment-chunk'),
    record: attachmentSecretStreamChunkRecordSchema,
    plaintextBytes: z
      .number()
      .int()
      .nonnegative()
      .max(MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES),
    recordRevision: recordRevisionSchema,
    ciphertextHash: sha256DigestSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((chunk, context) => {
    const ciphertextBytes = Buffer.from(
      chunk.record.ciphertext,
      'base64url',
    ).byteLength;
    if (ciphertextBytes !== chunk.plaintextBytes + SECRETSTREAM_CHUNK_OVERHEAD_BYTES) {
      context.addIssue({
        code: 'custom',
        message: 'Chunk ciphertext length must equal plaintext plus stream overhead',
        path: ['plaintextBytes'],
      });
    }
  });

// This manifest is sensitive authenticated plaintext. Persist it only inside
// encryptedAttachmentRecordSchema.encryptedManifest.
export const attachmentSecretStreamManifestSchema = attachmentSecretStreamIdentitySchema
  .extend({
    manifestVersion: z.literal(1),
    header: secretStreamHeaderSchema,
    chunkCount: z.number().int().positive().max(MAX_ATTACHMENT_CHUNKS),
    totalPlaintextBytes: z
      .number()
      .int()
      .nonnegative()
      .max(MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES),
    plaintextSha256: sha256DigestSchema,
  })
  .strict();

export const HKDF_SALT_BASE64URL_CHARS = 43;
export const ARGON2ID_SALT_BASE64URL_CHARS = 22;
export const KEY_DERIVATION_OUTPUT_BYTES = 32;
export const MIN_ARGON2_MEMORY_KIB = 65_536;
export const MAX_ARGON2_MEMORY_KIB = 1_048_576;
export const MIN_ARGON2_PASSES = 3;
export const MAX_ARGON2_PASSES = 64;
export const MIN_ARGON2_PARALLELISM = 4;
export const MAX_ARGON2_PARALLELISM = 32;
export const MAX_DEVICE_KEY_PROVIDER_CHARS = 128;

const hkdfSaltSchema = base64UrlSchema.length(HKDF_SALT_BASE64URL_CHARS);
const argon2idSaltSchema = base64UrlSchema.length(ARGON2ID_SALT_BASE64URL_CHARS);

export const portableKeyDerivationSchema = z
  .object({
    algorithm: z.literal('hkdf-sha256'),
    version: z.literal(1),
    salt: hkdfSaltSchema,
    context: z.literal('credvault/v1/portable-key-wrap'),
    outputLength: z.literal(KEY_DERIVATION_OUTPUT_BYTES),
  })
  .strict();

export const passphraseDerivationSchema = z
  .object({
    algorithm: z.literal('argon2id'),
    version: z.literal(1),
    salt: argon2idSaltSchema,
    memoryKiB: z.number().int().min(MIN_ARGON2_MEMORY_KIB).max(MAX_ARGON2_MEMORY_KIB),
    passes: z.number().int().min(MIN_ARGON2_PASSES).max(MAX_ARGON2_PASSES),
    parallelism: z
      .number()
      .int()
      .min(MIN_ARGON2_PARALLELISM)
      .max(MAX_ARGON2_PARALLELISM),
    outputLength: z.literal(KEY_DERIVATION_OUTPUT_BYTES),
  })
  .strict();

export const recoveryKeyDerivationSchema = z
  .object({
    algorithm: z.literal('hkdf-sha256'),
    version: z.literal(1),
    salt: hkdfSaltSchema,
    context: z.literal('credvault/v1/recovery-key-wrap'),
    outputLength: z.literal(KEY_DERIVATION_OUTPUT_BYTES),
  })
  .strict();

export const deviceKeyDerivationSchema = z
  .object({
    algorithm: z.literal('hkdf-sha256'),
    version: z.literal(1),
    salt: hkdfSaltSchema,
    context: z.literal('credvault/v1/device-key-wrap'),
    outputLength: z.literal(KEY_DERIVATION_OUTPUT_BYTES),
    provider: z.string().min(1).max(MAX_DEVICE_KEY_PROVIDER_CHARS),
  })
  .strict();

export const MIN_VAULT_KEY_SLOTS = 1;
export const MAX_VAULT_KEY_SLOTS = 128;

const keySlotBaseSchema = z.object({
  slotVersion: keySlotVersionSchema,
  id: keySlotIdSchema,
  state: z.enum(['pending', 'active', 'superseded', 'revoked']),
  keyVersion: keyVersionSchema,
  wrappedRootKey: aeadEnvelopeSchema,
  createdAt: timestampSchema,
  supersededAt: timestampSchema.optional(),
  revokedAt: timestampSchema.optional(),
});

export const keySlotSchema = z
  .discriminatedUnion('type', [
    keySlotBaseSchema
      .extend({
        type: z.literal('portable-key'),
        derivation: portableKeyDerivationSchema,
      })
      .strict(),
    keySlotBaseSchema
      .extend({
        type: z.literal('passphrase'),
        derivation: passphraseDerivationSchema,
      })
      .strict(),
    keySlotBaseSchema
      .extend({
        type: z.literal('recovery-key'),
        derivation: recoveryKeyDerivationSchema,
      })
      .strict(),
    keySlotBaseSchema
      .extend({
        type: z.literal('device-key'),
        derivation: deviceKeyDerivationSchema,
        deviceId: deviceIdSchema,
      })
      .strict(),
  ])
  .superRefine((slot, context) => {
    if (slot.wrappedRootKey.aad.entityType !== 'wrapped-root-key') {
      context.addIssue({
        code: 'custom',
        message: 'Key slot envelope must be bound as a wrapped root key',
        path: ['wrappedRootKey', 'aad', 'entityType'],
      });
    }
    if (slot.wrappedRootKey.aad.entityId !== slot.id) {
      context.addIssue({
        code: 'custom',
        message: 'Key slot envelope is bound to a different slot',
        path: ['wrappedRootKey', 'aad', 'entityId'],
      });
    }
    if (slot.wrappedRootKey.keyVersion !== slot.keyVersion) {
      context.addIssue({
        code: 'custom',
        message: 'Wrapped root-key version does not match its slot',
        path: ['wrappedRootKey', 'keyVersion'],
      });
    }
    if (slot.state === 'revoked' && slot.revokedAt === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Revoked slots require a timestamp',
        path: ['revokedAt'],
      });
    }
    if (slot.state !== 'revoked' && slot.revokedAt !== undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Only revoked slots may have a revoked timestamp',
        path: ['revokedAt'],
      });
    }
    if (slot.state === 'superseded' && slot.supersededAt === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Superseded slots require a timestamp',
        path: ['supersededAt'],
      });
    }
    if (slot.state !== 'superseded' && slot.supersededAt !== undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Only superseded slots may have a superseded timestamp',
        path: ['supersededAt'],
      });
    }
  });

export const vaultRecordSchema = z
  .object({
    id: vaultIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    cryptographicVersion: supportedCryptographicVersionSchema,
    keySlots: z.array(keySlotSchema).min(MIN_VAULT_KEY_SLOTS).max(MAX_VAULT_KEY_SLOTS),
    currentKeyVersion: keyVersionSchema,
    revision: vaultRevisionSchema,
    encryptedPreferences: aeadEnvelopeSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((vault, context) => {
    const ids = new Set<string>();
    for (const [index, slot] of vault.keySlots.entries()) {
      if (slot.wrappedRootKey.aad.vaultId !== vault.id) {
        context.addIssue({
          code: 'custom',
          message: 'Key slot belongs to a different vault',
          path: ['keySlots', index, 'wrappedRootKey', 'aad', 'vaultId'],
        });
      }
      if (slot.wrappedRootKey.aad.schemaVersion !== vault.schemaVersion) {
        context.addIssue({
          code: 'custom',
          message: 'Key slot schema version does not match its vault',
          path: ['keySlots', index, 'wrappedRootKey', 'aad', 'schemaVersion'],
        });
      }
      if (ids.has(slot.id)) {
        context.addIssue({
          code: 'custom',
          message: 'Key slot IDs must be unique',
          path: ['keySlots', index, 'id'],
        });
      }
      ids.add(slot.id);
    }
    if (!vault.keySlots.some((slot) => slot.state === 'active')) {
      context.addIssue({
        code: 'custom',
        message: 'Vault requires an active unlock slot',
        path: ['keySlots'],
      });
    }
    if (
      !vault.keySlots.some(
        (slot) =>
          slot.state === 'active' && slot.keyVersion === vault.currentKeyVersion,
      )
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Current key version requires an active unlock slot',
        path: ['currentKeyVersion'],
      });
    }
    if (
      vault.encryptedPreferences.aad.vaultId !== vault.id ||
      vault.encryptedPreferences.aad.entityType !== 'vault-preferences' ||
      vault.encryptedPreferences.aad.entityId !== vault.id ||
      vault.encryptedPreferences.aad.schemaVersion !== vault.schemaVersion
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Encrypted preferences have invalid associated data',
        path: ['encryptedPreferences', 'aad'],
      });
    }
  });

export const encryptedGroupRecordSchema = z
  .object({
    id: groupIdSchema,
    vaultId: vaultIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    wrappedGroupKey: aeadEnvelopeSchema,
    encryptedPayload: aeadEnvelopeSchema,
    templateVersion: templateVersionSchema,
    recordRevision: recordRevisionSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    tombstonedAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((record, context) => {
    validateEnvelopeBinding(
      context,
      record.encryptedPayload,
      record.vaultId,
      record.schemaVersion,
      'group',
      record.id,
    );
    validateEnvelopeBinding(
      context,
      record.wrappedGroupKey,
      record.vaultId,
      record.schemaVersion,
      'wrapped-group-key',
      record.id,
    );
  });

export const encryptedItemRecordSchema = z
  .object({
    id: itemIdSchema,
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    wrappedItemKey: aeadEnvelopeSchema,
    encryptedPayload: aeadEnvelopeSchema,
    recordRevision: recordRevisionSchema,
    ciphertextHash: sha256DigestSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    tombstonedAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((record, context) => {
    validateEnvelopeBinding(
      context,
      record.encryptedPayload,
      record.vaultId,
      record.schemaVersion,
      'item',
      record.id,
      record.groupId,
    );
    validateEnvelopeBinding(
      context,
      record.wrappedItemKey,
      record.vaultId,
      record.schemaVersion,
      'wrapped-item-key',
      record.id,
      record.groupId,
    );
  });

export const encryptedAttachmentRecordSchema = z
  .object({
    id: attachmentIdSchema,
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    itemId: itemIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    wrappedAttachmentKey: aeadEnvelopeSchema,
    encryptedManifest: aeadEnvelopeSchema,
    chunkCount: z.number().int().positive().max(MAX_ATTACHMENT_CHUNKS),
    recordRevision: recordRevisionSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    tombstonedAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((record, context) => {
    validateEnvelopeBinding(
      context,
      record.encryptedManifest,
      record.vaultId,
      record.schemaVersion,
      'attachment',
      record.id,
      record.groupId,
      record.itemId,
    );
    validateEnvelopeBinding(
      context,
      record.wrappedAttachmentKey,
      record.vaultId,
      record.schemaVersion,
      'wrapped-attachment-key',
      record.id,
      record.groupId,
      record.itemId,
    );
    if (
      record.wrappedAttachmentKey.keyVersion !== record.encryptedManifest.keyVersion
    ) {
      context.addIssue({
        code: 'custom',
        path: ['wrappedAttachmentKey', 'keyVersion'],
        message: 'Attachment key envelopes must use one exact key version',
      });
    }
  });

export const encryptedAuditRecordSchema = z
  .object({
    id: auditEventIdSchema,
    vaultId: vaultIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    encryptedPayload: aeadEnvelopeSchema,
    recordRevision: recordRevisionSchema,
    createdAt: timestampSchema,
  })
  .strict()
  .superRefine((record, context) => {
    validateEnvelopeBinding(
      context,
      record.encryptedPayload,
      record.vaultId,
      record.schemaVersion,
      'audit-event',
      record.id,
    );
  });

export const encryptedHistoryRecordSchema = z
  .object({
    id: historyIdSchema,
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    itemId: itemIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    encryptedPayload: aeadEnvelopeSchema,
    itemRecordRevision: recordRevisionSchema,
    ciphertextHash: sha256DigestSchema,
    createdAt: timestampSchema,
  })
  .strict()
  .superRefine((record, context) => {
    validateEnvelopeBinding(
      context,
      record.encryptedPayload,
      record.vaultId,
      record.schemaVersion,
      'history',
      record.id,
      record.groupId,
      record.itemId,
    );
  });

export const encryptedRecordSchema = z.union([
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  encryptedAttachmentRecordSchema,
  encryptedAuditRecordSchema,
  encryptedHistoryRecordSchema,
]);

function validateEnvelopeBinding(
  context: z.core.$RefinementCtx,
  envelope: z.infer<typeof aeadEnvelopeSchema>,
  vaultId: string,
  schemaVersion: number,
  entityType: z.infer<typeof encryptedEntityTypeSchema>,
  entityId: string,
  groupId?: string,
  parentId?: string,
): void {
  if (
    envelope.aad.vaultId !== vaultId ||
    envelope.aad.schemaVersion !== schemaVersion ||
    envelope.aad.entityType !== entityType ||
    envelope.aad.entityId !== entityId ||
    envelope.aad.groupId !== groupId ||
    envelope.aad.parentId !== parentId
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Envelope associated data does not match its record',
      path: ['aad'],
    });
  }
}

export type AssociatedData = z.infer<typeof associatedDataSchema>;
export type AeadEnvelope = z.infer<typeof aeadEnvelopeSchema>;
export type AttachmentSecretStreamHeaderRecord = z.infer<
  typeof attachmentSecretStreamHeaderRecordSchema
>;
export type AttachmentSecretStreamChunkRecord = z.infer<
  typeof attachmentSecretStreamChunkRecordSchema
>;
export type AttachmentSecretStreamRecord = z.infer<
  typeof attachmentSecretStreamRecordSchema
>;
export type AttachmentChunkCiphertext = z.infer<typeof attachmentChunkCiphertextSchema>;
export type PersistedAttachmentHeaderRecord = z.infer<
  typeof persistedAttachmentHeaderRecordSchema
>;
export type PersistedAttachmentChunkRecord = z.infer<
  typeof persistedAttachmentChunkRecordSchema
>;
export type AttachmentSecretStreamManifest = z.infer<
  typeof attachmentSecretStreamManifestSchema
>;
export type KeySlot = z.infer<typeof keySlotSchema>;
export type VaultRecord = z.infer<typeof vaultRecordSchema>;
export type EncryptedGroupRecord = z.infer<typeof encryptedGroupRecordSchema>;
export type EncryptedItemRecord = z.infer<typeof encryptedItemRecordSchema>;
export type EncryptedAttachmentRecord = z.infer<typeof encryptedAttachmentRecordSchema>;
export type EncryptedAuditRecord = z.infer<typeof encryptedAuditRecordSchema>;
export type EncryptedHistoryRecord = z.infer<typeof encryptedHistoryRecordSchema>;
export type EncryptedRecord = z.infer<typeof encryptedRecordSchema>;
