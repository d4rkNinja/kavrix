import { createHash } from 'node:crypto';

import {
  aeadEnvelopeSchema,
  apiBearerTokenSchema,
  associatedDataSchema,
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  attachmentStreamFinalizeInputSchema,
  attachmentStreamStartInputSchema,
  attachmentTransferPathSchema,
  encryptedAttachmentRecordSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  sha256DigestSchema,
  timestampSchema,
  type AeadEnvelope,
  type AttachmentStreamFinalizeInput,
  type AttachmentStreamStartInput,
  type AttachmentTransferPath,
  type PersistedAttachmentChunkRecord,
  type Sha256Digest,
} from '@kavrix/schemas';

const timestamp = timestampSchema.parse('2026-08-10T00:00:00.000Z');
export const attachmentBearerToken = apiBearerTokenSchema.parse(
  Buffer.alloc(32, 13).toString('base64url'),
);

export function attachmentTransportFixture(): Readonly<{
  path: AttachmentTransferPath;
  start: AttachmentStreamStartInput;
  chunks: readonly [PersistedAttachmentChunkRecord, PersistedAttachmentChunkRecord];
  finalize: AttachmentStreamFinalizeInput;
}> {
  const path = attachmentTransferPathSchema.parse({
    vaultId: 'vault-client-attachment',
    groupId: 'group-client-attachment',
    itemId: 'item-client-attachment',
    attachmentId: 'attachment-client-transport',
  });
  const initialHeader = persistedAttachmentHeaderRecordSchema.parse({
    entityType: 'attachment-header',
    record: {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: 1,
      keyVersion: 1,
      ...path,
      recordType: 'header',
      header: Buffer.alloc(24, 2).toString('base64url'),
    },
    recordRevision: 0,
    contentHash: digest('temporary-header'),
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  const start = attachmentStreamStartInputSchema.parse({
    version: 1,
    idempotencyKey: 'client-attachment-idempotency-0001',
    expectedAttachmentRevision: null,
    header: {
      ...initialHeader,
      contentHash: attachmentHeaderContentHash(initialHeader),
    },
  });
  const chunks = [chunk(start, 0, 'message'), chunk(start, 1, 'final')] as const;
  const finalize = attachmentStreamFinalizeInputSchema.parse({
    version: 1,
    record: encryptedAttachmentRecordSchema.parse({
      id: path.attachmentId,
      vaultId: path.vaultId,
      groupId: path.groupId,
      itemId: path.itemId,
      schemaVersion: 1,
      wrappedAttachmentKey: envelope(path, 'wrapped-attachment-key', 'attachment-key'),
      encryptedManifest: envelope(path, 'attachment', 'attachment-metadata'),
      chunkCount: chunks.length,
      recordRevision: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    }),
  });
  return { path, start, chunks, finalize };
}

function chunk(
  start: AttachmentStreamStartInput,
  index: number,
  tag: 'message' | 'final',
): PersistedAttachmentChunkRecord {
  const plaintextBytes = 8 + index;
  const ciphertext = Buffer.alloc(plaintextBytes + 17, index + 21).toString(
    'base64url',
  );
  const initial = persistedAttachmentChunkRecordSchema.parse({
    entityType: 'attachment-chunk',
    record: {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: start.header.record.vaultId,
      groupId: start.header.record.groupId,
      itemId: start.header.record.itemId,
      attachmentId: start.header.record.attachmentId,
      recordType: 'chunk',
      index,
      ciphertext,
      tag,
    },
    plaintextBytes,
    recordRevision: 0,
    ciphertextHash: digest(`temporary-chunk-${String(index)}`),
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  return persistedAttachmentChunkRecordSchema.parse({
    ...initial,
    ciphertextHash: attachmentChunkCiphertextHash(initial),
  });
}

function envelope(
  path: ReturnType<typeof attachmentTransferPathSchema.parse>,
  entityType: 'wrapped-attachment-key' | 'attachment',
  purpose: 'attachment-key' | 'attachment-metadata',
): AeadEnvelope {
  return aeadEnvelopeSchema.parse({
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: Buffer.alloc(24, entityType === 'attachment' ? 3 : 4).toString('base64url'),
    ciphertext: Buffer.from(`opaque-${purpose}`).toString('base64url'),
    authenticationTag: Buffer.alloc(16, 5).toString('base64url'),
    aad: associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: path.vaultId,
      entityType,
      entityId: path.attachmentId,
      groupId: path.groupId,
      parentId: path.itemId,
      purpose,
    }),
    keyVersion: 1,
  });
}

function digest(value: string): Sha256Digest {
  return sha256DigestSchema.parse(
    createHash('sha256').update(value).digest('base64url'),
  );
}
