import { createHash } from 'node:crypto';

import {
  aeadEnvelopeSchema,
  associatedDataSchema,
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  attachmentFinalizeRequestSchema,
  attachmentStreamFinalizeInputSchema,
  attachmentStreamStartInputSchema,
  attachmentTransferPathSchema,
  encryptedAttachmentRecordSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  sha256DigestSchema,
  timestampSchema,
  type AeadEnvelope,
  type AttachmentStreamFinalizeInput,
  type AttachmentStreamStartInput,
  type AttachmentTransferPath,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type PersistedAttachmentChunkRecord,
  type Sha256Digest,
} from '@kavrix/schemas';

import { vaultId } from './helpers.js';

const timestamp = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const groupId = 'group-attachment-1';
const itemId = 'item-attachment-1';
const attachmentId = 'attachment-transport-1';
export const plaintextAttachmentCanary = 'plaintext-attachment-never-persisted';
export const ciphertextAttachmentCanary = 'opaque-attachment-ciphertext';

export function attachmentFixture(): Readonly<{
  path: AttachmentTransferPath;
  start: AttachmentStreamStartInput;
  chunks: readonly [PersistedAttachmentChunkRecord, PersistedAttachmentChunkRecord];
  finalize: AttachmentStreamFinalizeInput;
  group: EncryptedGroupRecord;
  item: EncryptedItemRecord;
}> {
  const path = attachmentTransferPathSchema.parse({
    vaultId,
    groupId,
    itemId,
    attachmentId,
  });
  const unboundHeader = persistedAttachmentHeaderRecordSchema.parse({
    entityType: 'attachment-header',
    record: {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: 1,
      keyVersion: 1,
      ...path,
      recordType: 'header',
      header: Buffer.alloc(24, 4).toString('base64url'),
    },
    recordRevision: 0,
    contentHash: hash('temporary-attachment-header'),
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  const start = attachmentStreamStartInputSchema.parse({
    version: 1,
    idempotencyKey: 'attachment-transfer-idempotency-0001',
    expectedAttachmentRevision: null,
    header: {
      ...unboundHeader,
      contentHash: attachmentHeaderContentHash(unboundHeader),
    },
  });
  const group = encryptedGroupRecordSchema.parse({
    id: groupId,
    vaultId,
    schemaVersion: 1,
    wrappedGroupKey: parentEnvelope('wrapped-group-key', groupId, 'group-key'),
    encryptedPayload: parentEnvelope('group', groupId, 'group-payload'),
    templateVersion: 1,
    recordRevision: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  const item = encryptedItemRecordSchema.parse({
    id: itemId,
    vaultId,
    groupId,
    schemaVersion: 1,
    wrappedItemKey: parentEnvelope('wrapped-item-key', itemId, 'item-key', groupId),
    encryptedPayload: parentEnvelope('item', itemId, 'item-payload', groupId),
    recordRevision: 0,
    ciphertextHash: hash('opaque-item-record'),
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  const chunks = [
    attachmentChunk(start, 0, 'message', ciphertextAttachmentCanary),
    attachmentChunk(start, 1, 'final', 'opaque-attachment-final'),
  ] as const;
  const finalize = attachmentStreamFinalizeInputSchema.parse({
    version: 1,
    record: encryptedAttachmentRecordSchema.parse({
      id: attachmentId,
      vaultId,
      groupId,
      itemId,
      schemaVersion: 1,
      wrappedAttachmentKey: envelope('wrapped-attachment-key', 'attachment-key'),
      encryptedManifest: envelope('attachment', 'attachment-metadata'),
      chunkCount: chunks.length,
      recordRevision: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    }),
  });
  attachmentFinalizeRequestSchema.parse({ start, finalize });
  return { path, start, chunks, finalize, group, item };
}

function attachmentChunk(
  start: AttachmentStreamStartInput,
  index: number,
  tag: 'message' | 'final',
  opaqueText: string,
): PersistedAttachmentChunkRecord {
  const plaintextBytes = Buffer.byteLength(opaqueText);
  const ciphertext = Buffer.concat([
    Buffer.from(opaqueText, 'utf8'),
    Buffer.alloc(17, index + 1),
  ]).toString('base64url');
  const unbound = persistedAttachmentChunkRecordSchema.parse({
    entityType: 'attachment-chunk',
    record: {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: start.header.record.schemaVersion,
      keyVersion: start.header.record.keyVersion,
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
    recordRevision: start.header.recordRevision,
    ciphertextHash: hash(`temporary-${String(index)}`),
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  return persistedAttachmentChunkRecordSchema.parse({
    ...unbound,
    ciphertextHash: attachmentChunkCiphertextHash(unbound),
  });
}

function envelope(
  entityType: 'wrapped-attachment-key' | 'attachment',
  purpose: 'attachment-key' | 'attachment-metadata',
): AeadEnvelope {
  return aeadEnvelopeSchema.parse({
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: Buffer.alloc(24, entityType === 'attachment' ? 5 : 6).toString('base64url'),
    ciphertext: Buffer.from(`opaque-${purpose}`).toString('base64url'),
    authenticationTag: Buffer.alloc(16, 7).toString('base64url'),
    aad: associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType,
      entityId: attachmentId,
      groupId,
      parentId: itemId,
      purpose,
    }),
    keyVersion: 1,
  });
}

function parentEnvelope(
  entityType: 'wrapped-group-key' | 'group' | 'wrapped-item-key' | 'item',
  entityId: string,
  purpose: 'group-key' | 'group-payload' | 'item-key' | 'item-payload',
  parentGroupId?: string,
): AeadEnvelope {
  return aeadEnvelopeSchema.parse({
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: Buffer.alloc(24, 8).toString('base64url'),
    ciphertext: Buffer.from(`opaque-${purpose}`).toString('base64url'),
    authenticationTag: Buffer.alloc(16, 9).toString('base64url'),
    aad: associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId,
      entityType,
      entityId,
      ...(parentGroupId === undefined ? {} : { groupId: parentGroupId }),
      purpose,
    }),
    keyVersion: 1,
  });
}

function hash(value: string): Sha256Digest {
  return sha256DigestSchema.parse(
    createHash('sha256').update(value).digest('base64url'),
  );
}
