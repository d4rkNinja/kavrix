import { createHash } from 'node:crypto';

import {
  attachmentStreamFinalizeInputSchema,
  attachmentStreamStartInputSchema,
  attachmentHeaderContentHash,
  encryptedAttachmentRecordSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  opaqueMutationSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  vaultRecordSchema,
  type AttachmentStreamFinalizeInput,
  type AttachmentStreamStartInput,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type OpaqueMutation,
  type PersistedAttachmentChunkRecord,
  type VaultRecord,
} from '@kavrix/schemas';

export const timestamp = '2026-08-10T00:00:00.000Z';
export const later = '2026-08-10T00:01:00.000Z';
export const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
export const plaintextCanary = 'plaintext-storage-canary';

const purposeByEntity = {
  'vault-preferences': 'vault-preferences',
  group: 'group-payload',
  item: 'item-payload',
  attachment: 'attachment-metadata',
  'wrapped-root-key': 'vrk-slot',
  'wrapped-group-key': 'group-key',
  'wrapped-item-key': 'item-key',
  'wrapped-attachment-key': 'attachment-key',
} as const;

type EntityType = keyof typeof purposeByEntity;

function envelope(
  entityType: EntityType,
  entityId: string,
  options: { groupId?: string; parentId?: string; ciphertext?: string } = {},
): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: options.ciphertext ?? 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: 'vault.1',
      entityType,
      entityId,
      ...(options.groupId === undefined ? {} : { groupId: options.groupId }),
      ...(options.parentId === undefined ? {} : { parentId: options.parentId }),
      purpose: purposeByEntity[entityType],
    },
    keyVersion: 1,
  };
}

export function vaultRecord(revision = 0): VaultRecord {
  return vaultRecordSchema.parse({
    id: 'vault.1',
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [
      {
        id: 'slot.1',
        slotVersion: 1,
        type: 'portable-key',
        state: 'active',
        keyVersion: 1,
        derivation: {
          algorithm: 'hkdf-sha256',
          version: 1,
          salt: digest,
          context: 'credvault/v1/portable-key-wrap',
          outputLength: 32,
        },
        wrappedRootKey: envelope('wrapped-root-key', 'slot.1'),
        createdAt: timestamp,
      },
    ],
    currentKeyVersion: 1,
    revision,
    encryptedPreferences: envelope('vault-preferences', 'vault.1'),
    createdAt: timestamp,
    updatedAt: revision === 0 ? timestamp : later,
  });
}

export function groupRecord(revision = 0, tombstonedAt?: string): EncryptedGroupRecord {
  return encryptedGroupRecordSchema.parse({
    id: 'group.1',
    vaultId: 'vault.1',
    schemaVersion: 1,
    wrappedGroupKey: envelope('wrapped-group-key', 'group.1'),
    encryptedPayload: envelope('group', 'group.1'),
    templateVersion: 1,
    recordRevision: revision,
    createdAt: timestamp,
    updatedAt: revision === 0 ? timestamp : later,
    ...(tombstonedAt === undefined ? {} : { tombstonedAt }),
  });
}

export function itemRecord(revision = 0, tombstonedAt?: string): EncryptedItemRecord {
  return encryptedItemRecordSchema.parse({
    id: 'item.1',
    vaultId: 'vault.1',
    groupId: 'group.1',
    schemaVersion: 1,
    wrappedItemKey: envelope('wrapped-item-key', 'item.1', {
      groupId: 'group.1',
    }),
    encryptedPayload: envelope('item', 'item.1', {
      groupId: 'group.1',
      ciphertext: Buffer.from(plaintextCanary).toString('base64url'),
    }),
    recordRevision: revision,
    ciphertextHash: digest,
    createdAt: timestamp,
    updatedAt: revision === 0 ? timestamp : later,
    ...(tombstonedAt === undefined ? {} : { tombstonedAt }),
  });
}

export function mutation(
  entityType: 'vault' | 'group' | 'item',
  record: VaultRecord | EncryptedGroupRecord | EncryptedItemRecord,
  expectedRevision: number | null,
  idempotencyKey = `idempotency-${entityType}-0001`,
): OpaqueMutation {
  if (entityType === 'vault') {
    return opaqueMutationSchema.parse({
      entityType,
      expectedVaultRevision: expectedRevision,
      idempotencyKey,
      record,
    });
  }
  return opaqueMutationSchema.parse({
    entityType,
    expectedRecordRevision: expectedRevision,
    idempotencyKey,
    record,
  });
}

export function attachmentStart(): AttachmentStreamStartInput {
  const header = persistedAttachmentHeaderRecordSchema.parse({
    entityType: 'attachment-header',
    record: {
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
    },
    recordRevision: 0,
    contentHash: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  return attachmentStreamStartInputSchema.parse({
    version: 1,
    idempotencyKey: 'attachment-stream-0001',
    expectedAttachmentRevision: null,
    header: {
      ...header,
      contentHash: attachmentHeaderContentHash(header),
    },
  });
}

export function attachmentChunk(
  index: number,
  tag: 'message' | 'final',
  plaintextBytes = 3,
): PersistedAttachmentChunkRecord {
  const ciphertext = Buffer.alloc(plaintextBytes + 17, index + 1).toString('base64url');
  return persistedAttachmentChunkRecordSchema.parse({
    entityType: 'attachment-chunk',
    record: {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: 'vault.1',
      groupId: 'group.1',
      itemId: 'item.1',
      attachmentId: 'attachment.1',
      recordType: 'chunk',
      index,
      ciphertext,
      tag,
    },
    plaintextBytes,
    recordRevision: 0,
    ciphertextHash: createHash('sha256')
      .update(Buffer.from(ciphertext, 'base64url'))
      .digest('base64url'),
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

export function attachmentFinalize(chunkCount = 2): AttachmentStreamFinalizeInput {
  return attachmentStreamFinalizeInputSchema.parse({
    version: 1,
    record: encryptedAttachmentRecordSchema.parse({
      id: 'attachment.1',
      vaultId: 'vault.1',
      groupId: 'group.1',
      itemId: 'item.1',
      schemaVersion: 1,
      wrappedAttachmentKey: envelope('wrapped-attachment-key', 'attachment.1', {
        groupId: 'group.1',
        parentId: 'item.1',
      }),
      encryptedManifest: envelope('attachment', 'attachment.1', {
        groupId: 'group.1',
        parentId: 'item.1',
      }),
      chunkCount,
      recordRevision: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
    }),
  });
}
