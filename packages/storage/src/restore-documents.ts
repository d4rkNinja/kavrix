import {
  DEFAULT_MAX_BACKUP_RECORDS,
  MAX_SUPPORTED_BACKUP_BYTES,
  backupRestoreStatusSchema,
  backupVerificationSchema,
  canonicalJson,
  encryptedBackupEntrySchema,
  type BackupRestoreStatus,
  type EncryptedBackupEntry,
  sha256DigestSchema,
  timestampSchema,
  vaultIdSchema,
  type Sha256Digest,
  type VaultId,
} from '@kavrix/schemas';
import { ValidationError } from '@kavrix/core';
import { z } from 'zod';

import { hashCanonical } from './documents.js';

export const MAX_MONGO_RESTORE_ENTRY_BYTES = 15 * 1024 * 1024;

const sha256HexSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const progressSessionDocumentSchema = z
  .object({
    _id: sha256DigestSchema,
    protocolVersion: z.literal(2),
    restoreSessionId: sha256DigestSchema,
    maximumBytes: z.number().int().positive().max(MAX_SUPPORTED_BACKUP_BYTES),
    maximumRecords: z.number().int().positive().max(DEFAULT_MAX_BACKUP_RECORDS),
    stagedBytes: z.number().int().nonnegative().max(MAX_SUPPORTED_BACKUP_BYTES),
    stagedRecords: z.number().int().nonnegative().max(DEFAULT_MAX_BACKUP_RECORDS),
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

const stagingRestoreSessionSchema = progressSessionDocumentSchema
  .extend({
    state: z.literal('staging'),
    vaultId: vaultIdSchema.optional(),
  })
  .strict();

const sealedRestoreSessionSchema = progressSessionDocumentSchema
  .extend({
    state: z.literal('sealed'),
    vaultId: vaultIdSchema,
    summary: backupVerificationSchema,
    sealedAt: timestampSchema,
  })
  .strict();

const publishedRestoreSessionSchema = progressSessionDocumentSchema
  .extend({
    state: z.literal('published'),
    vaultId: vaultIdSchema,
    summary: backupVerificationSchema,
    sealedAt: timestampSchema,
    publishedAt: timestampSchema,
  })
  .strict();

const committedRestoreSessionSchema = z
  .object({
    _id: sha256DigestSchema,
    state: z.literal('committed'),
    protocolVersion: z.literal(2),
    restoreSessionId: sha256DigestSchema,
    summary: backupVerificationSchema,
    committedAt: timestampSchema,
  })
  .strict();

const abortedRestoreSessionSchema = z
  .object({
    _id: sha256DigestSchema,
    state: z.literal('aborted'),
    protocolVersion: z.literal(2),
    restoreSessionId: sha256DigestSchema,
    abortedAt: timestampSchema,
  })
  .strict();

export const backupRestoreSessionDocumentSchema = z
  .discriminatedUnion('state', [
    stagingRestoreSessionSchema,
    sealedRestoreSessionSchema,
    publishedRestoreSessionSchema,
    committedRestoreSessionSchema,
    abortedRestoreSessionSchema,
  ])
  .superRefine((document, context) => {
    if (document._id !== document.restoreSessionId) {
      context.addIssue({
        code: 'custom',
        path: ['_id'],
        message: 'Restore session identity is inconsistent',
      });
    }
    const { _id: documentId, ...status } = document;
    void documentId;
    if (!backupRestoreStatusSchema.safeParse(status).success) {
      context.addIssue({
        code: 'custom',
        message: 'Restore session status is inconsistent',
      });
    }
  });

export const backupRestoreEntryDocumentSchema = z
  .object({
    _id: z.string().min(1).max(512),
    restoreSessionId: sha256DigestSchema,
    ordinal: z
      .number()
      .int()
      .nonnegative()
      .max(DEFAULT_MAX_BACKUP_RECORDS - 1),
    identity: z.string().min(1).max(512),
    entryHash: sha256HexSchema,
    vaultId: vaultIdSchema,
    bytes: z.number().int().positive().max(MAX_MONGO_RESTORE_ENTRY_BYTES),
    entry: encryptedBackupEntrySchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !==
        restoreEntryDocumentId(document.restoreSessionId, document.identity) ||
      document.identity !== restoreEntryIdentity(document.entry) ||
      document.entryHash !== hashCanonical(document.entry) ||
      document.vaultId !== backupEntryVaultId(document.entry) ||
      document.bytes !== Buffer.byteLength(canonicalJson(document.entry), 'utf8') + 1
    ) {
      context.addIssue({
        code: 'custom',
        path: ['_id'],
        message: 'Restore entry identity is inconsistent',
      });
    }
  });

export type BackupRestoreSessionDocument = z.infer<
  typeof backupRestoreSessionDocumentSchema
>;
export type BackupRestoreEntryDocument = z.infer<
  typeof backupRestoreEntryDocumentSchema
>;

export function restoreEntryDocumentId(
  restoreSessionId: Sha256Digest,
  identity: string,
): string {
  return `${restoreSessionId}|${hashCanonical(identity)}`;
}

export function restoreEntryIdentity(entry: EncryptedBackupEntry): string {
  switch (entry.kind) {
    case 'vault':
      return `vault:${entry.record.id}`;
    case 'group':
      return `group:${entry.record.id}`;
    case 'item':
      return `item:${entry.record.id}`;
    case 'attachment':
      return `attachment:${entry.record.id}`;
    case 'attachment-header':
      return `attachment-header:${entry.record.record.attachmentId}`;
    case 'attachment-chunk':
      return `attachment-chunk:${entry.record.record.attachmentId}:${String(
        entry.record.record.index,
      )}`;
    case 'audit':
      return `audit:${entry.record.id}`;
    case 'history':
      return `history:${entry.record.id}`;
    case 'tombstone-predecessor':
      return `tombstone-predecessor:${entry.entityType}:${entry.record.id}`;
    case 'tombstone':
      return `tombstone:${entry.record.entityType}:${entry.record.entityId}`;
  }
}

export function backupEntryVaultId(entry: EncryptedBackupEntry): VaultId {
  if (entry.kind === 'vault') return entry.record.id;
  if (entry.kind === 'attachment-header' || entry.kind === 'attachment-chunk') {
    return entry.record.record.vaultId;
  }
  return entry.record.vaultId;
}

export function makeRestoreEntryDocument(
  restoreSessionId: Sha256Digest,
  ordinal: number,
  bytes: number,
  entryInput: EncryptedBackupEntry,
): BackupRestoreEntryDocument {
  const entry = parseRestoreEntry(entryInput);
  const identity = restoreEntryIdentity(entry);
  return backupRestoreEntryDocumentSchema.parse({
    _id: restoreEntryDocumentId(restoreSessionId, identity),
    restoreSessionId,
    ordinal,
    identity,
    entryHash: hashCanonical(entry),
    vaultId: backupEntryVaultId(entry),
    bytes,
    entry,
  });
}

export function parseRestoreSessionDocument(
  input: unknown,
): BackupRestoreSessionDocument {
  return parseStored(
    backupRestoreSessionDocumentSchema,
    input,
    'backup restore session',
  );
}

export function backupRestoreStatusFromDocument(input: unknown): BackupRestoreStatus {
  const { _id: documentId, ...status } = parseRestoreSessionDocument(input);
  void documentId;
  return parseStored(backupRestoreStatusSchema, status, 'backup restore status');
}

export function parseRestoreEntryDocument(input: unknown): BackupRestoreEntryDocument {
  return parseStored(backupRestoreEntryDocumentSchema, input, 'backup restore entry');
}

export function parseRestoreEntry(input: unknown): EncryptedBackupEntry {
  return parseStored(encryptedBackupEntrySchema, input, 'encrypted backup entry');
}

function parseStored<Output>(
  schema: {
    safeParse(input: unknown): { success: true; data: Output } | { success: false };
  },
  input: unknown,
  label: string,
): Output {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new ValidationError(`Invalid ${label}.`);
  return parsed.data;
}
