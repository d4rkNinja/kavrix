import { z } from 'zod';

import {
  encryptedAttachmentRecordSchema,
  encryptedAuditRecordSchema,
  encryptedGroupRecordSchema,
  encryptedHistoryRecordSchema,
  encryptedItemRecordSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  vaultRecordSchema,
} from './encrypted-records.js';
import { vaultIdSchema } from './identifiers.js';
import {
  base64UrlSchema,
  sha256DigestSchema,
  supportedSchemaVersionSchema,
  timestampSchema,
} from './primitives.js';
import { tombstoneRecordSchema } from './sync.js';

export const DEFAULT_MAX_BACKUP_RECORDS = 2_000_000;
export const MAX_SUPPORTED_BACKUP_BYTES = 64 * 1024 * 1024 * 1024;

const canonical32ByteValueSchema = base64UrlSchema
  .length(43)
  .refine((value) => Buffer.from(value, 'base64url').byteLength === 32, {
    error: 'Value must canonically encode exactly 32 bytes',
  });

export const backupAuthenticationSaltSchema =
  canonical32ByteValueSchema.brand<'BackupAuthenticationSalt'>();
export const backupAuthenticationTagSchema =
  canonical32ByteValueSchema.brand<'BackupAuthenticationTag'>();

const backupAuthenticationSchema = z
  .object({
    algorithm: z.literal('hkdf-sha256+hmac-sha256'),
    salt: backupAuthenticationSaltSchema,
  })
  .strict();

export const encryptedBackupHeaderSchema = z
  .object({
    type: z.literal('header'),
    format: z.literal('kavrix-encrypted-backup'),
    version: z.literal(1),
    vaultId: vaultIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    createdAt: timestampSchema,
    authentication: backupAuthenticationSchema,
  })
  .strict();

export const encryptedBackupEntrySchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('vault'), record: vaultRecordSchema }).strict(),
  z.object({ kind: z.literal('group'), record: encryptedGroupRecordSchema }).strict(),
  z.object({ kind: z.literal('item'), record: encryptedItemRecordSchema }).strict(),
  z
    .object({ kind: z.literal('attachment'), record: encryptedAttachmentRecordSchema })
    .strict(),
  z
    .object({
      kind: z.literal('attachment-header'),
      record: persistedAttachmentHeaderRecordSchema,
    })
    .strict(),
  z
    .object({
      kind: z.literal('attachment-chunk'),
      record: persistedAttachmentChunkRecordSchema,
    })
    .strict(),
  z.object({ kind: z.literal('audit'), record: encryptedAuditRecordSchema }).strict(),
  z
    .object({ kind: z.literal('history'), record: encryptedHistoryRecordSchema })
    .strict(),
  z
    .object({
      kind: z.literal('tombstone-predecessor'),
      entityType: z.enum(['group', 'item', 'attachment']),
      record: z.union([
        encryptedGroupRecordSchema,
        encryptedItemRecordSchema,
        encryptedAttachmentRecordSchema,
      ]),
    })
    .strict()
    .superRefine((entry, context) => {
      const actualType =
        'itemId' in entry.record
          ? 'attachment'
          : 'groupId' in entry.record
            ? 'item'
            : 'group';
      if (entry.entityType !== actualType) {
        context.addIssue({
          code: 'custom',
          path: ['entityType'],
          message: 'Tombstone predecessor kind does not match its opaque record',
        });
      }
      if (entry.record.tombstonedAt !== undefined) {
        context.addIssue({
          code: 'custom',
          path: ['record', 'tombstonedAt'],
          message: 'Tombstone predecessor must be an active opaque record',
        });
      }
    }),
  z.object({ kind: z.literal('tombstone'), record: tombstoneRecordSchema }).strict(),
]);

export const encryptedBackupFooterSchema = z
  .object({
    type: z.literal('footer'),
    version: z.literal(1),
    recordCount: z.number().int().positive().max(10_000_000),
    transcriptSha256: sha256DigestSchema,
    authenticationTag: backupAuthenticationTagSchema,
  })
  .strict();

export type EncryptedBackupHeader = z.infer<typeof encryptedBackupHeaderSchema>;
export type EncryptedBackupEntry = z.infer<typeof encryptedBackupEntrySchema>;
export type EncryptedBackupFooter = z.infer<typeof encryptedBackupFooterSchema>;
export type BackupAuthenticationSalt = z.infer<typeof backupAuthenticationSaltSchema>;
export type BackupAuthenticationTag = z.infer<typeof backupAuthenticationTagSchema>;

export type BackupLimits = Readonly<{
  maximumBytes?: number;
  maximumRecords?: number;
}>;

export type ResolvedBackupLimits = Readonly<{
  maximumBytes: number;
  maximumRecords: number;
}>;

export type BackupStagingStatus = 'staging' | 'committed' | 'aborted';

export type BackupVerification = Readonly<{
  header: EncryptedBackupHeader;
  restoreSessionId: z.infer<typeof sha256DigestSchema>;
  recordCount: number;
  transcriptSha256: z.infer<typeof sha256DigestSchema>;
}>;

export type BackupRestoreStager = Readonly<{
  write(entry: EncryptedBackupEntry): Promise<void>;
  commit(summary: BackupVerification): Promise<void>;
  status(): Promise<BackupStagingStatus>;
  abort(): Promise<void>;
}>;

export type BackupRestoreStore = Readonly<{
  open(
    restoreSessionId: z.infer<typeof sha256DigestSchema>,
    limits: ResolvedBackupLimits,
  ): Promise<BackupRestoreStager>;
}>;
