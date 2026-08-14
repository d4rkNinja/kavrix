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
import { keySlotIdSchema, vaultIdSchema } from './identifiers.js';
import {
  base64UrlSchema,
  keyVersionSchema,
  sha256DigestSchema,
  supportedSchemaVersionSchema,
  timestampSchema,
  vaultRevisionSchema,
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

const backupRecordCountSchema = z
  .number()
  .int()
  .positive()
  .max(DEFAULT_MAX_BACKUP_RECORDS);
const backupSubcountSchema = z
  .number()
  .int()
  .nonnegative()
  .max(DEFAULT_MAX_BACKUP_RECORDS);

export const backupVerificationSchema = z
  .object({
    header: encryptedBackupHeaderSchema,
    restoreSessionId: sha256DigestSchema,
    recordCount: backupRecordCountSchema,
    transcriptSha256: sha256DigestSchema,
    canonicalEntriesSha256: sha256DigestSchema,
  })
  .strict();

const selectedRestoreSlotSchema = z
  .object({
    id: keySlotIdSchema,
    type: z.enum(['portable-key', 'passphrase', 'recovery-key']),
    keyVersion: keyVersionSchema,
  })
  .strict();

const verifiedRestoreCountsSchema = z
  .object({
    vaults: z.literal(1),
    groups: backupSubcountSchema,
    items: backupSubcountSchema,
    attachments: backupSubcountSchema,
    attachmentHeaders: backupSubcountSchema,
    attachmentChunks: backupSubcountSchema,
    tombstonePredecessors: z
      .object({
        groups: backupSubcountSchema,
        items: backupSubcountSchema,
        attachments: backupSubcountSchema,
      })
      .strict(),
    tombstones: backupSubcountSchema,
    histories: backupSubcountSchema,
    audits: backupSubcountSchema,
  })
  .strict();

export const restoreKnownRecordsVerificationV1Schema = z
  .object({
    version: z.literal(1),
    scope: z.literal('known-v1-records'),
    vaultId: vaultIdSchema,
    vaultRevision: vaultRevisionSchema,
    restoreSessionId: sha256DigestSchema,
    transcriptSha256: sha256DigestSchema,
    canonicalEntriesSha256: sha256DigestSchema,
    recordCount: backupRecordCountSchema,
    selectedSlot: selectedRestoreSlotSchema,
    verified: verifiedRestoreCountsSchema,
  })
  .strict()
  .superRefine((receipt, context) => {
    const predecessors = receipt.verified.tombstonePredecessors;
    const predecessorCount =
      predecessors.groups + predecessors.items + predecessors.attachments;
    const observedCount =
      receipt.verified.vaults +
      receipt.verified.groups +
      receipt.verified.items +
      receipt.verified.attachments +
      receipt.verified.attachmentHeaders +
      receipt.verified.attachmentChunks +
      predecessorCount +
      receipt.verified.tombstones +
      receipt.verified.histories +
      receipt.verified.audits;

    if (observedCount !== receipt.recordCount) {
      context.addIssue({
        code: 'custom',
        path: ['recordCount'],
        message: 'Restore verification counts do not match the backup record count',
      });
    }
    if (receipt.verified.attachmentHeaders !== receipt.verified.attachments) {
      context.addIssue({
        code: 'custom',
        path: ['verified', 'attachmentHeaders'],
        message: 'Every verified attachment must have one verified header',
      });
    }
    if (receipt.verified.attachmentChunks < receipt.verified.attachments) {
      context.addIssue({
        code: 'custom',
        path: ['verified', 'attachmentChunks'],
        message: 'Every verified attachment must have at least one verified chunk',
      });
    }
    if (receipt.verified.tombstones < predecessorCount) {
      context.addIssue({
        code: 'custom',
        path: ['verified', 'tombstones'],
        message: 'Verified tombstones cannot have more predecessors than tombstones',
      });
    }
  });

const restoreProgressStatusSchema = z.object({
  protocolVersion: z.literal(2),
  restoreSessionId: sha256DigestSchema,
  maximumBytes: z.number().int().positive().max(MAX_SUPPORTED_BACKUP_BYTES),
  maximumRecords: backupRecordCountSchema,
  stagedBytes: z.number().int().nonnegative().max(MAX_SUPPORTED_BACKUP_BYTES),
  stagedRecords: backupSubcountSchema,
  createdAt: timestampSchema,
  updatedAt: timestampSchema,
});

const stagingRestoreStatusSchema = restoreProgressStatusSchema
  .extend({
    state: z.literal('staging'),
    vaultId: vaultIdSchema.optional(),
  })
  .strict();

const sealedRestoreStatusSchema = restoreProgressStatusSchema
  .extend({
    state: z.literal('sealed'),
    vaultId: vaultIdSchema,
    summary: backupVerificationSchema,
    sealedAt: timestampSchema,
  })
  .strict();

const publishedRestoreStatusSchema = restoreProgressStatusSchema
  .extend({
    state: z.literal('published'),
    vaultId: vaultIdSchema,
    summary: backupVerificationSchema,
    sealedAt: timestampSchema,
    publishedAt: timestampSchema,
  })
  .strict();

const committedRestoreStatusSchema = z
  .object({
    state: z.literal('committed'),
    protocolVersion: z.literal(2),
    restoreSessionId: sha256DigestSchema,
    summary: backupVerificationSchema,
    committedAt: timestampSchema,
  })
  .strict();

const abortedRestoreStatusSchema = z
  .object({
    state: z.literal('aborted'),
    protocolVersion: z.literal(2),
    restoreSessionId: sha256DigestSchema,
    abortedAt: timestampSchema,
  })
  .strict();

export const backupRestoreStatusSchema = z
  .discriminatedUnion('state', [
    stagingRestoreStatusSchema,
    sealedRestoreStatusSchema,
    publishedRestoreStatusSchema,
    committedRestoreStatusSchema,
    abortedRestoreStatusSchema,
  ])
  .superRefine((status, context) => {
    if ('stagedBytes' in status && status.stagedBytes > status.maximumBytes) {
      context.addIssue({
        code: 'custom',
        path: ['stagedBytes'],
        message: 'Staged bytes exceed the restore session bound',
      });
    }
    if ('stagedRecords' in status && status.stagedRecords > status.maximumRecords) {
      context.addIssue({
        code: 'custom',
        path: ['stagedRecords'],
        message: 'Staged records exceed the restore session bound',
      });
    }
    if ('stagedRecords' in status) {
      const hasStagedRecords = status.stagedRecords > 0;
      const hasStagedBytes = status.stagedBytes > 0;
      if (hasStagedRecords !== hasStagedBytes) {
        context.addIssue({
          code: 'custom',
          path: ['stagedRecords'],
          message: 'Restore staging record and byte progress must advance together',
        });
      }
      if (
        status.state === 'staging' &&
        (status.vaultId !== undefined) !== hasStagedRecords
      ) {
        context.addIssue({
          code: 'custom',
          path: ['vaultId'],
          message: 'Restore staging binds a vault exactly when its prefix is nonempty',
        });
      }
    }
    if (status.state === 'staging' || status.state === 'aborted') return;

    if (status.restoreSessionId !== status.summary.restoreSessionId) {
      context.addIssue({
        code: 'custom',
        path: ['restoreSessionId'],
        message: 'Restore status and authenticated summary identify different sessions',
      });
    }
    if (status.state === 'committed') return;

    if (status.vaultId !== status.summary.header.vaultId) {
      context.addIssue({
        code: 'custom',
        path: ['vaultId'],
        message: 'Restore status and authenticated summary identify different vaults',
      });
    }
    if (
      status.stagedRecords !== status.summary.recordCount ||
      status.summary.recordCount > status.maximumRecords
    ) {
      context.addIssue({
        code: 'custom',
        path: ['stagedRecords'],
        message: 'Frozen restore progress does not match the authenticated summary',
      });
    }
  });

export type BackupVerification = z.infer<typeof backupVerificationSchema>;
export type RestoreKnownRecordsVerificationV1 = z.infer<
  typeof restoreKnownRecordsVerificationV1Schema
>;
export type BackupRestoreStatus = z.infer<typeof backupRestoreStatusSchema>;

export type BackupRestoreStager = Readonly<{
  write(entry: EncryptedBackupEntry): Promise<void>;
  seal(summary: BackupVerification): Promise<void>;
  readSealed(summary: BackupVerification): AsyncIterable<EncryptedBackupEntry>;
  publish(
    summary: BackupVerification,
    receipt: RestoreKnownRecordsVerificationV1,
  ): Promise<void>;
  finalize(
    summary: BackupVerification,
    receipt: RestoreKnownRecordsVerificationV1,
  ): Promise<void>;
  status(): Promise<BackupRestoreStatus>;
  abort(): Promise<void>;
}>;

export type BackupRestoreStore = Readonly<{
  open(
    restoreSessionId: z.infer<typeof sha256DigestSchema>,
    limits: ResolvedBackupLimits,
  ): Promise<BackupRestoreStager>;
}>;
