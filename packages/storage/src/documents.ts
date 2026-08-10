import { createHash } from 'node:crypto';

import { ValidationError } from '@kavrix/core';
import {
  attachmentIdSchema,
  auditEventIdSchema,
  attachmentStreamFinalizeInputSchema,
  attachmentStreamProgressSchema,
  attachmentStreamStartInputSchema,
  canonicalJson,
  changeRecordSchema,
  changeSequenceSchema,
  encryptedAttachmentRecordSchema,
  encryptedAuditRecordSchema,
  encryptedGroupRecordSchema,
  encryptedHistoryRecordSchema,
  encryptedItemRecordSchema,
  groupIdSchema,
  historyIdSchema,
  itemIdSchema,
  opaqueMutationSchema,
  opaqueSyncRecordSchema,
  persistedAttachmentChunkRecordSchema,
  timestampSchema,
  tombstoneRecordSchema,
  syncPulledChangeSchema,
  syncAcceptedPushResultSchema,
  syncConflictingPushResultSchema,
  syncPushResponseSchema,
  templateMigrationPublicationResponseSchema,
  vaultIdSchema,
  vaultRecordSchema,
  vaultRevisionSchema,
  type AttachmentStreamFinalizeInput,
  type AttachmentStreamProgress,
  type AttachmentStreamStartInput,
  type ChangeRecord,
  type EncryptedAttachmentRecord,
  type EncryptedAuditRecord,
  type EncryptedGroupRecord,
  type EncryptedHistoryRecord,
  type EncryptedItemRecord,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type PersistedAttachmentChunkRecord,
  type TombstoneRecord,
  type SyncPulledChange,
  type VaultRecord,
} from '@kavrix/schemas';
import { z } from 'zod';

export { contentHashForRecord } from '@kavrix/schemas';

const opaqueRecordKindSchema = z.enum(['vault', 'group', 'item', 'attachment']);
const sha256HexSchema = z.string().regex(/^[a-f0-9]{64}$/u);

export const storedVaultDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    record: vaultRecordSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (document._id !== document.vaultId || document.record.id !== document.vaultId) {
      context.addIssue({
        code: 'custom',
        message: 'Vault document identity is inconsistent',
        path: ['_id'],
      });
    }
  });

export const storedGroupDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    record: encryptedGroupRecordSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !== entityDocumentId(document.vaultId, document.groupId) ||
      document.record.vaultId !== document.vaultId ||
      document.record.id !== document.groupId
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Group document identity is inconsistent',
        path: ['_id'],
      });
    }
  });

export const storedItemDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    itemId: itemIdSchema,
    record: encryptedItemRecordSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !== entityDocumentId(document.vaultId, document.itemId) ||
      document.record.vaultId !== document.vaultId ||
      document.record.groupId !== document.groupId ||
      document.record.id !== document.itemId
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Item document identity is inconsistent',
        path: ['_id'],
      });
    }
  });

export const storedAttachmentDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    itemId: itemIdSchema,
    attachmentId: attachmentIdSchema,
    stagingId: z.string().min(1),
    record: encryptedAttachmentRecordSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !== entityDocumentId(document.vaultId, document.attachmentId) ||
      document.record.vaultId !== document.vaultId ||
      document.record.groupId !== document.groupId ||
      document.record.itemId !== document.itemId ||
      document.record.id !== document.attachmentId
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Attachment document identity is inconsistent',
        path: ['_id'],
      });
    }
  });

export const storedAuditDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    auditId: auditEventIdSchema,
    record: encryptedAuditRecordSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !== entityDocumentId(document.vaultId, document.auditId) ||
      document.record.vaultId !== document.vaultId ||
      document.record.id !== document.auditId
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Audit document identity is inconsistent',
        path: ['_id'],
      });
    }
  });

export const storedHistoryDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    itemId: itemIdSchema,
    historyId: historyIdSchema,
    record: encryptedHistoryRecordSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !== entityDocumentId(document.vaultId, document.historyId) ||
      document.record.vaultId !== document.vaultId ||
      document.record.groupId !== document.groupId ||
      document.record.itemId !== document.itemId ||
      document.record.id !== document.historyId
    ) {
      context.addIssue({
        code: 'custom',
        message: 'History document identity is inconsistent',
        path: ['_id'],
      });
    }
  });

export const storedChangeDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    serverSequence: changeSequenceSchema,
    record: changeRecordSchema,
    payload: opaqueSyncRecordSchema.nullable(),
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !== changeDocumentId(document.vaultId, document.serverSequence) ||
      document.record.vaultId !== document.vaultId ||
      document.record.serverSequence !== document.serverSequence ||
      !syncPulledChangeSchema.safeParse({
        change: document.record,
        record: document.payload,
      }).success
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Change document identity is inconsistent',
        path: ['_id'],
      });
    }
  });

export const storedTombstoneDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    entityType: opaqueRecordKindSchema,
    entityId: z.string().min(1).max(128),
    record: tombstoneRecordSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !== entityDocumentId(document.vaultId, document.entityId) ||
      document.record.vaultId !== document.vaultId ||
      document.record.entityType !== document.entityType ||
      document.record.entityId !== document.entityId
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Tombstone document identity is inconsistent',
        path: ['_id'],
      });
    }
  });

export const storageCounterDocumentSchema = z
  .object({
    _id: vaultIdSchema,
    changeSequence: changeSequenceSchema,
    vaultRevision: vaultRevisionSchema,
  })
  .strict();

export const idempotencyDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    idempotencyKey: z.string().min(16).max(256),
    inputHash: sha256HexSchema,
    entityType: opaqueRecordKindSchema,
    change: changeRecordSchema,
    committedAt: timestampSchema,
  })
  .strict();

const syncPushResultSchema = z.discriminatedUnion('status', [
  syncAcceptedPushResultSchema,
  syncConflictingPushResultSchema,
]);

export const syncPushBatchDocumentSchema = z
  .discriminatedUnion('state', [
    z
      .object({
        _id: z.string().min(1),
        vaultId: vaultIdSchema,
        batchIdempotencyKey: z.string().min(16).max(256),
        requestHash: sha256HexSchema,
        mutationCount: z.number().int().positive().max(100),
        state: z.literal('running'),
        nextMutationIndex: z.number().int().nonnegative().max(100),
        results: z.array(syncPushResultSchema).max(100),
        createdAt: timestampSchema,
        updatedAt: timestampSchema,
      })
      .strict(),
    z
      .object({
        _id: z.string().min(1),
        vaultId: vaultIdSchema,
        batchIdempotencyKey: z.string().min(16).max(256),
        requestHash: sha256HexSchema,
        mutationCount: z.number().int().positive().max(100),
        state: z.literal('completed'),
        nextMutationIndex: z.number().int().positive().max(100),
        results: z.array(syncPushResultSchema).min(1).max(100),
        response: syncPushResponseSchema,
        createdAt: timestampSchema,
        updatedAt: timestampSchema,
        completedAt: timestampSchema,
      })
      .strict(),
  ])
  .superRefine((document, context) => {
    if (
      document._id !==
      syncPushBatchDocumentId(document.vaultId, document.batchIdempotencyKey)
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Sync push batch identity is inconsistent',
        path: ['_id'],
      });
    }
    if (
      document.nextMutationIndex !== document.results.length ||
      document.nextMutationIndex > document.mutationCount
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Sync push checkpoint does not match its persisted results',
        path: ['nextMutationIndex'],
      });
    }
    if (
      document.state === 'completed' &&
      (document.nextMutationIndex !== document.mutationCount ||
        document.response.results.length !== document.mutationCount ||
        document.response.vaultId !== document.vaultId ||
        document.response.batchIdempotencyKey !== document.batchIdempotencyKey ||
        hashCanonical(document.response.results) !== hashCanonical(document.results))
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Completed sync push batches require every mutation result',
        path: ['response'],
      });
    }
  });

export const templateMigrationPublicationDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    batchIdempotencyKey: z.string().min(16).max(256),
    requestHash: sha256HexSchema,
    response: templateMigrationPublicationResponseSchema,
    committedAt: timestampSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !==
        templateMigrationPublicationDocumentId(
          document.vaultId,
          document.batchIdempotencyKey,
        ) ||
      document.response.vaultId !== document.vaultId ||
      document.response.batchIdempotencyKey !== document.batchIdempotencyKey
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Template migration publication identity is inconsistent',
        path: ['_id'],
      });
    }
  });

const activeAttachmentStagingDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    attachmentId: attachmentIdSchema,
    idempotencyKey: z.string().min(16).max(256),
    inputHash: sha256HexSchema,
    state: z.literal('active'),
    input: attachmentStreamStartInputSchema,
    progress: attachmentStreamProgressSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

const finalizedAttachmentStagingDocumentSchema = activeAttachmentStagingDocumentSchema
  .omit({ state: true })
  .extend({
    state: z.literal('finalized'),
    finalizeHash: sha256HexSchema,
    finalizedAt: timestampSchema,
  })
  .strict();

const abortedAttachmentStagingDocumentSchema = z
  .object({
    _id: z.string().min(1),
    vaultId: vaultIdSchema,
    attachmentId: attachmentIdSchema,
    idempotencyKey: z.string().min(16).max(256),
    inputHash: sha256HexSchema,
    state: z.literal('aborted'),
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    abortedAt: timestampSchema,
  })
  .strict();

export const attachmentStagingDocumentSchema = z
  .discriminatedUnion('state', [
    activeAttachmentStagingDocumentSchema,
    finalizedAttachmentStagingDocumentSchema,
    abortedAttachmentStagingDocumentSchema,
  ])
  .superRefine((document, context) => {
    if (document._id !== stagingDocumentId(document.vaultId, document.idempotencyKey)) {
      context.addIssue({
        code: 'custom',
        message: 'Attachment staging identity is inconsistent',
        path: ['_id'],
      });
    }
  });

export const stagedAttachmentChunkDocumentSchema = z
  .object({
    _id: z.string().min(1),
    stagingId: z.string().min(1),
    vaultId: vaultIdSchema,
    attachmentId: attachmentIdSchema,
    chunkIndex: z.number().int().nonnegative(),
    record: persistedAttachmentChunkRecordSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (
      document._id !== stagedChunkDocumentId(document.stagingId, document.chunkIndex) ||
      document.record.record.vaultId !== document.vaultId ||
      document.record.record.attachmentId !== document.attachmentId ||
      document.record.record.index !== document.chunkIndex
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Staged attachment chunk identity is inconsistent',
        path: ['_id'],
      });
    }
  });

export type StoredVaultDocument = z.infer<typeof storedVaultDocumentSchema>;
export type StoredGroupDocument = z.infer<typeof storedGroupDocumentSchema>;
export type StoredItemDocument = z.infer<typeof storedItemDocumentSchema>;
export type StoredAttachmentDocument = z.infer<typeof storedAttachmentDocumentSchema>;
export type StoredAuditDocument = z.infer<typeof storedAuditDocumentSchema>;
export type StoredHistoryDocument = z.infer<typeof storedHistoryDocumentSchema>;
export type StoredChangeDocument = z.infer<typeof storedChangeDocumentSchema>;
export type StoredTombstoneDocument = z.infer<typeof storedTombstoneDocumentSchema>;
export type StorageCounterDocument = z.infer<typeof storageCounterDocumentSchema>;
export type IdempotencyDocument = z.infer<typeof idempotencyDocumentSchema>;
export type SyncPushBatchDocument = z.infer<typeof syncPushBatchDocumentSchema>;
export type TemplateMigrationPublicationDocument = z.infer<
  typeof templateMigrationPublicationDocumentSchema
>;
export type AttachmentStagingDocument = z.infer<typeof attachmentStagingDocumentSchema>;
export type ActiveAttachmentStagingDocument = z.infer<
  typeof activeAttachmentStagingDocumentSchema
>;
export type FinalizedAttachmentStagingDocument = z.infer<
  typeof finalizedAttachmentStagingDocumentSchema
>;
export type StagedAttachmentChunkDocument = z.infer<
  typeof stagedAttachmentChunkDocumentSchema
>;

export function entityDocumentId(vaultId: string, entityId: string): string {
  return `${vaultId}|${entityId}`;
}

export function changeDocumentId(vaultId: string, sequence: number): string {
  return `${vaultId}|${String(sequence)}`;
}

export function stagingDocumentId(vaultId: string, idempotencyKey: string): string {
  return `${vaultId}|${hashCanonical(idempotencyKey)}`;
}

export function syncPushBatchDocumentId(
  vaultId: string,
  batchIdempotencyKey: string,
): string {
  return `${vaultId}|batch|${hashCanonical(batchIdempotencyKey)}`;
}

export function templateMigrationPublicationDocumentId(
  vaultId: string,
  batchIdempotencyKey: string,
): string {
  return `${vaultId}|template-migration|${hashCanonical(batchIdempotencyKey)}`;
}

export function stagedChunkDocumentId(stagingId: string, index: number): string {
  return `${stagingId}|${String(index)}`;
}

export function mutationVaultId(mutation: OpaqueMutation): string {
  return mutation.entityType === 'vault' ? mutation.record.id : mutation.record.vaultId;
}

export function hashCanonical(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

export function parseMutation(input: unknown): OpaqueMutation {
  return parseInput(opaqueMutationSchema, input, 'opaque mutation');
}

export function parseAttachmentStart(input: unknown): AttachmentStreamStartInput {
  return parseInput(attachmentStreamStartInputSchema, input, 'attachment stream start');
}

export function parseAttachmentFinalize(input: unknown): AttachmentStreamFinalizeInput {
  return parseInput(
    attachmentStreamFinalizeInputSchema,
    input,
    'attachment stream finalization',
  );
}

export function parseAttachmentChunk(input: unknown): PersistedAttachmentChunkRecord {
  return parseInput(persistedAttachmentChunkRecordSchema, input, 'attachment chunk');
}

export function toVaultDocument(recordInput: VaultRecord): StoredVaultDocument {
  const record = parseInput(vaultRecordSchema, recordInput, 'vault record');
  return storedVaultDocumentSchema.parse({
    _id: record.id,
    vaultId: record.id,
    record,
  });
}

export function fromVaultDocument(input: unknown): VaultRecord {
  return parseStored(storedVaultDocumentSchema, input, 'vault document').record;
}

export function toGroupDocument(
  recordInput: EncryptedGroupRecord,
): StoredGroupDocument {
  const record = parseInput(encryptedGroupRecordSchema, recordInput, 'group record');
  return storedGroupDocumentSchema.parse({
    _id: entityDocumentId(record.vaultId, record.id),
    vaultId: record.vaultId,
    groupId: record.id,
    record,
  });
}

export function fromGroupDocument(input: unknown): EncryptedGroupRecord {
  return parseStored(storedGroupDocumentSchema, input, 'group document').record;
}

export function toItemDocument(recordInput: EncryptedItemRecord): StoredItemDocument {
  const record = parseInput(encryptedItemRecordSchema, recordInput, 'item record');
  return storedItemDocumentSchema.parse({
    _id: entityDocumentId(record.vaultId, record.id),
    vaultId: record.vaultId,
    groupId: record.groupId,
    itemId: record.id,
    record,
  });
}

export function fromItemDocument(input: unknown): EncryptedItemRecord {
  return parseStored(storedItemDocumentSchema, input, 'item document').record;
}

export function toAttachmentDocument(
  recordInput: EncryptedAttachmentRecord,
  stagingId: string,
): StoredAttachmentDocument {
  const record = parseInput(
    encryptedAttachmentRecordSchema,
    recordInput,
    'attachment record',
  );
  return storedAttachmentDocumentSchema.parse({
    _id: entityDocumentId(record.vaultId, record.id),
    vaultId: record.vaultId,
    groupId: record.groupId,
    itemId: record.itemId,
    attachmentId: record.id,
    stagingId,
    record,
  });
}

export function fromAttachmentDocument(input: unknown): EncryptedAttachmentRecord {
  return parseStored(storedAttachmentDocumentSchema, input, 'attachment document')
    .record;
}

export function toAuditDocument(
  recordInput: EncryptedAuditRecord,
): StoredAuditDocument {
  const record = parseInput(encryptedAuditRecordSchema, recordInput, 'audit record');
  return storedAuditDocumentSchema.parse({
    _id: entityDocumentId(record.vaultId, record.id),
    vaultId: record.vaultId,
    auditId: record.id,
    record,
  });
}

export function fromAuditDocument(input: unknown): EncryptedAuditRecord {
  return parseStored(storedAuditDocumentSchema, input, 'audit document').record;
}

export function toHistoryDocument(
  recordInput: EncryptedHistoryRecord,
): StoredHistoryDocument {
  const record = parseInput(
    encryptedHistoryRecordSchema,
    recordInput,
    'history record',
  );
  return storedHistoryDocumentSchema.parse({
    _id: entityDocumentId(record.vaultId, record.id),
    vaultId: record.vaultId,
    groupId: record.groupId,
    itemId: record.itemId,
    historyId: record.id,
    record,
  });
}

export function fromHistoryDocument(input: unknown): EncryptedHistoryRecord {
  return parseStored(storedHistoryDocumentSchema, input, 'history document').record;
}

export function toChangeDocument(
  recordInput: ChangeRecord,
  payloadInput: OpaqueSyncRecord | null,
): StoredChangeDocument {
  const record = parseInput(changeRecordSchema, recordInput, 'change record');
  const payload = parseInput(
    opaqueSyncRecordSchema.nullable(),
    payloadInput,
    'change payload',
  );
  return storedChangeDocumentSchema.parse({
    _id: changeDocumentId(record.vaultId, record.serverSequence),
    vaultId: record.vaultId,
    serverSequence: record.serverSequence,
    record,
    payload,
  });
}

export function fromChangeDocument(input: unknown): ChangeRecord {
  return parseStored(storedChangeDocumentSchema, input, 'change document').record;
}

export function fromSyncPulledChangeDocument(input: unknown): SyncPulledChange {
  const document = parseStored(storedChangeDocumentSchema, input, 'change document');
  return parseStored(
    syncPulledChangeSchema,
    { change: document.record, record: document.payload },
    'pulled change',
  );
}

export function toTombstoneDocument(
  recordInput: TombstoneRecord,
): StoredTombstoneDocument {
  const record = parseInput(tombstoneRecordSchema, recordInput, 'tombstone record');
  return storedTombstoneDocumentSchema.parse({
    _id: entityDocumentId(record.vaultId, record.entityId),
    vaultId: record.vaultId,
    entityType: record.entityType,
    entityId: record.entityId,
    record,
  });
}

export function fromTombstoneDocument(input: unknown): TombstoneRecord {
  return parseStored(storedTombstoneDocumentSchema, input, 'tombstone document').record;
}

export function parseCounterDocument(input: unknown): StorageCounterDocument {
  return parseStored(storageCounterDocumentSchema, input, 'storage counter');
}

export function parseIdempotencyDocument(input: unknown): IdempotencyDocument {
  return parseStored(idempotencyDocumentSchema, input, 'idempotency document');
}

export function parseSyncPushBatchDocument(input: unknown): SyncPushBatchDocument {
  return parseStored(syncPushBatchDocumentSchema, input, 'sync push batch');
}

export function parseTemplateMigrationPublicationDocument(
  input: unknown,
): TemplateMigrationPublicationDocument {
  return parseStored(
    templateMigrationPublicationDocumentSchema,
    input,
    'template migration publication',
  );
}

export function parseStagingDocument(input: unknown): AttachmentStagingDocument {
  return parseStored(attachmentStagingDocumentSchema, input, 'attachment staging');
}

export function parseStagedChunkDocument(
  input: unknown,
): StagedAttachmentChunkDocument {
  return parseStored(
    stagedAttachmentChunkDocumentSchema,
    input,
    'staged attachment chunk',
  );
}

export function makeStagedChunkDocument(
  stagingId: string,
  recordInput: PersistedAttachmentChunkRecord,
): StagedAttachmentChunkDocument {
  const record = parseAttachmentChunk(recordInput);
  return stagedAttachmentChunkDocumentSchema.parse({
    _id: stagedChunkDocumentId(stagingId, record.record.index),
    stagingId,
    vaultId: record.record.vaultId,
    attachmentId: record.record.attachmentId,
    chunkIndex: record.record.index,
    record,
  });
}

export function expectedNextRevision(expectedRevision: number | null): number {
  return expectedRevision === null ? 0 : expectedRevision + 1;
}

export function synchronizeVaultRecordRevision(
  recordInput: VaultRecord,
  nextRevisionInput: number,
  observedUpdatedAtInput: string,
): VaultRecord {
  const record = parseInput(vaultRecordSchema, recordInput, 'vault record');
  const nextRevision = parseInput(
    vaultRevisionSchema,
    nextRevisionInput,
    'next vault revision',
  );
  const observedUpdatedAt = parseInput(
    timestampSchema,
    observedUpdatedAtInput,
    'observed update timestamp',
  );
  if (nextRevision !== record.revision + 1) {
    throw new ValidationError('A vault rollback anchor must advance exactly once.');
  }
  return vaultRecordSchema.parse({
    ...record,
    revision: nextRevision,
    updatedAt:
      observedUpdatedAt > record.updatedAt ? observedUpdatedAt : record.updatedAt,
  });
}

export function mutationRecordRevision(mutation: OpaqueMutation): number {
  return mutation.entityType === 'vault'
    ? mutation.record.revision
    : mutation.record.recordRevision;
}

export function mutationExpectedRevision(mutation: OpaqueMutation): number | null {
  return mutation.entityType === 'vault'
    ? mutation.expectedVaultRevision
    : mutation.expectedRecordRevision;
}

export function stagingProgress(
  document: AttachmentStagingDocument,
): AttachmentStreamProgress {
  if (document.state === 'aborted') {
    throw new ValidationError('An aborted attachment stream cannot be resumed.');
  }
  return document.progress;
}

export function finalizeHash(input: AttachmentStreamFinalizeInput): string {
  return hashCanonical(attachmentStreamFinalizeInputSchema.parse(input));
}

function parseInput<T>(schema: z.ZodType<T>, input: unknown, label: string): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new ValidationError(`The ${label} is invalid.`, { cause: result.error });
  }
  return result.data;
}

function parseStored<T>(schema: z.ZodType<T>, input: unknown, label: string): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new ValidationError(`Stored ${label} failed canonical validation.`, {
      cause: result.error,
    });
  }
  return result.data;
}
