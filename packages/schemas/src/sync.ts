import { z } from 'zod';

import { apiScopesSchema } from './authorization.js';
import {
  attachmentIdSchema,
  changeIdSchema,
  deviceIdSchema,
  groupIdSchema,
  itemIdSchema,
  vaultIdSchema,
} from './identifiers.js';
import {
  MAX_ATTACHMENT_CHUNKS,
  MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
  MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES,
  MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES,
  SECRETSTREAM_CHUNK_OVERHEAD_BYTES,
  encryptedDeviceLabelSchema,
  encryptedAttachmentRecordSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  vaultRecordSchema,
} from './encrypted-records.js';
import {
  changeSequenceSchema,
  recordRevisionSchema,
  sha256DigestSchema,
  supportedSchemaVersionSchema,
  supportedTokenVersionSchema,
  timestampSchema,
  vaultRevisionSchema,
} from './primitives.js';
import { attachmentHeaderContentHash } from './content-hash.js';

export const MIN_IDEMPOTENCY_KEY_CHARS = 16;
export const MAX_IDEMPOTENCY_KEY_CHARS = 256;

export const syncEntityTypeSchema = z.enum(['vault', 'group', 'item', 'attachment']);
export const syncOperationSchema = z.enum(['upsert', 'tombstone', 'restore', 'purge']);

const changeRecordBaseSchema = z
  .object({
    id: changeIdSchema,
    vaultId: vaultIdSchema,
    serverSequence: changeSequenceSchema,
    recordRevision: recordRevisionSchema,
    operation: syncOperationSchema,
    ciphertextHash: sha256DigestSchema.optional(),
    createdAt: timestampSchema,
  })
  .strict();

export const changeRecordSchema = z
  .discriminatedUnion('entityType', [
    changeRecordBaseSchema.extend({
      entityType: z.literal('vault'),
      entityId: vaultIdSchema,
    }),
    changeRecordBaseSchema.extend({
      entityType: z.literal('group'),
      entityId: groupIdSchema,
    }),
    changeRecordBaseSchema.extend({
      entityType: z.literal('item'),
      entityId: itemIdSchema,
    }),
    changeRecordBaseSchema.extend({
      entityType: z.literal('attachment'),
      entityId: attachmentIdSchema,
    }),
  ])
  .superRefine((change, context) => {
    if (change.serverSequence === 0) {
      context.addIssue({
        code: 'custom',
        message: 'Change records require a positive server sequence',
        path: ['serverSequence'],
      });
    }
    if (change.operation !== 'purge' && change.ciphertextHash === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Non-purge changes require the applicable content hash',
        path: ['ciphertextHash'],
      });
    }
    if (change.entityType === 'vault' && change.entityId !== change.vaultId) {
      context.addIssue({
        code: 'custom',
        message: 'A vault change must identify its containing vault',
        path: ['entityId'],
      });
    }
  });

const publicDeviceRecordObjectSchema = z
  .object({
    id: deviceIdSchema,
    vaultId: vaultIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    tokenVersion: supportedTokenVersionSchema,
    encryptedLabel: encryptedDeviceLabelSchema.optional(),
    scopes: apiScopesSchema,
    createdAt: timestampSchema,
    lastSeenAt: timestampSchema.optional(),
    revokedAt: timestampSchema.optional(),
  })
  .strict();

function validateDeviceBinding(
  device: z.infer<typeof publicDeviceRecordObjectSchema>,
  context: z.RefinementCtx,
): void {
  if (
    device.encryptedLabel !== undefined &&
    (device.encryptedLabel.aad.vaultId !== device.vaultId ||
      device.encryptedLabel.aad.schemaVersion !== device.schemaVersion ||
      device.encryptedLabel.aad.entityType !== 'device-label' ||
      device.encryptedLabel.aad.entityId !== device.id)
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Encrypted device label has invalid associated data',
      path: ['encryptedLabel', 'aad'],
    });
  }
}

/** Hash-free device shape returned over authenticated control-plane routes. */
export const publicDeviceRecordSchema =
  publicDeviceRecordObjectSchema.superRefine(validateDeviceBinding);

/** Server persistence shape; bearer material is represented only by its digest. */
export const deviceRecordSchema = publicDeviceRecordObjectSchema
  .extend({ tokenHash: sha256DigestSchema })
  .superRefine(validateDeviceBinding);

export const protectedLocalDeviceStateSchema = z
  .object({
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
    highestSeenVaultRevision: vaultRevisionSchema,
    updatedAt: timestampSchema,
  })
  .strict();

const tombstoneRecordBaseSchema = z
  .object({
    vaultId: vaultIdSchema,
    state: z.enum(['deleted', 'restored']),
    tombstoneRevision: recordRevisionSchema,
    lastRecordRevision: recordRevisionSchema,
    lastCiphertextHash: sha256DigestSchema,
    deletedAt: timestampSchema,
    restoredAt: timestampSchema.optional(),
    purgeAfter: timestampSchema.optional(),
  })
  .strict();

export const tombstoneRecordSchema = z
  .discriminatedUnion('entityType', [
    tombstoneRecordBaseSchema.extend({
      entityType: z.literal('vault'),
      entityId: vaultIdSchema,
    }),
    tombstoneRecordBaseSchema.extend({
      entityType: z.literal('group'),
      entityId: groupIdSchema,
    }),
    tombstoneRecordBaseSchema.extend({
      entityType: z.literal('item'),
      entityId: itemIdSchema,
    }),
    tombstoneRecordBaseSchema.extend({
      entityType: z.literal('attachment'),
      entityId: attachmentIdSchema,
    }),
  ])
  .superRefine((tombstone, context) => {
    if (tombstone.tombstoneRevision <= tombstone.lastRecordRevision) {
      context.addIssue({
        code: 'custom',
        message: 'Tombstone revision must be newer than the deleted record',
        path: ['tombstoneRevision'],
      });
    }
    if (tombstone.entityType === 'vault' && tombstone.entityId !== tombstone.vaultId) {
      context.addIssue({
        code: 'custom',
        message: 'A vault tombstone must identify its containing vault',
        path: ['entityId'],
      });
    }
    if (tombstone.state === 'restored' && tombstone.restoredAt === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Restored tombstones require a restoration timestamp',
        path: ['restoredAt'],
      });
    }
    if (tombstone.state === 'deleted' && tombstone.restoredAt !== undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Deleted tombstones cannot have a restoration timestamp',
        path: ['restoredAt'],
      });
    }
    if (tombstone.state === 'restored' && tombstone.purgeAfter !== undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Restored tombstones cannot remain scheduled for purge',
        path: ['purgeAfter'],
      });
    }
  });

export const opaqueMutationSchema = z.discriminatedUnion('entityType', [
  z
    .object({
      entityType: z.literal('vault'),
      expectedVaultRevision: vaultRevisionSchema.nullable(),
      idempotencyKey: z
        .string()
        .min(MIN_IDEMPOTENCY_KEY_CHARS)
        .max(MAX_IDEMPOTENCY_KEY_CHARS),
      record: vaultRecordSchema,
    })
    .strict(),
  z
    .object({
      entityType: z.literal('group'),
      expectedRecordRevision: recordRevisionSchema.nullable(),
      idempotencyKey: z
        .string()
        .min(MIN_IDEMPOTENCY_KEY_CHARS)
        .max(MAX_IDEMPOTENCY_KEY_CHARS),
      record: encryptedGroupRecordSchema,
    })
    .strict(),
  z
    .object({
      entityType: z.literal('item'),
      expectedRecordRevision: recordRevisionSchema.nullable(),
      idempotencyKey: z
        .string()
        .min(MIN_IDEMPOTENCY_KEY_CHARS)
        .max(MAX_IDEMPOTENCY_KEY_CHARS),
      record: encryptedItemRecordSchema,
    })
    .strict(),
]);

export const attachmentStreamStartInputSchema = z
  .object({
    version: z.literal(1),
    idempotencyKey: z
      .string()
      .min(MIN_IDEMPOTENCY_KEY_CHARS)
      .max(MAX_IDEMPOTENCY_KEY_CHARS),
    expectedAttachmentRevision: recordRevisionSchema.nullable(),
    header: persistedAttachmentHeaderRecordSchema,
  })
  .strict()
  .superRefine((input, context) => {
    const expectedNewRevision =
      input.expectedAttachmentRevision === null
        ? 0
        : input.expectedAttachmentRevision + 1;
    if (input.header.recordRevision !== expectedNewRevision) {
      context.addIssue({
        code: 'custom',
        message:
          'Staged header revision must immediately follow the expected attachment',
        path: ['header', 'recordRevision'],
      });
    }
    if (attachmentHeaderContentHash(input.header) !== input.header.contentHash) {
      context.addIssue({
        code: 'custom',
        message: 'Staged attachment headers require their exact canonical content hash',
        path: ['header', 'contentHash'],
      });
    }
  });

const attachmentStreamProgressCountersSchema = z.object({
  version: z.literal(1),
  nextChunkIndex: z.number().int().nonnegative().max(MAX_ATTACHMENT_CHUNKS),
  totalPlaintextBytes: z
    .number()
    .int()
    .nonnegative()
    .max(MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES),
  totalCiphertextBytes: z
    .number()
    .int()
    .nonnegative()
    .max(MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES),
});

export const attachmentStreamProgressSchema = z
  .discriminatedUnion('state', [
    attachmentStreamProgressCountersSchema
      .extend({
        state: z.literal('empty'),
        nextChunkIndex: z.literal(0),
        totalPlaintextBytes: z.literal(0),
        totalCiphertextBytes: z.literal(0),
      })
      .strict(),
    attachmentStreamProgressCountersSchema
      .extend({
        state: z.literal('writing'),
        nextChunkIndex: z.number().int().positive().max(MAX_ATTACHMENT_CHUNKS),
        lastChunkIndex: z
          .number()
          .int()
          .nonnegative()
          .max(MAX_ATTACHMENT_CHUNKS - 1),
        lastChunkCiphertextHash: sha256DigestSchema,
        lastChunkPlaintextBytes: z
          .number()
          .int()
          .nonnegative()
          .max(MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES),
      })
      .strict(),
    attachmentStreamProgressCountersSchema
      .extend({
        state: z.literal('ready-to-finalize'),
        nextChunkIndex: z.number().int().positive().max(MAX_ATTACHMENT_CHUNKS),
        lastChunkIndex: z
          .number()
          .int()
          .nonnegative()
          .max(MAX_ATTACHMENT_CHUNKS - 1),
        lastChunkCiphertextHash: sha256DigestSchema,
        lastChunkPlaintextBytes: z
          .number()
          .int()
          .nonnegative()
          .max(MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES),
      })
      .strict(),
  ])
  .superRefine((progress, context) => {
    if (progress.state === 'empty') return;
    if (
      progress.state === 'writing' &&
      progress.nextChunkIndex === MAX_ATTACHMENT_CHUNKS
    ) {
      context.addIssue({
        code: 'custom',
        message: 'The maximum chunk count requires final-chunk state',
        path: ['state'],
      });
    }
    if (progress.lastChunkIndex !== progress.nextChunkIndex - 1) {
      context.addIssue({
        code: 'custom',
        message: 'Last chunk index must immediately precede the next chunk index',
        path: ['lastChunkIndex'],
      });
    }
    if (
      progress.totalCiphertextBytes !==
      progress.totalPlaintextBytes +
        progress.nextChunkIndex * SECRETSTREAM_CHUNK_OVERHEAD_BYTES
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Staging byte totals must include exactly one overhead per chunk',
        path: ['totalCiphertextBytes'],
      });
    }
  });

export const attachmentStreamFinalizeInputSchema = z
  .object({
    version: z.literal(1),
    record: encryptedAttachmentRecordSchema,
  })
  .strict();

export const syncCursorSchema = z
  .object({
    vaultId: vaultIdSchema,
    serverSequence: changeSequenceSchema,
    highestSeenVaultRevision: vaultRevisionSchema,
  })
  .strict();

export const syncStateSchema = z.enum([
  'synced',
  'offline',
  'syncing',
  'conflict',
  'error',
]);

export type ChangeRecord = z.infer<typeof changeRecordSchema>;
export type DeviceRecord = z.infer<typeof deviceRecordSchema>;
export type ProtectedLocalDeviceState = z.infer<typeof protectedLocalDeviceStateSchema>;
export type TombstoneRecord = z.infer<typeof tombstoneRecordSchema>;
export type OpaqueMutation = z.infer<typeof opaqueMutationSchema>;
export type AttachmentStreamStartInput = z.infer<
  typeof attachmentStreamStartInputSchema
>;
export type AttachmentStreamProgress = z.infer<typeof attachmentStreamProgressSchema>;
export type AttachmentStreamFinalizeInput = z.infer<
  typeof attachmentStreamFinalizeInputSchema
>;
export type SyncCursor = z.infer<typeof syncCursorSchema>;
export type SyncState = z.infer<typeof syncStateSchema>;
