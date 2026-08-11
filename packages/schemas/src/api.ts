import { z } from 'zod';

import {
  attachmentIdSchema,
  deviceIdSchema,
  groupIdSchema,
  inviteIdSchema,
  itemIdSchema,
  keySlotIdSchema,
  vaultIdSchema,
} from './identifiers.js';
import {
  MAX_ATTACHMENT_CHUNKS,
  encryptedAttachmentRecordSchema,
  encryptedDeviceLabelSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  persistedAttachmentChunkRecordSchema,
  vaultRecordSchema,
} from './encrypted-records.js';
import {
  base64UrlSchema,
  changeSequenceSchema,
  recordRevisionSchema,
  supportedSchemaVersionSchema,
  timestampSchema,
  vaultRevisionSchema,
} from './primitives.js';
import { canonicalJson } from './content-hash.js';
import {
  attachmentStreamFinalizeInputSchema,
  attachmentStreamProgressSchema,
  attachmentStreamStartInputSchema,
  changeRecordSchema,
  opaqueMutationSchema,
  publicDeviceRecordSchema,
  syncCursorSchema,
  tombstoneRecordSchema,
} from './sync.js';

export const apiScopeSchema = z.enum(['sync:read', 'sync:write', 'device:manage']);

export const healthResponseSchema = z.object({ status: z.literal('ok') }).strict();

export const CONTROL_LIST_CURSOR_VERSION = 1;
export const DEFAULT_CONTROL_LIST_PAGE_SIZE = 50;
export const MAX_CONTROL_LIST_PAGE_SIZE = 200;
export const MAX_CONTROL_LIST_CURSOR_CHARS = 512;

/** Unsigned navigation hint. Authenticated routes must bind it to their resource/vault. */
const controlListCursorPayloadBaseSchema = z
  .object({
    version: z.literal(CONTROL_LIST_CURSOR_VERSION),
    vaultId: vaultIdSchema,
    createdAt: timestampSchema,
  })
  .strict();

export const controlListCursorPayloadSchema = z.discriminatedUnion('resource', [
  controlListCursorPayloadBaseSchema
    .extend({
      resource: z.literal('invites'),
      id: inviteIdSchema,
    })
    .strict(),
  controlListCursorPayloadBaseSchema
    .extend({
      resource: z.literal('devices'),
      id: deviceIdSchema,
    })
    .strict(),
]);

const boundedControlListCursorSchema = z
  .string()
  .min(1)
  .max(MAX_CONTROL_LIST_CURSOR_CHARS)
  .pipe(base64UrlSchema)
  .brand<'ControlListCursor'>();

export function encodeControlListCursor(
  payload: z.input<typeof controlListCursorPayloadSchema>,
): z.infer<typeof boundedControlListCursorSchema> {
  const parsedPayload = controlListCursorPayloadSchema.parse(payload);
  return boundedControlListCursorSchema.parse(
    Buffer.from(canonicalJson(parsedPayload), 'utf8').toString('base64url'),
  );
}

function decodeCanonicalControlListCursor(
  cursor: unknown,
): z.infer<typeof controlListCursorPayloadSchema> {
  try {
    const parsedCursor = boundedControlListCursorSchema.parse(cursor);
    const json = new TextDecoder('utf-8', { fatal: true }).decode(
      Buffer.from(parsedCursor, 'base64url'),
    );
    const payload = controlListCursorPayloadSchema.parse(JSON.parse(json) as unknown);
    if (encodeControlListCursor(payload) !== parsedCursor) {
      throw new TypeError('Noncanonical control-list cursor');
    }
    return payload;
  } catch {
    throw new TypeError('Invalid control-list cursor');
  }
}

export function decodeControlListCursor(
  cursor: string,
): z.infer<typeof controlListCursorPayloadSchema> {
  return decodeCanonicalControlListCursor(cursor);
}

export const controlListCursorSchema = boundedControlListCursorSchema.superRefine(
  (cursor, context) => {
    try {
      decodeCanonicalControlListCursor(cursor);
    } catch {
      context.addIssue({
        code: 'custom',
        message: 'Control-list cursor is malformed or noncanonical',
      });
    }
  },
);

export const apiBearerTokenSchema = z
  .string()
  .length(43)
  .regex(/^[A-Za-z0-9_-]+$/, 'Bearer tokens use canonical unpadded base64url')
  .refine((value) => Buffer.from(value, 'base64url').toString('base64url') === value, {
    error: 'Bearer tokens use canonical unpadded base64url',
  })
  .brand<'ApiBearerToken'>();

export const apiErrorResponseSchema = z
  .object({
    error: z
      .object({
        code: z.string().min(1).max(64),
        message: z.string().min(1).max(256),
        conflict: z
          .object({
            entityType: z.enum(['vault', 'group', 'item', 'attachment']),
            entityId: z.string().min(1).max(128),
            expectedRevision: z.number().int().nonnegative().nullable(),
            currentRevision: z.number().int().nonnegative().nullable(),
          })
          .strict()
          .optional(),
      })
      .strict(),
  })
  .strict();

export const inviteIssueRequestSchema = z
  .object({
    scopes: z.array(apiScopeSchema).min(1).max(3),
    expiresInSeconds: z.number().int().min(60).max(86_400),
  })
  .strict()
  .superRefine((value, context) => {
    if (new Set(value.scopes).size !== value.scopes.length) {
      context.addIssue({
        code: 'custom',
        path: ['scopes'],
        message: 'Invite scopes must be unique',
      });
    }
  });

export const inviteIssueResponseSchema = z
  .object({
    inviteId: inviteIdSchema,
    inviteToken: apiBearerTokenSchema,
    expiresAt: timestampSchema,
  })
  .strict();

export const publicInviteRecordSchema = z
  .object({
    id: inviteIdSchema,
    vaultId: vaultIdSchema,
    issuedByDeviceId: deviceIdSchema,
    scopes: z.array(apiScopeSchema).min(1).max(3),
    state: z.enum(['active', 'redeemed', 'revoked', 'expired']),
    createdAt: timestampSchema,
    expiresAt: timestampSchema,
    consumedAt: timestampSchema.optional(),
    revokedAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((invite, context) => {
    if (new Set(invite.scopes).size !== invite.scopes.length) {
      context.addIssue({
        code: 'custom',
        path: ['scopes'],
        message: 'Invite scopes must be unique',
      });
    }
    if ((invite.state === 'redeemed') !== (invite.consumedAt !== undefined)) {
      context.addIssue({
        code: 'custom',
        path: ['consumedAt'],
        message: 'Only redeemed invites carry a consumption timestamp',
      });
    }
    if ((invite.state === 'revoked') !== (invite.revokedAt !== undefined)) {
      context.addIssue({
        code: 'custom',
        path: ['revokedAt'],
        message: 'Only revoked invites carry a revocation timestamp',
      });
    }
  });

export const inviteListResponseSchema = z
  .object({ invites: z.array(publicInviteRecordSchema).max(10_000) })
  .strict();

export const inviteListPageResponseSchema = z
  .object({
    invites: z.array(publicInviteRecordSchema).max(MAX_CONTROL_LIST_PAGE_SIZE),
    nextCursor: controlListCursorSchema.nullable(),
  })
  .strict()
  .superRefine((page, context) => {
    validateControlListPage('invites', page.invites, page.nextCursor, context);
  });

export const vaultInvitePathSchema = z
  .object({ vaultId: vaultIdSchema, inviteId: inviteIdSchema })
  .strict();

export const inviteRedeemResponseSchema = z
  .object({
    vaultId: vaultIdSchema,
    expiresAt: timestampSchema,
    vault: vaultRecordSchema,
  })
  .strict()
  .refine((response) => response.vault.id === response.vaultId, {
    path: ['vault', 'id'],
    error: 'Redeemed vaults must match the invite vault',
  });

export const enrollmentCompleteRequestSchema = z
  .object({
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    encryptedLabel: encryptedDeviceLabelSchema.optional(),
  })
  .strict();

export const enrollmentCompleteResponseSchema = z
  .object({
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
  })
  .strict();

export const apiSessionResponseSchema = z
  .object({
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
    scopes: z.array(apiScopeSchema).min(1).max(3),
  })
  .strict()
  .refine((session) => new Set(session.scopes).size === session.scopes.length, {
    path: ['scopes'],
    error: 'Session scopes must be unique',
  });

/**
 * The first device sends an already-encrypted, revision-zero vault aggregate.
 * Its independently generated session bearer is carried only in the
 * Authorization header and is deliberately absent from this body.
 */
export const vaultBootstrapRequestSchema = z
  .object({
    vault: vaultRecordSchema,
    device: z
      .object({
        id: deviceIdSchema,
        schemaVersion: supportedSchemaVersionSchema,
        encryptedLabel: encryptedDeviceLabelSchema.optional(),
      })
      .strict(),
  })
  .strict()
  .superRefine((request, context) => {
    if (request.vault.revision !== 0) {
      context.addIssue({
        code: 'custom',
        path: ['vault', 'revision'],
        message: 'Initial vaults must start at revision zero',
      });
    }
    if (request.vault.createdAt !== request.vault.updatedAt) {
      context.addIssue({
        code: 'custom',
        path: ['vault', 'updatedAt'],
        message: 'Initial vault timestamps must match',
      });
    }
    if (request.device.schemaVersion !== request.vault.schemaVersion) {
      context.addIssue({
        code: 'custom',
        path: ['device', 'schemaVersion'],
        message: 'The first device and vault schema versions must match',
      });
    }
  });

export const vaultBootstrapResponseSchema = z
  .object({
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
  })
  .strict();

export { publicDeviceRecordSchema } from './sync.js';

export const deviceListResponseSchema = z
  .object({ devices: z.array(publicDeviceRecordSchema).max(10_000) })
  .strict();

export const deviceListPageResponseSchema = z
  .object({
    devices: z.array(publicDeviceRecordSchema).max(MAX_CONTROL_LIST_PAGE_SIZE),
    nextCursor: controlListCursorSchema.nullable(),
  })
  .strict()
  .superRefine((page, context) => {
    validateControlListPage('devices', page.devices, page.nextCursor, context);
  });

export const vaultPathSchema = z.object({ vaultId: vaultIdSchema }).strict();
export const vaultDevicePathSchema = z
  .object({ vaultId: vaultIdSchema, deviceId: deviceIdSchema })
  .strict();
export const vaultKeySlotPathSchema = z
  .object({ vaultId: vaultIdSchema, slotId: keySlotIdSchema })
  .strict();

export const vaultKeySlotUpdateRequestSchema = z
  .object({
    expectedVaultRevision: vaultRevisionSchema,
    idempotencyKey: z.string().min(16).max(256),
    record: vaultRecordSchema,
  })
  .strict()
  .refine((value) => value.record.revision === value.expectedVaultRevision + 1, {
    path: ['record', 'revision'],
    error: 'Key-slot updates must advance the vault revision exactly once',
  });

const decimalIntegerQuerySchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]*)$/, 'Must be a canonical nonnegative integer')
  .transform((value, context) => {
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) {
      context.addIssue({
        code: 'custom',
        message: 'Integer is outside the safe range',
      });
      return z.NEVER;
    }
    return parsed;
  });

const controlListPageLimitSchema = decimalIntegerQuerySchema.pipe(
  z.number().int().min(1).max(MAX_CONTROL_LIST_PAGE_SIZE),
);

export const controlListPageQuerySchema = z
  .object({
    limit: controlListPageLimitSchema.default(DEFAULT_CONTROL_LIST_PAGE_SIZE),
    cursor: controlListCursorSchema.optional(),
  })
  .strict();

export const attachmentTransferPathSchema = z
  .object({
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    itemId: itemIdSchema,
    attachmentId: attachmentIdSchema,
  })
  .strict();

export const attachmentChunkPathSchema = attachmentTransferPathSchema
  .extend({ chunkIndex: decimalIntegerQuerySchema })
  .strict()
  .refine((path) => path.chunkIndex < MAX_ATTACHMENT_CHUNKS, {
    path: ['chunkIndex'],
    error: 'Attachment chunk index is outside the canonical bound',
  });

export const attachmentChunkStageRequestSchema = z
  .object({
    start: attachmentStreamStartInputSchema,
    chunk: persistedAttachmentChunkRecordSchema,
  })
  .strict()
  .superRefine((request, context) => {
    validateAttachmentTransportIdentity(
      request.start,
      request.chunk.record,
      request.chunk.recordRevision,
      context,
      ['chunk'],
    );
  });

export const attachmentFinalizeRequestSchema = z
  .object({
    start: attachmentStreamStartInputSchema,
    finalize: attachmentStreamFinalizeInputSchema,
  })
  .strict()
  .superRefine((request, context) => {
    validateAttachmentTransportIdentity(
      request.start,
      request.finalize.record,
      request.finalize.record.recordRevision,
      context,
      ['finalize', 'record'],
    );
  });

export const attachmentStreamProgressResponseSchema = attachmentStreamProgressSchema;

export const syncPullQuerySchema = z
  .object({
    serverSequence: decimalIntegerQuerySchema.default(0),
    highestSeenVaultRevision: decimalIntegerQuerySchema,
    limit: decimalIntegerQuerySchema.default(100),
  })
  .strict()
  .transform((value) => ({
    serverSequence: changeSequenceSchema.parse(value.serverSequence),
    highestSeenVaultRevision: vaultRevisionSchema.parse(value.highestSeenVaultRevision),
    limit: value.limit,
  }))
  .refine((value) => value.limit >= 1 && value.limit <= 500, {
    path: ['limit'],
    error: 'Sync pull limits must be between 1 and 500',
  });

export const opaqueSyncRecordSchema = z.union([
  vaultRecordSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  encryptedAttachmentRecordSchema,
  tombstoneRecordSchema,
]);

export const syncPulledChangeSchema = z
  .object({
    change: changeRecordSchema,
    record: opaqueSyncRecordSchema.nullable(),
  })
  .strict()
  .superRefine((pulled, context) => {
    const { change, record } = pulled;
    if (change.operation === 'purge') {
      if (record !== null) {
        context.addIssue({
          code: 'custom',
          path: ['record'],
          message: 'Purged changes cannot include a record',
        });
      }
      return;
    }
    if (
      record === null ||
      syncRecordVaultId(record) !== change.vaultId ||
      syncRecordEntityType(record) !== change.entityType ||
      syncRecordId(record) !== change.entityId ||
      syncRecordRevision(record) !== change.recordRevision
    ) {
      context.addIssue({
        code: 'custom',
        path: ['record'],
        message: 'Pulled records must be bound to their change metadata',
      });
      return;
    }
    if (
      change.operation === 'tombstone' &&
      (!isTombstoneRecord(record) || record.state !== 'deleted')
    ) {
      context.addIssue({
        code: 'custom',
        path: ['record'],
        message: 'Tombstone changes require a deleted tombstone record',
      });
    }
    if (
      (change.operation === 'upsert' || change.operation === 'restore') &&
      !isCurrentOpaqueRecord(record)
    ) {
      context.addIssue({
        code: 'custom',
        path: ['record'],
        message: 'Upsert and restore changes require a current encrypted record',
      });
    }
  });

export const syncPullResponseSchema = z
  .object({
    vaultId: vaultIdSchema,
    serverVaultRevision: vaultRevisionSchema,
    changes: z.array(syncPulledChangeSchema).max(500),
    nextCursor: syncCursorSchema,
    hasMore: z.boolean(),
  })
  .strict()
  .superRefine((page, context) => {
    if (
      page.nextCursor.vaultId !== page.vaultId ||
      page.nextCursor.highestSeenVaultRevision !== page.serverVaultRevision
    ) {
      context.addIssue({
        code: 'custom',
        path: ['nextCursor'],
        message: 'The next cursor must be bound to the returned vault revision',
      });
    }
    if (page.changes.some(({ change }) => change.vaultId !== page.vaultId)) {
      context.addIssue({
        code: 'custom',
        path: ['changes'],
        message: 'All changes must belong to the response vault',
      });
    }
    if (page.hasMore && page.changes.length === 0) {
      context.addIssue({
        code: 'custom',
        path: ['hasMore'],
        message: 'A nonterminal page must contain at least one change',
      });
    }
  });

export const syncPushRequestSchema = z
  .object({
    vaultId: vaultIdSchema,
    batchIdempotencyKey: z.string().min(16).max(256),
    mutations: z.array(opaqueMutationSchema).min(1).max(100),
  })
  .strict()
  .superRefine((batch, context) => {
    const keys = new Set<string>();
    for (const [index, mutation] of batch.mutations.entries()) {
      if (syncMutationVaultId(mutation) !== batch.vaultId) {
        context.addIssue({
          code: 'custom',
          path: ['mutations', index],
          message: 'Every mutation must belong to the batch vault',
        });
      }
      if (keys.has(mutation.idempotencyKey)) {
        context.addIssue({
          code: 'custom',
          path: ['mutations', index, 'idempotencyKey'],
          message: 'Mutation idempotency keys must be unique within a batch',
        });
      }
      keys.add(mutation.idempotencyKey);
      const expected =
        mutation.entityType === 'vault'
          ? mutation.expectedVaultRevision
          : mutation.expectedRecordRevision;
      const revision =
        mutation.entityType === 'vault'
          ? mutation.record.revision
          : mutation.record.recordRevision;
      if (revision !== (expected === null ? 0 : expected + 1)) {
        context.addIssue({
          code: 'custom',
          path: ['mutations', index, 'record'],
          message: 'Mutations must advance their expected revision exactly once',
        });
      }
    }
  });

export const syncAcceptedPushResultSchema = z
  .object({
    status: z.literal('accepted'),
    idempotencyKey: z.string().min(16).max(256),
    disposition: z.enum(['committed', 'duplicate']),
    change: changeRecordSchema,
  })
  .strict();

export const syncConflictingPushResultSchema = z
  .object({
    status: z.literal('conflict'),
    idempotencyKey: z.string().min(16).max(256),
    currentRevision: z.union([vaultRevisionSchema, recordRevisionSchema]),
    current: opaqueSyncRecordSchema.nullable(),
  })
  .strict();

export const syncPushResponseSchema = z
  .object({
    vaultId: vaultIdSchema,
    serverVaultRevision: vaultRevisionSchema,
    batchIdempotencyKey: z.string().min(16).max(256),
    results: z
      .array(
        z.discriminatedUnion('status', [
          syncAcceptedPushResultSchema,
          syncConflictingPushResultSchema,
        ]),
      )
      .min(1)
      .max(100),
  })
  .strict();

/**
 * One bounded, opaque group-template migration. Items are published in stable
 * ID order and the group metadata record is published last.
 */
export const templateMigrationPublicationRequestSchema =
  syncPushRequestSchema.superRefine((batch, context) => {
    const entityIds = new Set<string>();
    const itemIds: string[] = [];
    let groupMutation:
      | Extract<z.infer<typeof opaqueMutationSchema>, { entityType: 'group' }>
      | undefined;

    for (const [index, mutation] of batch.mutations.entries()) {
      if (mutation.entityType !== 'group' && mutation.entityType !== 'item') {
        context.addIssue({
          code: 'custom',
          path: ['mutations', index, 'entityType'],
          message: 'Template migration batches accept only group and item mutations',
        });
        continue;
      }
      if (
        mutation.expectedRecordRevision === null ||
        mutation.record.tombstonedAt !== undefined
      ) {
        context.addIssue({
          code: 'custom',
          path: ['mutations', index],
          message: 'Template migration mutations must update active current records',
        });
      }
      if (entityIds.has(mutation.record.id)) {
        context.addIssue({
          code: 'custom',
          path: ['mutations', index, 'record', 'id'],
          message: 'Template migration entity IDs must be unique',
        });
      }
      entityIds.add(mutation.record.id);
      if (mutation.entityType === 'group') {
        if (groupMutation !== undefined) {
          context.addIssue({
            code: 'custom',
            path: ['mutations', index],
            message: 'A template migration batch requires exactly one group mutation',
          });
        }
        groupMutation = mutation;
      } else {
        itemIds.push(mutation.record.id);
      }
    }

    if (groupMutation === undefined) {
      context.addIssue({
        code: 'custom',
        path: ['mutations'],
        message: 'A template migration batch requires one group mutation',
      });
      return;
    }
    if (batch.mutations.at(-1) !== groupMutation) {
      context.addIssue({
        code: 'custom',
        path: ['mutations'],
        message: 'The group mutation must be last',
      });
    }
    for (const [index, mutation] of batch.mutations.entries()) {
      if (
        mutation.entityType === 'item' &&
        mutation.record.groupId !== groupMutation.record.id
      ) {
        context.addIssue({
          code: 'custom',
          path: ['mutations', index, 'record', 'groupId'],
          message: 'Every item must belong to the migrated group',
        });
      }
    }
    const sortedItemIds = [...itemIds].sort();
    if (itemIds.some((itemId, index) => itemId !== sortedItemIds[index])) {
      context.addIssue({
        code: 'custom',
        path: ['mutations'],
        message: 'Item mutations must be ordered by item ID',
      });
    }
  });

export const templateMigrationPublicationResultSchema = z
  .object({
    idempotencyKey: z.string().min(16).max(256),
    change: changeRecordSchema,
  })
  .strict()
  .superRefine((result, context) => {
    if (
      (result.change.entityType !== 'group' && result.change.entityType !== 'item') ||
      result.change.operation !== 'upsert'
    ) {
      context.addIssue({
        code: 'custom',
        path: ['change'],
        message: 'Template migration results require group or item upserts',
      });
    }
  });

export const templateMigrationPublicationResponseSchema = z
  .object({
    vaultId: vaultIdSchema,
    batchIdempotencyKey: z.string().min(16).max(256),
    serverVaultRevision: vaultRevisionSchema,
    results: z.array(templateMigrationPublicationResultSchema).min(1).max(100),
  })
  .strict()
  .superRefine((response, context) => {
    const itemIds: string[] = [];
    let groupCount = 0;
    for (const [index, result] of response.results.entries()) {
      if (result.change.vaultId !== response.vaultId) {
        context.addIssue({
          code: 'custom',
          path: ['results', index, 'change', 'vaultId'],
          message: 'Every result must belong to the response vault',
        });
      }
      if (index > 0) {
        const previous = response.results[index - 1];
        if (
          previous !== undefined &&
          result.change.serverSequence !== previous.change.serverSequence + 1
        ) {
          context.addIssue({
            code: 'custom',
            path: ['results', index, 'change', 'serverSequence'],
            message: 'Result sequences must be contiguous',
          });
        }
      }
      if (result.change.entityType === 'group') groupCount += 1;
      if (result.change.entityType === 'item') itemIds.push(result.change.entityId);
    }
    if (groupCount !== 1 || response.results.at(-1)?.change.entityType !== 'group') {
      context.addIssue({
        code: 'custom',
        path: ['results'],
        message: 'Results require exactly one group upsert last',
      });
    }
    const sortedItemIds = [...itemIds].sort();
    if (itemIds.some((itemId, index) => itemId !== sortedItemIds[index])) {
      context.addIssue({
        code: 'custom',
        path: ['results'],
        message: 'Item results must be ordered by item ID',
      });
    }
  });

export const opaqueMutationRequestSchema = opaqueMutationSchema;

export type ApiScope = z.infer<typeof apiScopeSchema>;
export type HealthResponse = z.infer<typeof healthResponseSchema>;
export type ApiBearerToken = z.infer<typeof apiBearerTokenSchema>;
export type ControlListCursor = z.infer<typeof controlListCursorSchema>;
export type ControlListCursorPayload = z.infer<typeof controlListCursorPayloadSchema>;
export type ControlListPageQuery = z.infer<typeof controlListPageQuerySchema>;
export type InviteListPageResponse = z.infer<typeof inviteListPageResponseSchema>;
export type DeviceListPageResponse = z.infer<typeof deviceListPageResponseSchema>;
export type ApiSessionResponse = z.infer<typeof apiSessionResponseSchema>;
export type VaultBootstrapRequest = z.infer<typeof vaultBootstrapRequestSchema>;
export type VaultBootstrapResponse = z.infer<typeof vaultBootstrapResponseSchema>;
export type InviteIssueRequest = z.infer<typeof inviteIssueRequestSchema>;
export type InviteRedeemResponse = z.infer<typeof inviteRedeemResponseSchema>;
export type PublicInviteRecord = z.infer<typeof publicInviteRecordSchema>;
export type EnrollmentCompleteRequest = z.infer<typeof enrollmentCompleteRequestSchema>;
export type PublicDeviceRecord = z.infer<typeof publicDeviceRecordSchema>;
export type VaultKeySlotUpdateRequest = z.infer<typeof vaultKeySlotUpdateRequestSchema>;
export type SyncPullQuery = z.infer<typeof syncPullQuerySchema>;
export type OpaqueSyncRecord = z.infer<typeof opaqueSyncRecordSchema>;
export type SyncPulledChange = z.infer<typeof syncPulledChangeSchema>;
export type SyncPullResponse = z.infer<typeof syncPullResponseSchema>;
export type SyncPushRequest = z.infer<typeof syncPushRequestSchema>;
export type SyncPushResponse = z.infer<typeof syncPushResponseSchema>;
export type TemplateMigrationPublicationRequest = z.infer<
  typeof templateMigrationPublicationRequestSchema
>;
export type TemplateMigrationPublicationResult = z.infer<
  typeof templateMigrationPublicationResultSchema
>;
export type TemplateMigrationPublicationResponse = z.infer<
  typeof templateMigrationPublicationResponseSchema
>;
export type AttachmentTransferPath = z.infer<typeof attachmentTransferPathSchema>;
export type AttachmentChunkStageRequest = z.infer<
  typeof attachmentChunkStageRequestSchema
>;
export type AttachmentFinalizeRequest = z.infer<typeof attachmentFinalizeRequestSchema>;

// This proves response self-consistency only. A route must still bind its
// authenticated requested vault, including for an empty terminal page.
function validateControlListPage(
  resource: 'invites' | 'devices',
  rows: readonly Readonly<{ id: string; vaultId: string; createdAt: string }>[],
  nextCursor: z.infer<typeof controlListCursorSchema> | null,
  context: z.core.$RefinementCtx,
): void {
  const firstRow = rows[0];
  if (firstRow !== undefined && rows.some((row) => row.vaultId !== firstRow.vaultId)) {
    context.addIssue({
      code: 'custom',
      message: 'Every control-list page row must belong to one vault',
      path: [resource],
    });
  }
  if (nextCursor === null) return;

  const finalRow = rows.at(-1);
  if (finalRow === undefined) {
    context.addIssue({
      code: 'custom',
      message: 'An empty control-list page cannot carry a next cursor',
      path: ['nextCursor'],
    });
    return;
  }

  let cursorPayload: z.infer<typeof controlListCursorPayloadSchema>;
  try {
    cursorPayload = decodeControlListCursor(nextCursor);
  } catch {
    context.addIssue({
      code: 'custom',
      message: 'Control-list page carries an invalid next cursor',
      path: ['nextCursor'],
    });
    return;
  }
  if (
    cursorPayload.resource !== resource ||
    cursorPayload.vaultId !== finalRow.vaultId ||
    cursorPayload.createdAt !== finalRow.createdAt ||
    cursorPayload.id !== finalRow.id
  ) {
    context.addIssue({
      code: 'custom',
      message: 'Next cursor must identify the final control-list page row',
      path: ['nextCursor'],
    });
  }
}

function validateAttachmentTransportIdentity(
  start: z.infer<typeof attachmentStreamStartInputSchema>,
  record:
    | z.infer<typeof persistedAttachmentChunkRecordSchema>['record']
    | z.infer<typeof encryptedAttachmentRecordSchema>,
  recordRevision: number,
  context: z.core.$RefinementCtx,
  path: PropertyKey[],
): void {
  const header = start.header;
  const attachmentId = 'id' in record ? record.id : record.attachmentId;
  const keyVersion =
    'id' in record ? record.encryptedManifest.keyVersion : record.keyVersion;
  if (
    record.vaultId !== header.record.vaultId ||
    record.groupId !== header.record.groupId ||
    record.itemId !== header.record.itemId ||
    attachmentId !== header.record.attachmentId ||
    record.schemaVersion !== header.record.schemaVersion ||
    keyVersion !== header.record.keyVersion ||
    recordRevision !== header.recordRevision
  ) {
    context.addIssue({
      code: 'custom',
      path,
      message: 'Attachment transport records must share one exact stream identity',
    });
  }
}

function isTombstoneRecord(
  record: OpaqueSyncRecord,
): record is Extract<OpaqueSyncRecord, { state: 'deleted' | 'restored' }> {
  return 'state' in record;
}

function isCurrentOpaqueRecord(record: OpaqueSyncRecord): boolean {
  return (
    !isTombstoneRecord(record) &&
    (!('tombstonedAt' in record) || record.tombstonedAt === undefined)
  );
}

function syncRecordVaultId(record: OpaqueSyncRecord): z.infer<typeof vaultIdSchema> {
  return 'vaultId' in record ? record.vaultId : record.id;
}

function syncRecordId(record: OpaqueSyncRecord): string {
  return isTombstoneRecord(record) ? record.entityId : record.id;
}

function syncRecordEntityType(
  record: OpaqueSyncRecord,
): z.infer<typeof changeRecordSchema>['entityType'] {
  if (isTombstoneRecord(record)) return record.entityType;
  if ('revision' in record) return 'vault';
  if ('itemId' in record) return 'attachment';
  if ('groupId' in record) return 'item';
  return 'group';
}

function syncRecordRevision(record: OpaqueSyncRecord): number {
  if (isTombstoneRecord(record)) return record.tombstoneRevision;
  return 'revision' in record ? record.revision : record.recordRevision;
}

function syncMutationVaultId(
  mutation: z.infer<typeof opaqueMutationSchema>,
): z.infer<typeof vaultIdSchema> {
  return mutation.entityType === 'vault' ? mutation.record.id : mutation.record.vaultId;
}
