import {
  credentialCopyReceiptSchema,
  credentialShowProjectionSchema,
  lifecycleOperationIdSchema,
  type CredentialCopyOptions,
  type CredentialCopyReceipt,
  type CredentialShowProjection,
} from '@kavrix/client';
import {
  apiBearerTokenSchema,
  inviteListPageResponseSchema,
  deviceIdSchema,
  inviteIdSchema,
  keySlotIdSchema,
  keyVersionSchema,
  MAX_VAULT_KEY_SLOTS,
  portableKeyRotationStateSchema,
  schemaVersionSchema,
  timestampSchema,
  vaultIdSchema,
  type ControlListPageOptions,
  type GroupPayload,
  type InviteId,
  type InviteListPageResponse,
  type ItemPayload,
  type VaultId,
} from '@kavrix/schemas';
import { z } from 'zod';

import type {
  CliAddFieldRequest,
  CliAddNoteRequest,
  CliArchiveEntityRequest,
  CliArchiveFieldRequest,
  CliArchiveNoteRequest,
  CliCreateCredentialRequest,
  CliCreateGroupRequest,
  CliCredentialMutationResult,
  CliGroupMutationResult,
  CliNoteMutationResult,
  CliRemoveFieldRequest,
  CliRemoveNoteRequest,
  CliRestoreEntityRequest,
  CliRestoreFieldRequest,
  CliRestoreNoteRequest,
  CliSetFieldRequest,
  CliUpdateFieldRequest,
  CliUpdateNoteRequest,
} from './mutation-contracts.js';

export const cliStatusSchema = z
  .object({
    vaultState: z.enum(['locked', 'unlocked']),
    vaultId: vaultIdSchema.optional(),
    deviceId: deviceIdSchema.optional(),
    syncState: z.enum(['offline', 'idle', 'syncing', 'error']),
    pendingChanges: z.number().int().nonnegative(),
    lastSyncAt: z.iso.datetime({ offset: true }).optional(),
  })
  .strict()
  .superRefine((status, context) => {
    if (status.vaultState === 'unlocked' && status.vaultId === undefined) {
      context.addIssue({
        code: 'custom',
        path: ['vaultId'],
        message: 'Unlocked status requires a vault ID',
      });
    }
  });

const cliConflictIdSchema = z.string().min(16).max(256);
const cliConflictSchema = z
  .object({
    vaultId: vaultIdSchema,
    entityType: z.enum(['vault', 'group', 'item']),
    entityId: z.string().trim().min(1).max(512),
    idempotencyKey: cliConflictIdSchema,
    expectedRevision: z.number().int().nonnegative().nullable(),
    currentRevision: z.number().int().nonnegative(),
    currentState: z.enum(['present', 'deleted', 'missing']),
  })
  .strict();
const cliConflictResolutionStrategySchema = z.enum(['keep-local', 'accept-remote']);
const cliConflictResolutionRequestSchema = z
  .object({
    conflictId: cliConflictIdSchema,
    currentRevision: z.number().int().nonnegative(),
    strategy: cliConflictResolutionStrategySchema,
  })
  .strict();
const cliConflictResolutionResultSchema = z
  .object({
    status: z.enum(['accepted-remote', 'queued-local']),
    conflictId: cliConflictIdSchema,
    strategy: cliConflictResolutionStrategySchema,
    replacementIdempotencyKey: cliConflictIdSchema.nullable(),
  })
  .strict();

export const cliConnectRequestSchema = z
  .object({
    serverUrl: z.string().min(1).max(2_048),
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
  })
  .strict();

export const cliConnectResultSchema = z
  .object({
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
  })
  .strict();

export const cliRecoverRequestSchema = z
  .object({
    serverUrl: z.string().min(1).max(2_048),
    vaultId: vaultIdSchema,
  })
  .strict();

export const cliRecoverResultSchema = z
  .object({
    operationId: lifecycleOperationIdSchema,
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
  })
  .strict();

const cliKeySlotTypeSchema = z.enum([
  'portable-key',
  'passphrase',
  'recovery-key',
  'device-key',
]);
const cliKeySlotStateSchema = z.enum(['pending', 'active', 'superseded', 'revoked']);

/** Public slot metadata; derivation and wrapped-root fields are intentionally absent. */
export const cliKeySlotSchema = z
  .object({
    id: keySlotIdSchema,
    type: cliKeySlotTypeSchema,
    state: cliKeySlotStateSchema,
    keyVersion: keyVersionSchema,
    createdAt: timestampSchema,
    revokedAt: timestampSchema.optional(),
    deviceId: deviceIdSchema.optional(),
  })
  .strict()
  .superRefine((slot, context) => {
    if (slot.type === 'device-key' && slot.deviceId === undefined) {
      context.addIssue({
        code: 'custom',
        path: ['deviceId'],
        message: 'Device slots require a device ID.',
      });
    }
    if (slot.type !== 'device-key' && slot.deviceId !== undefined) {
      context.addIssue({
        code: 'custom',
        path: ['deviceId'],
        message: 'Only device slots may expose a device ID.',
      });
    }
  });

export const cliKeySlotListSchema = z.array(cliKeySlotSchema).max(MAX_VAULT_KEY_SLOTS);
export const cliKeySlotResultSchema = z
  .object({
    action: z.enum(['created', 'disabled', 'revoked']),
    slot: cliKeySlotSchema,
  })
  .strict();

export const cliPortableKeyRotationListingSchema = z
  .object({
    operationId: lifecycleOperationIdSchema,
    state: portableKeyRotationStateSchema,
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
    sourceSlotId: keySlotIdSchema,
    replacementSlotId: keySlotIdSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const cliPortableKeyRotationResultSchema = z.discriminatedUnion('action', [
  z
    .object({
      action: z.enum(['rotated', 'resumed']),
      operationId: lifecycleOperationIdSchema,
      sourceSlotId: keySlotIdSchema,
      replacementSlotId: keySlotIdSchema,
      state: z.literal('completed'),
    })
    .strict(),
  z
    .object({
      action: z.literal('listed'),
      operations: z.array(cliPortableKeyRotationListingSchema).max(256),
    })
    .strict(),
]);

/**
 * The invite redemption request.
 *
 * The vault is named by the invite issuer, not chosen locally, and the device
 * ID is generated by the join coordinator so two devices can never collide on a
 * caller-supplied value. The portable key that unlocks the redeemed vault is
 * passed separately and never enters this validated object.
 */
export const cliInviteJoinRequestSchema = z
  .object({
    inviteToken: apiBearerTokenSchema,
    vaultId: vaultIdSchema,
    schemaVersion: schemaVersionSchema,
  })
  .strict();

export const cliInviteJoinResultSchema = z
  .object({
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
  })
  .strict();

export type CliStatus = z.infer<typeof cliStatusSchema>;
export type CliConflict = z.infer<typeof cliConflictSchema>;
export type CliConflictResolutionRequest = z.infer<
  typeof cliConflictResolutionRequestSchema
>;
export type CliConflictResolutionResult = z.infer<
  typeof cliConflictResolutionResultSchema
>;
export type CliConnectRequest = z.infer<typeof cliConnectRequestSchema>;
export type CliConnectResult = z.infer<typeof cliConnectResultSchema>;
export type CliRecoverRequest = z.infer<typeof cliRecoverRequestSchema>;
export type CliRecoverResult = z.infer<typeof cliRecoverResultSchema>;
export type CliKeySlot = z.infer<typeof cliKeySlotSchema>;
export type CliKeySlotResult = z.infer<typeof cliKeySlotResultSchema>;
export type CliPortableKeyRotationListing = z.infer<
  typeof cliPortableKeyRotationListingSchema
>;
export type CliPortableKeyRotationResult = z.infer<
  typeof cliPortableKeyRotationResultSchema
>;
export type CliShowResult = CredentialShowProjection;
export type CliInviteJoinRequest = z.infer<typeof cliInviteJoinRequestSchema>;
export type CliInviteJoinResult = z.infer<typeof cliInviteJoinResultSchema>;

export interface CliUseCasePorts {
  status(): Promise<CliStatus>;
  lock(): Promise<void>;
  show(groupQuery: string, credentialQuery: string): Promise<CliShowResult>;
  copy(
    groupQuery: string,
    credentialQuery: string,
    fieldQuery: string,
    options?: CredentialCopyOptions,
  ): Promise<CredentialCopyReceipt>;
  listInvitePage(
    vaultId: VaultId,
    options: ControlListPageOptions,
  ): Promise<InviteListPageResponse>;
  revokeInvite(vaultId: VaultId, inviteId: InviteId): Promise<void>;
  /**
   * Completes the two-step enrollment protocol. The adapter owns durable,
   * idempotent generation and reuse of independent enrollment/session successor
   * tokens; it must persist the resulting session token and never return it to
   * the renderer.
   */
  joinInvite(
    request: CliInviteJoinRequest,
    portableKey: string,
    serverUrl?: string,
  ): Promise<CliInviteJoinResult>;
  createGroup?(request: CliCreateGroupRequest): Promise<CliGroupMutationResult>;
  listGroups?(): Promise<readonly GroupPayload[]>;
  renameGroup?(query: string, newName: string): Promise<void>;
  archiveEntity?(request: CliArchiveEntityRequest): Promise<void>;
  restoreEntity?(request: CliRestoreEntityRequest): Promise<void>;
  deleteGroup?(query: string): Promise<void>;
  createCredential?(
    request: CliCreateCredentialRequest,
  ): Promise<CliCredentialMutationResult>;
  listCredentials?(groupQuery: string): Promise<readonly ItemPayload[]>;
  renameCredential?(groupQuery: string, query: string, newTitle: string): Promise<void>;
  deleteCredential?(groupQuery: string, query: string): Promise<void>;
  addField?(request: CliAddFieldRequest): Promise<CliCredentialMutationResult>;
  setField?(request: CliSetFieldRequest): Promise<CliCredentialMutationResult>;
  updateField?(request: CliUpdateFieldRequest): Promise<CliCredentialMutationResult>;
  archiveField?(request: CliArchiveFieldRequest): Promise<void>;
  restoreField?(request: CliRestoreFieldRequest): Promise<void>;
  removeField?(request: CliRemoveFieldRequest): Promise<void>;
  addNote?(request: CliAddNoteRequest): Promise<CliNoteMutationResult>;
  updateNote?(request: CliUpdateNoteRequest): Promise<CliNoteMutationResult>;
  archiveNote?(request: CliArchiveNoteRequest): Promise<void>;
  restoreNote?(request: CliRestoreNoteRequest): Promise<void>;
  removeNote?(request: CliRemoveNoteRequest): Promise<void>;
  reveal?(
    groupQuery: string,
    credentialQuery: string,
    fieldQuery: string,
    options?: { index?: number },
  ): Promise<{ value: string }>;
  get?(
    groupQuery: string,
    credentialQuery: string,
    fieldQuery: string,
    options?: { index?: number; reveal?: boolean },
  ): Promise<{
    groupName: string;
    credentialTitle: string;
    fieldLabel: string;
    fieldKey: string;
    fieldType: string;
    sensitive: boolean;
    value: string;
  }>;
  sync?(): Promise<CliStatus>;
  listConflicts?(): Promise<readonly CliConflict[]>;
  resolveConflict?(
    request: CliConflictResolutionRequest,
  ): Promise<CliConflictResolutionResult>;
  connect?(request: CliConnectRequest): Promise<CliConnectResult>;
  recover?(
    request: CliRecoverRequest,
    inviteToken: string,
    portableKey: string,
  ): Promise<CliRecoverResult>;
  listKeySlots?(): Promise<readonly CliKeySlot[]>;
  createKeySlot?(request: unknown): Promise<CliKeySlotResult>;
  disableKeySlot?(slotId: string): Promise<CliKeySlotResult>;
  revokeKeySlot?(slotId: string, request: unknown): Promise<CliKeySlotResult>;
}

export function parseStatus(value: unknown): CliStatus {
  return cliStatusSchema.parse(value);
}

export function parseConflicts(value: unknown): readonly CliConflict[] {
  return z.array(cliConflictSchema).max(100_000).parse(value);
}

export function parseConflictResolutionRequest(
  value: unknown,
): CliConflictResolutionRequest {
  return cliConflictResolutionRequestSchema.parse(value);
}

export function parseConflictResolutionResult(
  value: unknown,
): CliConflictResolutionResult {
  return cliConflictResolutionResultSchema.parse(value);
}

export function parseConnectRequest(value: unknown): CliConnectRequest {
  return cliConnectRequestSchema.parse(value);
}

export function parseConnectResult(value: unknown): CliConnectResult {
  return cliConnectResultSchema.parse(value);
}

export function parseRecoverRequest(value: unknown): CliRecoverRequest {
  return cliRecoverRequestSchema.parse(value);
}

export function parseRecoverResult(value: unknown): CliRecoverResult {
  return cliRecoverResultSchema.parse(value);
}

export function parseShowResult(value: unknown): CliShowResult {
  return credentialShowProjectionSchema.parse(value);
}

export function parseCopyReceipt(value: unknown): CredentialCopyReceipt {
  return credentialCopyReceiptSchema.parse(value);
}

export function parseInvitePage(value: unknown): InviteListPageResponse {
  return inviteListPageResponseSchema.parse(value);
}

export function parseJoinResult(value: unknown): CliInviteJoinResult {
  return cliInviteJoinResultSchema.parse(value);
}

export function parseVaultId(value: string): VaultId {
  return vaultIdSchema.parse(value);
}

export function parseInviteId(value: string): InviteId {
  return inviteIdSchema.parse(value);
}

export function shapeInviteJoinRequest(
  inviteToken: string,
  vaultId: string,
  schemaVersion: number,
): CliInviteJoinRequest {
  return cliInviteJoinRequestSchema.parse({
    inviteToken,
    vaultId: vaultIdSchema.parse(vaultId),
    schemaVersion: schemaVersionSchema.parse(schemaVersion),
  });
}
