import {
  credentialCopyReceiptSchema,
  credentialShowProjectionSchema,
  lifecycleOperationIdSchema,
  type CredentialCopyOptions,
  type CredentialCopyReceipt,
  type CredentialShowProjection,
} from '@kavrix/client/cli-contracts';
import type { TotpConfiguration } from '@kavrix/core';
import {
  apiBearerTokenSchema,
  deviceListPageResponseSchema,
  inviteListPageResponseSchema,
  deviceIdSchema,
  inviteIdSchema,
  keySlotIdSchema,
  keyVersionSchema,
  MAX_VAULT_KEY_SLOTS,
  portableKeyRotationStateSchema,
  sha256DigestSchema,
  schemaVersionSchema,
  timestampSchema,
  transferCollisionStrategySchema,
  vaultIdSchema,
  type ControlListPageOptions,
  type DeviceId,
  type DeviceListPageResponse,
  type GroupId,
  type GroupPayload,
  type GroupTemplate,
  type InviteIssueRequest,
  type InviteIssueResponse,
  type InviteId,
  type InviteListPageResponse,
  type ItemPayload,
  type LocalAuditEvent,
  type TemplateId,
  type TemplateMigrationId,
  type TemplateMigrationPlan,
  type VaultId,
} from '@kavrix/schemas';
import { z } from 'zod';

import type {
  CliAddFieldRequest,
  CliAddNoteRequest,
  CliApplyTemplateMigrationRequest,
  CliArchiveEntityRequest,
  CliArchiveFieldRequest,
  CliArchiveNoteRequest,
  CliCreateCredentialRequest,
  CliCreateGroupRequest,
  CliCreateTemplateRequest,
  CliCredentialMutationResult,
  CliDeleteAttachmentRequest,
  CliDiffHistoryRequest,
  CliDownloadAttachmentRequest,
  CliFieldMutationResult,
  CliFieldReadResult,
  CliGroupMutationResult,
  CliListAuditEventsRequest,
  CliListRecoveryCodesRequest,
  CliNoteMutationResult,
  CliPlanTemplateMigrationRequest,
  CliRemoveFieldRequest,
  CliRemoveNoteRequest,
  CliRestoreEntityRequest,
  CliRestoreFieldRequest,
  CliRestoreHistoryRequest,
  CliRestoreNoteRequest,
  CliRevealRecoveryCodeRequest,
  CliRunRequest,
  CliSetFieldRequest,
  CliShowAuditEventRequest,
  CliShowHistoryRequest,
  CliUpdateFieldRequest,
  CliUpdateNoteRequest,
  CliUpdateTemplateRequest,
  CliUploadAttachmentRequest,
  CliUseRecoveryCodeRequest,
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
/**
 * A guarded transfer is a curated hand-off rather than a whole-vault archive,
 * so the CLI caps it well below the format's own ceiling.
 */
export const MAX_CLI_TRANSFER_DOCUMENTS = 20_000;
const cliBackupPathSchema = z
  .string()
  .min(1)
  .max(32_768)
  .refine(
    (value) =>
      !Array.from(value).some((character) => {
        const codePoint = character.codePointAt(0);
        return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
      }),
    { error: 'The backup path contains a control character.' },
  );
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

export const cliBackupCreateRequestSchema = z
  .object({
    destination: cliBackupPathSchema,
    vaultId: vaultIdSchema.optional(),
  })
  .strict();

export const cliBackupVerifyRequestSchema = z
  .object({
    source: cliBackupPathSchema,
    vaultId: vaultIdSchema.optional(),
  })
  .strict();

export const cliBackupRestoreRequestSchema = z
  .object({
    source: cliBackupPathSchema,
    vaultId: vaultIdSchema.optional(),
    slotId: keySlotIdSchema.optional(),
  })
  .strict();

/**
 * A guarded transfer names an optional single group so an operator can hand off
 * one group without exporting the whole vault. Omitting it exports every active
 * group, which is still a policy-filtered projection rather than an archive.
 */
export const cliTransferExportRequestSchema = z
  .object({
    destination: cliBackupPathSchema,
    groupQuery: z.string().min(1).max(512).optional(),
    vaultId: vaultIdSchema.optional(),
  })
  .strict();

export const cliTransferImportRequestSchema = z
  .object({
    source: cliBackupPathSchema,
    onCollision: transferCollisionStrategySchema,
    vaultId: vaultIdSchema.optional(),
  })
  .strict();

export const cliTransferExportResultSchema = z
  .object({
    action: z.literal('exported'),
    vaultId: vaultIdSchema,
    groupCount: z.number().int().nonnegative().max(MAX_CLI_TRANSFER_DOCUMENTS),
    itemCount: z.number().int().nonnegative().max(MAX_CLI_TRANSFER_DOCUMENTS),
    withheldValues: z.number().int().nonnegative().max(10_000_000),
    bytes: z
      .number()
      .int()
      .positive()
      .max(128 * 1024 * 1024),
  })
  .strict();

export const cliTransferImportResultSchema = z
  .object({
    action: z.literal('imported'),
    vaultId: vaultIdSchema,
    createdAt: timestampSchema,
    groupsCreated: z.number().int().nonnegative().max(MAX_CLI_TRANSFER_DOCUMENTS),
    groupsSkipped: z.number().int().nonnegative().max(MAX_CLI_TRANSFER_DOCUMENTS),
    itemsCreated: z.number().int().nonnegative().max(MAX_CLI_TRANSFER_DOCUMENTS),
    /** Values the writer declared it could not carry, summed across items. */
    withheldValues: z.number().int().nonnegative().max(10_000_000),
    /**
     * Item-to-item references dropped because the reader minted new identities.
     * Reported rather than silently discarded.
     */
    referencesDropped: z.number().int().nonnegative().max(10_000_000),
  })
  .strict();

export const cliBackupCreateResultSchema = z
  .object({
    action: z.literal('created'),
    vaultId: vaultIdSchema,
    recordCount: z.number().int().positive().max(10_000),
    bytes: z
      .number()
      .int()
      .positive()
      .max(128 * 1024 * 1024),
  })
  .strict();

export const cliBackupVerifyResultSchema = z
  .object({
    action: z.literal('verified'),
    vaultId: vaultIdSchema,
    recordCount: z.number().int().positive().max(10_000),
    bytes: z
      .number()
      .int()
      .positive()
      .max(128 * 1024 * 1024),
    schemaVersion: schemaVersionSchema,
    createdAt: timestampSchema,
    restoreSessionId: sha256DigestSchema,
  })
  .strict();

export const cliBackupRestoreResultSchema = z
  .object({
    action: z.enum(['restored', 'already-committed']),
    vaultId: vaultIdSchema,
    recordCount: z.number().int().positive().max(10_000),
    bytes: z
      .number()
      .int()
      .positive()
      .max(128 * 1024 * 1024),
    restoreSessionId: sha256DigestSchema,
    selectedSlotId: keySlotIdSchema.optional(),
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

export interface CliTemplateSummary {
  readonly id: string;
  readonly name: string;
  readonly description?: string | undefined;
  readonly builtInKey?: string | undefined;
  readonly version: number;
  readonly fieldCount: number;
  readonly groupName?: string | undefined;
  readonly groupId?: string | undefined;
}

export interface CliTemplateMigrationStatusResult {
  readonly groupId: GroupId;
  readonly groupName: string;
  readonly templateId: TemplateId;
  readonly templateName: string;
  readonly currentVersion: number;
  readonly itemCount: number;
  readonly fieldCount: number;
  readonly pendingMigrations?: readonly string[] | undefined;
}

export interface CliTemplateMigrationApplyResult {
  readonly migrationId: TemplateMigrationId;
  readonly groupId: GroupId;
  readonly fromVersion: number;
  readonly toVersion: number;
  readonly totalItems: number;
  readonly affectedSteps: number;
}

export interface CliAttachmentSummary {
  readonly id: string;
  readonly groupId: string;
  readonly itemId: string;
  readonly chunkCount: number;
  readonly totalPlaintextBytes?: number | undefined;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly tombstonedAt?: string | undefined;
}

export interface CliAttachmentUploadResult {
  readonly attachmentId: string;
  readonly groupId: string;
  readonly itemId: string;
  readonly chunkCount: number;
  readonly totalPlaintextBytes: number;
  readonly plaintextSha256: string;
}

export interface CliAttachmentDownloadResult {
  readonly attachmentId: string;
  readonly destinationPath: string;
  readonly totalPlaintextBytes: number;
  readonly plaintextSha256: string;
}

export interface CliAttachmentDeleteResult {
  readonly attachmentId: string;
  readonly groupId: string;
  readonly itemId: string;
  readonly deleted: boolean;
}

export interface CliHistorySummary {
  readonly revision: number;
  readonly historyId: string;
  readonly groupId: string;
  readonly itemId: string;
  readonly schemaVersion: number;
  readonly createdAt: string;
  readonly fieldCount: number;
}

export interface CliHistoryDetail {
  readonly revision: number;
  readonly historyId: string;
  readonly groupId: string;
  readonly itemId: string;
  readonly title: string;
  readonly createdAt: string;
  readonly fields: readonly {
    readonly stableKey: string;
    readonly label: string;
    readonly type: string;
    readonly maskedValue: string;
  }[];
  readonly notes: readonly {
    readonly id: string;
    readonly title: string;
    readonly body: string;
  }[];
}

export interface CliHistoryDiff {
  readonly groupId: string;
  readonly itemId: string;
  readonly baseRevision: number;
  readonly targetRevision: number;
  readonly addedFields: readonly {
    readonly stableKey: string;
    readonly label: string;
    readonly type: string;
  }[];
  readonly removedFields: readonly {
    readonly stableKey: string;
    readonly label: string;
    readonly type: string;
  }[];
  readonly modifiedFields: readonly {
    readonly stableKey: string;
    readonly label: string;
    readonly type: string;
  }[];
  readonly unchangedFieldCount: number;
  readonly notesChanged: boolean;
}

export interface CliHistoryRestoreResult {
  readonly groupId: string;
  readonly itemId: string;
  readonly restoredFromRevision: number;
  readonly newRevision: number;
  readonly updatedAt: string;
}

/**
 * One recovery code as it may be shown. The code value is deliberately absent
 * rather than truncated: a partial code is still code material, and the stable
 * element identifier is what a caller needs in order to act on one entry.
 */
export interface CliRecoveryCodeEntry {
  readonly id: string;
  readonly status: 'available' | 'used';
  readonly usedAt: string | null;
}

export interface CliRecoveryCodeInventory {
  readonly total: number;
  readonly available: number;
  readonly used: number;
}

export interface CliRecoveryCodeListResult {
  readonly groupName: string;
  readonly credentialTitle: string;
  readonly fieldLabel: string;
  readonly inventory: CliRecoveryCodeInventory;
  readonly codes: readonly CliRecoveryCodeEntry[];
}

/**
 * Receipt for one consumed code. Names the element that moved to `used` and the
 * revisions on either side of the durable write, and never carries the code.
 */
export interface CliRecoveryCodeUseResult {
  readonly groupId: string;
  readonly credentialId: string;
  readonly fieldLabel: string;
  readonly codeId: string;
  readonly usedAt: string;
  readonly previousRevision: number;
  readonly revision: number;
  readonly inventory: CliRecoveryCodeInventory;
}

/**
 * One authorized reveal. `receipt` is present only when the reveal also
 * consumed the code, which happens before the value is returned.
 */
export interface CliRecoveryCodeRevealResult {
  readonly codeId: string;
  readonly value: string;
  readonly receipt: CliRecoveryCodeUseResult | null;
}

/**
 * A resolved stored-seed TOTP request.
 *
 * The queries name what to read; the configuration is the caller's bounded
 * policy, already validated. `unixTimeSeconds` is resolved before the request is
 * built so the generated code and the reported expiry describe the same step
 * rather than two clock reads either side of a vault unlock.
 */
export interface CliStoredTotpRequest {
  readonly groupQuery: string;
  readonly credentialQuery: string;
  readonly fieldQuery: string | undefined;
  readonly configuration: TotpConfiguration;
  readonly unixTimeSeconds: number;
}

/**
 * One generated code and the receipt that explains it.
 *
 * The seed is deliberately absent, and there is no field on this result from
 * which it could be recovered: the code is a one-way function of the seed and the
 * time step. `remainingSeconds` is how long this code stays valid, which is what
 * makes an operator's decision to reuse or regenerate an informed one.
 */
export interface CliStoredTotpResult {
  readonly groupName: string;
  readonly credentialTitle: string;
  readonly fieldLabel: string;
  readonly fieldKey: string;
  readonly code: string;
  readonly remainingSeconds: number;
  readonly algorithm: string;
  readonly digits: number;
  readonly periodSeconds: number;
}

/** One projected audit event. Carries opaque metadata only. */
export type CliAuditEventSummary = LocalAuditEvent;

/**
 * One bounded audit page. `nextCursor` is the last returned event identifier
 * when more events remain, and `null` when the projection is exhausted.
 */
export interface CliAuditEventPage {
  readonly events: readonly CliAuditEventSummary[];
  readonly nextCursor: string | null;
  readonly totalCount: number;
}

export interface CliAuditEventDetail {
  readonly vaultId: VaultId;
  readonly event: CliAuditEventSummary;
}

/**
 * One planned guarded execution. Carries destination names and addresses only:
 * a plan is printed before any field is resolved, so it can never hold a value.
 */
export interface CliRunPlan {
  readonly executable: string;
  readonly argumentCount: number;
  readonly environmentNames: readonly string[];
  readonly inherited: readonly string[];
  readonly cwd: string;
  readonly timeoutMs: number | null;
  readonly maxOutputBytes: number;
}

/**
 * One completed guarded execution. `stdout`/`stderr` are already bounded and
 * secret-redacted by the runner; `secretNames` reports which destinations were
 * classified as secret so the caller can state what was protected.
 */
export interface CliRunResult {
  readonly executable: string;
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly termination: 'exit' | 'signal' | 'timeout' | 'aborted' | 'output-limit';
  readonly outputTruncated: boolean;
  readonly environmentNames: readonly string[];
  readonly secretNames: readonly string[];
  readonly stdout: string;
  readonly stderr: string;
}

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
export type CliBackupCreateRequest = z.infer<typeof cliBackupCreateRequestSchema>;
export type CliBackupCreateResult = z.infer<typeof cliBackupCreateResultSchema>;
export type CliBackupVerifyRequest = z.infer<typeof cliBackupVerifyRequestSchema>;
export type CliBackupVerifyResult = z.infer<typeof cliBackupVerifyResultSchema>;
export type CliBackupRestoreRequest = z.infer<typeof cliBackupRestoreRequestSchema>;
export type CliBackupRestoreResult = z.infer<typeof cliBackupRestoreResultSchema>;
export type CliTransferExportRequest = z.infer<typeof cliTransferExportRequestSchema>;
export type CliTransferExportResult = z.infer<typeof cliTransferExportResultSchema>;
export type CliTransferImportRequest = z.infer<typeof cliTransferImportRequestSchema>;
export type CliTransferImportResult = z.infer<typeof cliTransferImportResultSchema>;
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
export type CliInviteIssueRequest = InviteIssueRequest;
export type CliInviteIssueResult = InviteIssueResponse;
export type CliDeviceListPage = DeviceListPageResponse;

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
  listDevicePage?(
    vaultId: VaultId,
    options: ControlListPageOptions,
  ): Promise<CliDeviceListPage>;
  issueInvite?(
    vaultId: VaultId,
    request: CliInviteIssueRequest,
  ): Promise<CliInviteIssueResult>;
  revokeInvite(vaultId: VaultId, inviteId: InviteId): Promise<void>;
  revokeDevice?(vaultId: VaultId, deviceId: DeviceId): Promise<void>;
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
  listTemplates?(): Promise<readonly CliTemplateSummary[]>;
  inspectTemplate?(query: string): Promise<GroupTemplate>;
  createTemplate?(request: CliCreateTemplateRequest): Promise<CliGroupMutationResult>;
  updateTemplate?(request: CliUpdateTemplateRequest): Promise<void>;
  archiveTemplate?(request: CliArchiveEntityRequest): Promise<void>;
  restoreTemplate?(request: CliRestoreEntityRequest): Promise<void>;
  deleteTemplate?(query: string): Promise<void>;
  planTemplateMigration?(
    request: CliPlanTemplateMigrationRequest,
  ): Promise<TemplateMigrationPlan>;
  applyTemplateMigration?(
    request: CliApplyTemplateMigrationRequest,
  ): Promise<CliTemplateMigrationApplyResult>;
  getTemplateMigrationStatus?(
    groupQuery: string,
  ): Promise<CliTemplateMigrationStatusResult>;
  createCredential?(
    request: CliCreateCredentialRequest,
  ): Promise<CliCredentialMutationResult>;
  listCredentials?(groupQuery: string): Promise<readonly ItemPayload[]>;
  renameCredential?(groupQuery: string, query: string, newTitle: string): Promise<void>;
  deleteCredential?(groupQuery: string, query: string): Promise<void>;
  addField?(request: CliAddFieldRequest): Promise<CliCredentialMutationResult>;
  setField?(request: CliSetFieldRequest): Promise<CliFieldMutationResult>;
  updateField?(request: CliUpdateFieldRequest): Promise<CliFieldMutationResult>;
  archiveField?(request: CliArchiveFieldRequest): Promise<void>;
  restoreField?(request: CliRestoreFieldRequest): Promise<void>;
  removeField?(request: CliRemoveFieldRequest): Promise<void>;
  addNote?(request: CliAddNoteRequest): Promise<CliNoteMutationResult>;
  updateNote?(request: CliUpdateNoteRequest): Promise<CliNoteMutationResult>;
  archiveNote?(request: CliArchiveNoteRequest): Promise<void>;
  restoreNote?(request: CliRestoreNoteRequest): Promise<void>;
  removeNote?(request: CliRemoveNoteRequest): Promise<void>;
  listAttachments?(
    groupQuery: string,
    credentialQuery: string,
  ): Promise<readonly CliAttachmentSummary[]>;
  uploadAttachment?(
    request: CliUploadAttachmentRequest,
  ): Promise<CliAttachmentUploadResult>;
  downloadAttachment?(
    request: CliDownloadAttachmentRequest,
  ): Promise<CliAttachmentDownloadResult>;
  deleteAttachment?(
    request: CliDeleteAttachmentRequest,
  ): Promise<CliAttachmentDeleteResult>;
  listHistory?(
    groupQuery: string,
    credentialQuery: string,
  ): Promise<readonly CliHistorySummary[]>;
  showHistory?(request: CliShowHistoryRequest): Promise<CliHistoryDetail>;
  diffHistory?(request: CliDiffHistoryRequest): Promise<CliHistoryDiff>;
  restoreHistory?(request: CliRestoreHistoryRequest): Promise<CliHistoryRestoreResult>;
  listAuditEvents?(request: CliListAuditEventsRequest): Promise<CliAuditEventPage>;
  showAuditEvent?(request: CliShowAuditEventRequest): Promise<CliAuditEventDetail>;
  listRecoveryCodes?(
    request: CliListRecoveryCodesRequest,
  ): Promise<CliRecoveryCodeListResult>;
  useRecoveryCode?(
    request: CliUseRecoveryCodeRequest,
  ): Promise<CliRecoveryCodeUseResult>;
  revealRecoveryCode?(
    request: CliRevealRecoveryCodeRequest,
  ): Promise<CliRecoveryCodeRevealResult>;
  storedTotp?(request: CliStoredTotpRequest): Promise<CliStoredTotpResult>;
  run?(request: CliRunRequest): Promise<CliRunResult>;
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
  ): Promise<CliFieldReadResult>;
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
  createBackup?(request: CliBackupCreateRequest): Promise<CliBackupCreateResult>;
  verifyBackup?(request: CliBackupVerifyRequest): Promise<CliBackupVerifyResult>;
  restoreBackup?(request: CliBackupRestoreRequest): Promise<CliBackupRestoreResult>;
  exportTransfer?(request: CliTransferExportRequest): Promise<CliTransferExportResult>;
  importTransfer?(request: CliTransferImportRequest): Promise<CliTransferImportResult>;
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

export function parseBackupCreateRequest(value: unknown): CliBackupCreateRequest {
  return cliBackupCreateRequestSchema.parse(value);
}

export function parseBackupCreateResult(value: unknown): CliBackupCreateResult {
  return cliBackupCreateResultSchema.parse(value);
}

export function parseBackupVerifyRequest(value: unknown): CliBackupVerifyRequest {
  return cliBackupVerifyRequestSchema.parse(value);
}

export function parseBackupVerifyResult(value: unknown): CliBackupVerifyResult {
  return cliBackupVerifyResultSchema.parse(value);
}

export function parseBackupRestoreRequest(value: unknown): CliBackupRestoreRequest {
  return cliBackupRestoreRequestSchema.parse(value);
}

export function parseBackupRestoreResult(value: unknown): CliBackupRestoreResult {
  return cliBackupRestoreResultSchema.parse(value);
}

export function parseTransferExportRequest(value: unknown): CliTransferExportRequest {
  return cliTransferExportRequestSchema.parse(value);
}

export function parseTransferExportResult(value: unknown): CliTransferExportResult {
  return cliTransferExportResultSchema.parse(value);
}

export function parseTransferImportRequest(value: unknown): CliTransferImportRequest {
  return cliTransferImportRequestSchema.parse(value);
}

export function parseTransferImportResult(value: unknown): CliTransferImportResult {
  return cliTransferImportResultSchema.parse(value);
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

export function parseDevicePage(value: unknown): CliDeviceListPage {
  return deviceListPageResponseSchema.parse(value);
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
