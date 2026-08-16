import { MAX_ROTATED_ITEM_KEYS } from '@kavrix/client';
import {
  MAX_REFERENCE_TRAVERSAL_DEPTH,
  MAX_VAULT_SEARCH_RESULTS,
  MAX_VAULT_SEARCH_TERM_LENGTH,
} from '@kavrix/core';
import {
  ENVIRONMENT_NAME_PATTERN,
  INHERITABLE_ENVIRONMENT_NAMES,
  RUNNER_LIMITS,
  isReservedEnvironmentName,
  type InheritableEnvironmentName,
} from '@kavrix/runner';
import {
  auditEventClassSchema,
  auditEventIdentifierSchema,
  fieldTypeSchema,
  groupIdSchema,
  itemIdSchema,
  noteIdSchema,
  secretValueSchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { z } from 'zod';

const NAME_BOUNDS = { min: 1, max: 256 };
const DESCRIPTION_BOUNDS = { min: 0, max: 1_024 };

/** Rejects control characters (\x00-\x1F, \x7F) and whitespace-only strings. */
const cleanNameSchema = z
  .string()
  .min(NAME_BOUNDS.min)
  .max(NAME_BOUNDS.max)
  // eslint-disable-next-line no-control-regex
  .refine((val) => !/[\x00-\x1F\x7F]/u.test(val), {
    message: 'Value must not contain control characters',
  })
  .refine((val) => val.trim().length > 0, {
    message: 'Value must not be empty or whitespace only',
  });

const cleanDescriptionSchema = z
  .string()
  .min(DESCRIPTION_BOUNDS.min)
  .max(DESCRIPTION_BOUNDS.max)
  // eslint-disable-next-line no-control-regex
  .refine((val) => !/[\x00-\x08\x0B-\x1F\x7F]/u.test(val), {
    message: 'Description must not contain control characters',
  });

const ownedUint8ArraySchema = z.custom<Uint8Array>(
  (val) => val instanceof Uint8Array && val.byteLength > 0,
  { message: 'Secret field value must be a non-empty owned Uint8Array' },
);

export const cliCreateGroupRequestSchema = z
  .object({
    name: cleanNameSchema,
    description: cleanDescriptionSchema.optional(),
    template: cleanNameSchema.optional(),
  })
  .strict();

export const cliCreateTemplateRequestSchema = z
  .object({
    name: cleanNameSchema,
    description: cleanDescriptionSchema.optional(),
    fromTemplate: cleanNameSchema.optional(),
  })
  .strict();

export const cliUpdateTemplateRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    name: cleanNameSchema.optional(),
    description: cleanDescriptionSchema.optional(),
  })
  .strict();

export const cliPlanTemplateMigrationRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    targetTemplateQuery: cleanNameSchema.optional(),
    templateFile: z.string().trim().min(1).max(4096).optional(),
    toVersion: z.number().int().positive().optional(),
  })
  .strict();

export const cliApplyTemplateMigrationRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    targetTemplateQuery: cleanNameSchema.optional(),
    templateFile: z.string().trim().min(1).max(4096).optional(),
    toVersion: z.number().int().positive().optional(),
    confirmRisky: z.boolean().optional(),
  })
  .strict();

export const cliTemplateMigrationStatusRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
  })
  .strict();

export const cliCreateCredentialRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    title: cleanNameSchema,
    templateId: z.string().min(1).max(256).optional(),
    note: cleanDescriptionSchema.optional(),
  })
  .strict();

export const cliAddFieldRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldKey: cleanNameSchema,
    fieldType: fieldTypeSchema.optional(),
    label: cleanNameSchema.optional(),
    sensitive: z.boolean().optional(),
    value: ownedUint8ArraySchema.optional(),
  })
  .strict();

/** One-based revision an optimistic write expects the record to be at. */
const expectedRevisionSchema = z.number().int().positive();

export const cliSetFieldRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldKey: cleanNameSchema,
    value: ownedUint8ArraySchema,
    create: z.boolean().optional(),
    ifRevision: expectedRevisionSchema.optional(),
  })
  .strict();

export const cliUpdateFieldRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldKey: cleanNameSchema,
    label: cleanNameSchema.optional(),
    fieldType: fieldTypeSchema.optional(),
    sensitive: z.boolean().optional(),
    ifRevision: expectedRevisionSchema.optional(),
  })
  .strict()
  .refine(
    (request) =>
      request.label !== undefined ||
      request.fieldType !== undefined ||
      request.sensitive !== undefined,
    { message: 'Provide at least one definition change' },
  );

export const cliArchiveFieldRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldKey: cleanNameSchema,
  })
  .strict();

export const cliRestoreFieldRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldKey: cleanNameSchema,
  })
  .strict();

export const cliRemoveFieldRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldKey: cleanNameSchema,
  })
  .strict();

export const cliArchiveEntityRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema.optional(),
  })
  .strict();

export const cliRestoreEntityRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema.optional(),
  })
  .strict();

export const cliGroupMutationResultSchema = z
  .object({
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    name: cleanNameSchema,
  })
  .strict();

export const cliCredentialMutationResultSchema = z
  .object({
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    credentialId: itemIdSchema,
    title: cleanNameSchema,
  })
  .strict();

/**
 * Machine-readable receipt for a field write.
 *
 * The receipt names the resolved target and the revisions on either side of
 * the write so a caller can chain the next optimistic write, and it never
 * carries the written value.
 */
export const cliFieldMutationResultSchema = cliCredentialMutationResultSchema
  .extend({
    fieldKey: cleanNameSchema,
    fieldLabel: cleanNameSchema,
    fieldType: fieldTypeSchema,
    sensitive: z.boolean(),
    created: z.boolean(),
    previousRevision: expectedRevisionSchema,
    revision: expectedRevisionSchema,
  })
  .strict();

/**
 * Machine-readable result for a single field read.
 *
 * `redacted` distinguishes a withheld secret from a stored value that happens
 * to look like the redaction placeholder, and `revision` lets a caller feed
 * the read straight into an `--if-revision` write.
 */
export const cliFieldReadResultSchema = z
  .object({
    groupName: cleanNameSchema,
    credentialTitle: cleanNameSchema,
    fieldLabel: cleanNameSchema,
    fieldKey: cleanNameSchema,
    fieldType: z.string().min(1).max(64),
    sensitive: z.boolean(),
    redacted: z.boolean(),
    revision: expectedRevisionSchema,
    value: z.string(),
  })
  .strict();

export const cliAddNoteRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema.optional(),
    title: cleanNameSchema,
    content: secretValueSchema.optional(),
    isSensitive: z.boolean().optional(),
    isPinned: z.boolean().optional(),
  })
  .strict();

export const cliUpdateNoteRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema.optional(),
    noteQuery: cleanNameSchema,
    title: cleanNameSchema.optional(),
    content: secretValueSchema.optional(),
    isSensitive: z.boolean().optional(),
    isPinned: z.boolean().optional(),
  })
  .strict();

export const cliArchiveNoteRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema.optional(),
    noteQuery: cleanNameSchema,
  })
  .strict();

export const cliRestoreNoteRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema.optional(),
    noteQuery: cleanNameSchema,
  })
  .strict();

export const cliRemoveNoteRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema.optional(),
    noteQuery: cleanNameSchema,
  })
  .strict();

export const cliNoteMutationResultSchema = z
  .object({
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    credentialId: itemIdSchema.optional(),
    noteId: noteIdSchema,
    title: cleanNameSchema,
  })
  .strict();

export type CliCreateGroupRequest = z.infer<typeof cliCreateGroupRequestSchema>;
export type CliCreateTemplateRequest = z.infer<typeof cliCreateTemplateRequestSchema>;
export type CliUpdateTemplateRequest = z.infer<typeof cliUpdateTemplateRequestSchema>;
export type CliPlanTemplateMigrationRequest = z.infer<
  typeof cliPlanTemplateMigrationRequestSchema
>;
export type CliApplyTemplateMigrationRequest = z.infer<
  typeof cliApplyTemplateMigrationRequestSchema
>;
export type CliTemplateMigrationStatusRequest = z.infer<
  typeof cliTemplateMigrationStatusRequestSchema
>;
export type CliCreateCredentialRequest = z.infer<
  typeof cliCreateCredentialRequestSchema
>;
export type CliAddFieldRequest = z.infer<typeof cliAddFieldRequestSchema>;
export type CliSetFieldRequest = z.infer<typeof cliSetFieldRequestSchema>;
export type CliUpdateFieldRequest = z.infer<typeof cliUpdateFieldRequestSchema>;
export type CliArchiveFieldRequest = z.infer<typeof cliArchiveFieldRequestSchema>;
export type CliRestoreFieldRequest = z.infer<typeof cliRestoreFieldRequestSchema>;
export type CliRemoveFieldRequest = z.infer<typeof cliRemoveFieldRequestSchema>;
export type CliAddNoteRequest = z.infer<typeof cliAddNoteRequestSchema>;
export type CliUpdateNoteRequest = z.infer<typeof cliUpdateNoteRequestSchema>;
export type CliArchiveNoteRequest = z.infer<typeof cliArchiveNoteRequestSchema>;
export type CliRestoreNoteRequest = z.infer<typeof cliRestoreNoteRequestSchema>;
export type CliRemoveNoteRequest = z.infer<typeof cliRemoveNoteRequestSchema>;
export type CliArchiveEntityRequest = z.infer<typeof cliArchiveEntityRequestSchema>;
export type CliRestoreEntityRequest = z.infer<typeof cliRestoreEntityRequestSchema>;
export type CliGroupMutationResult = z.infer<typeof cliGroupMutationResultSchema>;
export type CliCredentialMutationResult = z.infer<
  typeof cliCredentialMutationResultSchema
>;
export type CliNoteMutationResult = z.infer<typeof cliNoteMutationResultSchema>;
export type CliFieldMutationResult = z.infer<typeof cliFieldMutationResultSchema>;
export type CliFieldReadResult = z.infer<typeof cliFieldReadResultSchema>;

export const cliUploadAttachmentRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    filePath: z.string().trim().min(1).max(4096),
  })
  .strict();

export const cliDownloadAttachmentRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    attachmentId: cleanNameSchema,
    destinationPath: z.string().trim().min(1).max(4096),
    force: z.boolean().optional(),
  })
  .strict();

export const cliDeleteAttachmentRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    attachmentId: cleanNameSchema,
    force: z.boolean().optional(),
  })
  .strict();

export type CliUploadAttachmentRequest = z.infer<
  typeof cliUploadAttachmentRequestSchema
>;
export type CliDownloadAttachmentRequest = z.infer<
  typeof cliDownloadAttachmentRequestSchema
>;
export type CliDeleteAttachmentRequest = z.infer<
  typeof cliDeleteAttachmentRequestSchema
>;

export const cliListHistoryRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
  })
  .strict();

export const cliShowHistoryRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    revision: z.number().int().positive(),
  })
  .strict();

export const cliDiffHistoryRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    revision: z.number().int().positive(),
    compareRevision: z.number().int().positive().optional(),
  })
  .strict();

export const cliRestoreHistoryRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    revision: z.number().int().positive(),
    force: z.boolean().optional(),
  })
  .strict();

export type CliListHistoryRequest = z.infer<typeof cliListHistoryRequestSchema>;
export type CliShowHistoryRequest = z.infer<typeof cliShowHistoryRequestSchema>;
export type CliDiffHistoryRequest = z.infer<typeof cliDiffHistoryRequestSchema>;
export type CliRestoreHistoryRequest = z.infer<typeof cliRestoreHistoryRequestSchema>;

/**
 * A stable recovery-code element identifier, or an unambiguous prefix of one.
 *
 * Bounded and character-restricted to the opaque element identifier shape so a
 * malformed selector fails as usage before any vault is unlocked. Selection is
 * never positional, so a bare number is a legal query only in the sense that it
 * is a legal identifier: it resolves against identifiers, never against
 * ordinals.
 */
export const recoveryCodeSelectorSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._~-]*$/u, {
    message: 'A recovery code identifier accepts only [A-Za-z0-9._~-].',
  });

export const cliListRecoveryCodesRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldQuery: cleanNameSchema,
  })
  .strict();

export const cliUseRecoveryCodeRequestSchema = cliListRecoveryCodesRequestSchema
  .extend({
    code: recoveryCodeSelectorSchema,
    ifRevision: expectedRevisionSchema.optional(),
  })
  .strict();

/**
 * A reveal request. `use` asks for the same consuming write `recovery use`
 * performs, ordered before the value reaches the terminal so an interrupted
 * reveal can never leave a displayed code marked available.
 */
export const cliRevealRecoveryCodeRequestSchema = cliUseRecoveryCodeRequestSchema
  .extend({
    use: z.boolean().optional(),
  })
  .strict();

export type CliListRecoveryCodesRequest = z.infer<
  typeof cliListRecoveryCodesRequestSchema
>;
export type CliUseRecoveryCodeRequest = z.infer<typeof cliUseRecoveryCodeRequestSchema>;
export type CliRevealRecoveryCodeRequest = z.infer<
  typeof cliRevealRecoveryCodeRequestSchema
>;

/**
 * A stored-seed TOTP request.
 *
 * `fieldQuery` is optional because the common credential holds exactly one
 * TOTP-secret field, and requiring its name would make the safe path the verbose
 * one. When it is omitted the field is selected by type and refused if that
 * selection is not unique, so omitting it never widens what a caller reaches.
 *
 * The algorithm, digit count, and period are deliberately absent: they are policy
 * the caller supplies through bounded options, not stored field state, and they
 * are validated by the shared TOTP option parser before a vault is unlocked.
 */
export const cliStoredTotpRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldQuery: cleanNameSchema.optional(),
  })
  .strict();

export type CliStoredTotpQuery = z.infer<typeof cliStoredTotpRequestSchema>;

/** Inclusive upper bound on one audit page. Keeps local reads bounded. */
export const MAX_AUDIT_EVENT_PAGE_SIZE = 200;
/** Page size used when the caller does not request one. */
export const DEFAULT_AUDIT_EVENT_PAGE_SIZE = 50;

/**
 * One local search request.
 *
 * `includeSecretValues` is per-invocation by construction: there is no stored
 * setting that could leave secret-value search enabled for a later command.
 */
export const cliVaultSearchRequestSchema = z
  .object({
    term: cleanNameSchema.max(MAX_VAULT_SEARCH_TERM_LENGTH),
    groupQuery: cleanNameSchema.optional(),
    limit: z.number().int().min(1).max(MAX_VAULT_SEARCH_RESULTS).optional(),
    includeArchived: z.boolean(),
    includeSecretValues: z.boolean(),
  })
  .strict();

export type CliVaultSearchRequest = z.infer<typeof cliVaultSearchRequestSchema>;

/**
 * Accepts the raw `search` option strings and normalizes them into the request
 * contract. The bound lives in the pipe so an out-of-range limit is reported as a
 * usage error before any vault is opened.
 */
export const cliVaultSearchQuerySchema = z
  .object({
    term: cleanNameSchema.max(MAX_VAULT_SEARCH_TERM_LENGTH),
    group: cleanNameSchema.optional(),
    limit: z
      .string()
      .regex(/^(?:0|[1-9][0-9]*)$/u)
      .transform(Number)
      .pipe(z.number().int().min(1).max(MAX_VAULT_SEARCH_RESULTS))
      .optional(),
    includeArchived: z.boolean(),
    includeSecretValues: z.boolean(),
  })
  .strict()
  .transform((query): CliVaultSearchRequest => ({
    term: query.term,
    ...(query.group === undefined ? {} : { groupQuery: query.group }),
    ...(query.limit === undefined ? {} : { limit: query.limit }),
    includeArchived: query.includeArchived,
    includeSecretValues: query.includeSecretValues,
  }))
  .pipe(cliVaultSearchRequestSchema);

/**
 * One item-key rotation request.
 *
 * A rotation batch is published as a single queue transaction, so the selection
 * shares the queue's atomic bound: `MAX_ROTATED_ITEM_KEYS` credentials at most.
 * Omitting `credentialQueries` rotates every active credential in the group,
 * which is the whole-group form the bound then applies to as well.
 */
export const cliItemKeyRotationRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQueries: z
      .array(cleanNameSchema)
      .min(1)
      .max(MAX_ROTATED_ITEM_KEYS)
      .optional(),
  })
  .strict();

export type CliItemKeyRotationRequest = z.infer<typeof cliItemKeyRotationRequestSchema>;

/**
 * Accepts the raw `key rekey` option values and normalizes them.
 *
 * The repeatable collector always leaves an array behind, so an omitted
 * `--credential` arrives as an empty list and has to be mapped back to "every
 * active credential" rather than to an empty selection the client would refuse.
 */
export const cliItemKeyRotationQuerySchema = z
  .object({
    group: cleanNameSchema,
    credential: z.array(cleanNameSchema).max(MAX_ROTATED_ITEM_KEYS),
  })
  .strict()
  .transform((query): CliItemKeyRotationRequest => ({
    groupQuery: query.group,
    ...(query.credential.length === 0 ? {} : { credentialQueries: query.credential }),
  }))
  .pipe(cliItemKeyRotationRequestSchema);

/**
 * One reference-navigation request.
 *
 * The depth bound is the core policy's own ceiling rather than a second opinion,
 * so a walk the policy would refuse is reported as a usage error before any vault
 * is opened.
 */
export const cliReferenceListRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    depth: z.number().int().min(1).max(MAX_REFERENCE_TRAVERSAL_DEPTH).optional(),
  })
  .strict();

export type CliReferenceListRequest = z.infer<typeof cliReferenceListRequestSchema>;

export const cliReferenceListQuerySchema = z
  .object({
    group: cleanNameSchema,
    credential: cleanNameSchema,
    depth: z
      .string()
      .regex(/^(?:0|[1-9][0-9]*)$/u)
      .transform(Number)
      .pipe(z.number().int().min(1).max(MAX_REFERENCE_TRAVERSAL_DEPTH))
      .optional(),
  })
  .strict()
  .transform((query): CliReferenceListRequest => ({
    groupQuery: query.group,
    credentialQuery: query.credential,
    ...(query.depth === undefined ? {} : { depth: query.depth }),
  }))
  .pipe(cliReferenceListRequestSchema);

/**
 * One reference write.
 *
 * The target is named the same way every other credential is named, and
 * `targetGroupQuery` exists because a reference may cross groups: without it a
 * target in another group would be unreachable, and defaulting to the source
 * group would silently resolve the wrong credential when both groups hold a
 * similar title.
 *
 * `allowCycle` is a deliberate acknowledgement, not a bypass. A cycle is a legal
 * shape, but closing one unannounced is how a reference set becomes unnavigable,
 * so the write refuses until the operator says the loop is intended.
 */
export const cliReferenceWriteRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldQuery: cleanNameSchema,
    targetQuery: cleanNameSchema,
    targetGroupQuery: cleanNameSchema.optional(),
    allowCycle: z.boolean(),
    ifRevision: expectedRevisionSchema.optional(),
  })
  .strict();

export type CliReferenceWriteRequest = z.infer<typeof cliReferenceWriteRequestSchema>;

/**
 * One reference removal.
 *
 * `targetQuery` is optional so a single-valued reference field can be cleared
 * without restating what it points at, while a repeatable field still needs the
 * target named because clearing the whole list is a different intent.
 */
export const cliReferenceRemoveRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldQuery: cleanNameSchema,
    targetQuery: cleanNameSchema.optional(),
    targetGroupQuery: cleanNameSchema.optional(),
    ifRevision: expectedRevisionSchema.optional(),
  })
  .strict();

export type CliReferenceRemoveRequest = z.infer<typeof cliReferenceRemoveRequestSchema>;

export const cliListAuditEventsRequestSchema = z
  .object({
    eventClass: auditEventClassSchema.optional(),
    limit: z.number().int().min(1).max(MAX_AUDIT_EVENT_PAGE_SIZE).optional(),
    cursor: auditEventIdentifierSchema.optional(),
  })
  .strict();

export const cliShowAuditEventRequestSchema = z
  .object({
    eventId: auditEventIdentifierSchema,
  })
  .strict();

export type CliListAuditEventsRequest = z.infer<typeof cliListAuditEventsRequestSchema>;
export type CliShowAuditEventRequest = z.infer<typeof cliShowAuditEventRequestSchema>;

/**
 * Accepts the raw `audit list` option strings and normalizes them into the
 * request contract. Bounds live in the pipe rather than a nested parse so an
 * out-of-range page size fails as a usage error instead of escaping validation.
 */
export const cliListAuditEventsQuerySchema = z
  .object({
    class: auditEventClassSchema.optional(),
    limit: z
      .string()
      .regex(/^(?:0|[1-9][0-9]*)$/u)
      .transform(Number)
      .pipe(z.number().int().min(1).max(MAX_AUDIT_EVENT_PAGE_SIZE))
      .optional(),
    cursor: auditEventIdentifierSchema.optional(),
  })
  .strict()
  .transform((query): CliListAuditEventsRequest => ({
    ...(query.class === undefined ? {} : { eventClass: query.class }),
    ...(query.limit === undefined ? {} : { limit: query.limit }),
    ...(query.cursor === undefined ? {} : { cursor: query.cursor }),
  }));

/**
 * Narrows one requested parent variable against the runner's inheritance
 * allow-list. The allow-list itself stays owned by the runner, so this only
 * decides membership; it never extends what may be inherited.
 */
function isInheritableEnvironmentName(
  name: string,
): name is InheritableEnvironmentName {
  return INHERITABLE_ENVIRONMENT_NAMES.some((allowed) => allowed === name);
}

/**
 * One `--env` mapping. The destination name is validated against the runner's
 * published contract so a rejected name fails as usage before any vault is
 * unlocked, and so `--dry-run` cannot approve a mapping a real run would refuse.
 */
export const cliRunEnvironmentMappingSchema = z
  .object({
    name: z
      .string()
      .regex(ENVIRONMENT_NAME_PATTERN, {
        message: 'Destination names accept only [A-Za-z_][A-Za-z0-9_]*',
      })
      .refine((name) => !isReservedEnvironmentName(name), {
        message: 'The destination name is reserved by the runner.',
      }),
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldQuery: cleanNameSchema,
    index: z.number().int().positive().max(10_000).optional(),
  })
  .strict();

export const cliRunRequestSchema = z
  .object({
    executable: z
      .string()
      .min(1)
      .max(4_096)
      .refine((value) => !value.includes('\0'), {
        message: 'The executable path must not contain a NUL byte.',
      }),
    arguments: z
      .array(
        z
          .string()
          .max(RUNNER_LIMITS.maxArgumentBytes)
          .refine((value) => !value.includes('\0'), {
            message: 'Arguments must not contain a NUL byte.',
          }),
      )
      .max(RUNNER_LIMITS.maxArguments),
    environment: z
      .array(cliRunEnvironmentMappingSchema)
      .max(RUNNER_LIMITS.maxEnvironmentEntries),
    inherit: z
      .array(z.enum(INHERITABLE_ENVIRONMENT_NAMES))
      .max(INHERITABLE_ENVIRONMENT_NAMES.length),
    cwd: z.string().min(1).max(4_096).optional(),
    timeoutMs: z.number().int().positive().max(RUNNER_LIMITS.maxTimeoutMs).optional(),
    maxOutputBytes: z
      .number()
      .int()
      .positive()
      .max(RUNNER_LIMITS.maxCaptureBytes)
      .optional(),
    dryRun: z.boolean().optional(),
  })
  .strict()
  .superRefine((request, context) => {
    const seen = new Set<string>();
    for (const mapping of request.environment) {
      // Windows compares names case-insensitively, so a collision that only
      // differs by case must be refused here rather than silently overwritten.
      const canonical = mapping.name.toUpperCase();
      if (seen.has(canonical)) {
        context.addIssue({
          code: 'custom',
          message: 'Each destination name may be mapped at most once.',
          path: ['environment'],
        });
        return;
      }
      seen.add(canonical);
    }
  });

export type CliRunEnvironmentMapping = z.infer<typeof cliRunEnvironmentMappingSchema>;
export type CliRunRequest = z.infer<typeof cliRunRequestSchema>;

/** Matches `NAME=group/credential/field` with an optional `#index` suffix. */
const RUN_MAPPING = /^([^=]+)=([^/]+)\/([^/]+)\/([^/#]+)(?:#([1-9][0-9]*))?$/u;

/**
 * Normalizes the raw repeated `--env` strings and bounded option strings into
 * the run request. Bounds live in the pipes so an out-of-range value fails as a
 * usage error instead of reaching the executor.
 */
export const cliRunQuerySchema = z
  .object({
    env: z.array(z.string().min(1).max(2_048)),
    inherit: z.string().max(512).optional(),
    cwd: z.string().min(1).max(4_096).optional(),
    timeout: z
      .string()
      .regex(/^[1-9][0-9]*$/u)
      .transform(Number)
      .pipe(z.number().int().positive().max(RUNNER_LIMITS.maxTimeoutMs))
      .optional(),
    maxOutput: z
      .string()
      .regex(/^[1-9][0-9]*$/u)
      .transform(Number)
      .pipe(z.number().int().positive().max(RUNNER_LIMITS.maxCaptureBytes))
      .optional(),
    dryRun: z.boolean().optional(),
    executable: z.string().min(1).max(4_096),
    arguments: z.array(z.string()),
  })
  .strict()
  .transform((query, context): z.input<typeof cliRunRequestSchema> => {
    const environment: CliRunEnvironmentMapping[] = [];
    for (const raw of query.env) {
      const matched = RUN_MAPPING.exec(raw);
      if (matched === null) {
        context.addIssue({
          code: 'custom',
          message: 'Each mapping must read NAME=group/credential/field[#index].',
          path: ['env'],
        });
        return z.NEVER;
      }
      const [, name, groupQuery, credentialQuery, fieldQuery, index] = matched;
      environment.push({
        name: name ?? '',
        groupQuery: groupQuery ?? '',
        credentialQuery: credentialQuery ?? '',
        fieldQuery: fieldQuery ?? '',
        ...(index === undefined ? {} : { index: Number(index) }),
      });
    }
    const inheritRequested =
      query.inherit === undefined || query.inherit.length === 0
        ? []
        : query.inherit.split(',').map((name) => name.trim());
    const inherit = inheritRequested.filter(isInheritableEnvironmentName);
    if (inherit.length !== inheritRequested.length) {
      context.addIssue({
        code: 'custom',
        message: `Inheritable names are limited to: ${INHERITABLE_ENVIRONMENT_NAMES.join(', ')}.`,
        path: ['inherit'],
      });
      return z.NEVER;
    }
    return {
      executable: query.executable,
      arguments: query.arguments,
      environment,
      inherit,
      ...(query.cwd === undefined ? {} : { cwd: query.cwd }),
      ...(query.timeout === undefined ? {} : { timeoutMs: query.timeout }),
      ...(query.maxOutput === undefined ? {} : { maxOutputBytes: query.maxOutput }),
      ...(query.dryRun === undefined ? {} : { dryRun: query.dryRun }),
    };
  })
  .pipe(cliRunRequestSchema);
