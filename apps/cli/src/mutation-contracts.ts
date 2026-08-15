import {
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

export const cliSetFieldRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldKey: cleanNameSchema,
    value: ownedUint8ArraySchema,
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
  })
  .strict();

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
