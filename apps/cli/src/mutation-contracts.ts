import { groupIdSchema, itemIdSchema, vaultIdSchema } from '@kavrix/schemas';
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

export const cliSetFieldRequestSchema = z
  .object({
    groupQuery: cleanNameSchema,
    credentialQuery: cleanNameSchema,
    fieldKey: cleanNameSchema,
    value: ownedUint8ArraySchema,
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

export type CliCreateGroupRequest = z.infer<typeof cliCreateGroupRequestSchema>;
export type CliCreateCredentialRequest = z.infer<
  typeof cliCreateCredentialRequestSchema
>;
export type CliSetFieldRequest = z.infer<typeof cliSetFieldRequestSchema>;
export type CliArchiveEntityRequest = z.infer<typeof cliArchiveEntityRequestSchema>;
export type CliRestoreEntityRequest = z.infer<typeof cliRestoreEntityRequestSchema>;
export type CliGroupMutationResult = z.infer<typeof cliGroupMutationResultSchema>;
export type CliCredentialMutationResult = z.infer<
  typeof cliCredentialMutationResultSchema
>;
