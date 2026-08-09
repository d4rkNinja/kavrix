import { z } from 'zod';

export const MAX_TEXT_BYTES = 1_048_576;
export const MAX_CIPHERTEXT_CHARS = 22_369_632;

export const timestampSchema = z.iso.datetime({ offset: false });
export const revisionSchema = z.number().int().nonnegative().brand<'Revision'>();
export const positiveVersionSchema = z
  .number()
  .int()
  .positive()
  .max(0xff_ff_ff_ff)
  .brand<'PositiveVersion'>();
const semanticVersionSchema = z.number().int().positive().max(0xff_ff_ff_ff);
const semanticRevisionSchema = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER);

export const schemaVersionSchema = semanticVersionSchema.brand<'SchemaVersion'>();
export const keyVersionSchema = semanticVersionSchema.brand<'KeyVersion'>();
export const templateVersionSchema = semanticVersionSchema.brand<'TemplateVersion'>();
export const tokenVersionSchema = semanticVersionSchema.brand<'TokenVersion'>();
export const cryptographicVersionSchema =
  semanticVersionSchema.brand<'CryptographicVersion'>();
export const recordRevisionSchema = semanticRevisionSchema.brand<'RecordRevision'>();
export const vaultRevisionSchema = semanticRevisionSchema.brand<'VaultRevision'>();
export const changeSequenceSchema = semanticRevisionSchema.brand<'ChangeSequence'>();
export const envelopeVersionSchema = z.literal(1).brand<'EnvelopeVersion'>();
export const associatedDataVersionSchema = z
  .literal(1)
  .brand<'AssociatedDataVersion'>();
export const keySlotVersionSchema = z.literal(1).brand<'KeySlotVersion'>();
export const sortOrderSchema = z.number().int().nonnegative();
export const nonEmptyTextSchema = z.string().trim().min(1).max(256);
export const encryptedTextSchema = z.string().max(MAX_TEXT_BYTES);
export const secretValueSchema = z.string().max(MAX_TEXT_BYTES).brand<'SecretValue'>();
export const secretBytesSchema = z
  .instanceof(Uint8Array)
  .refine((value) => value.byteLength > 0 && value.byteLength <= MAX_TEXT_BYTES, {
    error: 'Secret byte length is outside the supported range',
  })
  .brand<'SecretBytes'>();

export const base64UrlSchema = z
  .string()
  .min(1)
  .max(MAX_CIPHERTEXT_CHARS)
  .regex(/^[A-Za-z0-9_-]+$/, 'Must use unpadded base64url encoding')
  .refine(
    (value) =>
      value.length % 4 !== 1 &&
      Buffer.from(value, 'base64url').toString('base64url') === value,
    { error: 'Must use canonical unpadded base64url encoding' },
  );

export const sha256DigestSchema = base64UrlSchema
  .length(43)
  .refine((value) => Buffer.from(value, 'base64url').byteLength === 32, {
    error: 'SHA-256 digests must canonically encode exactly 32 bytes',
  })
  .brand<'Sha256Digest'>();

export const slugSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .regex(/^[\p{L}\p{N}](?:[\p{L}\p{N}._~-]|-(?!-))*$/u, 'Invalid slug');

export type Timestamp = z.infer<typeof timestampSchema>;
export type Revision = z.infer<typeof revisionSchema>;
export type PositiveVersion = z.infer<typeof positiveVersionSchema>;
export type SchemaVersion = z.infer<typeof schemaVersionSchema>;
export type KeyVersion = z.infer<typeof keyVersionSchema>;
export type TemplateVersion = z.infer<typeof templateVersionSchema>;
export type TokenVersion = z.infer<typeof tokenVersionSchema>;
export type CryptographicVersion = z.infer<typeof cryptographicVersionSchema>;
export type RecordRevision = z.infer<typeof recordRevisionSchema>;
export type VaultRevision = z.infer<typeof vaultRevisionSchema>;
export type ChangeSequence = z.infer<typeof changeSequenceSchema>;
export type EnvelopeVersion = z.infer<typeof envelopeVersionSchema>;
export type AssociatedDataVersion = z.infer<typeof associatedDataVersionSchema>;
export type KeySlotVersion = z.infer<typeof keySlotVersionSchema>;
export type SecretValue = z.infer<typeof secretValueSchema>;
export type SecretBytes = z.infer<typeof secretBytesSchema>;
export type Sha256Digest = z.infer<typeof sha256DigestSchema>;
