import { z } from 'zod';

export const MAX_TEXT_BYTES = 1_048_576;
export const MAX_CIPHERTEXT_CHARS = 22_369_632;
export const MAX_SEMANTIC_VERSION = 0xffff_ffff;
export const MAX_SEMANTIC_REVISION = Number.MAX_SAFE_INTEGER;

const textEncoder = new TextEncoder();

/** Return the number of bytes needed to encode text as UTF-8. */
export function utf8ByteLength(value: string): number {
  return textEncoder.encode(value).byteLength;
}

/** Shared byte-bound schema for sensitive and encrypted text values. */
export const maxTextBytesSchema = z.string().superRefine((value, context) => {
  // Every UTF-16 code unit requires at least one UTF-8 byte, so reject an
  // obviously oversized value before allocating its encoded byte buffer.
  if (value.length > MAX_TEXT_BYTES || utf8ByteLength(value) > MAX_TEXT_BYTES) {
    context.addIssue({
      code: 'too_big',
      origin: 'string',
      maximum: MAX_TEXT_BYTES,
      inclusive: true,
      message: `Too big: expected string to have <=${String(MAX_TEXT_BYTES)} bytes`,
    });
  }
});

export const CURRENT_SCHEMA_VERSION = 1;
export const SUPPORTED_SCHEMA_VERSIONS = Object.freeze([
  CURRENT_SCHEMA_VERSION,
] as const);
export const CURRENT_CRYPTOGRAPHIC_VERSION = 1;
export const SUPPORTED_CRYPTOGRAPHIC_VERSIONS = Object.freeze([
  CURRENT_CRYPTOGRAPHIC_VERSION,
] as const);
export const CURRENT_TOKEN_VERSION = 1;
export const SUPPORTED_TOKEN_VERSIONS = Object.freeze([CURRENT_TOKEN_VERSION] as const);

export const CANONICAL_BASE64URL_PATTERN_SOURCE =
  '^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$';
export const CANONICAL_TIMESTAMP_CHARS = 24;
export const CANONICAL_TIMESTAMP_PATTERN_SOURCE =
  '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$';
export const SHA256_DIGEST_BASE64URL_CHARS = 43;

const canonicalBase64UrlPattern = new RegExp(CANONICAL_BASE64URL_PATTERN_SOURCE);
const canonicalTimestampPattern = new RegExp(CANONICAL_TIMESTAMP_PATTERN_SOURCE);

function hasCanonicalBase64UrlTerminalBits(value: string): boolean {
  if (value.length === 0) return false;
  const remainder = value.length % 4;
  if (remainder === 1) return false;
  // Applying the grouped pattern to multi-megabyte ciphertexts can overflow
  // the JavaScript regexp engine. The full alphabet is checked separately, so
  // one aligned suffix is sufficient to enforce the exact terminal-bit rule.
  const tailLength = remainder === 0 ? Math.min(value.length, 4) : remainder;
  return canonicalBase64UrlPattern.test(value.slice(-tailLength));
}

export const timestampSchema = z.iso
  .datetime({ offset: false, precision: 3 })
  .length(CANONICAL_TIMESTAMP_CHARS)
  .regex(canonicalTimestampPattern);
export const revisionSchema = z.number().int().nonnegative().brand<'Revision'>();
export const positiveVersionSchema = z
  .number()
  .int()
  .positive()
  .max(MAX_SEMANTIC_VERSION)
  .brand<'PositiveVersion'>();
const semanticVersionSchema = z.number().int().positive().max(MAX_SEMANTIC_VERSION);
const semanticRevisionSchema = z
  .number()
  .int()
  .nonnegative()
  .max(MAX_SEMANTIC_REVISION);

/**
 * Broad schema-version value for canonical encoding and migration evidence.
 * Representability does not grant current-record support.
 */
export const schemaVersionSchema = semanticVersionSchema.brand<'SchemaVersion'>();
export const keyVersionSchema = semanticVersionSchema.brand<'KeyVersion'>();
export const templateVersionSchema = semanticVersionSchema.brand<'TemplateVersion'>();
/** Broad token-version value; representability is not current wire support. */
export const tokenVersionSchema = semanticVersionSchema.brand<'TokenVersion'>();
/** Broad crypto-version value; representability is not current persisted support. */
export const cryptographicVersionSchema =
  semanticVersionSchema.brand<'CryptographicVersion'>();
export const supportedSchemaVersionSchema = schemaVersionSchema.refine(
  (value) => SUPPORTED_SCHEMA_VERSIONS.some((supported) => value === supported),
  { error: 'Unsupported schema version' },
);
export const supportedCryptographicVersionSchema = cryptographicVersionSchema.refine(
  (value) => SUPPORTED_CRYPTOGRAPHIC_VERSIONS.some((supported) => value === supported),
  { error: 'Unsupported cryptographic version' },
);
export const supportedTokenVersionSchema = tokenVersionSchema.refine(
  (value) => SUPPORTED_TOKEN_VERSIONS.some((supported) => value === supported),
  { error: 'Unsupported token version' },
);
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
export const encryptedTextSchema = maxTextBytesSchema;
export const secretValueSchema = maxTextBytesSchema.brand<'SecretValue'>();
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
  .refine(hasCanonicalBase64UrlTerminalBits, {
    error: 'Must use canonical unpadded base64url encoding',
  })
  .refine((value) => Buffer.from(value, 'base64url').toString('base64url') === value, {
    error: 'Must use canonical unpadded base64url encoding',
  });

export const sha256DigestSchema = base64UrlSchema
  .length(SHA256_DIGEST_BASE64URL_CHARS)
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
