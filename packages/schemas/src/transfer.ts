import { z } from 'zod';

import { aeadEnvelopeSchema, passphraseDerivationSchema } from './encrypted-records.js';
import { stableFieldKeySchema } from './fields.js';
import { groupIdSchema, itemIdSchema, vaultIdSchema } from './identifiers.js';
import {
  base64UrlSchema,
  supportedSchemaVersionSchema,
  timestampSchema,
} from './primitives.js';

/**
 * Aggregate and per-document bounds for an encrypted transfer file. A transfer
 * carries decrypted logical documents rather than opaque records, so its limits
 * are far below the backup limits: a transfer is a curated hand-off, not a
 * whole-vault image.
 */
export const DEFAULT_MAX_TRANSFER_DOCUMENTS = 20_000;
export const MAX_SUPPORTED_TRANSFER_BYTES = 512 * 1024 * 1024;

const canonical32ByteValueSchema = base64UrlSchema
  .length(43)
  .refine((value) => Buffer.from(value, 'base64url').byteLength === 32, {
    error: 'Value must canonically encode exactly 32 bytes',
  });

export const transferKeySaltSchema =
  canonical32ByteValueSchema.brand<'TransferKeySalt'>();
export const transferAuthenticationTagSchema =
  canonical32ByteValueSchema.brand<'TransferAuthenticationTag'>();

/**
 * How a reader turns a passphrase into the transfer keys.
 *
 * Argon2id stretches the passphrase into one key-encryption key using the
 * canonical vault parameters, then HKDF-SHA-256 expands that key into two
 * independent keys under distinct info strings: one seals every document
 * envelope, the other authenticates the line transcript. The transfer keys are
 * therefore unrelated to any vault, group, or item key, which is what keeps a
 * transfer envelope and a vault record from ever being interchangeable.
 */
export const transferProtectionSchema = z
  .object({
    algorithm: z.literal('argon2id+hkdf-sha256+xchacha20-poly1305-ietf'),
    derivation: passphraseDerivationSchema,
    expansionSalt: transferKeySaltSchema,
  })
  .strict();

export const encryptedTransferHeaderSchema = z
  .object({
    type: z.literal('header'),
    format: z.literal('kavrix-encrypted-transfer'),
    version: z.literal(1),
    vaultId: vaultIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    createdAt: timestampSchema,
    protection: transferProtectionSchema,
  })
  .strict();

/**
 * Why a stored field value is absent from a transfer document.
 *
 * A transfer declares every omission rather than substituting an invented
 * value, so a reader can distinguish "the source held nothing" from "the source
 * held something this format is not allowed to carry".
 */
export const transferWithholdingReasonSchema = z.enum([
  /** The field definition sets `exportPolicy: 'never'`. */
  'export-policy',
  /** The value points at attachment content, which this format does not carry. */
  'attachment-unsupported',
  /** The value points at an item outside the exported set. */
  'unresolved-reference',
]);

export const transferWithholdingSchema = z
  .object({
    stableKey: stableFieldKeySchema,
    scope: z.enum(['template', 'item']),
    reason: transferWithholdingReasonSchema,
  })
  .strict();

/**
 * A withholding manifest is the honest half of a policy-filtered export: the
 * document carries the field definitions but not the forbidden values, and this
 * list names exactly which values were dropped and why.
 */
export const transferWithholdingsSchema = z
  .array(transferWithholdingSchema)
  .max(2_000)
  .superRefine((withholdings, context) => {
    const seen = new Set<string>();
    for (const [index, withheld] of withholdings.entries()) {
      const key = `${withheld.scope}:${withheld.stableKey}`;
      if (seen.has(key)) {
        context.addIssue({
          code: 'custom',
          message: 'A withholding manifest cannot name the same field twice',
          path: [index, 'stableKey'],
        });
      }
      seen.add(key);
    }
  });

/**
 * One sealed logical document.
 *
 * The envelope's associated data binds it to the source vault and to the exact
 * group or item identity below, so a document cannot be moved between transfer
 * files or relabelled without failing authentication.
 */
export const encryptedTransferEntrySchema = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('group'),
      groupId: groupIdSchema,
      envelope: aeadEnvelopeSchema,
    })
    .strict(),
  z
    .object({
      kind: z.literal('item'),
      groupId: groupIdSchema,
      itemId: itemIdSchema,
      envelope: aeadEnvelopeSchema,
      withheld: transferWithholdingsSchema,
    })
    .strict(),
]);

export const encryptedTransferFooterSchema = z
  .object({
    type: z.literal('footer'),
    version: z.literal(1),
    groupCount: z.number().int().nonnegative().max(DEFAULT_MAX_TRANSFER_DOCUMENTS),
    itemCount: z.number().int().nonnegative().max(DEFAULT_MAX_TRANSFER_DOCUMENTS),
    transcriptSha256: canonical32ByteValueSchema,
    authenticationTag: transferAuthenticationTagSchema,
  })
  .strict();

export const transferLimitsSchema = z
  .object({
    maximumBytes: z.number().int().positive().max(MAX_SUPPORTED_TRANSFER_BYTES),
    maximumDocuments: z.number().int().positive().max(DEFAULT_MAX_TRANSFER_DOCUMENTS),
  })
  .strict();

/** What a reader does when a destination group already carries the name. */
export const transferCollisionStrategySchema = z.enum(['fail', 'skip', 'rename']);

export const transferImportSummarySchema = z
  .object({
    vaultId: vaultIdSchema,
    createdAt: timestampSchema,
    groupsCreated: z.number().int().nonnegative(),
    groupsSkipped: z.number().int().nonnegative(),
    itemsCreated: z.number().int().nonnegative(),
    withheldValues: z.number().int().nonnegative(),
  })
  .strict();

export type TransferProtection = z.infer<typeof transferProtectionSchema>;
/**
 * The Argon2id parameters a reader must reproduce. Structurally identical to a
 * passphrase key slot's derivation, but never interchangeable with one: a
 * transfer derivation stretches a transfer passphrase, not a vault passphrase.
 */
export type TransferPassphraseDerivation = TransferProtection['derivation'];
export type EncryptedTransferHeader = z.infer<typeof encryptedTransferHeaderSchema>;
export type EncryptedTransferEntry = z.infer<typeof encryptedTransferEntrySchema>;
export type EncryptedTransferFooter = z.infer<typeof encryptedTransferFooterSchema>;
export type TransferWithholding = z.infer<typeof transferWithholdingSchema>;
export type TransferWithholdingReason = z.infer<typeof transferWithholdingReasonSchema>;
export type TransferLimits = Partial<z.infer<typeof transferLimitsSchema>>;
export type ResolvedTransferLimits = z.infer<typeof transferLimitsSchema>;
export type TransferCollisionStrategy = z.infer<typeof transferCollisionStrategySchema>;
export type TransferImportSummary = z.infer<typeof transferImportSummarySchema>;
