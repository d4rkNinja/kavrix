import { z } from 'zod';

import {
  sealedArchiveNonceSchema,
  sealedArchiveTagSchema,
} from './database-backup-archive.js';
import { passphraseDerivationSchema } from './encrypted-records.js';
import {
  base64UrlSchemaWithMaxChars,
  maxBase64UrlCharsForByteLimit,
  maxTextBytesSchema,
  timestampSchema,
} from './primitives.js';

/**
 * Passphrase-sealed export of the flat credentials in one vault.
 *
 * Unlike a database backup, an export carries decrypted name/value records
 * re-sealed under a separate passphrase, so it can be imported into a
 * different database or vault. The archive never contains database, vault, or
 * key identifiers; it is bound only to its own canonical header.
 */
export const MAX_VAULT_EXPORT_ENTRIES = 10_000;
export const MAX_VAULT_EXPORT_PLAINTEXT_BYTES = 64 * 1024 * 1024;
/** Serialized archive bound: base64url ciphertext plus a small JSON header. */
export const MAX_VAULT_EXPORT_ARCHIVE_BYTES = 96 * 1024 * 1024;

export const vaultExportEntrySchema = z
  .object({
    name: z.string().min(1).max(256),
    value: maxTextBytesSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const vaultExportPlaintextSchema = z
  .object({
    entries: z.array(vaultExportEntrySchema).min(1).max(MAX_VAULT_EXPORT_ENTRIES),
  })
  .strict()
  .superRefine((plaintext, context) => {
    const seen = new Set<string>();
    for (const [index, entry] of plaintext.entries.entries()) {
      if (seen.has(entry.name)) {
        context.addIssue({
          code: 'custom',
          message: 'Export entries must have unique names',
          path: ['entries', index, 'name'],
        });
      }
      seen.add(entry.name);
    }
  });

/**
 * Character ceiling for export ciphertext: the largest unpadded base64url
 * string that cannot decode to more than the plaintext bound. The shared
 * record-level `base64UrlSchema` ceiling does not apply here because a whole
 * vault export is legitimately larger than a single record payload.
 */
export const MAX_VAULT_EXPORT_CIPHERTEXT_CHARS = maxBase64UrlCharsForByteLimit(
  MAX_VAULT_EXPORT_PLAINTEXT_BYTES,
);

const exportCiphertextSchema = base64UrlSchemaWithMaxChars(
  MAX_VAULT_EXPORT_CIPHERTEXT_CHARS,
).refine(
  (value) =>
    Buffer.from(value, 'base64url').byteLength <= MAX_VAULT_EXPORT_PLAINTEXT_BYTES,
  { error: 'Ciphertext exceeds the supported export size' },
);

export const vaultExportArchiveSchema = z
  .object({
    format: z.literal('kavrix-vault-export'),
    version: z.literal(1),
    createdAt: timestampSchema,
    entryCount: z.number().int().min(1).max(MAX_VAULT_EXPORT_ENTRIES),
    plaintextBytes: z.number().int().positive().max(MAX_VAULT_EXPORT_PLAINTEXT_BYTES),
    derivation: passphraseDerivationSchema,
    nonce: sealedArchiveNonceSchema,
    authenticationTag: sealedArchiveTagSchema,
    ciphertext: exportCiphertextSchema,
  })
  .strict();

export type VaultExportEntry = z.infer<typeof vaultExportEntrySchema>;
export type VaultExportPlaintext = z.infer<typeof vaultExportPlaintextSchema>;
export type VaultExportArchive = z.infer<typeof vaultExportArchiveSchema>;
