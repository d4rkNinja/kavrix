import { z } from 'zod';

import { databaseIdSchema } from './identifiers.js';
import { base64UrlSchema, timestampSchema } from './primitives.js';
import { passphraseDerivationSchema } from './encrypted-records.js';

/**
 * Size bounds for one passphrase-sealed database backup archive.
 *
 * The archive plaintext is a whole local database file, so its bound matches
 * the secure-stream file ceiling used by protected file IO. The bound exists
 * so a hostile archive path cannot make a reader allocate unbounded memory.
 */
export const MAX_DATABASE_BACKUP_PLAINTEXT_BYTES = 128 * 1024 * 1024;

const backupNonceSchema = base64UrlSchema
  .length(32)
  .refine((value) => Buffer.from(value, 'base64url').byteLength === 24, {
    error: 'Nonce must canonically encode exactly 24 bytes',
  });

const backupTagSchema = base64UrlSchema
  .length(22)
  .refine((value) => Buffer.from(value, 'base64url').byteLength === 16, {
    error: 'Authentication tag must canonically encode exactly 16 bytes',
  });

const backupCiphertextSchema = base64UrlSchema.refine(
  (value) =>
    Buffer.from(value, 'base64url').byteLength <= MAX_DATABASE_BACKUP_PLAINTEXT_BYTES,
  { error: 'Ciphertext exceeds the supported archive size' },
);

/**
 * Passphrase-sealed archive of one local-file database container.
 *
 * The whole encrypted database file is the plaintext of one XChaCha20-Poly1305
 * envelope whose associated data is the canonical header below, so no field
 * of the archive — including the opaque database identity — can be substituted
 * without failing authentication. The inner database file keeps its own
 * client-side encryption and rollback anchors; this envelope adds a portable,
 * independently passphrase-protected at-rest layer for backup media.
 */
export const databaseBackupArchiveSchema = z
  .object({
    format: z.literal('kavrix-database-backup'),
    version: z.literal(1),
    createdAt: timestampSchema,
    datastore: z.literal('file'),
    databaseId: databaseIdSchema,
    plaintextBytes: z
      .number()
      .int()
      .positive()
      .max(MAX_DATABASE_BACKUP_PLAINTEXT_BYTES),
    derivation: passphraseDerivationSchema,
    nonce: backupNonceSchema,
    authenticationTag: backupTagSchema,
    ciphertext: backupCiphertextSchema,
  })
  .strict();

export type DatabaseBackupArchive = z.infer<typeof databaseBackupArchiveSchema>;
