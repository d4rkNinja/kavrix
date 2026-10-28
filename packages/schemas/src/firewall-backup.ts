import { z } from 'zod';
import { authorizationStateEnvelopeSchema } from './policy.js';
import { databaseIdSchema } from './identifiers.js';
import { base64UrlSchemaWithMaxChars } from './primitives.js';
import { MAX_DATABASE_BACKUP_CIPHERTEXT_CHARS } from './database-backup-archive.js';

/** Inner document; the existing passphrase-sealed backup authenticates all bytes. */
export const firewallBackupBundleSchema = z
  .object({
    format: z.literal('kavrix-firewall-backup'),
    version: z.literal(1),
    databaseId: databaseIdSchema,
    database: base64UrlSchemaWithMaxChars(MAX_DATABASE_BACKUP_CIPHERTEXT_CHARS),
    authorization: authorizationStateEnvelopeSchema.nullable(),
  })
  .strict()
  .superRefine((bundle, context) => {
    if (
      bundle.authorization !== null &&
      (bundle.authorization.scopeKind !== 'database' ||
        bundle.authorization.scopeId !== bundle.databaseId)
    )
      context.addIssue({
        code: 'custom',
        message: 'Authorization state belongs to another database',
      });
  });
export type FirewallBackupBundle = z.infer<typeof firewallBackupBundleSchema>;
