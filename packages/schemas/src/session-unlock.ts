import { z } from 'zod';

import {
  AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS,
  AEAD_NONCE_BASE64URL_CHARS,
} from './encrypted-records.js';
import { opaqueIdentifierSchema } from './policy.js';
import { base64UrlSchema, timestampSchema } from './primitives.js';

/**
 * One local session-unlock association. The AAD binds a sealed session file
 * to exactly one profile/database target, one creation moment, and one
 * optional TTL so a session file cannot be transplanted or replayed.
 */
export const sessionUnlockAssociatedDataSchema = z
  .object({
    version: z.literal(1),
    kind: z.literal('session-unlock'),
    profileId: opaqueIdentifierSchema,
    databaseId: opaqueIdentifierSchema.optional(),
    createdAt: timestampSchema,
    ttlHours: z.number().int().min(1).max(8760).optional(),
  })
  .strict();

export const sessionUnlockEnvelopeSchema = z
  .object({
    version: z.literal(1),
    algorithm: z.literal('xchacha20-poly1305-ietf'),
    nonce: base64UrlSchema,
    ciphertext: base64UrlSchema,
    authenticationTag: base64UrlSchema,
    aad: sessionUnlockAssociatedDataSchema,
  })
  .strict()
  .superRefine((envelope, context) => {
    if (envelope.nonce.length !== AEAD_NONCE_BASE64URL_CHARS) {
      context.addIssue({
        code: 'custom',
        message: 'Nonce length does not match the authenticated-encryption algorithm',
        path: ['nonce'],
      });
    }
    if (envelope.authenticationTag.length !== AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS) {
      context.addIssue({
        code: 'custom',
        message: 'Authentication tag must encode 16 bytes',
        path: ['authenticationTag'],
      });
    }
  });

export type SessionUnlockAssociatedData = z.infer<
  typeof sessionUnlockAssociatedDataSchema
>;
export type SessionUnlockEnvelope = z.infer<typeof sessionUnlockEnvelopeSchema>;
