import { z } from 'zod';

import { deviceIdSchema, keySlotIdSchema } from './identifiers.js';
import { keyVersionSchema, timestampSchema } from './primitives.js';

/** Authenticated plaintext for unlock-slot audit entries; no secret material. */
export const keySlotAuditPayloadSchema = z
  .object({
    version: z.literal(1),
    action: z.enum(['create', 'revoke']),
    slotId: keySlotIdSchema,
    slotType: z.enum(['portable-key', 'passphrase', 'recovery-key', 'device-key']),
    resultingState: z.enum(['active', 'revoked']),
    keyVersion: keyVersionSchema,
    actorDeviceId: deviceIdSchema,
    occurredAt: timestampSchema,
  })
  .strict();

/** The currently documented semantic audit payload family. */
export const auditPayloadSchema = keySlotAuditPayloadSchema;

export type KeySlotAuditPayload = z.infer<typeof keySlotAuditPayloadSchema>;
export type AuditPayload = z.infer<typeof auditPayloadSchema>;
