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

/**
 * Coarse closed classification of an audit event. It must stay closed so an
 * unknown or future class fails validation instead of rendering as free text.
 */
export const auditEventClassSchema = z.enum([
  'device',
  'slot',
  'mutation',
  'backup',
  'recovery',
]);

/** Coarse closed audit action vocabulary. */
export const auditEventActionSchema = z.enum([
  'create',
  'supersede',
  'revoke',
  'queue',
]);

/** Closed lifecycle state vocabulary shared with unlock slots. */
export const auditEventStateSchema = z.enum([
  'pending',
  'active',
  'superseded',
  'revoked',
]);

const AUDIT_EVENT_ID_BOUNDS = { min: 1, max: 512 };
const AUDIT_EVENT_SUBJECT_BOUNDS = { min: 1, max: 256 };

/**
 * Deterministic identifier of one projected audit event. Bounded and restricted
 * to printable identifier characters so it can never carry terminal control
 * sequences into a renderer. The character class is a superset of the opaque
 * identifier alphabet so composing an event identifier from a real record
 * identifier can never fail validation.
 */
export const auditEventIdentifierSchema = z
  .string()
  .min(AUDIT_EVENT_ID_BOUNDS.min)
  .max(AUDIT_EVENT_ID_BOUNDS.max)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._~:-]*$/u, {
    message: 'Audit event identifiers accept only [A-Za-z0-9._~:-]',
  });

/** Opaque subject reference (slot, device, or entity identifier). */
export const auditEventSubjectSchema = z
  .string()
  .min(AUDIT_EVENT_SUBJECT_BOUNDS.min)
  .max(AUDIT_EVENT_SUBJECT_BOUNDS.max)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._~:-]*$/u, {
    message: 'Audit event subjects accept only [A-Za-z0-9._~:-]',
  });

/**
 * One locally derived audit event. It carries only opaque metadata: no secret
 * material, no plaintext names, labels, note bodies, or field values. Unknown
 * versions fail closed because `version` is a literal.
 */
export const localAuditEventSchema = z
  .object({
    version: z.literal(1),
    eventId: auditEventIdentifierSchema,
    eventClass: auditEventClassSchema,
    action: auditEventActionSchema,
    subject: auditEventSubjectSchema,
    occurredAt: timestampSchema,
    keyVersion: keyVersionSchema.optional(),
    state: auditEventStateSchema.optional(),
    deviceId: deviceIdSchema.optional(),
    recordRevision: z.number().int().nonnegative().optional(),
  })
  .strict();

export type KeySlotAuditPayload = z.infer<typeof keySlotAuditPayloadSchema>;
export type AuditPayload = z.infer<typeof auditPayloadSchema>;
export type AuditEventClass = z.infer<typeof auditEventClassSchema>;
export type AuditEventAction = z.infer<typeof auditEventActionSchema>;
export type AuditEventState = z.infer<typeof auditEventStateSchema>;
export type LocalAuditEvent = z.infer<typeof localAuditEventSchema>;
