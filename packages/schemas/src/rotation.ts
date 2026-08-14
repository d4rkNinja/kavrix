import { z } from 'zod';

import { deviceIdSchema, keySlotIdSchema, vaultIdSchema } from './identifiers.js';
import { keySlotSchema, type KeySlot } from './encrypted-records.js';
import {
  sha256DigestSchema,
  timestampSchema,
  vaultRevisionSchema,
} from './primitives.js';

export const portableKeyRotationStateSchema = z.enum([
  'prepared',
  'pending-published',
  'active-published',
  'completed',
]);

const rotationOperationIdSchema = z
  .string()
  .min(16)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._~-]*$/u);

export const portableKeyRotationCheckpointPayloadSchema = z
  .object({
    version: z.literal(1),
    vaultId: vaultIdSchema,
    operationId: rotationOperationIdSchema,
    sourceSlotId: keySlotIdSchema,
    replacementSlotId: keySlotIdSchema,
    sourceRevision: vaultRevisionSchema,
    remoteRevision: vaultRevisionSchema,
    sourceSlotDigest: sha256DigestSchema,
    replacementSlotDigest: sha256DigestSchema,
    transcriptDigest: sha256DigestSchema,
    state: portableKeyRotationStateSchema,
  })
  .strict()
  .superRefine((payload, context) => {
    if (payload.sourceSlotId === payload.replacementSlotId) {
      context.addIssue({
        code: 'custom',
        path: ['replacementSlotId'],
        message: 'A rotation must use distinct source and replacement slots',
      });
    }
    const offset = {
      prepared: 0,
      'pending-published': 1,
      'active-published': 2,
      completed: 3,
    }[payload.state];
    if (payload.sourceRevision + offset !== payload.remoteRevision) {
      context.addIssue({
        code: 'custom',
        path: ['remoteRevision'],
        message: 'The checkpoint revision does not match its lifecycle state',
      });
    }
  });

export const portableKeyRotationCheckpointSchema = z
  .object({
    payload: portableKeyRotationCheckpointPayloadSchema,
    authenticationTag: sha256DigestSchema,
  })
  .strict();

export type PortableKeyRotationState = z.infer<typeof portableKeyRotationStateSchema>;
export type PortableKeyRotationCheckpointPayload = z.infer<
  typeof portableKeyRotationCheckpointPayloadSchema
>;
export type PortableKeyRotationCheckpoint = z.infer<
  typeof portableKeyRotationCheckpointSchema
>;

export type PortableKeySlot = Extract<KeySlot, { readonly type: 'portable-key' }>;

export const portableKeyRotationSourceKindSchema = z.enum([
  'generated-file',
  'imported-file',
]);

const portableSlotSchema = keySlotSchema.refine(
  (slot): slot is PortableKeySlot => slot.type === 'portable-key',
  {
    error: 'Portable-key rotation requires portable-key slots',
  },
);

export const portableKeyRotationJournalRecordSchema = z
  .object({
    version: z.literal(1),
    kind: z.literal('portable-key-rotation'),
    operationId: rotationOperationIdSchema,
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
    state: portableKeyRotationStateSchema,
    sourceKind: portableKeyRotationSourceKindSchema,
    sourceSlot: portableSlotSchema,
    replacementSlot: portableSlotSchema,
    sourceRevision: vaultRevisionSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    checkpoint: portableKeyRotationCheckpointSchema,
  })
  .strict()
  .superRefine((record, context) => {
    const expectedReplacementState =
      record.state === 'prepared' || record.state === 'pending-published'
        ? 'pending'
        : 'active';
    if (
      record.sourceSlot.state !== 'active' ||
      record.replacementSlot.state !== expectedReplacementState ||
      record.sourceSlot.id === record.replacementSlot.id ||
      record.sourceSlot.keyVersion !== record.replacementSlot.keyVersion ||
      record.sourceRevision !== record.checkpoint.payload.sourceRevision ||
      record.checkpoint.payload.vaultId !== record.vaultId ||
      record.checkpoint.payload.operationId !== record.operationId ||
      record.checkpoint.payload.sourceSlotId !== record.sourceSlot.id ||
      record.checkpoint.payload.replacementSlotId !== record.replacementSlot.id ||
      record.checkpoint.payload.state !== record.state
    ) {
      context.addIssue({
        code: 'custom',
        path: ['checkpoint'],
        message: 'The rotation journal record and checkpoint must agree',
      });
    }
  });

export type PortableKeyRotationJournalRecord = z.infer<
  typeof portableKeyRotationJournalRecordSchema
>;

export const PORTABLE_KEY_ROTATION_JOURNAL_MAX_SERIALIZED_BYTES = 64 * 1024;

export function portableKeyRotationJournalSerializedBytes(
  value: PortableKeyRotationJournalRecord,
): number {
  return Buffer.byteLength(
    JSON.stringify(portableKeyRotationJournalRecordSchema.parse(value)),
    'utf8',
  );
}
