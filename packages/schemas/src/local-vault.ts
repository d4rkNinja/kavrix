import { z } from 'zod';

import { aeadEnvelopeSchema, keySlotSchema } from './encrypted-records.js';
import { vaultIdSchema } from './identifiers.js';
import {
  CURRENT_CRYPTOGRAPHIC_VERSION,
  CURRENT_SCHEMA_VERSION,
  keyVersionSchema,
  maxTextBytesSchema,
  supportedCryptographicVersionSchema,
  supportedSchemaVersionSchema,
  timestampSchema,
  vaultRevisionSchema,
} from './primitives.js';

export const localVaultFormatSchema = z.literal('kavrix-local-vault');
export const CURRENT_LOCAL_VAULT_VERSION = 2;
export const localVaultVersionSchema = z.literal(CURRENT_LOCAL_VAULT_VERSION);
export const MAX_LOCAL_RECOVERY_SLOTS = 32;

export const localRecoveryKeySlotSchema = keySlotSchema.refine(
  (slot) => slot.type === 'recovery-key',
  { error: 'Local recovery slots require recovery-key material' },
);

export const localVaultValueSchema = z
  .object({
    value: maxTextBytesSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const localVaultPayloadSchema = z
  .object({
    records: z.record(z.string().min(1).max(256), localVaultValueSchema),
  })
  .strict()
  .superRefine((payload, context) => {
    if (Object.keys(payload.records).length > 10_000) {
      context.addIssue({
        code: 'custom',
        message: 'Local vault contains too many credentials',
        path: ['records'],
      });
    }
  });

export const localVaultDocumentSchema = z
  .object({
    format: localVaultFormatSchema,
    version: localVaultVersionSchema,
    id: vaultIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    cryptographicVersion: supportedCryptographicVersionSchema,
    currentKeyVersion: keyVersionSchema,
    keySlot: keySlotSchema,
    recoverySlots: z
      .array(localRecoveryKeySlotSchema)
      .max(MAX_LOCAL_RECOVERY_SLOTS)
      .default([]),
    revision: vaultRevisionSchema,
    encryptedPayload: aeadEnvelopeSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((document, context) => {
    if (document.schemaVersion !== CURRENT_SCHEMA_VERSION) {
      context.addIssue({
        code: 'custom',
        message: 'Unsupported local vault schema version',
        path: ['schemaVersion'],
      });
    }
    if (document.cryptographicVersion !== CURRENT_CRYPTOGRAPHIC_VERSION) {
      context.addIssue({
        code: 'custom',
        message: 'Unsupported local vault cryptographic version',
        path: ['cryptographicVersion'],
      });
    }

    if (document.keySlot.type !== 'portable-key') {
      context.addIssue({
        code: 'custom',
        message: 'Local vaults require a portable-key unlock slot',
        path: ['keySlot', 'type'],
      });
    } else {
      if (document.keySlot.state !== 'active') {
        context.addIssue({
          code: 'custom',
          message: 'Local vault unlock slot must be active',
          path: ['keySlot', 'state'],
        });
      }
      if (document.keySlot.keyVersion !== document.currentKeyVersion) {
        context.addIssue({
          code: 'custom',
          message: 'Local vault key versions do not agree',
          path: ['keySlot', 'keyVersion'],
        });
      }
      if (document.keySlot.wrappedRootKey.aad.vaultId !== document.id) {
        context.addIssue({
          code: 'custom',
          message: 'Local vault key slot belongs to another vault',
          path: ['keySlot', 'wrappedRootKey', 'aad', 'vaultId'],
        });
      }
    }

    const slotIds = new Set([document.keySlot.id]);
    for (const [index, slot] of document.recoverySlots.entries()) {
      if (slotIds.has(slot.id)) {
        context.addIssue({
          code: 'custom',
          message: 'Local key slot IDs must be unique',
          path: ['recoverySlots', index, 'id'],
        });
      }
      slotIds.add(slot.id);
      if (slot.keyVersion !== document.currentKeyVersion) {
        context.addIssue({
          code: 'custom',
          message: 'Local recovery slot key version does not match the vault',
          path: ['recoverySlots', index, 'keyVersion'],
        });
      }
      if (slot.wrappedRootKey.aad.vaultId !== document.id) {
        context.addIssue({
          code: 'custom',
          message: 'Local recovery slot belongs to another vault',
          path: ['recoverySlots', index, 'wrappedRootKey', 'aad', 'vaultId'],
        });
      }
      if (slot.wrappedRootKey.aad.schemaVersion !== document.schemaVersion) {
        context.addIssue({
          code: 'custom',
          message: 'Local recovery slot schema version does not match the vault',
          path: ['recoverySlots', index, 'wrappedRootKey', 'aad', 'schemaVersion'],
        });
      }
      if (slot.state !== 'active' && slot.state !== 'revoked') {
        context.addIssue({
          code: 'custom',
          message: 'Local recovery slots must be active or revoked',
          path: ['recoverySlots', index, 'state'],
        });
      }
    }

    const aad = document.encryptedPayload.aad;
    if (
      aad.revision === undefined ||
      aad.metadataDigest === undefined ||
      aad.revision !== document.revision
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Local vault payload metadata binding is invalid',
        path: ['encryptedPayload', 'aad'],
      });
    }
    if (
      aad.vaultId !== document.id ||
      aad.entityId !== document.id ||
      aad.schemaVersion !== document.schemaVersion ||
      aad.keyVersion !== document.currentKeyVersion
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Local vault payload has invalid associated data',
        path: ['encryptedPayload', 'aad'],
      });
    }
  });

export type LocalVaultFormat = z.infer<typeof localVaultFormatSchema>;
export type LocalVaultValue = z.infer<typeof localVaultValueSchema>;
export type LocalVaultPayload = z.infer<typeof localVaultPayloadSchema>;
export type LocalRecoveryKeySlot = z.infer<typeof localRecoveryKeySlotSchema>;
export type LocalVaultDocument = z.infer<typeof localVaultDocumentSchema>;
