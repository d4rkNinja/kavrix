import { z } from 'zod';

import {
  AEAD_AUTHENTICATION_TAG_BASE64URL_CHARS,
  AEAD_NONCE_BASE64URL_CHARS,
  aeadEnvelopeSchema,
} from './encrypted-records.js';
import { databaseIdSchema, keySlotIdSchema, vaultIdSchema } from './identifiers.js';
import {
  base64UrlSchema,
  envelopeVersionSchema,
  keySlotVersionSchema,
  keyVersionSchema,
  sha256DigestSchema,
  supportedCryptographicVersionSchema,
  supportedSchemaVersionSchema,
  timestampSchema,
  vaultRevisionSchema,
} from './primitives.js';

export const DATABASE_CONTAINER_FORMAT = 'kavrix-encrypted-database';
export const FILE_DATABASE_CONTAINER_FORMAT = 'kavrix-file-database-container';
export const CURRENT_DATABASE_CONTAINER_VERSION = 1;
export const MAX_DATABASE_RECOVERY_SLOTS = 32;
export const MAX_DATABASE_VAULTS = 1_000;

export const databaseRevisionSchema = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER)
  .brand<'DatabaseRevision'>();

const opaqueDatabaseEntityIdSchema = z.union([
  databaseIdSchema,
  vaultIdSchema,
  keySlotIdSchema,
]);

export const databaseAssociatedDataSchema = z
  .object({
    version: z.literal(1),
    databaseId: databaseIdSchema,
    entityType: z.enum([
      'database-catalog',
      'wrapped-database-root',
      'wrapped-vault-root',
    ]),
    entityId: opaqueDatabaseEntityIdSchema,
    purpose: z.enum(['catalog', 'database-root', 'vault-root']),
    schemaVersion: supportedSchemaVersionSchema,
    keyVersion: keyVersionSchema,
    revision: databaseRevisionSchema,
    vaultId: vaultIdSchema.optional(),
    metadataDigest: sha256DigestSchema,
  })
  .strict()
  .superRefine((associatedData, context) => {
    const invalidRelation =
      (associatedData.entityType === 'database-catalog' &&
        (associatedData.purpose !== 'catalog' ||
          associatedData.entityId !== associatedData.databaseId ||
          associatedData.vaultId !== undefined)) ||
      (associatedData.entityType === 'wrapped-database-root' &&
        (associatedData.purpose !== 'database-root' ||
          !keySlotIdSchema.safeParse(associatedData.entityId).success ||
          associatedData.vaultId !== undefined)) ||
      (associatedData.entityType === 'wrapped-vault-root' &&
        (associatedData.purpose !== 'vault-root' ||
          !vaultIdSchema.safeParse(associatedData.entityId).success ||
          associatedData.vaultId === undefined ||
          associatedData.entityId !== associatedData.vaultId));

    if (invalidRelation) {
      context.addIssue({
        code: 'custom',
        message:
          'Database associated data has an invalid entity, purpose, or identity binding',
      });
    }
  });

export const databaseAeadEnvelopeSchema = z
  .object({
    version: envelopeVersionSchema,
    algorithm: z.literal('xchacha20-poly1305-ietf'),
    nonce: base64UrlSchema,
    ciphertext: base64UrlSchema,
    authenticationTag: base64UrlSchema,
    aad: databaseAssociatedDataSchema,
    keyVersion: keyVersionSchema,
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
    if (envelope.keyVersion !== envelope.aad.keyVersion) {
      context.addIssue({
        code: 'custom',
        message: 'Envelope key version must be authenticated in associated data',
        path: ['keyVersion'],
      });
    }
  });

const databaseCatalogVaultSchema = z
  .object({
    id: vaultIdSchema,
    label: z.string().trim().min(1).max(256),
    createdAt: timestampSchema,
  })
  .strict();

export const databaseCatalogPayloadSchema = z
  .object({
    label: z.string().trim().min(1).max(256),
    vaults: z.array(databaseCatalogVaultSchema).max(MAX_DATABASE_VAULTS),
  })
  .strict()
  .superRefine((catalog, context) => {
    const vaultIds = new Set<string>();
    for (const [index, vault] of catalog.vaults.entries()) {
      if (vaultIds.has(vault.id)) {
        context.addIssue({
          code: 'custom',
          path: ['vaults', index, 'id'],
          message: 'Database catalog vault IDs must be unique',
        });
      }
      vaultIds.add(vault.id);
    }
  });

const databasePortableKeyDerivationSchema = z
  .object({
    algorithm: z.literal('hkdf-sha256'),
    version: z.literal(1),
    salt: base64UrlSchema.length(43),
    context: z.literal('kavrix/database-root-wrap/v1'),
    outputLength: z.literal(32),
  })
  .strict();

const databaseRecoveryKeyDerivationSchema = z
  .object({
    algorithm: z.literal('hkdf-sha256'),
    version: z.literal(1),
    salt: base64UrlSchema.length(43),
    context: z.literal('kavrix/database-recovery-wrap/v1'),
    outputLength: z.literal(32),
  })
  .strict();

const databaseKeySlotBaseSchema = z.object({
  slotVersion: keySlotVersionSchema,
  id: keySlotIdSchema,
  state: z.enum(['active', 'revoked']),
  keyVersion: keyVersionSchema,
  wrappedDatabaseRoot: databaseAeadEnvelopeSchema,
  createdAt: timestampSchema,
  revokedAt: timestampSchema.optional(),
});

export const databasePortableKeySlotSchema = databaseKeySlotBaseSchema
  .extend({
    type: z.literal('portable-key'),
    state: z.literal('active'),
    derivation: databasePortableKeyDerivationSchema,
  })
  .strict()
  .superRefine((slot, context) => {
    if (slot.revokedAt !== undefined) {
      context.addIssue({
        code: 'custom',
        path: ['revokedAt'],
        message:
          'Active database portable-key slots cannot have a revocation timestamp',
      });
    }
    validateDatabaseRootSlotBinding(slot, context);
  });

export const databaseRecoverySlotSchema = databaseKeySlotBaseSchema
  .extend({
    type: z.literal('recovery-key'),
    derivation: databaseRecoveryKeyDerivationSchema,
  })
  .strict()
  .superRefine((slot, context) => {
    if (slot.state === 'revoked' && slot.revokedAt === undefined) {
      context.addIssue({
        code: 'custom',
        path: ['revokedAt'],
        message: 'Revoked database recovery slots require a timestamp',
      });
    }
    if (slot.state === 'active' && slot.revokedAt !== undefined) {
      context.addIssue({
        code: 'custom',
        path: ['revokedAt'],
        message: 'Active database recovery slots cannot have a revocation timestamp',
      });
    }
    validateDatabaseRootSlotBinding(slot, context);
  });

export const encryptedDatabaseDocumentSchema = z
  .object({
    format: z.literal(DATABASE_CONTAINER_FORMAT),
    version: z.literal(CURRENT_DATABASE_CONTAINER_VERSION),
    id: databaseIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    cryptographicVersion: supportedCryptographicVersionSchema,
    currentKeyVersion: keyVersionSchema,
    keySlot: databasePortableKeySlotSchema,
    recoverySlots: z.array(databaseRecoverySlotSchema).max(MAX_DATABASE_RECOVERY_SLOTS),
    revision: databaseRevisionSchema,
    encryptedCatalog: databaseAeadEnvelopeSchema,
    catalogMetadataDigest: sha256DigestSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((database, context) => {
    if (database.keySlot.keyVersion !== database.currentKeyVersion) {
      context.addIssue({
        code: 'custom',
        path: ['keySlot', 'keyVersion'],
        message:
          'Database portable-key slot version must match the current key version',
      });
    }
    if (database.keySlot.wrappedDatabaseRoot.aad.databaseId !== database.id) {
      context.addIssue({
        code: 'custom',
        path: ['keySlot', 'wrappedDatabaseRoot', 'aad', 'databaseId'],
        message: 'Database portable-key slot belongs to another database',
      });
    }

    const keySlotIds = new Set<string>([database.keySlot.id]);
    for (const [index, slot] of database.recoverySlots.entries()) {
      if (keySlotIds.has(slot.id)) {
        context.addIssue({
          code: 'custom',
          path: ['recoverySlots', index, 'id'],
          message: 'Database key slot IDs must be unique',
        });
      }
      keySlotIds.add(slot.id);
      if (slot.keyVersion !== database.currentKeyVersion) {
        context.addIssue({
          code: 'custom',
          path: ['recoverySlots', index, 'keyVersion'],
          message: 'Database recovery slot version must match the current key version',
        });
      }
      if (slot.wrappedDatabaseRoot.aad.databaseId !== database.id) {
        context.addIssue({
          code: 'custom',
          path: ['recoverySlots', index, 'wrappedDatabaseRoot', 'aad', 'databaseId'],
          message: 'Database recovery slot belongs to another database',
        });
      }
    }

    const catalog = database.encryptedCatalog;
    if (
      catalog.aad.databaseId !== database.id ||
      catalog.aad.schemaVersion !== database.schemaVersion ||
      catalog.aad.keyVersion !== database.currentKeyVersion ||
      catalog.aad.revision !== database.revision ||
      catalog.aad.metadataDigest !== database.catalogMetadataDigest
    ) {
      context.addIssue({
        code: 'custom',
        path: ['encryptedCatalog', 'aad'],
        message: 'Encrypted database catalog has invalid associated data',
      });
    }
  });

export const databaseVaultDocumentSchema = z
  .object({
    databaseId: databaseIdSchema,
    id: vaultIdSchema,
    schemaVersion: supportedSchemaVersionSchema,
    cryptographicVersion: supportedCryptographicVersionSchema,
    currentKeyVersion: keyVersionSchema,
    databaseRevision: databaseRevisionSchema,
    revision: vaultRevisionSchema,
    wrappedVaultRoot: databaseAeadEnvelopeSchema,
    encryptedPayload: aeadEnvelopeSchema,
    payloadMetadataDigest: sha256DigestSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((vault, context) => {
    const wrappedRoot = vault.wrappedVaultRoot;
    if (
      wrappedRoot.aad.databaseId !== vault.databaseId ||
      wrappedRoot.aad.vaultId !== vault.id ||
      wrappedRoot.aad.schemaVersion !== vault.schemaVersion ||
      wrappedRoot.aad.keyVersion !== vault.currentKeyVersion ||
      wrappedRoot.aad.revision !== vault.databaseRevision
    ) {
      context.addIssue({
        code: 'custom',
        path: ['wrappedVaultRoot', 'aad'],
        message: 'Wrapped vault root has invalid associated data',
      });
    }
    const payload = vault.encryptedPayload;
    if (
      payload.aad.vaultId !== vault.id ||
      payload.aad.entityId !== vault.id ||
      payload.aad.schemaVersion !== vault.schemaVersion ||
      payload.aad.keyVersion !== vault.currentKeyVersion ||
      payload.aad.revision !== vault.revision ||
      payload.aad.metadataDigest !== vault.payloadMetadataDigest
    ) {
      context.addIssue({
        code: 'custom',
        path: ['encryptedPayload', 'aad'],
        message: 'Encrypted vault payload has invalid associated data',
      });
    }
  });

export const fileDatabaseContainerSchema = z
  .object({
    format: z.literal(FILE_DATABASE_CONTAINER_FORMAT),
    version: z.literal(CURRENT_DATABASE_CONTAINER_VERSION),
    database: encryptedDatabaseDocumentSchema,
    vaults: z.record(vaultIdSchema, databaseVaultDocumentSchema),
  })
  .strict()
  .superRefine((container, context) => {
    const entries = Object.entries(container.vaults);
    if (entries.length > MAX_DATABASE_VAULTS) {
      context.addIssue({
        code: 'custom',
        path: ['vaults'],
        message: 'Database container contains too many vaults',
      });
    }
    for (const [vaultId, vault] of entries) {
      if (vaultId !== vault.id) {
        context.addIssue({
          code: 'custom',
          path: ['vaults', vaultId],
          message: 'Database container vault map keys must match vault IDs',
        });
      }
      if (vault.databaseId !== container.database.id) {
        context.addIssue({
          code: 'custom',
          path: ['vaults', vaultId, 'databaseId'],
          message: 'Database container vault belongs to another database',
        });
      }
    }
  });

function validateDatabaseRootSlotBinding(
  slot: {
    id: string;
    keyVersion: number;
    wrappedDatabaseRoot: z.infer<typeof databaseAeadEnvelopeSchema>;
  },
  context: z.core.$RefinementCtx,
): void {
  const envelope = slot.wrappedDatabaseRoot;
  if (envelope.aad.entityId !== slot.id) {
    context.addIssue({
      code: 'custom',
      path: ['wrappedDatabaseRoot', 'aad', 'entityId'],
      message: 'Database root slot envelope is bound to a different slot',
    });
  }
  if (envelope.keyVersion !== slot.keyVersion) {
    context.addIssue({
      code: 'custom',
      path: ['wrappedDatabaseRoot', 'keyVersion'],
      message: 'Database root slot envelope version must match its slot',
    });
  }
}

export type DatabaseRevision = z.infer<typeof databaseRevisionSchema>;
export type DatabaseAssociatedData = z.infer<typeof databaseAssociatedDataSchema>;
export type DatabaseAeadEnvelope = z.infer<typeof databaseAeadEnvelopeSchema>;
export type DatabaseCatalogPayload = z.infer<typeof databaseCatalogPayloadSchema>;
export type DatabasePortableKeySlot = z.infer<typeof databasePortableKeySlotSchema>;
export type DatabaseRecoverySlot = z.infer<typeof databaseRecoverySlotSchema>;
export type EncryptedDatabaseDocument = z.infer<typeof encryptedDatabaseDocumentSchema>;
export type DatabaseVaultDocument = z.infer<typeof databaseVaultDocumentSchema>;
export type FileDatabaseContainer = z.infer<typeof fileDatabaseContainerSchema>;
