import {
  databaseIdSchema,
  databaseRevisionSchema,
  databaseVaultDocumentSchema,
  encryptedDatabaseDocumentSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type DatabaseId,
  type DatabaseRevision,
  type DatabaseVaultDocument,
  type EncryptedDatabaseDocument,
  type VaultId,
  type VaultRevision,
} from '@kavrix/schemas';

const TIMESTAMP = '2026-08-19T00:00:00.000Z';
const DIGEST = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const NONCE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const AUTHENTICATION_TAG = 'AAAAAAAAAAAAAAAAAAAAAA';
const CIPHERTEXT = 'AQID';
const PORTABLE_SALT = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export function makeDatabaseId(value: string): DatabaseId {
  return databaseIdSchema.parse(value);
}

export function makeVaultId(value: string): VaultId {
  return vaultIdSchema.parse(value);
}

export function databaseRevision(value: number): DatabaseRevision {
  return databaseRevisionSchema.parse(value);
}

export function vaultRevision(value: number): VaultRevision {
  return vaultRevisionSchema.parse(value);
}

export function databaseDocument(
  id: DatabaseId,
  revision: DatabaseRevision,
): EncryptedDatabaseDocument {
  return encryptedDatabaseDocumentSchema.parse({
    format: 'kavrix-encrypted-database',
    version: 1,
    id,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    keySlot: {
      slotVersion: 1,
      id: 'slot.database-owner',
      type: 'portable-key',
      state: 'active',
      keyVersion: 1,
      derivation: {
        algorithm: 'hkdf-sha256',
        version: 1,
        salt: PORTABLE_SALT,
        context: 'kavrix/database-root-wrap/v1',
        outputLength: 32,
      },
      wrappedDatabaseRoot: databaseEnvelope(
        id,
        'wrapped-database-root',
        'slot.database-owner',
        'database-root',
        databaseRevision(0),
      ),
      createdAt: TIMESTAMP,
    },
    recoverySlots: [],
    revision,
    encryptedCatalog: databaseEnvelope(id, 'database-catalog', id, 'catalog', revision),
    catalogMetadataDigest: DIGEST,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
}

export function vaultDocument(
  databaseId: DatabaseId,
  id: VaultId,
  databaseRevisionValue: DatabaseRevision,
  revision: VaultRevision,
): DatabaseVaultDocument {
  return databaseVaultDocumentSchema.parse({
    databaseId,
    id,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    databaseRevision: databaseRevisionValue,
    revision,
    wrappedVaultRoot: databaseEnvelope(
      databaseId,
      'wrapped-vault-root',
      id,
      'vault-root',
      databaseRevisionValue,
      id,
    ),
    encryptedPayload: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: NONCE,
      ciphertext: CIPHERTEXT,
      authenticationTag: AUTHENTICATION_TAG,
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId: id,
        entityType: 'vault-preferences',
        entityId: id,
        purpose: 'vault-preferences',
        revision,
        metadataDigest: DIGEST,
      },
      keyVersion: 1,
    },
    payloadMetadataDigest: DIGEST,
    createdAt: TIMESTAMP,
    updatedAt: TIMESTAMP,
  });
}

function databaseEnvelope(
  databaseId: DatabaseId,
  entityType: 'database-catalog' | 'wrapped-database-root' | 'wrapped-vault-root',
  entityId: DatabaseId | VaultId | 'slot.database-owner',
  purpose: 'catalog' | 'database-root' | 'vault-root',
  revision: DatabaseRevision,
  vaultId?: VaultId,
): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: NONCE,
    ciphertext: CIPHERTEXT,
    authenticationTag: AUTHENTICATION_TAG,
    aad: {
      version: 1,
      databaseId,
      entityType,
      entityId,
      purpose,
      schemaVersion: 1,
      keyVersion: 1,
      revision,
      ...(vaultId === undefined ? {} : { vaultId }),
      metadataDigest: DIGEST,
    },
    keyVersion: 1,
  };
}
