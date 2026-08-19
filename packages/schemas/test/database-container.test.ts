import { describe, expect, it } from 'vitest';

import {
  databaseAeadEnvelopeSchema,
  databaseAssociatedDataSchema,
  databaseCatalogPayloadSchema,
  databaseIdSchema,
  databaseVaultDocumentSchema,
  encryptedDatabaseDocumentSchema,
  fileDatabaseContainerSchema,
  profileIdSchema,
  vaultIdSchema,
} from '../src/index.js';

const timestamp = '2026-08-19T00:00:00.000Z';
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const nonce = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const tag = 'AAAAAAAAAAAAAAAAAAAAAA';
const ciphertext = 'AQID';
const portableSalt = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function databaseEnvelope(
  databaseId: string,
  entityType: 'database-catalog' | 'wrapped-database-root' | 'wrapped-vault-root',
  entityId: string,
  purpose: 'catalog' | 'database-root' | 'vault-root',
  revision = 1,
  vaultId?: string,
): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce,
    ciphertext,
    authenticationTag: tag,
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
      metadataDigest: digest,
    },
    keyVersion: 1,
  };
}

function databaseFixture(databaseId: string): Record<string, unknown> {
  const keySlotId = 'slot.database-owner';
  return {
    format: 'kavrix-encrypted-database',
    version: 1,
    id: databaseId,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    keySlot: {
      slotVersion: 1,
      id: keySlotId,
      type: 'portable-key',
      state: 'active',
      keyVersion: 1,
      derivation: {
        algorithm: 'hkdf-sha256',
        version: 1,
        salt: portableSalt,
        context: 'kavrix/database-root-wrap/v1',
        outputLength: 32,
      },
      wrappedDatabaseRoot: databaseEnvelope(
        databaseId,
        'wrapped-database-root',
        keySlotId,
        'database-root',
      ),
      createdAt: timestamp,
    },
    recoverySlots: [],
    revision: 1,
    encryptedCatalog: databaseEnvelope(
      databaseId,
      'database-catalog',
      databaseId,
      'catalog',
    ),
    catalogMetadataDigest: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function vaultFixture(databaseId: string, vaultId: string): Record<string, unknown> {
  return {
    databaseId,
    id: vaultId,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    databaseRevision: 1,
    revision: 1,
    wrappedVaultRoot: databaseEnvelope(
      databaseId,
      'wrapped-vault-root',
      vaultId,
      'vault-root',
      1,
      vaultId,
    ),
    encryptedPayload: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce,
      ciphertext,
      authenticationTag: tag,
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId,
        entityType: 'vault-preferences',
        entityId: vaultId,
        purpose: 'vault-preferences',
        revision: 1,
        metadataDigest: digest,
      },
      keyVersion: 1,
    },
    payloadMetadataDigest: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

describe('encrypted database container contracts', () => {
  const databaseId = databaseIdSchema.parse('db_01JTESTDATABASE');
  const vaultId = vaultIdSchema.parse('vault_01JPROJECTA');

  it('accepts one canonical database document and rejects unknown plaintext fields', () => {
    expect(profileIdSchema.parse('profile_01JLOCAL')).toBe('profile_01JLOCAL');
    expect(encryptedDatabaseDocumentSchema.parse(databaseFixture(databaseId))).toEqual(
      databaseFixture(databaseId),
    );
    expect(() =>
      encryptedDatabaseDocumentSchema.parse({
        ...databaseFixture(databaseId),
        plaintextLabel: 'production',
      }),
    ).toThrow();
  });

  it('rejects unsupported document versions and mismatched catalog revisions', () => {
    expect(
      encryptedDatabaseDocumentSchema.safeParse({
        ...databaseFixture(databaseId),
        version: 2,
      }).success,
    ).toBe(false);
    expect(
      encryptedDatabaseDocumentSchema.safeParse({
        ...databaseFixture(databaseId),
        encryptedCatalog: databaseEnvelope(
          databaseId,
          'database-catalog',
          databaseId,
          'catalog',
          2,
        ),
      }).success,
    ).toBe(false);
  });

  it('enforces the exact catalog, database-root, and vault-root AAD relations', () => {
    const validCatalog = databaseEnvelope(
      databaseId,
      'database-catalog',
      databaseId,
      'catalog',
    );
    const invalidCatalogs = [
      {
        ...validCatalog,
        aad: { ...(validCatalog['aad'] as object), purpose: 'database-root' },
      },
      {
        ...validCatalog,
        aad: { ...(validCatalog['aad'] as object), entityId: 'slot.database-owner' },
      },
      { ...validCatalog, aad: { ...(validCatalog['aad'] as object), vaultId } },
    ];
    for (const candidate of invalidCatalogs) {
      expect(databaseAeadEnvelopeSchema.safeParse(candidate).success).toBe(false);
    }

    const validRoot = databaseEnvelope(
      databaseId,
      'wrapped-database-root',
      'slot.database-owner',
      'database-root',
    );
    const invalidRoots = [
      { ...validRoot, aad: { ...(validRoot['aad'] as object), purpose: 'catalog' } },
      { ...validRoot, aad: { ...(validRoot['aad'] as object), vaultId } },
    ];
    for (const candidate of invalidRoots) {
      expect(databaseAeadEnvelopeSchema.safeParse(candidate).success).toBe(false);
    }
    expect(
      encryptedDatabaseDocumentSchema.safeParse({
        ...databaseFixture(databaseId),
        keySlot: {
          ...(databaseFixture(databaseId)['keySlot'] as object),
          wrappedDatabaseRoot: databaseEnvelope(
            databaseId,
            'wrapped-database-root',
            'slot.different',
            'database-root',
          ),
        },
      }).success,
    ).toBe(false);

    const validVaultRoot = databaseEnvelope(
      databaseId,
      'wrapped-vault-root',
      vaultId,
      'vault-root',
      1,
      vaultId,
    );
    const invalidVaultRoots = [
      {
        ...validVaultRoot,
        aad: { ...(validVaultRoot['aad'] as object), purpose: 'database-root' },
      },
      {
        ...validVaultRoot,
        aad: { ...(validVaultRoot['aad'] as object), entityId: databaseId },
      },
      {
        ...validVaultRoot,
        aad: { ...(validVaultRoot['aad'] as object), vaultId: 'vault_01JOTHER' },
      },
    ];
    for (const candidate of invalidVaultRoots) {
      expect(databaseAeadEnvelopeSchema.safeParse(candidate).success).toBe(false);
    }
  });

  it('rejects cross-database vaults and invalid vault envelope bindings', () => {
    expect(() =>
      databaseVaultDocumentSchema.parse({
        ...vaultFixture(databaseId, vaultId),
        databaseId: databaseIdSchema.parse('db_01JOTHERDATABASE'),
      }),
    ).toThrow();
    expect(
      databaseVaultDocumentSchema.safeParse({
        ...vaultFixture(databaseId, vaultId),
        wrappedVaultRoot: databaseEnvelope(
          databaseId,
          'wrapped-vault-root',
          'vault_01JOTHER',
          'vault-root',
          1,
          'vault_01JOTHER',
        ),
      }).success,
    ).toBe(false);
  });

  it('keeps catalog IDs unique and bounded without exposing labels', () => {
    const catalog = {
      label: 'Production',
      vaults: [{ id: vaultId, label: 'API', createdAt: timestamp }],
    };
    expect(databaseCatalogPayloadSchema.safeParse(catalog).success).toBe(true);
    expect(
      databaseCatalogPayloadSchema.safeParse({
        ...catalog,
        vaults: [
          ...catalog.vaults,
          { id: vaultId, label: 'Duplicate', createdAt: timestamp },
        ],
      }).success,
    ).toBe(false);
    expect(
      databaseCatalogPayloadSchema.safeParse({
        ...catalog,
        vaults: Array.from({ length: 1_001 }, (_, index) => ({
          id: `vault_${String(index)}`,
          label: `Vault ${String(index)}`,
          createdAt: timestamp,
        })),
      }).success,
    ).toBe(false);
  });

  it('rejects malformed or oversized database ciphertext and noncanonical base64url', () => {
    expect(
      databaseAeadEnvelopeSchema.safeParse({
        ...databaseEnvelope(databaseId, 'database-catalog', databaseId, 'catalog'),
        ciphertext: 'A'.repeat(22_369_633),
      }).success,
    ).toBe(false);
    expect(
      databaseAeadEnvelopeSchema.safeParse({
        ...databaseEnvelope(databaseId, 'database-catalog', databaseId, 'catalog'),
        ciphertext: 'AB',
      }).success,
    ).toBe(false);
  });

  it('requires file-container map keys to match their opaque vault documents', () => {
    expect(
      fileDatabaseContainerSchema.safeParse({
        format: 'kavrix-file-database-container',
        version: 1,
        database: databaseFixture(databaseId),
        vaults: { [vaultId]: vaultFixture(databaseId, vaultId) },
      }).success,
    ).toBe(true);
    expect(
      fileDatabaseContainerSchema.safeParse({
        format: 'kavrix-file-database-container',
        version: 1,
        database: databaseFixture(databaseId),
        vaults: { vault_01JDIFFERENT: vaultFixture(databaseId, vaultId) },
      }).success,
    ).toBe(false);
  });

  it('keeps standalone AAD strict', () => {
    expect(
      databaseAssociatedDataSchema.safeParse({
        version: 1,
        databaseId,
        entityType: 'database-catalog',
        entityId: databaseId,
        purpose: 'catalog',
        schemaVersion: 1,
        keyVersion: 1,
        revision: 1,
        metadataDigest: digest,
        unexpected: true,
      }).success,
    ).toBe(false);
  });
});
