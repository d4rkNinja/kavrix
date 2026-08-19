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
import { describe, expect, it } from 'vitest';

import {
  EncryptedDatabaseStoreError,
  type CreateVaultInput,
  type DeleteVaultInput,
  type EncryptedDatabaseStore,
  type EncryptedDatabaseStoreErrorCode,
  type UpdateVaultInput,
} from '../src/encrypted-database-store.js';

const TIMESTAMP = '2026-08-19T00:00:00.000Z';
const DIGEST = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const NONCE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const AUTHENTICATION_TAG = 'AAAAAAAAAAAAAAAAAAAAAA';
const CIPHERTEXT = 'AQID';
const PORTABLE_SALT = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export type EncryptedDatabaseStoreFactory = () => Promise<EncryptedDatabaseStore>;

/**
 * Reusable behavioral contract for opaque database-scoped persistence adapters.
 *
 * Adapters persist schema-validated encrypted documents only. The tests never
 * inspect or decrypt their encrypted fields.
 */
export function defineEncryptedDatabaseStoreContractTests(
  name: string,
  createStore: EncryptedDatabaseStoreFactory,
): void {
  describe(name, () => {
    it('creates database documents, returns detached parsed values, and enforces exact revision increments', async () => {
      const store = await createStore();
      const databaseId = makeDatabaseId('db_01JCONTRACTDATABASE');
      const initial = databaseDocument(databaseId, databaseRevision(0));

      await store.ping();
      await store.createDatabase(initial);
      await expectStoreError(store.createDatabase(initial), 'exists');
      initial.encryptedCatalog.ciphertext = 'BAUG';

      const storedInitial = await store.getDatabase(databaseId);
      expect(storedInitial).not.toBeNull();
      expect(storedInitial?.encryptedCatalog.ciphertext).toBe(CIPHERTEXT);

      const firstUpdate = databaseDocument(databaseId, databaseRevision(1));
      await expectStoreError(
        store.updateDatabase(firstUpdate, databaseRevision(1)),
        'invalid',
      );
      await store.updateDatabase(firstUpdate, databaseRevision(0));
      expect((await store.getDatabase(databaseId))?.revision).toBe(databaseRevision(1));

      await expectStoreError(
        store.updateDatabase(
          databaseDocument(databaseId, databaseRevision(1)),
          databaseRevision(0),
        ),
        'conflict',
      );
      await expectStoreError(
        store.updateDatabase(
          databaseDocument(databaseId, databaseRevision(3)),
          databaseRevision(1),
        ),
        'invalid',
      );
      await expectStoreError(
        store.updateDatabase(
          databaseDocument(
            makeDatabaseId('db_01JMISSINGDATABASE'),
            databaseRevision(1),
          ),
          databaseRevision(0),
        ),
        'conflict',
      );
      await store.close();
    });

    it('keeps vaults bound to their database, sorted, detached, and unique', async () => {
      const store = await createStore();
      const databaseId = makeDatabaseId('db_01JVAULTBINDING');
      const firstVaultId = makeVaultId('vault_01JALPHA');
      const secondVaultId = makeVaultId('vault_01JZULU');
      await store.createDatabase(databaseDocument(databaseId, databaseRevision(0)));

      const firstDatabaseUpdate = databaseDocument(databaseId, databaseRevision(1));
      await expectStoreError(
        store.createVault({
          database: firstDatabaseUpdate,
          expectedDatabaseRevision: databaseRevision(0),
          vault: vaultDocument(
            makeDatabaseId('db_01JOTHERDATABASE'),
            secondVaultId,
            databaseRevision(1),
            vaultRevision(0),
          ),
        }),
        'invalid',
      );

      const secondVault = vaultDocument(
        databaseId,
        secondVaultId,
        databaseRevision(1),
        vaultRevision(0),
      );
      await store.createVault({
        database: firstDatabaseUpdate,
        expectedDatabaseRevision: databaseRevision(0),
        vault: secondVault,
      });

      const secondDatabaseUpdate = databaseDocument(databaseId, databaseRevision(2));
      await store.createVault({
        database: secondDatabaseUpdate,
        expectedDatabaseRevision: databaseRevision(1),
        vault: vaultDocument(
          databaseId,
          firstVaultId,
          databaseRevision(2),
          vaultRevision(0),
        ),
      });

      expect((await store.listVaults(databaseId)).map((vault) => vault.id)).toEqual([
        firstVaultId,
        secondVaultId,
      ]);
      expect(
        await store.getVault(makeDatabaseId('db_01JOTHERDATABASE'), firstVaultId),
      ).toBeNull();

      const storedVault = await store.getVault(databaseId, firstVaultId);
      expect(storedVault).not.toBeNull();
      if (storedVault !== null) {
        storedVault.encryptedPayload.ciphertext = 'BAUG';
      }
      expect(
        (await store.getVault(databaseId, firstVaultId))?.encryptedPayload.ciphertext,
      ).toBe(CIPHERTEXT);

      await expectStoreError(
        store.createVault({
          database: databaseDocument(databaseId, databaseRevision(3)),
          expectedDatabaseRevision: databaseRevision(2),
          vault: vaultDocument(
            databaseId,
            firstVaultId,
            databaseRevision(3),
            vaultRevision(0),
          ),
        }),
        'exists',
      );
      expect((await store.getDatabase(databaseId))?.revision).toBe(databaseRevision(2));
      await store.close();
    });

    it('compares vault revisions independently and rejects missing or stale mutations', async () => {
      const store = await createStore();
      const databaseId = makeDatabaseId('db_01JINDEPENDENTVAULTS');
      const vaultId = makeVaultId('vault_01JPROJECT');
      await store.createDatabase(databaseDocument(databaseId, databaseRevision(0)));
      await store.createVault({
        database: databaseDocument(databaseId, databaseRevision(1)),
        expectedDatabaseRevision: databaseRevision(0),
        vault: vaultDocument(
          databaseId,
          vaultId,
          databaseRevision(1),
          vaultRevision(0),
        ),
      });

      const updatedVault = vaultDocument(
        databaseId,
        vaultId,
        databaseRevision(1),
        vaultRevision(1),
      );
      await expectStoreError(
        store.updateVault({
          vault: updatedVault,
          expectedVaultRevision: vaultRevision(1),
        }),
        'invalid',
      );
      await store.updateVault({
        vault: updatedVault,
        expectedVaultRevision: vaultRevision(0),
      });
      expect((await store.getVault(databaseId, vaultId))?.revision).toBe(
        vaultRevision(1),
      );
      expect((await store.getDatabase(databaseId))?.revision).toBe(databaseRevision(1));

      await expectStoreError(
        store.updateVault({
          vault: vaultDocument(
            databaseId,
            vaultId,
            databaseRevision(1),
            vaultRevision(1),
          ),
          expectedVaultRevision: vaultRevision(0),
        }),
        'conflict',
      );
      await expectStoreError(
        store.updateVault({
          vault: vaultDocument(
            databaseId,
            makeVaultId('vault_01JMISSINGVAULT'),
            databaseRevision(1),
            vaultRevision(1),
          ),
          expectedVaultRevision: vaultRevision(0),
        }),
        'conflict',
      );
      await store.close();
    });

    it('atomically compares database and vault revisions before deletion', async () => {
      const store = await createStore();
      const databaseId = makeDatabaseId('db_01JDELETEVAULT');
      const vaultId = makeVaultId('vault_01JDELETE');
      await store.createDatabase(databaseDocument(databaseId, databaseRevision(0)));
      await store.createVault({
        database: databaseDocument(databaseId, databaseRevision(1)),
        expectedDatabaseRevision: databaseRevision(0),
        vault: vaultDocument(
          databaseId,
          vaultId,
          databaseRevision(1),
          vaultRevision(0),
        ),
      });

      const deleteInput = {
        database: databaseDocument(databaseId, databaseRevision(2)),
        expectedDatabaseRevision: databaseRevision(1),
        vaultId,
        expectedVaultRevision: vaultRevision(0),
      } satisfies DeleteVaultInput;
      await expectStoreError(
        store.deleteVault({ ...deleteInput, expectedVaultRevision: vaultRevision(1) }),
        'conflict',
      );
      await expectStoreError(
        store.deleteVault({
          ...deleteInput,
          database: databaseDocument(databaseId, databaseRevision(1)),
          expectedDatabaseRevision: databaseRevision(0),
        }),
        'conflict',
      );
      expect(await store.getVault(databaseId, vaultId)).not.toBeNull();
      expect((await store.getDatabase(databaseId))?.revision).toBe(databaseRevision(1));

      await store.deleteVault(deleteInput);
      expect(await store.getVault(databaseId, vaultId)).toBeNull();
      expect((await store.getDatabase(databaseId))?.revision).toBe(databaseRevision(2));
      await expectStoreError(store.deleteVault(deleteInput), 'conflict');
      await store.close();
    });

    it('fails closed after close and makes close idempotent', async () => {
      const store = await createStore();
      const databaseId = makeDatabaseId('db_01JCLOSEDSTORE');
      const vaultId = makeVaultId('vault_01JCLOSED');
      const database = databaseDocument(databaseId, databaseRevision(1));
      const vault = vaultDocument(
        databaseId,
        vaultId,
        databaseRevision(1),
        vaultRevision(1),
      );
      await store.close();
      await store.close();

      await expectStoreError(store.ping(), 'closed');
      await expectStoreError(store.getDatabase(databaseId), 'closed');
      await expectStoreError(store.listVaults(databaseId), 'closed');
      await expectStoreError(
        store.createDatabase(databaseDocument(databaseId, databaseRevision(0))),
        'closed',
      );
      await expectStoreError(
        store.updateDatabase(database, databaseRevision(0)),
        'closed',
      );
      await expectStoreError(store.getVault(databaseId, vaultId), 'closed');
      await expectStoreError(
        store.createVault({
          database,
          expectedDatabaseRevision: databaseRevision(0),
          vault: vaultDocument(
            databaseId,
            vaultId,
            databaseRevision(1),
            vaultRevision(0),
          ),
        }),
        'closed',
      );
      await expectStoreError(
        store.updateVault({ vault, expectedVaultRevision: vaultRevision(0) }),
        'closed',
      );
      await expectStoreError(
        store.deleteVault({
          database,
          expectedDatabaseRevision: databaseRevision(0),
          vaultId,
          expectedVaultRevision: vaultRevision(0),
        }),
        'closed',
      );
    });
  });
}

class InMemoryEncryptedDatabaseStoreContractFixture implements EncryptedDatabaseStore {
  readonly #databases = new Map<string, EncryptedDatabaseDocument>();
  readonly #vaults = new Map<string, DatabaseVaultDocument>();
  #closed = false;

  async ping(): Promise<void> {
    this.#assertOpen();
  }

  async getDatabase(databaseId: DatabaseId): Promise<EncryptedDatabaseDocument | null> {
    this.#assertOpen();
    const document = this.#databases.get(databaseId);
    return document === undefined ? null : parseDatabaseDocument(document);
  }

  async createDatabase(document: EncryptedDatabaseDocument): Promise<void> {
    this.#assertOpen();
    const parsed = parseDatabaseDocument(document);
    if (this.#databases.has(parsed.id)) throw new EncryptedDatabaseStoreError('exists');
    this.#databases.set(parsed.id, parsed);
  }

  async updateDatabase(
    document: EncryptedDatabaseDocument,
    expectedRevision: DatabaseRevision,
  ): Promise<void> {
    this.#assertOpen();
    const parsed = parseDatabaseDocument(document);
    const expected = parseDatabaseRevision(expectedRevision);
    if (parsed.revision !== expected + 1)
      throw new EncryptedDatabaseStoreError('invalid');
    const current = this.#databases.get(parsed.id);
    if (current === undefined || current.revision !== expected) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    this.#databases.set(parsed.id, parsed);
  }

  async listVaults(databaseId: DatabaseId): Promise<readonly DatabaseVaultDocument[]> {
    this.#assertOpen();
    return [...this.#vaults.values()]
      .filter((vault) => vault.databaseId === databaseId)
      .sort((left, right) => compareOpaqueIds(left.id, right.id))
      .map((vault) => parseVaultDocument(vault));
  }

  async getVault(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<DatabaseVaultDocument | null> {
    this.#assertOpen();
    const vault = this.#vaults.get(vaultKey(databaseId, vaultId));
    return vault === undefined ? null : parseVaultDocument(vault);
  }

  async createVault(input: CreateVaultInput): Promise<void> {
    this.#assertOpen();
    const database = parseDatabaseDocument(input.database);
    const expectedDatabaseRevision = parseDatabaseRevision(
      input.expectedDatabaseRevision,
    );
    const vault = parseVaultDocument(input.vault);
    if (database.revision !== expectedDatabaseRevision + 1) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    if (
      vault.databaseId !== database.id ||
      vault.databaseRevision !== database.revision
    ) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    const current = this.#databases.get(database.id);
    if (current === undefined || current.revision !== expectedDatabaseRevision) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    const key = vaultKey(vault.databaseId, vault.id);
    if (this.#vaults.has(key)) throw new EncryptedDatabaseStoreError('exists');
    this.#databases.set(database.id, database);
    this.#vaults.set(key, vault);
  }

  async updateVault(input: UpdateVaultInput): Promise<void> {
    this.#assertOpen();
    const vault = parseVaultDocument(input.vault);
    const expectedVaultRevision = parseVaultRevision(input.expectedVaultRevision);
    if (vault.revision !== expectedVaultRevision + 1) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    const key = vaultKey(vault.databaseId, vault.id);
    const current = this.#vaults.get(key);
    if (current === undefined || current.revision !== expectedVaultRevision) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    this.#vaults.set(key, vault);
  }

  async deleteVault(input: DeleteVaultInput): Promise<void> {
    this.#assertOpen();
    const database = parseDatabaseDocument(input.database);
    const expectedDatabaseRevision = parseDatabaseRevision(
      input.expectedDatabaseRevision,
    );
    const expectedVaultRevision = parseVaultRevision(input.expectedVaultRevision);
    if (database.revision !== expectedDatabaseRevision + 1) {
      throw new EncryptedDatabaseStoreError('invalid');
    }
    const currentDatabase = this.#databases.get(database.id);
    if (
      currentDatabase === undefined ||
      currentDatabase.revision !== expectedDatabaseRevision
    ) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    const key = vaultKey(database.id, input.vaultId);
    const currentVault = this.#vaults.get(key);
    if (currentVault === undefined || currentVault.revision !== expectedVaultRevision) {
      throw new EncryptedDatabaseStoreError('conflict');
    }
    this.#databases.set(database.id, database);
    this.#vaults.delete(key);
  }

  async close(): Promise<void> {
    this.#closed = true;
  }

  #assertOpen(): void {
    if (this.#closed) throw new EncryptedDatabaseStoreError('closed');
  }
}

defineEncryptedDatabaseStoreContractTests(
  'EncryptedDatabaseStore contract fixture',
  async () => new InMemoryEncryptedDatabaseStoreContractFixture(),
);

function makeDatabaseId(value: string): DatabaseId {
  return databaseIdSchema.parse(value);
}

function makeVaultId(value: string): VaultId {
  return vaultIdSchema.parse(value);
}

function databaseRevision(value: number): DatabaseRevision {
  return databaseRevisionSchema.parse(value);
}

function vaultRevision(value: number): VaultRevision {
  return vaultRevisionSchema.parse(value);
}

function databaseDocument(
  id: DatabaseId,
  revision: DatabaseRevision,
): EncryptedDatabaseDocument {
  return parseDatabaseDocument({
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

function vaultDocument(
  databaseId: DatabaseId,
  id: VaultId,
  databaseRevision: DatabaseRevision,
  revision: VaultRevision,
): DatabaseVaultDocument {
  return parseVaultDocument({
    databaseId,
    id,
    schemaVersion: 1,
    cryptographicVersion: 1,
    currentKeyVersion: 1,
    databaseRevision,
    revision,
    wrappedVaultRoot: databaseEnvelope(
      databaseId,
      'wrapped-vault-root',
      id,
      'vault-root',
      databaseRevision,
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

function parseDatabaseDocument(value: unknown): EncryptedDatabaseDocument {
  try {
    return encryptedDatabaseDocumentSchema.parse(structuredClone(value));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseVaultDocument(value: unknown): DatabaseVaultDocument {
  try {
    return databaseVaultDocumentSchema.parse(structuredClone(value));
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseDatabaseRevision(value: unknown): DatabaseRevision {
  try {
    return databaseRevisionSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function parseVaultRevision(value: unknown): VaultRevision {
  try {
    return vaultRevisionSchema.parse(value);
  } catch {
    throw new EncryptedDatabaseStoreError('invalid');
  }
}

function vaultKey(databaseId: DatabaseId, vaultId: VaultId): string {
  return `${databaseId}\u0000${vaultId}`;
}

function compareOpaqueIds(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function expectStoreError(
  operation: Promise<unknown>,
  code: EncryptedDatabaseStoreErrorCode,
): Promise<void> {
  try {
    await operation;
    throw new Error('Expected a storage error');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(EncryptedDatabaseStoreError);
    const storageError = error as EncryptedDatabaseStoreError;
    expect(storageError.code).toBe(code);
    for (const forbidden of [
      'db_01J',
      'vault_01J',
      '/private/',
      'Mongo',
      'ciphertext',
      CIPHERTEXT,
    ]) {
      expect(storageError.message).not.toContain(forbidden);
    }
  }
}
