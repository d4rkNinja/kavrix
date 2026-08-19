import { access, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  databaseRevisionAnchorPath,
  deleteSecureFile,
  readDatabaseKeyFileBinding,
  writeDatabaseRevisionAnchor,
  type DatabaseRevisionAnchor,
} from '@kavrix/key-files';
import {
  databaseIdSchema,
  sha256DigestSchema,
  type DatabaseId,
  type DatabaseRevision,
  type DatabaseVaultDocument,
  type EncryptedDatabaseDocument,
  type VaultId,
  type VaultRevision,
} from '@kavrix/schemas';
import {
  EncryptedDatabaseStoreError,
  type CreateVaultInput,
  type DeleteVaultInput,
  type EncryptedDatabaseStore,
  type UpdateVaultInput,
} from '@kavrix/storage';
import { describe, expect, it } from 'vitest';

import { DatabaseSession } from '../src/database-session.js';

const PASSPHRASE = Buffer.from('correct horse battery staple', 'utf8');

describe('DatabaseSession', () => {
  it('initializes, authenticates an exact anchor, and manages two independent vaults', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    const initialized = await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      label: 'database-label-canary',
    });

    expect(initialized.databaseId).toMatch(/^db_/u);
    const session = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    const first = await session.createVault('alpha-label-canary');
    const second = await session.createVault('beta-label-canary');
    expect((await session.listVaults()).map((entry) => entry.label)).toEqual([
      'alpha-label-canary',
      'beta-label-canary',
    ]);
    await session.renameVault(second.id, 'renamed-label-canary');
    expect((await session.getVault(second.id)).label).toBe('renamed-label-canary');

    const firstDocument = await session.getVaultDocument(first.id);
    await session.updateVault({
      ...firstDocument,
      revision: (firstDocument.revision + 1) as VaultRevision,
      updatedAt: new Date().toISOString(),
    });
    expect((await session.getVaultDocument(second.id)).revision).toBe(0);
    await expect(session.createVault('renamed-label-canary')).rejects.toMatchObject({
      code: 'duplicate',
    });
    await session.close();

    const outer = JSON.stringify({
      database: await store.getDatabase(initialized.databaseId),
      vaults: await store.listVaults(initialized.databaseId),
    });
    expect(outer).not.toContain('database-label-canary');
    expect(outer).not.toContain('alpha-label-canary');
    expect(outer).not.toContain('renamed-label-canary');
  });

  it('fails generically on a wrong passphrase before catalog decryption', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      label: 'secret-database-name',
    });
    await expect(
      DatabaseSession.open({
        store,
        keyFile,
        passphrase: Buffer.from('incorrect passphrase value', 'utf8'),
      }),
    ).rejects.toMatchObject({ code: 'authentication' });
  });

  it('retains the recovery-capable key when datastore rollback is ambiguous', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    store.failList = true;
    await expect(
      DatabaseSession.initialize({
        store,
        keyFile,
        passphrase: PASSPHRASE,
        label: 'database',
      }),
    ).rejects.toBeInstanceOf(AggregateError);
    await expect(access(keyFile)).resolves.toBeUndefined();
    expect((await readDatabaseKeyFileBinding(keyFile)).databaseId).toBe(
      store.database?.id,
    );
  });

  it('rolls back owned key and datastore artifacts when rollback is proven', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    store.failList = true;
    await expect(
      DatabaseSession.initialize({
        store,
        keyFile,
        passphrase: PASSPHRASE,
        label: 'database',
        rollbackDatabase: async () => {
          store.database = null;
        },
      }),
    ).rejects.toMatchObject({ code: 'operation' });
    await expect(access(keyFile)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(store.database).toBeNull();
  });

  it('rejects catalog tampering and missing, lower, or forked exact anchors', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const make = async (name: string) => {
      const store = new MemoryDatabaseStore();
      const keyFile = join(directory, `${name}.kavrix-db-key`);
      const initialized = await DatabaseSession.initialize({
        store,
        keyFile,
        passphrase: PASSPHRASE,
        label: 'database',
      });
      return { store, keyFile, initialized };
    };

    const tampered = await make('tampered');
    if (tampered.store.database === null) throw new Error('missing fixture');
    tampered.store.database.encryptedCatalog.authenticationTag =
      'AAAAAAAAAAAAAAAAAAAAAA';
    await expect(
      DatabaseSession.open({
        store: tampered.store,
        keyFile: tampered.keyFile,
        passphrase: PASSPHRASE,
      }),
    ).rejects.toMatchObject({ code: 'authentication' });

    const missing = await make('missing');
    await deleteSecureFile(databaseRevisionAnchorPath(missing.keyFile));
    await expect(
      DatabaseSession.open({
        store: missing.store,
        keyFile: missing.keyFile,
        passphrase: PASSPHRASE,
      }),
    ).rejects.toMatchObject({ code: 'authentication' });

    for (const kind of ['lower', 'fork', 'missing-head'] as const) {
      const fixture = await make(kind);
      const roots: Uint8Array[] = [];
      const session = await DatabaseSession.open({
        store: fixture.store,
        keyFile: fixture.keyFile,
        passphrase: PASSPHRASE,
        onRootKeyOwned: (key) => roots.push(key),
      });
      const priorDatabase = structuredClone(fixture.store.database);
      await session.createVault('vault');
      const database = fixture.store.database;
      if (database === null || roots[0] === undefined)
        throw new Error('missing fixture');
      const vaults = await fixture.store.listVaults(database.id);
      const exact: DatabaseRevisionAnchor = {
        databaseId: database.id,
        databaseRevision: database.revision,
        catalogMetadataDigest: database.catalogMetadataDigest,
        vaultHeads: Object.fromEntries(
          vaults.map((vault) => [
            vault.id,
            { revision: vault.revision, metadataDigest: vault.payloadMetadataDigest },
          ]),
        ),
      } as DatabaseRevisionAnchor;
      const hostile: DatabaseRevisionAnchor =
        kind === 'fork'
          ? {
              ...exact,
              catalogMetadataDigest: sha256DigestSchema.parse(
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
              ),
            }
          : { ...exact, vaultHeads: {} };
      if (kind === 'lower') {
        fixture.store.database = priorDatabase;
        fixture.store.vaults.clear();
      } else {
        await writeDatabaseRevisionAnchor(
          databaseRevisionAnchorPath(fixture.keyFile),
          roots[0],
          hostile,
          'replace',
        );
      }
      await session.close();
      await expect(
        DatabaseSession.open({
          store: fixture.store,
          keyFile: fixture.keyFile,
          passphrase: PASSPHRASE,
        }),
      ).rejects.toMatchObject({ code: 'authentication' });
    }
  });

  it('rejects a bound profile mismatch before reading the passphrase', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    const initialized = await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      label: 'database',
    });
    let reads = 0;
    await expect(
      DatabaseSession.openWithSecret({
        store,
        keyFile,
        expectedDatabaseId: databaseIdSchema.parse('db_wrong_binding'),
        readPassphrase: async () => {
          reads += 1;
          return PASSPHRASE;
        },
      }),
    ).rejects.toMatchObject({ code: 'binding' });
    expect(reads).toBe(0);
    expect(initialized.databaseId).not.toBe('db_wrong_binding');
  });

  it('zeroizes the session root key even when store close fails', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      label: 'database',
    });
    const observed: Uint8Array[] = [];
    const session = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      onRootKeyOwned: (key) => observed.push(key),
    });
    store.failClose = true;
    await expect(session.close()).rejects.toMatchObject({ code: 'close' });
    expect(observed).toHaveLength(1);
    expect(observed[0]).toEqual(new Uint8Array(32));
  });

  it('maps an independent stale vault CAS to a generic conflict', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      label: 'database',
    });
    const creator = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    const entry = await creator.createVault('vault');
    await creator.close();
    const first = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    const second = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    const base = await first.getVaultDocument(entry.id);
    const requested = {
      ...base,
      revision: (base.revision + 1) as VaultRevision,
      updatedAt: new Date().toISOString(),
    };
    await first.updateVault(requested);
    await expect(second.updateVault(requested)).rejects.toMatchObject({
      code: 'conflict',
    });
    await first.close();
    await second.close();
  });

  it('creates, verifies, protects, revokes, and uses database recovery slots', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    const firstRecovery = join(directory, 'first.kavrix-db-recovery');
    const secondRecovery = join(directory, 'second.kavrix-db-recovery');
    const recoveredKey = join(directory, 'recovered.kavrix-db-key');
    const initialized = await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      label: 'database',
    });
    const session = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    const first = await session.createRecovery({
      recoveryFile: firstRecovery,
      passphrase: PASSPHRASE,
    });
    expect(
      await session.verifyRecovery({
        recoveryFile: firstRecovery,
        passphrase: PASSPHRASE,
      }),
    ).toBe(first.slotId);
    await expect(session.revokeRecovery(first.slotId)).rejects.toMatchObject({
      code: 'invalid',
    });
    const second = await session.createRecovery({
      recoveryFile: secondRecovery,
      passphrase: PASSPHRASE,
    });
    await session.revokeRecovery(first.slotId);
    expect(session.recoveryStatus()).toEqual({ active: 1, revoked: 1 });
    await session.close();

    const beforeVaults = JSON.stringify(await store.listVaults(initialized.databaseId));
    const recovered = await DatabaseSession.useRecovery({
      store,
      recoveryFile: secondRecovery,
      recoveryPassphrase: PASSPHRASE,
      outputKeyFile: recoveredKey,
      newPassphrase: PASSPHRASE,
      expectedDatabaseId: initialized.databaseId,
    });
    expect(recovered.databaseId).toBe(initialized.databaseId);
    expect(JSON.stringify(await store.listVaults(initialized.databaseId))).toBe(
      beforeVaults,
    );
    const reopened = await DatabaseSession.open({
      store,
      keyFile: recoveredKey,
      passphrase: PASSPHRASE,
      expectedDatabaseId: initialized.databaseId,
    });
    expect(reopened.status().activeRecoverySlots).toBe(1);
    await reopened.close();
    expect(second.slotId).not.toBe(first.slotId);
  });
});

class MemoryDatabaseStore implements EncryptedDatabaseStore {
  database: EncryptedDatabaseDocument | null = null;
  readonly vaults = new Map<VaultId, DatabaseVaultDocument>();
  failClose = false;
  failList = false;

  async ping(): Promise<void> {}
  async getDatabase(id: DatabaseId): Promise<EncryptedDatabaseDocument | null> {
    return this.database?.id === id ? structuredClone(this.database) : null;
  }
  async createDatabase(document: EncryptedDatabaseDocument): Promise<void> {
    if (this.database !== null) throw new EncryptedDatabaseStoreError('exists');
    this.database = structuredClone(document);
  }
  async updateDatabase(
    document: EncryptedDatabaseDocument,
    expectedRevision: DatabaseRevision,
  ): Promise<void> {
    if (this.database?.revision !== expectedRevision)
      throw new EncryptedDatabaseStoreError('conflict');
    this.database = structuredClone(document);
  }
  async listVaults(databaseId: DatabaseId): Promise<readonly DatabaseVaultDocument[]> {
    if (this.failList) throw new EncryptedDatabaseStoreError('operation');
    return [...this.vaults.values()]
      .filter((vault) => vault.databaseId === databaseId)
      .map((vault) => structuredClone(vault));
  }
  async getVault(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<DatabaseVaultDocument | null> {
    const vault = this.vaults.get(vaultId);
    return vault?.databaseId === databaseId ? structuredClone(vault) : null;
  }
  async createVault(input: CreateVaultInput): Promise<void> {
    if (this.database?.revision !== input.expectedDatabaseRevision)
      throw new EncryptedDatabaseStoreError('conflict');
    if (this.vaults.has(input.vault.id))
      throw new EncryptedDatabaseStoreError('exists');
    this.database = structuredClone(input.database);
    this.vaults.set(input.vault.id, structuredClone(input.vault));
  }
  async updateVault(input: UpdateVaultInput): Promise<void> {
    const current = this.vaults.get(input.vault.id);
    if (current?.revision !== input.expectedVaultRevision)
      throw new EncryptedDatabaseStoreError('conflict');
    this.vaults.set(input.vault.id, structuredClone(input.vault));
  }
  async deleteVault(input: DeleteVaultInput): Promise<void> {
    const current = this.vaults.get(input.vaultId);
    if (
      this.database?.revision !== input.expectedDatabaseRevision ||
      current?.revision !== input.expectedVaultRevision
    )
      throw new EncryptedDatabaseStoreError('conflict');
    this.database = structuredClone(input.database);
    this.vaults.delete(input.vaultId);
  }
  async close(): Promise<void> {
    if (this.failClose) throw new EncryptedDatabaseStoreError('operation');
  }
}
