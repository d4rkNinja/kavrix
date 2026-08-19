import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  databaseRevisionAnchorPath,
  deleteSecureFile,
  readDatabaseKeyFileBinding,
  readDatabaseRecoveryKitFileBinding,
} from '@kavrix/key-files';
import {
  databaseIdSchema,
  sha256DigestSchema,
  type DatabaseId,
  type DatabaseRevision,
  type DatabaseVaultDocument,
  type EncryptedDatabaseDocument,
  type LocalVaultPayload,
  type VaultId,
} from '@kavrix/schemas';
import {
  EncryptedDatabaseStoreError,
  type CreateVaultInput,
  type DeleteVaultInput,
  type EncryptedDatabaseStore,
  type UpdateVaultInput,
} from '@kavrix/storage';
import { afterEach, describe, expect, it } from 'vitest';

import {
  DatabaseSession,
  setDatabaseSessionZeroizationObserverForTest,
} from '../src/database-session.js';

const PASSPHRASE = Buffer.from('correct horse battery staple', 'utf8');

afterEach(() => setDatabaseSessionZeroizationObserverForTest(undefined));

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

    await session.updateVault(first.id, (payload) => ({
      records: {
        ...payload.records,
        changed: { value: 'updated-value', updatedAt: new Date().toISOString() },
      },
    }));
    expect((await session.getVaultDocument(first.id)).revision).toBe(1);
    await session.close();
    const reopened = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    let reopenedValue = '';
    await reopened.updateVault(first.id, (payload) => {
      reopenedValue = payload.records['changed']?.value ?? '';
      return payload;
    });
    expect(reopenedValue).toBe('updated-value');
    expect((await reopened.getVaultDocument(second.id)).revision).toBe(0);
    await expect(reopened.createVault('renamed-label-canary')).rejects.toMatchObject({
      code: 'duplicate',
    });
    await reopened.close();

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
    const cleared: boolean[] = [];
    setDatabaseSessionZeroizationObserverForTest((value) => cleared.push(value));
    await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      label: 'secret-database-name',
    });
    expect(cleared).toEqual([true]);
    cleared.length = 0;
    await expect(
      DatabaseSession.open({
        store,
        keyFile,
        passphrase: Buffer.from('incorrect passphrase value', 'utf8'),
      }),
    ).rejects.toMatchObject({ code: 'authentication' });
    expect(cleared).toEqual([]);
  });

  it('retains the recovery-capable key when datastore rollback is ambiguous', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    let thrown: unknown;
    try {
      await DatabaseSession.initialize({
        store,
        keyFile,
        passphrase: PASSPHRASE,
        label: 'database',
        publishBinding: async () => {
          throw new Error('mongodb://raw-error-canary');
        },
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ code: 'ambiguous-commit' });
    expect(serializeThrown(thrown)).not.toContain('raw-error-canary');
    await expect(access(keyFile)).resolves.toBeUndefined();
    await expect(access(databaseRevisionAnchorPath(keyFile))).resolves.toBeUndefined();
    expect((await readDatabaseKeyFileBinding(keyFile)).databaseId).toBe(
      store.database?.id,
    );
    const recovered = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    await recovered.close();
  });

  it('rolls back owned key and datastore artifacts when rollback is proven', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    await expect(
      DatabaseSession.initialize({
        store,
        keyFile,
        passphrase: PASSPHRASE,
        label: 'database',
        publishBinding: async () => {
          throw new Error('profile publication failed');
        },
        rollbackDatabase: async () => {
          store.database = null;
        },
      }),
    ).rejects.toMatchObject({ code: 'authentication' });
    await expect(access(keyFile)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(access(databaseRevisionAnchorPath(keyFile))).rejects.toMatchObject({
      code: 'ENOENT',
    });
    expect(store.database).toBeNull();
  });

  it('aggregates only redacted categories when owned cleanup meets a foreign race', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    let thrown: unknown;
    try {
      await DatabaseSession.initialize({
        store,
        keyFile,
        passphrase: PASSPHRASE,
        label: 'database',
        publishBinding: async () => {
          throw new Error('primary-secret-canary');
        },
        rollbackDatabase: async () => {
          store.database = null;
          await rm(keyFile);
          await writeFile(keyFile, 'foreign-cleanup-secret-canary', { mode: 0o600 });
        },
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(AggregateError);
    expect(serializeThrown(thrown)).not.toMatch(/(?:primary|cleanup)-secret-canary/u);
    await expect(readFile(keyFile, 'utf8')).resolves.toBe(
      'foreign-cleanup-secret-canary',
    );
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
    const failedClears: boolean[] = [];
    setDatabaseSessionZeroizationObserverForTest((value) => failedClears.push(value));
    await expect(
      DatabaseSession.open({
        store: tampered.store,
        keyFile: tampered.keyFile,
        passphrase: PASSPHRASE,
      }),
    ).rejects.toMatchObject({ code: 'authentication' });
    expect(failedClears).toEqual([true]);
    setDatabaseSessionZeroizationObserverForTest(undefined);

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
      let rootCleared = false;
      setDatabaseSessionZeroizationObserverForTest((cleared) => {
        rootCleared = cleared;
      });
      const session = await DatabaseSession.open({
        store: fixture.store,
        keyFile: fixture.keyFile,
        passphrase: PASSPHRASE,
      });
      const priorDatabase = structuredClone(fixture.store.database);
      await session.createVault('vault');
      const database = fixture.store.database;
      if (database === null) throw new Error('missing fixture');
      const vaults = await fixture.store.listVaults(database.id);
      if (kind === 'lower') {
        fixture.store.database = priorDatabase;
        fixture.store.vaults.clear();
      } else if (kind === 'missing-head') {
        fixture.store.vaults.clear();
      } else {
        const vault = vaults[0];
        if (vault === undefined) throw new Error('missing fixture');
        fixture.store.vaults.set(vault.id, {
          ...vault,
          payloadMetadataDigest: sha256DigestSchema.parse(
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          ),
        });
      }
      await session.close();
      expect(rootCleared).toBe(true);
      setDatabaseSessionZeroizationObserverForTest(undefined);
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
    const observed: boolean[] = [];
    setDatabaseSessionZeroizationObserverForTest((cleared) => observed.push(cleared));
    const session = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    store.failClose = true;
    await expect(session.close()).rejects.toMatchObject({ code: 'close' });
    expect(observed).toEqual([true]);
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
    let arrivals = 0;
    let releaseFirst: (() => void) | undefined;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let releaseSecond: (() => void) | undefined;
    const secondGate = new Promise<void>((resolve) => {
      releaseSecond = resolve;
    });
    let bothReady: (() => void) | undefined;
    const ready = new Promise<void>((resolve) => {
      bothReady = resolve;
    });
    const update = async (payload: LocalVaultPayload) => {
      arrivals += 1;
      const position = arrivals;
      if (arrivals === 2) bothReady?.();
      await (position === 1 ? firstGate : secondGate);
      return payload;
    };
    const firstUpdate = first.updateVault(entry.id, update);
    const secondUpdate = second.updateVault(entry.id, update);
    await ready;
    releaseFirst?.();
    await firstUpdate;
    releaseSecond?.();
    const results = await Promise.allSettled([Promise.resolve(), secondUpdate]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
    expect(results.find((result) => result.status === 'rejected')).toMatchObject({
      reason: { code: 'conflict' },
    });
    await first.close();
    await second.close();
  });

  it('poisons after an ambiguous post-CAS anchor failure and reconciles on reopen', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      label: 'database',
    });
    const cleared: boolean[] = [];
    setDatabaseSessionZeroizationObserverForTest((value) => cleared.push(value));
    const session = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    const vault = await session.createVault('vault');
    const anchorFile = databaseRevisionAnchorPath(keyFile);
    const savedAnchor = anchorFile + '.saved';
    store.afterVaultUpdate = async () => {
      await rename(anchorFile, savedAnchor);
      await mkdir(anchorFile);
    };
    try {
      await expect(
        session.updateVault(vault.id, (payload) => ({
          records: {
            ...payload.records,
            committed: {
              value: 'ambiguous-value',
              updatedAt: new Date().toISOString(),
            },
          },
        })),
      ).rejects.toMatchObject({ code: 'ambiguous-commit' });
    } finally {
      await rm(anchorFile, { recursive: true });
      await rename(savedAnchor, anchorFile);
      store.afterVaultUpdate = undefined;
    }
    expect(cleared).toEqual([true]);
    expect(() => session.status()).toThrow(
      expect.objectContaining({ code: 'operation' }),
    );

    const reopened = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    let recovered = '';
    await reopened.updateVault(vault.id, (payload) => {
      recovered = payload.records['committed']?.value ?? '';
      return payload;
    });
    expect(recovered).toBe('ambiguous-value');
    await reopened.close();
  });

  it('poisons when recovery companion-anchor publication fails after database CAS', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    const recoveryFile = join(directory, 'recovery.kavrix-db-recovery');
    await DatabaseSession.initialize({
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
    const recoveryAnchor = databaseRevisionAnchorPath(recoveryFile);
    const savedAnchor = recoveryAnchor + '.saved';
    store.afterDatabaseUpdate = async () => {
      await rename(recoveryAnchor, savedAnchor);
      await mkdir(recoveryAnchor);
    };
    try {
      await expect(
        session.createRecovery({ recoveryFile, passphrase: PASSPHRASE }),
      ).rejects.toMatchObject({ code: 'ambiguous-commit' });
    } finally {
      await rm(recoveryAnchor, { recursive: true });
      await rename(savedAnchor, recoveryAnchor);
      store.afterDatabaseUpdate = undefined;
    }
    expect(() => session.status()).toThrow(
      expect.objectContaining({ code: 'operation' }),
    );

    const reopened = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    await expect(
      reopened.verifyRecovery({
        recoveryFile,
        passphrase: PASSPHRASE,
        expectedBinding: await readDatabaseRecoveryKitFileBinding(recoveryFile),
      }),
    ).resolves.toMatch(/^recovery_/u);
    await reopened.close();
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
    const recoveredVault = await session.createVault('post-kit-vault');
    expect(
      await session.verifyRecovery({
        recoveryFile: secondRecovery,
        passphrase: PASSPHRASE,
        expectedBinding: await readDatabaseRecoveryKitFileBinding(secondRecovery),
      }),
    ).toBe(second.slotId);
    await session.revokeRecovery(first.slotId);
    expect(session.recoveryStatus()).toEqual({ active: 1, revoked: 1 });
    await session.close();

    const racedRecovery = join(directory, 'raced.kavrix-db-recovery');
    const racedOutput = join(directory, 'raced-owner.kavrix-db-key');
    await writeFile(racedRecovery, await readFile(firstRecovery), { mode: 0o600 });
    const expectedRaceBinding = await readDatabaseRecoveryKitFileBinding(racedRecovery);
    await writeFile(racedRecovery, await readFile(secondRecovery), { mode: 0o600 });
    await expect(
      DatabaseSession.useRecovery({
        store,
        recoveryFile: racedRecovery,
        recoveryPassphrase: PASSPHRASE,
        outputKeyFile: racedOutput,
        newPassphrase: PASSPHRASE,
        expectedBinding: expectedRaceBinding,
      }),
    ).rejects.toMatchObject({ code: 'authentication' });

    const beforeVaults = JSON.stringify(await store.listVaults(initialized.databaseId));
    const recovered = await DatabaseSession.useRecovery({
      store,
      recoveryFile: secondRecovery,
      recoveryPassphrase: PASSPHRASE,
      outputKeyFile: recoveredKey,
      newPassphrase: PASSPHRASE,
      expectedBinding: await readDatabaseRecoveryKitFileBinding(secondRecovery),
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
    expect(reopened.status()).toMatchObject({ activeRecoverySlots: 1, vaultCount: 1 });
    expect((await reopened.getVault(recoveredVault.id)).id).toBe(recoveredVault.id);
    await reopened.close();
    expect(second.slotId).not.toBe(first.slotId);
  });

  it('rejects missing and forked recovery companion anchors after vault additions', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    for (const kind of ['missing', 'fork'] as const) {
      const store = new MemoryDatabaseStore();
      const keyFile = join(directory, `${kind}.owner`);
      const recoveryFile = join(directory, `${kind}.recovery`);
      await DatabaseSession.initialize({
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
      await session.createRecovery({ recoveryFile, passphrase: PASSPHRASE });
      const vault = await session.createVault('later-vault');
      if (kind === 'missing') {
        await deleteSecureFile(databaseRevisionAnchorPath(recoveryFile));
      } else {
        const document = store.vaults.get(vault.id);
        if (document === undefined) throw new Error('missing fixture');
        store.vaults.set(vault.id, {
          ...document,
          payloadMetadataDigest: sha256DigestSchema.parse(
            'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          ),
        });
      }
      await expect(
        session.verifyRecovery({
          recoveryFile,
          passphrase: PASSPHRASE,
          expectedBinding: await readDatabaseRecoveryKitFileBinding(recoveryFile),
        }),
      ).rejects.toMatchObject({ code: 'authentication' });
      await session.close();
    }
  });

  it('rejects wrong-key and cross-purpose recovery-slot metadata digests', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    for (const kind of ['wrong-key', 'cross-purpose'] as const) {
      const store = new MemoryDatabaseStore();
      const keyFile = join(directory, `${kind}.owner`);
      const recoveryFile = join(directory, `${kind}.recovery`);
      await DatabaseSession.initialize({
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
      const recovery = await session.createRecovery({
        recoveryFile,
        passphrase: PASSPHRASE,
      });
      await session.close();
      const database = store.database;
      if (database === null) throw new Error('missing fixture');
      const slot = database.recoverySlots.find(
        (candidate) => candidate.id === recovery.slotId,
      );
      if (slot === undefined) throw new Error('missing fixture');
      slot.wrappedDatabaseRoot.aad.metadataDigest =
        kind === 'cross-purpose'
          ? database.catalogMetadataDigest
          : sha256DigestSchema.parse('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
      const reopened = await DatabaseSession.open({
        store,
        keyFile,
        passphrase: PASSPHRASE,
      });
      await expect(
        reopened.verifyRecovery({
          recoveryFile,
          passphrase: PASSPHRASE,
          expectedBinding: await readDatabaseRecoveryKitFileBinding(recoveryFile),
        }),
      ).rejects.toMatchObject({ code: 'authentication' });
      await reopened.close();
    }
  });
});

class MemoryDatabaseStore implements EncryptedDatabaseStore {
  database: EncryptedDatabaseDocument | null = null;
  readonly vaults = new Map<VaultId, DatabaseVaultDocument>();
  failClose = false;
  afterDatabaseUpdate: (() => Promise<void>) | undefined;
  afterVaultUpdate: (() => Promise<void>) | undefined;

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
    await this.afterDatabaseUpdate?.();
  }
  async listVaults(databaseId: DatabaseId): Promise<readonly DatabaseVaultDocument[]> {
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
    await this.afterVaultUpdate?.();
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

function serializeThrown(value: unknown, seen = new Set<unknown>()): string {
  if (value === null || typeof value !== 'object') return String(value);
  if (seen.has(value)) return '[cycle]';
  seen.add(value);
  const entries = Reflect.ownKeys(value).map((key) => {
    const label = typeof key === 'symbol' ? (key.description ?? 'symbol') : key;
    return `${label}:${serializeThrown(Reflect.get(value, key), seen)}`;
  });
  return entries.join('|');
}
