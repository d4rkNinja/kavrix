import {
  access,
  chmod,
  copyFile,
  mkdir,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  decryptPayload,
  encryptPayload,
  unlockDatabaseKeySlot,
  unwrapVaultRootForDatabase,
  zeroize,
} from '@kavrix/crypto';

import {
  databaseRevisionAnchorPath,
  deleteSecureFile,
  readDatabaseKeyFile,
  readDatabaseKeyFileBinding,
  readDatabaseRecoveryKitFileBinding,
  writeDatabaseKeyFile,
} from '@kavrix/key-files';
import { setWindowsUserOnlyAcl } from '@kavrix/key-files/windows-acl';
import {
  associatedDataSchema,
  databaseIdSchema,
  sha256DigestSchema,
  vaultIdSchema,
  type DatabaseId,
  type DatabaseRevision,
  type DatabaseVaultDocument,
  type EncryptedDatabaseDocument,
  type LocalVaultPayload,
  type VaultId,
} from '@kavrix/schemas';
import {
  EncryptedDatabaseStoreError,
  FileEncryptedDatabaseStore,
  type CreateVaultInput,
  type DeleteVaultInput,
  type EncryptedDatabaseStore,
  type UpdateVaultInput,
} from '@kavrix/storage';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  DatabaseSession,
  setDatabaseSessionZeroizationObserverForTest,
} from '../src/database-session.js';
import {
  DatastoreProfileError,
  DatastoreProfileRegistry,
} from '../src/datastore-profiles.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';

const PASSPHRASE = Buffer.from('correct horse battery staple', 'utf8');

afterEach(() => setDatabaseSessionZeroizationObserverForTest(undefined));

describe('DatabaseSession', () => {
  it('opens every vault from exactly a copied database file and one local-share key', async () => {
    const source = await mkdtemp(join(tmpdir(), 'kavrix-share-source-'));
    const recipient = await mkdtemp(join(tmpdir(), 'kavrix-share-recipient-'));
    const staleRecipient = await mkdtemp(join(tmpdir(), 'kavrix-share-stale-'));
    const dataFile = join(source, 'database.kavrix');
    const ownerKey = join(source, 'owner.key');
    const shareKey = join(source, 'share.key');
    const sharePassphrase = Buffer.from('recipient horse battery staple', 'utf8');
    const store = await FileEncryptedDatabaseStore.open(dataFile);
    await DatabaseSession.initialize({
      store,
      keyFile: ownerKey,
      passphrase: PASSPHRASE,
      label: 'shared database',
    });
    const owner = await DatabaseSession.open({
      store,
      keyFile: ownerKey,
      passphrase: PASSPHRASE,
    });
    const alpha = await owner.createVault('alpha');
    await owner.createVault('beta');
    await owner.createLocalShareKey({
      keyFile: shareKey,
      passphrase: sharePassphrase,
    });

    const recipientData = join(recipient, 'database.kavrix');
    const recipientKey = join(recipient, 'database.key');
    await copyFile(dataFile, recipientData);
    await copyFile(shareKey, recipientKey);
    if (process.platform === 'win32') {
      await setWindowsUserOnlyAcl(recipientData);
      await setWindowsUserOnlyAcl(recipientKey);
    } else {
      await chmod(recipientData, 0o600);
      await chmod(recipientKey, 0o600);
    }
    const recipientStore = await FileEncryptedDatabaseStore.open(recipientData);
    const opened = await DatabaseSession.open({
      store: recipientStore,
      keyFile: recipientKey,
      passphrase: sharePassphrase,
    });
    expect(opened.listVaults().map((vault) => vault.label)).toEqual(['alpha', 'beta']);
    await opened.close();
    await expect(
      access(databaseRevisionAnchorPath(recipientKey)),
    ).resolves.toBeUndefined();

    await rm(databaseRevisionAnchorPath(recipientKey));
    const missingAnchorStore = await FileEncryptedDatabaseStore.open(recipientData);
    await expect(
      DatabaseSession.open({
        store: missingAnchorStore,
        keyFile: recipientKey,
        passphrase: sharePassphrase,
      }),
    ).rejects.toMatchObject({ code: 'authentication' });
    await missingAnchorStore.close();

    await owner.updateVault(alpha.id, (payload) => payload);
    const staleData = join(staleRecipient, 'database.kavrix');
    const staleKey = join(staleRecipient, 'database.key');
    await copyFile(dataFile, staleData);
    await copyFile(shareKey, staleKey);
    if (process.platform === 'win32') {
      await setWindowsUserOnlyAcl(staleData);
      await setWindowsUserOnlyAcl(staleKey);
    } else {
      await chmod(staleData, 0o600);
      await chmod(staleKey, 0o600);
    }
    await owner.close();
    const staleStore = await FileEncryptedDatabaseStore.open(staleData);
    await expect(
      DatabaseSession.open({
        store: staleStore,
        keyFile: staleKey,
        passphrase: sharePassphrase,
      }),
    ).rejects.toMatchObject({ code: 'authentication' });
    await staleStore.close();
    zeroize(sharePassphrase);
  });

  it('does not let a stale local-share opener overwrite a concurrent rewrap', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-share-cas-'));
    const store = new MemoryDatabaseStore();
    const ownerKey = join(directory, 'owner.key');
    const shareKey = join(directory, 'share.key');
    const sharePassphrase = Buffer.from('recipient horse battery staple', 'utf8');
    let rewrapKey: Uint8Array | undefined;
    let rewrappedContents: Buffer | undefined;
    try {
      await DatabaseSession.initialize({
        store,
        keyFile: ownerKey,
        passphrase: PASSPHRASE,
        label: 'shared database',
      });
      const owner = await DatabaseSession.open({
        store,
        keyFile: ownerKey,
        passphrase: PASSPHRASE,
      });
      await owner.createLocalShareKey({
        keyFile: shareKey,
        passphrase: sharePassphrase,
      });
      await owner.close();

      const parsed = await readDatabaseKeyFile(shareKey, sharePassphrase);
      rewrapKey = Uint8Array.from(parsed.portableKey);
      zeroize(parsed.portableKey);
      const binding = await readDatabaseKeyFileBinding(shareKey);
      let rewrapped = false;
      store.afterListVaults = async () => {
        if (rewrapped || rewrapKey === undefined) return;
        rewrapped = true;
        await writeDatabaseKeyFile(shareKey, rewrapKey, binding, {
          mode: 'replace',
          protection: { kind: 'passphrase', passphrase: sharePassphrase },
        });
        rewrappedContents = await readFile(shareKey);
      };

      await expect(
        DatabaseSession.open({
          store,
          keyFile: shareKey,
          passphrase: sharePassphrase,
        }),
      ).rejects.toMatchObject({ code: 'authentication' });
      expect(rewrapped).toBe(true);
      expect(await readFile(shareKey)).toEqual(rewrappedContents);
      const rewrappedFile = await readDatabaseKeyFile(
        shareKey,
        sharePassphrase,
        binding,
      );
      try {
        expect(rewrappedFile.portableKey).toEqual(rewrapKey);
        expect(rewrappedFile.localShareBootstrap).toBeUndefined();
      } finally {
        zeroize(rewrappedFile.portableKey);
      }
    } finally {
      zeroize(rewrappedContents);
      zeroize(rewrapKey);
      zeroize(sharePassphrase);
    }
  });

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

  it('rejects a valid foreign AAD domain in every vault-preferences decrypt path', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-vault-aad-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    let portableKey: Uint8Array | undefined;
    let databaseRoot: Uint8Array | undefined;
    let vaultRoot: Uint8Array | undefined;
    let plaintext: Uint8Array | undefined;
    let sessionClosed = false;
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
    try {
      const vault = await session.createVault('vault');
      const document = await session.getVaultDocument(vault.id);
      const database = store.database;
      if (database === null) throw new Error('missing fixture');
      const parsed = await readDatabaseKeyFile(keyFile, PASSPHRASE);
      portableKey = parsed.portableKey;
      databaseRoot = await unlockDatabaseKeySlot(database.keySlot, portableKey, {
        databaseId: database.id,
        slotId: database.keySlot.id,
        schemaVersion: database.schemaVersion,
        keyVersion: database.keySlot.keyVersion,
        revision: database.keySlot.wrappedDatabaseRoot.aad.revision,
        metadataDigest: database.keySlot.wrappedDatabaseRoot.aad.metadataDigest,
      });
      vaultRoot = await unwrapVaultRootForDatabase(
        document.wrappedVaultRoot,
        databaseRoot,
        document.wrappedVaultRoot.aad,
      );
      plaintext = await decryptPayload(
        document.encryptedPayload,
        vaultRoot,
        document.encryptedPayload.aad,
      );
      const foreignContext = associatedDataSchema.parse({
        version: 1,
        vaultId: document.id,
        entityType: 'device-label',
        entityId: document.id,
        purpose: 'device-label',
        schemaVersion: document.schemaVersion,
        keyVersion: document.currentKeyVersion,
        revision: document.revision,
        metadataDigest: document.payloadMetadataDigest,
      });
      const encryptedPayload = await encryptPayload(
        plaintext,
        vaultRoot,
        foreignContext,
      );
      store.vaults.set(vault.id, { ...document, encryptedPayload });

      await expect(
        session.inspectVault(vault.id, () => undefined),
      ).rejects.toMatchObject({
        code: 'authentication',
      });
      await expect(
        session.updateVault(vault.id, (payload) => payload),
      ).rejects.toMatchObject({
        code: 'authentication',
      });
      await session.close();
      sessionClosed = true;
      await expect(
        DatabaseSession.open({ store, keyFile, passphrase: PASSPHRASE }),
      ).rejects.toMatchObject({ code: 'authentication' });
    } finally {
      if (!sessionClosed) await session.close();
      zeroize(plaintext);
      zeroize(vaultRoot);
      zeroize(databaseRoot);
      zeroize(portableKey);
    }
  });

  it('decodes authenticated catalog and vault plaintext without Buffer copies', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      label: 'catalog-copy-canary',
    });
    const session = await DatabaseSession.open({
      store,
      keyFile,
      passphrase: PASSPHRASE,
    });
    const vault = await session.createVault('vault');
    await session.updateVault(vault.id, (payload) => ({
      records: {
        ...payload.records,
        copyProbe: {
          value: 'vault-copy-canary',
          updatedAt: new Date().toISOString(),
        },
      },
    }));
    await session.close();

    const originalFrom = Buffer.from;
    let copiedSecretPlaintext = false;
    const fromSpy = vi.spyOn(Buffer, 'from').mockImplementation(((
      value: unknown,
      ...arguments_: unknown[]
    ) => {
      if (value instanceof Uint8Array) {
        const decoded = new TextDecoder().decode(value);
        if (
          decoded.includes('catalog-copy-canary') ||
          decoded.includes('vault-copy-canary')
        ) {
          copiedSecretPlaintext = true;
        }
      }
      return Reflect.apply(originalFrom, Buffer, [value, ...arguments_]) as Buffer;
    }) as typeof Buffer.from);
    try {
      const reopened = await DatabaseSession.open({
        store,
        keyFile,
        passphrase: PASSPHRASE,
      });
      await reopened.updateVault(vault.id, (payload) => payload);
      expect(copiedSecretPlaintext).toBe(false);
      await reopened.close();
    } finally {
      fromSpy.mockRestore();
    }
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
    let rollbackCalled = false;
    let thrown: unknown;
    try {
      await DatabaseSession.initialize({
        store,
        keyFile,
        passphrase: PASSPHRASE,
        label: 'database',
        publishBinding: async () => {
          return {
            status: 'publication-uncertain' as const,
            error: new Error('mongodb://raw-error-canary'),
          };
        },
        rollbackDatabase: async () => {
          rollbackCalled = true;
          store.database = null;
        },
      });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toMatchObject({ code: 'ambiguous-commit' });
    expect(serializeThrown(thrown)).not.toContain('raw-error-canary');
    expect(rollbackCalled).toBe(false);
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
    const authenticNotPublished = await authenticNonPublication(directory);
    await expect(
      DatabaseSession.initialize({
        store,
        keyFile,
        passphrase: PASSPHRASE,
        label: 'database',
        publishBinding: async () => authenticNotPublished,
        rollbackDatabase: async () => {
          store.database = null;
        },
      }),
    ).rejects.toSatisfy((error: unknown) => {
      expect(error).toMatchObject({ code: 'authentication' });
      expect(serializeThrown(error)).not.toContain(
        'profile-not-published-secret-canary',
      );
      return true;
    });
    for (const path of [keyFile, databaseRevisionAnchorPath(keyFile)]) {
      expect(await readFile(path)).toHaveLength(0);
      if (process.platform !== 'win32') {
        expect((await stat(path)).mode & 0o077).toBe(0);
      }
    }
    expect(store.database).toBeNull();
  });

  it('treats known create-database rejections as proven non-publication', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-create-reject-'));
    for (const [code, expected] of [
      ['exists', 'conflict'],
      ['conflict', 'conflict'],
      ['invalid', 'operation'],
    ] as const) {
      const store = new MemoryDatabaseStore();
      const keyFile = join(directory, `${code}.kavrix-db-key`);
      store.createDatabaseError = code;

      await expect(
        DatabaseSession.initialize({
          store,
          keyFile,
          passphrase: PASSPHRASE,
          label: 'database',
        }),
      ).rejects.toMatchObject({ code: expected });
      expect(store.database).toBeNull();
      await expect(readFile(keyFile)).resolves.toHaveLength(0);
    }
  });

  it('aggregates only redacted categories when owned cleanup meets a foreign race', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    const authenticNotPublished = await authenticNonPublication(directory);
    let thrown: unknown;
    try {
      await DatabaseSession.initialize({
        store,
        keyFile,
        passphrase: PASSPHRASE,
        label: 'database',
        publishBinding: async () => authenticNotPublished,
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

  it('retains artifacts for every malformed profile publication result', async () => {
    let getterReads = 0;
    const getterWrapper = Object.freeze(
      Object.defineProperties(
        {},
        {
          status: {
            enumerable: true,
            get: () => {
              getterReads += 1;
              return 'not-published';
            },
          },
          error: {
            enumerable: true,
            get: () => {
              getterReads += 1;
              return new DatastoreProfileError('PROFILE_OPERATION_FAILED');
            },
          },
        },
      ),
    );
    let proxyReads = 0;
    const statefulProxy = new Proxy(
      {},
      {
        get: (_target, property) => {
          if (property === 'then') return undefined;
          proxyReads += 1;
          if (property === 'status' && proxyReads === 1) return 'not-published';
          throw new Error('stateful-proxy-secret-canary');
        },
        ownKeys: () => {
          proxyReads += 1;
          return ['status', 'error'];
        },
      },
    );
    const malformedResults: readonly Readonly<{
      name: string;
      value: unknown;
      observedReads?: () => number;
    }>[] = [
      { name: 'null', value: null },
      { name: 'undefined', value: undefined },
      { name: 'primitive', value: 7 },
      {
        name: 'unknown-status',
        value: { status: 'unknown', detail: 'unknown-status-secret-canary' },
      },
      { name: 'not-published-missing-error', value: { status: 'not-published' } },
      {
        name: 'not-published-wrong-error',
        value: {
          status: 'not-published',
          error: new Error('malformed-not-published-secret-canary'),
        },
      },
      {
        name: 'not-published-exact-forgery',
        value: Object.freeze({
          status: 'not-published',
          error: new DatastoreProfileError('PROFILE_OPERATION_FAILED'),
        }),
      },
      {
        name: 'frozen-getter-wrapper',
        value: getterWrapper,
        observedReads: () => getterReads,
      },
      {
        name: 'stateful-throwing-proxy',
        value: statefulProxy,
        observedReads: () => proxyReads,
      },
      { name: 'published-missing-capability', value: { status: 'published' } },
      {
        name: 'published-forged-capability',
        value: { status: 'published', publication: Object.freeze({}) },
      },
      {
        name: 'uncertain-missing-error',
        value: {
          status: 'publication-uncertain',
          publication: Object.freeze({}),
        },
      },
    ];
    for (const malformed of malformedResults) {
      const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
      const store = new MemoryDatabaseStore();
      const keyFile = join(directory, `${malformed.name}.kavrix-db-key`);
      let rollbackCalled = false;
      let thrown: unknown;
      try {
        await DatabaseSession.initialize({
          store,
          keyFile,
          passphrase: PASSPHRASE,
          label: 'database',
          publishBinding: async () => malformed.value as never,
          rollbackDatabase: async () => {
            rollbackCalled = true;
            store.database = null;
          },
        });
      } catch (error) {
        thrown = error;
      }
      expect(thrown, malformed.name).toMatchObject({ code: 'ambiguous-commit' });
      expect(serializeThrown(thrown), malformed.name).not.toContain('secret-canary');
      expect(malformed.observedReads?.() ?? 0, malformed.name).toBe(0);
      expect(rollbackCalled, malformed.name).toBe(false);
      await expect(access(keyFile), malformed.name).resolves.toBeUndefined();
      await expect(
        access(databaseRevisionAnchorPath(keyFile)),
        malformed.name,
      ).resolves.toBeUndefined();
      const reopened = await DatabaseSession.open({
        store,
        keyFile,
        passphrase: PASSPHRASE,
      });
      await reopened.close();
    }
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

  it('rejects invalid labels, missing vaults, unauthorized deletion, and closed operations', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-validation-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
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

    await expect(session.createVault('')).rejects.toMatchObject({ code: 'invalid' });
    await expect(session.createVault(42 as never)).rejects.toMatchObject({
      code: 'invalid',
    });
    await expect(session.createVault('x'.repeat(1_025))).rejects.toMatchObject({
      code: 'invalid',
    });
    const first = await session.createVault('first');
    await expect(session.createVault('first')).rejects.toMatchObject({
      code: 'duplicate',
    });
    const storedFirst = store.vaults.get(first.id);
    if (storedFirst === undefined) throw new Error('missing fixture');
    store.vaults.delete(first.id);
    await expect(session.getVault(first.id)).rejects.toMatchObject({
      code: 'not-found',
    });
    store.vaults.set(first.id, storedFirst);

    await expect(
      session.inspectVault(first.id, () => {
        throw new Error('inspection-secret-canary');
      }),
    ).rejects.toMatchObject({ code: 'authentication' });
    const beforeInvalidUpdate = await session.getVaultDocument(first.id);
    await expect(
      session.updateVault(first.id, () => ({ records: null }) as never),
    ).rejects.toMatchObject({ code: 'authentication' });
    expect((await session.getVaultDocument(first.id)).revision).toBe(
      beforeInvalidUpdate.revision,
    );

    for (const [code, expected] of [
      ['exists', 'conflict'],
      ['invalid', 'operation'],
    ] as const) {
      store.createVaultError = code;
      await expect(session.createVault(`adapter-${code}`)).rejects.toMatchObject({
        code: expected,
      });
      expect(session.status().vaultCount).toBe(1);
    }
    store.createVaultError = undefined;
    const missingId = vaultIdSchema.parse('missing-vault');
    await expect(session.getVault(missingId)).rejects.toMatchObject({
      code: 'not-found',
    });
    await expect(session.getVaultDocument(missingId)).rejects.toMatchObject({
      code: 'not-found',
    });
    await expect(session.renameVault(missingId, 'renamed')).rejects.toMatchObject({
      code: 'not-found',
    });
    await session.createVault('second');
    await expect(session.renameVault(first.id, 'second')).rejects.toMatchObject({
      code: 'duplicate',
    });
    await expect(session.deleteVault(first.id)).rejects.toMatchObject({
      code: 'invalid',
    });

    await session.close();
    await session.close();
    expect(() => session.status()).toThrow(
      expect.objectContaining({ code: 'operation' }),
    );
    expect(() => session.listVaults()).toThrow(
      expect.objectContaining({ code: 'operation' }),
    );
    expect(() => session.recoveryStatus()).toThrow(
      expect.objectContaining({ code: 'operation' }),
    );
    await expect(session.createVault('after-close')).rejects.toMatchObject({
      code: 'operation',
    });
  });

  it('rejects missing databases and key-slot bindings before reading the passphrase', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-binding-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
    await DatabaseSession.initialize({
      store,
      keyFile,
      passphrase: PASSPHRASE,
      label: 'database',
    });
    const original = store.database;
    if (original === null) throw new Error('missing fixture');

    store.database = null;
    let reads = 0;
    await expect(
      DatabaseSession.openWithSecret({
        store,
        keyFile,
        readPassphrase: async () => {
          reads += 1;
          return PASSPHRASE;
        },
      }),
    ).rejects.toMatchObject({ code: 'binding' });
    expect(reads).toBe(0);

    const mismatched = structuredClone(original);
    mismatched.keySlot.id = 'foreign-slot';
    store.database = mismatched;
    await expect(
      DatabaseSession.open({
        store,
        keyFile,
        passphrase: PASSPHRASE,
      }),
    ).rejects.toMatchObject({ code: 'binding' });
  });

  it('maps a zeroization observer failure and leaves the session closed', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-zeroization-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
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
    setDatabaseSessionZeroizationObserverForTest(() => {
      throw new Error('observer-secret-canary');
    });
    await expect(session.close()).rejects.toMatchObject({ code: 'operation' });
    expect(() => session.status()).toThrow(
      expect.objectContaining({ code: 'operation' }),
    );
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

  it('poisons a stale session when a vault mutation applies before its adapter throws', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-'));
    const store = new MemoryDatabaseStore();
    const keyFile = join(directory, 'owner.kavrix-db-key');
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
    const vault = await session.createVault('vault');
    store.afterVaultUpdate = () =>
      Promise.reject(new EncryptedDatabaseStoreError('operation'));

    await expect(
      session.updateVault(vault.id, (payload) => ({
        records: {
          ...payload.records,
          committed: { value: 'applied', updatedAt: new Date().toISOString() },
        },
      })),
    ).rejects.toMatchObject({ code: 'ambiguous-commit' });
    expect(() => session.status()).toThrow(
      expect.objectContaining({ code: 'operation' }),
    );
    expect(store.vaults.get(vault.id)?.revision).toBe(1);
  });

  it('retains recovery artifacts when the database update applies before throwing', async () => {
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
    store.afterDatabaseUpdate = () =>
      Promise.reject(new EncryptedDatabaseStoreError('operation'));

    await expect(
      session.createRecovery({ recoveryFile, passphrase: PASSPHRASE }),
    ).rejects.toMatchObject({ code: 'ambiguous-commit' });
    await expect(access(recoveryFile)).resolves.toBeUndefined();
    await expect(
      access(databaseRevisionAnchorPath(recoveryFile)),
    ).resolves.toBeUndefined();
    expect(store.database?.recoverySlots).toHaveLength(1);
    expect(() => session.status()).toThrow(
      expect.objectContaining({ code: 'operation' }),
    );
  });

  it('poisons after an ambiguous post-CAS anchor failure and rejects the stale anchor on reopen', async () => {
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

    await expect(
      DatabaseSession.open({
        store,
        keyFile,
        passphrase: PASSPHRASE,
      }),
    ).rejects.toMatchObject({ code: 'rollback' });
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
    await expect(
      session.verifyRecovery({
        recoveryFile: firstRecovery,
        passphrase: PASSPHRASE,
        expectedBinding: await readDatabaseRecoveryKitFileBinding(firstRecovery),
      }),
    ).rejects.toMatchObject({ code: 'authentication' });
    await expect(session.revokeRecovery(first.slotId)).rejects.toMatchObject({
      code: 'not-found',
    });
    await expect(session.revokeRecovery(second.slotId)).rejects.toMatchObject({
      code: 'invalid',
    });
    await session.close();

    const racedRecovery = join(directory, 'raced.kavrix-db-recovery');
    const racedOutput = join(directory, 'raced-owner.kavrix-db-key');
    await writeFile(racedRecovery, await readFile(firstRecovery), { mode: 0o600 });
    if (process.platform === 'win32') {
      await setWindowsUserOnlyAcl(racedRecovery);
    }
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

  it('distinguishes rejected and uncertain owner recovery mutations', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-recovery-mutation-'));
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
    await session.createRecovery({ recoveryFile, passphrase: PASSPHRASE });
    await session.close();
    const expectedBinding = await readDatabaseRecoveryKitFileBinding(recoveryFile);

    const rejectedKey = join(directory, 'rejected-owner.kavrix-db-key');
    store.updateDatabaseError = 'conflict';
    await expect(
      DatabaseSession.useRecovery({
        store,
        recoveryFile,
        recoveryPassphrase: PASSPHRASE,
        outputKeyFile: rejectedKey,
        newPassphrase: PASSPHRASE,
        expectedBinding,
      }),
    ).rejects.toMatchObject({ code: 'conflict' });
    await expect(readFile(rejectedKey)).resolves.toHaveLength(0);
    await expect(
      readFile(databaseRevisionAnchorPath(rejectedKey)),
    ).resolves.toHaveLength(0);

    const uncertainKey = join(directory, 'uncertain-owner.kavrix-db-key');
    store.updateDatabaseError = 'operation';
    await expect(
      DatabaseSession.useRecovery({
        store,
        recoveryFile,
        recoveryPassphrase: PASSPHRASE,
        outputKeyFile: uncertainKey,
        newPassphrase: PASSPHRASE,
        expectedBinding,
      }),
    ).rejects.toMatchObject({ code: 'ambiguous-commit' });
    await expect(access(uncertainKey)).resolves.toBeUndefined();
    await expect(
      access(databaseRevisionAnchorPath(uncertainKey)),
    ).resolves.toBeUndefined();
  });

  it('rejects a recovery kit bound to another database', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'kavrix-session-recovery-binding-'));
    const primaryStore = new MemoryDatabaseStore();
    const foreignStore = new MemoryDatabaseStore();
    const primaryKey = join(directory, 'primary.kavrix-db-key');
    const foreignKey = join(directory, 'foreign.kavrix-db-key');
    const foreignRecovery = join(directory, 'foreign.kavrix-db-recovery');
    await DatabaseSession.initialize({
      store: primaryStore,
      keyFile: primaryKey,
      passphrase: PASSPHRASE,
      label: 'primary',
    });
    await DatabaseSession.initialize({
      store: foreignStore,
      keyFile: foreignKey,
      passphrase: PASSPHRASE,
      label: 'foreign',
    });
    const primary = await DatabaseSession.open({
      store: primaryStore,
      keyFile: primaryKey,
      passphrase: PASSPHRASE,
    });
    const foreign = await DatabaseSession.open({
      store: foreignStore,
      keyFile: foreignKey,
      passphrase: PASSPHRASE,
    });
    await foreign.createRecovery({
      recoveryFile: foreignRecovery,
      passphrase: PASSPHRASE,
    });
    await foreign.close();

    await expect(
      primary.verifyRecovery({
        recoveryFile: foreignRecovery,
        passphrase: PASSPHRASE,
        expectedBinding: await readDatabaseRecoveryKitFileBinding(foreignRecovery),
      }),
    ).rejects.toMatchObject({ code: 'binding' });
    await primary.close();
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
  createDatabaseError: 'conflict' | 'exists' | 'invalid' | undefined;
  createVaultError: 'exists' | 'invalid' | undefined;
  updateDatabaseError: 'conflict' | 'operation' | undefined;
  afterDatabaseUpdate: (() => Promise<void>) | undefined;
  afterVaultUpdate: (() => Promise<void>) | undefined;
  afterListVaults: (() => Promise<void>) | undefined;

  async ping(): Promise<void> {}
  async getDatabase(id: DatabaseId): Promise<EncryptedDatabaseDocument | null> {
    return this.database?.id === id ? structuredClone(this.database) : null;
  }
  async createDatabase(document: EncryptedDatabaseDocument): Promise<void> {
    if (this.createDatabaseError !== undefined)
      throw new EncryptedDatabaseStoreError(this.createDatabaseError);
    if (this.database !== null) throw new EncryptedDatabaseStoreError('exists');
    this.database = structuredClone(document);
  }
  async updateDatabase(
    document: EncryptedDatabaseDocument,
    expectedRevision: DatabaseRevision,
  ): Promise<void> {
    if (this.updateDatabaseError !== undefined)
      throw new EncryptedDatabaseStoreError(this.updateDatabaseError);
    if (this.database?.revision !== expectedRevision)
      throw new EncryptedDatabaseStoreError('conflict');
    this.database = structuredClone(document);
    await this.afterDatabaseUpdate?.();
  }
  async listVaults(databaseId: DatabaseId): Promise<readonly DatabaseVaultDocument[]> {
    await this.afterListVaults?.();
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
    if (this.createVaultError !== undefined)
      throw new EncryptedDatabaseStoreError(this.createVaultError);
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

async function authenticNonPublication(
  directory: string,
): Promise<
  Awaited<ReturnType<DatastoreProfileRegistry['bindDatabaseIdForInitialization']>>
> {
  const registry = await DatastoreProfileRegistry.open({
    configDirectory: join(directory, 'profile-proof'),
  });
  return registry.bindDatabaseIdForInitialization(
    'invalid profile id' as never,
    'db_proof' as never,
  );
}
