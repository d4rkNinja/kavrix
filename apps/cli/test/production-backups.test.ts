import {
  associatedDataSchema,
  encryptedGroupRecordSchema,
  groupIdSchema,
  keySlotIdSchema,
  restoreKnownRecordsVerificationV1Schema,
  timestampSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type EncryptedBackupEntry,
  type EncryptedGroupRecord,
  type VaultRecord,
} from '@kavrix/schemas';
import {
  BackupError,
  createEncryptedBackup,
  verifyEncryptedBackup,
  type BackupRestoreStore,
  type RestoreVerificationSessionFactory,
} from '@kavrix/import-export';
import type { restoreEncryptedBackup } from '@kavrix/import-export';
import {
  createPortableKeySlot,
  encryptPayload,
  generateGroupKey,
  generatePortableKey,
  generateVaultRootKey,
  wrapGroupKey,
  zeroize,
} from '@kavrix/crypto';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import type * as KeyFiles from '@kavrix/key-files';

const mockedKeyFiles = vi.hoisted(() => ({
  validateDestination: vi.fn(),
  validateSource: vi.fn(),
  readSource: vi.fn(),
  writeStream: vi.fn(),
}));

vi.mock('@kavrix/key-files', async () => {
  const actual = await vi.importActual<typeof KeyFiles>('@kavrix/key-files');
  return {
    ...actual,
    validateSecureFileDestination: mockedKeyFiles.validateDestination,
    validateSecureFileSource: mockedKeyFiles.validateSource,
    readSecureFile: mockedKeyFiles.readSource,
    writeSecureStreamFile: mockedKeyFiles.writeStream,
  };
});

import { PortableKeyFileError } from '@kavrix/key-files';
import {
  CliBackupCreationError,
  CliBackupRestoreError,
  CliBackupVerificationError,
  CliUsageError,
} from '../src/errors.js';
import {
  createProtectedEncryptedBackup,
  executeProtectedEncryptedBackupRestore,
  executeProductionBackupVerify,
  executeProductionBackupCreate,
  openLocalBackupSnapshot,
  type LocalBackupSnapshot,
  type LocalBackupStore,
  type ProductionBackupCreateDependencies,
  type ProductionBackupVerifyDependencies,
} from '../src/production/backups.js';
import type {
  ProductionUnlockedContext,
  ProductionUnlockedRequest,
} from '../src/production/unlock.js';
import type { SecretInputPort } from '../src/secret-input.js';

const VAULT_ID = vaultIdSchema.parse('vault.backup.test0001');
const GROUP_ID = groupIdSchema.parse('group.backup.test0001');
const SLOT_ID = keySlotIdSchema.parse('slot.backup.test0001');
const CREATED_AT = timestampSchema.parse('2026-08-14T00:00:00.000Z');
const PLAINTEXT_CANARY = 'KAVRIX-BACKUP-PRODUCTION-PLAINTEXT-CANARY';

beforeEach(() => {
  mockedKeyFiles.validateDestination.mockReset().mockResolvedValue(undefined);
  mockedKeyFiles.validateSource.mockReset().mockResolvedValue(undefined);
  mockedKeyFiles.readSource.mockReset();
  mockedKeyFiles.writeStream
    .mockReset()
    .mockImplementation(async (_path: string, source: AsyncIterable<Uint8Array>) => {
      let bytes = 0;
      for await (const chunk of source) {
        bytes += chunk.byteLength;
        chunk.fill(0);
      }
      return { bytes };
    });
});

describe('production encrypted backup creation', () => {
  it('streams authenticated ciphertext, reports bounded metadata, and closes the snapshot', async () => {
    const fixture = await createFixture();
    const snapshot = createSnapshot(fixture.vault, [
      { kind: 'group', record: fixture.group },
    ]);
    const archiveChunks: Buffer[] = [];
    mockedKeyFiles.writeStream.mockImplementationOnce(
      async (_path: string, source: AsyncIterable<Uint8Array>) => {
        let bytes = 0;
        for await (const chunk of source) {
          archiveChunks.push(Buffer.from(chunk));
          bytes += chunk.byteLength;
          chunk.fill(0);
        }
        return { bytes };
      },
    );

    try {
      await expect(
        createProtectedEncryptedBackup({
          destination: 'D:\\backups\\vault.cvkx',
          snapshot: snapshot.value,
          rootKey: fixture.rootKey,
          limits: { maximumBytes: 1024 * 1024, maximumRecords: 10 },
        }),
      ).resolves.toMatchObject({
        action: 'created',
        vaultId: VAULT_ID,
        recordCount: 2,
      });
      expect(Buffer.concat(archiveChunks).toString('utf8')).not.toContain(
        PLAINTEXT_CANARY,
      );
      expect(mockedKeyFiles.writeStream).toHaveBeenCalledWith(
        'D:\\backups\\vault.cvkx',
        expect.anything(),
        1024 * 1024,
      );
      expect(snapshot.close).toHaveBeenCalledOnce();
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('closes the snapshot when the authenticated source aborts before publication', async () => {
    const fixture = await createFixture();
    const snapshot = createSnapshot(fixture.vault, {
      async *[Symbol.asyncIterator](): AsyncGenerator<{
        kind: 'group';
        record: EncryptedGroupRecord;
      }> {
        await Promise.resolve();
        yield { kind: 'group', record: fixture.group };
        throw new Error(PLAINTEXT_CANARY);
      },
    });

    try {
      await expect(
        createProtectedEncryptedBackup({
          destination: 'D:\\backups\\aborted.cvkx',
          snapshot: snapshot.value,
          rootKey: fixture.rootKey,
          limits: { maximumBytes: 1024 * 1024, maximumRecords: 10 },
        }),
      ).rejects.toBeDefined();
      expect(snapshot.close).toHaveBeenCalledOnce();
      expect(mockedKeyFiles.writeStream).toHaveBeenCalledOnce();
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('validates the destination before entering the unlock runner', async () => {
    const validateDestination = vi
      .fn<typeof mockedKeyFiles.validateDestination>()
      .mockRejectedValue(new PortableKeyFileError('KEY_FILE_ALREADY_EXISTS'));
    const runUnlocked = vi.fn<ProductionBackupCreateDependencies['runUnlocked']>();

    await expect(
      executeProductionBackupCreate(
        {
          environment: {},
          secrets: {} as SecretInputPort,
          backendPolicy: { kind: 'native' },
          destination: 'D:\\backups\\existing.cvkx',
        },
        {
          validateDestination,
          runUnlocked:
            runUnlocked as unknown as ProductionBackupCreateDependencies['runUnlocked'],
        },
      ),
    ).rejects.toBeInstanceOf(CliBackupCreationError);
    expect(validateDestination).toHaveBeenCalledWith('D:\\backups\\existing.cvkx');
    expect(runUnlocked).not.toHaveBeenCalled();
  });

  it('zeroizes the caller-owned root key after production publication', async () => {
    const fixture = await createFixture();
    const snapshot = createSnapshot(fixture.vault, []);
    const store = {} as LocalBackupStore;
    const environment = {
      openSyncStore: vi.fn().mockResolvedValue(store),
    };
    const unlocked = {
      profile: { vaultId: VAULT_ID },
      environment,
    } as unknown as ProductionUnlockedContext;
    const runUnlockedMock = vi.fn(
      (
        _request: ProductionUnlockedRequest,
        operation: (context: ProductionUnlockedContext) => Promise<unknown>,
      ): Promise<unknown> => operation(unlocked),
    );
    const openSnapshot = vi.fn().mockResolvedValue(snapshot.value);
    const unwrapRootKey = vi.fn().mockResolvedValue(fixture.rootKey);

    try {
      await expect(
        executeProductionBackupCreate(
          {
            environment: {},
            secrets: {} as SecretInputPort,
            backendPolicy: { kind: 'native' },
            destination: 'D:\\backups\\published.cvkx',
          },
          {
            validateDestination: mockedKeyFiles.validateDestination,
            runUnlocked:
              runUnlockedMock as unknown as ProductionBackupCreateDependencies['runUnlocked'],
            openSnapshot,
            unwrapRootKey,
          },
        ),
      ).resolves.toMatchObject({ action: 'created', recordCount: 1 });
      expect(openSnapshot).toHaveBeenCalledWith(store, VAULT_ID);
      expect(unwrapRootKey).toHaveBeenCalledWith(unlocked);
      expect(snapshot.close).toHaveBeenCalledOnce();
      expect([...fixture.rootKey]).toEqual(
        Array.from({ length: fixture.rootKey.byteLength }, () => 0),
      );
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('refuses a backup while local opaque mutations are pending', async () => {
    const fixture = await createFixture();
    const store: LocalBackupStore = {
      getVault: () => Promise.resolve(fixture.vault),
      listPendingMutations: () => Promise.resolve([{}]),
      listOpaqueRecords: () => Promise.resolve([]),
      getCurrentGroup: () => Promise.resolve(null),
      listCurrentItems: () => emptyAsyncIterable(),
    };

    try {
      await expect(openLocalBackupSnapshot(store, VAULT_ID)).rejects.toBeInstanceOf(
        CliUsageError,
      );
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('fails closed instead of silently omitting unsupported local record families', async () => {
    const fixture = await createFixture();
    const store: LocalBackupStore = {
      getVault: () => Promise.resolve(fixture.vault),
      listPendingMutations: () => Promise.resolve([]),
      listOpaqueRecords: () =>
        Promise.resolve([
          {
            id: 'attachment.backup.test0001',
            vaultId: VAULT_ID,
            groupId: GROUP_ID,
            itemId: 'item.backup.test0001',
          },
        ]),
      getCurrentGroup: () => Promise.resolve(null),
      listCurrentItems: () => emptyAsyncIterable(),
    };

    try {
      await expect(openLocalBackupSnapshot(store, VAULT_ID)).rejects.toBeInstanceOf(
        CliUsageError,
      );
    } finally {
      zeroize(fixture.rootKey);
    }
  });
});

describe('production encrypted backup verification', () => {
  it('preflights the source before unlock and does not read an unsafe path', async () => {
    const validateSource = vi
      .fn<typeof mockedKeyFiles.validateSource>()
      .mockRejectedValue(new PortableKeyFileError('KEY_FILE_UNSAFE'));
    const runUnlocked = vi.fn<ProductionBackupVerifyDependencies['runUnlocked']>();

    await expect(
      executeProductionBackupVerify(
        {
          environment: {},
          secrets: {} as SecretInputPort,
          backendPolicy: { kind: 'native' },
          source: 'D:\\backups\\unsafe.cvkx',
        },
        {
          validateSource,
          runUnlocked:
            runUnlocked as unknown as ProductionBackupVerifyDependencies['runUnlocked'],
        },
      ),
    ).rejects.toMatchObject({ code: 'BACKUP_INVALID' });
    expect(validateSource).toHaveBeenCalledWith(
      'D:\\backups\\unsafe.cvkx',
      128 * 1024 * 1024,
    );
    expect(runUnlocked).not.toHaveBeenCalled();
  });

  it('authenticates a complete archive, returns only bounded metadata, and wipes inputs', async () => {
    const fixture = await createFixture();
    const chunks: Buffer[] = [];
    for await (const chunk of createEncryptedBackup(
      {
        vault: fixture.vault,
        records: values([{ kind: 'group', record: fixture.group }]),
        createdAt: CREATED_AT,
        limits: { maximumBytes: 1024 * 1024, maximumRecords: 10 },
      },
      fixture.rootKey,
    )) {
      chunks.push(Buffer.from(chunk));
    }
    const archive = Buffer.concat(chunks);
    const unlocked = {
      profile: { vaultId: VAULT_ID },
    } as unknown as ProductionUnlockedContext;
    const runUnlockedMock = vi.fn(
      (
        _request: ProductionUnlockedRequest,
        operation: (context: ProductionUnlockedContext) => Promise<unknown>,
      ): Promise<unknown> => operation(unlocked),
    );
    const unwrapRootKey = vi.fn().mockResolvedValue(fixture.rootKey);
    mockedKeyFiles.readSource.mockResolvedValue(archive);

    try {
      await expect(
        executeProductionBackupVerify(
          {
            environment: {},
            secrets: {} as SecretInputPort,
            backendPolicy: { kind: 'native' },
            source: 'D:\\backups\\verified.cvkx',
            limits: { maximumBytes: 1024 * 1024, maximumRecords: 10 },
          },
          {
            validateSource: mockedKeyFiles.validateSource,
            readSource: mockedKeyFiles.readSource,
            runUnlocked:
              runUnlockedMock as unknown as ProductionBackupVerifyDependencies['runUnlocked'],
            unwrapRootKey,
          },
        ),
      ).resolves.toMatchObject({
        action: 'verified',
        vaultId: VAULT_ID,
        recordCount: 2,
        bytes: archive.byteLength,
        schemaVersion: 1,
        createdAt: CREATED_AT,
      });
      expect(mockedKeyFiles.readSource).toHaveBeenCalledWith(
        'D:\\backups\\verified.cvkx',
        1024 * 1024,
      );
      expect(unwrapRootKey).toHaveBeenCalledWith(unlocked);
      expect([...fixture.rootKey]).toEqual(
        Array.from({ length: fixture.rootKey.byteLength }, () => 0),
      );
      expect([...archive]).toEqual(Array.from({ length: archive.length }, () => 0));
    } finally {
      zeroize(fixture.rootKey);
      archive.fill(0);
    }
  });

  it('rejects authenticated semantic families that this command cannot verify', async () => {
    const fixture = await createFixture();
    const chunks: Buffer[] = [];
    for await (const chunk of createEncryptedBackup(
      {
        vault: fixture.vault,
        records: values([{ kind: 'group', record: fixture.group }]),
        createdAt: CREATED_AT,
        limits: { maximumBytes: 1024 * 1024, maximumRecords: 10 },
      },
      fixture.rootKey,
    )) {
      chunks.push(Buffer.from(chunk));
    }
    const archive = Buffer.concat(chunks);
    const summary = await verifyEncryptedBackup(
      values([archive]),
      fixture.rootKey,
      VAULT_ID,
      { maximumBytes: 1024 * 1024, maximumRecords: 10 },
    );
    const unlocked = {
      profile: { vaultId: VAULT_ID },
    } as unknown as ProductionUnlockedContext;
    const runUnlockedMock = vi.fn(
      (
        _request: ProductionUnlockedRequest,
        operation: (context: ProductionUnlockedContext) => Promise<unknown>,
      ): Promise<unknown> => operation(unlocked),
    );
    const verifyArchive = vi
      .fn<typeof verifyEncryptedBackup>()
      .mockImplementation(async (_source, _rootKey, _vaultId, _limits, options) => {
        await options?.onEntry?.({ kind: 'history' } as EncryptedBackupEntry);
        return summary;
      });
    mockedKeyFiles.readSource.mockResolvedValue(Buffer.from(archive));

    try {
      await expect(
        executeProductionBackupVerify(
          {
            environment: {},
            secrets: {} as SecretInputPort,
            backendPolicy: { kind: 'native' },
            source: 'D:\\backups\\history.cvkx',
          },
          {
            validateSource: mockedKeyFiles.validateSource,
            readSource: mockedKeyFiles.readSource,
            verifyArchive,
            runUnlocked:
              runUnlockedMock as unknown as ProductionBackupVerifyDependencies['runUnlocked'],
            unwrapRootKey: vi.fn().mockResolvedValue(fixture.rootKey),
          },
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_DECRYPTABILITY_UNSUPPORTED' });
      expect(verifyArchive).toHaveBeenCalledOnce();
    } finally {
      zeroize(fixture.rootKey);
      archive.fill(0);
    }
  });

  it('maps authenticated tampering to the documented safe verification code', async () => {
    const fixture = await createFixture();
    const chunks: Buffer[] = [];
    for await (const chunk of createEncryptedBackup(
      {
        vault: fixture.vault,
        records: values([]),
        createdAt: CREATED_AT,
        limits: { maximumBytes: 1024 * 1024, maximumRecords: 10 },
      },
      fixture.rootKey,
    )) {
      chunks.push(Buffer.from(chunk));
    }
    const tampered = Buffer.concat(chunks);
    const saltMarker = Buffer.from('"salt":"', 'utf8');
    const saltStart = tampered.indexOf(saltMarker);
    if (saltStart < 0) throw new Error('Backup fixture has no salt.');
    const tamperedIndex = saltStart + saltMarker.byteLength;
    const tamperedByte = tampered[tamperedIndex];
    if (tamperedByte === undefined) throw new Error('Backup fixture is empty.');
    tampered[tamperedIndex] = tamperedByte === 65 ? 66 : 65;
    const unlocked = {
      profile: { vaultId: VAULT_ID },
    } as unknown as ProductionUnlockedContext;
    const runUnlockedMock = vi.fn(
      (
        _request: ProductionUnlockedRequest,
        operation: (context: ProductionUnlockedContext) => Promise<unknown>,
      ): Promise<unknown> => operation(unlocked),
    );
    mockedKeyFiles.readSource.mockImplementation(() =>
      Promise.resolve(Buffer.from(tampered)),
    );

    try {
      const verification = executeProductionBackupVerify(
        {
          environment: {},
          secrets: {} as SecretInputPort,
          backendPolicy: { kind: 'native' },
          source: 'D:\\backups\\tampered.cvkx',
        },
        {
          validateSource: mockedKeyFiles.validateSource,
          readSource: mockedKeyFiles.readSource,
          runUnlocked:
            runUnlockedMock as unknown as ProductionBackupVerifyDependencies['runUnlocked'],
          unwrapRootKey: vi.fn().mockResolvedValue(fixture.rootKey),
        },
      );
      await expect(verification).rejects.toBeInstanceOf(CliBackupVerificationError);
      await expect(verification).rejects.toMatchObject({
        code: 'BACKUP_AUTHENTICATION_FAILED',
      });
    } finally {
      zeroize(fixture.rootKey);
      tampered.fill(0);
    }
  });
});

describe('protected isolated encrypted backup restoration', () => {
  it('preflights the source before opening a target or restore coordinator', async () => {
    const validateSource = vi
      .fn<typeof mockedKeyFiles.validateSource>()
      .mockRejectedValue(new PortableKeyFileError('KEY_FILE_UNSAFE'));
    const restoreArchive = vi.fn<typeof restoreEncryptedBackup>();
    const store = {} as BackupRestoreStore;
    const openVerification = vi.fn() as unknown as RestoreVerificationSessionFactory;

    const operation = executeProtectedEncryptedBackupRestore(
      {
        source: 'D:\\backups\\unsafe-restore.cvkx',
        expectedVaultId: VAULT_ID,
        store,
        openVerification,
      },
      { validateSource, restoreArchive },
    );

    await expect(operation).rejects.toMatchObject({ code: 'BACKUP_INVALID' });
    expect(validateSource).toHaveBeenCalledWith(
      'D:\\backups\\unsafe-restore.cvkx',
      128 * 1024 * 1024,
    );
    expect(restoreArchive).not.toHaveBeenCalled();
    expect(mockedKeyFiles.readSource).not.toHaveBeenCalled();
  });

  it('passes the protected archive to the isolated restore ports and wipes it after commit', async () => {
    const fixture = await createFixture();
    const authenticated = await createAuthenticatedArchive(fixture);
    const store = {} as BackupRestoreStore;
    const openVerification = vi.fn() as unknown as RestoreVerificationSessionFactory;
    mockedKeyFiles.readSource.mockResolvedValue(authenticated.archive);
    const restoreArchive = vi
      .fn<typeof restoreEncryptedBackup>()
      .mockImplementation(
        async (source, expectedVaultId, receivedStore, receivedFactory, limits) => {
          let bytes = 0;
          for await (const chunk of source) bytes += chunk.byteLength;
          expect(bytes).toBe(authenticated.archive.byteLength);
          expect(expectedVaultId).toBe(VAULT_ID);
          expect(receivedStore).toBe(store);
          expect(receivedFactory).toBe(openVerification);
          expect(limits).toMatchObject({
            maximumBytes: 1024 * 1024,
            maximumRecords: 10,
          });
          return {
            disposition: 'verified-and-committed',
            backup: authenticated.summary,
            verification: authenticated.verification,
          };
        },
      );

    try {
      await expect(
        executeProtectedEncryptedBackupRestore(
          {
            source: 'D:\\backups\\restore.cvkx',
            expectedVaultId: VAULT_ID,
            store,
            openVerification,
            limits: { maximumBytes: 1024 * 1024, maximumRecords: 10 },
          },
          {
            validateSource: mockedKeyFiles.validateSource,
            readSource: mockedKeyFiles.readSource,
            restoreArchive,
          },
        ),
      ).resolves.toEqual({
        action: 'restored',
        vaultId: VAULT_ID,
        recordCount: authenticated.summary.recordCount,
        bytes: authenticated.archive.byteLength,
        restoreSessionId: authenticated.summary.restoreSessionId,
        selectedSlotId: SLOT_ID,
      });
      expect(mockedKeyFiles.validateSource).toHaveBeenCalledWith(
        'D:\\backups\\restore.cvkx',
        1024 * 1024,
      );
      expect(mockedKeyFiles.readSource).toHaveBeenCalledWith(
        'D:\\backups\\restore.cvkx',
        1024 * 1024,
      );
      expect([...authenticated.archive]).toEqual(
        Array.from({ length: authenticated.archive.length }, () => 0),
      );
    } finally {
      zeroize(fixture.rootKey);
      authenticated.archive.fill(0);
    }
  });

  it('reports an exact committed replay without fabricating a slot receipt', async () => {
    const fixture = await createFixture();
    const authenticated = await createAuthenticatedArchive(fixture);
    const store = {} as BackupRestoreStore;
    const openVerification = vi.fn() as unknown as RestoreVerificationSessionFactory;
    mockedKeyFiles.readSource.mockResolvedValue(authenticated.archive);
    const restoreArchive = vi.fn<typeof restoreEncryptedBackup>().mockResolvedValue({
      disposition: 'previously-committed',
      backup: authenticated.summary,
    });

    try {
      await expect(
        executeProtectedEncryptedBackupRestore(
          {
            source: 'D:\\backups\\replay.cvkx',
            expectedVaultId: VAULT_ID,
            store,
            openVerification,
          },
          { restoreArchive },
        ),
      ).resolves.toEqual({
        action: 'already-committed',
        vaultId: VAULT_ID,
        recordCount: authenticated.summary.recordCount,
        bytes: authenticated.archive.byteLength,
        restoreSessionId: authenticated.summary.restoreSessionId,
      });
    } finally {
      zeroize(fixture.rootKey);
      authenticated.archive.fill(0);
    }
  });

  it('maps uncertain publication to preservation instructions without exposing the cause', async () => {
    const archive = Buffer.from(PLAINTEXT_CANARY, 'utf8');
    mockedKeyFiles.readSource.mockResolvedValue(archive);
    const store = {} as BackupRestoreStore;
    const openVerification = vi.fn() as unknown as RestoreVerificationSessionFactory;
    const restoreArchive = vi
      .fn<typeof restoreEncryptedBackup>()
      .mockRejectedValue(
        new BackupError(
          'BACKUP_COMMIT_UNCERTAIN',
          `target contains ${PLAINTEXT_CANARY}`,
        ),
      );

    try {
      const operation = executeProtectedEncryptedBackupRestore(
        {
          source: 'D:\\backups\\uncertain.cvkx',
          expectedVaultId: VAULT_ID,
          store,
          openVerification,
        },
        { restoreArchive },
      );
      const caught = await operation.catch((error: unknown) => error);
      expect(caught).toBeInstanceOf(CliBackupRestoreError);
      if (!(caught instanceof CliBackupRestoreError)) {
        throw new Error('Expected a safe backup restore error.');
      }
      expect(caught.code).toBe('BACKUP_COMMIT_UNCERTAIN');
      expect(caught.message).toContain('Preserve the archive and isolated target');
      expect(caught.message).not.toContain(PLAINTEXT_CANARY);
      expect([...archive]).toEqual(Array.from({ length: archive.length }, () => 0));
    } finally {
      archive.fill(0);
    }
  });
});

function createSnapshot(
  vault: VaultRecord,
  records:
    | AsyncIterable<{ kind: 'group'; record: EncryptedGroupRecord }>
    | readonly [{ kind: 'group'; record: EncryptedGroupRecord }]
    | readonly [],
): Readonly<{ value: LocalBackupSnapshot; close: ReturnType<typeof vi.fn> }> {
  const close = vi.fn(() => Promise.resolve());
  const source = isAsyncIterable(records) ? records : values(records);
  return {
    value: { vault, records: source, close },
    close,
  };
}

function isAsyncIterable(
  value: AsyncIterable<unknown> | readonly unknown[],
): value is AsyncIterable<unknown> {
  return Symbol.asyncIterator in Object(value);
}

function values<T>(items: readonly T[]): AsyncIterable<T> {
  return {
    async *[Symbol.asyncIterator](): AsyncGenerator<T> {
      await Promise.resolve();
      yield* items;
    },
  };
}

function emptyAsyncIterable<T>(): AsyncIterable<T> {
  return values([]);
}

async function createFixture(): Promise<{
  rootKey: ReturnType<typeof generateVaultRootKey>;
  vault: VaultRecord;
  group: EncryptedGroupRecord;
}> {
  const rootKey = generateVaultRootKey();
  const portableKey = generatePortableKey();
  const slot = await createPortableKeySlot(
    {
      vaultId: VAULT_ID,
      slotId: SLOT_ID,
      schemaVersion: 1,
      keyVersion: 1,
      createdAt: CREATED_AT,
    },
    portableKey,
    rootKey,
  );
  zeroize(portableKey);

  const encryptedPreferences = await encryptPayload(
    Buffer.from('{"locked":true}', 'utf8'),
    rootKey,
    associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: VAULT_ID,
      entityType: 'vault-preferences',
      entityId: VAULT_ID,
      purpose: 'vault-preferences',
    }),
  );
  const vault = vaultRecordSchema.parse({
    id: VAULT_ID,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [slot],
    currentKeyVersion: 1,
    revision: 0,
    encryptedPreferences,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });

  const groupKey = generateGroupKey();
  const wrappedGroupKey = await wrapGroupKey(
    groupKey,
    rootKey,
    associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: VAULT_ID,
      entityType: 'wrapped-group-key',
      entityId: GROUP_ID,
      purpose: 'group-key',
    }),
  );
  const encryptedPayload = await encryptPayload(
    Buffer.from(PLAINTEXT_CANARY, 'utf8'),
    groupKey,
    associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: VAULT_ID,
      entityType: 'group',
      entityId: GROUP_ID,
      purpose: 'group-payload',
    }),
  );
  zeroize(groupKey);
  const group = encryptedGroupRecordSchema.parse({
    id: GROUP_ID,
    vaultId: VAULT_ID,
    schemaVersion: 1,
    wrappedGroupKey,
    encryptedPayload,
    templateVersion: 1,
    recordRevision: 1,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
  return { rootKey, vault, group };
}

async function createAuthenticatedArchive(
  fixture: Awaited<ReturnType<typeof createFixture>>,
): Promise<{
  archive: Buffer;
  summary: Awaited<ReturnType<typeof verifyEncryptedBackup>>;
  verification: ReturnType<typeof restoreKnownRecordsVerificationV1Schema.parse>;
}> {
  const chunks: Buffer[] = [];
  for await (const chunk of createEncryptedBackup(
    {
      vault: fixture.vault,
      records: values([{ kind: 'group', record: fixture.group }]),
      createdAt: CREATED_AT,
      limits: { maximumBytes: 1024 * 1024, maximumRecords: 10 },
    },
    fixture.rootKey,
  )) {
    chunks.push(Buffer.from(chunk));
  }
  const archive = Buffer.concat(chunks);
  const summary = await verifyEncryptedBackup(
    values([archive]),
    fixture.rootKey,
    VAULT_ID,
    { maximumBytes: 1024 * 1024, maximumRecords: 10 },
  );
  const verification = restoreKnownRecordsVerificationV1Schema.parse({
    version: 1,
    scope: 'known-v1-records',
    vaultId: VAULT_ID,
    vaultRevision: fixture.vault.revision,
    restoreSessionId: summary.restoreSessionId,
    transcriptSha256: summary.transcriptSha256,
    canonicalEntriesSha256: summary.canonicalEntriesSha256,
    recordCount: summary.recordCount,
    selectedSlot: { id: SLOT_ID, type: 'portable-key', keyVersion: 1 },
    verified: {
      vaults: 1,
      groups: 1,
      items: 0,
      attachments: 0,
      attachmentHeaders: 0,
      attachmentChunks: 0,
      tombstonePredecessors: { groups: 0, items: 0, attachments: 0 },
      tombstones: 0,
      histories: 0,
      audits: 0,
    },
  });
  return { archive, summary, verification };
}
