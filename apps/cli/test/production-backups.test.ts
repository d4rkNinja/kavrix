import {
  associatedDataSchema,
  encryptedGroupRecordSchema,
  groupIdSchema,
  keySlotIdSchema,
  timestampSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type EncryptedGroupRecord,
  type VaultRecord,
} from '@kavrix/schemas';
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
  writeStream: vi.fn(),
}));

vi.mock('@kavrix/key-files', async () => {
  const actual = await vi.importActual<typeof KeyFiles>('@kavrix/key-files');
  return {
    ...actual,
    validateSecureFileDestination: mockedKeyFiles.validateDestination,
    writeSecureStreamFile: mockedKeyFiles.writeStream,
  };
});

import { PortableKeyFileError } from '@kavrix/key-files';
import { CliBackupCreationError, CliUsageError } from '../src/errors.js';
import {
  createProtectedEncryptedBackup,
  executeProductionBackupCreate,
  openLocalBackupSnapshot,
  type LocalBackupSnapshot,
  type LocalBackupStore,
  type ProductionBackupCreateDependencies,
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
