import {
  BackupError,
  createEncryptedBackup,
  resolveBackupLimits,
  type BackupLimits,
  type EncryptedBackupEntry,
} from '@kavrix/import-export';
import {
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  tombstoneRecordSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type TombstoneRecord,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import {
  MAX_SECURE_STREAM_FILE_BYTES,
  validateSecureFileDestination,
  writeSecureStreamFile,
  PortableKeyFileError,
} from '@kavrix/key-files';
import { zeroize, type VaultRootKey } from '@kavrix/crypto';

import { CliBackupCreationError, CliUsageError } from '../errors.js';
import type { CliBackupCreateResult } from '../contracts.js';
import type { SecretInputPort } from '../secret-input.js';
import type { SecretBackendPolicy } from './secret-backend.js';
import { runProductionUnlocked, unwrapRememberedDeviceRootKey } from './unlock.js';

export const MAX_CLI_BACKUP_RECORDS = 10_000;
export const MAX_CLI_BACKUP_BYTES = MAX_SECURE_STREAM_FILE_BYTES;

const DEFAULT_BACKUP_LIMITS: Required<BackupLimits> = {
  maximumBytes: MAX_CLI_BACKUP_BYTES,
  maximumRecords: MAX_CLI_BACKUP_RECORDS,
};

type BackupCurrentGroup = Readonly<
  | { state: 'active'; record: EncryptedGroupRecord }
  | { state: 'deleted'; predecessor: EncryptedGroupRecord; tombstone: TombstoneRecord }
>;

type BackupCurrentItem = Readonly<
  | { state: 'active'; record: EncryptedItemRecord }
  | { state: 'deleted'; predecessor: EncryptedItemRecord; tombstone: TombstoneRecord }
>;

export interface LocalBackupStore {
  getVault(vaultId: VaultId): Promise<VaultRecord | null>;
  listPendingMutations(vaultId: VaultId): Promise<readonly unknown[]>;
  listOpaqueRecords(vaultId: VaultId): Promise<readonly unknown[]>;
  getCurrentGroup(
    vaultId: VaultId,
    groupId: string,
  ): Promise<BackupCurrentGroup | null>;
  listCurrentItems(vaultId: VaultId, groupId: string): AsyncIterable<BackupCurrentItem>;
}

export interface LocalBackupSnapshot {
  readonly vault: VaultRecord;
  readonly records: AsyncIterable<EncryptedBackupEntry>;
  close(): Promise<void>;
}

export type ProtectedBackupCreateInput = Readonly<{
  destination: string;
  snapshot: LocalBackupSnapshot;
  rootKey: VaultRootKey;
  limits?: BackupLimits;
}>;

export interface ProductionBackupCreateRequest {
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly secrets: SecretInputPort;
  readonly backendPolicy: SecretBackendPolicy;
  readonly destination: string;
  readonly vaultId?: VaultId;
  readonly limits?: BackupLimits;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

export interface ProductionBackupCreateDependencies {
  readonly validateDestination: typeof validateSecureFileDestination;
  readonly runUnlocked: typeof runProductionUnlocked;
  readonly openSnapshot: (
    store: LocalBackupStore,
    vaultId: VaultId,
  ) => Promise<LocalBackupSnapshot>;
  readonly unwrapRootKey: typeof unwrapRememberedDeviceRootKey;
}

const DEFAULT_DEPENDENCIES: ProductionBackupCreateDependencies = {
  validateDestination: validateSecureFileDestination,
  runUnlocked: runProductionUnlocked,
  openSnapshot: openLocalBackupSnapshot,
  unwrapRootKey: unwrapRememberedDeviceRootKey,
};

/**
 * Creates and publishes one complete authenticated archive. Destination
 * validation happens before the unlock runner is entered.
 */
export async function executeProductionBackupCreate(
  request: ProductionBackupCreateRequest,
  overrides: Partial<ProductionBackupCreateDependencies> = {},
): Promise<CliBackupCreateResult> {
  const dependencies = { ...DEFAULT_DEPENDENCIES, ...overrides };
  const destination = validateDestinationPath(request.destination);
  const limits = resolveCliBackupLimits(request.limits);
  try {
    await dependencies.validateDestination(destination);
  } catch (error) {
    if (error instanceof PortableKeyFileError || error instanceof BackupError) {
      throw new CliBackupCreationError();
    }
    throw error;
  }

  try {
    return await dependencies.runUnlocked(
      {
        environment: request.environment,
        secrets: request.secrets,
        backendPolicy: request.backendPolicy,
        ...(request.allowInsecureLoopbackDevelopment === undefined
          ? {}
          : {
              allowInsecureLoopbackDevelopment:
                request.allowInsecureLoopbackDevelopment,
            }),
      },
      async (unlocked) => {
        const requestedVault = request.vaultId;
        if (
          requestedVault !== undefined &&
          requestedVault !== unlocked.profile.vaultId
        ) {
          throw new CliUsageError(
            'The requested vault is not enrolled on this device.',
          );
        }
        const store = await unlocked.environment.openSyncStore(unlocked.profile);
        const rootKey = await dependencies.unwrapRootKey(unlocked);
        try {
          const snapshot = await dependencies.openSnapshot(
            store,
            unlocked.profile.vaultId,
          );
          return await createProtectedEncryptedBackup({
            destination,
            snapshot,
            rootKey,
            limits,
          });
        } finally {
          zeroizeRootKey(rootKey);
        }
      },
    );
  } catch (error) {
    if (error instanceof CliUsageError) throw error;
    if (error instanceof CliBackupCreationError) throw error;
    if (error instanceof PortableKeyFileError || error instanceof BackupError) {
      throw new CliBackupCreationError();
    }
    throw error;
  }
}

/** Streams the library-owned authenticated format through protected output. */
export async function createProtectedEncryptedBackup(
  input: ProtectedBackupCreateInput,
): Promise<CliBackupCreateResult> {
  let records = 1;
  let result: CliBackupCreateResult | undefined;
  let operationError: unknown;
  try {
    const destination = validateDestinationPath(input.destination);
    const limits = resolveCliBackupLimits(input.limits);
    const stream = createEncryptedBackup(
      {
        vault: input.snapshot.vault,
        records: countRecords(input.snapshot.records, () => {
          records += 1;
        }),
        limits,
      },
      input.rootKey,
    );
    const written = await writeSecureStreamFile(
      destination,
      stream,
      limits.maximumBytes,
    );
    result = {
      action: 'created',
      vaultId: vaultIdSchema.parse(input.snapshot.vault.id),
      recordCount: records,
      bytes: written.bytes,
    };
  } catch (error) {
    operationError = error;
  }

  let closeError: unknown;
  try {
    await input.snapshot.close();
  } catch (error) {
    closeError = error;
  }
  if (closeError !== undefined) throw new CliBackupCreationError();
  if (operationError instanceof CliUsageError) throw operationError;
  if (operationError instanceof CliBackupCreationError) throw operationError;
  if (operationError instanceof PortableKeyFileError) throw operationError;
  if (operationError instanceof BackupError) throw operationError;
  if (operationError !== undefined) throw new CliBackupCreationError();
  if (result === undefined) throw new CliBackupCreationError();
  return result;
}

/** Opens a bounded snapshot over the durable opaque local state. */
export async function openLocalBackupSnapshot(
  store: LocalBackupStore,
  vaultIdInput: VaultId,
): Promise<LocalBackupSnapshot> {
  const vaultId = vaultIdSchema.parse(vaultIdInput);
  const vaultResult = vaultRecordSchema.safeParse(await store.getVault(vaultId));
  if (!vaultResult.success || vaultResult.data.id !== vaultId) {
    throw new CliBackupCreationError();
  }
  const vault = vaultResult.data;
  const pending = await store.listPendingMutations(vaultId);
  if (pending.length !== 0) {
    throw new CliUsageError(
      'Synchronize or resolve pending local changes before creating a backup.',
    );
  }

  const opaqueRecords = await store.listOpaqueRecords(vaultId);
  const groupIds = new Set<string>();
  for (const candidate of opaqueRecords) {
    if (!isSupportedLocalOpaqueRecord(candidate, vaultId)) {
      throw new CliUsageError(
        'The local backup source contains a record family not supported by this command.',
      );
    }
    if (isOpaqueGroup(candidate)) groupIds.add(candidate.id);
  }
  const state = { closed: false };
  return {
    vault,
    records: localBackupEntries(store, vaultId, [...groupIds].sort(), state),
    close: () => {
      state.closed = true;
      return Promise.resolve();
    },
  };
}

function localBackupEntries(
  store: LocalBackupStore,
  vaultId: VaultId,
  groupIds: readonly string[],
  state: { closed: boolean },
): AsyncIterable<EncryptedBackupEntry> {
  return {
    async *[Symbol.asyncIterator](): AsyncGenerator<EncryptedBackupEntry> {
      for (const groupId of groupIds) {
        assertSnapshotOpen(state);
        const group = await store.getCurrentGroup(vaultId, groupId);
        if (group === null) throw new CliBackupCreationError();
        if (group.state === 'active') {
          yield { kind: 'group', record: group.record };
        } else {
          yield { kind: 'group', record: deletedCurrentGroup(group) };
          yield {
            kind: 'tombstone-predecessor',
            entityType: 'group',
            record: group.predecessor,
          };
          yield { kind: 'tombstone', record: group.tombstone };
        }

        for await (const item of store.listCurrentItems(vaultId, groupId)) {
          assertSnapshotOpen(state);
          if (item.state === 'active') {
            yield { kind: 'item', record: item.record };
          } else {
            yield { kind: 'item', record: deletedCurrentItem(item) };
            yield {
              kind: 'tombstone-predecessor',
              entityType: 'item',
              record: item.predecessor,
            };
            yield { kind: 'tombstone', record: item.tombstone };
          }
        }
      }
    },
  };
}

function deletedCurrentGroup(
  state: Extract<BackupCurrentGroup, { state: 'deleted' }>,
): EncryptedGroupRecord {
  return encryptedGroupRecordSchema.parse({
    ...state.predecessor,
    recordRevision: state.tombstone.tombstoneRevision,
    updatedAt: state.tombstone.deletedAt,
    tombstonedAt: state.tombstone.deletedAt,
  });
}

function deletedCurrentItem(
  state: Extract<BackupCurrentItem, { state: 'deleted' }>,
): EncryptedItemRecord {
  return encryptedItemRecordSchema.parse({
    ...state.predecessor,
    recordRevision: state.tombstone.tombstoneRevision,
    updatedAt: state.tombstone.deletedAt,
    tombstonedAt: state.tombstone.deletedAt,
  });
}

function countRecords(
  source: AsyncIterable<EncryptedBackupEntry>,
  onRecord: () => void,
): AsyncIterable<EncryptedBackupEntry> {
  return {
    async *[Symbol.asyncIterator](): AsyncGenerator<EncryptedBackupEntry> {
      for await (const entry of source) {
        onRecord();
        yield entry;
      }
    },
  };
}

function resolveCliBackupLimits(
  input: BackupLimits | undefined,
): Required<BackupLimits> {
  const resolved = resolveBackupLimits({
    maximumBytes: input?.maximumBytes ?? DEFAULT_BACKUP_LIMITS.maximumBytes,
    maximumRecords: input?.maximumRecords ?? DEFAULT_BACKUP_LIMITS.maximumRecords,
  });
  if (
    resolved.maximumBytes > MAX_CLI_BACKUP_BYTES ||
    resolved.maximumRecords > MAX_CLI_BACKUP_RECORDS
  ) {
    throw new CliUsageError('The backup limits exceed the CLI safety bound.');
  }
  return resolved;
}

function validateDestinationPath(input: string): string {
  if (
    typeof input !== 'string' ||
    input.length === 0 ||
    input.length > 32_768 ||
    Array.from(input).some((character) => {
      const codePoint = character.codePointAt(0);
      return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
    })
  ) {
    throw new CliUsageError('The backup destination path is invalid.');
  }
  return input;
}

function isOpaqueGroup(
  candidate: unknown,
): candidate is Readonly<{ id: string; vaultId: VaultId }> {
  return (
    typeof candidate === 'object' &&
    candidate !== null &&
    'id' in candidate &&
    'vaultId' in candidate &&
    typeof candidate.id === 'string' &&
    typeof candidate.vaultId === 'string' &&
    !('groupId' in candidate) &&
    !('itemId' in candidate) &&
    !('state' in candidate) &&
    candidate.vaultId.length > 0
  );
}

function isSupportedLocalOpaqueRecord(candidate: unknown, vaultId: VaultId): boolean {
  const vault = vaultRecordSchema.safeParse(candidate);
  if (vault.success) return vault.data.id === vaultId;
  const group = encryptedGroupRecordSchema.safeParse(candidate);
  if (group.success) return group.data.vaultId === vaultId;
  const item = encryptedItemRecordSchema.safeParse(candidate);
  if (item.success) return item.data.vaultId === vaultId;
  const tombstone = tombstoneRecordSchema.safeParse(candidate);
  return (
    tombstone.success &&
    tombstone.data.vaultId === vaultId &&
    (tombstone.data.entityType === 'group' || tombstone.data.entityType === 'item')
  );
}

function assertSnapshotOpen(state: { closed: boolean }): void {
  if (state.closed) throw new CliBackupCreationError();
}

function zeroizeRootKey(rootKey: VaultRootKey): void {
  zeroize(rootKey);
}
