import { createSecureClipboard, type SecureClipboard } from '@kavrix/clipboard';
import type { VaultProfile } from '@kavrix/client';
import {
  acquireLocalWriterLease,
  openSqliteInitializationJournal,
  openSqliteJoinLifecycleJournal,
  openSqliteSyncLocalStore,
  openSqliteVaultProfileStore,
  recoverStaleLocalWriterLease,
  type LocalWriterLease,
  type SqliteInitializationJournal,
  type SqliteJoinLifecycleJournal,
  type SqliteSyncLocalStore,
  type SqliteVaultProfileStore,
} from '@kavrix/local-store';

import { CliUsageError } from '../errors.js';
import type { CliDataPaths } from './paths.js';
import { ensureDataDirectory } from './runtime-adapters.js';
import type { SecretBackend } from './secret-backend.js';

/**
 * The stores that exist before any vault is known. The per-vault sync database
 * is opened separately, because its file name is derived from the vault the
 * active profile names.
 */
export interface ProductionEnvironment {
  readonly profiles: SqliteVaultProfileStore;
  readonly initializationJournal: SqliteInitializationJournal;
  readonly joinJournal: SqliteJoinLifecycleJournal;
  readonly clipboard: SecureClipboard;
  openSyncStore(profile: VaultProfile): Promise<SqliteSyncLocalStore>;
  close(): Promise<void>;
}

/** Resources needed by the locked, local-only status vertical slice. */
export interface ProductionStatusEnvironment {
  readonly profiles: SqliteVaultProfileStore;
  openSyncStore(profile: VaultProfile): Promise<SqliteSyncLocalStore>;
  close(): Promise<void>;
}

export interface ProductionEnvironmentDependencies {
  readonly ensureDataDirectory: typeof ensureDataDirectory;
  readonly acquireLease: typeof acquireLocalWriterLease;
  readonly recoverLease: typeof recoverStaleLocalWriterLease;
  readonly openProfiles: typeof openSqliteVaultProfileStore;
  readonly openInitializationJournal: typeof openSqliteInitializationJournal;
  readonly openJoinJournal: typeof openSqliteJoinLifecycleJournal;
  readonly openSyncStore: typeof openSqliteSyncLocalStore;
  readonly createClipboard: typeof createSecureClipboard;
}

export type ProductionStatusEnvironmentDependencies = Pick<
  ProductionEnvironmentDependencies,
  | 'ensureDataDirectory'
  | 'acquireLease'
  | 'recoverLease'
  | 'openProfiles'
  | 'openSyncStore'
>;

const DEFAULT_DEPENDENCIES: ProductionEnvironmentDependencies = {
  ensureDataDirectory,
  acquireLease: acquireLocalWriterLease,
  recoverLease: recoverStaleLocalWriterLease,
  openProfiles: openSqliteVaultProfileStore,
  openInitializationJournal: openSqliteInitializationJournal,
  openJoinJournal: openSqliteJoinLifecycleJournal,
  openSyncStore: openSqliteSyncLocalStore,
  createClipboard: createSecureClipboard,
};

const DEFAULT_STATUS_DEPENDENCIES: ProductionStatusEnvironmentDependencies = {
  ensureDataDirectory,
  acquireLease: acquireLocalWriterLease,
  recoverLease: recoverStaleLocalWriterLease,
  openProfiles: openSqliteVaultProfileStore,
  openSyncStore: openSqliteSyncLocalStore,
};

export async function openProductionEnvironment(
  paths: CliDataPaths,
  secrets: SecretBackend,
  dependencies: ProductionEnvironmentDependencies = DEFAULT_DEPENDENCIES,
): Promise<ProductionEnvironment> {
  let lease: LocalWriterLease | undefined;
  let profiles: SqliteVaultProfileStore | undefined;
  let initializationJournal: SqliteInitializationJournal | undefined;
  let joinJournal: SqliteJoinLifecycleJournal | undefined;
  let clipboard: SecureClipboard | undefined;
  try {
    await dependencies.ensureDataDirectory(paths.home);
    lease = await acquireGlobalLease(paths.writerLease, dependencies);
    profiles = await dependencies.openProfiles({ path: paths.profileStore });
    initializationJournal = await dependencies.openInitializationJournal({
      path: paths.initializationJournal,
    });
    joinJournal = await dependencies.openJoinJournal({
      path: paths.joinJournal,
      protectedSecrets: secrets.joinJournalSecrets,
    });
    clipboard = dependencies.createClipboard();
  } catch (openFailure) {
    const cleanupOperations: (() => unknown)[] = [];
    if (clipboard !== undefined) {
      const acquired = clipboard;
      cleanupOperations.push(() => acquired.dispose());
    }
    if (joinJournal !== undefined) {
      const acquired = joinJournal;
      cleanupOperations.push(() => acquired.close());
    }
    if (initializationJournal !== undefined) {
      const acquired = initializationJournal;
      cleanupOperations.push(() => acquired.close());
    }
    if (profiles !== undefined) {
      const acquired = profiles;
      cleanupOperations.push(() => acquired.close());
    }
    cleanupOperations.push(() => secrets.close());
    if (lease !== undefined) {
      const acquired = lease;
      cleanupOperations.push(() => acquired.release());
    }
    const cleanupFailures = await cleanup(cleanupOperations);
    if (cleanupFailures.length > 0) {
      throw closeFailure([openFailure, ...cleanupFailures]);
    }
    throw openFailure;
  }

  const ownedProfiles = requiredResource(profiles);
  const ownedInitializationJournal = requiredResource(initializationJournal);
  const ownedJoinJournal = requiredResource(joinJournal);
  const ownedClipboard = requiredResource(clipboard);
  const ownedLease = requiredResource(lease);
  const syncStores = createSyncStoreCache(paths, dependencies.openSyncStore);
  let closePromise: Promise<void> | undefined;

  return {
    profiles: ownedProfiles,
    initializationJournal: ownedInitializationJournal,
    joinJournal: ownedJoinJournal,
    clipboard: ownedClipboard,
    openSyncStore: syncStores.open,
    close: () => {
      closePromise ??= (async () => {
        const failures = await cleanup([
          ...syncStores.closeOperations(),
          () => ownedClipboard.dispose(),
          () => ownedJoinJournal.close(),
          () => ownedInitializationJournal.close(),
          () => ownedProfiles.close(),
          () => secrets.close(),
          () => ownedLease.release(),
        ]);
        if (failures.length > 0) throw closeFailure(failures);
      })();
      return closePromise;
    },
  };
}

/**
 * Opens only the local resources status can name. Calling this function
 * transfers backend ownership immediately: rollback closes it even when open
 * fails, and the returned environment owns it after a successful open.
 */
export async function openProductionStatusEnvironment(
  paths: CliDataPaths,
  secrets: SecretBackend,
  dependencies: ProductionStatusEnvironmentDependencies = DEFAULT_STATUS_DEPENDENCIES,
): Promise<ProductionStatusEnvironment> {
  let lease: LocalWriterLease | undefined;
  let profiles: SqliteVaultProfileStore | undefined;
  try {
    await dependencies.ensureDataDirectory(paths.home);
    lease = await acquireGlobalLease(paths.writerLease, dependencies);
    profiles = await dependencies.openProfiles({ path: paths.profileStore });
  } catch (openFailure) {
    const cleanupOperations: (() => unknown)[] = [];
    if (profiles !== undefined) {
      const acquired = profiles;
      cleanupOperations.push(() => acquired.close());
    }
    cleanupOperations.push(() => secrets.close());
    if (lease !== undefined) {
      const acquired = lease;
      cleanupOperations.push(() => acquired.release());
    }
    const cleanupFailures = await cleanup(cleanupOperations);
    if (cleanupFailures.length > 0) {
      throw closeFailure([openFailure, ...cleanupFailures]);
    }
    throw openFailure;
  }

  const ownedProfiles = requiredResource(profiles);
  const ownedLease = requiredResource(lease);
  const syncStores = createSyncStoreCache(paths, dependencies.openSyncStore);
  let closePromise: Promise<void> | undefined;

  return {
    profiles: ownedProfiles,
    openSyncStore: syncStores.open,
    close: () => {
      closePromise ??= (async () => {
        const failures = await cleanup([
          ...syncStores.closeOperations(),
          () => ownedProfiles.close(),
          () => secrets.close(),
          () => ownedLease.release(),
        ]);
        if (failures.length > 0) throw closeFailure(failures);
      })();
      return closePromise;
    },
  };
}

async function acquireGlobalLease(
  path: string,
  dependencies: Pick<
    ProductionEnvironmentDependencies,
    'acquireLease' | 'recoverLease'
  >,
): Promise<LocalWriterLease> {
  try {
    return await dependencies.acquireLease(path);
  } catch {
    await dependencies.recoverLease(path);
    return dependencies.acquireLease(path);
  }
}

/**
 * Resolves the single enrolled profile. Multiple enrollments are a real state,
 * but silently guessing between them could unlock the wrong vault, so the
 * ambiguity is surfaced instead.
 */
export async function resolveActiveProfile(
  profiles: SqliteVaultProfileStore,
): Promise<VaultProfile> {
  const enrolled = await profiles.listProfiles();
  if (enrolled.length > 1) {
    throw new CliUsageError(
      'More than one vault is enrolled on this device. Set CREDS_HOME to select one.',
    );
  }
  const [only] = enrolled;
  if (only === undefined) {
    throw new CliUsageError('No vault profile is enrolled in this data home.');
  }
  return only;
}

/** Runs cleanup sequentially in ownership order, including synchronous failures. */
async function cleanup(operations: readonly (() => unknown)[]): Promise<unknown[]> {
  const failures: unknown[] = [];
  for (const operation of operations) {
    try {
      await operation();
    } catch (error) {
      failures.push(error);
    }
  }
  return failures;
}

function closeFailure(failures: readonly unknown[]): AggregateError {
  return new AggregateError(failures, 'Production resources could not be closed.');
}

async function closeOpenedSyncStore(
  pending: Promise<SqliteSyncLocalStore>,
): Promise<void> {
  let store: SqliteSyncLocalStore;
  try {
    store = await pending;
  } catch {
    // No store was acquired, so this promise owns nothing to clean up.
    return;
  }
  store.close();
}

function createSyncStoreCache(
  paths: CliDataPaths,
  openStore: ProductionEnvironmentDependencies['openSyncStore'],
): Readonly<{
  open(profile: VaultProfile): Promise<SqliteSyncLocalStore>;
  closeOperations(): readonly (() => unknown)[];
}> {
  const stores = new Map<string, Promise<SqliteSyncLocalStore>>();
  const order: Promise<SqliteSyncLocalStore>[] = [];
  let closed = false;
  return {
    open: async (profile) => {
      if (closed) throw new CliUsageError('The production environment is closed.');
      const vaultId = profile.vaultId;
      let pending = stores.get(vaultId);
      if (pending === undefined) {
        const opening = openStore({ path: paths.vaultStore(vaultId) });
        pending = opening;
        stores.set(vaultId, opening);
        order.push(opening);
        void opening.catch(() => {
          if (stores.get(vaultId) === opening) {
            stores.delete(vaultId);
            const index = order.indexOf(opening);
            if (index >= 0) void order.splice(index, 1);
          }
        });
      }
      return pending;
    },
    closeOperations: () => {
      closed = true;
      return order.toReversed().map((pending) => () => closeOpenedSyncStore(pending));
    },
  };
}

function requiredResource<Resource>(resource: Resource | undefined): Resource {
  if (resource === undefined) {
    throw new Error('Production resource acquisition did not complete.');
  }
  return resource;
}
