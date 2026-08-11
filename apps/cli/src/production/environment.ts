import { createSecureClipboard, type SecureClipboard } from '@kavrix/clipboard';
import type { VaultProfile } from '@kavrix/client';
import {
  openSqliteInitializationJournal,
  openSqliteJoinLifecycleJournal,
  openSqliteSyncLocalStore,
  openSqliteVaultProfileStore,
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

export async function openProductionEnvironment(
  paths: CliDataPaths,
  secrets: SecretBackend,
): Promise<ProductionEnvironment> {
  await ensureDataDirectory(paths.home);
  const profiles = await openSqliteVaultProfileStore({ path: paths.profileStore });
  const initializationJournal = await openSqliteInitializationJournal({
    path: paths.initializationJournal,
  });
  const joinJournal = await openSqliteJoinLifecycleJournal({
    path: paths.joinJournal,
    protectedSecrets: secrets.joinJournalSecrets,
  });
  const clipboard = createSecureClipboard();
  const syncStores: SqliteSyncLocalStore[] = [];

  return {
    profiles,
    initializationJournal,
    joinJournal,
    clipboard,
    openSyncStore: async (profile) => {
      const store = await openSqliteSyncLocalStore({
        path: paths.vaultStore(profile.vaultId),
      });
      syncStores.push(store);
      return store;
    },
    close: async () => {
      for (const store of syncStores) store.close();
      await settle([
        initializationJournal.close(),
        joinJournal.close(),
        profiles.close(),
        clipboard.dispose().then(() => undefined),
      ]);
    },
  };
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
    throw new CliUsageError(
      "No vault is enrolled on this device. Run 'creds init' or 'creds device invite join' first.",
    );
  }
  return only;
}

/** Closes every resource even when one of them fails. */
async function settle(operations: readonly Promise<unknown>[]): Promise<void> {
  const results = await Promise.allSettled(operations);
  const failure = results.find((result) => result.status === 'rejected');
  if (failure !== undefined) throw failure.reason;
}
