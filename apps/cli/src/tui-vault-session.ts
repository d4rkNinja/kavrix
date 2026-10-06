import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';

import { readSecureFile } from '@kavrix/key-files';
import { zeroize } from '@kavrix/crypto';
import {
  FileEncryptedDatabaseStore,
  MongoEncryptedDatabaseStore,
  EncryptedDatabaseStoreError,
  type EncryptedDatabaseStore,
} from '@kavrix/storage';
import type { VaultId } from '@kavrix/schemas';

import { DatabaseSession } from './database-session.js';
import type { DatastoreProfile } from './datastore-profiles.js';

export const TUI_SESSION_IDLE_MS = 120_000;
export const TUI_SESSION_MAX_MS = 900_000;

/** Storage leases never remain open between TUI actions. No key material lives here. */
class LeasedStore implements EncryptedDatabaseStore {
  current: EncryptedDatabaseStore | undefined;
  get active(): EncryptedDatabaseStore {
    if (this.current === undefined) throw new EncryptedDatabaseStoreError('closed');
    return this.current;
  }
  ping: EncryptedDatabaseStore['ping'] = () => this.active.ping();
  getDatabase: EncryptedDatabaseStore['getDatabase'] = (...args) =>
    this.active.getDatabase(...args);
  createDatabase: EncryptedDatabaseStore['createDatabase'] = (...args) =>
    this.active.createDatabase(...args);
  updateDatabase: EncryptedDatabaseStore['updateDatabase'] = (...args) =>
    this.active.updateDatabase(...args);
  listVaults: EncryptedDatabaseStore['listVaults'] = (...args) =>
    this.active.listVaults(...args);
  getVault: EncryptedDatabaseStore['getVault'] = (...args) =>
    this.active.getVault(...args);
  createVault: EncryptedDatabaseStore['createVault'] = (...args) =>
    this.active.createVault(...args);
  updateVault: EncryptedDatabaseStore['updateVault'] = (...args) =>
    this.active.updateVault(...args);
  deleteVault: EncryptedDatabaseStore['deleteVault'] = (...args) =>
    this.active.deleteVault(...args);
  async close(): Promise<void> {
    const store = this.current;
    this.current = undefined;
    await store?.close();
  }
}

/** CLI-owned reusable keys; fresh permissions, routing, ciphertext and anchor per operation. */
export class TuiVaultSession {
  readonly #store = new LeasedStore();
  #session: DatabaseSession | undefined;
  #binding: string | undefined;
  #keyIdentity: string | undefined;
  #startedAt = 0;
  #lastUsedAt = 0;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #inFlight = false;
  #expired = false;

  constructor(
    private readonly onExpired: (error?: unknown) => Promise<void>,
    private readonly idleMs = TUI_SESSION_IDLE_MS,
    private readonly maxMs = TUI_SESSION_MAX_MS,
  ) {
    if (
      !Number.isSafeInteger(idleMs) ||
      idleMs <= 0 ||
      idleMs > TUI_SESSION_IDLE_MS ||
      !Number.isSafeInteger(maxMs) ||
      maxMs <= 0 ||
      maxMs > TUI_SESSION_MAX_MS
    )
      throw new Error('Invalid TUI session lifetime.');
  }

  async run<T>(
    profile: DatastoreProfile,
    vaultId: VaultId,
    passphrase: Uint8Array,
    databaseUrl: string | undefined,
    operation: (session: DatabaseSession, vaultId: VaultId) => Promise<T>,
  ): Promise<T> {
    if (this.#expiryFailure !== undefined)
      throw new Error('TUI session cleanup failed; restart the app.');
    if (this.#inFlight) throw new Error('TUI session is busy.');
    if (profile.databaseId === undefined)
      throw new Error('A bound database profile is required.');
    if (this.#expired) throw new Error('TUI session expired; unlock again.');
    this.#inFlight = true;
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    try {
      const binding = JSON.stringify(profile);
      const identity = await keyIdentity(profile.keyFile);
      if (this.#session !== undefined) {
        const elapsed = performance.now();
        if (
          binding !== this.#binding ||
          identity !== this.#keyIdentity ||
          elapsed - this.#startedAt >= this.maxMs ||
          elapsed - this.#lastUsedAt >= this.idleMs
        )
          throw new Error('TUI session changed or expired; unlock again.');
      }
      this.#store.current =
        profile.datastore === 'file'
          ? await FileEncryptedDatabaseStore.open(profile.dataFile)
          : await MongoEncryptedDatabaseStore.connect(
              requireUrl(databaseUrl),
              profile.database,
              {
                databaseCollectionName: profile.databaseCollection,
                vaultCollectionName: profile.vaultCollection,
                allowInsecureTransport: needsInsecureTransport(requireUrl(databaseUrl)),
              },
            );
      if (this.#session === undefined) {
        this.#session = await DatabaseSession.open({
          store: this.#store,
          keyFile: profile.keyFile,
          passphrase,
          expectedDatabaseId: profile.databaseId,
        });
        if ((await keyIdentity(profile.keyFile)) !== identity)
          throw new Error('TUI key file changed; unlock again.');
        this.#binding = binding;
        this.#keyIdentity = identity;
        this.#startedAt = performance.now();
      } else {
        await this.#session.verifyCurrentState();
      }
      const result = await operation(this.#session, vaultId);
      if (performance.now() - this.#startedAt >= this.maxMs) {
        this.#expired = true;
        throw new Error('TUI session expired; unlock again.');
      }
      this.#lastUsedAt = performance.now();
      return result;
    } catch (error) {
      await this.#clear();
      throw error;
    } finally {
      try {
        await this.#releaseStore();
      } finally {
        this.#inFlight = false;
      }
      if (this.#session !== undefined) {
        this.touch();
      }
    }
  }

  async close(): Promise<void> {
    if (this.#inFlight) throw new Error('TUI session is busy.');
    await this.#clear();
    this.#expired = false;
  }

  /** Backend activity renews idle retention, never the absolute deadline. */
  touch(): void {
    if (this.#session === undefined || this.#inFlight || this.#expired) return;
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#lastUsedAt = performance.now();
    const delay = Math.max(
      1,
      Math.min(this.idleMs, this.maxMs - (this.#lastUsedAt - this.#startedAt)),
    );
    this.#timer = setTimeout(() => {
      this.#expired = true;
      void this.#expire();
    }, delay);
    this.#timer.unref();
  }

  async #releaseStore(): Promise<void> {
    try {
      await this.#store.close();
    } catch (error) {
      await this.#clear();
      throw error;
    }
  }

  async #expire(): Promise<void> {
    let failure: unknown;
    try {
      await this.#clear();
    } catch (error) {
      failure = error;
    }
    try {
      await this.onExpired(failure);
    } catch (error) {
      this.#expiryFailure = error;
    }
  }

  #expiryFailure: unknown;

  async #clear(): Promise<void> {
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
    const session = this.#session;
    this.#session = undefined;
    this.#binding = undefined;
    this.#keyIdentity = undefined;
    await session?.close();
  }
}

async function keyIdentity(path: string): Promise<string> {
  const bytes = await readSecureFile(path, 256 * 1024);
  try {
    return createHash('sha256').update(bytes).digest('hex');
  } finally {
    zeroize(bytes);
  }
}

function requireUrl(value: string | undefined): string {
  if (value === undefined) throw new Error('MongoDB connection input is required.');
  return value;
}

function needsInsecureTransport(value: string): boolean {
  const host = new URL(value).hostname.replace(/^\[|\]$/gu, '').toLowerCase();
  return host !== 'localhost' && host !== '127.0.0.1' && host !== '::1';
}
