import type { KeychainPort, SessionCredentialPort } from '@kavrix/core';
import { CryptoAuthenticationError, VaultLockedError } from '@kavrix/core';
import {
  AuthenticationError,
  CryptoInputError,
  encodeBase64Url,
  parsePortableKey,
  parseRecoveryKey,
  unlockDeviceKeySlot,
  unlockPassphraseKeySlot,
  unlockPortableKeySlot,
  unlockRecoveryKeySlot,
  zeroize,
  type SlotBinding,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  apiBearerTokenSchema,
  deviceUnlockSecretSchema,
  keySlotIdSchema,
  sessionCredentialSecretSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type GroupId,
  type ItemId,
  type KeySlot,
  type KeySlotId,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import {
  SyncEngine,
  SyncLocalStateError,
  SyncProtocolError,
  SyncRollbackError,
  SyncTransportFailure,
  type SyncEngineOptions,
  type SyncLocalStorePort,
  type SyncRunResult,
} from '@kavrix/sync';
import type { SecureClipboardPort } from '@kavrix/clipboard';
import { z } from 'zod';

import {
  ControlPlaneClient,
  type ControlPlaneClientOptions,
} from './control-plane-client.js';
import { ControlPlaneFailure, VaultClientSessionError } from './errors.js';
import { FetchSyncTransport } from './fetch-sync-transport.js';
import {
  VaultInteractionService,
  type CredentialCopyOptions,
  type CredentialCopyReceipt,
  type CredentialShowProjection,
  type VaultInteractionOptions,
} from './vault-interaction-service.js';
import { VaultReadSession, type VaultReadSourcePort } from './vault-read-session.js';
import {
  isInsecureLoopbackProfile,
  vaultProfileSchema,
  type VaultProfile,
} from './vault-profile.js';

const REQUIRED_SCOPES = new Set(['sync:read', 'sync:write'] as const);
const MAX_PASSPHRASE_BYTES = 1024 * 1024;

export const vaultClientSessionStatusSchema = z.discriminatedUnion('state', [
  z
    .object({
      state: z.literal('locked'),
      vaultId: vaultProfileSchema.shape.vaultId,
      deviceId: vaultProfileSchema.shape.deviceId,
    })
    .strict(),
  z
    .object({
      state: z.literal('unlocked'),
      vaultId: vaultProfileSchema.shape.vaultId,
      deviceId: vaultProfileSchema.shape.deviceId,
    })
    .strict(),
]);

export type VaultClientSessionStatus = z.infer<typeof vaultClientSessionStatusSchema>;

export type VaultSyncStorePort = SyncLocalStorePort & VaultReadSourcePort;

export interface VaultClientSessionOptions {
  readonly profile: VaultProfile;
  readonly sessions: SessionCredentialPort;
  readonly keychain: KeychainPort;
  /** One concrete backing object prevents syncing and reading different stores. */
  readonly store: VaultSyncStorePort;
  readonly sync: Omit<SyncEngineOptions, 'transport' | 'local'>;
  readonly clipboard: SecureClipboardPort;
  readonly interaction: VaultInteractionOptions;
  readonly network?: Omit<
    ControlPlaneClientOptions,
    'baseUrl' | 'signal' | 'allowInsecureLoopbackDevelopment'
  >;
  readonly allowInsecureLoopbackDevelopment?: boolean;
}

type ActiveSession = Readonly<{
  epoch: number;
  abort: AbortController;
  source: BoundVaultReadSource;
  read: VaultReadSession;
  interaction: VaultInteractionService;
  sync: SyncEngine;
}>;

type SlotType = KeySlot['type'];

/**
 * Online-only, key-owning facade. It never returns a VRK, device secret, API
 * bearer, or copied credential value.
 */
export class VaultClientSession {
  readonly #profile: VaultProfile;
  readonly #sessions: SessionCredentialPort;
  readonly #keychain: KeychainPort;
  readonly #store: VaultSyncStorePort;
  readonly #syncOptions: Omit<SyncEngineOptions, 'transport' | 'local'>;
  readonly #clipboard: SecureClipboardPort;
  readonly #interactionOptions: VaultInteractionOptions;
  readonly #network:
    | Omit<
        ControlPlaneClientOptions,
        'baseUrl' | 'signal' | 'allowInsecureLoopbackDevelopment'
      >
    | undefined;
  readonly #allowInsecureLoopback: boolean;
  #state: ActiveSession | null = null;
  #pendingAbort: AbortController | null = null;
  #busy = false;
  #epoch = 0;

  constructor(options: VaultClientSessionOptions) {
    let profile: VaultProfile;
    try {
      profile = vaultProfileSchema.parse(options.profile);
    } catch {
      throw new VaultClientSessionError('invalid-input');
    }
    const allowInsecureLoopback = options.allowInsecureLoopbackDevelopment === true;
    if (isInsecureLoopbackProfile(profile) && !allowInsecureLoopback) {
      throw new VaultClientSessionError('invalid-input');
    }
    this.#profile = profile;
    this.#sessions = options.sessions;
    this.#keychain = options.keychain;
    this.#store = options.store;
    this.#syncOptions = options.sync;
    this.#clipboard = options.clipboard;
    this.#interactionOptions = options.interaction;
    this.#network = options.network;
    this.#allowInsecureLoopback = allowInsecureLoopback;
  }

  get locked(): boolean {
    return this.#state === null;
  }

  status(): VaultClientSessionStatus {
    return vaultClientSessionStatusSchema.parse({
      state: this.locked ? 'locked' : 'unlocked',
      vaultId: this.#profile.vaultId,
      deviceId: this.#profile.deviceId,
    });
  }

  async unlockPortable(
    formattedPortableKey: string,
    slotId?: KeySlotId,
  ): Promise<void> {
    validateFormattedKey(formattedPortableKey, 'portable');
    const expectedSlotId = parseOptionalSlotId(slotId);
    await this.#unlock((vault) => {
      const slot = selectCurrentSlot(vault, 'portable-key', expectedSlotId);
      return unlockPortableKeySlot(
        slot,
        formattedPortableKey,
        slotBinding(vault, slot),
      );
    });
  }

  async unlockRecovery(
    formattedRecoveryKey: string,
    slotId?: KeySlotId,
  ): Promise<void> {
    validateFormattedKey(formattedRecoveryKey, 'recovery');
    const expectedSlotId = parseOptionalSlotId(slotId);
    await this.#unlock((vault) => {
      const slot = selectCurrentSlot(vault, 'recovery-key', expectedSlotId);
      return unlockRecoveryKeySlot(
        slot,
        formattedRecoveryKey,
        slotBinding(vault, slot),
      );
    });
  }

  async unlockPassphrase(passphrase: Uint8Array, slotId: KeySlotId): Promise<void> {
    if (
      !(passphrase instanceof Uint8Array) ||
      passphrase.byteLength === 0 ||
      passphrase.byteLength > MAX_PASSPHRASE_BYTES
    ) {
      throw new VaultClientSessionError('invalid-input');
    }
    const expectedSlotId = parseRequiredSlotId(slotId);
    const ownedPassphrase = Uint8Array.from(passphrase);
    try {
      await this.#unlock((vault) => {
        const slot = selectCurrentSlot(vault, 'passphrase', expectedSlotId);
        return unlockPassphraseKeySlot(slot, ownedPassphrase, slotBinding(vault, slot));
      });
    } finally {
      zeroize(ownedPassphrase);
    }
  }

  async unlockRememberedDevice(): Promise<void> {
    await this.#unlock(async (vault, signal) => {
      const slot = selectCurrentSlot(
        vault,
        'device-key',
        this.#profile.deviceLocator.keySlotId,
      );
      if (slot.deviceId !== this.#profile.deviceId) {
        throw new VaultClientSessionError('authentication');
      }
      let deviceSecret: Awaited<ReturnType<KeychainPort['load']>>;
      try {
        deviceSecret = await this.#keychain.load(this.#profile.deviceLocator, signal);
      } catch {
        throw new VaultClientSessionError('authentication');
      }
      if (deviceSecret === null) {
        throw new VaultClientSessionError('authentication');
      }
      try {
        const parsed = deviceUnlockSecretSchema.safeParse(deviceSecret);
        if (!parsed.success) throw new VaultClientSessionError('authentication');
        return await unlockDeviceKeySlot(slot, parsed.data, slotBinding(vault, slot));
      } finally {
        zeroize(deviceSecret);
      }
    });
  }

  async synchronize(): Promise<SyncRunResult> {
    return this.#runActive(async (state) => {
      try {
        const result = await state.sync.synchronize({
          vaultId: this.#profile.vaultId,
          deviceId: this.#profile.deviceId,
        });
        if (!(await state.source.matchesCurrentVaultBinding())) {
          throw await this.#lockForFailure(
            new VaultClientSessionError('terminal-sync'),
          );
        }
        return result;
      } catch (error) {
        if (terminalSyncFailure(error)) {
          throw await this.#lockForFailure(syncSessionError(error));
        }
        throw error;
      }
    });
  }

  async show(
    groupQuery: string,
    credentialQuery: string,
  ): Promise<CredentialShowProjection> {
    return this.#runActive((state) =>
      state.interaction.show(groupQuery, credentialQuery),
    );
  }

  async copy(
    groupQuery: string,
    credentialQuery: string,
    fieldQuery: string,
    options: CredentialCopyOptions = {},
  ): Promise<CredentialCopyReceipt> {
    return this.#runActive((state) => {
      const signal =
        options.signal === undefined
          ? state.abort.signal
          : AbortSignal.any([state.abort.signal, options.signal]);
      return state.interaction.copy(groupQuery, credentialQuery, fieldQuery, {
        ...options,
        signal,
      });
    });
  }

  async lock(): Promise<void> {
    this.#detachAndWipe();
    try {
      await this.#clipboard.lock();
    } catch {
      throw new VaultClientSessionError('clipboard');
    }
  }

  async #unlock(
    unwrap: (vault: VaultRecord, signal: AbortSignal) => Promise<VaultRootKey>,
  ): Promise<void> {
    if (this.#busy || this.#state !== null) {
      throw new VaultClientSessionError('concurrency');
    }
    this.#busy = true;
    const epoch = this.#epoch;
    const abort = new AbortController();
    this.#pendingAbort = abort;
    let sessionSecret: Awaited<ReturnType<SessionCredentialPort['load']>> | undefined;
    let rootKey: VaultRootKey | undefined;
    let source: BoundVaultReadSource | undefined;
    let read: VaultReadSession | undefined;
    try {
      try {
        sessionSecret = await this.#sessions.load(
          this.#profile.sessionLocator,
          abort.signal,
        );
      } catch {
        throw new VaultClientSessionError('authentication');
      }
      if (sessionSecret === null) {
        throw new VaultClientSessionError('authentication');
      }
      const parsedSecret = sessionCredentialSecretSchema.safeParse(sessionSecret);
      if (!parsedSecret.success) throw new VaultClientSessionError('authentication');
      const bearer = bearerFromSecret(parsedSecret.data);
      const controlPlane = new ControlPlaneClient(this.#remoteOptions(abort.signal));
      const remoteSession = await controlPlane.getSession(
        bearer,
        this.#profile.vaultId,
        this.#profile.deviceId,
      );
      if (
        [...REQUIRED_SCOPES].some(
          (requiredScope) => !remoteSession.scopes.includes(requiredScope),
        )
      ) {
        throw new VaultClientSessionError('authentication');
      }
      const vault = vaultRecordSchema.parse(
        await controlPlane.fetchVault(bearer, this.#profile.vaultId),
      );
      rootKey = await unwrap(vault, abort.signal);
      source = new BoundVaultReadSource(this.#store, vault);
      read = new VaultReadSession(source, this.#profile.vaultId);
      await read.unlock(rootKey);
      if (this.#epoch !== epoch || abort.signal.aborted) {
        throw new VaultClientSessionError('locked');
      }
      const transport = new FetchSyncTransport({
        ...this.#remoteOptions(abort.signal),
        bearerToken: bearer,
      });
      const sync = new SyncEngine({
        ...this.#syncOptions,
        local: this.#store,
        transport,
      });
      const interaction = new VaultInteractionService(
        read,
        this.#clipboard,
        this.#interactionOptions,
      );
      this.#state = { epoch, abort, source, read, interaction, sync };
      read = undefined;
      source = undefined;
    } catch (error) {
      read?.lock();
      source?.clear();
      abort.abort();
      if (this.#epoch !== epoch) throw new VaultClientSessionError('locked');
      throw unlockSessionError(error);
    } finally {
      if (this.#pendingAbort === abort) this.#pendingAbort = null;
      zeroize(rootKey);
      zeroize(sessionSecret ?? undefined);
      this.#busy = false;
    }
  }

  async #runActive<Output>(
    operation: (state: ActiveSession) => Promise<Output>,
  ): Promise<Output> {
    if (this.#busy) throw new VaultClientSessionError('concurrency');
    const state = this.#state;
    if (state === null) throw new VaultClientSessionError('locked');
    this.#busy = true;
    try {
      const result = await operation(state);
      if (this.#state !== state || this.#epoch !== state.epoch) {
        throw new VaultClientSessionError('locked');
      }
      return result;
    } finally {
      this.#busy = false;
    }
  }

  #remoteOptions(signal: AbortSignal): ControlPlaneClientOptions {
    return {
      baseUrl: this.#profile.serverUrl,
      ...this.#network,
      signal,
      ...(this.#allowInsecureLoopback
        ? { allowInsecureLoopbackDevelopment: true }
        : {}),
    };
  }

  #detachAndWipe(): void {
    this.#epoch += 1;
    this.#pendingAbort?.abort();
    this.#pendingAbort = null;
    const state = this.#state;
    this.#state = null;
    state?.abort.abort();
    state?.read.lock();
    state?.source.clear();
  }

  async #lockForFailure(error: VaultClientSessionError): Promise<Error> {
    this.#detachAndWipe();
    try {
      await this.#clipboard.lock();
      return error;
    } catch {
      return new VaultClientSessionError('clipboard');
    }
  }
}

class BoundVaultReadSource implements VaultReadSourcePort {
  readonly #store: VaultReadSourcePort;
  readonly #vaultId: VaultId;
  #vault: VaultRecord | null;

  constructor(store: VaultReadSourcePort, vault: VaultRecord) {
    this.#store = store;
    this.#vaultId = vault.id;
    this.#vault = structuredClone(vault);
  }

  clear(): void {
    this.#vault = null;
  }

  async matchesCurrentVaultBinding(): Promise<boolean> {
    const bound = this.#vault;
    if (bound === null) return false;
    let current: VaultRecord;
    try {
      const raw: unknown = await this.#store.getVault(this.#vaultId);
      current = vaultRecordSchema.parse(raw);
    } catch {
      return false;
    }
    return (
      current.id === bound.id &&
      current.schemaVersion === bound.schemaVersion &&
      current.cryptographicVersion === bound.cryptographicVersion &&
      current.currentKeyVersion === bound.currentKeyVersion &&
      current.revision >= bound.revision
    );
  }

  getVault(vaultId: VaultId): Promise<VaultRecord | null> {
    return Promise.resolve(
      vaultId === this.#vaultId && this.#vault !== null
        ? structuredClone(this.#vault)
        : null,
    );
  }

  getGroup(vaultId: VaultId, groupId: GroupId): Promise<EncryptedGroupRecord | null> {
    return this.#store.getGroup(vaultId, groupId);
  }

  listGroups(vaultId: VaultId): AsyncIterable<EncryptedGroupRecord> {
    return this.#store.listGroups(vaultId);
  }

  getItem(vaultId: VaultId, itemId: ItemId): Promise<EncryptedItemRecord | null> {
    return this.#store.getItem(vaultId, itemId);
  }

  listItems(vaultId: VaultId, groupId: GroupId): AsyncIterable<EncryptedItemRecord> {
    return this.#store.listItems(vaultId, groupId);
  }
}

function validateFormattedKey(value: string, kind: 'portable' | 'recovery'): void {
  let parsed: Uint8Array | undefined;
  try {
    parsed = kind === 'portable' ? parsePortableKey(value) : parseRecoveryKey(value);
  } catch {
    throw new VaultClientSessionError('invalid-input');
  } finally {
    zeroize(parsed);
  }
}

function parseOptionalSlotId(value: KeySlotId | undefined): KeySlotId | undefined {
  return value === undefined ? undefined : parseRequiredSlotId(value);
}

function parseRequiredSlotId(value: KeySlotId): KeySlotId {
  const parsed = keySlotIdSchema.safeParse(value);
  if (!parsed.success) throw new VaultClientSessionError('invalid-input');
  return parsed.data;
}

function selectCurrentSlot<Type extends SlotType>(
  vault: VaultRecord,
  type: Type,
  slotId: KeySlotId | undefined,
): Extract<KeySlot, { readonly type: Type }> {
  const candidates = vault.keySlots.filter(
    (slot): slot is Extract<KeySlot, { readonly type: Type }> =>
      slot.type === type &&
      slot.state === 'active' &&
      slot.keyVersion === vault.currentKeyVersion &&
      (slotId === undefined || slot.id === slotId),
  );
  if (candidates.length !== 1) {
    throw new VaultClientSessionError('authentication');
  }
  return candidates[0] as Extract<KeySlot, { readonly type: Type }>;
}

function slotBinding(vault: VaultRecord, slot: KeySlot): SlotBinding {
  return {
    vaultId: vault.id,
    slotId: slot.id,
    schemaVersion: vault.schemaVersion,
    keyVersion: vault.currentKeyVersion,
  };
}

function bearerFromSecret(secret: Uint8Array): ApiBearerToken {
  try {
    return apiBearerTokenSchema.parse(encodeBase64Url(secret));
  } catch {
    throw new VaultClientSessionError('authentication');
  }
}

function terminalSyncFailure(error: unknown): boolean {
  return (
    error instanceof SyncRollbackError ||
    error instanceof SyncProtocolError ||
    error instanceof SyncLocalStateError ||
    (error instanceof SyncTransportFailure &&
      (error.kind === 'unauthorized' || error.kind === 'device-revoked'))
  );
}

function syncSessionError(error: unknown): VaultClientSessionError {
  if (
    error instanceof SyncTransportFailure &&
    (error.kind === 'unauthorized' || error.kind === 'device-revoked')
  ) {
    return new VaultClientSessionError('authentication');
  }
  return new VaultClientSessionError('terminal-sync');
}

function unlockSessionError(error: unknown): Error {
  if (error instanceof VaultClientSessionError) return error;
  if (
    error instanceof AuthenticationError ||
    error instanceof CryptoInputError ||
    error instanceof CryptoAuthenticationError
  ) {
    return new VaultClientSessionError('authentication');
  }
  if (error instanceof VaultLockedError) {
    return new VaultClientSessionError('locked');
  }
  if (error instanceof ControlPlaneFailure) {
    if (
      error.kind === 'unauthorized' ||
      error.kind === 'forbidden' ||
      error.kind === 'not-found'
    ) {
      return new VaultClientSessionError('authentication');
    }
    if (error.kind === 'timeout' || error.kind === 'offline') {
      return new VaultClientSessionError('network-unavailable');
    }
    if (error.kind === 'rate-limited') {
      return new VaultClientSessionError('rate-limited', error.retryAfterMs);
    }
    if (error.kind === 'server') {
      return new VaultClientSessionError('server-unavailable');
    }
    return new VaultClientSessionError('protocol');
  }
  return new VaultClientSessionError('protocol');
}
