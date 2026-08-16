import {
  AmbiguousNameError,
  CryptoAuthenticationError,
  NotFoundError,
  VaultLockedError,
  resolveNamedEntity,
  type VaultStoragePort,
} from '@kavrix/core';
import {
  cloneSecretKey,
  requireByteLength,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  encryptedItemRecordSchema,
  groupIdSchema,
  itemIdSchema,
  vaultRecordSchema,
  type GroupPayload,
  type GroupTemplate,
  type ItemPayload,
  type KeyVersion,
  type SchemaVersion,
  type VaultId,
} from '@kavrix/schemas';

import { VaultSessionConcurrencyError } from './errors.js';
import {
  openGroupRecord,
  openItemRecord,
  type OpenGroup,
} from './vault-mutation-records.js';

export { MAX_VAULT_PAYLOAD_BYTES } from './vault-mutation-records.js';
export const MAX_VAULT_GROUPS = 1_000;
export const MAX_GROUP_ITEMS = 10_000;

export type VaultReadSourcePort = Pick<
  VaultStoragePort,
  'getVault' | 'getGroup' | 'listGroups' | 'getItem' | 'listItems'
>;

export type CredentialShowResult = Readonly<{
  group: GroupPayload;
  item: ItemPayload;
  template: GroupTemplate;
}>;

/**
 * One group and every item it holds, read while that group's key was live.
 *
 * Callers that need the whole vault use this instead of `listGroups` followed by
 * one `listItems` per group: resolving a group query re-opens every group, so the
 * per-group form costs a quadratic number of decryptions on a large vault.
 */
export type VaultGroupScope = Readonly<{
  group: GroupPayload;
  items: readonly ItemPayload[];
}>;

interface UnlockedState {
  readonly rootKey: VaultRootKey;
  readonly keyVersion: KeyVersion;
  readonly schemaVersion: SchemaVersion;
}

/** Owns the only client-side copy of the active root key and never returns keys. */
export class VaultReadSession {
  readonly #source: VaultReadSourcePort;
  readonly #vaultId: VaultId;
  #state: UnlockedState | null = null;
  #epoch = 0;
  #busy = false;

  constructor(source: VaultReadSourcePort, vaultId: VaultId) {
    this.#source = source;
    this.#vaultId = vaultId;
  }

  get locked(): boolean {
    return this.#state === null;
  }

  async unlock(rootKey: VaultRootKey): Promise<void> {
    if (this.#state !== null) throw new VaultSessionConcurrencyError();
    if (this.#busy) throw new VaultSessionConcurrencyError();
    this.#busy = true;
    const epoch = this.#epoch;
    let ownedKey: VaultRootKey | undefined;
    try {
      requireByteLength(rootKey, 32, 'vault root key');
      const candidate = await this.#source.getVault(this.#vaultId);
      if (candidate === null) throw new NotFoundError();
      const parsed = vaultRecordSchema.safeParse(candidate);
      if (!parsed.success || parsed.data.id !== this.#vaultId) {
        throw new CryptoAuthenticationError();
      }
      ownedKey = cloneSecretKey(rootKey);
      if (this.#epoch !== epoch) throw new VaultLockedError();
      this.#state = {
        rootKey: ownedKey,
        keyVersion: parsed.data.currentKeyVersion,
        schemaVersion: parsed.data.schemaVersion,
      };
      ownedKey = undefined;
    } catch (error) {
      throw safeReadError(error);
    } finally {
      zeroize(ownedKey);
      this.#busy = false;
    }
  }

  lock(): void {
    this.#epoch += 1;
    const state = this.#state;
    this.#state = null;
    zeroize(state?.rootKey);
  }

  async listGroups(): Promise<readonly GroupPayload[]> {
    return this.#read(async (state, epoch) => {
      const groups = await this.#loadGroups(state, epoch);
      try {
        return groups.map(({ payload }) => payload);
      } finally {
        for (const group of groups) zeroize(group.key);
      }
    });
  }

  async showGroup(query: string): Promise<GroupPayload> {
    return this.#read(async (state, epoch) => {
      const groups = await this.#loadGroups(state, epoch);
      try {
        return resolveNamedEntity(
          query,
          groups.map(({ payload }) => payload),
        );
      } finally {
        for (const group of groups) zeroize(group.key);
      }
    });
  }

  async listItems(groupQuery: string): Promise<readonly ItemPayload[]> {
    return this.#read(async (state, epoch) => {
      const group = await this.#resolveOpenGroup(groupQuery, state, epoch);
      try {
        return await this.#loadItems(group, state, epoch);
      } finally {
        zeroize(group.key);
      }
    });
  }

  /**
   * Reads whole groups with their items in a single pass over the vault.
   *
   * Group keys stay live only while that group's items are being opened, and
   * every key is zeroized before the call returns. Archived and deleted records
   * are returned as stored; filtering them is the caller's policy decision.
   */
  async listScopes(groupQuery?: string): Promise<readonly VaultGroupScope[]> {
    return this.#read(async (state, epoch) => {
      const groups = await this.#loadGroups(state, epoch);
      try {
        const selected =
          groupQuery === undefined
            ? groups
            : [this.#selectOpenGroup(groups, groupQuery)];
        const scopes: VaultGroupScope[] = [];
        for (const group of selected) {
          scopes.push({
            group: group.payload,
            items: await this.#loadItems(group, state, epoch),
          });
        }
        return scopes;
      } finally {
        for (const group of groups) zeroize(group.key);
      }
    });
  }

  async show(
    groupQuery: string,
    credentialQuery: string,
  ): Promise<CredentialShowResult> {
    return this.#read(async (state, epoch) => {
      const direct = await this.#tryShowExactIds(
        groupQuery,
        credentialQuery,
        state,
        epoch,
      );
      if (direct !== undefined) return direct;
      const group = await this.#resolveOpenGroup(groupQuery, state, epoch);
      try {
        const items = await this.#loadItems(group, state, epoch);
        const resolved = resolveNamedEntity(
          credentialQuery,
          items.map((candidate) => ({
            id: candidate.id,
            name: candidate.title,
            slug: candidate.slug,
            aliases: candidate.aliases,
            item: candidate,
          })),
        );
        return {
          group: group.payload,
          item: resolved.item,
          template: group.payload.template,
        };
      } finally {
        zeroize(group.key);
      }
    });
  }

  async #tryShowExactIds(
    groupQuery: string,
    credentialQuery: string,
    state: UnlockedState,
    epoch: number,
  ): Promise<CredentialShowResult | undefined> {
    const groupId = groupIdSchema.safeParse(groupQuery.trim());
    const itemId = itemIdSchema.safeParse(credentialQuery.trim());
    if (!groupId.success || !itemId.success) return undefined;

    const groupCandidate = await this.#source.getGroup(this.#vaultId, groupId.data);
    this.#assertActive(state, epoch);
    if (groupCandidate === null) return undefined;
    if (groupCandidate.id !== groupId.data) throw new CryptoAuthenticationError();
    const group = await openGroupRecord(
      groupCandidate,
      this.#vaultId,
      state,
      state.rootKey,
    );
    try {
      const itemCandidate = await this.#source.getItem(this.#vaultId, itemId.data);
      this.#assertActive(state, epoch);
      if (itemCandidate === null) return undefined;
      const parsedItem = encryptedItemRecordSchema.safeParse(itemCandidate);
      if (
        !parsedItem.success ||
        parsedItem.data.id !== itemId.data ||
        parsedItem.data.vaultId !== this.#vaultId
      ) {
        throw new CryptoAuthenticationError();
      }
      if (parsedItem.data.groupId !== group.payload.id) return undefined;
      const item = await openItemRecord(parsedItem.data, group, state);
      try {
        return {
          group: group.payload,
          item: item.payload,
          template: group.payload.template,
        };
      } finally {
        zeroize(item.key);
      }
    } finally {
      zeroize(group.key);
    }
  }

  async #read<TResult>(
    operation: (state: UnlockedState, epoch: number) => Promise<TResult>,
  ): Promise<TResult> {
    const state = this.#state;
    if (state === null) throw new VaultLockedError();
    if (this.#busy) throw new VaultSessionConcurrencyError();
    this.#busy = true;
    const epoch = this.#epoch;
    try {
      const result = await operation(state, epoch);
      this.#assertActive(state, epoch);
      return result;
    } catch (error) {
      if (this.#epoch !== epoch || this.#state !== state) throw new VaultLockedError();
      throw safeReadError(error);
    } finally {
      this.#busy = false;
    }
  }

  async #loadGroups(
    state: UnlockedState,
    epoch: number,
  ): Promise<readonly OpenGroup[]> {
    const groups: OpenGroup[] = [];
    const ids = new Set<string>();
    try {
      for await (const candidate of this.#source.listGroups(this.#vaultId)) {
        if (groups.length >= MAX_VAULT_GROUPS) {
          throw new CryptoAuthenticationError();
        }
        this.#assertActive(state, epoch);
        const opened = await openGroupRecord(
          candidate,
          this.#vaultId,
          state,
          state.rootKey,
        );
        if (ids.has(opened.record.id)) {
          zeroize(opened.key);
          throw new CryptoAuthenticationError();
        }
        ids.add(opened.record.id);
        groups.push(opened);
      }
      this.#assertActive(state, epoch);
      return groups;
    } catch (error) {
      for (const group of groups) zeroize(group.key);
      throw error;
    }
  }

  async #resolveOpenGroup(
    query: string,
    state: UnlockedState,
    epoch: number,
  ): Promise<OpenGroup> {
    const groups = await this.#loadGroups(state, epoch);
    let selected: OpenGroup | undefined;
    try {
      selected = this.#selectOpenGroup(groups, query);
      return selected;
    } finally {
      for (const group of groups) {
        if (group !== selected) zeroize(group.key);
      }
    }
  }

  /** Resolves a query against already-opened groups without releasing any key. */
  #selectOpenGroup(groups: readonly OpenGroup[], query: string): OpenGroup {
    const payload = resolveNamedEntity(
      query,
      groups.map((group) => group.payload),
    );
    const selected = groups.find((group) => group.payload.id === payload.id);
    if (selected === undefined) throw new CryptoAuthenticationError();
    return selected;
  }

  async #loadItems(
    group: OpenGroup,
    state: UnlockedState,
    epoch: number,
  ): Promise<readonly ItemPayload[]> {
    const items: ItemPayload[] = [];
    const ids = new Set<string>();
    for await (const candidate of this.#source.listItems(
      this.#vaultId,
      group.payload.id,
    )) {
      if (items.length >= MAX_GROUP_ITEMS) throw new CryptoAuthenticationError();
      this.#assertActive(state, epoch);
      const opened = await openItemRecord(candidate, group, state);
      try {
        if (ids.has(opened.record.id)) throw new CryptoAuthenticationError();
        ids.add(opened.record.id);
        items.push(opened.payload);
      } finally {
        zeroize(opened.key);
      }
    }
    this.#assertActive(state, epoch);
    return items;
  }

  #assertActive(state: UnlockedState, epoch: number): void {
    if (this.#state !== state || this.#epoch !== epoch) throw new VaultLockedError();
  }
}

function safeReadError(error: unknown): Error {
  if (
    error instanceof VaultLockedError ||
    error instanceof NotFoundError ||
    error instanceof AmbiguousNameError ||
    error instanceof VaultSessionConcurrencyError ||
    error instanceof CryptoAuthenticationError
  ) {
    return error;
  }
  return new CryptoAuthenticationError();
}
