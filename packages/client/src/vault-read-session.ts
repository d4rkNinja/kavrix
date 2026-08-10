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
  decryptPayload,
  requireByteLength,
  unwrapGroupKey,
  unwrapItemKey,
  zeroize,
  type GroupKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  associatedDataSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  fieldValueMatchesDefinition,
  groupPayloadSchema,
  groupIdSchema,
  itemPayloadSchema,
  itemIdSchema,
  vaultRecordSchema,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type GroupPayload,
  type GroupTemplate,
  type ItemPayload,
  type KeyVersion,
  type SchemaVersion,
  type VaultId,
} from '@kavrix/schemas';

import { VaultSessionConcurrencyError } from './errors.js';

export const MAX_VAULT_PAYLOAD_BYTES = 16 * 1024 * 1024;
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

interface UnlockedState {
  readonly rootKey: VaultRootKey;
  readonly keyVersion: KeyVersion;
  readonly schemaVersion: SchemaVersion;
}

type OpenGroup = Readonly<{
  payload: GroupPayload;
  key: GroupKey;
}>;

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
    const group = await openGroup(
      parseGroupRecord(groupCandidate, this.#vaultId, state),
      state,
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
      const item = await openItem(
        parseItemRecord(parsedItem.data, this.#vaultId, group.payload.id, state),
        group,
        state,
      );
      return { group: group.payload, item, template: group.payload.template };
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
        const record = parseGroupRecord(candidate, this.#vaultId, state);
        if (ids.has(record.id)) throw new CryptoAuthenticationError();
        ids.add(record.id);
        groups.push(await openGroup(record, state));
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
      const payload = resolveNamedEntity(
        query,
        groups.map((group) => group.payload),
      );
      selected = groups.find((group) => group.payload.id === payload.id);
      if (selected === undefined) throw new CryptoAuthenticationError();
      return selected;
    } finally {
      for (const group of groups) {
        if (group !== selected) zeroize(group.key);
      }
    }
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
      const record = parseItemRecord(candidate, this.#vaultId, group.payload.id, state);
      if (ids.has(record.id)) throw new CryptoAuthenticationError();
      ids.add(record.id);
      items.push(await openItem(record, group, state));
    }
    this.#assertActive(state, epoch);
    return items;
  }

  #assertActive(state: UnlockedState, epoch: number): void {
    if (this.#state !== state || this.#epoch !== epoch) throw new VaultLockedError();
  }
}

function parseGroupRecord(
  candidate: EncryptedGroupRecord,
  vaultId: VaultId,
  state: UnlockedState,
): EncryptedGroupRecord {
  const parsed = encryptedGroupRecordSchema.safeParse(candidate);
  if (
    !parsed.success ||
    parsed.data.vaultId !== vaultId ||
    parsed.data.schemaVersion !== state.schemaVersion ||
    parsed.data.tombstonedAt !== undefined ||
    parsed.data.wrappedGroupKey.keyVersion !== state.keyVersion ||
    parsed.data.encryptedPayload.keyVersion !== state.keyVersion
  ) {
    throw new CryptoAuthenticationError();
  }
  return parsed.data;
}

async function openGroup(
  record: EncryptedGroupRecord,
  state: UnlockedState,
): Promise<OpenGroup> {
  const keyContext = associatedDataSchema.parse({
    version: 1,
    schemaVersion: state.schemaVersion,
    keyVersion: state.keyVersion,
    vaultId: record.vaultId,
    entityType: 'wrapped-group-key',
    entityId: record.id,
    purpose: 'group-key',
  });
  const payloadContext = associatedDataSchema.parse({
    version: 1,
    schemaVersion: state.schemaVersion,
    keyVersion: state.keyVersion,
    vaultId: record.vaultId,
    entityType: 'group',
    entityId: record.id,
    purpose: 'group-payload',
  });
  const key = await unwrapGroupKey(record.wrappedGroupKey, state.rootKey, keyContext);
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = await decryptPayload(record.encryptedPayload, key, payloadContext);
    const payload = parseCanonicalPayload(plaintext, groupPayloadSchema);
    if (
      payload.id !== record.id ||
      payload.vaultId !== record.vaultId ||
      payload.revision !== record.recordRevision ||
      payload.template.version !== record.templateVersion ||
      payload.createdAt !== record.createdAt ||
      payload.updatedAt !== record.updatedAt ||
      payload.deletedAt !== undefined
    ) {
      throw new CryptoAuthenticationError();
    }
    return { key, payload };
  } catch (error) {
    zeroize(key);
    throw error;
  } finally {
    zeroize(plaintext);
  }
}

function parseItemRecord(
  candidate: EncryptedItemRecord,
  vaultId: VaultId,
  groupId: GroupPayload['id'],
  state: UnlockedState,
): EncryptedItemRecord {
  const parsed = encryptedItemRecordSchema.safeParse(candidate);
  if (
    !parsed.success ||
    parsed.data.vaultId !== vaultId ||
    parsed.data.groupId !== groupId ||
    parsed.data.schemaVersion !== state.schemaVersion ||
    parsed.data.tombstonedAt !== undefined ||
    parsed.data.wrappedItemKey.keyVersion !== state.keyVersion ||
    parsed.data.encryptedPayload.keyVersion !== state.keyVersion
  ) {
    throw new CryptoAuthenticationError();
  }
  return parsed.data;
}

async function openItem(
  record: EncryptedItemRecord,
  group: OpenGroup,
  state: UnlockedState,
): Promise<ItemPayload> {
  const keyContext = associatedDataSchema.parse({
    version: 1,
    schemaVersion: state.schemaVersion,
    keyVersion: state.keyVersion,
    vaultId: record.vaultId,
    entityType: 'wrapped-item-key',
    entityId: record.id,
    groupId: record.groupId,
    purpose: 'item-key',
  });
  const payloadContext = associatedDataSchema.parse({
    version: 1,
    schemaVersion: state.schemaVersion,
    keyVersion: state.keyVersion,
    vaultId: record.vaultId,
    entityType: 'item',
    entityId: record.id,
    groupId: record.groupId,
    purpose: 'item-payload',
  });
  const itemKey = await unwrapItemKey(record.wrappedItemKey, group.key, keyContext);
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = await decryptPayload(record.encryptedPayload, itemKey, payloadContext);
    const payload = parseCanonicalPayload(plaintext, itemPayloadSchema);
    if (
      payload.id !== record.id ||
      payload.vaultId !== record.vaultId ||
      payload.groupId !== record.groupId ||
      payload.revision !== record.recordRevision ||
      payload.createdAt !== record.createdAt ||
      payload.updatedAt !== record.updatedAt ||
      payload.deletedAt !== undefined ||
      payload.templateId !== group.payload.template.id ||
      payload.templateVersion !== group.payload.template.version ||
      !templateValuesMatch(payload, group.payload.template)
    ) {
      throw new CryptoAuthenticationError();
    }
    return payload;
  } finally {
    zeroize(itemKey);
    zeroize(plaintext);
  }
}

function parseCanonicalPayload<TOutput>(
  plaintext: Uint8Array,
  schema: {
    safeParse(
      value: unknown,
    ): Readonly<{ success: true; data: TOutput }> | Readonly<{ success: false }>;
  },
): TOutput {
  if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_VAULT_PAYLOAD_BYTES) {
    throw new CryptoAuthenticationError();
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    const decoded = JSON.parse(text) as unknown;
    const result = schema.safeParse(decoded);
    if (!result.success || JSON.stringify(result.data) !== text) {
      throw new CryptoAuthenticationError();
    }
    return result.data;
  } catch {
    throw new CryptoAuthenticationError();
  }
}

function templateValuesMatch(item: ItemPayload, template: GroupTemplate): boolean {
  const values = new Map(item.templateValues.map((value) => [value.fieldId, value]));
  for (const definition of template.fields) {
    const value = values.get(definition.id);
    if (
      value?.stableKey !== definition.stableKey ||
      !fieldValueMatchesDefinition(definition, value.value)
    ) {
      return false;
    }
    values.delete(definition.id);
  }
  return values.size === 0;
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
