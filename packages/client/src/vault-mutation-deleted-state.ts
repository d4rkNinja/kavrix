import { CryptoAuthenticationError } from '@kavrix/core';
import type { VaultRootKey } from '@kavrix/crypto';
import {
  contentHashForRecord,
  tombstoneRecordSchema,
  type TombstoneRecord,
  type VaultId,
} from '@kavrix/schemas';

import type {
  GroupMutationState,
  ItemMutationState,
} from './vault-mutation-service.js';
import {
  openGroupRecord,
  openItemRecord,
  type ActiveVault,
  type OpenGroup,
  type OpenItem,
} from './vault-mutation-records.js';

export async function openDeletedGroupState(
  state: Extract<GroupMutationState, { state: 'deleted' }>,
  vaultId: VaultId,
  vault: ActiveVault,
  rootKey: VaultRootKey,
): Promise<OpenGroup> {
  const tombstone = tombstoneRecordSchema.safeParse(state.tombstone);
  if (
    !tombstone.success ||
    tombstone.data.entityType !== 'group' ||
    tombstone.data.state !== 'deleted' ||
    tombstone.data.vaultId !== vaultId ||
    tombstone.data.entityId !== state.predecessor.id ||
    state.predecessor.vaultId !== vaultId ||
    state.predecessor.recordRevision !== tombstone.data.lastRecordRevision ||
    contentHashForRecord(state.predecessor) !== tombstone.data.lastCiphertextHash
  ) {
    throw new CryptoAuthenticationError();
  }
  const opened = await openGroupRecord(state.predecessor, vaultId, vault, rootKey);
  return {
    ...opened,
    expectedRecordRevision: tombstone.data.tombstoneRevision,
    deleted: true,
  };
}

export async function openDeletedItemState(
  state: Extract<ItemMutationState, { state: 'deleted' }>,
  group: OpenGroup,
  vault: ActiveVault,
): Promise<OpenItem> {
  const tombstone = tombstoneRecordSchema.safeParse(state.tombstone);
  if (
    !tombstone.success ||
    tombstone.data.entityType !== 'item' ||
    tombstone.data.state !== 'deleted' ||
    tombstone.data.vaultId !== group.payload.vaultId ||
    tombstone.data.entityId !== state.predecessor.id ||
    state.predecessor.vaultId !== group.payload.vaultId ||
    state.predecessor.groupId !== group.payload.id ||
    state.predecessor.recordRevision !== tombstone.data.lastRecordRevision ||
    contentHashForRecord(state.predecessor) !== tombstone.data.lastCiphertextHash
  ) {
    throw new CryptoAuthenticationError();
  }
  const opened = await openItemRecord(state.predecessor, group, vault);
  return {
    ...opened,
    expectedRecordRevision: tombstone.data.tombstoneRevision,
    deleted: true,
  };
}

export function assertGroupTombstoneRelation(
  current: OpenGroup,
  tombstoneCandidate: Extract<TombstoneRecord, { entityType: 'group' }>,
  predecessor?: OpenGroup,
): void {
  const tombstone = tombstoneRecordSchema.safeParse(tombstoneCandidate);
  if (
    !tombstone.success ||
    tombstone.data.entityType !== 'group' ||
    current.record.id !== tombstone.data.entityId ||
    current.payload.id !== tombstone.data.entityId ||
    current.record.vaultId !== tombstone.data.vaultId ||
    current.payload.vaultId !== tombstone.data.vaultId
  ) {
    throw new CryptoAuthenticationError();
  }
  assertTombstoneStateRelation(current, tombstone.data, predecessor);
  if (
    predecessor !== undefined &&
    (predecessor.record.id !== current.record.id ||
      predecessor.payload.id !== current.payload.id ||
      predecessor.record.vaultId !== current.record.vaultId ||
      predecessor.payload.vaultId !== current.payload.vaultId)
  ) {
    throw new CryptoAuthenticationError();
  }
}

export function assertItemTombstoneRelation(
  current: OpenItem,
  tombstoneCandidate: Extract<TombstoneRecord, { entityType: 'item' }>,
  predecessor?: OpenItem,
): void {
  const tombstone = tombstoneRecordSchema.safeParse(tombstoneCandidate);
  if (
    !tombstone.success ||
    tombstone.data.entityType !== 'item' ||
    current.record.id !== tombstone.data.entityId ||
    current.payload.id !== tombstone.data.entityId ||
    current.record.vaultId !== tombstone.data.vaultId ||
    current.payload.vaultId !== tombstone.data.vaultId ||
    current.record.groupId !== current.payload.groupId
  ) {
    throw new CryptoAuthenticationError();
  }
  assertTombstoneStateRelation(current, tombstone.data, predecessor);
  if (
    predecessor !== undefined &&
    (predecessor.record.id !== current.record.id ||
      predecessor.payload.id !== current.payload.id ||
      predecessor.record.vaultId !== current.record.vaultId ||
      predecessor.payload.vaultId !== current.payload.vaultId ||
      predecessor.record.groupId !== current.record.groupId ||
      predecessor.payload.groupId !== current.payload.groupId)
  ) {
    throw new CryptoAuthenticationError();
  }
}

function assertTombstoneStateRelation(
  current: OpenGroup | OpenItem,
  tombstone: Extract<TombstoneRecord, { entityType: 'group' | 'item' }>,
  predecessor?: OpenGroup | OpenItem,
): void {
  if (
    current.record.recordRevision !== tombstone.tombstoneRevision ||
    current.payload.revision !== tombstone.tombstoneRevision ||
    current.expectedRecordRevision !== tombstone.tombstoneRevision
  ) {
    throw new CryptoAuthenticationError();
  }
  if (tombstone.state === 'deleted') {
    if (
      !current.deleted ||
      current.record.tombstonedAt !== tombstone.deletedAt ||
      current.payload.deletedAt !== tombstone.deletedAt ||
      predecessor === undefined ||
      predecessor.deleted ||
      predecessor.record.tombstonedAt !== undefined ||
      predecessor.payload.deletedAt !== undefined ||
      predecessor.record.recordRevision !== tombstone.lastRecordRevision ||
      predecessor.payload.revision !== tombstone.lastRecordRevision ||
      predecessor.expectedRecordRevision !== tombstone.lastRecordRevision ||
      contentHashForRecord(predecessor.record) !== tombstone.lastCiphertextHash
    ) {
      throw new CryptoAuthenticationError();
    }
    return;
  }
  if (
    current.deleted ||
    current.record.tombstonedAt !== undefined ||
    current.payload.deletedAt !== undefined ||
    predecessor !== undefined ||
    current.record.updatedAt !== tombstone.restoredAt ||
    current.payload.updatedAt !== tombstone.restoredAt
  ) {
    throw new CryptoAuthenticationError();
  }
}
