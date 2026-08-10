import { CryptoAuthenticationError } from '@kavrix/core';
import type { VaultRootKey } from '@kavrix/crypto';
import {
  contentHashForRecord,
  tombstoneRecordSchema,
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
