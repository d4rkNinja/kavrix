import type { DatabaseSync } from 'node:sqlite';

import type {
  GroupMutationState,
  ItemMutationState,
  OpaqueMutationQueuePort,
  VaultMutationStatePort,
  VaultSyncStorePort,
} from '@kavrix/client';
import type {
  EncryptedGroupRecord,
  EncryptedItemRecord,
  GroupId,
  ItemId,
  OpaqueMutation,
  SyncPulledChange,
  TemplateMigrationPublicationRequest,
  VaultId,
  VaultRecord,
} from '@kavrix/schemas';
import type { CompleteTemplateMigrationPublicationInput } from '@kavrix/sync';

import { SqliteMutationQueue } from './sqlite-mutation-queue.js';
import { SqliteRecordState } from './sqlite-record-state.js';
import { SqliteTemplatePublications } from './sqlite-template-publications.js';
import type { VaultStateLimits } from './sqlite-vault-schema.js';

export {
  LEGACY_V2_VAULT_STATE_SCHEMA_DEFINITIONS,
  VAULT_STATE_SCHEMA_DEFINITIONS,
} from './sqlite-vault-schema.js';
export type { VaultStateLimits } from './sqlite-vault-schema.js';

/**
 * Internal facade that keeps the public SQLite store independent of the
 * record, generic-queue, and atomic-publication persistence details.
 */
export class SqliteVaultState {
  readonly #records: SqliteRecordState;
  readonly #queue: SqliteMutationQueue;
  readonly #publications: SqliteTemplatePublications;

  constructor(database: DatabaseSync, limits: VaultStateLimits) {
    this.#records = new SqliteRecordState(database, limits);
    this.#queue = new SqliteMutationQueue(database, limits, this.#records);
    this.#publications = new SqliteTemplatePublications(
      database,
      limits,
      this.#records,
      this.#queue,
    );
  }

  getVault(vaultId: VaultId): VaultRecord | null {
    return this.#records.getVault(vaultId);
  }

  getGroup(vaultId: VaultId, groupId: GroupId): EncryptedGroupRecord | null {
    return this.#records.getGroup(vaultId, groupId);
  }

  listGroups(vaultId: VaultId): readonly EncryptedGroupRecord[] {
    return this.#records.listGroups(vaultId);
  }

  getItem(vaultId: VaultId, itemId: ItemId): EncryptedItemRecord | null {
    return this.#records.getItem(vaultId, itemId);
  }

  listItems(vaultId: VaultId, groupId: GroupId): readonly EncryptedItemRecord[] {
    return this.#records.listItems(vaultId, groupId);
  }

  getCurrentGroup(vaultId: VaultId, groupId: GroupId): GroupMutationState | null {
    return this.#records.getCurrentGroup(vaultId, groupId);
  }

  getCurrentItem(vaultId: VaultId, itemId: ItemId): ItemMutationState | null {
    return this.#records.getCurrentItem(vaultId, itemId);
  }

  listCurrentItems(vaultId: VaultId, groupId: GroupId): readonly ItemMutationState[] {
    return this.#records.listCurrentItems(vaultId, groupId);
  }

  enqueueBatch(mutations: readonly OpaqueMutation[]): 'duplicate' | 'queued' {
    return this.#queue.enqueue(mutations);
  }

  applyPulledChange(pulled: SyncPulledChange, vaultId: VaultId): void {
    this.#records.applyPulledChange(pulled, vaultId);
  }

  promoteMutation(mutation: OpaqueMutation): void {
    this.#records.promote(mutation);
  }

  recordCompletedMutation(
    mutation: OpaqueMutation,
    queueKind: 'generic' | 'template-migration',
  ): void {
    this.#queue.recordCompleted(mutation, queueKind);
  }

  pruneCompletedMutationReceipts(protectedKeys: readonly string[]): void {
    this.#queue.pruneCompleted(protectedKeys);
  }

  loadPendingPublication(vaultId: VaultId): TemplateMigrationPublicationRequest | null {
    return this.#publications.load(vaultId);
  }

  enqueuePublication(publication: TemplateMigrationPublicationRequest): void {
    this.#publications.enqueue(publication);
  }

  completePublication(input: CompleteTemplateMigrationPublicationInput): void {
    this.#publications.complete(input);
  }

  completeReconciledPublication(
    input: CompleteTemplateMigrationPublicationInput,
  ): void {
    this.#publications.completeReconciled(input);
  }

  assertExactPendingPublication(
    publication: TemplateMigrationPublicationRequest,
  ): void {
    this.#publications.assertExactPending(publication);
  }

  assertNoQueueCoexistence(): void {
    this.#publications.assertNoQueueCoexistence();
  }

  assertBounds(): void {
    this.#records.assertBounds();
    this.#queue.assertBounds();
    this.#publications.assertBounds();
  }

  assertCanonicalState(): void {
    this.#records.assertCanonicalState();
    this.#publications.assertCanonicalState();
  }
}

export type SqliteVaultPorts = VaultSyncStorePort &
  VaultMutationStatePort &
  OpaqueMutationQueuePort;
