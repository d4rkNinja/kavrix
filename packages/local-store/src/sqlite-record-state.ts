import type { DatabaseSync } from 'node:sqlite';

import type { GroupMutationState, ItemMutationState } from '@kavrix/client';
import {
  canonicalJson,
  contentHashForRecord,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  vaultRecordSchema,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type GroupId,
  type ItemId,
  type OpaqueMutation,
  type OpaqueSyncRecord,
  type SyncPulledChange,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';

import { SqliteDeletionPredecessors } from './sqlite-deletion-predecessors.js';
import {
  assertTombstonePredecessor,
  encodeBounded,
  getInteger,
  invalidState,
  isDeleteMutation,
  isTombstone,
  mutationVaultId,
  parseMutationInput,
  parseMutationRow,
  parseOpaqueRecord,
  parseRecordRow,
  recordEntityType,
  recordIdentity,
  recordVaultId,
  requireGroupTombstone,
  requireItemTombstone,
  samePulledState,
  stateRecord,
  stateRevision,
  syncRecordRevision,
  synthesizeTombstone,
} from './sqlite-vault-codecs.js';
import type {
  CurrentState,
  EntityType,
  PersistedMutationRow,
  PersistedRecordRow,
  VaultStateLimits,
} from './sqlite-vault-schema.js';

export class SqliteRecordState {
  readonly #database: DatabaseSync;
  readonly #limits: VaultStateLimits;
  readonly #predecessors: SqliteDeletionPredecessors;

  constructor(database: DatabaseSync, limits: VaultStateLimits) {
    this.#database = database;
    this.#limits = limits;
    this.#predecessors = new SqliteDeletionPredecessors(database, limits);
  }

  getVault(vaultId: VaultId): VaultRecord | null {
    const state = this.effective(vaultId, 'vault', vaultId);
    if (state === null || state.state === 'deleted') return null;
    return vaultRecordSchema.parse(state.record);
  }

  getGroup(vaultId: VaultId, groupId: GroupId): EncryptedGroupRecord | null {
    const state = this.effective(vaultId, 'group', groupId);
    if (state === null || state.state === 'deleted') return null;
    return encryptedGroupRecordSchema.parse(state.record);
  }

  listGroups(vaultId: VaultId): readonly EncryptedGroupRecord[] {
    return [...this.#effectiveAll(vaultId, 'group').values()]
      .filter(
        (state): state is Extract<CurrentState, { state: 'active' }> =>
          state.state === 'active',
      )
      .map((state) => encryptedGroupRecordSchema.parse(state.record))
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  getItem(vaultId: VaultId, itemId: ItemId): EncryptedItemRecord | null {
    const state = this.effective(vaultId, 'item', itemId);
    if (state === null || state.state === 'deleted') return null;
    const item = encryptedItemRecordSchema.parse(state.record);
    return this.getGroup(vaultId, item.groupId) === null ? null : item;
  }

  listItems(vaultId: VaultId, groupId: GroupId): readonly EncryptedItemRecord[] {
    if (this.getGroup(vaultId, groupId) === null) return [];
    return [...this.#effectiveAll(vaultId, 'item').values()]
      .filter(
        (state): state is Extract<CurrentState, { state: 'active' }> =>
          state.state === 'active',
      )
      .map((state) => encryptedItemRecordSchema.parse(state.record))
      .filter((record) => record.groupId === groupId)
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  getCurrentGroup(vaultId: VaultId, groupId: GroupId): GroupMutationState | null {
    const state = this.effective(vaultId, 'group', groupId);
    if (state === null) return null;
    if (state.state === 'active') {
      return {
        state: 'active',
        record: encryptedGroupRecordSchema.parse(state.record),
      };
    }
    return {
      state: 'deleted',
      tombstone: requireGroupTombstone(state.tombstone),
      predecessor: encryptedGroupRecordSchema.parse(state.predecessor),
    };
  }

  getCurrentItem(vaultId: VaultId, itemId: ItemId): ItemMutationState | null {
    const state = this.effective(vaultId, 'item', itemId);
    if (state === null) return null;
    if (state.state === 'active') {
      return { state: 'active', record: encryptedItemRecordSchema.parse(state.record) };
    }
    return {
      state: 'deleted',
      tombstone: requireItemTombstone(state.tombstone),
      predecessor: encryptedItemRecordSchema.parse(state.predecessor),
    };
  }

  listCurrentItems(vaultId: VaultId, groupId: GroupId): readonly ItemMutationState[] {
    const result: ItemMutationState[] = [];
    for (const state of this.#effectiveAll(vaultId, 'item').values()) {
      if (state.state === 'active') {
        const record = encryptedItemRecordSchema.parse(state.record);
        if (record.groupId === groupId) result.push({ state: 'active', record });
      } else {
        const predecessor = encryptedItemRecordSchema.parse(state.predecessor);
        if (predecessor.groupId === groupId) {
          result.push({
            state: 'deleted',
            tombstone: requireItemTombstone(state.tombstone),
            predecessor,
          });
        }
      }
    }
    return result.sort((left, right) =>
      stateRecord(left).id.localeCompare(stateRecord(right).id),
    );
  }

  applyPulledChange(pulled: SyncPulledChange, vaultId: VaultId): void {
    const { change, record } = pulled;
    if (change.vaultId !== vaultId) throw invalidState();
    const existing = this.base(vaultId, change.entityType, change.entityId);
    if (existing !== null) {
      const existingRevision = stateRevision(existing);
      if (change.recordRevision < existingRevision) throw invalidState();
      if (change.recordRevision === existingRevision) {
        if (!samePulledState(existing, record)) throw invalidState();
        return;
      }
    }
    if (record === null) {
      this.#deleteBase(vaultId, change.entityType, change.entityId);
      this.#predecessors.delete(vaultId, change.entityType, change.entityId, '');
      return;
    }
    const canonical = parseOpaqueRecord(record);
    if (isTombstone(canonical)) {
      if (canonical.state !== 'deleted' || existing?.state !== 'active') {
        throw invalidState();
      }
      assertTombstonePredecessor(canonical, existing.record);
      this.#predecessors.store(existing.record, '');
    } else {
      if (change.ciphertextHash !== contentHashForRecord(canonical)) {
        throw invalidState();
      }
      if (existing?.state === 'deleted') {
        this.#predecessors.delete(vaultId, change.entityType, change.entityId, '');
      }
    }
    this.#storeBase(canonical);
    this.assertBounds();
  }

  promote(mutationInput: OpaqueMutation): void {
    const mutation = parseMutationInput(mutationInput);
    const vaultId = mutationVaultId(mutation);
    const entityType = mutation.entityType;
    const entityId = mutation.record.id;
    const current = this.base(vaultId, entityType, entityId);
    this.assertMutationApplies(current, mutation);
    if (isDeleteMutation(mutation)) {
      const predecessor = this.#predecessors.load(
        vaultId,
        entityType,
        entityId,
        mutation.idempotencyKey,
      );
      if (predecessor === null) throw invalidState();
      this.#predecessors.store(predecessor, '');
      this.#storeBase(synthesizeTombstone(mutation, predecessor));
    } else {
      if (current?.state === 'deleted') {
        this.#predecessors.delete(vaultId, entityType, entityId, '');
      }
      this.#storeBase(mutation.record);
    }
    this.#predecessors.delete(vaultId, entityType, entityId, mutation.idempotencyKey);
    this.assertBounds();
  }

  effective(
    vaultId: VaultId,
    entityType: EntityType,
    entityId: string,
  ): CurrentState | null {
    let state = this.base(vaultId, entityType, entityId);
    const generic = this.#database
      .prepare(
        `SELECT vault_id, entity_type, entity_id, idempotency_key,
                mutation_json, serialized_bytes
           FROM pending_mutations
          WHERE vault_id = ? AND entity_type = ? AND entity_id = ?
          ORDER BY sequence ASC`,
      )
      .all(vaultId, entityType, entityId) as unknown as PersistedMutationRow[];
    const migration = this.#database
      .prepare(
        `SELECT vault_id, entity_type, entity_id, idempotency_key,
                mutation_json, serialized_bytes
           FROM pending_template_migration_mutations
          WHERE vault_id = ? AND entity_type = ? AND entity_id = ?
          ORDER BY position ASC`,
      )
      .all(vaultId, entityType, entityId) as unknown as PersistedMutationRow[];
    if (generic.length > 0 && migration.length > 0) throw invalidState();
    let hasPending = false;
    for (const row of generic.length > 0 ? generic : migration) {
      const mutation = parseMutationRow(row, vaultId, entityType, entityId);
      if (hasPending) this.assertMutationApplies(state, mutation);
      if (isDeleteMutation(mutation)) {
        const predecessor = this.#predecessors.load(
          vaultId,
          entityType,
          entityId,
          mutation.idempotencyKey,
        );
        if (predecessor === null) throw invalidState();
        state = {
          state: 'deleted',
          tombstone: synthesizeTombstone(mutation, predecessor),
          predecessor,
        };
      } else {
        state = { state: 'active', record: mutation.record };
      }
      hasPending = true;
    }
    return state;
  }

  base(
    vaultId: VaultId,
    entityType: EntityType,
    entityId: string,
  ): CurrentState | null {
    const row = this.#database
      .prepare(
        `SELECT vault_id, entity_type, entity_id, revision, record_json,
                serialized_bytes
           FROM opaque_records
          WHERE vault_id = ? AND entity_type = ? AND entity_id = ?`,
      )
      .get(vaultId, entityType, entityId) as PersistedRecordRow | undefined;
    if (row === undefined) return null;
    const record = parseRecordRow(row, vaultId, entityType, entityId);
    if (!isTombstone(record)) return { state: 'active', record };
    if (record.state !== 'deleted') throw invalidState();
    const predecessor = this.#predecessors.load(vaultId, entityType, entityId, '');
    if (predecessor === null) throw invalidState();
    assertTombstonePredecessor(record, predecessor);
    return { state: 'deleted', tombstone: record, predecessor };
  }

  assertMutationApplies(current: CurrentState | null, mutation: OpaqueMutation): void {
    const expected =
      mutation.entityType === 'vault'
        ? mutation.expectedVaultRevision
        : mutation.expectedRecordRevision;
    if (
      (expected === null && current !== null) ||
      (expected !== null && (current === null || stateRevision(current) !== expected))
    ) {
      throw invalidState();
    }
    if (isDeleteMutation(mutation) && current?.state !== 'active') throw invalidState();
  }

  storePendingDeletePredecessor(
    mutation: Extract<OpaqueMutation, { entityType: 'group' | 'item' }>,
    current: CurrentState,
  ): void {
    if (current.state !== 'active') throw invalidState();
    this.#predecessors.store(current.record, mutation.idempotencyKey);
  }

  assertBounds(): void {
    const bounds = this.#database
      .prepare(
        `SELECT
           (SELECT COUNT(*) FROM opaque_records) +
           (SELECT COUNT(*) FROM deletion_predecessors) AS row_count,
           (SELECT COALESCE(SUM(serialized_bytes), 0) FROM opaque_records) +
           (SELECT COALESCE(SUM(serialized_bytes), 0) FROM deletion_predecessors)
             AS total_bytes`,
      )
      .get();
    if (
      getInteger(bounds, 'row_count') > this.#limits.maxRecords ||
      getInteger(bounds, 'total_bytes') > this.#limits.maxRecordBytes
    ) {
      throw invalidState();
    }
  }

  assertCanonicalState(): void {
    const baseRows = this.#database
      .prepare(`SELECT vault_id, entity_type, entity_id FROM opaque_records`)
      .all() as unknown as {
      vault_id?: unknown;
      entity_type?: unknown;
      entity_id?: unknown;
    }[];
    for (const row of baseRows) {
      if (
        typeof row.vault_id !== 'string' ||
        typeof row.entity_type !== 'string' ||
        typeof row.entity_id !== 'string'
      ) {
        throw invalidState();
      }
      this.base(row.vault_id as VaultId, row.entity_type as EntityType, row.entity_id);
    }

    const identities = this.#database
      .prepare(
        `SELECT vault_id, entity_type, entity_id FROM pending_mutations
         UNION
         SELECT vault_id, entity_type, entity_id
           FROM pending_template_migration_mutations`,
      )
      .all() as unknown as {
      vault_id?: unknown;
      entity_type?: unknown;
      entity_id?: unknown;
    }[];
    for (const identity of identities) {
      if (
        typeof identity.vault_id !== 'string' ||
        typeof identity.entity_type !== 'string' ||
        typeof identity.entity_id !== 'string'
      ) {
        throw invalidState();
      }
      const vaultId = identity.vault_id as VaultId;
      const entityType = identity.entity_type as EntityType;
      const entityId = identity.entity_id;
      const generic = this.#database
        .prepare(
          `SELECT vault_id, entity_type, entity_id, idempotency_key,
                  mutation_json, serialized_bytes
             FROM pending_mutations
            WHERE vault_id = ? AND entity_type = ? AND entity_id = ?
            ORDER BY sequence ASC`,
        )
        .all(vaultId, entityType, entityId) as unknown as PersistedMutationRow[];
      const publication = this.#database
        .prepare(
          `SELECT vault_id, entity_type, entity_id, idempotency_key,
                  mutation_json, serialized_bytes
             FROM pending_template_migration_mutations
            WHERE vault_id = ? AND entity_type = ? AND entity_id = ?
            ORDER BY position ASC`,
        )
        .all(vaultId, entityType, entityId) as unknown as PersistedMutationRow[];
      if (generic.length > 0 && publication.length > 0) throw invalidState();
      let current = this.base(vaultId, entityType, entityId);
      for (const row of generic.length > 0 ? generic : publication) {
        const mutation = parseMutationRow(row, vaultId, entityType, entityId);
        this.assertMutationApplies(current, mutation);
        if (isDeleteMutation(mutation)) {
          const predecessor = this.#predecessors.load(
            vaultId,
            entityType,
            entityId,
            mutation.idempotencyKey,
          );
          if (
            predecessor === null ||
            current?.state !== 'active' ||
            canonicalJson(predecessor) !== canonicalJson(current.record)
          ) {
            throw invalidState();
          }
          current = {
            state: 'deleted',
            tombstone: synthesizeTombstone(mutation, predecessor),
            predecessor,
          };
        } else {
          current = { state: 'active', record: mutation.record };
        }
      }
    }

    const predecessorOwners = this.#database
      .prepare(
        `SELECT vault_id, entity_type, entity_id, owner_key
           FROM deletion_predecessors`,
      )
      .all() as unknown as {
      vault_id?: unknown;
      entity_type?: unknown;
      entity_id?: unknown;
      owner_key?: unknown;
    }[];
    for (const row of predecessorOwners) {
      if (
        typeof row.vault_id !== 'string' ||
        typeof row.entity_type !== 'string' ||
        typeof row.entity_id !== 'string' ||
        typeof row.owner_key !== 'string'
      ) {
        throw invalidState();
      }
      if (row.owner_key === '') {
        if (
          this.base(
            row.vault_id as VaultId,
            row.entity_type as EntityType,
            row.entity_id,
          )?.state !== 'deleted'
        ) {
          throw invalidState();
        }
        continue;
      }
      const claims = this.#database
        .prepare(
          `SELECT mutation_json FROM pending_mutations WHERE idempotency_key = ?
           UNION ALL
           SELECT mutation_json FROM pending_template_migration_mutations
            WHERE idempotency_key = ?`,
        )
        .all(row.owner_key, row.owner_key) as unknown as { mutation_json?: unknown }[];
      if (claims.length !== 1 || typeof claims[0]?.mutation_json !== 'string') {
        throw invalidState();
      }
      const mutation = parseMutationInput(
        JSON.parse(claims[0].mutation_json) as unknown,
      );
      if (
        !isDeleteMutation(mutation) ||
        mutationVaultId(mutation) !== row.vault_id ||
        mutation.entityType !== row.entity_type ||
        mutation.record.id !== row.entity_id ||
        mutation.idempotencyKey !== row.owner_key
      ) {
        throw invalidState();
      }
    }
  }

  #effectiveAll(vaultId: VaultId, entityType: EntityType): Map<string, CurrentState> {
    const identities = new Set<string>();
    const collect = (sql: string): void => {
      const rows = this.#database.prepare(sql).all(vaultId, entityType) as unknown as {
        entity_id?: unknown;
      }[];
      for (const row of rows) {
        if (typeof row.entity_id !== 'string') throw invalidState();
        identities.add(row.entity_id);
      }
    };
    collect(
      `SELECT entity_id FROM opaque_records WHERE vault_id = ? AND entity_type = ?`,
    );
    collect(
      `SELECT entity_id FROM pending_mutations WHERE vault_id = ? AND entity_type = ?`,
    );
    collect(
      `SELECT entity_id FROM pending_template_migration_mutations
        WHERE vault_id = ? AND entity_type = ?`,
    );
    const states = new Map<string, CurrentState>();
    for (const identity of [...identities].sort()) {
      const state = this.effective(vaultId, entityType, identity);
      if (state !== null) states.set(identity, state);
    }
    return states;
  }

  #storeBase(record: OpaqueSyncRecord): void {
    const vaultId = recordVaultId(record);
    const entityType = recordEntityType(record);
    const entityId = recordIdentity(record);
    const revision = syncRecordRevision(record);
    const encoded = encodeBounded(record, this.#limits.maxSerializedRowBytes);
    this.#database
      .prepare(
        `INSERT INTO opaque_records
           (vault_id, entity_type, entity_id, revision, record_json,
            serialized_bytes)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(vault_id, entity_type, entity_id) DO UPDATE SET
           revision = excluded.revision,
           record_json = excluded.record_json,
           serialized_bytes = excluded.serialized_bytes`,
      )
      .run(vaultId, entityType, entityId, revision, encoded.json, encoded.bytes);
  }

  #deleteBase(vaultId: VaultId, entityType: EntityType, entityId: string): void {
    this.#database
      .prepare(
        `DELETE FROM opaque_records
          WHERE vault_id = ? AND entity_type = ? AND entity_id = ?`,
      )
      .run(vaultId, entityType, entityId);
  }
}
