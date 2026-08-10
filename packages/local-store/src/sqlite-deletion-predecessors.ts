import type { DatabaseSync } from 'node:sqlite';

import type { HashableOpaqueRecord, VaultId } from '@kavrix/schemas';

import {
  activeRecordRevision,
  encodeBounded,
  invalidState,
  parsePredecessorRow,
  recordEntityType,
  recordIdentity,
  recordVaultId,
} from './sqlite-vault-codecs.js';
import type {
  EntityType,
  PersistedPredecessorRow,
  VaultStateLimits,
} from './sqlite-vault-schema.js';

export class SqliteDeletionPredecessors {
  readonly #database: DatabaseSync;
  readonly #limits: VaultStateLimits;

  constructor(database: DatabaseSync, limits: VaultStateLimits) {
    this.#database = database;
    this.#limits = limits;
  }

  load(
    vaultId: VaultId,
    entityType: EntityType,
    entityId: string,
    ownerKey: string,
  ): HashableOpaqueRecord | null {
    const row = this.#database
      .prepare(
        `SELECT vault_id, entity_type, entity_id, owner_key, revision,
                record_json, serialized_bytes
           FROM deletion_predecessors
          WHERE vault_id = ? AND entity_type = ? AND entity_id = ?
            AND owner_key = ?`,
      )
      .get(vaultId, entityType, entityId, ownerKey) as
      PersistedPredecessorRow | undefined;
    return row === undefined
      ? null
      : parsePredecessorRow(row, vaultId, entityType, entityId, ownerKey);
  }

  store(record: HashableOpaqueRecord, ownerKey: string): void {
    const vaultId = recordVaultId(record);
    const entityType = recordEntityType(record);
    const entityId = recordIdentity(record);
    const revision = activeRecordRevision(record);
    const encoded = encodeBounded(record, this.#limits.maxSerializedRowBytes);
    const existing = this.load(vaultId, entityType, entityId, ownerKey);
    if (existing !== null) {
      if (JSON.stringify(existing) !== encoded.json) throw invalidState();
      return;
    }
    this.#database
      .prepare(
        `INSERT INTO deletion_predecessors
           (vault_id, entity_type, entity_id, owner_key, revision, record_json,
            serialized_bytes)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        vaultId,
        entityType,
        entityId,
        ownerKey,
        revision,
        encoded.json,
        encoded.bytes,
      );
  }

  delete(
    vaultId: VaultId,
    entityType: EntityType,
    entityId: string,
    ownerKey: string,
  ): void {
    this.#database
      .prepare(
        `DELETE FROM deletion_predecessors
          WHERE vault_id = ? AND entity_type = ? AND entity_id = ?
            AND owner_key = ?`,
      )
      .run(vaultId, entityType, entityId, ownerKey);
  }
}
