import type { VaultReadSourcePort } from './vault-read-session.js';
import {
  contentHashForRecord,
  syncCursorSchema,
  syncPullResponseSchema,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type GroupId,
  type ItemId,
  type OpaqueSyncRecord,
  type SyncCursor,
  type SyncPullResponse,
  type TombstoneRecord,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';
import { SyncProtocolError, type SyncTransportPort } from '@kavrix/sync';

import { OpaqueSnapshotCapacityError } from './errors.js';

const DEFAULT_MAXIMUM_RECORDS = 100_000;
const DEFAULT_MAXIMUM_BYTES = 256 * 1024 * 1024;
const HARD_MAXIMUM_RECORDS = 1_000_000;
const HARD_MAXIMUM_BYTES = 1024 * 1024 * 1024;
const MAXIMUM_REFRESH_PAGES = 100_000;

export type OpaqueVaultSnapshotOptions = Readonly<{
  maximumRecords?: number;
  maximumBytes?: number;
}>;

type StoredRecord<TRecord> = Readonly<{
  record: TRecord;
  bytes: number;
  contentHash: string;
  deleted: boolean;
  tombstoneRevision: number | null;
}>;

/**
 * Bounded, process-local ciphertext snapshot. It is intentionally non-durable
 * and stores only canonical opaque records received from sync pages.
 */
export class OpaqueVaultSnapshot implements VaultReadSourcePort {
  readonly #vaultId: VaultId;
  readonly #maximumRecords: number;
  readonly #maximumBytes: number;
  #vault: StoredRecord<VaultRecord> | null = null;
  #groups = new Map<GroupId, StoredRecord<EncryptedGroupRecord>>();
  #items = new Map<ItemId, StoredRecord<EncryptedItemRecord>>();
  #cursor: SyncCursor;
  #totalBytes = 0;

  constructor(vaultId: VaultId, options: OpaqueVaultSnapshotOptions = {}) {
    this.#vaultId = vaultId;
    this.#maximumRecords = boundedPositiveInteger(
      options.maximumRecords ?? DEFAULT_MAXIMUM_RECORDS,
      HARD_MAXIMUM_RECORDS,
    );
    this.#maximumBytes = boundedPositiveInteger(
      options.maximumBytes ?? DEFAULT_MAXIMUM_BYTES,
      HARD_MAXIMUM_BYTES,
    );
    this.#cursor = syncCursorSchema.parse({
      vaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 0,
    });
  }

  get cursor(): SyncCursor {
    return structuredClone(this.#cursor);
  }

  get recordCount(): number {
    return this.#groups.size + this.#items.size + (this.#vault === null ? 0 : 1);
  }

  get totalBytes(): number {
    return this.#totalBytes;
  }

  applyPullPage(candidate: SyncPullResponse): void {
    const parsed = syncPullResponseSchema.safeParse(candidate);
    if (!parsed.success) throw new SyncProtocolError();
    const page = parsed.data;
    validatePageProgress(page, this.#vaultId, this.#cursor);

    let vault = this.#vault;
    const groups = new Map(this.#groups);
    const items = new Map(this.#items);
    let totalBytes = this.#totalBytes;
    for (const pulled of page.changes) {
      const { change, record } = pulled;
      if (record === null) {
        if (change.operation !== 'purge') throw new SyncProtocolError();
        if (change.entityType === 'vault') {
          totalBytes = 0;
          vault = null;
          groups.clear();
          items.clear();
        } else if (change.entityType === 'group') {
          const previous = groups.get(change.entityId);
          totalBytes -= previous?.bytes ?? 0;
          groups.delete(change.entityId);
          for (const [itemId, stored] of items) {
            if (stored.record.groupId === change.entityId) {
              totalBytes -= stored.bytes;
              items.delete(itemId);
            }
          }
        } else if (change.entityType === 'item') {
          totalBytes -= items.get(change.entityId)?.bytes ?? 0;
          items.delete(change.entityId);
        }
        continue;
      }
      if (isTombstone(record)) {
        if (record.entityType === 'vault') {
          vault = applyDeletedTombstone(vault, record, true);
        } else if (record.entityType === 'group') {
          groups.set(
            record.entityId,
            applyDeletedTombstone(groups.get(record.entityId), record, vault !== null),
          );
        } else if (record.entityType === 'item') {
          const stored = items.get(record.entityId);
          const parentExists =
            stored !== undefined && groups.has(stored.record.groupId);
          items.set(
            record.entityId,
            applyDeletedTombstone(stored, record, parentExists),
          );
        }
        continue;
      }
      const contentHash = change.ciphertextHash;
      if (contentHash === undefined || contentHashForRecord(record) !== contentHash) {
        throw new SyncProtocolError();
      }
      if (isVaultRecord(record)) {
        const stored = acceptCurrentRecord(
          vault,
          record,
          contentHash,
          change.operation,
          true,
        );
        totalBytes += stored.bytes - (vault?.bytes ?? 0);
        vault = stored;
      } else if (isGroupRecord(record)) {
        const previous = groups.get(record.id);
        const stored = acceptCurrentRecord(
          previous,
          record,
          contentHash,
          change.operation,
          vault !== null && vault.record.id === record.vaultId,
        );
        totalBytes += stored.bytes - (groups.get(record.id)?.bytes ?? 0);
        groups.set(record.id, stored);
      } else if (isItemRecord(record)) {
        const previous = items.get(record.id);
        const parent = groups.get(record.groupId);
        const stored = acceptCurrentRecord(
          previous,
          record,
          contentHash,
          change.operation,
          parent?.record.vaultId === record.vaultId,
        );
        totalBytes += stored.bytes - (items.get(record.id)?.bytes ?? 0);
        items.set(record.id, stored);
      }
    }

    const recordCount = groups.size + items.size + (vault === null ? 0 : 1);
    if (recordCount > this.#maximumRecords || totalBytes > this.#maximumBytes) {
      throw new OpaqueSnapshotCapacityError();
    }
    this.#vault = vault;
    this.#groups = groups;
    this.#items = items;
    this.#totalBytes = totalBytes;
    this.#cursor = page.nextCursor;
  }

  async refresh(transport: SyncTransportPort, limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      throw new SyncProtocolError();
    }
    let changes = 0;
    for (let pageIndex = 0; pageIndex < MAXIMUM_REFRESH_PAGES; pageIndex += 1) {
      const page = await transport.pull({
        vaultId: this.#vaultId,
        cursor: this.cursor,
        limit,
      });
      this.applyPullPage(page);
      changes += page.changes.length;
      if (!page.hasMore) return changes;
    }
    throw new SyncProtocolError();
  }

  clear(): void {
    this.#vault = null;
    this.#groups.clear();
    this.#items.clear();
    this.#totalBytes = 0;
    this.#cursor = syncCursorSchema.parse({
      vaultId: this.#vaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 0,
    });
  }

  getVault(vaultId: VaultId): Promise<VaultRecord | null> {
    return Promise.resolve(
      vaultId === this.#vaultId && this.#vault !== null && !this.#vault.deleted
        ? structuredClone(this.#vault.record)
        : null,
    );
  }

  getGroup(vaultId: VaultId, groupId: GroupId): Promise<EncryptedGroupRecord | null> {
    const stored = vaultId === this.#vaultId ? this.#groups.get(groupId) : undefined;
    return Promise.resolve(
      stored === undefined || !this.#isGroupActive(stored)
        ? null
        : structuredClone(stored.record),
    );
  }

  listGroups(vaultId: VaultId): AsyncIterable<EncryptedGroupRecord> {
    const records =
      vaultId === this.#vaultId
        ? [...this.#groups.values()]
            .filter((stored) => this.#isGroupActive(stored))
            .map(({ record }) => structuredClone(record))
        : [];
    return asyncValues(records);
  }

  getItem(vaultId: VaultId, itemId: ItemId): Promise<EncryptedItemRecord | null> {
    const stored = vaultId === this.#vaultId ? this.#items.get(itemId) : undefined;
    return Promise.resolve(
      stored === undefined || !this.#isItemActive(stored)
        ? null
        : structuredClone(stored.record),
    );
  }

  listItems(vaultId: VaultId, groupId: GroupId): AsyncIterable<EncryptedItemRecord> {
    const records =
      vaultId === this.#vaultId
        ? [...this.#items.values()]
            .filter(
              (stored) =>
                stored.record.groupId === groupId && this.#isItemActive(stored),
            )
            .map(({ record }) => structuredClone(record))
        : [];
    return asyncValues(records);
  }

  #isGroupActive(stored: StoredRecord<EncryptedGroupRecord>): boolean {
    return this.#vault !== null && !this.#vault.deleted && !stored.deleted;
  }

  #isItemActive(stored: StoredRecord<EncryptedItemRecord>): boolean {
    const group = this.#groups.get(stored.record.groupId);
    return (
      this.#vault !== null &&
      !this.#vault.deleted &&
      group !== undefined &&
      !group.deleted &&
      !stored.deleted
    );
  }
}

function validatePageProgress(
  page: SyncPullResponse,
  vaultId: VaultId,
  cursor: SyncCursor,
): void {
  if (
    page.vaultId !== vaultId ||
    page.serverVaultRevision < cursor.highestSeenVaultRevision ||
    page.nextCursor.vaultId !== vaultId ||
    page.nextCursor.highestSeenVaultRevision !== page.serverVaultRevision
  ) {
    throw new SyncProtocolError();
  }
  let expectedSequence = cursor.serverSequence + 1;
  for (const pulled of page.changes) {
    if (pulled.change.serverSequence !== expectedSequence) {
      throw new SyncProtocolError();
    }
    expectedSequence += 1;
  }
  if (page.nextCursor.serverSequence !== expectedSequence - 1) {
    throw new SyncProtocolError();
  }
}

function isTombstone(
  record: OpaqueSyncRecord,
): record is Extract<OpaqueSyncRecord, { state: 'deleted' | 'restored' }> {
  return 'state' in record;
}

function isVaultRecord(record: OpaqueSyncRecord): record is VaultRecord {
  return 'revision' in record;
}

function isGroupRecord(record: OpaqueSyncRecord): record is EncryptedGroupRecord {
  return !('groupId' in record) && !('itemId' in record) && !('revision' in record);
}

function isItemRecord(record: OpaqueSyncRecord): record is EncryptedItemRecord {
  return 'groupId' in record && !('itemId' in record);
}

function storeRecord<TRecord>(
  record: TRecord,
  contentHash: string,
): StoredRecord<TRecord> {
  const copy = structuredClone(record);
  return {
    record: copy,
    bytes: Buffer.byteLength(JSON.stringify(copy), 'utf8'),
    contentHash,
    deleted: false,
    tombstoneRevision: null,
  };
}

function acceptCurrentRecord<
  TRecord extends VaultRecord | EncryptedGroupRecord | EncryptedItemRecord,
>(
  stored: StoredRecord<TRecord> | null | undefined,
  record: TRecord,
  contentHash: string,
  operation: 'upsert' | 'tombstone' | 'restore' | 'purge',
  parentExists: boolean,
): StoredRecord<TRecord> {
  if (!parentExists || (operation !== 'upsert' && operation !== 'restore')) {
    throw new SyncProtocolError();
  }
  if (operation === 'restore') {
    if (
      stored === null ||
      stored === undefined ||
      !stored.deleted ||
      stored.tombstoneRevision === null ||
      recordRevision(record) <= stored.tombstoneRevision ||
      !sameRecordIdentity(stored.record, record)
    ) {
      throw new SyncProtocolError();
    }
  } else if (
    stored?.deleted === true ||
    (stored !== null &&
      stored !== undefined &&
      recordRevision(record) <= recordRevision(stored.record))
  ) {
    throw new SyncProtocolError();
  }
  return storeRecord(record, contentHash);
}

function applyDeletedTombstone<
  TRecord extends VaultRecord | EncryptedGroupRecord | EncryptedItemRecord,
>(
  stored: StoredRecord<TRecord> | null | undefined,
  tombstone: TombstoneRecord,
  parentExists: boolean,
): StoredRecord<TRecord> {
  if (
    stored === null ||
    stored === undefined ||
    !parentExists ||
    recordRevision(stored.record) !== tombstone.lastRecordRevision ||
    stored.contentHash !== tombstone.lastCiphertextHash ||
    contentHashForRecord(stored.record) !== tombstone.lastCiphertextHash ||
    tombstone.tombstoneRevision <= tombstone.lastRecordRevision ||
    tombstone.state !== 'deleted' ||
    stored.deleted
  ) {
    throw new SyncProtocolError();
  }
  return {
    ...stored,
    deleted: true,
    tombstoneRevision: tombstone.tombstoneRevision,
  };
}

function sameRecordIdentity(
  previous: VaultRecord | EncryptedGroupRecord | EncryptedItemRecord,
  current: VaultRecord | EncryptedGroupRecord | EncryptedItemRecord,
): boolean {
  if ('revision' in previous || 'revision' in current) {
    return (
      'revision' in previous && 'revision' in current && previous.id === current.id
    );
  }
  if ('groupId' in previous || 'groupId' in current) {
    return (
      'groupId' in previous &&
      'groupId' in current &&
      previous.id === current.id &&
      previous.vaultId === current.vaultId &&
      previous.groupId === current.groupId
    );
  }
  return previous.id === current.id && previous.vaultId === current.vaultId;
}

function recordRevision(
  record: VaultRecord | EncryptedGroupRecord | EncryptedItemRecord,
): number {
  return 'revision' in record ? record.revision : record.recordRevision;
}

function boundedPositiveInteger(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError('An opaque snapshot bound is invalid.');
  }
  return value;
}

function asyncValues<TValue>(values: readonly TValue[]): AsyncIterable<TValue> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<TValue> {
      let index = 0;
      return {
        next: () => {
          const value = values[index];
          index += 1;
          return Promise.resolve(
            value === undefined
              ? { done: true, value: undefined }
              : { done: false, value },
          );
        },
      };
    },
  };
}
