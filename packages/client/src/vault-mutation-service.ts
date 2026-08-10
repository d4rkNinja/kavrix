import {
  CryptoAuthenticationError,
  NotFoundError,
  SchemaMigrationError,
  SyncConflictError,
  ValidationError,
  VaultLockedError,
  applyTemplateMigrationBatch,
  planTemplateMigration,
  validateItemAgainstTemplate,
  type ClockPort,
  type IdGeneratorPort,
  type VaultStoragePort,
} from '@kavrix/core';
import {
  cloneSecretKey,
  generateGroupKey,
  generateItemKey,
  requireByteLength,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  auditEventIdSchema,
  groupIdSchema,
  groupPayloadSchema,
  groupTemplateSchema,
  itemIdSchema,
  itemPayloadSchema,
  opaqueMutationSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationIdSchema,
  timestampSchema,
  type AuditEventId,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type GroupId,
  type GroupPayload,
  type GroupTemplate,
  type ItemId,
  type ItemPayload,
  type OpaqueMutation,
  type RecordRevision,
  type TemplateMigrationId,
  type TemplateMigrationPublicationRequest,
  type TombstoneRecord,
  type VaultId,
} from '@kavrix/schemas';

import { VaultSessionConcurrencyError } from './errors.js';
import {
  openDeletedGroupState,
  openDeletedItemState,
} from './vault-mutation-deleted-state.js';
import {
  authenticateVaultRecord,
  encryptGroupRecord,
  encryptItemRecord,
  openGroupRecord,
  openItemRecord,
  type ActiveVault,
  type OpenGroup,
  type OpenItem,
} from './vault-mutation-records.js';
const MAX_ATOMIC_TEMPLATE_MIGRATION_ITEMS = 99;

/** Exact current opaque state, including tombstoned records and queue overlays. */
export interface VaultMutationStatePort extends Pick<VaultStoragePort, 'getVault'> {
  getCurrentGroup(
    vaultId: VaultId,
    groupId: GroupId,
  ): Promise<GroupMutationState | null>;
  getCurrentItem(vaultId: VaultId, itemId: ItemId): Promise<ItemMutationState | null>;
  listCurrentItems(
    vaultId: VaultId,
    groupId: GroupId,
  ): AsyncIterable<ItemMutationState>;
}

type GroupTombstone = Extract<TombstoneRecord, { entityType: 'group' }>;
type ItemTombstone = Extract<TombstoneRecord, { entityType: 'item' }>;

export type GroupMutationState =
  | Readonly<{ state: 'active'; record: EncryptedGroupRecord }>
  | Readonly<{
      state: 'deleted';
      tombstone: GroupTombstone;
      predecessor: EncryptedGroupRecord;
    }>;

export type ItemMutationState =
  | Readonly<{ state: 'active'; record: EncryptedItemRecord }>
  | Readonly<{
      state: 'deleted';
      tombstone: ItemTombstone;
      predecessor: EncryptedItemRecord;
    }>;

/**
 * Resolution means the complete batch is durably recorded as one idempotent
 * queue transaction. Repeating an identical batch must succeed; reusing an
 * idempotency key for different bytes must fail closed.
 */
export interface OpaqueMutationQueuePort {
  /** Generic and atomic pending work must never coexist for one vault. */
  enqueueBatch(mutations: readonly OpaqueMutation[]): Promise<void>;
  enqueueTemplateMigrationPublication(
    publication: TemplateMigrationPublicationRequest,
  ): Promise<void>;
}

/** Must return a fresh, unpredictable 16-256 character idempotency value. */
export interface MutationIdempotencyPort {
  next(): string;
}

/** Queue acknowledgement failed after durable outcome became unknowable. */
export class OpaqueMutationDurabilityUnknownError extends Error {
  readonly safe = true;

  constructor(options?: ErrorOptions) {
    super('The mutation queue durability outcome is unknown.', options);
    this.name = 'OpaqueMutationDurabilityUnknownError';
  }
}

export type CreateGroupInput = Omit<
  GroupPayload,
  'id' | 'vaultId' | 'revision' | 'createdAt' | 'updatedAt' | 'deletedAt'
>;

export type CreateItemInput = Omit<
  ItemPayload,
  | 'id'
  | 'vaultId'
  | 'groupId'
  | 'templateId'
  | 'templateVersion'
  | 'revision'
  | 'createdAt'
  | 'updatedAt'
  | 'deletedAt'
>;

export type VaultMutationServiceDependencies = Readonly<{
  clock: ClockPort;
  groupIds: IdGeneratorPort<GroupId>;
  itemIds: IdGeneratorPort<ItemId>;
  migrationIds: IdGeneratorPort<TemplateMigrationId>;
  auditEventIds: IdGeneratorPort<AuditEventId>;
  idempotency: MutationIdempotencyPort;
}>;

/**
 * Produces only authenticated opaque mutations. Queue persistence and remote
 * publication remain outside this zero-knowledge service.
 */
export class VaultMutationService {
  readonly #source: VaultMutationStatePort;
  readonly #queue: OpaqueMutationQueuePort;
  readonly #vaultId: VaultId;
  readonly #dependencies: VaultMutationServiceDependencies;
  #rootKey: VaultRootKey | null;
  #epoch = 0;
  #busy = false;

  constructor(
    source: VaultMutationStatePort,
    queue: OpaqueMutationQueuePort,
    vaultId: VaultId,
    rootKey: VaultRootKey,
    dependencies: VaultMutationServiceDependencies,
  ) {
    requireByteLength(rootKey, 32, 'vault root key');
    this.#source = source;
    this.#queue = queue;
    this.#vaultId = vaultId;
    this.#dependencies = dependencies;
    this.#rootKey = cloneSecretKey(rootKey);
  }

  get locked(): boolean {
    return this.#rootKey === null;
  }

  lock(): void {
    this.#epoch += 1;
    const rootKey = this.#rootKey;
    this.#rootKey = null;
    zeroize(rootKey ?? undefined);
  }

  async createGroup(input: CreateGroupInput): Promise<GroupId> {
    return this.#mutate(async (rootKey, epoch) => {
      const vault = await this.#loadVault(rootKey, epoch);
      const id = groupIdSchema.parse(this.#dependencies.groupIds.next());
      if ((await this.#source.getCurrentGroup(this.#vaultId, id)) !== null) {
        throw new ValidationError('The generated group ID is already in use.');
      }
      this.#assertActive(epoch);
      const timestamp = this.#timestamp();
      const payload = parseGroupInput({
        ...input,
        id,
        vaultId: this.#vaultId,
        revision: 0,
        createdAt: timestamp,
        updatedAt: timestamp,
      });
      const key = generateGroupKey();
      try {
        const record = await encryptGroupRecord(payload, key, rootKey, vault);
        await this.#enqueue([this.#groupMutation(null, record)], epoch);
        return id;
      } finally {
        zeroize(key);
      }
    });
  }

  async createItem(groupId: GroupId, input: CreateItemInput): Promise<ItemId> {
    return this.#mutate(async (rootKey, epoch) => {
      const vault = await this.#loadVault(rootKey, epoch);
      const group = await this.#loadGroup(groupId, vault, rootKey, epoch, false);
      try {
        const id = itemIdSchema.parse(this.#dependencies.itemIds.next());
        if ((await this.#source.getCurrentItem(this.#vaultId, id)) !== null) {
          throw new ValidationError('The generated item ID is already in use.');
        }
        this.#assertActive(epoch);
        const timestamp = this.#timestamp();
        const payload = parseItemInput({
          ...input,
          id,
          vaultId: this.#vaultId,
          groupId: group.payload.id,
          templateId: group.payload.template.id,
          templateVersion: group.payload.template.version,
          revision: 0,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
        validateItemAgainstTemplate(payload, group.payload.template);
        const key = generateItemKey();
        try {
          const record = await encryptItemRecord(payload, key, group.key, vault);
          await this.#enqueue([this.#itemMutation(null, record)], epoch);
          return id;
        } finally {
          zeroize(key);
        }
      } finally {
        zeroize(group.key);
      }
    });
  }

  async updateGroup(payloadInput: GroupPayload): Promise<void> {
    await this.#mutate(async (rootKey, epoch) => {
      const input = parseGroupInput(payloadInput);
      this.#assertPayloadVault(input.vaultId);
      const vault = await this.#loadVault(rootKey, epoch);
      const group = await this.#loadGroup(input.id, vault, rootKey, epoch, false);
      try {
        assertRevisionBase(input, group.payload);
        if (
          canonicalTemplate(input.template) !==
          canonicalTemplate(group.payload.template)
        ) {
          throw new SchemaMigrationError(
            'Template changes must use the template migration operation.',
          );
        }
        const payload = parseGroupInput({
          ...input,
          revision: nextRevision(group.record.recordRevision),
          updatedAt: this.#timestamp(),
        });
        const record = await encryptGroupRecord(
          payload,
          group.key,
          rootKey,
          vault,
          group.record.wrappedGroupKey,
        );
        await this.#enqueue(
          [this.#groupMutation(group.record.recordRevision, record)],
          epoch,
        );
      } finally {
        zeroize(group.key);
      }
    });
  }

  async updateItem(groupId: GroupId, payloadInput: ItemPayload): Promise<void> {
    await this.#mutate(async (rootKey, epoch) => {
      const input = parseItemInput(payloadInput);
      this.#assertPayloadVault(input.vaultId);
      if (input.groupId !== groupId) {
        throw new ValidationError('The item does not belong to the requested group.');
      }
      const vault = await this.#loadVault(rootKey, epoch);
      const group = await this.#loadGroup(groupId, vault, rootKey, epoch, false);
      try {
        const item = await this.#loadItem(input.id, group, vault, epoch, false);
        try {
          assertRevisionBase(input, item.payload);
          validateItemAgainstTemplate(input, group.payload.template);
          const payload = parseItemInput({
            ...input,
            revision: nextRevision(item.record.recordRevision),
            updatedAt: this.#timestamp(),
          });
          const record = await encryptItemRecord(
            payload,
            item.key,
            group.key,
            vault,
            item.record.wrappedItemKey,
          );
          await this.#enqueue(
            [this.#itemMutation(item.record.recordRevision, record)],
            epoch,
          );
        } finally {
          zeroize(item.key);
        }
      } finally {
        zeroize(group.key);
      }
    });
  }

  async deleteGroup(id: GroupId, expectedRevision: RecordRevision): Promise<void> {
    await this.#changeGroupDeletion(id, expectedRevision, true);
  }

  async restoreGroup(id: GroupId, expectedRevision: RecordRevision): Promise<void> {
    await this.#changeGroupDeletion(id, expectedRevision, false);
  }

  async deleteItem(
    groupId: GroupId,
    id: ItemId,
    expectedRevision: RecordRevision,
  ): Promise<void> {
    await this.#changeItemDeletion(groupId, id, expectedRevision, true);
  }

  async restoreItem(
    groupId: GroupId,
    id: ItemId,
    expectedRevision: RecordRevision,
  ): Promise<void> {
    await this.#changeItemDeletion(groupId, id, expectedRevision, false);
  }

  async migrateGroupTemplate(
    groupId: GroupId,
    expectedRevision: RecordRevision,
    targetTemplateInput: GroupTemplate,
    confirmRiskyChanges = false,
  ): Promise<void> {
    await this.#mutate(async (rootKey, epoch) => {
      const targetTemplate = groupTemplateSchema.safeParse(targetTemplateInput);
      if (!targetTemplate.success) throw new ValidationError();
      const vault = await this.#loadVault(rootKey, epoch);
      const group = await this.#loadGroup(groupId, vault, rootKey, epoch, false);
      const items: OpenItem[] = [];
      try {
        assertExpectedRevision(expectedRevision, group.record.recordRevision);
        const itemIds = new Set<string>();
        for await (const candidate of this.#source.listCurrentItems(
          this.#vaultId,
          groupId,
        )) {
          if (candidate.state === 'deleted') {
            throw new SchemaMigrationError(
              'Restore deleted items before migrating their group template.',
            );
          }
          if (items.length >= MAX_ATOMIC_TEMPLATE_MIGRATION_ITEMS) {
            throw new SchemaMigrationError(
              'Atomic template migrations support at most 99 active items.',
            );
          }
          if (itemIds.has(candidate.record.id)) {
            throw new CryptoAuthenticationError();
          }
          itemIds.add(candidate.record.id);
          items.push(await openItemRecord(candidate.record, group, vault));
          this.#assertActive(epoch);
        }
        const timestamp = this.#timestamp();
        const plan = planTemplateMigration({
          migrationId: templateMigrationIdSchema.parse(
            this.#dependencies.migrationIds.next(),
          ),
          auditEventId: auditEventIdSchema.parse(
            this.#dependencies.auditEventIds.next(),
          ),
          fromTemplate: group.payload.template,
          toTemplate: targetTemplate.data,
          items: items.map(({ payload }) => payload),
          timestamp,
        });
        const applied = applyTemplateMigrationBatch(
          plan,
          items.map(({ payload }) => payload),
          Math.max(items.length, 1),
          timestamp,
          confirmRiskyChanges,
        );
        if (applied.plan.status !== 'completed') {
          throw new SchemaMigrationError();
        }
        const itemsById = new Map(items.map((item) => [item.payload.id, item]));
        const mutations: OpaqueMutation[] = [];
        for (const payload of applied.items) {
          const item = itemsById.get(payload.id);
          if (item === undefined) throw new CryptoAuthenticationError();
          const record = await encryptItemRecord(
            payload,
            item.key,
            group.key,
            vault,
            item.record.wrappedItemKey,
          );
          mutations.push(this.#itemMutation(item.record.recordRevision, record));
        }
        mutations.sort(compareMutationEntityId);
        const migratedGroup = parseGroupInput({
          ...group.payload,
          template: targetTemplate.data,
          revision: nextRevision(group.record.recordRevision),
          updatedAt: timestamp,
        });
        const groupRecord = await encryptGroupRecord(
          migratedGroup,
          group.key,
          rootKey,
          vault,
          group.record.wrappedGroupKey,
        );
        mutations.push(this.#groupMutation(group.record.recordRevision, groupRecord));
        const batchIdempotencyKey = this.#dependencies.idempotency.next();
        if (
          mutations.some((mutation) => mutation.idempotencyKey === batchIdempotencyKey)
        ) {
          throw new ValidationError('The idempotency provider reused a value.');
        }
        const publication = templateMigrationPublicationRequestSchema.parse({
          vaultId: this.#vaultId,
          batchIdempotencyKey,
          mutations,
        });
        await this.#enqueueTemplateMigration(publication, epoch);
      } finally {
        for (const item of items) zeroize(item.key);
        zeroize(group.key);
      }
    });
  }

  async #changeGroupDeletion(
    id: GroupId,
    expectedRevision: RecordRevision,
    deleted: boolean,
  ): Promise<void> {
    await this.#mutate(async (rootKey, epoch) => {
      const vault = await this.#loadVault(rootKey, epoch);
      const group = await this.#loadGroup(id, vault, rootKey, epoch, !deleted);
      try {
        assertExpectedRevision(expectedRevision, group.expectedRecordRevision);
        const timestamp = this.#timestamp();
        const payload = parseGroupInput({
          ...group.payload,
          ...(deleted ? { deletedAt: timestamp } : { deletedAt: undefined }),
          revision: nextRevision(group.expectedRecordRevision),
          updatedAt: timestamp,
        });
        const record = await encryptGroupRecord(
          payload,
          group.key,
          rootKey,
          vault,
          group.record.wrappedGroupKey,
          deleted ? timestamp : undefined,
        );
        await this.#enqueue(
          [this.#groupMutation(group.expectedRecordRevision, record)],
          epoch,
        );
      } finally {
        zeroize(group.key);
      }
    });
  }

  async #changeItemDeletion(
    groupId: GroupId,
    id: ItemId,
    expectedRevision: RecordRevision,
    deleted: boolean,
  ): Promise<void> {
    await this.#mutate(async (rootKey, epoch) => {
      const vault = await this.#loadVault(rootKey, epoch);
      const group = await this.#loadGroup(groupId, vault, rootKey, epoch, false);
      try {
        const item = await this.#loadItem(id, group, vault, epoch, !deleted);
        try {
          assertExpectedRevision(expectedRevision, item.expectedRecordRevision);
          const timestamp = this.#timestamp();
          const payload = parseItemInput({
            ...item.payload,
            ...(deleted ? { deletedAt: timestamp } : { deletedAt: undefined }),
            revision: nextRevision(item.expectedRecordRevision),
            updatedAt: timestamp,
          });
          const record = await encryptItemRecord(
            payload,
            item.key,
            group.key,
            vault,
            item.record.wrappedItemKey,
            deleted ? timestamp : undefined,
          );
          await this.#enqueue(
            [this.#itemMutation(item.expectedRecordRevision, record)],
            epoch,
          );
        } finally {
          zeroize(item.key);
        }
      } finally {
        zeroize(group.key);
      }
    });
  }

  async #mutate<TResult>(
    operation: (rootKey: VaultRootKey, epoch: number) => Promise<TResult>,
  ): Promise<TResult> {
    const rootKey = this.#rootKey;
    if (rootKey === null) throw new VaultLockedError();
    if (this.#busy) throw new VaultSessionConcurrencyError();
    this.#busy = true;
    const epoch = this.#epoch;
    try {
      const result = await operation(rootKey, epoch);
      this.#assertActive(epoch);
      return result;
    } catch (error) {
      if (this.#epoch !== epoch || this.#rootKey !== rootKey) {
        throw new VaultLockedError();
      }
      throw error;
    } finally {
      this.#busy = false;
    }
  }

  async #loadVault(rootKey: VaultRootKey, epoch: number): Promise<ActiveVault> {
    const candidate = await this.#source.getVault(this.#vaultId);
    this.#assertActive(epoch);
    if (candidate === null) throw new NotFoundError();
    const vault = await authenticateVaultRecord(candidate, this.#vaultId, rootKey);
    this.#assertActive(epoch);
    return vault;
  }

  async #loadGroup(
    id: GroupId,
    vault: ActiveVault,
    rootKey: VaultRootKey,
    epoch: number,
    deleted: boolean,
  ): Promise<OpenGroup> {
    const candidate = await this.#source.getCurrentGroup(this.#vaultId, id);
    this.#assertActive(epoch);
    if (candidate === null) throw new NotFoundError();
    if (candidate.state === 'active') {
      if (deleted || candidate.record.id !== id) throw new SyncConflictError();
      return openGroupRecord(candidate.record, this.#vaultId, vault, rootKey);
    }
    if (!deleted) throw new SyncConflictError();
    const opened = await openDeletedGroupState(
      candidate,
      this.#vaultId,
      vault,
      rootKey,
    );
    if (opened.record.id !== id) throw new CryptoAuthenticationError();
    return opened;
  }

  async #loadItem(
    id: ItemId,
    group: OpenGroup,
    vault: ActiveVault,
    epoch: number,
    deleted: boolean,
  ): Promise<OpenItem> {
    const candidate = await this.#source.getCurrentItem(this.#vaultId, id);
    this.#assertActive(epoch);
    if (candidate === null) throw new NotFoundError();
    if (candidate.state === 'active') {
      if (deleted || candidate.record.id !== id) throw new SyncConflictError();
      return openItemRecord(candidate.record, group, vault);
    }
    if (!deleted) throw new SyncConflictError();
    const opened = await openDeletedItemState(candidate, group, vault);
    if (opened.record.id !== id) throw new CryptoAuthenticationError();
    return opened;
  }

  #groupMutation(
    expectedRecordRevision: RecordRevision | null,
    record: EncryptedGroupRecord,
  ): OpaqueMutation {
    return opaqueMutationSchema.parse({
      entityType: 'group',
      expectedRecordRevision,
      idempotencyKey: this.#dependencies.idempotency.next(),
      record,
    });
  }

  #itemMutation(
    expectedRecordRevision: RecordRevision | null,
    record: EncryptedItemRecord,
  ): OpaqueMutation {
    return opaqueMutationSchema.parse({
      entityType: 'item',
      expectedRecordRevision,
      idempotencyKey: this.#dependencies.idempotency.next(),
      record,
    });
  }

  async #enqueue(mutations: readonly OpaqueMutation[], epoch: number): Promise<void> {
    this.#assertActive(epoch);
    const canonical = Object.freeze(
      mutations.map((mutation) => opaqueMutationSchema.parse(mutation)),
    );
    try {
      await this.#queue.enqueueBatch(canonical);
    } catch (error) {
      if (!(error instanceof OpaqueMutationDurabilityUnknownError)) throw error;
      this.#assertActive(epoch);
      await this.#queue.enqueueBatch(canonical);
    }
    this.#assertActive(epoch);
  }

  async #enqueueTemplateMigration(
    publicationInput: TemplateMigrationPublicationRequest,
    epoch: number,
  ): Promise<void> {
    this.#assertActive(epoch);
    const canonicalJson = JSON.stringify(
      templateMigrationPublicationRequestSchema.parse(publicationInput),
    );
    const enqueueExactCopy = (): Promise<void> =>
      this.#queue.enqueueTemplateMigrationPublication(
        templateMigrationPublicationRequestSchema.parse(
          JSON.parse(canonicalJson) as unknown,
        ),
      );
    try {
      await enqueueExactCopy();
    } catch (error) {
      if (!(error instanceof OpaqueMutationDurabilityUnknownError)) throw error;
      this.#assertActive(epoch);
      await enqueueExactCopy();
    }
    this.#assertActive(epoch);
  }

  #timestamp(): string {
    return timestampSchema.parse(this.#dependencies.clock.now().toISOString());
  }

  #assertActive(epoch: number): void {
    if (this.#rootKey === null || this.#epoch !== epoch) throw new VaultLockedError();
  }

  #assertPayloadVault(vaultId: VaultId): void {
    if (vaultId !== this.#vaultId) {
      throw new ValidationError('The payload belongs to a different vault.');
    }
  }
}

function parseGroupInput(input: unknown): GroupPayload {
  const result = groupPayloadSchema.safeParse(input);
  if (!result.success) throw new ValidationError();
  return result.data;
}

function parseItemInput(input: unknown): ItemPayload {
  const result = itemPayloadSchema.safeParse(input);
  if (!result.success) throw new ValidationError();
  return result.data;
}

function assertRevisionBase(
  input: Pick<
    GroupPayload | ItemPayload,
    'revision' | 'createdAt' | 'updatedAt' | 'deletedAt'
  >,
  current: Pick<
    GroupPayload | ItemPayload,
    'revision' | 'createdAt' | 'updatedAt' | 'deletedAt'
  >,
): void {
  if (
    input.revision !== current.revision ||
    input.createdAt !== current.createdAt ||
    input.updatedAt !== current.updatedAt ||
    input.deletedAt !== current.deletedAt
  ) {
    throw new SyncConflictError();
  }
}

function assertExpectedRevision(
  expected: RecordRevision,
  actual: RecordRevision,
): void {
  if (expected !== actual) throw new SyncConflictError();
}

function nextRevision(revision: RecordRevision): RecordRevision {
  if (revision >= Number.MAX_SAFE_INTEGER) {
    throw new ValidationError('The record revision cannot be incremented safely.');
  }
  return (revision + 1) as RecordRevision;
}

function canonicalTemplate(template: GroupTemplate): string {
  return JSON.stringify(groupTemplateSchema.parse(template));
}

function compareMutationEntityId(left: OpaqueMutation, right: OpaqueMutation): number {
  return left.record.id < right.record.id
    ? -1
    : left.record.id > right.record.id
      ? 1
      : 0;
}
