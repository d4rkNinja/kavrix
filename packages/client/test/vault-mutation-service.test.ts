import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  CryptoAuthenticationError,
  SchemaMigrationError,
  SyncConflictError,
  ValidationError,
  VaultLockedError,
  type ClockPort,
  type IdGeneratorPort,
} from '@kavrix/core';
import {
  cloneSecretKey,
  encryptPayload,
  generateVaultRootKey,
  zeroize,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  activeFieldValueSchema,
  associatedDataSchema,
  auditEventIdSchema,
  contentHashForRecord,
  fieldDefinitionSchema,
  groupIdSchema,
  groupPayloadSchema,
  groupTemplateSchema,
  itemIdSchema,
  itemPayloadSchema,
  noteSchema,
  opaqueMutationSchema,
  recordRevisionSchema,
  schemaVersionSchema,
  sha256DigestSchema,
  templateMigrationIdSchema,
  templateMigrationPublicationRequestSchema,
  tombstoneRecordSchema,
  vaultRecordSchema,
  type AuditEventId,
  type EncryptedItemRecord,
  type FieldDefinition,
  type GroupId,
  type GroupPayload,
  type GroupTemplate,
  type ItemId,
  type ItemPayload,
  type OpaqueMutation,
  type RecordRevision,
  type StoredFieldValue,
  type TemplateMigrationId,
  type TemplateMigrationPublicationRequest,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';

import { VaultSessionConcurrencyError } from '../src/errors.js';
import {
  OpaqueMutationDurabilityUnknownError,
  VaultMutationService,
  type GroupMutationState,
  type ItemMutationState,
  type CreateGroupInput,
  type CreateItemInput,
  type MutationIdempotencyPort,
  type OpaqueMutationQueuePort,
  type VaultMutationServiceDependencies,
  type VaultMutationStatePort,
} from '../src/vault-mutation-service.js';
import {
  VaultReadSession,
  type VaultReadSourcePort,
} from '../src/vault-read-session.js';
import {
  encryptedFixture,
  mutateCiphertext,
  type EncryptedFixture,
} from './fixtures.js';

const initialTime = '2026-08-10T00:00:00.000Z';
const mutationTime = '2026-08-11T00:00:00.000Z';
const secretCanary = 'test-owned-plaintext-canary-value';

class MutationState implements VaultMutationStatePort {
  readonly vault: VaultRecord;
  readonly groups = new Map<GroupId, GroupMutationState>();
  readonly items = new Map<ItemId, ItemMutationState>();
  getVaultGate: Promise<void> | undefined;

  constructor(fixture: EncryptedFixture) {
    this.vault = fixture.vault;
    for (const group of fixture.groups) {
      this.groups.set(group.id, { state: 'active', record: group });
    }
    for (const records of fixture.items.values()) {
      for (const record of records) {
        this.items.set(record.id, {
          state: 'active',
          record: withCorrectCiphertextHash(record),
        });
      }
    }
  }

  async getVault(vaultId: VaultId): Promise<VaultRecord | null> {
    await this.getVaultGate;
    return this.vault.id === vaultId ? this.vault : null;
  }

  getCurrentGroup(
    vaultId: VaultId,
    groupId: GroupId,
  ): Promise<GroupMutationState | null> {
    const state = this.groups.get(groupId);
    const record = state?.state === 'active' ? state.record : state?.predecessor;
    return Promise.resolve(record?.vaultId === vaultId ? required(state) : null);
  }

  getCurrentItem(vaultId: VaultId, itemId: ItemId): Promise<ItemMutationState | null> {
    const state = this.items.get(itemId);
    const record = state?.state === 'active' ? state.record : state?.predecessor;
    return Promise.resolve(record?.vaultId === vaultId ? required(state) : null);
  }

  async *listCurrentItems(
    vaultId: VaultId,
    groupId: GroupId,
  ): AsyncIterable<ItemMutationState> {
    for (const state of this.items.values()) {
      const item = state.state === 'active' ? state.record : state.predecessor;
      if (item.vaultId === vaultId && item.groupId === groupId) {
        yield await Promise.resolve(state);
      }
    }
  }

  apply(batch: readonly OpaqueMutation[]): void {
    for (const mutation of batch) {
      if (mutation.entityType === 'group') {
        const current = this.groups.get(mutation.record.id);
        if (mutation.record.tombstonedAt !== undefined) {
          if (current?.state !== 'active') throw new Error('invalid test deletion');
          this.groups.set(mutation.record.id, {
            state: 'deleted',
            predecessor: current.record,
            tombstone: tombstoneRecordSchema.parse({
              entityType: 'group',
              entityId: current.record.id,
              vaultId: current.record.vaultId,
              state: 'deleted',
              tombstoneRevision: mutation.record.recordRevision,
              lastRecordRevision: current.record.recordRevision,
              lastCiphertextHash: contentHashForRecord(current.record),
              deletedAt: mutation.record.tombstonedAt,
            }) as Extract<
              ReturnType<typeof tombstoneRecordSchema.parse>,
              { entityType: 'group' }
            >,
          });
        } else {
          this.groups.set(mutation.record.id, {
            state: 'active',
            record: mutation.record,
          });
        }
      } else if (mutation.entityType === 'item') {
        const current = this.items.get(mutation.record.id);
        if (mutation.record.tombstonedAt !== undefined) {
          if (current?.state !== 'active') throw new Error('invalid test deletion');
          this.items.set(mutation.record.id, {
            state: 'deleted',
            predecessor: current.record,
            tombstone: tombstoneRecordSchema.parse({
              entityType: 'item',
              entityId: current.record.id,
              vaultId: current.record.vaultId,
              state: 'deleted',
              tombstoneRevision: mutation.record.recordRevision,
              lastRecordRevision: current.record.recordRevision,
              lastCiphertextHash: contentHashForRecord(current.record),
              deletedAt: mutation.record.tombstonedAt,
            }) as Extract<
              ReturnType<typeof tombstoneRecordSchema.parse>,
              { entityType: 'item' }
            >,
          });
        } else {
          this.items.set(mutation.record.id, {
            state: 'active',
            record: mutation.record,
          });
        }
      } else {
        throw new Error('unsupported test mutation entity');
      }
    }
  }
}

class DurableMutationQueue implements OpaqueMutationQueuePort {
  readonly durable = new Map<string, string>();
  readonly batches: OpaqueMutation[][] = [];
  readonly publications: TemplateMigrationPublicationRequest[] = [];
  readonly publicationArguments: string[] = [];
  readonly durablePublications = new Map<string, string>();
  calls = 0;
  failAfterDurableOnce = false;
  failBeforeDurable = false;
  failAfterDurablePublicationOnce = false;
  activePublication: TemplateMigrationPublicationRequest | null = null;

  constructor(private readonly state: MutationState) {}

  async enqueueBatch(batchInput: readonly OpaqueMutation[]): Promise<void> {
    await Promise.resolve();
    this.calls += 1;
    if (this.failBeforeDurable) throw new Error('test queue unavailable');
    if (this.activePublication !== null) {
      throw new Error('atomic publication is pending');
    }
    const batch = batchInput.map((entry) => opaqueMutationSchema.parse(entry));
    const serialized = batch.map((entry) => JSON.stringify(entry));
    const existing = batch.map((entry) => this.durable.get(entry.idempotencyKey));
    if (existing.some((entry) => entry !== undefined)) {
      if (
        existing.some(
          (entry, index) => entry === undefined || entry !== serialized[index],
        )
      ) {
        throw new Error('idempotency collision');
      }
      return;
    }
    this.state.apply(batch);
    for (const [index, entry] of batch.entries()) {
      this.durable.set(entry.idempotencyKey, required(serialized[index]));
    }
    this.batches.push(batch);
    if (this.failAfterDurableOnce) {
      this.failAfterDurableOnce = false;
      throw new OpaqueMutationDurabilityUnknownError();
    }
  }

  async enqueueTemplateMigrationPublication(
    publicationInput: TemplateMigrationPublicationRequest,
  ): Promise<void> {
    await Promise.resolve();
    this.calls += 1;
    this.publicationArguments.push(JSON.stringify(publicationInput));
    if (this.failBeforeDurable) throw new Error('test queue unavailable');
    const publication =
      templateMigrationPublicationRequestSchema.parse(publicationInput);
    const serialized = JSON.stringify(publication);
    const existing = this.durablePublications.get(publication.batchIdempotencyKey);
    if (existing !== undefined) {
      if (existing !== serialized) throw new Error('publication key collision');
      return;
    }
    if (this.batches.length > 0 || this.activePublication !== null) {
      throw new Error('another queue class is pending');
    }
    this.state.apply(publication.mutations);
    this.durablePublications.set(publication.batchIdempotencyKey, serialized);
    this.publications.push(publication);
    this.activePublication = publication;
    if (this.failAfterDurablePublicationOnce) {
      this.failAfterDurablePublicationOnce = false;
      (publicationInput as { batchIdempotencyKey: string }).batchIdempotencyKey =
        'mutated-by-queue-0001';
      throw new OpaqueMutationDurabilityUnknownError();
    }
  }

  completePublication(): void {
    if (this.activePublication === null) {
      throw new Error('no atomic publication is pending');
    }
    this.activePublication = null;
  }
}

class SequenceIds<TId extends string> implements IdGeneratorPort<TId> {
  #index = 0;

  constructor(private readonly values: readonly TId[]) {}

  next(): TId {
    const value = this.values[this.#index];
    if (value === undefined) throw new Error('test ID sequence exhausted');
    this.#index += 1;
    return value;
  }
}

class SequenceIdempotency implements MutationIdempotencyPort {
  #index = 0;

  next(): string {
    this.#index += 1;
    return `idempotency.test.${String(this.#index).padStart(8, '0')}`;
  }
}

class FixedClock implements ClockPort {
  constructor(private readonly timestamp = mutationTime) {}

  now(): Date {
    return new Date(this.timestamp);
  }
}

describe('VaultMutationService', () => {
  it('creates, updates, deletes, and restores complete encrypted group/item payloads', async () => {
    const fixture = await mutationFixture();
    const state = new MutationState(fixture);
    const queue = new DurableMutationQueue(state);
    const service = mutationService(state, queue, fixture.rootKey, fixture.vaultId);
    const templateField = field();

    const groupId = await service.createGroup(
      groupInput(template(1, [templateField]), [note('note.group.1', secretCanary)]),
    );
    const itemId = await service.createItem(
      groupId,
      itemInput(templateField, [note('note.item.1', secretCanary)]),
    );
    let aggregate = await show(state, fixture, groupId, itemId);
    expect(aggregate.group.notes).toHaveLength(1);
    expect(aggregate.item.templateValues[0]?.value).toEqual(
      activeFieldValueSchema.parse({
        version: 1,
        state: 'present',
        content: {
          cardinality: 'single',
          value: { kind: 'secret', value: secretCanary },
        },
      }),
    );
    expect(aggregate.item.itemFields).toHaveLength(1);
    expect(aggregate.item.itemValues).toHaveLength(1);

    await service.updateGroup(
      groupPayloadSchema.parse({
        ...aggregate.group,
        description: 'updated description',
        notes: [...aggregate.group.notes, note('note.group.2', 'second test note')],
      }),
    );
    await service.updateItem(
      groupId,
      itemPayloadSchema.parse({
        ...aggregate.item,
        title: 'Updated item',
        notes: [...aggregate.item.notes, note('note.item.2', 'second item note')],
      }),
    );
    aggregate = await show(state, fixture, groupId, itemId);
    expect(aggregate.group).toMatchObject({ revision: 1, notes: [{}, {}] });
    expect(aggregate.item).toMatchObject({
      revision: 1,
      title: 'Updated item',
      notes: [{}, {}],
    });

    await service.deleteItem(groupId, itemId, aggregate.item.revision);
    const deletedItemState = required(state.items.get(itemId));
    expect(deletedItemState.state).toBe('deleted');
    if (deletedItemState.state !== 'deleted') throw new Error('expected deletion');
    expect(deletedItemState.tombstone.deletedAt).toBe(mutationTime);
    expect(deletedItemState.predecessor.recordRevision).toBe(1);
    expect(deletedItemState.predecessor.tombstonedAt).toBeUndefined();
    const corruptedTombstone = tombstoneRecordSchema.parse({
      ...deletedItemState.tombstone,
      lastCiphertextHash: sha256DigestSchema.parse(
        Buffer.alloc(32, 9).toString('base64url'),
      ),
    });
    if (corruptedTombstone.entityType !== 'item') {
      throw new Error('expected item tombstone');
    }
    state.items.set(itemId, {
      state: 'deleted',
      predecessor: deletedItemState.predecessor,
      tombstone: corruptedTombstone,
    });
    await expect(
      service.restoreItem(groupId, itemId, revision(2)),
    ).rejects.toBeInstanceOf(CryptoAuthenticationError);
    state.items.set(itemId, deletedItemState);
    await service.restoreItem(groupId, itemId, revision(2));
    aggregate = await show(state, fixture, groupId, itemId);
    expect(aggregate.item).toMatchObject({
      revision: 3,
      title: 'Updated item',
      notes: [{}, {}],
    });

    await service.deleteGroup(groupId, aggregate.group.revision);
    const deletedGroupState = required(state.groups.get(groupId));
    expect(deletedGroupState.state).toBe('deleted');
    if (deletedGroupState.state !== 'deleted') throw new Error('expected deletion');
    expect(deletedGroupState.tombstone.deletedAt).toBe(mutationTime);
    expect(deletedGroupState.predecessor.tombstonedAt).toBeUndefined();
    await service.restoreGroup(groupId, revision(2));
    aggregate = await show(state, fixture, groupId, itemId);
    expect(aggregate.group).toMatchObject({
      revision: 3,
      description: 'updated description',
      notes: [{}, {}],
    });

    expect(JSON.stringify(queue.batches)).not.toContain(secretCanary);
    expect(JSON.stringify([...state.items.values()])).not.toContain(secretCanary);
    expect(queue.batches.every((batch) => batch.length > 0)).toBe(true);
  });

  it('uses the core migration policy to require confirmation and preserve remove/restore values', async () => {
    const templateField = field();
    const fixture = await mutationFixture({
      transformGroup: (group) =>
        groupPayloadSchema.parse({
          ...group,
          template: template(1, [templateField]),
        }),
      transformItem: (item) =>
        itemPayloadSchema.parse({
          ...item,
          templateValues: [storedValue(templateField, secretCanary)],
        }),
    });
    const state = new MutationState(fixture);
    const queue = new DurableMutationQueue(state);
    const service = mutationService(state, queue, fixture.rootKey, fixture.vaultId);
    const groupId = required(fixture.groupPayloads[0]).id;
    const itemId = required(fixture.itemPayloads[0]).id;

    await expect(
      service.migrateGroupTemplate(groupId, revision(1), template(2, [])),
    ).rejects.toBeInstanceOf(SchemaMigrationError);
    expect(queue.batches).toHaveLength(0);
    expect(queue.publications).toHaveLength(0);

    await service.migrateGroupTemplate(groupId, revision(1), template(2, []), true);
    let aggregate = await show(state, fixture, groupId, itemId);
    expect(aggregate.item.templateValues).toHaveLength(0);
    expect(aggregate.item.archivedFieldValues).toHaveLength(1);
    expect(JSON.stringify(aggregate.item.archivedFieldValues)).toContain(secretCanary);
    queue.completePublication();

    await service.migrateGroupTemplate(groupId, revision(2), template(3, [field()]));
    aggregate = await show(state, fixture, groupId, itemId);
    expect(aggregate.item.templateValues).toEqual([
      expect.objectContaining({
        fieldId: templateField.id,
        stableKey: templateField.stableKey,
      }),
    ]);
    expect(aggregate.item.archivedFieldValues).toHaveLength(0);
    expect(JSON.stringify(queue.publications)).not.toContain(secretCanary);
    expect(queue.batches).toHaveLength(0);
    expect(queue.publications.map(({ mutations }) => mutations.length)).toEqual([2, 2]);
    for (const publication of queue.publications) {
      expect(publication.mutations.map((mutation) => mutation.entityType)).toEqual([
        'item',
        'group',
      ]);
      expect(publication.batchIdempotencyKey).not.toBe(
        publication.mutations[0]?.idempotencyKey,
      );
    }

    queue.completePublication();
    await service.deleteItem(groupId, itemId, revision(3));
    await expect(
      service.migrateGroupTemplate(groupId, revision(3), template(4, [field()])),
    ).rejects.toThrow('Restore deleted items before migrating');
  });

  it('retries an ambiguous atomic publication enqueue with identical bytes', async () => {
    const fixture = await mutationFixture();
    const state = new MutationState(fixture);
    const queue = new DurableMutationQueue(state);
    queue.failAfterDurablePublicationOnce = true;
    const service = mutationService(state, queue, fixture.rootKey, fixture.vaultId);
    const groupId = required(fixture.groupPayloads[0]).id;

    await service.migrateGroupTemplate(groupId, revision(1), template(2, []));

    expect(queue.calls).toBe(2);
    expect(queue.publications).toHaveLength(1);
    expect(queue.durablePublications).toHaveLength(1);
    expect(queue.batches).toHaveLength(0);
    expect(queue.publicationArguments[1]).toBe(queue.publicationArguments[0]);
  });

  it('sorts atomic item mutations and rejects reused batch idempotency values', async () => {
    const fixture = await mutationFixture({ itemTitles: ['First', 'Second'] });
    const state = new MutationState(fixture);
    const entries = [...state.items.entries()].reverse();
    state.items.clear();
    for (const [id, item] of entries) state.items.set(id, item);
    const queue = new DurableMutationQueue(state);
    const service = mutationService(state, queue, fixture.rootKey, fixture.vaultId);
    const groupId = required(fixture.groupPayloads[0]).id;

    await service.migrateGroupTemplate(groupId, revision(1), template(2, []));
    expect(
      required(queue.publications[0]).mutations.map(({ record }) => record.id),
    ).toEqual(['item.1.1', 'item.1.2', groupId]);

    const collisionFixture = await mutationFixture();
    const collisionState = new MutationState(collisionFixture);
    const collisionQueue = new DurableMutationQueue(collisionState);
    const collisionDependencies = dependencies();
    const collisionService = new VaultMutationService(
      collisionState,
      collisionQueue,
      collisionFixture.vaultId,
      collisionFixture.rootKey,
      {
        ...collisionDependencies,
        idempotency: new SequenceIds<string>([
          'atomic-item-key-0001',
          'atomic-group-key-0001',
          'atomic-item-key-0001',
        ]),
      },
    );
    await expect(
      collisionService.migrateGroupTemplate(
        required(collisionFixture.groupPayloads[0]).id,
        revision(1),
        template(2, []),
      ),
    ).rejects.toThrow('idempotency provider reused');
    expect(collisionQueue.publications).toHaveLength(0);
  });

  it('fails before publication when a migration exceeds the 99-item wire cap', async () => {
    const fixture = await mutationFixture({
      itemTitles: Array.from({ length: 100 }, (_, index) => `Item ${String(index)}`),
    });
    const state = new MutationState(fixture);
    const queue = new DurableMutationQueue(state);
    const service = mutationService(state, queue, fixture.rootKey, fixture.vaultId);

    await expect(
      service.migrateGroupTemplate(
        required(fixture.groupPayloads[0]).id,
        revision(1),
        template(2, []),
      ),
    ).rejects.toThrow('at most 99 active items');
    expect(queue.publications).toHaveLength(0);
    expect(queue.batches).toHaveLength(0);
  });

  it('rejects stale revisions, cross-boundary payloads, bad versions, and tampering', async () => {
    const fixture = await mutationFixture();
    const state = new MutationState(fixture);
    const queue = new DurableMutationQueue(state);
    const service = mutationService(state, queue, fixture.rootKey, fixture.vaultId);
    const group = required(fixture.groupPayloads[0]);
    const item = required(fixture.itemPayloads[0]);

    const wrongRootKey = generateVaultRootKey();
    const wrongKeyQueue = new DurableMutationQueue(state);
    const wrongKeyService = mutationService(
      state,
      wrongKeyQueue,
      wrongRootKey,
      fixture.vaultId,
    );
    zeroize(wrongRootKey);
    await expect(
      wrongKeyService.createGroup(groupInput(template(1, []), [])),
    ).rejects.toBeInstanceOf(CryptoAuthenticationError);
    expect(wrongKeyQueue.batches).toHaveLength(0);

    await expect(
      service.deleteItem(group.id, item.id, revision(0)),
    ).rejects.toBeInstanceOf(SyncConflictError);
    await expect(
      service.updateGroup(
        groupPayloadSchema.parse({ ...group, revision: revision(0) }),
      ),
    ).rejects.toBeInstanceOf(SyncConflictError);
    await expect(
      service.updateItem(group.id, {
        ...item,
        vaultId: 'vault.cross-boundary',
      } as ItemPayload),
    ).rejects.toBeInstanceOf(ValidationError);
    await expect(
      service.updateItem(groupIdSchema.parse('group.wrong-parent'), item),
    ).rejects.toBeInstanceOf(ValidationError);

    const currentState = required(state.items.get(item.id));
    if (currentState.state !== 'active') throw new Error('expected active item');
    const current = currentState.record;
    state.items.set(item.id, { state: 'active', record: mutateCiphertext(current) });
    await expect(
      service.deleteItem(group.id, item.id, revision(1)),
    ).rejects.toBeInstanceOf(CryptoAuthenticationError);
    state.items.set(item.id, {
      state: 'active',
      record: { ...current, schemaVersion: schemaVersionSchema.parse(2) },
    });
    await expect(
      service.deleteItem(group.id, item.id, revision(1)),
    ).rejects.toBeInstanceOf(CryptoAuthenticationError);
    state.items.set(item.id, {
      state: 'active',
      record: {
        ...current,
        groupId: groupIdSchema.parse('group.cross-boundary'),
      },
    });
    await expect(
      service.deleteItem(group.id, item.id, revision(1)),
    ).rejects.toBeInstanceOf(CryptoAuthenticationError);
    expect(queue.batches).toHaveLength(0);
  });

  it('retries an interrupted durable acknowledgement with the identical batch', async () => {
    const fixture = await mutationFixture();
    const state = new MutationState(fixture);
    const queue = new DurableMutationQueue(state);
    queue.failAfterDurableOnce = true;
    const service = mutationService(state, queue, fixture.rootKey, fixture.vaultId);

    await service.updateGroup(
      groupPayloadSchema.parse({
        ...required(fixture.groupPayloads[0]),
        description: 'durably queued',
      }),
    );
    expect(queue.calls).toBe(2);
    expect(queue.batches).toHaveLength(1);
    expect(queue.durable).toHaveLength(1);

    const failedQueue = new DurableMutationQueue(new MutationState(fixture));
    failedQueue.failBeforeDurable = true;
    const failedService = mutationService(
      new MutationState(fixture),
      failedQueue,
      fixture.rootKey,
      fixture.vaultId,
    );
    await expect(
      failedService.updateGroup(required(fixture.groupPayloads[0])),
    ).rejects.toThrow('test queue unavailable');
    expect(failedQueue.calls).toBe(1);
    expect(failedQueue.durable).toHaveLength(0);
  });

  it('owns its root-key copy, rejects concurrency, and prevents publication after lock', async () => {
    const fixture = await mutationFixture();
    const ownedState = new MutationState(fixture);
    const ownedQueue = new DurableMutationQueue(ownedState);
    const supplied = cloneSecretKey(fixture.rootKey);
    const ownedService = mutationService(
      ownedState,
      ownedQueue,
      supplied,
      fixture.vaultId,
    );
    supplied.fill(0);
    await ownedService.updateGroup(required(fixture.groupPayloads[0]));
    ownedService.lock();
    expect(ownedService.locked).toBe(true);
    await expect(
      ownedService.updateGroup(required(fixture.groupPayloads[0])),
    ).rejects.toBeInstanceOf(VaultLockedError);

    const state = new MutationState(fixture);
    let releaseVault: (() => void) | undefined;
    state.getVaultGate = new Promise<void>((resolve) => {
      releaseVault = resolve;
    });
    const queue = new DurableMutationQueue(state);
    const service = mutationService(state, queue, fixture.rootKey, fixture.vaultId);
    const pending = service.updateGroup(required(fixture.groupPayloads[0]));
    await expect(
      service.updateGroup(required(fixture.groupPayloads[0])),
    ).rejects.toBeInstanceOf(VaultSessionConcurrencyError);
    service.lock();
    required(releaseVault)();
    await expect(pending).rejects.toBeInstanceOf(VaultLockedError);
    expect(queue.batches).toHaveLength(0);
  });
});

function mutationService(
  state: MutationState,
  queue: DurableMutationQueue,
  rootKey: VaultRootKey,
  vaultId: VaultId,
): VaultMutationService {
  return new VaultMutationService(state, queue, vaultId, rootKey, dependencies());
}

function dependencies(): VaultMutationServiceDependencies {
  return {
    clock: new FixedClock(),
    groupIds: new SequenceIds([groupIdSchema.parse('group.created')]),
    itemIds: new SequenceIds([itemIdSchema.parse('item.created')]),
    migrationIds: new SequenceIds<TemplateMigrationId>([
      templateMigrationIdSchema.parse('migration.test.1'),
      templateMigrationIdSchema.parse('migration.test.2'),
      templateMigrationIdSchema.parse('migration.test.3'),
      templateMigrationIdSchema.parse('migration.test.4'),
    ]),
    auditEventIds: new SequenceIds<AuditEventId>([
      auditEventIdSchema.parse('audit.test.1'),
      auditEventIdSchema.parse('audit.test.2'),
      auditEventIdSchema.parse('audit.test.3'),
      auditEventIdSchema.parse('audit.test.4'),
    ]),
    idempotency: new SequenceIdempotency(),
  };
}

function groupInput(
  groupTemplate: GroupTemplate,
  notes: GroupPayload['notes'],
): CreateGroupInput {
  return {
    name: 'Created group',
    aliases: ['created'],
    tags: ['test'],
    notes,
    template: groupTemplate,
    sortOrder: 10,
  };
}

function itemInput(
  templateField: FieldDefinition,
  notes: ItemPayload['notes'],
): CreateItemInput {
  const itemField = field({
    id: 'field.item_only',
    stableKey: 'item_only',
    label: 'Item only',
    type: 'custom',
  });
  return {
    version: 1,
    title: 'Created item',
    aliases: ['created-item'],
    templateValues: [storedValue(templateField, secretCanary)],
    itemFields: [itemField],
    itemValues: [storedValue(itemField, 'dynamic value')],
    archivedFieldValues: [],
    notes,
    tags: ['dynamic'],
    favorite: true,
    productionSensitive: true,
    relatedItemIds: [],
    attachmentIds: [],
    copySequences: [],
  };
}

function field(overrides: Record<string, unknown> = {}): FieldDefinition {
  return fieldDefinitionSchema.parse({
    id: 'field.support_pin',
    stableKey: 'support_pin',
    label: 'Support PIN',
    type: 'secret',
    required: false,
    sensitive: true,
    repeatable: false,
    copyable: true,
    searchableLocally: false,
    showInPreview: false,
    copyPolicy: 'allowed',
    revealPolicy: 'timed',
    reauthenticationPolicy: 'after-lock',
    exportPolicy: 'guarded',
    sortOrder: 0,
    createdAt: initialTime,
    updatedAt: initialTime,
    ...overrides,
  });
}

function template(version: number, fields: readonly FieldDefinition[]): GroupTemplate {
  return groupTemplateSchema.parse({
    id: 'template.1',
    name: 'Mutation template',
    version,
    fields,
    createdAt: initialTime,
    updatedAt: version === 1 ? initialTime : mutationTime,
  });
}

function storedValue(definition: FieldDefinition, value: string): StoredFieldValue {
  return {
    fieldId: definition.id,
    stableKey: definition.stableKey,
    value: activeFieldValueSchema.parse({
      version: 1,
      state: 'present',
      content: {
        cardinality: 'single',
        value: {
          kind: definition.sensitive ? 'secret' : 'text',
          value,
        },
      },
    }),
    updatedAt: initialTime,
  };
}

function note(id: string, content: string): ItemPayload['notes'][number] {
  return noteSchema.parse({
    id,
    title: id,
    content,
    isSensitive: true,
    isPinned: false,
    tags: ['test'],
    sortOrder: 0,
    createdAt: initialTime,
    updatedAt: initialTime,
  });
}

async function show(
  state: MutationState,
  fixture: EncryptedFixture,
  groupId: GroupId,
  itemId: ItemId,
): Promise<Readonly<{ group: GroupPayload; item: ItemPayload }>> {
  const session = new VaultReadSession(activeReadSource(state), fixture.vaultId);
  await session.unlock(fixture.rootKey);
  const result = await session.show(groupId, itemId);
  session.lock();
  return result;
}

function activeReadSource(state: MutationState): VaultReadSourcePort {
  return {
    getVault: (vaultId) => state.getVault(vaultId),
    getGroup: async (vaultId, groupId) => {
      const current = await state.getCurrentGroup(vaultId, groupId);
      return current?.state === 'active' ? current.record : null;
    },
    listGroups: async function* (vaultId) {
      for (const current of state.groups.values()) {
        if (current.state === 'active' && current.record.vaultId === vaultId) {
          yield await Promise.resolve(current.record);
        }
      }
    },
    getItem: async (vaultId, itemId) => {
      const current = await state.getCurrentItem(vaultId, itemId);
      return current?.state === 'active' ? current.record : null;
    },
    listItems: async function* (vaultId, groupId) {
      for await (const current of state.listCurrentItems(vaultId, groupId)) {
        if (current.state === 'active') yield current.record;
      }
    },
  };
}

async function mutationFixture(
  options: Parameters<typeof encryptedFixture>[0] = {},
): Promise<EncryptedFixture> {
  const fixture = await encryptedFixture(options);
  const plaintext = Buffer.from(
    JSON.stringify({
      productLabel: 'CredVault',
      executableName: 'creds',
      clipboardClearSeconds: 30,
      revealHideSeconds: 30,
      historyRetentionDays: 365,
      telemetryEnabled: false,
    }),
    'utf8',
  );
  try {
    const encryptedPreferences = await encryptPayload(
      plaintext,
      fixture.rootKey,
      associatedDataSchema.parse({
        version: 1,
        schemaVersion: fixture.vault.schemaVersion,
        keyVersion: fixture.vault.currentKeyVersion,
        vaultId: fixture.vaultId,
        entityType: 'vault-preferences',
        entityId: fixture.vaultId,
        purpose: 'vault-preferences',
      }),
    );
    return {
      ...fixture,
      vault: vaultRecordSchema.parse({
        ...fixture.vault,
        encryptedPreferences,
      }),
    };
  } finally {
    zeroize(plaintext);
  }
}

function withCorrectCiphertextHash(record: EncryptedItemRecord): EncryptedItemRecord {
  return {
    ...record,
    ciphertextHash: sha256DigestSchema.parse(
      createHash('sha256')
        .update(Buffer.from(record.encryptedPayload.ciphertext, 'base64url'))
        .digest('base64url'),
    ),
  };
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('Required test fixture value is missing.');
  return value;
}

function revision(value: number): RecordRevision {
  return recordRevisionSchema.parse(value);
}
