import { randomBytes } from 'node:crypto';

import {
  VaultMutationService,
  VaultReadSession,
  type OpaqueMutationQueuePort,
  type VaultMutationServiceDependencies,
  type VaultMutationStatePort,
  type VaultReadSourcePort,
} from '@kavrix/client';
import { type VaultRootKey, zeroize } from '@kavrix/crypto';
import {
  auditEventIdSchema,
  groupIdSchema,
  itemIdSchema,
  recordRevisionSchema,
  templateIdSchema,
  templateMigrationIdSchema,
  templateVersionSchema,
  type GroupId,
  type GroupTemplate,
  type ItemId,
  type VaultId,
} from '@kavrix/schemas';

import type {
  CliArchiveEntityRequest,
  CliCreateCredentialRequest,
  CliCreateGroupRequest,
  CliCredentialMutationResult,
  CliGroupMutationResult,
  CliRestoreEntityRequest,
  CliSetFieldRequest,
} from '../mutation-contracts.js';
import { productionClock, randomIdempotencyKeys } from './runtime-adapters.js';

export interface ProductionMutationOptions {
  readonly source: VaultMutationStatePort & VaultReadSourcePort;
  readonly queue: OpaqueMutationQueuePort;
  readonly vaultId: VaultId;
  readonly rootKey: VaultRootKey;
}

const DEFAULT_TIMESTAMP = '1970-01-01T00:00:00.000Z';
const DEFAULT_GROUP_TEMPLATE: GroupTemplate = {
  id: templateIdSchema.parse('template.default000000000000001'),
  name: 'Default',
  version: templateVersionSchema.parse(1),
  fields: [],
  createdAt: DEFAULT_TIMESTAMP,
  updatedAt: DEFAULT_TIMESTAMP,
};

export function createDefaultMutationDependencies(): VaultMutationServiceDependencies {
  return {
    clock: productionClock(),
    groupIds: {
      next: () => groupIdSchema.parse(`group.${randomBytes(12).toString('hex')}`),
    },
    itemIds: {
      next: () => itemIdSchema.parse(`item.${randomBytes(12).toString('hex')}`),
    },
    migrationIds: {
      next: () =>
        templateMigrationIdSchema.parse(`migration.${randomBytes(12).toString('hex')}`),
    },
    auditEventIds: {
      next: () => auditEventIdSchema.parse(`audit.${randomBytes(12).toString('hex')}`),
    },
    idempotency: randomIdempotencyKeys(),
  };
}

export async function executeProductionCreateGroup(
  options: ProductionMutationOptions,
  request: CliCreateGroupRequest,
): Promise<CliGroupMutationResult> {
  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  const groupId = await service.createGroup({
    name: request.name,
    aliases: [],
    tags: [],
    notes: [],
    template: DEFAULT_GROUP_TEMPLATE,
    sortOrder: 0,
    ...(request.description ? { description: request.description } : {}),
  });

  return {
    vaultId: options.vaultId,
    groupId,
    name: request.name,
  };
}

export async function executeProductionCreateCredential(
  options: ProductionMutationOptions,
  request: CliCreateCredentialRequest,
): Promise<CliCredentialMutationResult> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);

  let group: Awaited<ReturnType<typeof readSession.showGroup>>;
  try {
    group = await readSession.showGroup(request.groupQuery);
  } finally {
    readSession.lock();
  }

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  const itemId = await service.createItem(group.id, {
    version: 1,
    title: request.title,
    aliases: [],
    tags: [],
    favorite: false,
    productionSensitive: false,
    relatedItemIds: [],
    attachmentIds: [],
    copySequences: [],
    templateValues: [],
    itemFields: [],
    itemValues: [],
    archivedFieldValues: [],
    notes: [],
  });

  return {
    vaultId: options.vaultId,
    groupId: group.id,
    credentialId: itemId,
    title: request.title,
  };
}

export async function executeProductionSetField(
  options: ProductionMutationOptions,
  request: CliSetFieldRequest,
): Promise<CliCredentialMutationResult> {
  let ownedValue: Uint8Array | undefined;
  try {
    ownedValue = Uint8Array.from(request.value);
    const readSession = new VaultReadSession(options.source, options.vaultId);
    await readSession.unlock(options.rootKey);

    let found: Awaited<ReturnType<typeof readSession.show>>;
    try {
      found = await readSession.show(request.groupQuery, request.credentialQuery);
    } finally {
      readSession.lock();
    }

    const state = await options.source.getCurrentItem(options.vaultId, found.item.id);
    if (state === null || state.state !== 'active') {
      throw new Error('Credential item is not active or found');
    }

    const { fieldDefinitionSchema, fieldIdSchema, secretValueSchema } =
      await import('@kavrix/schemas');
    const fieldId = fieldIdSchema.parse(`field.${randomBytes(12).toString('hex')}`);
    const stringValue = new TextDecoder().decode(ownedValue);

    const existingFields = found.item.itemFields.filter(
      (f) => f.stableKey !== request.fieldKey,
    );
    const existingValues = found.item.itemValues.filter(
      (v) => v.stableKey !== request.fieldKey,
    );

    const timestamp = new Date().toISOString();
    const newFieldDef = fieldDefinitionSchema.parse({
      id: fieldId,
      stableKey: request.fieldKey,
      type: 'secret',
      label: request.fieldKey,
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
      sortOrder: existingFields.length,
      createdAt: timestamp,
      updatedAt: timestamp,
    });

    const newStoredValue = {
      fieldId,
      stableKey: request.fieldKey,
      value: {
        version: 1 as const,
        state: 'present' as const,
        content: {
          cardinality: 'single' as const,
          value: {
            kind: 'secret' as const,
            value: secretValueSchema.parse(stringValue),
          },
        },
      },
      updatedAt: new Date().toISOString(),
    };

    const service = new VaultMutationService(
      options.source,
      options.queue,
      options.vaultId,
      options.rootKey,
      createDefaultMutationDependencies(),
    );

    await service.updateItem(found.group.id, {
      ...found.item,
      itemFields: [...existingFields, newFieldDef],
      itemValues: [...existingValues, newStoredValue],
    });

    return {
      vaultId: options.vaultId,
      groupId: found.group.id,
      credentialId: found.item.id,
      title: found.item.title,
    };
  } finally {
    zeroize(ownedValue);
    zeroize(request.value);
  }
}

export async function executeProductionArchiveEntity(
  options: ProductionMutationOptions,
  request: CliArchiveEntityRequest,
): Promise<void> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  if (request.credentialQuery !== undefined) {
    let found: Awaited<ReturnType<typeof readSession.show>>;
    try {
      found = await readSession.show(request.groupQuery, request.credentialQuery);
    } finally {
      readSession.lock();
    }
    const state = await options.source.getCurrentItem(options.vaultId, found.item.id);
    if (state === null || state.state !== 'active') {
      throw new Error('Credential item is not active or found');
    }
    await service.deleteItem(
      found.group.id,
      found.item.id,
      state.record.recordRevision,
    );
  } else {
    let group: Awaited<ReturnType<typeof readSession.showGroup>>;
    try {
      group = await readSession.showGroup(request.groupQuery);
    } finally {
      readSession.lock();
    }
    const state = await options.source.getCurrentGroup(options.vaultId, group.id);
    if (state === null || state.state !== 'active') {
      throw new Error('Group is not active or found');
    }
    await service.deleteGroup(group.id, state.record.recordRevision);
  }
}

export async function executeProductionRestoreEntity(
  options: ProductionMutationOptions,
  request: CliRestoreEntityRequest,
): Promise<void> {
  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  if (request.credentialQuery !== undefined) {
    const itemId = itemIdSchema.parse(request.credentialQuery);
    const state = await options.source.getCurrentItem(options.vaultId, itemId);
    if (state === null || state.state !== 'deleted') {
      throw new Error('Tombstoned item record not found for restore');
    }
    const groupId = state.predecessor.groupId;
    const revision = recordRevisionSchema.parse(state.tombstone.tombstoneRevision);
    await service.restoreItem(groupId, itemId, revision);
  } else {
    const groupId = groupIdSchema.parse(request.groupQuery);
    const state = await options.source.getCurrentGroup(options.vaultId, groupId);
    if (state === null || state.state !== 'deleted') {
      throw new Error('Tombstoned group record not found for restore');
    }
    const revision = recordRevisionSchema.parse(state.tombstone.tombstoneRevision);
    await service.restoreGroup(groupId, revision);
  }
}
