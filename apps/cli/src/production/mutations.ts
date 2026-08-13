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
  fieldDefinitionSchema,
  fieldIdSchema,
  groupIdSchema,
  isSensitiveFieldType,
  itemIdSchema,
  recordRevisionSchema,
  secretValueSchema,
  templateIdSchema,
  templateMigrationIdSchema,
  templateVersionSchema,
  type GroupTemplate,
  type VaultId,
} from '@kavrix/schemas';

import type {
  CliAddFieldRequest,
  CliArchiveEntityRequest,
  CliArchiveFieldRequest,
  CliCreateCredentialRequest,
  CliCreateGroupRequest,
  CliCredentialMutationResult,
  CliGroupMutationResult,
  CliRemoveFieldRequest,
  CliRestoreEntityRequest,
  CliRestoreFieldRequest,
  CliSetFieldRequest,
  CliUpdateFieldRequest,
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

export async function executeProductionAddField(
  options: ProductionMutationOptions,
  request: CliAddFieldRequest,
): Promise<CliCredentialMutationResult> {
  let ownedValue: Uint8Array | undefined;
  try {
    if (request.value !== undefined) {
      ownedValue = Uint8Array.from(request.value);
    }
    const readSession = new VaultReadSession(options.source, options.vaultId);
    await readSession.unlock(options.rootKey);

    let found: Awaited<ReturnType<typeof readSession.show>>;
    try {
      found = await readSession.show(request.groupQuery, request.credentialQuery);
    } finally {
      readSession.lock();
    }

    const state = await options.source.getCurrentItem(options.vaultId, found.item.id);
    if (state?.state !== 'active') {
      throw new Error('Credential item is not active or found');
    }

    const existingField =
      found.item.itemFields.find((f) => f.stableKey === request.fieldKey) ??
      found.template.fields.find((f) => f.stableKey === request.fieldKey);
    if (existingField !== undefined) {
      throw new Error(`Field key "${request.fieldKey}" already exists`);
    }

    const fieldId = fieldIdSchema.parse(`field.${randomBytes(12).toString('hex')}`);
    const sensitive =
      request.sensitive ??
      (request.fieldType !== undefined
        ? isSensitiveFieldType(request.fieldType)
        : false);
    const type = request.fieldType ?? (sensitive ? 'secret' : 'text');
    const timestamp = new Date().toISOString();

    const newFieldDef = fieldDefinitionSchema.parse({
      id: fieldId,
      stableKey: request.fieldKey,
      type,
      label: request.label ?? request.fieldKey,
      required: false,
      sensitive,
      repeatable: false,
      copyable: true,
      searchableLocally: false,
      showInPreview: false,
      copyPolicy: 'allowed',
      revealPolicy: sensitive ? 'timed' : 'never',
      reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
      exportPolicy: 'guarded',
      sortOrder: found.item.itemFields.length,
      createdAt: timestamp,
      updatedAt: timestamp,
    });

    let newStoredValue: (typeof found.item.itemValues)[number] | undefined;
    if (ownedValue !== undefined) {
      const stringValue = new TextDecoder().decode(ownedValue);
      newStoredValue = {
        fieldId,
        stableKey: request.fieldKey,
        value: {
          version: 1 as const,
          state: 'present' as const,
          content: {
            cardinality: 'single' as const,
            value: sensitive
              ? { kind: 'secret' as const, value: secretValueSchema.parse(stringValue) }
              : { kind: 'text' as const, value: stringValue },
          },
        },
        updatedAt: timestamp,
      };
    }

    const service = new VaultMutationService(
      options.source,
      options.queue,
      options.vaultId,
      options.rootKey,
      createDefaultMutationDependencies(),
    );

    await service.updateItem(found.group.id, {
      ...found.item,
      itemFields: [...found.item.itemFields, newFieldDef],
      itemValues: newStoredValue
        ? [...found.item.itemValues, newStoredValue]
        : found.item.itemValues,
    });

    return {
      vaultId: options.vaultId,
      groupId: found.group.id,
      credentialId: found.item.id,
      title: found.item.title,
    };
  } finally {
    if (ownedValue !== undefined) zeroize(ownedValue);
    if (request.value !== undefined) zeroize(request.value);
  }
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
    if (state?.state !== 'active') {
      throw new Error('Credential item is not active or found');
    }

    const stringValue = new TextDecoder().decode(ownedValue);
    const timestamp = new Date().toISOString();

    let fieldDef =
      found.item.itemFields.find((f) => f.stableKey === request.fieldKey) ??
      found.template.fields.find((f) => f.stableKey === request.fieldKey);

    let updatedItemFields = found.item.itemFields;

    if (fieldDef === undefined) {
      const fieldId = fieldIdSchema.parse(`field.${randomBytes(12).toString('hex')}`);
      fieldDef = fieldDefinitionSchema.parse({
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
        sortOrder: found.item.itemFields.length,
        createdAt: timestamp,
        updatedAt: timestamp,
      });
      updatedItemFields = [...updatedItemFields, fieldDef];
    }

    const existingValues = found.item.itemValues.filter(
      (v) => v.stableKey !== request.fieldKey,
    );

    const isSensitive = fieldDef.sensitive || isSensitiveFieldType(fieldDef.type);
    const newStoredValue = {
      fieldId: fieldDef.id,
      stableKey: request.fieldKey,
      value: {
        version: 1 as const,
        state: 'present' as const,
        content: {
          cardinality: 'single' as const,
          value: isSensitive
            ? { kind: 'secret' as const, value: secretValueSchema.parse(stringValue) }
            : { kind: 'text' as const, value: stringValue },
        },
      },
      updatedAt: timestamp,
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
      itemFields: updatedItemFields,
      itemValues: [...existingValues, newStoredValue],
    });

    return {
      vaultId: options.vaultId,
      groupId: found.group.id,
      credentialId: found.item.id,
      title: found.item.title,
    };
  } finally {
    if (ownedValue !== undefined) zeroize(ownedValue);
    zeroize(request.value);
  }
}

export async function executeProductionUpdateField(
  options: ProductionMutationOptions,
  request: CliUpdateFieldRequest,
): Promise<CliCredentialMutationResult> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);

  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  const state = await options.source.getCurrentItem(options.vaultId, found.item.id);
  if (state?.state !== 'active') {
    throw new Error('Credential item is not active or found');
  }

  const existingFieldIndex = found.item.itemFields.findIndex(
    (f) => f.stableKey === request.fieldKey,
  );
  if (existingFieldIndex < 0) {
    throw new Error(`Item-specific field "${request.fieldKey}" not found`);
  }

  const existingField = found.item.itemFields[existingFieldIndex]!;
  const sensitive =
    request.sensitive ??
    (request.fieldType !== undefined
      ? isSensitiveFieldType(request.fieldType)
      : existingField.sensitive);
  const type = request.fieldType ?? existingField.type;

  const updatedFieldDef = fieldDefinitionSchema.parse({
    ...existingField,
    label: request.label ?? existingField.label,
    type,
    sensitive,
    revealPolicy: sensitive ? 'timed' : 'never',
    reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
    updatedAt: new Date().toISOString(),
  });

  const updatedFields = [...found.item.itemFields];
  updatedFields[existingFieldIndex] = updatedFieldDef;

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  await service.updateItem(found.group.id, {
    ...found.item,
    itemFields: updatedFields,
  });

  return {
    vaultId: options.vaultId,
    groupId: found.group.id,
    credentialId: found.item.id,
    title: found.item.title,
  };
}

export async function executeProductionArchiveField(
  options: ProductionMutationOptions,
  request: CliArchiveFieldRequest,
): Promise<void> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);

  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  const state = await options.source.getCurrentItem(options.vaultId, found.item.id);
  if (state?.state !== 'active') {
    throw new Error('Credential item is not active or found');
  }

  const fieldDef =
    found.item.itemFields.find((f) => f.stableKey === request.fieldKey) ??
    found.template.fields.find((f) => f.stableKey === request.fieldKey);
  if (fieldDef === undefined) {
    throw new Error(`Field "${request.fieldKey}" not found`);
  }

  const activeValueIndex = found.item.itemValues.findIndex(
    (v) => v.stableKey === request.fieldKey,
  );
  if (activeValueIndex < 0) {
    throw new Error(`Active value for field "${request.fieldKey}" not found`);
  }

  const activeValue = found.item.itemValues[activeValueIndex]!;
  const archivedEntry = {
    definition: fieldDef,
    value: {
      version: 1 as const,
      state: 'orphaned' as const,
      originalValue: activeValue.value,
    },
    sourceTemplateId: found.item.templateId,
    sourceTemplateVersion: found.item.templateVersion,
    archivedAt: new Date().toISOString(),
    reason: 'user-archived' as const,
  };

  const updatedValues = found.item.itemValues.filter(
    (_, index) => index !== activeValueIndex,
  );
  const updatedArchived = [...found.item.archivedFieldValues, archivedEntry];

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  await service.updateItem(found.group.id, {
    ...found.item,
    itemValues: updatedValues,
    archivedFieldValues: updatedArchived,
  });
}

export async function executeProductionRestoreField(
  options: ProductionMutationOptions,
  request: CliRestoreFieldRequest,
): Promise<void> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);

  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  const state = await options.source.getCurrentItem(options.vaultId, found.item.id);
  if (state?.state !== 'active') {
    throw new Error('Credential item is not active or found');
  }

  const archivedIndex = found.item.archivedFieldValues.findIndex(
    (a) => a.definition.stableKey === request.fieldKey,
  );
  if (archivedIndex < 0) {
    throw new Error(`Archived field value "${request.fieldKey}" not found`);
  }

  const archivedEntry = found.item.archivedFieldValues[archivedIndex]!;
  const restoredValue = {
    fieldId: archivedEntry.definition.id,
    stableKey: archivedEntry.definition.stableKey,
    value: archivedEntry.value.originalValue,
    updatedAt: new Date().toISOString(),
  };

  const updatedArchived = found.item.archivedFieldValues.filter(
    (_, index) => index !== archivedIndex,
  );
  const updatedValues = [
    ...found.item.itemValues.filter((v) => v.stableKey !== request.fieldKey),
    restoredValue,
  ];

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  await service.updateItem(found.group.id, {
    ...found.item,
    itemValues: updatedValues,
    archivedFieldValues: updatedArchived,
  });
}

export async function executeProductionRemoveField(
  options: ProductionMutationOptions,
  request: CliRemoveFieldRequest,
): Promise<void> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);

  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  const state = await options.source.getCurrentItem(options.vaultId, found.item.id);
  if (state?.state !== 'active') {
    throw new Error('Credential item is not active or found');
  }

  const itemFieldIndex = found.item.itemFields.findIndex(
    (f) => f.stableKey === request.fieldKey,
  );
  if (itemFieldIndex < 0) {
    throw new Error(
      `Item-specific field "${request.fieldKey}" not found or is a template field`,
    );
  }

  const updatedItemFields = found.item.itemFields.filter(
    (_, index) => index !== itemFieldIndex,
  );
  const updatedItemValues = found.item.itemValues.filter(
    (v) => v.stableKey !== request.fieldKey,
  );
  const updatedArchivedValues = found.item.archivedFieldValues.filter(
    (a) => a.definition.stableKey !== request.fieldKey,
  );

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  await service.updateItem(found.group.id, {
    ...found.item,
    itemFields: updatedItemFields,
    itemValues: updatedItemValues,
    archivedFieldValues: updatedArchivedValues,
  });
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
    if (state?.state !== 'active') {
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
    if (state?.state !== 'active') {
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
    if (state?.state !== 'deleted') {
      throw new Error('Tombstoned item record not found for restore');
    }
    const groupId = state.predecessor.groupId;
    const revision = recordRevisionSchema.parse(state.tombstone.tombstoneRevision);
    await service.restoreItem(groupId, itemId, revision);
  } else {
    const groupId = groupIdSchema.parse(request.groupQuery);
    const state = await options.source.getCurrentGroup(options.vaultId, groupId);
    if (state?.state !== 'deleted') {
      throw new Error('Tombstoned group record not found for restore');
    }
    const revision = recordRevisionSchema.parse(state.tombstone.tombstoneRevision);
    await service.restoreGroup(groupId, revision);
  }
}
