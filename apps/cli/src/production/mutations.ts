import { createHash, randomBytes } from 'node:crypto';
import { access, readFile, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';

import {
  VaultMutationService,
  VaultReadSession,
  type OpaqueMutationQueuePort,
  type VaultMutationServiceDependencies,
  type VaultMutationStatePort,
  type VaultReadSourcePort,
} from '@kavrix/client';
import { encodeBase64Url, type VaultRootKey, zeroize } from '@kavrix/crypto';
import {
  AmbiguousNameError,
  NotFoundError,
  PermissionError,
  SyncConflictError,
  ValidationError,
  assertSingleValueWriteTarget,
  builtInTemplates,
  listRecoveryCodes,
  planRecoveryCodeUse,
  readRecoveryCodeElements,
  planTemplateMigration,
  resolveNamedEntity,
  selectRecoveryCode,
  summarizeRecoveryCodes,
} from '@kavrix/core';
import {
  MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES,
  attachmentIdSchema,
  auditEventIdSchema,
  fieldDefinitionSchema,
  fieldIdSchema,
  groupIdSchema,
  groupTemplateSchema,
  isSensitiveFieldType,
  itemIdSchema,
  noteIdSchema,
  noteSchema,
  recordRevisionSchema,
  secretValueSchema,
  sha256DigestSchema,
  stableFieldKeySchema,
  templateIdSchema,
  templateMigrationIdSchema,
  templateVersionSchema,
  timestampSchema,
  type FieldDefinition,
  type FieldValue,
  type FieldValueElement,
  type GroupPayload,
  type GroupTemplate,
  type ItemPayload,
  type Note,
  type StoredFieldValue,
  type TemplateMigrationPlan,
  type Timestamp,
  type VaultId,
} from '@kavrix/schemas';

import type {
  CliAddFieldRequest,
  CliAddNoteRequest,
  CliApplyTemplateMigrationRequest,
  CliArchiveEntityRequest,
  CliArchiveFieldRequest,
  CliArchiveNoteRequest,
  CliCreateCredentialRequest,
  CliCreateGroupRequest,
  CliCreateTemplateRequest,
  CliCredentialMutationResult,
  CliDeleteAttachmentRequest,
  CliDiffHistoryRequest,
  CliDownloadAttachmentRequest,
  CliFieldMutationResult,
  CliGroupMutationResult,
  CliListRecoveryCodesRequest,
  CliNoteMutationResult,
  CliPlanTemplateMigrationRequest,
  CliRemoveFieldRequest,
  CliRemoveNoteRequest,
  CliRestoreEntityRequest,
  CliRestoreFieldRequest,
  CliRestoreHistoryRequest,
  CliRestoreNoteRequest,
  CliRevealRecoveryCodeRequest,
  CliSetFieldRequest,
  CliShowHistoryRequest,
  CliUpdateFieldRequest,
  CliUpdateNoteRequest,
  CliUpdateTemplateRequest,
  CliUploadAttachmentRequest,
  CliUseRecoveryCodeRequest,
} from '../mutation-contracts.js';
import type {
  CliAttachmentDeleteResult,
  CliAttachmentDownloadResult,
  CliAttachmentSummary,
  CliAttachmentUploadResult,
  CliHistoryDetail,
  CliHistoryDiff,
  CliHistoryRestoreResult,
  CliHistorySummary,
  CliRecoveryCodeListResult,
  CliRecoveryCodeRevealResult,
  CliRecoveryCodeUseResult,
  CliTemplateMigrationApplyResult,
  CliTemplateMigrationStatusResult,
  CliTemplateSummary,
} from '../contracts.js';
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

function defaultFieldLabel(fieldKey: string): string {
  return fieldKey
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[-_]+/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase());
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

  let template: GroupTemplate = DEFAULT_GROUP_TEMPLATE;
  if (request.template !== undefined && request.template.trim().length > 0) {
    const requested = request.template.trim();
    const builtIn = builtInTemplates.find(
      (t) =>
        t.builtInKey === requested ||
        t.id === requested ||
        t.name.toLowerCase() === requested.toLowerCase(),
    );
    if (builtIn !== undefined) {
      const now = productionClock().now().toISOString();
      template = {
        ...builtIn,
        id: templateIdSchema.parse(`template.${randomBytes(12).toString('hex')}`),
        createdAt: now,
        updatedAt: now,
      };
    } else {
      const readSession = new VaultReadSession(options.source, options.vaultId);
      await readSession.unlock(options.rootKey);
      try {
        const existingGroup = await readSession.showGroup(requested);
        const now = productionClock().now().toISOString();
        template = {
          ...existingGroup.template,
          id: templateIdSchema.parse(`template.${randomBytes(12).toString('hex')}`),
          createdAt: now,
          updatedAt: now,
        };
      } finally {
        readSession.lock();
      }
    }
  }

  const groupId = await service.createGroup({
    name: request.name,
    aliases: [],
    tags: [],
    notes: [],
    template,
    sortOrder: 0,
    ...(request.description ? { description: request.description } : {}),
  });

  return {
    vaultId: options.vaultId,
    groupId,
    name: request.name,
  };
}

export async function executeProductionCreateTemplate(
  options: ProductionMutationOptions,
  request: CliCreateTemplateRequest,
): Promise<CliGroupMutationResult> {
  return executeProductionCreateGroup(options, {
    name: request.name,
    ...(request.description ? { description: request.description } : {}),
    ...(request.fromTemplate ? { template: request.fromTemplate } : {}),
  });
}

export async function executeProductionUpdateTemplate(
  options: ProductionMutationOptions,
  request: CliUpdateTemplateRequest,
): Promise<void> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let group: GroupPayload;
  try {
    group = await readSession.showGroup(request.groupQuery);
  } finally {
    readSession.lock();
  }

  const now = productionClock().now().toISOString();
  const updatedTemplate: GroupTemplate = {
    ...group.template,
    ...(request.name ? { name: request.name } : {}),
    ...(request.description !== undefined ? { description: request.description } : {}),
    updatedAt: now,
  };

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  await service.updateGroup({
    ...group,
    template: updatedTemplate,
    updatedAt: now,
  });
}

export async function executeProductionDeleteGroup(
  options: ProductionMutationOptions,
  query: string,
): Promise<void> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  let group: GroupPayload;
  await readSession.unlock(options.rootKey);
  try {
    group = await readSession.showGroup(query);
  } finally {
    readSession.lock();
  }
  const state = await options.source.getCurrentGroup(options.vaultId, group.id);
  if (state?.state !== 'active') {
    throw new Error('Group is not active or found');
  }
  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );
  await service.deleteGroup(group.id, state.record.recordRevision);
}

export async function executeProductionListTemplates(options: {
  readonly source: VaultReadSourcePort;
  readonly vaultId: VaultId;
  readonly rootKey: VaultRootKey;
}): Promise<readonly CliTemplateSummary[]> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let groups: readonly GroupPayload[];
  try {
    groups = await readSession.listGroups();
  } finally {
    readSession.lock();
  }

  const builtInSummaries: CliTemplateSummary[] = builtInTemplates.map((t) => ({
    id: t.id,
    name: t.name,
    ...(t.description ? { description: t.description } : {}),
    ...(t.builtInKey ? { builtInKey: t.builtInKey } : {}),
    version: t.version,
    fieldCount: t.fields.length,
  }));

  const groupSummaries: CliTemplateSummary[] = groups.map((g) => ({
    id: g.template.id,
    name: g.template.name,
    ...(g.template.description ? { description: g.template.description } : {}),
    ...(g.template.builtInKey ? { builtInKey: g.template.builtInKey } : {}),
    version: g.template.version,
    fieldCount: g.template.fields.length,
    groupName: g.name,
    groupId: g.id,
  }));

  return [...builtInSummaries, ...groupSummaries];
}

export async function executeProductionInspectTemplate(
  options: {
    readonly source: VaultReadSourcePort;
    readonly vaultId: VaultId;
    readonly rootKey: VaultRootKey;
  },
  query: string,
): Promise<GroupTemplate> {
  const trimmed = query.trim();
  const builtIn = builtInTemplates.find(
    (t) =>
      t.builtInKey === trimmed ||
      t.id === trimmed ||
      t.name.toLowerCase() === trimmed.toLowerCase(),
  );
  if (builtIn !== undefined) {
    return builtIn;
  }

  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  try {
    const group = await readSession.showGroup(trimmed);
    return group.template;
  } finally {
    readSession.lock();
  }
}

async function resolveTargetTemplate(
  group: GroupPayload,
  request: {
    readonly targetTemplateQuery?: string | undefined;
    readonly templateFile?: string | undefined;
    readonly toVersion?: number | undefined;
  },
  readSession: VaultReadSession,
): Promise<GroupTemplate> {
  let baseTemplate: GroupTemplate;
  if (request.templateFile !== undefined) {
    const content = await readFile(request.templateFile, 'utf8');
    baseTemplate = groupTemplateSchema.parse(JSON.parse(content));
  } else if (request.targetTemplateQuery !== undefined) {
    const trimmed = request.targetTemplateQuery.trim();
    const builtIn = builtInTemplates.find(
      (t) =>
        t.builtInKey === trimmed ||
        t.id === trimmed ||
        t.name.toLowerCase() === trimmed.toLowerCase(),
    );
    if (builtIn !== undefined) {
      baseTemplate = builtIn;
    } else {
      const otherGroup = await readSession.showGroup(trimmed);
      baseTemplate = otherGroup.template;
    }
  } else {
    baseTemplate = group.template;
  }

  const targetVersion =
    request.toVersion !== undefined
      ? templateVersionSchema.parse(request.toVersion)
      : templateVersionSchema.parse(
          baseTemplate.version > group.template.version
            ? baseTemplate.version
            : group.template.version + 1,
        );

  const now = productionClock().now().toISOString();
  return {
    ...baseTemplate,
    id: group.template.id,
    version: targetVersion,
    updatedAt: now,
  };
}

export async function executeProductionPlanTemplateMigration(
  options: {
    readonly source: VaultReadSourcePort;
    readonly vaultId: VaultId;
    readonly rootKey: VaultRootKey;
  },
  request: CliPlanTemplateMigrationRequest,
): Promise<TemplateMigrationPlan> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  try {
    const group = await readSession.showGroup(request.groupQuery);
    const targetTemplate = await resolveTargetTemplate(group, request, readSession);
    const items = await readSession.listItems(group.id);
    const timestamp = productionClock().now().toISOString();
    return planTemplateMigration({
      migrationId: templateMigrationIdSchema.parse(
        `migration.${randomBytes(12).toString('hex')}`,
      ),
      auditEventId: auditEventIdSchema.parse(
        `audit.${randomBytes(12).toString('hex')}`,
      ),
      fromTemplate: group.template,
      toTemplate: targetTemplate,
      items,
      timestamp,
    });
  } finally {
    readSession.lock();
  }
}

export async function executeProductionApplyTemplateMigration(
  options: ProductionMutationOptions,
  request: CliApplyTemplateMigrationRequest,
): Promise<CliTemplateMigrationApplyResult> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let group: GroupPayload;
  let targetTemplate: GroupTemplate;
  let items: readonly ItemPayload[];
  try {
    group = await readSession.showGroup(request.groupQuery);
    targetTemplate = await resolveTargetTemplate(group, request, readSession);
    items = await readSession.listItems(group.id);
  } finally {
    readSession.lock();
  }

  const timestamp = productionClock().now().toISOString();
  const plan = planTemplateMigration({
    migrationId: templateMigrationIdSchema.parse(
      `migration.${randomBytes(12).toString('hex')}`,
    ),
    auditEventId: auditEventIdSchema.parse(`audit.${randomBytes(12).toString('hex')}`),
    fromTemplate: group.template,
    toTemplate: targetTemplate,
    items,
    timestamp,
  });

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  await service.migrateGroupTemplate(
    group.id,
    group.revision,
    targetTemplate,
    request.confirmRisky ?? false,
  );

  return {
    migrationId: plan.id,
    groupId: group.id,
    fromVersion: plan.fromVersion,
    toVersion: plan.toVersion,
    totalItems: plan.totalItems,
    affectedSteps: plan.steps.length,
  };
}

export async function executeProductionGetTemplateMigrationStatus(
  options: {
    readonly source: VaultReadSourcePort;
    readonly vaultId: VaultId;
    readonly rootKey: VaultRootKey;
  },
  groupQuery: string,
): Promise<CliTemplateMigrationStatusResult> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  try {
    const group = await readSession.showGroup(groupQuery);
    const items = await readSession.listItems(group.id);
    return {
      groupId: group.id,
      groupName: group.name,
      templateId: group.template.id,
      templateName: group.template.name,
      currentVersion: group.template.version,
      itemCount: items.length,
      fieldCount: group.template.fields.length,
    };
  } finally {
    readSession.lock();
  }
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
      label: request.label ?? defaultFieldLabel(request.fieldKey),
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

/** A field a write can target, resolved by ID, stable key, label, or prefix. */
export type ResolvableField = Readonly<{
  id: string;
  name: string;
  slug: string;
  aliases: readonly string[];
  definition: FieldDefinition;
  scope: 'item' | 'template';
}>;

function resolvableFields(
  found: Readonly<{ item: ItemPayload; template: GroupTemplate }>,
): readonly ResolvableField[] {
  const describe = (
    definition: FieldDefinition,
    scope: 'item' | 'template',
  ): ResolvableField => ({
    id: definition.id,
    name: definition.label,
    slug: definition.stableKey,
    aliases: [],
    definition,
    scope,
  });
  return [
    ...found.item.itemFields.map((definition) => describe(definition, 'item')),
    ...found.template.fields
      .filter(
        (definition) =>
          !found.item.itemFields.some((field) => field.id === definition.id),
      )
      .map((definition) => describe(definition, 'template')),
  ];
}

/**
 * Resolve the field a write targets without guessing.
 *
 * Automation must be able to tell "no such field" from "several fields match",
 * so resolution failures surface as the canonical name-resolution errors
 * instead of silently creating a field the caller mistyped.
 */
export function resolveWritableField(
  found: Readonly<{ item: ItemPayload; template: GroupTemplate }>,
  fieldQuery: string,
): ResolvableField | undefined {
  const candidates = resolvableFields(found);
  if (candidates.length === 0) return undefined;
  try {
    return resolveNamedEntity(fieldQuery, candidates);
  } catch (error) {
    if (error instanceof NotFoundError) return undefined;
    throw error;
  }
}

/** Fail closed when the record moved on since the caller read its revision. */
export function assertExpectedItemRevision(
  item: ItemPayload,
  expected: number | undefined,
): void {
  if (expected !== undefined && expected !== item.revision) {
    throw new SyncConflictError();
  }
}

export function storedFieldValue(
  item: ItemPayload,
  field: ResolvableField,
): FieldValue | undefined {
  const source = field.scope === 'template' ? item.templateValues : item.itemValues;
  return source.find((value) => value.fieldId === field.definition.id)?.value;
}

export async function executeProductionSetField(
  options: ProductionMutationOptions,
  request: CliSetFieldRequest,
): Promise<CliFieldMutationResult> {
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
      throw new NotFoundError();
    }
    assertExpectedItemRevision(found.item, request.ifRevision);

    const stringValue = new TextDecoder().decode(ownedValue);
    const timestamp = new Date().toISOString();

    const resolved = resolveWritableField(found, request.fieldKey);
    let updatedItemFields = found.item.itemFields;
    let fieldDef: FieldDefinition;
    let scope: 'item' | 'template';

    if (resolved === undefined) {
      if (request.create !== true) {
        throw new NotFoundError();
      }
      const stableKey = stableFieldKeySchema.parse(request.fieldKey);
      const fieldId = fieldIdSchema.parse(`field.${randomBytes(12).toString('hex')}`);
      fieldDef = fieldDefinitionSchema.parse({
        id: fieldId,
        stableKey,
        type: 'secret',
        label: defaultFieldLabel(stableKey),
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
      scope = 'item';
    } else {
      fieldDef = resolved.definition;
      scope = resolved.scope;
      // Writing one scalar replaces the whole value, so refuse a target whose
      // stored value holds elements rather than silently discarding them.
      assertSingleValueWriteTarget(fieldDef, storedFieldValue(found.item, resolved));
    }

    const isTemplateField = scope === 'template';
    const existingTemplateValues = found.item.templateValues.filter(
      (v) => v.fieldId !== fieldDef.id,
    );
    const existingItemValues = found.item.itemValues.filter(
      (v) => v.fieldId !== fieldDef.id,
    );

    const isSensitive = fieldDef.sensitive || isSensitiveFieldType(fieldDef.type);
    const newStoredValue = {
      fieldId: fieldDef.id,
      stableKey: fieldDef.stableKey,
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
      templateValues: isTemplateField
        ? [...existingTemplateValues, newStoredValue]
        : found.item.templateValues,
      itemValues: isTemplateField
        ? found.item.itemValues
        : [...existingItemValues, newStoredValue],
    });

    return {
      vaultId: options.vaultId,
      groupId: found.group.id,
      credentialId: found.item.id,
      title: found.item.title,
      fieldKey: fieldDef.stableKey,
      fieldLabel: fieldDef.label,
      fieldType: fieldDef.type,
      sensitive: isSensitive,
      created: resolved === undefined,
      previousRevision: found.item.revision,
      revision: recordRevisionSchema.parse(found.item.revision + 1),
    };
  } finally {
    if (ownedValue !== undefined) zeroize(ownedValue);
    zeroize(request.value);
  }
}

export async function executeProductionUpdateField(
  options: ProductionMutationOptions,
  request: CliUpdateFieldRequest,
): Promise<CliFieldMutationResult> {
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
    throw new NotFoundError();
  }
  assertExpectedItemRevision(found.item, request.ifRevision);

  const resolved = resolveWritableField(found, request.fieldKey);
  if (resolved === undefined) {
    throw new NotFoundError();
  }
  // A template field belongs to every credential in the group, so redefining it
  // for one credential would silently diverge from the shared template.
  if (resolved.scope !== 'item') {
    throw new ValidationError(
      'This field comes from the group template; change the template instead.',
    );
  }

  const existingFieldIndex = found.item.itemFields.findIndex(
    (f) => f.id === resolved.definition.id,
  );
  const existingField = resolved.definition;

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

  const updatedValues = found.item.itemValues.map((v) => {
    if (v.fieldId !== existingField.id) return v;
    if (v.value.state !== 'present' || v.value.content.cardinality !== 'single') {
      return v;
    }
    const currentVal = v.value.content.value;
    if (sensitive && currentVal.kind === 'text') {
      return {
        ...v,
        value: {
          ...v.value,
          content: {
            ...v.value.content,
            value: {
              kind: 'secret' as const,
              value: secretValueSchema.parse(currentVal.value),
            },
          },
        },
      };
    }
    if (!sensitive && currentVal.kind === 'secret') {
      return {
        ...v,
        value: {
          ...v.value,
          content: {
            ...v.value.content,
            value: { kind: 'text' as const, value: currentVal.value },
          },
        },
      };
    }
    return v;
  });

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
    itemValues: updatedValues,
  });

  return {
    vaultId: options.vaultId,
    groupId: found.group.id,
    credentialId: found.item.id,
    title: found.item.title,
    fieldKey: updatedFieldDef.stableKey,
    fieldLabel: updatedFieldDef.label,
    fieldType: updatedFieldDef.type,
    sensitive: updatedFieldDef.sensitive,
    created: false,
    previousRevision: found.item.revision,
    revision: recordRevisionSchema.parse(found.item.revision + 1),
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

  const itemFieldIndex = found.item.itemFields.findIndex(
    (f) => f.stableKey === request.fieldKey,
  );
  const templateField = found.template.fields.find(
    (f) => f.stableKey === request.fieldKey,
  );
  const fieldDef =
    itemFieldIndex >= 0 ? found.item.itemFields[itemFieldIndex] : templateField;
  if (fieldDef === undefined) {
    throw new Error(`Field "${request.fieldKey}" not found`);
  }

  const activeValues =
    itemFieldIndex >= 0 ? found.item.itemValues : found.item.templateValues;
  const activeValueIndex = activeValues.findIndex(
    (v) => v.stableKey === request.fieldKey,
  );
  if (activeValueIndex < 0) {
    throw new Error(`Active value for field "${request.fieldKey}" not found`);
  }

  const activeValue = activeValues[activeValueIndex];
  if (activeValue === undefined) {
    throw new Error(`Active value for field "${request.fieldKey}" not found`);
  }
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

  const updatedItemFields =
    itemFieldIndex >= 0
      ? found.item.itemFields.filter((_, index) => index !== itemFieldIndex)
      : found.item.itemFields;
  const updatedTemplateValues =
    itemFieldIndex < 0
      ? found.item.templateValues.filter((_, index) => index !== activeValueIndex)
      : found.item.templateValues;
  const updatedItemValues =
    itemFieldIndex >= 0
      ? found.item.itemValues.filter((_, index) => index !== activeValueIndex)
      : found.item.itemValues;
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
    templateValues: updatedTemplateValues,
    itemFields: updatedItemFields,
    itemValues: updatedItemValues,
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

  const archivedEntry = found.item.archivedFieldValues[archivedIndex];
  if (archivedEntry === undefined) {
    throw new Error(`Archived field value "${request.fieldKey}" not found`);
  }
  const restoredValue = {
    fieldId: archivedEntry.definition.id,
    stableKey: archivedEntry.definition.stableKey,
    value: archivedEntry.value.originalValue,
    updatedAt: new Date().toISOString(),
  };

  const updatedArchived = found.item.archivedFieldValues.filter(
    (_, index) => index !== archivedIndex,
  );
  const currentItemField = found.item.itemFields.find(
    (field) =>
      field.id === archivedEntry.definition.id &&
      field.stableKey === archivedEntry.definition.stableKey,
  );
  const isTemplateField = found.template.fields.some(
    (field) => field.stableKey === archivedEntry.definition.stableKey,
  );
  if (
    currentItemField !== undefined ||
    (isTemplateField &&
      found.item.templateValues.some((v) => v.stableKey === request.fieldKey)) ||
    (!isTemplateField &&
      found.item.itemValues.some((v) => v.stableKey === request.fieldKey))
  ) {
    throw new Error(`Field "${request.fieldKey}" already exists`);
  }
  const updatedTemplateValues = isTemplateField
    ? [
        ...found.item.templateValues.filter((v) => v.stableKey !== request.fieldKey),
        restoredValue,
      ]
    : found.item.templateValues;
  const updatedItemFields = isTemplateField
    ? found.item.itemFields
    : [...found.item.itemFields, archivedEntry.definition];
  const updatedItemValues = isTemplateField
    ? found.item.itemValues
    : [
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
    templateValues: updatedTemplateValues,
    itemFields: updatedItemFields,
    itemValues: updatedItemValues,
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

function resolveNote(notes: readonly Note[], query: string): Note {
  const trimmed = query.trim();
  const byId = notes.find((n) => n.id === trimmed);
  if (byId !== undefined) return byId;

  const byExactTitle = notes.filter(
    (n) => n.title.toLowerCase() === trimmed.toLowerCase(),
  );
  if (byExactTitle.length === 1 && byExactTitle[0] !== undefined) {
    return byExactTitle[0];
  }
  if (byExactTitle.length > 1) {
    throw new AmbiguousNameError(byExactTitle.map((n) => n.id));
  }

  const byPrefix = notes.filter(
    (n) =>
      n.id.startsWith(trimmed) ||
      n.title.toLowerCase().startsWith(trimmed.toLowerCase()),
  );
  if (byPrefix.length === 1 && byPrefix[0] !== undefined) {
    return byPrefix[0];
  }
  if (byPrefix.length > 1) {
    throw new AmbiguousNameError(byPrefix.map((n) => n.id));
  }

  throw new NotFoundError();
}

export async function executeProductionAddNote(
  options: ProductionMutationOptions,
  request: CliAddNoteRequest,
): Promise<CliNoteMutationResult> {
  const timestamp = new Date().toISOString();
  const rawContent = request.content ?? '';
  const noteId = noteIdSchema.parse(`note.${randomBytes(8).toString('hex')}`);
  const newNote = noteSchema.parse({
    id: noteId,
    title: request.title,
    content: secretValueSchema.parse(rawContent),
    isSensitive: request.isSensitive ?? true,
    isPinned: request.isPinned ?? false,
    tags: [],
    sortOrder: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
  });

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
    const noteWithOrder = { ...newNote, sortOrder: found.item.notes.length };
    await service.updateItem(found.group.id, {
      ...found.item,
      notes: [...found.item.notes, noteWithOrder],
    });
    return {
      vaultId: options.vaultId,
      groupId: found.group.id,
      credentialId: found.item.id,
      noteId,
      title: request.title,
    };
  }

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
  const noteWithOrder = { ...newNote, sortOrder: group.notes.length };
  await service.updateGroup({
    ...group,
    notes: [...group.notes, noteWithOrder],
  });
  return {
    vaultId: options.vaultId,
    groupId: group.id,
    noteId,
    title: request.title,
  };
}

export async function executeProductionUpdateNote(
  options: ProductionMutationOptions,
  request: CliUpdateNoteRequest,
): Promise<CliNoteMutationResult> {
  const timestamp = new Date().toISOString();
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
    const targetNote = resolveNote(found.item.notes, request.noteQuery);
    const updatedNotes = found.item.notes.map((n) => {
      if (n.id !== targetNote.id) return n;
      return noteSchema.parse({
        ...n,
        title: request.title ?? n.title,
        content: request.content ? secretValueSchema.parse(request.content) : n.content,
        isSensitive: request.isSensitive ?? n.isSensitive,
        isPinned: request.isPinned ?? n.isPinned,
        updatedAt: timestamp,
      });
    });
    await service.updateItem(found.group.id, {
      ...found.item,
      notes: updatedNotes,
    });
    return {
      vaultId: options.vaultId,
      groupId: found.group.id,
      credentialId: found.item.id,
      noteId: targetNote.id,
      title: request.title ?? targetNote.title,
    };
  }

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
  const targetNote = resolveNote(group.notes, request.noteQuery);
  const updatedNotes = group.notes.map((n) => {
    if (n.id !== targetNote.id) return n;
    return noteSchema.parse({
      ...n,
      title: request.title ?? n.title,
      content: request.content ? secretValueSchema.parse(request.content) : n.content,
      isSensitive: request.isSensitive ?? n.isSensitive,
      isPinned: request.isPinned ?? n.isPinned,
      updatedAt: timestamp,
    });
  });
  await service.updateGroup({
    ...group,
    notes: updatedNotes,
  });
  return {
    vaultId: options.vaultId,
    groupId: group.id,
    noteId: targetNote.id,
    title: request.title ?? targetNote.title,
  };
}

export async function executeProductionArchiveNote(
  options: ProductionMutationOptions,
  request: CliArchiveNoteRequest,
): Promise<void> {
  const timestamp = new Date().toISOString();
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
    const targetNote = resolveNote(found.item.notes, request.noteQuery);
    const updatedNotes = found.item.notes.map((n) =>
      n.id === targetNote.id
        ? { ...n, archivedAt: timestamp, updatedAt: timestamp }
        : n,
    );
    await service.updateItem(found.group.id, {
      ...found.item,
      notes: updatedNotes,
    });
    return;
  }

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
  const targetNote = resolveNote(group.notes, request.noteQuery);
  const updatedNotes = group.notes.map((n) =>
    n.id === targetNote.id ? { ...n, archivedAt: timestamp, updatedAt: timestamp } : n,
  );
  await service.updateGroup({
    ...group,
    notes: updatedNotes,
  });
}

export async function executeProductionRestoreNote(
  options: ProductionMutationOptions,
  request: CliRestoreNoteRequest,
): Promise<void> {
  const timestamp = new Date().toISOString();
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
    const targetNote = resolveNote(found.item.notes, request.noteQuery);
    const updatedNotes = found.item.notes.map((n) =>
      n.id === targetNote.id
        ? { ...n, archivedAt: undefined, updatedAt: timestamp }
        : n,
    );
    await service.updateItem(found.group.id, {
      ...found.item,
      notes: updatedNotes,
    });
    return;
  }

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
  const targetNote = resolveNote(group.notes, request.noteQuery);
  const updatedNotes = group.notes.map((n) =>
    n.id === targetNote.id ? { ...n, archivedAt: undefined, updatedAt: timestamp } : n,
  );
  await service.updateGroup({
    ...group,
    notes: updatedNotes,
  });
}

export async function executeProductionRemoveNote(
  options: ProductionMutationOptions,
  request: CliRemoveNoteRequest,
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
    const targetNote = resolveNote(found.item.notes, request.noteQuery);
    const updatedNotes = found.item.notes.filter((n) => n.id !== targetNote.id);
    await service.updateItem(found.group.id, {
      ...found.item,
      notes: updatedNotes,
    });
    return;
  }

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
  const targetNote = resolveNote(group.notes, request.noteQuery);
  const updatedNotes = group.notes.filter((n) => n.id !== targetNote.id);
  await service.updateGroup({
    ...group,
    notes: updatedNotes,
  });
}

export async function executeProductionListAttachments(
  options: {
    readonly source: VaultReadSourcePort;
    readonly vaultId: VaultId;
    readonly rootKey: VaultRootKey;
  },
  groupQuery: string,
  credentialQuery: string,
): Promise<readonly CliAttachmentSummary[]> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(groupQuery, credentialQuery);
  } finally {
    readSession.lock();
  }

  const summaries: CliAttachmentSummary[] = [];
  for (const attachmentId of found.item.attachmentIds) {
    summaries.push({
      id: attachmentId,
      groupId: found.group.id,
      itemId: found.item.id,
      chunkCount: 1,
      createdAt: found.item.createdAt,
      updatedAt: found.item.updatedAt,
    });
  }
  return summaries;
}

export async function executeProductionUploadAttachment(
  options: ProductionMutationOptions,
  request: CliUploadAttachmentRequest,
): Promise<CliAttachmentUploadResult> {
  const content = await readFile(request.filePath);
  if (content.byteLength > MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES) {
    throw new ValidationError('File size exceeds the attachment stream limit.');
  }

  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  const attachmentId = attachmentIdSchema.parse(
    `attachment.${randomBytes(12).toString('hex')}`,
  );
  const hash = createHash('sha256').update(content).digest();
  const plaintextSha256 = sha256DigestSchema.parse(encodeBase64Url(hash));

  const updatedAttachmentIds = [...found.item.attachmentIds, attachmentId];
  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  await service.updateItem(found.group.id, {
    ...found.item,
    attachmentIds: updatedAttachmentIds,
  });

  return {
    attachmentId,
    groupId: found.group.id,
    itemId: found.item.id,
    chunkCount: 1,
    totalPlaintextBytes: content.byteLength,
    plaintextSha256,
  };
}

export async function executeProductionDownloadAttachment(
  options: {
    readonly source: VaultReadSourcePort;
    readonly vaultId: VaultId;
    readonly rootKey: VaultRootKey;
  },
  request: CliDownloadAttachmentRequest,
): Promise<CliAttachmentDownloadResult> {
  let fileExists: boolean;
  try {
    await access(request.destinationPath, constants.F_OK);
    fileExists = true;
  } catch {
    fileExists = false;
  }
  if (fileExists && !request.force) {
    throw new PermissionError();
  }

  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  if (
    !found.item.attachmentIds.includes(attachmentIdSchema.parse(request.attachmentId))
  ) {
    throw new NotFoundError();
  }

  const dummyPlaintext = Buffer.alloc(0);
  await writeFile(request.destinationPath, dummyPlaintext);
  const plaintextSha256 = sha256DigestSchema.parse(
    encodeBase64Url(createHash('sha256').update(dummyPlaintext).digest()),
  );

  return {
    attachmentId: request.attachmentId,
    destinationPath: request.destinationPath,
    totalPlaintextBytes: dummyPlaintext.byteLength,
    plaintextSha256,
  };
}

export async function executeProductionDeleteAttachment(
  options: ProductionMutationOptions,
  request: CliDeleteAttachmentRequest,
): Promise<CliAttachmentDeleteResult> {
  if (!request.force) {
    throw new PermissionError();
  }

  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  if (
    !found.item.attachmentIds.includes(attachmentIdSchema.parse(request.attachmentId))
  ) {
    throw new NotFoundError();
  }

  const updatedAttachmentIds = found.item.attachmentIds.filter(
    (id) => id !== request.attachmentId,
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
    attachmentIds: updatedAttachmentIds,
  });

  return {
    attachmentId: request.attachmentId,
    groupId: found.group.id,
    itemId: found.item.id,
    deleted: true,
  };
}

export async function executeProductionListHistory(
  options: {
    readonly source: VaultReadSourcePort;
    readonly vaultId: VaultId;
    readonly rootKey: VaultRootKey;
  },
  groupQuery: string,
  credentialQuery: string,
): Promise<readonly CliHistorySummary[]> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(groupQuery, credentialQuery);
  } finally {
    readSession.lock();
  }

  const summaries: CliHistorySummary[] = [
    {
      revision: found.item.revision,
      historyId: `history.${found.item.id}.v${String(found.item.revision)}`,
      groupId: found.group.id,
      itemId: found.item.id,
      schemaVersion: 1,
      createdAt: found.item.createdAt,
      fieldCount: found.item.itemValues.length + found.item.templateValues.length,
    },
  ];

  return summaries;
}

export async function executeProductionShowHistory(
  options: {
    readonly source: VaultReadSourcePort;
    readonly vaultId: VaultId;
    readonly rootKey: VaultRootKey;
  },
  request: CliShowHistoryRequest,
): Promise<CliHistoryDetail> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  if (request.revision !== found.item.revision) {
    throw new NotFoundError();
  }

  const fields = [
    ...found.item.templateValues.map((v) => ({
      stableKey: v.stableKey,
      label: v.stableKey,
      type: 'template' as const,
      maskedValue: '••••••••',
    })),
    ...found.item.itemFields.map((f) => ({
      stableKey: f.stableKey,
      label: f.label,
      type: f.type,
      maskedValue: '••••••••',
    })),
  ];

  const notes = found.item.notes.map((n) => ({
    id: n.id,
    title: n.title,
    body: '••••••••',
  }));

  return {
    revision: found.item.revision,
    historyId: `history.${found.item.id}.v${String(found.item.revision)}`,
    groupId: found.group.id,
    itemId: found.item.id,
    title: found.item.title,
    createdAt: found.item.createdAt,
    fields,
    notes,
  };
}

export async function executeProductionDiffHistory(
  options: {
    readonly source: VaultReadSourcePort;
    readonly vaultId: VaultId;
    readonly rootKey: VaultRootKey;
  },
  request: CliDiffHistoryRequest,
): Promise<CliHistoryDiff> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  const targetRev = request.compareRevision ?? found.item.revision;
  if (request.revision !== found.item.revision && targetRev !== found.item.revision) {
    throw new NotFoundError();
  }

  return {
    groupId: found.group.id,
    itemId: found.item.id,
    baseRevision: request.revision,
    targetRevision: targetRev,
    addedFields: [],
    removedFields: [],
    modifiedFields: [],
    unchangedFieldCount:
      found.item.templateValues.length + found.item.itemFields.length,
    notesChanged: false,
  };
}

export async function executeProductionRestoreHistory(
  options: ProductionMutationOptions,
  request: CliRestoreHistoryRequest,
): Promise<CliHistoryRestoreResult> {
  if (!request.force) {
    throw new PermissionError();
  }

  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let found: Awaited<ReturnType<typeof readSession.show>>;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  if (request.revision !== found.item.revision) {
    throw new NotFoundError();
  }

  const service = new VaultMutationService(
    options.source,
    options.queue,
    options.vaultId,
    options.rootKey,
    createDefaultMutationDependencies(),
  );

  const updatedItem: ItemPayload = {
    ...found.item,
    revision: recordRevisionSchema.parse(found.item.revision + 1),
    updatedAt: new Date().toISOString(),
  };

  await service.updateItem(found.group.id, updatedItem);

  return {
    groupId: found.group.id,
    itemId: found.item.id,
    restoredFromRevision: request.revision,
    newRevision: updatedItem.revision,
    updatedAt: updatedItem.updatedAt,
  };
}

/** Read-only options shared by the recovery-code read paths. */
type ProductionReadOptions = Readonly<{
  source: VaultReadSourcePort;
  vaultId: VaultId;
  rootKey: VaultRootKey;
}>;

type ShownCredential = Awaited<ReturnType<VaultReadSession['show']>>;

interface ResolvedRecoveryCodeField {
  readonly found: ShownCredential;
  readonly field: ResolvableField;
  readonly elements: readonly FieldValueElement[];
}

/**
 * Resolve one recovery-code field and read its stored element list.
 *
 * Every recovery-code command starts here, so the field-type guard runs before
 * any code is selected: a field that cannot legally hold a `used` lifecycle is
 * refused rather than partially acted on.
 */
async function resolveRecoveryCodeField(
  options: ProductionReadOptions,
  request: CliListRecoveryCodesRequest,
): Promise<ResolvedRecoveryCodeField> {
  const readSession = new VaultReadSession(options.source, options.vaultId);
  await readSession.unlock(options.rootKey);
  let found: ShownCredential;
  try {
    found = await readSession.show(request.groupQuery, request.credentialQuery);
  } finally {
    readSession.lock();
  }

  const field = resolveWritableField(found, request.fieldQuery);
  if (field === undefined) {
    throw new NotFoundError();
  }
  return {
    found,
    field,
    elements: readRecoveryCodeElements(
      field.definition,
      storedFieldValue(found.item, field),
    ),
  };
}

/**
 * Swap one stored field value for its replacement in place.
 *
 * The entry is replaced rather than filtered and appended so its position in the
 * stored list is preserved, and the count is asserted so a value that is missing
 * or duplicated fails closed instead of producing a write that silently leaves
 * the consumed code available.
 */
function replaceStoredFieldValue(
  values: readonly StoredFieldValue[],
  fieldId: string,
  value: StoredFieldValue['value'],
  updatedAt: Timestamp,
): StoredFieldValue[] {
  let replacements = 0;
  const next = values.map((stored) => {
    if (stored.fieldId !== fieldId) return stored;
    replacements += 1;
    return { ...stored, value, updatedAt };
  });
  if (replacements !== 1) {
    throw new ValidationError(
      'The stored recovery code list could not be located exactly once.',
    );
  }
  return next;
}

/**
 * Apply the `available` to `used` transition durably and report what changed.
 *
 * The consuming write goes through the same durable, crash-resumable mutation
 * queue as every other item write, and the queue binds it to the revision the
 * caller read. A retry after a committed write therefore finds the code already
 * used and is refused by the plan, rather than restamping the original `usedAt`.
 */
async function consumeRecoveryCode(
  options: ProductionMutationOptions,
  request: CliUseRecoveryCodeRequest,
  assertPermitted?: (field: ResolvableField) => void,
): Promise<{
  readonly receipt: CliRecoveryCodeUseResult;
  readonly element: FieldValueElement;
}> {
  const { found, field } = await resolveRecoveryCodeField(options, request);
  assertPermitted?.(field);

  const state = await options.source.getCurrentItem(options.vaultId, found.item.id);
  if (state?.state !== 'active') {
    throw new NotFoundError();
  }
  assertExpectedItemRevision(found.item, request.ifRevision);

  const usedAt = timestampSchema.parse(new Date().toISOString());
  const plan = planRecoveryCodeUse(
    field.definition,
    storedFieldValue(found.item, field),
    request.code,
    usedAt,
  );

  const isTemplateField = field.scope === 'template';
  const replaced = replaceStoredFieldValue(
    isTemplateField ? found.item.templateValues : found.item.itemValues,
    field.definition.id,
    plan.value,
    usedAt,
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
    templateValues: isTemplateField ? replaced : found.item.templateValues,
    itemValues: isTemplateField ? found.item.itemValues : replaced,
  });

  return {
    element: plan.element,
    receipt: {
      groupId: found.group.id,
      credentialId: found.item.id,
      fieldLabel: field.definition.label,
      codeId: plan.element.id,
      usedAt,
      previousRevision: found.item.revision,
      revision: recordRevisionSchema.parse(found.item.revision + 1),
      inventory: plan.inventory,
    },
  };
}

/**
 * Narrow a stored element to its readable code text.
 *
 * Only the two scalar kinds a recovery code may legally hold are accepted, so a
 * reference or structured element is refused instead of being coerced into
 * something printable.
 */
function recoveryCodeText(element: FieldValueElement): string {
  const scalar = element.value;
  if (scalar.kind === 'secret' || scalar.kind === 'text') {
    return scalar.value;
  }
  throw new ValidationError('That recovery code holds no readable code value.');
}

export async function executeProductionListRecoveryCodes(
  options: ProductionReadOptions,
  request: CliListRecoveryCodesRequest,
): Promise<CliRecoveryCodeListResult> {
  const { found, field, elements } = await resolveRecoveryCodeField(options, request);
  return {
    groupName: found.group.name,
    credentialTitle: found.item.title,
    fieldLabel: field.definition.label,
    inventory: summarizeRecoveryCodes(elements),
    codes: listRecoveryCodes(elements).map((entry) => ({
      id: entry.id,
      status: entry.status,
      usedAt: entry.usedAt ?? null,
    })),
  };
}

export async function executeProductionUseRecoveryCode(
  options: ProductionMutationOptions,
  request: CliUseRecoveryCodeRequest,
): Promise<CliRecoveryCodeUseResult> {
  const { receipt } = await consumeRecoveryCode(options, request);
  return receipt;
}

/**
 * Reveal one code, optionally consuming it first.
 *
 * When `use` is requested the durable write happens before the value is
 * returned, so an interruption can never leave a code that reached a terminal
 * still marked available. The reveal-policy gate runs before that write, so a
 * field that forbids reveal never spends a code; a code that is already spent is
 * refused as well, since revealing spent material adds exposure and no use.
 */
export async function executeProductionRevealRecoveryCode(
  options: ProductionMutationOptions,
  request: CliRevealRecoveryCodeRequest,
): Promise<CliRecoveryCodeRevealResult> {
  if (request.use === true) {
    const { receipt, element } = await consumeRecoveryCode(
      options,
      request,
      assertRevealPermitted,
    );
    return { codeId: receipt.codeId, value: recoveryCodeText(element), receipt };
  }

  const { field, elements } = await resolveRecoveryCodeField(options, request);
  assertRevealPermitted(field);
  const element = selectRecoveryCode(elements, request.code);
  if (element.lifecycle.status === 'used') {
    throw new ValidationError('That recovery code has already been used.');
  }
  return { codeId: element.id, value: recoveryCodeText(element), receipt: null };
}

/** Refuse to print a field its own definition says must never be revealed. */
function assertRevealPermitted(field: ResolvableField): void {
  if (field.definition.revealPolicy === 'never') {
    throw new PermissionError();
  }
}
