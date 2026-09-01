import { randomUUID } from 'node:crypto';

import {
  encryptedTextSchema,
  fieldDefinitionSchema,
  fieldExpectsMultipleValues,
  fieldIdSchema,
  isSensitiveFieldType,
  fieldTypeSchema,
  fieldValueElementIdSchema,
  fieldValueMatchesDefinition,
  fieldValueSchema,
  groupIdSchema,
  groupTemplateSchema,
  itemIdSchema,
  itemPayloadSchema,
  projectContextIdSchema,
  projectContextPayloadSchema,
  recordRevisionSchema,
  secretValueSchema,
  stableFieldKeySchema,
  structuredGroupPayloadSchema,
  structuredVaultPayloadSchema,
  templateIdSchema,
  templateVersionSchema,
  timestampSchema,
  type ActiveFieldValue,
  type FieldDefinition,
  type FieldScalarValue,
  type FieldType,
  type FieldValue,
  type GroupTemplate,
  type ItemPayload,
  type ProjectContextPayload,
  type StructuredGroupPayload,
  type StructuredVaultPayload,
} from '@kavrix/schemas';
import type { Command } from 'commander';

import {
  DatabaseFlatCommandError,
  readDatabaseFlatSecrets,
  withDatabaseFlatVault,
  type DatabaseFlatCommandOptions,
} from './database-flat-commands.js';
import { enforceRevealPolicy } from './execution/reveal-policy.js';
import { LocalCliError } from './cli-error.js';
import {
  DEFAULT_PROJECT_CONTEXT_ID,
  DEFAULT_SERVICE_ID,
  DEFAULT_VALUE_FIELD_ID,
  DEFAULT_VALUE_FIELD_KEY,
  DEFAULT_VALUE_FIELD_LABEL,
} from './structured-vault-projection.js';

/** Default projection names used by the legacy flat commands. */
export {
  DEFAULT_PROJECT_CONTEXT_NAME,
  DEFAULT_SERVICE_NAME,
} from './structured-vault-projection.js';

const REDACTED = '[REDACTED]';
const MISSING = '[MISSING]';
const EMPTY = '[EMPTY]';
const MAX_POLICY_REFERENCE_CHARS = 256;
const ESCAPE_CHARACTER = String.fromCodePoint(0x1b);
const BELL_CHARACTER = String.fromCodePoint(0x07);
const OSC_SEQUENCE_PATTERN = new RegExp(
  `${ESCAPE_CHARACTER}\\][^${BELL_CHARACTER}]*(?:${BELL_CHARACTER}|${ESCAPE_CHARACTER}\\\\)`,
  'gu',
);
const CSI_SEQUENCE_PATTERN = new RegExp(
  `${ESCAPE_CHARACTER}\\[[0-?]*[ -/]*[@-~]`,
  'gu',
);

/**
 * A structured command failure is intentionally a local CLI error. It is
 * mapped by the existing top-level error handling and never carries a value
 * read from the protected input flow.
 */
export class StructuredVaultCommandError extends LocalCliError {
  public constructor(message: string) {
    super(message);
    this.name = 'StructuredVaultCommandError';
  }
}

export type StructuredFieldSetInput = Readonly<{
  name: string;
  type: string;
  rawValue: string;
  sensitive?: boolean;
  publicValue?: boolean;
  now?: string;
}>;

export type StructuredCommandResult = Readonly<Record<string, unknown>>;

export type StructuredRoutingInput = Readonly<{
  datastore?: string;
  dataFile?: string;
  database?: string;
  collection?: string;
  keyFile?: string;
}>;

/**
 * Add the structured command family to a Commander program. The command
 * aliases deliberately share one command object, so `service`/`group`,
 * `item`/`credential`, and `context`/`environment` cannot drift.
 */
export function registerStructuredVaultCommands(program: Command): void {
  registerContextCommands(program);
  registerServiceCommands(program);
  registerItemCommands(program);
  registerFieldCommands(program);
}

/** Pure creation/mutation helpers are exported for deterministic tests and migration code. */
export function createProjectContext(
  payload: StructuredVaultPayload,
  name: string,
  environment?: string,
  now = timestampNow(),
): StructuredVaultPayload {
  const normalizedName = parseEntityName(name, 'Project context');
  const context = projectContextPayloadSchemaParse({
    id: projectContextIdSchema.parse(randomUUID()),
    name: normalizedName,
    ...(environment === undefined
      ? {}
      : { environment: parseOptionalEnvironment(environment) }),
    revision: recordRevisionSchema.parse(0),
    createdAt: parseTimestamp(now),
    updatedAt: parseTimestamp(now),
  });
  if (payload.projectContexts.some((entry) => entry.name === context.name)) {
    throw new StructuredVaultCommandError('Project context already exists.');
  }
  return parseStructuredPayload({
    ...payload,
    projectContexts: [...payload.projectContexts, context],
  });
}

export function renameProjectContext(
  payload: StructuredVaultPayload,
  currentName: string,
  nextName: string,
  now = timestampNow(),
): StructuredVaultPayload {
  const context = resolveProjectContext(payload, currentName);
  if (context.id === DEFAULT_PROJECT_CONTEXT_ID) {
    throw new StructuredVaultCommandError(
      'The default project context is reserved for flat-command compatibility.',
    );
  }
  const normalizedName = parseEntityName(nextName, 'Project context');
  if (
    payload.projectContexts.some(
      (entry) => entry.id !== context.id && entry.name === normalizedName,
    )
  ) {
    throw new StructuredVaultCommandError('Project context already exists.');
  }
  return parseStructuredPayload({
    ...payload,
    projectContexts: payload.projectContexts.map((entry) =>
      entry.id === context.id
        ? {
            ...entry,
            name: normalizedName,
            revision: incrementRevision(entry.revision),
            updatedAt: parseTimestamp(now),
          }
        : entry,
    ),
  });
}

export function removeProjectContext(
  payload: StructuredVaultPayload,
  name: string,
): StructuredVaultPayload {
  const context = resolveProjectContext(payload, name);
  if (context.id === DEFAULT_PROJECT_CONTEXT_ID) {
    throw new StructuredVaultCommandError(
      'The default project context is reserved for flat-command compatibility.',
    );
  }
  if (payload.groups.some((group) => group.projectContextId === context.id)) {
    throw new StructuredVaultCommandError(
      'Project context is not empty; remove its services first.',
    );
  }
  return parseStructuredPayload({
    ...payload,
    projectContexts: payload.projectContexts.filter((entry) => entry.id !== context.id),
  });
}

export function createStructuredService(
  payload: StructuredVaultPayload,
  contextName: string,
  name: string,
  now = timestampNow(),
): StructuredVaultPayload {
  const context = resolveProjectContext(payload, contextName);
  const normalizedName = parseEntityName(name, 'Service');
  if (
    payload.groups.some(
      (group) => group.projectContextId === context.id && group.name === normalizedName,
    )
  ) {
    throw new StructuredVaultCommandError('Service already exists in this context.');
  }
  const template = createMinimalTemplate(now);
  const group = structuredGroupPayloadSchema.parse({
    id: groupIdSchema.parse(randomUUID()),
    vaultId: payload.vaultId,
    projectContextId: context.id,
    name: normalizedName,
    aliases: [],
    tags: [],
    notes: [],
    template,
    sortOrder: payload.groups.length,
    revision: recordRevisionSchema.parse(0),
    createdAt: parseTimestamp(now),
    updatedAt: parseTimestamp(now),
  });
  return parseStructuredPayload({
    ...payload,
    groups: [...payload.groups, group],
  });
}

export function renameStructuredService(
  payload: StructuredVaultPayload,
  contextName: string,
  currentName: string,
  nextName: string,
  now = timestampNow(),
): StructuredVaultPayload {
  const context = resolveProjectContext(payload, contextName);
  const group = resolveService(payload, context.id, currentName);
  if (group.id === DEFAULT_SERVICE_ID) {
    throw new StructuredVaultCommandError(
      'The default service is reserved for flat-command compatibility.',
    );
  }
  const normalizedName = parseEntityName(nextName, 'Service');
  if (
    payload.groups.some(
      (entry) =>
        entry.id !== group.id &&
        entry.projectContextId === context.id &&
        entry.name === normalizedName,
    )
  ) {
    throw new StructuredVaultCommandError('Service already exists in this context.');
  }
  return parseStructuredPayload({
    ...payload,
    groups: payload.groups.map((entry) =>
      entry.id === group.id
        ? {
            ...entry,
            name: normalizedName,
            revision: incrementRevision(entry.revision),
            updatedAt: parseTimestamp(now),
          }
        : entry,
    ),
  });
}

export function removeStructuredService(
  payload: StructuredVaultPayload,
  contextName: string,
  name: string,
): StructuredVaultPayload {
  const context = resolveProjectContext(payload, contextName);
  const group = resolveService(payload, context.id, name);
  if (group.id === DEFAULT_SERVICE_ID) {
    throw new StructuredVaultCommandError(
      'The default service is reserved for flat-command compatibility.',
    );
  }
  if (payload.items.some((item) => item.groupId === group.id)) {
    throw new StructuredVaultCommandError(
      'Service is not empty; remove its credential items first.',
    );
  }
  return parseStructuredPayload({
    ...payload,
    groups: payload.groups.filter((entry) => entry.id !== group.id),
  });
}

export function createStructuredItem(
  payload: StructuredVaultPayload,
  contextName: string,
  serviceName: string,
  title: string,
  now = timestampNow(),
): StructuredVaultPayload {
  const context = resolveProjectContext(payload, contextName);
  const group = resolveService(payload, context.id, serviceName);
  const normalizedTitle = parseEntityName(title, 'Credential item');
  const createdAt = parseTimestamp(now);
  const compatibilityField =
    group.id === DEFAULT_SERVICE_ID
      ? createCompatibilityValueField(createdAt)
      : undefined;
  if (
    payload.items.some(
      (item) =>
        item.groupId === group.id &&
        item.deletedAt === undefined &&
        item.title === normalizedTitle,
    )
  ) {
    throw new StructuredVaultCommandError(
      'Credential item already exists in this service.',
    );
  }
  const item = itemPayloadSchema.parse({
    version: 1,
    id: itemIdSchema.parse(randomUUID()),
    vaultId: payload.vaultId,
    groupId: group.id,
    templateId: group.template.id,
    title: normalizedTitle,
    aliases: [],
    templateVersion: group.template.version,
    templateValues: [],
    itemFields: compatibilityField === undefined ? [] : [compatibilityField],
    itemValues:
      compatibilityField === undefined
        ? []
        : [
            {
              fieldId: compatibilityField.id,
              stableKey: compatibilityField.stableKey,
              value: { version: 1, state: 'empty' },
              updatedAt: createdAt,
            },
          ],
    archivedFieldValues: [],
    notes: [],
    tags: [],
    favorite: false,
    productionSensitive: compatibilityField !== undefined,
    relatedItemIds: [],
    attachmentIds: [],
    copySequences: [],
    revision: recordRevisionSchema.parse(0),
    createdAt,
    updatedAt: createdAt,
  });
  return parseStructuredPayload({
    ...payload,
    items: [...payload.items, item],
  });
}

export function renameStructuredItem(
  payload: StructuredVaultPayload,
  contextName: string,
  serviceName: string,
  currentTitle: string,
  nextTitle: string,
  now = timestampNow(),
): StructuredVaultPayload {
  const context = resolveProjectContext(payload, contextName);
  const group = resolveService(payload, context.id, serviceName);
  const item = resolveItem(payload, group.id, currentTitle);
  const normalizedTitle = parseEntityName(nextTitle, 'Credential item');
  if (
    payload.items.some(
      (entry) =>
        entry.id !== item.id &&
        entry.groupId === group.id &&
        entry.deletedAt === undefined &&
        entry.title === normalizedTitle,
    )
  ) {
    throw new StructuredVaultCommandError(
      'Credential item already exists in this service.',
    );
  }
  return parseStructuredPayload({
    ...payload,
    items: payload.items.map((entry) =>
      entry.id === item.id
        ? {
            ...entry,
            title: normalizedTitle,
            revision: incrementRevision(entry.revision),
            updatedAt: parseTimestamp(now),
          }
        : entry,
    ),
  });
}

/** Remove an item and its encrypted attachment/history records as one aggregate mutation. */
export function removeStructuredItem(
  payload: StructuredVaultPayload,
  contextName: string,
  serviceName: string,
  title: string,
  now = timestampNow(),
): StructuredVaultPayload {
  const context = resolveProjectContext(payload, contextName);
  const group = resolveService(payload, context.id, serviceName);
  const item = resolveItem(payload, group.id, title);
  return parseStructuredPayload({
    ...payload,
    items: payload.items
      .filter((entry) => entry.id !== item.id)
      .map((entry) => {
        if (!entry.relatedItemIds.includes(item.id)) return entry;
        return {
          ...entry,
          relatedItemIds: entry.relatedItemIds.filter((id) => id !== item.id),
          revision: incrementRevision(entry.revision),
          updatedAt: parseTimestamp(now),
        };
      }),
    attachments: payload.attachments.filter((record) => record.itemId !== item.id),
    history: payload.history.filter((record) => record.itemId !== item.id),
  });
}

/**
 * Set a typed field from a value that has already crossed the protected input
 * boundary. This function never logs or returns the raw value in diagnostics.
 */
export function setStructuredField(
  payload: StructuredVaultPayload,
  contextName: string,
  serviceName: string,
  itemTitle: string,
  input: StructuredFieldSetInput,
): StructuredVaultPayload {
  if (input.sensitive === true && input.publicValue === true) {
    throw new StructuredVaultCommandError(
      'A field cannot be both sensitive and public.',
    );
  }
  const context = resolveProjectContext(payload, contextName);
  const group = resolveService(payload, context.id, serviceName);
  const item = resolveItem(payload, group.id, itemTitle);
  const type = parseFieldType(input.type);
  const now = parseTimestamp(input.now ?? timestampNow());
  const existing = resolveFieldOptional(item, input.name, group.template);
  const templateField =
    existing === undefined
      ? undefined
      : group.template.fields.some((field) => field.id === existing.id);
  const definition =
    existing === undefined
      ? createFieldDefinition(
          input.name,
          type,
          input.sensitive,
          input.publicValue,
          item.itemFields.length,
          now,
        )
      : templateField === true
        ? validateExistingDefinition(existing, type, input.sensitive, input.publicValue)
        : updateExistingDefinition(
            existing,
            type,
            input.sensitive,
            input.publicValue,
            now,
          );
  const value = parseFieldValue(definition, input.rawValue, now);
  const nextItem = itemPayloadSchema.parse({
    ...item,
    itemFields:
      existing === undefined
        ? [...item.itemFields, definition]
        : templateField === true
          ? item.itemFields
          : item.itemFields.map((entry) =>
              entry.id === definition.id ? definition : entry,
            ),
    templateValues:
      templateField === true
        ? [
            ...item.templateValues.filter((entry) => entry.fieldId !== definition.id),
            {
              fieldId: definition.id,
              stableKey: definition.stableKey,
              value,
              updatedAt: now,
            },
          ]
        : item.templateValues,
    itemValues: [
      ...(templateField === true
        ? item.itemValues
        : [
            ...item.itemValues.filter((entry) => entry.fieldId !== definition.id),
            {
              fieldId: definition.id,
              stableKey: definition.stableKey,
              value,
              updatedAt: now,
            },
          ]),
    ],
    revision: incrementRevision(item.revision),
    updatedAt: now,
  });
  return parseStructuredPayload({
    ...payload,
    items: payload.items.map((entry) => (entry.id === item.id ? nextItem : entry)),
  });
}

export function removeStructuredField(
  payload: StructuredVaultPayload,
  contextName: string,
  serviceName: string,
  itemTitle: string,
  fieldName: string,
  now = timestampNow(),
): StructuredVaultPayload {
  const context = resolveProjectContext(payload, contextName);
  const group = resolveService(payload, context.id, serviceName);
  const item = resolveItem(payload, group.id, itemTitle);
  const field = resolveField(item, fieldName, group.template);
  if (group.id === DEFAULT_SERVICE_ID && field.id === DEFAULT_VALUE_FIELD_ID) {
    throw new StructuredVaultCommandError(
      'The default value field is reserved for flat-command compatibility.',
    );
  }
  if (group.template.fields.some((entry) => entry.id === field.id)) {
    throw new StructuredVaultCommandError(
      'Template fields are managed by the service template and cannot be removed from one item.',
    );
  }
  // Preserve a removed definition/value as an archived value. The command
  // only removes it from the active field projection; encrypted history is
  // still retained inside the item aggregate.
  const stored = item.itemValues.find((entry) => entry.fieldId === field.id);
  const originalValue: FieldValue = stored?.value ?? {
    version: 1,
    state: 'missing',
  };
  const archived = {
    definition: field,
    value: { version: 1 as const, state: 'orphaned' as const, originalValue },
    sourceTemplateId: item.templateId,
    sourceTemplateVersion: item.templateVersion,
    archivedAt: parseTimestamp(now),
    reason: 'user-archived' as const,
  };
  const nextItem = itemPayloadSchema.parse({
    ...item,
    itemFields: item.itemFields.filter((entry) => entry.id !== field.id),
    itemValues: item.itemValues.filter((entry) => entry.fieldId !== field.id),
    archivedFieldValues: [...item.archivedFieldValues, archived],
    revision: incrementRevision(item.revision),
    updatedAt: parseTimestamp(now),
  });
  return parseStructuredPayload({
    ...payload,
    items: payload.items.map((entry) => (entry.id === item.id ? nextItem : entry)),
  });
}

export function resolveProjectContext(
  payload: StructuredVaultPayload,
  name: string,
): ProjectContextPayload {
  const normalized = parseEntityName(name, 'Project context');
  const matches = payload.projectContexts.filter((entry) => entry.name === normalized);
  if (matches.length !== 1) {
    throw new StructuredVaultCommandError(
      matches.length === 0
        ? 'Project context was not found.'
        : 'Project context name is ambiguous.',
    );
  }
  const match = matches[0];
  if (match === undefined)
    throw new StructuredVaultCommandError('Project context was not found.');
  return match;
}

export function resolveService(
  payload: StructuredVaultPayload,
  projectContextId: string,
  name: string,
): StructuredGroupPayload {
  const normalized = parseEntityName(name, 'Service');
  const matches = payload.groups.filter(
    (entry) => entry.projectContextId === projectContextId && entry.name === normalized,
  );
  if (matches.length !== 1) {
    throw new StructuredVaultCommandError(
      matches.length === 0 ? 'Service was not found.' : 'Service name is ambiguous.',
    );
  }
  const match = matches[0];
  if (match === undefined)
    throw new StructuredVaultCommandError('Service was not found.');
  return match;
}

export function resolveItem(
  payload: StructuredVaultPayload,
  groupId: string,
  title: string,
): ItemPayload {
  const normalized = parseEntityName(title, 'Credential item');
  const matches = payload.items.filter(
    (entry) =>
      entry.groupId === groupId &&
      entry.deletedAt === undefined &&
      entry.title === normalized,
  );
  if (matches.length !== 1) {
    throw new StructuredVaultCommandError(
      matches.length === 0
        ? 'Credential item was not found.'
        : 'Credential item name is ambiguous.',
    );
  }
  const match = matches[0];
  if (match === undefined)
    throw new StructuredVaultCommandError('Credential item was not found.');
  return match;
}

export function projectStructuredField(
  item: ItemPayload,
  fieldName: string,
  template?: GroupTemplate,
): Readonly<{
  definition: FieldDefinition;
  value: ActiveFieldValue | undefined;
}> {
  const definition = resolveField(item, fieldName, template);
  const templateField =
    template?.fields.some((field) => field.id === definition.id) === true;
  return {
    definition,
    value: (templateField ? item.templateValues : item.itemValues).find(
      (entry) => entry.fieldId === definition.id,
    )?.value,
  };
}

/** Return only the safe default display token for a field read. */
export function redactStructuredFieldValue(
  item: ItemPayload,
  fieldName: string,
  template?: GroupTemplate,
): string {
  const { value } = projectStructuredField(item, fieldName, template);
  return value?.state === 'present' ? REDACTED : fieldState(value);
}

/** Render public fields, while keeping every present sensitive field redacted. */
export function displayStructuredFieldValue(
  item: ItemPayload,
  fieldName: string,
  template?: GroupTemplate,
): string {
  const { definition, value } = projectStructuredField(item, fieldName, template);
  if (value?.state !== 'present') return fieldState(value);
  return definition.sensitive ? REDACTED : renderFieldValue(value);
}

/** Exact transport for an already-authorized multiline field value. */
export function encodeStructuredFieldValueBase64(value: ActiveFieldValue): string {
  if (value.state !== 'present') {
    throw new StructuredVaultCommandError('Field has no readable value.');
  }
  return Buffer.from(renderFieldValue(value), 'utf8').toString('base64');
}

/** Enforce the field-level reveal gate before any outer authorization check. */
export function assertStructuredFieldRevealAllowed(definition: FieldDefinition): void {
  if (definition.revealPolicy === 'never') {
    throw new StructuredVaultCommandError(
      'Field reveal is disabled by its schema policy.',
    );
  }
}

/** Map structured-command routing flags to the same profile override contract as root commands. */
export function structuredRoutingOverrides(
  input: StructuredRoutingInput,
): NonNullable<DatabaseFlatCommandOptions['routingOverrides']> {
  const datastore = input.datastore;
  if (datastore !== undefined && datastore !== 'mongodb' && datastore !== 'file') {
    throw new StructuredVaultCommandError('--datastore must be mongodb or file.');
  }
  return {
    ...(datastore === undefined ? {} : { datastore }),
    ...(input.dataFile === undefined ? {} : { dataFile: input.dataFile }),
    ...(input.database === undefined ? {} : { database: input.database }),
    ...(input.collection === undefined ? {} : { vaultCollection: input.collection }),
    ...(input.keyFile === undefined ? {} : { keyFile: input.keyFile }),
  };
}

function resolveField(
  item: ItemPayload,
  name: string,
  template?: GroupTemplate,
): FieldDefinition {
  const normalized = parseEntityName(name, 'Field');
  const matches = [...(template?.fields ?? []), ...item.itemFields].filter(
    (field) => field.stableKey === normalized || field.label === normalized,
  );
  if (matches.length !== 1) {
    throw new StructuredVaultCommandError(
      matches.length === 0 ? 'Field was not found.' : 'Field name is ambiguous.',
    );
  }
  const match = matches[0];
  if (match === undefined)
    throw new StructuredVaultCommandError('Field was not found.');
  return match;
}

function resolveFieldOptional(
  item: ItemPayload,
  name: string,
  template?: GroupTemplate,
): FieldDefinition | undefined {
  const normalized = parseEntityName(name, 'Field');
  const matches = [...(template?.fields ?? []), ...item.itemFields].filter(
    (field) => field.stableKey === normalized || field.label === normalized,
  );
  if (matches.length > 1)
    throw new StructuredVaultCommandError('Field name is ambiguous.');
  return matches[0];
}

function createMinimalTemplate(now: string): GroupTemplate {
  return groupTemplateSchema.parse({
    id: templateIdSchema.parse(randomUUID()),
    name: 'Custom service template',
    builtInKey: 'custom',
    version: templateVersionSchema.parse(1),
    fields: [],
    createdAt: parseTimestamp(now),
    updatedAt: parseTimestamp(now),
  });
}

function createCompatibilityValueField(now: string): FieldDefinition {
  return fieldDefinitionSchema.parse({
    id: DEFAULT_VALUE_FIELD_ID,
    stableKey: DEFAULT_VALUE_FIELD_KEY,
    label: DEFAULT_VALUE_FIELD_LABEL,
    type: 'password',
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
    createdAt: now,
    updatedAt: now,
  });
}

function createFieldDefinition(
  name: string,
  type: FieldType,
  sensitiveOverride: boolean | undefined,
  publicOverride: boolean | undefined,
  sortOrder: number,
  now: string,
): FieldDefinition {
  const label = parseEntityName(name, 'Field');
  const inherentSensitive = type === 'environment-map' || isSensitiveFieldType(type);
  if (publicOverride === true && isSensitiveFieldType(type)) {
    throw new StructuredVaultCommandError('Sensitive field types cannot be public.');
  }
  const sensitive =
    publicOverride === true ? false : sensitiveOverride === true || inherentSensitive;
  const stableKey = makeStableFieldKey(label);
  return fieldDefinitionSchema.parse({
    id: fieldIdSchema.parse(randomUUID()),
    stableKey,
    label,
    type,
    required: false,
    sensitive,
    repeatable: fieldExpectsMultipleValues({
      type,
      repeatable: false,
    } as FieldDefinition),
    copyable: true,
    searchableLocally: !sensitive,
    showInPreview: !sensitive,
    copyPolicy: sensitive ? 'confirm' : 'allowed',
    revealPolicy: sensitive ? 'timed' : 'never',
    reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
    exportPolicy: sensitive ? 'guarded' : 'encrypted-only',
    sortOrder,
    createdAt: parseTimestamp(now),
    updatedAt: parseTimestamp(now),
  });
}

function updateExistingDefinition(
  existing: FieldDefinition,
  type: FieldType,
  sensitiveOverride: boolean | undefined,
  publicOverride: boolean | undefined,
  now: string,
): FieldDefinition {
  if (existing.type !== type) {
    throw new StructuredVaultCommandError(
      'Field type cannot change in place; remove the field before recreating it.',
    );
  }
  if (sensitiveOverride !== undefined || publicOverride !== undefined) {
    const expectedSensitive =
      publicOverride === true
        ? false
        : sensitiveOverride === true || existing.sensitive;
    if (expectedSensitive !== existing.sensitive) {
      throw new StructuredVaultCommandError(
        'Field sensitivity cannot change in place; remove the field before recreating it.',
      );
    }
  }
  return fieldDefinitionSchema.parse({
    ...existing,
    updatedAt: parseTimestamp(now),
  });
}

function validateExistingDefinition(
  existing: FieldDefinition,
  type: FieldType,
  sensitiveOverride: boolean | undefined,
  publicOverride: boolean | undefined,
): FieldDefinition {
  if (existing.type !== type) {
    throw new StructuredVaultCommandError(
      'Field type cannot change in place; update the service template instead.',
    );
  }
  if (sensitiveOverride !== undefined || publicOverride !== undefined) {
    const expectedSensitive =
      publicOverride === true
        ? false
        : sensitiveOverride === true || existing.sensitive;
    if (expectedSensitive !== existing.sensitive) {
      throw new StructuredVaultCommandError(
        'Template field sensitivity is controlled by its service template.',
      );
    }
  }
  return existing;
}

function parseFieldValue(
  definition: FieldDefinition,
  rawValue: string,
  now: string,
): FieldValue {
  const scalarValues = parseScalarValues(definition, rawValue);
  const content = fieldExpectsMultipleValues(definition)
    ? {
        cardinality: 'multiple' as const,
        elements: scalarValues.map((value) => ({
          id: fieldValueElementIdSchema.parse(randomUUID()),
          value,
          lifecycle: { version: 1 as const, status: 'available' as const },
        })),
      }
    : {
        cardinality: 'single' as const,
        value: scalarValues[0],
      };
  if (content.cardinality === 'single' && content.value === undefined) {
    throw new StructuredVaultCommandError('Field value is empty.');
  }
  const parsed = fieldValueSchema.parse({
    version: 1,
    state: 'present',
    content,
  });
  if (!fieldValueMatchesDefinition(definition, parsed)) {
    throw new StructuredVaultCommandError('Field value does not match its field type.');
  }
  // Keep the timestamp argument part of the call contract so all callers
  // construct values through one path; the value schema intentionally has no
  // timestamp of its own.
  void now;
  return parsed;
}

function parseScalarValues(
  definition: FieldDefinition,
  rawValue: string,
): FieldScalarValue[] {
  if (rawValue.length === 0)
    throw new StructuredVaultCommandError('Field value is empty.');
  if (definition.type === 'attachment' || definition.type === 'item-reference') {
    throw new StructuredVaultCommandError(
      'Reference fields must be linked through their dedicated encrypted records.',
    );
  }
  if (definition.type === 'select' || definition.type === 'multi-select') {
    if (definition.selectOptions === undefined) {
      throw new StructuredVaultCommandError(
        'Select fields require configured options.',
      );
    }
  }
  if (definition.type === 'environment-map') {
    const lines = rawValue.split(/\r?\n/u);
    const values = lines.map((line) => {
      const separator = line.indexOf('=');
      if (separator <= 0) {
        throw new StructuredVaultCommandError(
          'Environment-map values must use KEY=VALUE entries.',
        );
      }
      const key = line.slice(0, separator);
      const value = line.slice(separator + 1);
      if (key.trim() !== key || key.length === 0 || value.length === 0) {
        throw new StructuredVaultCommandError(
          'Environment-map entries must contain non-empty keys and values.',
        );
      }
      if (definition.sensitive) {
        return {
          kind: 'environment-entry' as const,
          key,
          value: {
            classification: 'secret' as const,
            value: secretValueSchema.parse(value),
          },
        };
      }
      return {
        kind: 'environment-entry' as const,
        key,
        value: {
          classification: 'text' as const,
          value: encryptedTextSchema.parse(value),
        },
      };
    });
    return values;
  }
  const multiple = fieldExpectsMultipleValues(definition);
  const rawValues = multiple ? rawValue.split(/\r?\n/u) : [rawValue];
  if (rawValues.some((value) => value.length === 0)) {
    throw new StructuredVaultCommandError(
      'Collection field values cannot contain empty entries.',
    );
  }
  return rawValues.map((value) => parseScalarValue(definition, value));
}

function parseScalarValue(
  definition: FieldDefinition,
  rawValue: string,
): FieldScalarValue {
  if (definition.type === 'number' || definition.type === 'port') {
    const value = Number(rawValue);
    if (!Number.isFinite(value))
      throw new StructuredVaultCommandError('Numeric field value is invalid.');
    return { kind: 'number', value };
  }
  if (definition.type === 'boolean') {
    if (rawValue !== 'true' && rawValue !== 'false') {
      throw new StructuredVaultCommandError(
        'Boolean field values must be true or false.',
      );
    }
    return { kind: 'boolean', value: rawValue === 'true' };
  }
  if (definition.sensitive) {
    return { kind: 'secret', value: secretValueSchema.parse(rawValue) };
  }
  return { kind: 'text', value: encryptedTextSchema.parse(rawValue) };
}

function parseFieldType(value: string): FieldType {
  const aliases: Readonly<Record<string, string>> = {
    'totp-seed': 'totp-secret',
    'recovery-code': 'recovery-code-list',
    environment: 'environment-map',
    api_key: 'api-key',
  };
  const canonical = aliases[value] ?? value;
  const parsed = fieldTypeSchema.safeParse(canonical);
  if (!parsed.success) throw new StructuredVaultCommandError('Unsupported field type.');
  return parsed.data;
}

function makeStableFieldKey(label: string): string {
  const parsed = stableFieldKeySchema.safeParse(label);
  if (parsed.success) return parsed.data;
  return `field-${randomUUID()}`;
}

function containsC0Control(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x1f || codePoint === 0x7f) return true;
  }
  return false;
}

function parseEntityName(value: string, label: string): string {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 256 ||
    containsC0Control(normalized)
  ) {
    throw new StructuredVaultCommandError(`${label} name is invalid.`);
  }
  return normalized;
}

function parseOptionalEnvironment(value: string): string {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 128 ||
    containsC0Control(normalized)
  ) {
    throw new StructuredVaultCommandError('Environment name is invalid.');
  }
  return normalized;
}

function projectContextPayloadSchemaParse(value: unknown): ProjectContextPayload {
  return projectContextPayloadSchema.parse(value);
}

function parseStructuredPayload(value: unknown): StructuredVaultPayload {
  return structuredVaultPayloadSchema.parse(value);
}

function parseTimestamp(value: string): string {
  return timestampSchema.parse(value);
}

function timestampNow(): string {
  return timestampSchema.parse(new Date().toISOString());
}

function incrementRevision(value: number): number {
  return recordRevisionSchema.parse(value + 1);
}

function addDatabaseOptions(command: Command): Command {
  return command
    .option('--vault <id>', 'Opaque database vault identifier.', 'default')
    .option('--profile <id>', 'Database profile identifier.')
    .option('--profile-config-dir <path>', 'Protected profile configuration directory.')
    .option('--datastore <type>', 'Datastore routing override.')
    .option('--data-file <path>', 'Encrypted file datastore path.')
    .option('--database <name>', 'MongoDB database name.')
    .option('--collection <name>', 'MongoDB vault collection name.')
    .option('--key-file <path>', 'Protected portable key-file path.')
    .option('--database-url-stdin', 'Read the MongoDB URL from protected stdin.')
    .option('--passphrase-stdin', 'Read the key-file passphrase from protected stdin.')
    .option(
      '--allow-insecure-transport',
      'Allow explicitly requested insecure MongoDB transport.',
    );
}

function commandOptions(command: Command): DatabaseFlatCommandOptions {
  const options = command.opts<Record<string, unknown>>();
  const vault = options['vault'];
  if (typeof vault !== 'string')
    throw new StructuredVaultCommandError('A vault is required.');
  const vaultSource = command.getOptionValueSource('vault');
  const profile = stringOption(options, 'profile');
  const profileConfigDir = stringOption(options, 'profileConfigDir');
  const datastore = stringOption(options, 'datastore');
  const dataFile = stringOption(options, 'dataFile');
  const database = stringOption(options, 'database');
  const collection = stringOption(options, 'collection');
  const keyFile = stringOption(options, 'keyFile');
  return {
    vault,
    ...(vaultSource === undefined || vaultSource === 'default'
      ? { vaultWasDefaulted: true }
      : {}),
    ...(profile === undefined ? {} : { profile }),
    ...(profileConfigDir === undefined ? {} : { profileConfigDir }),
    ...(datastore === undefined ? {} : { datastore }),
    ...(dataFile === undefined ? {} : { dataFile }),
    ...(database === undefined ? {} : { database }),
    ...(collection === undefined ? {} : { collection }),
    ...(keyFile === undefined ? {} : { keyFile }),
    routingOverrides: structuredRoutingOverrides({
      ...(datastore === undefined ? {} : { datastore }),
      ...(dataFile === undefined ? {} : { dataFile }),
      ...(database === undefined ? {} : { database }),
      ...(collection === undefined ? {} : { collection }),
      ...(keyFile === undefined ? {} : { keyFile }),
    }),
    ...(options['databaseUrlStdin'] === true ? { databaseUrlStdin: true } : {}),
    ...(options['passphraseStdin'] === true ? { passphraseStdin: true } : {}),
    ...(options['valueStdin'] === true ? { valueStdin: true } : {}),
    ...(options['valueStdinBase64'] === true ? { valueStdinBase64: true } : {}),
    ...(options['allowInsecureTransport'] === true
      ? { allowInsecureTransport: true }
      : {}),
  };
}

function stringOption(
  options: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = options[key];
  return typeof value === 'string' ? value : undefined;
}

function registerContextCommands(program: Command): void {
  const context = program
    .command('context')
    .alias('environment')
    .description('Manage project contexts/environments in a database vault.');
  const create = context
    .command('create <name>')
    .description('Create a project context.');
  addDatabaseOptions(create)
    .option('--environment <name>', 'Optional deployment environment label.')
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (name: string, options: Record<string, unknown>, command: Command) => {
        const flat = commandOptions(command);
        const values = await readDatabaseFlatSecrets(flat, []);
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            createProjectContext(payload, name, stringOption(options, 'environment')),
          );
          writeJsonResult({
            created: true,
            type: 'context',
            name: sanitizeText(name),
            revision: updated.revision,
          });
        });
      },
    );
  const list = context.command('list').description('List project contexts.');
  addDatabaseOptions(list)
    .option('--json', 'Emit machine-readable output.')
    .action(async (_options: Record<string, unknown>, command: Command) => {
      const flat = commandOptions(command);
      const values = await readDatabaseFlatSecrets(flat, []);
      await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
        let result: StructuredCommandResult = {};
        const document = await session.inspectStructuredVault(vaultId, (payload) => {
          result = {
            contexts: payload.projectContexts.map((entry) => ({
              name: sanitizeText(entry.name),
              ...(entry.environment === undefined
                ? {}
                : { environment: sanitizeText(entry.environment) }),
            })),
          };
        });
        writeJsonResult({ ...result, revision: document.revision });
      });
    });
  const rename = context
    .command('rename <from> <to>')
    .description('Rename a project context.');
  addDatabaseOptions(rename)
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (
        from: string,
        to: string,
        _options: Record<string, unknown>,
        command: Command,
      ) => {
        const flat = commandOptions(command);
        const values = await readDatabaseFlatSecrets(flat, []);
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            renameProjectContext(payload, from, to),
          );
          writeJsonResult({
            renamed: true,
            type: 'context',
            from: sanitizeText(from),
            to: sanitizeText(to),
            revision: updated.revision,
          });
        });
      },
    );
  const remove = context
    .command('remove <name>')
    .description('Remove an empty project context.');
  addDatabaseOptions(remove)
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (name: string, _options: Record<string, unknown>, command: Command) => {
        const flat = commandOptions(command);
        const values = await readDatabaseFlatSecrets(flat, []);
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            removeProjectContext(payload, name),
          );
          writeJsonResult({
            removed: true,
            type: 'context',
            name: sanitizeText(name),
            revision: updated.revision,
          });
        });
      },
    );
}

function registerServiceCommands(program: Command): void {
  const service = program
    .command('service')
    .alias('group')
    .description('Manage services/groups inside a project context.');
  const create = service
    .command('create <name>')
    .description('Create a service/group.');
  addDatabaseOptions(create)
    .requiredOption('--context <name>', 'Project context name.')
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (name: string, options: Record<string, unknown>, command: Command) => {
        const flat = commandOptions(command);
        const contextName = requiredOption(options, 'context');
        const values = await readDatabaseFlatSecrets(flat, []);
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            createStructuredService(payload, contextName, name),
          );
          writeJsonResult({
            created: true,
            type: 'service',
            context: sanitizeText(contextName),
            name: sanitizeText(name),
            revision: updated.revision,
          });
        });
      },
    );
  const list = service
    .command('list')
    .description('List services/groups in a project context.');
  addDatabaseOptions(list)
    .requiredOption('--context <name>', 'Project context name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (options: Record<string, unknown>, command: Command) => {
      const flat = commandOptions(command);
      const contextName = requiredOption(options, 'context');
      const values = await readDatabaseFlatSecrets(flat, []);
      await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
        let result: StructuredCommandResult = {};
        const document = await session.inspectStructuredVault(vaultId, (payload) => {
          const context = resolveProjectContext(payload, contextName);
          result = {
            context: sanitizeText(context.name),
            services: payload.groups
              .filter((entry) => entry.projectContextId === context.id)
              .map((entry) => sanitizeText(entry.name)),
          };
        });
        writeJsonResult({ ...result, revision: document.revision });
      });
    });
  const rename = service
    .command('rename <from> <to>')
    .description('Rename a service/group.');
  addDatabaseOptions(rename)
    .requiredOption('--context <name>', 'Project context name.')
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (
        from: string,
        to: string,
        options: Record<string, unknown>,
        command: Command,
      ) => {
        const flat = commandOptions(command);
        const contextName = requiredOption(options, 'context');
        const values = await readDatabaseFlatSecrets(flat, []);
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            renameStructuredService(payload, contextName, from, to),
          );
          writeJsonResult({
            renamed: true,
            type: 'service',
            context: sanitizeText(contextName),
            from: sanitizeText(from),
            to: sanitizeText(to),
            revision: updated.revision,
          });
        });
      },
    );
  const remove = service
    .command('remove <name>')
    .description('Remove an empty service/group.');
  addDatabaseOptions(remove)
    .requiredOption('--context <name>', 'Project context name.')
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (name: string, options: Record<string, unknown>, command: Command) => {
        const flat = commandOptions(command);
        const contextName = requiredOption(options, 'context');
        const values = await readDatabaseFlatSecrets(flat, []);
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            removeStructuredService(payload, contextName, name),
          );
          writeJsonResult({
            removed: true,
            type: 'service',
            context: sanitizeText(contextName),
            name: sanitizeText(name),
            revision: updated.revision,
          });
        });
      },
    );
}

function registerItemCommands(program: Command): void {
  const item = program
    .command('item')
    .alias('credential')
    .description('Manage credential items inside a service/group.');
  const create = item
    .command('create <title>')
    .description('Create a credential item.');
  addDatabaseOptions(create)
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (title: string, options: Record<string, unknown>, command: Command) => {
        const flat = commandOptions(command);
        const contextName = requiredOption(options, 'context');
        const serviceName = requiredOption(options, 'service');
        const values = await readDatabaseFlatSecrets(flat, []);
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            createStructuredItem(payload, contextName, serviceName, title),
          );
          writeJsonResult({
            created: true,
            type: 'item',
            context: sanitizeText(contextName),
            service: sanitizeText(serviceName),
            title: sanitizeText(title),
            revision: updated.revision,
          });
        });
      },
    );
  const list = item
    .command('list')
    .description('List credential items in a service/group.');
  addDatabaseOptions(list)
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(async (options: Record<string, unknown>, command: Command) => {
      const flat = commandOptions(command);
      const contextName = requiredOption(options, 'context');
      const serviceName = requiredOption(options, 'service');
      const values = await readDatabaseFlatSecrets(flat, []);
      await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
        let result: StructuredCommandResult = {};
        const document = await session.inspectStructuredVault(vaultId, (payload) => {
          const context = resolveProjectContext(payload, contextName);
          const group = resolveService(payload, context.id, serviceName);
          result = {
            context: sanitizeText(context.name),
            service: sanitizeText(group.name),
            items: payload.items
              .filter(
                (entry) => entry.groupId === group.id && entry.deletedAt === undefined,
              )
              .map((entry) => sanitizeText(entry.title)),
          };
        });
        writeJsonResult({ ...result, revision: document.revision });
      });
    });
  const show = item
    .command('show <title>')
    .description('Show item metadata and redacted field states.');
  addDatabaseOptions(show)
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (title: string, options: Record<string, unknown>, command: Command) => {
        const flat = commandOptions(command);
        const contextName = requiredOption(options, 'context');
        const serviceName = requiredOption(options, 'service');
        const values = await readDatabaseFlatSecrets(flat, []);
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          let result: StructuredCommandResult = {};
          const document = await session.inspectStructuredVault(vaultId, (payload) => {
            const context = resolveProjectContext(payload, contextName);
            const group = resolveService(payload, context.id, serviceName);
            const item = resolveItem(payload, group.id, title);
            result = {
              context: sanitizeText(context.name),
              service: sanitizeText(group.name),
              title: sanitizeText(item.title),
              notes: item.notes.length,
              attachments: item.attachmentIds.length,
              history: payload.history.filter((record) => record.itemId === item.id)
                .length,
              fields: [...group.template.fields, ...item.itemFields].map((field) => ({
                name: sanitizeText(field.label),
                stableKey: sanitizeText(field.stableKey),
                type: field.type,
                sensitive: field.sensitive,
                state:
                  (group.template.fields.some((entry) => entry.id === field.id)
                    ? item.templateValues
                    : item.itemValues
                  ).find((entry) => entry.fieldId === field.id)?.value.state ??
                  'missing',
              })),
            };
          });
          writeJsonResult({ ...result, revision: document.revision });
        });
      },
    );
  const rename = item
    .command('rename <from> <to>')
    .description('Rename a credential item.');
  addDatabaseOptions(rename)
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (
        from: string,
        to: string,
        options: Record<string, unknown>,
        command: Command,
      ) => {
        const flat = commandOptions(command);
        const contextName = requiredOption(options, 'context');
        const serviceName = requiredOption(options, 'service');
        const values = await readDatabaseFlatSecrets(flat, []);
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            renameStructuredItem(payload, contextName, serviceName, from, to),
          );
          writeJsonResult({
            renamed: true,
            type: 'item',
            context: sanitizeText(contextName),
            service: sanitizeText(serviceName),
            from: sanitizeText(from),
            to: sanitizeText(to),
            revision: updated.revision,
          });
        });
      },
    );
  const remove = item
    .command('remove <title>')
    .description('Remove an item and its owned encrypted records.');
  addDatabaseOptions(remove)
    .requiredOption('--context <name>', 'Project context name.')
    .requiredOption('--service <name>', 'Service/group name.')
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (title: string, options: Record<string, unknown>, command: Command) => {
        const flat = commandOptions(command);
        const contextName = requiredOption(options, 'context');
        const serviceName = requiredOption(options, 'service');
        const values = await readDatabaseFlatSecrets(flat, []);
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            removeStructuredItem(payload, contextName, serviceName, title),
          );
          writeJsonResult({
            removed: true,
            type: 'item',
            context: sanitizeText(contextName),
            service: sanitizeText(serviceName),
            title: sanitizeText(title),
            revision: updated.revision,
          });
        });
      },
    );
}

function registerFieldCommands(program: Command): void {
  const field = program
    .command('field')
    .description('Manage schema-driven typed item fields.');
  const base = (command: Command): Command =>
    addDatabaseOptions(command)
      .requiredOption('--context <name>', 'Project context name.')
      .requiredOption('--service <name>', 'Service/group name.')
      .requiredOption('--item <title>', 'Credential item title.');
  const set = field
    .command('set <name>')
    .description('Set a typed field value from protected input.');
  base(set)
    .option('--value-stdin', 'Read a field value from protected stdin.')
    .option(
      '--value-stdin-base64',
      'Read one base64-encoded field value frame from protected stdin.',
    )
    .requiredOption('--type <type>', 'Canonical field type or supported alias.')
    .option('--sensitive', 'Mark an otherwise public field as sensitive.')
    .option('--public', 'Explicitly make an environment-map field non-sensitive.')
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (name: string, options: Record<string, unknown>, command: Command) => {
        const flat = commandOptions(command);
        if (flat.valueStdin === true && flat.valueStdinBase64 === true) {
          throw new StructuredVaultCommandError(
            'Use either --value-stdin or --value-stdin-base64, not both.',
          );
        }
        if (options['sensitive'] === true && options['public'] === true) {
          throw new StructuredVaultCommandError(
            'A field cannot be both sensitive and public.',
          );
        }
        const inputType = requiredOption(options, 'type');
        const kind =
          flat.valueStdinBase64 === true ? 'field-value-base64' : 'field-value';
        const values = await readDatabaseFlatSecrets(flat, [kind]);
        const rawValue = values.extras[0];
        if (rawValue === undefined)
          throw new DatabaseFlatCommandError('Secret input is incomplete.');
        const contextName = requiredOption(options, 'context');
        const serviceName = requiredOption(options, 'service');
        const itemTitle = requiredOption(options, 'item');
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            setStructuredField(payload, contextName, serviceName, itemTitle, {
              name,
              type: inputType,
              rawValue,
              ...(options['sensitive'] === true ? { sensitive: true } : {}),
              ...(options['public'] === true ? { publicValue: true } : {}),
            }),
          );
          writeJsonResult({
            saved: true,
            type: 'field',
            context: sanitizeText(contextName),
            service: sanitizeText(serviceName),
            item: sanitizeText(itemTitle),
            name: sanitizeText(name),
            revision: updated.revision,
          });
        });
      },
    );
  const list = field
    .command('list')
    .description('List item fields and their schema policies without values.');
  base(list)
    .option('--json', 'Emit machine-readable output.')
    .action(async (options: Record<string, unknown>, command: Command) => {
      const flat = commandOptions(command);
      const values = await readDatabaseFlatSecrets(flat, []);
      const contextName = requiredOption(options, 'context');
      const serviceName = requiredOption(options, 'service');
      const itemTitle = requiredOption(options, 'item');
      await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
        let result: StructuredCommandResult = {};
        const document = await session.inspectStructuredVault(vaultId, (payload) => {
          const context = resolveProjectContext(payload, contextName);
          const group = resolveService(payload, context.id, serviceName);
          const item = resolveItem(payload, group.id, itemTitle);
          result = {
            fields: [...group.template.fields, ...item.itemFields].map(
              (definition) => ({
                name: sanitizeText(definition.label),
                stableKey: sanitizeText(definition.stableKey),
                type: definition.type,
                sensitive: definition.sensitive,
                copyPolicy: definition.copyPolicy,
                revealPolicy: definition.revealPolicy,
                reauthenticationPolicy: definition.reauthenticationPolicy,
                exportPolicy: definition.exportPolicy,
                hasValue: (group.template.fields.some(
                  (entry) => entry.id === definition.id,
                )
                  ? item.templateValues
                  : item.itemValues
                ).some((entry) => entry.fieldId === definition.id),
              }),
            ),
          };
        });
        writeJsonResult({ ...result, revision: document.revision });
      });
    });
  const get = field
    .command('get <name>')
    .description(
      'Read one field; sensitive values are redacted unless explicitly authorized.',
    );
  base(get)
    .option('--reveal', 'Request an authorized plaintext field value.')
    .option(
      '--reveal-base64',
      'Request an authorized exact base64 field value for multiline-safe transport.',
    )
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (name: string, options: Record<string, unknown>, command: Command) => {
        const flat = commandOptions(command);
        const values = await readDatabaseFlatSecrets(flat, []);
        const contextName = requiredOption(options, 'context');
        const serviceName = requiredOption(options, 'service');
        const itemTitle = requiredOption(options, 'item');
        await withDatabaseFlatVault(flat, values, async (session, vaultId, profile) => {
          let observed:
            | Readonly<{
                definition: FieldDefinition;
                value: ActiveFieldValue | undefined;
                itemTitle: string;
                contextName: string;
                serviceName: string;
              }>
            | undefined;
          const document = await session.inspectStructuredVault(vaultId, (payload) => {
            const context = resolveProjectContext(payload, contextName);
            const group = resolveService(payload, context.id, serviceName);
            const item = resolveItem(payload, group.id, itemTitle);
            const projection = projectStructuredField(item, name, group.template);
            observed = {
              ...projection,
              itemTitle: item.title,
              contextName: context.name,
              serviceName: group.name,
            };
          });
          if (observed === undefined)
            throw new StructuredVaultCommandError('Field was not found.');
          const field = observed.definition;
          const storedValue = observed.value;
          const reveal = options['reveal'] === true;
          const revealBase64 = options['revealBase64'] === true;
          if (reveal && revealBase64) {
            throw new StructuredVaultCommandError(
              'Use either --reveal or --reveal-base64, not both.',
            );
          }
          if (!field.sensitive) {
            writeJsonResult({
              context: sanitizeText(observed.contextName),
              service: sanitizeText(observed.serviceName),
              item: sanitizeText(observed.itemTitle),
              name: sanitizeText(field.label),
              type: field.type,
              value:
                storedValue?.state === 'present'
                  ? renderFieldValue(storedValue)
                  : fieldState(storedValue),
              revision: document.revision,
            });
            return;
          }
          if (!reveal && !revealBase64) {
            writeJsonResult({
              context: sanitizeText(observed.contextName),
              service: sanitizeText(observed.serviceName),
              item: sanitizeText(observed.itemTitle),
              name: sanitizeText(field.label),
              type: field.type,
              value:
                storedValue?.state === 'present' ? REDACTED : fieldState(storedValue),
              revision: document.revision,
            });
            return;
          }
          assertStructuredFieldRevealAllowed(field);
          if (storedValue?.state !== 'present') {
            throw new StructuredVaultCommandError('Field has no readable value.');
          }
          await enforceRevealPolicy(
            session,
            profile,
            structuredFieldReference(
              observed.contextName,
              observed.serviceName,
              observed.itemTitle,
              field.stableKey,
            ),
          );
          process.stdout.write(
            revealBase64
              ? `${encodeStructuredFieldValueBase64(storedValue)}\n`
              : `${sanitizeText(renderFieldValue(storedValue))}\n`,
          );
        });
      },
    );
  const remove = field
    .command('remove <name>')
    .description('Archive one active field definition and value.');
  base(remove)
    .option('--json', 'Emit machine-readable output.')
    .action(
      async (name: string, options: Record<string, unknown>, command: Command) => {
        const flat = commandOptions(command);
        const values = await readDatabaseFlatSecrets(flat, []);
        const contextName = requiredOption(options, 'context');
        const serviceName = requiredOption(options, 'service');
        const itemTitle = requiredOption(options, 'item');
        await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
          const updated = await session.updateStructuredVault(vaultId, (payload) =>
            removeStructuredField(payload, contextName, serviceName, itemTitle, name),
          );
          writeJsonResult({
            removed: true,
            type: 'field',
            context: sanitizeText(contextName),
            service: sanitizeText(serviceName),
            item: sanitizeText(itemTitle),
            name: sanitizeText(name),
            revision: updated.revision,
          });
        });
      },
    );
}

function requiredOption(options: Record<string, unknown>, key: string): string {
  const value = options[key];
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new StructuredVaultCommandError(`Missing required option --${key}.`);
  }
  return value;
}

function writeJsonResult(value: StructuredCommandResult): void {
  process.stdout.write(JSON.stringify(value, safeJsonReplacer) + '\n');
}

function safeJsonReplacer(_key: string, value: unknown): unknown {
  if (typeof value !== 'string') return value;
  return sanitizeJsonText(value);
}

function sanitizeJsonText(value: string): string {
  const withoutTerminalSequences = value
    .replace(OSC_SEQUENCE_PATTERN, '')
    .replace(CSI_SEQUENCE_PATTERN, '');
  // JSON escapes tab/newline/carriage-return before terminal rendering; keep
  // those semantic separators while rejecting the remaining control set.
  return removeControlCharacters(withoutTerminalSequences, true);
}

function sanitizeText(value: string): string {
  // Strip CSI/OSC terminal controls before anything is rendered.
  const withoutTerminalSequences = value
    .replace(OSC_SEQUENCE_PATTERN, '')
    .replace(CSI_SEQUENCE_PATTERN, '');
  return removeControlCharacters(withoutTerminalSequences, false);
}

function removeControlCharacters(
  value: string,
  preserveJsonSeparators: boolean,
): string {
  let sanitized = '';
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    const isJsonSeparator =
      preserveJsonSeparators &&
      (codePoint === 0x09 || codePoint === 0x0a || codePoint === 0x0d);
    const isControl = codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
    if (!isControl || isJsonSeparator) sanitized += character;
  }
  return sanitized;
}

function fieldState(value: ActiveFieldValue | undefined): string {
  if (value === undefined || value.state === 'missing') return MISSING;
  if (value.state === 'empty') return EMPTY;
  return `[${value.state.toUpperCase()}]`;
}

function renderFieldValue(value: ActiveFieldValue): string {
  if (value.state !== 'present') return fieldState(value);
  const scalars =
    value.content.cardinality === 'single'
      ? [value.content.value]
      : value.content.elements.map((element) => element.value);
  return scalars.map(renderScalar).join('\n');
}

function renderScalar(value: FieldScalarValue): string {
  switch (value.kind) {
    case 'text':
    case 'secret':
      return value.value;
    case 'number':
      return String(value.value);
    case 'boolean':
      return String(value.value);
    case 'item-reference':
      return `item:${value.itemId}`;
    case 'attachment-reference':
      return `attachment:${value.attachmentId}`;
    case 'environment-entry':
      return `${value.key}=${value.value.value}`;
  }
}

function structuredFieldReference(
  contextName: string,
  serviceName: string,
  itemTitle: string,
  fieldKey: string,
): string {
  const reference = `${contextName}/${serviceName}/${itemTitle}/${fieldKey}`;
  if (reference.length > MAX_POLICY_REFERENCE_CHARS) {
    throw new StructuredVaultCommandError(
      'Structured field reference is too long for authorization policy.',
    );
  }
  return reference;
}
