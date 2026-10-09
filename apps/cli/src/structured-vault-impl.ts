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
  noteIdSchema,
  noteSchema,
  nonEmptyTextSchema,
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
  type Note,
  type NoteId,
  type ProjectContextPayload,
  type StructuredGroupPayload,
  type StructuredVaultPayload,
  VAULT_BROWSE_CONTEXT_LIMIT,
  VAULT_BROWSE_SERVICE_LIMIT,
  VAULT_BROWSE_ITEM_LIMIT,
  vaultBrowseSnapshotSchema,
  type VaultBrowseNode,
  type VaultBrowseSnapshot,
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
import { resolveProfileConfigDirectory } from './profile-config-directory.js';
import {
  DEFAULT_PROJECT_CONTEXT_ID,
  DEFAULT_SERVICE_ID,
  DEFAULT_VALUE_FIELD_ID,
  DEFAULT_VALUE_FIELD_KEY,
  DEFAULT_VALUE_FIELD_LABEL,
} from './structured-vault-projection.js';

/**
 * Runtime implementation for the structured vault command families. Handlers
 * here are dynamically imported by `structured-vault-commands.ts` at action
 * time so command registration stays light on startup.
 */

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

/** Note input that has already crossed the protected input boundary. */
export type StructuredNoteInput = Readonly<{
  title: string;
  content: string;
  sensitive?: boolean;
  pinned?: boolean;
  now?: string;
}>;

/** One note mutation: the next aggregate and the note the mutation touched. */
export type StructuredNoteMutation = Readonly<{
  payload: StructuredVaultPayload;
  note: Note;
}>;

/** Non-secret note metadata emitted by list/show; the body is never included. */
export type StructuredNoteSummary = Readonly<{
  id: string;
  title: string;
  sensitive: boolean;
  pinned: boolean;
  tags: readonly string[];
  sortOrder: number;
  createdAt: string;
  updatedAt: string;
}>;

export type StructuredCommandResult = Readonly<Record<string, unknown>>;

export type StructuredRoutingInput = Readonly<{
  datastore?: string;
  dataFile?: string;
  database?: string;
  collection?: string;
  keyFile?: string;
}>;

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

/** Attach one note to an item. The note body never leaves the protected input path. */
export function addStructuredNote(
  payload: StructuredVaultPayload,
  contextName: string,
  serviceName: string,
  itemTitle: string,
  input: StructuredNoteInput,
): StructuredNoteMutation {
  const context = resolveProjectContext(payload, contextName);
  const group = resolveService(payload, context.id, serviceName);
  const item = resolveItem(payload, group.id, itemTitle);
  const note = createNote(item, input);
  const nextItem = itemPayloadSchema.parse({
    ...item,
    notes: [...item.notes, note],
    revision: incrementRevision(item.revision),
    updatedAt: note.updatedAt,
  });
  return {
    payload: parseStructuredPayload({
      ...payload,
      items: payload.items.map((entry) => (entry.id === item.id ? nextItem : entry)),
    }),
    note,
  };
}

/**
 * Archive one note inside the item aggregate. Consistent with field removal,
 * the encrypted note is retained rather than silently discarded; only the
 * active projection drops it. The returned note is the archived record.
 */
export function removeStructuredNote(
  payload: StructuredVaultPayload,
  contextName: string,
  serviceName: string,
  itemTitle: string,
  noteId: string,
  now = timestampNow(),
): StructuredNoteMutation {
  const context = resolveProjectContext(payload, contextName);
  const group = resolveService(payload, context.id, serviceName);
  const item = resolveItem(payload, group.id, itemTitle);
  const target = resolveNote(item, noteId);
  const at = parseTimestamp(now);
  const archived = noteSchema.parse({ ...target, archivedAt: at, updatedAt: at });
  const nextItem = itemPayloadSchema.parse({
    ...item,
    notes: item.notes.map((entry) => (entry.id === target.id ? archived : entry)),
    revision: incrementRevision(item.revision),
    updatedAt: at,
  });
  return {
    payload: parseStructuredPayload({
      ...payload,
      items: payload.items.map((entry) => (entry.id === item.id ? nextItem : entry)),
    }),
    note: archived,
  };
}

/** Note metadata only; the archived flag never carries the note body. */
export function projectStructuredNotes(
  item: ItemPayload,
): readonly StructuredNoteSummary[] {
  return item.notes
    .filter((entry) => entry.archivedAt === undefined)
    .map((note) => ({
      id: note.id,
      title: sanitizeText(note.title),
      sensitive: note.isSensitive,
      pinned: note.isPinned,
      tags: note.tags.map((tag) => sanitizeText(tag)),
      sortOrder: note.sortOrder,
      createdAt: note.createdAt,
      updatedAt: note.updatedAt,
    }))
    .sort((left, right) =>
      left.sortOrder === right.sortOrder
        ? left.id.localeCompare(right.id)
        : left.sortOrder - right.sortOrder,
    );
}

/**
 * Return the display token for one note read. A sensitive note body is masked
 * unless the caller has already passed the note-level reveal guard.
 */
export function displayStructuredNoteContent(note: Note, reveal: boolean): string {
  if (note.isSensitive && !reveal) return REDACTED;
  return sanitizeText(note.content);
}

/** Reference one note for the stored authorization policy, as field reads do. */
export function structuredNoteReference(
  contextName: string,
  serviceName: string,
  itemTitle: string,
  noteId: string,
): string {
  const reference = `${contextName}/${serviceName}/${itemTitle}/${noteId}`;
  if (reference.length > MAX_POLICY_REFERENCE_CHARS) {
    throw new StructuredVaultCommandError(
      'Structured note reference is too long for authorization policy.',
    );
  }
  return reference;
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

/** Build one canonical note; identifiers and timestamps are generated here. */
function createNote(item: ItemPayload, input: StructuredNoteInput): Note {
  const title = parseNoteTitle(input.title);
  const content = parseNoteContent(input.content);
  const now = parseTimestamp(input.now ?? timestampNow());
  if (
    item.notes.some((entry) => entry.archivedAt === undefined && entry.title === title)
  ) {
    throw new StructuredVaultCommandError(
      'A note with this title already exists on this item.',
    );
  }
  return noteSchema.parse({
    id: noteIdSchema.parse(`note_${randomUUID()}`),
    title,
    content,
    isSensitive: input.sensitive === true,
    isPinned: input.pinned === true,
    tags: [],
    sortOrder: item.notes.length,
    createdAt: now,
    updatedAt: now,
  });
}

/** Resolve exactly one active note identifier, failing closed on any miss. */
function resolveNote(item: ItemPayload, noteId: string): Note {
  const id = parseNoteId(noteId);
  const matches = item.notes.filter(
    (entry) => entry.id === id && entry.archivedAt === undefined,
  );
  if (matches.length !== 1) {
    throw new StructuredVaultCommandError('Note was not found.');
  }
  const match = matches[0];
  if (match === undefined) throw new StructuredVaultCommandError('Note was not found.');
  return match;
}

function parseNoteId(value: string): NoteId {
  const parsed = noteIdSchema.safeParse(value.trim());
  if (!parsed.success) throw new StructuredVaultCommandError('Note ID is invalid.');
  return parsed.data;
}

function parseNoteTitle(value: string): string {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 256 ||
    containsC0Control(normalized)
  ) {
    throw new StructuredVaultCommandError('Note title is invalid.');
  }
  return nonEmptyTextSchema.parse(normalized);
}

function parseNoteContent(value: string): string {
  if (value.length === 0) {
    throw new StructuredVaultCommandError('Note content is empty.');
  }
  return secretValueSchema.parse(value);
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

function commandOptions(command: Command): DatabaseFlatCommandOptions {
  const options = command.opts<Record<string, unknown>>();
  const vault = options['vault'];
  if (typeof vault !== 'string')
    throw new StructuredVaultCommandError('A vault is required.');
  const vaultSource = command.getOptionValueSource('vault');
  const profile = stringOption(options, 'profile');
  const profileConfigDir = resolveProfileConfigDirectory(
    stringOption(options, 'profileConfigDir'),
    stringOption(options, 'configDir'),
  );
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
    ...(options['contentStdin'] === true ? { contentStdin: true } : {}),
    ...(options['contentStdinBase64'] === true ? { contentStdinBase64: true } : {}),
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

function requiredOption(options: Record<string, unknown>, key: string): string {
  const value = options[key];
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new StructuredVaultCommandError(`Missing required option --${key}.`);
  }
  return value;
}

/**
 * Command handlers. Each function is the exact former `.action` body for one
 * registered command; the light registration module dynamically imports these
 * at invocation time and forwards Commander's arguments unchanged.
 */

/** Handler for `context create <name>`. */
export async function contextCreate(
  name: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `context list`. */
export async function contextList(
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
  const flat = commandOptions(command);
  const values = await readDatabaseFlatSecrets(flat, []);
  await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
    let result: StructuredCommandResult = {};
    const document = await session.inspectStructuredVault(vaultId, (payload) => {
      result =
        options['tree'] === true
          ? projectVaultBrowse(payload)
          : {
              contexts: payload.projectContexts.map((entry) => ({
                name: sanitizeText(entry.name),
                ...(entry.environment === undefined
                  ? {}
                  : { environment: sanitizeText(entry.environment) }),
              })),
            };
    });
    const output = { ...result, revision: document.revision };
    writeJsonResult(
      options['tree'] === true ? vaultBrowseSnapshotSchema.parse(output) : output,
    );
  });
}

/** One authenticated payload, indexed once; no secret-bearing fields escape. */
export function projectVaultBrowse(
  payload: StructuredVaultPayload,
): Omit<VaultBrowseSnapshot, 'revision'> {
  const services = new Map<string, StructuredGroupPayload[]>();
  const items = new Map<string, ItemPayload[]>();
  for (const group of payload.groups) {
    const entries = services.get(group.projectContextId) ?? [];
    entries.push(group);
    services.set(group.projectContextId, entries);
  }
  for (const item of payload.items) {
    if (item.deletedAt !== undefined) continue;
    const entries = items.get(item.groupId) ?? [];
    entries.push(item);
    items.set(item.groupId, entries);
  }
  const nodes: VaultBrowseNode[] = [];
  let truncated = payload.projectContexts.length > VAULT_BROWSE_CONTEXT_LIMIT;
  for (const context of payload.projectContexts.slice(0, VAULT_BROWSE_CONTEXT_LIMIT)) {
    nodes.push({
      id: `context:${context.id}`,
      kind: 'context',
      label: sanitizeText(context.name),
      detail: 'project context',
    });
    const groups = services.get(context.id) ?? [];
    truncated ||= groups.length > VAULT_BROWSE_SERVICE_LIMIT;
    for (const group of groups.slice(0, VAULT_BROWSE_SERVICE_LIMIT)) {
      nodes.push({
        id: `service:${group.id}`,
        kind: 'service',
        label: sanitizeText(group.name),
        detail: `context ${sanitizeText(context.name)}`,
      });
      const entries = items.get(group.id) ?? [];
      truncated ||= entries.length > VAULT_BROWSE_ITEM_LIMIT;
      for (const item of entries.slice(0, VAULT_BROWSE_ITEM_LIMIT)) {
        nodes.push({
          id: `item:${item.id}`,
          kind: 'item',
          label: sanitizeText(item.title),
          detail: `service ${sanitizeText(group.name)}`,
        });
      }
    }
  }
  return { nodes, truncated };
}

/** Handler for `context rename <from> <to>`. */
export async function contextRename(
  from: string,
  to: string,
  _options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `context remove <name>`. */
export async function contextRemove(
  name: string,
  _options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `service create <name>`. */
export async function serviceCreate(
  name: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `service list`. */
export async function serviceList(
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `service rename <from> <to>`. */
export async function serviceRename(
  from: string,
  to: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `service remove <name>`. */
export async function serviceRemove(
  name: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `item create <title>`. */
export async function itemCreate(
  title: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `item list`. */
export async function itemList(
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `item show <title>`. */
export async function itemShow(
  title: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
        history: payload.history.filter((record) => record.itemId === item.id).length,
        fields: [...group.template.fields, ...item.itemFields].map((field) => ({
          name: sanitizeText(field.label),
          stableKey: sanitizeText(field.stableKey),
          type: field.type,
          sensitive: field.sensitive,
          state:
            (group.template.fields.some((entry) => entry.id === field.id)
              ? item.templateValues
              : item.itemValues
            ).find((entry) => entry.fieldId === field.id)?.value.state ?? 'missing',
        })),
      };
    });
    writeJsonResult({ ...result, revision: document.revision });
  });
}

/** Handler for `item rename <from> <to>`. */
export async function itemRename(
  from: string,
  to: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `item remove <title>`. */
export async function itemRemove(
  title: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `field set <name>`. */
export async function fieldSet(
  name: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
  const kind = flat.valueStdinBase64 === true ? 'field-value-base64' : 'field-value';
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
}

/** Handler for `field list`. */
export async function fieldList(
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
        fields: [...group.template.fields, ...item.itemFields].map((definition) => ({
          name: sanitizeText(definition.label),
          stableKey: sanitizeText(definition.stableKey),
          type: definition.type,
          sensitive: definition.sensitive,
          copyPolicy: definition.copyPolicy,
          revealPolicy: definition.revealPolicy,
          reauthenticationPolicy: definition.reauthenticationPolicy,
          exportPolicy: definition.exportPolicy,
          hasValue: (group.template.fields.some((entry) => entry.id === definition.id)
            ? item.templateValues
            : item.itemValues
          ).some((entry) => entry.fieldId === definition.id),
        })),
      };
    });
    writeJsonResult({ ...result, revision: document.revision });
  });
}

/** Handler for `field get <name>`. */
export async function fieldGet(
  name: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
        value: storedValue?.state === 'present' ? REDACTED : fieldState(storedValue),
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
}

/** Handler for `field remove <name>`. */
export async function fieldRemove(
  name: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
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
}

/** Handler for `note list <item>`. */
export async function noteList(
  itemTitle: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
  const flat = commandOptions(command);
  const contextName = requiredOption(options, 'context');
  const serviceName = requiredOption(options, 'service');
  const values = await readDatabaseFlatSecrets(flat, []);
  await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
    let result: StructuredCommandResult = {};
    const document = await session.inspectStructuredVault(vaultId, (payload) => {
      const context = resolveProjectContext(payload, contextName);
      const group = resolveService(payload, context.id, serviceName);
      const item = resolveItem(payload, group.id, itemTitle);
      result = {
        context: sanitizeText(context.name),
        service: sanitizeText(group.name),
        item: sanitizeText(item.title),
        notes: projectStructuredNotes(item),
      };
    });
    writeJsonResult({ ...result, revision: document.revision });
  });
}

/** Handler for `note add <item> <title>`. */
export async function noteAdd(
  itemTitle: string,
  title: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
  const flat = commandOptions(command);
  if (flat.contentStdin === true && flat.contentStdinBase64 === true) {
    throw new StructuredVaultCommandError(
      'Use either --content-stdin or --content-stdin-base64, not both.',
    );
  }
  const contextName = requiredOption(options, 'context');
  const serviceName = requiredOption(options, 'service');
  const kind =
    flat.contentStdinBase64 === true ? 'note-content-base64' : 'note-content';
  const values = await readDatabaseFlatSecrets(flat, [kind]);
  const rawContent = values.extras[0];
  if (rawContent === undefined)
    throw new DatabaseFlatCommandError('Secret input is incomplete.');
  await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
    let mutation: StructuredNoteMutation | undefined;
    const updated = await session.updateStructuredVault(vaultId, (payload) => {
      mutation = addStructuredNote(payload, contextName, serviceName, itemTitle, {
        title,
        content: rawContent,
        ...(options['sensitive'] === true ? { sensitive: true } : {}),
        ...(options['pin'] === true ? { pinned: true } : {}),
        ...(options['pin'] === false ? { pinned: false } : {}),
      });
      return mutation.payload;
    });
    const created = mutation;
    if (created === undefined)
      throw new StructuredVaultCommandError('Note was not created.');
    writeJsonResult({
      added: true,
      type: 'note',
      context: sanitizeText(contextName),
      service: sanitizeText(serviceName),
      item: sanitizeText(itemTitle),
      id: created.note.id,
      title: sanitizeText(created.note.title),
      sensitive: created.note.isSensitive,
      pinned: created.note.isPinned,
      revision: updated.revision,
    });
  });
}

/** Handler for `note show <item> <noteId>`. */
export async function noteShow(
  itemTitle: string,
  noteId: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
  const flat = commandOptions(command);
  const contextName = requiredOption(options, 'context');
  const serviceName = requiredOption(options, 'service');
  const reveal = options['reveal'] === true;
  const values = await readDatabaseFlatSecrets(flat, []);
  await withDatabaseFlatVault(flat, values, async (session, vaultId, profile) => {
    let observed:
      | Readonly<{
          note: Note;
          itemTitle: string;
          contextName: string;
          serviceName: string;
        }>
      | undefined;
    const document = await session.inspectStructuredVault(vaultId, (payload) => {
      const context = resolveProjectContext(payload, contextName);
      const group = resolveService(payload, context.id, serviceName);
      const item = resolveItem(payload, group.id, itemTitle);
      observed = {
        note: resolveNote(item, noteId),
        itemTitle: item.title,
        contextName: context.name,
        serviceName: group.name,
      };
    });
    const observation = observed;
    if (observation === undefined)
      throw new StructuredVaultCommandError('Note was not found.');
    // Permission to read a note never implies permission to print it: a
    // sensitive body passes the same stored reveal policy as a field read.
    if (reveal && observation.note.isSensitive) {
      await enforceRevealPolicy(
        session,
        profile,
        structuredNoteReference(
          observation.contextName,
          observation.serviceName,
          observation.itemTitle,
          observation.note.id,
        ),
      );
    }
    writeJsonResult({
      context: sanitizeText(observation.contextName),
      service: sanitizeText(observation.serviceName),
      item: sanitizeText(observation.itemTitle),
      id: observation.note.id,
      title: sanitizeText(observation.note.title),
      sensitive: observation.note.isSensitive,
      pinned: observation.note.isPinned,
      tags: observation.note.tags.map((tag) => sanitizeText(tag)),
      sortOrder: observation.note.sortOrder,
      createdAt: observation.note.createdAt,
      updatedAt: observation.note.updatedAt,
      content: displayStructuredNoteContent(observation.note, reveal),
      revision: document.revision,
    });
  });
}

/** Handler for `note remove <item> <noteId>`. */
export async function noteRemove(
  itemTitle: string,
  noteId: string,
  options: Record<string, unknown>,
  command: Command,
): Promise<void> {
  const flat = commandOptions(command);
  const contextName = requiredOption(options, 'context');
  const serviceName = requiredOption(options, 'service');
  const values = await readDatabaseFlatSecrets(flat, []);
  await withDatabaseFlatVault(flat, values, async (session, vaultId) => {
    let mutation: StructuredNoteMutation | undefined;
    const updated = await session.updateStructuredVault(vaultId, (payload) => {
      mutation = removeStructuredNote(
        payload,
        contextName,
        serviceName,
        itemTitle,
        noteId,
      );
      return mutation.payload;
    });
    const removed = mutation;
    if (removed === undefined)
      throw new StructuredVaultCommandError('Note was not found.');
    writeJsonResult({
      removed: true,
      type: 'note',
      context: sanitizeText(contextName),
      service: sanitizeText(serviceName),
      item: sanitizeText(itemTitle),
      id: removed.note.id,
      revision: updated.revision,
    });
  });
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
