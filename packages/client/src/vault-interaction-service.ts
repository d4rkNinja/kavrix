import {
  MAX_CLEAR_TIMEOUT_MS,
  MAX_CLIPBOARD_BYTES,
  MIN_CLEAR_TIMEOUT_MS,
  type SecureClipboardPort,
} from '@kavrix/clipboard';
import { resolveNamedEntity } from '@kavrix/core';
import {
  fieldDefinitionSchema,
  groupPayloadSchema,
  groupTemplateSchema,
  isSensitiveFieldType,
  itemPayloadSchema,
  noteSchema,
  type ActiveFieldValue,
  type FieldDefinition,
  type FieldScalarValue,
  type ItemPayload,
  type Note,
  type StoredFieldValue,
} from '@kavrix/schemas';
import { z } from 'zod';

import { CredentialCopyError } from './errors.js';
import type { CredentialShowResult, VaultReadSession } from './vault-read-session.js';

const REDACTED = '[REDACTED]';
const MISSING = '[MISSING]';
const EMPTY = '[EMPTY]';
const INAPPLICABLE = '[INAPPLICABLE]';
const UNREADABLE = '[UNREADABLE]';
const ORPHANED = '[ORPHANED]';

const credentialShowFieldStateSchema = z.enum([
  'missing',
  'empty',
  'present',
  'inapplicable',
  'unreadable',
  'orphaned',
]);

export const credentialShowFieldSchema = z
  .object({
    id: fieldDefinitionSchema.shape.id,
    stableKey: fieldDefinitionSchema.shape.stableKey,
    label: fieldDefinitionSchema.shape.label,
    type: fieldDefinitionSchema.shape.type,
    sensitive: fieldDefinitionSchema.shape.sensitive,
    copyable: fieldDefinitionSchema.shape.copyable,
    copyPolicy: fieldDefinitionSchema.shape.copyPolicy,
    sortOrder: fieldDefinitionSchema.shape.sortOrder,
    state: credentialShowFieldStateSchema,
    value: z.string().max(MAX_CLIPBOARD_BYTES),
    source: z.enum(['template', 'item', 'archived']),
  })
  .strict()
  .superRefine((field, context) => {
    const expected = expectedFieldSentinel(field);
    if (expected !== undefined && field.value !== expected) {
      context.addIssue({
        code: 'custom',
        path: ['value'],
        message: 'Redacted field values must use the exact safe sentinel',
      });
    }
    if (field.copyable !== (field.copyPolicy !== 'never')) {
      context.addIssue({
        code: 'custom',
        path: ['copyPolicy'],
        message: 'The projected copy policy is inconsistent',
      });
    }
    if (isSensitiveFieldType(field.type) && !field.sensitive) {
      context.addIssue({
        code: 'custom',
        path: ['sensitive'],
        message: 'A sensitive field type cannot be projected as non-sensitive',
      });
    }
  });

export const credentialShowNoteSchema = z
  .object({
    id: noteSchema.shape.id,
    title: noteSchema.shape.title,
    content: z.literal(REDACTED),
    sensitive: noteSchema.shape.isSensitive,
    pinned: noteSchema.shape.isPinned,
    tags: noteSchema.shape.tags,
    createdAt: noteSchema.shape.createdAt,
    updatedAt: noteSchema.shape.updatedAt,
    archivedAt: noteSchema.shape.archivedAt,
  })
  .strict();

const credentialShowGroupSchema = z
  .object({
    id: groupPayloadSchema.shape.id,
    name: groupPayloadSchema.shape.name,
    slug: groupPayloadSchema.shape.slug,
    aliases: groupPayloadSchema.shape.aliases,
    description: groupPayloadSchema.shape.description,
    tags: groupPayloadSchema.shape.tags,
    notes: z.array(credentialShowNoteSchema).max(10_000),
  })
  .strict();

const credentialShowTemplateSchema = z
  .object({
    id: groupTemplateSchema.shape.id,
    name: groupTemplateSchema.shape.name,
    version: groupTemplateSchema.shape.version,
  })
  .strict();

export const credentialShowProjectionSchema = z
  .object({
    id: itemPayloadSchema.shape.id,
    title: itemPayloadSchema.shape.title,
    slug: itemPayloadSchema.shape.slug,
    aliases: itemPayloadSchema.shape.aliases,
    subtitle: itemPayloadSchema.shape.subtitle,
    environment: itemPayloadSchema.shape.environment,
    owner: itemPayloadSchema.shape.owner,
    purpose: itemPayloadSchema.shape.purpose,
    favorite: itemPayloadSchema.shape.favorite,
    productionSensitive: itemPayloadSchema.shape.productionSensitive,
    tags: itemPayloadSchema.shape.tags,
    expiresAt: itemPayloadSchema.shape.expiresAt,
    rotationIntervalDays: itemPayloadSchema.shape.rotationIntervalDays,
    lastRotatedAt: itemPayloadSchema.shape.lastRotatedAt,
    lastVerifiedAt: itemPayloadSchema.shape.lastVerifiedAt,
    createdAt: itemPayloadSchema.shape.createdAt,
    updatedAt: itemPayloadSchema.shape.updatedAt,
    archivedAt: itemPayloadSchema.shape.archivedAt,
    revision: itemPayloadSchema.shape.revision,
    group: credentialShowGroupSchema,
    template: credentialShowTemplateSchema,
    relatedItemCount: z.number().int().nonnegative().max(1_000),
    attachmentCount: z.number().int().nonnegative().max(1_000),
    noteCount: z.number().int().nonnegative().max(10_000),
    activeNoteCount: z.number().int().nonnegative().max(10_000),
    archivedNoteCount: z.number().int().nonnegative().max(10_000),
    notes: z.array(credentialShowNoteSchema).max(10_000),
    fields: z.array(credentialShowFieldSchema).max(12_000),
  })
  .strict()
  .superRefine((projection, context) => {
    if (
      projection.noteCount !== projection.notes.length ||
      projection.activeNoteCount + projection.archivedNoteCount !==
        projection.noteCount ||
      projection.archivedNoteCount !==
        projection.notes.filter(({ archivedAt }) => archivedAt !== undefined).length
    ) {
      context.addIssue({
        code: 'custom',
        path: ['noteCount'],
        message: 'Projected note counts must match the redacted note list',
      });
    }
    const ids = new Set<string>();
    const keys = new Set<string>();
    for (const [index, field] of projection.fields.entries()) {
      if (ids.has(field.id) || keys.has(field.stableKey)) {
        context.addIssue({
          code: 'custom',
          path: ['fields', index],
          message: 'Projected fields must have unique IDs and stable keys',
        });
      }
      ids.add(field.id);
      keys.add(field.stableKey);
    }
  });

export type CredentialShowFieldState = z.infer<typeof credentialShowFieldStateSchema>;
export type CredentialShowField = z.infer<typeof credentialShowFieldSchema>;
export type CredentialShowNote = z.infer<typeof credentialShowNoteSchema>;
export type CredentialShowProjection = z.infer<typeof credentialShowProjectionSchema>;

export type CopyAuthorizationReason =
  'copy-policy-confirm' | 'production-sensitive' | 'reauthentication-always';

export type CopyAuthorizationRequest = Readonly<{
  vaultId: ItemPayload['vaultId'];
  groupId: ItemPayload['groupId'];
  itemId: ItemPayload['id'];
  fieldId: FieldDefinition['id'];
  fieldLabel: string;
  reasons: readonly CopyAuthorizationReason[];
}>;

export interface CopyAuthorizationPort {
  authorizeCopy(request: CopyAuthorizationRequest): Promise<boolean>;
}

export type CredentialCopyOptions = Readonly<{
  index?: number;
  /**
   * Selects one element of a repeatable field by its stable identifier.
   *
   * Preferred over `index` wherever the caller has an identifier: an index is
   * positional, so adding, consuming, or merging elements can make the same
   * index name a different element, while the identifier names the same element
   * on every replica. The two selectors are mutually exclusive.
   */
  elementId?: string;
  signal?: AbortSignal;
}>;

export const credentialCopyReceiptSchema = z
  .object({
    label: z
      .string()
      .min(1)
      .max(1_024)
      .refine((label) => safeLabel(label) === label),
    clearAfterSeconds: z
      .number()
      .positive()
      .max(MAX_CLEAR_TIMEOUT_MS / 1_000),
  })
  .strict();

export type CredentialCopyReceipt = z.infer<typeof credentialCopyReceiptSchema>;

export type VaultInteractionOptions = Readonly<{
  clearAfterMs: number;
  authorization?: CopyAuthorizationPort;
}>;

type ResolvedField = Readonly<{
  definition: FieldDefinition;
  value: ActiveFieldValue | undefined;
  archived: boolean;
}>;

export class VaultInteractionService {
  readonly #session: VaultReadSession;
  readonly #clipboard: SecureClipboardPort;
  readonly #authorization: CopyAuthorizationPort | undefined;
  readonly #clearAfterMs: number;

  constructor(
    session: VaultReadSession,
    clipboard: SecureClipboardPort,
    options: VaultInteractionOptions,
  ) {
    if (
      !Number.isInteger(options.clearAfterMs) ||
      options.clearAfterMs < MIN_CLEAR_TIMEOUT_MS ||
      options.clearAfterMs > MAX_CLEAR_TIMEOUT_MS
    ) {
      throw new RangeError('The clipboard clear deadline is outside the safe range.');
    }
    this.#session = session;
    this.#clipboard = clipboard;
    this.#authorization = options.authorization;
    this.#clearAfterMs = options.clearAfterMs;
  }

  async show(
    groupQuery: string,
    credentialQuery: string,
  ): Promise<CredentialShowProjection> {
    return projectCredentialShow(await this.#session.show(groupQuery, credentialQuery));
  }

  async copy(
    groupQuery: string,
    credentialQuery: string,
    fieldQuery: string,
    options: CredentialCopyOptions = {},
  ): Promise<CredentialCopyReceipt> {
    const aggregate = await this.#session.show(groupQuery, credentialQuery);
    const field = resolveField(aggregate, fieldQuery);
    if (field.archived) throw new CredentialCopyError('orphaned');
    if (!field.definition.copyable || field.definition.copyPolicy === 'never') {
      throw new CredentialCopyError('not-copyable');
    }
    const scalar = selectScalar(field.value, options.index, options.elementId);
    await this.#authorizeIfRequired(aggregate.item, field.definition);

    const encoded = new TextEncoder().encode(copyScalarText(scalar));
    try {
      if (encoded.byteLength === 0 || encoded.byteLength > MAX_CLIPBOARD_BYTES) {
        throw new CredentialCopyError('clipboard-failed');
      }
      try {
        await this.#clipboard.copy(encoded, {
          clearAfterMs: this.#clearAfterMs,
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      } catch {
        throw new CredentialCopyError('clipboard-failed');
      }
    } finally {
      encoded.fill(0);
    }
    return credentialCopyReceiptSchema.parse({
      label: safeLabel(field.definition.label),
      clearAfterSeconds: this.#clearAfterMs / 1_000,
    });
  }

  async #authorizeIfRequired(
    item: ItemPayload,
    definition: FieldDefinition,
  ): Promise<void> {
    await authorizeFieldRelease(item, definition, this.#authorization);
  }
}

/** One field to release to an approved non-clipboard sink. */
export type CredentialFieldRequest = Readonly<{
  groupQuery: string;
  credentialQuery: string;
  fieldQuery: string;
  index?: number;
}>;

/**
 * One resolved plaintext scalar. `secret` reports whether the value must be
 * treated as secret material by the sink, so a caller can redact it without
 * re-deriving field classification rules.
 */
export type ResolvedCredentialField = Readonly<{
  label: string;
  secret: boolean;
  value: FieldScalarValue;
}>;

export type VaultFieldAccessOptions = Readonly<{
  authorization?: CopyAuthorizationPort;
}>;

/**
 * Resolves single field values for callers that hand plaintext to an approved
 * sink other than the clipboard, such as a child process environment.
 *
 * The release rules are deliberately identical to `copy`: an injected value
 * leaves the vault exactly as a copied one does, and a process can disclose it
 * further, so a field that may not be copied may not be injected either.
 */
export class VaultFieldAccessService {
  readonly #session: VaultReadSession;
  readonly #authorization: CopyAuthorizationPort | undefined;

  constructor(session: VaultReadSession, options: VaultFieldAccessOptions = {}) {
    this.#session = session;
    this.#authorization = options.authorization;
  }

  async resolve(request: CredentialFieldRequest): Promise<ResolvedCredentialField> {
    const aggregate = await this.#session.show(
      request.groupQuery,
      request.credentialQuery,
    );
    const field = resolveField(aggregate, request.fieldQuery);
    if (field.archived) throw new CredentialCopyError('orphaned');
    if (!field.definition.copyable || field.definition.copyPolicy === 'never') {
      throw new CredentialCopyError('not-copyable');
    }
    const value = selectScalar(field.value, request.index);
    if (value.kind === 'attachment-reference' || value.kind === 'item-reference') {
      throw new CredentialCopyError('not-copyable');
    }
    await authorizeFieldRelease(aggregate.item, field.definition, this.#authorization);
    return Object.freeze({
      label: safeLabel(field.definition.label),
      secret: field.definition.sensitive || isSecretScalar(value),
      value,
    });
  }
}

/**
 * Requires explicit authorization before plaintext leaves the vault. Shared by
 * every release path so a new sink cannot accidentally skip the gate.
 */
async function authorizeFieldRelease(
  item: ItemPayload,
  definition: FieldDefinition,
  authorization: CopyAuthorizationPort | undefined,
): Promise<void> {
  const reasons: CopyAuthorizationReason[] = [];
  if (definition.copyPolicy === 'confirm') reasons.push('copy-policy-confirm');
  if (item.productionSensitive) reasons.push('production-sensitive');
  if (definition.reauthenticationPolicy === 'always') {
    reasons.push('reauthentication-always');
  }
  if (reasons.length === 0) return;
  if (authorization === undefined) {
    throw new CredentialCopyError('authorization-required');
  }
  let authorized: boolean;
  try {
    authorized = await authorization.authorizeCopy({
      vaultId: item.vaultId,
      groupId: item.groupId,
      itemId: item.id,
      fieldId: definition.id,
      fieldLabel: safeLabel(definition.label),
      reasons,
    });
  } catch {
    throw new CredentialCopyError('authorization-failed');
  }
  if (!authorized) throw new CredentialCopyError('authorization-denied');
}

export function projectCredentialShow(
  result: CredentialShowResult,
): CredentialShowProjection {
  const { group, item, template } = result;
  const templateValues = new Map(
    item.templateValues.map((stored) => [stored.fieldId, stored]),
  );
  const itemValues = new Map(item.itemValues.map((stored) => [stored.fieldId, stored]));
  const fields = [
    ...template.fields.map((definition) =>
      projectField(definition, templateValues.get(definition.id), 'template'),
    ),
    ...item.itemFields.map((definition) =>
      projectField(definition, itemValues.get(definition.id), 'item'),
    ),
    ...item.archivedFieldValues.map(({ definition }) =>
      projectField(definition, undefined, 'archived'),
    ),
  ].sort(compareFields);
  const archivedNoteCount = item.notes.filter(
    ({ archivedAt }) => archivedAt !== undefined,
  ).length;
  return credentialShowProjectionSchema.parse({
    group: {
      id: group.id,
      name: group.name,
      ...(group.slug === undefined ? {} : { slug: group.slug }),
      aliases: group.aliases,
      ...(group.description === undefined ? {} : { description: group.description }),
      tags: group.tags,
      notes: projectNotes(group.notes),
    },
    template: { id: template.id, name: template.name, version: template.version },
    id: item.id,
    title: item.title,
    ...(item.slug === undefined ? {} : { slug: item.slug }),
    aliases: item.aliases,
    ...(item.subtitle === undefined ? {} : { subtitle: item.subtitle }),
    ...(item.environment === undefined ? {} : { environment: item.environment }),
    ...(item.owner === undefined ? {} : { owner: item.owner }),
    ...(item.purpose === undefined ? {} : { purpose: item.purpose }),
    favorite: item.favorite,
    productionSensitive: item.productionSensitive,
    tags: item.tags,
    ...(item.expiresAt === undefined ? {} : { expiresAt: item.expiresAt }),
    ...(item.rotationIntervalDays === undefined
      ? {}
      : { rotationIntervalDays: item.rotationIntervalDays }),
    ...(item.lastRotatedAt === undefined ? {} : { lastRotatedAt: item.lastRotatedAt }),
    ...(item.lastVerifiedAt === undefined
      ? {}
      : { lastVerifiedAt: item.lastVerifiedAt }),
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    ...(item.archivedAt === undefined ? {} : { archivedAt: item.archivedAt }),
    revision: item.revision,
    relatedItemCount: item.relatedItemIds.length,
    attachmentCount: item.attachmentIds.length,
    noteCount: item.notes.length,
    activeNoteCount: item.notes.length - archivedNoteCount,
    archivedNoteCount,
    notes: projectNotes(item.notes),
    fields,
  });
}

function projectNotes(notes: readonly Note[]): readonly CredentialShowNote[] {
  return [...notes]
    .sort(
      (left, right) =>
        left.sortOrder - right.sortOrder || left.id.localeCompare(right.id),
    )
    .map((note) => ({
      id: note.id,
      title: note.title,
      content: REDACTED,
      sensitive: note.isSensitive,
      pinned: note.isPinned,
      tags: note.tags,
      createdAt: note.createdAt,
      updatedAt: note.updatedAt,
      ...(note.archivedAt === undefined ? {} : { archivedAt: note.archivedAt }),
    }));
}

function projectField(
  definition: FieldDefinition,
  stored: StoredFieldValue | undefined,
  source: CredentialShowField['source'],
): CredentialShowField {
  const value = stored?.value;
  return {
    id: definition.id,
    stableKey: definition.stableKey,
    label: definition.label,
    type: definition.type,
    sensitive: definition.sensitive,
    copyable: definition.copyable,
    copyPolicy: definition.copyPolicy,
    state: source === 'archived' ? 'orphaned' : (value?.state ?? 'missing'),
    value: source === 'archived' ? ORPHANED : redactedFieldValue(definition, value),
    source,
    sortOrder: definition.sortOrder,
  };
}

function redactedFieldValue(
  definition: FieldDefinition,
  value: ActiveFieldValue | undefined,
): string {
  if (definition.sensitive) return REDACTED;
  if (value === undefined || value.state === 'missing') return MISSING;
  if (value.state === 'empty') return EMPTY;
  if (value.state === 'inapplicable') return INAPPLICABLE;
  if (value.state === 'unreadable') return UNREADABLE;
  const scalars =
    value.content.cardinality === 'single'
      ? [value.content.value]
      : value.content.elements.map(({ value: scalar }) => scalar);
  if (scalars.some(isSecretScalar)) return REDACTED;
  return scalars.map(showScalarText).join(', ');
}

function expectedFieldSentinel(
  field: Readonly<{
    sensitive: boolean;
    type: FieldDefinition['type'];
    state: CredentialShowFieldState;
    source: CredentialShowField['source'];
  }>,
): string | undefined {
  if (field.source === 'archived' || field.state === 'orphaned') return ORPHANED;
  if (field.sensitive || isSensitiveFieldType(field.type)) return REDACTED;
  switch (field.state) {
    case 'missing':
      return MISSING;
    case 'empty':
      return EMPTY;
    case 'inapplicable':
      return INAPPLICABLE;
    case 'unreadable':
      return UNREADABLE;
    case 'present':
      return undefined;
  }
}

function resolveField(result: CredentialShowResult, query: string): ResolvedField {
  const { item, template } = result;
  const templateValues = new Map(
    item.templateValues.map((stored) => [stored.fieldId, stored]),
  );
  const itemValues = new Map(item.itemValues.map((stored) => [stored.fieldId, stored]));
  const candidates = [
    ...template.fields.map((definition) => ({
      id: definition.id,
      name: definition.label,
      slug: definition.stableKey,
      aliases: [] as const,
      definition,
      value: templateValues.get(definition.id)?.value,
      archived: false,
    })),
    ...item.itemFields.map((definition) => ({
      id: definition.id,
      name: definition.label,
      slug: definition.stableKey,
      aliases: [] as const,
      definition,
      value: itemValues.get(definition.id)?.value,
      archived: false,
    })),
    ...item.archivedFieldValues.map(({ definition, value }) => ({
      id: definition.id,
      name: definition.label,
      slug: definition.stableKey,
      aliases: [] as const,
      definition,
      value: value.originalValue,
      archived: true,
    })),
  ];
  return resolveNamedEntity(query, candidates);
}

function selectScalar(
  value: ActiveFieldValue | undefined,
  index: number | undefined,
  elementId?: string,
): FieldScalarValue {
  if (index !== undefined && elementId !== undefined) {
    throw new CredentialCopyError('selector-conflict');
  }
  if (value === undefined || value.state === 'missing') {
    throw new CredentialCopyError('missing');
  }
  if (value.state === 'empty') throw new CredentialCopyError('empty');
  if (value.state === 'inapplicable') {
    throw new CredentialCopyError('inapplicable');
  }
  if (value.state === 'unreadable') throw new CredentialCopyError('unreadable');
  if (value.content.cardinality === 'single') {
    if (index !== undefined || elementId !== undefined) {
      throw new CredentialCopyError('index-inapplicable');
    }
    return value.content.value;
  }
  if (elementId !== undefined) {
    // Matched exactly: a prefix is resolved to a full identifier before it
    // reaches here, so this lookup can never pick a neighbouring element.
    const named = value.content.elements.find(({ id }) => id === elementId);
    if (named === undefined) throw new CredentialCopyError('element-not-found');
    if (named.lifecycle.status === 'used') throw new CredentialCopyError('used');
    return named.value;
  }
  if (index === undefined) throw new CredentialCopyError('index-required');
  if (!Number.isSafeInteger(index) || index < 1) {
    throw new CredentialCopyError('index-out-of-range');
  }
  const element = value.content.elements[index - 1];
  if (element === undefined) throw new CredentialCopyError('index-out-of-range');
  if (element.lifecycle.status === 'used') throw new CredentialCopyError('used');
  return element.value;
}

function copyScalarText(value: FieldScalarValue): string {
  switch (value.kind) {
    case 'text':
    case 'secret':
      return value.value;
    case 'number':
    case 'boolean':
      return String(value.value);
    case 'item-reference':
      return value.itemId;
    case 'attachment-reference':
      return value.attachmentId;
    case 'environment-entry':
      return `${value.key}=${value.value.value}`;
  }
}

function showScalarText(value: FieldScalarValue): string {
  if (isSecretScalar(value)) return REDACTED;
  return copyScalarText(value);
}

function isSecretScalar(value: FieldScalarValue): boolean {
  return (
    value.kind === 'secret' ||
    (value.kind === 'environment-entry' && value.value.classification === 'secret')
  );
}

function compareFields(left: CredentialShowField, right: CredentialShowField): number {
  return (
    sourceRank(left.source) - sourceRank(right.source) ||
    left.sortOrder - right.sortOrder ||
    left.stableKey.localeCompare(right.stableKey)
  );
}

function sourceRank(source: CredentialShowField['source']): number {
  switch (source) {
    case 'template':
      return 0;
    case 'item':
      return 1;
    case 'archived':
      return 2;
  }
}

function safeLabel(value: string): string {
  let safe = '';
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint === undefined ||
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      codePoint === 0x061c ||
      codePoint === 0x200e ||
      codePoint === 0x200f ||
      (codePoint >= 0x202a && codePoint <= 0x202e) ||
      (codePoint >= 0x2066 && codePoint <= 0x2069)
    ) {
      safe += '\uFFFD';
    } else {
      safe += character;
    }
  }
  return safe;
}
