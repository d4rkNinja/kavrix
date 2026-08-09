import { z } from 'zod';

import {
  attachmentIdSchema,
  groupIdSchema,
  itemIdSchema,
  templateIdSchema,
  vaultIdSchema,
} from './identifiers.js';
import {
  type ActiveFieldValue,
  archivedFieldValueSchema,
  fieldDefinitionSchema,
  fieldValueMatchesDefinition,
  stableFieldKeySchema,
  storedFieldValueSchema,
} from './fields.js';
import { noteCollectionSchema } from './notes.js';
import {
  nonEmptyTextSchema,
  recordRevisionSchema,
  slugSchema,
  sortOrderSchema,
  templateVersionSchema,
  timestampSchema,
} from './primitives.js';
import { groupTemplateSchema } from './templates.js';

const aliasesSchema = z.array(z.string().trim().min(1).max(256)).max(256);
const tagsSchema = z.array(z.string().trim().min(1).max(128)).max(256);
const copySequenceIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._~-]*$/)
  .brand<'CopySequenceId'>();

export const copySequenceSchema = z
  .object({
    id: copySequenceIdSchema,
    name: nonEmptyTextSchema,
    fieldKeys: z.array(stableFieldKeySchema).min(1).max(100),
  })
  .strict()
  .superRefine((sequence, context) => {
    const keys = new Set<string>();
    for (const [index, key] of sequence.fieldKeys.entries()) {
      if (keys.has(key)) {
        context.addIssue({
          code: 'custom',
          message: 'A copy sequence cannot contain the same field twice',
          path: ['fieldKeys', index],
        });
      }
      keys.add(key);
    }
  });

export const groupPayloadSchema = z
  .object({
    id: groupIdSchema,
    vaultId: vaultIdSchema,
    name: nonEmptyTextSchema,
    slug: slugSchema.optional(),
    aliases: aliasesSchema,
    description: z.string().trim().max(8_192).optional(),
    icon: z.string().max(64).optional(),
    colorToken: z.string().max(64).optional(),
    tags: tagsSchema,
    notes: noteCollectionSchema,
    template: groupTemplateSchema,
    sortOrder: sortOrderSchema,
    revision: recordRevisionSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    archivedAt: timestampSchema.optional(),
    deletedAt: timestampSchema.optional(),
  })
  .strict();

export const itemPayloadV1Schema = z
  .object({
    version: z.literal(1),
    id: itemIdSchema,
    vaultId: vaultIdSchema,
    groupId: groupIdSchema,
    templateId: templateIdSchema,
    title: nonEmptyTextSchema,
    slug: slugSchema.optional(),
    aliases: aliasesSchema,
    subtitle: z.string().trim().max(512).optional(),
    templateVersion: templateVersionSchema,
    templateValues: z.array(storedFieldValueSchema).max(1_000),
    itemFields: z.array(fieldDefinitionSchema).max(1_000),
    itemValues: z.array(storedFieldValueSchema).max(1_000),
    archivedFieldValues: z.array(archivedFieldValueSchema).max(10_000),
    notes: noteCollectionSchema,
    tags: tagsSchema,
    favorite: z.boolean(),
    environment: z.string().trim().max(128).optional(),
    owner: z.string().trim().min(1).max(512).optional(),
    purpose: z.string().trim().min(1).max(2_048).optional(),
    productionSensitive: z.boolean(),
    expiresAt: timestampSchema.optional(),
    rotationIntervalDays: z.number().int().positive().max(36_500).optional(),
    lastRotatedAt: timestampSchema.optional(),
    lastVerifiedAt: timestampSchema.optional(),
    relatedItemIds: z.array(itemIdSchema).max(1_000),
    attachmentIds: z.array(attachmentIdSchema).max(1_000),
    copySequences: z.array(copySequenceSchema).max(100),
    revision: recordRevisionSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
    archivedAt: timestampSchema.optional(),
    deletedAt: timestampSchema.optional(),
  })
  .strict()
  .superRefine((item, context) => {
    const fieldIds = new Set<string>();
    const stableKeys = new Set<string>();
    const templateFieldIds = new Set<string>();
    const templateStableKeys = new Set<string>();
    for (const [index, value] of [
      ...item.templateValues,
      ...item.itemValues,
    ].entries()) {
      if (fieldIds.has(value.fieldId) || stableKeys.has(value.stableKey)) {
        context.addIssue({
          code: 'custom',
          message: 'Active field values must have unique IDs and stable keys',
          path: ['templateValues', index],
        });
      }
      fieldIds.add(value.fieldId);
      stableKeys.add(value.stableKey);
      if (index < item.templateValues.length) {
        templateFieldIds.add(value.fieldId);
        templateStableKeys.add(value.stableKey);
      }
    }

    const itemDefinitionsById = new Map<string, (typeof item.itemFields)[number]>();
    const itemDefinitionKeys = new Set<string>();
    for (const [index, definition] of item.itemFields.entries()) {
      if (
        itemDefinitionsById.has(definition.id) ||
        itemDefinitionKeys.has(definition.stableKey) ||
        templateFieldIds.has(definition.id) ||
        templateStableKeys.has(definition.stableKey)
      ) {
        context.addIssue({
          code: 'custom',
          message:
            'Item-only field definitions must be unique and cannot shadow template fields',
          path: ['itemFields', index],
        });
      }
      itemDefinitionsById.set(definition.id, definition);
      itemDefinitionKeys.add(definition.stableKey);
    }
    const itemValueIds = new Set<string>();
    for (const [index, value] of item.itemValues.entries()) {
      const definition = itemDefinitionsById.get(value.fieldId);
      const definitionMatches =
        definition?.stableKey === value.stableKey &&
        fieldValueMatchesDefinition(definition, value.value);
      if (itemValueIds.has(value.fieldId) || !definitionMatches) {
        context.addIssue({
          code: 'custom',
          message: 'Item-only values must match one unique item-only definition',
          path: ['itemValues', index],
        });
      }
      itemValueIds.add(value.fieldId);
    }
    for (const [index, definition] of item.itemFields.entries()) {
      const stored = item.itemValues.find((value) => value.fieldId === definition.id);
      if (
        definition.required &&
        (stored === undefined || !fieldValueMatchesDefinition(definition, stored.value))
      ) {
        context.addIssue({
          code: 'custom',
          message: 'Required item-only fields must have a value',
          path: ['itemFields', index],
        });
      }
    }

    const activeDefinitionIds = new Set([
      ...item.templateValues.map(({ fieldId }) => fieldId),
      ...item.itemFields.map(({ id }) => id),
    ]);
    const activeDefinitionKeys = new Set([
      ...item.templateValues.map(({ stableKey }) => stableKey),
      ...item.itemFields.map(({ stableKey }) => stableKey),
    ]);
    const archivedIds = new Set<string>();
    const archivedKeys = new Set<string>();
    for (const [index, archived] of item.archivedFieldValues.entries()) {
      if (
        archivedIds.has(archived.definition.id) ||
        archivedKeys.has(archived.definition.stableKey) ||
        activeDefinitionIds.has(archived.definition.id) ||
        activeDefinitionKeys.has(archived.definition.stableKey)
      ) {
        context.addIssue({
          code: 'custom',
          message:
            'Archived field IDs and stable keys must be unique and disjoint from active fields',
          path: ['archivedFieldValues', index],
        });
      }
      archivedIds.add(archived.definition.id);
      archivedKeys.add(archived.definition.stableKey);
    }

    const relatedItemIds = new Set<string>();
    for (const [index, relatedItemId] of item.relatedItemIds.entries()) {
      if (relatedItemId === item.id || relatedItemIds.has(relatedItemId)) {
        context.addIssue({
          code: 'custom',
          message:
            'Related item IDs must be unique and cannot reference the item itself',
          path: ['relatedItemIds', index],
        });
      }
      relatedItemIds.add(relatedItemId);
    }
    const attachmentIds = new Set<string>();
    for (const [index, attachmentId] of item.attachmentIds.entries()) {
      if (attachmentIds.has(attachmentId)) {
        context.addIssue({
          code: 'custom',
          message: 'Attachment IDs must be unique',
          path: ['attachmentIds', index],
        });
      }
      attachmentIds.add(attachmentId);
    }

    for (const [collectionName, values] of [
      ['templateValues', item.templateValues],
      ['itemValues', item.itemValues],
    ] as const) {
      for (const [valueIndex, stored] of values.entries()) {
        for (const reference of referencedEntities(stored.value)) {
          const valid =
            reference.kind === 'item-reference'
              ? relatedItemIds.has(reference.itemId)
              : attachmentIds.has(reference.attachmentId);
          if (!valid) {
            context.addIssue({
              code: 'custom',
              message: 'Field references must resolve through the item reference lists',
              path: [collectionName, valueIndex, 'value'],
            });
          }
        }
      }
    }

    const activeKeys = new Set([
      ...item.templateValues.map(({ stableKey }) => stableKey),
      ...item.itemFields.map(({ stableKey }) => stableKey),
    ]);
    const sequenceIds = new Set<string>();
    for (const [index, sequence] of item.copySequences.entries()) {
      if (sequenceIds.has(sequence.id)) {
        context.addIssue({
          code: 'custom',
          message: 'Copy sequence IDs must be unique',
          path: ['copySequences', index, 'id'],
        });
      }
      sequenceIds.add(sequence.id);
      if (sequence.fieldKeys.some((key) => !activeKeys.has(key))) {
        context.addIssue({
          code: 'custom',
          message: 'Copy sequences may contain only active stable field keys',
          path: ['copySequences', index, 'fieldKeys'],
        });
      }
    }
  });

export const itemPayloadSchema = itemPayloadV1Schema;

function referencedEntities(
  value: ActiveFieldValue,
): readonly (
  | Readonly<{ kind: 'item-reference'; itemId: string }>
  | Readonly<{ kind: 'attachment-reference'; attachmentId: string }>
)[] {
  if (value.state !== 'present') return [];
  const scalars =
    value.content.cardinality === 'single'
      ? [value.content.value]
      : value.content.elements.map(({ value: scalar }) => scalar);
  const references: (
    | Readonly<{ kind: 'item-reference'; itemId: string }>
    | Readonly<{ kind: 'attachment-reference'; attachmentId: string }>
  )[] = [];
  for (const scalar of scalars) {
    if (scalar.kind === 'item-reference') references.push(scalar);
    if (scalar.kind === 'attachment-reference') references.push(scalar);
  }
  return references;
}

export const vaultPreferencesSchema = z
  .object({
    productLabel: nonEmptyTextSchema,
    executableName: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[A-Za-z0-9_-]+$/),
    clipboardClearSeconds: z.number().int().min(1).max(3_600),
    revealHideSeconds: z.number().int().min(1).max(3_600),
    historyRetentionDays: z.number().int().min(1).max(36_500),
    telemetryEnabled: z.literal(false),
  })
  .strict();

export type GroupPayload = z.infer<typeof groupPayloadSchema>;
export type CopySequence = z.infer<typeof copySequenceSchema>;
export type ItemPayloadV1 = z.infer<typeof itemPayloadV1Schema>;
export type ItemPayload = ItemPayloadV1;
export type VaultPreferences = z.infer<typeof vaultPreferencesSchema>;
