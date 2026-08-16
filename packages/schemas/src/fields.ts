import { z } from 'zod';

import {
  attachmentIdSchema,
  fieldIdSchema,
  itemIdSchema,
  templateIdSchema,
} from './identifiers.js';
import {
  encryptedTextSchema,
  nonEmptyTextSchema,
  secretValueSchema,
  sortOrderSchema,
  templateVersionSchema,
  timestampSchema,
} from './primitives.js';

export const fieldTypeSchema = z.enum([
  'text',
  'secret',
  'username',
  'email',
  'url',
  'phone',
  'number',
  'boolean',
  'date',
  'datetime',
  'multiline',
  'secure-multiline',
  'api-key',
  'access-token',
  'refresh-token',
  'client-id',
  'client-secret',
  'connection-string',
  'host',
  'port',
  'database-name',
  'private-key',
  'public-key',
  'certificate',
  'totp-secret',
  'recovery-code-list',
  'json',
  'select',
  'multi-select',
  'tags',
  'environment-map',
  'command-snippet',
  'attachment',
  'item-reference',
  'custom',
]);

const sensitiveFieldTypes = new Set<z.infer<typeof fieldTypeSchema>>([
  'secret',
  'api-key',
  'access-token',
  'refresh-token',
  'client-secret',
  'connection-string',
  'private-key',
  'totp-secret',
  'recovery-code-list',
  'secure-multiline',
]);

export function isSensitiveFieldType(
  fieldType: z.infer<typeof fieldTypeSchema>,
): boolean {
  return sensitiveFieldTypes.has(fieldType);
}

export const copyPolicySchema = z.enum(['never', 'allowed', 'confirm']);
export const revealPolicySchema = z.enum(['never', 'timed', 'confirm']);
export const reauthenticationPolicySchema = z.enum(['never', 'after-lock', 'always']);
export const exportPolicySchema = z.enum(['never', 'encrypted-only', 'guarded']);

/** Closed, linear-time validators. User-supplied JavaScript regular expressions are forbidden. */
export const namedValidationSchema = z.enum([
  'ascii',
  'lowercase-ascii',
  'alphanumeric-ascii',
  'hostname',
  'ipv4',
  'base64url',
]);

export const validationRulesSchema = z
  .object({
    minLength: z.number().int().nonnegative().optional(),
    maxLength: z.number().int().positive().max(1_048_576).optional(),
    namedValidation: namedValidationSchema.optional(),
    min: z.number().optional(),
    max: z.number().optional(),
    allowedSchemes: z.array(z.string().min(1).max(32)).max(16).optional(),
  })
  .strict()
  .superRefine((rules, context) => {
    if (
      rules.minLength !== undefined &&
      rules.maxLength !== undefined &&
      rules.minLength > rules.maxLength
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Minimum length cannot exceed maximum length',
        path: ['minLength'],
      });
    }
    if (rules.min !== undefined && rules.max !== undefined && rules.min > rules.max) {
      context.addIssue({
        code: 'custom',
        message: 'Minimum cannot exceed maximum',
        path: ['min'],
      });
    }
  });

export const selectOptionSchema = z
  .object({
    value: z.string().min(1).max(128),
    label: nonEmptyTextSchema,
  })
  .strict();

const opaqueFieldValueIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._~-]*$/, 'Must be an opaque identifier');

export const fieldValueElementIdSchema =
  opaqueFieldValueIdSchema.brand<'FieldValueElementId'>();

const nonEmptyFieldTextSchema = encryptedTextSchema.refine(
  (value) => value.length > 0,
  { error: 'Present text values cannot be empty' },
);
const nonEmptySecretValueSchema = secretValueSchema.refine(
  (value) => value.length > 0,
  { error: 'Present secret values cannot be empty' },
);

export const fieldScalarValueSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('text'), value: nonEmptyFieldTextSchema }).strict(),
  z.object({ kind: z.literal('secret'), value: nonEmptySecretValueSchema }).strict(),
  z.object({ kind: z.literal('number'), value: z.number() }).strict(),
  z.object({ kind: z.literal('boolean'), value: z.boolean() }).strict(),
  z.object({ kind: z.literal('item-reference'), itemId: itemIdSchema }).strict(),
  z
    .object({
      kind: z.literal('attachment-reference'),
      attachmentId: attachmentIdSchema,
    })
    .strict(),
  z
    .object({
      kind: z.literal('environment-entry'),
      key: z.string().min(1).max(256),
      value: z.discriminatedUnion('classification', [
        z
          .object({
            classification: z.literal('text'),
            value: nonEmptyFieldTextSchema,
          })
          .strict(),
        z
          .object({
            classification: z.literal('secret'),
            value: nonEmptySecretValueSchema,
          })
          .strict(),
      ]),
    })
    .strict(),
]);

export const fieldValueElementLifecycleSchema = z.discriminatedUnion('status', [
  z
    .object({
      version: z.literal(1),
      status: z.literal('available'),
      usedAt: z.undefined().optional(),
    })
    .strict(),
  z
    .object({
      version: z.literal(1),
      status: z.literal('used'),
      usedAt: timestampSchema,
    })
    .strict(),
]);

export const fieldValueElementSchema = z
  .object({
    id: fieldValueElementIdSchema,
    value: fieldScalarValueSchema,
    lifecycle: fieldValueElementLifecycleSchema,
  })
  .strict();

export const fieldValueContentSchema = z
  .discriminatedUnion('cardinality', [
    z
      .object({
        cardinality: z.literal('single'),
        value: fieldScalarValueSchema,
      })
      .strict(),
    z
      .object({
        cardinality: z.literal('multiple'),
        elements: z.array(fieldValueElementSchema).min(1).max(10_000),
      })
      .strict()
      .superRefine((content, context) => {
        const ids = new Set<string>();
        const environmentKeys = new Set<string>();
        for (const [index, element] of content.elements.entries()) {
          if (ids.has(element.id)) {
            context.addIssue({
              code: 'custom',
              message: 'Repeatable field element IDs must be unique',
              path: ['elements', index, 'id'],
            });
          }
          ids.add(element.id);
          if (element.value.kind === 'environment-entry') {
            if (environmentKeys.has(element.value.key)) {
              context.addIssue({
                code: 'custom',
                message: 'Environment entry keys must be unique',
                path: ['elements', index, 'value', 'key'],
              });
            }
            environmentKeys.add(element.value.key);
          }
        }
      }),
  ])
  .refine(
    (value) => new TextEncoder().encode(JSON.stringify(value)).byteLength <= 4_194_304,
    { error: 'Field value content exceeds the aggregate size limit' },
  );

export const missingFieldValueSchema = z
  .object({ version: z.literal(1), state: z.literal('missing') })
  .strict();
export const emptyFieldValueSchema = z
  .object({ version: z.literal(1), state: z.literal('empty') })
  .strict();
export const inapplicableFieldValueSchema = z
  .object({
    version: z.literal(1),
    state: z.literal('inapplicable'),
    reason: z.string().trim().min(1).max(256).optional(),
  })
  .strict();
export const unreadableFieldValueSchema = z
  .object({
    version: z.literal(1),
    state: z.literal('unreadable'),
    reason: z.enum([
      'unsupported-version',
      'invalid-encoding',
      'decryption-failed',
      'reference-unavailable',
    ]),
  })
  .strict();
export const presentFieldValueSchema = z
  .object({
    version: z.literal(1),
    state: z.literal('present'),
    content: fieldValueContentSchema,
  })
  .strict();
export const activeFieldValueSchema = z.discriminatedUnion('state', [
  missingFieldValueSchema,
  emptyFieldValueSchema,
  presentFieldValueSchema,
  inapplicableFieldValueSchema,
  unreadableFieldValueSchema,
]);
export const orphanedFieldValueSchema = z
  .object({
    version: z.literal(1),
    state: z.literal('orphaned'),
    originalValue: activeFieldValueSchema,
  })
  .strict();

export const fieldValueSchema = z
  .discriminatedUnion('state', [
    missingFieldValueSchema,
    emptyFieldValueSchema,
    presentFieldValueSchema,
    orphanedFieldValueSchema,
    inapplicableFieldValueSchema,
    unreadableFieldValueSchema,
  ])
  .refine(
    (value) => new TextEncoder().encode(JSON.stringify(value)).byteLength <= 4_194_304,
    { error: 'Field value exceeds the aggregate size limit' },
  );

export const stableFieldKeySchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/, 'Invalid stable field key');

export const fieldDefinitionSchema = z
  .object({
    id: fieldIdSchema,
    stableKey: stableFieldKeySchema,
    label: nonEmptyTextSchema,
    description: z.string().trim().max(1_024).optional(),
    type: fieldTypeSchema,
    required: z.boolean(),
    sensitive: z.boolean(),
    repeatable: z.boolean(),
    copyable: z.boolean(),
    searchableLocally: z.boolean(),
    showInPreview: z.boolean(),
    defaultValue: presentFieldValueSchema.optional(),
    placeholder: z.string().max(256).optional(),
    validationRules: validationRulesSchema.optional(),
    selectOptions: z.array(selectOptionSchema).max(1_000).optional(),
    environmentVariableName: z
      .string()
      .regex(/^[A-Za-z_][A-Za-z0-9_]*$/)
      .max(256)
      .optional(),
    copyPolicy: copyPolicySchema,
    revealPolicy: revealPolicySchema,
    reauthenticationPolicy: reauthenticationPolicySchema,
    exportPolicy: exportPolicySchema,
    sortOrder: sortOrderSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((field, context) => {
    if (field.copyable !== (field.copyPolicy !== 'never')) {
      context.addIssue({
        code: 'custom',
        message: 'Copyable and copy policy must describe one canonical state',
        path: ['copyPolicy'],
      });
    }
    if (field.sensitive && field.defaultValue !== undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Sensitive fields cannot define default values',
        path: ['defaultValue'],
      });
    }
    if (isSensitiveFieldType(field.type) && !field.sensitive) {
      context.addIssue({
        code: 'custom',
        message: 'This field type must be sensitive',
        path: ['sensitive'],
      });
    }
    if (field.sensitive && field.showInPreview) {
      context.addIssue({
        code: 'custom',
        message: 'Sensitive fields cannot appear in list previews',
        path: ['showInPreview'],
      });
    }
    if (field.sensitive && field.reauthenticationPolicy === 'never') {
      context.addIssue({
        code: 'custom',
        message: 'Sensitive fields require reauthentication after locking',
        path: ['reauthenticationPolicy'],
      });
    }
    if (!field.sensitive && field.revealPolicy !== 'never') {
      context.addIssue({
        code: 'custom',
        message: 'Non-sensitive fields do not use reveal policies',
        path: ['revealPolicy'],
      });
    }
    const isSelect = field.type === 'select' || field.type === 'multi-select';
    if (isSelect && (!field.selectOptions || field.selectOptions.length === 0)) {
      context.addIssue({
        code: 'custom',
        message: 'Select fields require at least one option',
        path: ['selectOptions'],
      });
    }
    if (!isSelect && field.selectOptions !== undefined) {
      context.addIssue({
        code: 'custom',
        message: 'Only select fields may define options',
        path: ['selectOptions'],
      });
    }
    if (
      field.defaultValue !== undefined &&
      !fieldValueMatchesDefinition(field, field.defaultValue)
    ) {
      context.addIssue({
        code: 'custom',
        message: 'A default value must satisfy its field definition',
        path: ['defaultValue'],
      });
    }
  });

export const storedFieldValueSchema = z
  .object({
    fieldId: fieldIdSchema,
    stableKey: stableFieldKeySchema,
    value: activeFieldValueSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const archivedFieldValueSchema = z
  .object({
    definition: fieldDefinitionSchema,
    value: orphanedFieldValueSchema,
    sourceTemplateId: templateIdSchema,
    sourceTemplateVersion: templateVersionSchema,
    archivedAt: timestampSchema,
    reason: z.enum(['template-field-removed', 'type-conversion', 'user-archived']),
  })
  .strict()
  .superRefine((archived, context) => {
    if (
      !fieldValueMatchesDefinition(archived.definition, archived.value.originalValue)
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Archived values must preserve a state valid for their definition',
        path: ['value', 'originalValue'],
      });
    }
  });

export const itemReferenceSchema = z
  .object({
    itemId: itemIdSchema,
    relationship: z.string().trim().min(1).max(128),
  })
  .strict();

const collectionFieldTypes = new Set<FieldType>([
  'multi-select',
  'tags',
  'recovery-code-list',
  'environment-map',
]);

/**
 * Report whether a definition stores its value as repeatable elements.
 *
 * Both an explicitly repeatable field and a collection field type hold
 * elements, so callers that write a single scalar must consult this first.
 */
export function fieldExpectsMultipleValues(field: FieldDefinition): boolean {
  return field.repeatable || collectionFieldTypes.has(field.type);
}

export function fieldValueMatchesDefinition(
  field: FieldDefinition,
  value: FieldValue,
): boolean {
  if (value.state === 'orphaned') return false;
  if (value.state !== 'present') return !field.required;

  const expectsMultiple = fieldExpectsMultipleValues(field);
  if (expectsMultiple !== (value.content.cardinality === 'multiple')) return false;
  const elements =
    value.content.cardinality === 'multiple' ? value.content.elements : undefined;
  if (
    field.type !== 'recovery-code-list' &&
    elements?.some(({ lifecycle }) => lifecycle.status === 'used') === true
  ) {
    return false;
  }
  const candidates =
    value.content.cardinality === 'multiple'
      ? value.content.elements.map(({ value: candidate }) => candidate)
      : [value.content.value];
  return candidates.every(
    (candidate) =>
      singleValueMatchesType(field, candidate) && valueMatchesRules(field, candidate),
  );
}

function singleValueMatchesType(
  field: FieldDefinition,
  value: FieldScalarValue,
): boolean {
  switch (field.type) {
    case 'number':
      return value.kind === 'number';
    case 'port':
      return (
        value.kind === 'number' &&
        Number.isInteger(value.value) &&
        value.value >= 1 &&
        value.value <= 65_535
      );
    case 'boolean':
      return value.kind === 'boolean';
    case 'attachment':
      return value.kind === 'attachment-reference';
    case 'item-reference':
      return value.kind === 'item-reference';
    case 'environment-map':
      return (
        value.kind === 'environment-entry' &&
        value.value.classification === (field.sensitive ? 'secret' : 'text')
      );
    case 'json':
      if (!isExpectedTextKind(field, value)) return false;
      try {
        JSON.parse(value.value);
        return true;
      } catch {
        return false;
      }
    case 'select':
    case 'multi-select':
      return isExpectedTextKind(field, value) && selectValuesMatch(field, value.value);
    case 'email':
      return isExpectedTextKind(field, value) && isSimpleEmail(value.value);
    case 'url':
      if (!isExpectedTextKind(field, value)) return false;
      try {
        const parsed = new URL(value.value);
        const schemes = field.validationRules?.allowedSchemes;
        return schemes === undefined || schemes.includes(parsed.protocol.slice(0, -1));
      } catch {
        return false;
      }
    default:
      return isExpectedTextKind(field, value);
  }
}

function isExpectedTextKind(
  field: FieldDefinition,
  value: FieldScalarValue,
): value is Extract<FieldScalarValue, { kind: 'text' | 'secret' }> {
  return field.sensitive ? value.kind === 'secret' : value.kind === 'text';
}

function valueMatchesRules(field: FieldDefinition, value: FieldScalarValue): boolean {
  const rules = field.validationRules;
  if (rules === undefined) return true;
  if (value.kind === 'text' || value.kind === 'secret') {
    if (rules.minLength !== undefined && value.value.length < rules.minLength)
      return false;
    if (rules.maxLength !== undefined && value.value.length > rules.maxLength)
      return false;
    if (
      rules.namedValidation !== undefined &&
      !matchesNamedValidation(rules.namedValidation, value.value)
    )
      return false;
  }
  if (value.kind === 'number') {
    if (rules.min !== undefined && value.value < rules.min) return false;
    if (rules.max !== undefined && value.value > rules.max) return false;
  }
  return true;
}

export function matchesNamedValidation(
  validation: z.infer<typeof namedValidationSchema>,
  value: string,
): boolean {
  switch (validation) {
    case 'ascii':
      return everyCodeUnit(value, (code) => code <= 0x7f);
    case 'lowercase-ascii':
      return everyCodeUnit(
        value,
        (code) =>
          (code >= 0x61 && code <= 0x7a) ||
          (code >= 0x30 && code <= 0x39) ||
          code === 0x2d ||
          code === 0x5f,
      );
    case 'alphanumeric-ascii':
      return everyCodeUnit(
        value,
        (code) =>
          (code >= 0x30 && code <= 0x39) ||
          (code >= 0x41 && code <= 0x5a) ||
          (code >= 0x61 && code <= 0x7a),
      );
    case 'hostname':
      return isHostname(value);
    case 'ipv4':
      return isIpv4(value);
    case 'base64url':
      return everyCodeUnit(
        value,
        (code) =>
          (code >= 0x30 && code <= 0x39) ||
          (code >= 0x41 && code <= 0x5a) ||
          (code >= 0x61 && code <= 0x7a) ||
          code === 0x2d ||
          code === 0x5f,
      );
  }
}

function everyCodeUnit(value: string, predicate: (code: number) => boolean): boolean {
  if (value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    if (!predicate(value.charCodeAt(index))) return false;
  }
  return true;
}

function isHostname(value: string): boolean {
  if (value.length === 0 || value.length > 253) return false;
  const labels = value.split('.');
  return labels.every((label) => {
    if (label.length === 0 || label.length > 63) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
    return everyCodeUnit(
      label,
      (code) =>
        (code >= 0x30 && code <= 0x39) ||
        (code >= 0x41 && code <= 0x5a) ||
        (code >= 0x61 && code <= 0x7a) ||
        code === 0x2d,
    );
  });
}

function isIpv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (part.length === 0 || part.length > 3) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    if (!everyCodeUnit(part, (code) => code >= 0x30 && code <= 0x39)) return false;
    const octet = Number(part);
    return octet >= 0 && octet <= 255;
  });
}

function isSimpleEmail(value: string): boolean {
  const at = value.indexOf('@');
  if (at <= 0 || at !== value.lastIndexOf('@')) return false;
  const domain = value.slice(at + 1);
  return domain.includes('.') && !value.includes(' ') && !value.includes('\t');
}

function selectValuesMatch(field: FieldDefinition, value: string): boolean {
  return field.selectOptions?.some((option) => option.value === value) === true;
}

export type FieldType = z.infer<typeof fieldTypeSchema>;
export type FieldValueElementId = z.infer<typeof fieldValueElementIdSchema>;
export type FieldValueElementLifecycle = z.infer<
  typeof fieldValueElementLifecycleSchema
>;
export type FieldValueElement = z.infer<typeof fieldValueElementSchema>;
export type FieldScalarValue = z.infer<typeof fieldScalarValueSchema>;
export type FieldValueContent = z.infer<typeof fieldValueContentSchema>;
export type PresentFieldValue = z.infer<typeof presentFieldValueSchema>;
export type OrphanedFieldValue = z.infer<typeof orphanedFieldValueSchema>;
export type ActiveFieldValue = z.infer<typeof activeFieldValueSchema>;
export type FieldValue = z.infer<typeof fieldValueSchema>;
export type FieldDefinition = z.infer<typeof fieldDefinitionSchema>;
export type StoredFieldValue = z.infer<typeof storedFieldValueSchema>;
export type ArchivedFieldValue = z.infer<typeof archivedFieldValueSchema>;
