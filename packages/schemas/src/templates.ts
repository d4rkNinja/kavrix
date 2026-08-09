import { z } from 'zod';

import {
  auditEventIdSchema,
  fieldIdSchema,
  itemIdSchema,
  templateIdSchema,
  templateMigrationIdSchema,
} from './identifiers.js';
import { fieldDefinitionSchema, fieldTypeSchema } from './fields.js';
import {
  nonEmptyTextSchema,
  recordRevisionSchema,
  sortOrderSchema,
  templateVersionSchema,
  timestampSchema,
} from './primitives.js';

export const builtInTemplateKeySchema = z.enum([
  'email',
  'database',
  'api-oauth',
  'server-ssh',
  'cloud-provider',
  'git-source-control',
  'application-environment',
  'software-license',
  'secure-note',
  'custom',
]);

export const groupTemplateSchema = z
  .object({
    id: templateIdSchema,
    name: nonEmptyTextSchema,
    description: z.string().trim().max(1_024).optional(),
    builtInKey: builtInTemplateKeySchema.optional(),
    version: templateVersionSchema,
    fields: z.array(fieldDefinitionSchema).max(1_000),
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((template, context) => {
    const ids = new Set<string>();
    const keys = new Set<string>();
    const orders = new Set<number>();
    for (const [index, field] of template.fields.entries()) {
      if (ids.has(field.id)) {
        context.addIssue({
          code: 'custom',
          message: 'Field IDs must be unique',
          path: ['fields', index, 'id'],
        });
      }
      if (keys.has(field.stableKey)) {
        context.addIssue({
          code: 'custom',
          message: 'Stable field keys must be unique',
          path: ['fields', index, 'stableKey'],
        });
      }
      if (orders.has(field.sortOrder)) {
        context.addIssue({
          code: 'custom',
          message: 'Field sort orders must be unique',
          path: ['fields', index, 'sortOrder'],
        });
      }
      ids.add(field.id);
      keys.add(field.stableKey);
      orders.add(field.sortOrder);
    }
  });

const migrationStepBaseSchema = z.object({
  affectedItemCount: z.number().int().nonnegative(),
  requiresConfirmation: z.boolean(),
});

export const templateMigrationStepSchema = z.discriminatedUnion('kind', [
  migrationStepBaseSchema.extend({
    kind: z.literal('add-field'),
    field: fieldDefinitionSchema,
  }),
  migrationStepBaseSchema.extend({
    kind: z.literal('restore-field'),
    field: fieldDefinitionSchema,
  }),
  migrationStepBaseSchema.extend({
    kind: z.literal('rename-label'),
    fieldId: fieldIdSchema,
    fromLabel: nonEmptyTextSchema,
    toLabel: nonEmptyTextSchema,
  }),
  migrationStepBaseSchema.extend({
    kind: z.literal('reorder-field'),
    fieldId: fieldIdSchema,
    fromSortOrder: sortOrderSchema,
    toSortOrder: sortOrderSchema,
  }),
  migrationStepBaseSchema.extend({
    kind: z.literal('change-required'),
    fieldId: fieldIdSchema,
    fromRequired: z.boolean(),
    toRequired: z.boolean(),
    missingValueCount: z.number().int().nonnegative(),
  }),
  migrationStepBaseSchema.extend({
    kind: z.literal('update-field-policy'),
    fieldId: fieldIdSchema,
    fromField: fieldDefinitionSchema,
    toField: fieldDefinitionSchema,
  }),
  migrationStepBaseSchema.extend({
    kind: z.literal('convert-type'),
    fieldId: fieldIdSchema,
    fromField: fieldDefinitionSchema,
    toField: fieldDefinitionSchema,
    fromType: fieldTypeSchema,
    toType: fieldTypeSchema,
    strategy: z.enum([
      'identity',
      'number-to-string',
      'string-to-number',
      'boolean-to-string',
      'string-to-boolean',
      'archive-incompatible',
    ]),
    incompatibleValueCount: z.number().int().nonnegative(),
  }),
  migrationStepBaseSchema.extend({
    kind: z.literal('archive-field'),
    field: fieldDefinitionSchema,
  }),
]);

export const templateMigrationPlanSchema = z
  .object({
    id: templateMigrationIdSchema,
    fromVersion: templateVersionSchema,
    toVersion: templateVersionSchema,
    sourceTemplate: groupTemplateSchema,
    targetTemplate: groupTemplateSchema,
    itemSnapshots: z
      .array(
        z
          .object({
            itemId: itemIdSchema,
            revision: recordRevisionSchema,
          })
          .strict(),
      )
      .max(1_000_000),
    steps: z.array(templateMigrationStepSchema).max(4_000),
    status: z.enum(['pending', 'running', 'completed']),
    nextItemIndex: z.number().int().nonnegative(),
    totalItems: z.number().int().nonnegative(),
    auditEventId: auditEventIdSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict()
  .superRefine((plan, context) => {
    if (plan.toVersion <= plan.fromVersion) {
      context.addIssue({
        code: 'custom',
        message: 'Migration target version must be newer',
        path: ['toVersion'],
      });
    }
    if (plan.targetTemplate.version !== plan.toVersion) {
      context.addIssue({
        code: 'custom',
        message: 'Target template version must match the migration',
        path: ['targetTemplate', 'version'],
      });
    }
    if (plan.sourceTemplate.version !== plan.fromVersion) {
      context.addIssue({
        code: 'custom',
        message: 'Source template version must match the migration',
        path: ['sourceTemplate', 'version'],
      });
    }
    if (plan.sourceTemplate.id !== plan.targetTemplate.id) {
      context.addIssue({
        code: 'custom',
        message: 'A migration cannot change template identity',
        path: ['targetTemplate', 'id'],
      });
    }
    if (plan.itemSnapshots.length !== plan.totalItems) {
      context.addIssue({
        code: 'custom',
        message: 'Migration item snapshots must match the item count',
        path: ['itemSnapshots'],
      });
    }
    const snapshotIds = new Set<string>();
    for (const [index, snapshot] of plan.itemSnapshots.entries()) {
      if (snapshotIds.has(snapshot.itemId)) {
        context.addIssue({
          code: 'custom',
          message: 'Migration item snapshots must have unique item IDs',
          path: ['itemSnapshots', index, 'itemId'],
        });
      }
      snapshotIds.add(snapshot.itemId);
    }
    if (plan.nextItemIndex > plan.totalItems) {
      context.addIssue({
        code: 'custom',
        message: 'Migration checkpoint exceeds item count',
        path: ['nextItemIndex'],
      });
    }
    if (plan.status === 'completed' && plan.nextItemIndex !== plan.totalItems) {
      context.addIssue({
        code: 'custom',
        message: 'Completed migration must include every item',
        path: ['status'],
      });
    }
  });

export type BuiltInTemplateKey = z.infer<typeof builtInTemplateKeySchema>;
export type GroupTemplate = z.infer<typeof groupTemplateSchema>;
export type TemplateMigrationStep = z.infer<typeof templateMigrationStepSchema>;
export type TemplateMigrationPlan = z.infer<typeof templateMigrationPlanSchema>;
