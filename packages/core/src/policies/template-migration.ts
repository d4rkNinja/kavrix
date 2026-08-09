import {
  activeFieldValueSchema,
  itemPayloadSchema,
  secretValueSchema,
  templateMigrationPlanSchema,
  type ActiveFieldValue,
  type FieldDefinition,
  type FieldScalarValue,
  type FieldType,
  type ItemPayload,
  type StoredFieldValue,
  type TemplateMigrationPlan,
  type TemplateMigrationStep,
  type GroupTemplate,
  type AuditEventId,
  type TemplateMigrationId,
} from '@kavrix/schemas';

import { SchemaMigrationError, ValidationError } from '../errors.js';
import { validateFieldValue, validateItemAgainstTemplate } from './field-values.js';

export type PlanTemplateMigrationInput = Readonly<{
  migrationId: TemplateMigrationId;
  auditEventId: AuditEventId;
  fromTemplate: GroupTemplate;
  toTemplate: GroupTemplate;
  items: readonly ItemPayload[];
  timestamp: string;
}>;

export type MigrationBatchResult = Readonly<{
  plan: TemplateMigrationPlan;
  items: readonly ItemPayload[];
}>;

const stringTypes = new Set<FieldType>([
  'text',
  'secret',
  'username',
  'email',
  'url',
  'phone',
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
  'database-name',
  'private-key',
  'public-key',
  'certificate',
  'totp-secret',
  'json',
  'select',
  'command-snippet',
  'attachment',
  'item-reference',
  'custom',
]);
const stringArrayTypes = new Set<FieldType>([
  'multi-select',
  'tags',
  'recovery-code-list',
]);

export function planTemplateMigration(
  input: PlanTemplateMigrationInput,
): TemplateMigrationPlan {
  const { fromTemplate, toTemplate, items } = input;
  if (toTemplate.id !== fromTemplate.id) {
    throw new SchemaMigrationError(
      'A template migration cannot change template identity.',
    );
  }
  if (toTemplate.version <= fromTemplate.version) {
    throw new SchemaMigrationError('A template migration must increase the version.');
  }
  for (const item of items) {
    validateItemAgainstTemplate(item, fromTemplate);
  }

  const oldById = new Map(fromTemplate.fields.map((field) => [field.id, field]));
  const newById = new Map(toTemplate.fields.map((field) => [field.id, field]));
  const oldByKey = new Map(
    fromTemplate.fields.map((field) => [field.stableKey, field]),
  );
  const steps: TemplateMigrationStep[] = [];

  for (const oldField of fromTemplate.fields) {
    const nextField = newById.get(oldField.id);
    if (!nextField) {
      const affectedItemCount = countActiveValues(items, oldField);
      steps.push({
        kind: 'archive-field',
        field: oldField,
        affectedItemCount,
        requiresConfirmation: affectedItemCount > 0,
      });
      continue;
    }
    if (nextField.stableKey !== oldField.stableKey) {
      throw new SchemaMigrationError('A field stable key cannot be changed.');
    }

    const affectedItemCount = countActiveValues(items, oldField);
    if (oldField.label !== nextField.label) {
      steps.push({
        kind: 'rename-label',
        fieldId: oldField.id,
        fromLabel: oldField.label,
        toLabel: nextField.label,
        affectedItemCount,
        requiresConfirmation: false,
      });
    }
    if (oldField.sortOrder !== nextField.sortOrder) {
      steps.push({
        kind: 'reorder-field',
        fieldId: oldField.id,
        fromSortOrder: oldField.sortOrder,
        toSortOrder: nextField.sortOrder,
        affectedItemCount,
        requiresConfirmation: false,
      });
    }
    if (oldField.required !== nextField.required) {
      const missingValueCount = nextField.required
        ? items.filter(
            (item) => findActiveValue(item, oldField)?.value.state !== 'present',
          ).length
        : 0;
      steps.push({
        kind: 'change-required',
        fieldId: oldField.id,
        fromRequired: oldField.required,
        toRequired: nextField.required,
        missingValueCount,
        affectedItemCount: items.length,
        requiresConfirmation: missingValueCount > 0,
      });
    }
    if (oldField.type !== nextField.type) {
      const strategy = conversionStrategy(oldField.type, nextField.type);
      const incompatibleValueCount = items.reduce((count, item) => {
        const value = findActiveValue(item, oldField)?.value;
        return value !== undefined &&
          !convertAndValidate(value, strategy, nextField).success
          ? count + 1
          : count;
      }, 0);
      steps.push({
        kind: 'convert-type',
        fieldId: oldField.id,
        fromField: oldField,
        toField: nextField,
        fromType: oldField.type,
        toType: nextField.type,
        strategy,
        incompatibleValueCount,
        affectedItemCount,
        requiresConfirmation:
          strategy === 'archive-incompatible' || incompatibleValueCount > 0,
      });
    }
    if (fieldPolicyFingerprint(oldField) !== fieldPolicyFingerprint(nextField)) {
      const weakensProtection = fieldProtectionWeakens(oldField, nextField);
      steps.push({
        kind: 'update-field-policy',
        fieldId: oldField.id,
        fromField: oldField,
        toField: nextField,
        affectedItemCount,
        requiresConfirmation: weakensProtection,
      });
    }
  }

  for (const newField of toTemplate.fields) {
    if (oldById.has(newField.id)) continue;
    const previousWithKey = oldByKey.get(newField.stableKey);
    if (previousWithKey) {
      throw new SchemaMigrationError(
        'A stable field key cannot be reassigned to a different field ID.',
      );
    }
    const archivesWithReusedIdentity = items.flatMap((item) =>
      item.archivedFieldValues.filter(
        (entry) =>
          entry.definition.id === newField.id ||
          entry.definition.stableKey === newField.stableKey,
      ),
    );
    if (
      archivesWithReusedIdentity.some(
        (entry) =>
          entry.definition.id !== newField.id ||
          entry.definition.stableKey !== newField.stableKey ||
          entry.definition.type !== newField.type ||
          entry.sourceTemplateId !== toTemplate.id ||
          entry.sourceTemplateVersion >= toTemplate.version,
      )
    ) {
      throw new SchemaMigrationError(
        'An archived field ID cannot be restored under different field provenance.',
      );
    }
    const archivedCount = items.filter((item) =>
      item.archivedFieldValues.some(
        (entry) =>
          entry.definition.id === newField.id &&
          entry.definition.stableKey === newField.stableKey &&
          entry.definition.type === newField.type &&
          entry.sourceTemplateId === toTemplate.id &&
          entry.sourceTemplateVersion < toTemplate.version,
      ),
    ).length;
    steps.push({
      kind: archivedCount > 0 ? 'restore-field' : 'add-field',
      field: newField,
      affectedItemCount: archivedCount > 0 ? archivedCount : items.length,
      requiresConfirmation:
        newField.required &&
        newField.defaultValue === undefined &&
        archivedCount < items.length,
    });
  }

  return templateMigrationPlanSchema.parse({
    id: input.migrationId,
    fromVersion: fromTemplate.version,
    toVersion: toTemplate.version,
    sourceTemplate: fromTemplate,
    targetTemplate: toTemplate,
    itemSnapshots: items.map((item) => ({ itemId: item.id, revision: item.revision })),
    steps,
    status: 'pending',
    nextItemIndex: 0,
    totalItems: items.length,
    auditEventId: input.auditEventId,
    createdAt: input.timestamp,
    updatedAt: input.timestamp,
  });
}

export function applyTemplateMigrationBatch(
  plan: TemplateMigrationPlan,
  items: readonly ItemPayload[],
  batchSize: number,
  timestamp: string,
  confirmRiskyChanges = false,
): MigrationBatchResult {
  if (!Number.isSafeInteger(batchSize) || batchSize <= 0) {
    throw new ValidationError('Migration batch size must be a positive integer.');
  }
  if (items.length !== plan.totalItems) {
    throw new SchemaMigrationError('Migration item count changed after planning.');
  }
  for (const [index, item] of items.entries()) {
    const snapshot = plan.itemSnapshots[index];
    const expectedRevision =
      snapshot?.revision === undefined
        ? undefined
        : snapshot.revision + (index < plan.nextItemIndex ? 1 : 0);
    if (snapshot?.itemId !== item.id || item.revision !== expectedRevision) {
      throw new SchemaMigrationError(
        'Migration items changed or were reordered after planning.',
      );
    }
  }
  if (plan.status === 'completed') return { plan, items };
  if (plan.steps.some((step) => step.requiresConfirmation) && !confirmRiskyChanges) {
    throw new SchemaMigrationError(
      'The migration contains changes that require explicit confirmation.',
    );
  }

  const end = Math.min(plan.nextItemIndex + batchSize, items.length);
  const updatedItems = [...items];
  for (let index = plan.nextItemIndex; index < end; index += 1) {
    const item = items[index];
    if (item === undefined)
      throw new SchemaMigrationError('Migration checkpoint is invalid.');
    updatedItems[index] = applyStepsToItem(
      item,
      plan.steps,
      plan.sourceTemplate,
      plan.targetTemplate,
      timestamp,
    );
  }
  const completed = end === items.length;
  const updatedPlan = templateMigrationPlanSchema.parse({
    ...plan,
    status: completed ? 'completed' : 'running',
    nextItemIndex: end,
    updatedAt: timestamp,
  });
  return { plan: updatedPlan, items: updatedItems };
}

function applyStepsToItem(
  item: ItemPayload,
  steps: readonly TemplateMigrationStep[],
  sourceTemplate: GroupTemplate,
  targetTemplate: GroupTemplate,
  timestamp: string,
): ItemPayload {
  let templateValues = [...item.templateValues];
  let archivedFieldValues = [...item.archivedFieldValues];

  for (const step of steps) {
    if (step.kind === 'archive-field') {
      const entry = templateValues.find((value) => value.fieldId === step.field.id);
      if (!entry) continue;
      const existingArchive = archivedFieldValues.find(
        (archived) =>
          archived.definition.id === step.field.id ||
          archived.definition.stableKey === step.field.stableKey,
      );
      if (existingArchive !== undefined) {
        throw new SchemaMigrationError(
          'An active field cannot overwrite an existing archived value.',
        );
      }
      archivedFieldValues.push({
        definition: step.field,
        value: {
          version: 1,
          state: 'orphaned',
          originalValue: entry.value,
        },
        sourceTemplateId: sourceTemplate.id,
        sourceTemplateVersion: sourceTemplate.version,
        archivedAt: timestamp,
        reason: 'template-field-removed',
      });
      templateValues = templateValues.filter(
        (value) => value.fieldId !== step.field.id,
      );
      continue;
    }

    if (step.kind === 'restore-field') {
      const archived = archivedFieldValues.find(
        (value) =>
          value.definition.id === step.field.id &&
          value.definition.stableKey === step.field.stableKey &&
          value.definition.type === step.field.type &&
          value.sourceTemplateId === targetTemplate.id &&
          value.sourceTemplateVersion < targetTemplate.version,
      );
      if (
        archived &&
        !templateValues.some((value) => value.fieldId === step.field.id)
      ) {
        templateValues.push({
          fieldId: step.field.id,
          stableKey: step.field.stableKey,
          value: archived.value.originalValue,
          updatedAt: timestamp,
        });
        archivedFieldValues = archivedFieldValues.filter(
          (value) =>
            !(
              value.definition.id === step.field.id &&
              value.definition.stableKey === step.field.stableKey &&
              value.definition.type === step.field.type &&
              value.sourceTemplateId === targetTemplate.id &&
              value.sourceTemplateVersion < targetTemplate.version
            ),
        );
      } else if (!templateValues.some((value) => value.fieldId === step.field.id)) {
        templateValues.push({
          fieldId: step.field.id,
          stableKey: step.field.stableKey,
          value: { version: 1, state: 'missing' },
          updatedAt: timestamp,
        });
      }
      continue;
    }

    if (step.kind === 'add-field') {
      if (!templateValues.some((value) => value.fieldId === step.field.id)) {
        templateValues.push({
          fieldId: step.field.id,
          stableKey: step.field.stableKey,
          value: step.field.defaultValue ?? ({ version: 1, state: 'missing' } as const),
          updatedAt: timestamp,
        });
      }
      continue;
    }

    if (step.kind === 'update-field-policy') {
      const entryIndex = templateValues.findIndex(
        (value) => value.fieldId === step.fieldId,
      );
      const entry = templateValues[entryIndex];
      if (entry !== undefined) {
        const reclassified = reclassifyTextSensitivity(entry.value, step.toField);
        if (!fieldValueMatchesTarget(step.toField, reclassified)) {
          throw new SchemaMigrationError(
            'A policy migration cannot reinterpret the stored field value.',
          );
        }
        templateValues[entryIndex] = {
          ...entry,
          value: reclassified,
          updatedAt: timestamp,
        };
      }
      continue;
    }

    if (step.kind === 'convert-type') {
      const entryIndex = templateValues.findIndex(
        (value) => value.fieldId === step.fieldId,
      );
      if (entryIndex === -1) continue;
      const entry = templateValues[entryIndex];
      if (entry === undefined)
        throw new SchemaMigrationError('A field conversion checkpoint is invalid.');
      const converted = convertAndValidate(entry.value, step.strategy, step.toField);
      if (converted.success) {
        templateValues[entryIndex] = {
          ...entry,
          value: converted.value,
          updatedAt: timestamp,
        };
      } else {
        if (
          archivedFieldValues.some(
            (archived) =>
              archived.definition.id === step.fieldId ||
              archived.definition.stableKey === step.fromField.stableKey,
          )
        ) {
          throw new SchemaMigrationError(
            'An incompatible conversion cannot overwrite an archived value.',
          );
        }
        archivedFieldValues.push({
          definition: step.fromField,
          value: {
            version: 1,
            state: 'orphaned',
            originalValue: entry.value,
          },
          sourceTemplateId: sourceTemplate.id,
          sourceTemplateVersion: sourceTemplate.version,
          archivedAt: timestamp,
          reason: 'type-conversion',
        });
        templateValues.splice(entryIndex, 1);
      }
    }
  }

  for (const targetField of targetTemplate.fields) {
    const activeValue = templateValues.find(
      (value) => value.fieldId === targetField.id,
    );
    if (activeValue === undefined) {
      if (targetField.required) {
        throw new SchemaMigrationError(
          'A required field must be populated before the migration can complete.',
        );
      }
      continue;
    }
    try {
      validateFieldValue(targetField, activeValue.value);
    } catch {
      throw new SchemaMigrationError(
        'A migrated field value does not satisfy the target definition.',
      );
    }
  }

  const migratedItem = itemPayloadSchema.parse({
    ...item,
    templateId: targetTemplate.id,
    templateVersion: targetTemplate.version,
    templateValues,
    archivedFieldValues,
    revision: item.revision + 1,
    updatedAt: timestamp,
  });
  validateItemAgainstTemplate(migratedItem, targetTemplate);
  return migratedItem;
}

function countActiveValues(
  items: readonly ItemPayload[],
  field: FieldDefinition,
): number {
  return items.filter((item) => findActiveValue(item, field) !== undefined).length;
}

function findActiveValue(
  item: ItemPayload,
  field: FieldDefinition,
): StoredFieldValue | undefined {
  return item.templateValues.find(
    (entry) => entry.fieldId === field.id && entry.stableKey === field.stableKey,
  );
}

function fieldPolicyFingerprint(field: FieldDefinition): string {
  return JSON.stringify({
    sensitive: field.sensitive,
    repeatable: field.repeatable,
    copyable: field.copyable,
    searchableLocally: field.searchableLocally,
    showInPreview: field.showInPreview,
    environmentVariableName: field.environmentVariableName,
    copyPolicy: field.copyPolicy,
    revealPolicy: field.revealPolicy,
    reauthenticationPolicy: field.reauthenticationPolicy,
    exportPolicy: field.exportPolicy,
    validationRules: field.validationRules,
    selectOptions: field.selectOptions,
  });
}

function fieldProtectionWeakens(
  fromField: FieldDefinition,
  toField: FieldDefinition,
): boolean {
  const copyRank = { allowed: 1, confirm: 2, never: 3 } as const;
  const revealRank = { timed: 1, confirm: 2, never: 3 } as const;
  const reauthenticationRank = {
    never: 1,
    'after-lock': 2,
    always: 3,
  } as const;
  const exportRank = { guarded: 1, 'encrypted-only': 2, never: 3 } as const;
  return (
    (fromField.sensitive && !toField.sensitive) ||
    (!fromField.copyable && toField.copyable) ||
    copyRank[toField.copyPolicy] < copyRank[fromField.copyPolicy] ||
    (fromField.sensitive &&
      toField.sensitive &&
      revealRank[toField.revealPolicy] < revealRank[fromField.revealPolicy]) ||
    (!fromField.showInPreview && toField.showInPreview) ||
    (!fromField.searchableLocally && toField.searchableLocally) ||
    reauthenticationRank[toField.reauthenticationPolicy] <
      reauthenticationRank[fromField.reauthenticationPolicy] ||
    exportRank[toField.exportPolicy] < exportRank[fromField.exportPolicy] ||
    (fromField.environmentVariableName === undefined &&
      toField.environmentVariableName !== undefined)
  );
}

function conversionStrategy(
  from: FieldType,
  to: FieldType,
): Extract<TemplateMigrationStep, { kind: 'convert-type' }>['strategy'] {
  if (
    (stringTypes.has(from) && stringTypes.has(to)) ||
    (stringArrayTypes.has(from) && stringArrayTypes.has(to))
  ) {
    return 'identity';
  }
  if ((from === 'number' || from === 'port') && stringTypes.has(to))
    return 'number-to-string';
  if (stringTypes.has(from) && (to === 'number' || to === 'port'))
    return 'string-to-number';
  if (from === 'boolean' && stringTypes.has(to)) return 'boolean-to-string';
  if (stringTypes.has(from) && to === 'boolean') return 'string-to-boolean';
  return 'archive-incompatible';
}

type ConversionResult =
  Readonly<{ success: true; value: ActiveFieldValue }> | Readonly<{ success: false }>;

function convertValue(
  value: ActiveFieldValue,
  strategy: Extract<TemplateMigrationStep, { kind: 'convert-type' }>['strategy'],
  targetField: FieldDefinition,
): ConversionResult {
  if (value.state !== 'present') return { success: true, value };
  const convertedContent = (() => {
    if (value.content.cardinality === 'multiple') {
      return convertMultiple(value.content.elements, strategy, targetField);
    }
    const converted = convertScalar(value.content.value, strategy, targetField);
    return converted === undefined
      ? undefined
      : { cardinality: 'single' as const, value: converted };
  })();
  if (convertedContent === undefined) return { success: false };
  return {
    success: true,
    value: activeFieldValueSchema.parse({
      version: 1,
      state: 'present',
      content: convertedContent,
    }),
  };
}

function convertAndValidate(
  value: ActiveFieldValue,
  strategy: Extract<TemplateMigrationStep, { kind: 'convert-type' }>['strategy'],
  targetField: FieldDefinition,
): ConversionResult {
  const converted = convertValue(value, strategy, targetField);
  if (!converted.success) return converted;
  try {
    validateFieldValue(targetField, converted.value);
    return converted;
  } catch {
    return { success: false };
  }
}

function convertMultiple(
  elements: Extract<
    NonNullable<Extract<ActiveFieldValue, { state: 'present' }>['content']>,
    { cardinality: 'multiple' }
  >['elements'],
  strategy: Extract<TemplateMigrationStep, { kind: 'convert-type' }>['strategy'],
  targetField: FieldDefinition,
):
  | Readonly<{
      cardinality: 'multiple';
      elements: typeof elements;
    }>
  | undefined {
  const convertedElements: (typeof elements)[number][] = [];
  for (const element of elements) {
    const converted = convertScalar(element.value, strategy, targetField);
    if (converted === undefined) return undefined;
    convertedElements.push({ ...element, value: converted });
  }
  return { cardinality: 'multiple', elements: convertedElements };
}

function convertScalar(
  value: FieldScalarValue,
  strategy: Extract<TemplateMigrationStep, { kind: 'convert-type' }>['strategy'],
  targetField: FieldDefinition,
): FieldScalarValue | undefined {
  if (strategy === 'identity') {
    return value.kind === 'text' || value.kind === 'secret'
      ? textScalar(targetField, value.value)
      : value;
  }
  if (strategy === 'number-to-string' && value.kind === 'number') {
    return textScalar(targetField, String(value.value));
  }
  if (strategy === 'boolean-to-string' && value.kind === 'boolean') {
    return textScalar(targetField, String(value.value));
  }
  if (
    strategy === 'string-to-number' &&
    (value.kind === 'text' || value.kind === 'secret')
  ) {
    const parsed = Number(value.value);
    return Number.isFinite(parsed) && value.value.trim() !== ''
      ? { kind: 'number', value: parsed }
      : undefined;
  }
  if (
    strategy === 'string-to-boolean' &&
    (value.kind === 'text' || value.kind === 'secret')
  ) {
    if (value.value === 'true') return { kind: 'boolean', value: true };
    if (value.value === 'false') return { kind: 'boolean', value: false };
  }
  return undefined;
}

function textScalar(field: FieldDefinition, value: string): FieldScalarValue {
  return field.sensitive
    ? { kind: 'secret', value: secretValueSchema.parse(value) }
    : { kind: 'text', value };
}

function reclassifyTextSensitivity(
  value: ActiveFieldValue,
  targetField: FieldDefinition,
): ActiveFieldValue {
  if (value.state !== 'present') return value;
  const content =
    value.content.cardinality === 'single'
      ? {
          cardinality: 'single' as const,
          value: reclassifyScalarSensitivity(value.content.value, targetField),
        }
      : {
          cardinality: 'multiple' as const,
          elements: value.content.elements.map((element) => ({
            ...element,
            value: reclassifyScalarSensitivity(element.value, targetField),
          })),
        };
  return activeFieldValueSchema.parse({ ...value, content });
}

function reclassifyScalarSensitivity(
  value: FieldScalarValue,
  targetField: FieldDefinition,
): FieldScalarValue {
  if (value.kind === 'text' || value.kind === 'secret') {
    return textScalar(targetField, value.value);
  }
  if (value.kind === 'environment-entry') {
    return {
      ...value,
      value: targetField.sensitive
        ? {
            classification: 'secret',
            value: secretValueSchema.parse(value.value.value),
          }
        : { classification: 'text', value: value.value.value },
    };
  }
  return value;
}

function fieldValueMatchesTarget(
  targetField: FieldDefinition,
  value: ActiveFieldValue,
): boolean {
  try {
    validateFieldValue(targetField, value);
    return true;
  } catch {
    return false;
  }
}
