import {
  fieldExpectsMultipleValues,
  fieldValueMatchesDefinition,
  type FieldDefinition,
  type FieldValue,
  type GroupTemplate,
  type ItemPayload,
} from '@kavrix/schemas';

import { SchemaMigrationError, ValidationError } from '../errors.js';

export function validateFieldValue(field: FieldDefinition, value: FieldValue): void {
  if (!fieldValueMatchesDefinition(field, value)) {
    throw new ValidationError('The field value does not satisfy its definition.');
  }
}

/**
 * Guard a whole-value scalar write against a target that holds elements.
 *
 * Writing one scalar replaces the entire stored value, so accepting the write
 * on a repeatable field or a collection type would silently discard every
 * element. Callers must fail closed instead of losing stored data.
 */
export function assertSingleValueWriteTarget(
  field: FieldDefinition,
  current: FieldValue | undefined,
): void {
  if (fieldExpectsMultipleValues(field)) {
    throw new ValidationError(
      'This field holds multiple elements, so a single value write would discard them.',
    );
  }
  if (current !== undefined && holdsElements(current)) {
    throw new ValidationError(
      'This field already stores multiple elements, so a single value write would discard them.',
    );
  }
}

function holdsElements(value: FieldValue): boolean {
  if (value.state === 'orphaned') return holdsElements(value.originalValue);
  return value.state === 'present' && value.content.cardinality === 'multiple';
}

export function validateItemAgainstTemplate(
  item: ItemPayload,
  template: GroupTemplate,
): void {
  if (item.templateId !== template.id || item.templateVersion !== template.version) {
    throw new SchemaMigrationError(
      'The item is bound to a different template version.',
    );
  }

  const valuesById = new Map(
    item.templateValues.map((value) => [value.fieldId, value]),
  );
  for (const definition of template.fields) {
    const stored = valuesById.get(definition.id);
    if (stored === undefined) {
      if (definition.required) {
        throw new ValidationError('A required template field is missing.');
      }
      continue;
    }
    if (
      stored.stableKey !== definition.stableKey ||
      !fieldValueMatchesDefinition(definition, stored.value)
    ) {
      throw new ValidationError(
        'A template field value does not match its definition.',
      );
    }
    valuesById.delete(definition.id);
  }
  if (valuesById.size > 0) {
    throw new ValidationError(
      'The item contains a value without a template definition.',
    );
  }
}
