import {
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
