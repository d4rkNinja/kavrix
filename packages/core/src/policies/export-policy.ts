import {
  itemPayloadSchema,
  type FieldDefinition,
  type FieldScalarValue,
  type GroupTemplate,
  type ItemPayload,
  type StoredFieldValue,
  type TransferWithholding,
  type TransferWithholdingReason,
} from '@kavrix/schemas';

import { ValidationError } from '../errors.js';
import { validateItemAgainstTemplate } from './field-values.js';

/**
 * An item reduced to what a transfer format is permitted to carry, together with
 * the manifest of everything the reduction dropped.
 */
export type TransferItemProjection = Readonly<{
  item: ItemPayload;
  withheld: readonly TransferWithholding[];
}>;

export type TransferProjectionOptions = Readonly<{
  /**
   * Every item identifier travelling in the same transfer. A reference to an
   * item outside this set cannot be resolved by the reader, so it is withheld
   * rather than exported as a dangling pointer.
   */
  exportedItemIds: ReadonlySet<string>;
}>;

/**
 * Decide whether a field definition's value may leave the vault at all.
 *
 * `never` withholds the value from every export, including an encrypted one.
 * `encrypted-only` and `guarded` both permit an authenticated encrypted
 * transfer; they differ only in the confirmation the command surface must
 * obtain first, which is not a property of the file format.
 */
export function fieldValueMayBeExported(field: FieldDefinition): boolean {
  return field.exportPolicy !== 'never';
}

/**
 * Project an item onto the encrypted transfer format, withholding every value
 * that field policy or the format's declared limits forbid.
 *
 * The projection fails closed instead of emitting a document that could never be
 * imported. A required field whose value must be withheld would leave the item
 * permanently invalid against its own definitions, so the caller is told which
 * conflict to resolve rather than handed a broken export.
 */
export function projectItemForTransfer(
  item: ItemPayload,
  template: GroupTemplate,
  options: TransferProjectionOptions,
): TransferItemProjection {
  validateItemAgainstTemplate(item, template);

  const withheld: TransferWithholding[] = [];
  const templateValues = exportableValues(
    item.templateValues,
    new Map(template.fields.map((field) => [field.id, field])),
    'template',
    options,
    withheld,
  );
  const itemValues = exportableValues(
    item.itemValues,
    new Map(item.itemFields.map((field) => [field.id, field])),
    'item',
    options,
    withheld,
  );

  // Withholding a template value removes its stable key from the item's active
  // keys, so any copy sequence naming that key would no longer validate. An
  // item-only value keeps its definition, and therefore its key, either way.
  const withheldTemplateKeys = new Set(
    withheld
      .filter((entry) => entry.scope === 'template')
      .map((entry) => entry.stableKey),
  );

  const projected = itemPayloadSchema.parse({
    ...item,
    templateValues,
    itemValues,
    archivedFieldValues: item.archivedFieldValues.filter((archived) =>
      fieldValueMayBeExported(archived.definition),
    ),
    // Attachment content is authenticated and streamed on its own; a transfer
    // never claims to carry it, so it carries no attachment identifiers either.
    attachmentIds: [],
    relatedItemIds: item.relatedItemIds.filter((id) => options.exportedItemIds.has(id)),
    copySequences: item.copySequences.filter(
      (sequence) => !sequence.fieldKeys.some((key) => withheldTemplateKeys.has(key)),
    ),
  });

  // The reader recreates the item through the same template validation the
  // writer just ran, so prove here that the projection still satisfies it.
  validateItemAgainstTemplate(projected, template);

  return { item: projected, withheld };
}

function exportableValues(
  values: readonly StoredFieldValue[],
  definitions: ReadonlyMap<string, FieldDefinition>,
  scope: TransferWithholding['scope'],
  options: TransferProjectionOptions,
  withheld: TransferWithholding[],
): readonly StoredFieldValue[] {
  const retained: StoredFieldValue[] = [];
  for (const stored of values) {
    const definition = definitions.get(stored.fieldId);
    if (definition === undefined) {
      throw new ValidationError('A stored field value has no matching definition.');
    }
    const reason = withholdingReason(definition, stored, options);
    if (reason === undefined) {
      retained.push(stored);
      continue;
    }
    if (definition.required) {
      throw new ValidationError(
        'A required field cannot be transferred because its value must be withheld.',
      );
    }
    withheld.push({ stableKey: stored.stableKey, scope, reason });
  }
  return retained;
}

function withholdingReason(
  definition: FieldDefinition,
  stored: StoredFieldValue,
  options: TransferProjectionOptions,
): TransferWithholdingReason | undefined {
  if (!fieldValueMayBeExported(definition)) return 'export-policy';
  for (const scalar of scalarsOf(stored)) {
    if (scalar.kind === 'attachment-reference') return 'attachment-unsupported';
    if (
      scalar.kind === 'item-reference' &&
      !options.exportedItemIds.has(scalar.itemId)
    ) {
      return 'unresolved-reference';
    }
  }
  return undefined;
}

function scalarsOf(stored: StoredFieldValue): readonly FieldScalarValue[] {
  const { value } = stored;
  if (value.state !== 'present') return [];
  return value.content.cardinality === 'single'
    ? [value.content.value]
    : value.content.elements.map((element) => element.value);
}
