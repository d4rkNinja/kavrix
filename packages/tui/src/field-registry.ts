import type { FieldDefinition, FieldScalarValue, FieldType } from '@kavrix/schemas';

export type FieldInputMode =
  | 'single-line'
  | 'multiline'
  | 'masked'
  | 'masked-multiline'
  | 'number'
  | 'toggle'
  | 'select'
  | 'multi-select'
  | 'structured'
  | 'reference'
  | 'attachment';

export interface FieldEditorDescriptor {
  readonly inputMode: FieldInputMode;
  readonly valueKind:
    | 'text'
    | 'secret'
    | 'number'
    | 'boolean'
    | 'item-reference'
    | 'attachment-reference'
    | 'environment-entry';
  readonly allowsNewlines: boolean;
  readonly supportsMultiple: boolean;
}

const descriptor = (
  inputMode: FieldInputMode,
  valueKind: FieldEditorDescriptor['valueKind'],
  allowsNewlines = false,
  supportsMultiple = false,
): FieldEditorDescriptor => ({
  inputMode,
  valueKind,
  allowsNewlines,
  supportsMultiple,
});

const text = descriptor('single-line', 'text');
const secret = descriptor('masked', 'secret');

/** Every canonical field type has one editor descriptor; no credential template is special-cased. */
export const fieldEditorRegistry: Readonly<Record<FieldType, FieldEditorDescriptor>> =
  Object.freeze({
    text,
    secret,
    password: secret,
    username: text,
    email: text,
    url: text,
    phone: text,
    number: descriptor('number', 'number'),
    boolean: descriptor('toggle', 'boolean'),
    date: text,
    datetime: text,
    multiline: descriptor('multiline', 'text', true),
    'secure-multiline': descriptor('masked-multiline', 'secret', true),
    'api-key': secret,
    'access-token': secret,
    'refresh-token': secret,
    'client-id': text,
    'client-secret': secret,
    'connection-string': secret,
    host: text,
    port: descriptor('number', 'number'),
    'database-name': text,
    'private-key': descriptor('masked-multiline', 'secret', true),
    'public-key': descriptor('multiline', 'text', true),
    certificate: descriptor('multiline', 'text', true),
    'totp-secret': secret,
    'recovery-code-list': descriptor('masked-multiline', 'secret', true, true),
    json: descriptor('multiline', 'text', true),
    select: descriptor('select', 'text'),
    'multi-select': descriptor('multi-select', 'text', false, true),
    tags: descriptor('multi-select', 'text', false, true),
    'environment-map': descriptor('structured', 'environment-entry', true, true),
    'command-snippet': descriptor('multiline', 'text', true),
    attachment: descriptor('attachment', 'attachment-reference', false, true),
    'item-reference': descriptor('reference', 'item-reference'),
    custom: text,
  });

export function describeFieldEditor(field: FieldDefinition): FieldEditorDescriptor {
  const base = fieldEditorRegistry[field.type];
  if (!field.repeatable || base.supportsMultiple) return base;
  return { ...base, supportsMultiple: true };
}

export function scalarDisplayValue(value: FieldScalarValue): string {
  switch (value.kind) {
    case 'text':
    case 'secret':
      return value.value;
    case 'number':
      return String(value.value);
    case 'boolean':
      return value.value ? 'Yes' : 'No';
    case 'item-reference':
      return `item:${value.itemId}`;
    case 'attachment-reference':
      return `attachment:${value.attachmentId}`;
    case 'environment-entry':
      return `${value.key}=${value.value.value}`;
  }
}
