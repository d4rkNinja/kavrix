import {
  fieldDefinitionSchema,
  groupPayloadSchema,
  groupTemplateSchema,
  itemPayloadSchema,
  noteSchema,
  secretValueSchema,
  type FieldDefinition,
  type ActiveFieldValue,
  type GroupPayload,
  type ItemPayload,
  type Note,
} from '@kavrix/schemas';

const timestamp = '2026-08-10T00:00:00.000Z';

function field(
  id: string,
  stableKey: string,
  label: string,
  type: FieldDefinition['type'],
  sortOrder: number,
  sensitive = false,
  repeatable = false,
): FieldDefinition {
  return fieldDefinitionSchema.parse({
    id,
    stableKey,
    label,
    type,
    required: true,
    sensitive,
    repeatable,
    copyable: true,
    searchableLocally: !sensitive,
    showInPreview: !sensitive,
    copyPolicy: sensitive ? 'confirm' : 'allowed',
    revealPolicy: sensitive ? 'timed' : 'never',
    reauthenticationPolicy: sensitive ? 'after-lock' : 'never',
    exportPolicy: sensitive ? 'guarded' : 'encrypted-only',
    sortOrder,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

export const usernameField = field(
  'field.username',
  'username',
  'Username',
  'username',
  0,
);
export const passwordField = field(
  'field.password',
  'password',
  'Password',
  'secret',
  1,
  true,
);
export const backupCodesField = field(
  'field.backup-codes',
  'backup_codes',
  'Backup codes',
  'recovery-code-list',
  2,
  true,
  true,
);
export const tenantField = field(
  'field.tenant',
  'tenant_id',
  'Workspace Tenant ID',
  'text',
  3,
);

const template = groupTemplateSchema.parse({
  id: 'template.email',
  name: 'Email template',
  builtInKey: 'email',
  version: 1,
  fields: [usernameField, passwordField, backupCodesField],
  createdAt: timestamp,
  updatedAt: timestamp,
});

function note(
  id: string,
  title: string,
  content: string,
  isSensitive: boolean,
  sortOrder: number,
): Note {
  return noteSchema.parse({
    id,
    title,
    content: secretValueSchema.parse(content),
    isSensitive,
    isPinned: sortOrder === 0,
    tags: [],
    sortOrder,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

export const groupNotes = [
  note('note.group.1', 'Support', 'Call the enterprise desk', false, 0),
  note('note.group.2', 'Recovery', 'GROUP-NOTE-CANARY', true, 1),
  note('note.group.3', 'Owner', 'Platform team', false, 2),
];

export const itemNotes = [
  note('note.item.1', 'Context', 'Work mailbox', false, 0),
  note('note.item.2', 'Recovery detail', 'ITEM-NOTE-CANARY', true, 1),
  note('note.item.3', 'Rotation', 'Every quarter', false, 2),
  note('note.item.4', 'Escaped', '\u001b]2;NOTE-INJECTION\u0007safe', false, 3),
];

export const group = groupPayloadSchema.parse({
  id: 'group.email',
  vaultId: 'vault.primary',
  name: 'Email\u001b]2;GROUP-INJECTION\u0007 Accounts',
  aliases: [],
  tags: ['work'],
  notes: groupNotes,
  template,
  sortOrder: 0,
  revision: 1,
  createdAt: timestamp,
  updatedAt: timestamp,
});

export const secondGroup = groupPayloadSchema.parse({
  ...group,
  id: 'group.database',
  name: 'Production Databases',
  sortOrder: 1,
});

const textValue = (value: string): ActiveFieldValue => ({
  version: 1 as const,
  state: 'present' as const,
  content: { cardinality: 'single' as const, value: { kind: 'text' as const, value } },
});

export const item = itemPayloadSchema.parse({
  version: 1,
  id: 'item.gmail',
  vaultId: 'vault.primary',
  groupId: group.id,
  templateId: template.id,
  title: 'Gmail Work',
  aliases: ['mail'],
  subtitle: 'Primary mailbox',
  templateVersion: 1,
  templateValues: [
    {
      fieldId: usernameField.id,
      stableKey: usernameField.stableKey,
      value: textValue('operator@example.test'),
      updatedAt: timestamp,
    },
    {
      fieldId: passwordField.id,
      stableKey: passwordField.stableKey,
      value: {
        version: 1,
        state: 'present',
        content: {
          cardinality: 'single',
          value: { kind: 'secret', value: secretValueSchema.parse('PASSWORD-CANARY') },
        },
      },
      updatedAt: timestamp,
    },
    {
      fieldId: backupCodesField.id,
      stableKey: backupCodesField.stableKey,
      value: {
        version: 1,
        state: 'present',
        content: {
          cardinality: 'multiple',
          elements: ['code-a', 'code-b'].map((value, index) => ({
            id: `code.${String(index)}`,
            value: { kind: 'secret', value: secretValueSchema.parse(value) },
            lifecycle: { version: 1, status: 'available' },
          })),
        },
      },
      updatedAt: timestamp,
    },
  ],
  itemFields: [tenantField],
  itemValues: [
    {
      fieldId: tenantField.id,
      stableKey: tenantField.stableKey,
      value: textValue('tenant-42'),
      updatedAt: timestamp,
    },
  ],
  archivedFieldValues: [],
  notes: itemNotes,
  tags: ['email', 'work'],
  favorite: true,
  environment: 'production',
  productionSensitive: true,
  relatedItemIds: [],
  attachmentIds: [],
  copySequences: [],
  revision: 7,
  createdAt: timestamp,
  updatedAt: timestamp,
});

export const secondItem: ItemPayload = itemPayloadSchema.parse({
  ...item,
  id: 'item.outlook',
  title: 'Outlook Personal',
  aliases: [],
  favorite: false,
});

export function browserState(
  width = 80,
  height = 24,
  ascii = false,
): Readonly<{
  width: number;
  height: number;
  ascii: boolean;
  groups: readonly GroupPayload[];
  items: readonly ItemPayload[];
}> {
  return {
    width,
    height,
    ascii,
    groups: [group, secondGroup] as readonly GroupPayload[],
    items: [item, secondItem] as readonly ItemPayload[],
  };
}
