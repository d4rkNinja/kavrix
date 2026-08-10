import type { CredentialShowProjection } from '@kavrix/client';
import {
  fieldIdSchema,
  groupIdSchema,
  itemIdSchema,
  noteIdSchema,
  recordRevisionSchema,
  stableFieldKeySchema,
  templateIdSchema,
  templateVersionSchema,
} from '@kavrix/schemas';

const NOW = '2026-08-10T00:00:00.000Z';

export const PUBLIC_CANARY = 'visible-user';
export const SECRET_CANARY = 'secret-password-canary';
export const NOTE_CANARY = 'secret-note-canary';

export function showFixture(): CredentialShowProjection {
  return {
    group: {
      id: groupIdSchema.parse('group.logins'),
      name: 'Production',
      slug: 'production',
      aliases: ['prod'],
      description: 'Production credentials',
      tags: ['critical'],
      notes: [
        {
          id: noteIdSchema.parse('note.group'),
          title: 'Group recovery',
          content: '[REDACTED]',
          sensitive: false,
          pinned: true,
          tags: ['recovery'],
          createdAt: NOW,
          updatedAt: NOW,
        },
      ],
    },
    template: {
      id: templateIdSchema.parse('template.login'),
      name: 'Login\u001b]8;;https://unsafe.invalid\u0007',
      version: templateVersionSchema.parse(1),
    },
    id: itemIdSchema.parse('item.primary'),
    title: 'Primary\u001b[2J login',
    aliases: ['primary'],
    environment: 'production',
    owner: 'Platform',
    purpose: 'Deployment',
    favorite: true,
    productionSensitive: true,
    tags: ['production'],
    expiresAt: '2026-12-01T00:00:00.000Z',
    rotationIntervalDays: 30,
    lastRotatedAt: NOW,
    lastVerifiedAt: NOW,
    createdAt: NOW,
    updatedAt: NOW,
    revision: recordRevisionSchema.parse(7),
    relatedItemCount: 2,
    attachmentCount: 1,
    noteCount: 1,
    activeNoteCount: 1,
    archivedNoteCount: 0,
    notes: [
      {
        id: noteIdSchema.parse('note.primary'),
        title: 'Recovery\u202e code',
        content: '[REDACTED]',
        sensitive: false,
        pinned: true,
        tags: ['recovery'],
        createdAt: NOW,
        updatedAt: NOW,
      },
    ],
    fields: [
      {
        id: fieldIdSchema.parse('field.username'),
        stableKey: stableFieldKeySchema.parse('username'),
        label: 'User\u001b[31m name',
        type: 'username',
        sensitive: false,
        copyable: true,
        copyPolicy: 'allowed',
        state: 'present',
        value: PUBLIC_CANARY,
        source: 'template',
        sortOrder: 0,
      },
      {
        id: fieldIdSchema.parse('field.password'),
        stableKey: stableFieldKeySchema.parse('password'),
        label: 'Password',
        type: 'secret',
        sensitive: true,
        copyable: true,
        copyPolicy: 'allowed',
        state: 'present',
        value: '[REDACTED]',
        source: 'template',
        sortOrder: 1,
      },
      {
        id: fieldIdSchema.parse('field.archived'),
        stableKey: stableFieldKeySchema.parse('archived_secret'),
        label: 'Archived secret',
        type: 'secret',
        sensitive: true,
        copyable: false,
        copyPolicy: 'never',
        state: 'orphaned',
        value: '[ORPHANED]',
        source: 'archived',
        sortOrder: 2,
      },
    ],
  };
}
