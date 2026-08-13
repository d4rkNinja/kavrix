import type {
  CredentialCopyReceipt,
  CredentialShowField,
  CredentialShowNote,
} from '@kavrix/client';
import {
  isSensitiveFieldType,
  type InviteListPageResponse,
  type PublicInviteRecord,
} from '@kavrix/schemas';

import type { CliShowResult, CliStatus } from './contracts.js';
import { safeJson, sanitizeTerminalText } from './terminal.js';

type SafeInvite = Readonly<{
  id: string;
  vaultId: string;
  issuedByDeviceId: string;
  scopes: readonly string[];
  state: PublicInviteRecord['state'];
  createdAt: string;
  expiresAt: string;
  consumedAt?: string;
  revokedAt?: string;
}>;

export function renderStatus(status: CliStatus, json: boolean): string {
  const safe = {
    vaultState: status.vaultState,
    ...(status.vaultId === undefined ? {} : { vaultId: status.vaultId }),
    ...(status.deviceId === undefined ? {} : { deviceId: status.deviceId }),
    syncState: status.syncState,
    pendingChanges: status.pendingChanges,
    ...(status.lastSyncAt === undefined ? {} : { lastSyncAt: status.lastSyncAt }),
  };
  if (json) return safeJson(safe);
  return [
    `Vault: ${safe.vaultState}`,
    ...(safe.vaultId === undefined ? [] : [`Vault ID: ${safe.vaultId}`]),
    ...(safe.deviceId === undefined ? [] : [`Device ID: ${safe.deviceId}`]),
    `Sync: ${safe.syncState}`,
    `Pending changes: ${String(safe.pendingChanges)}`,
    ...(safe.lastSyncAt === undefined ? [] : [`Last sync: ${safe.lastSyncAt}`]),
  ]
    .join('\n')
    .concat('\n');
}

export function renderShow(result: CliShowResult, json: boolean): string {
  const safe = safeShow(result);
  if (json) return safeJson(safe);
  const lines = [
    `Title: ${safe.title}`,
    `ID: ${safe.id}`,
    `Group: ${safe.group.name} (${safe.group.id})`,
    ...(safe.group.slug === undefined ? [] : [`Group slug: ${safe.group.slug}`]),
    ...(safe.group.aliases.length === 0
      ? []
      : [`Group aliases: ${safe.group.aliases.join(', ')}`]),
    ...(safe.group.description === undefined
      ? []
      : [`Group description: ${safe.group.description}`]),
    ...(safe.group.tags.length === 0
      ? []
      : [`Group tags: ${safe.group.tags.join(', ')}`]),
    `Template: ${safe.template.name} (${safe.template.id} v${String(safe.template.version)})`,
    ...(safe.slug === undefined ? [] : [`Slug: ${safe.slug}`]),
    ...(safe.aliases.length === 0 ? [] : [`Aliases: ${safe.aliases.join(', ')}`]),
    ...(safe.subtitle === undefined ? [] : [`Subtitle: ${safe.subtitle}`]),
    ...(safe.environment === undefined ? [] : [`Environment: ${safe.environment}`]),
    ...(safe.owner === undefined ? [] : [`Owner: ${safe.owner}`]),
    ...(safe.purpose === undefined ? [] : [`Purpose: ${safe.purpose}`]),
    `Favorite: ${String(safe.favorite)}`,
    `Production sensitive: ${String(safe.productionSensitive)}`,
    ...(safe.tags.length === 0 ? [] : [`Tags: ${safe.tags.join(', ')}`]),
    ...(safe.expiresAt === undefined ? [] : [`Expires: ${safe.expiresAt}`]),
    ...(safe.rotationIntervalDays === undefined
      ? []
      : [`Rotation interval: ${String(safe.rotationIntervalDays)} days`]),
    ...(safe.lastRotatedAt === undefined
      ? []
      : [`Last rotated: ${safe.lastRotatedAt}`]),
    ...(safe.lastVerifiedAt === undefined
      ? []
      : [`Last verified: ${safe.lastVerifiedAt}`]),
    `Created: ${safe.createdAt}`,
    `Updated: ${safe.updatedAt}`,
    ...(safe.archivedAt === undefined ? [] : [`Archived: ${safe.archivedAt}`]),
    `Revision: ${String(safe.revision)}`,
    `Related items: ${String(safe.relatedItemCount)}`,
    `Attachments: ${String(safe.attachmentCount)}`,
    `Notes: ${String(safe.noteCount)} (${String(safe.activeNoteCount)} active, ${String(safe.archivedNoteCount)} archived)`,
    'Fields:',
    ...safe.fields.map(
      (field) =>
        `  ${field.label} (${field.stableKey}; ${field.id}) [${field.source}/${field.state}]: ${field.value}`,
    ),
    ...(safe.notes.length === 0
      ? []
      : ['Item notes:', ...safe.notes.map((note) => renderNote(note))]),
    ...(safe.group.notes.length === 0
      ? []
      : ['Group notes:', ...safe.group.notes.map((note) => renderNote(note))]),
  ];
  return `${lines.join('\n')}\n`;
}

export function renderCopyReceipt(receipt: CredentialCopyReceipt): string {
  if (
    typeof receipt.label !== 'string' ||
    typeof receipt.clearAfterSeconds !== 'number' ||
    !Number.isFinite(receipt.clearAfterSeconds) ||
    receipt.clearAfterSeconds <= 0
  ) {
    throw new Error('Invalid clipboard receipt');
  }
  return `Copied ${sanitizeTerminalText(receipt.label)} — clipboard clears in ${String(receipt.clearAfterSeconds)} seconds.\n`;
}

export function renderInvites(page: InviteListPageResponse, json: boolean): string {
  const safe = page.invites.map((invite) => safeInvite(invite));
  const nextCursor =
    page.nextCursor === null ? null : sanitizeTerminalText(page.nextCursor);
  if (json) return safeJson({ invites: safe, nextCursor });
  if (safe.length === 0) return 'No device invites.\n';
  const rows = safe
    .map(
      (invite) =>
        `${invite.id}\t${invite.state}\t${invite.scopes.join(',')}\t${invite.expiresAt}`,
    )
    .join('\n');
  const continuation = nextCursor === null ? '' : `Next cursor: ${nextCursor}\n`;
  return `${rows}\n${continuation}`;
}

function safeShow(result: CliShowResult): CliShowResult {
  return {
    group: {
      id: result.group.id,
      name: sanitizeTerminalText(result.group.name),
      ...(result.group.slug === undefined
        ? {}
        : { slug: sanitizeTerminalText(result.group.slug) }),
      aliases: result.group.aliases.map(sanitizeTerminalText),
      ...(result.group.description === undefined
        ? {}
        : { description: sanitizeTerminalText(result.group.description) }),
      tags: result.group.tags.map(sanitizeTerminalText),
      notes: result.group.notes.map(safeNote),
    },
    template: {
      id: result.template.id,
      name: sanitizeTerminalText(result.template.name),
      version: result.template.version,
    },
    id: result.id,
    title: sanitizeTerminalText(result.title),
    ...(result.slug === undefined ? {} : { slug: sanitizeTerminalText(result.slug) }),
    aliases: result.aliases.map(sanitizeTerminalText),
    ...(result.subtitle === undefined
      ? {}
      : { subtitle: sanitizeTerminalText(result.subtitle) }),
    ...(result.environment === undefined
      ? {}
      : { environment: sanitizeTerminalText(result.environment) }),
    ...(result.owner === undefined
      ? {}
      : { owner: sanitizeTerminalText(result.owner) }),
    ...(result.purpose === undefined
      ? {}
      : { purpose: sanitizeTerminalText(result.purpose) }),
    favorite: result.favorite,
    productionSensitive: result.productionSensitive,
    tags: result.tags.map(sanitizeTerminalText),
    ...(result.expiresAt === undefined ? {} : { expiresAt: result.expiresAt }),
    ...(result.rotationIntervalDays === undefined
      ? {}
      : { rotationIntervalDays: result.rotationIntervalDays }),
    ...(result.lastRotatedAt === undefined
      ? {}
      : { lastRotatedAt: result.lastRotatedAt }),
    ...(result.lastVerifiedAt === undefined
      ? {}
      : { lastVerifiedAt: result.lastVerifiedAt }),
    createdAt: result.createdAt,
    updatedAt: result.updatedAt,
    ...(result.archivedAt === undefined ? {} : { archivedAt: result.archivedAt }),
    revision: result.revision,
    relatedItemCount: result.relatedItemCount,
    attachmentCount: result.attachmentCount,
    noteCount: result.noteCount,
    activeNoteCount: result.activeNoteCount,
    archivedNoteCount: result.archivedNoteCount,
    notes: result.notes.map(safeNote),
    fields: result.fields.map(safeField),
  };
}

function safeField(field: CredentialShowField): CredentialShowField {
  return {
    id: field.id,
    stableKey: field.stableKey,
    label: sanitizeTerminalText(field.label),
    type: field.type,
    sensitive: field.sensitive,
    copyable: field.copyable,
    copyPolicy: field.copyPolicy,
    state: field.state,
    value:
      field.source === 'archived'
        ? '[ORPHANED]'
        : field.sensitive || isSensitiveFieldType(field.type)
          ? '[REDACTED]'
          : sanitizeTerminalText(field.value),
    source: field.source,
    sortOrder: field.sortOrder,
  };
}

function safeNote(note: CredentialShowNote): CredentialShowNote {
  return {
    id: note.id,
    title: sanitizeTerminalText(note.title),
    content: '[REDACTED]',
    sensitive: note.sensitive,
    pinned: note.pinned,
    tags: note.tags.map(sanitizeTerminalText),
    createdAt: note.createdAt,
    updatedAt: note.updatedAt,
    ...(note.archivedAt === undefined ? {} : { archivedAt: note.archivedAt }),
  };
}

function renderNote(note: CredentialShowNote): string {
  const flags = [
    ...(note.pinned ? ['pinned'] : []),
    ...(note.sensitive ? ['sensitive'] : []),
    ...(note.archivedAt === undefined ? [] : ['archived']),
  ];
  return `  ${note.title} (${note.id})${flags.length === 0 ? '' : ` [${flags.join(', ')}]`}: ${note.content}`;
}

function safeInvite(invite: PublicInviteRecord): SafeInvite {
  return {
    id: sanitizeTerminalText(invite.id),
    vaultId: sanitizeTerminalText(invite.vaultId),
    issuedByDeviceId: sanitizeTerminalText(invite.issuedByDeviceId),
    scopes: invite.scopes.map(sanitizeTerminalText),
    state: invite.state,
    createdAt: sanitizeTerminalText(invite.createdAt),
    expiresAt: sanitizeTerminalText(invite.expiresAt),
    ...(invite.consumedAt === undefined
      ? {}
      : { consumedAt: sanitizeTerminalText(invite.consumedAt) }),
    ...(invite.revokedAt === undefined
      ? {}
      : { revokedAt: sanitizeTerminalText(invite.revokedAt) }),
  };
}

export function renderGroupList(
  groups: readonly {
    id: string;
    name: string;
    description?: string | undefined;
    slug?: string | undefined;
  }[],
  json: boolean,
): string {
  const safeGroups = groups.map((g) => ({
    id: sanitizeTerminalText(g.id),
    name: sanitizeTerminalText(g.name),
    ...(g.description === undefined
      ? {}
      : { description: sanitizeTerminalText(g.description) }),
    ...(g.slug === undefined ? {} : { slug: sanitizeTerminalText(g.slug) }),
  }));
  if (json) return safeJson(safeGroups);
  if (safeGroups.length === 0) return 'No groups found.\n';
  const lines = [
    `Groups (${String(safeGroups.length)}):`,
    ...safeGroups.map(
      (g) => `  - ${g.name} (${g.id})${g.description ? `: ${g.description}` : ''}`,
    ),
  ];
  return lines.join('\n').concat('\n');
}

export function renderCredentialList(
  items: readonly {
    id: string;
    title: string;
    subtitle?: string | undefined;
    favorite?: boolean | undefined;
  }[],
  json: boolean,
): string {
  const safeItems = items.map((item) => ({
    id: sanitizeTerminalText(item.id),
    title: sanitizeTerminalText(item.title),
    ...(item.subtitle === undefined
      ? {}
      : { subtitle: sanitizeTerminalText(item.subtitle) }),
    ...(item.favorite === undefined ? {} : { favorite: item.favorite }),
  }));
  if (json) return safeJson(safeItems);
  if (safeItems.length === 0) return 'No credentials found.\n';
  const lines = [
    `Credentials (${String(safeItems.length)}):`,
    ...safeItems.map(
      (item) =>
        `  - ${item.title} (${item.id})${item.subtitle ? `: ${item.subtitle}` : ''}`,
    ),
  ];
  return lines.join('\n').concat('\n');
}
