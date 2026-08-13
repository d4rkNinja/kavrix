import type {
  CredentialCopyReceipt,
  CredentialShowField,
  CredentialShowNote,
} from '@kavrix/client';
import {
  isSensitiveFieldType,
  type DeviceListPageResponse,
  type InviteIssueResponse,
  type InviteListPageResponse,
  type PublicInviteRecord,
} from '@kavrix/schemas';

import type {
  CliConnectResult,
  CliBackupCreateResult,
  CliConflict,
  CliConflictResolutionResult,
  CliKeySlot,
  CliKeySlotResult,
  CliPortableKeyRotationResult,
  CliRecoverResult,
  CliShowResult,
  CliStatus,
} from './contracts.js';
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

export function renderConflicts(
  conflicts: readonly CliConflict[],
  json: boolean,
): string {
  const safe = conflicts.map((conflict) => ({
    vaultId: sanitizeTerminalText(conflict.vaultId),
    entityType: conflict.entityType,
    entityId: sanitizeTerminalText(conflict.entityId),
    idempotencyKey: sanitizeTerminalText(conflict.idempotencyKey),
    expectedRevision: conflict.expectedRevision,
    currentRevision: conflict.currentRevision,
    currentState: conflict.currentState,
  }));
  if (json) return safeJson(safe);
  if (safe.length === 0) return 'No unresolved sync conflicts.\n';
  return `${safe
    .map(
      (conflict) =>
        `${conflict.idempotencyKey}\t${conflict.entityType}\t${conflict.entityId}\t${String(conflict.expectedRevision ?? 'none')}\t${String(conflict.currentRevision)}\t${conflict.currentState}`,
    )
    .join('\n')}\n`;
}

export function renderConflictResolution(
  result: CliConflictResolutionResult,
  json: boolean,
): string {
  const safe = {
    status: result.status,
    conflictId: sanitizeTerminalText(result.conflictId),
    strategy: result.strategy,
  };
  if (json) return safeJson(safe);
  return `Conflict ${safe.conflictId} resolved with ${safe.strategy}.\n`;
}

export function renderConnect(result: CliConnectResult, json: boolean): string {
  const safe = {
    vaultId: sanitizeTerminalText(result.vaultId),
    deviceId: sanitizeTerminalText(result.deviceId),
  };
  if (json) return safeJson(safe);
  return `Connected vault ${safe.vaultId} on device ${safe.deviceId}.\n`;
}

export function renderRecover(result: CliRecoverResult, json: boolean): string {
  const safe = {
    operationId: sanitizeTerminalText(result.operationId),
    vaultId: sanitizeTerminalText(result.vaultId),
    deviceId: sanitizeTerminalText(result.deviceId),
  };
  if (json) return safeJson(safe);
  return `Vault recovered ${safe.vaultId} on device ${safe.deviceId}.\n`;
}

export function renderBackupCreate(
  result: CliBackupCreateResult,
  json: boolean,
): string {
  const safe = {
    action: result.action,
    vaultId: sanitizeTerminalText(result.vaultId),
    recordCount: result.recordCount,
    bytes: result.bytes,
  };
  if (json) return safeJson(safe);
  return `Encrypted backup created for vault ${safe.vaultId} (${String(safe.recordCount)} records, ${String(safe.bytes)} bytes).\n`;
}

export function renderDeviceJoin(result: CliRecoverResult, json: boolean): string {
  const safe = {
    operationId: sanitizeTerminalText(result.operationId),
    vaultId: sanitizeTerminalText(result.vaultId),
    deviceId: sanitizeTerminalText(result.deviceId),
  };
  if (json) return safeJson(safe);
  return `Device joined vault ${safe.vaultId} on device ${safe.deviceId}.\n`;
}

export function renderKeySlots(slots: readonly CliKeySlot[], json: boolean): string {
  const safe = slots.map((slot) => ({
    id: sanitizeTerminalText(slot.id),
    type: slot.type,
    state: slot.state,
    keyVersion: slot.keyVersion,
    createdAt: slot.createdAt,
    ...(slot.revokedAt === undefined ? {} : { revokedAt: slot.revokedAt }),
    ...(slot.deviceId === undefined
      ? {}
      : { deviceId: sanitizeTerminalText(slot.deviceId) }),
  }));
  if (json) return safeJson(safe);
  if (safe.length === 0) return 'No unlock slots.\n';
  return `${safe
    .map(
      (slot) =>
        `${slot.id}\t${slot.type}\t${slot.state}\tv${String(slot.keyVersion)}\t${slot.createdAt}${slot.deviceId === undefined ? '' : `\t${slot.deviceId}`}`,
    )
    .join('\n')}\n`;
}

export function renderKeySlotResult(result: CliKeySlotResult, json: boolean): string {
  const safe = {
    action: result.action,
    slot: {
      id: sanitizeTerminalText(result.slot.id),
      type: result.slot.type,
      state: result.slot.state,
      keyVersion: result.slot.keyVersion,
      createdAt: result.slot.createdAt,
      ...(result.slot.revokedAt === undefined
        ? {}
        : { revokedAt: result.slot.revokedAt }),
      ...(result.slot.deviceId === undefined
        ? {}
        : { deviceId: sanitizeTerminalText(result.slot.deviceId) }),
    },
  };
  if (json) return safeJson(safe);
  return `Unlock slot ${safe.slot.id} ${safe.action}.\n`;
}

export function renderDeviceKeyAction(
  result: CliKeySlotResult,
  action: 'remembered' | 'forgotten',
  json: boolean,
): string {
  const safe = {
    action,
    slot: {
      id: sanitizeTerminalText(result.slot.id),
      type: result.slot.type,
      state: result.slot.state,
      keyVersion: result.slot.keyVersion,
      createdAt: result.slot.createdAt,
      ...(result.slot.revokedAt === undefined
        ? {}
        : { revokedAt: result.slot.revokedAt }),
      ...(result.slot.deviceId === undefined
        ? {}
        : { deviceId: sanitizeTerminalText(result.slot.deviceId) }),
    },
  };
  if (json) return safeJson(safe);
  return action === 'remembered'
    ? `Device remembered in the native keychain (unlock slot ${safe.slot.id}); API session credentials unchanged.\n`
    : `Device unlock slot ${safe.slot.id} forgotten locally; remote slot and API session credentials unchanged.\n`;
}

export function renderPortableKeyRotation(
  result: CliPortableKeyRotationResult,
  json: boolean,
): string {
  const safe =
    result.action === 'listed'
      ? {
          action: result.action,
          operations: result.operations.map((operation) => ({
            operationId: sanitizeTerminalText(operation.operationId),
            state: operation.state,
            vaultId: sanitizeTerminalText(operation.vaultId),
            deviceId: sanitizeTerminalText(operation.deviceId),
            sourceSlotId: sanitizeTerminalText(operation.sourceSlotId),
            replacementSlotId: sanitizeTerminalText(operation.replacementSlotId),
            createdAt: operation.createdAt,
            updatedAt: operation.updatedAt,
          })),
        }
      : {
          action: result.action,
          operationId: sanitizeTerminalText(result.operationId),
          sourceSlotId: sanitizeTerminalText(result.sourceSlotId),
          replacementSlotId: sanitizeTerminalText(result.replacementSlotId),
          state: result.state,
        };
  if (json) return safeJson(safe);
  if (safe.action === 'listed') {
    if (safe.operations.length === 0) return 'No portable-key rotations.\n';
    return `${safe.operations
      .map(
        (operation) =>
          `${operation.operationId}\t${operation.state}\t${operation.vaultId}\t${operation.sourceSlotId}\t${operation.replacementSlotId}\t${operation.updatedAt}`,
      )
      .join('\n')}\n`;
  }
  return `Portable-key rotation ${safe.action} (${safe.operationId}).\n`;
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

export function renderDevices(page: DeviceListPageResponse, json: boolean): string {
  const safe = page.devices.map((device) => ({
    id: sanitizeTerminalText(device.id),
    vaultId: sanitizeTerminalText(device.vaultId),
    schemaVersion: device.schemaVersion,
    tokenVersion: device.tokenVersion,
    ...(device.encryptedLabel === undefined
      ? {}
      : { encryptedLabel: device.encryptedLabel }),
    scopes: device.scopes.map(sanitizeTerminalText),
    createdAt: device.createdAt,
    ...(device.lastSeenAt === undefined ? {} : { lastSeenAt: device.lastSeenAt }),
    ...(device.revokedAt === undefined ? {} : { revokedAt: device.revokedAt }),
  }));
  const nextCursor =
    page.nextCursor === null ? null : sanitizeTerminalText(page.nextCursor);
  if (json) return safeJson({ devices: safe, nextCursor });
  if (safe.length === 0) return 'No devices.\n';
  const rows = safe
    .map((device) =>
      [
        device.id,
        device.revokedAt === undefined ? 'active' : 'revoked',
        device.scopes.join(','),
        device.createdAt,
        device.lastSeenAt ?? 'never',
      ].join('\t'),
    )
    .join('\n');
  const continuation = nextCursor === null ? '' : `Next cursor: ${nextCursor}\n`;
  return `${rows}\n${continuation}`;
}

/** Renders the returned bearer exactly once after the command authorizes it. */
export function renderInviteIssue(result: InviteIssueResponse, json: boolean): string {
  const safe = {
    inviteId: sanitizeTerminalText(result.inviteId),
    inviteToken: sanitizeTerminalText(result.inviteToken),
    expiresAt: sanitizeTerminalText(result.expiresAt),
  };
  if (json) return safeJson(safe);
  return [
    `Invite token (display once): ${safe.inviteToken}`,
    `Invite ID: ${safe.inviteId}`,
    `Expires: ${safe.expiresAt}`,
  ]
    .join('\n')
    .concat('\n');
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
