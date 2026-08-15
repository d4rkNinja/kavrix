import type {
  CredentialCopyReceipt,
  CredentialShowField,
  CredentialShowNote,
} from '@kavrix/client/cli-contracts';
import {
  isSensitiveFieldType,
  type DeviceListPageResponse,
  type GroupTemplate,
  type InviteIssueResponse,
  type InviteListPageResponse,
  type PublicInviteRecord,
  type TemplateMigrationPlan,
} from '@kavrix/schemas';

import type {
  CliAttachmentDeleteResult,
  CliAttachmentDownloadResult,
  CliAttachmentSummary,
  CliAttachmentUploadResult,
  CliAuditEventDetail,
  CliAuditEventPage,
  CliAuditEventSummary,
  CliConnectResult,
  CliBackupCreateResult,
  CliBackupRestoreResult,
  CliBackupVerifyResult,
  CliConflict,
  CliConflictResolutionResult,
  CliHistoryDetail,
  CliHistoryDiff,
  CliHistoryRestoreResult,
  CliHistorySummary,
  CliKeySlot,
  CliKeySlotResult,
  CliPortableKeyRotationResult,
  CliRecoverResult,
  CliRunPlan,
  CliRunResult,
  CliShowResult,
  CliStatus,
  CliTemplateMigrationApplyResult,
  CliTemplateMigrationStatusResult,
  CliTemplateSummary,
} from './contracts.js';
import { safeJson, sanitizeTerminalOutput, sanitizeTerminalText } from './terminal.js';

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

export function renderBackupVerify(
  result: CliBackupVerifyResult,
  json: boolean,
): string {
  const safe = {
    action: result.action,
    vaultId: sanitizeTerminalText(result.vaultId),
    recordCount: result.recordCount,
    bytes: result.bytes,
    schemaVersion: result.schemaVersion,
    createdAt: result.createdAt,
    restoreSessionId: sanitizeTerminalText(result.restoreSessionId),
  };
  if (json) return safeJson(safe);
  return `Encrypted backup verified for vault ${safe.vaultId} (${String(safe.recordCount)} records, ${String(safe.bytes)} bytes; created ${safe.createdAt}).\n`;
}

export function renderBackupRestore(
  result: CliBackupRestoreResult,
  json: boolean,
): string {
  const safe = {
    action: result.action,
    vaultId: sanitizeTerminalText(result.vaultId),
    recordCount: result.recordCount,
    bytes: result.bytes,
    restoreSessionId: sanitizeTerminalText(result.restoreSessionId),
    ...(result.selectedSlotId === undefined
      ? {}
      : { selectedSlotId: sanitizeTerminalText(result.selectedSlotId) }),
  };
  if (json) return safeJson(safe);
  const verb = result.action === 'restored' ? 'restored' : 'was already restored';
  return `Encrypted backup ${verb} for vault ${safe.vaultId} (${String(safe.recordCount)} records, ${String(safe.bytes)} bytes).\n`;
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

export function renderTemplateList(
  templates: readonly CliTemplateSummary[],
  json: boolean,
): string {
  const safe = templates.map((t) => ({
    id: sanitizeTerminalText(t.id),
    name: sanitizeTerminalText(t.name),
    ...(t.description === undefined
      ? {}
      : { description: sanitizeTerminalText(t.description) }),
    ...(t.builtInKey === undefined
      ? {}
      : { builtInKey: sanitizeTerminalText(t.builtInKey) }),
    version: t.version,
    fieldCount: t.fieldCount,
    ...(t.groupName === undefined
      ? {}
      : { groupName: sanitizeTerminalText(t.groupName) }),
    ...(t.groupId === undefined ? {} : { groupId: sanitizeTerminalText(t.groupId) }),
  }));
  if (json) return safeJson(safe);
  if (safe.length === 0) return 'No templates found.\n';
  const lines = [
    `Templates (${String(safe.length)}):`,
    ...safe.map((t) => {
      const typeLabel = t.builtInKey
        ? ` [builtin: ${t.builtInKey}]`
        : t.groupName
          ? ` [group: ${t.groupName}]`
          : '';
      const desc = t.description ? `: ${t.description}` : '';
      return `  - ${t.name} (${t.id})${typeLabel} [v${String(t.version)}, ${String(t.fieldCount)} fields]${desc}`;
    }),
  ];
  return lines.join('\n').concat('\n');
}

export function renderTemplateInspect(template: GroupTemplate, json: boolean): string {
  if (json) {
    return safeJson({
      id: sanitizeTerminalText(template.id),
      name: sanitizeTerminalText(template.name),
      ...(template.description === undefined
        ? {}
        : { description: sanitizeTerminalText(template.description) }),
      ...(template.builtInKey === undefined
        ? {}
        : { builtInKey: sanitizeTerminalText(template.builtInKey) }),
      version: template.version,
      createdAt: sanitizeTerminalText(template.createdAt),
      updatedAt: sanitizeTerminalText(template.updatedAt),
      fields: template.fields.map((f) => ({
        id: sanitizeTerminalText(f.id),
        stableKey: sanitizeTerminalText(f.stableKey),
        label: sanitizeTerminalText(f.label),
        type: f.type,
        required: f.required,
        sensitive: f.sensitive,
        repeatable: f.repeatable,
        copyable: f.copyable,
        sortOrder: f.sortOrder,
        copyPolicy: f.copyPolicy,
        revealPolicy: f.revealPolicy,
        reauthenticationPolicy: f.reauthenticationPolicy,
        exportPolicy: f.exportPolicy,
        ...(f.selectOptions === undefined
          ? {}
          : {
              selectOptions: f.selectOptions.map((opt) => ({
                value: sanitizeTerminalText(opt.value),
                label: sanitizeTerminalText(opt.label),
              })),
            }),
      })),
    });
  }
  const lines = [
    `Template: ${sanitizeTerminalText(template.name)} (${sanitizeTerminalText(template.id)})`,
    `Version: ${String(template.version)}`,
    ...(template.builtInKey
      ? [`Built-in key: ${sanitizeTerminalText(template.builtInKey)}`]
      : []),
    ...(template.description
      ? [`Description: ${sanitizeTerminalText(template.description)}`]
      : []),
    `Fields (${String(template.fields.length)}):`,
    ...template.fields.map((f) => {
      const flags = [
        f.type,
        ...(f.required ? ['required'] : []),
        ...(f.sensitive ? ['sensitive'] : []),
        ...(f.repeatable ? ['repeatable'] : []),
      ];
      return `  - [${String(f.sortOrder)}] ${sanitizeTerminalText(f.label)} (${sanitizeTerminalText(f.stableKey)}): ${flags.join(', ')}`;
    }),
  ];
  return lines.join('\n').concat('\n');
}

function formatMigrationStepDescription(
  step: TemplateMigrationPlan['steps'][number],
): string {
  if (step.kind === 'add-field') {
    return `add-field: ${sanitizeTerminalText(step.field.label)} (${sanitizeTerminalText(step.field.stableKey)})`;
  }
  if (step.kind === 'restore-field') {
    return `restore-field: ${sanitizeTerminalText(step.field.label)} (${sanitizeTerminalText(step.field.stableKey)})`;
  }
  if (step.kind === 'archive-field') {
    return `archive-field: ${sanitizeTerminalText(step.field.label)} (${sanitizeTerminalText(step.field.stableKey)})`;
  }
  if (step.kind === 'rename-label') {
    return `rename-label: ${sanitizeTerminalText(step.fromLabel)} -> ${sanitizeTerminalText(step.toLabel)}`;
  }
  if (step.kind === 'reorder-field') {
    return `reorder-field: sortOrder ${String(step.fromSortOrder)} -> ${String(step.toSortOrder)}`;
  }
  if (step.kind === 'change-required') {
    return `change-required: ${String(step.fromRequired)} -> ${String(step.toRequired)}`;
  }
  if (step.kind === 'convert-type') {
    return `convert-type: ${step.fromType} -> ${step.toType} (${step.strategy})`;
  }
  return 'update-field-policy: updated field definition policy';
}

export function renderTemplateMigrationPlan(
  plan: TemplateMigrationPlan,
  json: boolean,
): string {
  if (json) {
    return safeJson(plan);
  }
  const lines = [
    `Migration Plan: ${sanitizeTerminalText(plan.id)}`,
    `From Version: ${String(plan.fromVersion)} -> To Version: ${String(plan.toVersion)}`,
    `Source Template: ${sanitizeTerminalText(plan.sourceTemplate.name)} (${sanitizeTerminalText(plan.sourceTemplate.id)})`,
    `Target Template: ${sanitizeTerminalText(plan.targetTemplate.name)} (${sanitizeTerminalText(plan.targetTemplate.id)})`,
    `Total Items: ${String(plan.totalItems)}`,
    `Status: ${plan.status}`,
    `Steps (${String(plan.steps.length)}):`,
    ...plan.steps.map((step) => {
      const desc = formatMigrationStepDescription(step);
      const flags = [
        `affected items: ${String(step.affectedItemCount)}`,
        ...(step.requiresConfirmation ? ['[requires confirmation]'] : []),
      ];
      return `  - ${desc} (${flags.join(', ')})`;
    }),
  ];
  return lines.join('\n').concat('\n');
}

export function renderTemplateMigrationApply(
  result: CliTemplateMigrationApplyResult,
  json: boolean,
): string {
  if (json) {
    return safeJson(result);
  }
  const lines = [
    'Migration applied successfully.',
    `Migration ID: ${sanitizeTerminalText(result.migrationId)}`,
    `Group ID: ${sanitizeTerminalText(result.groupId)}`,
    `Migrated ${String(result.totalItems)} item(s) to template version ${String(result.toVersion)}.`,
    `Applied ${String(result.affectedSteps)} migration step(s).`,
  ];
  return lines.join('\n').concat('\n');
}

export function renderTemplateMigrationStatus(
  status: CliTemplateMigrationStatusResult,
  json: boolean,
): string {
  if (json) {
    return safeJson(status);
  }
  const lines = [
    `Group: ${sanitizeTerminalText(status.groupName)} (${sanitizeTerminalText(status.groupId)})`,
    `Template: ${sanitizeTerminalText(status.templateName)} (${sanitizeTerminalText(status.templateId)})`,
    `Current Version: ${String(status.currentVersion)}`,
    `Active Items: ${String(status.itemCount)}`,
    `Field Count: ${String(status.fieldCount)}`,
  ];
  return lines.join('\n').concat('\n');
}

export function renderAttachmentList(
  attachments: readonly CliAttachmentSummary[],
  json: boolean,
): string {
  if (json) {
    return safeJson(attachments);
  }
  if (attachments.length === 0) {
    return 'No attachments found for this credential item.\n';
  }
  const lines = [
    `Attachments (${String(attachments.length)}):`,
    ...attachments.map((att) => {
      const parts = [
        sanitizeTerminalText(att.id),
        `Chunks: ${String(att.chunkCount)}`,
        ...(att.totalPlaintextBytes !== undefined
          ? [`${String(att.totalPlaintextBytes)} bytes`]
          : []),
        ...(att.tombstonedAt !== undefined ? ['[deleted]'] : []),
      ];
      return `  - ${parts.join(' | ')}`;
    }),
  ];
  return lines.join('\n').concat('\n');
}

export function renderAttachmentUpload(
  result: CliAttachmentUploadResult,
  json: boolean,
): string {
  if (json) {
    return safeJson(result);
  }
  const lines = [
    'Attachment uploaded successfully.',
    `Attachment ID: ${sanitizeTerminalText(result.attachmentId)}`,
    `Group ID: ${sanitizeTerminalText(result.groupId)}`,
    `Item ID: ${sanitizeTerminalText(result.itemId)}`,
    `Chunks: ${String(result.chunkCount)}`,
    `Size: ${String(result.totalPlaintextBytes)} bytes`,
    `Plaintext SHA-256: ${sanitizeTerminalText(result.plaintextSha256)}`,
  ];
  return lines.join('\n').concat('\n');
}

export function renderAttachmentDownload(
  result: CliAttachmentDownloadResult,
  json: boolean,
): string {
  if (json) {
    return safeJson(result);
  }
  const lines = [
    'Attachment downloaded successfully.',
    `Attachment ID: ${sanitizeTerminalText(result.attachmentId)}`,
    `Destination: ${sanitizeTerminalText(result.destinationPath)}`,
    `Size: ${String(result.totalPlaintextBytes)} bytes`,
    `Plaintext SHA-256: ${sanitizeTerminalText(result.plaintextSha256)}`,
  ];
  return lines.join('\n').concat('\n');
}

export function renderAttachmentDelete(
  result: CliAttachmentDeleteResult,
  json: boolean,
): string {
  if (json) {
    return safeJson(result);
  }
  return `Attachment "${sanitizeTerminalText(result.attachmentId)}" deleted.\n`;
}

export function renderHistoryList(
  summaries: readonly CliHistorySummary[],
  json: boolean,
): string {
  if (json) {
    return safeJson(summaries);
  }
  if (summaries.length === 0) {
    return 'No history revisions found for this credential item.\n';
  }
  const lines = [
    `Credential History (${String(summaries.length)} revision(s)):`,
    ...summaries.map((summary) => {
      const parts = [
        `Revision ${String(summary.revision)}`,
        sanitizeTerminalText(summary.historyId),
        `Fields: ${String(summary.fieldCount)}`,
        `Created: ${sanitizeTerminalText(summary.createdAt)}`,
      ];
      return `  - ${parts.join(' | ')}`;
    }),
  ];
  return lines.join('\n').concat('\n');
}

export function renderHistoryDetail(detail: CliHistoryDetail, json: boolean): string {
  if (json) {
    return safeJson(detail);
  }
  const lines = [
    `Credential History Revision ${String(detail.revision)}:`,
    `  Title: ${sanitizeTerminalText(detail.title)}`,
    `  History ID: ${sanitizeTerminalText(detail.historyId)}`,
    `  Group ID: ${sanitizeTerminalText(detail.groupId)}`,
    `  Item ID: ${sanitizeTerminalText(detail.itemId)}`,
    `  Created At: ${sanitizeTerminalText(detail.createdAt)}`,
    `  Fields (${String(detail.fields.length)}):`,
    ...detail.fields.map(
      (field) =>
        `    - ${sanitizeTerminalText(field.label)} (${sanitizeTerminalText(field.type)}): ${sanitizeTerminalText(field.maskedValue)}`,
    ),
  ];
  if (detail.notes.length > 0) {
    lines.push(
      `  Notes (${String(detail.notes.length)}):`,
      ...detail.notes.map(
        (note) =>
          `    - ${sanitizeTerminalText(note.title)}: ${sanitizeTerminalText(note.body)}`,
      ),
    );
  }
  return lines.join('\n').concat('\n');
}

export function renderHistoryDiff(diff: CliHistoryDiff, json: boolean): string {
  if (json) {
    return safeJson(diff);
  }
  const lines = [
    `History Diff (Revision ${String(diff.baseRevision)} -> Revision ${String(diff.targetRevision)}):`,
    `  Group ID: ${sanitizeTerminalText(diff.groupId)}`,
    `  Item ID: ${sanitizeTerminalText(diff.itemId)}`,
    `  Added fields (${String(diff.addedFields.length)}):`,
    ...(diff.addedFields.length === 0
      ? ['    (none)']
      : diff.addedFields.map(
          (f) =>
            `    + ${sanitizeTerminalText(f.label)} [${sanitizeTerminalText(f.stableKey)}] (${sanitizeTerminalText(f.type)})`,
        )),
    `  Removed fields (${String(diff.removedFields.length)}):`,
    ...(diff.removedFields.length === 0
      ? ['    (none)']
      : diff.removedFields.map(
          (f) =>
            `    - ${sanitizeTerminalText(f.label)} [${sanitizeTerminalText(f.stableKey)}] (${sanitizeTerminalText(f.type)})`,
        )),
    `  Modified fields (${String(diff.modifiedFields.length)}):`,
    ...(diff.modifiedFields.length === 0
      ? ['    (none)']
      : diff.modifiedFields.map(
          (f) =>
            `    ~ ${sanitizeTerminalText(f.label)} [${sanitizeTerminalText(f.stableKey)}] (${sanitizeTerminalText(f.type)})`,
        )),
    `  Unchanged fields: ${String(diff.unchangedFieldCount)}`,
    `  Notes changed: ${diff.notesChanged ? 'yes' : 'no'}`,
  ];
  return lines.join('\n').concat('\n');
}

export function renderHistoryRestore(
  result: CliHistoryRestoreResult,
  json: boolean,
): string {
  if (json) {
    return safeJson(result);
  }
  const lines = [
    `Credential restored from revision ${String(result.restoredFromRevision)}.`,
    `New Revision: ${String(result.newRevision)}`,
    `Group ID: ${sanitizeTerminalText(result.groupId)}`,
    `Item ID: ${sanitizeTerminalText(result.itemId)}`,
    `Updated At: ${sanitizeTerminalText(result.updatedAt)}`,
  ];
  return lines.join('\n').concat('\n');
}

/** Renders one audit event as a single sanitized summary line. */
function auditEventLine(event: CliAuditEventSummary): string {
  const parts = [
    sanitizeTerminalText(event.occurredAt),
    `${sanitizeTerminalText(event.eventClass)}/${sanitizeTerminalText(event.action)}`,
    `Subject: ${sanitizeTerminalText(event.subject)}`,
    `Event: ${sanitizeTerminalText(event.eventId)}`,
  ];
  if (event.state !== undefined) {
    parts.push(`State: ${sanitizeTerminalText(event.state)}`);
  }
  return `  - ${parts.join(' | ')}`;
}

export function renderAuditEventList(page: CliAuditEventPage, json: boolean): string {
  if (json) {
    return safeJson(page);
  }
  if (page.events.length === 0) {
    return 'No audit events found for this vault.\n';
  }
  const lines = [
    `Audit Events (${String(page.events.length)} of ${String(page.totalCount)}):`,
    ...page.events.map((event) => auditEventLine(event)),
  ];
  if (page.nextCursor !== null) {
    lines.push(`Next cursor: ${sanitizeTerminalText(page.nextCursor)}`);
  }
  return lines.join('\n').concat('\n');
}

export function renderAuditEventDetail(
  detail: CliAuditEventDetail,
  json: boolean,
): string {
  if (json) {
    return safeJson(detail);
  }
  const { event } = detail;
  const lines = [
    `Audit Event ${sanitizeTerminalText(event.eventId)}:`,
    `  Vault ID: ${sanitizeTerminalText(detail.vaultId)}`,
    `  Class: ${sanitizeTerminalText(event.eventClass)}`,
    `  Action: ${sanitizeTerminalText(event.action)}`,
    `  Subject: ${sanitizeTerminalText(event.subject)}`,
    `  Occurred At: ${sanitizeTerminalText(event.occurredAt)}`,
  ];
  if (event.state !== undefined) {
    lines.push(`  State: ${sanitizeTerminalText(event.state)}`);
  }
  if (event.keyVersion !== undefined) {
    lines.push(`  Key Version: ${String(event.keyVersion)}`);
  }
  if (event.deviceId !== undefined) {
    lines.push(`  Device ID: ${sanitizeTerminalText(event.deviceId)}`);
  }
  if (event.recordRevision !== undefined) {
    lines.push(`  Record Revision: ${String(event.recordRevision)}`);
  }
  return lines.join('\n').concat('\n');
}

/** Joins destination names, marking which ones carry vault-classified secrets. */
function runDestinations(
  names: readonly string[],
  secretNames: readonly string[] = [],
): string {
  if (names.length === 0) return '(none)';
  const secret = new Set(secretNames);
  return names
    .map(
      (name) => `${sanitizeTerminalText(name)}${secret.has(name) ? ' (secret)' : ''}`,
    )
    .join(', ');
}

/**
 * Renders a planned guarded execution. A plan carries destination names only, so
 * this output can never contain a released value.
 */
export function renderRunPlan(plan: CliRunPlan, json: boolean): string {
  if (json) {
    return safeJson(plan);
  }
  const lines = [
    'Planned guarded execution (no command was started):',
    `  Executable: ${sanitizeTerminalText(plan.executable)}`,
    `  Arguments: ${String(plan.argumentCount)}`,
    `  Working Directory: ${sanitizeTerminalText(plan.cwd)}`,
    `  Environment Destinations: ${runDestinations(plan.environmentNames)}`,
    `  Inherited Variables: ${runDestinations(plan.inherited)}`,
    `  Timeout: ${plan.timeoutMs === null ? 'none' : `${String(plan.timeoutMs)} ms`}`,
    `  Output Limit: ${String(plan.maxOutputBytes)} bytes per stream`,
    '  No field was read, so no value was decrypted for this plan.',
  ];
  return lines.join('\n').concat('\n');
}

/** Renders one captured stream, which the runner already bounded and redacted. */
function runStream(name: string, text: string): readonly string[] {
  if (text.length === 0) return [`  ${name}: (empty)`];
  return [`  ${name}:`, sanitizeTerminalOutput(text)];
}

export function renderRunResult(result: CliRunResult, json: boolean): string {
  if (json) {
    return safeJson(result);
  }
  const lines = [
    `Command: ${sanitizeTerminalText(result.executable)}`,
    `  Exit Code: ${result.exitCode === null ? 'none' : String(result.exitCode)}`,
    `  Signal: ${result.signal === null ? 'none' : sanitizeTerminalText(result.signal)}`,
    `  Termination: ${sanitizeTerminalText(result.termination)}`,
    `  Environment Destinations: ${runDestinations(
      result.environmentNames,
      result.secretNames,
    )}`,
    `  Output Truncated: ${result.outputTruncated ? 'yes' : 'no'}`,
    ...runStream('stdout', result.stdout),
    ...runStream('stderr', result.stderr),
  ];
  return lines.join('\n').concat('\n');
}
