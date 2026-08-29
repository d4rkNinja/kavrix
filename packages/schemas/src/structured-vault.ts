import { z } from 'zod';

import { projectContextIdSchema, vaultIdSchema } from './identifiers.js';
import {
  encryptedAttachmentRecordSchema,
  encryptedHistoryRecordSchema,
} from './encrypted-records.js';
import { localVaultPayloadSchema } from './local-vault.js';
import { groupPayloadSchema, itemPayloadSchema } from './payloads.js';
import {
  nonEmptyTextSchema,
  recordRevisionSchema,
  timestampSchema,
} from './primitives.js';

/**
 * The version of the structured plaintext held by a database-vault envelope.
 * This is deliberately independent from the enclosing cryptographic schema
 * version: an authenticated payload must still reject an unknown semantic
 * representation before any of its values are used.
 */
export const CURRENT_STRUCTURED_VAULT_PAYLOAD_VERSION = 1;
export const structuredVaultPayloadVersionSchema = z.literal(
  CURRENT_STRUCTURED_VAULT_PAYLOAD_VERSION,
);

export const MAX_PROJECT_CONTEXTS = 10_000;
export const MAX_STRUCTURED_SERVICES = 10_000;
export const MAX_STRUCTURED_ITEMS = 100_000;
export const MAX_STRUCTURED_ATTACHMENTS = 100_000;
export const MAX_STRUCTURED_HISTORY_RECORDS = 1_000_000;

/** A project/deployment context is a private organizational label. */
export const projectContextSchema = z
  .object({
    id: projectContextIdSchema,
    name: nonEmptyTextSchema,
    environment: z.string().trim().max(128).optional(),
    revision: recordRevisionSchema,
    createdAt: timestampSchema,
    updatedAt: timestampSchema,
  })
  .strict();

export const projectContextPayloadSchema = projectContextSchema;

/**
 * Services are the structured form of groups. Keeping the canonical group
 * payload as the base schema prevents the typed field, note, and policy
 * contracts from drifting between standalone and database vaults.
 */
export const structuredServicePayloadSchema = groupPayloadSchema
  .extend({
    projectContextId: projectContextIdSchema,
  })
  .strict();

/** Alias that makes the group projection explicit at call sites. */
export const structuredGroupPayloadSchema = structuredServicePayloadSchema;

export const structuredVaultPayloadSchema = z
  .object({
    version: structuredVaultPayloadVersionSchema,
    vaultId: vaultIdSchema,
    projectContexts: z.array(projectContextPayloadSchema).max(MAX_PROJECT_CONTEXTS),
    groups: z.array(structuredGroupPayloadSchema).max(MAX_STRUCTURED_SERVICES),
    items: z.array(itemPayloadSchema).max(MAX_STRUCTURED_ITEMS),
    attachments: z
      .array(encryptedAttachmentRecordSchema)
      .max(MAX_STRUCTURED_ATTACHMENTS),
    history: z.array(encryptedHistoryRecordSchema).max(MAX_STRUCTURED_HISTORY_RECORDS),
  })
  .strict()
  .superRefine((payload, context) => {
    const projectContextIds = uniqueIds(
      payload.projectContexts,
      context,
      ['projectContexts'],
      'Project context IDs must be unique',
    );
    const projectContextNames = new Set<string>();
    for (const [index, projectContext] of payload.projectContexts.entries()) {
      if (projectContextNames.has(projectContext.name)) {
        addIssue(
          context,
          ['projectContexts', index, 'name'],
          'Project context names must be unique',
        );
      }
      projectContextNames.add(projectContext.name);
    }
    uniqueIds(payload.groups, context, ['groups'], 'Group IDs must be unique');
    const groupNamesByProjectContext = new Set<string>();
    for (const [index, group] of payload.groups.entries()) {
      const identity = `${group.projectContextId}\u0000${group.name}`;
      if (groupNamesByProjectContext.has(identity)) {
        addIssue(
          context,
          ['groups', index, 'name'],
          'Group names must be unique within a project context',
        );
      }
      groupNamesByProjectContext.add(identity);
    }
    uniqueIds(payload.items, context, ['items'], 'Item IDs must be unique');
    uniqueIds(
      payload.attachments,
      context,
      ['attachments'],
      'Attachment IDs must be unique',
    );
    uniqueIds(payload.history, context, ['history'], 'History IDs must be unique');

    // Keep identities distinct even though Zod brands are erased at runtime.
    // A duplicate raw identity can otherwise make a relationship map depend
    // on array order and hide a malformed record.
    const allIdentityIds = new Set<string>();
    addGlobalIdentityIds(payload.projectContexts, allIdentityIds, context, [
      'projectContexts',
    ]);
    addGlobalIdentityIds(payload.groups, allIdentityIds, context, ['groups']);
    addGlobalIdentityIds(payload.items, allIdentityIds, context, ['items']);
    addGlobalIdentityIds(payload.attachments, allIdentityIds, context, ['attachments']);
    addGlobalIdentityIds(payload.history, allIdentityIds, context, ['history']);

    for (const [index, group] of payload.groups.entries()) {
      if (group.vaultId !== payload.vaultId) {
        addIssue(
          context,
          ['groups', index, 'vaultId'],
          'Group belongs to another vault',
        );
      }
      if (!projectContextIds.has(group.projectContextId)) {
        addIssue(
          context,
          ['groups', index, 'projectContextId'],
          'Group project context must resolve within this vault',
        );
      }
    }

    const groupsById = new Map(payload.groups.map((group) => [group.id, group]));
    const itemsById = new Map(payload.items.map((item) => [item.id, item]));
    const attachmentsById = new Map(
      payload.attachments.map((attachment) => [attachment.id, attachment]),
    );

    const activeItemNamesByGroup = new Set<string>();

    for (const [index, item] of payload.items.entries()) {
      if (item.vaultId !== payload.vaultId) {
        addIssue(context, ['items', index, 'vaultId'], 'Item belongs to another vault');
      }
      const group = groupsById.get(item.groupId);
      if (group === undefined) {
        addIssue(
          context,
          ['items', index, 'groupId'],
          'Item group must resolve within this vault',
        );
      } else if (group.vaultId !== item.vaultId) {
        addIssue(
          context,
          ['items', index, 'groupId'],
          'Item group belongs to another vault',
        );
      } else if (
        item.templateId !== group.template.id ||
        item.templateVersion !== group.template.version
      ) {
        addIssue(
          context,
          ['items', index, 'templateId'],
          'Item template identity and version must match its group template',
        );
      }
      if (item.deletedAt === undefined) {
        const identity = `${item.groupId}\u0000${item.title}`;
        if (activeItemNamesByGroup.has(identity)) {
          addIssue(
            context,
            ['items', index, 'title'],
            'Active item titles must be unique within a group',
          );
        }
        activeItemNamesByGroup.add(identity);
      }

      for (const attachmentId of item.attachmentIds) {
        const attachment = attachmentsById.get(attachmentId);
        if (attachment === undefined) {
          addIssue(
            context,
            ['items', index, 'attachmentIds'],
            'Item attachment references must resolve to its own attachment records',
          );
        } else if (
          attachment.itemId !== item.id ||
          attachment.groupId !== item.groupId ||
          attachment.vaultId !== item.vaultId
        ) {
          addIssue(
            context,
            ['items', index, 'attachmentIds'],
            'Item attachment references must resolve to its own attachment records',
          );
        }
      }

      for (const relatedItemId of item.relatedItemIds) {
        const related = itemsById.get(relatedItemId);
        if (related?.vaultId !== item.vaultId) {
          addIssue(
            context,
            ['items', index, 'relatedItemIds'],
            'Related item references must resolve within this vault',
          );
        }
      }
    }

    for (const [index, attachment] of payload.attachments.entries()) {
      if (attachment.vaultId !== payload.vaultId) {
        addIssue(
          context,
          ['attachments', index, 'vaultId'],
          'Attachment belongs to another vault',
        );
      }
      const item = itemsById.get(attachment.itemId);
      if (item === undefined) {
        addIssue(
          context,
          ['attachments', index, 'itemId'],
          'Attachment item must resolve within this vault',
        );
      } else {
        if (attachment.groupId !== item.groupId) {
          addIssue(
            context,
            ['attachments', index, 'groupId'],
            'Attachment group must match its item group',
          );
        }
        if (!item.attachmentIds.includes(attachment.id)) {
          addIssue(
            context,
            ['attachments', index, 'id'],
            'Attachment must be listed by its owning item',
          );
        }
      }
    }

    for (const [index, record] of payload.history.entries()) {
      if (record.vaultId !== payload.vaultId) {
        addIssue(
          context,
          ['history', index, 'vaultId'],
          'History record belongs to another vault',
        );
      }
      const item = itemsById.get(record.itemId);
      if (item === undefined) {
        addIssue(
          context,
          ['history', index, 'itemId'],
          'History item must resolve within this vault',
        );
      } else if (record.groupId !== item.groupId) {
        addIssue(
          context,
          ['history', index, 'groupId'],
          'History group must match its item group',
        );
      }
    }
  });

/**
 * Database vaults accept the historical flat payload while they are being
 * upgraded. New writes should use `structuredVaultPayloadSchema`; the union
 * exists only at the authenticated database-vault boundary for migration.
 */
export const databaseVaultPayloadSchema = z.union([
  localVaultPayloadSchema,
  structuredVaultPayloadSchema,
]);

type Identified = Readonly<{ id: string }>;

function uniqueIds(
  values: readonly Identified[],
  context: z.core.$RefinementCtx,
  path: readonly (string | number)[],
  message: string,
): Set<string> {
  const ids = new Set<string>();
  for (const [index, value] of values.entries()) {
    if (ids.has(value.id)) {
      addIssue(context, [...path, index, 'id'], message);
    }
    ids.add(value.id);
  }
  return ids;
}

function addGlobalIdentityIds(
  values: readonly Identified[],
  allIds: Set<string>,
  context: z.core.$RefinementCtx,
  path: readonly (string | number)[],
): void {
  for (const [index, value] of values.entries()) {
    if (allIds.has(value.id)) {
      addIssue(
        context,
        [...path, index, 'id'],
        'Entity identities must be unique across the structured vault',
      );
    }
    allIds.add(value.id);
  }
}

function addIssue(
  context: z.core.$RefinementCtx,
  path: readonly (string | number)[],
  message: string,
): void {
  context.addIssue({ code: 'custom', path: [...path], message });
}

export type ProjectContextPayload = z.infer<typeof projectContextPayloadSchema>;
export type ProjectContext = ProjectContextPayload;
export type StructuredServicePayload = z.infer<typeof structuredServicePayloadSchema>;
export type StructuredGroupPayload = StructuredServicePayload;
export type StructuredVaultPayload = z.infer<typeof structuredVaultPayloadSchema>;
export type DatabaseVaultPayload = z.infer<typeof databaseVaultPayloadSchema>;
