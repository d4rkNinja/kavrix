import { z } from 'zod';

export const MIN_OPAQUE_ID_CHARS = 1;
export const MAX_OPAQUE_ID_CHARS = 128;
export const OPAQUE_ID_PATTERN_SOURCE = '^[A-Za-z0-9][A-Za-z0-9._~-]*$';

const opaqueIdPattern = new RegExp(OPAQUE_ID_PATTERN_SOURCE);
const opaqueId = z
  .string()
  .min(MIN_OPAQUE_ID_CHARS)
  .max(MAX_OPAQUE_ID_CHARS)
  .regex(opaqueIdPattern, 'Must be an opaque identifier');

export const vaultIdSchema = opaqueId.brand<'VaultId'>();
export const databaseIdSchema = opaqueId.brand<'DatabaseId'>();
export const profileIdSchema = opaqueId.brand<'ProfileId'>();
export const keySlotIdSchema = opaqueId.brand<'KeySlotId'>();
export const groupIdSchema = opaqueId.brand<'GroupId'>();
export const itemIdSchema = opaqueId.brand<'ItemId'>();
export const fieldIdSchema = opaqueId.brand<'FieldId'>();
export const noteIdSchema = opaqueId.brand<'NoteId'>();
export const templateIdSchema = opaqueId.brand<'TemplateId'>();
export const templateMigrationIdSchema = opaqueId.brand<'TemplateMigrationId'>();
export const deviceIdSchema = opaqueId.brand<'DeviceId'>();
export const changeIdSchema = opaqueId.brand<'ChangeId'>();
export const auditEventIdSchema = opaqueId.brand<'AuditEventId'>();
export const attachmentIdSchema = opaqueId.brand<'AttachmentId'>();
export const historyIdSchema = opaqueId.brand<'HistoryId'>();
export const inviteIdSchema = opaqueId.brand<'InviteId'>();
export const policyIdSchema = opaqueId.brand<'PolicyId'>();
export const grantIdSchema = opaqueId.brand<'GrantId'>();

export type VaultId = z.infer<typeof vaultIdSchema>;
export type DatabaseId = z.infer<typeof databaseIdSchema>;
export type ProfileId = z.infer<typeof profileIdSchema>;
export type KeySlotId = z.infer<typeof keySlotIdSchema>;
export type GroupId = z.infer<typeof groupIdSchema>;
export type ItemId = z.infer<typeof itemIdSchema>;
export type FieldId = z.infer<typeof fieldIdSchema>;
export type NoteId = z.infer<typeof noteIdSchema>;
export type TemplateId = z.infer<typeof templateIdSchema>;
export type TemplateMigrationId = z.infer<typeof templateMigrationIdSchema>;
export type DeviceId = z.infer<typeof deviceIdSchema>;
export type ChangeId = z.infer<typeof changeIdSchema>;
export type AuditEventId = z.infer<typeof auditEventIdSchema>;
export type AttachmentId = z.infer<typeof attachmentIdSchema>;
export type HistoryId = z.infer<typeof historyIdSchema>;
export type InviteId = z.infer<typeof inviteIdSchema>;
export type PolicyId = z.infer<typeof policyIdSchema>;
export type GrantId = z.infer<typeof grantIdSchema>;
