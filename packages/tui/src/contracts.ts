import type {
  FieldDefinition,
  GroupId,
  GroupPayload,
  ItemId,
  ItemPayload,
  RecordRevision,
} from '@kavrix/schemas';

export type TuiSaveResult =
  | Readonly<{ status: 'saved'; item: ItemPayload }>
  | Readonly<{
      status: 'conflict';
      local: ItemPayload;
      remote: ItemPayload;
    }>;

export interface TuiUseCasePort {
  /** Returns decrypted group metadata only after the caller has unlocked locally. */
  listGroups(signal: AbortSignal): Promise<readonly GroupPayload[]>;
  /** Loads one selected group's decrypted items; implementations must not pre-load other groups. */
  listItems(groupId: GroupId, signal: AbortSignal): Promise<readonly ItemPayload[]>;
  /** Copies through the platform clipboard policy without returning the value to the TUI. */
  copyField(
    itemId: ItemId,
    fieldId: FieldDefinition['id'],
    options: Readonly<{ index?: number }>,
    signal: AbortSignal,
  ): Promise<void>;
  /** Enforces the field's reveal and reauthentication policy without returning data. */
  authorizeReveal(
    itemId: ItemId,
    fieldId: FieldDefinition['id'],
    options: Readonly<{ index?: number }>,
    signal: AbortSignal,
  ): Promise<void>;
  /** Persists a canonical item draft with optimistic concurrency. */
  saveItem(
    item: ItemPayload,
    expectedRevision: RecordRevision,
    signal: AbortSignal,
  ): Promise<TuiSaveResult>;
  /** Clears use-case-owned decrypted state and device-local unlock material from memory. */
  lock(signal: AbortSignal): Promise<void>;
}
