import {
  lifecycleOperationIdSchema,
  type LifecycleOperationId,
} from './vault-lifecycle-journals.js';
import {
  portableKeyRotationJournalRecordSchema as storedPortableKeyRotationJournalRecordSchema,
  type DeviceId,
  type PortableKeyRotationCheckpoint,
  type PortableKeyRotationJournalRecord as StoredPortableKeyRotationJournalRecord,
  type Timestamp,
  type VaultId,
} from '@kavrix/schemas';
import { z } from 'zod';

export const portableKeyRotationJournalRecordSchema =
  storedPortableKeyRotationJournalRecordSchema;

export type PortableKeyRotationJournalRecord = Omit<
  StoredPortableKeyRotationJournalRecord,
  'operationId'
> & {
  readonly operationId: LifecycleOperationId;
};

export type PortableKeyRotationActiveJournalRecord = PortableKeyRotationJournalRecord;

export interface PortableKeyRotationJournalPort {
  createPrepared(record: PortableKeyRotationJournalRecord): Promise<void>;
  listOperationIds(): Promise<readonly LifecycleOperationId[]>;
  load(
    operationId: LifecycleOperationId,
  ): Promise<PortableKeyRotationJournalRecord | null>;
  markPendingPublished(
    operationId: LifecycleOperationId,
    updatedAt: Timestamp,
    checkpoint: PortableKeyRotationCheckpoint,
  ): Promise<void>;
  markActivePublished(
    operationId: LifecycleOperationId,
    updatedAt: Timestamp,
    checkpoint: PortableKeyRotationCheckpoint,
  ): Promise<void>;
  complete(
    operationId: LifecycleOperationId,
    completedAt: Timestamp,
    checkpoint: PortableKeyRotationCheckpoint,
  ): Promise<void>;
}

export function parsePortableKeyRotationJournalRecord(
  value: unknown,
): PortableKeyRotationJournalRecord {
  const parsed = portableKeyRotationJournalRecordSchema.parse(value);
  return {
    ...parsed,
    operationId: lifecycleOperationIdSchema.parse(parsed.operationId),
  };
}

export function portableKeyRotationJournalSerializedBytes(
  value: PortableKeyRotationJournalRecord,
): number {
  const parsed = parsePortableKeyRotationJournalRecord(value);
  return Buffer.byteLength(JSON.stringify(parsed), 'utf8');
}

export function portableKeyRotationOperationId(value: unknown): LifecycleOperationId {
  return lifecycleOperationIdSchema.parse(value);
}

export type PortableKeyRotationDeviceBinding = Readonly<{
  readonly vaultId: VaultId;
  readonly deviceId: DeviceId;
}>;

export const portableKeyRotationJournalInputSchema = z.object({
  operationId: lifecycleOperationIdSchema,
});
