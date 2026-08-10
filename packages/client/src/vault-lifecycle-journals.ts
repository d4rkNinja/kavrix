import {
  deviceIdSchema,
  enrollmentCompleteRequestSchema,
  keychainLocatorSchema,
  sessionCredentialLocatorSchema,
  timestampSchema,
  vaultBootstrapRequestSchema,
  vaultBootstrapResponseSchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { z } from 'zod';

export const lifecycleOperationIdSchema = z
  .string()
  .min(16)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._~-]*$/)
  .brand<'LifecycleOperationId'>();

export type LifecycleOperationId = z.infer<typeof lifecycleOperationIdSchema>;
export const JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES = 1_536;

export const lifecycleOperationIdListSchema = z
  .array(lifecycleOperationIdSchema)
  .max(256)
  .refine((values) => new Set(values).size === values.length, {
    error: 'Lifecycle operation IDs must be unique',
  })
  .refine(
    (values) =>
      values.every((value, index) => {
        if (index === 0) return true;
        const previous = values[index - 1];
        return previous !== undefined && previous < value;
      }),
    { error: 'Lifecycle operation IDs must use canonical lexical order' },
  );

const initializationActiveSchema = z
  .object({
    version: z.literal(1),
    kind: z.literal('vault-initialization'),
    operationId: lifecycleOperationIdSchema,
    state: z.enum(['prepared', 'network-attempted']),
    request: vaultBootstrapRequestSchema,
    deviceLocator: keychainLocatorSchema,
    sessionLocator: sessionCredentialLocatorSchema,
  })
  .strict()
  .superRefine((record, context) => {
    const { vault, device } = record.request;
    if (
      record.deviceLocator.vaultId !== vault.id ||
      record.deviceLocator.deviceId !== device.id ||
      record.sessionLocator.vaultId !== vault.id ||
      record.sessionLocator.deviceId !== device.id
    ) {
      context.addIssue({
        code: 'custom',
        path: ['request'],
        message: 'Protected locators must match the initialization request',
      });
    }
    const deviceSlot = vault.keySlots.find(
      (slot) => slot.id === record.deviceLocator.keySlotId,
    );
    if (
      deviceSlot?.type !== 'device-key' ||
      deviceSlot.deviceId !== device.id ||
      deviceSlot.state !== 'active' ||
      deviceSlot.keyVersion !== vault.currentKeyVersion
    ) {
      context.addIssue({
        code: 'custom',
        path: ['deviceLocator', 'keySlotId'],
        message: 'The device locator must identify the current active device slot',
      });
    }
  });

const initializationCommittedSchema = z
  .object({
    version: z.literal(1),
    kind: z.literal('vault-initialization'),
    operationId: lifecycleOperationIdSchema,
    state: z.literal('committed'),
    receipt: vaultBootstrapResponseSchema,
    committedAt: timestampSchema,
  })
  .strict();

export const initializationJournalRecordSchema = z.union([
  initializationActiveSchema,
  initializationCommittedSchema,
]);

export type InitializationActiveJournalRecord = z.infer<
  typeof initializationActiveSchema
>;
export type InitializationCommittedJournalRecord = z.infer<
  typeof initializationCommittedSchema
>;
export type InitializationJournalRecord = z.infer<
  typeof initializationJournalRecordSchema
>;

const successorSecretSchema = z
  .instanceof(Uint8Array)
  .refine((value) => value.byteLength === 32, {
    error: 'Lifecycle bearer material must contain exactly 32 bytes',
  })
  .brand<'LifecycleBearerSecret'>();

const joinSecretBaseSchema = z
  .object({
    version: z.literal(1),
    kind: z.literal('vault-join'),
    operationId: lifecycleOperationIdSchema,
    expectedVaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
    completionRequest: enrollmentCompleteRequestSchema,
    sessionLocator: sessionCredentialLocatorSchema,
    inviteBearer: successorSecretSchema,
    enrollmentSuccessor: successorSecretSchema,
    sessionSuccessor: successorSecretSchema,
  })
  .strict();

type JoinSecretBase = z.infer<typeof joinSecretBaseSchema>;

const joinActiveSchema = joinSecretBaseSchema
  .extend({
    state: z.enum(['prepared', 'redeem-attempted', 'completion-attempted']),
  })
  .strict()
  .refine(
    (record) =>
      serializedJoinBytes(record) <= JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES,
    {
      error: 'The protected lifecycle journal record is too large',
    },
  );

export const joinPreparedJournalRecordSchema = joinSecretBaseSchema
  .extend({ state: z.literal('prepared') })
  .strict()
  .refine(
    (record) =>
      serializedJoinBytes(record) <= JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES,
    {
      error: 'The protected lifecycle journal record is too large',
    },
  );

const joinCommittedSchema = z
  .object({
    version: z.literal(1),
    kind: z.literal('vault-join'),
    operationId: lifecycleOperationIdSchema,
    state: z.literal('committed'),
    vaultId: vaultIdSchema,
    deviceId: deviceIdSchema,
    committedAt: timestampSchema,
  })
  .strict();

export const joinJournalRecordSchema = z
  .union([joinActiveSchema, joinCommittedSchema])
  .superRefine((record, context) => {
    if (record.state === 'committed') return;
    if (
      record.completionRequest.vaultId !== record.expectedVaultId ||
      record.completionRequest.deviceId !== record.deviceId ||
      record.sessionLocator.vaultId !== record.expectedVaultId ||
      record.sessionLocator.deviceId !== record.deviceId
    ) {
      context.addIssue({
        code: 'custom',
        path: ['completionRequest'],
        message: 'Join records must use one exact vault and device binding',
      });
    }
  });

export type JoinPreparedJournalRecord = z.infer<typeof joinPreparedJournalRecordSchema>;
export type JoinActiveJournalRecord = z.infer<typeof joinActiveSchema>;
export type JoinCommittedJournalRecord = z.infer<typeof joinCommittedSchema>;
export type JoinJournalRecord = z.infer<typeof joinJournalRecordSchema>;

/**
 * Durable, opaque initialization recovery state.
 *
 * Implementations must durably flush before resolving, atomically reserve each
 * operation ID and protected locator, reject incompatible reuse, and implement
 * transitions as compare-and-set operations that are idempotent only for an
 * identical target record. `commit` must atomically replace the encrypted
 * request and locators with the receipt. `deletePrepared` must reject any state
 * other than `prepared`. Loaded values are fresh structural copies.
 */
export interface InitializationJournalPort {
  createPrepared(record: InitializationActiveJournalRecord): Promise<void>;
  listOperationIds(): Promise<readonly LifecycleOperationId[]>;
  load(operationId: LifecycleOperationId): Promise<InitializationJournalRecord | null>;
  markNetworkAttempted(operationId: LifecycleOperationId): Promise<void>;
  commit(
    operationId: LifecycleOperationId,
    receipt: InitializationCommittedJournalRecord['receipt'],
    committedAt: InitializationCommittedJournalRecord['committedAt'],
  ): Promise<void>;
  deletePrepared(operationId: LifecycleOperationId): Promise<void>;
}

/**
 * Protected durable join recovery state. This port stores bearer-equivalent
 * bytes and therefore requires native protected storage; a plaintext file or
 * in-memory production fallback is forbidden. The fixed secret-bearing record
 * must serialize to at most 1,536 bytes in the adapter's canonical encoding.
 * A redeemed VaultRecord is deliberately never stored here: it can exceed
 * native credential-manager limits and is safely recovered by replaying the
 * exact redeem exchange.
 *
 * Implementations must copy all byte inputs before resolving and return fresh
 * owned byte arrays from `load`. The caller zeroizes every loaded array. They
 * must atomically reserve operation/session identities, reject incompatible
 * reuse, durably flush before resolving, and make transitions compare-and-set
 * and idempotent only for identical target data. `commit` atomically replaces
 * all bearer material with the non-secret receipt and wipes superseded
 * protected bytes. `deletePrepared` accepts only `prepared`.
 */
export interface JoinLifecycleJournalPort {
  createPrepared(record: JoinPreparedJournalRecord): Promise<void>;
  listOperationIds(): Promise<readonly LifecycleOperationId[]>;
  load(operationId: LifecycleOperationId): Promise<JoinJournalRecord | null>;
  markRedeemAttempted(operationId: LifecycleOperationId): Promise<void>;
  markCompletionAttempted(operationId: LifecycleOperationId): Promise<void>;
  commit(
    operationId: LifecycleOperationId,
    vaultId: JoinCommittedJournalRecord['vaultId'],
    deviceId: JoinCommittedJournalRecord['deviceId'],
    committedAt: JoinCommittedJournalRecord['committedAt'],
  ): Promise<void>;
  deletePrepared(operationId: LifecycleOperationId): Promise<void>;
}

/** Size of the canonical protected representation without materializing tokens. */
export function joinLifecycleJournalSerializedBytes(
  value: JoinPreparedJournalRecord,
): number {
  const record = joinPreparedJournalRecordSchema.parse(value);
  return serializedJoinBytes(record);
}

function serializedJoinBytes(
  record: JoinSecretBase & {
    readonly state: 'prepared' | 'redeem-attempted' | 'completion-attempted';
  },
): number {
  const placeholder = 'A'.repeat(43);
  const serialized = JSON.stringify({
    ...record,
    inviteBearer: placeholder,
    enrollmentSuccessor: placeholder,
    sessionSuccessor: placeholder,
  });
  return Buffer.byteLength(serialized, 'utf8');
}
