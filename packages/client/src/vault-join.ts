import { randomFillSync } from 'node:crypto';

import type { ClockPort, IdGeneratorPort, SessionCredentialPort } from '@kavrix/core';
import {
  constantTimeEqual,
  decodeBase64Url,
  encodeBase64Url,
  zeroize,
} from '@kavrix/crypto';
import {
  apiBearerTokenSchema,
  deviceIdSchema,
  enrollmentCompleteRequestSchema,
  schemaVersionSchema,
  sessionCredentialSecretSchema,
  timestampSchema,
  vaultIdSchema,
  type ApiBearerToken,
  type DeviceId,
  type SchemaVersion,
  type SessionCredentialSecret,
  type Timestamp,
  type VaultId,
} from '@kavrix/schemas';
import { z } from 'zod';

import type { ControlPlaneClient } from './control-plane-client.js';
import { ControlPlaneFailure, VaultLifecycleError } from './errors.js';
import { unlockRedeemedVaultWithPortableKey } from './portable-enrollment.js';
import {
  JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES,
  joinJournalRecordSchema,
  joinLifecycleJournalSerializedBytes,
  joinPreparedJournalRecordSchema,
  lifecycleOperationIdListSchema,
  lifecycleOperationIdSchema,
  type JoinActiveJournalRecord,
  type JoinJournalRecord,
  type JoinLifecycleJournalPort,
  type JoinPreparedJournalRecord,
  type LifecycleOperationId,
} from './vault-lifecycle-journals.js';
import type { VaultLifecycleReceipt } from './vault-initialization.js';

const joinInputSchema = z
  .object({
    inviteBearer: apiBearerTokenSchema,
    expectedVaultId: vaultIdSchema,
    schemaVersion: schemaVersionSchema.optional(),
  })
  .strict();

export interface VaultJoinIds {
  readonly operation: IdGeneratorPort<LifecycleOperationId>;
  readonly device: IdGeneratorPort<DeviceId>;
}

export interface VaultJoinCoordinatorOptions {
  readonly controlPlane: ControlPlaneClient;
  readonly journal: JoinLifecycleJournalPort;
  readonly sessions: SessionCredentialPort;
  readonly clock: ClockPort;
  readonly ids: VaultJoinIds;
}

export interface VaultJoinInput {
  readonly inviteBearer: ApiBearerToken;
  readonly expectedVaultId: VaultId;
  readonly schemaVersion?: SchemaVersion;
}

export interface VaultJoinPreparation {
  readonly operationId: LifecycleOperationId;
  readonly vaultId: VaultId;
  readonly deviceId: DeviceId;
}

/**
 * Crash-safe invite enrollment. `begin` is local-only and durably persists all
 * independently generated successors before `resume` can perform an exchange.
 */
export class VaultJoinCoordinator {
  readonly #options: VaultJoinCoordinatorOptions;
  readonly #busy = new Set<LifecycleOperationId>();

  constructor(options: VaultJoinCoordinatorOptions) {
    this.#options = options;
  }

  async begin(input: VaultJoinInput): Promise<VaultJoinPreparation> {
    let parsed: z.infer<typeof joinInputSchema>;
    try {
      parsed = joinInputSchema.parse(input);
    } catch {
      throw new VaultLifecycleError('invalid-input');
    }
    const operationId = parseId(
      lifecycleOperationIdSchema,
      this.#options.ids.operation.next(),
    );
    const deviceId = parseId(deviceIdSchema, this.#options.ids.device.next());
    const inviteBearer = decodeBearer(parsed.inviteBearer);
    const enrollmentSuccessor = independentBearer([inviteBearer]);
    const sessionSuccessor = independentBearer([inviteBearer, enrollmentSuccessor]);
    try {
      const record = joinPreparedJournalRecordSchema.parse({
        version: 1,
        kind: 'vault-join',
        operationId,
        state: 'prepared',
        expectedVaultId: parsed.expectedVaultId,
        deviceId,
        completionRequest: enrollmentCompleteRequestSchema.parse({
          vaultId: parsed.expectedVaultId,
          deviceId,
          schemaVersion: parsed.schemaVersion ?? schemaVersionSchema.parse(1),
        }),
        sessionLocator: {
          version: 1,
          vaultId: parsed.expectedVaultId,
          deviceId,
          purpose: 'api-session',
        },
        inviteBearer,
        enrollmentSuccessor,
        sessionSuccessor,
      });
      assertBoundedJournal(record);
      await this.#options.journal.createPrepared(record);
      return {
        operationId,
        vaultId: parsed.expectedVaultId,
        deviceId,
      };
    } catch (error) {
      throw lifecycleError(error, 'journal');
    } finally {
      zeroize(inviteBearer);
      zeroize(enrollmentSuccessor);
      zeroize(sessionSuccessor);
    }
  }

  async listOperations(): Promise<readonly LifecycleOperationId[]> {
    try {
      return lifecycleOperationIdListSchema.parse(
        await this.#options.journal.listOperationIds(),
      );
    } catch {
      throw new VaultLifecycleError('journal');
    }
  }

  async resume(
    operationId: LifecycleOperationId,
    formattedPortableKey: string,
  ): Promise<VaultLifecycleReceipt> {
    const id = parseId(lifecycleOperationIdSchema, operationId);
    return this.#exclusive(id, async () => {
      const record = await this.#load(id);
      if (record === null) throw new VaultLifecycleError('operation-unavailable');
      if (record.state === 'committed') {
        return {
          operationId: record.operationId,
          vaultId: record.vaultId,
          deviceId: record.deviceId,
        };
      }
      return this.#resumeActive(record, formattedPortableKey);
    });
  }

  async cancel(operationId: LifecycleOperationId): Promise<void> {
    const id = parseId(lifecycleOperationIdSchema, operationId);
    await this.#exclusive(id, async () => {
      const record = await this.#load(id);
      if (record === null || record.state === 'committed') return;
      if (record.state !== 'prepared') throw new VaultLifecycleError('unsafe-cancel');
      try {
        await this.#options.journal.deletePrepared(id);
      } catch {
        throw new VaultLifecycleError('journal');
      }
    });
  }

  async #resumeActive(
    initial: JoinActiveJournalRecord,
    formattedPortableKey: string,
  ): Promise<VaultLifecycleReceipt> {
    let record = initial;
    if (record.state === 'prepared') {
      try {
        await this.#options.journal.markRedeemAttempted(record.operationId);
      } catch {
        throw new VaultLifecycleError('journal');
      }
      record = { ...record, state: 'redeem-attempted' };
    }
    try {
      if (
        record.state === 'completion-attempted' &&
        (await this.#recoverCommittedSession(record))
      ) {
        return await this.#commit(record);
      }
      const inviteBearer = bearerFromBytes(record.inviteBearer);
      const redemption = await this.#options.controlPlane.redeemInvite(
        inviteBearer,
        record.enrollmentSuccessor,
        record.expectedVaultId,
      );
      const expiresAt = timestampMillis(redemption.expiresAt);
      if (clockMillis(this.#options.clock) >= expiresAt) {
        throw new VaultLifecycleError('expired');
      }

      const rootKey = await unlockRedeemedVaultWithPortableKey(
        redemption,
        formattedPortableKey,
      );
      zeroize(rootKey);

      if (record.state === 'redeem-attempted') {
        try {
          await this.#options.journal.markCompletionAttempted(record.operationId);
        } catch {
          throw new VaultLifecycleError('journal');
        }
        record = { ...record, state: 'completion-attempted' };
      }

      const enrollmentBearer = bearerFromBytes(record.enrollmentSuccessor);
      await this.#options.controlPlane.completeEnrollment(
        enrollmentBearer,
        record.sessionSuccessor,
        record.completionRequest,
      );
      await this.#validateCommittedSession(record);
      await this.#storeFinalSession(record);
      return await this.#commit(record);
    } catch (error) {
      throw lifecycleError(error);
    } finally {
      wipeJoinRecord(record);
    }
  }

  async #recoverCommittedSession(record: JoinActiveJournalRecord): Promise<boolean> {
    try {
      await this.#validateCommittedSession(record);
    } catch (error) {
      if (
        error instanceof ControlPlaneFailure &&
        (error.kind === 'unauthorized' || error.kind === 'not-found')
      ) {
        return false;
      }
      throw error;
    }
    await this.#storeFinalSession(record);
    return true;
  }

  async #validateCommittedSession(record: JoinActiveJournalRecord): Promise<void> {
    const sessionBearer = bearerFromBytes(record.sessionSuccessor);
    await this.#options.controlPlane.getSession(
      sessionBearer,
      record.expectedVaultId,
      record.deviceId,
    );
  }

  async #storeFinalSession(record: JoinActiveJournalRecord): Promise<void> {
    let existing: Awaited<ReturnType<SessionCredentialPort['load']>> | undefined;
    try {
      existing = await this.#options.sessions.load(record.sessionLocator);
      if (existing !== null) {
        if (!constantTimeEqual(existing, record.sessionSuccessor)) {
          throw new VaultLifecycleError('protected-storage');
        }
        return;
      }
      await this.#options.sessions.store(
        record.sessionLocator,
        sessionCredentialSecretSchema.parse(record.sessionSuccessor),
      );
      const stored = await this.#options.sessions.load(record.sessionLocator);
      try {
        if (stored === null || !constantTimeEqual(stored, record.sessionSuccessor)) {
          throw new VaultLifecycleError('protected-storage');
        }
      } finally {
        zeroize(stored ?? undefined);
      }
    } catch (error) {
      throw lifecycleError(error, 'protected-storage');
    } finally {
      zeroize(existing ?? undefined);
    }
  }

  async #commit(record: JoinActiveJournalRecord): Promise<VaultLifecycleReceipt> {
    try {
      await this.#options.journal.commit(
        record.operationId,
        record.expectedVaultId,
        record.deviceId,
        nowTimestamp(this.#options.clock),
      );
    } catch {
      throw new VaultLifecycleError('journal');
    }
    return {
      operationId: record.operationId,
      vaultId: record.expectedVaultId,
      deviceId: record.deviceId,
    };
  }

  async #load(operationId: LifecycleOperationId): Promise<JoinJournalRecord | null> {
    let loaded: JoinJournalRecord | null | undefined;
    try {
      loaded = await this.#options.journal.load(operationId);
      if (loaded === null) return null;
      return joinJournalRecordSchema.parse(loaded);
    } catch {
      wipeJoinRecord(loaded);
      throw new VaultLifecycleError('journal');
    }
  }

  async #exclusive<Output>(
    operationId: LifecycleOperationId,
    operation: () => Promise<Output>,
  ): Promise<Output> {
    if (this.#busy.has(operationId)) throw new VaultLifecycleError('operation-busy');
    this.#busy.add(operationId);
    try {
      return await operation();
    } finally {
      this.#busy.delete(operationId);
    }
  }
}

function independentBearer(excluded: readonly Uint8Array[]): SessionCredentialSecret {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const candidate = sessionCredentialSecretSchema.parse(
      randomFillSync(new Uint8Array(32)),
    );
    if (excluded.every((value) => !constantTimeEqual(candidate, value)))
      return candidate;
    zeroize(candidate);
  }
  throw new VaultLifecycleError('protocol');
}

function decodeBearer(value: ApiBearerToken): SessionCredentialSecret {
  try {
    return sessionCredentialSecretSchema.parse(
      decodeBase64Url(value, { exactBytes: 32 }),
    );
  } catch {
    throw new VaultLifecycleError('invalid-input');
  }
}

function bearerFromBytes(value: Uint8Array): ApiBearerToken {
  try {
    return apiBearerTokenSchema.parse(encodeBase64Url(value));
  } catch {
    throw new VaultLifecycleError('protocol');
  }
}

function assertBoundedJournal(record: JoinPreparedJournalRecord): void {
  if (
    joinLifecycleJournalSerializedBytes(record) >
    JOIN_LIFECYCLE_JOURNAL_MAX_SERIALIZED_BYTES
  ) {
    throw new VaultLifecycleError('journal');
  }
}

function timestampMillis(value: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new VaultLifecycleError('protocol');
  return parsed;
}

function nowTimestamp(clock: ClockPort): Timestamp {
  try {
    return timestampSchema.parse(clock.now().toISOString());
  } catch {
    throw new VaultLifecycleError('invalid-input');
  }
}

function clockMillis(clock: ClockPort): number {
  const value = clock.now().getTime();
  if (!Number.isFinite(value)) throw new VaultLifecycleError('invalid-input');
  return value;
}

function parseId<Output>(
  schema: Readonly<{ parse(value: unknown): Output }>,
  value: unknown,
): Output {
  try {
    return schema.parse(value);
  } catch {
    throw new VaultLifecycleError('invalid-input');
  }
}

function wipeJoinRecord(record: JoinJournalRecord | null | undefined): void {
  if (record === undefined || record === null || record.state === 'committed') return;
  zeroize(record.inviteBearer);
  zeroize(record.enrollmentSuccessor);
  zeroize(record.sessionSuccessor);
}

function lifecycleError(
  error: unknown,
  fallback: ConstructorParameters<typeof VaultLifecycleError>[0] = 'protocol',
): Error {
  return error instanceof VaultLifecycleError || error instanceof ControlPlaneFailure
    ? error
    : new VaultLifecycleError(fallback);
}
