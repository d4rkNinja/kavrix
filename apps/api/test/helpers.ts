import { isDeepStrictEqual } from 'node:util';

import {
  advanceAttachmentStaging,
  createAttachmentStagingProgress,
  validateAttachmentStagingFinalization,
  ValidationError,
  type AttachmentStreamStagingSession,
  type ClockPort,
  type IdGeneratorPort,
} from '@kavrix/core';
import {
  aeadEnvelopeSchema,
  attachmentStreamFinalizeInputSchema,
  attachmentStreamStartInputSchema,
  associatedDataSchema,
  changeRecordSchema,
  controlListPageOptionsSchema,
  contentHashForRecord,
  decodeControlListCursor,
  deviceIdSchema,
  deviceRecordSchema,
  encodeControlListCursor,
  groupIdSchema,
  inviteIdSchema,
  keySlotIdSchema,
  publicInviteRecordSchema,
  sha256DigestSchema,
  syncPushResponseSchema,
  templateMigrationPublicationResponseSchema,
  timestampSchema,
  tombstoneRecordSchema,
  vaultIdSchema,
  vaultRecordSchema,
  vaultBootstrapResponseSchema,
  type ApiScope,
  type AeadEnvelope,
  type AttachmentId,
  type AttachmentStreamFinalizeInput,
  type AttachmentStreamProgress,
  type AttachmentStreamStartInput,
  type ChangeRecord,
  type ControlListCursorPayload,
  type ControlListPageOptions,
  type DeviceId,
  type DeviceRecord,
  type EncryptedAttachmentRecord,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type InviteId,
  type GroupId,
  type ItemId,
  type OpaqueMutation,
  type PersistedAttachmentChunkRecord,
  type PersistedAttachmentHeaderRecord,
  type PublicInviteRecord,
  type SyncPulledChange,
  type Sha256Digest,
  type SyncCursor,
  type SyncPullResponse,
  type SyncPushRequest,
  type SyncPushResponse,
  type TemplateMigrationPublicationRequest,
  type TemplateMigrationPublicationResponse,
  type Timestamp,
  type TombstoneRecord,
  type VaultId,
  type VaultRecord,
  type VaultBootstrapResponse,
} from '@kavrix/schemas';

import {
  ApiConflictError,
  NodeTokenPort,
  type ApiPorts,
  type ApiStoragePort,
  type AuthorizationDevicePage,
  type AuthorizationInvitePage,
  type AuthorizationPort,
  type EnrollmentCompletion,
  type InviteGrant,
  type InviteRedemption,
  type RateLimitAttempt,
  type RateLimitPort,
  type SessionPrincipal,
  type VaultBootstrapInput,
  type VaultBootstrapPort,
} from '../src/index.js';
import { bindSessionToDevice } from '../src/session-device-binding.js';

export const vaultId = vaultIdSchema.parse('vault-1');
export const otherVaultId = vaultIdSchema.parse('vault-2');
export const deviceId = deviceIdSchema.parse('device-1');
export const nowIso = '2026-08-10T00:00:00.000Z';

export class TestClock implements ClockPort {
  private current = new Date(nowIso);

  public now(): Date {
    return new Date(this.current);
  }

  public advanceSeconds(seconds: number): void {
    this.current = new Date(this.current.getTime() + seconds * 1_000);
  }
}

interface EnrollmentGrant {
  readonly vaultId: VaultId;
  readonly scopes: readonly ApiScope[];
  readonly expiresAt: Timestamp;
}

export class MemoryAuthorization implements AuthorizationPort {
  readonly invites = new Map<string, InviteGrant>();
  readonly enrollments = new Map<string, EnrollmentGrant>();
  readonly sessions = new Map<string, SessionPrincipal>();
  readonly devices = new Map<string, DeviceRecord>();
  readonly redemptions = new Map<
    string,
    Readonly<{ enrollmentTokenHash: Sha256Digest; value: InviteRedemption }>
  >();
  readonly completions = new Map<
    string,
    Readonly<{
      expiresAt: Timestamp;
      input: EnrollmentCompletion;
      value: DeviceRecord;
    }>
  >();

  public findSession(
    tokenHash: Sha256Digest,
    now: Date,
  ): Promise<SessionPrincipal | null> {
    void now;
    const session = this.sessions.get(tokenHash);
    const device =
      session === undefined ? undefined : this.devices.get(session.deviceId);
    if (session === undefined || device === undefined) return Promise.resolve(null);
    return Promise.resolve(
      bindSessionToDevice({
        presentedTokenHash: tokenHash,
        sessionTokenHash: tokenHash,
        session,
        device,
      }),
    );
  }

  public createInvite(grant: InviteGrant): Promise<void> {
    this.invites.set(grant.tokenHash, structuredClone(grant));
    return Promise.resolve();
  }

  public async listInvitePage(
    vaultInput: VaultId,
    optionsInput: ControlListPageOptions,
    now: Date,
  ): Promise<AuthorizationInvitePage> {
    await Promise.resolve();
    const vault = vaultIdSchema.parse(vaultInput);
    const options = controlListPageOptionsSchema.parse(optionsInput);
    const cursor = bindMemoryControlListCursor(options, 'invites', vault);
    const values = [...this.invites.values()]
      .filter((invite) => invite.vaultId === vault)
      .map((invite) =>
        publicInviteRecordSchema.parse({
          id: invite.id,
          vaultId: invite.vaultId,
          issuedByDeviceId: invite.issuedByDeviceId,
          scopes: invite.scopes,
          state:
            invite.revokedAt !== undefined
              ? 'revoked'
              : invite.consumedAt !== undefined
                ? 'redeemed'
                : Date.parse(invite.expiresAt) <= now.getTime()
                  ? 'expired'
                  : 'active',
          createdAt: invite.createdAt,
          expiresAt: invite.expiresAt,
          ...(invite.consumedAt === undefined ? {} : { consumedAt: invite.consumedAt }),
          ...(invite.revokedAt === undefined ? {} : { revokedAt: invite.revokedAt }),
        }),
      )
      .sort(compareInviteRows)
      .filter((invite) => cursor === undefined || isAfterInviteCursor(invite, cursor));
    const invites = values.slice(0, options.limit);
    const final = invites.at(-1);
    return {
      invites,
      nextCursor:
        values.length <= options.limit || final === undefined
          ? null
          : encodeControlListCursor({
              version: 1,
              resource: 'invites',
              vaultId: vault,
              createdAt: final.createdAt,
              id: final.id,
            }),
    };
  }

  public revokeInvite(
    vault: VaultId,
    inviteId: InviteId,
    revokedAt: Timestamp,
  ): Promise<boolean> {
    for (const [hash, invite] of this.invites) {
      if (
        invite.vaultId === vault &&
        invite.id === inviteId &&
        invite.revokedAt !== undefined
      ) {
        return Promise.resolve(true);
      }
      if (
        invite.vaultId === vault &&
        invite.id === inviteId &&
        invite.consumedAt === undefined &&
        invite.revokedAt === undefined &&
        Date.parse(invite.expiresAt) > Date.parse(revokedAt)
      ) {
        this.invites.set(hash, { ...invite, revokedAt });
        return Promise.resolve(true);
      }
    }
    return Promise.resolve(false);
  }

  public redeemInvite(
    inviteTokenHash: Sha256Digest,
    enrollmentTokenHash: Sha256Digest,
    enrollmentExpiresAt: Timestamp,
    now: Date,
  ): Promise<InviteRedemption | null> {
    const previous = this.redemptions.get(inviteTokenHash);
    if (previous !== undefined) {
      return Promise.resolve(
        previous.enrollmentTokenHash === enrollmentTokenHash &&
          Date.parse(previous.value.enrollmentExpiresAt) > now.getTime()
          ? structuredClone(previous.value)
          : null,
      );
    }
    const invite = this.invites.get(inviteTokenHash);
    if (
      invite === undefined ||
      invite.revokedAt !== undefined ||
      invite.consumedAt !== undefined ||
      Date.parse(invite.expiresAt) <= now.getTime() ||
      this.hasCredentialHash(enrollmentTokenHash)
    ) {
      return Promise.resolve(null);
    }
    this.invites.set(inviteTokenHash, {
      ...invite,
      consumedAt: timestampSchema.parse(now.toISOString()),
    });
    const expiresAt = timestampSchema.parse(
      new Date(
        Math.min(Date.parse(invite.expiresAt), Date.parse(enrollmentExpiresAt)),
      ).toISOString(),
    );
    this.enrollments.set(enrollmentTokenHash, {
      vaultId: invite.vaultId,
      scopes: invite.scopes,
      expiresAt,
    });
    const value = {
      vaultId: invite.vaultId,
      scopes: invite.scopes,
      enrollmentExpiresAt: expiresAt,
    } satisfies InviteRedemption;
    this.redemptions.set(inviteTokenHash, {
      enrollmentTokenHash,
      value: structuredClone(value),
    });
    return Promise.resolve(value);
  }

  public completeEnrollment(
    enrollmentTokenHash: Sha256Digest,
    completion: EnrollmentCompletion,
    now: Date,
  ): Promise<DeviceRecord | null> {
    const previous = this.completions.get(enrollmentTokenHash);
    if (previous !== undefined) {
      const device = this.devices.get(completion.deviceId);
      const session = this.sessions.get(completion.sessionTokenHash);
      const intactAuthorization =
        device !== undefined &&
        session !== undefined &&
        device.revokedAt === undefined &&
        bindSessionToDevice({
          presentedTokenHash: completion.sessionTokenHash,
          sessionTokenHash: completion.sessionTokenHash,
          session,
          device,
        }) !== null;
      return Promise.resolve(
        isDeepStrictEqual(previous.input, completion) &&
          Date.parse(previous.expiresAt) > now.getTime() &&
          intactAuthorization
          ? structuredClone(previous.value)
          : null,
      );
    }
    const enrollment = this.enrollments.get(enrollmentTokenHash);
    if (
      enrollment?.expiresAt === undefined ||
      enrollment.vaultId !== completion.vaultId ||
      this.devices.has(completion.deviceId) ||
      this.hasCredentialHash(completion.sessionTokenHash) ||
      Date.parse(enrollment.expiresAt) <= now.getTime()
    ) {
      return Promise.resolve(null);
    }
    this.enrollments.delete(enrollmentTokenHash);
    const createdAt = timestampSchema.parse(now.toISOString());
    const device = deviceRecordSchema.parse({
      id: completion.deviceId,
      vaultId: enrollment.vaultId,
      schemaVersion: completion.schemaVersion,
      tokenHash: completion.sessionTokenHash,
      tokenVersion: 1,
      ...(completion.encryptedLabel === undefined
        ? {}
        : { encryptedLabel: completion.encryptedLabel }),
      scopes: enrollment.scopes,
      createdAt,
    });
    this.devices.set(device.id, device);
    this.sessions.set(completion.sessionTokenHash, {
      vaultId: enrollment.vaultId,
      deviceId: completion.deviceId,
      scopes: enrollment.scopes,
    });
    this.completions.set(enrollmentTokenHash, {
      expiresAt: enrollment.expiresAt,
      input: structuredClone(completion),
      value: structuredClone(device),
    });
    return Promise.resolve(device);
  }

  private hasCredentialHash(hash: Sha256Digest): boolean {
    return (
      this.invites.has(hash) || this.enrollments.has(hash) || this.sessions.has(hash)
    );
  }

  public async listDevicePage(
    vaultInput: VaultId,
    optionsInput: ControlListPageOptions,
  ): Promise<AuthorizationDevicePage> {
    await Promise.resolve();
    const vault = vaultIdSchema.parse(vaultInput);
    const options = controlListPageOptionsSchema.parse(optionsInput);
    const cursor = bindMemoryControlListCursor(options, 'devices', vault);
    const values = [...this.devices.values()]
      .filter((device) => device.vaultId === vault)
      .sort(compareDeviceRows)
      .filter((device) => cursor === undefined || isAfterDeviceCursor(device, cursor));
    const devices = values.slice(0, options.limit);
    const final = devices.at(-1);
    return {
      devices,
      nextCursor:
        values.length <= options.limit || final === undefined
          ? null
          : encodeControlListCursor({
              version: 1,
              resource: 'devices',
              vaultId: vault,
              createdAt: final.createdAt,
              id: final.id,
            }),
    };
  }

  public revokeDevice(
    vault: VaultId,
    targetDeviceId: DeviceId,
    revokedAt: Timestamp,
  ): Promise<boolean> {
    const device = this.devices.get(targetDeviceId);
    if (device?.vaultId !== vault) {
      return Promise.resolve(false);
    }
    this.devices.set(
      targetDeviceId,
      deviceRecordSchema.parse({ ...device, revokedAt }),
    );
    for (const [hash, principal] of this.sessions) {
      if (principal.deviceId === targetDeviceId && principal.vaultId === vault) {
        this.sessions.delete(hash);
      }
    }
    return Promise.resolve(true);
  }

  public seedSession(
    hash: Sha256Digest,
    principal: SessionPrincipal,
    createdAt = timestampSchema.parse(nowIso),
  ): void {
    this.sessions.set(hash, principal);
    this.devices.set(
      principal.deviceId,
      deviceRecordSchema.parse({
        id: principal.deviceId,
        vaultId: principal.vaultId,
        schemaVersion: 1,
        tokenHash: hash,
        tokenVersion: 1,
        scopes: principal.scopes,
        createdAt,
      }),
    );
  }
}

export class MemoryRateLimits implements RateLimitPort {
  readonly attempts = new Map<string, number>();
  denied = false;

  public consume(attempt: RateLimitAttempt): Promise<boolean> {
    const count = (this.attempts.get(attempt.key) ?? 0) + 1;
    this.attempts.set(attempt.key, count);
    return Promise.resolve(!this.denied && count <= attempt.limit);
  }
}

export class MemoryStorage implements ApiStoragePort {
  readonly vaults = new Map<string, VaultRecord>();
  readonly changes: SyncPulledChange[] = [];
  readonly batches = new Map<string, SyncPushResponse>();
  readonly batchRequests = new Map<string, string>();
  readonly acceptedMutations = new Map<string, ChangeRecord>();
  readonly migrationPublications = new Map<
    string,
    TemplateMigrationPublicationResponse
  >();
  readonly migrationPublicationRequests = new Map<string, string>();
  readonly attachments = new Map<string, EncryptedAttachmentRecord>();
  readonly groups = new Map<string, EncryptedGroupRecord>();
  readonly items = new Map<string, EncryptedItemRecord>();
  readonly attachmentHeaders = new Map<string, PersistedAttachmentHeaderRecord>();
  readonly attachmentChunks = new Map<string, PersistedAttachmentChunkRecord>();
  readonly attachmentStaging = new Map<
    string,
    {
      readonly start: AttachmentStreamStartInput;
      progress: AttachmentStreamProgress;
      readonly chunks: Map<number, PersistedAttachmentChunkRecord>;
      state: 'active' | 'finalized' | 'aborted';
      finalize?: AttachmentStreamFinalizeInput;
    }
  >();

  public getVault(id: VaultId): Promise<VaultRecord | null> {
    return Promise.resolve(this.vaults.get(id) ?? null);
  }

  public getAttachment(
    targetVaultId: VaultId,
    attachmentId: AttachmentId,
  ): Promise<EncryptedAttachmentRecord | null> {
    return Promise.resolve(
      structuredClone(
        this.attachments.get(attachmentKey(targetVaultId, attachmentId)),
      ) ?? null,
    );
  }

  public getGroup(
    targetVaultId: VaultId,
    groupId: GroupId,
  ): Promise<EncryptedGroupRecord | null> {
    const record = this.groups.get(attachmentKey(targetVaultId, groupId));
    return Promise.resolve(
      record === undefined || record.tombstonedAt !== undefined
        ? null
        : structuredClone(record),
    );
  }

  public getItem(
    targetVaultId: VaultId,
    itemId: ItemId,
  ): Promise<EncryptedItemRecord | null> {
    const record = this.items.get(attachmentKey(targetVaultId, itemId));
    return Promise.resolve(
      record === undefined || record.tombstonedAt !== undefined
        ? null
        : structuredClone(record),
    );
  }

  public beginAttachmentStream(
    inputValue: AttachmentStreamStartInput,
  ): Promise<AttachmentStreamStagingSession> {
    const input = attachmentStreamStartInputSchema.parse(inputValue);
    const key = `${input.header.record.vaultId}:${input.idempotencyKey}`;
    let staging = this.attachmentStaging.get(key);
    if (staging === undefined) {
      staging = {
        start: structuredClone(input),
        progress: createAttachmentStagingProgress(),
        chunks: new Map(),
        state: 'active',
      };
      this.attachmentStaging.set(key, staging);
    } else if (
      !isDeepStrictEqual(staging.start, input) ||
      staging.state === 'aborted'
    ) {
      throw new ValidationError();
    }
    const current = staging;
    return Promise.resolve({
      progress: structuredClone(current.progress),
      writeChunk: (chunk) => {
        if (current.state !== 'active') throw new ValidationError();
        const advanced = advanceAttachmentStaging(
          current.start,
          current.progress,
          chunk,
        );
        if (advanced.disposition === 'staged') {
          current.chunks.set(chunk.record.index, structuredClone(chunk));
          current.progress = advanced.progress;
        }
        return Promise.resolve(structuredClone(current.progress));
      },
      finalize: (finalizeValue) => {
        const finalize = attachmentStreamFinalizeInputSchema.parse(finalizeValue);
        if (current.state === 'finalized') {
          if (!isDeepStrictEqual(current.finalize, finalize)) {
            throw new ValidationError();
          }
          return Promise.resolve();
        }
        if (current.state !== 'active') throw new ValidationError();
        validateAttachmentStagingFinalization(
          current.start,
          current.progress,
          finalize,
        );
        const id = finalize.record.id;
        const visibleKey = attachmentKey(finalize.record.vaultId, id);
        this.attachments.set(visibleKey, structuredClone(finalize.record));
        this.attachmentHeaders.set(visibleKey, structuredClone(current.start.header));
        for (const [index, chunk] of current.chunks) {
          this.attachmentChunks.set(
            `${visibleKey}:${String(index)}`,
            structuredClone(chunk),
          );
        }
        current.finalize = structuredClone(finalize);
        current.state = 'finalized';
        return Promise.resolve();
      },
      abort: () => {
        if (current.state === 'finalized') throw new ValidationError();
        current.chunks.clear();
        current.state = 'aborted';
        return Promise.resolve();
      },
    });
  }

  public abortAttachmentStream(inputValue: AttachmentStreamStartInput): Promise<void> {
    const input = attachmentStreamStartInputSchema.parse(inputValue);
    const key = `${input.header.record.vaultId}:${input.idempotencyKey}`;
    const staging = this.attachmentStaging.get(key);
    if (staging === undefined) {
      return this.beginAttachmentStream(input).then((session) => session.abort());
    }
    if (!isDeepStrictEqual(staging.start, input)) throw new ValidationError();
    if (staging.state === 'finalized') throw new ValidationError();
    if (staging.state === 'aborted') return Promise.resolve();
    staging.chunks.clear();
    staging.state = 'aborted';
    return Promise.resolve();
  }

  public getAttachmentStreamHeader(
    targetVaultId: VaultId,
    attachmentId: AttachmentId,
  ): Promise<PersistedAttachmentHeaderRecord | null> {
    return Promise.resolve(
      structuredClone(
        this.attachmentHeaders.get(attachmentKey(targetVaultId, attachmentId)),
      ) ?? null,
    );
  }

  public getAttachmentChunk(
    targetVaultId: VaultId,
    attachmentId: AttachmentId,
    chunkIndex: number,
  ): Promise<PersistedAttachmentChunkRecord | null> {
    return Promise.resolve(
      structuredClone(
        this.attachmentChunks.get(
          `${attachmentKey(targetVaultId, attachmentId)}:${String(chunkIndex)}`,
        ),
      ) ?? null,
    );
  }

  public commit(mutation: OpaqueMutation): Promise<void> {
    if (mutation.entityType !== 'vault') {
      return Promise.resolve();
    }
    const current = this.vaults.get(mutation.record.id);
    const currentRevision = current?.revision ?? null;
    if (mutation.expectedVaultRevision !== currentRevision) {
      throw new ApiConflictError(
        'vault',
        mutation.record.id,
        mutation.expectedVaultRevision,
        currentRevision,
      );
    }
    this.vaults.set(mutation.record.id, structuredClone(mutation.record));
    return Promise.resolve();
  }

  public pullSyncPage(cursor: SyncCursor, limit: number): Promise<SyncPullResponse> {
    const vault = cursor.vaultId;
    const remaining = this.changes.filter(
      ({ change }) =>
        change.vaultId === vault && change.serverSequence > cursor.serverSequence,
    );
    const changes = remaining.slice(0, limit);
    const lastSequence = changes.at(-1)?.change.serverSequence ?? cursor.serverSequence;
    const serverVaultRevision =
      this.vaults.get(vault)?.revision ?? cursor.highestSeenVaultRevision;
    return Promise.resolve({
      vaultId: vault,
      serverVaultRevision,
      changes: structuredClone(changes),
      nextCursor: {
        vaultId: vault,
        serverSequence: lastSequence,
        highestSeenVaultRevision: serverVaultRevision,
      },
      hasMore: remaining.length > changes.length,
    });
  }

  public async pushSyncBatch(batch: SyncPushRequest): Promise<SyncPushResponse> {
    const requestEncoding = JSON.stringify(batch);
    const previousEncoding = this.batchRequests.get(batch.batchIdempotencyKey);
    const previous = this.batches.get(batch.batchIdempotencyKey);
    if (previous !== undefined) {
      if (previousEncoding !== requestEncoding) {
        throw new Error('Batch idempotency key was reused with different input');
      }
      return {
        ...structuredClone(previous),
        results: previous.results.map((result) =>
          result.status === 'accepted'
            ? { ...result, disposition: 'duplicate' as const }
            : result,
        ),
      };
    }

    const results: unknown[] = [];
    for (const mutation of batch.mutations) {
      const duplicate = this.acceptedMutations.get(mutation.idempotencyKey);
      if (duplicate !== undefined) {
        results.push({
          status: 'accepted',
          idempotencyKey: mutation.idempotencyKey,
          disposition: 'duplicate',
          change: duplicate,
        });
        continue;
      }
      if (mutation.entityType !== 'vault') {
        throw new Error('The test service only persists vault mutations');
      }
      const current = this.vaults.get(batch.vaultId);
      const currentRevision = current?.revision ?? null;
      if (mutation.expectedVaultRevision !== currentRevision) {
        if (current === undefined) {
          throw new Error('The test service cannot represent a missing conflict');
        }
        results.push({
          status: 'conflict',
          idempotencyKey: mutation.idempotencyKey,
          currentRevision: current.revision,
          current,
        });
        continue;
      }
      await this.commit(mutation);
      const change = changeRecordSchema.parse({
        id: `change-push-${String(this.changes.length + 1)}`,
        vaultId: batch.vaultId,
        serverSequence: this.changes.length + 1,
        recordRevision: mutation.record.revision,
        operation: 'upsert',
        ciphertextHash: digest(`push-${mutation.idempotencyKey}`),
        createdAt: timestampSchema.parse(nowIso),
        entityType: 'vault',
        entityId: batch.vaultId,
      });
      this.acceptedMutations.set(mutation.idempotencyKey, change);
      results.push({
        status: 'accepted',
        idempotencyKey: mutation.idempotencyKey,
        disposition: 'committed',
        change,
      });
    }
    const currentVault = this.vaults.get(batch.vaultId);
    if (currentVault === undefined) throw new Error('Missing vault fixture');
    const response = syncPushResponseSchema.parse({
      vaultId: batch.vaultId,
      serverVaultRevision: currentVault.revision,
      batchIdempotencyKey: batch.batchIdempotencyKey,
      results,
    });
    this.batchRequests.set(batch.batchIdempotencyKey, requestEncoding);
    this.batches.set(batch.batchIdempotencyKey, structuredClone(response));
    return response;
  }

  public publishTemplateMigration(
    batch: TemplateMigrationPublicationRequest,
  ): Promise<TemplateMigrationPublicationResponse> {
    const encoded = JSON.stringify(batch);
    const previous = this.migrationPublications.get(batch.batchIdempotencyKey);
    if (previous !== undefined) {
      if (
        this.migrationPublicationRequests.get(batch.batchIdempotencyKey) !== encoded
      ) {
        throw new Error('Migration batch key was reused with different input');
      }
      return Promise.resolve(structuredClone(previous));
    }
    const current = this.vaults.get(batch.vaultId);
    if (current === undefined) throw new Error('Missing vault fixture');
    const results = batch.mutations.map((mutation) => {
      if (mutation.entityType !== 'group' && mutation.entityType !== 'item') {
        throw new Error('Unexpected migration mutation');
      }
      const change = changeRecordSchema.parse({
        id: `change-migration-${String(this.changes.length + 1)}`,
        vaultId: batch.vaultId,
        serverSequence: this.changes.length + 1,
        recordRevision: mutation.record.recordRevision,
        operation: 'upsert',
        ciphertextHash: contentHashForRecord(mutation.record),
        createdAt: mutation.record.updatedAt,
        entityType: mutation.entityType,
        entityId: mutation.record.id,
      });
      this.changes.push({ change, record: structuredClone(mutation.record) });
      return { idempotencyKey: mutation.idempotencyKey, change };
    });
    const serverVaultRevision = current.revision + batch.mutations.length;
    this.vaults.set(
      batch.vaultId,
      vaultRecordSchema.parse({
        ...current,
        revision: serverVaultRevision,
        updatedAt: batch.mutations.at(-1)?.record.updatedAt ?? current.updatedAt,
      }),
    );
    const response = templateMigrationPublicationResponseSchema.parse({
      vaultId: batch.vaultId,
      batchIdempotencyKey: batch.batchIdempotencyKey,
      serverVaultRevision,
      results,
    });
    this.migrationPublicationRequests.set(batch.batchIdempotencyKey, encoded);
    this.migrationPublications.set(
      batch.batchIdempotencyKey,
      structuredClone(response),
    );
    return Promise.resolve(response);
  }
}

export class MemoryBootstrap implements VaultBootstrapPort {
  readonly receipts = new Map<
    Sha256Digest,
    Readonly<{ input: VaultBootstrapInput; receipt: VaultBootstrapResponse }>
  >();

  public constructor(
    private readonly storage: MemoryStorage,
    private readonly authorization: MemoryAuthorization,
  ) {}

  public bootstrap(input: VaultBootstrapInput): Promise<VaultBootstrapResponse | null> {
    const previous = this.receipts.get(input.sessionTokenHash);
    if (previous !== undefined) {
      const session = this.authorization.sessions.get(input.sessionTokenHash);
      const device = this.authorization.devices.get(input.device.id);
      return Promise.resolve(
        isDeepStrictEqual(previous.input, input) &&
          session !== undefined &&
          device !== undefined &&
          device.revokedAt === undefined &&
          bindSessionToDevice({
            presentedTokenHash: input.sessionTokenHash,
            sessionTokenHash: input.sessionTokenHash,
            session,
            device,
          }) !== null
          ? structuredClone(previous.receipt)
          : null,
      );
    }
    if (
      this.storage.vaults.has(input.vault.id) ||
      this.authorization.devices.has(input.device.id) ||
      this.authorization.sessions.has(input.sessionTokenHash) ||
      this.authorization.invites.has(input.sessionTokenHash) ||
      this.authorization.enrollments.has(input.sessionTokenHash)
    ) {
      return Promise.resolve(null);
    }
    const scopes = ['sync:read', 'sync:write', 'device:manage'] as const;
    const device = deviceRecordSchema.parse({
      id: input.device.id,
      vaultId: input.vault.id,
      schemaVersion: input.device.schemaVersion,
      tokenHash: input.sessionTokenHash,
      tokenVersion: 1,
      ...(input.device.encryptedLabel === undefined
        ? {}
        : { encryptedLabel: input.device.encryptedLabel }),
      scopes,
      createdAt: input.vault.createdAt,
    });
    this.storage.vaults.set(input.vault.id, structuredClone(input.vault));
    this.authorization.devices.set(input.device.id, device);
    this.authorization.sessions.set(input.sessionTokenHash, {
      vaultId: input.vault.id,
      deviceId: input.device.id,
      scopes,
    });
    const receipt = vaultBootstrapResponseSchema.parse({
      vaultId: input.vault.id,
      deviceId: input.device.id,
    });
    this.receipts.set(input.sessionTokenHash, {
      input: structuredClone(input),
      receipt: structuredClone(receipt),
    });
    return Promise.resolve(receipt);
  }
}

export async function createTestPorts(
  scopes: readonly ApiScope[] = ['sync:read', 'sync:write', 'device:manage'],
): Promise<{
  readonly ports: ApiPorts;
  readonly token: string;
  readonly authorization: MemoryAuthorization;
  readonly storage: MemoryStorage;
  readonly clock: TestClock;
  readonly rateLimits: MemoryRateLimits;
  readonly bootstrap: MemoryBootstrap;
}> {
  const tokens = new NodeTokenPort();
  const issued = await tokens.issue();
  const authorization = new MemoryAuthorization();
  authorization.seedSession(issued.hash, { vaultId, deviceId, scopes });
  const storage = new MemoryStorage();
  storage.vaults.set(vaultId, vaultFixture(vaultId));
  storage.vaults.set(otherVaultId, vaultFixture(otherVaultId));
  const clock = new TestClock();
  const rateLimits = new MemoryRateLimits();
  const inviteIds = new SequentialInviteIds();
  const bootstrap = new MemoryBootstrap(storage, authorization);
  return {
    ports: {
      storage,
      authorization,
      tokens,
      rateLimits,
      clock,
      inviteIds,
      bootstrap,
    },
    token: issued.token,
    authorization,
    storage,
    clock,
    rateLimits,
    bootstrap,
  };
}

class SequentialInviteIds implements IdGeneratorPort<InviteId> {
  private value = 0;

  public next(): InviteId {
    this.value += 1;
    return inviteIdSchema.parse(`invite-${String(this.value)}`);
  }
}

export function vaultFixture(id: VaultId, revision = 1): VaultRecord {
  const createdAt = timestampSchema.parse(nowIso);
  const slotId = keySlotIdSchema.parse('slot-1');
  const wrappedRootKey = envelope(id, 'wrapped-root-key', slotId, 'vrk-slot');
  return vaultRecordSchema.parse({
    id,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [
      {
        slotVersion: 1,
        id: slotId,
        type: 'portable-key',
        state: 'active',
        keyVersion: 1,
        derivation: {
          algorithm: 'hkdf-sha256',
          version: 1,
          salt: Buffer.alloc(32).toString('base64url'),
          context: 'credvault/v1/portable-key-wrap',
          outputLength: 32,
        },
        wrappedRootKey,
        createdAt,
      },
    ],
    currentKeyVersion: 1,
    revision,
    encryptedPreferences: envelope(id, 'vault-preferences', id, 'vault-preferences'),
    createdAt,
    updatedAt: createdAt,
  });
}

export function envelope(
  id: VaultId,
  entityType: 'wrapped-root-key' | 'vault-preferences',
  entityId: string,
  purpose: 'vrk-slot' | 'vault-preferences',
): AeadEnvelope {
  return aeadEnvelopeSchema.parse({
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: Buffer.alloc(24).toString('base64url'),
    ciphertext: 'AQID',
    authenticationTag: Buffer.alloc(16).toString('base64url'),
    aad: associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: id,
      entityType,
      entityId,
      purpose,
    }),
    keyVersion: 1,
  });
}

export function deviceLabelEnvelope(
  vaultValue: string,
  deviceValue: string,
  schemaVersion = 1,
): Readonly<Record<string, unknown>> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: Buffer.alloc(24).toString('base64url'),
    ciphertext: 'AQID',
    authenticationTag: Buffer.alloc(16).toString('base64url'),
    aad: {
      version: 1,
      schemaVersion,
      keyVersion: 1,
      vaultId: vaultValue,
      entityType: 'device-label',
      entityId: deviceValue,
      purpose: 'device-label',
    },
    keyVersion: 1,
  } as const;
}

export function digest(value: string): Sha256Digest {
  return sha256DigestSchema.parse(
    Buffer.from(value.padEnd(32, '0').slice(0, 32)).toString('base64url'),
  );
}

export function groupTombstone(id: string, revision: number): TombstoneRecord {
  return tombstoneRecordSchema.parse({
    vaultId,
    entityType: 'group',
    entityId: groupIdSchema.parse(id),
    state: 'deleted',
    tombstoneRevision: revision,
    lastRecordRevision: revision - 1,
    lastCiphertextHash: digest(`deleted-${id}`),
    deletedAt: timestampSchema.parse(nowIso),
  });
}

export function authHeader(token: string): { readonly authorization: string } {
  return { authorization: `Bearer ${token}` };
}

function attachmentKey(targetVaultId: VaultId, entityId: string): string {
  return `${targetVaultId}:${entityId}`;
}

function bindMemoryControlListCursor<Resource extends 'invites' | 'devices'>(
  options: ControlListPageOptions,
  resource: Resource,
  vaultId: VaultId,
): Extract<ControlListCursorPayload, { resource: Resource }> | undefined {
  if (options.cursor === undefined) return undefined;
  const cursor = decodeControlListCursor(options.cursor);
  if (cursor.resource !== resource || cursor.vaultId !== vaultId) {
    throw new TypeError('Control-list cursor does not match this resource');
  }
  return cursor as Extract<ControlListCursorPayload, { resource: Resource }>;
}

function compareInviteRows(
  left: PublicInviteRecord,
  right: PublicInviteRecord,
): number {
  if (left.createdAt !== right.createdAt) {
    return left.createdAt > right.createdAt ? -1 : 1;
  }
  return compareBinaryIdentifiers(left.id, right.id);
}

function compareDeviceRows(left: DeviceRecord, right: DeviceRecord): number {
  if (left.createdAt !== right.createdAt) {
    return left.createdAt < right.createdAt ? -1 : 1;
  }
  return compareBinaryIdentifiers(left.id, right.id);
}

function compareBinaryIdentifiers(left: string, right: string): number {
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function isAfterInviteCursor(
  invite: PublicInviteRecord,
  cursor: Extract<ControlListCursorPayload, { resource: 'invites' }>,
): boolean {
  return (
    invite.createdAt < cursor.createdAt ||
    (invite.createdAt === cursor.createdAt && invite.id > cursor.id)
  );
}

function isAfterDeviceCursor(
  device: DeviceRecord,
  cursor: Extract<ControlListCursorPayload, { resource: 'devices' }>,
): boolean {
  return (
    device.createdAt > cursor.createdAt ||
    (device.createdAt === cursor.createdAt && device.id > cursor.id)
  );
}
