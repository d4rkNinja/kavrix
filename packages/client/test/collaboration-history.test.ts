import type * as CryptoModule from '@kavrix/crypto';
import type * as SchemasModule from '@kavrix/schemas';

const testConfig = vi.hoisted(() => ({ historyByteLimit: 450_000 }));
const zeroizeObservations = vi.hoisted(
  (): {
    readonly reference: Uint8Array;
    readonly before: Uint8Array;
  }[] => [],
);

vi.mock('@kavrix/schemas', async (importOriginal) => {
  const actual = await importOriginal<typeof SchemasModule>();
  return {
    ...actual,
    MAX_COLLABORATIVE_HISTORY_BYTES: testConfig.historyByteLimit,
  };
});

vi.mock('@kavrix/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof CryptoModule>();
  return {
    ...actual,
    zeroize(value: Uint8Array | undefined): void {
      if (value !== undefined) {
        zeroizeObservations.push({
          reference: value,
          before: Uint8Array.from(value),
        });
      }
      actual.zeroize(value);
    },
  };
});

import {
  COLLABORATION_DOMAINS,
  COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  computeMembershipHistoryCompactionDigest,
  computeMembershipHistoryDigest,
  generateDeviceSigningKeyPair,
  signCollaborationRecord,
  verifyCollaborationRecord,
  zeroize,
  type DeviceSigningKeyPair,
} from '@kavrix/crypto';
import {
  canonicalJson,
  collaborationOperationIdSchema,
  collaborationRevisionTupleSchema,
  databaseIdSchema,
  historyIdSchema,
  MAX_COLLABORATIVE_HISTORY_BYTES,
  MAX_COLLABORATIVE_HISTORY_EVENTS,
  membershipHistoryCheckpointSchema,
  membershipHistoryEventSchema,
  membershipHistorySchema,
  principalIdSchema,
  sha256DigestSchema,
  timestampSchema,
  vaultIdSchema,
  type CollaborationRevisionTuple,
  type MembershipHistory,
  type MembershipHistoryCheckpoint,
  type MembershipHistoryEvent,
  type Sha256Digest,
} from '@kavrix/schemas';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  MembershipHistoryAppendError,
  appendOrCompactMembershipHistory,
  verifyMembershipHistoryAppendOrCompaction,
  type AppendOrCompactMembershipHistoryInput,
  type VerifyMembershipHistoryAppendOrCompactionInput,
} from '../src/collaboration-history.js';

const DATABASE_ID = databaseIdSchema.parse('database-history');
const OTHER_DATABASE_ID = databaseIdSchema.parse('database-history-other');
const VAULT_ID = vaultIdSchema.parse('vault-history');
const ACTOR_ID = principalIdSchema.parse('principal-history-owner');
const ACTOR_DEVICE_ID = 'device-history-owner';
const EVENT_AT = timestampSchema.parse('2026-08-30T10:00:00.000Z');
const EXPIRES_AT = timestampSchema.parse('2026-08-30T10:10:00.000Z');
const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');

const signingKeys: DeviceSigningKeyPair[] = [];

afterEach(() => {
  for (const key of signingKeys.splice(0)) zeroize(key.privateKey);
  zeroizeObservations.splice(0);
});

function digest(fill: number): Sha256Digest {
  return sha256DigestSchema.parse(Buffer.alloc(32, fill).toString('base64url'));
}

function mutateBase64(value: string): string {
  return `${value.startsWith('A') ? 'B' : 'A'}${value.slice(1)}`;
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('Missing required test fixture');
  return value;
}

function canonicalBytes(value: unknown): number {
  return Buffer.byteLength(canonicalJson(value), 'utf8');
}

function tuple(
  documentRevision: number,
  membershipRevision = 1,
  overrides: Partial<CollaborationRevisionTuple> = {},
): CollaborationRevisionTuple {
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: 1,
    documentRevision,
    membershipRevision,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(1),
    authorizationStateDigest: digest(2),
    ...overrides,
  });
}

function paddedId(prefix: string, index: number): string {
  return `${prefix}${String(index)}`.padEnd(128, 'x').slice(0, 128);
}

function historyEvent(
  index: number,
  position: CollaborationRevisionTuple,
  options: Readonly<{
    full?: boolean;
    operationId?: string;
    signature?: string;
  }> = {},
): MembershipHistoryEvent {
  const full = options.full === true;
  return membershipHistoryEventSchema.parse({
    protocolVersion: 1,
    operationId: options.operationId ?? `operation-prior-${String(index)}`,
    eventType: full ? 'role-changed' : 'policy-changed',
    actorPrincipalId: full ? paddedId('principal', index) : ACTOR_ID,
    actorDeviceId: full ? paddedId('device', index) : ACTOR_DEVICE_ID,
    ...(full
      ? {
          targetPrincipalId: paddedId('targetprincipal', index),
          targetDeviceId: paddedId('targetdevice', index),
          previousRole: 'reader' as const,
          newRole: 'owner' as const,
          previousState: 'active' as const,
          newState: 'active' as const,
        }
      : {}),
    previousDocumentRevision: index,
    newDocumentRevision: index + 1,
    previousMembershipRevision: position.membershipRevision,
    newMembershipRevision: position.membershipRevision,
    previousPolicyRevision: position.policyRevision,
    newPolicyRevision: position.policyRevision,
    previousKeyEpoch: position.keyEpoch,
    newKeyEpoch: position.keyEpoch,
    previousAuthorityEpoch: position.authorityEpoch,
    newAuthorityEpoch: position.authorityEpoch,
    previousDatabaseDeviceGeneration: position.databaseDeviceGeneration,
    newDatabaseDeviceGeneration: position.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: position.databaseDeviceRegistryDigest,
    newDatabaseDeviceRegistryDigest: position.databaseDeviceRegistryDigest,
    previousAuthorizationStateDigest: position.authorizationStateDigest,
    newAuthorizationStateDigest: position.authorizationStateDigest,
    previousHeadDigest: digest((index % 250) + 3),
    ...(full
      ? {
          approvalRequestId: paddedId('approval', index),
          approvalRequestDigest: digest((index % 250) + 4),
        }
      : {}),
    timestamp: EVENT_AT,
    ...(full ? { expiresAt: EXPIRES_AT } : {}),
    signature: options.signature ?? PLACEHOLDER_SIGNATURE,
  });
}

function historyCheckpoint(
  position: CollaborationRevisionTuple,
  overrides: Partial<MembershipHistoryCheckpoint> = {},
): MembershipHistoryCheckpoint {
  return membershipHistoryCheckpointSchema.parse({
    protocolVersion: 1,
    checkpointId: 'checkpoint-prior',
    authorityEpoch: position.authorityEpoch,
    databaseDeviceGeneration: position.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: position.databaseDeviceRegistryDigest,
    membershipRevision: position.membershipRevision,
    documentRevision: position.documentRevision,
    policyRevision: position.policyRevision,
    keyEpoch: position.keyEpoch,
    previousHeadDigest: digest(19),
    compactedThroughRevision: 0,
    compactedHistoryDigest: COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
    signerPrincipalId: ACTOR_ID,
    signerDeviceId: ACTOR_DEVICE_ID,
    createdAt: EVENT_AT,
    signature: PLACEHOLDER_SIGNATURE,
    ...overrides,
  });
}

function historyDraft(
  position: CollaborationRevisionTuple,
  events: readonly MembershipHistoryEvent[],
  checkpoints: readonly MembershipHistoryCheckpoint[] = [],
  compactedThroughRevision = 0,
  compactedHistoryDigest: Sha256Digest = COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
): Omit<MembershipHistory, 'currentHistoryDigest'> & {
  readonly currentHistoryDigest: Sha256Digest;
} {
  return {
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: position.authorityEpoch,
    databaseDeviceGeneration: position.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: position.databaseDeviceRegistryDigest,
    events: [...events],
    checkpoints: [...checkpoints],
    compactedThroughRevision:
      membershipHistorySchema.shape.compactedThroughRevision.parse(
        compactedThroughRevision,
      ),
    compactedHistoryDigest,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousHistoryDigest: COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
    currentHistoryDigest: sha256DigestSchema.parse(PLACEHOLDER_DIGEST),
  };
}

function history(
  position: CollaborationRevisionTuple,
  events: readonly MembershipHistoryEvent[],
  checkpoints: readonly MembershipHistoryCheckpoint[] = [],
  compactedThroughRevision = 0,
  compactedHistoryDigest: Sha256Digest = COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
): MembershipHistory {
  const draft = historyDraft(
    position,
    events,
    checkpoints,
    compactedThroughRevision,
    compactedHistoryDigest,
  );
  return membershipHistorySchema.parse({
    ...draft,
    currentHistoryDigest: computeMembershipHistoryDigest(draft),
  });
}

async function keyPair(): Promise<DeviceSigningKeyPair> {
  const key = await generateDeviceSigningKeyPair();
  signingKeys.push(key);
  return key;
}

function inputFor(
  signer: DeviceSigningKeyPair,
  priorHistory: MembershipHistory,
  previousTuple: CollaborationRevisionTuple,
  nextTuple: CollaborationRevisionTuple,
  overrides: Partial<AppendOrCompactMembershipHistoryInput> = {},
): AppendOrCompactMembershipHistoryInput {
  return {
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: collaborationOperationIdSchema.parse('operation-new'),
    previousHeadDigest: digest(61),
    previousTuple,
    nextTuple,
    priorHistory,
    actorPrincipalId: ACTOR_ID,
    actorDeviceId:
      membershipHistoryEventSchema.shape.actorDeviceId.parse(ACTOR_DEVICE_ID),
    actorSigningPublicKey: signer.publicKeyBase64,
    event: {
      eventType: 'member-added',
      targetPrincipalId: principalIdSchema.parse('principal-added'),
      timestamp: EVENT_AT,
    },
    deviceSigningPrivateKey: signer.privateKey,
    ...overrides,
  };
}

function compactionDigestFor(
  input: AppendOrCompactMembershipHistoryInput,
): Sha256Digest {
  return computeMembershipHistoryCompactionDigest({
    protocolVersion: input.protocolVersion,
    databaseId: input.databaseId,
    vaultId: input.vaultId,
    authorityEpoch: input.previousTuple.authorityEpoch,
    compactingOperationId: input.operationId,
    previousHeadDigest: input.previousHeadDigest,
    previousTuple: input.previousTuple,
    priorHistory: input.priorHistory,
  });
}

function verificationInputFor(
  input: AppendOrCompactMembershipHistoryInput,
  nextHistory: MembershipHistory,
  overrides: Partial<VerifyMembershipHistoryAppendOrCompactionInput> = {},
): VerifyMembershipHistoryAppendOrCompactionInput {
  return {
    protocolVersion: input.protocolVersion,
    databaseId: input.databaseId,
    vaultId: input.vaultId,
    operationId: input.operationId,
    previousHeadDigest: input.previousHeadDigest,
    previousTuple: input.previousTuple,
    nextTuple: input.nextTuple,
    priorHistory: input.priorHistory,
    nextHistory,
    actorPrincipalId: input.actorPrincipalId,
    actorDeviceId: input.actorDeviceId,
    timestamp: input.event.timestamp,
    ...(input.event.expiresAt === undefined
      ? {}
      : { expiresAt: input.event.expiresAt }),
    ...overrides,
  };
}

function redigestHistory(
  input: Omit<MembershipHistory, 'currentHistoryDigest'> &
    Partial<Pick<MembershipHistory, 'currentHistoryDigest'>>,
): MembershipHistory {
  const draft = {
    ...input,
    currentHistoryDigest: sha256DigestSchema.parse(PLACEHOLDER_DIGEST),
  };
  return membershipHistorySchema.parse({
    ...draft,
    currentHistoryDigest: computeMembershipHistoryDigest(draft),
  });
}

function publicHistory(historyValue: MembershipHistory): unknown {
  return {
    ...historyValue,
    events: historyValue.events.map((event) => ({
      ...event,
      signature: '<signature>',
    })),
    checkpoints: historyValue.checkpoints.map((checkpoint) => ({
      ...checkpoint,
      signature: '<signature>',
    })),
  };
}

describe('appendOrCompactMembershipHistory', () => {
  it('appends exactly one signed event without changing prior checkpoint bytes', async () => {
    const signer = await keyPair();
    const previousTuple = tuple(1);
    const nextTuple = tuple(2, 2, { authorizationStateDigest: digest(10) });
    const checkpoint = historyCheckpoint(previousTuple);
    const priorHistory = history(
      previousTuple,
      [historyEvent(0, previousTuple)],
      [checkpoint],
    );
    const input = inputFor(signer, priorHistory, previousTuple, nextTuple);

    const result = await appendOrCompactMembershipHistory(input);

    expect(result.compacted).toBe(false);
    expect(result.history.events).toHaveLength(2);
    expect(canonicalJson(result.history.checkpoints)).toBe(
      canonicalJson(priorHistory.checkpoints),
    );
    expect(result.history.compactedThroughRevision).toBe(
      priorHistory.compactedThroughRevision,
    );
    expect(result.history.compactedHistoryDigest).toBe(
      priorHistory.compactedHistoryDigest,
    );
    expect(result.history.previousHeadDigest).toBe(input.previousHeadDigest);
    expect(result.history.previousHistoryDigest).toBe(
      priorHistory.currentHistoryDigest,
    );
    expect(computeMembershipHistoryDigest(result.history)).toBe(
      result.history.currentHistoryDigest,
    );
    expect(membershipHistorySchema.parse(result.history)).toEqual(result.history);
    const appended = result.history.events[1];
    expect(appended).toMatchObject({
      operationId: input.operationId,
      actorPrincipalId: input.actorPrincipalId,
      actorDeviceId: input.actorDeviceId,
      previousDocumentRevision: previousTuple.documentRevision,
      newDocumentRevision: nextTuple.documentRevision,
      previousMembershipRevision: previousTuple.membershipRevision,
      newMembershipRevision: nextTuple.membershipRevision,
      previousHeadDigest: input.previousHeadDigest,
      timestamp: EVENT_AT,
    });
    expect(
      await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistorySignature,
        appended,
        membershipHistoryEventSchema,
        'signature',
        signer.publicKeyBase64,
      ),
    ).toBe(true);
  });

  it('compacts the full authenticated predecessor at the event-count boundary', async () => {
    const signer = await keyPair();
    const previousTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS);
    const nextTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS + 1, 2, {
      authorizationStateDigest: digest(11),
    });
    const events = Array.from(
      { length: MAX_COLLABORATIVE_HISTORY_EVENTS },
      (_, index) => historyEvent(index, previousTuple),
    );
    const oldCheckpoint = historyCheckpoint(previousTuple);
    const priorHistory = history(previousTuple, events, [oldCheckpoint]);
    const input = inputFor(signer, priorHistory, previousTuple, nextTuple);

    const result = await appendOrCompactMembershipHistory(input);

    expect(result.compacted).toBe(true);
    expect(result.history.events).toHaveLength(1);
    expect(result.history.checkpoints).toHaveLength(1);
    const event = result.history.events[0];
    const checkpoint = result.history.checkpoints[0];
    expect(event?.operationId).toBe(input.operationId);
    expect(checkpoint).toMatchObject({
      checkpointId: historyIdSchema.parse(input.operationId),
      authorityEpoch: nextTuple.authorityEpoch,
      databaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
      membershipRevision: nextTuple.membershipRevision,
      documentRevision: nextTuple.documentRevision,
      policyRevision: nextTuple.policyRevision,
      keyEpoch: nextTuple.keyEpoch,
      previousHeadDigest: input.previousHeadDigest,
      compactedThroughRevision: previousTuple.membershipRevision,
      compactedHistoryDigest: compactionDigestFor(input),
      signerPrincipalId: input.actorPrincipalId,
      signerDeviceId: input.actorDeviceId,
      createdAt: EVENT_AT,
    });
    expect(result.history.compactedThroughRevision).toBe(
      checkpoint?.compactedThroughRevision,
    );
    expect(result.history.compactedHistoryDigest).toBe(
      checkpoint?.compactedHistoryDigest,
    );
    expect(
      await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
        checkpoint,
        membershipHistoryCheckpointSchema,
        'signature',
        signer.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistorySignature,
        event,
        membershipHistoryEventSchema,
        'signature',
        signer.publicKeyBase64,
      ),
    ).toBe(true);
    expect(canonicalBytes(result.history)).toBeLessThanOrEqual(
      MAX_COLLABORATIVE_HISTORY_BYTES,
    );
    expect(computeMembershipHistoryDigest(result.history)).toBe(
      result.history.currentHistoryDigest,
    );
  });

  it('compacts only after an exact canonical-byte append crosses the byte limit', async () => {
    const signer = await keyPair();
    const fullEvents = Array.from({ length: 255 }, (_, index) =>
      historyEvent(index, tuple(255), { full: true }),
    );
    let selected:
      | Readonly<{
          priorHistory: MembershipHistory;
          previousTuple: CollaborationRevisionTuple;
          nextTuple: CollaborationRevisionTuple;
        }>
      | undefined;
    for (let count = 1; count < fullEvents.length; count += 1) {
      const previousTuple = tuple(count);
      const nextTuple = tuple(count + 1, 2, {
        authorizationStateDigest: digest(12),
      });
      const priorDraft = historyDraft(previousTuple, fullEvents.slice(0, count));
      const priorSize = canonicalBytes(priorDraft);
      const previewEvent = historyEvent(count, nextTuple, {
        full: true,
        operationId: 'operation-byte-boundary',
      });
      const appendedPreview = {
        ...priorDraft,
        authorityEpoch: nextTuple.authorityEpoch,
        databaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
        databaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
        events: [...priorDraft.events, previewEvent],
        previousHeadDigest: digest(61),
        previousHistoryDigest: digest(62),
      };
      if (
        priorSize <= MAX_COLLABORATIVE_HISTORY_BYTES &&
        canonicalBytes(appendedPreview) > MAX_COLLABORATIVE_HISTORY_BYTES
      ) {
        selected = {
          priorHistory: history(previousTuple, fullEvents.slice(0, count)),
          previousTuple,
          nextTuple,
        };
        break;
      }
    }
    expect(selected).toBeDefined();
    if (selected === undefined) throw new Error('Missing byte-boundary fixture');
    expect(selected.priorHistory.events.length).toBeLessThan(
      MAX_COLLABORATIVE_HISTORY_EVENTS,
    );
    expect(canonicalBytes(selected.priorHistory)).toBeLessThanOrEqual(
      MAX_COLLABORATIVE_HISTORY_BYTES,
    );
    const input = inputFor(
      signer,
      selected.priorHistory,
      selected.previousTuple,
      selected.nextTuple,
      {
        operationId: collaborationOperationIdSchema.parse('operation-byte-boundary'),
        actorPrincipalId: principalIdSchema.parse(paddedId('newprincipal', 1)),
        actorDeviceId: membershipHistoryEventSchema.shape.actorDeviceId.parse(
          paddedId('newdevice', 1),
        ),
        event: {
          eventType: 'role-changed',
          targetPrincipalId: principalIdSchema.parse(paddedId('newtargetprincipal', 1)),
          targetDeviceId: membershipHistoryEventSchema.shape.targetDeviceId.parse(
            paddedId('newtargetdevice', 1),
          ),
          previousRole: 'reader',
          newRole: 'owner',
          previousState: 'active',
          newState: 'active',
          approvalRequestId: membershipHistoryEventSchema.shape.approvalRequestId.parse(
            paddedId('newapproval', 1),
          ),
          approvalRequestDigest: digest(13),
          timestamp: EVENT_AT,
          expiresAt: EXPIRES_AT,
        },
      },
    );

    const result = await appendOrCompactMembershipHistory(input);

    expect(result.compacted).toBe(true);
    expect(result.history.events).toHaveLength(1);
    expect(result.history.checkpoints[0]?.compactedHistoryDigest).toBe(
      compactionDigestFor(input),
    );
    expect(canonicalBytes(result.history)).toBeLessThanOrEqual(
      MAX_COLLABORATIVE_HISTORY_BYTES,
    );
  });

  it('commits an earlier compaction chain through the exact prior-history digest', async () => {
    const signer = await keyPair();
    const previousTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS, 6);
    const nextTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS + 1, 7, {
      authorizationStateDigest: digest(15),
    });
    const chainDigest = digest(70);
    const priorCheckpoint = historyCheckpoint(previousTuple, {
      compactedThroughRevision:
        membershipHistoryCheckpointSchema.shape.compactedThroughRevision.parse(5),
      compactedHistoryDigest: chainDigest,
    });
    const events = Array.from(
      { length: MAX_COLLABORATIVE_HISTORY_EVENTS },
      (_, index) => historyEvent(index, previousTuple),
    );
    const priorHistory = history(
      previousTuple,
      events,
      [priorCheckpoint],
      5,
      chainDigest,
    );
    const input = inputFor(signer, priorHistory, previousTuple, nextTuple);
    const expectedDigest = compactionDigestFor(input);

    const result = await appendOrCompactMembershipHistory(input);

    expect(result.history.checkpoints[0]?.compactedHistoryDigest).toBe(expectedDigest);
    const changedCheckpoint = membershipHistoryCheckpointSchema.parse({
      ...priorCheckpoint,
      compactedHistoryDigest: digest(71),
    });
    const changedPrior = history(
      previousTuple,
      events,
      [changedCheckpoint],
      5,
      digest(71),
    );
    expect(compactionDigestFor({ ...input, priorHistory: changedPrior })).not.toBe(
      expectedDigest,
    );
  });

  it('does not compact a valid append below both limits', async () => {
    const signer = await keyPair();
    const previousTuple = tuple(2);
    const nextTuple = tuple(3, 2, { authorizationStateDigest: digest(20) });
    const priorHistory = history(previousTuple, [
      historyEvent(0, previousTuple),
      historyEvent(1, previousTuple),
    ]);

    const result = await appendOrCompactMembershipHistory(
      inputFor(signer, priorHistory, previousTuple, nextTuple),
    );

    expect(result).toMatchObject({ compacted: false });
    expect(result.history.events).toHaveLength(3);
    expect(canonicalBytes(result.history)).toBeLessThan(
      MAX_COLLABORATIVE_HISTORY_BYTES,
    );
  });

  it.each([
    'previousDocumentRevision',
    'previousHeadDigest',
    'actorPrincipalId',
  ] as const)(
    'rejects caller-supplied event %s instead of hiding it through compaction',
    async (field) => {
      const signer = await keyPair();
      const previousTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS);
      const nextTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS + 1, 2, {
        authorizationStateDigest: digest(21),
      });
      const priorHistory = history(
        previousTuple,
        Array.from({ length: MAX_COLLABORATIVE_HISTORY_EVENTS }, (_, index) =>
          historyEvent(index, previousTuple),
        ),
      );
      const valid = inputFor(signer, priorHistory, previousTuple, nextTuple);
      const malformed = {
        ...valid,
        event: {
          ...valid.event,
          [field]: field === 'actorPrincipalId' ? 'principal-attacker' : 0,
        },
      };

      await expect(
        appendOrCompactMembershipHistory(malformed as never),
      ).rejects.toBeInstanceOf(MembershipHistoryAppendError);
    },
  );

  it.each(['digest', 'scope', 'fence'] as const)(
    'rejects invalid prior %s rather than using compaction as recovery',
    async (kind) => {
      const signer = await keyPair();
      const previousTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS);
      const nextTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS + 1, 2, {
        authorizationStateDigest: digest(22),
      });
      const priorHistory = history(
        previousTuple,
        Array.from({ length: MAX_COLLABORATIVE_HISTORY_EVENTS }, (_, index) =>
          historyEvent(index, previousTuple),
        ),
      );
      const valid = inputFor(signer, priorHistory, previousTuple, nextTuple);
      const malformed =
        kind === 'digest'
          ? {
              ...valid,
              priorHistory: {
                ...valid.priorHistory,
                currentHistoryDigest: mutateBase64(
                  valid.priorHistory.currentHistoryDigest,
                ),
              },
            }
          : kind === 'scope'
            ? { ...valid, databaseId: OTHER_DATABASE_ID }
            : {
                ...valid,
                previousTuple: tuple(MAX_COLLABORATIVE_HISTORY_EVENTS, 1, {
                  databaseDeviceGeneration:
                    membershipHistorySchema.shape.databaseDeviceGeneration.parse(2),
                  databaseDeviceRegistryDigest: digest(23),
                }),
              };

      await expect(
        appendOrCompactMembershipHistory(malformed as never),
      ).rejects.toBeInstanceOf(MembershipHistoryAppendError);
    },
  );

  it('rejects a public/private signing-key mismatch and preserves the caller key', async () => {
    const signer = await keyPair();
    const wrongSigner = await keyPair();
    const previousTuple = tuple(1);
    const nextTuple = tuple(2, 2, { authorizationStateDigest: digest(24) });
    const priorHistory = history(previousTuple, [historyEvent(0, previousTuple)]);
    const before = Uint8Array.from(signer.privateKey);

    await expect(
      appendOrCompactMembershipHistory(
        inputFor(signer, priorHistory, previousTuple, nextTuple, {
          actorSigningPublicKey: wrongSigner.publicKeyBase64,
        }),
      ),
    ).rejects.toBeInstanceOf(MembershipHistoryAppendError);

    expect(signer.privateKey).toEqual(before);
    zeroize(before);
  });

  it('zeroizes its owned signing-key copy on success without mutating caller bytes', async () => {
    const signer = await keyPair();
    const previousTuple = tuple(1);
    const nextTuple = tuple(2, 2, { authorizationStateDigest: digest(25) });
    const priorHistory = history(previousTuple, [historyEvent(0, previousTuple)]);
    const before = Uint8Array.from(signer.privateKey);

    await appendOrCompactMembershipHistory(
      inputFor(signer, priorHistory, previousTuple, nextTuple),
    );

    expect(signer.privateKey).toEqual(before);
    const ownedCopy = zeroizeObservations.find(
      (entry) =>
        entry.reference !== signer.privateKey &&
        entry.before.length === before.length &&
        entry.before.every((value, index) => value === before[index]),
    );
    expect(ownedCopy).toBeDefined();
    expect(ownedCopy?.reference.every((value) => value === 0)).toBe(true);
    zeroize(before);
  });

  it('produces deterministic public fields for fixed inputs', async () => {
    const signer = await keyPair();
    const previousTuple = tuple(1);
    const nextTuple = tuple(2, 2, { authorizationStateDigest: digest(26) });
    const priorHistory = history(previousTuple, [historyEvent(0, previousTuple)]);
    const input = inputFor(signer, priorHistory, previousTuple, nextTuple);

    const first = await appendOrCompactMembershipHistory(input);
    const second = await appendOrCompactMembershipHistory(input);

    expect(publicHistory(first.history)).toEqual(publicHistory(second.history));
  });

  it('signs checkpoints and events with the exact existing protocol domains', async () => {
    const signer = await keyPair();
    const previousTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS);
    const nextTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS + 1, 2, {
      authorizationStateDigest: digest(27),
    });
    const priorHistory = history(
      previousTuple,
      Array.from({ length: MAX_COLLABORATIVE_HISTORY_EVENTS }, (_, index) =>
        historyEvent(index, previousTuple),
      ),
    );
    const input = inputFor(signer, priorHistory, previousTuple, nextTuple);

    const result = await appendOrCompactMembershipHistory(input);
    const event = result.history.events[0];
    const checkpoint = result.history.checkpoints[0];

    expect(result.compacted).toBe(true);
    expect(
      await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistorySignature,
        event,
        membershipHistoryEventSchema,
        'signature',
        signer.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
        checkpoint,
        membershipHistoryCheckpointSchema,
        'signature',
        signer.publicKeyBase64,
      ),
    ).toBe(true);
    const wrongDomainSignature = await signCollaborationRecord(
      COLLABORATION_DOMAINS.membershipHistorySignature,
      checkpoint,
      membershipHistoryCheckpointSchema,
      'signature',
      signer.privateKey,
    );
    expect(wrongDomainSignature).not.toBe(checkpoint?.signature);
  });

  it('verifies the exact normal and capacity-compacted structural transitions', async () => {
    const signer = await keyPair();
    const normalPreviousTuple = tuple(1);
    const normalNextTuple = tuple(2, 2, {
      authorizationStateDigest: digest(81),
    });
    const normalPrior = history(normalPreviousTuple, [
      historyEvent(0, normalPreviousTuple),
    ]);
    const normalInput = inputFor(
      signer,
      normalPrior,
      normalPreviousTuple,
      normalNextTuple,
    );
    const normal = await appendOrCompactMembershipHistory(normalInput);

    expect(
      verifyMembershipHistoryAppendOrCompaction(
        verificationInputFor(normalInput, normal.history),
      ),
    ).toMatchObject({ compacted: false, event: normal.history.events[1] });

    const compactPreviousTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS);
    const compactNextTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS + 1, 2, {
      authorizationStateDigest: digest(82),
    });
    const compactPrior = history(
      compactPreviousTuple,
      Array.from({ length: MAX_COLLABORATIVE_HISTORY_EVENTS }, (_, index) =>
        historyEvent(index, compactPreviousTuple),
      ),
    );
    const compactInput = inputFor(
      signer,
      compactPrior,
      compactPreviousTuple,
      compactNextTuple,
    );
    const compact = await appendOrCompactMembershipHistory(compactInput);

    expect(
      verifyMembershipHistoryAppendOrCompaction(
        verificationInputFor(compactInput, compact.history),
      ),
    ).toMatchObject({
      compacted: true,
      event: compact.history.events[0],
      checkpoint: compact.history.checkpoints[0],
    });
  });

  it.each([
    'omitted-prior',
    'substituted-prior',
    'reordered-prior',
    'checkpoint-position',
    'checkpoint-digest',
    'checkpoint-signer',
    'history-boundary',
    'event-actor',
    'non-monotonic-next',
    'unnecessary-compaction',
  ] as const)('rejects malformed or forked compaction evidence: %s', async (kind) => {
    const signer = await keyPair();
    const previousTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS);
    const nextTuple = tuple(MAX_COLLABORATIVE_HISTORY_EVENTS + 1, 2, {
      authorizationStateDigest: digest(83),
    });
    const priorEvents = Array.from(
      { length: MAX_COLLABORATIVE_HISTORY_EVENTS },
      (_, index) => historyEvent(index, previousTuple),
    );
    const priorHistory = history(previousTuple, priorEvents);
    const input = inputFor(signer, priorHistory, previousTuple, nextTuple);
    const compact = await appendOrCompactMembershipHistory(input);
    const checkpoint = compact.history.checkpoints[0];
    const event = compact.history.events[0];
    if (checkpoint === undefined || event === undefined) {
      throw new Error('Missing compacted history fixture');
    }

    let verificationInput = verificationInputFor(input, compact.history);
    if (kind === 'omitted-prior') {
      verificationInput = verificationInputFor(input, compact.history, {
        priorHistory: history(previousTuple, priorEvents.slice(1)),
      });
    } else if (kind === 'substituted-prior') {
      const substituted = membershipHistoryEventSchema.parse({
        ...priorEvents[0],
        signature: mutateBase64(priorEvents[0]?.signature ?? ''),
      });
      verificationInput = verificationInputFor(input, compact.history, {
        priorHistory: history(previousTuple, [substituted, ...priorEvents.slice(1)]),
      });
    } else if (kind === 'reordered-prior') {
      verificationInput = verificationInputFor(input, compact.history, {
        priorHistory: history(previousTuple, [
          required(priorEvents[1]),
          required(priorEvents[0]),
          ...priorEvents.slice(2),
        ]),
      });
    } else if (kind === 'checkpoint-position') {
      const changed = membershipHistoryCheckpointSchema.parse({
        ...checkpoint,
        compactedThroughRevision: 0,
      });
      verificationInput = verificationInputFor(
        input,
        redigestHistory({
          ...compact.history,
          checkpoints: [changed],
          compactedThroughRevision: changed.compactedThroughRevision,
        }),
      );
    } else if (kind === 'checkpoint-digest') {
      const changed = membershipHistoryCheckpointSchema.parse({
        ...checkpoint,
        compactedHistoryDigest: digest(84),
      });
      verificationInput = verificationInputFor(
        input,
        redigestHistory({
          ...compact.history,
          checkpoints: [changed],
          compactedHistoryDigest: changed.compactedHistoryDigest,
        }),
      );
    } else if (kind === 'checkpoint-signer') {
      const changed = membershipHistoryCheckpointSchema.parse({
        ...checkpoint,
        signerPrincipalId: principalIdSchema.parse('principal-attacker'),
      });
      verificationInput = verificationInputFor(
        input,
        redigestHistory({ ...compact.history, checkpoints: [changed] }),
      );
    } else if (kind === 'history-boundary') {
      verificationInput = verificationInputFor(
        input,
        redigestHistory({
          ...compact.history,
          previousHistoryDigest: digest(85),
        }),
      );
    } else if (kind === 'event-actor') {
      const changed = membershipHistoryEventSchema.parse({
        ...event,
        actorPrincipalId: principalIdSchema.parse('principal-attacker'),
      });
      verificationInput = verificationInputFor(
        input,
        redigestHistory({ ...compact.history, events: [changed] }),
      );
    } else if (kind === 'non-monotonic-next') {
      verificationInput = verificationInputFor(input, compact.history, {
        nextTuple: tuple(previousTuple.documentRevision - 1, 0),
      });
    } else {
      verificationInput = verificationInputFor(input, compact.history, {
        priorHistory: history(previousTuple, [required(priorEvents[0])]),
      });
    }

    expect(() => verifyMembershipHistoryAppendOrCompaction(verificationInput)).toThrow(
      MembershipHistoryAppendError,
    );
  });
});
