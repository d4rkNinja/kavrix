import { describe, expect, it } from 'vitest';

import {
  approvalEvidenceSchema,
  approvalRequestSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationMembershipSchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborationSignatureSchema,
  deviceCertificateSchema,
  sha256DigestSchema,
  timestampSchema,
  transferIntentSchema,
} from '@kavrix/schemas';
import type {
  ApprovalRequest,
  CollaborationMembership,
  CollaborationRevisionTuple,
  CollaborationPolicyState,
  DeviceCertificate,
  TransferIntent,
} from '@kavrix/schemas';
import {
  authorizeOperation,
  checkActiveOwnerInvariant,
  evaluateDeviceFence,
  validateApproval,
  validateOwnershipTransfer,
  validateOwnerTransition,
  validateRevisionTransition,
  type ApprovalValidationInput,
  type OwnershipTransferValidationInput,
} from '../src/index.js';

type CollaborationOperationType = ApprovalRequest['operationType'];

const timestamp = timestampSchema.parse('2026-01-01T00:00:00.000Z');
const approvedAt = timestampSchema.parse('2026-01-01T01:00:00.000Z');
const expiry = timestampSchema.parse('2026-01-02T00:00:00.000Z');

const bytes = (length: number, value: number): string =>
  Buffer.alloc(length, value).toString('base64url');
const digest = (value: number): ReturnType<typeof sha256DigestSchema.parse> =>
  sha256DigestSchema.parse(bytes(32, value));
const signature = (
  value: number,
): ReturnType<typeof collaborationSignatureSchema.parse> =>
  collaborationSignatureSchema.parse(bytes(64, value));
const nonce = (value: number): string => bytes(16, value);

function makeDevice(
  principalId: string,
  deviceId: string,
  value: number,
  state: DeviceCertificate['state'] = 'active',
): DeviceCertificate {
  return deviceCertificateSchema.parse({
    protocolVersion: 1,
    principalId,
    deviceId,
    deviceGeneration: 1,
    signingPublicKey: bytes(32, value),
    encryptionPublicKey: bytes(32, value + 1),
    state,
    createdAt: timestamp,
    stateChangedAt: state === 'active' ? timestamp : approvedAt,
    ...(state === 'active' ? {} : { revokedAt: approvedAt }),
    rootSignature: signature(value),
  });
}

function makeMembership(
  principalId: string,
  role: CollaborationMembership['role'],
  value: number,
  state: CollaborationMembership['state'] = 'active',
  devices: readonly DeviceCertificate[] = [
    makeDevice(principalId, `device-${principalId}`, value),
  ],
): CollaborationMembership {
  return collaborationMembershipSchema.parse({
    membershipId: `membership-${principalId}`,
    principalId,
    principalFingerprint: digest(value),
    rootSigningPublicKey: bytes(32, value + 2),
    identityGeneration: 1,
    role,
    state,
    devices,
    createdAt: timestamp,
    updatedAt: approvedAt,
    ...(state === 'active' ? {} : { removedAt: approvedAt }),
  });
}

function firstDevice(membership: CollaborationMembership): DeviceCertificate {
  const device = membership.devices[0];
  if (device === undefined) {
    throw new Error('Fixture membership must contain a device.');
  }
  return device;
}

function initiatorSignature(
  intent: TransferIntent,
): NonNullable<TransferIntent['initiatorSignature']> {
  if (intent.initiatorSignature === undefined) {
    throw new Error('Fixture transfer must contain an initiator signature.');
  }
  return intent.initiatorSignature;
}

function recipientSignature(
  intent: TransferIntent,
): NonNullable<TransferIntent['recipientAcceptance']>['signature'] {
  const signatureValue = intent.recipientAcceptance?.signature;
  if (signatureValue === undefined) {
    throw new Error('Fixture transfer must contain recipient acceptance.');
  }
  return signatureValue;
}

function makeTuple(
  overrides: Record<string, unknown> = {},
): CollaborationRevisionTuple {
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: 1,
    documentRevision: 3,
    membershipRevision: 2,
    policyRevision: 1,
    keyEpoch: 4,
    databaseDeviceGeneration: 2,
    databaseDeviceRegistryDigest: digest(2),
    authorizationStateDigest: digest(5),
    ...overrides,
  });
}

function makePolicy(
  approvalPolicy: CollaborationPolicyState['approvalPolicy'],
  tuple = makeTuple(),
): CollaborationPolicyState {
  return collaborationPolicyStateSchema.parse({
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    authorityEpoch: tuple.authorityEpoch,
    policyRevision: tuple.policyRevision,
    approvalPolicy,
    policyDigest: digest(40),
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    changedByPrincipalId: 'principal-a',
    changedByDeviceId: 'device-principal-a',
    changedAt: timestamp,
    signature: signature(40),
  });
}

function makeRegistry(
  generation: number,
  registryDigest: ReturnType<typeof digest>,
  deniedDevices: readonly Record<string, unknown>[] = [],
): ReturnType<typeof collaborationDatabaseDeviceRegistrySchema.parse> {
  return collaborationDatabaseDeviceRegistrySchema.parse({
    format: 'kavrix-collaborative-device-registry',
    protocolVersion: 1,
    databaseId: 'database-a',
    authorityEpoch: 1,
    authorityFingerprint: digest(41),
    generation,
    previousRegistryDigest: digest(42),
    registryDigest,
    deniedDevices,
    updatedAt: approvedAt,
    authoritySignature: signature(41),
  });
}

interface ApprovalFixture {
  readonly request: ApprovalRequest;
  readonly evidence: ReturnType<typeof approvalEvidenceSchema.parse>;
}

function makeApprovalFixture(): ApprovalFixture {
  const tuple = makeTuple();
  const pending = approvalRequestSchema.parse({
    format: 'kavrix-collaborative-approval-request',
    protocolVersion: 1,
    approvalRequestId: 'approval-a',
    operationId: 'operation-a',
    operationType: 'add-member',
    databaseId: 'database-a',
    vaultId: 'vault-a',
    requestDigest: digest(50),
    actionParametersDigest: digest(51),
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    documentRevision: tuple.documentRevision,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    priorHeadDigest: digest(52),
    authorizationStateDigest: tuple.authorizationStateDigest,
    requestingPrincipalId: 'principal-a',
    requestingDeviceId: 'device-principal-a',
    requiredApprovalPolicy: 'one-additional-owner',
    state: 'pending',
    createdAt: timestamp,
    expiresAt: expiry,
    nonce: nonce(53),
    requesterSignature: signature(55),
    approvals: [],
  });
  const evidence = approvalEvidenceSchema.parse({
    protocolVersion: 1,
    approvalRequestId: pending.approvalRequestId,
    operationId: pending.operationId,
    databaseId: pending.databaseId,
    vaultId: pending.vaultId,
    requestDigest: pending.requestDigest,
    authorityEpoch: pending.authorityEpoch,
    databaseDeviceGeneration: pending.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: pending.databaseDeviceRegistryDigest,
    documentRevision: pending.documentRevision,
    membershipRevision: pending.membershipRevision,
    policyRevision: pending.policyRevision,
    keyEpoch: pending.keyEpoch,
    priorHeadDigest: pending.priorHeadDigest,
    authorizationStateDigest: pending.authorizationStateDigest,
    requestingPrincipalId: pending.requestingPrincipalId,
    approverPrincipalId: 'principal-b',
    approverDeviceId: 'device-principal-b',
    approvedAt,
    signature: signature(54),
  });
  return {
    request: approvalRequestSchema.parse({
      ...pending,
      state: 'quorum-reached',
      approvals: [evidence],
    }),
    evidence,
  };
}

function makeTransferFixture(
  disposition: TransferIntent['originalOwnerDisposition'] = 'editor',
  state: TransferIntent['state'] = 'recipient-accepted',
): TransferIntent {
  const tuple = makeTuple();
  const acceptance = {
    protocolVersion: 1 as const,
    transferIntentId: 'transfer-a',
    operationId: 'operation-transfer',
    databaseId: 'database-a',
    vaultId: 'vault-a',
    intentDigest: digest(61),
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    authorizationStateDigest: tuple.authorizationStateDigest,
    recipientPrincipalId: 'principal-b',
    recipientDeviceId: 'device-principal-b',
    acceptedAt: approvedAt,
    signature: signature(63),
  };
  return transferIntentSchema.parse({
    format: 'kavrix-collaborative-transfer-intent',
    protocolVersion: 1,
    transferIntentId: 'transfer-a',
    operationId: 'operation-transfer',
    databaseId: 'database-a',
    vaultId: 'vault-a',
    initiatorPrincipalId: 'principal-a',
    initiatorDeviceId: 'device-principal-a',
    recipientPrincipalId: 'principal-b',
    recipientDeviceId: 'device-principal-b',
    targetRole: 'owner',
    originalOwnerDisposition: disposition,
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    documentRevision: tuple.documentRevision,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    currentHeadDigest: digest(60),
    authorizationStateDigest: tuple.authorizationStateDigest,
    intentDigest: digest(61),
    approvalRequestId: 'approval-transfer',
    state,
    createdAt: timestamp,
    expiresAt: expiry,
    initiatorSignedAt: approvedAt,
    initiatorSignature: signature(62),
    ...(state === 'recipient-accepted' || state === 'published'
      ? { recipientAcceptance: acceptance }
      : {}),
    ...(state === 'published' ? { publishedAt: approvedAt } : {}),
  });
}

describe('collaboration policy', () => {
  const owner = makeMembership('principal-a', 'owner', 1);
  const editor = makeMembership('principal-b', 'editor', 2);
  const reader = makeMembership('principal-c', 'reader', 3);

  it('enforces every role × operation class and active lifecycle', () => {
    const operations: readonly CollaborationOperationType[] = [
      'ordinary-write',
      'add-member',
      'add-device',
      'remove-member',
      'revoke-device',
      'change-role',
      'rotate-key',
      'change-policy',
      'transfer-owner',
      'destroy-vault',
      'recover-owner',
      'emergency-rekey',
    ];
    for (const operationType of operations) {
      expect(
        authorizeOperation({
          operationType,
          membership: owner,
          device: firstDevice(owner),
        }),
      ).toMatchObject({ authorized: true });
      expect(
        authorizeOperation({
          operationType,
          membership: reader,
          device: firstDevice(reader),
        }),
      ).toMatchObject({ authorized: false });
      expect(
        authorizeOperation({
          operationType,
          membership: editor,
          device: firstDevice(editor),
        }).authorized,
      ).toBe(operationType === 'ordinary-write');
    }

    const revokedDevice = makeDevice('principal-a', 'device-revoked', 4, 'revoked');
    const ownerWithRevokedDevice = makeMembership('principal-a', 'owner', 5, 'active', [
      firstDevice(owner),
      revokedDevice,
    ]);
    expect(
      authorizeOperation({
        operationType: 'ordinary-write',
        membership: ownerWithRevokedDevice,
        device: revokedDevice,
      }).error?.code,
    ).toBe('inactive-actor');
    expect(
      authorizeOperation({
        operationType: 'genesis-migration',
        membership: owner,
        device: firstDevice(owner),
      }).error?.code,
    ).toBe('operation-not-supported');
    const revokedMembership = makeMembership('principal-a', 'owner', 6, 'revoked');
    expect(
      authorizeOperation({
        operationType: 'ordinary-write',
        membership: revokedMembership,
        device: firstDevice(revokedMembership),
      }).error?.code,
    ).toBe('inactive-actor');
  });

  it('enforces every revision delta and authority epoch rule', () => {
    const prior = makeTuple();
    const cases: readonly [CollaborationOperationType, Record<string, unknown>][] = [
      ['ordinary-write', { documentRevision: 4 }],
      ['add-member', { documentRevision: 4, membershipRevision: 3, keyEpoch: 5 }],
      ['add-device', { documentRevision: 4, membershipRevision: 3, keyEpoch: 5 }],
      ['remove-member', { documentRevision: 4, membershipRevision: 3, keyEpoch: 5 }],
      ['revoke-device', { documentRevision: 4, membershipRevision: 3, keyEpoch: 5 }],
      ['change-role', { documentRevision: 4, membershipRevision: 3 }],
      ['rotate-key', { documentRevision: 4, keyEpoch: 5 }],
      ['change-policy', { documentRevision: 4, policyRevision: 2 }],
      ['transfer-owner', { documentRevision: 4, membershipRevision: 3 }],
      ['destroy-vault', { documentRevision: 4 }],
      ['recover-owner', { documentRevision: 4, membershipRevision: 3, keyEpoch: 5 }],
      ['emergency-rekey', { documentRevision: 4, keyEpoch: 5 }],
    ];
    for (const [index, [operationType, overrides]] of cases.entries()) {
      const next = makeTuple(
        operationType === 'ordinary-write' || operationType === 'destroy-vault'
          ? overrides
          : {
              ...overrides,
              authorizationStateDigest: digest(80 + index),
            },
      );
      const result =
        operationType === 'ordinary-write'
          ? validateRevisionTransition({ operationType, prior, next })
          : validateRevisionTransition({
              operationType,
              prior,
              next,
              authorizationTransitionDigest: digest(100 + index),
            });
      expect(result.valid).toBe(true);
    }
    expect(
      validateRevisionTransition({
        operationType: 'transfer-owner',
        prior,
        next: makeTuple({
          documentRevision: 4,
          membershipRevision: 3,
          keyEpoch: 5,
          authorizationStateDigest: digest(90),
        }),
        decryptAccessChanged: true,
        authorizationTransitionDigest: digest(91),
      }).valid,
    ).toBe(true);
    expect(
      validateRevisionTransition({
        operationType: 'change-role',
        prior,
        next: makeTuple({
          documentRevision: 4,
          membershipRevision: 3,
          keyEpoch: 5,
          authorizationStateDigest: digest(92),
        }),
        authorizationTransitionDigest: digest(93),
      }).error?.code,
    ).toBe('key-rotation-required');
    expect(
      validateRevisionTransition({
        operationType: 'recover-owner',
        prior,
        next: makeTuple({
          documentRevision: 4,
          membershipRevision: 3,
          authorizationStateDigest: digest(94),
        }),
        authorizationTransitionDigest: digest(95),
      }).error?.code,
    ).toBe('key-rotation-required');
    expect(
      validateRevisionTransition({
        operationType: 'ordinary-write',
        prior,
        next: makeTuple({
          documentRevision: 4,
          databaseDeviceGeneration: 3,
          databaseDeviceRegistryDigest: digest(3),
        }),
      }).error?.code,
    ).toBe('rekey-required');
    const registry = makeRegistry(3, digest(3));
    expect(
      validateRevisionTransition({
        operationType: 'rotate-key',
        prior,
        next: makeTuple({
          documentRevision: 4,
          keyEpoch: 5,
          databaseDeviceGeneration: 3,
          databaseDeviceRegistryDigest: digest(3),
          authorizationStateDigest: digest(94),
        }),
        authoritativeRegistry: registry,
        authorizationTransitionDigest: digest(95),
      }).valid,
    ).toBe(true);
    expect(
      validateRevisionTransition({
        operationType: 'rotate-key',
        prior,
        next: makeTuple({
          documentRevision: 4,
          keyEpoch: 5,
          databaseDeviceGeneration: 3,
          databaseDeviceRegistryDigest: digest(3),
          authorizationStateDigest: digest(96),
        }),
        authorizationTransitionDigest: digest(97),
      }).error?.code,
    ).toBe('invalid-input');
    expect(
      validateRevisionTransition({
        operationType: 'ordinary-write',
        prior,
        next: makeTuple({ authorityEpoch: 2, documentRevision: 4 }),
      }).error?.code,
    ).toBe('authority-epoch-change');

    expect(
      validateRevisionTransition({
        operationType: 'ordinary-write',
        prior,
        next: makeTuple({ documentRevision: 4, authorizationStateDigest: digest(98) }),
      }).error?.code,
    ).toBe('revision-advance-invalid');
    expect(
      validateRevisionTransition({
        operationType: 'change-role',
        prior,
        next: makeTuple({
          documentRevision: 4,
          membershipRevision: 3,
          authorizationStateDigest: prior.authorizationStateDigest,
        }),
        authorizationTransitionDigest: digest(99),
      }).error?.code,
    ).toBe('revision-advance-invalid');
    expect(
      validateRevisionTransition({
        operationType: 'change-role',
        prior,
        next: makeTuple({
          documentRevision: 4,
          membershipRevision: 3,
          authorizationStateDigest: digest(100),
        }),
      }).error?.code,
    ).toBe('revision-advance-invalid');

    const genesisPrior = makeTuple({
      documentRevision: 0,
      membershipRevision: 0,
      policyRevision: 0,
      keyEpoch: 1,
      authorizationStateDigest: digest(101),
    });
    expect(
      validateRevisionTransition({
        operationType: 'genesis-migration',
        prior: genesisPrior,
        next: makeTuple({
          documentRevision: 1,
          membershipRevision: 1,
          policyRevision: 1,
          keyEpoch: 1,
          authorizationStateDigest: digest(102),
        }),
        authorizationTransitionDigest: digest(103),
      }).valid,
    ).toBe(true);
  });

  it('requires exact add-device membership and VRK deltas without a registry advance', () => {
    const prior = makeTuple();
    const nextAuthorizationStateDigest = digest(110);
    const transitionDigest = digest(111);
    const validNext = makeTuple({
      documentRevision: prior.documentRevision + 1,
      membershipRevision: prior.membershipRevision + 1,
      keyEpoch: prior.keyEpoch + 1,
      authorizationStateDigest: nextAuthorizationStateDigest,
    });
    const validate = (
      next: CollaborationRevisionTuple,
    ): ReturnType<typeof validateRevisionTransition> =>
      validateRevisionTransition({
        operationType: 'add-device',
        prior,
        next,
        authorizationTransitionDigest: transitionDigest,
      });

    expect(validate(validNext).valid).toBe(true);
    expect(
      validate(
        makeTuple({
          documentRevision: prior.documentRevision + 1,
          membershipRevision: prior.membershipRevision + 1,
          authorizationStateDigest: nextAuthorizationStateDigest,
        }),
      ).error?.code,
    ).toBe('key-rotation-required');
    expect(
      validate(
        makeTuple({
          documentRevision: prior.documentRevision + 1,
          keyEpoch: prior.keyEpoch + 1,
          authorizationStateDigest: nextAuthorizationStateDigest,
        }),
      ).error?.code,
    ).toBe('revision-advance-invalid');
    expect(
      validate(
        makeTuple({
          documentRevision: prior.documentRevision + 1,
          membershipRevision: prior.membershipRevision + 1,
          policyRevision: prior.policyRevision + 1,
          keyEpoch: prior.keyEpoch + 1,
          authorizationStateDigest: nextAuthorizationStateDigest,
        }),
      ).error?.code,
    ).toBe('revision-advance-invalid');

    const advancedRegistry = makeRegistry(3, digest(112));
    expect(
      validateRevisionTransition({
        operationType: 'add-device',
        prior,
        next: makeTuple({
          documentRevision: prior.documentRevision + 1,
          membershipRevision: prior.membershipRevision + 1,
          keyEpoch: prior.keyEpoch + 1,
          databaseDeviceGeneration: advancedRegistry.generation,
          databaseDeviceRegistryDigest: advancedRegistry.registryDigest,
          authorizationStateDigest: nextAuthorizationStateDigest,
        }),
        authoritativeRegistry: advancedRegistry,
        authorizationTransitionDigest: transitionDigest,
      }).error?.code,
    ).toBe('rekey-required');
  });

  it('requires the exact owner-authorized terminal destroy transition', () => {
    const prior = makeTuple();
    const transitionDigest = digest(113);
    const validNext = makeTuple({
      documentRevision: prior.documentRevision + 1,
    });
    const validate = (
      next: CollaborationRevisionTuple,
      authoritativeRegistry?: ReturnType<typeof makeRegistry>,
    ): ReturnType<typeof validateRevisionTransition> =>
      validateRevisionTransition({
        operationType: 'destroy-vault',
        prior,
        next,
        authorizationTransitionDigest: transitionDigest,
        ...(authoritativeRegistry === undefined ? {} : { authoritativeRegistry }),
      });

    expect(validate(validNext)).toMatchObject({
      valid: true,
      documentRevisionDelta: 1,
      membershipRevisionDelta: 0,
      policyRevisionDelta: 0,
      keyEpochDelta: 0,
      databaseDeviceGenerationDelta: 0,
      keyRotationRequired: false,
    });
    expect(
      validateRevisionTransition({
        operationType: 'destroy-vault',
        prior,
        next: validNext,
      }).error?.code,
    ).toBe('revision-advance-invalid');
    expect(
      validate(
        makeTuple({
          documentRevision: prior.documentRevision + 1,
          authorizationStateDigest: digest(114),
        }),
      ).error?.code,
    ).toBe('revision-advance-invalid');
    expect(
      validate(
        makeTuple({
          documentRevision: prior.documentRevision + 1,
          membershipRevision: prior.membershipRevision + 1,
        }),
      ).error?.code,
    ).toBe('revision-advance-invalid');
    expect(
      validate(
        makeTuple({
          documentRevision: prior.documentRevision + 1,
          policyRevision: prior.policyRevision + 1,
        }),
      ).error?.code,
    ).toBe('revision-advance-invalid');
    expect(
      validate(
        makeTuple({
          documentRevision: prior.documentRevision + 1,
          keyEpoch: prior.keyEpoch + 1,
        }),
      ).error?.code,
    ).toBe('key-rotation-required');

    const advancedRegistry = makeRegistry(3, digest(115));
    expect(
      validate(
        makeTuple({
          documentRevision: prior.documentRevision + 1,
          databaseDeviceGeneration: advancedRegistry.generation,
          databaseDeviceRegistryDigest: advancedRegistry.registryDigest,
        }),
        advancedRegistry,
      ).error?.code,
    ).toBe('rekey-required');
    expect(
      authorizeOperation({
        operationType: 'destroy-vault',
        membership: owner,
        device: firstDevice(owner),
      }).authorized,
    ).toBe(true);
    expect(
      authorizeOperation({
        operationType: 'destroy-vault',
        membership: editor,
        device: firstDevice(editor),
      }).error?.code,
    ).toBe('unauthorized-role');
  });

  it('fences stale generation and digest and identifies rekey-required state', () => {
    const registry = makeRegistry(3, digest(3));
    expect(
      evaluateDeviceFence({
        vault: makeTuple({ databaseDeviceGeneration: 2 }),
        authoritativeRegistry: registry,
      }),
    ).toMatchObject({ status: 'rekey-required', canWrite: false, rekeyRequired: true });
    expect(
      evaluateDeviceFence({
        vault: makeTuple({
          databaseDeviceGeneration: 3,
          databaseDeviceRegistryDigest: digest(4),
        }),
        authoritativeRegistry: registry,
      }),
    ).toMatchObject({
      status: 'digest-mismatch',
      canWrite: false,
      rekeyRequired: false,
    });
    expect(
      evaluateDeviceFence({
        vault: makeTuple({
          databaseDeviceGeneration: 4,
          databaseDeviceRegistryDigest: digest(4),
        }),
        authoritativeRegistry: registry,
      }),
    ).toMatchObject({ status: 'future-generation', canWrite: false });
    expect(
      evaluateDeviceFence({
        vault: makeTuple({
          databaseDeviceGeneration: 3,
          databaseDeviceRegistryDigest: digest(3),
        }),
        authoritativeRegistry: registry,
      }),
    ).toMatchObject({ status: 'current', canWrite: true, rekeyRequired: false });
  });

  it('uses the registry as a deny-only device fence', () => {
    const ownerDevice = firstDevice(owner);
    const currentRegistry = makeRegistry(2, digest(2));
    expect('devices' in currentRegistry).toBe(false);
    expect(
      authorizeOperation({
        operationType: 'ordinary-write',
        membership: owner,
        device: ownerDevice,
        authoritativeRegistry: currentRegistry,
        deviceSigningKeyFingerprint: digest(104),
      }).authorized,
    ).toBe(true);
    expect(
      evaluateDeviceFence({
        vault: makeTuple(),
        authoritativeRegistry: currentRegistry,
        actorDevice: ownerDevice,
        actorSigningKeyFingerprint: digest(104),
      }),
    ).toMatchObject({ status: 'current', canWrite: true });

    const deniedByDevice = makeRegistry(2, digest(2), [
      {
        principalId: ownerDevice.principalId,
        deviceId: ownerDevice.deviceId,
        deviceGeneration: 2,
        signingKeyFingerprint: digest(105),
        reason: 'revoked',
        deniedAt: approvedAt,
      },
    ]);
    expect(
      authorizeOperation({
        operationType: 'ordinary-write',
        membership: owner,
        device: ownerDevice,
        authoritativeRegistry: deniedByDevice,
        deviceSigningKeyFingerprint: digest(106),
      }),
    ).toMatchObject({ authorized: false, error: { code: 'device-denied' } });
    expect(
      evaluateDeviceFence({
        vault: makeTuple(),
        authoritativeRegistry: deniedByDevice,
        actorDevice: ownerDevice,
        actorSigningKeyFingerprint: digest(106),
      }),
    ).toMatchObject({ status: 'device-denied', canWrite: false });

    const deniedByFingerprint = makeRegistry(2, digest(2), [
      {
        principalId: ownerDevice.principalId,
        deviceId: 'device-other',
        deviceGeneration: 2,
        signingKeyFingerprint: digest(107),
        reason: 'compromised',
        deniedAt: approvedAt,
      },
    ]);
    expect(
      authorizeOperation({
        operationType: 'ordinary-write',
        membership: owner,
        device: ownerDevice,
        authoritativeRegistry: deniedByFingerprint,
        deviceSigningKeyFingerprint: digest(107),
      }).error?.code,
    ).toBe('device-denied');
  });

  it('protects the last owner and requires recovery to appoint a replacement atomically', () => {
    expect(checkActiveOwnerInvariant({ memberships: [owner] }).valid).toBe(true);
    expect(
      checkActiveOwnerInvariant({
        memberships: [owner],
        ownerPrincipalIds: [owner.principalId],
      }),
    ).toMatchObject({ valid: true, ownerIndexMatches: true });
    expect(
      checkActiveOwnerInvariant({
        memberships: [owner],
        ownerPrincipalIds: [],
      }).error?.code,
    ).toBe('owner-index-invalid');
    expect(
      checkActiveOwnerInvariant({
        memberships: [owner],
        ownerPrincipalIds: ['principal-b'],
      }).error?.code,
    ).toBe('owner-index-invalid');
    expect(
      checkActiveOwnerInvariant({
        memberships: [owner, makeMembership('principal-a', 'owner', 16)],
      }).error?.code,
    ).toBe('owner-index-invalid');
    expect(
      checkActiveOwnerInvariant({
        memberships: [makeMembership('principal-a', 'editor', 7)],
      }).error?.code,
    ).toBe('active-owner-required');
    expect(
      validateOwnerTransition({
        priorMemberships: [owner],
        nextMemberships: [makeMembership('principal-a', 'editor', 8)],
        authorityRecoveryRecorded: false,
      }).error?.code,
    ).toBe('last-owner-protected');
    expect(
      validateOwnerTransition({
        priorMemberships: [owner],
        nextMemberships: [
          makeMembership('principal-a', 'editor', 9),
          makeMembership('principal-b', 'owner', 10),
        ],
        authorityRecoveryRecorded: true,
      }).valid,
    ).toBe(true);
    expect(
      validateOwnerTransition({
        priorMemberships: [owner],
        nextMemberships: [],
        authorityRecoveryRecorded: true,
      }).error?.code,
    ).toBe('last-owner-protected');
  });

  it('requires exact prior policy/tuple, eligible owner, and verifier facts for approval consumption', () => {
    const fixture = makeApprovalFixture();
    const tuple = makeTuple();
    const base: ApprovalValidationInput = {
      request: fixture.request,
      priorPolicy: makePolicy('one-additional-owner'),
      priorTuple: tuple,
      priorHeadDigest: fixture.request.priorHeadDigest,
      activeMemberships: [owner, makeMembership('principal-b', 'owner', 11)],
      now: approvedAt,
      verifiedRequesterSignature: {
        approvalRequestId: fixture.request.approvalRequestId,
        requesterPrincipalId: fixture.request.requestingPrincipalId,
        requesterDeviceId: fixture.request.requestingDeviceId,
        signedRequestDigest: fixture.request.requestDigest,
        signature: fixture.request.requesterSignature,
      },
      verifiedApprovalSignatures: [
        {
          approvalRequestId: fixture.request.approvalRequestId,
          approverPrincipalId: fixture.evidence.approverPrincipalId,
          approverDeviceId: fixture.evidence.approverDeviceId,
          signedRequestDigest: fixture.request.requestDigest,
          signature: fixture.evidence.signature,
        },
      ],
    };
    const verifiedApprovalSignature = base.verifiedApprovalSignatures[0];
    if (verifiedApprovalSignature === undefined) {
      throw new Error('Approval fixture must contain a verifier signature.');
    }
    expect(validateApproval(base)).toMatchObject({
      valid: true,
      eligibleForConsumption: true,
    });
    const pending = approvalRequestSchema.parse({
      ...fixture.request,
      state: 'pending',
      approvals: [],
    });
    expect(
      validateApproval({
        ...base,
        request: pending,
        verifiedApprovalSignatures: [],
      }),
    ).toMatchObject({ valid: true, eligibleForConsumption: false });
    expect(validateApproval({ ...base, verifiedApprovalSignatures: [] })).toMatchObject(
      {
        valid: false,
        eligibleForConsumption: false,
      },
    );
    expect(
      validateApproval({
        ...base,
        verifiedRequesterSignature: {
          ...base.verifiedRequesterSignature,
          signedRequestDigest: digest(56),
        },
      }),
    ).toMatchObject({ valid: false, eligibleForConsumption: false });
    expect(
      validateApproval({
        ...base,
        priorPolicy: makePolicy('none'),
      }).error?.code,
    ).toBe('approval-policy-stale');
    expect(
      validateApproval({ ...base, priorTuple: makeTuple({ documentRevision: 4 }) })
        .error?.code,
    ).toBe('approval-stale');
    expect(
      validateApproval({
        ...base,
        priorTuple: makeTuple({ authorizationStateDigest: digest(108) }),
      }).error?.code,
    ).toBe('approval-stale');
    expect(validateApproval({ ...base, now: expiry }).error?.code).toBe(
      'approval-expired',
    );
    const approvalFree = approvalRequestSchema.parse({
      ...fixture.request,
      requiredApprovalPolicy: 'none',
      state: 'pending',
      approvals: [],
    });
    expect(
      validateApproval({
        ...base,
        request: approvalFree,
        priorPolicy: makePolicy('none'),
        verifiedApprovalSignatures: [],
      }),
    ).toMatchObject({ valid: true, eligibleForConsumption: false });
    const consumedApprovalFree = approvalRequestSchema.parse({
      ...approvalFree,
      state: 'consumed',
      resolvedAt: approvedAt,
    });
    expect(
      validateApproval({
        ...base,
        request: consumedApprovalFree,
        priorPolicy: makePolicy('none'),
        verifiedApprovalSignatures: [],
      }).error?.code,
    ).toBe('approval-already-consumed');
    const pendingWithEvidence = approvalRequestSchema.parse({
      ...fixture.request,
      state: 'pending',
    });
    expect(
      validateApproval({ ...base, request: pendingWithEvidence }).error?.code,
    ).toBe('approval-quorum-invalid');
    const expiredRequest = approvalRequestSchema.parse({
      ...fixture.request,
      state: 'expired',
      resolvedAt: expiry,
    });
    expect(validateApproval({ ...base, request: expiredRequest }).error?.code).toBe(
      'approval-expired',
    );
    const earlyEvidence = approvalEvidenceSchema.parse({
      ...fixture.evidence,
      approvedAt: timestampSchema.parse('2025-12-31T23:59:59.000Z'),
    });
    const earlyEvidenceRequest = approvalRequestSchema.parse({
      ...fixture.request,
      approvals: [earlyEvidence],
    });
    expect(
      validateApproval({ ...base, request: earlyEvidenceRequest }).error?.code,
    ).toBe('approval-expired');
    expect(
      validateApproval({
        ...base,
        activeMemberships: [owner, editor],
      }).error?.code,
    ).toBe('approval-invalid');
    expect(
      validateApproval({
        ...base,
        verifiedApprovalSignatures: [
          {
            ...verifiedApprovalSignature,
            signature: signature(57),
          },
        ],
      }).error?.code,
    ).toBe('approval-invalid');
    const consumed = approvalRequestSchema.parse({
      ...fixture.request,
      state: 'consumed',
      resolvedAt: approvedAt,
    });
    expect(validateApproval({ ...base, request: consumed }).error?.code).toBe(
      'approval-already-consumed',
    );
    const cancelled = approvalRequestSchema.parse({
      ...fixture.request,
      state: 'cancelled',
      approvals: [],
      resolvedAt: approvedAt,
    });
    expect(validateApproval({ ...base, request: cancelled }).error?.code).toBe(
      'approval-invalid',
    );
    expect(
      approvalRequestSchema.safeParse({
        ...fixture.request,
        approvals: [
          {
            ...fixture.evidence,
            approverPrincipalId: fixture.request.requestingPrincipalId,
          },
        ],
      }).success,
    ).toBe(false);
    expect(
      approvalRequestSchema.safeParse({
        ...fixture.request,
        approvals: [fixture.evidence, fixture.evidence],
      }).success,
    ).toBe(false);
  });

  it('requires verifier-bound two-party transfer signatures and exact owner disposition', () => {
    const intent = makeTransferFixture('editor');
    const priorMemberships = [owner, editor];
    const nextMemberships = [
      makeMembership('principal-a', 'editor', 12),
      makeMembership('principal-b', 'owner', 13),
    ];
    const base: OwnershipTransferValidationInput = {
      intent,
      priorMemberships,
      nextMemberships,
      priorTuple: makeTuple(),
      priorHeadDigest: intent.currentHeadDigest,
      now: approvedAt,
      initiatorSignatureVerification: {
        signerPrincipalId: intent.initiatorPrincipalId,
        signerDeviceId: intent.initiatorDeviceId,
        signedIntentDigest: intent.intentDigest,
        signature: initiatorSignature(intent),
      },
      recipientAcceptanceVerification: {
        signerPrincipalId: intent.recipientPrincipalId,
        signerDeviceId: intent.recipientDeviceId,
        signedIntentDigest: intent.intentDigest,
        signature: recipientSignature(intent),
      },
    };
    expect(validateOwnershipTransfer(base)).toMatchObject({
      valid: true,
      complete: true,
      initiatorSignatureValid: true,
      recipientAcceptanceValid: true,
    });
    const dispositionCases = [
      {
        disposition: 'remain-owner' as const,
        nextInitiator: makeMembership('principal-a', 'owner', 16),
      },
      {
        disposition: 'reader' as const,
        nextInitiator: makeMembership('principal-a', 'reader', 17),
      },
      {
        disposition: 'removed' as const,
        nextInitiator: makeMembership('principal-a', 'owner', 18, 'revoked'),
      },
    ];
    for (const { disposition, nextInitiator } of dispositionCases) {
      const dispositionIntent = makeTransferFixture(disposition);
      expect(
        validateOwnershipTransfer({
          ...base,
          intent: dispositionIntent,
          nextMemberships: [nextInitiator, makeMembership('principal-b', 'owner', 19)],
          priorHeadDigest: dispositionIntent.currentHeadDigest,
          initiatorSignatureVerification: {
            ...base.initiatorSignatureVerification,
            signedIntentDigest: dispositionIntent.intentDigest,
            signature: initiatorSignature(dispositionIntent),
          },
          recipientAcceptanceVerification: {
            ...base.recipientAcceptanceVerification,
            signedIntentDigest: dispositionIntent.intentDigest,
            signature: recipientSignature(dispositionIntent),
          },
        }),
      ).toMatchObject({ valid: true, complete: true });
    }
    const publishedIntent = makeTransferFixture('editor', 'published');
    expect(
      validateOwnershipTransfer({
        ...base,
        intent: publishedIntent,
        priorHeadDigest: publishedIntent.currentHeadDigest,
      }),
    ).toMatchObject({ valid: true, complete: true });
    const initiatorSignedIntent = makeTransferFixture('editor', 'initiator-signed');
    expect(
      validateOwnershipTransfer({
        ...base,
        intent: initiatorSignedIntent,
        priorHeadDigest: initiatorSignedIntent.currentHeadDigest,
      }).error?.code,
    ).toBe('transfer-state-invalid');
    expect(
      validateOwnershipTransfer({
        ...base,
        initiatorSignatureVerification: {
          ...base.initiatorSignatureVerification,
          signedIntentDigest: digest(70),
        },
      }),
    ).toMatchObject({
      valid: false,
      complete: false,
      initiatorSignatureValid: false,
      recipientAcceptanceValid: false,
    });
    expect(
      validateOwnershipTransfer({
        ...base,
        recipientAcceptanceVerification: {
          ...base.recipientAcceptanceVerification,
          signedIntentDigest: digest(72),
        },
      }),
    ).toMatchObject({
      valid: false,
      complete: false,
      initiatorSignatureValid: true,
      recipientAcceptanceValid: false,
    });
    expect(validateOwnershipTransfer({ ...base, now: expiry }).error?.code).toBe(
      'transfer-expired',
    );
    expect(
      validateOwnershipTransfer({ ...base, priorHeadDigest: digest(71) }).error?.code,
    ).toBe('transfer-stale');
    expect(
      validateOwnershipTransfer({
        ...base,
        priorTuple: makeTuple({ authorizationStateDigest: digest(109) }),
      }).error?.code,
    ).toBe('transfer-stale');
    expect(
      validateOwnershipTransfer({
        ...base,
        nextMemberships: [
          makeMembership('principal-a', 'owner', 14),
          makeMembership('principal-b', 'editor', 15),
        ],
      }).error?.code,
    ).toBe('transfer-invalid');
  });
});
