import {
  COLLABORATION_DOMAINS,
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
  computeAuthorizationStateDigest,
  computeMembershipManifestDigest,
  computePublicKeyFingerprint,
  generateDeviceEncryptionKeyPair,
  generateDeviceSigningKeyPair,
  generatePrincipalSigningKeyPair,
  signCollaborationRecord,
  zeroize,
  type CollaborationDomain,
  type CollaborationEncryptionKeyPair,
  type CollaborationSignatureField,
  type DeviceSigningKeyPair,
  type PrincipalSigningKeyPair,
} from '@kavrix/crypto';
import {
  approvalRequestSchema,
  canonicalJson,
  collaborationAuthorizationStateCoreSchema,
  collaborationKeyEnvelopeSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  deviceCertificateSchema,
  sha256DigestSchema,
  transferIntentSchema,
  type CollaborationMembership,
  type CollaborationKeyEnvelope,
  type CollaborationOperationId,
  type CollaborationAuthorizationStateCore,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type ApprovalRequest,
  type ApprovalRequestId,
  type DeviceCertificate,
  type Sha256Digest,
  type TransferIntentId,
} from '@kavrix/schemas';
import { afterEach, describe, expect, it } from 'vitest';

import {
  CollaborationAuthorizationWorkflowError,
  acceptOwnershipTransferIntent,
  addApproval,
  createApprovalRequest,
  createOwnershipTransferIntent,
  resolveApprovalRequest,
  resolveOwnershipTransferIntent,
  type AuthenticatedAuthorizationPriorState,
  type AuthorizationDeviceSigner,
} from '../src/collaboration-authorization-workflows.js';

const CREATED_AT = '2026-08-30T00:00:00.000Z';
const REQUESTED_AT = '2026-08-30T00:01:00.000Z';
const APPROVED_AT = '2026-08-30T00:02:00.000Z';
const ACCEPTED_AT = '2026-08-30T00:03:00.000Z';
const PUBLISHED_AT = '2026-08-30T00:04:00.000Z';
const EXPIRES_AT = '2026-08-30T00:11:00.000Z';
const AFTER_EXPIRY = '2026-08-30T00:12:00.000Z';
const DATABASE_ID = 'database-authorization-workflow';
const VAULT_ID = 'vault-authorization-workflow';
const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');

interface SchemaLike<T> {
  readonly parse: (input: unknown) => T;
}

type Identity = Readonly<{
  root: PrincipalSigningKeyPair;
  signing: DeviceSigningKeyPair;
  encryption: CollaborationEncryptionKeyPair;
  certificate: DeviceCertificate;
}>;

type Fixture = Readonly<{
  document: CollaborativeVaultDocument;
  manifest: CollaborativeMembershipManifest;
  firstOwner: Identity;
  secondOwner: Identity;
  recipient: Identity;
  outsider: Identity;
}>;

const fixtures: Fixture[] = [];

afterEach(() => {
  for (const fixture of fixtures.splice(0)) {
    for (const identity of [
      fixture.firstOwner,
      fixture.secondOwner,
      fixture.recipient,
      fixture.outsider,
    ]) {
      zeroize(identity.root.privateKey);
      zeroize(identity.signing.privateKey);
      zeroize(identity.encryption.privateKey);
    }
  }
});

function bytes(length: number, value: number): string {
  return Buffer.alloc(length, value).toString('base64url');
}

function digest(value: number): Sha256Digest {
  return sha256DigestSchema.parse(bytes(32, value));
}

const operationId = (value: string): CollaborationOperationId =>
  approvalRequestSchema.shape.operationId.parse(value);
const approvalId = (value: string): ApprovalRequestId =>
  approvalRequestSchema.shape.approvalRequestId.parse(value);
const transferId = (value: string): TransferIntentId =>
  transferIntentSchema.shape.transferIntentId.parse(value);

async function signedRecord<T>(
  domain: CollaborationDomain,
  value: Record<string, unknown>,
  schema: SchemaLike<T>,
  field: CollaborationSignatureField,
  privateKey: Uint8Array,
): Promise<T> {
  return schema.parse({
    ...value,
    [field]: await signCollaborationRecord(domain, value, schema, field, privateKey),
  });
}

async function identity(principalId: string, deviceId: string): Promise<Identity> {
  const root = await generatePrincipalSigningKeyPair();
  const signing = await generateDeviceSigningKeyPair();
  const encryption = await generateDeviceEncryptionKeyPair();
  const certificate = await signedRecord(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    {
      protocolVersion: 1,
      principalId,
      deviceId,
      deviceGeneration: 1,
      signingPublicKey: signing.publicKeyBase64,
      encryptionPublicKey: encryption.publicKeyBase64,
      state: 'active',
      createdAt: CREATED_AT,
      stateChangedAt: CREATED_AT,
      rootSignature: PLACEHOLDER_SIGNATURE,
    },
    deviceCertificateSchema,
    'rootSignature',
    root.privateKey,
  );
  return { root, signing, encryption, certificate };
}

function membership(
  identityValue: Identity,
  membershipId: string,
  role: CollaborationMembership['role'],
): CollaborationMembership {
  return collaborativeMembershipManifestSchema.shape.memberships.element.parse({
    membershipId,
    principalId: identityValue.certificate.principalId,
    principalFingerprint: computePublicKeyFingerprint(
      identityValue.root.publicKeyBase64,
      'ed25519',
    ),
    rootSigningPublicKey: identityValue.root.publicKeyBase64,
    identityGeneration: 1,
    role,
    state: 'active',
    devices: [identityValue.certificate],
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
}

function memberEnvelope(
  member: CollaborationMembership,
  fill: number,
): CollaborationKeyEnvelope {
  const device = requireValue(member.devices[0]);
  return collaborationKeyEnvelopeSchema.parse({
    format: 'kavrix-collaborative-member-key-envelope' as const,
    protocolVersion: 1 as const,
    algorithm: 'x25519-sealed-box' as const,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    membershipId: member.membershipId,
    principalId: member.principalId,
    deviceId: device.deviceId,
    recipientEncryptionKeyFingerprint: digest(fill),
    keyEpoch: 1,
    membershipRevision: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    sealedVaultRootKey: bytes(80, fill + 1),
    envelopeDigest: digest(fill + 2),
    createdAt: CREATED_AT,
    ownerSignature: bytes(64, fill + 3),
  });
}

function authorizationCore(
  memberships: readonly CollaborationMembership[],
  keyEnvelopes: CollaborativeMembershipManifest['keyEnvelopes'],
  approvalPolicy: CollaborativeMembershipManifest['approvalPolicy'],
): CollaborationAuthorizationStateCore {
  return collaborationAuthorizationStateCoreSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    memberships: memberships.map((member) => ({
      membershipId: member.membershipId,
      principalId: member.principalId,
      principalFingerprint: member.principalFingerprint,
      rootSigningPublicKey: member.rootSigningPublicKey,
      identityGeneration: member.identityGeneration,
      role: member.role,
      state: member.state,
      devices: member.devices.map(deviceAuthorizationCore),
      createdAt: member.createdAt,
      updatedAt: member.updatedAt,
    })),
    ownerPrincipalIds: memberships
      .filter((member) => member.role === 'owner')
      .map((member) => member.principalId),
    keyEnvelopes: keyEnvelopes.map(keyEnvelopeAuthorizationCore),
    approvalPolicy,
  });
}

function deviceAuthorizationCore(
  device: DeviceCertificate,
): Omit<DeviceCertificate, 'rootSignature'> {
  const result = { ...device };
  Reflect.deleteProperty(result, 'rootSignature');
  return result;
}

function keyEnvelopeAuthorizationCore(
  envelope: CollaborativeMembershipManifest['keyEnvelopes'][number],
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...envelope };
  Reflect.deleteProperty(result, 'envelopeDigest');
  Reflect.deleteProperty(result, 'createdAt');
  Reflect.deleteProperty(result, 'ownerSignature');
  return result;
}

function requireValue<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('fixture setup failed');
  return value;
}

async function buildFixture(
  approvalPolicy: 'none' | 'one-additional-owner' = 'one-additional-owner',
): Promise<Fixture> {
  const firstOwner = await identity('principal-owner-one', 'device-owner-one');
  const secondOwner = await identity('principal-owner-two', 'device-owner-two');
  const recipient = await identity('principal-recipient', 'device-recipient');
  const outsider = await identity('principal-outsider', 'device-outsider');
  const members = [
    membership(firstOwner, 'membership-owner-one', 'owner'),
    membership(secondOwner, 'membership-owner-two', 'owner'),
    membership(recipient, 'membership-recipient', 'reader'),
  ];
  const keyEnvelopes = [
    memberEnvelope(requireValue(members[0]), 10),
    memberEnvelope(requireValue(members[1]), 20),
    memberEnvelope(requireValue(members[2]), 30),
    databaseAuthorityRecoveryEnvelopeSchema.parse({
      format: 'kavrix-collaborative-authority-recovery-envelope' as const,
      protocolVersion: 1 as const,
      algorithm: 'x25519-sealed-box' as const,
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      authorityEpoch: 1,
      authorityRecoveryKeyFingerprint: digest(64),
      keyEpoch: 1,
      membershipRevision: 1,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: digest(2),
      sealedVaultRootKey: bytes(80, 41),
      envelopeDigest: digest(42),
      sealedByPrincipalId: firstOwner.certificate.principalId,
      sealedByDeviceId: firstOwner.certificate.deviceId,
      createdAt: CREATED_AT,
      ownerSignature: bytes(64, 43),
    }),
  ];
  const authorizationStateDigest = computeAuthorizationStateDigest(
    authorizationCore(members, keyEnvelopes, approvalPolicy),
  );
  const tuple = {
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    authorizationStateDigest,
  } as const;
  const policy = {
    protocolVersion: 1 as const,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    policyRevision: 1,
    approvalPolicy,
    policyDigest: digest(50),
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    changedByPrincipalId: firstOwner.certificate.principalId,
    changedByDeviceId: firstOwner.certificate.deviceId,
    changedAt: CREATED_AT,
    signature: bytes(64, 51),
  };
  const history = {
    protocolVersion: 1 as const,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    events: [],
    checkpoints: [],
    compactedThroughRevision: 0,
    compactedHistoryDigest: COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousHistoryDigest: COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
    currentHistoryDigest: digest(54),
  };
  const manifestBase = collaborativeMembershipManifestSchema.parse({
    format: 'kavrix-collaborative-membership-manifest',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    ...tuple,
    memberships: members,
    ownerPrincipalIds: [
      firstOwner.certificate.principalId,
      secondOwner.certificate.principalId,
    ],
    keyEnvelopes,
    approvalPolicy,
    policy,
    pendingApprovals: [],
    pendingTransfers: [],
    history,
    previousMembershipDigest: COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
    membershipDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
  const manifest = collaborativeMembershipManifestSchema.parse({
    ...manifestBase,
    membershipDigest: computeMembershipManifestDigest(manifestBase),
  });
  const previousTuple = {
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    documentRevision: 0,
    membershipRevision: 0,
    policyRevision: 0,
    keyEpoch: 1,
    authorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  } as const;
  const headDigest = digest(60);
  const authorityDelegation = {
    format: 'kavrix-collaborative-authority-delegation' as const,
    protocolVersion: 1 as const,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    authoritySigningPublicKey: bytes(32, 61),
    authoritySigningKeyFingerprint: digest(62),
    authorityRecoveryPublicKey: bytes(32, 63),
    authorityRecoveryKeyFingerprint: digest(64),
    genesisOperationId: 'operation-genesis',
    genesisTuple: tuple,
    genesisHeadDigest: headDigest,
    initialAuthorizationStateDigest: authorizationStateDigest,
    initialOwnerPrincipalId: firstOwner.certificate.principalId,
    initialOwnerRootKeyFingerprint: computePublicKeyFingerprint(
      firstOwner.root.publicKeyBase64,
      'ed25519',
    ),
    initialOwnerDeviceId: firstOwner.certificate.deviceId,
    initialOwnerDeviceSigningKeyFingerprint: computePublicKeyFingerprint(
      firstOwner.signing.publicKeyBase64,
      'ed25519',
    ),
    initialOwnerDeviceEncryptionKeyFingerprint: computePublicKeyFingerprint(
      firstOwner.encryption.publicKeyBase64,
      'x25519',
    ),
    issuedAt: CREATED_AT,
    authoritySignature: bytes(64, 65),
  };
  const transitionDigest = digest(66);
  const authorizationTransition = {
    format: 'kavrix-collaborative-authorization-transition' as const,
    protocolVersion: 1 as const,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: 'operation-genesis',
    operationType: 'genesis-migration' as const,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousAuthorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
    authorizationStateDigest,
    previousTuple,
    nextTuple: tuple,
    evidence: { kind: 'none' as const },
    issuedAt: CREATED_AT,
    expiresAt: EXPIRES_AT,
    transitionDigest,
    transitionSignature: {
      signerKind: 'owner-device' as const,
      signerPrincipalId: firstOwner.certificate.principalId,
      signerDeviceId: firstOwner.certificate.deviceId,
      signature: bytes(64, 67),
    },
  };
  const commitment = {
    protocolVersion: 1 as const,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: 'operation-genesis',
    operationType: 'genesis-migration' as const,
    requestDigest: digest(68),
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousAuthorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
    authorizationStateDigest,
    authorizationTransitionDigest: transitionDigest,
    previousAuthorityEpoch: 1,
    previousDocumentRevision: 0,
    previousMembershipRevision: 0,
    previousPolicyRevision: 0,
    previousKeyEpoch: 1,
    previousDatabaseDeviceGeneration: 1,
    previousDatabaseDeviceRegistryDigest: digest(2),
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    encryptedPayloadDigest: digest(69),
    encryptedMembershipDigest: digest(70),
    encryptedEnvelopesDigest: digest(71),
    policyDigest: policy.policyDigest,
    writerPrincipalId: firstOwner.certificate.principalId,
    writerDeviceId: firstOwner.certificate.deviceId,
    timestamp: CREATED_AT,
  };
  const aad = (entityType: 'vault-payload' | 'membership-manifest', fill: number) =>
    ({
      protocolVersion: 1 as const,
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      authorityEpoch: 1,
      entityType,
      entityId: VAULT_ID,
      documentRevision: 1,
      membershipRevision: 1,
      policyRevision: 1,
      keyEpoch: 1,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: digest(2),
      authorizationStateDigest,
      metadataDigest: digest(fill),
    }) as const;
  const document = collaborativeVaultDocumentSchema.parse({
    format: 'kavrix-collaborative-vault',
    documentVersion: 1,
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    ...tuple,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    headDigest,
    authorityDelegation,
    authorityDelegationDigest: digest(72),
    encryptedPayloadDigest: commitment.encryptedPayloadDigest,
    encryptedMembershipDigest: commitment.encryptedMembershipDigest,
    encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
    policyDigest: policy.policyDigest,
    databaseAuthorityRecoveryEnvelope: manifest.keyEnvelopes.find(
      (envelope) => !('membershipId' in envelope),
    ),
    encryptedPayload: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: bytes(24, 73),
      ciphertext: bytes(32, 74),
      authenticationTag: bytes(16, 75),
      aad: aad('vault-payload', 76),
    },
    encryptedMembershipManifest: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: bytes(24, 77),
      ciphertext: bytes(32, 78),
      authenticationTag: bytes(16, 79),
      aad: aad('membership-manifest', 80),
    },
    discoveryRecords: [],
    currentMutationLink: {
      format: 'kavrix-collaborative-finalized-mutation-link',
      protocolVersion: 1,
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      authorityDelegationDigest: digest(72),
      commitment,
      authorizationTransition,
      resultingHeadDigest: headDigest,
      writerSignature: {
        algorithm: 'ed25519',
        writerPrincipalId: firstOwner.certificate.principalId,
        writerDeviceId: firstOwner.certificate.deviceId,
        commitmentDigest: headDigest,
        signature: bytes(64, 81),
      },
      finalizedAt: CREATED_AT,
    },
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
  const fixture = {
    document,
    manifest,
    firstOwner,
    secondOwner,
    recipient,
    outsider,
  };
  fixtures.push(fixture);
  return fixture;
}

function prior(fixture: Fixture): AuthenticatedAuthorizationPriorState {
  return { document: fixture.document, manifest: fixture.manifest };
}

function signer(identityValue: Identity): AuthorizationDeviceSigner {
  return {
    deviceCertificate: identityValue.certificate,
    deviceSigningPrivateKey: identityValue.signing.privateKey,
  };
}

async function approvedRequest(
  fixture: Fixture,
  actionDigest = digest(90),
  operationType: 'transfer-owner' | 'change-policy' = 'transfer-owner',
  requestOperationId = operationId('operation-transfer'),
  requestId = approvalId('approval-transfer'),
): Promise<ApprovalRequest> {
  const created = await createApprovalRequest({
    prior: prior(fixture),
    requester: signer(fixture.firstOwner),
    operationType,
    operationId: requestOperationId,
    approvalRequestId: requestId,
    actionParametersDigest: actionDigest,
    createdAt: REQUESTED_AT,
    expiresAt: EXPIRES_AT,
    nonce: bytes(16, 91),
  });
  if (created.kind !== 'approval-required') throw new Error('fixture setup failed');
  return await addApproval({
    prior: prior(fixture),
    request: created.request,
    approver: signer(fixture.secondOwner),
    approvedAt: APPROVED_AT,
  });
}

describe('collaboration authorization workflows', () => {
  it('creates, approves, and consumes one-additional-owner evidence immutably', async () => {
    const fixture = await buildFixture();
    const request = await approvedRequest(fixture);
    expect(request.state).toBe('quorum-reached');
    expect(request.approvals).toHaveLength(1);
    expect(Object.isFrozen(request)).toBe(true);
    expect(Object.isFrozen(request.approvals[0])).toBe(true);

    const consumed = await resolveApprovalRequest({
      prior: prior(fixture),
      request,
      resolution: 'consumed',
      resolvedAt: PUBLISHED_AT,
    });
    expect(consumed.state).toBe('consumed');
    expect(consumed.requesterSignature).toBe(request.requesterSignature);
    expect(consumed.approvals).toStrictEqual(request.approvals);
    await expect(
      resolveApprovalRequest({
        prior: prior(fixture),
        request: consumed,
        resolution: 'cancelled',
        resolvedAt: PUBLISHED_AT,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
  });

  it('returns an explicit no-approval result under policy none', async () => {
    const fixture = await buildFixture('none');
    await expect(
      createApprovalRequest({
        prior: prior(fixture),
        requester: signer(fixture.firstOwner),
        operationType: 'change-policy',
        operationId: operationId('operation-no-approval'),
        approvalRequestId: approvalId('approval-no-approval'),
        actionParametersDigest: digest(92),
        createdAt: REQUESTED_AT,
        expiresAt: EXPIRES_AT,
        nonce: bytes(16, 93),
      }),
    ).resolves.toStrictEqual({ kind: 'approval-not-required' });
  });

  it('rejects self/non-owner, stale, expired, substituted, and replayed approvals', async () => {
    const fixture = await buildFixture();
    const created = await createApprovalRequest({
      prior: prior(fixture),
      requester: signer(fixture.firstOwner),
      operationType: 'change-policy',
      operationId: operationId('operation-policy'),
      approvalRequestId: approvalId('approval-policy'),
      actionParametersDigest: digest(94),
      createdAt: REQUESTED_AT,
      expiresAt: EXPIRES_AT,
      nonce: bytes(16, 95),
    });
    if (created.kind !== 'approval-required') throw new Error('fixture setup failed');
    for (const approver of [fixture.firstOwner, fixture.recipient]) {
      await expect(
        addApproval({
          prior: prior(fixture),
          request: created.request,
          approver: signer(approver),
          approvedAt: APPROVED_AT,
        }),
      ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    }
    const staleDocument = {
      ...fixture.document,
      headDigest: digest(96),
      currentMutationLink: {
        ...fixture.document.currentMutationLink,
        resultingHeadDigest: digest(96),
        writerSignature: {
          ...fixture.document.currentMutationLink.writerSignature,
          commitmentDigest: digest(96),
        },
      },
      authorityDelegation: {
        ...fixture.document.authorityDelegation,
        genesisHeadDigest: digest(96),
      },
    } as CollaborativeVaultDocument;
    await expect(
      addApproval({
        prior: { document: staleDocument, manifest: fixture.manifest },
        request: created.request,
        approver: signer(fixture.secondOwner),
        approvedAt: APPROVED_AT,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    await expect(
      addApproval({
        prior: prior(fixture),
        request: created.request,
        approver: signer(fixture.secondOwner),
        approvedAt: AFTER_EXPIRY,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    await expect(
      addApproval({
        prior: prior(fixture),
        request: { ...created.request, actionParametersDigest: digest(97) },
        approver: signer(fixture.secondOwner),
        approvedAt: APPROVED_AT,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    const approved = await addApproval({
      prior: prior(fixture),
      request: created.request,
      approver: signer(fixture.secondOwner),
      approvedAt: APPROVED_AT,
    });
    await expect(
      addApproval({
        prior: prior(fixture),
        request: approved,
        approver: signer(fixture.secondOwner),
        approvedAt: ACCEPTED_AT,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
  });

  it('creates, accepts, and publishes an exact two-party ownership transfer', async () => {
    const fixture = await buildFixture();
    const actionDigest = digest(100);
    const approval = await approvedRequest(fixture, actionDigest);
    const intent = await createOwnershipTransferIntent({
      prior: prior(fixture),
      initiator: signer(fixture.firstOwner),
      recipientDeviceCertificate: fixture.recipient.certificate,
      transferIntentId: transferId('transfer-one'),
      operationId: operationId('operation-transfer'),
      actionParametersDigest: actionDigest,
      originalOwnerDisposition: 'editor',
      createdAt: APPROVED_AT,
      expiresAt: EXPIRES_AT,
      approvalRequest: approval,
    });
    const accepted = await acceptOwnershipTransferIntent({
      prior: prior(fixture),
      intent,
      recipient: signer(fixture.recipient),
      acceptedAt: ACCEPTED_AT,
      actionParametersDigest: actionDigest,
      approvalRequest: approval,
    });
    const nextMemberships = fixture.manifest.memberships.map((member) =>
      member.principalId === fixture.firstOwner.certificate.principalId
        ? { ...member, role: 'editor' as const, updatedAt: PUBLISHED_AT }
        : member.principalId === fixture.recipient.certificate.principalId
          ? { ...member, role: 'owner' as const, updatedAt: PUBLISHED_AT }
          : member,
    );
    const published = await resolveOwnershipTransferIntent({
      prior: prior(fixture),
      intent: accepted,
      resolution: 'published',
      resolvedAt: PUBLISHED_AT,
      actionParametersDigest: actionDigest,
      approvalRequest: approval,
      nextMemberships,
    });
    expect(published.state).toBe('published');
    expect(published.initiatorSignature).toBe(intent.initiatorSignature);
    expect(published.recipientAcceptance).toStrictEqual(accepted.recipientAcceptance);
    expect(Object.isFrozen(published.recipientAcceptance)).toBe(true);
    await expect(
      resolveOwnershipTransferIntent({
        prior: prior(fixture),
        intent: published,
        resolution: 'cancelled',
        resolvedAt: PUBLISHED_AT,
        actionParametersDigest: actionDigest,
        approvalRequest: approval,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
  });

  it('rejects modified, expired, stale, wrong-recipient, and approval-mismatch transfers', async () => {
    const fixture = await buildFixture();
    const actionDigest = digest(101);
    const approval = await approvedRequest(fixture, actionDigest);
    const intent = await createOwnershipTransferIntent({
      prior: prior(fixture),
      initiator: signer(fixture.firstOwner),
      recipientDeviceCertificate: fixture.recipient.certificate,
      transferIntentId: transferId('transfer-reject'),
      operationId: operationId('operation-transfer'),
      actionParametersDigest: actionDigest,
      originalOwnerDisposition: 'remain-owner',
      createdAt: APPROVED_AT,
      expiresAt: EXPIRES_AT,
      approvalRequest: approval,
    });
    const cases = [
      {
        intent: { ...intent, originalOwnerDisposition: 'removed' as const },
        recipient: signer(fixture.recipient),
        acceptedAt: ACCEPTED_AT,
        approvalRequest: approval,
        actionParametersDigest: actionDigest,
      },
      {
        intent,
        recipient: signer(fixture.recipient),
        acceptedAt: AFTER_EXPIRY,
        approvalRequest: approval,
        actionParametersDigest: actionDigest,
      },
      {
        intent,
        recipient: signer(fixture.outsider),
        acceptedAt: ACCEPTED_AT,
        approvalRequest: approval,
        actionParametersDigest: actionDigest,
      },
      {
        intent,
        recipient: signer(fixture.recipient),
        acceptedAt: ACCEPTED_AT,
        approvalRequest: approval,
        actionParametersDigest: digest(102),
      },
    ];
    for (const candidate of cases) {
      await expect(
        acceptOwnershipTransferIntent({ prior: prior(fixture), ...candidate }),
      ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    }
    const staleDocument = {
      ...fixture.document,
      documentRevision: 2,
      currentMutationLink: {
        ...fixture.document.currentMutationLink,
        commitment: {
          ...fixture.document.currentMutationLink.commitment,
          documentRevision: 2,
        },
      },
      encryptedPayload: {
        ...fixture.document.encryptedPayload,
        aad: { ...fixture.document.encryptedPayload.aad, documentRevision: 2 },
      },
      encryptedMembershipManifest: {
        ...fixture.document.encryptedMembershipManifest,
        aad: {
          ...fixture.document.encryptedMembershipManifest.aad,
          documentRevision: 2,
        },
      },
    } as CollaborativeVaultDocument;
    await expect(
      acceptOwnershipTransferIntent({
        prior: { document: staleDocument, manifest: fixture.manifest },
        intent,
        recipient: signer(fixture.recipient),
        acceptedAt: ACCEPTED_AT,
        actionParametersDigest: actionDigest,
        approvalRequest: approval,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
  });

  it('enforces the prior approval policy through every transfer lifecycle stage', async () => {
    const fixture = await buildFixture();
    const actionDigest = digest(106);
    const transferInput = {
      prior: prior(fixture),
      initiator: signer(fixture.firstOwner),
      recipientDeviceCertificate: fixture.recipient.certificate,
      transferIntentId: transferId('transfer-policy-guard'),
      operationId: operationId('operation-transfer'),
      actionParametersDigest: actionDigest,
      originalOwnerDisposition: 'remain-owner' as const,
      createdAt: APPROVED_AT,
      expiresAt: EXPIRES_AT,
    };
    await expect(createOwnershipTransferIntent(transferInput)).rejects.toBeInstanceOf(
      CollaborationAuthorizationWorkflowError,
    );

    const approval = await approvedRequest(fixture, actionDigest);
    const consumed = await resolveApprovalRequest({
      prior: prior(fixture),
      request: approval,
      resolution: 'consumed',
      resolvedAt: PUBLISHED_AT,
    });
    const expired = await resolveApprovalRequest({
      prior: prior(fixture),
      request: approval,
      resolution: 'expired',
      resolvedAt: AFTER_EXPIRY,
    });
    const wrongAction = await approvedRequest(
      fixture,
      actionDigest,
      'change-policy',
      operationId('operation-transfer'),
      approvalId('approval-wrong-action'),
    );
    const wrongDigest = await approvedRequest(
      fixture,
      digest(107),
      'transfer-owner',
      operationId('operation-transfer'),
      approvalId('approval-wrong-digest'),
    );
    const foreignFixture = await buildFixture();
    const foreignApproval = await approvedRequest(foreignFixture, actionDigest);
    const invalidApprovals = [
      consumed,
      expired,
      wrongAction,
      wrongDigest,
      foreignApproval,
    ];
    for (const invalidApproval of invalidApprovals) {
      await expect(
        createOwnershipTransferIntent({
          ...transferInput,
          approvalRequest: invalidApproval,
        }),
      ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    }

    const intent = await createOwnershipTransferIntent({
      ...transferInput,
      approvalRequest: approval,
    });
    await expect(
      acceptOwnershipTransferIntent({
        prior: prior(fixture),
        intent,
        recipient: signer(fixture.recipient),
        acceptedAt: ACCEPTED_AT,
        actionParametersDigest: actionDigest,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    for (const invalidApproval of invalidApprovals) {
      await expect(
        acceptOwnershipTransferIntent({
          prior: prior(fixture),
          intent,
          recipient: signer(fixture.recipient),
          acceptedAt: ACCEPTED_AT,
          actionParametersDigest: actionDigest,
          approvalRequest: invalidApproval,
        }),
      ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    }
    const accepted = await acceptOwnershipTransferIntent({
      prior: prior(fixture),
      intent,
      recipient: signer(fixture.recipient),
      acceptedAt: ACCEPTED_AT,
      actionParametersDigest: actionDigest,
      approvalRequest: approval,
    });
    await expect(
      resolveOwnershipTransferIntent({
        prior: prior(fixture),
        intent: accepted,
        resolution: 'published',
        resolvedAt: PUBLISHED_AT,
        actionParametersDigest: actionDigest,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    const nextMemberships = fixture.manifest.memberships.map((member) =>
      member.principalId === fixture.recipient.certificate.principalId
        ? { ...member, role: 'owner' as const, updatedAt: PUBLISHED_AT }
        : member,
    );
    for (const invalidApproval of invalidApprovals) {
      await expect(
        resolveOwnershipTransferIntent({
          prior: prior(fixture),
          intent: accepted,
          resolution: 'published',
          resolvedAt: PUBLISHED_AT,
          actionParametersDigest: actionDigest,
          approvalRequest: invalidApproval,
          nextMemberships,
        }),
      ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    }

    const noApprovalFixture = await buildFixture('none');
    await expect(
      createOwnershipTransferIntent({
        ...transferInput,
        prior: prior(noApprovalFixture),
        initiator: signer(noApprovalFixture.firstOwner),
        recipientDeviceCertificate: noApprovalFixture.recipient.certificate,
        transferIntentId: transferId('transfer-none-attached'),
        approvalRequest: approval,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    const noApprovalIntent = await createOwnershipTransferIntent({
      ...transferInput,
      prior: prior(noApprovalFixture),
      initiator: signer(noApprovalFixture.firstOwner),
      recipientDeviceCertificate: noApprovalFixture.recipient.certificate,
      transferIntentId: transferId('transfer-none'),
    });
    expect(noApprovalIntent.approvalRequestId).toBeUndefined();
    await expect(
      acceptOwnershipTransferIntent({
        prior: prior(noApprovalFixture),
        intent: noApprovalIntent,
        recipient: signer(noApprovalFixture.recipient),
        acceptedAt: ACCEPTED_AT,
        actionParametersDigest: actionDigest,
        approvalRequest: approval,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    const noApprovalAccepted = await acceptOwnershipTransferIntent({
      prior: prior(noApprovalFixture),
      intent: noApprovalIntent,
      recipient: signer(noApprovalFixture.recipient),
      acceptedAt: ACCEPTED_AT,
      actionParametersDigest: actionDigest,
    });
    await expect(
      resolveOwnershipTransferIntent({
        prior: prior(noApprovalFixture),
        intent: noApprovalAccepted,
        resolution: 'cancelled',
        resolvedAt: PUBLISHED_AT,
        actionParametersDigest: actionDigest,
        approvalRequest: approval,
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
  });

  it('allows only legal cancellation, conflict, and expiry transitions', async () => {
    const fixture = await buildFixture();
    const request = await approvedRequest(fixture);
    for (const resolution of ['cancelled', 'conflicted'] as const) {
      const resolved = await resolveApprovalRequest({
        prior: prior(fixture),
        request,
        resolution,
        resolvedAt: PUBLISHED_AT,
      });
      expect(resolved.state).toBe(resolution);
    }
    const expired = await resolveApprovalRequest({
      prior: prior(fixture),
      request,
      resolution: 'expired',
      resolvedAt: AFTER_EXPIRY,
    });
    expect(expired.state).toBe('expired');

    const noApprovalFixture = await buildFixture('none');
    const intent = await createOwnershipTransferIntent({
      prior: prior(noApprovalFixture),
      initiator: signer(noApprovalFixture.firstOwner),
      recipientDeviceCertificate: noApprovalFixture.recipient.certificate,
      transferIntentId: transferId('transfer-terminal'),
      operationId: operationId('operation-terminal'),
      actionParametersDigest: digest(103),
      originalOwnerDisposition: 'remain-owner',
      createdAt: REQUESTED_AT,
      expiresAt: EXPIRES_AT,
    });
    for (const resolution of ['cancelled', 'conflicted'] as const) {
      const resolved = await resolveOwnershipTransferIntent({
        prior: prior(noApprovalFixture),
        intent,
        resolution,
        resolvedAt: PUBLISHED_AT,
        actionParametersDigest: digest(103),
      });
      expect(resolved.state).toBe(resolution);
    }
    const expiredIntent = await resolveOwnershipTransferIntent({
      prior: prior(noApprovalFixture),
      intent,
      resolution: 'expired',
      resolvedAt: AFTER_EXPIRY,
      actionParametersDigest: digest(103),
    });
    expect(expiredIntent.state).toBe('expired');
  });

  it('copies signing inputs, preserves caller keys, and returns no private material', async () => {
    const fixture = await buildFixture();
    const before = Uint8Array.from(fixture.firstOwner.signing.privateKey);
    const created = await createApprovalRequest({
      prior: prior(fixture),
      requester: signer(fixture.firstOwner),
      operationType: 'change-policy',
      operationId: operationId('operation-secret-lifecycle'),
      approvalRequestId: approvalId('approval-secret-lifecycle'),
      actionParametersDigest: digest(104),
      createdAt: REQUESTED_AT,
      expiresAt: EXPIRES_AT,
      nonce: bytes(16, 105),
    });
    expect(fixture.firstOwner.signing.privateKey).toEqual(before);
    expect(canonicalJson(created)).not.toContain(
      Buffer.from(before).toString('base64url'),
    );

    const wrong = Uint8Array.from(fixture.firstOwner.signing.privateKey);
    wrong[0] = (wrong[0] ?? 0) ^ 0xff;
    await expect(
      createApprovalRequest({
        prior: prior(fixture),
        requester: {
          deviceCertificate: fixture.firstOwner.certificate,
          deviceSigningPrivateKey: wrong,
        },
        operationType: 'change-policy',
        operationId: operationId('operation-wrong-key'),
        approvalRequestId: approvalId('approval-wrong-key'),
        actionParametersDigest: digest(106),
        createdAt: REQUESTED_AT,
        expiresAt: EXPIRES_AT,
        nonce: bytes(16, 107),
      }),
    ).rejects.toBeInstanceOf(CollaborationAuthorizationWorkflowError);
    expect(wrong.some((value) => value !== 0)).toBe(true);
    zeroize(wrong);
    zeroize(before);
  });
});
