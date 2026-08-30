import {
  COLLABORATION_DOMAINS,
  computeAadMetadataDigest,
  computeAuthorityDelegationDigest,
  computeAuthorityRecoveryEnvelopeDigest,
  computeAuthorizationStateDigest,
  computeAuthorizationTransitionDigest,
  computeDeviceRegistryDigest,
  computeDiscoveryRecordDigest,
  computeDiscoveryTag,
  computeEncryptedMembershipDigest,
  computeEncryptedPayloadDigest,
  computeFinalizedMutationLinkDigest,
  computeKeyEnvelopeDigest,
  computeKeyEnvelopeSetDigest,
  computeMembershipHistoryDigest,
  computeMembershipManifestDigest,
  computeMutationHead,
  computeMutationRequestDigest,
  computePolicyDigest,
  computePublicKeyFingerprint,
  decryptCollaborationEnvelope,
  encryptCollaborationEnvelope,
  generateDeviceEncryptionKeyPair,
  generateDeviceSigningKeyPair,
  generatePrincipalSigningKeyPair,
  generateVaultRootKey,
  sealCollaborationVaultRootForDatabaseAuthority,
  sealVaultRootKeyForDevice,
  signAuthorityDelegation,
  signAuthorizationTransitionOwner,
  signCollaborationRecord,
  signDiscoveryRecord,
  signFinalizedMutationLink,
  verifyAuthorizationCheckpoint,
  verifyEnrollmentReceipt,
  zeroize,
  type CollaborationDomain,
  type CollaborationEncryptionKeyPair,
  type CollaborationSignatureField,
  type DeviceSigningKeyPair,
  type PrincipalSigningKeyPair,
  type VaultRootKey,
} from '@kavrix/crypto';
import type * as CollaborationCrypto from '@kavrix/crypto';
import {
  COLLABORATION_GENESIS_HEAD_DIGEST,
  canonicalJson,
  collaborationAadMetadataSchema,
  collaborationAadSchema,
  collaborationAuthorizationCheckpointSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationTransitionSchema,
  collaborationAuthorityDelegationSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationKeyEnvelopeSchema,
  collaborationMutationCommitmentSchema,
  collaborationMutationProofEntrySchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  deviceCertificateSchema,
  enrollmentReceiptSchema,
  membershipHistoryCheckpointSchema,
  membershipHistoryEventSchema,
  membershipHistorySchema,
  publicIdentityExportSchema,
  sha256DigestSchema,
  timestampSchema,
  type CollaborationKeyEnvelope,
  type CollaborationMembership,
  type CollaborativeMembershipManifest,
  type DatabaseAuthorityRecoveryEnvelope,
  type DeviceCertificate,
  type PublicIdentityExport,
  type Sha256Digest,
} from '@kavrix/schemas';
import { afterEach, describe, expect, it, vi } from 'vitest';

const zeroizeSpy = vi.hoisted(() => vi.fn());

vi.mock('@kavrix/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof CollaborationCrypto>();
  return {
    ...actual,
    zeroize(value: Uint8Array | undefined): void {
      actual.zeroize(value);
      zeroizeSpy(value);
    },
  };
});

import {
  CollaborationEnrollmentError,
  buildCollaborationEnrollmentArtifacts,
  type BuildCollaborationEnrollmentArtifactsInput,
} from '../src/collaboration-enrollment.js';
import { buildAdministrativeCollaborativeMutation } from '../src/collaboration-candidate-builder.js';

const DATABASE_ID = 'database-enrollment';
const VAULT_ID = 'vault-enrollment';
const OWNER_ID = 'principal-owner';
const OWNER_DEVICE_ID = 'device-owner';
const RECIPIENT_ID = 'principal-recipient';
const RECIPIENT_DEVICE_ID = 'device-recipient';
const ADDED_DEVICE_ID = 'device-added';
const HISTORICAL_DEVICE_ID = 'device-historical-owner';
const OWNER_MEMBERSHIP_ID = 'membership-owner';
const RECIPIENT_MEMBERSHIP_ID = 'membership-recipient';
const CREATED_AT = timestampSchema.parse('2026-08-29T00:00:00.000Z');
const HISTORICAL_AT = timestampSchema.parse('2026-08-29T00:01:00.000Z');
const DENIED_AT = timestampSchema.parse('2026-08-29T00:03:00.000Z');
const MUTATION_AT = timestampSchema.parse('2026-08-29T00:05:00.000Z');
const RECEIPT_AT = timestampSchema.parse('2026-08-29T00:06:00.000Z');
const NOW = timestampSchema.parse('2026-08-29T00:07:00.000Z');
const EXPIRES_AT = timestampSchema.parse('2026-08-29T00:16:00.000Z');
const PLACEHOLDER_DIGEST = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PLACEHOLDER_SIGNATURE =
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

interface SchemaLike<T> {
  readonly parse: (value: unknown) => T;
}

type Identity = Readonly<{
  root: PrincipalSigningKeyPair;
  signing: DeviceSigningKeyPair;
  encryption: CollaborationEncryptionKeyPair;
  certificate: DeviceCertificate;
  publicIdentity: PublicIdentityExport;
}>;

type Fixture = Readonly<{
  candidate: ReturnType<typeof collaborativeVaultDocumentSchema.parse>;
  proofEntry: ReturnType<typeof collaborationMutationProofEntrySchema.parse>;
  manifest: CollaborativeMembershipManifest;
  owner: Identity;
  recipient: Identity;
  authoritySigning: PrincipalSigningKeyPair;
  authorityRecovery: CollaborationEncryptionKeyPair;
  vaultRootKey: VaultRootKey;
  historicalSigning: DeviceSigningKeyPair;
  historicalEncryption: CollaborationEncryptionKeyPair;
}>;

const fixtures: Fixture[] = [];

afterEach(() => {
  for (const fixture of fixtures.splice(0)) {
    for (const bytes of [
      fixture.owner.root.privateKey,
      fixture.owner.signing.privateKey,
      fixture.owner.encryption.privateKey,
      fixture.recipient.root.privateKey,
      fixture.recipient.signing.privateKey,
      fixture.recipient.encryption.privateKey,
      fixture.authoritySigning.privateKey,
      fixture.authorityRecovery.privateKey,
      fixture.vaultRootKey,
      fixture.historicalSigning.privateKey,
      fixture.historicalEncryption.privateKey,
    ]) {
      zeroize(bytes);
    }
  }
});

function digest(fill: number): Sha256Digest {
  return sha256DigestSchema.parse(Buffer.alloc(32, fill).toString('base64url'));
}

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
  const publicIdentity = await signedRecord(
    COLLABORATION_DOMAINS.publicIdentitySignature,
    {
      format: 'kavrix-collaborative-public-identity',
      protocolVersion: 1,
      principalId,
      identityGeneration: 1,
      rootSigningPublicKey: root.publicKeyBase64,
      devices: [certificate],
      createdAt: CREATED_AT,
      selfSignature: PLACEHOLDER_SIGNATURE,
    },
    publicIdentityExportSchema,
    'selfSignature',
    root.privateKey,
  );
  return { root, signing, encryption, certificate, publicIdentity };
}

function membership(
  keys: Identity,
  membershipId: string,
  role: CollaborationMembership['role'],
  additionalDevices: readonly DeviceCertificate[] = [],
): CollaborationMembership {
  return collaborativeMembershipManifestSchema.shape.memberships.element.parse({
    membershipId,
    principalId: keys.certificate.principalId,
    principalFingerprint: computePublicKeyFingerprint(
      keys.root.publicKeyBase64,
      'ed25519',
    ),
    rootSigningPublicKey: keys.root.publicKeyBase64,
    identityGeneration: 1,
    role,
    state: 'active',
    devices: [keys.certificate, ...additionalDevices],
    createdAt: CREATED_AT,
    updatedAt: MUTATION_AT,
  });
}

async function memberEnvelope(
  vaultRootKey: VaultRootKey,
  member: CollaborationMembership,
  recipient: Identity,
  owner: Identity,
  registryDigest: Sha256Digest,
): Promise<CollaborationKeyEnvelope> {
  const base = collaborationKeyEnvelopeSchema.parse({
    format: 'kavrix-collaborative-member-key-envelope',
    protocolVersion: 1,
    algorithm: 'x25519-sealed-box',
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    membershipId: member.membershipId,
    principalId: member.principalId,
    deviceId: recipient.certificate.deviceId,
    recipientEncryptionKeyFingerprint: computePublicKeyFingerprint(
      recipient.encryption.publicKeyBase64,
      'x25519',
    ),
    keyEpoch: 1,
    membershipRevision: 2,
    databaseDeviceGeneration: 2,
    databaseDeviceRegistryDigest: registryDigest,
    sealedVaultRootKey: await sealVaultRootKeyForDevice(
      vaultRootKey,
      recipient.encryption.publicKeyBase64,
    ),
    envelopeDigest: PLACEHOLDER_DIGEST,
    createdAt: MUTATION_AT,
    ownerSignature: PLACEHOLDER_SIGNATURE,
  });
  const withDigest = collaborationKeyEnvelopeSchema.parse({
    ...base,
    envelopeDigest: computeKeyEnvelopeDigest(base),
  });
  return signedRecord(
    COLLABORATION_DOMAINS.keyEnvelopeSignature,
    withDigest,
    collaborationKeyEnvelopeSchema,
    'ownerSignature',
    owner.signing.privateKey,
  );
}

async function recoveryEnvelope(
  vaultRootKey: VaultRootKey,
  recovery: CollaborationEncryptionKeyPair,
  owner: Identity,
  registryDigest: Sha256Digest,
): Promise<DatabaseAuthorityRecoveryEnvelope> {
  const base = databaseAuthorityRecoveryEnvelopeSchema.parse({
    format: 'kavrix-collaborative-authority-recovery-envelope',
    protocolVersion: 1,
    algorithm: 'x25519-sealed-box',
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    authorityRecoveryKeyFingerprint: computePublicKeyFingerprint(
      recovery.publicKeyBase64,
      'x25519',
    ),
    keyEpoch: 1,
    membershipRevision: 2,
    databaseDeviceGeneration: 2,
    databaseDeviceRegistryDigest: registryDigest,
    sealedVaultRootKey: await sealCollaborationVaultRootForDatabaseAuthority(
      vaultRootKey,
      recovery.publicKeyBase64,
    ),
    envelopeDigest: PLACEHOLDER_DIGEST,
    sealedByPrincipalId: OWNER_ID,
    sealedByDeviceId: OWNER_DEVICE_ID,
    createdAt: MUTATION_AT,
    ownerSignature: PLACEHOLDER_SIGNATURE,
  });
  const withDigest = databaseAuthorityRecoveryEnvelopeSchema.parse({
    ...base,
    envelopeDigest: computeAuthorityRecoveryEnvelopeDigest(base),
  });
  return signedRecord(
    COLLABORATION_DOMAINS.keyEnvelopeSignature,
    withDigest,
    databaseAuthorityRecoveryEnvelopeSchema,
    'ownerSignature',
    owner.signing.privateKey,
  );
}

function authorizationCore(
  memberships: readonly CollaborationMembership[],
  envelopes: readonly CollaborativeMembershipManifest['keyEnvelopes'][number][],
  registryDigest: Sha256Digest,
): ReturnType<typeof collaborationAuthorizationStateCoreSchema.parse> {
  return collaborationAuthorizationStateCoreSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    databaseDeviceGeneration: 2,
    databaseDeviceRegistryDigest: registryDigest,
    membershipRevision: 2,
    policyRevision: 1,
    keyEpoch: 1,
    memberships: memberships.map((value) => ({
      membershipId: value.membershipId,
      principalId: value.principalId,
      principalFingerprint: value.principalFingerprint,
      rootSigningPublicKey: value.rootSigningPublicKey,
      identityGeneration: value.identityGeneration,
      role: value.role,
      state: value.state,
      devices: value.devices.map((device) => {
        const core = { ...device };
        Reflect.deleteProperty(core, 'rootSignature');
        return core;
      }),
      createdAt: value.createdAt,
      updatedAt: value.updatedAt,
    })),
    ownerPrincipalIds: [OWNER_ID],
    keyEnvelopes: envelopes.map((envelope) => {
      const core = { ...envelope };
      Reflect.deleteProperty(core, 'envelopeDigest');
      Reflect.deleteProperty(core, 'createdAt');
      Reflect.deleteProperty(core, 'ownerSignature');
      return core;
    }),
    approvalPolicy: 'none',
  });
}

async function buildFixture(
  options: Readonly<{
    denyCurrentOwnerByIdentity?: boolean;
    denyCurrentOwnerByFingerprint?: boolean;
    sameDeviceIdUnderOtherPrincipal?: boolean;
    substituteCheckpointSigner?: boolean;
  }> = {},
): Promise<Fixture> {
  const authoritySigning = await generatePrincipalSigningKeyPair();
  const authorityRecovery = await generateDeviceEncryptionKeyPair();
  const owner = await identity(OWNER_ID, OWNER_DEVICE_ID);
  const recipient = await identity(RECIPIENT_ID, RECIPIENT_DEVICE_ID);
  const historicalSigning = await generateDeviceSigningKeyPair();
  const historicalEncryption = await generateDeviceEncryptionKeyPair();
  const historicalCertificate = await signedRecord(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    {
      protocolVersion: 1,
      principalId: OWNER_ID,
      deviceId: HISTORICAL_DEVICE_ID,
      deviceGeneration: 1,
      signingPublicKey: historicalSigning.publicKeyBase64,
      encryptionPublicKey: historicalEncryption.publicKeyBase64,
      state: 'revoked',
      createdAt: CREATED_AT,
      stateChangedAt: DENIED_AT,
      revokedAt: DENIED_AT,
      rootSignature: PLACEHOLDER_SIGNATURE,
    },
    deviceCertificateSchema,
    'rootSignature',
    owner.root.privateKey,
  );
  const vaultRootKey = generateVaultRootKey();
  const priorRegistryBase = collaborationDatabaseDeviceRegistrySchema.parse({
    format: 'kavrix-collaborative-device-registry',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    authorityEpoch: 1,
    authorityFingerprint: computePublicKeyFingerprint(
      authoritySigning.publicKeyBase64,
      'ed25519',
    ),
    generation: 1,
    previousRegistryDigest: digest(2),
    registryDigest: PLACEHOLDER_DIGEST,
    deniedDevices: [],
    updatedAt: HISTORICAL_AT,
    authoritySignature: PLACEHOLDER_SIGNATURE,
  });
  const priorRegistryWithDigest = collaborationDatabaseDeviceRegistrySchema.parse({
    ...priorRegistryBase,
    registryDigest: computeDeviceRegistryDigest(priorRegistryBase),
  });
  const priorRegistry = await signedRecord(
    COLLABORATION_DOMAINS.deviceRegistrySignature,
    priorRegistryWithDigest,
    collaborationDatabaseDeviceRegistrySchema,
    'authoritySignature',
    authoritySigning.privateKey,
  );
  const deniedDevices = [
    {
      principalId: OWNER_ID,
      deviceId: HISTORICAL_DEVICE_ID,
      deviceGeneration: 1,
      signingKeyFingerprint: computePublicKeyFingerprint(
        historicalSigning.publicKeyBase64,
        'ed25519',
      ),
      reason: 'revoked' as const,
      deniedAt: DENIED_AT,
    },
    ...(options.denyCurrentOwnerByIdentity === true
      ? [
          {
            principalId: OWNER_ID,
            deviceId: OWNER_DEVICE_ID,
            deviceGeneration: 1,
            signingKeyFingerprint: digest(30),
            reason: 'revoked' as const,
            deniedAt: DENIED_AT,
          },
        ]
      : []),
    ...(options.denyCurrentOwnerByFingerprint === true
      ? [
          {
            principalId: RECIPIENT_ID,
            deviceId: 'device-signing-key-alias',
            deviceGeneration: 1,
            signingKeyFingerprint: computePublicKeyFingerprint(
              owner.signing.publicKeyBase64,
              'ed25519',
            ),
            reason: 'revoked' as const,
            deniedAt: DENIED_AT,
          },
        ]
      : []),
    ...(options.sameDeviceIdUnderOtherPrincipal === true
      ? [
          {
            principalId: RECIPIENT_ID,
            deviceId: OWNER_DEVICE_ID,
            deviceGeneration: 1,
            signingKeyFingerprint: digest(31),
            reason: 'revoked' as const,
            deniedAt: DENIED_AT,
          },
        ]
      : []),
  ];
  const registryBase = collaborationDatabaseDeviceRegistrySchema.parse({
    ...priorRegistry,
    generation: 2,
    previousRegistryDigest: priorRegistry.registryDigest,
    registryDigest: PLACEHOLDER_DIGEST,
    deniedDevices,
    updatedAt: DENIED_AT,
    authoritySignature: PLACEHOLDER_SIGNATURE,
  });
  const registryWithDigest = collaborationDatabaseDeviceRegistrySchema.parse({
    ...registryBase,
    registryDigest: computeDeviceRegistryDigest(registryBase),
  });
  const registry = await signedRecord(
    COLLABORATION_DOMAINS.deviceRegistrySignature,
    registryWithDigest,
    collaborationDatabaseDeviceRegistrySchema,
    'authoritySignature',
    authoritySigning.privateKey,
  );

  const ownerMembership = membership(owner, OWNER_MEMBERSHIP_ID, 'owner', [
    historicalCertificate,
  ]);
  const recipientMembership = membership(recipient, RECIPIENT_MEMBERSHIP_ID, 'reader');
  const memberships = [ownerMembership, recipientMembership] as const;
  const envelopes = [
    await memberEnvelope(
      vaultRootKey,
      ownerMembership,
      owner,
      owner,
      registry.registryDigest,
    ),
    await memberEnvelope(
      vaultRootKey,
      recipientMembership,
      recipient,
      owner,
      registry.registryDigest,
    ),
    await recoveryEnvelope(
      vaultRootKey,
      authorityRecovery,
      owner,
      registry.registryDigest,
    ),
  ] as const;
  const authorizationStateDigest = computeAuthorizationStateDigest(
    authorizationCore(memberships, envelopes, registry.registryDigest),
  );
  const previousTuple = collaborationRevisionTupleSchema.parse({
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: priorRegistry.registryDigest,
    authorizationStateDigest: digest(3),
  });
  const tuple = collaborationRevisionTupleSchema.parse({
    ...previousTuple,
    documentRevision: 2,
    membershipRevision: 2,
    databaseDeviceGeneration: 2,
    databaseDeviceRegistryDigest: registry.registryDigest,
    authorizationStateDigest,
  });
  const previousHeadDigest = digest(7);
  const historicalEvent = await signedRecord(
    COLLABORATION_DOMAINS.membershipHistorySignature,
    {
      protocolVersion: 1,
      operationId: 'operation-historical-owner-write',
      eventType: 'key-rotated',
      actorPrincipalId: OWNER_ID,
      actorDeviceId: HISTORICAL_DEVICE_ID,
      previousDocumentRevision: 0,
      newDocumentRevision: 1,
      previousMembershipRevision: 0,
      newMembershipRevision: 1,
      previousPolicyRevision: 0,
      newPolicyRevision: 1,
      previousKeyEpoch: 1,
      newKeyEpoch: 1,
      previousAuthorityEpoch: 1,
      newAuthorityEpoch: 1,
      previousDatabaseDeviceGeneration: 1,
      newDatabaseDeviceGeneration: 1,
      previousDatabaseDeviceRegistryDigest: priorRegistry.registryDigest,
      newDatabaseDeviceRegistryDigest: priorRegistry.registryDigest,
      previousAuthorizationStateDigest: digest(8),
      newAuthorizationStateDigest: previousTuple.authorizationStateDigest,
      previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
      timestamp: HISTORICAL_AT,
      signature: PLACEHOLDER_SIGNATURE,
    },
    membershipHistoryEventSchema,
    'signature',
    historicalSigning.privateKey,
  );
  const historicalCheckpoint = await signedRecord(
    COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
    {
      protocolVersion: 1,
      checkpointId: 'checkpoint-historical-owner',
      authorityEpoch: 1,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: priorRegistry.registryDigest,
      membershipRevision: 1,
      documentRevision: 1,
      policyRevision: 1,
      keyEpoch: 1,
      previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
      compactedThroughRevision: 1,
      compactedHistoryDigest: digest(9),
      signerPrincipalId: OWNER_ID,
      signerDeviceId:
        options.substituteCheckpointSigner === true
          ? OWNER_DEVICE_ID
          : HISTORICAL_DEVICE_ID,
      createdAt: HISTORICAL_AT,
      signature: PLACEHOLDER_SIGNATURE,
    },
    membershipHistoryCheckpointSchema,
    'signature',
    historicalSigning.privateKey,
  );
  const historyEvent = await signedRecord(
    COLLABORATION_DOMAINS.membershipHistorySignature,
    {
      protocolVersion: 1,
      operationId: 'operation-add-member',
      eventType: 'member-added',
      actorPrincipalId: OWNER_ID,
      actorDeviceId: OWNER_DEVICE_ID,
      targetPrincipalId: RECIPIENT_ID,
      previousDocumentRevision: 1,
      newDocumentRevision: 2,
      previousMembershipRevision: 1,
      newMembershipRevision: 2,
      previousPolicyRevision: 1,
      newPolicyRevision: 1,
      previousKeyEpoch: 1,
      newKeyEpoch: 1,
      previousAuthorityEpoch: 1,
      newAuthorityEpoch: 1,
      previousDatabaseDeviceGeneration: 1,
      newDatabaseDeviceGeneration: 2,
      previousDatabaseDeviceRegistryDigest: priorRegistry.registryDigest,
      newDatabaseDeviceRegistryDigest: registry.registryDigest,
      previousAuthorizationStateDigest: previousTuple.authorizationStateDigest,
      newAuthorizationStateDigest: tuple.authorizationStateDigest,
      previousHeadDigest,
      timestamp: MUTATION_AT,
      signature: PLACEHOLDER_SIGNATURE,
    },
    membershipHistoryEventSchema,
    'signature',
    owner.signing.privateKey,
  );
  const historyBase = membershipHistorySchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    databaseDeviceGeneration: 2,
    databaseDeviceRegistryDigest: registry.registryDigest,
    events: [historicalEvent, historyEvent],
    checkpoints: [historicalCheckpoint],
    compactedThroughRevision: 0,
    compactedHistoryDigest: digest(4),
    previousHeadDigest,
    previousHistoryDigest: digest(5),
    currentHistoryDigest: PLACEHOLDER_DIGEST,
  });
  const history = membershipHistorySchema.parse({
    ...historyBase,
    currentHistoryDigest: computeMembershipHistoryDigest(historyBase),
  });
  const policyBase = collaborationPolicyStateSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    policyRevision: 1,
    approvalPolicy: 'none',
    policyDigest: PLACEHOLDER_DIGEST,
    databaseDeviceGeneration: 2,
    databaseDeviceRegistryDigest: registry.registryDigest,
    changedByPrincipalId: OWNER_ID,
    changedByDeviceId: OWNER_DEVICE_ID,
    changedAt: MUTATION_AT,
    signature: PLACEHOLDER_SIGNATURE,
  });
  const policyWithDigest = collaborationPolicyStateSchema.parse({
    ...policyBase,
    policyDigest: computePolicyDigest(policyBase),
  });
  const policy = await signedRecord(
    COLLABORATION_DOMAINS.policySignature,
    policyWithDigest,
    collaborationPolicyStateSchema,
    'signature',
    owner.signing.privateKey,
  );
  const manifestBase = collaborativeMembershipManifestSchema.parse({
    format: 'kavrix-collaborative-membership-manifest',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    databaseDeviceGeneration: 2,
    databaseDeviceRegistryDigest: registry.registryDigest,
    documentRevision: 2,
    membershipRevision: 2,
    policyRevision: 1,
    keyEpoch: 1,
    authorizationStateDigest,
    memberships,
    ownerPrincipalIds: [OWNER_ID],
    keyEnvelopes: envelopes,
    approvalPolicy: 'none',
    policy,
    pendingApprovals: [],
    pendingTransfers: [],
    history,
    previousMembershipDigest: digest(6),
    membershipDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest,
    createdAt: CREATED_AT,
    updatedAt: MUTATION_AT,
  });
  const manifest = collaborativeMembershipManifestSchema.parse({
    ...manifestBase,
    membershipDigest: computeMembershipManifestDigest(manifestBase),
  });
  const aad = (
    entityType: 'vault-payload' | 'membership-manifest',
  ): ReturnType<typeof collaborationAadSchema.parse> => {
    const metadata = collaborationAadMetadataSchema.parse({
      protocolVersion: 1,
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      ...tuple,
      entityType,
      entityId: VAULT_ID,
    });
    return collaborationAadSchema.parse({
      ...metadata,
      metadataDigest: computeAadMetadataDigest(metadata),
    });
  };
  const encryptedPayload = await encryptCollaborationEnvelope(
    Uint8Array.from([1, 2, 3]),
    vaultRootKey,
    aad('vault-payload'),
  );
  const manifestBytes = new TextEncoder().encode(canonicalJson(manifest));
  const encryptedMembershipManifest = await encryptCollaborationEnvelope(
    manifestBytes,
    vaultRootKey,
    aad('membership-manifest'),
  );
  zeroize(manifestBytes);
  const encryptedMembershipDigest = computeEncryptedMembershipDigest(
    encryptedMembershipManifest,
  );
  const discoveryRecords = await Promise.all(
    memberships.map(async (member, index) => {
      const envelope = envelopes[index];
      if (envelope === undefined || !('membershipId' in envelope)) {
        throw new Error('Invalid test envelope');
      }
      const base = collaborationDiscoveryRecordSchema.parse({
        format: 'kavrix-collaborative-discovery-record',
        protocolVersion: 1,
        databaseId: DATABASE_ID,
        vaultId: VAULT_ID,
        authorityEpoch: 1,
        databaseDeviceGeneration: 2,
        databaseDeviceRegistryDigest: registry.registryDigest,
        discoveryTag: computeDiscoveryTag(DATABASE_ID, member.principalFingerprint),
        membershipId: member.membershipId,
        membershipState: 'active',
        keyEpoch: 1,
        membershipRevision: 2,
        authorizationStateDigest,
        encryptedMemberKeyEnvelope: envelope,
        encryptedMembershipMetadataDigest: encryptedMembershipDigest,
        discoveryRecordDigest: PLACEHOLDER_DIGEST,
        signerPrincipalId: OWNER_ID,
        signerDeviceId: OWNER_DEVICE_ID,
        writerSignature: PLACEHOLDER_SIGNATURE,
        createdAt: MUTATION_AT,
        updatedAt: MUTATION_AT,
      });
      const withDigest = collaborationDiscoveryRecordSchema.parse({
        ...base,
        discoveryRecordDigest: computeDiscoveryRecordDigest(base),
      });
      return collaborationDiscoveryRecordSchema.parse({
        ...withDigest,
        writerSignature: await signDiscoveryRecord(
          withDigest,
          owner.signing.privateKey,
        ),
      });
    }),
  );
  const transitionBase = collaborationAuthorizationTransitionSchema.parse({
    format: 'kavrix-collaborative-authorization-transition',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: 'operation-add-member',
    operationType: 'add-member',
    previousHeadDigest,
    previousAuthorizationStateDigest: previousTuple.authorizationStateDigest,
    authorizationStateDigest,
    previousTuple,
    nextTuple: tuple,
    evidence: { kind: 'none' },
    issuedAt: MUTATION_AT,
    expiresAt: EXPIRES_AT,
    transitionDigest: PLACEHOLDER_DIGEST,
    transitionSignature: {
      signerKind: 'owner-device',
      signerPrincipalId: OWNER_ID,
      signerDeviceId: OWNER_DEVICE_ID,
      signature: PLACEHOLDER_SIGNATURE,
    },
  });
  const transitionWithDigest = collaborationAuthorizationTransitionSchema.parse({
    ...transitionBase,
    transitionDigest: computeAuthorizationTransitionDigest(transitionBase),
  });
  const transition = collaborationAuthorizationTransitionSchema.parse({
    ...transitionWithDigest,
    transitionSignature: {
      ...transitionWithDigest.transitionSignature,
      signature: await signAuthorizationTransitionOwner(
        transitionWithDigest,
        owner.signing.privateKey,
      ),
    },
  });
  const commitmentBase = collaborationMutationCommitmentSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: 'operation-add-member',
    operationType: 'add-member',
    requestDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest,
    previousAuthorizationStateDigest: previousTuple.authorizationStateDigest,
    authorizationStateDigest,
    authorizationTransitionDigest: transition.transitionDigest,
    previousAuthorityEpoch: 1,
    previousDocumentRevision: 1,
    previousMembershipRevision: 1,
    previousPolicyRevision: 1,
    previousKeyEpoch: 1,
    previousDatabaseDeviceGeneration: 1,
    previousDatabaseDeviceRegistryDigest: priorRegistry.registryDigest,
    authorityEpoch: 1,
    documentRevision: 2,
    membershipRevision: 2,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 2,
    databaseDeviceRegistryDigest: registry.registryDigest,
    encryptedPayloadDigest: computeEncryptedPayloadDigest(encryptedPayload),
    encryptedMembershipDigest,
    encryptedEnvelopesDigest: computeKeyEnvelopeSetDigest(envelopes),
    policyDigest: policy.policyDigest,
    writerPrincipalId: OWNER_ID,
    writerDeviceId: OWNER_DEVICE_ID,
    timestamp: MUTATION_AT,
    expiresAt: EXPIRES_AT,
  });
  const commitment = collaborationMutationCommitmentSchema.parse({
    ...commitmentBase,
    requestDigest: computeMutationRequestDigest(commitmentBase),
  });
  const headDigest = computeMutationHead(commitment);
  const genesisTuple = collaborationRevisionTupleSchema.parse({
    ...previousTuple,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
  });
  const delegationBase = collaborationAuthorityDelegationSchema.parse({
    format: 'kavrix-collaborative-authority-delegation',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    authoritySigningPublicKey: authoritySigning.publicKeyBase64,
    authoritySigningKeyFingerprint: computePublicKeyFingerprint(
      authoritySigning.publicKeyBase64,
      'ed25519',
    ),
    authorityRecoveryPublicKey: authorityRecovery.publicKeyBase64,
    authorityRecoveryKeyFingerprint: computePublicKeyFingerprint(
      authorityRecovery.publicKeyBase64,
      'x25519',
    ),
    genesisOperationId: 'operation-genesis',
    genesisTuple,
    genesisHeadDigest: previousHeadDigest,
    initialAuthorizationStateDigest: genesisTuple.authorizationStateDigest,
    initialOwnerPrincipalId: OWNER_ID,
    initialOwnerRootKeyFingerprint: ownerMembership.principalFingerprint,
    initialOwnerDeviceId: OWNER_DEVICE_ID,
    initialOwnerDeviceSigningKeyFingerprint: computePublicKeyFingerprint(
      owner.signing.publicKeyBase64,
      'ed25519',
    ),
    initialOwnerDeviceEncryptionKeyFingerprint: computePublicKeyFingerprint(
      owner.encryption.publicKeyBase64,
      'x25519',
    ),
    issuedAt: CREATED_AT,
    authoritySignature: PLACEHOLDER_SIGNATURE,
  });
  const delegation = collaborationAuthorityDelegationSchema.parse({
    ...delegationBase,
    authoritySignature: await signAuthorityDelegation(
      delegationBase,
      authoritySigning.privateKey,
    ),
  });
  const authorityDelegationDigest = computeAuthorityDelegationDigest(delegation);
  const linkBase = collaborationFinalizedMutationLinkSchema.parse({
    format: 'kavrix-collaborative-finalized-mutation-link',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityDelegationDigest,
    commitment,
    authorizationTransition: transition,
    resultingHeadDigest: headDigest,
    writerSignature: {
      algorithm: 'ed25519',
      writerPrincipalId: OWNER_ID,
      writerDeviceId: OWNER_DEVICE_ID,
      commitmentDigest: headDigest,
      signature: PLACEHOLDER_SIGNATURE,
    },
    finalizedAt: MUTATION_AT,
  });
  const link = collaborationFinalizedMutationLinkSchema.parse({
    ...linkBase,
    writerSignature: {
      ...linkBase.writerSignature,
      signature: await signFinalizedMutationLink(linkBase, owner.signing.privateKey),
    },
  });
  const candidate = collaborativeVaultDocumentSchema.parse({
    format: 'kavrix-collaborative-vault',
    documentVersion: 1,
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    ...tuple,
    previousHeadDigest,
    headDigest,
    authorityDelegation: delegation,
    authorityDelegationDigest,
    encryptedPayloadDigest: commitment.encryptedPayloadDigest,
    encryptedMembershipDigest,
    encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
    policyDigest: commitment.policyDigest,
    databaseAuthorityRecoveryEnvelope: manifest.keyEnvelopes.find(
      (envelope) => !('membershipId' in envelope),
    ),
    encryptedPayload,
    encryptedMembershipManifest,
    discoveryRecords,
    currentMutationLink: link,
    createdAt: CREATED_AT,
    updatedAt: MUTATION_AT,
  });
  const proofEntry = collaborationMutationProofEntrySchema.parse({
    link,
    authorizationWitness: {
      format: 'kavrix-collaborative-authorization-witness',
      protocolVersion: 1,
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      authorityDelegationDigest,
      tuple,
      previousHeadDigest,
      headDigest,
      encryptedMembershipDigest,
      encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
      policyDigest: commitment.policyDigest,
      databaseDeviceRegistry: registry,
      databaseAuthorityRecoveryEnvelope: candidate.databaseAuthorityRecoveryEnvelope,
      encryptedMembershipManifest,
      discoveryRecords,
      finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(link),
    },
  });
  const fixture = {
    candidate,
    proofEntry,
    manifest,
    owner,
    recipient,
    authoritySigning,
    authorityRecovery,
    vaultRootKey,
    historicalSigning,
    historicalEncryption,
  };
  fixtures.push(fixture);
  return fixture;
}

function validInput(fixture: Fixture): BuildCollaborationEnrollmentArtifactsInput {
  return {
    candidate: fixture.candidate,
    proofEntry: fixture.proofEntry,
    resultingManifest: fixture.manifest,
    ownerPublicIdentity: fixture.owner.publicIdentity,
    ownerPrincipalId: OWNER_ID,
    ownerDeviceId: OWNER_DEVICE_ID,
    recipientPublicIdentity: fixture.recipient.publicIdentity,
    recipientDeviceId: RECIPIENT_DEVICE_ID,
    ownerDeviceSigningPrivateKey: fixture.owner.signing.privateKey,
    checkpointId: 'checkpoint-enrollment',
    issuedAt: RECEIPT_AT,
    expiresAt: EXPIRES_AT,
    now: NOW,
  } as const;
}

type AddDeviceFixture = Readonly<{
  prepared: Awaited<ReturnType<typeof buildAdministrativeCollaborativeMutation>>;
  manifest: CollaborativeMembershipManifest;
  publicIdentity: PublicIdentityExport;
  signing: DeviceSigningKeyPair;
  encryption: CollaborationEncryptionKeyPair;
  target: Identity;
}>;

async function buildAddDeviceFixture(
  fixture: Fixture,
  targetKind: 'recipient' | 'owner',
): Promise<AddDeviceFixture> {
  const target = targetKind === 'recipient' ? fixture.recipient : fixture.owner;
  const priorWitness = fixture.proofEntry.authorizationWitness;
  if (priorWitness === undefined) {
    throw new Error('Missing authorization witness');
  }
  const signing = await generateDeviceSigningKeyPair();
  const encryption = await generateDeviceEncryptionKeyPair();
  const certificate = await signedRecord(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    {
      protocolVersion: 1,
      principalId: target.certificate.principalId,
      deviceId: ADDED_DEVICE_ID,
      deviceGeneration: 1,
      signingPublicKey: signing.publicKeyBase64,
      encryptionPublicKey: encryption.publicKeyBase64,
      state: 'active',
      createdAt: RECEIPT_AT,
      stateChangedAt: RECEIPT_AT,
      rootSignature: PLACEHOLDER_SIGNATURE,
    },
    deviceCertificateSchema,
    'rootSignature',
    target.root.privateKey,
  );
  const publicIdentity = await signedRecord(
    COLLABORATION_DOMAINS.publicIdentitySignature,
    {
      ...target.publicIdentity,
      identityGeneration: target.publicIdentity.identityGeneration + 1,
      devices: [...target.publicIdentity.devices, certificate],
      selfSignature: PLACEHOLDER_SIGNATURE,
    },
    publicIdentityExportSchema,
    'selfSignature',
    target.root.privateKey,
  );
  const targetIndex = fixture.manifest.memberships.findIndex(
    (membershipValue) => membershipValue.principalId === target.certificate.principalId,
  );
  const priorMembership = fixture.manifest.memberships[targetIndex];
  if (targetIndex < 0 || priorMembership === undefined) {
    throw new Error('Missing add-device target membership');
  }
  const nextMembership =
    collaborativeMembershipManifestSchema.shape.memberships.element.parse({
      ...priorMembership,
      identityGeneration: priorMembership.identityGeneration + 1,
      devices: [...priorMembership.devices, certificate],
      updatedAt: RECEIPT_AT,
    });
  const memberships = fixture.manifest.memberships.map((membershipValue, index) =>
    index === targetIndex ? nextMembership : membershipValue,
  );
  const prepared = await buildAdministrativeCollaborativeMutation({
    prior: {
      document: fixture.candidate,
      manifest: fixture.manifest,
      deviceRegistry: priorWitness.databaseDeviceRegistry,
      currentVaultRootKey: fixture.vaultRootKey,
      quarantinedVaultPayload: Uint8Array.from([1, 2, 3]),
    },
    authoritativeDeviceRegistry: priorWitness.databaseDeviceRegistry,
    actor: {
      principalId: fixture.owner.certificate.principalId,
      deviceId: fixture.owner.certificate.deviceId,
      rootSigningPublicKey: fixture.owner.root.publicKeyBase64,
      deviceCertificate: fixture.owner.certificate,
      deviceSigningPrivateKey: fixture.owner.signing.privateKey,
    },
    authorityRecoveryPublicKey: fixture.authorityRecovery.publicKeyBase64,
    operationId:
      collaborationMutationCommitmentSchema.shape.operationId.parse(
        'operation-add-device',
      ),
    timestamp: RECEIPT_AT,
    expiresAt: EXPIRES_AT,
    anchorScope: {
      databaseId: fixture.candidate.databaseId,
      vaultId: fixture.candidate.vaultId,
      principalId: fixture.owner.certificate.principalId,
      deviceId: fixture.owner.certificate.deviceId,
    },
    operationType: 'add-device',
    next: {
      memberships,
      ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
      approvalPolicy: fixture.manifest.approvalPolicy,
      historyEvent: {
        eventType: 'device-added',
        targetPrincipalId: target.certificate.principalId,
        targetDeviceId: certificate.deviceId,
      },
    },
    decryptAccessChanged: true,
  });
  const nextVaultRootKey = prepared.nextVaultRootKey;
  if (nextVaultRootKey === undefined) throw new Error('Missing rotated key');
  const plaintext = await decryptCollaborationEnvelope(
    prepared.candidate.encryptedMembershipManifest,
    nextVaultRootKey,
    prepared.candidate.encryptedMembershipManifest.aad,
  );
  try {
    const manifest = collaborativeMembershipManifestSchema.parse(
      JSON.parse(Buffer.from(plaintext).toString('utf8')),
    );
    return { prepared, manifest, publicIdentity, signing, encryption, target };
  } finally {
    zeroize(plaintext);
  }
}

describe('collaboration enrollment artifacts', () => {
  it('accepts historical signatures predating a canonical registry denial', async () => {
    const fixture = await buildFixture();
    const privateKeyBefore = Uint8Array.from(fixture.owner.signing.privateKey);
    zeroizeSpy.mockClear();
    const artifacts = await buildCollaborationEnrollmentArtifacts(validInput(fixture));

    expect(
      collaborationAuthorizationCheckpointSchema.parse(artifacts.checkpoint),
    ).toStrictEqual(artifacts.checkpoint);
    expect(enrollmentReceiptSchema.parse(artifacts.receipt)).toStrictEqual(
      artifacts.receipt,
    );
    expect(
      await verifyAuthorizationCheckpoint(
        artifacts.checkpoint,
        fixture.owner.signing.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyEnrollmentReceipt(
        artifacts.receipt,
        fixture.owner.signing.publicKeyBase64,
      ),
    ).toBe(true);
    expect(artifacts.receipt.recipientDeviceId).toBe(RECIPIENT_DEVICE_ID);
    expect(artifacts.receipt.membershipId).toBe(RECIPIENT_MEMBERSHIP_ID);
    expect(artifacts.receipt.role).toBe('reader');
    expect(
      fixture.proofEntry.authorizationWitness?.databaseDeviceRegistry.generation,
    ).toBe(2);
    expect(
      fixture.proofEntry.authorizationWitness?.databaseDeviceRegistry.deniedDevices,
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ deviceId: HISTORICAL_DEVICE_ID }),
      ]),
    );
    expect(fixture.manifest.history.checkpoints[0]).toMatchObject({
      signerPrincipalId: OWNER_ID,
      signerDeviceId: HISTORICAL_DEVICE_ID,
    });
    expect(Object.isFrozen(artifacts)).toBe(true);
    expect(Object.isFrozen(artifacts.receipt.recipientPublicIdentity)).toBe(true);
    expect(fixture.owner.signing.privateKey).toEqual(privateKeyBefore);
    expect(zeroizeSpy).toHaveBeenCalledTimes(1);
    const wipedCopy = zeroizeSpy.mock.calls[0]?.[0] as Uint8Array | undefined;
    expect(wipedCopy).toBeInstanceOf(Uint8Array);
    expect(wipedCopy).not.toBe(fixture.owner.signing.privateKey);
    expect(wipedCopy).toEqual(new Uint8Array(64));
    for (const substituted of [
      { ...artifacts.receipt, vaultId: 'vault-substituted' },
      { ...artifacts.receipt, role: 'editor' },
      { ...artifacts.receipt, membershipId: 'membership-substituted' },
      { ...artifacts.receipt, discoveryRecordDigest: digest(20) },
      { ...artifacts.receipt, memberKeyEnvelopeDigest: digest(21) },
      { ...artifacts.receipt, headDigest: digest(22) },
      { ...artifacts.receipt, finalizedMutationLinkDigest: digest(23) },
      { ...artifacts.receipt, authorizationCheckpointDigest: digest(24) },
    ]) {
      expect(
        await verifyEnrollmentReceipt(
          substituted,
          fixture.owner.signing.publicKeyBase64,
        ),
      ).toBe(false);
    }
    expect(
      await verifyAuthorizationCheckpoint(
        { ...artifacts.checkpoint, checkpointDigest: digest(25) },
        fixture.owner.signing.publicKeyBase64,
      ),
    ).toBe(false);
    zeroize(privateKeyBefore);
  });

  it('issues add-device receipts for another member and for the owner itself', async () => {
    for (const targetKind of ['recipient', 'owner'] as const) {
      const fixture = await buildFixture();
      const added = await buildAddDeviceFixture(fixture, targetKind);
      try {
        const artifacts = await buildCollaborationEnrollmentArtifacts({
          candidate: added.prepared.candidate,
          proofEntry: added.prepared.proofEntry,
          resultingManifest: added.manifest,
          ownerPublicIdentity:
            targetKind === 'owner'
              ? added.publicIdentity
              : fixture.owner.publicIdentity,
          ownerPrincipalId: OWNER_ID,
          ownerDeviceId: OWNER_DEVICE_ID,
          recipientPublicIdentity: added.publicIdentity,
          recipientDeviceId: ADDED_DEVICE_ID,
          ownerDeviceSigningPrivateKey: fixture.owner.signing.privateKey,
          checkpointId: `checkpoint-add-device-${targetKind}`,
          issuedAt: NOW,
          expiresAt: EXPIRES_AT,
          now: NOW,
        });
        expect(artifacts.receipt).toMatchObject({
          operationType: 'add-device',
          recipientPrincipalId: added.target.certificate.principalId,
          recipientDeviceId: ADDED_DEVICE_ID,
        });
        expect(
          await verifyEnrollmentReceipt(
            artifacts.receipt,
            fixture.owner.signing.publicKeyBase64,
          ),
        ).toBe(true);
        expect(
          await verifyAuthorizationCheckpoint(
            artifacts.checkpoint,
            fixture.owner.signing.publicKeyBase64,
          ),
        ).toBe(true);
      } finally {
        zeroize(added.prepared.nextVaultRootKey);
        zeroize(added.signing.privateKey);
        zeroize(added.encryption.privateKey);
      }
    }
  });

  it('rejects add-device operation, event, recipient, and device substitution', async () => {
    const fixture = await buildFixture();
    const added = await buildAddDeviceFixture(fixture, 'recipient');
    const input: BuildCollaborationEnrollmentArtifactsInput = {
      candidate: added.prepared.candidate,
      proofEntry: added.prepared.proofEntry,
      resultingManifest: added.manifest,
      ownerPublicIdentity: fixture.owner.publicIdentity,
      ownerPrincipalId: OWNER_ID,
      ownerDeviceId: OWNER_DEVICE_ID,
      recipientPublicIdentity: added.publicIdentity,
      recipientDeviceId: ADDED_DEVICE_ID,
      ownerDeviceSigningPrivateKey: fixture.owner.signing.privateKey,
      checkpointId: 'checkpoint-add-device-negative',
      issuedAt: NOW,
      expiresAt: EXPIRES_AT,
      now: NOW,
    };
    try {
      const lastIndex = added.manifest.history.events.length - 1;
      const substitutedEvents = added.manifest.history.events.map((event, index) =>
        index === lastIndex ? { ...event, targetDeviceId: RECIPIENT_DEVICE_ID } : event,
      );
      const cases: readonly BuildCollaborationEnrollmentArtifactsInput[] = [
        {
          ...input,
          candidate: {
            ...added.prepared.candidate,
            currentMutationLink: {
              ...added.prepared.candidate.currentMutationLink,
              commitment: {
                ...added.prepared.candidate.currentMutationLink.commitment,
                operationType: 'add-member',
              },
            },
          },
        },
        {
          ...input,
          resultingManifest: {
            ...added.manifest,
            history: { ...added.manifest.history, events: substitutedEvents },
          },
        },
        { ...input, recipientPublicIdentity: fixture.recipient.publicIdentity },
        { ...input, recipientDeviceId: RECIPIENT_DEVICE_ID },
      ];
      for (const substituted of cases) {
        await expect(
          buildCollaborationEnrollmentArtifacts(substituted),
        ).rejects.toBeInstanceOf(CollaborationEnrollmentError);
      }
    } finally {
      zeroize(added.prepared.nextVaultRootKey);
      zeroize(added.signing.privateKey);
      zeroize(added.encryption.privateKey);
    }
  });

  it('keeps add-member self-enrollment forbidden', async () => {
    const fixture = await buildFixture();
    await expect(
      buildCollaborationEnrollmentArtifacts({
        ...validInput(fixture),
        recipientPublicIdentity: fixture.owner.publicIdentity,
        recipientDeviceId: OWNER_DEVICE_ID,
      }),
    ).rejects.toBeInstanceOf(CollaborationEnrollmentError);
  });

  it('still rejects a currently denied finalized writer and receipt issuer', async () => {
    const identityDenied = await buildFixture({
      denyCurrentOwnerByIdentity: true,
    });
    const fingerprintDenied = await buildFixture({
      denyCurrentOwnerByFingerprint: true,
    });

    for (const fixture of [identityDenied, fingerprintDenied]) {
      await expect(
        buildCollaborationEnrollmentArtifacts(validInput(fixture)),
      ).rejects.toBeInstanceOf(CollaborationEnrollmentError);
    }
  });

  it('does not deny a deviceId collision owned by another principal', async () => {
    const fixture = await buildFixture({ sameDeviceIdUnderOtherPrincipal: true });

    await expect(
      buildCollaborationEnrollmentArtifacts(validInput(fixture)),
    ).resolves.toMatchObject({
      receipt: {
        ownerPrincipalId: OWNER_ID,
        ownerDeviceCertificate: { deviceId: OWNER_DEVICE_ID },
      },
    });
  });

  it('rejects a history checkpoint signer identity substitution', async () => {
    const fixture = await buildFixture({ substituteCheckpointSigner: true });

    await expect(
      buildCollaborationEnrollmentArtifacts(validInput(fixture)),
    ).rejects.toBeInstanceOf(CollaborationEnrollmentError);
  });

  it('fails closed for scope, identity, discovery, expiry, and key substitutions', async () => {
    const fixture = await buildFixture();
    const input = validInput(fixture);
    const wrongOwner = await identity('principal-wrong-owner', 'device-wrong-owner');
    const wrongKey = await generateDeviceSigningKeyPair();
    try {
      const cases = [
        { ...input, ownerPublicIdentity: wrongOwner.publicIdentity },
        { ...input, recipientPublicIdentity: wrongOwner.publicIdentity },
        { ...input, ownerDeviceId: 'device-wrong' },
        { ...input, recipientDeviceId: 'device-wrong' },
        { ...input, ownerDeviceSigningPrivateKey: wrongKey.privateKey },
        { ...input, expiresAt: RECEIPT_AT },
        { ...input, expiresAt: '2027-08-29T00:06:00.000Z' },
        { ...input, now: CREATED_AT },
        {
          ...input,
          candidate: { ...fixture.candidate, databaseId: 'database-substituted' },
        },
        {
          ...input,
          candidate: { ...fixture.candidate, vaultId: 'vault-substituted' },
        },
        {
          ...input,
          proofEntry: {
            ...fixture.proofEntry,
            authorizationWitness: {
              ...fixture.proofEntry.authorizationWitness,
              authorityDelegationDigest: digest(26),
            },
          },
        },
        {
          ...input,
          candidate: { ...fixture.candidate, headDigest: digest(27) },
        },
        {
          ...input,
          proofEntry: {
            ...fixture.proofEntry,
            link: {
              ...fixture.proofEntry.link,
              resultingHeadDigest: digest(28),
            },
          },
        },
        {
          ...input,
          candidate: {
            ...fixture.candidate,
            discoveryRecords: fixture.candidate.discoveryRecords.map((record) =>
              record.membershipId === RECIPIENT_MEMBERSHIP_ID
                ? { ...record, discoveryTag: digest(29) }
                : record,
            ),
          },
        },
        {
          ...input,
          resultingManifest: {
            ...fixture.manifest,
            memberships: fixture.manifest.memberships.map((membership) =>
              membership.principalId === RECIPIENT_ID
                ? { ...membership, role: 'editor' }
                : membership,
            ),
          },
        },
      ];
      for (const substituted of cases) {
        await expect(
          buildCollaborationEnrollmentArtifacts(substituted),
        ).rejects.toEqual(new CollaborationEnrollmentError());
      }
    } finally {
      zeroize(wrongOwner.root.privateKey);
      zeroize(wrongOwner.signing.privateKey);
      zeroize(wrongOwner.encryption.privateKey);
      zeroize(wrongKey.privateKey);
    }
  });

  it('rejects missing or duplicate recipient-device discovery and non-add-member links', async () => {
    const fixture = await buildFixture();
    const input = validInput(fixture);
    const recipientRecords = fixture.candidate.discoveryRecords.filter(
      (record) => record.membershipId === RECIPIENT_MEMBERSHIP_ID,
    );
    expect(recipientRecords).toHaveLength(1);
    const withoutRecipient = fixture.candidate.discoveryRecords.filter(
      (record) => record.membershipId !== RECIPIENT_MEMBERSHIP_ID,
    );
    const missingCandidate = {
      ...fixture.candidate,
      discoveryRecords: withoutRecipient,
    };
    const missingProof = {
      ...fixture.proofEntry,
      authorizationWitness: {
        ...fixture.proofEntry.authorizationWitness,
        discoveryRecords: withoutRecipient,
      },
    };
    await expect(
      buildCollaborationEnrollmentArtifacts({
        ...input,
        candidate: missingCandidate,
        proofEntry: missingProof,
      }),
    ).rejects.toBeInstanceOf(CollaborationEnrollmentError);

    const duplicate = [...fixture.candidate.discoveryRecords, ...recipientRecords];
    await expect(
      buildCollaborationEnrollmentArtifacts({
        ...input,
        candidate: { ...fixture.candidate, discoveryRecords: duplicate },
        proofEntry: {
          ...fixture.proofEntry,
          authorizationWitness: {
            ...fixture.proofEntry.authorizationWitness,
            discoveryRecords: duplicate,
          },
        },
      }),
    ).rejects.toBeInstanceOf(CollaborationEnrollmentError);

    await expect(
      buildCollaborationEnrollmentArtifacts({
        ...input,
        candidate: {
          ...fixture.candidate,
          currentMutationLink: {
            ...fixture.candidate.currentMutationLink,
            commitment: {
              ...fixture.candidate.currentMutationLink.commitment,
              operationType: 'change-role',
            },
          },
        },
      }),
    ).rejects.toBeInstanceOf(CollaborationEnrollmentError);
  });
});
