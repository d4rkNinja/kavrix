import {
  COLLABORATION_DOMAINS,
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
  computeAadMetadataDigest,
  computeApprovalRequestDigest,
  computeAuthorityDelegationDigest,
  computeAuthorityRecoveryEnvelopeDigest,
  computeAuthorizationStateDigest,
  computeAuthorizationTransitionDigest,
  computeDeviceCertificateFingerprint,
  computeDeviceRegistryDigest,
  computeDiscoveryRecordDigest,
  computeDiscoveryTag,
  computeEncryptedMembershipDigest,
  computeEncryptedPayloadDigest,
  computeFinalizedMutationLinkDigest,
  computeKeyEnvelopeDigest,
  computeKeyEnvelopeSetDigest,
  computeMembershipHistoryCompactionDigest,
  computeMembershipHistoryDigest,
  computeMembershipManifestDigest,
  computeMembershipStateDigest,
  computeMutationHead,
  computeMutationRequestDigest,
  computePolicyDigest,
  computePolicyStateDigest,
  computePublicKeyFingerprint,
  computeTransferIntentDigest,
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
  signApprovalEvidence,
  signApprovalRequest,
  signCollaborationRecord,
  signDiscoveryRecord,
  signFinalizedMutationLink,
  signOwnershipTransferAcceptance,
  signTransferIntent,
  verifyAuthorizationTransitionOwner,
  verifyAuthorizationTransitionAuthority,
  verifyCommittedOperationOutcome,
  verifyCollaborationRecord,
  verifyDiscoveryRecord,
  verifyFinalizedMutationLink,
  zeroize,
  type CollaborationDomain,
  type CollaborationEncryptionKeyPair,
  type CollaborationSignatureField,
  type DeviceSigningKeyPair,
  type PrincipalSigningKeyPair,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  canonicalJson,
  collaborationAadMetadataSchema,
  collaborationAadSchema,
  approvalRequestSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationTransitionSchema,
  collaborationAuthorityDelegationSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationKeyEnvelopeSchema,
  collaborationMembershipSchema,
  collaborationMutationProofEntrySchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  deviceCertificateSchema,
  durableOperationOutcomeSchema,
  membershipHistoryEventSchema,
  membershipHistoryCheckpointSchema,
  membershipHistorySchema,
  MAX_COLLABORATIVE_HISTORY_EVENTS,
  recipientRollbackAnchorSchema,
  sha256DigestSchema,
  timestampSchema,
  transferIntentSchema,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationKeyEnvelope,
  type CollaborationMembership,
  type ApprovalRequest,
  type CollaborationRevisionTuple,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DatabaseAuthorityRecoveryEnvelope,
  type DeviceCertificate,
  type Sha256Digest,
  type Timestamp,
  type TransferIntent,
} from '@kavrix/schemas';
import { afterEach, describe, expect, it } from 'vitest';

import {
  CollaborationCandidatePreparationError,
  buildAdministrativeCollaborativeMutation,
  buildOrdinaryCollaborativeMutation,
  computeCollaborativeAdministrativeActionParametersDigest,
  type BuildAdministrativeCollaborativeMutationInput,
  type BuildOrdinaryCollaborativeMutationInput,
} from '../src/collaboration-candidate-builder.js';
import { verifyCollaborativeAdministrativeManifestTransition } from '../src/collaboration-administrative-state.js';

const DATABASE_ID = 'database-candidate-builder';
const VAULT_ID = 'vault-candidate-builder';
const OWNER_ID = 'principal-owner';
const OWNER_DEVICE_ID = 'device-owner';
const MEMBER_ID = 'principal-member';
const MEMBER_DEVICE_ID = 'device-member';
const ADDED_MEMBER_DEVICE_ID = 'device-member-added';
const APPROVER_ID = 'principal-approver';
const APPROVER_DEVICE_ID = 'device-approver';
const OWNER_MEMBERSHIP_ID = 'membership-owner';
const MEMBER_MEMBERSHIP_ID = 'membership-member';
const APPROVER_MEMBERSHIP_ID = 'membership-approver';
const CREATED_AT = timestampSchema.parse('2026-08-29T00:00:00.000Z');
const BEFORE_CREATED_AT = timestampSchema.parse('2026-08-28T23:59:00.000Z');
const GENESIS_AT = timestampSchema.parse('2026-08-29T00:01:00.000Z');
const MUTATION_AT = timestampSchema.parse('2026-08-29T00:02:00.000Z');
const EXPIRES_AT = timestampSchema.parse('2026-08-29T00:12:00.000Z');
const FOLLOW_UP_AT = timestampSchema.parse('2026-08-29T00:03:00.000Z');
const FOLLOW_UP_EXPIRES_AT = timestampSchema.parse('2026-08-29T00:13:00.000Z');
const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');
const PRIOR_PAYLOAD = Buffer.from('prior-private-payload-canary', 'utf8');
const NEXT_PAYLOAD = Buffer.from('next-private-payload-canary', 'utf8');

interface SchemaLike<T> {
  readonly parse: (input: unknown) => T;
}

type Identity = Readonly<{
  root: PrincipalSigningKeyPair;
  signing: DeviceSigningKeyPair;
  encryption: CollaborationEncryptionKeyPair;
  certificate: DeviceCertificate;
}>;

type AdditionalDevice = Readonly<{
  signing: DeviceSigningKeyPair;
  encryption: CollaborationEncryptionKeyPair;
  certificate: DeviceCertificate;
}>;

type Fixture = Readonly<{
  document: CollaborativeVaultDocument;
  manifest: CollaborativeMembershipManifest;
  registry: CollaborationDatabaseDeviceRegistry;
  owner: Identity;
  member: Identity;
  additionalOwner?: Identity;
  authoritySigning: PrincipalSigningKeyPair;
  authorityRecovery: CollaborationEncryptionKeyPair;
  vaultRootKey: VaultRootKey;
}>;

const fixtures: Fixture[] = [];

afterEach(() => {
  for (const fixture of fixtures.splice(0)) {
    zeroize(fixture.owner.root.privateKey);
    zeroize(fixture.owner.signing.privateKey);
    zeroize(fixture.owner.encryption.privateKey);
    zeroize(fixture.member.root.privateKey);
    zeroize(fixture.member.signing.privateKey);
    zeroize(fixture.member.encryption.privateKey);
    zeroize(fixture.additionalOwner?.root.privateKey);
    zeroize(fixture.additionalOwner?.signing.privateKey);
    zeroize(fixture.additionalOwner?.encryption.privateKey);
    zeroize(fixture.authoritySigning.privateKey);
    zeroize(fixture.authorityRecovery.privateKey);
    zeroize(fixture.vaultRootKey);
  }
});

function digest(fill: number): Sha256Digest {
  return sha256DigestSchema.parse(Buffer.alloc(32, fill).toString('base64url'));
}

function mutateBase64(value: string): string {
  return `${value.startsWith('A') ? 'B' : 'A'}${value.slice(1)}`;
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('Incomplete collaboration fixture');
  return value;
}

function deviceCore(device: DeviceCertificate): Record<string, unknown> {
  const core: Record<string, unknown> = { ...device };
  Reflect.deleteProperty(core, 'rootSignature');
  return core;
}

function envelopeCore(
  envelope: CollaborationKeyEnvelope | DatabaseAuthorityRecoveryEnvelope,
): Record<string, unknown> {
  const core: Record<string, unknown> = { ...envelope };
  Reflect.deleteProperty(core, 'envelopeDigest');
  Reflect.deleteProperty(core, 'createdAt');
  Reflect.deleteProperty(core, 'ownerSignature');
  return core;
}

async function signedRecord<T>(
  domain: CollaborationDomain,
  value: Record<string, unknown>,
  schema: SchemaLike<T>,
  field: CollaborationSignatureField,
  privateKey: Uint8Array,
): Promise<T> {
  const signature = await signCollaborationRecord(
    domain,
    value,
    schema,
    field,
    privateKey,
  );
  return schema.parse({ ...value, [field]: signature });
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

async function additionalDevice(
  principal: Identity,
  deviceId = ADDED_MEMBER_DEVICE_ID,
): Promise<AdditionalDevice> {
  const signing = await generateDeviceSigningKeyPair();
  const encryption = await generateDeviceEncryptionKeyPair();
  const certificate = await signedRecord(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    {
      protocolVersion: 1,
      principalId: principal.certificate.principalId,
      deviceId,
      deviceGeneration: 1,
      signingPublicKey: signing.publicKeyBase64,
      encryptionPublicKey: encryption.publicKeyBase64,
      state: 'active',
      createdAt: MUTATION_AT,
      stateChangedAt: MUTATION_AT,
      rootSignature: PLACEHOLDER_SIGNATURE,
    },
    deviceCertificateSchema,
    'rootSignature',
    principal.root.privateKey,
  );
  return { signing, encryption, certificate };
}

async function resignDevice(
  principal: Identity,
  certificate: DeviceCertificate,
  overrides: Partial<DeviceCertificate>,
): Promise<DeviceCertificate> {
  return signedRecord(
    COLLABORATION_DOMAINS.deviceCertificateSignature,
    {
      ...certificate,
      ...overrides,
      rootSignature: PLACEHOLDER_SIGNATURE,
    },
    deviceCertificateSchema,
    'rootSignature',
    principal.root.privateKey,
  );
}

function membership(
  keys: Identity,
  membershipId: string,
  role: CollaborationMembership['role'],
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
    devices: [keys.certificate],
    createdAt: CREATED_AT,
    updatedAt: GENESIS_AT,
  });
}

async function registry(
  authority: PrincipalSigningKeyPair,
  generation = 1,
  deniedDevices: CollaborationDatabaseDeviceRegistry['deniedDevices'] = [],
  previousRegistryDigest: Sha256Digest = digest(10 + generation),
): Promise<CollaborationDatabaseDeviceRegistry> {
  const base = collaborationDatabaseDeviceRegistrySchema.parse({
    format: 'kavrix-collaborative-device-registry',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    authorityEpoch: 1,
    authorityFingerprint: computePublicKeyFingerprint(
      authority.publicKeyBase64,
      'ed25519',
    ),
    generation,
    previousRegistryDigest,
    registryDigest: PLACEHOLDER_DIGEST,
    deniedDevices,
    updatedAt: MUTATION_AT,
    authoritySignature: PLACEHOLDER_SIGNATURE,
  });
  const withDigest = collaborationDatabaseDeviceRegistrySchema.parse({
    ...base,
    registryDigest: computeDeviceRegistryDigest(base),
  });
  return signedRecord(
    COLLABORATION_DOMAINS.deviceRegistrySignature,
    withDigest,
    collaborationDatabaseDeviceRegistrySchema,
    'authoritySignature',
    authority.privateKey,
  );
}

async function memberEnvelope(
  vaultRootKey: VaultRootKey,
  member: CollaborationMembership,
  device: Identity,
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
    deviceId: device.certificate.deviceId,
    recipientEncryptionKeyFingerprint: computePublicKeyFingerprint(
      device.encryption.publicKeyBase64,
      'x25519',
    ),
    keyEpoch: 1,
    membershipRevision: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registryDigest,
    sealedVaultRootKey: await sealVaultRootKeyForDevice(
      vaultRootKey,
      device.encryption.publicKeyBase64,
    ),
    envelopeDigest: PLACEHOLDER_DIGEST,
    createdAt: GENESIS_AT,
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

async function authorityEnvelope(
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
    membershipRevision: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registryDigest,
    sealedVaultRootKey: await sealCollaborationVaultRootForDatabaseAuthority(
      vaultRootKey,
      recovery.publicKeyBase64,
    ),
    envelopeDigest: PLACEHOLDER_DIGEST,
    sealedByPrincipalId: OWNER_ID,
    sealedByDeviceId: OWNER_DEVICE_ID,
    createdAt: GENESIS_AT,
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
  envelopes: CollaborativeMembershipManifest['keyEnvelopes'],
  registryDigest: Sha256Digest,
  ownerPrincipalIds: readonly string[] = [OWNER_ID],
  approvalPolicy: CollaborativeMembershipManifest['approvalPolicy'] = 'none',
): ReturnType<typeof collaborationAuthorizationStateCoreSchema.parse> {
  return collaborationAuthorizationStateCoreSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registryDigest,
    membershipRevision: 1,
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
      devices: value.devices.map(deviceCore),
      createdAt: value.createdAt,
      updatedAt: value.updatedAt,
    })),
    ownerPrincipalIds,
    keyEnvelopes: envelopes.map(envelopeCore),
    approvalPolicy,
  });
}

async function policy(
  owner: Identity,
  registryDigest: Sha256Digest,
  approvalPolicy: CollaborativeMembershipManifest['approvalPolicy'] = 'none',
): Promise<ReturnType<typeof collaborationPolicyStateSchema.parse>> {
  const base = collaborationPolicyStateSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    policyRevision: 1,
    approvalPolicy,
    policyDigest: PLACEHOLDER_DIGEST,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registryDigest,
    changedByPrincipalId: OWNER_ID,
    changedByDeviceId: OWNER_DEVICE_ID,
    changedAt: GENESIS_AT,
    signature: PLACEHOLDER_SIGNATURE,
  });
  const withDigest = collaborationPolicyStateSchema.parse({
    ...base,
    policyDigest: computePolicyDigest(base),
  });
  return signedRecord(
    COLLABORATION_DOMAINS.policySignature,
    withDigest,
    collaborationPolicyStateSchema,
    'signature',
    owner.signing.privateKey,
  );
}

function aad(
  tuple: CollaborationRevisionTuple,
  entityType: 'vault-payload' | 'membership-manifest',
): ReturnType<typeof collaborationAadSchema.parse> {
  const metadata = collaborationAadMetadataSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: tuple.authorityEpoch,
    entityType,
    entityId: VAULT_ID,
    documentRevision: tuple.documentRevision,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    authorizationStateDigest: tuple.authorizationStateDigest,
  });
  return collaborationAadSchema.parse({
    ...metadata,
    metadataDigest: computeAadMetadataDigest(metadata),
  });
}

async function genesisHistoryEvent(
  signer: Identity,
  previous: CollaborationRevisionTuple,
  next: CollaborationRevisionTuple,
  timestamp: Timestamp = GENESIS_AT,
  operationId = 'operation-genesis',
): Promise<ReturnType<typeof membershipHistoryEventSchema.parse>> {
  return signedRecord(
    COLLABORATION_DOMAINS.membershipHistorySignature,
    {
      protocolVersion: 1,
      operationId,
      eventType: 'genesis-created',
      actorPrincipalId: signer.certificate.principalId,
      actorDeviceId: signer.certificate.deviceId,
      previousDocumentRevision: previous.documentRevision,
      newDocumentRevision: next.documentRevision,
      previousMembershipRevision: previous.membershipRevision,
      newMembershipRevision: next.membershipRevision,
      previousPolicyRevision: previous.policyRevision,
      newPolicyRevision: next.policyRevision,
      previousKeyEpoch: previous.keyEpoch,
      newKeyEpoch: next.keyEpoch,
      previousAuthorityEpoch: previous.authorityEpoch,
      newAuthorityEpoch: next.authorityEpoch,
      previousDatabaseDeviceGeneration: previous.databaseDeviceGeneration,
      newDatabaseDeviceGeneration: next.databaseDeviceGeneration,
      previousDatabaseDeviceRegistryDigest: previous.databaseDeviceRegistryDigest,
      newDatabaseDeviceRegistryDigest: next.databaseDeviceRegistryDigest,
      previousAuthorizationStateDigest: previous.authorizationStateDigest,
      newAuthorizationStateDigest: next.authorizationStateDigest,
      previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
      timestamp,
      signature: PLACEHOLDER_SIGNATURE,
    },
    membershipHistoryEventSchema,
    'signature',
    signer.signing.privateKey,
  );
}

async function genesisHistoryCheckpoint(
  signer: Identity,
  declaredSigner: Identity,
  tuple: CollaborationRevisionTuple,
): Promise<ReturnType<typeof membershipHistoryCheckpointSchema.parse>> {
  return signedRecord(
    COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
    {
      protocolVersion: 1,
      checkpointId: 'checkpoint-genesis',
      authorityEpoch: tuple.authorityEpoch,
      databaseDeviceGeneration: tuple.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
      membershipRevision: tuple.membershipRevision,
      documentRevision: tuple.documentRevision,
      policyRevision: tuple.policyRevision,
      keyEpoch: tuple.keyEpoch,
      previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
      compactedThroughRevision: 0,
      compactedHistoryDigest: COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
      signerPrincipalId: declaredSigner.certificate.principalId,
      signerDeviceId: declaredSigner.certificate.deviceId,
      createdAt: GENESIS_AT,
      signature: PLACEHOLDER_SIGNATURE,
    },
    membershipHistoryCheckpointSchema,
    'signature',
    signer.signing.privateKey,
  );
}

async function transition(
  owner: Identity,
  previous: CollaborationRevisionTuple,
  next: CollaborationRevisionTuple,
): Promise<ReturnType<typeof collaborationAuthorizationTransitionSchema.parse>> {
  const base = collaborationAuthorizationTransitionSchema.parse({
    format: 'kavrix-collaborative-authorization-transition',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: 'operation-genesis',
    operationType: 'genesis-migration',
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousAuthorizationStateDigest: previous.authorizationStateDigest,
    authorizationStateDigest: next.authorizationStateDigest,
    previousTuple: previous,
    nextTuple: next,
    evidence: { kind: 'none' },
    issuedAt: GENESIS_AT,
    expiresAt: EXPIRES_AT,
    transitionDigest: PLACEHOLDER_DIGEST,
    transitionSignature: {
      signerKind: 'owner-device',
      signerPrincipalId: OWNER_ID,
      signerDeviceId: OWNER_DEVICE_ID,
      signature: PLACEHOLDER_SIGNATURE,
    },
  });
  const withDigest = collaborationAuthorizationTransitionSchema.parse({
    ...base,
    transitionDigest: computeAuthorizationTransitionDigest(base),
  });
  const signature = await signAuthorizationTransitionOwner(
    withDigest,
    owner.signing.privateKey,
  );
  return collaborationAuthorizationTransitionSchema.parse({
    ...withDigest,
    transitionSignature: { ...withDigest.transitionSignature, signature },
  });
}

async function discovery(
  member: CollaborationMembership,
  envelope: CollaborationKeyEnvelope,
  tuple: CollaborationRevisionTuple,
  encryptedMembershipDigest: Sha256Digest,
  owner: Identity,
): Promise<ReturnType<typeof collaborationDiscoveryRecordSchema.parse>> {
  const base = collaborationDiscoveryRecordSchema.parse({
    format: 'kavrix-collaborative-discovery-record',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    discoveryTag: computeDiscoveryTag(DATABASE_ID, member.principalFingerprint),
    membershipId: member.membershipId,
    membershipState: 'active',
    keyEpoch: tuple.keyEpoch,
    membershipRevision: tuple.membershipRevision,
    authorizationStateDigest: tuple.authorizationStateDigest,
    encryptedMemberKeyEnvelope: envelope,
    encryptedMembershipMetadataDigest: encryptedMembershipDigest,
    discoveryRecordDigest: PLACEHOLDER_DIGEST,
    signerPrincipalId: OWNER_ID,
    signerDeviceId: OWNER_DEVICE_ID,
    writerSignature: PLACEHOLDER_SIGNATURE,
    createdAt: GENESIS_AT,
    updatedAt: GENESIS_AT,
  });
  const withDigest = collaborationDiscoveryRecordSchema.parse({
    ...base,
    discoveryRecordDigest: computeDiscoveryRecordDigest(base),
  });
  return collaborationDiscoveryRecordSchema.parse({
    ...withDigest,
    writerSignature: await signDiscoveryRecord(withDigest, owner.signing.privateKey),
  });
}

async function buildFixture(
  options: Readonly<{
    historySigner?: 'owner' | 'member';
    historyEventTimestamp?: Timestamp;
    checkpointSigner?: 'owner' | 'member';
    checkpointDeclaredSigner?: 'owner' | 'member';
    historyEventCount?: number;
    approvalPolicy?: CollaborativeMembershipManifest['approvalPolicy'];
    includeAdditionalOwner?: boolean;
    denyFutureMemberDevice?: boolean;
  }> = {},
): Promise<Fixture> {
  const authoritySigning = await generatePrincipalSigningKeyPair();
  const authorityRecovery = await generateDeviceEncryptionKeyPair();
  const owner = await identity(OWNER_ID, OWNER_DEVICE_ID);
  const member = await identity(MEMBER_ID, MEMBER_DEVICE_ID);
  const additionalOwner = options.includeAdditionalOwner
    ? await identity(APPROVER_ID, APPROVER_DEVICE_ID)
    : undefined;
  const approvalPolicy = options.approvalPolicy ?? 'none';
  const vaultRootKey = generateVaultRootKey();
  const currentRegistry = await registry(
    authoritySigning,
    1,
    options.denyFutureMemberDevice === true
      ? collaborationDatabaseDeviceRegistrySchema.shape.deniedDevices.parse([
          {
            principalId: member.certificate.principalId,
            deviceId:
              deviceCertificateSchema.shape.deviceId.parse(ADDED_MEMBER_DEVICE_ID),
            deviceGeneration: 1,
            signingKeyFingerprint: digest(109),
            reason: 'authority-fence',
            deniedAt: MUTATION_AT,
          },
        ])
      : [],
  );
  const ownerMembership = membership(owner, OWNER_MEMBERSHIP_ID, 'owner');
  const memberMembership = membership(member, MEMBER_MEMBERSHIP_ID, 'reader');
  const additionalOwnerMembership =
    additionalOwner === undefined
      ? undefined
      : membership(additionalOwner, APPROVER_MEMBERSHIP_ID, 'owner');
  const memberships = [
    ownerMembership,
    memberMembership,
    ...(additionalOwnerMembership === undefined ? [] : [additionalOwnerMembership]),
  ];
  const ownerPrincipalIds = [
    OWNER_ID,
    ...(additionalOwner === undefined ? [] : [APPROVER_ID]),
  ];
  const memberEnvelopes: CollaborationKeyEnvelope[] = [
    await memberEnvelope(
      vaultRootKey,
      ownerMembership,
      owner,
      owner,
      currentRegistry.registryDigest,
    ),
    await memberEnvelope(
      vaultRootKey,
      memberMembership,
      member,
      owner,
      currentRegistry.registryDigest,
    ),
  ];
  if (additionalOwnerMembership !== undefined && additionalOwner !== undefined) {
    memberEnvelopes.push(
      await memberEnvelope(
        vaultRootKey,
        additionalOwnerMembership,
        additionalOwner,
        owner,
        currentRegistry.registryDigest,
      ),
    );
  }
  const envelopes = [
    ...memberEnvelopes,
    await authorityEnvelope(
      vaultRootKey,
      authorityRecovery,
      owner,
      currentRegistry.registryDigest,
    ),
  ];
  const authorizationStateDigest = computeAuthorizationStateDigest(
    authorizationCore(
      memberships,
      envelopes,
      currentRegistry.registryDigest,
      ownerPrincipalIds,
      approvalPolicy,
    ),
  );
  const previousTuple = collaborationRevisionTupleSchema.parse({
    authorityEpoch: 1,
    documentRevision: 0,
    membershipRevision: 0,
    policyRevision: 0,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: currentRegistry.registryDigest,
    authorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  });
  const tuple = collaborationRevisionTupleSchema.parse({
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: currentRegistry.registryDigest,
    authorizationStateDigest,
  });
  const currentPolicy = await policy(
    owner,
    currentRegistry.registryDigest,
    approvalPolicy,
  );
  const historySigner = options.historySigner === 'member' ? member : owner;
  const events = await Promise.all(
    Array.from({ length: options.historyEventCount ?? 1 }, (_, index) =>
      genesisHistoryEvent(
        historySigner,
        previousTuple,
        tuple,
        options.historyEventTimestamp,
        index === 0
          ? 'operation-genesis'
          : `operation-genesis-history-${String(index)}`,
      ),
    ),
  );
  const checkpointSigner =
    options.checkpointSigner === undefined
      ? undefined
      : options.checkpointSigner === 'member'
        ? member
        : owner;
  const checkpointDeclaredSigner =
    options.checkpointDeclaredSigner === 'member' ? member : owner;
  const checkpoint =
    checkpointSigner === undefined
      ? undefined
      : await genesisHistoryCheckpoint(
          checkpointSigner,
          checkpointDeclaredSigner,
          tuple,
        );
  const historyBase = {
    protocolVersion: 1 as const,
    databaseId: currentRegistry.databaseId,
    vaultId: collaborativeVaultDocumentSchema.shape.vaultId.parse(VAULT_ID),
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    events,
    checkpoints: checkpoint === undefined ? [] : [checkpoint],
    compactedThroughRevision: 0,
    compactedHistoryDigest: COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousHistoryDigest: COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
    currentHistoryDigest: PLACEHOLDER_DIGEST,
  };
  const history = membershipHistorySchema.parse({
    ...historyBase,
    currentHistoryDigest: computeMembershipHistoryDigest(historyBase),
  });
  const manifestBase = collaborativeMembershipManifestSchema.parse({
    format: 'kavrix-collaborative-membership-manifest',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    documentRevision: tuple.documentRevision,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    authorizationStateDigest: tuple.authorizationStateDigest,
    memberships,
    ownerPrincipalIds,
    keyEnvelopes: envelopes,
    approvalPolicy,
    policy: currentPolicy,
    pendingApprovals: [],
    pendingTransfers: [],
    history,
    previousMembershipDigest: COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
    membershipDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    createdAt: CREATED_AT,
    updatedAt: GENESIS_AT,
  });
  const manifest = collaborativeMembershipManifestSchema.parse({
    ...manifestBase,
    membershipDigest: computeMembershipManifestDigest(manifestBase),
  });
  const encryptedPayload = await encryptCollaborationEnvelope(
    PRIOR_PAYLOAD,
    vaultRootKey,
    aad(tuple, 'vault-payload'),
  );
  const manifestBytes = Buffer.from(canonicalJson(manifest), 'utf8');
  let encryptedMembershipManifest;
  try {
    encryptedMembershipManifest = await encryptCollaborationEnvelope(
      manifestBytes,
      vaultRootKey,
      aad(tuple, 'membership-manifest'),
    );
  } finally {
    zeroize(manifestBytes);
  }
  const encryptedMembershipDigest = computeEncryptedMembershipDigest(
    encryptedMembershipManifest,
  );
  const discoveryRecords = await Promise.all(
    memberships.map((membershipValue, index) =>
      discovery(
        membershipValue,
        required(memberEnvelopes[index]),
        tuple,
        encryptedMembershipDigest,
        owner,
      ),
    ),
  );
  const genesisTransition = await transition(owner, previousTuple, tuple);
  const commitment = {
    protocolVersion: 1 as const,
    databaseId: currentRegistry.databaseId,
    vaultId: collaborativeVaultDocumentSchema.shape.vaultId.parse(VAULT_ID),
    operationId: 'operation-genesis',
    operationType: 'genesis-migration' as const,
    requestDigest: digest(35),
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousAuthorizationStateDigest: previousTuple.authorizationStateDigest,
    authorizationStateDigest: tuple.authorizationStateDigest,
    authorizationTransitionDigest: genesisTransition.transitionDigest,
    previousAuthorityEpoch: previousTuple.authorityEpoch,
    previousDocumentRevision: previousTuple.documentRevision,
    previousMembershipRevision: previousTuple.membershipRevision,
    previousPolicyRevision: previousTuple.policyRevision,
    previousKeyEpoch: previousTuple.keyEpoch,
    previousDatabaseDeviceGeneration: previousTuple.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: previousTuple.databaseDeviceRegistryDigest,
    authorityEpoch: tuple.authorityEpoch,
    documentRevision: tuple.documentRevision,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    encryptedPayloadDigest: computeEncryptedPayloadDigest(encryptedPayload),
    encryptedMembershipDigest,
    encryptedEnvelopesDigest: computeKeyEnvelopeSetDigest(envelopes),
    policyDigest: currentPolicy.policyDigest,
    writerPrincipalId: ownerMembership.principalId,
    writerDeviceId: owner.certificate.deviceId,
    timestamp: GENESIS_AT,
  };
  const headDigest = computeMutationHead(commitment);
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
    genesisTuple: tuple,
    genesisHeadDigest: headDigest,
    initialAuthorizationStateDigest: tuple.authorizationStateDigest,
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
    authorizationTransition: genesisTransition,
    resultingHeadDigest: headDigest,
    writerSignature: {
      algorithm: 'ed25519',
      writerPrincipalId: OWNER_ID,
      writerDeviceId: OWNER_DEVICE_ID,
      commitmentDigest: headDigest,
      signature: PLACEHOLDER_SIGNATURE,
    },
    finalizedAt: GENESIS_AT,
  });
  const link = collaborationFinalizedMutationLinkSchema.parse({
    ...linkBase,
    writerSignature: {
      ...linkBase.writerSignature,
      signature: await signFinalizedMutationLink(linkBase, owner.signing.privateKey),
    },
  });
  const document = collaborativeVaultDocumentSchema.parse({
    format: 'kavrix-collaborative-vault',
    documentVersion: 1,
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: tuple.authorityEpoch,
    databaseDeviceGeneration: tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple.databaseDeviceRegistryDigest,
    documentRevision: tuple.documentRevision,
    membershipRevision: tuple.membershipRevision,
    policyRevision: tuple.policyRevision,
    keyEpoch: tuple.keyEpoch,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    headDigest,
    authorityDelegation: delegation,
    authorityDelegationDigest,
    authorizationStateDigest: tuple.authorizationStateDigest,
    encryptedPayloadDigest: commitment.encryptedPayloadDigest,
    encryptedMembershipDigest,
    encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
    policyDigest: currentPolicy.policyDigest,
    databaseAuthorityRecoveryEnvelope: envelopes[envelopes.length - 1],
    encryptedPayload,
    encryptedMembershipManifest,
    discoveryRecords,
    currentMutationLink: link,
    createdAt: CREATED_AT,
    updatedAt: GENESIS_AT,
  });
  const fixture = {
    document,
    manifest,
    registry: currentRegistry,
    owner,
    member,
    ...(additionalOwner === undefined ? {} : { additionalOwner }),
    authoritySigning,
    authorityRecovery,
    vaultRootKey,
  };
  fixtures.push(fixture);
  return fixture;
}

function ordinaryInput(fixture: Fixture): BuildOrdinaryCollaborativeMutationInput {
  const ownerMembership = required(fixture.manifest.memberships[0]);
  return {
    prior: {
      document: fixture.document,
      manifest: fixture.manifest,
      deviceRegistry: fixture.registry,
      currentVaultRootKey: fixture.vaultRootKey,
      quarantinedVaultPayload: PRIOR_PAYLOAD,
    },
    authoritativeDeviceRegistry: fixture.registry,
    actor: {
      principalId: ownerMembership.principalId,
      deviceId: fixture.owner.certificate.deviceId,
      rootSigningPublicKey: fixture.owner.root.publicKeyBase64,
      deviceCertificate: fixture.owner.certificate,
      deviceSigningPrivateKey: fixture.owner.signing.privateKey,
    },
    authorityRecoveryPublicKey: fixture.authorityRecovery.publicKeyBase64,
    operationId:
      collaborativeVaultDocumentSchema.shape.currentMutationLink.shape.commitment.shape.operationId.parse(
        'operation-ordinary-2',
      ),
    timestamp: MUTATION_AT,
    expiresAt: EXPIRES_AT,
    anchorScope: {
      databaseId: fixture.document.databaseId,
      vaultId: fixture.document.vaultId,
      principalId: ownerMembership.principalId,
      deviceId: fixture.owner.certificate.deviceId,
    },
    vaultPayload: NEXT_PAYLOAD,
  };
}

function administrativeInput(
  fixture: Fixture,
  next: BuildAdministrativeCollaborativeMutationInput['next'],
  operationType:
    'add-device' | 'change-policy' | 'remove-member' | 'rotate-key' | 'transfer-owner',
  decryptAccessChanged: boolean,
): Exclude<
  BuildAdministrativeCollaborativeMutationInput,
  { operationType: 'recover-owner' }
> {
  return {
    ...ordinaryInput(fixture),
    operationType,
    next,
    decryptAccessChanged,
  };
}

async function approvedRequest(
  fixture: Fixture,
  operationType: 'change-policy' | 'transfer-owner',
  operationId: ApprovalRequest['operationId'],
  actionParametersDigest: Sha256Digest,
  suffix: string,
): Promise<ApprovalRequest> {
  const approver = required(fixture.additionalOwner);
  const base = approvalRequestSchema.parse({
    format: 'kavrix-collaborative-approval-request',
    protocolVersion: 1,
    approvalRequestId: approvalRequestSchema.shape.approvalRequestId.parse(
      `approval-${suffix}`,
    ),
    operationId,
    operationType,
    databaseId: fixture.document.databaseId,
    vaultId: fixture.document.vaultId,
    requestDigest: PLACEHOLDER_DIGEST,
    actionParametersDigest,
    authorityEpoch: fixture.document.authorityEpoch,
    databaseDeviceGeneration: fixture.document.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: fixture.document.databaseDeviceRegistryDigest,
    documentRevision: fixture.document.documentRevision,
    membershipRevision: fixture.document.membershipRevision,
    policyRevision: fixture.document.policyRevision,
    keyEpoch: fixture.document.keyEpoch,
    priorHeadDigest: fixture.document.headDigest,
    authorizationStateDigest: fixture.document.authorizationStateDigest,
    requestingPrincipalId: fixture.owner.certificate.principalId,
    requestingDeviceId: fixture.owner.certificate.deviceId,
    requiredApprovalPolicy: 'one-additional-owner',
    state: 'pending',
    createdAt: GENESIS_AT,
    expiresAt: EXPIRES_AT,
    nonce: Buffer.alloc(16, suffix.length).toString('base64url'),
    requesterSignature: PLACEHOLDER_SIGNATURE,
    approvals: [],
  });
  const withDigest = approvalRequestSchema.parse({
    ...base,
    requestDigest: computeApprovalRequestDigest(base),
  });
  const request = approvalRequestSchema.parse({
    ...withDigest,
    requesterSignature: await signApprovalRequest(
      withDigest,
      fixture.owner.signing.privateKey,
    ),
  });
  const evidenceBase = approvalRequestSchema.shape.approvals.element.parse({
    protocolVersion: 1,
    approvalRequestId: request.approvalRequestId,
    operationId: request.operationId,
    databaseId: request.databaseId,
    vaultId: request.vaultId,
    requestDigest: request.requestDigest,
    authorityEpoch: request.authorityEpoch,
    databaseDeviceGeneration: request.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: request.databaseDeviceRegistryDigest,
    documentRevision: request.documentRevision,
    membershipRevision: request.membershipRevision,
    policyRevision: request.policyRevision,
    keyEpoch: request.keyEpoch,
    priorHeadDigest: request.priorHeadDigest,
    authorizationStateDigest: request.authorizationStateDigest,
    requestingPrincipalId: request.requestingPrincipalId,
    approverPrincipalId: approver.certificate.principalId,
    approverDeviceId: approver.certificate.deviceId,
    approvedAt: GENESIS_AT,
    signature: PLACEHOLDER_SIGNATURE,
  });
  const evidence = approvalRequestSchema.shape.approvals.element.parse({
    ...evidenceBase,
    signature: await signApprovalEvidence(evidenceBase, approver.signing.privateKey),
  });
  return approvalRequestSchema.parse({
    ...request,
    state: 'quorum-reached',
    approvals: [evidence],
  });
}

async function acceptedTransfer(
  fixture: Fixture,
  operationId: TransferIntent['operationId'],
  approvalRequest?: ApprovalRequest,
): Promise<TransferIntent> {
  const base = transferIntentSchema.parse({
    format: 'kavrix-collaborative-transfer-intent',
    protocolVersion: 1,
    transferIntentId: transferIntentSchema.shape.transferIntentId.parse(
      `transfer-${operationId}`,
    ),
    operationId,
    databaseId: fixture.document.databaseId,
    vaultId: fixture.document.vaultId,
    initiatorPrincipalId: fixture.owner.certificate.principalId,
    initiatorDeviceId: fixture.owner.certificate.deviceId,
    recipientPrincipalId: fixture.member.certificate.principalId,
    recipientDeviceId: fixture.member.certificate.deviceId,
    targetRole: 'owner',
    originalOwnerDisposition: 'remain-owner',
    authorityEpoch: fixture.document.authorityEpoch,
    databaseDeviceGeneration: fixture.document.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: fixture.document.databaseDeviceRegistryDigest,
    documentRevision: fixture.document.documentRevision,
    membershipRevision: fixture.document.membershipRevision,
    policyRevision: fixture.document.policyRevision,
    keyEpoch: fixture.document.keyEpoch,
    currentHeadDigest: fixture.document.headDigest,
    authorizationStateDigest: fixture.document.authorizationStateDigest,
    intentDigest: PLACEHOLDER_DIGEST,
    ...(approvalRequest === undefined
      ? {}
      : { approvalRequestId: approvalRequest.approvalRequestId }),
    state: 'initiator-signed',
    createdAt: GENESIS_AT,
    expiresAt: EXPIRES_AT,
    initiatorSignedAt: GENESIS_AT,
    initiatorSignature: PLACEHOLDER_SIGNATURE,
  });
  const withDigest = transferIntentSchema.parse({
    ...base,
    intentDigest: computeTransferIntentDigest(base),
  });
  const signed = transferIntentSchema.parse({
    ...withDigest,
    initiatorSignature: await signTransferIntent(
      withDigest,
      fixture.owner.signing.privateKey,
    ),
  });
  const acceptanceSchema = transferIntentSchema.shape.recipientAcceptance.unwrap();
  const acceptanceBase = acceptanceSchema.parse({
    protocolVersion: 1,
    transferIntentId: signed.transferIntentId,
    operationId: signed.operationId,
    databaseId: signed.databaseId,
    vaultId: signed.vaultId,
    intentDigest: signed.intentDigest,
    authorityEpoch: signed.authorityEpoch,
    databaseDeviceGeneration: signed.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: signed.databaseDeviceRegistryDigest,
    authorizationStateDigest: signed.authorizationStateDigest,
    recipientPrincipalId: signed.recipientPrincipalId,
    recipientDeviceId: signed.recipientDeviceId,
    acceptedAt: GENESIS_AT,
    signature: PLACEHOLDER_SIGNATURE,
  });
  const acceptance = acceptanceSchema.parse({
    ...acceptanceBase,
    signature: await signOwnershipTransferAcceptance(
      acceptanceBase,
      fixture.member.signing.privateKey,
    ),
  });
  return transferIntentSchema.parse({
    ...signed,
    state: 'recipient-accepted',
    recipientAcceptance: acceptance,
  });
}

describe('collaboration candidate builder', () => {
  it('builds an exact immutable ordinary mutation with no transition or witness', async () => {
    const fixture = await buildFixture();
    const prepared = await buildOrdinaryCollaborativeMutation(ordinaryInput(fixture));

    expect(collaborativeVaultDocumentSchema.parse(prepared.candidate)).toStrictEqual(
      prepared.candidate,
    );
    expect(
      collaborationMutationProofEntrySchema.parse(prepared.proofEntry),
    ).toStrictEqual(prepared.proofEntry);
    expect(durableOperationOutcomeSchema.parse(prepared.proposedOutcome)).toStrictEqual(
      prepared.proposedOutcome,
    );
    expect(recipientRollbackAnchorSchema.parse(prepared.candidateAnchor)).toStrictEqual(
      prepared.candidateAnchor,
    );
    expect(prepared.nextVaultRootKey).toBeUndefined();
    expect(prepared.proofEntry.authorizationWitness).toBeUndefined();
    expect(
      prepared.candidate.currentMutationLink.authorizationTransition,
    ).toBeUndefined();
    expect(prepared.candidate.authorizationStateDigest).toBe(
      fixture.document.authorizationStateDigest,
    );
    expect(prepared.candidate.keyEpoch).toBe(fixture.document.keyEpoch);
    expect(prepared.candidate.membershipRevision).toBe(
      fixture.document.membershipRevision,
    );
    expect(prepared.candidate.policyRevision).toBe(fixture.document.policyRevision);
    expect(prepared.candidate.documentRevision).toBe(
      fixture.document.documentRevision + 1,
    );
    expect(
      computeMutationRequestDigest(prepared.candidate.currentMutationLink.commitment),
    ).toBe(prepared.candidate.currentMutationLink.commitment.requestDigest);
    expect(
      await verifyFinalizedMutationLink(
        prepared.candidate.currentMutationLink,
        fixture.owner.signing.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyCommittedOperationOutcome(
        prepared.proposedOutcome,
        fixture.owner.signing.publicKeyBase64,
      ),
    ).toBe(true);
    for (const record of prepared.candidate.discoveryRecords) {
      expect(
        await verifyDiscoveryRecord(record, fixture.owner.signing.publicKeyBase64),
      ).toBe(true);
    }
    const plaintext = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedPayload,
      fixture.vaultRootKey,
      prepared.candidate.encryptedPayload.aad,
    );
    expect(Buffer.from(plaintext)).toEqual(NEXT_PAYLOAD);
    zeroize(plaintext);
    const manifestPlaintext = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedMembershipManifest,
      fixture.vaultRootKey,
      prepared.candidate.encryptedMembershipManifest.aad,
    );
    const candidateManifest = collaborativeMembershipManifestSchema.parse(
      JSON.parse(Buffer.from(manifestPlaintext).toString('utf8')),
    );
    zeroize(manifestPlaintext);
    expect(prepared.candidateAnchor.headDigest).toBe(prepared.candidate.headDigest);
    const priorLogicalMembershipDigest = computeMembershipStateDigest(
      authorizationCore(
        fixture.manifest.memberships,
        fixture.manifest.keyEnvelopes,
        fixture.registry.registryDigest,
      ),
    );
    expect(prepared.candidateAnchor.membershipDigest).toBe(
      priorLogicalMembershipDigest,
    );
    expect(prepared.candidateAnchor.policyDigest).toBe(
      computePolicyStateDigest(fixture.manifest.policy),
    );
    expect(prepared.candidateAnchor.membershipDigest).not.toBe(
      candidateManifest.membershipDigest,
    );
    expect(prepared.candidateAnchor.finalizedMutationLinkDigest).toBe(
      computeFinalizedMutationLinkDigest(prepared.candidate.currentMutationLink),
    );
    expect(Object.isFrozen(prepared)).toBe(true);
    expect(Object.isFrozen(prepared.candidate.currentMutationLink)).toBe(true);
    const journalable = canonicalJson({
      candidate: prepared.candidate,
      proofEntry: prepared.proofEntry,
      proposedOutcome: prepared.proposedOutcome,
      candidateAnchor: prepared.candidateAnchor,
    });
    expect(journalable).not.toContain(PRIOR_PAYLOAD.toString('utf8'));
    expect(journalable).not.toContain(NEXT_PAYLOAD.toString('utf8'));
  });

  it('atomically compacts a capacity-bound authenticated history inside an administrative mutation', async () => {
    const fixture = await buildFixture({
      historyEventCount: MAX_COLLABORATIVE_HISTORY_EVENTS,
    });
    const input = administrativeInput(
      fixture,
      {
        memberships: fixture.manifest.memberships,
        ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
        approvalPolicy: 'one-additional-owner',
        historyEvent: { eventType: 'policy-changed' },
      },
      'change-policy',
      false,
    );

    const prepared = await buildAdministrativeCollaborativeMutation(input);
    const plaintext = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedMembershipManifest,
      fixture.vaultRootKey,
      prepared.candidate.encryptedMembershipManifest.aad,
    );
    const candidateManifest = collaborativeMembershipManifestSchema.parse(
      JSON.parse(Buffer.from(plaintext).toString('utf8')),
    );
    zeroize(plaintext);

    const previousTuple = collaborationRevisionTupleSchema.parse({
      authorityEpoch: fixture.document.authorityEpoch,
      documentRevision: fixture.document.documentRevision,
      membershipRevision: fixture.document.membershipRevision,
      policyRevision: fixture.document.policyRevision,
      keyEpoch: fixture.document.keyEpoch,
      databaseDeviceGeneration: fixture.document.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: fixture.document.databaseDeviceRegistryDigest,
      authorizationStateDigest: fixture.document.authorizationStateDigest,
    });
    const checkpoint = required(candidateManifest.history.checkpoints[0]);
    const event = required(candidateManifest.history.events[0]);
    const expectedCompactionDigest = computeMembershipHistoryCompactionDigest({
      protocolVersion: 1,
      databaseId: fixture.document.databaseId,
      vaultId: fixture.document.vaultId,
      authorityEpoch: previousTuple.authorityEpoch,
      compactingOperationId: input.operationId,
      previousHeadDigest: fixture.document.headDigest,
      previousTuple,
      priorHistory: fixture.manifest.history,
    });

    expect(candidateManifest.history.events).toHaveLength(1);
    expect(candidateManifest.history.checkpoints).toHaveLength(1);
    expect(event.operationId).toBe(input.operationId);
    expect(checkpoint).toMatchObject({
      checkpointId: input.operationId,
      previousHeadDigest: fixture.document.headDigest,
      compactedThroughRevision: fixture.document.membershipRevision,
      compactedHistoryDigest: expectedCompactionDigest,
      signerPrincipalId: OWNER_ID,
      signerDeviceId: OWNER_DEVICE_ID,
      createdAt: MUTATION_AT,
    });
    expect(candidateManifest.history.compactedThroughRevision).toBe(
      checkpoint.compactedThroughRevision,
    );
    expect(candidateManifest.history.compactedHistoryDigest).toBe(
      checkpoint.compactedHistoryDigest,
    );
    expect(
      await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistorySignature,
        event,
        membershipHistoryEventSchema,
        'signature',
        fixture.owner.signing.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyCollaborationRecord(
        COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
        checkpoint,
        membershipHistoryCheckpointSchema,
        'signature',
        fixture.owner.signing.publicKeyBase64,
      ),
    ).toBe(true);
    expect(() =>
      verifyCollaborativeAdministrativeManifestTransition({
        link: prepared.candidate.currentMutationLink,
        priorManifest: fixture.manifest,
        nextManifest: candidateManifest,
      }),
    ).not.toThrow();
  });

  it('builds a policy-only administrative transition without rotating the VRK', async () => {
    const fixture = await buildFixture();
    const input = administrativeInput(
      fixture,
      {
        memberships: fixture.manifest.memberships,
        ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
        approvalPolicy: 'one-additional-owner',
        historyEvent: { eventType: 'policy-changed' },
      },
      'change-policy',
      false,
    );
    const prepared = await buildAdministrativeCollaborativeMutation(input);
    const transition = prepared.candidate.currentMutationLink.authorizationTransition;

    expect(transition).toBeDefined();
    expect(prepared.proofEntry.authorizationWitness).toBeDefined();
    expect(
      prepared.proofEntry.authorizationWitness?.databaseDeviceRegistry,
    ).toStrictEqual(fixture.registry);
    expect(prepared.nextVaultRootKey).toBeUndefined();
    expect(prepared.candidate.keyEpoch).toBe(fixture.document.keyEpoch);
    expect(prepared.candidate.policyRevision).toBe(fixture.document.policyRevision + 1);
    expect(prepared.candidate.authorizationStateDigest).not.toBe(
      fixture.document.authorizationStateDigest,
    );
    expect(
      await verifyAuthorizationTransitionOwner(
        transition,
        fixture.owner.signing.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      await verifyFinalizedMutationLink(
        prepared.candidate.currentMutationLink,
        fixture.owner.signing.publicKeyBase64,
      ),
    ).toBe(true);
    expect(
      computeFinalizedMutationLinkDigest(prepared.candidate.currentMutationLink),
    ).toBe(prepared.proofEntry.authorizationWitness?.finalizedMutationLinkDigest);
    const plaintext = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedPayload,
      fixture.vaultRootKey,
      prepared.candidate.encryptedPayload.aad,
    );
    expect(Buffer.from(plaintext)).toEqual(PRIOR_PAYLOAD);
    zeroize(plaintext);
    const manifestPlaintext = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedMembershipManifest,
      fixture.vaultRootKey,
      prepared.candidate.encryptedMembershipManifest.aad,
    );
    const candidateManifest = collaborativeMembershipManifestSchema.parse(
      JSON.parse(Buffer.from(manifestPlaintext).toString('utf8')),
    );
    zeroize(manifestPlaintext);
    const witness = required(prepared.proofEntry.authorizationWitness);
    const recoveryEnvelope = candidateManifest.keyEnvelopes.find(
      (envelope) => !('membershipId' in envelope),
    );
    expect(canonicalJson(witness.databaseAuthorityRecoveryEnvelope)).toBe(
      canonicalJson(recoveryEnvelope),
    );
    expect(() =>
      verifyCollaborativeAdministrativeManifestTransition({
        link: prepared.candidate.currentMutationLink,
        priorManifest: fixture.manifest,
        nextManifest: candidateManifest,
      }),
    ).not.toThrow();
    const substitutedMember =
      collaborativeMembershipManifestSchema.shape.memberships.element.parse({
        ...required(candidateManifest.memberships[1]),
        updatedAt: FOLLOW_UP_AT,
      });
    expect(() =>
      verifyCollaborativeAdministrativeManifestTransition({
        link: prepared.candidate.currentMutationLink,
        priorManifest: fixture.manifest,
        nextManifest: {
          ...candidateManifest,
          memberships: [required(candidateManifest.memberships[0]), substitutedMember],
        },
      }),
    ).toThrow('Invalid collaborative administrative manifest transition');
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        next: {
          ...input.next,
          pendingTransfers: [],
        } as never,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
  });

  it('consumes exact external approval evidence and rejects replay, substitution, or pending-list injection', async () => {
    const fixture = await buildFixture({
      approvalPolicy: 'one-additional-owner',
      includeAdditionalOwner: true,
    });
    const next = {
      memberships: fixture.manifest.memberships,
      ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
      approvalPolicy: 'none' as const,
      historyEvent: { eventType: 'policy-changed' as const },
    };
    const input = administrativeInput(fixture, next, 'change-policy', false);
    const actionParametersDigest =
      computeCollaborativeAdministrativeActionParametersDigest({
        operationType: 'change-policy',
        next,
        decryptAccessChanged: false,
      });
    const approval = await approvedRequest(
      fixture,
      'change-policy',
      input.operationId,
      actionParametersDigest,
      'policy',
    );
    const prepared = await buildAdministrativeCollaborativeMutation({
      ...input,
      approvalRequest: approval,
    });
    const manifestPlaintext = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedMembershipManifest,
      fixture.vaultRootKey,
      prepared.candidate.encryptedMembershipManifest.aad,
    );
    const candidateManifest = collaborativeMembershipManifestSchema.parse(
      JSON.parse(Buffer.from(manifestPlaintext).toString('utf8')),
    );
    zeroize(manifestPlaintext);
    const consumed = required(candidateManifest.pendingApprovals.at(-1));
    const transition = required(
      prepared.candidate.currentMutationLink.authorizationTransition,
    );
    const historyEvent = required(candidateManifest.history.events.at(-1));

    expect(consumed.state).toBe('consumed');
    expect(consumed.resolvedAt).toBe(MUTATION_AT);
    expect(consumed.requestDigest).toBe(approval.requestDigest);
    expect(consumed.requesterSignature).toBe(approval.requesterSignature);
    expect(consumed.approvals).toStrictEqual(approval.approvals);
    expect(transition.evidence).toStrictEqual({
      kind: 'approval',
      evidenceDigest: approval.requestDigest,
    });
    expect(historyEvent.approvalRequestId).toBe(approval.approvalRequestId);
    expect(historyEvent.approvalRequestDigest).toBe(approval.requestDigest);

    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        approvalRequest: consumed,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        next: {
          ...next,
          historyEvent: {
            eventType: 'policy-changed',
            targetPrincipalId: fixture.member.certificate.principalId,
          },
        },
        approvalRequest: approval,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        next: {
          ...next,
          pendingApprovals: [approval],
        } as never,
        approvalRequest: approval,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
  });

  it('publishes an accepted transfer with its exact required approval and rejects missing, foreign, or replayed workflow evidence', async () => {
    const fixture = await buildFixture({
      approvalPolicy: 'one-additional-owner',
      includeAdditionalOwner: true,
    });
    const recipientOwner =
      collaborativeMembershipManifestSchema.shape.memberships.element.parse({
        ...required(fixture.manifest.memberships[1]),
        role: 'owner',
        updatedAt: MUTATION_AT,
      });
    const next = {
      memberships: [
        required(fixture.manifest.memberships[0]),
        recipientOwner,
        required(fixture.manifest.memberships[2]),
      ],
      ownerPrincipalIds: [
        ...fixture.manifest.ownerPrincipalIds,
        fixture.member.certificate.principalId,
      ],
      approvalPolicy: fixture.manifest.approvalPolicy,
      historyEvent: {
        eventType: 'owner-transfer' as const,
        targetPrincipalId: fixture.member.certificate.principalId,
        previousRole: 'reader' as const,
        newRole: 'owner' as const,
      },
    };
    const input = administrativeInput(fixture, next, 'transfer-owner', false);
    const actionParametersDigest =
      computeCollaborativeAdministrativeActionParametersDigest({
        operationType: 'transfer-owner',
        next,
        decryptAccessChanged: false,
      });
    const approval = await approvedRequest(
      fixture,
      'transfer-owner',
      input.operationId,
      actionParametersDigest,
      'transfer',
    );
    const intent = await acceptedTransfer(fixture, input.operationId, approval);
    const prepared = await buildAdministrativeCollaborativeMutation({
      ...input,
      approvalRequest: approval,
      transferIntent: intent,
    });
    const manifestPlaintext = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedMembershipManifest,
      fixture.vaultRootKey,
      prepared.candidate.encryptedMembershipManifest.aad,
    );
    const candidateManifest = collaborativeMembershipManifestSchema.parse(
      JSON.parse(Buffer.from(manifestPlaintext).toString('utf8')),
    );
    zeroize(manifestPlaintext);
    const consumed = required(candidateManifest.pendingApprovals.at(-1));
    const published = required(candidateManifest.pendingTransfers.at(-1));
    const transition = required(
      prepared.candidate.currentMutationLink.authorizationTransition,
    );

    expect(consumed.state).toBe('consumed');
    expect(consumed.resolvedAt).toBe(MUTATION_AT);
    expect(published.state).toBe('published');
    expect(published.publishedAt).toBe(MUTATION_AT);
    expect(published.intentDigest).toBe(intent.intentDigest);
    expect(published.initiatorSignature).toBe(intent.initiatorSignature);
    expect(published.recipientAcceptance).toStrictEqual(intent.recipientAcceptance);
    expect(transition.evidence).toStrictEqual({
      kind: 'ownership-transfer',
      evidenceDigest: intent.intentDigest,
    });

    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        transferIntent: intent,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
    const foreignApproval = await approvedRequest(
      fixture,
      'transfer-owner',
      input.operationId,
      actionParametersDigest,
      'foreign',
    );
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        approvalRequest: foreignApproval,
        transferIntent: intent,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        approvalRequest: consumed,
        transferIntent: intent,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        approvalRequest: approval,
        transferIntent: published,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);

    const approvalFreeFixture = await buildFixture();
    const approvalFreeRecipient =
      collaborativeMembershipManifestSchema.shape.memberships.element.parse({
        ...required(approvalFreeFixture.manifest.memberships[1]),
        role: 'owner',
        updatedAt: MUTATION_AT,
      });
    const approvalFreeNext = {
      memberships: [
        required(approvalFreeFixture.manifest.memberships[0]),
        approvalFreeRecipient,
      ],
      ownerPrincipalIds: [
        approvalFreeFixture.owner.certificate.principalId,
        approvalFreeFixture.member.certificate.principalId,
      ],
      approvalPolicy: 'none' as const,
      historyEvent: {
        eventType: 'owner-transfer' as const,
        targetPrincipalId: approvalFreeFixture.member.certificate.principalId,
        previousRole: 'reader' as const,
        newRole: 'owner' as const,
      },
    };
    const approvalFreeInput = administrativeInput(
      approvalFreeFixture,
      approvalFreeNext,
      'transfer-owner',
      false,
    );
    const approvalFreeIntent = await acceptedTransfer(
      approvalFreeFixture,
      approvalFreeInput.operationId,
    );
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...approvalFreeInput,
        approvalRequest: approval,
        transferIntent: approvalFreeIntent,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
  });

  it('removes decrypt access only with a fresh caller-owned VRK and new envelopes', async () => {
    const fixture = await buildFixture();
    const ownerMembership = required(fixture.manifest.memberships[0]);
    const removed =
      collaborativeMembershipManifestSchema.shape.memberships.element.parse({
        ...fixture.manifest.memberships[1],
        state: 'revoked',
        updatedAt: MUTATION_AT,
        removedAt: MUTATION_AT,
      });
    const prepared = await buildAdministrativeCollaborativeMutation(
      administrativeInput(
        fixture,
        {
          memberships: [ownerMembership, removed],
          ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
          approvalPolicy: fixture.manifest.approvalPolicy,
          historyEvent: {
            eventType: 'member-removed',
            targetPrincipalId: removed.principalId,
            previousState: 'active',
            newState: 'revoked',
          },
        },
        'remove-member',
        true,
      ),
    );

    const nextKey = prepared.nextVaultRootKey;
    expect(nextKey).toBeDefined();
    expect(nextKey).not.toEqual(fixture.vaultRootKey);
    const ownedNextKey = required(nextKey);
    expect(prepared.candidate.keyEpoch).toBe(fixture.document.keyEpoch + 1);
    expect(prepared.candidateAnchor.membershipDigest).not.toBe(
      computeMembershipStateDigest(
        authorizationCore(
          fixture.manifest.memberships,
          fixture.manifest.keyEnvelopes,
          fixture.registry.registryDigest,
        ),
      ),
    );
    expect(prepared.candidate.discoveryRecords).toHaveLength(1);
    expect(
      prepared.candidate.discoveryRecords[0]?.encryptedMemberKeyEnvelope.principalId,
    ).toBe(OWNER_ID);
    const plaintext = await decryptCollaborationEnvelope(
      prepared.candidate.encryptedPayload,
      ownedNextKey,
      prepared.candidate.encryptedPayload.aad,
    );
    expect(Buffer.from(plaintext)).toEqual(PRIOR_PAYLOAD);
    zeroize(plaintext);
    await expect(
      decryptCollaborationEnvelope(
        prepared.candidate.encryptedPayload,
        fixture.vaultRootKey,
        prepared.candidate.encryptedPayload.aad,
      ),
    ).rejects.toThrow();
    expect([...ownedNextKey]).not.toEqual(new Array(32).fill(0));
    zeroize(ownedNextKey);
  });

  it('adds exactly one certified active device with a mandatory VRK rotation', async () => {
    const fixture = await buildFixture();
    const added = await additionalDevice(fixture.member);
    let second: AdditionalDevice | undefined;
    let prepared:
      Awaited<ReturnType<typeof buildAdministrativeCollaborativeMutation>> | undefined;
    try {
      const ownerMembership = required(fixture.manifest.memberships[0]);
      const priorMember = required(fixture.manifest.memberships[1]);
      const nextMember = collaborationMembershipSchema.parse({
        ...priorMember,
        identityGeneration: priorMember.identityGeneration + 1,
        devices: [...priorMember.devices, added.certificate],
        updatedAt: MUTATION_AT,
      });
      const next = {
        memberships: [ownerMembership, nextMember],
        ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
        approvalPolicy: fixture.manifest.approvalPolicy,
        historyEvent: {
          eventType: 'device-added' as const,
          targetPrincipalId: added.certificate.principalId,
          targetDeviceId: added.certificate.deviceId,
        },
      };
      const input = administrativeInput(fixture, next, 'add-device', true);
      prepared = await buildAdministrativeCollaborativeMutation(input);

      expect(prepared.candidate).toMatchObject({
        documentRevision: fixture.document.documentRevision + 1,
        membershipRevision: fixture.document.membershipRevision + 1,
        policyRevision: fixture.document.policyRevision,
        keyEpoch: fixture.document.keyEpoch + 1,
        databaseDeviceGeneration: fixture.document.databaseDeviceGeneration,
        databaseDeviceRegistryDigest: fixture.document.databaseDeviceRegistryDigest,
      });
      const nextKey = required(prepared.nextVaultRootKey);
      expect(nextKey).not.toEqual(fixture.vaultRootKey);
      const manifestPlaintext = await decryptCollaborationEnvelope(
        prepared.candidate.encryptedMembershipManifest,
        nextKey,
        prepared.candidate.encryptedMembershipManifest.aad,
      );
      const manifest = collaborativeMembershipManifestSchema.parse(
        JSON.parse(Buffer.from(manifestPlaintext).toString('utf8')),
      );
      zeroize(manifestPlaintext);
      expect(manifest.memberships[1]).toStrictEqual(nextMember);
      expect(manifest.history.events.at(-1)).toMatchObject({
        eventType: 'device-added',
        targetPrincipalId: MEMBER_ID,
        targetDeviceId: ADDED_MEMBER_DEVICE_ID,
      });
      expect(
        manifest.keyEnvelopes.filter((envelope) => 'membershipId' in envelope),
      ).toHaveLength(3);
      expect(prepared.candidate.discoveryRecords).toHaveLength(3);
      expect(
        new Set(
          prepared.candidate.discoveryRecords.map(
            (record) => record.encryptedMemberKeyEnvelope.deviceId,
          ),
        ),
      ).toEqual(new Set([OWNER_DEVICE_ID, MEMBER_DEVICE_ID, ADDED_MEMBER_DEVICE_ID]));
      expect(
        verifyCollaborativeAdministrativeManifestTransition({
          link: prepared.candidate.currentMutationLink,
          priorManifest: fixture.manifest,
          nextManifest: manifest,
        }).decryptAccessChanged,
      ).toBe(true);
      await expect(
        decryptCollaborationEnvelope(
          prepared.candidate.encryptedPayload,
          fixture.vaultRootKey,
          prepared.candidate.encryptedPayload.aad,
        ),
      ).rejects.toThrow();

      const rejects = async (
        membershipValue: unknown,
        nextOverrides: Readonly<Record<string, unknown>> = {},
        decryptAccessChanged = true,
      ): Promise<void> => {
        await expect(
          buildAdministrativeCollaborativeMutation(
            administrativeInput(
              fixture,
              {
                ...next,
                ...nextOverrides,
                memberships: [
                  ownerMembership,
                  membershipValue,
                ] as readonly CollaborationMembership[],
              },
              'add-device',
              decryptAccessChanged,
            ),
          ),
        ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
      };

      await rejects({
        ...nextMember,
        identityGeneration: priorMember.identityGeneration,
      });
      await rejects({ ...nextMember, identityGeneration: 0 });
      await rejects({
        ...nextMember,
        devices: [added.certificate, ...priorMember.devices],
      });
      second = await additionalDevice(fixture.member, 'device-member-added-second');
      await rejects({
        ...nextMember,
        devices: [...priorMember.devices, added.certificate, second.certificate],
      });
      await rejects({
        ...nextMember,
        devices: [
          await resignDevice(fixture.member, required(priorMember.devices[0]), {
            deviceGeneration: deviceCertificateSchema.shape.deviceGeneration.parse(
              required(priorMember.devices[0]).deviceGeneration + 1,
            ),
          }),
          added.certificate,
        ],
      });
      await rejects({
        ...nextMember,
        devices: [
          ...priorMember.devices,
          await resignDevice(fixture.member, added.certificate, {
            state: 'verified',
          }),
        ],
      });
      await rejects({
        ...nextMember,
        devices: [
          ...priorMember.devices,
          {
            ...added.certificate,
            rootSignature: mutateBase64(added.certificate.rootSignature),
          },
        ],
      });
      await rejects({
        ...nextMember,
        devices: [
          ...priorMember.devices,
          await resignDevice(fixture.member, added.certificate, {
            createdAt: CREATED_AT,
            stateChangedAt: CREATED_AT,
            expiresAt: GENESIS_AT,
          }),
        ],
      });
      await rejects(nextMember, {}, false);

      const deniedFixture = await buildFixture({ denyFutureMemberDevice: true });
      const deniedAdded = await additionalDevice(deniedFixture.member);
      try {
        const deniedPriorMember = required(deniedFixture.manifest.memberships[1]);
        await expect(
          buildAdministrativeCollaborativeMutation(
            administrativeInput(
              deniedFixture,
              {
                memberships: [
                  required(deniedFixture.manifest.memberships[0]),
                  collaborationMembershipSchema.parse({
                    ...deniedPriorMember,
                    identityGeneration: deniedPriorMember.identityGeneration + 1,
                    devices: [...deniedPriorMember.devices, deniedAdded.certificate],
                    updatedAt: MUTATION_AT,
                  }),
                ],
                ownerPrincipalIds: deniedFixture.manifest.ownerPrincipalIds,
                approvalPolicy: deniedFixture.manifest.approvalPolicy,
                historyEvent: {
                  eventType: 'device-added',
                  targetPrincipalId: deniedAdded.certificate.principalId,
                  targetDeviceId: deniedAdded.certificate.deviceId,
                },
              },
              'add-device',
              true,
            ),
          ),
        ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
      } finally {
        zeroize(deniedAdded.signing.privateKey);
        zeroize(deniedAdded.encryption.privateKey);
      }

      const twoOwnerFixture = await buildFixture({ includeAdditionalOwner: true });
      const twoOwnerAdded = await additionalDevice(twoOwnerFixture.member);
      try {
        const twoOwnerPriorMember = required(twoOwnerFixture.manifest.memberships[1]);
        await expect(
          buildAdministrativeCollaborativeMutation(
            administrativeInput(
              twoOwnerFixture,
              {
                memberships: [
                  required(twoOwnerFixture.manifest.memberships[0]),
                  collaborationMembershipSchema.parse({
                    ...twoOwnerPriorMember,
                    identityGeneration: twoOwnerPriorMember.identityGeneration + 1,
                    devices: [
                      ...twoOwnerPriorMember.devices,
                      twoOwnerAdded.certificate,
                    ],
                    updatedAt: MUTATION_AT,
                  }),
                  required(twoOwnerFixture.manifest.memberships[2]),
                ],
                ownerPrincipalIds: [
                  ...twoOwnerFixture.manifest.ownerPrincipalIds,
                ].reverse(),
                approvalPolicy: twoOwnerFixture.manifest.approvalPolicy,
                historyEvent: {
                  eventType: 'device-added',
                  targetPrincipalId: twoOwnerAdded.certificate.principalId,
                  targetDeviceId: twoOwnerAdded.certificate.deviceId,
                },
              },
              'add-device',
              true,
            ),
          ),
        ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
      } finally {
        zeroize(twoOwnerAdded.signing.privateKey);
        zeroize(twoOwnerAdded.encryption.privateKey);
      }
    } finally {
      zeroize(prepared?.nextVaultRootKey);
      zeroize(added.signing.privateKey);
      zeroize(added.encryption.privateKey);
      zeroize(second?.signing.privateKey);
      zeroize(second?.encryption.privateKey);
    }
  });

  it('binds a one-step append-only registry advance and rejects skipped generations', async () => {
    const fixture = await buildFixture();
    const advancedRegistry = await registry(
      fixture.authoritySigning,
      2,
      collaborationDatabaseDeviceRegistrySchema.shape.deniedDevices.parse([
        {
          principalId: MEMBER_ID,
          deviceId: OWNER_DEVICE_ID,
          deviceGeneration: 1,
          signingKeyFingerprint: digest(101),
          reason: 'authority-fence',
          deniedAt: MUTATION_AT,
        },
        {
          principalId: 'principal-unrelated',
          deviceId: 'device-unrelated',
          deviceGeneration: 1,
          signingKeyFingerprint: computeDeviceCertificateFingerprint(
            fixture.owner.certificate,
          ),
          reason: 'authority-fence',
          deniedAt: MUTATION_AT,
        },
      ]),
      fixture.registry.registryDigest,
    );
    const input = administrativeInput(
      fixture,
      {
        memberships: fixture.manifest.memberships,
        ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
        approvalPolicy: fixture.manifest.approvalPolicy,
        historyEvent: { eventType: 'key-rotated' },
      },
      'rotate-key',
      false,
    );
    const prepared = await buildAdministrativeCollaborativeMutation({
      ...input,
      authoritativeDeviceRegistry: advancedRegistry,
    });

    expect(
      prepared.proofEntry.authorizationWitness?.databaseDeviceRegistry,
    ).toStrictEqual(advancedRegistry);
    expect(prepared.candidate.databaseDeviceGeneration).toBe(2);
    zeroize(prepared.nextVaultRootKey);

    const skippedRegistry = await registry(
      fixture.authoritySigning,
      3,
      [],
      fixture.registry.registryDigest,
    );
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        authoritativeDeviceRegistry: skippedRegistry,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
  });

  it('keeps historical signatures valid after their device is subsequently denied', async () => {
    const fixture = await buildFixture({
      historySigner: 'member',
      checkpointSigner: 'member',
      checkpointDeclaredSigner: 'member',
    });
    const ownerMembership = required(fixture.manifest.memberships[0]);
    const removedMember =
      collaborativeMembershipManifestSchema.shape.memberships.element.parse({
        ...required(fixture.manifest.memberships[1]),
        state: 'revoked',
        updatedAt: MUTATION_AT,
        removedAt: MUTATION_AT,
      });
    const removal = await buildAdministrativeCollaborativeMutation(
      administrativeInput(
        fixture,
        {
          memberships: [ownerMembership, removedMember],
          ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
          approvalPolicy: fixture.manifest.approvalPolicy,
          historyEvent: {
            eventType: 'member-removed',
            targetPrincipalId: removedMember.principalId,
            previousState: 'active',
            newState: 'revoked',
          },
        },
        'remove-member',
        true,
      ),
    );
    const removalVaultRootKey = required(removal.nextVaultRootKey);
    const manifestPlaintext = await decryptCollaborationEnvelope(
      removal.candidate.encryptedMembershipManifest,
      removalVaultRootKey,
      removal.candidate.encryptedMembershipManifest.aad,
    );
    const removalManifest = collaborativeMembershipManifestSchema.parse(
      JSON.parse(Buffer.from(manifestPlaintext).toString('utf8')),
    );
    zeroize(manifestPlaintext);
    const advancedRegistry = await registry(
      fixture.authoritySigning,
      2,
      [
        {
          principalId: fixture.member.certificate.principalId,
          deviceId: fixture.member.certificate.deviceId,
          deviceGeneration: fixture.member.certificate.deviceGeneration,
          signingKeyFingerprint: computePublicKeyFingerprint(
            fixture.member.signing.publicKeyBase64,
            'ed25519',
          ),
          reason: 'revoked',
          deniedAt: MUTATION_AT,
        },
      ],
      fixture.registry.registryDigest,
    );
    const followUp = await buildAdministrativeCollaborativeMutation({
      ...administrativeInput(
        fixture,
        {
          memberships: removalManifest.memberships,
          ownerPrincipalIds: removalManifest.ownerPrincipalIds,
          approvalPolicy: removalManifest.approvalPolicy,
          historyEvent: { eventType: 'key-rotated' },
        },
        'rotate-key',
        false,
      ),
      prior: {
        document: removal.candidate,
        manifest: removalManifest,
        deviceRegistry: fixture.registry,
        currentVaultRootKey: removalVaultRootKey,
        quarantinedVaultPayload: PRIOR_PAYLOAD,
      },
      authoritativeDeviceRegistry: advancedRegistry,
      operationId:
        collaborativeVaultDocumentSchema.shape.currentMutationLink.shape.commitment.shape.operationId.parse(
          'operation-ordinary-3',
        ),
      timestamp: FOLLOW_UP_AT,
      expiresAt: FOLLOW_UP_EXPIRES_AT,
    });

    expect(followUp.candidate.documentRevision).toBe(
      removal.candidate.documentRevision + 1,
    );
    expect(followUp.candidateAnchor.membershipDigest).toBe(
      removal.candidateAnchor.membershipDigest,
    );
    expect(followUp.candidateAnchor.policyDigest).toBe(
      computePolicyStateDigest(removalManifest.policy),
    );
    expect(
      removalManifest.history.events.some(
        (event) => event.actorDeviceId === fixture.member.certificate.deviceId,
      ),
    ).toBe(true);
    expect(removalManifest.history.checkpoints).toEqual([
      expect.objectContaining({
        signerPrincipalId: fixture.member.certificate.principalId,
        signerDeviceId: fixture.member.certificate.deviceId,
      }),
    ]);
    zeroize(removalVaultRootKey);
    zeroize(followUp.nextVaultRootKey);
  });

  it('rejects a checkpoint whose named signer does not match its signing key', async () => {
    const fixture = await buildFixture({
      checkpointSigner: 'member',
      checkpointDeclaredSigner: 'owner',
    });

    await expect(
      buildOrdinaryCollaborativeMutation(ordinaryInput(fixture)),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
  });

  it('rejects a history event created before its named signer existed', async () => {
    const fixture = await buildFixture({
      historySigner: 'member',
      historyEventTimestamp: BEFORE_CREATED_AT,
    });

    await expect(
      buildOrdinaryCollaborativeMutation(ordinaryInput(fixture)),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
  });

  it('requires an authority-signed recover-owner transition and always rotates its VRK', async () => {
    const fixture = await buildFixture();
    const removedOwner =
      collaborativeMembershipManifestSchema.shape.memberships.element.parse({
        ...required(fixture.manifest.memberships[0]),
        state: 'revoked',
        updatedAt: MUTATION_AT,
        removedAt: MUTATION_AT,
      });
    const recoveredOwner =
      collaborativeMembershipManifestSchema.shape.memberships.element.parse({
        ...required(fixture.manifest.memberships[1]),
        role: 'owner',
        updatedAt: MUTATION_AT,
      });
    const base = ordinaryInput(fixture);
    const input: BuildAdministrativeCollaborativeMutationInput = {
      ...base,
      operationType: 'recover-owner',
      decryptAccessChanged: true,
      authoritySigningPrivateKey: fixture.authoritySigning.privateKey,
      authorityRecoveryEvidenceDigest: digest(89),
      actor: {
        principalId: fixture.member.certificate.principalId,
        deviceId: fixture.member.certificate.deviceId,
        rootSigningPublicKey: fixture.member.root.publicKeyBase64,
        deviceCertificate: fixture.member.certificate,
        deviceSigningPrivateKey: fixture.member.signing.privateKey,
      },
      anchorScope: {
        ...base.anchorScope,
        principalId: fixture.member.certificate.principalId,
        deviceId: fixture.member.certificate.deviceId,
      },
      next: {
        memberships: [removedOwner, recoveredOwner],
        ownerPrincipalIds: [recoveredOwner.principalId],
        approvalPolicy: fixture.manifest.approvalPolicy,
        historyEvent: {
          eventType: 'owner-recovery',
          targetPrincipalId: recoveredOwner.principalId,
        },
      },
    };
    const prepared = await buildAdministrativeCollaborativeMutation(input);
    const transition = required(
      prepared.candidate.currentMutationLink.authorizationTransition,
    );

    expect(prepared.nextVaultRootKey).toBeDefined();
    expect(prepared.candidate.keyEpoch).toBe(fixture.document.keyEpoch + 1);
    expect(prepared.candidate.currentMutationLink.writerSignature).toMatchObject({
      writerPrincipalId: recoveredOwner.principalId,
      writerDeviceId: fixture.member.certificate.deviceId,
    });
    expect(
      required(prepared.candidate.currentMutationLink.authorizationTransition),
    ).toMatchObject({
      transitionSignature: { signerKind: 'database-authority' },
    });
    expect(
      await verifyAuthorizationTransitionAuthority(
        transition,
        fixture.authoritySigning.publicKeyBase64,
      ),
    ).toBe(true);
    zeroize(prepared.nextVaultRootKey);

    const wrongAuthorityKey = Uint8Array.from(fixture.authoritySigning.privateKey);
    wrongAuthorityKey[0] = (wrongAuthorityKey[0] ?? 0) ^ 0xff;
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        authoritySigningPrivateKey: wrongAuthorityKey,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
    zeroize(wrongAuthorityKey);

    await expect(
      buildAdministrativeCollaborativeMutation({
        ...input,
        actor: base.actor,
        anchorScope: base.anchorScope,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
  });

  it('builds recover-owner with a new root-certified replacement and no prior owner signing key', async () => {
    const fixture = await buildFixture();
    const replacement = await identity('principal-new-owner', 'device-new-owner');
    const replacementMembership = membership(
      replacement,
      'membership-new-owner',
      'owner',
    );
    const removedOwner =
      collaborativeMembershipManifestSchema.shape.memberships.element.parse({
        ...required(fixture.manifest.memberships[0]),
        state: 'revoked',
        updatedAt: MUTATION_AT,
        removedAt: MUTATION_AT,
      });
    const unchangedReader = required(fixture.manifest.memberships[1]);
    const base = ordinaryInput(fixture);
    let prepared:
      Awaited<ReturnType<typeof buildAdministrativeCollaborativeMutation>> | undefined;
    try {
      prepared = await buildAdministrativeCollaborativeMutation({
        ...base,
        operationType: 'recover-owner',
        decryptAccessChanged: true,
        authoritySigningPrivateKey: fixture.authoritySigning.privateKey,
        authorityRecoveryEvidenceDigest: digest(90),
        actor: {
          principalId: replacement.certificate.principalId,
          deviceId: replacement.certificate.deviceId,
          rootSigningPublicKey: replacement.root.publicKeyBase64,
          deviceCertificate: replacement.certificate,
          deviceSigningPrivateKey: replacement.signing.privateKey,
        },
        anchorScope: {
          ...base.anchorScope,
          principalId: replacement.certificate.principalId,
          deviceId: replacement.certificate.deviceId,
        },
        next: {
          memberships: [removedOwner, unchangedReader, replacementMembership],
          ownerPrincipalIds: [replacementMembership.principalId],
          approvalPolicy: fixture.manifest.approvalPolicy,
          historyEvent: {
            eventType: 'owner-recovery',
            targetPrincipalId: replacementMembership.principalId,
          },
        },
      });
      expect(prepared.candidate.currentMutationLink.writerSignature).toMatchObject({
        writerPrincipalId: replacement.certificate.principalId,
        writerDeviceId: replacement.certificate.deviceId,
      });
      expect(prepared.candidateAnchor).toMatchObject({
        principalId: replacement.certificate.principalId,
        deviceId: replacement.certificate.deviceId,
      });
    } finally {
      zeroize(prepared?.nextVaultRootKey);
      zeroize(replacement.root.privateKey);
      zeroize(replacement.signing.privateKey);
      zeroize(replacement.encryption.privateKey);
    }
  });

  it('fails closed for ownerless state, wrong signer/evidence, and denied actors or recipients', async () => {
    const fixture = await buildFixture();
    const ownerMembership = required(fixture.manifest.memberships[0]);
    const memberMembership = required(fixture.manifest.memberships[1]);
    const ownerless = administrativeInput(
      fixture,
      {
        memberships: [
          {
            ...ownerMembership,
            role: 'reader',
            updatedAt: MUTATION_AT,
          },
          memberMembership,
        ],
        ownerPrincipalIds: [],
        approvalPolicy: 'one-additional-owner',
        historyEvent: { eventType: 'policy-changed' },
      },
      'change-policy',
      false,
    );
    await expect(
      buildAdministrativeCollaborativeMutation(ownerless),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);

    const wrongKey = Uint8Array.from(fixture.owner.signing.privateKey);
    wrongKey[0] = (wrongKey[0] ?? 0) ^ 0xff;
    await expect(
      buildOrdinaryCollaborativeMutation({
        ...ordinaryInput(fixture),
        actor: { ...ordinaryInput(fixture).actor, deviceSigningPrivateKey: wrongKey },
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
    zeroize(wrongKey);

    await expect(
      buildAdministrativeCollaborativeMutation({
        ...administrativeInput(
          fixture,
          {
            memberships: fixture.manifest.memberships,
            ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
            approvalPolicy: 'one-additional-owner',
            historyEvent: { eventType: 'policy-changed' },
          },
          'change-policy',
          false,
        ),
        approvalRequest: {} as never,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);

    const deniedRegistry = await registry(
      fixture.authoritySigning,
      2,
      [
        {
          principalId: fixture.member.certificate.principalId,
          deviceId: fixture.member.certificate.deviceId,
          deviceGeneration: fixture.member.certificate.deviceGeneration,
          signingKeyFingerprint: computePublicKeyFingerprint(
            fixture.member.signing.publicKeyBase64,
            'ed25519',
          ),
          reason: 'revoked',
          deniedAt: MUTATION_AT,
        },
      ],
      fixture.registry.registryDigest,
    );
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...administrativeInput(
          fixture,
          {
            memberships: fixture.manifest.memberships,
            ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
            approvalPolicy: fixture.manifest.approvalPolicy,
            historyEvent: { eventType: 'key-rotated' },
          },
          'rotate-key',
          false,
        ),
        authoritativeDeviceRegistry: deniedRegistry,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);

    const deniedActorRegistry = await registry(
      fixture.authoritySigning,
      2,
      [
        {
          principalId: fixture.owner.certificate.principalId,
          deviceId: fixture.owner.certificate.deviceId,
          deviceGeneration: fixture.owner.certificate.deviceGeneration,
          signingKeyFingerprint: computePublicKeyFingerprint(
            fixture.owner.signing.publicKeyBase64,
            'ed25519',
          ),
          reason: 'compromised',
          deniedAt: MUTATION_AT,
        },
      ],
      fixture.registry.registryDigest,
    );
    await expect(
      buildAdministrativeCollaborativeMutation({
        ...administrativeInput(
          fixture,
          {
            memberships: fixture.manifest.memberships,
            ownerPrincipalIds: fixture.manifest.ownerPrincipalIds,
            approvalPolicy: fixture.manifest.approvalPolicy,
            historyEvent: { eventType: 'key-rotated' },
          },
          'rotate-key',
          false,
        ),
        authoritativeDeviceRegistry: deniedActorRegistry,
      }),
    ).rejects.toBeInstanceOf(CollaborationCandidatePreparationError);
  });

  it('binds request digests deterministically to every finalized commitment field', async () => {
    const fixture = await buildFixture();
    const prepared = await buildOrdinaryCollaborativeMutation(ordinaryInput(fixture));
    const commitment = prepared.candidate.currentMutationLink.commitment;
    const first = computeMutationRequestDigest(commitment);
    const second = computeMutationRequestDigest(commitment);
    const changed = computeMutationRequestDigest({
      ...commitment,
      encryptedPayloadDigest: mutateBase64(commitment.encryptedPayloadDigest),
      requestDigest: PLACEHOLDER_DIGEST,
    });

    expect(first).toBe(second);
    expect(first).toBe(commitment.requestDigest);
    expect(changed).not.toBe(first);
  });

  it('rejects digest, AAD, and signature tampering with strict schemas or verifiers', async () => {
    const fixture = await buildFixture();
    const prepared = await buildOrdinaryCollaborativeMutation(ordinaryInput(fixture));
    const digestTampered = structuredClone(prepared.candidate);
    digestTampered.encryptedPayloadDigest = mutateBase64(
      digestTampered.encryptedPayloadDigest,
    ) as Sha256Digest;
    expect(collaborativeVaultDocumentSchema.safeParse(digestTampered).success).toBe(
      false,
    );

    const aadTampered = structuredClone(prepared.candidate);
    aadTampered.encryptedPayload.aad.documentRevision =
      collaborationRevisionTupleSchema.shape.documentRevision.parse(
        aadTampered.encryptedPayload.aad.documentRevision + 1,
      );
    expect(collaborativeVaultDocumentSchema.safeParse(aadTampered).success).toBe(false);

    const signatureTampered = structuredClone(prepared.candidate.currentMutationLink);
    signatureTampered.writerSignature.signature = mutateBase64(
      signatureTampered.writerSignature.signature,
    );
    expect(
      await verifyFinalizedMutationLink(
        signatureTampered,
        fixture.owner.signing.publicKeyBase64,
      ),
    ).toBe(false);
  });
});
