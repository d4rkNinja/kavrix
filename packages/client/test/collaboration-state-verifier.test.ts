import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  COLLABORATION_DOMAINS,
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
  computeAadMetadataDigest,
  computeAuthorityDelegationDigest,
  computeAuthorityRecoveryEnvelopeDigest,
  computeAuthorizationCheckpointDigest,
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
  deriveDatabaseAuthorityRecoveryKeyPair,
  encryptCollaborationEnvelope,
  generateDeviceEncryptionKeyPair,
  generateDeviceSigningKeyPair,
  generateDatabaseRootKey,
  generatePrincipalSigningKeyPair,
  generateVaultRootKey,
  sealVaultRootKeyForDevice,
  signAuthorityDelegation,
  signAuthorizationCheckpoint,
  signAuthorizationTransitionAuthority,
  signAuthorizationTransitionOwner,
  signCollaborationRecord,
  signDiscoveryRecord,
  signEnrollmentReceipt,
  signFinalizedMutationLink,
  signOwnershipTransferAcceptance,
  signTransferIntent,
  zeroize,
  type CollaborationDomain,
  type CollaborationEncryptionKeyPair,
  type DatabaseAuthorityRecoveryKeyPair,
  type DatabaseRootKey,
  type CollaborationSignatureField,
  type DeviceSigningKeyPair,
  type PrincipalSigningKeyPair,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument,
  createCollaborationAuthorityRollbackAnchor,
  readCollaborationAuthorityRollbackAnchor,
  readRecipientRollbackAnchor,
} from '@kavrix/key-files';
import {
  canonicalJson,
  collaborationAadMetadataSchema,
  collaborationAadSchema,
  collaborationAuthorizationCheckpointSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationTransitionSchema,
  collaborationAuthorizationWitnessSchema,
  collaborationAuthorityDelegationSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationDiscoveryRecordSchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationKeyEnvelopeSchema,
  collaborationMutationCommitmentSchema,
  collaborationMutationProofSchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  deviceCertificateSchema,
  enrollmentReceiptSchema,
  membershipHistoryCheckpointSchema,
  membershipHistoryEventSchema,
  ownershipTransferAcceptanceSchema,
  publicIdentityExportSchema,
  sha256DigestSchema,
  transferIntentSchema,
  type CollaborationAuthorityDelegation,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationDiscoveryRecord,
  type CollaborationFinalizedMutationLink,
  type CollaborationKeyEnvelope,
  type CollaborationMembership,
  type CollaborationMutationProof,
  type CollaborationRevisionTuple,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DatabaseAuthorityRecoveryEnvelope,
  type DeviceCertificate,
  type EnrollmentReceipt,
  type PublicIdentityExport,
  type RecipientRollbackAnchor,
  type Sha256Digest,
} from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../key-files/dist/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(() => Promise.resolve()),
  verifyWindowsDirectoryAcl: vi.fn(() => Promise.resolve()),
  verifyWindowsUserOnlyAcl: vi.fn(() => Promise.resolve()),
}));

import { buildCollaborationEnrollmentArtifacts } from '../src/collaboration-enrollment.js';
import { buildAdministrativeCollaborativeMutation } from '../src/collaboration-candidate-builder.js';
import {
  CollaborationStateVerificationError,
  enrollAndOpenCollaborativeVault,
  openCollaborativeVaultWithPinnedTrust,
  openCollaborativeVaultForDatabaseAuthorityRecovery,
  verifyCollaborativeJournalSuccessorChain,
  type CollaborativeVaultPinnedTrust,
  type EnrollAndOpenCollaborativeVaultInput,
  type OpenedCollaborativeVaultState,
} from '../src/collaboration-state-verifier.js';

const DATABASE_ID = 'database-collaboration';
const VAULT_ID = 'vault-collaboration';
const OWNER_ID = 'principal-owner';
const OWNER_DEVICE_ID = 'device-owner';
const RECIPIENT_ID = 'principal-recipient';
const RECIPIENT_DEVICE_ID = 'device-recipient';
const ADDED_DEVICE_ID = 'device-added';
const OWNER_MEMBERSHIP_ID = 'membership-owner';
const RECIPIENT_MEMBERSHIP_ID = 'membership-recipient';
const CREATED_AT = '2026-08-29T00:00:00.000Z';
const T1 = '2026-08-29T00:01:00.000Z';
const T2 = '2026-08-29T00:02:00.000Z';
const T3 = '2026-08-29T00:03:00.000Z';
const NOW = '2026-08-29T00:04:00.000Z';
const EXPIRES_AT = '2026-08-30T00:00:00.000Z';
const PLACEHOLDER_SIGNATURE = Buffer.alloc(64).toString('base64url');
const PLACEHOLDER_DIGEST = Buffer.alloc(32).toString('base64url');
const PAYLOAD = Buffer.from('non-sensitive collaboration fixture', 'utf8');

interface SchemaLike<T> {
  readonly parse: (input: unknown) => T;
}

type IdentityKeys = Readonly<{
  root: PrincipalSigningKeyPair;
  signing: DeviceSigningKeyPair;
  encryption: CollaborationEncryptionKeyPair;
  certificate: DeviceCertificate;
  identity: PublicIdentityExport;
}>;

type BuiltState = Readonly<{
  tuple: CollaborationRevisionTuple;
  manifest: CollaborativeMembershipManifest;
  discoveryRecords: readonly CollaborationDiscoveryRecord[];
  encryptedPayload: CollaborativeVaultDocument['encryptedPayload'];
  encryptedMembershipManifest: CollaborativeVaultDocument['encryptedMembershipManifest'];
  encryptedPayloadDigest: Sha256Digest;
  encryptedMembershipDigest: Sha256Digest;
  encryptedEnvelopesDigest: Sha256Digest;
  link: CollaborationFinalizedMutationLink;
  document: CollaborativeVaultDocument;
  witness: ReturnType<typeof collaborationAuthorizationWitnessSchema.parse>;
}>;

type Fixture = Readonly<{
  registry: CollaborationDatabaseDeviceRegistry;
  delegation: CollaborationAuthorityDelegation;
  receipt: EnrollmentReceipt;
  checkpoint: ReturnType<typeof collaborationAuthorizationCheckpointSchema.parse>;
  genesisState: BuiltState;
  state1: BuiltState;
  state2: BuiltState;
  state3: BuiltState;
  proof1To2: CollaborationMutationProof;
  proof1To3: CollaborationMutationProof;
  genesisProofTo3: CollaborationMutationProof;
  owner: IdentityKeys;
  recipient: IdentityKeys;
  authoritySigning: PrincipalSigningKeyPair;
  authorityRecovery: DatabaseAuthorityRecoveryKeyPair;
  databaseRootKey: DatabaseRootKey;
  vaultRootKey: VaultRootKey;
  deviceProtectionSecret: Uint8Array;
  trust: CollaborativeVaultPinnedTrust;
  scope: Readonly<{
    databaseId: EnrollmentReceipt['databaseId'];
    vaultId: EnrollmentReceipt['vaultId'];
    principalId: EnrollmentReceipt['recipientPrincipalId'];
    deviceId: EnrollmentReceipt['recipientDeviceId'];
  }>;
}>;

type GenesisHistoryCheckpointScenario =
  'none' | 'wrong-signer-ids' | 'reader-signer' | 'key-substitution' | 'pre-creation';
type GenesisHistoryEventScenario = 'normal' | 'pre-creation';

let directory = '';
const fixtures: Fixture[] = [];

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-verifier-'));
});

afterEach(async () => {
  for (const fixture of fixtures.splice(0)) destroyFixture(fixture);
  await rm(directory, { recursive: true, force: true });
});

function anchorPath(name = 'recipient.anchor'): string {
  return join(directory, name);
}

async function initializeAuthorityAnchor(
  fixture: Fixture,
  state: BuiltState = fixture.genesisState,
  path = anchorPath('authority.anchor'),
): Promise<string> {
  await createCollaborationAuthorityRollbackAnchor(
    path,
    fixture.databaseRootKey,
    collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
      state.document,
      authorityLogicalDigests(state),
    ),
  );
  return path;
}

function authorityLogicalDigests(state: BuiltState): Readonly<{
  membershipDigest: Sha256Digest;
  policyDigest: Sha256Digest;
}> {
  const manifest = state.manifest;
  return {
    membershipDigest: computeMembershipStateDigest(
      authorizationCore(
        manifest.memberships,
        manifest.ownerPrincipalIds,
        manifest.keyEnvelopes,
        manifest.membershipRevision,
        manifest.databaseDeviceRegistryDigest,
        manifest.keyEpoch,
        manifest.databaseDeviceGeneration,
        manifest.approvalPolicy,
      ),
    ),
    policyDigest: computePolicyStateDigest(manifest.policy),
  };
}

function digest(fill: number): Sha256Digest {
  return sha256DigestSchema.parse(Buffer.alloc(32, fill).toString('base64url'));
}

function mutateBase64(value: string): string {
  return `${value.startsWith('A') ? 'B' : 'A'}${value.slice(1)}`;
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

async function identityKeys(
  principalId: string,
  deviceId: string,
): Promise<IdentityKeys> {
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
  const identity = await signedRecord(
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
  return { root, signing, encryption, certificate, identity };
}

function membership(
  keys: IdentityKeys,
  principalId: string,
  membershipId: string,
  role: CollaborationMembership['role'],
  updatedAt: string,
): CollaborationMembership {
  return {
    membershipId: collaborationKeyEnvelopeSchema.shape.membershipId.parse(membershipId),
    principalId: keys.certificate.principalId,
    principalFingerprint: computePublicKeyFingerprint(
      keys.root.publicKeyBase64,
      'ed25519',
    ),
    rootSigningPublicKey: keys.root.publicKeyBase64,
    identityGeneration:
      collaborationRevisionTupleSchema.shape.documentRevision.parse(1),
    role,
    state: 'active',
    devices: [keys.certificate],
    createdAt: CREATED_AT,
    updatedAt,
  };
}

function tuple(
  documentRevision: number,
  membershipRevision: number,
  keyEpoch: number,
  registryDigest: Sha256Digest,
  authorizationStateDigest: Sha256Digest,
  databaseDeviceGeneration = 1,
): CollaborationRevisionTuple {
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: 1,
    documentRevision,
    membershipRevision,
    policyRevision: 1,
    keyEpoch,
    databaseDeviceGeneration,
    databaseDeviceRegistryDigest: registryDigest,
    authorizationStateDigest,
  });
}

function aad(
  value: CollaborationRevisionTuple,
  entityType: 'vault-payload' | 'membership-manifest',
): ReturnType<typeof collaborationAadSchema.parse> {
  const metadata = collaborationAadMetadataSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: value.authorityEpoch,
    entityType,
    entityId: VAULT_ID,
    documentRevision: value.documentRevision,
    membershipRevision: value.membershipRevision,
    policyRevision: value.policyRevision,
    keyEpoch: value.keyEpoch,
    databaseDeviceGeneration: value.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: value.databaseDeviceRegistryDigest,
    authorizationStateDigest: value.authorizationStateDigest,
  });
  return collaborationAadSchema.parse({
    ...metadata,
    metadataDigest: computeAadMetadataDigest(metadata),
  });
}

async function memberEnvelope(
  vaultRootKey: VaultRootKey,
  member: CollaborationMembership,
  keys: IdentityKeys,
  membershipRevision: number,
  registryDigest: Sha256Digest,
  owner: IdentityKeys,
  createdAt: string,
  keyEpoch = 1,
  databaseDeviceGeneration = 1,
): Promise<CollaborationKeyEnvelope> {
  const sealedVaultRootKey = await sealVaultRootKeyForDevice(
    vaultRootKey,
    keys.encryption.publicKeyBase64,
  );
  const base = collaborationKeyEnvelopeSchema.parse({
    format: 'kavrix-collaborative-member-key-envelope',
    protocolVersion: 1,
    algorithm: 'x25519-sealed-box',
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    membershipId: member.membershipId,
    principalId: member.principalId,
    deviceId: keys.certificate.deviceId,
    recipientEncryptionKeyFingerprint: computePublicKeyFingerprint(
      keys.encryption.publicKeyBase64,
      'x25519',
    ),
    keyEpoch,
    membershipRevision,
    databaseDeviceGeneration,
    databaseDeviceRegistryDigest: registryDigest,
    sealedVaultRootKey,
    envelopeDigest: PLACEHOLDER_DIGEST,
    createdAt,
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
  recovery: Readonly<{ publicKeyBase64: string }>,
  membershipRevision: number,
  registryDigest: Sha256Digest,
  owner: IdentityKeys,
  createdAt: string,
  keyEpoch = 1,
  databaseDeviceGeneration = 1,
): Promise<DatabaseAuthorityRecoveryEnvelope> {
  const sealedVaultRootKey = await sealVaultRootKeyForDevice(
    vaultRootKey,
    recovery.publicKeyBase64,
  );
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
    keyEpoch,
    membershipRevision,
    databaseDeviceGeneration,
    databaseDeviceRegistryDigest: registryDigest,
    sealedVaultRootKey,
    envelopeDigest: PLACEHOLDER_DIGEST,
    sealedByPrincipalId: owner.certificate.principalId,
    sealedByDeviceId: owner.certificate.deviceId,
    createdAt,
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
  ownerPrincipalIds: readonly string[],
  envelopes: readonly CollaborativeMembershipManifest['keyEnvelopes'][number][],
  membershipRevision: number,
  registryDigest: Sha256Digest,
  keyEpoch = 1,
  databaseDeviceGeneration = 1,
  approvalPolicy: CollaborativeMembershipManifest['approvalPolicy'] = 'none',
): ReturnType<typeof collaborationAuthorizationStateCoreSchema.parse> {
  return collaborationAuthorizationStateCoreSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    databaseDeviceGeneration,
    databaseDeviceRegistryDigest: registryDigest,
    membershipRevision,
    policyRevision: 1,
    keyEpoch,
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
      ...(value.removedAt === undefined ? {} : { removedAt: value.removedAt }),
    })),
    ownerPrincipalIds,
    keyEnvelopes: envelopes.map((envelope) => {
      const core = { ...envelope };
      Reflect.deleteProperty(core, 'envelopeDigest');
      Reflect.deleteProperty(core, 'createdAt');
      Reflect.deleteProperty(core, 'ownerSignature');
      return core;
    }),
    approvalPolicy,
  });
}

async function signedPolicy(
  owner: IdentityKeys,
  registryDigest: Sha256Digest,
  databaseDeviceGeneration = 1,
  changedAt = CREATED_AT,
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
    databaseDeviceGeneration,
    databaseDeviceRegistryDigest: registryDigest,
    changedByPrincipalId: owner.certificate.principalId,
    changedByDeviceId: owner.certificate.deviceId,
    changedAt,
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

async function historyEvent(
  owner: IdentityKeys,
  values: Readonly<{
    operationId: string;
    eventType:
      | 'genesis-created'
      | 'member-added'
      | 'owner-transfer'
      | 'member-removed'
      | 'device-revoked'
      | 'emergency-rekey'
      | 'owner-recovery'
      | 'key-rotated';
    previousTuple: CollaborationRevisionTuple;
    nextTuple: CollaborationRevisionTuple;
    previousHeadDigest: Sha256Digest;
    timestamp: string;
    targetPrincipalId?: string;
    targetDeviceId?: string;
    previousRole?: CollaborationMembership['role'];
    newRole?: CollaborationMembership['role'];
    previousState?: CollaborationMembership['state'];
    newState?: CollaborationMembership['state'];
  }>,
): Promise<ReturnType<typeof membershipHistoryEventSchema.parse>> {
  return signedRecord(
    COLLABORATION_DOMAINS.membershipHistorySignature,
    {
      protocolVersion: 1,
      operationId: values.operationId,
      eventType: values.eventType,
      actorPrincipalId: owner.certificate.principalId,
      actorDeviceId: owner.certificate.deviceId,
      ...(values.targetPrincipalId === undefined
        ? {}
        : { targetPrincipalId: values.targetPrincipalId }),
      ...(values.targetDeviceId === undefined
        ? {}
        : { targetDeviceId: values.targetDeviceId }),
      ...(values.previousRole === undefined
        ? {}
        : { previousRole: values.previousRole }),
      ...(values.newRole === undefined ? {} : { newRole: values.newRole }),
      ...(values.previousState === undefined
        ? {}
        : { previousState: values.previousState }),
      ...(values.newState === undefined ? {} : { newState: values.newState }),
      previousDocumentRevision: values.previousTuple.documentRevision,
      newDocumentRevision: values.nextTuple.documentRevision,
      previousMembershipRevision: values.previousTuple.membershipRevision,
      newMembershipRevision: values.nextTuple.membershipRevision,
      previousPolicyRevision: values.previousTuple.policyRevision,
      newPolicyRevision: values.nextTuple.policyRevision,
      previousKeyEpoch: values.previousTuple.keyEpoch,
      newKeyEpoch: values.nextTuple.keyEpoch,
      previousAuthorityEpoch: values.previousTuple.authorityEpoch,
      newAuthorityEpoch: values.nextTuple.authorityEpoch,
      previousDatabaseDeviceGeneration: values.previousTuple.databaseDeviceGeneration,
      newDatabaseDeviceGeneration: values.nextTuple.databaseDeviceGeneration,
      previousDatabaseDeviceRegistryDigest:
        values.previousTuple.databaseDeviceRegistryDigest,
      newDatabaseDeviceRegistryDigest: values.nextTuple.databaseDeviceRegistryDigest,
      previousAuthorizationStateDigest: values.previousTuple.authorizationStateDigest,
      newAuthorizationStateDigest: values.nextTuple.authorizationStateDigest,
      previousHeadDigest: values.previousHeadDigest,
      timestamp: values.timestamp,
      expiresAt: EXPIRES_AT,
      signature: PLACEHOLDER_SIGNATURE,
    },
    membershipHistoryEventSchema,
    'signature',
    owner.signing.privateKey,
  );
}

async function historyCheckpoint(
  signer: IdentityKeys,
  tupleValue: CollaborationRevisionTuple,
  previousHeadDigest: Sha256Digest,
  options: Readonly<{
    checkpointId?: string;
    signerPrincipalId?: string;
    signerDeviceId?: string;
    createdAt?: string;
  }> = {},
): Promise<ReturnType<typeof membershipHistoryCheckpointSchema.parse>> {
  return signedRecord(
    COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature,
    {
      protocolVersion: 1,
      checkpointId: options.checkpointId ?? 'history-checkpoint-before-denial',
      authorityEpoch: tupleValue.authorityEpoch,
      databaseDeviceGeneration: tupleValue.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: tupleValue.databaseDeviceRegistryDigest,
      membershipRevision: tupleValue.membershipRevision,
      documentRevision: tupleValue.documentRevision,
      policyRevision: tupleValue.policyRevision,
      keyEpoch: tupleValue.keyEpoch,
      previousHeadDigest,
      compactedThroughRevision: 1,
      compactedHistoryDigest: digest(13),
      signerPrincipalId: options.signerPrincipalId ?? signer.certificate.principalId,
      signerDeviceId: options.signerDeviceId ?? signer.certificate.deviceId,
      createdAt: options.createdAt ?? T3,
      signature: PLACEHOLDER_SIGNATURE,
    },
    membershipHistoryCheckpointSchema,
    'signature',
    signer.signing.privateKey,
  );
}

function history(
  events: readonly ReturnType<typeof membershipHistoryEventSchema.parse>[],
  previousHeadDigest: Sha256Digest,
  registryDigest: Sha256Digest,
  databaseDeviceGeneration: number,
  checkpoints: readonly ReturnType<
    typeof membershipHistoryCheckpointSchema.parse
  >[] = [],
  previousHistoryDigest?: Sha256Digest,
): CollaborativeMembershipManifest['history'] {
  const base = {
    protocolVersion: 1 as const,
    databaseId:
      collaborationDatabaseDeviceRegistrySchema.shape.databaseId.parse(DATABASE_ID),
    vaultId: collaborativeVaultDocumentSchema.shape.vaultId.parse(VAULT_ID),
    authorityEpoch: collaborationRevisionTupleSchema.shape.authorityEpoch.parse(1),
    databaseDeviceGeneration:
      collaborationRevisionTupleSchema.shape.databaseDeviceGeneration.parse(
        databaseDeviceGeneration,
      ),
    databaseDeviceRegistryDigest: registryDigest,
    events: [...events],
    checkpoints: [...checkpoints],
    compactedThroughRevision:
      collaborationRevisionTupleSchema.shape.documentRevision.parse(0),
    compactedHistoryDigest: COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
    previousHeadDigest,
    previousHistoryDigest:
      previousHeadDigest === COLLABORATION_GENESIS_HEAD_DIGEST
        ? COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST
        : (previousHistoryDigest ?? digest(12)),
    currentHistoryDigest: PLACEHOLDER_DIGEST,
  };
  return {
    ...base,
    currentHistoryDigest: computeMembershipHistoryDigest(base),
  };
}

function manifestForState(
  input: Readonly<{
    tuple: CollaborationRevisionTuple;
    memberships: readonly CollaborationMembership[];
    ownerPrincipalIds: readonly string[];
    envelopes: readonly CollaborativeMembershipManifest['keyEnvelopes'][number][];
    policy: ReturnType<typeof collaborationPolicyStateSchema.parse>;
    events: readonly ReturnType<typeof membershipHistoryEventSchema.parse>[];
    checkpoints?: readonly ReturnType<typeof membershipHistoryCheckpointSchema.parse>[];
    previousHistoryDigest?: Sha256Digest;
    pendingTransfers?: CollaborativeMembershipManifest['pendingTransfers'];
    approvalPolicy?: CollaborativeMembershipManifest['approvalPolicy'];
    previousMembershipDigest: Sha256Digest;
    previousHeadDigest: Sha256Digest;
    updatedAt: string;
  }>,
): CollaborativeMembershipManifest {
  const manifestHistory = history(
    input.events,
    input.previousHeadDigest,
    input.tuple.databaseDeviceRegistryDigest,
    input.tuple.databaseDeviceGeneration,
    input.checkpoints ?? [],
    input.previousHistoryDigest,
  );
  const base = collaborativeMembershipManifestSchema.parse({
    format: 'kavrix-collaborative-membership-manifest',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: input.tuple.authorityEpoch,
    databaseDeviceGeneration: input.tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: input.tuple.databaseDeviceRegistryDigest,
    documentRevision: input.tuple.documentRevision,
    membershipRevision: input.tuple.membershipRevision,
    policyRevision: input.tuple.policyRevision,
    keyEpoch: input.tuple.keyEpoch,
    authorizationStateDigest: input.tuple.authorizationStateDigest,
    memberships: input.memberships,
    ownerPrincipalIds: input.ownerPrincipalIds,
    keyEnvelopes: input.envelopes,
    approvalPolicy: input.approvalPolicy ?? 'none',
    policy: input.policy,
    pendingApprovals: [],
    pendingTransfers: input.pendingTransfers ?? [],
    history: manifestHistory,
    previousMembershipDigest: input.previousMembershipDigest,
    membershipDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest: input.previousHeadDigest,
    createdAt: CREATED_AT,
    updatedAt: input.updatedAt,
  });
  return collaborativeMembershipManifestSchema.parse({
    ...base,
    membershipDigest: computeMembershipManifestDigest(base),
  });
}

async function discoveryRecord(
  member: CollaborationMembership,
  envelope: CollaborationKeyEnvelope,
  tupleValue: CollaborationRevisionTuple,
  encryptedMembershipDigest: Sha256Digest,
  owner: IdentityKeys,
  updatedAt: string,
): Promise<CollaborationDiscoveryRecord> {
  const base = collaborationDiscoveryRecordSchema.parse({
    format: 'kavrix-collaborative-discovery-record',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: tupleValue.authorityEpoch,
    databaseDeviceGeneration: tupleValue.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tupleValue.databaseDeviceRegistryDigest,
    discoveryTag: computeDiscoveryTag(DATABASE_ID, member.principalFingerprint),
    membershipId: member.membershipId,
    membershipState: 'active',
    keyEpoch: tupleValue.keyEpoch,
    membershipRevision: tupleValue.membershipRevision,
    authorizationStateDigest: tupleValue.authorizationStateDigest,
    encryptedMemberKeyEnvelope: envelope,
    encryptedMembershipMetadataDigest: encryptedMembershipDigest,
    discoveryRecordDigest: PLACEHOLDER_DIGEST,
    signerPrincipalId: owner.certificate.principalId,
    signerDeviceId: owner.certificate.deviceId,
    writerSignature: PLACEHOLDER_SIGNATURE,
    createdAt: CREATED_AT,
    updatedAt,
  });
  const withDigest = collaborationDiscoveryRecordSchema.parse({
    ...base,
    discoveryRecordDigest: computeDiscoveryRecordDigest(base),
  });
  const writerSignature = await signDiscoveryRecord(
    withDigest,
    owner.signing.privateKey,
  );
  return collaborationDiscoveryRecordSchema.parse({
    ...withDigest,
    writerSignature,
  });
}

type PreparedState = Readonly<{
  manifest: CollaborativeMembershipManifest;
  discoveryRecords: readonly CollaborationDiscoveryRecord[];
  encryptedPayload: CollaborativeVaultDocument['encryptedPayload'];
  encryptedMembershipManifest: CollaborativeVaultDocument['encryptedMembershipManifest'];
  encryptedPayloadDigest: Sha256Digest;
  encryptedMembershipDigest: Sha256Digest;
  encryptedEnvelopesDigest: Sha256Digest;
}>;

async function prepareState(
  tupleValue: CollaborationRevisionTuple,
  manifest: CollaborativeMembershipManifest,
  owner: IdentityKeys,
  _recipient: IdentityKeys,
  vaultRootKey: VaultRootKey,
): Promise<PreparedState> {
  const memberEnvelopes = manifest.keyEnvelopes.filter(
    (value): value is CollaborationKeyEnvelope => 'membershipId' in value,
  );
  const encryptedPayload = await encryptCollaborationEnvelope(
    PAYLOAD,
    vaultRootKey,
    aad(tupleValue, 'vault-payload'),
  );
  const manifestBytes = Buffer.from(canonicalJson(manifest), 'utf8');
  try {
    const encryptedMembershipManifest = await encryptCollaborationEnvelope(
      manifestBytes,
      vaultRootKey,
      aad(tupleValue, 'membership-manifest'),
    );
    const encryptedMembershipDigest = computeEncryptedMembershipDigest(
      encryptedMembershipManifest,
    );
    const discoveryRecords = await Promise.all(
      memberEnvelopes.map(async (envelope) => {
        const membership = manifest.memberships.find(
          (value) => value.membershipId === envelope.membershipId,
        );
        if (membership === undefined) {
          throw new Error('Fixture member discovery state is incomplete');
        }
        return discoveryRecord(
          membership,
          envelope,
          tupleValue,
          encryptedMembershipDigest,
          owner,
          manifest.updatedAt,
        );
      }),
    );
    return {
      manifest,
      discoveryRecords,
      encryptedPayload,
      encryptedMembershipManifest,
      encryptedPayloadDigest: computeEncryptedPayloadDigest(encryptedPayload),
      encryptedMembershipDigest,
      encryptedEnvelopesDigest: computeKeyEnvelopeSetDigest(manifest.keyEnvelopes),
    };
  } finally {
    zeroize(manifestBytes);
  }
}

async function signedTransition(
  owner: IdentityKeys,
  input: Readonly<{
    operationId: string;
    operationType:
      | 'genesis-migration'
      | 'add-member'
      | 'add-device'
      | 'transfer-owner'
      | 'remove-member'
      | 'emergency-rekey'
      | 'revoke-device';
    previousTuple: CollaborationRevisionTuple;
    nextTuple: CollaborationRevisionTuple;
    previousHeadDigest: Sha256Digest;
    evidence:
      | Readonly<{ kind: 'none' }>
      | Readonly<{ kind: 'ownership-transfer'; evidenceDigest: Sha256Digest }>;
    issuedAt: string;
    expiresAt?: string;
  }>,
): Promise<ReturnType<typeof collaborationAuthorizationTransitionSchema.parse>> {
  const base = collaborationAuthorizationTransitionSchema.parse({
    format: 'kavrix-collaborative-authorization-transition',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: input.operationId,
    operationType: input.operationType,
    previousHeadDigest: input.previousHeadDigest,
    previousAuthorizationStateDigest: input.previousTuple.authorizationStateDigest,
    authorizationStateDigest: input.nextTuple.authorizationStateDigest,
    previousTuple: input.previousTuple,
    nextTuple: input.nextTuple,
    evidence: input.evidence,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt ?? EXPIRES_AT,
    transitionDigest: PLACEHOLDER_DIGEST,
    transitionSignature: {
      signerKind: 'owner-device',
      signerPrincipalId: owner.certificate.principalId,
      signerDeviceId: owner.certificate.deviceId,
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

async function signedRecoveryTransition(
  authoritySigning: PrincipalSigningKeyPair,
  delegation: CollaborationAuthorityDelegation,
  input: Readonly<{
    previousTuple: CollaborationRevisionTuple;
    nextTuple: CollaborationRevisionTuple;
    previousHeadDigest: Sha256Digest;
    issuedAt: string;
  }>,
): Promise<ReturnType<typeof collaborationAuthorizationTransitionSchema.parse>> {
  const base = collaborationAuthorizationTransitionSchema.parse({
    format: 'kavrix-collaborative-authorization-transition',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: 'operation-recover-owner',
    operationType: 'recover-owner',
    previousHeadDigest: input.previousHeadDigest,
    previousAuthorizationStateDigest: input.previousTuple.authorizationStateDigest,
    authorizationStateDigest: input.nextTuple.authorizationStateDigest,
    previousTuple: input.previousTuple,
    nextTuple: input.nextTuple,
    evidence: { kind: 'authority-recovery', evidenceDigest: digest(91) },
    issuedAt: input.issuedAt,
    expiresAt: EXPIRES_AT,
    transitionDigest: PLACEHOLDER_DIGEST,
    transitionSignature: {
      signerKind: 'database-authority',
      authorityEpoch: delegation.authorityEpoch,
      authoritySigningKeyFingerprint: delegation.authoritySigningKeyFingerprint,
      signature: PLACEHOLDER_SIGNATURE,
    },
  });
  const withDigest = collaborationAuthorizationTransitionSchema.parse({
    ...base,
    transitionDigest: computeAuthorizationTransitionDigest(base),
  });
  const signature = await signAuthorizationTransitionAuthority(
    withDigest,
    authoritySigning.privateKey,
  );
  return collaborationAuthorizationTransitionSchema.parse({
    ...withDigest,
    transitionSignature: { ...withDigest.transitionSignature, signature },
  });
}

async function finalizedLink(
  input: Readonly<{
    operationId: string;
    operationType:
      | 'genesis-migration'
      | 'ordinary-write'
      | 'add-member'
      | 'add-device'
      | 'transfer-owner'
      | 'remove-member'
      | 'emergency-rekey'
      | 'recover-owner'
      | 'revoke-device';
    previousTuple: CollaborationRevisionTuple;
    nextTuple: CollaborationRevisionTuple;
    previousHeadDigest: Sha256Digest;
    prepared: PreparedState;
    policyDigest: Sha256Digest;
    delegationDigest: Sha256Digest;
    writer: IdentityKeys;
    timestamp: string;
    transition?: ReturnType<typeof collaborationAuthorizationTransitionSchema.parse>;
  }>,
): Promise<CollaborationFinalizedMutationLink> {
  const commitmentBase = collaborationMutationCommitmentSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: input.operationId,
    operationType: input.operationType,
    requestDigest: PLACEHOLDER_DIGEST,
    previousHeadDigest: input.previousHeadDigest,
    previousAuthorizationStateDigest: input.previousTuple.authorizationStateDigest,
    authorizationStateDigest: input.nextTuple.authorizationStateDigest,
    ...(input.transition === undefined
      ? {}
      : { authorizationTransitionDigest: input.transition.transitionDigest }),
    previousAuthorityEpoch: input.previousTuple.authorityEpoch,
    previousDocumentRevision: input.previousTuple.documentRevision,
    previousMembershipRevision: input.previousTuple.membershipRevision,
    previousPolicyRevision: input.previousTuple.policyRevision,
    previousKeyEpoch: input.previousTuple.keyEpoch,
    previousDatabaseDeviceGeneration: input.previousTuple.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest:
      input.previousTuple.databaseDeviceRegistryDigest,
    authorityEpoch: input.nextTuple.authorityEpoch,
    documentRevision: input.nextTuple.documentRevision,
    membershipRevision: input.nextTuple.membershipRevision,
    policyRevision: input.nextTuple.policyRevision,
    keyEpoch: input.nextTuple.keyEpoch,
    databaseDeviceGeneration: input.nextTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: input.nextTuple.databaseDeviceRegistryDigest,
    encryptedPayloadDigest: input.prepared.encryptedPayloadDigest,
    encryptedMembershipDigest: input.prepared.encryptedMembershipDigest,
    encryptedEnvelopesDigest: input.prepared.encryptedEnvelopesDigest,
    policyDigest: input.policyDigest,
    writerPrincipalId: input.writer.certificate.principalId,
    writerDeviceId: input.writer.certificate.deviceId,
    timestamp: input.timestamp,
    ...(input.transition === undefined
      ? {}
      : { expiresAt: input.transition.expiresAt }),
  });
  const commitment = collaborationMutationCommitmentSchema.parse({
    ...commitmentBase,
    requestDigest:
      input.operationType === 'genesis-migration'
        ? digest(20 + input.nextTuple.documentRevision)
        : computeMutationRequestDigest(commitmentBase),
  });
  const headDigest = computeMutationHead(commitment);
  const base = collaborationFinalizedMutationLinkSchema.parse({
    format: 'kavrix-collaborative-finalized-mutation-link',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityDelegationDigest: input.delegationDigest,
    commitment,
    ...(input.transition === undefined
      ? {}
      : { authorizationTransition: input.transition }),
    resultingHeadDigest: headDigest,
    writerSignature: {
      algorithm: 'ed25519',
      writerPrincipalId: input.writer.certificate.principalId,
      writerDeviceId: input.writer.certificate.deviceId,
      commitmentDigest: headDigest,
      signature: PLACEHOLDER_SIGNATURE,
    },
    finalizedAt: input.timestamp,
  });
  const signature = await signFinalizedMutationLink(
    base,
    input.writer.signing.privateKey,
  );
  return collaborationFinalizedMutationLinkSchema.parse({
    ...base,
    writerSignature: { ...base.writerSignature, signature },
  });
}

function documentAndWitness(
  input: Readonly<{
    tuple: CollaborationRevisionTuple;
    databaseDeviceRegistry: CollaborationDatabaseDeviceRegistry;
    previousHeadDigest: Sha256Digest;
    delegation: CollaborationAuthorityDelegation;
    delegationDigest: Sha256Digest;
    prepared: PreparedState;
    link: CollaborationFinalizedMutationLink;
    policyDigest: Sha256Digest;
    updatedAt: string;
  }>,
): Pick<BuiltState, 'document' | 'witness'> {
  const document = collaborativeVaultDocumentSchema.parse({
    format: 'kavrix-collaborative-vault',
    documentVersion: 1,
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: input.tuple.authorityEpoch,
    databaseDeviceGeneration: input.tuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: input.tuple.databaseDeviceRegistryDigest,
    documentRevision: input.tuple.documentRevision,
    membershipRevision: input.tuple.membershipRevision,
    policyRevision: input.tuple.policyRevision,
    keyEpoch: input.tuple.keyEpoch,
    previousHeadDigest: input.previousHeadDigest,
    headDigest: input.link.resultingHeadDigest,
    authorityDelegation: input.delegation,
    authorityDelegationDigest: input.delegationDigest,
    authorizationStateDigest: input.tuple.authorizationStateDigest,
    encryptedPayloadDigest: input.prepared.encryptedPayloadDigest,
    encryptedMembershipDigest: input.prepared.encryptedMembershipDigest,
    encryptedEnvelopesDigest: input.prepared.encryptedEnvelopesDigest,
    policyDigest: input.policyDigest,
    databaseAuthorityRecoveryEnvelope: input.prepared.manifest.keyEnvelopes.find(
      (envelope) => !('membershipId' in envelope),
    ),
    encryptedPayload: input.prepared.encryptedPayload,
    encryptedMembershipManifest: input.prepared.encryptedMembershipManifest,
    discoveryRecords: input.prepared.discoveryRecords,
    currentMutationLink: input.link,
    createdAt: CREATED_AT,
    updatedAt: input.updatedAt,
  });
  const witness = collaborationAuthorizationWitnessSchema.parse({
    format: 'kavrix-collaborative-authorization-witness',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityDelegationDigest: input.delegationDigest,
    tuple: input.tuple,
    previousHeadDigest: input.previousHeadDigest,
    headDigest: input.link.resultingHeadDigest,
    encryptedMembershipDigest: input.prepared.encryptedMembershipDigest,
    encryptedEnvelopesDigest: input.prepared.encryptedEnvelopesDigest,
    policyDigest: input.policyDigest,
    databaseDeviceRegistry: input.databaseDeviceRegistry,
    databaseAuthorityRecoveryEnvelope: document.databaseAuthorityRecoveryEnvelope,
    encryptedMembershipManifest: input.prepared.encryptedMembershipManifest,
    discoveryRecords: input.prepared.discoveryRecords,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(input.link),
  });
  return { document, witness };
}

async function authorityRegistry(
  authority: PrincipalSigningKeyPair,
  deniedDevices: CollaborationDatabaseDeviceRegistry['deniedDevices'] = [],
  options: Readonly<{
    generation: number;
    previousRegistryDigest: Sha256Digest;
    updatedAt: string;
  }> = {
    generation: 1,
    previousRegistryDigest: digest(30),
    updatedAt: NOW,
  },
): Promise<CollaborationDatabaseDeviceRegistry> {
  const authorityFingerprint = computePublicKeyFingerprint(
    authority.publicKeyBase64,
    'ed25519',
  );
  const base = collaborationDatabaseDeviceRegistrySchema.parse({
    format: 'kavrix-collaborative-device-registry',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    authorityEpoch: 1,
    authorityFingerprint,
    generation: options.generation,
    previousRegistryDigest: options.previousRegistryDigest,
    registryDigest: PLACEHOLDER_DIGEST,
    deniedDevices,
    updatedAt: options.updatedAt,
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

async function transferIntentForState(
  owner: IdentityKeys,
  recipient: IdentityKeys,
  priorTuple: CollaborationRevisionTuple,
  priorHeadDigest: Sha256Digest,
): Promise<ReturnType<typeof transferIntentSchema.parse>> {
  const base = transferIntentSchema.parse({
    format: 'kavrix-collaborative-transfer-intent',
    protocolVersion: 1,
    transferIntentId: 'transfer-owner-1',
    operationId: 'operation-transfer-owner',
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    initiatorPrincipalId: OWNER_ID,
    initiatorDeviceId: OWNER_DEVICE_ID,
    recipientPrincipalId: RECIPIENT_ID,
    recipientDeviceId: RECIPIENT_DEVICE_ID,
    targetRole: 'owner',
    originalOwnerDisposition: 'remain-owner',
    authorityEpoch: priorTuple.authorityEpoch,
    databaseDeviceGeneration: priorTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: priorTuple.databaseDeviceRegistryDigest,
    documentRevision: priorTuple.documentRevision,
    membershipRevision: priorTuple.membershipRevision,
    policyRevision: priorTuple.policyRevision,
    keyEpoch: priorTuple.keyEpoch,
    currentHeadDigest: priorHeadDigest,
    authorizationStateDigest: priorTuple.authorizationStateDigest,
    intentDigest: PLACEHOLDER_DIGEST,
    state: 'published',
    createdAt: T2,
    expiresAt: EXPIRES_AT,
    initiatorSignedAt: T2,
    initiatorSignature: PLACEHOLDER_SIGNATURE,
    recipientAcceptance: {
      protocolVersion: 1,
      transferIntentId: 'transfer-owner-1',
      operationId: 'operation-transfer-owner',
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      intentDigest: PLACEHOLDER_DIGEST,
      authorityEpoch: priorTuple.authorityEpoch,
      databaseDeviceGeneration: priorTuple.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: priorTuple.databaseDeviceRegistryDigest,
      authorizationStateDigest: priorTuple.authorizationStateDigest,
      recipientPrincipalId: RECIPIENT_ID,
      recipientDeviceId: RECIPIENT_DEVICE_ID,
      acceptedAt: T2,
      signature: PLACEHOLDER_SIGNATURE,
    },
    publishedAt: T3,
  });
  const intentDigest = computeTransferIntentDigest(base);
  const withDigest = transferIntentSchema.parse({
    ...base,
    intentDigest,
    recipientAcceptance: { ...base.recipientAcceptance, intentDigest },
  });
  const initiatorSignature = await signTransferIntent(
    withDigest,
    owner.signing.privateKey,
  );
  const acceptanceBase = ownershipTransferAcceptanceSchema.parse({
    ...withDigest.recipientAcceptance,
    signature: PLACEHOLDER_SIGNATURE,
  });
  const acceptanceSignature = await signOwnershipTransferAcceptance(
    acceptanceBase,
    recipient.signing.privateKey,
  );
  return transferIntentSchema.parse({
    ...withDigest,
    initiatorSignature,
    recipientAcceptance: {
      ...acceptanceBase,
      signature: acceptanceSignature,
    },
  });
}

async function buildFixture(
  denial: 'none' | 'recipient-device' | 'owner-signing-fingerprint' = 'none',
  checkpointScenario: GenesisHistoryCheckpointScenario = 'none',
  eventScenario: GenesisHistoryEventScenario = 'normal',
): Promise<Fixture> {
  const authoritySigning = await generatePrincipalSigningKeyPair();
  const databaseRootKey = generateDatabaseRootKey();
  const authorityRecovery = await deriveDatabaseAuthorityRecoveryKeyPair(
    databaseRootKey,
    DATABASE_ID,
    1,
  );
  const owner = await identityKeys(OWNER_ID, OWNER_DEVICE_ID);
  const recipient = await identityKeys(RECIPIENT_ID, RECIPIENT_DEVICE_ID);
  const vaultRootKey = generateVaultRootKey();
  const deviceProtectionSecret = Uint8Array.from(
    { length: 32 },
    (_, index) => (index * 17 + 5) & 0xff,
  );
  const deniedDevices: CollaborationDatabaseDeviceRegistry['deniedDevices'] =
    denial === 'recipient-device'
      ? [
          {
            principalId: recipient.certificate.principalId,
            deviceId: recipient.certificate.deviceId,
            deviceGeneration: recipient.certificate.deviceGeneration,
            signingKeyFingerprint: digest(31),
            reason: 'revoked',
            deniedAt: NOW,
          },
        ]
      : denial === 'owner-signing-fingerprint'
        ? [
            {
              principalId: recipient.certificate.principalId,
              deviceId: recipient.certificate.deviceId,
              deviceGeneration: recipient.certificate.deviceGeneration,
              signingKeyFingerprint: computePublicKeyFingerprint(
                owner.signing.publicKeyBase64,
                'ed25519',
              ),
              reason: 'compromised',
              deniedAt: NOW,
            },
          ]
        : [];
  const registry = await authorityRegistry(authoritySigning, deniedDevices);
  const policy = await signedPolicy(owner, registry.registryDigest);

  const genesisOwnerMembership = membership(
    owner,
    OWNER_ID,
    OWNER_MEMBERSHIP_ID,
    'owner',
    T1,
  );
  const genesisMemberships = [genesisOwnerMembership] as const;
  const genesisEnvelopes = [
    await memberEnvelope(
      vaultRootKey,
      genesisOwnerMembership,
      owner,
      1,
      registry.registryDigest,
      owner,
      T1,
    ),
    await recoveryEnvelope(
      vaultRootKey,
      authorityRecovery,
      1,
      registry.registryDigest,
      owner,
      T1,
    ),
  ] as const;
  const genesisAuthorizationDigest = computeAuthorizationStateDigest(
    authorizationCore(
      genesisMemberships,
      [OWNER_ID],
      genesisEnvelopes,
      1,
      registry.registryDigest,
    ),
  );
  const genesisPreviousTuple = collaborationRevisionTupleSchema.parse({
    authorityEpoch: 1,
    documentRevision: 0,
    membershipRevision: 0,
    policyRevision: 0,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registry.registryDigest,
    authorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  });
  const genesisTuple = tuple(
    1,
    1,
    1,
    registry.registryDigest,
    genesisAuthorizationDigest,
  );
  const genesisEvent = await historyEvent(owner, {
    operationId: 'operation-genesis',
    eventType: 'genesis-created',
    previousTuple: genesisPreviousTuple,
    nextTuple: genesisTuple,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    timestamp: eventScenario === 'pre-creation' ? '2026-08-28T23:59:00.000Z' : T1,
  });
  const preDenialCheckpoint = await historyCheckpoint(
    owner,
    genesisTuple,
    COLLABORATION_GENESIS_HEAD_DIGEST,
    { createdAt: T1 },
  );
  const genesisHistoryCheckpoints = [
    ...(checkpointScenario === 'none'
      ? []
      : [
          await historyCheckpoint(
            checkpointScenario === 'reader-signer' ||
              checkpointScenario === 'key-substitution'
              ? recipient
              : owner,
            genesisTuple,
            COLLABORATION_GENESIS_HEAD_DIGEST,
            {
              checkpointId: `history-checkpoint-${checkpointScenario}`,
              ...(checkpointScenario === 'wrong-signer-ids'
                ? {
                    signerPrincipalId: 'principal-unknown',
                    signerDeviceId: 'device-unknown',
                  }
                : checkpointScenario === 'key-substitution'
                  ? {
                      signerPrincipalId: owner.certificate.principalId,
                      signerDeviceId: owner.certificate.deviceId,
                    }
                  : {}),
              createdAt:
                checkpointScenario === 'pre-creation' ? '2026-08-28T23:59:00.000Z' : T1,
            },
          ),
        ]),
    preDenialCheckpoint,
  ];
  const genesisManifest = manifestForState({
    tuple: genesisTuple,
    memberships: genesisMemberships,
    ownerPrincipalIds: [OWNER_ID],
    envelopes: genesisEnvelopes,
    policy,
    events: [genesisEvent],
    checkpoints: genesisHistoryCheckpoints,
    previousMembershipDigest: COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    updatedAt: T1,
  });
  const preparedGenesis = await prepareState(
    genesisTuple,
    genesisManifest,
    owner,
    owner,
    vaultRootKey,
  );
  const genesisTransition = await signedTransition(owner, {
    operationId: 'operation-genesis',
    operationType: 'genesis-migration',
    previousTuple: genesisPreviousTuple,
    nextTuple: genesisTuple,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    evidence: { kind: 'none' },
    issuedAt: T1,
  });
  const temporaryGenesisLink = await finalizedLink({
    operationId: 'operation-genesis',
    operationType: 'genesis-migration',
    previousTuple: genesisPreviousTuple,
    nextTuple: genesisTuple,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    prepared: preparedGenesis,
    policyDigest: policy.policyDigest,
    delegationDigest: digest(42),
    writer: owner,
    timestamp: T1,
    transition: genesisTransition,
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
    genesisHeadDigest: temporaryGenesisLink.resultingHeadDigest,
    initialAuthorizationStateDigest: genesisTuple.authorizationStateDigest,
    initialOwnerPrincipalId: OWNER_ID,
    initialOwnerRootKeyFingerprint: computePublicKeyFingerprint(
      owner.root.publicKeyBase64,
      'ed25519',
    ),
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
  const delegationSignature = await signAuthorityDelegation(
    delegationBase,
    authoritySigning.privateKey,
  );
  const delegation = collaborationAuthorityDelegationSchema.parse({
    ...delegationBase,
    authoritySignature: delegationSignature,
  });
  const delegationDigest = computeAuthorityDelegationDigest(delegation);
  const genesisLink = await finalizedLink({
    operationId: 'operation-genesis',
    operationType: 'genesis-migration',
    previousTuple: genesisPreviousTuple,
    nextTuple: genesisTuple,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    prepared: preparedGenesis,
    policyDigest: policy.policyDigest,
    delegationDigest,
    writer: owner,
    timestamp: T1,
    transition: genesisTransition,
  });
  const genesisDocuments = documentAndWitness({
    tuple: genesisTuple,
    databaseDeviceRegistry: registry,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    delegation,
    delegationDigest,
    prepared: preparedGenesis,
    link: genesisLink,
    policyDigest: policy.policyDigest,
    updatedAt: T1,
  });
  const genesisState: BuiltState = {
    tuple: genesisTuple,
    ...preparedGenesis,
    link: genesisLink,
    ...genesisDocuments,
  };

  const ownerMembership1 = membership(
    owner,
    OWNER_ID,
    OWNER_MEMBERSHIP_ID,
    'owner',
    T1,
  );
  const recipientMembership1 = membership(
    recipient,
    RECIPIENT_ID,
    RECIPIENT_MEMBERSHIP_ID,
    'reader',
    T1,
  );
  const memberships1 = [ownerMembership1, recipientMembership1] as const;
  const envelopes1 = [
    await memberEnvelope(
      vaultRootKey,
      ownerMembership1,
      owner,
      2,
      registry.registryDigest,
      owner,
      T1,
      2,
    ),
    await memberEnvelope(
      vaultRootKey,
      recipientMembership1,
      recipient,
      2,
      registry.registryDigest,
      owner,
      T1,
      2,
    ),
    await recoveryEnvelope(
      vaultRootKey,
      authorityRecovery,
      2,
      registry.registryDigest,
      owner,
      T1,
      2,
    ),
  ] as const;
  const state1AuthorizationDigest = computeAuthorizationStateDigest(
    authorizationCore(
      memberships1,
      [OWNER_ID],
      envelopes1,
      2,
      registry.registryDigest,
      2,
    ),
  );
  const tuple1 = tuple(2, 2, 2, registry.registryDigest, state1AuthorizationDigest);
  const addMemberEvent = await historyEvent(owner, {
    operationId: 'operation-add-member',
    eventType: 'member-added',
    previousTuple: genesisTuple,
    nextTuple: tuple1,
    previousHeadDigest: genesisLink.resultingHeadDigest,
    timestamp: T1,
    targetPrincipalId: RECIPIENT_ID,
  });
  const manifest1 = manifestForState({
    tuple: tuple1,
    memberships: memberships1,
    ownerPrincipalIds: [OWNER_ID],
    envelopes: envelopes1,
    policy,
    events: [genesisEvent, addMemberEvent],
    checkpoints: genesisHistoryCheckpoints,
    previousHistoryDigest: genesisManifest.history.currentHistoryDigest,
    previousMembershipDigest: genesisManifest.membershipDigest,
    previousHeadDigest: genesisLink.resultingHeadDigest,
    updatedAt: T1,
  });
  const prepared1 = await prepareState(
    tuple1,
    manifest1,
    owner,
    recipient,
    vaultRootKey,
  );
  const transition1 = await signedTransition(owner, {
    operationId: 'operation-add-member',
    operationType: 'add-member',
    previousTuple: genesisTuple,
    nextTuple: tuple1,
    previousHeadDigest: genesisLink.resultingHeadDigest,
    evidence: { kind: 'none' },
    issuedAt: T1,
  });
  const link1 = await finalizedLink({
    operationId: 'operation-add-member',
    operationType: 'add-member',
    previousTuple: genesisTuple,
    nextTuple: tuple1,
    previousHeadDigest: genesisLink.resultingHeadDigest,
    prepared: prepared1,
    policyDigest: policy.policyDigest,
    delegationDigest,
    writer: owner,
    timestamp: T1,
    transition: transition1,
  });
  const state1Documents = documentAndWitness({
    tuple: tuple1,
    databaseDeviceRegistry: registry,
    previousHeadDigest: genesisLink.resultingHeadDigest,
    delegation,
    delegationDigest,
    prepared: prepared1,
    link: link1,
    policyDigest: policy.policyDigest,
    updatedAt: T1,
  });
  const state1: BuiltState = {
    tuple: tuple1,
    ...prepared1,
    link: link1,
    ...state1Documents,
  };

  const tuple2 = tuple(3, 2, 2, registry.registryDigest, state1AuthorizationDigest);
  const manifest2 = manifestForState({
    tuple: tuple2,
    memberships: memberships1,
    ownerPrincipalIds: [OWNER_ID],
    envelopes: envelopes1,
    policy,
    events: [genesisEvent, addMemberEvent],
    checkpoints: genesisHistoryCheckpoints,
    previousHistoryDigest: manifest1.history.currentHistoryDigest,
    previousMembershipDigest: manifest1.membershipDigest,
    previousHeadDigest: link1.resultingHeadDigest,
    updatedAt: T2,
  });
  const prepared2 = await prepareState(
    tuple2,
    manifest2,
    owner,
    recipient,
    vaultRootKey,
  );
  const link2 = await finalizedLink({
    operationId: 'operation-write-2',
    operationType: 'ordinary-write',
    previousTuple: tuple1,
    nextTuple: tuple2,
    previousHeadDigest: link1.resultingHeadDigest,
    prepared: prepared2,
    policyDigest: policy.policyDigest,
    delegationDigest,
    writer: owner,
    timestamp: T2,
  });
  const state2Documents = documentAndWitness({
    tuple: tuple2,
    databaseDeviceRegistry: registry,
    previousHeadDigest: link1.resultingHeadDigest,
    delegation,
    delegationDigest,
    prepared: prepared2,
    link: link2,
    policyDigest: policy.policyDigest,
    updatedAt: T2,
  });
  const state2: BuiltState = {
    tuple: tuple2,
    ...prepared2,
    link: link2,
    ...state2Documents,
  };

  const ownerMembership3 = membership(
    owner,
    OWNER_ID,
    OWNER_MEMBERSHIP_ID,
    'owner',
    T3,
  );
  const recipientMembership3 = membership(
    recipient,
    RECIPIENT_ID,
    RECIPIENT_MEMBERSHIP_ID,
    'owner',
    T3,
  );
  const memberships3 = [ownerMembership3, recipientMembership3] as const;
  const envelopes3 = [
    await memberEnvelope(
      vaultRootKey,
      ownerMembership3,
      owner,
      3,
      registry.registryDigest,
      owner,
      T3,
      2,
    ),
    await memberEnvelope(
      vaultRootKey,
      recipientMembership3,
      recipient,
      3,
      registry.registryDigest,
      owner,
      T3,
      2,
    ),
    await recoveryEnvelope(
      vaultRootKey,
      authorityRecovery,
      3,
      registry.registryDigest,
      owner,
      T3,
      2,
    ),
  ] as const;
  const state3AuthorizationDigest = computeAuthorizationStateDigest(
    authorizationCore(
      memberships3,
      [OWNER_ID, RECIPIENT_ID],
      envelopes3,
      3,
      registry.registryDigest,
      2,
    ),
  );
  const tuple3 = tuple(4, 3, 2, registry.registryDigest, state3AuthorizationDigest);
  const transferIntent = await transferIntentForState(
    owner,
    recipient,
    tuple2,
    link2.resultingHeadDigest,
  );
  const transferEvent = await historyEvent(owner, {
    operationId: 'operation-transfer-owner',
    eventType: 'owner-transfer',
    previousTuple: tuple2,
    nextTuple: tuple3,
    previousHeadDigest: link2.resultingHeadDigest,
    timestamp: T3,
    targetPrincipalId: RECIPIENT_ID,
    previousRole: 'reader',
    newRole: 'owner',
  });
  const manifest3 = manifestForState({
    tuple: tuple3,
    memberships: memberships3,
    ownerPrincipalIds: [OWNER_ID, RECIPIENT_ID],
    envelopes: envelopes3,
    policy,
    events: [genesisEvent, addMemberEvent, transferEvent],
    checkpoints: manifest2.history.checkpoints,
    previousHistoryDigest: manifest2.history.currentHistoryDigest,
    pendingTransfers: [transferIntent],
    previousMembershipDigest: manifest2.membershipDigest,
    previousHeadDigest: link2.resultingHeadDigest,
    updatedAt: T3,
  });
  const prepared3 = await prepareState(
    tuple3,
    manifest3,
    owner,
    recipient,
    vaultRootKey,
  );
  const transition3 = await signedTransition(owner, {
    operationId: 'operation-transfer-owner',
    operationType: 'transfer-owner',
    previousTuple: tuple2,
    nextTuple: tuple3,
    previousHeadDigest: link2.resultingHeadDigest,
    evidence: {
      kind: 'ownership-transfer',
      evidenceDigest: transferIntent.intentDigest,
    },
    issuedAt: T3,
  });
  const link3 = await finalizedLink({
    operationId: 'operation-transfer-owner',
    operationType: 'transfer-owner',
    previousTuple: tuple2,
    nextTuple: tuple3,
    previousHeadDigest: link2.resultingHeadDigest,
    prepared: prepared3,
    policyDigest: policy.policyDigest,
    delegationDigest,
    writer: owner,
    timestamp: T3,
    transition: transition3,
  });
  const state3Documents = documentAndWitness({
    tuple: tuple3,
    databaseDeviceRegistry: registry,
    previousHeadDigest: link2.resultingHeadDigest,
    delegation,
    delegationDigest,
    prepared: prepared3,
    link: link3,
    policyDigest: policy.policyDigest,
    updatedAt: T3,
  });
  const state3: BuiltState = {
    tuple: tuple3,
    ...prepared3,
    link: link3,
    ...state3Documents,
  };

  const checkpointBase = collaborationAuthorizationCheckpointSchema.parse({
    format: 'kavrix-collaborative-authorization-checkpoint',
    protocolVersion: 1,
    checkpointId: 'checkpoint-enrollment',
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityDelegationDigest: delegationDigest,
    tuple: tuple1,
    headDigest: link1.resultingHeadDigest,
    authorizationStateDigest: tuple1.authorizationStateDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(link1),
    compactedThroughDocumentRevision: tuple1.documentRevision,
    checkpointDigest: PLACEHOLDER_DIGEST,
    signerPrincipalId: OWNER_ID,
    signerDeviceId: OWNER_DEVICE_ID,
    createdAt: T1,
    ownerSignature: PLACEHOLDER_SIGNATURE,
  });
  const checkpointWithDigest = collaborationAuthorizationCheckpointSchema.parse({
    ...checkpointBase,
    checkpointDigest: computeAuthorizationCheckpointDigest(checkpointBase),
  });
  const checkpointSignature = await signAuthorizationCheckpoint(
    checkpointWithDigest,
    owner.signing.privateKey,
  );
  const checkpoint = collaborationAuthorizationCheckpointSchema.parse({
    ...checkpointWithDigest,
    ownerSignature: checkpointSignature,
  });
  const receiptDiscovery = prepared1.discoveryRecords.find(
    (record) => record.membershipId === recipientMembership1.membershipId,
  );
  if (receiptDiscovery === undefined)
    throw new Error('Receipt discovery fixture missing');
  const receiptBase = enrollmentReceiptSchema.parse({
    format: 'kavrix-collaborative-enrollment-receipt',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    operationType: 'add-member',
    authorityDelegation: delegation,
    authorityDelegationDigest: delegationDigest,
    ownerPrincipalId: OWNER_ID,
    ownerPrincipalFingerprint: ownerMembership1.principalFingerprint,
    ownerRootSigningPublicKey: owner.root.publicKeyBase64,
    ownerDeviceCertificate: owner.certificate,
    recipientPrincipalId: RECIPIENT_ID,
    recipientPrincipalFingerprint: recipientMembership1.principalFingerprint,
    recipientPublicIdentity: recipient.identity,
    recipientDeviceId: RECIPIENT_DEVICE_ID,
    recipientDeviceFingerprints: [
      computeDeviceCertificateFingerprint(recipient.certificate),
    ],
    membershipId: RECIPIENT_MEMBERSHIP_ID,
    role: 'reader',
    discoveryTag: receiptDiscovery.discoveryTag,
    discoveryRecordDigest: receiptDiscovery.discoveryRecordDigest,
    memberKeyEnvelopeDigest: receiptDiscovery.encryptedMemberKeyEnvelope.envelopeDigest,
    databaseDeviceGeneration: tuple1.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: tuple1.databaseDeviceRegistryDigest,
    documentRevision: tuple1.documentRevision,
    membershipRevision: tuple1.membershipRevision,
    policyRevision: tuple1.policyRevision,
    keyEpoch: tuple1.keyEpoch,
    headDigest: link1.resultingHeadDigest,
    authorizationStateDigest: tuple1.authorizationStateDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(link1),
    authorizationCheckpointDigest: checkpoint.checkpointDigest,
    issuedAt: T1,
    expiresAt: EXPIRES_AT,
    ownerSignature: PLACEHOLDER_SIGNATURE,
  });
  const receiptSignature = await signEnrollmentReceipt(
    receiptBase,
    owner.signing.privateKey,
  );
  const receipt = enrollmentReceiptSchema.parse({
    ...receiptBase,
    ownerSignature: receiptSignature,
  });
  const proof1To2 = collaborationMutationProofSchema.parse({
    format: 'kavrix-collaborative-mutation-proof',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityDelegationDigest: delegationDigest,
    fromDocumentRevision: tuple1.documentRevision,
    fromHeadDigest: link1.resultingHeadDigest,
    toDocumentRevision: tuple2.documentRevision,
    toHeadDigest: link2.resultingHeadDigest,
    startingAuthorizationWitness: state1.witness,
    entries: [{ link: link2 }],
  });
  const proof1To3 = collaborationMutationProofSchema.parse({
    format: 'kavrix-collaborative-mutation-proof',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityDelegationDigest: delegationDigest,
    fromDocumentRevision: tuple1.documentRevision,
    fromHeadDigest: link1.resultingHeadDigest,
    toDocumentRevision: tuple3.documentRevision,
    toHeadDigest: link3.resultingHeadDigest,
    startingAuthorizationWitness: state1.witness,
    entries: [{ link: link2 }, { link: link3, authorizationWitness: state3.witness }],
  });
  const genesisProofTo3 = collaborationMutationProofSchema.parse({
    format: 'kavrix-collaborative-mutation-proof',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityDelegationDigest: delegationDigest,
    fromDocumentRevision: genesisTuple.documentRevision,
    fromHeadDigest: genesisLink.resultingHeadDigest,
    toDocumentRevision: tuple3.documentRevision,
    toHeadDigest: link3.resultingHeadDigest,
    startingAuthorizationWitness: genesisState.witness,
    entries: [
      { link: link1, authorizationWitness: state1.witness },
      { link: link2 },
      { link: link3, authorizationWitness: state3.witness },
    ],
  });
  const fixture: Fixture = {
    registry,
    delegation,
    receipt,
    checkpoint,
    genesisState,
    state1,
    state2,
    state3,
    proof1To2,
    proof1To3,
    genesisProofTo3,
    owner,
    recipient,
    authoritySigning,
    authorityRecovery,
    databaseRootKey,
    vaultRootKey,
    deviceProtectionSecret,
    trust: {
      authorityDelegation: delegation,
      principalPublicIdentities: [owner.identity, recipient.identity],
    },
    scope: {
      databaseId: receipt.databaseId,
      vaultId: receipt.vaultId,
      principalId: receipt.recipientPrincipalId,
      deviceId: receipt.recipientDeviceId,
    },
  };
  fixtures.push(fixture);
  return fixture;
}

function firstInput(
  fixture: Fixture,
  state: BuiltState = fixture.state1,
  proof?: CollaborationMutationProof,
  path = anchorPath(),
): EnrollAndOpenCollaborativeVaultInput {
  return {
    document: state.document,
    authoritativeDeviceRegistry: fixture.registry,
    ...(proof === undefined ? {} : { mutationProof: proof }),
    scope: fixture.scope,
    recipientEncryptionPrivateKey: fixture.recipient.encryption.privateKey,
    deviceProtectionSecret: fixture.deviceProtectionSecret,
    rollbackAnchorPath: path,
    now: NOW,
    enrollmentReceipt: fixture.receipt,
    enrollmentCheckpoint: fixture.checkpoint,
  };
}

function pinnedInput(
  fixture: Fixture,
  state: BuiltState,
  proof?: CollaborationMutationProof,
  path = anchorPath(),
  registry = fixture.registry,
): Parameters<typeof openCollaborativeVaultWithPinnedTrust>[0] {
  return {
    document: state.document,
    authoritativeDeviceRegistry: registry,
    ...(proof === undefined ? {} : { mutationProof: proof }),
    scope: fixture.scope,
    recipientEncryptionPrivateKey: fixture.recipient.encryption.privateKey,
    deviceProtectionSecret: fixture.deviceProtectionSecret,
    rollbackAnchorPath: path,
    now: NOW,
    trusted: fixture.trust,
  };
}

async function journalSuccessorInput(
  fixture: Fixture,
  name: string,
): Promise<Parameters<typeof verifyCollaborativeJournalSuccessorChain>[0]> {
  const path = anchorPath(name);
  const enrolled = await enrollAndOpenCollaborativeVault(
    firstInput(fixture, fixture.state1, undefined, path),
  );
  releaseOpened(enrolled);
  const candidate = await openCollaborativeVaultWithPinnedTrust(
    pinnedInput(fixture, fixture.state2, fixture.proof1To2, path),
  );
  releaseOpened(candidate);
  const candidateAnchor = await readRecipientRollbackAnchor(
    path,
    fixture.deviceProtectionSecret,
    { expectedScope: fixture.scope },
  );
  const journalProofEntry = fixture.proof1To3.entries[0];
  if (journalProofEntry === undefined) throw new Error('Journal proof entry missing');
  return {
    currentDocument: fixture.state3.document,
    authoritativeDeviceRegistry: fixture.registry,
    mutationProof: fixture.proof1To3,
    trusted: fixture.trust,
    scope: fixture.scope,
    journalCandidate: fixture.state2.document,
    journalCandidateAnchor: candidateAnchor,
    journalProofEntry,
    access: {
      kind: 'recipient',
      recipientEncryptionPrivateKey: fixture.recipient.encryption.privateKey,
    },
    now: NOW,
  };
}

async function state3CandidateWithTransition(
  fixture: Fixture,
  signer: IdentityKeys,
  times: Readonly<{ issuedAt: string; expiresAt?: string }> = { issuedAt: T3 },
): Promise<
  Readonly<{
    document: CollaborativeVaultDocument;
    proof: CollaborationMutationProof;
  }>
> {
  const intent = fixture.state3.manifest.pendingTransfers[0];
  if (intent === undefined) throw new Error('Transfer fixture missing');
  const transition = await signedTransition(signer, {
    operationId: 'operation-transfer-owner',
    operationType: 'transfer-owner',
    previousTuple: fixture.state2.tuple,
    nextTuple: fixture.state3.tuple,
    previousHeadDigest: fixture.state2.link.resultingHeadDigest,
    evidence: {
      kind: 'ownership-transfer',
      evidenceDigest: intent.intentDigest,
    },
    issuedAt: times.issuedAt,
    ...(times.expiresAt === undefined ? {} : { expiresAt: times.expiresAt }),
  });
  const link = await finalizedLink({
    operationId: 'operation-transfer-owner',
    operationType: 'transfer-owner',
    previousTuple: fixture.state2.tuple,
    nextTuple: fixture.state3.tuple,
    previousHeadDigest: fixture.state2.link.resultingHeadDigest,
    prepared: fixture.state3,
    policyDigest: fixture.state3.document.policyDigest,
    delegationDigest: fixture.state3.document.authorityDelegationDigest,
    writer: fixture.owner,
    timestamp: T3,
    transition,
  });
  const candidate = documentAndWitness({
    tuple: fixture.state3.tuple,
    databaseDeviceRegistry: fixture.registry,
    previousHeadDigest: fixture.state2.link.resultingHeadDigest,
    delegation: fixture.delegation,
    delegationDigest: fixture.state3.document.authorityDelegationDigest,
    prepared: fixture.state3,
    link,
    policyDigest: fixture.state3.document.policyDigest,
    updatedAt: T3,
  });
  const proof = collaborationMutationProofSchema.parse({
    ...fixture.proof1To3,
    toHeadDigest: link.resultingHeadDigest,
    entries: [
      { link: fixture.state2.link },
      { link, authorizationWitness: candidate.witness },
    ],
  });
  return { document: candidate.document, proof };
}

async function registryDenialAdvance(
  fixture: Fixture,
  approvalPolicy: CollaborativeMembershipManifest['approvalPolicy'] = 'none',
  options: Readonly<{
    denialMode?: 'identity' | 'fingerprint' | 'unrelated';
    deniedAt?: string;
    lateEvent?: boolean;
    lateCheckpoint?: boolean;
    omitCheckpoints?: boolean;
    signerExpiresAt?: string;
  }> = {},
): Promise<
  Readonly<{
    registry: CollaborationDatabaseDeviceRegistry;
    state: BuiltState;
    proof: CollaborationMutationProof;
    vaultRootKey: VaultRootKey;
  }>
> {
  const vaultRootKey = generateVaultRootKey();
  try {
    const denialMode = options.denialMode ?? 'unrelated';
    const deniesByIdentity = denialMode === 'identity';
    const deniesByFingerprint = denialMode !== 'unrelated';
    const registry = await authorityRegistry(
      fixture.authoritySigning,
      [
        {
          principalId: deniesByIdentity
            ? fixture.owner.certificate.principalId
            : publicIdentityExportSchema.shape.principalId.parse('principal-unrelated'),
          deviceId: deniesByIdentity
            ? fixture.owner.certificate.deviceId
            : deviceCertificateSchema.shape.deviceId.parse('device-unrelated'),
          deviceGeneration: fixture.owner.certificate.deviceGeneration,
          signingKeyFingerprint: deniesByFingerprint
            ? computePublicKeyFingerprint(
                fixture.owner.signing.publicKeyBase64,
                'ed25519',
              )
            : digest(31),
          reason: 'compromised',
          deniedAt: options.deniedAt ?? NOW,
        },
      ],
      {
        generation: 2,
        previousRegistryDigest: fixture.registry.registryDigest,
        updatedAt: NOW,
      },
    );
    const ownerMembership = fixture.state3.manifest.memberships[0];
    const recipientMembership = fixture.state3.manifest.memberships[1];
    if (ownerMembership === undefined || recipientMembership === undefined) {
      throw new Error('Registry advance membership fixture missing');
    }
    const memberships = [ownerMembership, recipientMembership] as const;
    const envelopes = [
      await memberEnvelope(
        vaultRootKey,
        ownerMembership,
        fixture.owner,
        3,
        registry.registryDigest,
        fixture.recipient,
        NOW,
        3,
        2,
      ),
      await memberEnvelope(
        vaultRootKey,
        recipientMembership,
        fixture.recipient,
        3,
        registry.registryDigest,
        fixture.recipient,
        NOW,
        3,
        2,
      ),
      await recoveryEnvelope(
        vaultRootKey,
        fixture.authorityRecovery,
        3,
        registry.registryDigest,
        fixture.recipient,
        NOW,
        3,
        2,
      ),
    ] as const;
    const authorizationStateDigest = computeAuthorizationStateDigest(
      authorizationCore(
        memberships,
        [OWNER_ID, RECIPIENT_ID],
        envelopes,
        3,
        registry.registryDigest,
        3,
        2,
        approvalPolicy,
      ),
    );
    const tuple4 = tuple(5, 3, 3, registry.registryDigest, authorizationStateDigest, 2);
    const policy = await signedPolicy(
      fixture.recipient,
      registry.registryDigest,
      2,
      NOW,
      approvalPolicy,
    );
    const revocationEvent = await historyEvent(fixture.recipient, {
      operationId: 'operation-revoke-owner-device',
      eventType: 'emergency-rekey',
      previousTuple: fixture.state3.tuple,
      nextTuple: tuple4,
      previousHeadDigest: fixture.state3.link.resultingHeadDigest,
      timestamp: NOW,
    });
    const events = [...fixture.state3.manifest.history.events, revocationEvent];
    if (options.lateEvent === true) {
      events.push(
        await historyEvent(fixture.owner, {
          operationId: 'operation-history-event-after-fence',
          eventType: 'key-rotated',
          previousTuple: fixture.state3.tuple,
          nextTuple: tuple4,
          previousHeadDigest: fixture.state3.link.resultingHeadDigest,
          timestamp: NOW,
        }),
      );
    }
    const checkpoints = options.omitCheckpoints
      ? []
      : [...fixture.state3.manifest.history.checkpoints];
    if (options.lateCheckpoint === true) {
      checkpoints.push(
        await historyCheckpoint(
          fixture.owner,
          tuple4,
          fixture.state3.link.resultingHeadDigest,
          {
            checkpointId: 'history-checkpoint-after-denial',
            createdAt: NOW,
          },
        ),
      );
    }
    const manifest = manifestForState({
      tuple: tuple4,
      memberships,
      ownerPrincipalIds: [OWNER_ID, RECIPIENT_ID],
      envelopes,
      policy,
      approvalPolicy,
      events,
      checkpoints,
      pendingTransfers: fixture.state3.manifest.pendingTransfers,
      previousHistoryDigest: fixture.state3.manifest.history.currentHistoryDigest,
      previousMembershipDigest: fixture.state3.manifest.membershipDigest,
      previousHeadDigest: fixture.state3.link.resultingHeadDigest,
      updatedAt: NOW,
    });
    const prepared = await prepareState(
      tuple4,
      manifest,
      fixture.recipient,
      fixture.recipient,
      vaultRootKey,
    );
    const transition = await signedTransition(fixture.recipient, {
      operationId: 'operation-revoke-owner-device',
      operationType: 'emergency-rekey',
      previousTuple: fixture.state3.tuple,
      nextTuple: tuple4,
      previousHeadDigest: fixture.state3.link.resultingHeadDigest,
      evidence: { kind: 'none' },
      issuedAt: NOW,
    });
    const link = await finalizedLink({
      operationId: 'operation-revoke-owner-device',
      operationType: 'emergency-rekey',
      previousTuple: fixture.state3.tuple,
      nextTuple: tuple4,
      previousHeadDigest: fixture.state3.link.resultingHeadDigest,
      prepared,
      policyDigest: policy.policyDigest,
      delegationDigest: fixture.state3.document.authorityDelegationDigest,
      writer: fixture.recipient,
      timestamp: NOW,
      transition,
    });
    const documents = documentAndWitness({
      tuple: tuple4,
      databaseDeviceRegistry: registry,
      previousHeadDigest: fixture.state3.link.resultingHeadDigest,
      delegation: fixture.delegation,
      delegationDigest: fixture.state3.document.authorityDelegationDigest,
      prepared,
      link,
      policyDigest: policy.policyDigest,
      updatedAt: NOW,
    });
    const state: BuiltState = { tuple: tuple4, ...prepared, link, ...documents };
    const proof = collaborationMutationProofSchema.parse({
      format: 'kavrix-collaborative-mutation-proof',
      protocolVersion: 1,
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      authorityDelegationDigest: fixture.state3.document.authorityDelegationDigest,
      fromDocumentRevision: fixture.state3.tuple.documentRevision,
      fromHeadDigest: fixture.state3.link.resultingHeadDigest,
      toDocumentRevision: tuple4.documentRevision,
      toHeadDigest: link.resultingHeadDigest,
      startingAuthorizationWitness: fixture.state3.witness,
      entries: [{ link, authorizationWitness: documents.witness }],
    });
    return { registry, state, proof, vaultRootKey };
  } catch (error) {
    zeroize(vaultRootKey);
    throw error;
  }
}

async function recoveryAdvance(
  fixture: Fixture,
  options: Readonly<{
    writer?: 'replacement' | 'old-owner';
    registryAdvance?: boolean;
    denyReplacementInNextRegistry?: boolean;
    commitmentTimestamp?: string;
  }> = {},
): Promise<
  Readonly<{
    registry: CollaborationDatabaseDeviceRegistry;
    state: BuiltState;
    proof: CollaborationMutationProof;
    vaultRootKey: VaultRootKey;
  }>
> {
  const vaultRootKey = generateVaultRootKey();
  try {
    const registry =
      options.registryAdvance === true
        ? await authorityRegistry(
            fixture.authoritySigning,
            options.denyReplacementInNextRegistry === true
              ? [
                  {
                    principalId: fixture.recipient.certificate.principalId,
                    deviceId: fixture.recipient.certificate.deviceId,
                    deviceGeneration: fixture.recipient.certificate.deviceGeneration,
                    signingKeyFingerprint: computePublicKeyFingerprint(
                      fixture.recipient.signing.publicKeyBase64,
                      'ed25519',
                    ),
                    reason: 'compromised',
                    deniedAt: NOW,
                  },
                ]
              : [],
            {
              generation: 2,
              previousRegistryDigest: fixture.registry.registryDigest,
              updatedAt: NOW,
            },
          )
        : fixture.registry;
    const timestamp =
      options.commitmentTimestamp ?? (options.registryAdvance === true ? NOW : T3);
    const priorOwner = fixture.state2.manifest.memberships[0];
    const priorRecipient = fixture.state2.manifest.memberships[1];
    if (priorOwner === undefined || priorRecipient === undefined) {
      throw new Error('Recovery fixture memberships missing');
    }
    const removedOwner =
      collaborativeMembershipManifestSchema.shape.memberships.element.parse({
        ...priorOwner,
        state: 'revoked',
        updatedAt: timestamp,
        removedAt: timestamp,
      });
    const replacement =
      collaborativeMembershipManifestSchema.shape.memberships.element.parse({
        ...priorRecipient,
        role: 'owner',
        updatedAt: timestamp,
      });
    const memberships = [removedOwner, replacement] as const;
    const envelopes = [
      await memberEnvelope(
        vaultRootKey,
        replacement,
        fixture.recipient,
        3,
        registry.registryDigest,
        fixture.recipient,
        timestamp,
        3,
        registry.generation,
      ),
      await recoveryEnvelope(
        vaultRootKey,
        fixture.authorityRecovery,
        3,
        registry.registryDigest,
        fixture.recipient,
        timestamp,
        3,
        registry.generation,
      ),
    ] as const;
    const authorizationStateDigest = computeAuthorizationStateDigest(
      authorizationCore(
        memberships,
        [RECIPIENT_ID],
        envelopes,
        3,
        registry.registryDigest,
        3,
        registry.generation,
      ),
    );
    const nextTuple = tuple(
      4,
      3,
      3,
      registry.registryDigest,
      authorizationStateDigest,
      registry.generation,
    );
    const policy =
      registry.generation === fixture.registry.generation
        ? fixture.state2.manifest.policy
        : await signedPolicy(
            fixture.recipient,
            registry.registryDigest,
            registry.generation,
            timestamp,
          );
    const writer = options.writer === 'old-owner' ? fixture.owner : fixture.recipient;
    const recoveryEvent = await historyEvent(writer, {
      operationId: 'operation-recover-owner',
      eventType: 'owner-recovery',
      previousTuple: fixture.state2.tuple,
      nextTuple,
      previousHeadDigest: fixture.state2.link.resultingHeadDigest,
      timestamp,
      targetPrincipalId: RECIPIENT_ID,
    });
    const manifest = manifestForState({
      tuple: nextTuple,
      memberships,
      ownerPrincipalIds: [RECIPIENT_ID],
      envelopes,
      policy,
      events: [...fixture.state2.manifest.history.events, recoveryEvent],
      checkpoints: fixture.state2.manifest.history.checkpoints,
      previousHistoryDigest: fixture.state2.manifest.history.currentHistoryDigest,
      previousMembershipDigest: fixture.state2.manifest.membershipDigest,
      previousHeadDigest: fixture.state2.link.resultingHeadDigest,
      updatedAt: timestamp,
    });
    const prepared = await prepareState(
      nextTuple,
      manifest,
      writer,
      fixture.recipient,
      vaultRootKey,
    );
    const transition = await signedRecoveryTransition(
      fixture.authoritySigning,
      fixture.delegation,
      {
        previousTuple: fixture.state2.tuple,
        nextTuple,
        previousHeadDigest: fixture.state2.link.resultingHeadDigest,
        issuedAt: timestamp,
      },
    );
    const link = await finalizedLink({
      operationId: 'operation-recover-owner',
      operationType: 'recover-owner',
      previousTuple: fixture.state2.tuple,
      nextTuple,
      previousHeadDigest: fixture.state2.link.resultingHeadDigest,
      prepared,
      policyDigest: policy.policyDigest,
      delegationDigest: fixture.state2.document.authorityDelegationDigest,
      writer,
      timestamp,
      transition,
    });
    const documents = documentAndWitness({
      tuple: nextTuple,
      databaseDeviceRegistry: registry,
      previousHeadDigest: fixture.state2.link.resultingHeadDigest,
      delegation: fixture.delegation,
      delegationDigest: fixture.state2.document.authorityDelegationDigest,
      prepared,
      link,
      policyDigest: policy.policyDigest,
      updatedAt: timestamp,
    });
    const state: BuiltState = { tuple: nextTuple, ...prepared, link, ...documents };
    const proof = collaborationMutationProofSchema.parse({
      format: 'kavrix-collaborative-mutation-proof',
      protocolVersion: 1,
      databaseId: DATABASE_ID,
      vaultId: VAULT_ID,
      authorityDelegationDigest: fixture.state2.document.authorityDelegationDigest,
      fromDocumentRevision: fixture.state2.tuple.documentRevision,
      fromHeadDigest: fixture.state2.link.resultingHeadDigest,
      toDocumentRevision: nextTuple.documentRevision,
      toHeadDigest: link.resultingHeadDigest,
      startingAuthorizationWitness: fixture.state2.witness,
      entries: [{ link, authorizationWitness: documents.witness }],
    });
    return { registry, state, proof, vaultRootKey };
  } catch (error) {
    zeroize(vaultRootKey);
    throw error;
  }
}

async function ordinarySuccessorAfterRecovery(
  fixture: Fixture,
  recovered: Readonly<{
    registry: CollaborationDatabaseDeviceRegistry;
    state: BuiltState;
    proof: CollaborationMutationProof;
    vaultRootKey: VaultRootKey;
  }>,
): Promise<Readonly<{ state: BuiltState; proof: CollaborationMutationProof }>> {
  const prior = recovered.state;
  const nextTuple = tuple(
    prior.tuple.documentRevision + 1,
    prior.tuple.membershipRevision,
    prior.tuple.keyEpoch,
    prior.tuple.databaseDeviceRegistryDigest,
    prior.tuple.authorizationStateDigest,
    prior.tuple.databaseDeviceGeneration,
  );
  const historyDraft = {
    ...prior.manifest.history,
    previousHeadDigest: prior.link.resultingHeadDigest,
    previousHistoryDigest: prior.manifest.history.currentHistoryDigest,
    currentHistoryDigest: prior.manifest.history.currentHistoryDigest,
  };
  const history = {
    ...historyDraft,
    currentHistoryDigest: computeMembershipHistoryDigest(historyDraft),
  };
  const manifestDraft = collaborativeMembershipManifestSchema.parse({
    ...prior.manifest,
    documentRevision: nextTuple.documentRevision,
    history,
    previousMembershipDigest: prior.manifest.membershipDigest,
    previousHeadDigest: prior.link.resultingHeadDigest,
    membershipDigest: PLACEHOLDER_DIGEST,
    updatedAt: NOW,
  });
  const manifest = collaborativeMembershipManifestSchema.parse({
    ...manifestDraft,
    membershipDigest: computeMembershipManifestDigest(manifestDraft),
  });
  const prepared = await prepareState(
    nextTuple,
    manifest,
    fixture.recipient,
    fixture.recipient,
    recovered.vaultRootKey,
  );
  const link = await finalizedLink({
    operationId: 'operation-after-recovery',
    operationType: 'ordinary-write',
    previousTuple: prior.tuple,
    nextTuple,
    previousHeadDigest: prior.link.resultingHeadDigest,
    prepared,
    policyDigest: manifest.policy.policyDigest,
    delegationDigest: prior.document.authorityDelegationDigest,
    writer: fixture.recipient,
    timestamp: NOW,
  });
  const documents = documentAndWitness({
    tuple: nextTuple,
    databaseDeviceRegistry: recovered.registry,
    previousHeadDigest: prior.link.resultingHeadDigest,
    delegation: fixture.delegation,
    delegationDigest: prior.document.authorityDelegationDigest,
    prepared,
    link,
    policyDigest: manifest.policy.policyDigest,
    updatedAt: NOW,
  });
  const state: BuiltState = { tuple: nextTuple, ...prepared, link, ...documents };
  return {
    state,
    proof: collaborationMutationProofSchema.parse({
      ...recovered.proof,
      toDocumentRevision: nextTuple.documentRevision,
      toHeadDigest: link.resultingHeadDigest,
      entries: [...recovered.proof.entries, { link }],
    }),
  };
}

function releaseOpened(opened: OpenedCollaborativeVaultState): void {
  zeroize(opened.vaultRootKey);
  zeroize(opened.decryptedPayload);
}

function destroyFixture(fixture: Fixture): void {
  zeroize(fixture.vaultRootKey);
  zeroize(fixture.deviceProtectionSecret);
  zeroize(fixture.authoritySigning.privateKey);
  zeroize(fixture.authorityRecovery.privateKey);
  zeroize(fixture.databaseRootKey);
  zeroize(fixture.owner.root.privateKey);
  zeroize(fixture.owner.signing.privateKey);
  zeroize(fixture.owner.encryption.privateKey);
  zeroize(fixture.recipient.root.privateKey);
  zeroize(fixture.recipient.signing.privateKey);
  zeroize(fixture.recipient.encryption.privateKey);
}

async function expectFailure(
  promise: Promise<unknown>,
  kind?: CollaborationStateVerificationError['kind'],
): Promise<void> {
  try {
    await promise;
    throw new Error('Expected collaboration verification failure');
  } catch (error) {
    if (!(error instanceof CollaborationStateVerificationError)) throw error;
    if (kind !== undefined) {
      expect(error.kind).toBe(kind);
    }
  }
}

describe('collaboration state verifier', () => {
  it('enrolls an exact receipt checkpoint and persists the full anchor before return', async () => {
    const fixture = await buildFixture();
    const path = anchorPath();

    const opened = await enrollAndOpenCollaborativeVault(firstInput(fixture));
    const anchor = await readRecipientRollbackAnchor(
      path,
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );

    expect(Buffer.from(opened.decryptedPayload).equals(PAYLOAD)).toBe(true);
    expect(anchor.documentRevision).toBe(fixture.state1.tuple.documentRevision);
    expect(anchor.headDigest).toBe(fixture.state1.link.resultingHeadDigest);
    expect(anchor.authorizationStateDigest).toBe(
      fixture.state1.tuple.authorizationStateDigest,
    );
    expect(anchor.finalizedMutationLinkDigest).toBe(
      computeFinalizedMutationLinkDigest(fixture.state1.link),
    );
    expect(anchor.membershipDigest).toBe(
      computeMembershipStateDigest(
        authorizationCore(
          fixture.state1.manifest.memberships,
          fixture.state1.manifest.ownerPrincipalIds,
          fixture.state1.manifest.keyEnvelopes,
          fixture.state1.manifest.membershipRevision,
          fixture.state1.manifest.databaseDeviceRegistryDigest,
          fixture.state1.manifest.keyEpoch,
          fixture.state1.manifest.databaseDeviceGeneration,
          fixture.state1.manifest.approvalPolicy,
        ),
      ),
    );
    releaseOpened(opened);
  });

  it('opens another member and the owner on a newly enrolled add-device receipt', async () => {
    for (const targetKind of ['recipient', 'owner'] as const) {
      const fixture = await buildFixture();
      const target = targetKind === 'recipient' ? fixture.recipient : fixture.owner;
      const signing = await generateDeviceSigningKeyPair();
      const encryption = await generateDeviceEncryptionKeyPair();
      let nextVaultRootKey: VaultRootKey | undefined;
      try {
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
            createdAt: T2,
            stateChangedAt: T2,
            rootSignature: PLACEHOLDER_SIGNATURE,
          },
          deviceCertificateSchema,
          'rootSignature',
          target.root.privateKey,
        );
        const publicIdentity = await signedRecord(
          COLLABORATION_DOMAINS.publicIdentitySignature,
          {
            ...target.identity,
            identityGeneration: target.identity.identityGeneration + 1,
            devices: [...target.identity.devices, certificate],
            selfSignature: PLACEHOLDER_SIGNATURE,
          },
          publicIdentityExportSchema,
          'selfSignature',
          target.root.privateKey,
        );
        const targetIndex = fixture.state1.manifest.memberships.findIndex(
          (membershipValue) =>
            membershipValue.principalId === target.certificate.principalId,
        );
        const priorMembership = fixture.state1.manifest.memberships[targetIndex];
        if (targetIndex < 0 || priorMembership === undefined) {
          throw new Error('Add-device target membership fixture missing');
        }
        const nextMembership =
          collaborativeMembershipManifestSchema.shape.memberships.element.parse({
            ...priorMembership,
            identityGeneration: priorMembership.identityGeneration + 1,
            devices: [...priorMembership.devices, certificate],
            updatedAt: NOW,
          });
        const prepared = await buildAdministrativeCollaborativeMutation({
          prior: {
            document: fixture.state1.document,
            manifest: fixture.state1.manifest,
            deviceRegistry: fixture.registry,
            currentVaultRootKey: fixture.vaultRootKey,
            quarantinedVaultPayload: Uint8Array.from(PAYLOAD),
          },
          authoritativeDeviceRegistry: fixture.registry,
          actor: {
            principalId: fixture.owner.certificate.principalId,
            deviceId: fixture.owner.certificate.deviceId,
            rootSigningPublicKey: fixture.owner.root.publicKeyBase64,
            deviceCertificate: fixture.owner.certificate,
            deviceSigningPrivateKey: fixture.owner.signing.privateKey,
          },
          authorityRecoveryPublicKey: fixture.authorityRecovery.publicKeyBase64,
          operationId: collaborationMutationCommitmentSchema.shape.operationId.parse(
            `operation-add-device-${targetKind}`,
          ),
          timestamp: NOW,
          expiresAt: EXPIRES_AT,
          anchorScope: {
            databaseId: fixture.state1.document.databaseId,
            vaultId: fixture.state1.document.vaultId,
            principalId: fixture.owner.certificate.principalId,
            deviceId: fixture.owner.certificate.deviceId,
          },
          operationType: 'add-device',
          next: {
            memberships: fixture.state1.manifest.memberships.map(
              (membershipValue, index) =>
                index === targetIndex ? nextMembership : membershipValue,
            ),
            ownerPrincipalIds: fixture.state1.manifest.ownerPrincipalIds,
            approvalPolicy: fixture.state1.manifest.approvalPolicy,
            historyEvent: {
              eventType: 'device-added',
              targetPrincipalId: target.certificate.principalId,
              targetDeviceId: certificate.deviceId,
            },
          },
          decryptAccessChanged: true,
        });
        nextVaultRootKey = prepared.nextVaultRootKey;
        if (nextVaultRootKey === undefined) {
          throw new Error('Add-device fixture did not rotate the vault root key');
        }
        const manifestBytes = await decryptCollaborationEnvelope(
          prepared.candidate.encryptedMembershipManifest,
          nextVaultRootKey,
          prepared.candidate.encryptedMembershipManifest.aad,
        );
        let resultingManifest: CollaborativeMembershipManifest;
        try {
          resultingManifest = collaborativeMembershipManifestSchema.parse(
            JSON.parse(Buffer.from(manifestBytes).toString('utf8')),
          );
        } finally {
          zeroize(manifestBytes);
        }
        const artifacts = await buildCollaborationEnrollmentArtifacts({
          candidate: prepared.candidate,
          proofEntry: prepared.proofEntry,
          resultingManifest,
          ownerPublicIdentity:
            targetKind === 'owner' ? publicIdentity : fixture.owner.identity,
          ownerPrincipalId: OWNER_ID,
          ownerDeviceId: OWNER_DEVICE_ID,
          recipientPublicIdentity: publicIdentity,
          recipientDeviceId: certificate.deviceId,
          ownerDeviceSigningPrivateKey: fixture.owner.signing.privateKey,
          checkpointId: `checkpoint-add-device-${targetKind}`,
          issuedAt: NOW,
          expiresAt: EXPIRES_AT,
          now: NOW,
        });
        const scope = {
          databaseId: prepared.candidate.databaseId,
          vaultId: prepared.candidate.vaultId,
          principalId: target.certificate.principalId,
          deviceId: certificate.deviceId,
        } as const;
        const path = anchorPath(`add-device-${targetKind}`);
        const opened = await enrollAndOpenCollaborativeVault({
          document: prepared.candidate,
          authoritativeDeviceRegistry: fixture.registry,
          scope,
          recipientEncryptionPrivateKey: encryption.privateKey,
          deviceProtectionSecret: fixture.deviceProtectionSecret,
          rollbackAnchorPath: path,
          now: NOW,
          enrollmentReceipt: artifacts.receipt,
          enrollmentCheckpoint: artifacts.checkpoint,
        });
        const anchor = await readRecipientRollbackAnchor(
          path,
          fixture.deviceProtectionSecret,
          { expectedScope: scope },
        );

        expect(artifacts.receipt.operationType).toBe('add-device');
        expect(opened.recipientMembership.principalId).toBe(
          target.certificate.principalId,
        );
        expect(opened.recipientDevice.deviceId).toBe(ADDED_DEVICE_ID);
        expect(opened.decryptedPayload).toEqual(Uint8Array.from(PAYLOAD));
        expect(anchor.documentRevision).toBe(prepared.candidate.documentRevision);
        expect(anchor.finalizedMutationLinkDigest).toBe(
          computeFinalizedMutationLinkDigest(prepared.candidate.currentMutationLink),
        );
        releaseOpened(opened);
      } finally {
        zeroize(nextVaultRootKey);
        zeroize(signing.privateKey);
        zeroize(encryption.privateKey);
      }
    }
  });

  it('accepts a receipt-to-newer ordinary proof and rejects a bare newer head', async () => {
    const valid = await buildFixture();
    const opened = await enrollAndOpenCollaborativeVault(
      firstInput(valid, valid.state2, valid.proof1To2),
    );
    expect(opened.document.documentRevision).toBe(valid.state2.tuple.documentRevision);
    releaseOpened(opened);

    const missing = await buildFixture();
    await expectFailure(
      enrollAndOpenCollaborativeVault(
        firstInput(missing, missing.state2, undefined, anchorPath('missing-proof')),
      ),
      'proof-required',
    );
  });

  it('opens genesis and a newer exact history through database-authority recovery without recipient state', async () => {
    const fixture = await buildFixture();
    const authorityRollbackAnchorPath = await initializeAuthorityAnchor(fixture);
    const authorityTrust: CollaborativeVaultPinnedTrust = {
      authorityDelegation: fixture.delegation,
      principalPublicIdentities: [],
    };
    const originalDrk = Uint8Array.from(fixture.databaseRootKey);

    const genesis = await openCollaborativeVaultForDatabaseAuthorityRecovery({
      document: fixture.genesisState.document,
      authoritativeDeviceRegistry: fixture.registry,
      trusted: authorityTrust,
      databaseRootKey: fixture.databaseRootKey,
      authorityRollbackAnchorPath,
      now: NOW,
    });
    expect(genesis.manifest.authorizationStateDigest).toBe(
      fixture.delegation.initialAuthorizationStateDigest,
    );
    expect(genesis.decryptedPayload).toEqual(Uint8Array.from(PAYLOAD));
    zeroize(genesis.vaultRootKey);
    zeroize(genesis.decryptedPayload);

    const newer = await openCollaborativeVaultForDatabaseAuthorityRecovery({
      document: fixture.state3.document,
      authoritativeDeviceRegistry: fixture.registry,
      mutationProof: fixture.genesisProofTo3,
      trusted: authorityTrust,
      databaseRootKey: fixture.databaseRootKey,
      authorityRollbackAnchorPath,
      now: NOW,
    });
    expect(newer.document.documentRevision).toBe(fixture.state3.tuple.documentRevision);
    expect(newer.decryptedPayload).toEqual(Uint8Array.from(PAYLOAD));
    await expect(
      readCollaborationAuthorityRollbackAnchor(
        authorityRollbackAnchorPath,
        fixture.databaseRootKey,
      ),
    ).resolves.toMatchObject({
      documentRevision: fixture.state3.tuple.documentRevision,
      headDigest: fixture.state3.document.headDigest,
    });
    expect(fixture.databaseRootKey).toEqual(originalDrk);
    zeroize(newer.vaultRootKey);
    zeroize(newer.decryptedPayload);
    zeroize(originalDrk);
  });

  it('derives intrinsic authority-anchor bindings only from the authenticated document', async () => {
    const fixture = await buildFixture();
    const document = fixture.state3.document;
    const anchor = collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
      document,
      {
        ...authorityLogicalDigests(fixture.state3),
        encryptedPayloadDigest: digest(240),
        finalizedMutationLinkDigest: digest(241),
        updatedAt: CREATED_AT,
      } as unknown as Parameters<
        typeof collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument
      >[1],
    );

    expect(anchor.encryptedPayloadDigest).toBe(document.encryptedPayloadDigest);
    expect(anchor.finalizedMutationLinkDigest).toBe(
      computeFinalizedMutationLinkDigest(document.currentMutationLink),
    );
    expect(anchor.updatedAt).toBe(document.updatedAt);
  });

  it('fails authority recovery closed for a wrong DRK or missing, truncated, and non-genesis proof', async () => {
    const fixture = await buildFixture();
    const authorityRollbackAnchorPath = await initializeAuthorityAnchor(fixture);
    const authorityTrust: CollaborativeVaultPinnedTrust = {
      authorityDelegation: fixture.delegation,
      principalPublicIdentities: [],
    };
    const wrongDrk = generateDatabaseRootKey();
    try {
      await expectFailure(
        openCollaborativeVaultForDatabaseAuthorityRecovery({
          document: fixture.genesisState.document,
          authoritativeDeviceRegistry: fixture.registry,
          trusted: authorityTrust,
          databaseRootKey: fixture.databaseRootKey,
          authorityRollbackAnchorPath: anchorPath('missing-authority.anchor'),
          now: NOW,
        }),
        'trust-required',
      );
      await expectFailure(
        openCollaborativeVaultForDatabaseAuthorityRecovery({
          document: fixture.genesisState.document,
          authoritativeDeviceRegistry: fixture.registry,
          trusted: authorityTrust,
          databaseRootKey: wrongDrk,
          authorityRollbackAnchorPath,
          now: NOW,
        }),
        'trust-required',
      );
      await expectFailure(
        openCollaborativeVaultForDatabaseAuthorityRecovery({
          document: fixture.state3.document,
          authoritativeDeviceRegistry: fixture.registry,
          trusted: authorityTrust,
          databaseRootKey: fixture.databaseRootKey,
          authorityRollbackAnchorPath,
          now: NOW,
        }),
        'proof-required',
      );

      const truncated = structuredClone(fixture.genesisProofTo3);
      truncated.entries.splice(0, 1);
      await expectFailure(
        openCollaborativeVaultForDatabaseAuthorityRecovery({
          document: fixture.state3.document,
          authoritativeDeviceRegistry: fixture.registry,
          mutationProof: truncated,
          trusted: authorityTrust,
          databaseRootKey: fixture.databaseRootKey,
          authorityRollbackAnchorPath,
          now: NOW,
        }),
        'invalid-input',
      );

      const substitutedStart = structuredClone(fixture.genesisProofTo3);
      substitutedStart.startingAuthorizationWitness = structuredClone(
        fixture.state2.witness,
      );
      await expectFailure(
        openCollaborativeVaultForDatabaseAuthorityRecovery({
          document: fixture.state3.document,
          authoritativeDeviceRegistry: fixture.registry,
          mutationProof: substitutedStart,
          trusted: authorityTrust,
          databaseRootKey: fixture.databaseRootKey,
          authorityRollbackAnchorPath,
          now: NOW,
        }),
        'invalid-input',
      );
    } finally {
      zeroize(wrongDrk);
    }
  });

  it('advances an ordinary-write anchor with a stable logical membership digest', async () => {
    const fixture = await buildFixture();
    const path = anchorPath('ordinary-anchor');
    const enrolled = await enrollAndOpenCollaborativeVault(
      firstInput(fixture, fixture.state1, undefined, path),
    );
    releaseOpened(enrolled);
    const before = await readRecipientRollbackAnchor(
      path,
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );

    const opened = await openCollaborativeVaultWithPinnedTrust(
      pinnedInput(fixture, fixture.state2, fixture.proof1To2, path),
    );
    const after = await readRecipientRollbackAnchor(
      path,
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );

    expect(after.documentRevision).toBe(fixture.state2.tuple.documentRevision);
    expect(after.membershipRevision).toBe(before.membershipRevision);
    expect(after.membershipDigest).toBe(before.membershipDigest);
    expect(after.headDigest).toBe(fixture.state2.link.resultingHeadDigest);
    releaseOpened(opened);
  });

  it('verifies an exact journal candidate as the first link and returns every successor anchor without exposing access secrets', async () => {
    const fixture = await buildFixture();
    const input = await journalSuccessorInput(fixture, 'journal-successor.anchor');
    const originalPrivateKey = Uint8Array.from(fixture.recipient.encryption.privateKey);

    const verified = await verifyCollaborativeJournalSuccessorChain(input);

    expect(verified.currentDocument).toEqual(fixture.state3.document);
    expect(verified.anchors).toHaveLength(2);
    expect(verified.anchors[0]).toEqual(input.journalCandidateAnchor);
    expect(verified.anchors[1]).toMatchObject({
      documentRevision: fixture.state3.tuple.documentRevision,
      headDigest: fixture.state3.link.resultingHeadDigest,
      finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
        fixture.state3.link,
      ),
    });
    expect(fixture.recipient.encryption.privateKey).toEqual(originalPrivateKey);
    expect(JSON.stringify(verified)).not.toContain(
      Buffer.from(originalPrivateKey).toString('base64url'),
    );
    zeroize(originalPrivateKey);
  });

  it('rejects a substituted journal entry or same-position candidate anchor metadata', async () => {
    const fixture = await buildFixture();
    const input = await journalSuccessorInput(fixture, 'journal-substitution.anchor');
    const substitutedEntry = fixture.genesisProofTo3.entries[0];
    if (substitutedEntry === undefined) {
      throw new Error('Substituted journal proof entry missing');
    }
    await expectFailure(
      verifyCollaborativeJournalSuccessorChain({
        ...input,
        journalProofEntry: substitutedEntry,
      }),
      'proof-invalid',
    );
    await expectFailure(
      verifyCollaborativeJournalSuccessorChain({
        ...input,
        journalCandidateAnchor: {
          ...(input.journalCandidateAnchor as RecipientRollbackAnchor),
          membershipDigest: digest(0x4a),
        },
      }),
      'proof-invalid',
    );
  });

  it('rejects a forked successor chain after the exact journal entry', async () => {
    const fixture = await buildFixture();
    const input = await journalSuccessorInput(fixture, 'journal-fork.anchor');
    const forkedProof = structuredClone(fixture.proof1To3);
    const forkedEntry = forkedProof.entries[1];
    if (forkedEntry === undefined) throw new Error('Forked proof entry missing');
    forkedEntry.link.writerSignature.signature = mutateBase64(
      forkedEntry.link.writerSignature.signature,
    );

    await expectFailure(
      verifyCollaborativeJournalSuccessorChain({
        ...input,
        mutationProof: forkedProof,
      }),
      'signature-invalid',
    );
  });

  it('advances an anchored reopen across ordinary and owner-succession links', async () => {
    const fixture = await buildFixture();
    const enrolled = await enrollAndOpenCollaborativeVault(firstInput(fixture));
    releaseOpened(enrolled);

    const opened = await openCollaborativeVaultWithPinnedTrust(
      pinnedInput(fixture, fixture.state3, fixture.proof1To3),
    );
    expect(opened.recipientMembership.role).toBe('owner');
    const anchor = await readRecipientRollbackAnchor(
      anchorPath(),
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );
    expect(anchor.documentRevision).toBe(fixture.state3.tuple.documentRevision);
    expect(anchor.headDigest).toBe(fixture.state3.link.resultingHeadDigest);
    releaseOpened(opened);
  });

  it('accepts authority recovery whose exact replacement signs the next state and proof link', async () => {
    const fixture = await buildFixture();
    const path = anchorPath('recovery-replacement');
    const anchored = await enrollAndOpenCollaborativeVault(
      firstInput(fixture, fixture.state2, fixture.proof1To2, path),
    );
    releaseOpened(anchored);
    const recovered = await recoveryAdvance(fixture);
    try {
      const opened = await openCollaborativeVaultWithPinnedTrust(
        pinnedInput(fixture, recovered.state, recovered.proof, path),
      );
      expect(opened.manifest.ownerPrincipalIds).toEqual([RECIPIENT_ID]);
      expect(opened.document.currentMutationLink.writerSignature).toMatchObject({
        writerPrincipalId: RECIPIENT_ID,
        writerDeviceId: RECIPIENT_DEVICE_ID,
      });
      releaseOpened(opened);
    } finally {
      zeroize(recovered.vaultRootKey);
    }
  });

  it('rejects recover-owner proof artifacts signed by the removed prior owner', async () => {
    const fixture = await buildFixture();
    const path = anchorPath('recovery-old-owner');
    const anchored = await enrollAndOpenCollaborativeVault(
      firstInput(fixture, fixture.state2, fixture.proof1To2, path),
    );
    releaseOpened(anchored);
    const recovered = await recoveryAdvance(fixture, { writer: 'old-owner' });
    try {
      await expectFailure(
        openCollaborativeVaultWithPinnedTrust(
          pinnedInput(fixture, recovered.state, recovered.proof, path),
        ),
        'writer-inactive',
      );
    } finally {
      zeroize(recovered.vaultRootKey);
    }
  });

  it('rejects registry-advancing recovery before the next registry update time', async () => {
    const fixture = await buildFixture();
    const path = anchorPath('recovery-registry-backdate');
    const anchored = await enrollAndOpenCollaborativeVault(
      firstInput(fixture, fixture.state2, fixture.proof1To2, path),
    );
    releaseOpened(anchored);
    const recovered = await recoveryAdvance(fixture, {
      registryAdvance: true,
      commitmentTimestamp: T3,
    });
    try {
      await expectFailure(
        openCollaborativeVaultWithPinnedTrust(
          pinnedInput(
            fixture,
            recovered.state,
            recovered.proof,
            path,
            recovered.registry,
          ),
        ),
        'proof-invalid',
      );
    } finally {
      zeroize(recovered.vaultRootKey);
    }
  });

  it('rejects a recovery replacement denied only by the next registry', async () => {
    const fixture = await buildFixture();
    const path = anchorPath('recovery-next-registry-denial');
    const anchored = await enrollAndOpenCollaborativeVault(
      firstInput(fixture, fixture.state2, fixture.proof1To2, path),
    );
    releaseOpened(anchored);
    const recovered = await recoveryAdvance(fixture, {
      registryAdvance: true,
      denyReplacementInNextRegistry: true,
    });
    try {
      await expectFailure(
        openCollaborativeVaultWithPinnedTrust(
          pinnedInput(
            fixture,
            recovered.state,
            recovered.proof,
            path,
            recovered.registry,
          ),
        ),
        'recipient-inactive',
      );
    } finally {
      zeroize(recovered.vaultRootKey);
    }
  });

  it('rejects a backdated registry-advancing recovery even when it is an intermediate proof link', async () => {
    const fixture = await buildFixture();
    const path = anchorPath('recovery-intermediate-registry-backdate');
    const anchored = await enrollAndOpenCollaborativeVault(
      firstInput(fixture, fixture.state2, fixture.proof1To2, path),
    );
    releaseOpened(anchored);
    const recovered = await recoveryAdvance(fixture, {
      registryAdvance: true,
      commitmentTimestamp: T3,
    });
    try {
      const successor = await ordinarySuccessorAfterRecovery(fixture, recovered);
      await expectFailure(
        openCollaborativeVaultWithPinnedTrust(
          pinnedInput(
            fixture,
            successor.state,
            successor.proof,
            path,
            recovered.registry,
          ),
        ),
        'proof-invalid',
      );
    } finally {
      zeroize(recovered.vaultRootKey);
    }
  });

  it('persists a direct registry-rekey link without retroactively denying old history', async () => {
    const fixture = await buildFixture();
    const path = anchorPath('temporal-denial');
    const anchored = await enrollAndOpenCollaborativeVault(
      firstInput(fixture, fixture.state3, fixture.proof1To3, path),
    );
    releaseOpened(anchored);
    const before = await readRecipientRollbackAnchor(
      path,
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );

    const advanced = await registryDenialAdvance(fixture);
    try {
      const opened = await openCollaborativeVaultWithPinnedTrust(
        pinnedInput(fixture, advanced.state, advanced.proof, path, advanced.registry),
      );
      const anchor = await readRecipientRollbackAnchor(
        path,
        fixture.deviceProtectionSecret,
        { expectedScope: fixture.scope },
      );

      expect(opened.document.documentRevision).toBe(
        advanced.state.tuple.documentRevision,
      );
      expect(opened.recipientMembership.role).toBe('owner');
      expect(advanced.proof.entries).toHaveLength(1);
      expect(advanced.state.manifest.history.events[0]?.actorDeviceId).toBe(
        OWNER_DEVICE_ID,
      );
      expect(
        advanced.state.manifest.history.checkpoints.some(
          (checkpoint) => checkpoint.createdAt === T1,
        ),
      ).toBe(true);
      expect(anchor.databaseDeviceGeneration).toBe(2);
      expect(anchor.policyRevision).toBe(before.policyRevision);
      expect(anchor.policyDigest).toBe(before.policyDigest);
      expect(advanced.state.document.policyDigest).not.toBe(
        fixture.state3.document.policyDigest,
      );
      expect(computePolicyStateDigest(advanced.state.manifest.policy)).toBe(
        computePolicyStateDigest(fixture.state3.manifest.policy),
      );
      expect(anchor.headDigest).toBe(advanced.state.link.resultingHeadDigest);
      releaseOpened(opened);
    } finally {
      zeroize(advanced.vaultRootKey);
    }
  });

  it('accepts a then-valid reader checkpoint signer', async () => {
    const fixture = await buildFixture('none', 'reader-signer');
    const opened = await enrollAndOpenCollaborativeVault(
      firstInput(fixture, fixture.state1, undefined, anchorPath('checkpoint-reader')),
    );
    expect(opened.recipientMembership.role).toBe('reader');
    releaseOpened(opened);
  });

  it('rejects wrong checkpoint signer IDs, substituted keys, and pre-creation signatures', async () => {
    const scenarios = ['wrong-signer-ids', 'key-substitution', 'pre-creation'] as const;
    for (const scenario of scenarios) {
      const fixture = await buildFixture('none', scenario);
      await expectFailure(
        enrollAndOpenCollaborativeVault(
          firstInput(
            fixture,
            fixture.state1,
            undefined,
            anchorPath(`checkpoint-${scenario}`),
          ),
        ),
      );
    }
  });

  it('rejects checkpoints after denial or an unrelated checkpoint append', async () => {
    const cases = [
      {
        name: 'denial',
        options: { deniedAt: T3, denialMode: 'fingerprint' as const },
        expected: 'writer-inactive' as const,
      },
      {
        name: 'unrelated-append',
        options: { denialMode: 'unrelated' as const, lateCheckpoint: true },
        expected: 'proof-invalid' as const,
      },
    ] as const;
    for (const testCase of cases) {
      const fixture = await buildFixture();
      const path = anchorPath(`checkpoint-${testCase.name}`);
      const anchored = await enrollAndOpenCollaborativeVault(
        firstInput(fixture, fixture.state3, fixture.proof1To3, path),
      );
      releaseOpened(anchored);
      const before = await readRecipientRollbackAnchor(
        path,
        fixture.deviceProtectionSecret,
        { expectedScope: fixture.scope },
      );
      const advanced = await registryDenialAdvance(fixture, 'none', testCase.options);
      try {
        await expectFailure(
          openCollaborativeVaultWithPinnedTrust(
            pinnedInput(
              fixture,
              advanced.state,
              advanced.proof,
              path,
              advanced.registry,
            ),
          ),
          testCase.expected,
        );
        const after = await readRecipientRollbackAnchor(
          path,
          fixture.deviceProtectionSecret,
          { expectedScope: fixture.scope },
        );
        expect(after, testCase.name).toEqual(before);
      } finally {
        zeroize(advanced.vaultRootKey);
      }
    }
  });

  it('rejects a membership-history event signed before its actor existed', async () => {
    const fixture = await buildFixture('none', 'none', 'pre-creation');
    await expectFailure(
      enrollAndOpenCollaborativeVault(
        firstInput(
          fixture,
          fixture.state1,
          undefined,
          anchorPath('event-pre-creation'),
        ),
      ),
      'writer-inactive',
    );
  });

  it('rejects membership-history events after denial or an unrelated event append', async () => {
    const cases = [
      {
        name: 'denial',
        options: {
          deniedAt: T3,
          denialMode: 'fingerprint' as const,
          omitCheckpoints: true,
        },
        expected: 'writer-inactive' as const,
      },
      {
        name: 'unrelated-append',
        options: {
          denialMode: 'unrelated' as const,
          lateEvent: true,
          omitCheckpoints: true,
        },
        expected: 'proof-invalid' as const,
      },
    ] as const;
    for (const testCase of cases) {
      const fixture = await buildFixture();
      const path = anchorPath(`event-${testCase.name}`);
      const anchored = await enrollAndOpenCollaborativeVault(
        firstInput(fixture, fixture.state3, fixture.proof1To3, path),
      );
      releaseOpened(anchored);
      const before = await readRecipientRollbackAnchor(
        path,
        fixture.deviceProtectionSecret,
        { expectedScope: fixture.scope },
      );
      const advanced = await registryDenialAdvance(fixture, 'none', testCase.options);
      try {
        await expectFailure(
          openCollaborativeVaultWithPinnedTrust(
            pinnedInput(
              fixture,
              advanced.state,
              advanced.proof,
              path,
              advanced.registry,
            ),
          ),
          testCase.expected,
        );
        const after = await readRecipientRollbackAnchor(
          path,
          fixture.deviceProtectionSecret,
          { expectedScope: fixture.scope },
        );
        expect(after, testCase.name).toEqual(before);
      } finally {
        zeroize(advanced.vaultRootKey);
      }
    }
  });

  it('rejects substituted logical policy at the same policy revision', async () => {
    const fixture = await buildFixture();
    const path = anchorPath('policy-substitution');
    const anchored = await enrollAndOpenCollaborativeVault(
      firstInput(fixture, fixture.state3, fixture.proof1To3, path),
    );
    releaseOpened(anchored);
    const before = await readRecipientRollbackAnchor(
      path,
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );

    const substituted = await registryDenialAdvance(fixture, 'one-additional-owner');
    try {
      await expectFailure(
        openCollaborativeVaultWithPinnedTrust(
          pinnedInput(
            fixture,
            substituted.state,
            substituted.proof,
            path,
            substituted.registry,
          ),
        ),
        'proof-invalid',
      );
      const after = await readRecipientRollbackAnchor(
        path,
        fixture.deviceProtectionSecret,
        { expectedScope: fixture.scope },
      );
      expect(after).toEqual(before);
    } finally {
      zeroize(substituted.vaultRootKey);
    }
  });

  it('rejects a transition signed by a prior reader and an expired owner transition', async () => {
    const fixture = await buildFixture();
    const enrolled = await enrollAndOpenCollaborativeVault(firstInput(fixture));
    releaseOpened(enrolled);
    const before = await readRecipientRollbackAnchor(
      anchorPath(),
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );
    const unauthorized = await state3CandidateWithTransition(
      fixture,
      fixture.recipient,
    );
    await expectFailure(
      openCollaborativeVaultWithPinnedTrust({
        ...pinnedInput(fixture, fixture.state3, fixture.proof1To3),
        document: unauthorized.document,
        mutationProof: unauthorized.proof,
      }),
      'writer-unauthorized',
    );
    await expect(
      state3CandidateWithTransition(fixture, fixture.owner, {
        issuedAt: T2,
        expiresAt: T3,
      }),
    ).rejects.toThrow('Mutation expiry must follow its timestamp');
    const after = await readRecipientRollbackAnchor(
      anchorPath(),
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );
    expect(after).toEqual(before);
  });

  it('rejects reordered, gapped, wrong-starting, and invalid-registry proofs without moving the anchor', async () => {
    const fixture = await buildFixture();
    const enrolled = await enrollAndOpenCollaborativeVault(firstInput(fixture));
    releaseOpened(enrolled);
    const before = await readRecipientRollbackAnchor(
      anchorPath(),
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );
    const malformed = [
      { ...fixture.proof1To3, entries: [...fixture.proof1To3.entries].reverse() },
      { ...fixture.proof1To3, entries: [fixture.proof1To3.entries[1]] },
      {
        ...fixture.proof1To3,
        startingAuthorizationWitness: fixture.state3.witness,
      },
      {
        ...fixture.proof1To3,
        startingAuthorizationWitness: {
          ...fixture.proof1To3.startingAuthorizationWitness,
          databaseDeviceRegistry: {
            ...fixture.proof1To3.startingAuthorizationWitness.databaseDeviceRegistry,
            authoritySignature: mutateBase64(
              fixture.proof1To3.startingAuthorizationWitness.databaseDeviceRegistry
                .authoritySignature,
            ),
          },
        },
      },
      {
        ...fixture.proof1To3,
        startingAuthorizationWitness: {
          ...fixture.proof1To3.startingAuthorizationWitness,
          databaseAuthorityRecoveryEnvelope: {
            ...fixture.proof1To3.startingAuthorizationWitness
              .databaseAuthorityRecoveryEnvelope,
            sealedVaultRootKey: mutateBase64(
              fixture.proof1To3.startingAuthorizationWitness
                .databaseAuthorityRecoveryEnvelope.sealedVaultRootKey,
            ),
          },
        },
      },
      {
        ...fixture.proof1To3,
        startingAuthorizationWitness: {
          ...fixture.proof1To3.startingAuthorizationWitness,
          databaseAuthorityRecoveryEnvelope: {
            ...fixture.proof1To3.startingAuthorizationWitness
              .databaseAuthorityRecoveryEnvelope,
            authorityRecoveryKeyFingerprint: digest(99),
          },
        },
      },
    ];
    for (const [index, proof] of malformed.entries()) {
      await expectFailure(
        openCollaborativeVaultWithPinnedTrust({
          ...pinnedInput(fixture, fixture.state3, fixture.proof1To3),
          mutationProof: proof,
          rollbackAnchorPath: anchorPath(),
        }),
      );
      const after = await readRecipientRollbackAnchor(
        anchorPath(),
        fixture.deviceProtectionSecret,
        { expectedScope: fixture.scope },
      );
      expect(after, `malformed proof ${String(index)}`).toEqual(before);
    }
  });

  it('rejects a wrong writer signature and leaves protected state unchanged', async () => {
    const fixture = await buildFixture();
    const enrolled = await enrollAndOpenCollaborativeVault(firstInput(fixture));
    releaseOpened(enrolled);
    const badLink = {
      ...fixture.state2.link,
      writerSignature: {
        ...fixture.state2.link.writerSignature,
        signature: mutateBase64(fixture.state2.link.writerSignature.signature),
      },
    };
    const badDocument = {
      ...fixture.state2.document,
      currentMutationLink: badLink,
    };
    const badProof = {
      ...fixture.proof1To2,
      entries: [{ link: badLink }],
    };
    const before = await readRecipientRollbackAnchor(
      anchorPath(),
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );
    await expectFailure(
      openCollaborativeVaultWithPinnedTrust({
        ...pinnedInput(fixture, fixture.state2, fixture.proof1To2),
        document: badDocument,
        mutationProof: badProof,
      }),
      'signature-invalid',
    );
    const after = await readRecipientRollbackAnchor(
      anchorPath(),
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );
    expect(after).toEqual(before);
  });

  it('rejects a discovery record not signed by the exact mutation writer', async () => {
    const fixture = await buildFixture();
    const enrolled = await enrollAndOpenCollaborativeVault(firstInput(fixture));
    releaseOpened(enrolled);
    const record = fixture.state2.document.discoveryRecords[0];
    if (record === undefined) throw new Error('Discovery fixture missing');
    const document = {
      ...fixture.state2.document,
      discoveryRecords: fixture.state2.document.discoveryRecords.map(
        (candidate, index) =>
          index === 0
            ? {
                ...candidate,
                writerSignature: mutateBase64(candidate.writerSignature),
              }
            : candidate,
      ),
    };
    await expectFailure(
      openCollaborativeVaultWithPinnedTrust({
        ...pinnedInput(fixture, fixture.state2, fixture.proof1To2),
        document,
      }),
      'signature-invalid',
    );
    const anchor = await readRecipientRollbackAnchor(
      anchorPath(),
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );
    expect(anchor.documentRevision).toBe(fixture.state1.tuple.documentRevision);
  });

  it('applies the authority deny fence by device identity and signing fingerprint', async () => {
    const deniedRecipient = await buildFixture('recipient-device');
    await expectFailure(
      enrollAndOpenCollaborativeVault(
        firstInput(
          deniedRecipient,
          deniedRecipient.state1,
          undefined,
          anchorPath('denied-recipient'),
        ),
      ),
      'recipient-inactive',
    );

    const deniedWriter = await buildFixture('owner-signing-fingerprint');
    await expectFailure(
      enrollAndOpenCollaborativeVault(
        firstInput(
          deniedWriter,
          deniedWriter.state1,
          undefined,
          anchorPath('denied-writer'),
        ),
      ),
      'writer-inactive',
    );
  });

  it('rejects manifest ciphertext, AAD, and recipient-envelope substitution', async () => {
    const fixture = await buildFixture();
    const ciphertextTamper = {
      ...fixture.state1.document,
      encryptedMembershipManifest: {
        ...fixture.state1.document.encryptedMembershipManifest,
        ciphertext: mutateBase64(
          fixture.state1.document.encryptedMembershipManifest.ciphertext,
        ),
      },
    };
    const aadTamper = {
      ...fixture.state1.document,
      encryptedPayload: {
        ...fixture.state1.document.encryptedPayload,
        aad: {
          ...fixture.state1.document.encryptedPayload.aad,
          documentRevision: fixture.state1.tuple.documentRevision + 1,
        },
      },
    };
    const discovery = fixture.state1.document.discoveryRecords[0];
    if (discovery === undefined) throw new Error('Fixture discovery missing');
    const envelopeTamper = {
      ...fixture.state1.document,
      discoveryRecords: [
        {
          ...discovery,
          encryptedMemberKeyEnvelope: {
            ...discovery.encryptedMemberKeyEnvelope,
            sealedVaultRootKey: mutateBase64(
              discovery.encryptedMemberKeyEnvelope.sealedVaultRootKey,
            ),
          },
        },
      ],
    };
    for (const [index, document] of [
      ciphertextTamper,
      aadTamper,
      envelopeTamper,
    ].entries()) {
      await expectFailure(
        enrollAndOpenCollaborativeVault({
          ...firstInput(
            fixture,
            fixture.state1,
            undefined,
            anchorPath(`tamper-${String(index)}`),
          ),
          document,
        }),
      );
    }
  });

  it('rejects rollback and a same-revision finalized-link fork before key release', async () => {
    const fixture = await buildFixture();
    const enrolled = await enrollAndOpenCollaborativeVault(firstInput(fixture));
    releaseOpened(enrolled);
    const advanced = await openCollaborativeVaultWithPinnedTrust(
      pinnedInput(fixture, fixture.state3, fixture.proof1To3),
    );
    releaseOpened(advanced);

    await expectFailure(
      openCollaborativeVaultWithPinnedTrust(
        pinnedInput(fixture, fixture.state1, undefined),
      ),
      'rollback',
    );

    const second = await buildFixture();
    const path = anchorPath('fork.anchor');
    const openedSecond = await enrollAndOpenCollaborativeVault(
      firstInput(second, second.state2, second.proof1To2, path),
    );
    releaseOpened(openedSecond);
    const forkLink = {
      ...second.state2.link,
      writerSignature: {
        ...second.state2.link.writerSignature,
        signature: mutateBase64(second.state2.link.writerSignature.signature),
      },
    };
    await expectFailure(
      openCollaborativeVaultWithPinnedTrust({
        ...pinnedInput(second, second.state2, undefined, path),
        document: { ...second.state2.document, currentMutationLink: forkLink },
      }),
      'fork',
    );
  });

  it('rejects substituted pinned authority and recipient device identities', async () => {
    const fixture = await buildFixture();
    const substitute = await buildFixture();
    const enrolled = await enrollAndOpenCollaborativeVault(firstInput(fixture));
    releaseOpened(enrolled);
    await expectFailure(
      openCollaborativeVaultWithPinnedTrust({
        ...pinnedInput(fixture, fixture.state1),
        trusted: substitute.trust,
      }),
      'trust-mismatch',
    );
    await expectFailure(
      openCollaborativeVaultWithPinnedTrust({
        ...pinnedInput(fixture, fixture.state1),
        trusted: {
          authorityDelegation: fixture.delegation,
          principalPublicIdentities: [
            fixture.owner.identity,
            substitute.recipient.identity,
          ],
        },
      }),
      'recipient-inactive',
    );
    const anchor = await readRecipientRollbackAnchor(
      anchorPath(),
      fixture.deviceProtectionSecret,
      { expectedScope: fixture.scope },
    );
    expect(anchor.documentRevision).toBe(fixture.state1.tuple.documentRevision);
  });

  it('rejects expired or checkpoint-mismatched enrollment trust', async () => {
    const fixture = await buildFixture();
    await expectFailure(
      enrollAndOpenCollaborativeVault({
        ...firstInput(fixture, fixture.state1, undefined, anchorPath('expired')),
        enrollmentReceipt: {
          ...fixture.receipt,
          expiresAt: T2,
        },
      }),
      'trust-expired',
    );
    await expectFailure(
      enrollAndOpenCollaborativeVault({
        ...firstInput(
          fixture,
          fixture.state1,
          undefined,
          anchorPath('checkpoint-mismatch'),
        ),
        enrollmentCheckpoint: {
          ...fixture.checkpoint,
          headDigest: digest(70),
        },
      }),
      'trust-mismatch',
    );
  });

  it('rejects first use without an enrollment receipt and checkpoint', async () => {
    const fixture = await buildFixture();
    await expectFailure(
      enrollAndOpenCollaborativeVault({
        ...firstInput(
          fixture,
          fixture.state1,
          undefined,
          anchorPath('missing-enrollment-trust'),
        ),
        enrollmentReceipt: undefined,
        enrollmentCheckpoint: undefined,
      }),
      'trust-required',
    );
  });

  it('releases no result when protected-anchor persistence fails', async () => {
    const fixture = await buildFixture();
    await expectFailure(
      enrollAndOpenCollaborativeVault(
        firstInput(
          fixture,
          fixture.state1,
          undefined,
          join(directory, 'missing-directory', 'anchor'),
        ),
      ),
      'anchor-persistence-failed',
    );
  });
});
