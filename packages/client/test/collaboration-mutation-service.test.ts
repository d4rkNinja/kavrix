import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
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
  computeAuthorizationCheckpointDigest,
  computeAuthorityDelegationDigest,
  computeAuthorityRecoveryEnvelopeDigest,
  computeAuthorizationStateDigest,
  computeAuthorizationTransitionDigest,
  computeDeviceRegistryDigest,
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
  computeOperationOutcomeDigest,
  computePolicyDigest,
  computePolicyStateDigest,
  computePublicKeyFingerprint,
  zeroize,
  verifyCollaborationRecord,
} from '@kavrix/crypto';
import {
  collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument,
  createCollaborationAuthorityRollbackAnchor,
  createRecipientRollbackAnchor,
  createCollaborativeOperationJournal,
  readCollaborativeOperationJournal,
  readCollaborationAuthorityRollbackAnchor,
  readRecipientRollbackAnchor,
  reconcileCollaborativeOperationJournal,
  recipientRollbackAnchorFromCollaborativeVaultDocument,
  transitionCollaborationAuthorityRollbackAnchor,
} from '@kavrix/key-files';
import * as keyFiles from '@kavrix/key-files';
import {
  canonicalJson,
  collaborationAadMetadataSchema,
  collaborationAadSchema,
  collaborationAuthorizationStateCoreSchema,
  collaborationAuthorizationCheckpointSchema,
  collaborationAuthorizationTransitionSchema,
  collaborationAuthorityDelegationSchema,
  collaborationDatabaseDeviceRegistrySchema,
  collaborationFinalizedMutationLinkSchema,
  collaborationKeyEnvelopeSchema,
  collaborationMutationProofEntrySchema,
  collaborationPolicyStateSchema,
  collaborationRevisionTupleSchema,
  collaborativeMembershipManifestSchema,
  collaborativeVaultDocumentSchema,
  databaseAuthorityRecoveryEnvelopeSchema,
  deviceCertificateSchema,
  durableOperationOutcomeSchema,
  membershipHistoryEventSchema,
  membershipHistorySchema,
  membershipHistoryCheckpointSchema,
  principalIdSchema,
  publicIdentityExportSchema,
  sha256DigestSchema,
  type CollaborationDatabaseDeviceRegistry,
  type CollaborationAuthorizationCheckpoint,
  type CollaborationAeadEnvelope,
  type CollaborationRevisionTuple,
  type CollaborativeMembershipManifest,
  type CollaborativeVaultDocument,
  type DurableOperationOutcome,
  type DeviceCertificate,
  type Sha256Digest,
} from '@kavrix/schemas';
import {
  EncryptedDatabaseStoreError,
  type CollaborativeVaultStore,
  type PublishCollaborativeVaultInput,
} from '@kavrix/storage';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@kavrix/core', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    authorizeOperation: vi.fn(() => ({ authorized: true })),
    checkActiveOwnerInvariant: vi.fn(() => ({ valid: true })),
    validateRevisionTransition: vi.fn(() => ({ valid: true })),
  };
});

vi.mock('@kavrix/crypto', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    decryptCollaborationEnvelope: vi.fn(),
    verifyAuthorityDelegation: vi.fn(() => Promise.resolve(true)),
    verifyAuthorizationCheckpoint: vi.fn(() => Promise.resolve(true)),
    verifyAuthorizationTransitionAuthority: vi.fn(() => Promise.resolve(true)),
    verifyCollaborationRecord: vi.fn(() => Promise.resolve(true)),
    verifyCommittedOperationOutcome: vi.fn(() => Promise.resolve(true)),
    verifyDiscoveryRecord: vi.fn(() => Promise.resolve(true)),
    verifyFinalizedMutationLink: vi.fn(() => Promise.resolve(true)),
    verifyOperationTombstone: vi.fn(() => Promise.resolve(true)),
  };
});

vi.mock('../../key-files/dist/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(() => Promise.resolve()),
  verifyWindowsDirectoryAcl: vi.fn(() => Promise.resolve()),
  verifyWindowsUserOnlyAcl: vi.fn(() => Promise.resolve()),
}));

vi.mock('../src/collaboration-state-verifier.js', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    openCollaborativeVaultForDatabaseAuthorityRecovery: vi.fn(),
    openCollaborativeVaultWithPinnedTrust: vi.fn(),
    verifyCollaborativeJournalSuccessorChain: vi.fn(),
  };
});

import { decryptCollaborationEnvelope } from '@kavrix/crypto';
import {
  CollaborationStateVerificationError,
  openCollaborativeVaultForDatabaseAuthorityRecovery,
  openCollaborativeVaultWithPinnedTrust,
  verifyCollaborativeJournalSuccessorChain,
  type CollaborativeVaultPinnedTrust,
} from '../src/collaboration-state-verifier.js';
import {
  publishPreparedCollaborativeMutation,
  resumeCollaborativeMutationFromJournal,
  type PublishPreparedCollaborativeMutationInput,
  type ResumeCollaborativeMutationFromJournalInput,
} from '../src/collaboration-mutation-service.js';

const DATABASE_ID = 'database-publisher';
const VAULT_ID = 'vault-publisher';
const PRINCIPAL_ID = 'principal-owner';
const DEVICE_ID = 'device-owner';
const MEMBERSHIP_ID = 'membership-owner';
const CREATED_AT = '2026-08-29T00:00:00.000Z';
const GENESIS_AT = '2026-08-29T00:01:00.000Z';
const MUTATION_AT = '2026-08-29T00:03:00.000Z';
const NOW = '2026-08-29T00:04:00.000Z';
const EXPIRES_AT = '2026-08-29T00:10:00.000Z';
const RETAIN_UNTIL = '2026-09-29T00:00:00.000Z';
const SIGNATURE = Buffer.alloc(64, 40).toString('base64url');
const ROOT_PUBLIC_KEY = Buffer.alloc(32, 1).toString('base64url');
const DEVICE_SIGNING_PUBLIC_KEY = Buffer.alloc(32, 2).toString('base64url');
const DEVICE_ENCRYPTION_PUBLIC_KEY = Buffer.alloc(32, 3).toString('base64url');
const AUTHORITY_SIGNING_PUBLIC_KEY = Buffer.alloc(32, 4).toString('base64url');
const AUTHORITY_RECOVERY_PUBLIC_KEY = Buffer.alloc(32, 5).toString('base64url');
const HISTORICAL_DEVICE_ID = 'device-historical-owner';
const HISTORICAL_SIGNING_PUBLIC_KEY = Buffer.alloc(32, 6).toString('base64url');
const HISTORICAL_ENCRYPTION_PUBLIC_KEY = Buffer.alloc(32, 7).toString('base64url');
const HISTORY_EVENT_AT = '2026-08-29T00:01:30.000Z';
const HISTORY_CHECKPOINT_AT = '2026-08-29T00:01:30.000Z';
const HISTORICAL_DEVICE_RETIRED_AT = '2026-08-29T00:02:00.000Z';
const HISTORICAL_DEVICE_DENIED_AT = '2026-08-29T00:02:30.000Z';
const REPLACEMENT_PRINCIPAL_ID = 'principal-replacement';
const REPLACEMENT_DEVICE_ID = 'device-replacement';
const REPLACEMENT_MEMBERSHIP_ID = 'membership-replacement';
const REPLACEMENT_ROOT_PUBLIC_KEY = Buffer.alloc(32, 8).toString('base64url');
const REPLACEMENT_SIGNING_PUBLIC_KEY = Buffer.alloc(32, 9).toString('base64url');
const REPLACEMENT_ENCRYPTION_PUBLIC_KEY = Buffer.alloc(32, 10).toString('base64url');

type PreparedBundle = PublishPreparedCollaborativeMutationInput['prepared'];

type Fixture = Readonly<{
  current: CollaborativeVaultDocument;
  currentManifest: CollaborativeMembershipManifest;
  candidateManifest: CollaborativeMembershipManifest;
  registry: CollaborationDatabaseDeviceRegistry;
  prepared: PreparedBundle;
  trusted: CollaborativeVaultPinnedTrust;
  scope: PublishPreparedCollaborativeMutationInput['scope'];
}>;

type StoreBehavior =
  | 'success'
  | 'conflict'
  | 'rejected'
  | 'commit-then-throw'
  | 'throw-without-outcome'
  | 'readback-mismatch';

class TestStore {
  current: CollaborativeVaultDocument;
  outcome: DurableOperationOutcome | null = null;
  behavior: StoreBehavior = 'success';
  readonly publications: PublishCollaborativeVaultInput[] = [];
  readonly checkpointAppends: CollaborationAuthorizationCheckpoint[] = [];
  readonly proofRangeRequests: unknown[] = [];
  readonly events: string[] = [];
  failCheckpointAppend = false;
  proofRange: Record<string, unknown> | undefined;
  postPublishCurrent: CollaborativeVaultDocument | undefined;
  readonly registry: CollaborationDatabaseDeviceRegistry;

  constructor(fixture: Fixture) {
    this.current = fixture.current;
    this.registry = fixture.registry;
  }

  getCollaborativeVault(): Promise<CollaborativeVaultDocument | null> {
    if (this.publications.length > 0) this.events.push('readback');
    return Promise.resolve(structuredClone(this.current));
  }

  getDatabaseDeviceRegistry(): Promise<CollaborationDatabaseDeviceRegistry> {
    return Promise.resolve(structuredClone(this.registry));
  }

  getCollaborationAuthorizationWitness(): Promise<null> {
    return Promise.resolve(null);
  }

  getCollaborativeMutationProofRange(input: unknown): Promise<unknown> {
    this.proofRangeRequests.push(structuredClone(input));
    return this.proofRange === undefined
      ? Promise.reject(new Error('proof range not configured'))
      : Promise.resolve(structuredClone(this.proofRange));
  }

  getCollaborativeOperationOutcome(): Promise<DurableOperationOutcome | null> {
    return Promise.resolve(
      this.outcome === null ? null : structuredClone(this.outcome),
    );
  }

  publishCollaborativeVault(
    input: PublishCollaborativeVaultInput,
  ): Promise<DurableOperationOutcome> {
    this.publications.push(structuredClone(input));
    this.events.push('publish');
    if (this.behavior === 'conflict') {
      return Promise.reject(new EncryptedDatabaseStoreError('conflict'));
    }
    if (this.behavior === 'rejected') {
      return Promise.resolve(rejectedOutcome(input.outcome));
    }
    if (this.behavior === 'throw-without-outcome') {
      return Promise.reject(new EncryptedDatabaseStoreError('connection'));
    }
    this.outcome = structuredClone(input.outcome);
    this.current =
      this.behavior === 'readback-mismatch'
        ? this.current
        : structuredClone(this.postPublishCurrent ?? input.candidate);
    if (this.behavior === 'commit-then-throw') {
      return Promise.reject(new EncryptedDatabaseStoreError('connection'));
    }
    return Promise.resolve(structuredClone(input.outcome));
  }

  appendCollaborationAuthorizationCheckpoint(
    checkpoint: CollaborationAuthorizationCheckpoint,
  ): Promise<void> {
    this.checkpointAppends.push(structuredClone(checkpoint));
    this.events.push('checkpoint');
    return this.failCheckpointAppend
      ? Promise.reject(new EncryptedDatabaseStoreError('connection'))
      : Promise.resolve();
  }
}

let directory = '';
let rollbackAnchorPath = '';
let authorityRollbackAnchorPath = '';
let operationJournalPath = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-publisher-'));
  rollbackAnchorPath = join(directory, 'recipient-anchor.cvkx');
  authorityRollbackAnchorPath = join(directory, 'authority-anchor.cvkx');
  operationJournalPath = join(directory, 'operation-journal.cvkx');
  vi.clearAllMocks();
  vi.mocked(verifyCollaborativeJournalSuccessorChain).mockReset();
  vi.mocked(verifyCollaborationRecord).mockImplementation(() => Promise.resolve(true));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

function bytes(length: number, value: number): string {
  return Buffer.alloc(length, value).toString('base64url');
}

function digest(value: number): Sha256Digest {
  return sha256DigestSchema.parse(bytes(32, value));
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('Incomplete publisher fixture');
  return value;
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

function authorizationCore(
  manifest: CollaborativeMembershipManifest,
): ReturnType<typeof collaborationAuthorizationStateCoreSchema.parse> {
  return collaborationAuthorizationStateCoreSchema.parse({
    protocolVersion: manifest.protocolVersion,
    databaseId: manifest.databaseId,
    vaultId: manifest.vaultId,
    authorityEpoch: manifest.authorityEpoch,
    databaseDeviceGeneration: manifest.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: manifest.databaseDeviceRegistryDigest,
    membershipRevision: manifest.membershipRevision,
    policyRevision: manifest.policyRevision,
    keyEpoch: manifest.keyEpoch,
    memberships: manifest.memberships.map((membership) => ({
      ...membership,
      devices: membership.devices.map((device) => {
        const core: Record<string, unknown> = { ...device };
        Reflect.deleteProperty(core, 'rootSignature');
        return core;
      }),
    })),
    ownerPrincipalIds: manifest.ownerPrincipalIds,
    keyEnvelopes: manifest.keyEnvelopes.map((envelope) => {
      const core: Record<string, unknown> = { ...envelope };
      Reflect.deleteProperty(core, 'envelopeDigest');
      Reflect.deleteProperty(core, 'createdAt');
      Reflect.deleteProperty(core, 'ownerSignature');
      return core;
    }),
    approvalPolicy: manifest.approvalPolicy,
  });
}

function tupleOf(document: CollaborativeVaultDocument): CollaborationRevisionTuple {
  return collaborationRevisionTupleSchema.parse({
    authorityEpoch: document.authorityEpoch,
    documentRevision: document.documentRevision,
    membershipRevision: document.membershipRevision,
    policyRevision: document.policyRevision,
    keyEpoch: document.keyEpoch,
    databaseDeviceGeneration: document.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: document.databaseDeviceRegistryDigest,
    authorizationStateDigest: document.authorizationStateDigest,
  });
}

function buildRegistry(
  deniedDevices: CollaborationDatabaseDeviceRegistry['deniedDevices'] = [],
): CollaborationDatabaseDeviceRegistry {
  const base = collaborationDatabaseDeviceRegistrySchema.parse({
    format: 'kavrix-collaborative-device-registry',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    authorityEpoch: 1,
    authorityFingerprint: computePublicKeyFingerprint(
      AUTHORITY_SIGNING_PUBLIC_KEY,
      'ed25519',
    ),
    generation: 1,
    previousRegistryDigest: digest(9),
    registryDigest: digest(10),
    deniedDevices,
    updatedAt: deniedDevices.length === 0 ? GENESIS_AT : MUTATION_AT,
    authoritySignature: SIGNATURE,
  });
  return collaborationDatabaseDeviceRegistrySchema.parse({
    ...base,
    registryDigest: computeDeviceRegistryDigest(base),
  });
}

function buildManifest(
  registry: CollaborationDatabaseDeviceRegistry,
  documentRevision: 1 | 2,
  previousHeadDigest: Sha256Digest,
  previousMembershipDigest: Sha256Digest,
  previousHistoryDigest: Sha256Digest,
  historicalDevice?: DeviceCertificate,
): CollaborativeMembershipManifest {
  const device = deviceCertificateSchema.parse({
    protocolVersion: 1,
    principalId: PRINCIPAL_ID,
    deviceId: DEVICE_ID,
    deviceGeneration: 1,
    signingPublicKey: DEVICE_SIGNING_PUBLIC_KEY,
    encryptionPublicKey: DEVICE_ENCRYPTION_PUBLIC_KEY,
    state: 'active',
    createdAt: CREATED_AT,
    stateChangedAt: CREATED_AT,
    rootSignature: SIGNATURE,
  });
  const membership =
    collaborativeMembershipManifestSchema.shape.memberships.element.parse({
      membershipId: MEMBERSHIP_ID,
      principalId: PRINCIPAL_ID,
      principalFingerprint: computePublicKeyFingerprint(ROOT_PUBLIC_KEY, 'ed25519'),
      rootSigningPublicKey: ROOT_PUBLIC_KEY,
      identityGeneration: 1,
      role: 'owner',
      state: 'active',
      devices: historicalDevice === undefined ? [device] : [device, historicalDevice],
      createdAt: CREATED_AT,
      updatedAt: GENESIS_AT,
    });
  const memberEnvelopeBase = collaborationKeyEnvelopeSchema.parse({
    format: 'kavrix-collaborative-member-key-envelope',
    protocolVersion: 1,
    algorithm: 'x25519-sealed-box',
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    membershipId: MEMBERSHIP_ID,
    principalId: PRINCIPAL_ID,
    deviceId: DEVICE_ID,
    recipientEncryptionKeyFingerprint: computePublicKeyFingerprint(
      DEVICE_ENCRYPTION_PUBLIC_KEY,
      'x25519',
    ),
    keyEpoch: 1,
    membershipRevision: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registry.registryDigest,
    sealedVaultRootKey: bytes(48, 20),
    envelopeDigest: digest(21),
    createdAt: GENESIS_AT,
    ownerSignature: SIGNATURE,
  });
  const memberEnvelope = collaborationKeyEnvelopeSchema.parse({
    ...memberEnvelopeBase,
    envelopeDigest: computeKeyEnvelopeDigest(memberEnvelopeBase),
  });
  const recoveryEnvelopeBase = databaseAuthorityRecoveryEnvelopeSchema.parse({
    format: 'kavrix-collaborative-authority-recovery-envelope',
    protocolVersion: 1,
    algorithm: 'x25519-sealed-box',
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    authorityRecoveryKeyFingerprint: computePublicKeyFingerprint(
      AUTHORITY_RECOVERY_PUBLIC_KEY,
      'x25519',
    ),
    keyEpoch: 1,
    membershipRevision: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registry.registryDigest,
    sealedVaultRootKey: bytes(48, 22),
    envelopeDigest: digest(23),
    sealedByPrincipalId: PRINCIPAL_ID,
    sealedByDeviceId: DEVICE_ID,
    createdAt: GENESIS_AT,
    ownerSignature: SIGNATURE,
  });
  const recoveryEnvelope = databaseAuthorityRecoveryEnvelopeSchema.parse({
    ...recoveryEnvelopeBase,
    envelopeDigest: computeAuthorityRecoveryEnvelopeDigest(recoveryEnvelopeBase),
  });
  const policyBase = collaborationPolicyStateSchema.parse({
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    policyRevision: 1,
    approvalPolicy: 'none',
    policyDigest: digest(24),
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registry.registryDigest,
    changedByPrincipalId: PRINCIPAL_ID,
    changedByDeviceId: DEVICE_ID,
    changedAt: GENESIS_AT,
    signature: SIGNATURE,
  });
  const policy = collaborationPolicyStateSchema.parse({
    ...policyBase,
    policyDigest: computePolicyDigest(policyBase),
  });
  const historyBase = {
    protocolVersion: 1 as const,
    databaseId: registry.databaseId,
    vaultId: collaborativeVaultDocumentSchema.shape.vaultId.parse(VAULT_ID),
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registry.registryDigest,
    events: [],
    checkpoints: [],
    compactedThroughRevision: 0,
    compactedHistoryDigest: COLLABORATION_GENESIS_COMPACTED_HISTORY_DIGEST,
    previousHeadDigest,
    previousHistoryDigest,
    currentHistoryDigest: digest(25),
  };
  const history = membershipHistorySchema.parse({
    ...historyBase,
    currentHistoryDigest: computeMembershipHistoryDigest(historyBase),
  });
  const semantic = {
    protocolVersion: 1 as const,
    databaseId: registry.databaseId,
    vaultId: collaborativeVaultDocumentSchema.shape.vaultId.parse(VAULT_ID),
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registry.registryDigest,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    memberships: [membership],
    ownerPrincipalIds: [
      collaborativeVaultDocumentSchema.shape.currentMutationLink.shape.commitment.shape.writerPrincipalId.parse(
        PRINCIPAL_ID,
      ),
    ],
    keyEnvelopes: [memberEnvelope, recoveryEnvelope],
    approvalPolicy: 'none' as const,
  };
  const provisional = collaborativeMembershipManifestSchema.parse({
    format: 'kavrix-collaborative-membership-manifest',
    ...semantic,
    documentRevision,
    authorizationStateDigest: digest(26),
    policy,
    pendingApprovals: [],
    pendingTransfers: [],
    history,
    previousMembershipDigest,
    membershipDigest: digest(27),
    previousHeadDigest,
    createdAt: CREATED_AT,
    updatedAt: documentRevision === 1 ? GENESIS_AT : MUTATION_AT,
  });
  const authorizationStateDigest = computeAuthorizationStateDigest(
    authorizationCore(provisional),
  );
  const withAuthorization = collaborativeMembershipManifestSchema.parse({
    ...provisional,
    authorizationStateDigest,
  });
  return collaborativeMembershipManifestSchema.parse({
    ...withAuthorization,
    membershipDigest: computeMembershipManifestDigest(withAuthorization),
  });
}

function buildEnvelope(
  tuple: CollaborationRevisionTuple,
  value: number,
): CollaborationAeadEnvelope {
  return {
    version: 1 as const,
    algorithm: 'xchacha20-poly1305-ietf' as const,
    nonce: bytes(24, value),
    ciphertext: bytes(64, value + 1),
    authenticationTag: bytes(16, value + 2),
    aad: aad(tuple, value === 30 ? 'vault-payload' : 'membership-manifest'),
  };
}

function buildCurrentDocument(
  registry: CollaborationDatabaseDeviceRegistry,
  manifest: CollaborativeMembershipManifest,
): CollaborativeVaultDocument {
  const tuple = collaborationRevisionTupleSchema.parse({
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: registry.registryDigest,
    authorizationStateDigest: manifest.authorizationStateDigest,
  });
  const payload = buildEnvelope(tuple, 30);
  const encryptedManifest = buildEnvelope(tuple, 34);
  const transitionBase = collaborationAuthorizationTransitionSchema.parse({
    format: 'kavrix-collaborative-authorization-transition',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: 'operation-genesis',
    operationType: 'genesis-migration',
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousAuthorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
    authorizationStateDigest: tuple.authorizationStateDigest,
    previousTuple: {
      ...tuple,
      documentRevision: 0,
      membershipRevision: 0,
      policyRevision: 0,
      authorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
    },
    nextTuple: tuple,
    evidence: { kind: 'none' },
    issuedAt: GENESIS_AT,
    expiresAt: EXPIRES_AT,
    transitionDigest: digest(38),
    transitionSignature: {
      signerKind: 'owner-device',
      signerPrincipalId: PRINCIPAL_ID,
      signerDeviceId: DEVICE_ID,
      signature: SIGNATURE,
    },
  });
  const transition = collaborationAuthorizationTransitionSchema.parse({
    ...transitionBase,
    transitionDigest: computeAuthorizationTransitionDigest(transitionBase),
  });
  const placeholder = {
    protocolVersion: 1 as const,
    databaseId: registry.databaseId,
    vaultId: collaborativeVaultDocumentSchema.shape.vaultId.parse(VAULT_ID),
    operationId: 'operation-genesis',
    operationType: 'genesis-migration' as const,
    requestDigest: digest(39),
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    previousAuthorizationStateDigest: COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
    authorizationTransitionDigest: transition.transitionDigest,
    previousAuthorityEpoch: 1,
    previousDocumentRevision: 0,
    previousMembershipRevision: 0,
    previousPolicyRevision: 0,
    previousKeyEpoch: 1,
    previousDatabaseDeviceGeneration: 1,
    previousDatabaseDeviceRegistryDigest: registry.registryDigest,
    ...tuple,
    encryptedPayloadDigest: computeEncryptedPayloadDigest(payload),
    encryptedMembershipDigest: computeEncryptedMembershipDigest(encryptedManifest),
    encryptedEnvelopesDigest: computeKeyEnvelopeSetDigest(manifest.keyEnvelopes),
    policyDigest: manifest.policy.policyDigest,
    writerPrincipalId: PRINCIPAL_ID,
    writerDeviceId: DEVICE_ID,
    timestamp: GENESIS_AT,
    expiresAt: EXPIRES_AT,
  };
  const commitment = placeholder;
  const headDigest = computeMutationHead(commitment);
  const delegationBase = collaborationAuthorityDelegationSchema.parse({
    format: 'kavrix-collaborative-authority-delegation',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    authoritySigningPublicKey: AUTHORITY_SIGNING_PUBLIC_KEY,
    authoritySigningKeyFingerprint: registry.authorityFingerprint,
    authorityRecoveryPublicKey: AUTHORITY_RECOVERY_PUBLIC_KEY,
    authorityRecoveryKeyFingerprint: computePublicKeyFingerprint(
      AUTHORITY_RECOVERY_PUBLIC_KEY,
      'x25519',
    ),
    genesisOperationId: 'operation-genesis',
    genesisTuple: tuple,
    genesisHeadDigest: headDigest,
    initialAuthorizationStateDigest: tuple.authorizationStateDigest,
    initialOwnerPrincipalId: PRINCIPAL_ID,
    initialOwnerRootKeyFingerprint: computePublicKeyFingerprint(
      ROOT_PUBLIC_KEY,
      'ed25519',
    ),
    initialOwnerDeviceId: DEVICE_ID,
    initialOwnerDeviceSigningKeyFingerprint: computePublicKeyFingerprint(
      DEVICE_SIGNING_PUBLIC_KEY,
      'ed25519',
    ),
    initialOwnerDeviceEncryptionKeyFingerprint: computePublicKeyFingerprint(
      DEVICE_ENCRYPTION_PUBLIC_KEY,
      'x25519',
    ),
    issuedAt: CREATED_AT,
    authoritySignature: SIGNATURE,
  });
  const authorityDelegationDigest = computeAuthorityDelegationDigest(delegationBase);
  const link = collaborationFinalizedMutationLinkSchema.parse({
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
      writerPrincipalId: PRINCIPAL_ID,
      writerDeviceId: DEVICE_ID,
      commitmentDigest: headDigest,
      signature: SIGNATURE,
    },
    finalizedAt: GENESIS_AT,
  });
  return collaborativeVaultDocumentSchema.parse({
    format: 'kavrix-collaborative-vault',
    documentVersion: 1,
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    ...tuple,
    previousHeadDigest: COLLABORATION_GENESIS_HEAD_DIGEST,
    headDigest,
    authorityDelegation: delegationBase,
    authorityDelegationDigest,
    encryptedPayloadDigest: commitment.encryptedPayloadDigest,
    encryptedMembershipDigest: commitment.encryptedMembershipDigest,
    encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
    policyDigest: commitment.policyDigest,
    databaseAuthorityRecoveryEnvelope: manifest.keyEnvelopes.find(
      (envelope) => !('membershipId' in envelope),
    ),
    encryptedPayload: payload,
    encryptedMembershipManifest: encryptedManifest,
    discoveryRecords: [],
    currentMutationLink: link,
    createdAt: CREATED_AT,
    updatedAt: GENESIS_AT,
  });
}

function buildPrepared(
  current: CollaborativeVaultDocument,
  manifest: CollaborativeMembershipManifest,
  scope: PublishPreparedCollaborativeMutationInput['scope'],
): PreparedBundle {
  const tuple = collaborationRevisionTupleSchema.parse({
    ...tupleOf(current),
    documentRevision: current.documentRevision + 1,
  });
  const payload = buildEnvelope(tuple, 30);
  const encryptedManifest = buildEnvelope(tuple, 34);
  const placeholder = {
    protocolVersion: 1 as const,
    databaseId: current.databaseId,
    vaultId: current.vaultId,
    operationId: 'operation-ordinary-2',
    operationType: 'ordinary-write' as const,
    requestDigest: digest(43),
    previousHeadDigest: current.headDigest,
    previousAuthorizationStateDigest: current.authorizationStateDigest,
    previousAuthorityEpoch: current.authorityEpoch,
    previousDocumentRevision: current.documentRevision,
    previousMembershipRevision: current.membershipRevision,
    previousPolicyRevision: current.policyRevision,
    previousKeyEpoch: current.keyEpoch,
    previousDatabaseDeviceGeneration: current.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: current.databaseDeviceRegistryDigest,
    ...tuple,
    encryptedPayloadDigest: computeEncryptedPayloadDigest(payload),
    encryptedMembershipDigest: computeEncryptedMembershipDigest(encryptedManifest),
    encryptedEnvelopesDigest: computeKeyEnvelopeSetDigest(manifest.keyEnvelopes),
    policyDigest: manifest.policy.policyDigest,
    writerPrincipalId: PRINCIPAL_ID,
    writerDeviceId: DEVICE_ID,
    timestamp: MUTATION_AT,
    expiresAt: EXPIRES_AT,
  };
  const commitment = {
    ...placeholder,
    requestDigest: computeMutationRequestDigest(placeholder),
  };
  const headDigest = computeMutationHead(commitment);
  const link = collaborationFinalizedMutationLinkSchema.parse({
    format: 'kavrix-collaborative-finalized-mutation-link',
    protocolVersion: 1,
    databaseId: current.databaseId,
    vaultId: current.vaultId,
    authorityDelegationDigest: current.authorityDelegationDigest,
    commitment,
    resultingHeadDigest: headDigest,
    writerSignature: {
      algorithm: 'ed25519',
      writerPrincipalId: PRINCIPAL_ID,
      writerDeviceId: DEVICE_ID,
      commitmentDigest: headDigest,
      signature: SIGNATURE,
    },
    finalizedAt: MUTATION_AT,
  });
  const candidate = collaborativeVaultDocumentSchema.parse({
    ...current,
    ...tuple,
    previousHeadDigest: current.headDigest,
    headDigest,
    encryptedPayloadDigest: commitment.encryptedPayloadDigest,
    encryptedMembershipDigest: commitment.encryptedMembershipDigest,
    encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
    policyDigest: commitment.policyDigest,
    encryptedPayload: payload,
    encryptedMembershipManifest: encryptedManifest,
    currentMutationLink: link,
    updatedAt: MUTATION_AT,
  });
  const proofEntry = collaborationMutationProofEntrySchema.parse({ link });
  const finalizedMutationLinkDigest = computeFinalizedMutationLinkDigest(link);
  const priorTuple = tupleOf(current);
  const outcomeBase = {
    format: 'kavrix-collaborative-operation-outcome' as const,
    protocolVersion: 1 as const,
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    operationId: commitment.operationId,
    operationType: commitment.operationType,
    requestDigest: commitment.requestDigest,
    actorPrincipalId: PRINCIPAL_ID,
    actorDeviceId: DEVICE_ID,
    priorTuple,
    priorHeadDigest: current.headDigest,
    state: 'committed' as const,
    committedTuple: tuple,
    committedHeadDigest: candidate.headDigest,
    finalizedMutationLinkDigest,
    committedAt: MUTATION_AT,
    outcomeDigest: digest(44),
    signedMutationReceipt: {
      format: 'kavrix-collaborative-mutation-receipt' as const,
      protocolVersion: 1 as const,
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      operationId: commitment.operationId,
      operationType: commitment.operationType,
      requestDigest: commitment.requestDigest,
      actorPrincipalId: PRINCIPAL_ID,
      actorDeviceId: DEVICE_ID,
      priorTuple,
      priorHeadDigest: current.headDigest,
      committedTuple: tuple,
      committedHeadDigest: candidate.headDigest,
      finalizedMutationLinkDigest,
      outcomeDigest: digest(44),
      committedAt: MUTATION_AT,
      receiptSignature: SIGNATURE,
    },
    createdAt: MUTATION_AT,
    resolvedAt: MUTATION_AT,
    detailsRetainedUntil: RETAIN_UNTIL,
  };
  const outcomeDigest = computeOperationOutcomeDigest(outcomeBase);
  const proposedOutcome = durableOperationOutcomeSchema.parse({
    ...outcomeBase,
    outcomeDigest,
    signedMutationReceipt: {
      ...outcomeBase.signedMutationReceipt,
      outcomeDigest,
    },
  });
  const candidateAnchor = recipientRollbackAnchorFromCollaborativeVaultDocument(
    candidate,
    scope,
    {
      membershipDigest: computeMembershipStateDigest(authorizationCore(manifest)),
      policyDigest: computePolicyStateDigest(manifest.policy),
      finalizedMutationLinkDigest,
    },
  );
  return { candidate, proofEntry, proposedOutcome, candidateAnchor };
}

function buildCheckpoint(fixture: Fixture): CollaborationAuthorizationCheckpoint {
  const candidate = fixture.prepared.candidate;
  const checkpoint = collaborationAuthorizationCheckpointSchema.parse({
    format: 'kavrix-collaborative-authorization-checkpoint',
    protocolVersion: 1,
    checkpointId: 'checkpoint-operation-ordinary-2',
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    authorityDelegationDigest: candidate.authorityDelegationDigest,
    tuple: tupleOf(candidate),
    headDigest: candidate.headDigest,
    authorizationStateDigest: candidate.authorizationStateDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
      candidate.currentMutationLink,
    ),
    compactedThroughDocumentRevision: candidate.documentRevision,
    checkpointDigest: digest(46),
    signerPrincipalId: PRINCIPAL_ID,
    signerDeviceId: DEVICE_ID,
    createdAt: MUTATION_AT,
    ownerSignature: SIGNATURE,
  });
  return collaborationAuthorizationCheckpointSchema.parse({
    ...checkpoint,
    checkpointDigest: computeAuthorizationCheckpointDigest(checkpoint),
  });
}

function asAddMemberPrepared(
  fixture: Fixture,
  operationType: 'add-member' | 'add-device' = 'add-member',
): PreparedBundle {
  const prior = fixture.current;
  const ordinary = fixture.prepared.candidate;
  const previousTuple = tupleOf(prior);
  const nextTuple = collaborationRevisionTupleSchema.parse({
    ...tupleOf(ordinary),
    membershipRevision: ordinary.membershipRevision + 1,
    authorizationStateDigest: digest(96),
  });
  const encryptedPayload = buildEnvelope(nextTuple, 30);
  const encryptedMembershipManifest = buildEnvelope(nextTuple, 34);
  const transitionInput = collaborationAuthorizationTransitionSchema.parse({
    format: 'kavrix-collaborative-authorization-transition',
    protocolVersion: 1,
    databaseId: ordinary.databaseId,
    vaultId: ordinary.vaultId,
    operationId: ordinary.currentMutationLink.commitment.operationId,
    operationType,
    previousHeadDigest: prior.headDigest,
    previousAuthorizationStateDigest: prior.authorizationStateDigest,
    authorizationStateDigest: nextTuple.authorizationStateDigest,
    previousTuple,
    nextTuple,
    evidence: { kind: 'none' },
    issuedAt: MUTATION_AT,
    expiresAt: EXPIRES_AT,
    transitionDigest: digest(47),
    transitionSignature: {
      signerKind: 'owner-device',
      signerPrincipalId: PRINCIPAL_ID,
      signerDeviceId: DEVICE_ID,
      signature: SIGNATURE,
    },
  });
  const transition = collaborationAuthorizationTransitionSchema.parse({
    ...transitionInput,
    transitionDigest: computeAuthorizationTransitionDigest(transitionInput),
  });
  const commitmentInput = {
    ...ordinary.currentMutationLink.commitment,
    operationType,
    requestDigest: digest(48),
    authorizationTransitionDigest: transition.transitionDigest,
    ...nextTuple,
    encryptedPayloadDigest: computeEncryptedPayloadDigest(encryptedPayload),
    encryptedMembershipDigest: computeEncryptedMembershipDigest(
      encryptedMembershipManifest,
    ),
  };
  const commitment = {
    ...commitmentInput,
    requestDigest: computeMutationRequestDigest(commitmentInput),
  };
  const resultingHeadDigest = computeMutationHead(commitment);
  const link = collaborationFinalizedMutationLinkSchema.parse({
    ...ordinary.currentMutationLink,
    commitment,
    authorizationTransition: transition,
    resultingHeadDigest,
    writerSignature: {
      ...ordinary.currentMutationLink.writerSignature,
      commitmentDigest: resultingHeadDigest,
    },
  });
  const candidate = collaborativeVaultDocumentSchema.parse({
    ...ordinary,
    ...nextTuple,
    headDigest: resultingHeadDigest,
    encryptedPayloadDigest: commitment.encryptedPayloadDigest,
    encryptedMembershipDigest: commitment.encryptedMembershipDigest,
    databaseAuthorityRecoveryEnvelope: {
      ...ordinary.databaseAuthorityRecoveryEnvelope,
      membershipRevision: nextTuple.membershipRevision,
    },
    encryptedPayload,
    encryptedMembershipManifest,
    currentMutationLink: link,
  });
  const finalizedMutationLinkDigest = computeFinalizedMutationLinkDigest(link);
  const proofEntry = collaborationMutationProofEntrySchema.parse({
    link,
    authorizationWitness: {
      format: 'kavrix-collaborative-authorization-witness',
      protocolVersion: 1,
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      authorityDelegationDigest: candidate.authorityDelegationDigest,
      tuple: nextTuple,
      previousHeadDigest: candidate.previousHeadDigest,
      headDigest: candidate.headDigest,
      encryptedMembershipDigest: candidate.encryptedMembershipDigest,
      encryptedEnvelopesDigest: candidate.encryptedEnvelopesDigest,
      policyDigest: candidate.policyDigest,
      databaseDeviceRegistry: fixture.registry,
      databaseAuthorityRecoveryEnvelope: candidate.databaseAuthorityRecoveryEnvelope,
      encryptedMembershipManifest: candidate.encryptedMembershipManifest,
      discoveryRecords: candidate.discoveryRecords,
      finalizedMutationLinkDigest,
    },
  });
  const outcomeInput = {
    ...fixture.prepared.proposedOutcome,
    operationType,
    requestDigest: commitment.requestDigest,
    committedHeadDigest: candidate.headDigest,
    finalizedMutationLinkDigest,
    outcomeDigest: digest(49),
    signedMutationReceipt: {
      ...fixture.prepared.proposedOutcome.signedMutationReceipt,
      operationType,
      requestDigest: commitment.requestDigest,
      committedHeadDigest: candidate.headDigest,
      finalizedMutationLinkDigest,
      outcomeDigest: digest(49),
    },
  };
  const outcomeDigest = computeOperationOutcomeDigest(outcomeInput);
  const proposedOutcome = durableOperationOutcomeSchema.parse({
    ...outcomeInput,
    outcomeDigest,
    signedMutationReceipt: {
      ...outcomeInput.signedMutationReceipt,
      outcomeDigest,
    },
  });
  const candidateAnchor = recipientRollbackAnchorFromCollaborativeVaultDocument(
    candidate,
    fixture.scope,
    {
      membershipDigest: computeMembershipStateDigest(
        authorizationCore(fixture.candidateManifest),
      ),
      policyDigest: computePolicyStateDigest(fixture.candidateManifest.policy),
      finalizedMutationLinkDigest,
    },
  );
  return { candidate, proofEntry, proposedOutcome, candidateAnchor };
}

function rejectedOutcome(committed: DurableOperationOutcome): DurableOperationOutcome {
  const rejected = {
    format: committed.format,
    protocolVersion: committed.protocolVersion,
    databaseId: committed.databaseId,
    vaultId: committed.vaultId,
    operationId: committed.operationId,
    operationType: committed.operationType,
    requestDigest: committed.requestDigest,
    actorPrincipalId: committed.actorPrincipalId,
    actorDeviceId: committed.actorDeviceId,
    priorTuple: committed.priorTuple,
    priorHeadDigest: committed.priorHeadDigest,
    state: 'rejected' as const,
    outcomeDigest: digest(48),
    createdAt: committed.createdAt,
    resolvedAt: committed.resolvedAt,
    detailsRetainedUntil: committed.detailsRetainedUntil,
  };
  return durableOperationOutcomeSchema.parse({
    ...rejected,
    outcomeDigest: computeOperationOutcomeDigest(rejected),
  });
}

function buildFixture(
  options: Readonly<{
    historicalCheckpointSigner?: boolean;
    historicalDeviceRetiredAt?: string;
    historicalDeviceDeniedAt?: string;
  }> = {},
): Fixture {
  const historicalDeviceRetiredAt =
    options.historicalDeviceRetiredAt ?? HISTORICAL_DEVICE_RETIRED_AT;
  const historicalDevice =
    options.historicalCheckpointSigner === true
      ? deviceCertificateSchema.parse({
          protocolVersion: 1,
          principalId: PRINCIPAL_ID,
          deviceId: HISTORICAL_DEVICE_ID,
          deviceGeneration: 1,
          signingPublicKey: HISTORICAL_SIGNING_PUBLIC_KEY,
          encryptionPublicKey: HISTORICAL_ENCRYPTION_PUBLIC_KEY,
          state: 'revoked',
          createdAt: CREATED_AT,
          stateChangedAt: historicalDeviceRetiredAt,
          revokedAt: historicalDeviceRetiredAt,
          rootSignature: SIGNATURE,
        })
      : undefined;
  const registry = buildRegistry(
    historicalDevice === undefined
      ? []
      : [
          {
            principalId: historicalDevice.principalId,
            deviceId: historicalDevice.deviceId,
            deviceGeneration: historicalDevice.deviceGeneration,
            signingKeyFingerprint: computePublicKeyFingerprint(
              historicalDevice.signingPublicKey,
              'ed25519',
            ),
            reason: 'revoked',
            deniedAt: options.historicalDeviceDeniedAt ?? HISTORICAL_DEVICE_DENIED_AT,
          },
        ],
  );
  const currentManifest = buildManifest(
    registry,
    1,
    COLLABORATION_GENESIS_HEAD_DIGEST,
    COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
    COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
    historicalDevice,
  );
  const current = buildCurrentDocument(registry, currentManifest);
  const candidateManifest = buildManifest(
    registry,
    2,
    current.headDigest,
    currentManifest.membershipDigest,
    currentManifest.history.currentHistoryDigest,
    historicalDevice,
  );
  const scope = {
    databaseId: current.databaseId,
    vaultId: current.vaultId,
    principalId: current.currentMutationLink.commitment.writerPrincipalId,
    deviceId: current.currentMutationLink.commitment.writerDeviceId,
  };
  const prepared = buildPrepared(current, candidateManifest, scope);
  const trusted = {
    authorityDelegation: current.authorityDelegation,
    principalPublicIdentities: [
      publicIdentityExportSchema.parse({
        format: 'kavrix-collaborative-public-identity',
        protocolVersion: 1,
        principalId: PRINCIPAL_ID,
        identityGeneration: 1,
        rootSigningPublicKey: ROOT_PUBLIC_KEY,
        devices: required(currentManifest.memberships[0]).devices.filter(
          (device) => device.state === 'active',
        ),
        createdAt: CREATED_AT,
        selfSignature: SIGNATURE,
      }),
    ],
  };
  return {
    current,
    currentManifest,
    candidateManifest,
    registry,
    prepared,
    trusted,
    scope,
  };
}

function buildRecoveryFixture(): Fixture {
  const registry = buildRegistry();
  const baseManifest = buildManifest(
    registry,
    1,
    COLLABORATION_GENESIS_HEAD_DIGEST,
    COLLABORATION_GENESIS_MEMBERSHIP_STATE_DIGEST,
    COLLABORATION_GENESIS_MEMBERSHIP_HISTORY_DIGEST,
  );
  const oldOwner = required(baseManifest.memberships[0]);
  const replacementDevice = deviceCertificateSchema.parse({
    protocolVersion: 1,
    principalId: REPLACEMENT_PRINCIPAL_ID,
    deviceId: REPLACEMENT_DEVICE_ID,
    deviceGeneration: 1,
    signingPublicKey: REPLACEMENT_SIGNING_PUBLIC_KEY,
    encryptionPublicKey: REPLACEMENT_ENCRYPTION_PUBLIC_KEY,
    state: 'active',
    createdAt: CREATED_AT,
    stateChangedAt: CREATED_AT,
    rootSignature: SIGNATURE,
  });
  const priorReplacement =
    collaborativeMembershipManifestSchema.shape.memberships.element.parse({
      membershipId: REPLACEMENT_MEMBERSHIP_ID,
      principalId: REPLACEMENT_PRINCIPAL_ID,
      principalFingerprint: computePublicKeyFingerprint(
        REPLACEMENT_ROOT_PUBLIC_KEY,
        'ed25519',
      ),
      rootSigningPublicKey: REPLACEMENT_ROOT_PUBLIC_KEY,
      identityGeneration: 1,
      role: 'reader',
      state: 'active',
      devices: [replacementDevice],
      createdAt: CREATED_AT,
      updatedAt: GENESIS_AT,
    });
  const replacementEnvelopeBase = collaborationKeyEnvelopeSchema.parse({
    format: 'kavrix-collaborative-member-key-envelope',
    protocolVersion: 1,
    algorithm: 'x25519-sealed-box',
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    authorityEpoch: 1,
    membershipId: REPLACEMENT_MEMBERSHIP_ID,
    principalId: REPLACEMENT_PRINCIPAL_ID,
    deviceId: REPLACEMENT_DEVICE_ID,
    recipientEncryptionKeyFingerprint: computePublicKeyFingerprint(
      REPLACEMENT_ENCRYPTION_PUBLIC_KEY,
      'x25519',
    ),
    keyEpoch: 1,
    membershipRevision: 1,
    databaseDeviceGeneration: registry.generation,
    databaseDeviceRegistryDigest: registry.registryDigest,
    sealedVaultRootKey: bytes(48, 70),
    envelopeDigest: digest(71),
    createdAt: GENESIS_AT,
    ownerSignature: SIGNATURE,
  });
  const replacementEnvelope = collaborationKeyEnvelopeSchema.parse({
    ...replacementEnvelopeBase,
    envelopeDigest: computeKeyEnvelopeDigest(replacementEnvelopeBase),
  });
  const currentDraft = collaborativeMembershipManifestSchema.parse({
    ...baseManifest,
    memberships: [oldOwner],
    keyEnvelopes: baseManifest.keyEnvelopes,
    authorizationStateDigest: digest(72),
    membershipDigest: digest(73),
  });
  const currentWithAuthorization = collaborativeMembershipManifestSchema.parse({
    ...currentDraft,
    authorizationStateDigest: computeAuthorizationStateDigest(
      authorizationCore(currentDraft),
    ),
  });
  const currentManifest = collaborativeMembershipManifestSchema.parse({
    ...currentWithAuthorization,
    membershipDigest: computeMembershipManifestDigest(currentWithAuthorization),
  });
  const current = buildCurrentDocument(registry, currentManifest);
  const removedOwner =
    collaborativeMembershipManifestSchema.shape.memberships.element.parse({
      ...oldOwner,
      state: 'revoked',
      updatedAt: MUTATION_AT,
      removedAt: MUTATION_AT,
    });
  const replacementOwner =
    collaborativeMembershipManifestSchema.shape.memberships.element.parse({
      ...priorReplacement,
      role: 'owner',
      updatedAt: MUTATION_AT,
    });
  const nextReplacementEnvelopeBase = collaborationKeyEnvelopeSchema.parse({
    ...replacementEnvelope,
    keyEpoch: 2,
    membershipRevision: 2,
    sealedVaultRootKey: bytes(48, 74),
    envelopeDigest: digest(75),
    createdAt: MUTATION_AT,
  });
  const nextReplacementEnvelope = collaborationKeyEnvelopeSchema.parse({
    ...nextReplacementEnvelopeBase,
    envelopeDigest: computeKeyEnvelopeDigest(nextReplacementEnvelopeBase),
  });
  const priorRecoveryEnvelope = required(
    baseManifest.keyEnvelopes.find((envelope) => !('membershipId' in envelope)),
  );
  const nextRecoveryEnvelopeBase = databaseAuthorityRecoveryEnvelopeSchema.parse({
    ...priorRecoveryEnvelope,
    keyEpoch: 2,
    membershipRevision: 2,
    sealedVaultRootKey: bytes(48, 76),
    envelopeDigest: digest(77),
    sealedByPrincipalId: REPLACEMENT_PRINCIPAL_ID,
    sealedByDeviceId: REPLACEMENT_DEVICE_ID,
    createdAt: MUTATION_AT,
  });
  const nextRecoveryEnvelope = databaseAuthorityRecoveryEnvelopeSchema.parse({
    ...nextRecoveryEnvelopeBase,
    envelopeDigest: computeAuthorityRecoveryEnvelopeDigest(nextRecoveryEnvelopeBase),
  });
  const semanticDraft = {
    ...currentManifest,
    documentRevision: 2,
    membershipRevision: 2,
    keyEpoch: 2,
    memberships: [removedOwner, replacementOwner],
    ownerPrincipalIds: [REPLACEMENT_PRINCIPAL_ID],
    keyEnvelopes: [nextReplacementEnvelope, nextRecoveryEnvelope],
    previousMembershipDigest: currentManifest.membershipDigest,
    previousHeadDigest: current.headDigest,
    authorizationStateDigest: digest(78),
    membershipDigest: digest(79),
    updatedAt: MUTATION_AT,
  } as CollaborativeMembershipManifest;
  const authorizationStateDigest = computeAuthorizationStateDigest(
    authorizationCore(semanticDraft),
  );
  const nextTuple = collaborationRevisionTupleSchema.parse({
    ...tupleOf(current),
    documentRevision: 2,
    membershipRevision: 2,
    keyEpoch: 2,
    authorizationStateDigest,
  });
  const recoveryEvent = membershipHistoryEventSchema.parse({
    protocolVersion: 1,
    operationId: 'operation-recover-owner',
    eventType: 'owner-recovery',
    actorPrincipalId: REPLACEMENT_PRINCIPAL_ID,
    actorDeviceId: REPLACEMENT_DEVICE_ID,
    targetPrincipalId: REPLACEMENT_PRINCIPAL_ID,
    previousDocumentRevision: current.documentRevision,
    newDocumentRevision: nextTuple.documentRevision,
    previousMembershipRevision: current.membershipRevision,
    newMembershipRevision: nextTuple.membershipRevision,
    previousPolicyRevision: current.policyRevision,
    newPolicyRevision: nextTuple.policyRevision,
    previousKeyEpoch: current.keyEpoch,
    newKeyEpoch: nextTuple.keyEpoch,
    previousAuthorityEpoch: current.authorityEpoch,
    newAuthorityEpoch: nextTuple.authorityEpoch,
    previousDatabaseDeviceGeneration: current.databaseDeviceGeneration,
    newDatabaseDeviceGeneration: nextTuple.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: current.databaseDeviceRegistryDigest,
    newDatabaseDeviceRegistryDigest: nextTuple.databaseDeviceRegistryDigest,
    previousAuthorizationStateDigest: current.authorizationStateDigest,
    newAuthorizationStateDigest: nextTuple.authorizationStateDigest,
    previousHeadDigest: current.headDigest,
    timestamp: MUTATION_AT,
    expiresAt: EXPIRES_AT,
    signature: SIGNATURE,
  });
  const historyDraft = membershipHistorySchema.parse({
    ...currentManifest.history,
    events: [...currentManifest.history.events, recoveryEvent],
    previousHeadDigest: current.headDigest,
    previousHistoryDigest: currentManifest.history.currentHistoryDigest,
    currentHistoryDigest: digest(80),
  });
  const history = membershipHistorySchema.parse({
    ...historyDraft,
    currentHistoryDigest: computeMembershipHistoryDigest(historyDraft),
  });
  const candidateDraft = collaborativeMembershipManifestSchema.parse({
    ...semanticDraft,
    authorizationStateDigest,
    history,
  });
  const candidateManifest = collaborativeMembershipManifestSchema.parse({
    ...candidateDraft,
    membershipDigest: computeMembershipManifestDigest(candidateDraft),
  });
  const encryptedPayload = buildEnvelope(nextTuple, 30);
  const encryptedMembershipManifest = buildEnvelope(nextTuple, 34);
  const transitionDraft = collaborationAuthorizationTransitionSchema.parse({
    format: 'kavrix-collaborative-authorization-transition',
    protocolVersion: 1,
    databaseId: DATABASE_ID,
    vaultId: VAULT_ID,
    operationId: 'operation-recover-owner',
    operationType: 'recover-owner',
    previousHeadDigest: current.headDigest,
    previousAuthorizationStateDigest: current.authorizationStateDigest,
    authorizationStateDigest,
    previousTuple: tupleOf(current),
    nextTuple,
    evidence: { kind: 'authority-recovery', evidenceDigest: digest(81) },
    issuedAt: MUTATION_AT,
    expiresAt: EXPIRES_AT,
    transitionDigest: digest(82),
    transitionSignature: {
      signerKind: 'database-authority',
      authorityEpoch: current.authorityEpoch,
      authoritySigningKeyFingerprint:
        current.authorityDelegation.authoritySigningKeyFingerprint,
      signature: SIGNATURE,
    },
  });
  const transition = collaborationAuthorizationTransitionSchema.parse({
    ...transitionDraft,
    transitionDigest: computeAuthorizationTransitionDigest(transitionDraft),
  });
  const commitmentDraft = {
    protocolVersion: 1 as const,
    databaseId: current.databaseId,
    vaultId: current.vaultId,
    operationId: 'operation-recover-owner',
    operationType: 'recover-owner' as const,
    requestDigest: digest(83),
    previousHeadDigest: current.headDigest,
    previousAuthorizationStateDigest: current.authorizationStateDigest,
    authorizationTransitionDigest: transition.transitionDigest,
    previousAuthorityEpoch: current.authorityEpoch,
    previousDocumentRevision: current.documentRevision,
    previousMembershipRevision: current.membershipRevision,
    previousPolicyRevision: current.policyRevision,
    previousKeyEpoch: current.keyEpoch,
    previousDatabaseDeviceGeneration: current.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: current.databaseDeviceRegistryDigest,
    ...nextTuple,
    encryptedPayloadDigest: computeEncryptedPayloadDigest(encryptedPayload),
    encryptedMembershipDigest: computeEncryptedMembershipDigest(
      encryptedMembershipManifest,
    ),
    encryptedEnvelopesDigest: computeKeyEnvelopeSetDigest(
      candidateManifest.keyEnvelopes,
    ),
    policyDigest: candidateManifest.policy.policyDigest,
    writerPrincipalId: REPLACEMENT_PRINCIPAL_ID,
    writerDeviceId: REPLACEMENT_DEVICE_ID,
    timestamp: MUTATION_AT,
    expiresAt: EXPIRES_AT,
  };
  const commitment = {
    ...commitmentDraft,
    requestDigest: computeMutationRequestDigest(commitmentDraft),
  };
  const resultingHeadDigest = computeMutationHead(commitment);
  const link = collaborationFinalizedMutationLinkSchema.parse({
    format: 'kavrix-collaborative-finalized-mutation-link',
    protocolVersion: 1,
    databaseId: current.databaseId,
    vaultId: current.vaultId,
    authorityDelegationDigest: current.authorityDelegationDigest,
    commitment,
    authorizationTransition: transition,
    resultingHeadDigest,
    writerSignature: {
      algorithm: 'ed25519',
      writerPrincipalId: REPLACEMENT_PRINCIPAL_ID,
      writerDeviceId: REPLACEMENT_DEVICE_ID,
      commitmentDigest: resultingHeadDigest,
      signature: SIGNATURE,
    },
    finalizedAt: MUTATION_AT,
  });
  const candidate = collaborativeVaultDocumentSchema.parse({
    ...current,
    ...nextTuple,
    previousHeadDigest: current.headDigest,
    headDigest: resultingHeadDigest,
    encryptedPayloadDigest: commitment.encryptedPayloadDigest,
    encryptedMembershipDigest: commitment.encryptedMembershipDigest,
    encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
    policyDigest: commitment.policyDigest,
    databaseAuthorityRecoveryEnvelope: candidateManifest.keyEnvelopes.find(
      (envelope) => !('membershipId' in envelope),
    ),
    encryptedPayload,
    encryptedMembershipManifest,
    currentMutationLink: link,
    updatedAt: MUTATION_AT,
  });
  const finalizedMutationLinkDigest = computeFinalizedMutationLinkDigest(link);
  const proofEntry = collaborationMutationProofEntrySchema.parse({
    link,
    authorizationWitness: {
      format: 'kavrix-collaborative-authorization-witness',
      protocolVersion: 1,
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      authorityDelegationDigest: candidate.authorityDelegationDigest,
      tuple: nextTuple,
      previousHeadDigest: candidate.previousHeadDigest,
      headDigest: candidate.headDigest,
      encryptedMembershipDigest: candidate.encryptedMembershipDigest,
      encryptedEnvelopesDigest: candidate.encryptedEnvelopesDigest,
      policyDigest: candidate.policyDigest,
      databaseDeviceRegistry: registry,
      databaseAuthorityRecoveryEnvelope: candidate.databaseAuthorityRecoveryEnvelope,
      encryptedMembershipManifest: candidate.encryptedMembershipManifest,
      discoveryRecords: candidate.discoveryRecords,
      finalizedMutationLinkDigest,
    },
  });
  const outcomeDraft = {
    format: 'kavrix-collaborative-operation-outcome' as const,
    protocolVersion: 1 as const,
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    operationId: commitment.operationId,
    operationType: commitment.operationType,
    requestDigest: commitment.requestDigest,
    actorPrincipalId: REPLACEMENT_PRINCIPAL_ID,
    actorDeviceId: REPLACEMENT_DEVICE_ID,
    priorTuple: tupleOf(current),
    priorHeadDigest: current.headDigest,
    state: 'committed' as const,
    committedTuple: nextTuple,
    committedHeadDigest: candidate.headDigest,
    finalizedMutationLinkDigest,
    committedAt: MUTATION_AT,
    outcomeDigest: digest(84),
    signedMutationReceipt: {
      format: 'kavrix-collaborative-mutation-receipt' as const,
      protocolVersion: 1 as const,
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      operationId: commitment.operationId,
      operationType: commitment.operationType,
      requestDigest: commitment.requestDigest,
      actorPrincipalId: REPLACEMENT_PRINCIPAL_ID,
      actorDeviceId: REPLACEMENT_DEVICE_ID,
      priorTuple: tupleOf(current),
      priorHeadDigest: current.headDigest,
      committedTuple: nextTuple,
      committedHeadDigest: candidate.headDigest,
      finalizedMutationLinkDigest,
      outcomeDigest: digest(84),
      committedAt: MUTATION_AT,
      receiptSignature: SIGNATURE,
    },
    createdAt: MUTATION_AT,
    resolvedAt: MUTATION_AT,
    detailsRetainedUntil: RETAIN_UNTIL,
  };
  const outcomeDigest = computeOperationOutcomeDigest(outcomeDraft);
  const proposedOutcome = durableOperationOutcomeSchema.parse({
    ...outcomeDraft,
    outcomeDigest,
    signedMutationReceipt: {
      ...outcomeDraft.signedMutationReceipt,
      outcomeDigest,
    },
  });
  const scope = {
    databaseId: current.databaseId,
    vaultId: current.vaultId,
    principalId: principalIdSchema.parse(REPLACEMENT_PRINCIPAL_ID),
    deviceId: replacementDevice.deviceId,
  };
  const candidateAnchor = recipientRollbackAnchorFromCollaborativeVaultDocument(
    candidate,
    scope,
    {
      membershipDigest: computeMembershipStateDigest(
        authorizationCore(candidateManifest),
      ),
      policyDigest: computePolicyStateDigest(candidateManifest.policy),
      finalizedMutationLinkDigest,
    },
  );
  const prepared = {
    candidate,
    proofEntry,
    proposedOutcome,
    candidateAnchor,
    nextVaultRootKey: new Uint8Array(32).fill(86) as never,
  };
  const trusted = {
    authorityDelegation: current.authorityDelegation,
    principalPublicIdentities: [
      publicIdentityExportSchema.parse({
        format: 'kavrix-collaborative-public-identity',
        protocolVersion: 1,
        principalId: PRINCIPAL_ID,
        identityGeneration: 1,
        rootSigningPublicKey: ROOT_PUBLIC_KEY,
        devices: oldOwner.devices.filter((device) => device.state === 'active'),
        createdAt: CREATED_AT,
        selfSignature: SIGNATURE,
      }),
      publicIdentityExportSchema.parse({
        format: 'kavrix-collaborative-public-identity',
        protocolVersion: 1,
        principalId: REPLACEMENT_PRINCIPAL_ID,
        identityGeneration: 1,
        rootSigningPublicKey: REPLACEMENT_ROOT_PUBLIC_KEY,
        devices: [replacementDevice],
        createdAt: CREATED_AT,
        selfSignature: SIGNATURE,
      }),
    ],
  };
  return {
    current,
    currentManifest,
    candidateManifest,
    registry,
    prepared,
    trusted,
    scope,
  };
}

function withHistoryCheckpoint(fixture: Fixture, signerDeviceId: string): Fixture {
  const manifest = fixture.candidateManifest;
  const checkpoint = membershipHistoryCheckpointSchema.parse({
    protocolVersion: 1,
    checkpointId: 'history-checkpoint-publisher',
    authorityEpoch: manifest.authorityEpoch,
    databaseDeviceGeneration: manifest.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: manifest.databaseDeviceRegistryDigest,
    membershipRevision: manifest.membershipRevision,
    documentRevision: manifest.documentRevision,
    policyRevision: manifest.policyRevision,
    keyEpoch: manifest.keyEpoch,
    previousHeadDigest: manifest.previousHeadDigest,
    compactedThroughRevision: 0,
    compactedHistoryDigest: manifest.history.compactedHistoryDigest,
    signerPrincipalId: PRINCIPAL_ID,
    signerDeviceId,
    createdAt: HISTORY_CHECKPOINT_AT,
    signature: SIGNATURE,
  });
  const historyInput = {
    ...manifest.history,
    checkpoints: [checkpoint],
    currentHistoryDigest: digest(97),
  };
  const history = membershipHistorySchema.parse({
    ...historyInput,
    currentHistoryDigest: computeMembershipHistoryDigest(historyInput),
  });
  const manifestInput = collaborativeMembershipManifestSchema.parse({
    ...manifest,
    history,
    membershipDigest: digest(98),
  });
  const candidateManifest = collaborativeMembershipManifestSchema.parse({
    ...manifestInput,
    membershipDigest: computeMembershipManifestDigest(manifestInput),
  });
  return { ...fixture, candidateManifest };
}

function withHistoryEvent(
  fixture: Fixture,
  actorDeviceId: string,
  timestamp: string,
): Fixture {
  const manifest = fixture.candidateManifest;
  const event = membershipHistoryEventSchema.parse({
    protocolVersion: 1,
    operationId: 'operation-history-event-publisher',
    eventType: 'device-revoked',
    actorPrincipalId: PRINCIPAL_ID,
    actorDeviceId,
    previousDocumentRevision: 1,
    newDocumentRevision: manifest.documentRevision,
    previousMembershipRevision: manifest.membershipRevision,
    newMembershipRevision: manifest.membershipRevision,
    previousPolicyRevision: manifest.policyRevision,
    newPolicyRevision: manifest.policyRevision,
    previousKeyEpoch: manifest.keyEpoch,
    newKeyEpoch: manifest.keyEpoch,
    previousAuthorityEpoch: manifest.authorityEpoch,
    newAuthorityEpoch: manifest.authorityEpoch,
    previousDatabaseDeviceGeneration: manifest.databaseDeviceGeneration,
    newDatabaseDeviceGeneration: manifest.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: manifest.databaseDeviceRegistryDigest,
    newDatabaseDeviceRegistryDigest: manifest.databaseDeviceRegistryDigest,
    previousAuthorizationStateDigest: manifest.authorizationStateDigest,
    newAuthorizationStateDigest: manifest.authorizationStateDigest,
    previousHeadDigest: manifest.previousHeadDigest,
    timestamp,
    signature: SIGNATURE,
  });
  const historyInput = {
    ...manifest.history,
    events: [event],
    currentHistoryDigest: digest(103),
  };
  const history = membershipHistorySchema.parse({
    ...historyInput,
    currentHistoryDigest: computeMembershipHistoryDigest(historyInput),
  });
  const manifestInput = collaborativeMembershipManifestSchema.parse({
    ...manifest,
    history,
    membershipDigest: digest(104),
  });
  const candidateManifest = collaborativeMembershipManifestSchema.parse({
    ...manifestInput,
    membershipDigest: computeMembershipManifestDigest(manifestInput),
  });
  return { ...fixture, candidateManifest };
}

async function initialize(fixture: Fixture, secret: Uint8Array): Promise<void> {
  await createRecipientRollbackAnchor(
    rollbackAnchorPath,
    secret,
    recipientRollbackAnchorFromCollaborativeVaultDocument(
      fixture.current,
      fixture.scope,
      {
        membershipDigest: computeMembershipStateDigest(
          authorizationCore(fixture.currentManifest),
        ),
        policyDigest: computePolicyStateDigest(fixture.currentManifest.policy),
        finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
          fixture.current.currentMutationLink,
        ),
      },
    ),
  );
  const membership = required(fixture.currentManifest.memberships[0]);
  const device = required(membership.devices[0]);
  vi.mocked(openCollaborativeVaultWithPinnedTrust).mockResolvedValue({
    document: fixture.current,
    manifest: fixture.currentManifest,
    recipientMembership: membership,
    recipientDevice: device,
    vaultRootKey: new Uint8Array(32).fill(60) as never,
    decryptedPayload: new Uint8Array([61, 62]),
  });
  vi.mocked(decryptCollaborationEnvelope).mockImplementation((envelope) =>
    Promise.resolve(
      envelope.aad.entityType === 'membership-manifest'
        ? Buffer.from(canonicalJson(fixture.candidateManifest), 'utf8')
        : new Uint8Array([63, 64]),
    ),
  );
}

async function initializeAuthorityRecovery(
  fixture: Fixture,
  databaseRootKey: Uint8Array,
): Promise<void> {
  await createCollaborationAuthorityRollbackAnchor(
    authorityRollbackAnchorPath,
    databaseRootKey,
    collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
      fixture.current,
      {
        membershipDigest: computeMembershipStateDigest(
          authorizationCore(fixture.currentManifest),
        ),
        policyDigest: computePolicyStateDigest(fixture.currentManifest.policy),
      },
    ),
  );
  vi.mocked(openCollaborativeVaultForDatabaseAuthorityRecovery).mockResolvedValue({
    document: fixture.current,
    manifest: fixture.currentManifest,
    vaultRootKey: new Uint8Array(32).fill(60) as never,
    decryptedPayload: new Uint8Array([61, 62]),
  });
  vi.mocked(decryptCollaborationEnvelope).mockImplementation((envelope) =>
    Promise.resolve(
      envelope.aad.entityType === 'membership-manifest'
        ? Buffer.from(canonicalJson(fixture.candidateManifest), 'utf8')
        : new Uint8Array([63, 64]),
    ),
  );
}

function serviceInput(
  fixture: Fixture,
  store: TestStore,
  recipientPrivateKey: Uint8Array,
  secret: Uint8Array,
  prepared: PreparedBundle = fixture.prepared,
  journalPath = operationJournalPath,
  authorizationCheckpoint?: CollaborationAuthorizationCheckpoint,
): PublishPreparedCollaborativeMutationInput {
  return {
    store: store as unknown as CollaborativeVaultStore,
    prepared,
    trusted: fixture.trusted,
    scope: fixture.scope,
    access: {
      kind: 'recipient',
      recipientEncryptionPrivateKey: recipientPrivateKey,
    },
    deviceProtectionSecret: secret,
    rollbackAnchorPath,
    operationJournalPath: journalPath,
    ...(authorizationCheckpoint === undefined ? {} : { authorizationCheckpoint }),
    now: NOW,
  };
}

function authorityRecoveryServiceInput(
  fixture: Fixture,
  store: TestStore,
  databaseRootKey: Uint8Array,
  secret: Uint8Array,
): PublishPreparedCollaborativeMutationInput {
  return {
    store: store as unknown as CollaborativeVaultStore,
    prepared: fixture.prepared,
    trusted: fixture.trusted,
    scope: fixture.scope,
    access: {
      kind: 'database-authority-recovery',
      databaseRootKey,
      authorityRollbackAnchorPath,
    },
    deviceProtectionSecret: secret,
    rollbackAnchorPath,
    operationJournalPath,
    now: NOW,
  };
}

function resumeInput(
  fixture: Fixture,
  store: TestStore,
  recipientPrivateKey: Uint8Array,
  secret: Uint8Array,
): ResumeCollaborativeMutationFromJournalInput {
  return {
    store: store as unknown as CollaborativeVaultStore,
    trusted: fixture.trusted,
    scope: fixture.scope,
    access: {
      kind: 'recipient',
      recipientEncryptionPrivateKey: recipientPrivateKey,
    },
    deviceProtectionSecret: secret,
    rollbackAnchorPath,
    operationJournalPath,
    now: NOW,
  };
}

function authorityResumeInput(
  fixture: Fixture,
  store: TestStore,
  databaseRootKey: Uint8Array,
  secret: Uint8Array,
): ResumeCollaborativeMutationFromJournalInput {
  return {
    store: store as unknown as CollaborativeVaultStore,
    trusted: fixture.trusted,
    scope: fixture.scope,
    access: {
      kind: 'database-authority-recovery',
      databaseRootKey,
      authorityRollbackAnchorPath,
    },
    deviceProtectionSecret: secret,
    rollbackAnchorPath,
    operationJournalPath,
    now: NOW,
  };
}

async function createPreparedJournal(
  fixture: Fixture,
  secret: Uint8Array,
): Promise<void> {
  await createCollaborativeOperationJournal(operationJournalPath, secret, {
    accessMode: 'recipient',
    candidate: fixture.prepared.candidate,
    candidateAnchor: fixture.prepared.candidateAnchor,
    proofEntry: fixture.prepared.proofEntry,
    proposedOutcome: fixture.prepared.proposedOutcome,
    createdAt: fixture.prepared.proposedOutcome.createdAt,
  });
}

async function createPreparedAuthorityJournal(
  fixture: Fixture,
  secret: Uint8Array,
): Promise<void> {
  await createCollaborativeOperationJournal(operationJournalPath, secret, {
    accessMode: 'database-authority-recovery',
    recoveryRestartEvidence: {
      priorTuple: tupleOf(fixture.current),
      priorHeadDigest: fixture.current.headDigest,
      priorDatabaseAuthorityRecoveryEnvelopeDigest:
        computeAuthorityRecoveryEnvelopeDigest(
          fixture.current.databaseAuthorityRecoveryEnvelope,
        ),
    },
    candidate: fixture.prepared.candidate,
    candidateAnchor: fixture.prepared.candidateAnchor,
    proofEntry: fixture.prepared.proofEntry,
    proposedOutcome: fixture.prepared.proposedOutcome,
    createdAt: fixture.prepared.proposedOutcome.createdAt,
  });
}

function buildRemoteSuccessors(
  fixture: Fixture,
  count: number,
): Readonly<{
  current: CollaborativeVaultDocument;
  anchors: readonly ReturnType<
    typeof recipientRollbackAnchorFromCollaborativeVaultDocument
  >[];
  authorityAnchors: readonly ReturnType<
    typeof collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument
  >[];
}> {
  let current = fixture.prepared.candidate;
  const anchors = [fixture.prepared.candidateAnchor];
  const logicalDigests = {
    membershipDigest: computeMembershipStateDigest(
      authorizationCore(fixture.candidateManifest),
    ),
    policyDigest: computePolicyStateDigest(fixture.candidateManifest.policy),
  };
  const authorityAnchors = [
    collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
      current,
      logicalDigests,
    ),
  ];
  for (let index = 0; index < count; index += 1) {
    current = buildPrepared(
      current,
      fixture.candidateManifest,
      fixture.scope,
    ).candidate;
    anchors.push(
      recipientRollbackAnchorFromCollaborativeVaultDocument(current, fixture.scope, {
        ...logicalDigests,
        finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
          current.currentMutationLink,
        ),
      }),
    );
    authorityAnchors.push(
      collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
        current,
        logicalDigests,
      ),
    );
  }
  return { current, anchors, authorityAnchors };
}

function incompatibleOutcome(fixture: Fixture): DurableOperationOutcome {
  const proposed = fixture.prepared.proposedOutcome;
  if (proposed.state !== 'committed') throw new Error('Committed outcome required');
  const draft = {
    ...proposed,
    operationId: 'operation-incompatible',
    outcomeDigest: digest(0x6d),
    signedMutationReceipt: {
      ...proposed.signedMutationReceipt,
      operationId: 'operation-incompatible',
      outcomeDigest: digest(0x6d),
    },
  };
  const outcomeDigest = computeOperationOutcomeDigest(draft);
  return durableOperationOutcomeSchema.parse({
    ...draft,
    outcomeDigest,
    signedMutationReceipt: {
      ...draft.signedMutationReceipt,
      outcomeDigest,
    },
  });
}

async function readJournal(
  fixture: Fixture,
  secret: Uint8Array,
): Promise<Awaited<ReturnType<typeof readCollaborativeOperationJournal>>> {
  return readCollaborativeOperationJournal(operationJournalPath, secret, {
    expectedScope: fixture.scope,
  });
}

describe('prepared collaboration mutation publisher', () => {
  it('never publishes a DRK journal restart outside the authority-anchor transition lock', async () => {
    const fixture = buildRecoveryFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(107);
    const databaseRootKey = new Uint8Array(32).fill(108);
    await initializeAuthorityRecovery(fixture, databaseRootKey);
    await createPreparedAuthorityJournal(fixture, secret);
    const currentAuthorityAnchor = await readCollaborationAuthorityRollbackAnchor(
      authorityRollbackAnchorPath,
      databaseRootKey,
    );
    let release!: () => void;
    let entered!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const callbackEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const competingTransition = transitionCollaborationAuthorityRollbackAnchor(
      authorityRollbackAnchorPath,
      databaseRootKey,
      currentAuthorityAnchor,
      async () => {
        entered();
        await held;
        return {
          nextAnchor: currentAuthorityAnchor,
          result: undefined,
        };
      },
    );
    await callbackEntered;

    const blocked = await resumeCollaborativeMutationFromJournal(
      authorityResumeInput(fixture, store, databaseRootKey, secret),
    );

    expect(blocked).toEqual({
      status: 'unknown',
      reason: 'anchor-persistence-failed',
    });
    expect(store.publications).toHaveLength(0);
    expect(await readJournal(fixture, secret)).toMatchObject({ state: 'prepared' });
    release();
    await competingTransition;

    const resumed = await resumeCollaborativeMutationFromJournal(
      authorityResumeInput(fixture, store, databaseRootKey, secret),
    );
    expect(resumed).toMatchObject({
      status: 'committed',
      disposition: 'published',
    });
    expect(store.publications).toHaveLength(1);
  });

  it('resumes from only the authenticated prepared journal and republishes its exact bytes', async () => {
    const fixture = buildFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(68);
    const privateKey = new Uint8Array(32).fill(69);
    const originalPrivateKey = Uint8Array.from(privateKey);
    await initialize(fixture, secret);
    await createPreparedJournal(fixture, secret);
    const reconcileImplementation = keyFiles.reconcileCollaborativeOperationJournal;
    let reconcileSecret: Uint8Array | undefined;
    const reconcileSpy = vi
      .spyOn(keyFiles, 'reconcileCollaborativeOperationJournal')
      .mockImplementation((path, candidateSecret, outcome) => {
        reconcileSecret = Uint8Array.from(candidateSecret);
        return reconcileImplementation(path, candidateSecret, outcome);
      });

    const result = await resumeCollaborativeMutationFromJournal(
      resumeInput(fixture, store, privateKey, secret),
    );

    expect(reconcileSpy).toHaveBeenCalledTimes(1);
    expect(reconcileSecret).toEqual(secret);
    await expect(reconcileSpy.mock.results[0]?.value).resolves.toBeUndefined();
    expect(await readJournal(fixture, secret)).toMatchObject({ state: 'committed' });
    expect(result).toEqual({
      status: 'committed',
      disposition: 'published',
      outcome: fixture.prepared.proposedOutcome,
    });
    expect(canonicalJson(store.publications[0])).toBe(
      canonicalJson({
        candidate: fixture.prepared.candidate,
        outcome: fixture.prepared.proposedOutcome,
        proofEntry: fixture.prepared.proofEntry,
      }),
    );
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      fixture.prepared.candidateAnchor,
    );
    expect(privateKey).toEqual(originalPrivateKey);
    expect(JSON.stringify(result)).not.toContain(
      Buffer.from(originalPrivateKey).toString('base64url'),
    );
    zeroize(originalPrivateKey);
    reconcileSpy.mockRestore();
  });

  it('finishes the protected anchor after the journal was terminalized at the exact candidate', async () => {
    const fixture = buildFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(66);
    const privateKey = new Uint8Array(32).fill(67);
    await initialize(fixture, secret);
    await createPreparedJournal(fixture, secret);
    await reconcileCollaborativeOperationJournal(
      operationJournalPath,
      secret,
      fixture.prepared.proposedOutcome,
    );
    store.outcome = structuredClone(fixture.prepared.proposedOutcome);
    store.current = structuredClone(fixture.prepared.candidate);
    vi.mocked(openCollaborativeVaultWithPinnedTrust).mockClear();

    const result = await resumeCollaborativeMutationFromJournal(
      resumeInput(fixture, store, privateKey, secret),
    );

    expect(result).toMatchObject({
      status: 'committed',
      disposition: 'already-committed',
    });
    expect(store.publications).toHaveLength(0);
    expect(verifyCollaborativeJournalSuccessorChain).not.toHaveBeenCalled();
    expect(openCollaborativeVaultWithPinnedTrust).not.toHaveBeenCalled();
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      fixture.prepared.candidateAnchor,
    );
  });

  it('authenticates an ahead successor proof and advances every recovered anchor through the tip', async () => {
    const fixture = buildFixture();
    const remote = buildRemoteSuccessors(fixture, 2);
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(64);
    const privateKey = new Uint8Array(32).fill(65);
    await initialize(fixture, secret);
    await createPreparedJournal(fixture, secret);
    await reconcileCollaborativeOperationJournal(
      operationJournalPath,
      secret,
      fixture.prepared.proposedOutcome,
    );
    store.outcome = structuredClone(fixture.prepared.proposedOutcome);
    store.current = structuredClone(remote.current);
    store.proofRange = { exact: 'candidate-predecessor-to-tip' };
    vi.mocked(verifyCollaborativeJournalSuccessorChain).mockResolvedValue({
      currentDocument: remote.current,
      anchors: remote.anchors,
    });

    const first = await resumeCollaborativeMutationFromJournal(
      resumeInput(fixture, store, privateKey, secret),
    );
    const replay = await resumeCollaborativeMutationFromJournal(
      resumeInput(fixture, store, privateKey, secret),
    );

    expect(first).toMatchObject({ status: 'committed' });
    expect(replay).toMatchObject({
      status: 'committed',
      disposition: 'already-committed',
    });
    expect(store.proofRangeRequests[0]).toMatchObject({
      fromExclusive: {
        documentRevision: fixture.current.documentRevision,
        headDigest: fixture.current.headDigest,
      },
      toInclusive: {
        documentRevision: remote.current.documentRevision,
        headDigest: remote.current.headDigest,
      },
      limit: 3,
    });
    expect(verifyCollaborativeJournalSuccessorChain).toHaveBeenCalledWith(
      expect.objectContaining({
        journalCandidate: fixture.prepared.candidate,
        journalCandidateAnchor: fixture.prepared.candidateAnchor,
        journalProofEntry: fixture.prepared.proofEntry,
        mutationProof: store.proofRange,
      }),
    );
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      remote.anchors.at(-1),
    );
  });

  it('continues an authenticated successor recovery from an already-persisted intermediate anchor', async () => {
    const fixture = buildFixture();
    const remote = buildRemoteSuccessors(fixture, 2);
    const intermediate = remote.anchors[1];
    if (intermediate === undefined) throw new Error('Intermediate anchor missing');
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(62);
    const privateKey = new Uint8Array(32).fill(63);
    await createRecipientRollbackAnchor(rollbackAnchorPath, secret, intermediate);
    await createPreparedJournal(fixture, secret);
    await reconcileCollaborativeOperationJournal(
      operationJournalPath,
      secret,
      fixture.prepared.proposedOutcome,
    );
    store.outcome = structuredClone(fixture.prepared.proposedOutcome);
    store.current = structuredClone(remote.current);
    store.proofRange = { exact: 'candidate-predecessor-to-tip' };
    vi.mocked(verifyCollaborativeJournalSuccessorChain).mockResolvedValue({
      currentDocument: remote.current,
      anchors: remote.anchors,
    });

    const result = await resumeCollaborativeMutationFromJournal(
      resumeInput(fixture, store, privateKey, secret),
    );

    expect(result).toMatchObject({ status: 'committed' });
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      remote.anchors.at(-1),
    );
  });

  it.each([
    ['invalid-input', 'proof-invalid'],
    ['fork', 'fork'],
  ] as const)(
    'normalizes an authenticated successor verifier %s failure to terminal %s',
    async (verifierKind, reason) => {
      const fixture = buildFixture();
      const remote = buildRemoteSuccessors(fixture, 1);
      const store = new TestStore(fixture);
      const secret = new Uint8Array(32).fill(60);
      const privateKey = new Uint8Array(32).fill(61);
      await initialize(fixture, secret);
      await createPreparedJournal(fixture, secret);
      store.outcome = structuredClone(fixture.prepared.proposedOutcome);
      store.current = structuredClone(remote.current);
      store.proofRange = { malformed: verifierKind };
      vi.mocked(verifyCollaborativeJournalSuccessorChain).mockRejectedValue(
        new CollaborationStateVerificationError(verifierKind),
      );

      const result = await resumeCollaborativeMutationFromJournal(
        resumeInput(fixture, store, privateKey, secret),
      );

      expect(result).toEqual({ status: 'terminal', reason });
      expect(await readJournal(fixture, secret)).toMatchObject({ state: 'prepared' });
      expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).not.toEqual(
        fixture.prepared.candidateAnchor,
      );
    },
  );

  it('keeps missing and over-limit successor proofs availability-unknown without advancing the anchor', async () => {
    const fixture = buildFixture();
    const missing = buildRemoteSuccessors(fixture, 1);
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(58);
    const privateKey = new Uint8Array(32).fill(59);
    await initialize(fixture, secret);
    const initialAnchor = await readRecipientRollbackAnchor(rollbackAnchorPath, secret);
    await createPreparedJournal(fixture, secret);
    store.outcome = structuredClone(fixture.prepared.proposedOutcome);
    store.current = structuredClone(missing.current);

    const missingResult = await resumeCollaborativeMutationFromJournal(
      resumeInput(fixture, store, privateKey, secret),
    );

    expect(missingResult).toEqual({
      status: 'unknown',
      reason: 'proof-unavailable',
    });
    const overLimit = buildRemoteSuccessors(fixture, 256);
    store.current = structuredClone(overLimit.current);
    store.proofRangeRequests.splice(0);

    const overLimitResult = await resumeCollaborativeMutationFromJournal(
      resumeInput(fixture, store, privateKey, secret),
    );

    expect(overLimitResult).toEqual({
      status: 'unknown',
      reason: 'proof-unavailable',
    });
    expect(store.proofRangeRequests).toHaveLength(0);
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      initialAnchor,
    );
  });

  it('rejects an incompatible same-ID outcome and keeps an absent-outcome remote successor retryable', async () => {
    const fixture = buildFixture();
    const remote = buildRemoteSuccessors(fixture, 1);
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(56);
    const privateKey = new Uint8Array(32).fill(57);
    await initialize(fixture, secret);
    await createPreparedJournal(fixture, secret);
    store.outcome = incompatibleOutcome(fixture);

    const incompatible = await resumeCollaborativeMutationFromJournal(
      resumeInput(fixture, store, privateKey, secret),
    );

    expect(incompatible).toEqual({
      status: 'terminal',
      reason: 'operation-id-reused',
    });
    store.outcome = null;
    store.current = structuredClone(remote.current);

    const absent = await resumeCollaborativeMutationFromJournal(
      resumeInput(fixture, store, privateKey, secret),
    );

    expect(absent).toEqual({ status: 'retryable', reason: 'conflict' });
    expect(store.publications).toHaveLength(0);
  });

  it('journals and publishes the exact immutable bundle before advancing the anchor', async () => {
    const fixture = buildFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(71);
    const privateKey = new Uint8Array(32).fill(72);
    await initialize(fixture, secret);

    const result = await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret),
    );

    expect(result).toEqual({
      status: 'committed',
      disposition: 'published',
      outcome: fixture.prepared.proposedOutcome,
    });
    expect(canonicalJson(store.publications[0])).toBe(
      canonicalJson({
        candidate: fixture.prepared.candidate,
        outcome: fixture.prepared.proposedOutcome,
        proofEntry: fixture.prepared.proofEntry,
      }),
    );
    expect(await readJournal(fixture, secret)).toMatchObject({ state: 'committed' });
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      fixture.prepared.candidateAnchor,
    );
    expect(privateKey).toEqual(new Uint8Array(32).fill(72));
    expect(secret).toEqual(new Uint8Array(32).fill(71));
  });

  it('publishes authority recovery with the exact next-state replacement writer', async () => {
    const fixture = buildRecoveryFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(87);
    const privateKey = new Uint8Array(32).fill(88);
    await initialize(fixture, secret);

    const result = await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret),
    );

    expect(result).toMatchObject({ status: 'committed', disposition: 'published' });
    expect(
      store.publications[0]?.candidate.currentMutationLink.writerSignature,
    ).toMatchObject({
      writerPrincipalId: REPLACEMENT_PRINCIPAL_ID,
      writerDeviceId: REPLACEMENT_DEVICE_ID,
    });
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      fixture.prepared.candidateAnchor,
    );
  });

  it('publishes all-new-principal recovery through DRK access and creates the first exact anchor only after readback', async () => {
    const fixture = buildRecoveryFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(89);
    const databaseRootKey = new Uint8Array(32).fill(90);
    const originalDrk = Uint8Array.from(databaseRootKey);
    await initializeAuthorityRecovery(fixture, databaseRootKey);
    expect(
      fixture.currentManifest.memberships.some(
        (membership) => membership.principalId === REPLACEMENT_PRINCIPAL_ID,
      ),
    ).toBe(false);
    await expect(
      readRecipientRollbackAnchor(rollbackAnchorPath, secret),
    ).rejects.toMatchObject({ code: 'KEY_FILE_NOT_FOUND' });

    const result = await publishPreparedCollaborativeMutation(
      authorityRecoveryServiceInput(fixture, store, databaseRootKey, secret),
    );

    expect(result).toMatchObject({ status: 'committed', disposition: 'published' });
    expect(store.events).toEqual(['publish', 'readback']);
    await expect(
      readCollaborationAuthorityRollbackAnchor(
        authorityRollbackAnchorPath,
        databaseRootKey,
      ),
    ).resolves.toEqual(
      collaborationAuthorityRollbackAnchorFromCollaborativeVaultDocument(
        fixture.prepared.candidate,
        {
          membershipDigest: fixture.prepared.candidateAnchor.membershipDigest,
          policyDigest: fixture.prepared.candidateAnchor.policyDigest,
        },
      ),
    );
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      fixture.prepared.candidateAnchor,
    );
    const journal = await readJournal(fixture, secret);
    expect(journal).toMatchObject({
      state: 'committed',
      accessMode: 'database-authority-recovery',
      recoveryRestartEvidence: {
        priorTuple: tupleOf(fixture.current),
        priorHeadDigest: fixture.current.headDigest,
        priorDatabaseAuthorityRecoveryEnvelopeDigest:
          computeAuthorityRecoveryEnvelopeDigest(
            fixture.current.databaseAuthorityRecoveryEnvelope,
          ),
      },
    });
    const serialized = await readFile(operationJournalPath, 'utf8');
    expect(serialized).not.toContain(
      Buffer.from(databaseRootKey).toString('base64url'),
    );
    expect(serialized).not.toContain('plaintext-canary');
    expect(databaseRootKey).toEqual(originalDrk);
    zeroize(originalDrk);
  });

  it('requires the DRK-protected authority anchor before any owner-recovery publication', async () => {
    const fixture = buildRecoveryFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(101);
    const databaseRootKey = new Uint8Array(32).fill(102);
    await initializeAuthorityRecovery(fixture, databaseRootKey);
    await rm(authorityRollbackAnchorPath, { force: true });

    await expect(
      publishPreparedCollaborativeMutation(
        authorityRecoveryServiceInput(fixture, store, databaseRootKey, secret),
      ),
    ).rejects.toMatchObject({ kind: 'current-state-invalid' });
    expect(store.publications).toHaveLength(0);
    await expect(readFile(operationJournalPath, 'utf8')).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('replays safely after authority advancement when first-recipient persistence failed', async () => {
    const fixture = buildRecoveryFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(103);
    const databaseRootKey = new Uint8Array(32).fill(104);
    await initializeAuthorityRecovery(fixture, databaseRootKey);
    await mkdir(rollbackAnchorPath);
    const input = authorityRecoveryServiceInput(
      fixture,
      store,
      databaseRootKey,
      secret,
    );

    const first = await publishPreparedCollaborativeMutation(input);

    expect(first).toEqual({
      status: 'unknown',
      reason: 'anchor-persistence-failed',
    });
    await expect(
      readCollaborationAuthorityRollbackAnchor(
        authorityRollbackAnchorPath,
        databaseRootKey,
      ),
    ).resolves.toMatchObject({
      documentRevision: fixture.prepared.candidate.documentRevision,
      headDigest: fixture.prepared.candidate.headDigest,
    });
    await rm(rollbackAnchorPath, { recursive: true, force: true });

    const replay = await publishPreparedCollaborativeMutation(input);

    expect(replay).toMatchObject({
      status: 'committed',
      disposition: 'already-committed',
    });
    expect(store.publications).toHaveLength(1);
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      fixture.prepared.candidateAnchor,
    );
  });

  it('continues DRK successor recovery from partial authority and recipient progress', async () => {
    const fixture = buildRecoveryFixture();
    const remote = buildRemoteSuccessors(fixture, 2);
    const store = new TestStore(fixture);
    store.postPublishCurrent = remote.current;
    store.proofRange = { exact: 'candidate-predecessor-to-successor-tip' };
    const secret = new Uint8Array(32).fill(105);
    const databaseRootKey = new Uint8Array(32).fill(106);
    await initializeAuthorityRecovery(fixture, databaseRootKey);
    vi.mocked(verifyCollaborativeJournalSuccessorChain).mockResolvedValue({
      currentDocument: remote.current,
      anchors: remote.anchors,
      authorityAnchors: remote.authorityAnchors,
    });
    const input = authorityRecoveryServiceInput(
      fixture,
      store,
      databaseRootKey,
      secret,
    );

    const raced = await publishPreparedCollaborativeMutation(input);
    expect(raced).toEqual({
      status: 'unknown',
      reason: 'readback-unavailable',
    });
    for (const anchor of remote.authorityAnchors.slice(0, 2)) {
      await transitionCollaborationAuthorityRollbackAnchor(
        authorityRollbackAnchorPath,
        databaseRootKey,
        anchor,
        () => ({ nextAnchor: anchor, result: undefined }),
      );
    }
    const recipientCandidate = remote.anchors[0];
    if (recipientCandidate === undefined) throw new Error('Candidate anchor missing');
    await createRecipientRollbackAnchor(rollbackAnchorPath, secret, recipientCandidate);

    const resumed = await publishPreparedCollaborativeMutation(input);

    expect(resumed).toMatchObject({
      status: 'committed',
      disposition: 'already-committed',
    });
    expect(store.publications).toHaveLength(1);
    expect(
      await readCollaborationAuthorityRollbackAnchor(
        authorityRollbackAnchorPath,
        databaseRootKey,
      ),
    ).toEqual(remote.authorityAnchors.at(-1));
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      remote.anchors.at(-1),
    );
  });

  it('restarts a committed DRK recovery without reopening prior state and accepts only the exact pre-existing anchor', async () => {
    const fixture = buildRecoveryFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(91);
    const databaseRootKey = new Uint8Array(32).fill(92);
    await initializeAuthorityRecovery(fixture, databaseRootKey);
    const input = authorityRecoveryServiceInput(
      fixture,
      store,
      databaseRootKey,
      secret,
    );
    await publishPreparedCollaborativeMutation(input);
    vi.mocked(openCollaborativeVaultForDatabaseAuthorityRecovery).mockClear();

    const replay = await publishPreparedCollaborativeMutation(input);

    expect(replay).toMatchObject({
      status: 'committed',
      disposition: 'already-committed',
    });
    expect(openCollaborativeVaultForDatabaseAuthorityRecovery).not.toHaveBeenCalled();
    expect(store.publications).toHaveLength(1);
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      fixture.prepared.candidateAnchor,
    );

    const substitutedAccess = serviceInput(
      fixture,
      store,
      new Uint8Array(32).fill(93),
      secret,
    );
    await expect(
      publishPreparedCollaborativeMutation(substitutedAccess),
    ).resolves.toEqual({ status: 'terminal', reason: 'operation-id-reused' });
  });

  it('never overwrites a foreign destination anchor after an exact DRK-authorized commit', async () => {
    const fixture = buildRecoveryFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(94);
    const databaseRootKey = new Uint8Array(32).fill(95);
    await initializeAuthorityRecovery(fixture, databaseRootKey);
    const foreignAnchor = {
      ...fixture.prepared.candidateAnchor,
      membershipDigest: digest(96),
    };
    await createRecipientRollbackAnchor(rollbackAnchorPath, secret, foreignAnchor);

    const result = await publishPreparedCollaborativeMutation(
      authorityRecoveryServiceInput(fixture, store, databaseRootKey, secret),
    );

    expect(result).toEqual({
      status: 'unknown',
      reason: 'anchor-persistence-failed',
    });
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      foreignAnchor,
    );
  });

  it('rejects mixed or legacy recovery secrets before authentication or persistence', async () => {
    const fixture = buildRecoveryFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(97);
    const databaseRootKey = new Uint8Array(32).fill(98);
    await initializeAuthorityRecovery(fixture, databaseRootKey);
    const valid = authorityRecoveryServiceInput(
      fixture,
      store,
      databaseRootKey,
      secret,
    );

    await expect(
      publishPreparedCollaborativeMutation({
        ...valid,
        access: {
          kind: 'database-authority-recovery',
          databaseRootKey,
          recipientEncryptionPrivateKey: new Uint8Array(32).fill(99),
        },
      } as unknown as PublishPreparedCollaborativeMutationInput),
    ).rejects.toMatchObject({ kind: 'invalid-input' });
    await expect(
      publishPreparedCollaborativeMutation({
        ...valid,
        databaseRootKey,
      } as unknown as PublishPreparedCollaborativeMutationInput),
    ).rejects.toMatchObject({ kind: 'invalid-input' });

    expect(openCollaborativeVaultForDatabaseAuthorityRecovery).not.toHaveBeenCalled();
    expect(store.publications).toHaveLength(0);
    await expect(readFile(operationJournalPath, 'utf8')).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('replays the same journal bytes and does not republish an existing exact commit', async () => {
    const fixture = buildFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(73);
    const privateKey = new Uint8Array(32).fill(74);
    await initialize(fixture, secret);
    const input = serviceInput(fixture, store, privateKey, secret);
    await publishPreparedCollaborativeMutation(input);

    const replay = await publishPreparedCollaborativeMutation(input);

    expect(replay).toMatchObject({
      status: 'committed',
      disposition: 'already-committed',
    });
    expect(store.publications).toHaveLength(1);
  });

  it('fails closed when the same operation journal path is replayed with changed bytes', async () => {
    const fixture = buildFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(75);
    const privateKey = new Uint8Array(32).fill(76);
    await initialize(fixture, secret);
    await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret),
    );
    const changed = {
      ...fixture.prepared,
      candidateAnchor: {
        ...fixture.prepared.candidateAnchor,
        updatedAt: '2026-08-29T00:03:01.000Z',
      },
    } as PreparedBundle;

    const result = await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret, changed),
    );

    expect(result).toEqual({ status: 'terminal', reason: 'operation-id-reused' });
    expect(store.publications).toHaveLength(1);
  });

  it.each([
    ['conflict', 'conflict'],
    ['rejected', 'rejected'],
  ] as const)(
    'keeps a direct %s result retryable and retains the prepared journal',
    async (behavior, reason) => {
      const fixture = buildFixture();
      const store = new TestStore(fixture);
      store.behavior = behavior;
      const secret = new Uint8Array(32).fill(77);
      const privateKey = new Uint8Array(32).fill(78);
      await initialize(fixture, secret);
      const before = await readRecipientRollbackAnchor(rollbackAnchorPath, secret);

      const result = await publishPreparedCollaborativeMutation(
        serviceInput(fixture, store, privateKey, secret),
      );

      expect(result).toEqual({ status: 'retryable', reason });
      expect(await readJournal(fixture, secret)).toMatchObject({ state: 'prepared' });
      expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
        before,
      );
    },
  );

  it('reconciles a lost response after the exact committed outcome becomes authoritative', async () => {
    const fixture = buildFixture();
    const store = new TestStore(fixture);
    store.behavior = 'commit-then-throw';
    const secret = new Uint8Array(32).fill(79);
    const privateKey = new Uint8Array(32).fill(80);
    await initialize(fixture, secret);

    const result = await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret),
    );

    expect(result).toMatchObject({ status: 'committed' });
    expect(await readJournal(fixture, secret)).toMatchObject({ state: 'committed' });
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      fixture.prepared.candidateAnchor,
    );
  });

  it('requires exact candidate readback before advancing the protected anchor', async () => {
    const fixture = buildFixture();
    const store = new TestStore(fixture);
    store.behavior = 'readback-mismatch';
    const secret = new Uint8Array(32).fill(81);
    const privateKey = new Uint8Array(32).fill(82);
    await initialize(fixture, secret);
    const before = await readRecipientRollbackAnchor(rollbackAnchorPath, secret);

    const result = await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret),
    );

    expect(result).toEqual({ status: 'terminal', reason: 'readback-mismatch' });
    expect(await readJournal(fixture, secret)).toMatchObject({ state: 'prepared' });
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      before,
    );
  });

  it('keeps an ahead commit readback resumable and recovers it without republishing', async () => {
    const fixture = buildFixture();
    const remote = buildRemoteSuccessors(fixture, 1);
    const store = new TestStore(fixture);
    store.postPublishCurrent = remote.current;
    store.proofRange = { exact: 'candidate-predecessor-to-successor' };
    const secret = new Uint8Array(32).fill(80);
    const privateKey = new Uint8Array(32).fill(81);
    await initialize(fixture, secret);
    const before = await readRecipientRollbackAnchor(rollbackAnchorPath, secret);
    vi.mocked(verifyCollaborativeJournalSuccessorChain).mockResolvedValue({
      currentDocument: remote.current,
      anchors: remote.anchors,
    });
    const input = serviceInput(fixture, store, privateKey, secret);

    const raced = await publishPreparedCollaborativeMutation(input);

    expect(raced).toEqual({
      status: 'unknown',
      reason: 'readback-unavailable',
    });
    expect(await readJournal(fixture, secret)).toMatchObject({ state: 'prepared' });
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      before,
    );

    const resumed = await publishPreparedCollaborativeMutation(input);

    expect(resumed).toMatchObject({
      status: 'committed',
      disposition: 'already-committed',
    });
    expect(store.publications).toHaveLength(1);
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      remote.anchors.at(-1),
    );
  });

  it('returns a resumable unknown and retains local evidence after an ambiguous absent outcome', async () => {
    const fixture = buildFixture();
    const store = new TestStore(fixture);
    store.behavior = 'throw-without-outcome';
    const secret = new Uint8Array(32).fill(83);
    const privateKey = new Uint8Array(32).fill(84);
    await initialize(fixture, secret);
    const before = await readRecipientRollbackAnchor(rollbackAnchorPath, secret);

    const result = await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret),
    );

    expect(result).toEqual({ status: 'unknown', reason: 'publication-ambiguous' });
    expect(await readJournal(fixture, secret)).toMatchObject({ state: 'prepared' });
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      before,
    );
  });

  it('distinguishes pre-publication journal persistence failure as resumable unknown', async () => {
    const fixture = buildFixture();
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(85);
    const privateKey = new Uint8Array(32).fill(86);
    await initialize(fixture, secret);

    const result = await publishPreparedCollaborativeMutation(
      serviceInput(
        fixture,
        store,
        privateKey,
        secret,
        fixture.prepared,
        join(directory, 'missing-parent', 'journal.cvkx'),
      ),
    );

    expect(result).toEqual({
      status: 'unknown',
      reason: 'journal-persistence-failed',
    });
    expect(store.publications).toHaveLength(0);
  });

  it('appends the exact checkpoint only after committed candidate readback', async () => {
    const fixture = buildFixture();
    const checkpoint = buildCheckpoint(fixture);
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(87);
    const privateKey = new Uint8Array(32).fill(88);
    await initialize(fixture, secret);

    const result = await publishPreparedCollaborativeMutation(
      serviceInput(
        fixture,
        store,
        privateKey,
        secret,
        fixture.prepared,
        operationJournalPath,
        checkpoint,
      ),
    );

    expect(result).toMatchObject({ status: 'committed' });
    expect(store.events).toEqual(['publish', 'readback', 'checkpoint']);
    expect(canonicalJson(store.checkpointAppends[0])).toBe(canonicalJson(checkpoint));
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      fixture.prepared.candidateAnchor,
    );
  });

  it('binds the checkpoint across append-failure replay and resumes only exact bytes', async () => {
    const fixture = buildFixture();
    const checkpoint = buildCheckpoint(fixture);
    const store = new TestStore(fixture);
    store.failCheckpointAppend = true;
    const secret = new Uint8Array(32).fill(89);
    const privateKey = new Uint8Array(32).fill(90);
    await initialize(fixture, secret);
    const before = await readRecipientRollbackAnchor(rollbackAnchorPath, secret);
    const input = serviceInput(
      fixture,
      store,
      privateKey,
      secret,
      fixture.prepared,
      operationJournalPath,
      checkpoint,
    );

    const first = await publishPreparedCollaborativeMutation(input);

    expect(first).toEqual({
      status: 'retryable',
      reason: 'checkpoint-append-failed',
    });
    expect(await readJournal(fixture, secret)).toMatchObject({
      state: 'prepared',
      authorizationCheckpoint: checkpoint,
    });
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      before,
    );

    const omitted = await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret),
    );
    expect(omitted).toEqual({
      status: 'terminal',
      reason: 'operation-id-reused',
    });

    const substitutedInput = collaborationAuthorizationCheckpointSchema.parse({
      ...checkpoint,
      checkpointId: 'checkpoint-operation-ordinary-2-substitute',
    });
    const substituted = collaborationAuthorizationCheckpointSchema.parse({
      ...substitutedInput,
      checkpointDigest: computeAuthorizationCheckpointDigest(substitutedInput),
    });
    const changed = await publishPreparedCollaborativeMutation(
      serviceInput(
        fixture,
        store,
        privateKey,
        secret,
        fixture.prepared,
        operationJournalPath,
        substituted,
      ),
    );
    expect(changed).toEqual({
      status: 'terminal',
      reason: 'operation-id-reused',
    });
    expect(store.checkpointAppends).toHaveLength(1);
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      before,
    );

    store.failCheckpointAppend = false;
    const resumed = await publishPreparedCollaborativeMutation(input);

    expect(resumed).toMatchObject({
      status: 'committed',
      disposition: 'already-committed',
    });
    expect(store.publications).toHaveLength(1);
    expect(store.checkpointAppends).toHaveLength(2);
    expect(await readRecipientRollbackAnchor(rollbackAnchorPath, secret)).toEqual(
      fixture.prepared.candidateAnchor,
    );

    const terminalOmission = await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret),
    );
    expect(terminalOmission).toEqual({
      status: 'terminal',
      reason: 'operation-id-reused',
    });
    expect(store.checkpointAppends).toHaveLength(2);
  });

  it('rejects a substituted checkpoint binding before remote publication', async () => {
    const fixture = buildFixture();
    const valid = buildCheckpoint(fixture);
    const substitutedInput = collaborationAuthorizationCheckpointSchema.parse({
      ...valid,
      headDigest: digest(91),
    });
    const substituted = collaborationAuthorizationCheckpointSchema.parse({
      ...substitutedInput,
      checkpointDigest: computeAuthorizationCheckpointDigest(substitutedInput),
    });
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(92);
    const privateKey = new Uint8Array(32).fill(93);
    await initialize(fixture, secret);

    await expect(
      publishPreparedCollaborativeMutation(
        serviceInput(
          fixture,
          store,
          privateKey,
          secret,
          fixture.prepared,
          operationJournalPath,
          substituted,
        ),
      ),
    ).rejects.toMatchObject({
      kind: 'candidate-invalid',
    });
    expect(store.publications).toHaveLength(0);
    expect(store.checkpointAppends).toHaveLength(0);
  });

  it('requires an authorization checkpoint for add-member publication', async () => {
    const fixture = buildFixture();
    const prepared = asAddMemberPrepared(fixture);
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(94);
    const privateKey = new Uint8Array(32).fill(95);

    await expect(
      publishPreparedCollaborativeMutation(
        serviceInput(fixture, store, privateKey, secret, prepared),
      ),
    ).rejects.toMatchObject({
      kind: 'invalid-input',
    });
    expect(store.publications).toHaveLength(0);
  });

  it('requires an authorization checkpoint for add-device publication', async () => {
    const fixture = buildFixture();
    const prepared = asAddMemberPrepared(fixture, 'add-device');
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(96);
    const privateKey = new Uint8Array(32).fill(97);

    await expect(
      publishPreparedCollaborativeMutation(
        serviceInput(fixture, store, privateKey, secret, prepared),
      ),
    ).rejects.toMatchObject({
      kind: 'invalid-input',
    });
    expect(store.publications).toHaveLength(0);
  });

  it('rejects membership-history checkpoint signer substitution without trying other device keys', async () => {
    const fixture = withHistoryCheckpoint(
      buildFixture({ historicalCheckpointSigner: true }),
      DEVICE_ID,
    );
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(99);
    const privateKey = new Uint8Array(32).fill(100);
    vi.mocked(verifyCollaborationRecord).mockImplementation(
      (domain, _value, _schema, _signatureField, publicKey) =>
        Promise.resolve(
          domain !== COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature ||
            publicKey === HISTORICAL_SIGNING_PUBLIC_KEY,
        ),
    );
    await initialize(fixture, secret);

    await expect(
      publishPreparedCollaborativeMutation(
        serviceInput(fixture, store, privateKey, secret),
      ),
    ).rejects.toMatchObject({ kind: 'candidate-invalid' });
    expect(store.publications).toHaveLength(0);
  });

  it('accepts a named historical checkpoint signer revoked and denied only later', async () => {
    const fixture = withHistoryCheckpoint(
      buildFixture({ historicalCheckpointSigner: true }),
      HISTORICAL_DEVICE_ID,
    );
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(101);
    const privateKey = new Uint8Array(32).fill(102);
    vi.mocked(verifyCollaborationRecord).mockImplementation(
      (domain, _value, _schema, _signatureField, publicKey) =>
        Promise.resolve(
          domain !== COLLABORATION_DOMAINS.membershipHistoryCheckpointSignature ||
            publicKey === HISTORICAL_SIGNING_PUBLIC_KEY,
        ),
    );
    await initialize(fixture, secret);

    const result = await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret),
    );

    expect(result).toMatchObject({ status: 'committed' });
    expect(store.publications).toHaveLength(1);
  });

  it('accepts a named history-event signer revoked and denied only later', async () => {
    const fixture = withHistoryEvent(
      buildFixture({ historicalCheckpointSigner: true }),
      HISTORICAL_DEVICE_ID,
      HISTORY_EVENT_AT,
    );
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(105);
    const privateKey = new Uint8Array(32).fill(106);
    vi.mocked(verifyCollaborationRecord).mockImplementation(
      (domain, _value, _schema, _signatureField, publicKey) =>
        Promise.resolve(
          domain !== COLLABORATION_DOMAINS.membershipHistorySignature ||
            publicKey === HISTORICAL_SIGNING_PUBLIC_KEY,
        ),
    );
    await initialize(fixture, secret);

    const result = await publishPreparedCollaborativeMutation(
      serviceInput(fixture, store, privateKey, secret),
    );

    expect(result).toMatchObject({ status: 'committed' });
    expect(store.publications).toHaveLength(1);
  });

  it.each([
    {
      fence: 'revocation',
      eventAt: HISTORICAL_DEVICE_RETIRED_AT,
      retiredAt: HISTORICAL_DEVICE_RETIRED_AT,
    },
    {
      fence: 'denial',
      eventAt: HISTORICAL_DEVICE_DENIED_AT,
      retiredAt: '2026-08-29T00:02:45.000Z',
    },
  ])('rejects a named history-event signer at its $fence fence', async (values) => {
    const fixture = withHistoryEvent(
      buildFixture({
        historicalCheckpointSigner: true,
        historicalDeviceRetiredAt: values.retiredAt,
      }),
      HISTORICAL_DEVICE_ID,
      values.eventAt,
    );
    const store = new TestStore(fixture);
    const secret = new Uint8Array(32).fill(107);
    const privateKey = new Uint8Array(32).fill(108);
    vi.mocked(verifyCollaborationRecord).mockImplementation(
      (domain, _value, _schema, _signatureField, publicKey) =>
        Promise.resolve(
          domain !== COLLABORATION_DOMAINS.membershipHistorySignature ||
            publicKey === HISTORICAL_SIGNING_PUBLIC_KEY,
        ),
    );
    await initialize(fixture, secret);

    await expect(
      publishPreparedCollaborativeMutation(
        serviceInput(fixture, store, privateKey, secret),
      ),
    ).rejects.toMatchObject({ kind: 'candidate-invalid' });
    expect(store.publications).toHaveLength(0);
  });
});
