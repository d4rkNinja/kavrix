import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST,
  COLLABORATIVE_AUTHORIZATION_CHECKPOINT_FORMAT,
  COLLABORATIVE_AUTHORITY_DELEGATION_FORMAT,
  COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT,
  COLLABORATIVE_VAULT_FORMAT,
  COLLABORATION_GENESIS_HEAD_DIGEST,
  collaborationMutationReceiptSchema,
  collaborationAuthorizationCheckpointSchema,
  collaborativeVaultDocumentSchema,
  collaborationMutationProofEntrySchema,
  databaseIdSchema,
  deviceIdSchema,
  durableOperationOutcomeSchema,
  principalIdSchema,
  recipientRollbackAnchorSchema,
  sha256DigestSchema,
  type CollaborativeVaultDocument,
  type CollaborationAuthorizationCheckpoint,
  type DurableOperationOutcome,
  type RecipientRollbackAnchor,
  type Sha256Digest,
  vaultIdSchema,
} from '@kavrix/schemas';
import {
  computeAuthorizationCheckpointDigest,
  computeAuthorizationTransitionDigest,
  computeMutationHead,
  encodeBase64Url,
  zeroize,
} from '@kavrix/crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(async () => undefined),
  verifyWindowsDirectoryAcl: vi.fn(async () => undefined),
  verifyWindowsUserOnlyAcl: vi.fn(async () => undefined),
}));

import {
  collaborativeOperationJournalPath,
  computeFinalizedMutationLinkDigest,
  createCollaborativeOperationJournal,
  readCollaborativeOperationJournal,
  reconcileCollaborativeOperationJournal,
  type CollaborationOperationJournalScope,
} from '../src/index.js';

const timestamp = '2026-01-01T00:00:00.000Z';
const laterTimestamp = '2026-01-02T00:00:00.000Z';
const expiryTimestamp = '2026-01-03T00:00:00.000Z';
const bytes = (length: number, value: number): string =>
  Buffer.alloc(length, value).toString('base64url');
const digest = (value: number): string => bytes(32, value);
const signature = (value: number): string => bytes(64, value);

const scope: CollaborationOperationJournalScope = {
  databaseId: databaseIdSchema.parse('database-a'),
  vaultId: vaultIdSchema.parse('vault-a'),
  principalId: principalIdSchema.parse('principal-a'),
  deviceId: deviceIdSchema.parse('device-a'),
};

function candidateWithRequestDigest(requestDigest: string): CollaborativeVaultDocument {
  const stateFence = {
    authorityEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
  } as const;
  const authorizationStateDigest = digest(9);
  const previousAuthorizationStateDigest =
    COLLABORATION_GENESIS_AUTHORIZATION_STATE_DIGEST;
  const previousHeadDigest = COLLABORATION_GENESIS_HEAD_DIGEST;
  let headDigest = digest(7);
  const operationId = 'operation-genesis';
  const aad = {
    protocolVersion: 1 as const,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    ...stateFence,
    authorizationStateDigest,
    entityType: 'vault-payload' as const,
    entityId: 'vault-a',
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    metadataDigest: digest(16),
  };
  const membershipAad = {
    ...aad,
    entityType: 'membership-manifest' as const,
    metadataDigest: digest(17),
  };
  const previousTuple = {
    authorityEpoch: 1,
    documentRevision: 0,
    membershipRevision: 0,
    policyRevision: 0,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    authorizationStateDigest: previousAuthorizationStateDigest,
  } as const;
  const nextTuple = {
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: digest(2),
    authorizationStateDigest,
  } as const;
  const delegation = {
    format: COLLABORATIVE_AUTHORITY_DELEGATION_FORMAT,
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    authorityEpoch: 1,
    authoritySigningPublicKey: bytes(32, 30),
    authoritySigningKeyFingerprint: digest(5),
    authorityRecoveryPublicKey: bytes(32, 31),
    authorityRecoveryKeyFingerprint: digest(32),
    genesisOperationId: operationId,
    genesisTuple: nextTuple,
    genesisHeadDigest: headDigest,
    initialAuthorizationStateDigest: authorizationStateDigest,
    initialOwnerPrincipalId: 'principal-a',
    initialOwnerRootKeyFingerprint: digest(33),
    initialOwnerDeviceId: 'device-a',
    initialOwnerDeviceSigningKeyFingerprint: digest(34),
    initialOwnerDeviceEncryptionKeyFingerprint: digest(35),
    issuedAt: timestamp,
    authoritySignature: signature(36),
  };
  const commitment = {
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId,
    operationType: 'genesis-migration' as const,
    requestDigest,
    previousHeadDigest,
    previousAuthorizationStateDigest,
    authorizationStateDigest,
    authorizationTransitionDigest: digest(37),
    previousAuthorityEpoch: previousTuple.authorityEpoch,
    previousDocumentRevision: previousTuple.documentRevision,
    previousMembershipRevision: previousTuple.membershipRevision,
    previousPolicyRevision: previousTuple.policyRevision,
    previousKeyEpoch: previousTuple.keyEpoch,
    previousDatabaseDeviceGeneration: previousTuple.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: previousTuple.databaseDeviceRegistryDigest,
    ...stateFence,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    encryptedPayloadDigest: digest(16),
    encryptedMembershipDigest: digest(17),
    encryptedEnvelopesDigest: digest(18),
    policyDigest: digest(4),
    writerPrincipalId: 'principal-a',
    writerDeviceId: 'device-a',
    timestamp,
  };
  const authorizationTransition = {
    format: 'kavrix-collaborative-authorization-transition',
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId,
    operationType: 'genesis-migration' as const,
    previousHeadDigest,
    previousAuthorizationStateDigest,
    authorizationStateDigest,
    previousTuple,
    nextTuple,
    evidence: { kind: 'none' as const },
    issuedAt: timestamp,
    expiresAt: expiryTimestamp,
    transitionDigest: digest(37),
    transitionSignature: {
      signerKind: 'owner-device' as const,
      signerPrincipalId: 'principal-a',
      signerDeviceId: 'device-a',
      signature: signature(38),
    },
  };
  const transitionDigest = computeAuthorizationTransitionDigest(
    authorizationTransition,
  );
  authorizationTransition.transitionDigest = transitionDigest;
  commitment.authorizationTransitionDigest = transitionDigest;
  headDigest = computeMutationHead(commitment);
  delegation.genesisHeadDigest = headDigest;
  const currentMutationLink = {
    format: COLLABORATIVE_FINALIZED_MUTATION_LINK_FORMAT,
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    authorityDelegationDigest: digest(39),
    commitment,
    authorizationTransition,
    resultingHeadDigest: headDigest,
    writerSignature: {
      algorithm: 'ed25519' as const,
      writerPrincipalId: 'principal-a',
      writerDeviceId: 'device-a',
      commitmentDigest: headDigest,
      signature: signature(40),
    },
    finalizedAt: laterTimestamp,
  };
  return collaborativeVaultDocumentSchema.parse({
    format: COLLABORATIVE_VAULT_FORMAT,
    documentVersion: 1,
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    ...stateFence,
    documentRevision: 1,
    membershipRevision: 1,
    policyRevision: 1,
    keyEpoch: 1,
    previousHeadDigest,
    headDigest,
    authorityDelegation: delegation,
    authorityDelegationDigest: digest(39),
    authorizationStateDigest,
    encryptedPayloadDigest: digest(16),
    encryptedMembershipDigest: digest(17),
    encryptedEnvelopesDigest: digest(18),
    policyDigest: digest(4),
    databaseAuthorityRecoveryEnvelope: {
      format: 'kavrix-collaborative-authority-recovery-envelope',
      protocolVersion: 1,
      algorithm: 'x25519-sealed-box',
      databaseId: 'database-a',
      vaultId: 'vault-a',
      authorityEpoch: 1,
      authorityRecoveryKeyFingerprint: digest(32),
      keyEpoch: 1,
      membershipRevision: 1,
      databaseDeviceGeneration: 1,
      databaseDeviceRegistryDigest: digest(2),
      sealedVaultRootKey: bytes(80, 41),
      envelopeDigest: digest(42),
      sealedByPrincipalId: 'principal-a',
      sealedByDeviceId: 'device-a',
      createdAt: timestamp,
      ownerSignature: signature(43),
    },
    encryptedPayload: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: bytes(24, 19),
      ciphertext: bytes(64, 20),
      authenticationTag: bytes(16, 21),
      aad,
    },
    encryptedMembershipManifest: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: bytes(24, 22),
      ciphertext: bytes(64, 23),
      authenticationTag: bytes(16, 24),
      aad: membershipAad,
    },
    discoveryRecords: [],
    currentMutationLink,
    createdAt: timestamp,
    updatedAt: laterTimestamp,
  });
}

function outcomeFor(
  candidate: CollaborativeVaultDocument,
  requestDigest: Sha256Digest = candidate.currentMutationLink.commitment.requestDigest,
): DurableOperationOutcome {
  const commitment = candidate.currentMutationLink.commitment;
  const priorTuple = {
    authorityEpoch: commitment.previousAuthorityEpoch,
    databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
    databaseDeviceRegistryDigest: commitment.previousDatabaseDeviceRegistryDigest,
    documentRevision: commitment.previousDocumentRevision,
    membershipRevision: commitment.previousMembershipRevision,
    policyRevision: commitment.previousPolicyRevision,
    keyEpoch: commitment.previousKeyEpoch,
    authorizationStateDigest: commitment.previousAuthorizationStateDigest,
  };
  const committedTuple = {
    authorityEpoch: candidate.authorityEpoch,
    databaseDeviceGeneration: candidate.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
    documentRevision: candidate.documentRevision,
    membershipRevision: candidate.membershipRevision,
    policyRevision: candidate.policyRevision,
    keyEpoch: candidate.keyEpoch,
    authorizationStateDigest: candidate.authorizationStateDigest,
  };
  const receipt = collaborationMutationReceiptSchema.parse({
    format: 'kavrix-collaborative-mutation-receipt',
    protocolVersion: 1,
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    operationId: commitment.operationId,
    operationType: commitment.operationType,
    requestDigest,
    actorPrincipalId: commitment.writerPrincipalId,
    actorDeviceId: commitment.writerDeviceId,
    priorTuple,
    priorHeadDigest: candidate.previousHeadDigest,
    committedTuple,
    committedHeadDigest: candidate.headDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
      candidate.currentMutationLink,
    ),
    outcomeDigest: digest(27),
    committedAt: laterTimestamp,
    receiptSignature: signature(9),
  });
  return durableOperationOutcomeSchema.parse({
    format: 'kavrix-collaborative-operation-outcome',
    protocolVersion: 1,
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    operationId: commitment.operationId,
    operationType: commitment.operationType,
    requestDigest,
    actorPrincipalId: commitment.writerPrincipalId,
    actorDeviceId: commitment.writerDeviceId,
    priorTuple,
    priorHeadDigest: candidate.previousHeadDigest,
    state: 'committed',
    committedTuple,
    committedHeadDigest: candidate.headDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
      candidate.currentMutationLink,
    ),
    committedAt: laterTimestamp,
    outcomeDigest: digest(27),
    signedMutationReceipt: receipt,
    createdAt: timestamp,
    resolvedAt: laterTimestamp,
    detailsRetainedUntil: expiryTimestamp,
  });
}

function authorizationCheckpointFor(
  candidate: CollaborativeVaultDocument,
  ownerSignature = signature(10),
): CollaborationAuthorizationCheckpoint {
  const draft = collaborationAuthorizationCheckpointSchema.parse({
    format: COLLABORATIVE_AUTHORIZATION_CHECKPOINT_FORMAT,
    protocolVersion: candidate.protocolVersion,
    checkpointId: 'checkpoint-a',
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    authorityDelegationDigest: candidate.authorityDelegationDigest,
    tuple: {
      authorityEpoch: candidate.authorityEpoch,
      databaseDeviceGeneration: candidate.databaseDeviceGeneration,
      databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
      documentRevision: candidate.documentRevision,
      membershipRevision: candidate.membershipRevision,
      policyRevision: candidate.policyRevision,
      keyEpoch: candidate.keyEpoch,
      authorizationStateDigest: candidate.authorizationStateDigest,
    },
    headDigest: candidate.headDigest,
    authorizationStateDigest: candidate.authorizationStateDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
      candidate.currentMutationLink,
    ),
    compactedThroughDocumentRevision: candidate.documentRevision,
    checkpointDigest: digest(90),
    signerPrincipalId: candidate.currentMutationLink.commitment.writerPrincipalId,
    signerDeviceId: candidate.currentMutationLink.commitment.writerDeviceId,
    createdAt: laterTimestamp,
    ownerSignature,
  });
  return collaborationAuthorizationCheckpointSchema.parse({
    ...draft,
    checkpointDigest: computeAuthorizationCheckpointDigest(draft),
  });
}

function candidateAnchorFor(
  candidate: CollaborativeVaultDocument,
  overrides: Record<string, unknown> = {},
): RecipientRollbackAnchor {
  const commitment = candidate.currentMutationLink.commitment;
  return recipientRollbackAnchorSchema.parse({
    format: 'kavrix-collaborative-recipient-rollback-anchor',
    protocolVersion: candidate.protocolVersion,
    databaseId: candidate.databaseId,
    vaultId: candidate.vaultId,
    principalId: commitment.writerPrincipalId,
    deviceId: commitment.writerDeviceId,
    authorityEpoch: candidate.authorityEpoch,
    authorityDelegationDigest: candidate.authorityDelegationDigest,
    databaseDeviceGeneration: candidate.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
    membershipRevision: candidate.membershipRevision,
    membershipDigest: digest(29),
    policyRevision: candidate.policyRevision,
    policyDigest: candidate.policyDigest,
    keyEpoch: candidate.keyEpoch,
    documentRevision: candidate.documentRevision,
    encryptedPayloadDigest: candidate.encryptedPayloadDigest,
    headDigest: candidate.headDigest,
    authorizationStateDigest: candidate.authorizationStateDigest,
    finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(
      candidate.currentMutationLink,
    ),
    updatedAt: candidate.updatedAt,
    ...overrides,
  });
}

function proofEntryFor(candidate: CollaborativeVaultDocument) {
  const link = candidate.currentMutationLink;
  const commitment = link.commitment;
  return collaborationMutationProofEntrySchema.parse({
    link,
    authorizationWitness: {
      format: 'kavrix-collaborative-authorization-witness',
      protocolVersion: candidate.protocolVersion,
      databaseId: candidate.databaseId,
      vaultId: candidate.vaultId,
      authorityDelegationDigest: link.authorityDelegationDigest,
      tuple: {
        authorityEpoch: candidate.authorityEpoch,
        documentRevision: candidate.documentRevision,
        membershipRevision: candidate.membershipRevision,
        policyRevision: candidate.policyRevision,
        keyEpoch: candidate.keyEpoch,
        databaseDeviceGeneration: candidate.databaseDeviceGeneration,
        databaseDeviceRegistryDigest: candidate.databaseDeviceRegistryDigest,
        authorizationStateDigest: candidate.authorizationStateDigest,
      },
      previousHeadDigest: candidate.previousHeadDigest,
      headDigest: candidate.headDigest,
      encryptedMembershipDigest: commitment.encryptedMembershipDigest,
      encryptedEnvelopesDigest: commitment.encryptedEnvelopesDigest,
      policyDigest: commitment.policyDigest,
      databaseDeviceRegistry: {
        format: 'kavrix-collaborative-device-registry',
        protocolVersion: candidate.protocolVersion,
        databaseId: candidate.databaseId,
        authorityEpoch: candidate.authorityEpoch,
        authorityFingerprint:
          candidate.authorityDelegation.authoritySigningKeyFingerprint,
        generation: candidate.databaseDeviceGeneration,
        previousRegistryDigest: digest(1),
        registryDigest: candidate.databaseDeviceRegistryDigest,
        deniedDevices: [],
        updatedAt: candidate.updatedAt,
        authoritySignature: signature(41),
      },
      databaseAuthorityRecoveryEnvelope: candidate.databaseAuthorityRecoveryEnvelope,
      encryptedMembershipManifest: candidate.encryptedMembershipManifest,
      discoveryRecords: [],
      finalizedMutationLinkDigest: computeFinalizedMutationLinkDigest(link),
    },
  });
}

let directory = '';
beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-collaboration-journal-'));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

describe('protected ambiguous-commit collaboration journals', () => {
  it('persists exact candidate bytes and the proposed committed outcome', async () => {
    const secret = new Uint8Array(32).fill(71);
    const candidate = candidateWithRequestDigest(digest(25));
    const candidateAnchor = candidateAnchorFor(candidate);
    const outcome = outcomeFor(candidate);
    const file = collaborativeOperationJournalPath(
      join(directory, 'vault.cvkx'),
      candidate.databaseId,
      candidate.vaultId,
      candidate.currentMutationLink.commitment.operationId,
    );
    try {
      await createCollaborativeOperationJournal(file, secret, {
        accessMode: 'recipient',
        candidate,
        candidateAnchor,
        proofEntry: proofEntryFor(candidate),
        proposedOutcome: outcome,
      });
      const read = await readCollaborativeOperationJournal(file, secret, {
        expectedScope: scope,
      });
      expect(read).toMatchObject({
        state: 'prepared',
        candidate,
        candidateAnchor,
        proofEntry: proofEntryFor(candidate),
        proposedOutcome: outcome,
      });
      if (read?.state !== 'prepared') throw new Error('journal was not prepared');
      expect(read.candidate).toEqual(candidate);
      const serialized = await readFile(file, 'utf8');
      expect(serialized).not.toContain('plaintext-canary');
      expect(serialized).not.toContain('privateKey');
      expect(serialized).not.toContain('passphrase');
      expect(serialized).not.toContain(encodeBase64Url(secret));
    } finally {
      zeroize(secret);
    }
  });

  it('accepts exact same-ID replay and rejects a different request digest', async () => {
    const secret = new Uint8Array(32).fill(32);
    const candidate = candidateWithRequestDigest(digest(25));
    const candidateAnchor = candidateAnchorFor(candidate);
    const outcome = outcomeFor(candidate);
    const file = collaborativeOperationJournalPath(
      join(directory, 'vault.cvkx'),
      candidate.databaseId,
      candidate.vaultId,
      candidate.currentMutationLink.commitment.operationId,
    );
    try {
      await createCollaborativeOperationJournal(file, secret, {
        accessMode: 'recipient',
        candidate,
        candidateAnchor,
        proofEntry: proofEntryFor(candidate),
        proposedOutcome: outcome,
      });
      await expect(
        createCollaborativeOperationJournal(file, secret, {
          accessMode: 'recipient',
          candidate,
          candidateAnchor,
          proofEntry: proofEntryFor(candidate),
          proposedOutcome: outcome,
        }),
      ).resolves.toBeUndefined();
      await expect(
        createCollaborativeOperationJournal(file, secret, {
          accessMode: 'recipient',
          candidate,
          candidateAnchor: candidateAnchorFor(candidate, {
            membershipDigest: digest(30),
          }),
          proofEntry: proofEntryFor(candidate),
          proposedOutcome: outcome,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const differentCandidate = candidateWithRequestDigest(digest(28));
      const differentCandidateAnchor = candidateAnchorFor(differentCandidate);
      const differentOutcome = outcomeFor(differentCandidate, digest(28));
      await expect(
        createCollaborativeOperationJournal(file, secret, {
          accessMode: 'recipient',
          candidate: differentCandidate,
          candidateAnchor: differentCandidateAnchor,
          proofEntry: proofEntryFor(differentCandidate),
          proposedOutcome: differentOutcome,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
    }
  });

  it('rejects access-evidence misuse, proof omission, witness substitution, and link substitution', async () => {
    const secret = new Uint8Array(32).fill(72);
    const candidate = candidateWithRequestDigest(digest(25));
    const candidateAnchor = candidateAnchorFor(candidate);
    const outcome = outcomeFor(candidate);
    const base = {
      accessMode: 'recipient' as const,
      candidate,
      candidateAnchor,
      proofEntry: proofEntryFor(candidate),
      proposedOutcome: outcome,
    };
    const commitment = candidate.currentMutationLink.commitment;
    const recoveryRestartEvidence = {
      priorTuple: {
        authorityEpoch: commitment.previousAuthorityEpoch,
        documentRevision: commitment.previousDocumentRevision,
        membershipRevision: commitment.previousMembershipRevision,
        policyRevision: commitment.previousPolicyRevision,
        keyEpoch: commitment.previousKeyEpoch,
        databaseDeviceGeneration: commitment.previousDatabaseDeviceGeneration,
        databaseDeviceRegistryDigest: commitment.previousDatabaseDeviceRegistryDigest,
        authorizationStateDigest: commitment.previousAuthorizationStateDigest,
      },
      priorHeadDigest: commitment.previousHeadDigest,
      priorDatabaseAuthorityRecoveryEnvelopeDigest: digest(74),
    };
    try {
      await expect(
        createCollaborativeOperationJournal(
          collaborativeOperationJournalPath(
            join(directory, 'recipient-recovery-evidence.cvkx'),
            candidate.databaseId,
            candidate.vaultId,
            candidate.currentMutationLink.commitment.operationId,
          ),
          secret,
          { ...base, recoveryRestartEvidence },
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        createCollaborativeOperationJournal(
          collaborativeOperationJournalPath(
            join(directory, 'authority-wrong-operation.cvkx'),
            candidate.databaseId,
            candidate.vaultId,
            candidate.currentMutationLink.commitment.operationId,
          ),
          secret,
          {
            ...base,
            accessMode: 'database-authority-recovery',
            recoveryRestartEvidence,
          },
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      await expect(
        createCollaborativeOperationJournal(
          collaborativeOperationJournalPath(
            join(directory, 'proof-omitted.cvkx'),
            candidate.databaseId,
            candidate.vaultId,
            candidate.currentMutationLink.commitment.operationId,
          ),
          secret,
          { ...base, proofEntry: undefined } as never,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const witnessSubstitution = structuredClone(base.proofEntry) as Record<
        string,
        any
      >;
      witnessSubstitution.authorizationWitness.finalizedMutationLinkDigest = digest(73);
      await expect(
        createCollaborativeOperationJournal(
          collaborativeOperationJournalPath(
            join(directory, 'proof-witness-substitution.cvkx'),
            candidate.databaseId,
            candidate.vaultId,
            candidate.currentMutationLink.commitment.operationId,
          ),
          secret,
          { ...base, proofEntry: witnessSubstitution } as never,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const substitutedCandidate = candidateWithRequestDigest(digest(28));
      await expect(
        createCollaborativeOperationJournal(
          collaborativeOperationJournalPath(
            join(directory, 'proof-link-substitution.cvkx'),
            candidate.databaseId,
            candidate.vaultId,
            candidate.currentMutationLink.commitment.operationId,
          ),
          secret,
          {
            ...base,
            proofEntry: proofEntryFor(substitutedCandidate),
          } as never,
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
    }
  });

  it('rejects a candidate anchor whose scope, tuple, digest, head, or time differs', async () => {
    const secret = new Uint8Array(32).fill(37);
    const candidate = candidateWithRequestDigest(digest(25));
    const outcome = outcomeFor(candidate);
    const mismatches: Array<Partial<RecipientRollbackAnchor>> = [
      { databaseId: databaseIdSchema.parse('database-b') },
      { vaultId: vaultIdSchema.parse('vault-b') },
      { principalId: principalIdSchema.parse('principal-b') },
      { deviceId: deviceIdSchema.parse('device-b') },
      { authorityEpoch: 2 },
      { authorityDelegationDigest: digest(38) },
      { databaseDeviceGeneration: 2 },
      { databaseDeviceRegistryDigest: digest(39) },
      { membershipRevision: 2 },
      { policyRevision: 2 },
      { keyEpoch: 2 },
      { documentRevision: 2 },
      { encryptedPayloadDigest: digest(41) },
      { authorizationStateDigest: digest(43) },
      { finalizedMutationLinkDigest: digest(44) },
      { headDigest: digest(42) },
      { updatedAt: expiryTimestamp },
    ];
    try {
      for (const [index, mismatch] of mismatches.entries()) {
        const file = collaborativeOperationJournalPath(
          join(directory, `mismatch-${index}.cvkx`),
          candidate.databaseId,
          candidate.vaultId,
          candidate.currentMutationLink.commitment.operationId,
        );
        await expect(
          createCollaborativeOperationJournal(file, secret, {
            accessMode: 'recipient',
            candidate,
            candidateAnchor: candidateAnchorFor(candidate, mismatch),
            proofEntry: proofEntryFor(candidate),
            proposedOutcome: outcome,
          }),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      }

      const changedCandidate = candidateWithRequestDigest(digest(26));
      await expect(
        createCollaborativeOperationJournal(
          collaborativeOperationJournalPath(
            join(directory, 'candidate-mismatch.cvkx'),
            candidate.databaseId,
            candidate.vaultId,
            candidate.currentMutationLink.commitment.operationId,
          ),
          secret,
          {
            accessMode: 'recipient',
            candidate: changedCandidate,
            candidateAnchor: candidateAnchorFor(candidate),
            proofEntry: proofEntryFor(changedCandidate),
            proposedOutcome: outcome,
          },
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
    }
  });

  it('rejects wrong scope, wrong secret, tampered bytes, and malformed records', async () => {
    const secret = new Uint8Array(32).fill(33);
    const wrongSecret = new Uint8Array(32).fill(34);
    const candidate = candidateWithRequestDigest(digest(25));
    const candidateAnchor = candidateAnchorFor(candidate);
    const outcome = outcomeFor(candidate);
    const file = collaborativeOperationJournalPath(
      join(directory, 'vault.cvkx'),
      candidate.databaseId,
      candidate.vaultId,
      candidate.currentMutationLink.commitment.operationId,
    );
    try {
      await createCollaborativeOperationJournal(file, secret, {
        accessMode: 'recipient',
        candidate,
        candidateAnchor,
        proofEntry: proofEntryFor(candidate),
        proposedOutcome: outcome,
      });
      await expect(
        readCollaborativeOperationJournal(file, wrongSecret),
      ).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      await expect(
        readCollaborativeOperationJournal(file, secret, {
          expectedScope: { ...scope, deviceId: deviceIdSchema.parse('device-other') },
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const tampered = JSON.parse(await readFile(file, 'utf8')) as {
        candidate: CollaborativeVaultDocument;
      };
      tampered.candidate = {
        ...tampered.candidate,
        headDigest: sha256DigestSchema.parse(digest(35)),
      };
      await writeFile(file, JSON.stringify(tampered), { mode: 0o600 });
      await expect(
        readCollaborativeOperationJournal(file, secret),
      ).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });

      await writeFile(file, '{"state":"prepared"}', { mode: 0o600 });
      await expect(
        readCollaborativeOperationJournal(file, secret),
      ).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    } finally {
      zeroize(secret);
      zeroize(wrongSecret);
    }
  });

  it('reconciles an authoritative committed outcome and preserves terminal authentication', async () => {
    const secret = new Uint8Array(32).fill(36);
    const candidate = candidateWithRequestDigest(digest(25));
    const candidateAnchor = candidateAnchorFor(candidate);
    const outcome = outcomeFor(candidate);
    const file = collaborativeOperationJournalPath(
      join(directory, 'vault.cvkx'),
      candidate.databaseId,
      candidate.vaultId,
      candidate.currentMutationLink.commitment.operationId,
    );
    try {
      await createCollaborativeOperationJournal(file, secret, {
        accessMode: 'recipient',
        candidate,
        candidateAnchor,
        proofEntry: proofEntryFor(candidate),
        proposedOutcome: outcome,
      });
      await reconcileCollaborativeOperationJournal(file, secret, outcome);
      const terminal = await readCollaborativeOperationJournal(file, secret, {
        expectedScope: scope,
      });
      expect(terminal).toMatchObject({ state: 'committed', outcome });
      expect(terminal).toMatchObject({ proofEntry: proofEntryFor(candidate) });
      expect(terminal).toMatchObject({ candidate });
      expect(terminal).toMatchObject({ candidateAnchor });
      const serialized = await readFile(file, 'utf8');
      expect(serialized).toContain('"candidate"');
      expect(serialized).not.toContain('plaintext-canary');
      await expect(
        reconcileCollaborativeOperationJournal(file, secret, {
          ...outcome,
          resolvedAt: expiryTimestamp,
          detailsRetainedUntil: '2026-01-04T00:00:00.000Z',
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
    }
  });

  it('authenticates the exact authorization checkpoint across create and terminal replay', async () => {
    const secret = new Uint8Array(32).fill(46);
    const candidate = candidateWithRequestDigest(digest(25));
    const outcome = outcomeFor(candidate);
    const authorizationCheckpoint = authorizationCheckpointFor(candidate);
    const file = collaborativeOperationJournalPath(
      join(directory, 'checkpoint.cvkx'),
      candidate.databaseId,
      candidate.vaultId,
      candidate.currentMutationLink.commitment.operationId,
    );
    const base = {
      accessMode: 'recipient' as const,
      candidate,
      candidateAnchor: candidateAnchorFor(candidate),
      proofEntry: proofEntryFor(candidate),
      proposedOutcome: outcome,
    };
    try {
      await createCollaborativeOperationJournal(file, secret, {
        ...base,
        authorizationCheckpoint,
      });
      await expect(
        createCollaborativeOperationJournal(file, secret, base),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        createCollaborativeOperationJournal(file, secret, {
          ...base,
          authorizationCheckpoint: authorizationCheckpointFor(candidate, signature(11)),
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      await reconcileCollaborativeOperationJournal(file, secret, outcome);
      const terminal = await readCollaborativeOperationJournal(file, secret, {
        expectedScope: scope,
      });
      expect(terminal).toMatchObject({
        state: 'committed',
        authorizationCheckpoint,
      });
    } finally {
      zeroize(secret);
    }
  });

  it('does not terminalize the prepared record on an unsigned rejection hint', async () => {
    const secret = new Uint8Array(32).fill(45);
    const candidate = candidateWithRequestDigest(digest(25));
    const candidateAnchor = candidateAnchorFor(candidate);
    const proposedOutcome = outcomeFor(candidate);
    const rejected = durableOperationOutcomeSchema.parse({
      ...proposedOutcome,
      state: 'rejected',
      committedTuple: undefined,
      committedHeadDigest: undefined,
      finalizedMutationLinkDigest: undefined,
      committedAt: undefined,
      signedMutationReceipt: undefined,
      outcomeDigest: digest(46),
    });
    const file = collaborativeOperationJournalPath(
      join(directory, 'rejection-hint.cvkx'),
      candidate.databaseId,
      candidate.vaultId,
      candidate.currentMutationLink.commitment.operationId,
    );
    try {
      await createCollaborativeOperationJournal(file, secret, {
        accessMode: 'recipient',
        candidate,
        candidateAnchor,
        proofEntry: proofEntryFor(candidate),
        proposedOutcome,
      });
      await expect(
        reconcileCollaborativeOperationJournal(file, secret, rejected),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readCollaborativeOperationJournal(file, secret),
      ).resolves.toMatchObject({ state: 'prepared', candidate });
    } finally {
      zeroize(secret);
    }
  });
});
