import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  canonicalJson,
  collaborationRevisionTupleSchema,
  collaborationVaultDestructionTombstoneSchema,
  databaseIdSchema,
  deviceIdSchema,
  durableOperationOutcomeSchema,
  principalIdSchema,
  recipientVaultDestructionAnchorSchema,
  sha256DigestSchema,
  vaultIdSchema,
  type CollaborationVaultDestructionTombstone,
  type DurableOperationOutcome,
  type RecipientVaultDestructionAnchor,
} from '@kavrix/schemas';
import {
  computeCollaborativeVaultDestroyedPayloadDigest,
  computeCollaborativeVaultDestructionActionDigest,
  computeAuthorizationTransitionDigest,
  computeFinalizedMutationLinkDigest,
  computeMutationHead,
  computeOperationOutcomeDigest,
  encodeBase64Url,
  zeroize,
} from '@kavrix/crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const transitionFault = vi.hoisted(() => ({ failNext: false }));

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(async () => undefined),
  verifyWindowsDirectoryAcl: vi.fn(async () => undefined),
  verifyWindowsUserOnlyAcl: vi.fn(async () => undefined),
}));

vi.mock('../src/canonical-json-document.js', async () => {
  const actual = await vi.importActual<
    typeof import('../src/canonical-json-document.js')
  >('../src/canonical-json-document.js');
  return {
    ...actual,
    transitionProtectedJsonDocument: async (
      ...args: Parameters<typeof actual.transitionProtectedJsonDocument>
    ) => {
      if (transitionFault.failNext) {
        transitionFault.failNext = false;
        throw new Error('injected protected transition failure');
      }
      return actual.transitionProtectedJsonDocument(...args);
    },
  };
});

import {
  COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_SUFFIX,
  MAX_COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_BYTES,
  collaborativeVaultDestructionJournalPath,
  createCollaborativeVaultDestructionJournal,
  readCollaborativeVaultDestructionJournal,
  reconcileCollaborativeVaultDestructionJournal,
  verifyCommittedCollaborativeVaultDestructionJournal,
  type CollaborationVaultDestructionJournalScope,
} from '../src/collaboration-destruction-journal.js';

const createdAt = '2026-08-30T00:00:00.000Z';
const destroyedAt = '2026-08-30T00:01:00.000Z';
const transitionExpiresAt = '2026-09-01T00:00:00.000Z';
const retainedUntil = '2026-09-30T00:00:00.000Z';
const bytes = (length: number, value: number): string =>
  Buffer.alloc(length, value).toString('base64url');
const digest = (value: number) =>
  sha256DigestSchema.parse(encodeBase64Url(new Uint8Array(32).fill(value)));
const signature = (value: number): string => bytes(64, value);

const scope: CollaborationVaultDestructionJournalScope = {
  databaseId: databaseIdSchema.parse('database-destroy'),
  vaultId: vaultIdSchema.parse('vault-destroy'),
  principalId: principalIdSchema.parse('principal-owner'),
  deviceId: deviceIdSchema.parse('device-owner'),
};

type Artifacts = Readonly<{
  tombstone: CollaborationVaultDestructionTombstone;
  outcome: DurableOperationOutcome;
  anchor: RecipientVaultDestructionAnchor;
}>;

function artifacts(
  seed = 1,
  options: Readonly<{ invalidActionDigest?: boolean }> = {},
): Artifacts {
  const registryDigest = digest(seed + 1);
  const authorizationStateDigest = digest(seed + 2);
  const priorTuple = collaborationRevisionTupleSchema.parse({
    authorityEpoch: 2,
    documentRevision: 8,
    membershipRevision: 4,
    policyRevision: 3,
    keyEpoch: 5,
    databaseDeviceGeneration: 2,
    databaseDeviceRegistryDigest: registryDigest,
    authorizationStateDigest,
  });
  const terminalTuple = collaborationRevisionTupleSchema.parse({
    ...priorTuple,
    documentRevision: priorTuple.documentRevision + 1,
  });
  const operationId = 'operation-destroy-vault';
  const priorHeadDigest = digest(seed + 3);
  const authorityDelegationDigest = digest(seed + 5);
  const actionParametersDigest = options.invalidActionDigest
    ? digest(seed + 6)
    : computeCollaborativeVaultDestructionActionDigest({
        protocolVersion: 1,
        operationType: 'destroy-vault',
        databaseId: scope.databaseId,
        vaultId: scope.vaultId,
        destructionMode: 'irreversible',
      });
  const core = {
    format: 'kavrix-collaborative-vault-destruction-core' as const,
    protocolVersion: 1 as const,
    databaseId: scope.databaseId,
    vaultId: scope.vaultId,
    operationId,
    authorityEpoch: terminalTuple.authorityEpoch,
    authorityDelegationDigest,
    priorTuple,
    priorHeadDigest,
    terminalTuple,
    actionParametersDigest,
    actorPrincipalId: scope.principalId,
    actorDeviceId: scope.deviceId,
    destructionMode: 'irreversible' as const,
    destroyedAt,
  };
  const destroyedPayloadDigest = computeCollaborativeVaultDestroyedPayloadDigest(core);
  const requestDigest = digest(seed + 7);
  const transitionDraft = {
    format: 'kavrix-collaborative-authorization-transition' as const,
    protocolVersion: 1 as const,
    databaseId: scope.databaseId,
    vaultId: scope.vaultId,
    operationId,
    operationType: 'destroy-vault' as const,
    previousHeadDigest: priorHeadDigest,
    previousAuthorizationStateDigest: authorizationStateDigest,
    authorizationStateDigest,
    previousTuple: priorTuple,
    nextTuple: terminalTuple,
    evidence: { kind: 'none' as const },
    issuedAt: createdAt,
    expiresAt: transitionExpiresAt,
    transitionDigest: digest(0),
    transitionSignature: {
      signerKind: 'owner-device' as const,
      signerPrincipalId: scope.principalId,
      signerDeviceId: scope.deviceId,
      signature: signature(seed + 12),
    },
  };
  const authorizationTransition = {
    ...transitionDraft,
    transitionDigest: computeAuthorizationTransitionDigest(transitionDraft),
  };
  const encryptedMembershipDigest = digest(seed + 9);
  const encryptedEnvelopesDigest = digest(seed + 10);
  const policyDigest = digest(seed + 11);
  const commitment = {
    protocolVersion: 1 as const,
    databaseId: scope.databaseId,
    vaultId: scope.vaultId,
    operationId,
    operationType: 'destroy-vault' as const,
    requestDigest,
    previousHeadDigest: priorHeadDigest,
    previousAuthorizationStateDigest: authorizationStateDigest,
    authorizationStateDigest,
    authorizationTransitionDigest: authorizationTransition.transitionDigest,
    previousAuthorityEpoch: priorTuple.authorityEpoch,
    previousDocumentRevision: priorTuple.documentRevision,
    previousMembershipRevision: priorTuple.membershipRevision,
    previousPolicyRevision: priorTuple.policyRevision,
    previousKeyEpoch: priorTuple.keyEpoch,
    previousDatabaseDeviceGeneration: priorTuple.databaseDeviceGeneration,
    previousDatabaseDeviceRegistryDigest: priorTuple.databaseDeviceRegistryDigest,
    authorityEpoch: terminalTuple.authorityEpoch,
    documentRevision: terminalTuple.documentRevision,
    membershipRevision: terminalTuple.membershipRevision,
    policyRevision: terminalTuple.policyRevision,
    keyEpoch: terminalTuple.keyEpoch,
    databaseDeviceGeneration: terminalTuple.databaseDeviceGeneration,
    databaseDeviceRegistryDigest: terminalTuple.databaseDeviceRegistryDigest,
    encryptedPayloadDigest: destroyedPayloadDigest,
    encryptedMembershipDigest,
    encryptedEnvelopesDigest,
    policyDigest,
    writerPrincipalId: scope.principalId,
    writerDeviceId: scope.deviceId,
    timestamp: destroyedAt,
  };
  const terminalHeadDigest = computeMutationHead(commitment);
  const link = {
    format: 'kavrix-collaborative-finalized-mutation-link' as const,
    protocolVersion: 1 as const,
    databaseId: scope.databaseId,
    vaultId: scope.vaultId,
    authorityDelegationDigest,
    commitment,
    authorizationTransition,
    resultingHeadDigest: terminalHeadDigest,
    writerSignature: {
      algorithm: 'ed25519' as const,
      writerPrincipalId: scope.principalId,
      writerDeviceId: scope.deviceId,
      commitmentDigest: terminalHeadDigest,
      signature: signature(seed + 13),
    },
    finalizedAt: destroyedAt,
  };
  const finalizedMutationLinkDigest = computeFinalizedMutationLinkDigest(link);
  const proofEntry = {
    link,
    authorizationWitness: {
      format: 'kavrix-collaborative-authorization-witness' as const,
      protocolVersion: 1 as const,
      databaseId: scope.databaseId,
      vaultId: scope.vaultId,
      authorityDelegationDigest,
      tuple: terminalTuple,
      previousHeadDigest: priorHeadDigest,
      headDigest: terminalHeadDigest,
      encryptedMembershipDigest,
      encryptedEnvelopesDigest,
      policyDigest,
      databaseDeviceRegistry: {
        format: 'kavrix-collaborative-device-registry' as const,
        protocolVersion: 1 as const,
        databaseId: scope.databaseId,
        authorityEpoch: terminalTuple.authorityEpoch,
        authorityFingerprint: digest(seed + 14),
        generation: terminalTuple.databaseDeviceGeneration,
        previousRegistryDigest: digest(seed + 15),
        registryDigest,
        deniedDevices: [],
        updatedAt: destroyedAt,
        authoritySignature: signature(seed + 16),
      },
      databaseAuthorityRecoveryEnvelope: {
        format: 'kavrix-collaborative-authority-recovery-envelope' as const,
        protocolVersion: 1 as const,
        algorithm: 'x25519-sealed-box' as const,
        databaseId: scope.databaseId,
        vaultId: scope.vaultId,
        authorityEpoch: terminalTuple.authorityEpoch,
        authorityRecoveryKeyFingerprint: digest(seed + 17),
        keyEpoch: terminalTuple.keyEpoch,
        membershipRevision: terminalTuple.membershipRevision,
        databaseDeviceGeneration: terminalTuple.databaseDeviceGeneration,
        databaseDeviceRegistryDigest: registryDigest,
        sealedVaultRootKey: bytes(80, seed + 18),
        envelopeDigest: digest(seed + 19),
        sealedByPrincipalId: scope.principalId,
        sealedByDeviceId: scope.deviceId,
        createdAt,
        ownerSignature: signature(seed + 20),
      },
      encryptedMembershipManifest: {
        version: 1 as const,
        algorithm: 'xchacha20-poly1305-ietf' as const,
        nonce: bytes(24, seed + 21),
        ciphertext: bytes(64, seed + 22),
        authenticationTag: bytes(16, seed + 23),
        aad: {
          protocolVersion: 1 as const,
          databaseId: scope.databaseId,
          vaultId: scope.vaultId,
          ...terminalTuple,
          entityType: 'membership-manifest' as const,
          entityId: scope.vaultId,
          metadataDigest: digest(seed + 24),
        },
      },
      discoveryRecords: [],
      finalizedMutationLinkDigest,
    },
  };
  const placeholderOutcomeDigest = digest(0);
  const placeholderReceipt = {
    format: 'kavrix-collaborative-mutation-receipt' as const,
    protocolVersion: 1 as const,
    databaseId: scope.databaseId,
    vaultId: scope.vaultId,
    operationId,
    operationType: 'destroy-vault' as const,
    requestDigest,
    actorPrincipalId: scope.principalId,
    actorDeviceId: scope.deviceId,
    priorTuple,
    priorHeadDigest,
    committedTuple: terminalTuple,
    committedHeadDigest: terminalHeadDigest,
    finalizedMutationLinkDigest,
    outcomeDigest: placeholderOutcomeDigest,
    committedAt: destroyedAt,
    receiptSignature: signature(seed + 25),
  };
  const placeholderOutcome = durableOperationOutcomeSchema.parse({
    format: 'kavrix-collaborative-operation-outcome',
    protocolVersion: 1,
    databaseId: scope.databaseId,
    vaultId: scope.vaultId,
    operationId,
    operationType: 'destroy-vault',
    requestDigest,
    actorPrincipalId: scope.principalId,
    actorDeviceId: scope.deviceId,
    priorTuple,
    priorHeadDigest,
    state: 'committed',
    committedTuple: terminalTuple,
    committedHeadDigest: terminalHeadDigest,
    finalizedMutationLinkDigest,
    committedAt: destroyedAt,
    outcomeDigest: placeholderOutcomeDigest,
    signedMutationReceipt: placeholderReceipt,
    createdAt,
    resolvedAt: destroyedAt,
    detailsRetainedUntil: retainedUntil,
  });
  const outcomeDigest = computeOperationOutcomeDigest(placeholderOutcome);
  const signedMutationReceipt = {
    ...placeholderReceipt,
    outcomeDigest,
  };
  const outcome = durableOperationOutcomeSchema.parse({
    ...placeholderOutcome,
    outcomeDigest,
    signedMutationReceipt,
  });
  const tombstone = collaborationVaultDestructionTombstoneSchema.parse({
    format: 'kavrix-collaborative-vault-destruction-tombstone',
    protocolVersion: 1,
    databaseId: scope.databaseId,
    vaultId: scope.vaultId,
    core,
    destroyedPayloadDigest,
    terminalHeadDigest,
    proofEntry,
    outcomeDigest,
    signedMutationReceipt,
  });
  const anchor = recipientVaultDestructionAnchorSchema.parse({
    format: 'kavrix-collaborative-recipient-vault-destruction-anchor',
    protocolVersion: 1,
    ...scope,
    authorityEpoch: core.authorityEpoch,
    authorityDelegationDigest,
    operationId,
    priorTuple,
    priorHeadDigest,
    terminalTuple,
    terminalHeadDigest,
    destroyedPayloadDigest,
    finalizedMutationLinkDigest,
    outcomeDigest,
    destroyedAt,
  });
  return { tombstone, outcome, anchor };
}

function rejectedOutcome(source: Artifacts): DurableOperationOutcome {
  const placeholder = durableOperationOutcomeSchema.parse({
    format: 'kavrix-collaborative-operation-outcome',
    protocolVersion: 1,
    databaseId: source.outcome.databaseId,
    vaultId: source.outcome.vaultId,
    operationId: source.outcome.operationId,
    operationType: source.outcome.operationType,
    requestDigest: source.outcome.requestDigest,
    actorPrincipalId: source.outcome.actorPrincipalId,
    actorDeviceId: source.outcome.actorDeviceId,
    priorTuple: source.outcome.priorTuple,
    priorHeadDigest: source.outcome.priorHeadDigest,
    state: 'rejected',
    outcomeDigest: digest(0),
    createdAt,
    resolvedAt: destroyedAt,
    detailsRetainedUntil: retainedUntil,
  });
  return durableOperationOutcomeSchema.parse({
    ...placeholder,
    outcomeDigest: computeOperationOutcomeDigest(placeholder),
  });
}

let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-destruction-journal-'));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

function filePath(name = 'destroy.journal'): string {
  return join(directory, name);
}

describe('protected collaborative vault-destruction journals', () => {
  it('derives a scoped path and round-trips exact prepared artifacts without secrets', async () => {
    const secret = new Uint8Array(32).fill(31);
    const prepared = artifacts();
    const path = filePath();
    try {
      expect(
        collaborativeVaultDestructionJournalPath(
          'vault.cvkx',
          scope.databaseId,
          scope.vaultId,
          prepared.tombstone.core.operationId,
        ),
      ).toBe(
        `vault.cvkx${COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_SUFFIX}.database-destroy.vault-destroy.operation-destroy-vault`,
      );
      await createCollaborativeVaultDestructionJournal(path, secret, {
        tombstone: prepared.tombstone,
        proposedOutcome: prepared.outcome,
        recipientAnchor: prepared.anchor,
        createdAt,
      });

      await expect(
        readCollaborativeVaultDestructionJournal(path, secret, {
          expectedScope: scope,
        }),
      ).resolves.toMatchObject({
        state: 'prepared',
        tombstone: prepared.tombstone,
        proposedOutcome: prepared.outcome,
        recipientAnchor: prepared.anchor,
      });
      const serialized = await readFile(path, 'utf8');
      expect(serialized).not.toContain(encodeBase64Url(secret));
      expect(serialized).not.toContain('privateKey');
      expect(serialized).not.toContain('databaseRootKey');
      expect(serialized).not.toContain('vaultRootKey');
      expect(serialized).not.toContain('plaintext-canary');
    } finally {
      zeroize(secret);
    }
  });

  it('commits only exact authoritative tombstone and outcome evidence and verifies replay', async () => {
    const secret = new Uint8Array(32).fill(32);
    const prepared = artifacts();
    const path = filePath();
    try {
      await createCollaborativeVaultDestructionJournal(path, secret, {
        tombstone: prepared.tombstone,
        proposedOutcome: prepared.outcome,
        recipientAnchor: prepared.anchor,
      });
      await reconcileCollaborativeVaultDestructionJournal(path, secret, {
        tombstone: prepared.tombstone,
        outcome: prepared.outcome,
      });
      await expect(
        verifyCommittedCollaborativeVaultDestructionJournal(path, secret, {
          tombstone: prepared.tombstone,
          outcome: prepared.outcome,
        }),
      ).resolves.toMatchObject({ state: 'committed' });

      await createCollaborativeVaultDestructionJournal(path, secret, {
        tombstone: prepared.tombstone,
        proposedOutcome: prepared.outcome,
        recipientAnchor: prepared.anchor,
      });
      await expect(
        readCollaborativeVaultDestructionJournal(path, secret),
      ).resolves.toMatchObject({ state: 'committed' });
    } finally {
      zeroize(secret);
    }
  });

  it('rejects same-operation artifact substitution and preserves the prepared bytes', async () => {
    const secret = new Uint8Array(32).fill(33);
    const prepared = artifacts(1);
    const substituted = artifacts(41);
    const path = filePath();
    try {
      await createCollaborativeVaultDestructionJournal(path, secret, {
        tombstone: prepared.tombstone,
        proposedOutcome: prepared.outcome,
        recipientAnchor: prepared.anchor,
      });
      const before = await readFile(path);
      await expect(
        createCollaborativeVaultDestructionJournal(path, secret, {
          tombstone: substituted.tombstone,
          proposedOutcome: substituted.outcome,
          recipientAnchor: substituted.anchor,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        reconcileCollaborativeVaultDestructionJournal(path, secret, {
          tombstone: substituted.tombstone,
          outcome: substituted.outcome,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      expect(await readFile(path)).toEqual(before);
    } finally {
      zeroize(secret);
    }
  });

  it('rejects missing, partial, unsigned, and noncommitted authoritative evidence', async () => {
    const secret = new Uint8Array(32).fill(34);
    const prepared = artifacts();
    const path = filePath();
    try {
      await createCollaborativeVaultDestructionJournal(path, secret, {
        tombstone: prepared.tombstone,
        proposedOutcome: prepared.outcome,
        recipientAnchor: prepared.anchor,
      });
      for (const evidence of [
        {},
        { tombstone: prepared.tombstone },
        { outcome: prepared.outcome },
        {
          tombstone: prepared.tombstone,
          outcome: rejectedOutcome(prepared),
        },
      ]) {
        await expect(
          reconcileCollaborativeVaultDestructionJournal(
            path,
            secret,
            evidence as never,
          ),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      }
      await expect(
        readCollaborativeVaultDestructionJournal(path, secret),
      ).resolves.toMatchObject({ state: 'prepared' });
    } finally {
      zeroize(secret);
    }
  });

  it('rejects action, anchor, outcome, scope, and caller-field substitution', async () => {
    const secret = new Uint8Array(32).fill(35);
    const prepared = artifacts();
    try {
      const invalidAction = artifacts(1, { invalidActionDigest: true });
      await expect(
        createCollaborativeVaultDestructionJournal(filePath('action'), secret, {
          tombstone: invalidAction.tombstone,
          proposedOutcome: invalidAction.outcome,
          recipientAnchor: invalidAction.anchor,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        createCollaborativeVaultDestructionJournal(filePath('anchor'), secret, {
          tombstone: prepared.tombstone,
          proposedOutcome: prepared.outcome,
          recipientAnchor: recipientVaultDestructionAnchorSchema.parse({
            ...prepared.anchor,
            terminalHeadDigest: digest(99),
          }),
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        createCollaborativeVaultDestructionJournal(filePath('outcome'), secret, {
          tombstone: prepared.tombstone,
          proposedOutcome: artifacts(41).outcome,
          recipientAnchor: prepared.anchor,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        createCollaborativeVaultDestructionJournal(filePath('extra'), secret, {
          tombstone: prepared.tombstone,
          proposedOutcome: prepared.outcome,
          recipientAnchor: prepared.anchor,
          plaintextCanary: 'plaintext-canary',
        } as never),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const path = filePath('scope');
      await createCollaborativeVaultDestructionJournal(path, secret, {
        tombstone: prepared.tombstone,
        proposedOutcome: prepared.outcome,
        recipientAnchor: prepared.anchor,
      });
      await expect(
        readCollaborativeVaultDestructionJournal(path, secret, {
          expectedScope: {
            ...scope,
            vaultId: vaultIdSchema.parse('vault-foreign'),
          },
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
    }
  });

  it('preserves prepared evidence when the protected terminal transition fails', async () => {
    const secret = new Uint8Array(32).fill(39);
    const prepared = artifacts();
    const path = filePath('transition-failure');
    try {
      await createCollaborativeVaultDestructionJournal(path, secret, {
        tombstone: prepared.tombstone,
        proposedOutcome: prepared.outcome,
        recipientAnchor: prepared.anchor,
      });
      const before = await readFile(path);
      transitionFault.failNext = true;
      await expect(
        reconcileCollaborativeVaultDestructionJournal(path, secret, {
          tombstone: prepared.tombstone,
          outcome: prepared.outcome,
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      expect(await readFile(path)).toEqual(before);
      await expect(
        readCollaborativeVaultDestructionJournal(path, secret),
      ).resolves.toMatchObject({ state: 'prepared' });
    } finally {
      transitionFault.failNext = false;
      zeroize(secret);
    }
  });

  it('rejects wrong secrets, tampering, malformed and oversized files', async () => {
    const secret = new Uint8Array(32).fill(36);
    const wrong = new Uint8Array(32).fill(37);
    const prepared = artifacts();
    try {
      const wrongSecretPath = filePath('wrong-secret');
      await createCollaborativeVaultDestructionJournal(wrongSecretPath, secret, {
        tombstone: prepared.tombstone,
        proposedOutcome: prepared.outcome,
        recipientAnchor: prepared.anchor,
      });
      await expect(
        readCollaborativeVaultDestructionJournal(wrongSecretPath, wrong),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const tampered = JSON.parse(await readFile(wrongSecretPath, 'utf8')) as Record<
        string,
        unknown
      >;
      tampered['state'] = 'committed';
      await writeFile(wrongSecretPath, canonicalJson(tampered), { mode: 0o600 });
      await expect(
        readCollaborativeVaultDestructionJournal(wrongSecretPath, secret),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const malformedPath = filePath('malformed');
      await writeFile(malformedPath, '{"format":"invalid"}', { mode: 0o600 });
      await expect(
        readCollaborativeVaultDestructionJournal(malformedPath, secret),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const oversizedPath = filePath('oversized');
      await writeFile(
        oversizedPath,
        Buffer.alloc(MAX_COLLABORATIVE_VAULT_DESTRUCTION_JOURNAL_BYTES + 1),
        { mode: 0o600 },
      );
      await expect(
        readCollaborativeVaultDestructionJournal(oversizedPath, secret),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
      zeroize(wrong);
    }
  });

  it('fails closed on invalid paths and returns null only for an absent journal', async () => {
    const secret = new Uint8Array(32).fill(38);
    try {
      expect(() =>
        collaborativeVaultDestructionJournalPath(
          '',
          scope.databaseId,
          scope.vaultId,
          'operation-destroy-vault',
        ),
      ).toThrow();
      await expect(
        readCollaborativeVaultDestructionJournal(filePath('missing'), secret),
      ).resolves.toBeNull();
      await expect(
        readCollaborativeVaultDestructionJournal('', secret),
      ).rejects.toMatchObject({ code: 'KEY_FILE_INVALID_PATH' });
      await expect(
        readCollaborativeVaultDestructionJournal(filePath(), new Uint8Array(31)),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
    }
  });
});
