import { describe, expect, it } from 'vitest';
import { collaborationMutationCommitmentSchema } from '../src/collaboration.js';
const bytes = (value: number, length = 32): string =>
  Buffer.alloc(length, value).toString('base64url');
const baseCommitment = (): ReturnType<
  typeof collaborationMutationCommitmentSchema.parse
> =>
  collaborationMutationCommitmentSchema.parse({
    protocolVersion: 1,
    databaseId: 'database-a',
    vaultId: 'vault-a',
    operationId: 'operation-a',
    operationType: 'ordinary-write',
    requestDigest: bytes(1),
    previousHeadDigest: bytes(2),
    previousAuthorizationStateDigest: bytes(24),
    authorizationStateDigest: bytes(24),
    previousAuthorityEpoch: 1,
    previousDocumentRevision: 0,
    previousMembershipRevision: 0,
    previousPolicyRevision: 0,
    previousKeyEpoch: 1,
    previousDatabaseDeviceGeneration: 1,
    previousDatabaseDeviceRegistryDigest: bytes(3),
    authorityEpoch: 1,
    documentRevision: 1,
    membershipRevision: 0,
    policyRevision: 0,
    keyEpoch: 1,
    databaseDeviceGeneration: 1,
    databaseDeviceRegistryDigest: bytes(3),
    encryptedPayloadDigest: bytes(4),
    encryptedMembershipDigest: bytes(5),
    encryptedEnvelopesDigest: bytes(6),
    policyDigest: bytes(7),
    writerPrincipalId: 'principal-a',
    writerDeviceId: 'device-a',
    timestamp: '2026-08-29T00:00:00.000Z',
  });

describe('authenticated mutation boundaries', () => {
  it.each([
    ['authority epoch', { previousAuthorityEpoch: 2 }],
    ['document revision', { previousDocumentRevision: 2 }],
    ['membership revision', { previousMembershipRevision: 1 }],
    ['policy revision', { previousPolicyRevision: 1 }],
    ['key epoch', { previousKeyEpoch: 2 }],
    ['device generation', { previousDatabaseDeviceGeneration: 2 }],
  ] as const)('rejects a rollback of the committed %s', (_label, patch) => {
    const result = collaborationMutationCommitmentSchema.safeParse({
      ...baseCommitment(),
      ...patch,
    });
    expect(result.success).toBe(false);
    if (result.success) throw new Error('A rollback commitment was accepted');
    expect(
      result.error.issues.some(
        ({ message }) => message === 'Mutation revisions cannot move backwards',
      ),
    ).toBe(true);
  });

  it.each([
    [
      { expiresAt: '2026-08-28T00:00:00.000Z' },
      'Mutation expiry must follow its timestamp',
    ],
    [
      { expiresAt: '2027-08-29T00:00:00.000Z' },
      'Mutation expiry exceeds its maximum lifetime',
    ],
    [
      { databaseDeviceRegistryDigest: bytes(9) },
      'An unchanged database device generation must retain its registry digest',
    ],
    [
      { authorizationTransitionDigest: bytes(9) },
      'Ordinary writes cannot carry an authorization-transition digest',
    ],
    [
      { authorizationStateDigest: bytes(9) },
      'Ordinary writes cannot change the authorization-state digest',
    ],
    [
      { operationType: 'add-member' },
      'Administrative and genesis mutations require an authorization transition',
    ],
    [
      {
        operationType: 'destroy-vault',
        authorizationTransitionDigest: bytes(9),
        authorizationStateDigest: bytes(10),
      },
      'Vault destruction must retain the authorization-state digest',
    ],
    [
      { operationType: 'add-member', authorizationTransitionDigest: bytes(9) },
      'Administrative and genesis mutations must change authorization state',
    ],
  ] as const)('rejects an invalid mutation binding: %s', (patch, message) => {
    const result = collaborationMutationCommitmentSchema.safeParse({
      ...baseCommitment(),
      ...patch,
    });
    expect(result.success).toBe(false);
    if (result.success) throw new Error('An invalid commitment was accepted');
    expect(result.error.issues.some((issue) => issue.message === message)).toBe(true);
  });

  it('accepts bounded mutation expiry without weakening its revision binding', () => {
    expect(
      collaborationMutationCommitmentSchema.safeParse({
        ...baseCommitment(),
        expiresAt: '2026-08-29T00:01:00.000Z',
      }).success,
    ).toBe(true);
  });
});
