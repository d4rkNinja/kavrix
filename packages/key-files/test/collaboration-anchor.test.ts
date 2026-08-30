import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  databaseIdSchema,
  deviceIdSchema,
  principalIdSchema,
  recipientRollbackAnchorSchema,
  sha256DigestSchema,
  vaultIdSchema,
  type RecipientRollbackAnchor,
} from '@kavrix/schemas';
import { encodeBase64Url, zeroize } from '@kavrix/crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(async () => undefined),
  verifyWindowsDirectoryAcl: vi.fn(async () => undefined),
  verifyWindowsUserOnlyAcl: vi.fn(async () => undefined),
}));

import {
  createRecipientRollbackAnchor,
  recipientRollbackAnchorPath,
  readRecipientRollbackAnchor,
  transitionRecipientRollbackAnchor,
  verifyRecipientRollbackAnchor,
  type RecipientRollbackAnchorScope,
} from '../src/index.js';

const digest = (value: number) =>
  sha256DigestSchema.parse(encodeBase64Url(new Uint8Array(32).fill(value)));

const scope: RecipientRollbackAnchorScope = {
  databaseId: databaseIdSchema.parse('database-a'),
  vaultId: vaultIdSchema.parse('vault-a'),
  principalId: principalIdSchema.parse('principal-a'),
  deviceId: deviceIdSchema.parse('device-a'),
};

function anchor(overrides: Record<string, unknown> = {}): RecipientRollbackAnchor {
  return recipientRollbackAnchorSchema.parse({
    format: 'kavrix-collaborative-recipient-rollback-anchor',
    protocolVersion: 1,
    ...scope,
    authorityEpoch: 4,
    authorityDelegationDigest: digest(1),
    databaseDeviceGeneration: 4,
    databaseDeviceRegistryDigest: digest(2),
    membershipRevision: 4,
    membershipDigest: digest(3),
    policyRevision: 4,
    policyDigest: digest(4),
    keyEpoch: 4,
    documentRevision: 4,
    encryptedPayloadDigest: digest(5),
    headDigest: digest(6),
    authorizationStateDigest: digest(7),
    finalizedMutationLinkDigest: digest(8),
    updatedAt: '2026-01-04T00:00:00.000Z',
    ...overrides,
  });
}

let directory = '';
beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-collaboration-anchor-'));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

function filePath(name = 'recipient.anchor'): string {
  return join(directory, name);
}

describe('protected per-device collaboration rollback anchors', () => {
  it('derives deterministic scoped sidecar paths and round-trips an authenticated anchor', async () => {
    const secret = new Uint8Array(32).fill(9);
    try {
      expect(recipientRollbackAnchorPath('vault.cvkx', scope)).toBe(
        'vault.cvkx.recipient-rollback-anchor.database-a.vault-a.principal-a.device-a',
      );
      expect(
        recipientRollbackAnchorPath('vault.cvkx', {
          ...scope,
          deviceId: deviceIdSchema.parse('device-b'),
        }),
      ).toBe(
        'vault.cvkx.recipient-rollback-anchor.database-a.vault-a.principal-a.device-b',
      );

      const file = filePath();
      await createRecipientRollbackAnchor(file, secret, anchor());
      const read = await readRecipientRollbackAnchor(file, secret, {
        expectedScope: scope,
      });
      expect(read).toEqual(anchor());
      const serialized = await readFile(file, 'utf8');
      expect(serialized).not.toContain(encodeBase64Url(secret));
      expect(serialized).not.toContain('privateKey');
      expect(serialized).not.toContain('plaintext');
    } finally {
      zeroize(secret);
    }
  });

  it('rejects a wrong secret, foreign scope, tampered data, and malformed documents', async () => {
    const secret = new Uint8Array(32).fill(10);
    const wrongSecret = new Uint8Array(32).fill(11);
    const file = filePath();
    try {
      await createRecipientRollbackAnchor(file, secret, anchor());
      await expect(
        readRecipientRollbackAnchor(file, wrongSecret),
      ).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      await expect(
        readRecipientRollbackAnchor(file, secret, {
          expectedScope: {
            ...scope,
            databaseId: databaseIdSchema.parse('database-b'),
          },
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const serialized = JSON.parse(await readFile(file, 'utf8')) as Record<
        string,
        unknown
      >;
      serialized.headDigest = digest(12);
      await writeFile(file, JSON.stringify(serialized), { mode: 0o600 });
      await expect(readRecipientRollbackAnchor(file, secret)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });

      await writeFile(file, '{"format":"not-an-anchor"}', { mode: 0o600 });
      await expect(readRecipientRollbackAnchor(file, secret)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    } finally {
      zeroize(secret);
      zeroize(wrongSecret);
    }
  });

  it('rejects rollback of every anchored component and equal-tuple forks', () => {
    const trusted = anchor();
    const rollbackCases: Array<Partial<RecipientRollbackAnchor>> = [
      { authorityEpoch: 3 },
      { databaseDeviceGeneration: 3 },
      { membershipRevision: 3 },
      { policyRevision: 3 },
      { keyEpoch: 3 },
      { documentRevision: 3 },
    ];
    for (const observed of rollbackCases) {
      expect(() => verifyRecipientRollbackAnchor(trusted, anchor(observed))).toThrow();
    }
    expect(() =>
      verifyRecipientRollbackAnchor(
        trusted,
        anchor({ documentRevision: 5, headDigest: trusted.headDigest }),
      ),
    ).toThrow();

    expect(() =>
      verifyRecipientRollbackAnchor(
        trusted,
        anchor({ authorityEpoch: 5, authorityDelegationDigest: digest(19) }),
      ),
    ).toThrow();

    const forkCases: Array<Partial<RecipientRollbackAnchor>> = [
      { authorityDelegationDigest: digest(13) },
      { databaseDeviceRegistryDigest: digest(14) },
      { membershipDigest: digest(15) },
      { policyDigest: digest(16) },
      { encryptedPayloadDigest: digest(17) },
      { headDigest: digest(18) },
      { authorizationStateDigest: digest(19) },
      { finalizedMutationLinkDigest: digest(20) },
    ];
    for (const observed of forkCases) {
      expect(() => verifyRecipientRollbackAnchor(trusted, anchor(observed))).toThrow();
    }

    expect(() =>
      verifyRecipientRollbackAnchor(
        trusted,
        anchor({
          documentRevision: 5,
          headDigest: digest(20),
          finalizedMutationLinkDigest: digest(21),
        }),
      ),
    ).not.toThrow();
  });

  it('requires a caller-verified proof for multi-revision observations', () => {
    const trusted = anchor();
    const observed = anchor({
      documentRevision: 7,
      headDigest: digest(30),
      finalizedMutationLinkDigest: digest(31),
    });

    expect(() => verifyRecipientRollbackAnchor(trusted, observed, scope)).toThrow();
    expect(() =>
      verifyRecipientRollbackAnchor(trusted, observed, scope, {
        kind: 'verified-chain',
        from: trusted,
        to: observed,
      }),
    ).not.toThrow();
    expect(() =>
      verifyRecipientRollbackAnchor(trusted, observed, scope, {
        kind: 'verified-chain',
        from: anchor({ headDigest: digest(32) }),
        to: observed,
      }),
    ).toThrow();
  });

  it('advances atomically and rejects a stale concurrent observation', async () => {
    const secret = new Uint8Array(32).fill(19);
    const file = filePath();
    let release!: () => void;
    let entered!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const callbackEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    try {
      const initial = anchor();
      const next = anchor({
        documentRevision: 5,
        headDigest: digest(20),
        finalizedMutationLinkDigest: digest(21),
      });
      await createRecipientRollbackAnchor(file, secret, initial);
      const first = transitionRecipientRollbackAnchor(
        file,
        secret,
        initial,
        async () => {
          entered();
          await held;
          return { nextAnchor: next, result: 'advanced' as const };
        },
      );
      await callbackEntered;
      await expect(
        transitionRecipientRollbackAnchor(file, secret, initial, async () => ({
          nextAnchor: anchor({
            documentRevision: 6,
            headDigest: digest(21),
            finalizedMutationLinkDigest: digest(22),
          }),
          result: 'stale' as const,
        })),
      ).rejects.toMatchObject({ code: 'KEY_FILE_BUSY' });
      release();
      await expect(first).resolves.toBe('advanced');
      await expect(readRecipientRollbackAnchor(file, secret)).resolves.toEqual(next);
      await expect(
        transitionRecipientRollbackAnchor(file, secret, initial, async () => ({
          nextAnchor: anchor({
            documentRevision: 6,
            headDigest: digest(22),
            finalizedMutationLinkDigest: digest(23),
          }),
          result: 'stale-retry' as const,
        })),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(readRecipientRollbackAnchor(file, secret)).resolves.toEqual(next);
    } finally {
      release?.();
      zeroize(secret);
    }
  });

  it.runIf(process.platform !== 'win32')(
    'rejects a file whose permissions become unsafe',
    async () => {
      const secret = new Uint8Array(32).fill(23);
      const file = filePath();
      try {
        await createRecipientRollbackAnchor(file, secret, anchor());
        await chmod(file, 0o644);
        await expect(readRecipientRollbackAnchor(file, secret)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
      } finally {
        zeroize(secret);
      }
    },
  );
});
