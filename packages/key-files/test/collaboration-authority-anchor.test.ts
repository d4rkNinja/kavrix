import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { databaseIdSchema, sha256DigestSchema, vaultIdSchema } from '@kavrix/schemas';
import { encodeBase64Url, zeroize } from '@kavrix/crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(async () => undefined),
  verifyWindowsDirectoryAcl: vi.fn(async () => undefined),
  verifyWindowsUserOnlyAcl: vi.fn(async () => undefined),
}));

import {
  collaborationAuthorityRollbackAnchorPath,
  collaborationAuthorityRollbackAnchorSchema,
  createCollaborationAuthorityRollbackAnchor,
  readCollaborationAuthorityRollbackAnchor,
  transitionCollaborationAuthorityRollbackAnchor,
  verifyCollaborationAuthorityRollbackAnchor,
  type CollaborationAuthorityRollbackAnchor,
  type CollaborationAuthorityRollbackAnchorScope,
} from '../src/index.js';

const digest = (value: number) =>
  sha256DigestSchema.parse(encodeBase64Url(new Uint8Array(32).fill(value)));

const scope: CollaborationAuthorityRollbackAnchorScope = {
  databaseId: databaseIdSchema.parse('database-authority-a'),
  vaultId: vaultIdSchema.parse('vault-authority-a'),
  authorityEpoch: 4,
  authorityDelegationDigest: digest(1),
};

function anchor(
  overrides: Record<string, unknown> = {},
): CollaborationAuthorityRollbackAnchor {
  return collaborationAuthorityRollbackAnchorSchema.parse({
    format: 'kavrix-collaborative-authority-rollback-anchor',
    protocolVersion: 1,
    ...scope,
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
    updatedAt: '2026-08-29T00:04:00.000Z',
    ...overrides,
  });
}

let directory = '';
beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-authority-anchor-'));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

function filePath(name = 'authority.anchor'): string {
  return join(directory, name);
}

describe('DRK-protected collaboration authority rollback anchor', () => {
  it('derives a non-recipient path and round-trips without mutating or persisting the DRK', async () => {
    const databaseRootKey = new Uint8Array(32).fill(9);
    const original = Uint8Array.from(databaseRootKey);
    try {
      expect(collaborationAuthorityRollbackAnchorPath('database.cvkx', scope)).toBe(
        'database.cvkx.authority-rollback-anchor.database-authority-a.vault-authority-a.4',
      );
      const file = filePath();
      await createCollaborationAuthorityRollbackAnchor(file, databaseRootKey, anchor());
      await expect(
        readCollaborationAuthorityRollbackAnchor(file, databaseRootKey, {
          expectedScope: scope,
        }),
      ).resolves.toEqual(anchor());
      expect(databaseRootKey).toEqual(original);
      const serialized = await readFile(file, 'utf8');
      expect(serialized).not.toContain(encodeBase64Url(databaseRootKey));
      expect(serialized).not.toContain('principalId');
      expect(serialized).not.toContain('deviceId');
      expect(serialized).not.toContain('plaintext');
    } finally {
      zeroize(databaseRootKey);
      zeroize(original);
    }
  });

  it('rejects wrong DRK, foreign authority scope, tampering, malformed input, and unsafe paths', async () => {
    const databaseRootKey = new Uint8Array(32).fill(10);
    const wrongRootKey = new Uint8Array(32).fill(11);
    const file = filePath();
    try {
      await createCollaborationAuthorityRollbackAnchor(file, databaseRootKey, anchor());
      await expect(
        readCollaborationAuthorityRollbackAnchor(file, wrongRootKey),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readCollaborationAuthorityRollbackAnchor(file, databaseRootKey, {
          expectedScope: { ...scope, databaseId: databaseIdSchema.parse('other') },
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const serialized = JSON.parse(await readFile(file, 'utf8')) as Record<
        string,
        unknown
      >;
      serialized.membershipDigest = digest(12);
      await writeFile(file, JSON.stringify(serialized), { mode: 0o600 });
      await expect(
        readCollaborationAuthorityRollbackAnchor(file, databaseRootKey),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await writeFile(file, '{"format":"not-an-anchor"}', { mode: 0o600 });
      await expect(
        readCollaborationAuthorityRollbackAnchor(file, databaseRootKey),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      expect(() => collaborationAuthorityRollbackAnchorPath('', scope)).toThrow();
    } finally {
      zeroize(databaseRootKey);
      zeroize(wrongRootKey);
    }
  });

  it('rejects rollback, same-position digest substitution, and unproved gaps', () => {
    const trusted = anchor();
    for (const observed of [
      { databaseDeviceGeneration: 3 },
      { membershipRevision: 3 },
      { policyRevision: 3 },
      { keyEpoch: 3 },
      { documentRevision: 3 },
      { membershipDigest: digest(20) },
      { policyDigest: digest(21) },
      { encryptedPayloadDigest: digest(22) },
      { headDigest: digest(23) },
      { authorizationStateDigest: digest(24) },
      { finalizedMutationLinkDigest: digest(25) },
    ]) {
      expect(() =>
        verifyCollaborationAuthorityRollbackAnchor(trusted, anchor(observed)),
      ).toThrow();
    }
    const distant = anchor({
      documentRevision: 7,
      headDigest: digest(30),
      finalizedMutationLinkDigest: digest(31),
    });
    expect(() =>
      verifyCollaborationAuthorityRollbackAnchor(trusted, distant, scope),
    ).toThrow();
    expect(() =>
      verifyCollaborationAuthorityRollbackAnchor(trusted, distant, scope, {
        kind: 'verified-chain',
        from: trusted,
        to: distant,
      }),
    ).not.toThrow();
  });

  it('advances under one exclusive lock and rejects concurrent or stale transitions', async () => {
    const databaseRootKey = new Uint8Array(32).fill(19);
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
        headDigest: digest(32),
        finalizedMutationLinkDigest: digest(33),
      });
      await createCollaborationAuthorityRollbackAnchor(file, databaseRootKey, initial);
      const first = transitionCollaborationAuthorityRollbackAnchor(
        file,
        databaseRootKey,
        initial,
        async () => {
          entered();
          await held;
          return { nextAnchor: next, result: 'advanced' as const };
        },
      );
      await callbackEntered;
      await expect(
        transitionCollaborationAuthorityRollbackAnchor(
          file,
          databaseRootKey,
          initial,
          async () => ({ nextAnchor: next, result: undefined }),
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_BUSY' });
      release();
      await expect(first).resolves.toBe('advanced');
      await expect(
        transitionCollaborationAuthorityRollbackAnchor(
          file,
          databaseRootKey,
          initial,
          async () => ({ nextAnchor: next, result: undefined }),
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readCollaborationAuthorityRollbackAnchor(file, databaseRootKey),
      ).resolves.toEqual(next);
    } finally {
      release?.();
      zeroize(databaseRootKey);
    }
  });

  it.runIf(process.platform !== 'win32')(
    'rejects an authority anchor whose permissions become unsafe',
    async () => {
      const databaseRootKey = new Uint8Array(32).fill(23);
      const file = filePath();
      try {
        await createCollaborationAuthorityRollbackAnchor(
          file,
          databaseRootKey,
          anchor(),
        );
        await chmod(file, 0o644);
        await expect(
          readCollaborationAuthorityRollbackAnchor(file, databaseRootKey),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      } finally {
        zeroize(databaseRootKey);
      }
    },
  );
});
