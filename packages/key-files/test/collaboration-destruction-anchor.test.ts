import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  COLLABORATIVE_RECIPIENT_VAULT_DESTRUCTION_ANCHOR_FORMAT,
  databaseIdSchema,
  deviceIdSchema,
  principalIdSchema,
  recipientVaultDestructionAnchorSchema,
  sha256DigestSchema,
  vaultIdSchema,
  type RecipientVaultDestructionAnchor,
} from '@kavrix/schemas';
import { encodeBase64Url, zeroize } from '@kavrix/crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: vi.fn(async () => undefined),
  verifyWindowsDirectoryAcl: vi.fn(async () => undefined),
  verifyWindowsUserOnlyAcl: vi.fn(async () => undefined),
}));

import {
  RECIPIENT_VAULT_DESTRUCTION_ANCHOR_SUFFIX,
  createOrVerifyRecipientVaultDestructionAnchor,
  createRecipientVaultDestructionAnchor,
  readRecipientVaultDestructionAnchor,
  recipientVaultDestructionAnchorPath,
  type RecipientVaultDestructionAnchorScope,
} from '../src/collaboration-destruction-anchor.js';

const digest = (value: number) =>
  sha256DigestSchema.parse(encodeBase64Url(new Uint8Array(32).fill(value)));

const scope: RecipientVaultDestructionAnchorScope = {
  databaseId: databaseIdSchema.parse('database-destroyed'),
  vaultId: vaultIdSchema.parse('vault-destroyed'),
  principalId: principalIdSchema.parse('principal-recipient'),
  deviceId: deviceIdSchema.parse('device-recipient'),
};

function anchor(
  overrides: Record<string, unknown> = {},
): RecipientVaultDestructionAnchor {
  return recipientVaultDestructionAnchorSchema.parse({
    format: COLLABORATIVE_RECIPIENT_VAULT_DESTRUCTION_ANCHOR_FORMAT,
    protocolVersion: 1,
    ...scope,
    authorityEpoch: 2,
    authorityDelegationDigest: digest(1),
    operationId: 'operation-destroy-vault',
    priorTuple: {
      authorityEpoch: 2,
      documentRevision: 8,
      membershipRevision: 4,
      policyRevision: 3,
      keyEpoch: 5,
      databaseDeviceGeneration: 2,
      databaseDeviceRegistryDigest: digest(2),
      authorizationStateDigest: digest(3),
    },
    priorHeadDigest: digest(4),
    terminalTuple: {
      authorityEpoch: 2,
      documentRevision: 9,
      membershipRevision: 4,
      policyRevision: 3,
      keyEpoch: 5,
      databaseDeviceGeneration: 2,
      databaseDeviceRegistryDigest: digest(2),
      authorizationStateDigest: digest(3),
    },
    terminalHeadDigest: digest(5),
    destroyedPayloadDigest: digest(6),
    finalizedMutationLinkDigest: digest(7),
    outcomeDigest: digest(8),
    destroyedAt: '2026-08-30T00:00:00.000Z',
    ...overrides,
  });
}

let directory = '';

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-destruction-anchor-'));
});

afterEach(async () => {
  await rm(directory, { recursive: true, force: true });
});

function filePath(name = 'destroyed.anchor'): string {
  return join(directory, name);
}

describe('protected recipient vault-destruction anchors', () => {
  it('derives a scoped path and round-trips canonical authenticated evidence', async () => {
    const secret = new Uint8Array(32).fill(9);
    try {
      expect(recipientVaultDestructionAnchorPath('vault.cvkx', scope)).toBe(
        `vault.cvkx${RECIPIENT_VAULT_DESTRUCTION_ANCHOR_SUFFIX}.database-destroyed.vault-destroyed.principal-recipient.device-recipient`,
      );
      const file = filePath();
      await createRecipientVaultDestructionAnchor(file, secret, anchor());
      await expect(
        readRecipientVaultDestructionAnchor(file, secret, scope),
      ).resolves.toEqual(anchor());

      const serialized = await readFile(file, 'utf8');
      expect(serialized).not.toContain(encodeBase64Url(secret));
      expect(serialized).not.toContain('privateKey');
      expect(serialized).not.toContain('plaintext');
    } finally {
      zeroize(secret);
    }
  });

  it('rejects a wrong secret, foreign scope, tampering, and malformed bytes', async () => {
    const secret = new Uint8Array(32).fill(10);
    const wrong = new Uint8Array(32).fill(11);
    const file = filePath();
    try {
      await createRecipientVaultDestructionAnchor(file, secret, anchor());
      await expect(
        readRecipientVaultDestructionAnchor(file, wrong),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readRecipientVaultDestructionAnchor(file, secret, {
          ...scope,
          vaultId: vaultIdSchema.parse('vault-foreign'),
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      const parsed = JSON.parse(await readFile(file, 'utf8')) as Record<
        string,
        unknown
      >;
      parsed.terminalHeadDigest = digest(12);
      await writeFile(file, JSON.stringify(parsed), { mode: 0o600 });
      await expect(
        readRecipientVaultDestructionAnchor(file, secret),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      await writeFile(file, '{"format":"not-an-anchor"}', { mode: 0o600 });
      await expect(
        readRecipientVaultDestructionAnchor(file, secret),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(secret);
      zeroize(wrong);
    }
  });

  it('accepts exact create-only replay and never overwrites foreign evidence', async () => {
    const secret = new Uint8Array(32).fill(13);
    const file = filePath();
    try {
      const terminal = anchor();
      await createOrVerifyRecipientVaultDestructionAnchor(file, secret, terminal);
      await createOrVerifyRecipientVaultDestructionAnchor(file, secret, terminal);
      const before = await readFile(file);

      await expect(
        createOrVerifyRecipientVaultDestructionAnchor(
          file,
          secret,
          anchor({ terminalHeadDigest: digest(14) }),
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      expect(await readFile(file)).toEqual(before);
      await expect(
        readRecipientVaultDestructionAnchor(file, secret, scope),
      ).resolves.toEqual(terminal);
    } finally {
      zeroize(secret);
    }
  });

  it('rejects invalid paths, secrets, and non-terminal tuple substitutions', async () => {
    const shortSecret = new Uint8Array(31);
    try {
      expect(() => recipientVaultDestructionAnchorPath('', scope)).toThrow();
      await expect(
        createRecipientVaultDestructionAnchor(filePath(), shortSecret, anchor()),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      expect(() =>
        anchor({
          terminalTuple: {
            ...anchor().terminalTuple,
            membershipRevision: anchor().terminalTuple.membershipRevision + 1,
          },
        }),
      ).toThrow();
    } finally {
      zeroize(shortSecret);
    }
  });
});
