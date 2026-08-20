import { readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { generateRecoveryKey, zeroize } from '@kavrix/crypto';
import { keySlotIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockedAcl = vi.hoisted(() => ({
  directoryVerify: vi.fn(),
  set: vi.fn(),
  verify: vi.fn(),
}));

vi.mock('../src/windows-acl.js', () => ({
  setWindowsUserOnlyAcl: mockedAcl.set,
  verifyWindowsDirectoryAcl: mockedAcl.directoryVerify,
  verifyWindowsUserOnlyAcl: mockedAcl.verify,
}));

import { PortableKeyFileError } from '../src/errors.js';
import {
  readRecoveryKitFile,
  writeRecoveryKitFile,
  type RecoveryKitBinding,
} from '../src/recovery-kit-files.js';

let directory = '';

const binding: RecoveryKitBinding = {
  vaultId: vaultIdSchema.parse('team'),
  recoverySlotId: keySlotIdSchema.parse('recovery.slot.test'),
};

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-recovery-kit-'));
  mockedAcl.directoryVerify.mockReset();
  mockedAcl.set.mockReset();
  mockedAcl.verify.mockReset();
});

afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

describe('protected recovery-kit files', () => {
  it('round-trips the recovery key without persisting plaintext key material', async () => {
    const path = join(directory, 'recovery.cvkx');
    const recoveryKey = generateRecoveryKey();
    const expectedKey = Uint8Array.from(recoveryKey);
    const passphrase = new TextEncoder().encode('correct horse battery staple');
    try {
      await writeRecoveryKitFile(path, recoveryKey, passphrase, binding);
      const serialized = await readFile(path, 'utf8');
      expect(serialized).not.toContain(Buffer.from(expectedKey).toString('base64url'));
      expect(serialized).not.toContain('correct horse battery staple');

      const parsed = await readRecoveryKitFile(path, passphrase, binding);
      try {
        expect(parsed.vaultId).toBe(binding.vaultId);
        expect(parsed.recoverySlotId).toBe(binding.recoverySlotId);
        expect(Buffer.from(parsed.recoveryKey)).toEqual(Buffer.from(expectedKey));
      } finally {
        zeroize(parsed.recoveryKey);
      }
    } finally {
      zeroize(recoveryKey);
      zeroize(expectedKey);
      zeroize(passphrase);
    }
  });

  it('maps wrong passphrases and binding swaps to the same safe failure', async () => {
    const path = join(directory, 'recovery.cvkx');
    const recoveryKey = generateRecoveryKey();
    const passphrase = new TextEncoder().encode('correct horse battery staple');
    const wrongPassphrase = new TextEncoder().encode('wrong passphrase');
    try {
      await writeRecoveryKitFile(path, recoveryKey, passphrase, binding);
      const wrongVault = {
        ...binding,
        vaultId: vaultIdSchema.parse('other-vault'),
      };
      await expect(readRecoveryKitFile(path, wrongPassphrase)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
        message: 'The portable key file is not safe to use.',
      } satisfies Partial<PortableKeyFileError>);
      await expect(
        readRecoveryKitFile(path, passphrase, wrongVault),
      ).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
        message: 'The portable key file is not safe to use.',
      } satisfies Partial<PortableKeyFileError>);
    } finally {
      zeroize(recoveryKey);
      zeroize(passphrase);
      zeroize(wrongPassphrase);
    }
  });

  it.each(['ciphertext', 'unexpected'])(
    'rejects a tampered recovery envelope (%s)',
    async (field) => {
      const path = join(directory, 'recovery.cvkx');
      const recoveryKey = generateRecoveryKey();
      const passphrase = new TextEncoder().encode('correct horse battery staple');
      try {
        await writeRecoveryKitFile(path, recoveryKey, passphrase, binding);
        const envelope = JSON.parse(await readFile(path, 'utf8')) as Record<
          string,
          unknown
        >;
        if (field === 'ciphertext') {
          const ciphertext = String(envelope['ciphertext']);
          envelope['ciphertext'] =
            `${ciphertext.startsWith('A') ? 'B' : 'A'}${ciphertext.slice(1)}`;
        } else {
          envelope['unexpected'] = 'must be rejected';
        }
        await writeFile(path, `${JSON.stringify(envelope)}\n`, 'utf8');
        await expect(
          readRecoveryKitFile(path, passphrase, binding),
        ).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
      } finally {
        zeroize(recoveryKey);
        zeroize(passphrase);
      }
    },
  );

  it('does not create a file for an empty passphrase', async () => {
    const path = join(directory, 'recovery.cvkx');
    const recoveryKey = generateRecoveryKey();
    try {
      await expect(
        writeRecoveryKitFile(path, recoveryKey, new Uint8Array(), binding),
      ).rejects.toThrow();
      await expect(readFile(path)).rejects.toMatchObject({ code: 'ENOENT' });
    } finally {
      zeroize(recoveryKey);
    }
  });
});
