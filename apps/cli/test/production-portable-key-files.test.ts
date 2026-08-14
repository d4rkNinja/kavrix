import {
  formatPortableKey,
  generatePortableKey,
  type ParsedPortableKeyFile,
  type PortableKeyFileBinding,
} from '@kavrix/crypto';
import {
  PortableKeyFileError,
  type PortableKeyFileProtection,
} from '@kavrix/key-files';
import type { readPortableKeyFile } from '@kavrix/key-files';
import { keySlotIdSchema, vaultIdSchema } from '@kavrix/schemas';
import {
  acquiredSecretSchema,
  type AcquiredSecret,
  type SecretInputPort,
} from '../src/secret-input.js';
import { describe, expect, it, vi } from 'vitest';

import { createProductionPortableKeyFileReader } from '../src/production/portable-key-files.js';

const UNBOUND: PortableKeyFileBinding = { kind: 'unbound' };

describe('production portable-key-file reader', () => {
  it('reads an unprotected unbound file without prompting or exposing key bytes', async () => {
    const key = generatePortableKey();
    const formatted = formatPortableKey(key);
    const readFile = vi
      .fn<
        (
          path: string,
          protection: PortableKeyFileProtection,
          expectedBinding?: PortableKeyFileBinding,
        ) => Promise<ParsedPortableKeyFile>
      >()
      .mockResolvedValue({ kind: 'unbound', key, protected: false });
    const readPassphrase = vi.fn();
    const reader = createProductionPortableKeyFileReader(
      { secrets: secretInput(readPassphrase), passphraseFromStdin: false },
      dependencies(readFile),
    );

    await expect(
      reader.readFormattedPortableKey('portable.cvk', UNBOUND, () => {
        readPassphrase();
        return Promise.resolve(acquiredSecretSchema.parse('unexpected'));
      }),
    ).resolves.toBe(formatted);
    expect(readFile).toHaveBeenCalledOnce();
    expect(readFile.mock.calls[0]?.[1]).toEqual({ kind: 'unprotected' });
    expect(readPassphrase).not.toHaveBeenCalled();
    expect(key.every((byte) => byte === 0)).toBe(true);
  });

  it('falls back to protected parsing only after a cryptographic parse failure', async () => {
    const key = generatePortableKey();
    const formatted = formatPortableKey(key);
    const readFile = vi
      .fn<
        (
          path: string,
          protection: PortableKeyFileProtection,
          expectedBinding?: PortableKeyFileBinding,
        ) => Promise<ParsedPortableKeyFile>
      >()
      .mockRejectedValueOnce(new Error('invalid format'))
      .mockResolvedValueOnce({ kind: 'unbound', key, protected: true });
    const readPassphrase = vi
      .fn()
      .mockResolvedValue(acquiredSecretSchema.parse('file-passphrase-canary'));
    const reader = createProductionPortableKeyFileReader(
      { secrets: secretInput(readPassphrase), passphraseFromStdin: false },
      dependencies(readFile),
    );

    await expect(
      reader.readFormattedPortableKey('portable.cvk', UNBOUND),
    ).resolves.toBe(formatted);
    expect(readFile).toHaveBeenCalledTimes(2);
    expect(readFile.mock.calls[1]?.[1]).toMatchObject({ kind: 'passphrase' });
    const passedProtection = readFile.mock.calls[1]?.[1];
    if (passedProtection?.kind !== 'passphrase') throw new Error('Missing passphrase');
    expect(passedProtection.passphrase.every((byte) => byte === 0)).toBe(true);
    expect(readPassphrase).toHaveBeenCalledOnce();
    expect(key.every((byte) => byte === 0)).toBe(true);
  });

  it('rejects a bound file for fresh initialization without prompting', async () => {
    const key = generatePortableKey();
    const readFile = vi
      .fn<
        (
          path: string,
          protection: PortableKeyFileProtection,
          expectedBinding?: PortableKeyFileBinding,
        ) => Promise<ParsedPortableKeyFile>
      >()
      .mockResolvedValue({
        kind: 'bound',
        vaultId: vaultIdSchema.parse('vault.bound'),
        keySlotId: keySlotIdSchema.parse('slot.bound'),
        key,
        protected: false,
      });
    const readPassphrase = vi.fn();
    const reader = createProductionPortableKeyFileReader(
      { secrets: secretInput(readPassphrase), passphraseFromStdin: false },
      dependencies(readFile),
    );

    await expect(
      reader.readFormattedPortableKey('portable.cvk', UNBOUND),
    ).rejects.toThrow();
    expect(readPassphrase).not.toHaveBeenCalled();
    expect(key.every((byte) => byte === 0)).toBe(true);
  });

  it('does not turn filesystem safety failures into passphrase prompts', async () => {
    const readFile = vi
      .fn<typeof readPortableKeyFile>()
      .mockRejectedValue(new PortableKeyFileError('KEY_FILE_UNSAFE'));
    const readPassphrase = vi.fn();
    const reader = createProductionPortableKeyFileReader(
      { secrets: secretInput(readPassphrase), passphraseFromStdin: false },
      dependencies(readFile),
    );

    await expect(
      reader.readFormattedPortableKey('unsafe.cvk', UNBOUND),
    ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    expect(readPassphrase).not.toHaveBeenCalled();
  });
});

function dependencies(readFile: typeof readPortableKeyFile): {
  readPortableKeyFile: typeof readPortableKeyFile;
  formatPortableKey: typeof formatPortableKey;
} {
  return { readPortableKeyFile: readFile, formatPortableKey };
}

function secretInput(readPassphrase: () => Promise<unknown>): SecretInputPort {
  return {
    read: async ({ kind }): Promise<AcquiredSecret> => {
      if (kind !== 'passphrase') throw new Error('Unexpected secret kind');
      return acquiredSecretSchema.parse(await readPassphrase());
    },
    readBatch: () => Promise.reject(new Error('Unexpected framed read')),
  };
}
