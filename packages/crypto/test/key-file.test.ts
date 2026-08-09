import { describe, expect, it } from 'vitest';

import { keySlotIdSchema, vaultIdSchema } from '@kavrix/schemas';

import {
  AuthenticationError,
  CryptoInputError,
  formatPortableKey,
  generatePortableKey,
  parsePortableKeyFile,
  parseProtectedPortableKeyFile,
  serializePortableKeyFile,
  serializeProtectedPortableKeyFile,
  type PortableKeyFileBinding,
} from '../src/index.js';
import { otherSlotId, otherVaultId, slotId, vaultId } from './helpers.js';

const binding = { kind: 'bound', vaultId, keySlotId: slotId } as const;
const goldenKey = Uint8Array.from({ length: 32 }, (_, index) => index);
const goldenCopyKey = 'cvk1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh-3RZV1Hw';

describe('portable key files', () => {
  it.each([
    {
      name: 'bound',
      binding,
      golden: [
        '-----BEGIN CREDVAULT PORTABLE KEY-----',
        'Version: 1',
        'Binding: bound',
        'Vault-ID: vault-1',
        'Key-ID: slot-1',
        `Key: ${goldenCopyKey}`,
        '-----END CREDVAULT PORTABLE KEY-----',
        '',
      ].join('\n'),
    },
    {
      name: 'unbound',
      binding: { kind: 'unbound' } as const,
      golden: [
        '-----BEGIN CREDVAULT PORTABLE KEY-----',
        'Version: 1',
        'Binding: unbound',
        'Vault-ID: -',
        'Key-ID: -',
        `Key: ${goldenCopyKey}`,
        '-----END CREDVAULT PORTABLE KEY-----',
        '',
      ].join('\n'),
    },
  ] satisfies readonly {
    readonly name: string;
    readonly binding: PortableKeyFileBinding;
    readonly golden: string;
  }[])('freezes the canonical v1 $name codec', ({ binding: fileBinding, golden }) => {
    const file = serializePortableKeyFile(goldenKey, fileBinding);
    expect(Buffer.from(file).toString('ascii')).toBe(golden);
    expect(
      parsePortableKeyFile(Buffer.from(golden, 'ascii'), fileBinding),
    ).toMatchObject({
      key: goldenKey,
      protected: false,
      ...fileBinding,
    });
  });

  it.each([
    'missing final newline',
    'crlf',
    'duplicate header',
    'extra document',
    'wrong binding',
  ] as const)('rejects %s and never normalizes it', (kind) => {
    const file = serializePortableKeyFile(generatePortableKey(), binding);
    const canonical = Buffer.from(file).toString('ascii');
    let malformed = canonical;
    let expected = binding;
    if (kind === 'missing final newline') {
      malformed = canonical.slice(0, -1);
    } else if (kind === 'crlf') {
      malformed = canonical.replaceAll('\n', '\r\n');
    } else if (kind === 'duplicate header') {
      malformed = canonical.replace('Version: 1\n', 'Version: 1\nVersion: 1\n');
    } else if (kind === 'extra document') {
      malformed += canonical;
    } else {
      expected = {
        kind: 'bound',
        vaultId: otherVaultId,
        keySlotId: otherSlotId,
      };
    }
    expect(() =>
      parsePortableKeyFile(Buffer.from(malformed, 'ascii'), expected),
    ).toThrow(CryptoInputError);
  });

  it('encrypts raw key bytes with Argon2id and authenticated file metadata', async () => {
    const key = generatePortableKey();
    const copyForm = formatPortableKey(key);
    const passphrase = new TextEncoder().encode('protected file passphrase');
    const file = await serializeProtectedPortableKeyFile(key, passphrase, binding);
    const serialized = Buffer.from(file).toString('ascii');
    expect(serialized).toContain('Protection: argon2id+xchacha20-poly1305-ietf');
    expect(serialized).toContain('KDF-Memory-KiB: 65536');
    expect(serialized).not.toContain(copyForm);

    await expect(
      parseProtectedPortableKeyFile(file, passphrase, binding),
    ).resolves.toMatchObject({ key, protected: true, ...binding });
    await expect(
      parseProtectedPortableKeyFile(
        file,
        new TextEncoder().encode('wrong passphrase'),
        binding,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);

    const moved = Buffer.from(
      serialized.replace('Vault-ID: vault-1', 'Vault-ID: vault-2'),
    );
    await expect(
      parseProtectedPortableKeyFile(moved, passphrase),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('rejects hostile persisted Argon2 parameters before allocating them', async () => {
    const passphrase = new TextEncoder().encode('bounded file passphrase');
    const file = await serializeProtectedPortableKeyFile(
      generatePortableKey(),
      passphrase,
      binding,
    );
    const hostile = Buffer.from(file)
      .toString('ascii')
      .replace('KDF-Memory-KiB: 65536', 'KDF-Memory-KiB: 1048576')
      .replace('KDF-Passes: 3', 'KDF-Passes: 64')
      .replace('KDF-Parallelism: 4', 'KDF-Parallelism: 32');
    await expect(
      parseProtectedPortableKeyFile(Buffer.from(hostile, 'ascii'), passphrase, binding),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('distinguishes unbound files from bound identifiers named unbound', () => {
    const key = generatePortableKey();
    const unbound = { kind: 'unbound' } as const;
    const collision = {
      kind: 'bound',
      vaultId: vaultIdSchema.parse('unbound'),
      keySlotId: keySlotIdSchema.parse('unbound'),
    } as const;
    const unboundFile = serializePortableKeyFile(key, unbound);
    const boundFile = serializePortableKeyFile(key, collision);
    expect(parsePortableKeyFile(unboundFile, unbound)).toMatchObject(unbound);
    expect(parsePortableKeyFile(boundFile, collision)).toMatchObject(collision);
    expect(() => parsePortableKeyFile(boundFile, unbound)).toThrow(CryptoInputError);
  });
});
