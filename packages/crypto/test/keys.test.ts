import { describe, expect, it } from 'vitest';

import {
  ARGON2ID_MINIMUM_MEMORY_KIB,
  ARGON2ID_MINIMUM_PASSES,
  ARGON2ID_MINIMUM_PARALLELISM,
  CryptoInputError,
  createDeviceKeyDerivation,
  createPassphraseDerivation,
  createPortableKeyDerivation,
  deriveDeviceKek,
  derivePassphraseKek,
  derivePortableKek,
  formatPortableKey,
  formatRecoveryKey,
  generateDeviceKey,
  generatePortableKey,
  generateRecoveryKey,
  parsePortableKey,
  parseRecoveryKey,
  zeroize,
} from '../src/index.js';

describe('copy-form keys and KDFs', () => {
  it('uses deterministic canonical portable and recovery formats', () => {
    const bytes = Uint8Array.from({ length: 32 }, (_, index) => index);
    const portable = formatPortableKey(bytes);
    const recovery = formatRecoveryKey(bytes);

    expect(portable).toBe('cvk1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh-3RZV1Hw');
    expect(recovery).toBe('cvr1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh_wx6wUAQ');
    expect(parsePortableKey(portable)).toEqual(bytes);
    expect(parseRecoveryKey(recovery)).toEqual(bytes);
  });

  it.each([
    '',
    'CVK1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh-3RZV1Hw',
    'cvk1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh-3RZV1Hw=',
    ' cvk1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh-3RZV1Hw',
    'cvk1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh-3RZV1HA',
  ])('rejects malformed portable key %j', (value) => {
    expect(() => parsePortableKey(value)).toThrow('Invalid key format');
  });

  it('generates independent portable and recovery keys', () => {
    const portable = generatePortableKey();
    const recovery = generateRecoveryKey();
    expect(portable).toHaveLength(32);
    expect(recovery).toHaveLength(32);
    expect(portable).not.toEqual(recovery);
  });

  it('derives a stable domain-separated portable KEK', () => {
    const key = Uint8Array.from({ length: 32 }, (_, index) => index);
    const derivation = createPortableKeyDerivation(new Uint8Array(32).fill(7));
    const kek = derivePortableKek(key, derivation);
    expect(Buffer.from(kek).toString('hex')).toBe(
      'b2e26bdba6d77415dd451e53f80ce21785b17502ed59671dae4b6d7604e8dc8b',
    );
  });

  it('serializes and honors the Argon2id floor deterministically', async () => {
    const derivation = createPassphraseDerivation({
      salt: Uint8Array.from({ length: 16 }, (_, index) => index),
    });
    expect(derivation).toMatchObject({
      memoryKiB: ARGON2ID_MINIMUM_MEMORY_KIB,
      passes: ARGON2ID_MINIMUM_PASSES,
      parallelism: ARGON2ID_MINIMUM_PARALLELISM,
      outputLength: 32,
    });
    const passphrase = Buffer.from('correct horse battery staple', 'utf8');
    const kek = await derivePassphraseKek(passphrase, derivation);
    expect(Buffer.from(kek).toString('hex')).toBe(
      '853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e',
    );
    zeroize(kek);
  });

  it('rejects schema-valid hostile Argon2 resources before allocation', async () => {
    const derivation = createPassphraseDerivation({
      salt: new Uint8Array(16).fill(3),
    });
    const hostile = {
      ...derivation,
      memoryKiB: 1_048_576,
      passes: 64,
      parallelism: 32,
    } as typeof derivation;
    await expect(
      derivePassphraseKek(Buffer.from('hostile parameters'), hostile),
    ).rejects.toBeInstanceOf(CryptoInputError);
  });

  it('uses canonical device HKDF metadata', () => {
    const deviceKey = generateDeviceKey();
    const derivation = createDeviceKeyDerivation(
      'windows-credential-manager',
      new Uint8Array(32).fill(9),
    );
    const first = deriveDeviceKek(deviceKey, derivation);
    const second = deriveDeviceKek(deviceKey, derivation);
    expect(first).toEqual(second);
    expect(derivation.context).toBe('credvault/v1/device-key-wrap');
    expect(derivation.salt).not.toContain('=');
  });
});
