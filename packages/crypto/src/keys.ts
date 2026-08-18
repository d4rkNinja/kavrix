import { createHash, hkdfSync, randomFillSync } from 'node:crypto';

import {
  passphraseDerivationSchema,
  portableKeyDerivationSchema,
  recoveryKeyDerivationSchema,
  deviceKeyDerivationSchema,
  type KeySlot,
} from '@kavrix/schemas';

import {
  constantTimeEqual,
  copyBytes,
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from './bytes.js';
import { deriveArgon2id } from './argon2id.js';
import { CryptoInputError } from './errors.js';

const KEY_BYTES = 32;
const CHECKSUM_BYTES = 5;
const ENCODED_KEY_BYTES = KEY_BYTES + CHECKSUM_BYTES;
const PORTABLE_PREFIX = 'cvk1_';
const RECOVERY_PREFIX = 'cvr1_';
const PORTABLE_CHECKSUM_DOMAIN = Buffer.from(
  'credvault/portable-key-checksum/v1\0',
  'ascii',
);
const RECOVERY_CHECKSUM_DOMAIN = Buffer.from(
  'credvault/recovery-key-checksum/v1\0',
  'ascii',
);
const PORTABLE_HKDF_INFO = 'credvault/v1/portable-key-wrap';
const RECOVERY_HKDF_INFO = 'credvault/v1/recovery-key-wrap';
const DEVICE_HKDF_INFO = 'credvault/v1/device-key-wrap';

type PortableKeyDerivation = Extract<
  KeySlot,
  { readonly type: 'portable-key' }
>['derivation'];
type RecoveryKeyDerivation = Extract<
  KeySlot,
  { readonly type: 'recovery-key' }
>['derivation'];
type PassphraseDerivation = Extract<
  KeySlot,
  { readonly type: 'passphrase' }
>['derivation'];
type DeviceKeyDerivation = Extract<
  KeySlot,
  { readonly type: 'device-key' }
>['derivation'];

export const ARGON2ID_MINIMUM_MEMORY_KIB = 65_536;
export const ARGON2ID_MINIMUM_PASSES = 3;
export const ARGON2ID_MINIMUM_PARALLELISM = 4;
export const MIN_PASSPHRASE_BYTES = 16;
// These local resource ceilings are deliberately stricter than the persistence
// schema. Untrusted key files are rejected before Node allocates Argon2 memory.
export const ARGON2ID_MAXIMUM_MEMORY_KIB = 262_144;
export const ARGON2ID_MAXIMUM_PASSES = 10;
export const ARGON2ID_MAXIMUM_PARALLELISM = 16;

declare const secretKeyBrand: unique symbol;
export type SecretKey<Kind extends string> = Uint8Array & {
  readonly [secretKeyBrand]: Kind;
};
export type PortableKey = SecretKey<'portable'>;
export type RecoveryKey = SecretKey<'recovery'>;
export type DeviceKey = SecretKey<'device'>;
export type VaultRootKey = SecretKey<'vault-root'>;
export type GroupKey = SecretKey<'group'>;
export type ItemKey = SecretKey<'item'>;
export type AttachmentKey = SecretKey<'attachment'>;
export type KeyEncryptionKey = SecretKey<'key-encryption'>;

export function generatePortableKey(): PortableKey {
  return randomSecret<'portable'>();
}

export function generateRecoveryKey(): RecoveryKey {
  return randomSecret<'recovery'>();
}

export function generateDeviceKey(): DeviceKey {
  return randomSecret<'device'>();
}

export function generateVaultRootKey(): VaultRootKey {
  return randomSecret<'vault-root'>();
}

export function generateGroupKey(): GroupKey {
  return randomSecret<'group'>();
}

export function generateItemKey(): ItemKey {
  return randomSecret<'item'>();
}

export function generateAttachmentKey(): AttachmentKey {
  return randomSecret<'attachment'>();
}

export function formatPortableKey(key: Uint8Array): string {
  return formatCopyKey(key, PORTABLE_PREFIX, PORTABLE_CHECKSUM_DOMAIN);
}

export function parsePortableKey(value: string): PortableKey {
  return parseCopyKey<'portable'>(value, PORTABLE_PREFIX, PORTABLE_CHECKSUM_DOMAIN);
}

export function formatRecoveryKey(key: Uint8Array): string {
  return formatCopyKey(key, RECOVERY_PREFIX, RECOVERY_CHECKSUM_DOMAIN);
}

export function parseRecoveryKey(value: string): RecoveryKey {
  return parseCopyKey<'recovery'>(value, RECOVERY_PREFIX, RECOVERY_CHECKSUM_DOMAIN);
}

export function generateKdfSalt(byteLength = KEY_BYTES): Uint8Array {
  if (byteLength !== 16 && byteLength !== KEY_BYTES) {
    throw new CryptoInputError('Unsupported KDF salt length');
  }
  return randomFillSync(new Uint8Array(byteLength));
}

export function createPortableKeyDerivation(
  salt = generateKdfSalt(),
): PortableKeyDerivation {
  requireByteLength(salt, KEY_BYTES, 'HKDF salt');
  return portableKeyDerivationSchema.parse({
    algorithm: 'hkdf-sha256',
    version: 1,
    salt: encodeBase64Url(salt),
    context: PORTABLE_HKDF_INFO,
    outputLength: KEY_BYTES,
  });
}

export function createRecoveryKeyDerivation(
  salt = generateKdfSalt(),
): RecoveryKeyDerivation {
  requireByteLength(salt, KEY_BYTES, 'HKDF salt');
  return recoveryKeyDerivationSchema.parse({
    algorithm: 'hkdf-sha256',
    version: 1,
    salt: encodeBase64Url(salt),
    context: RECOVERY_HKDF_INFO,
    outputLength: KEY_BYTES,
  });
}

export function createPassphraseDerivation(options?: {
  readonly salt?: Uint8Array;
  readonly memoryKiB?: number;
  readonly passes?: number;
  readonly parallelism?: number;
}): PassphraseDerivation {
  const salt = options?.salt ?? generateKdfSalt(16);
  requireByteLength(salt, 16, 'Argon2id salt');
  const derivation = passphraseDerivationSchema.parse({
    algorithm: 'argon2id',
    version: 1,
    salt: encodeBase64Url(salt),
    memoryKiB: options?.memoryKiB ?? ARGON2ID_MINIMUM_MEMORY_KIB,
    passes: options?.passes ?? ARGON2ID_MINIMUM_PASSES,
    parallelism: options?.parallelism ?? ARGON2ID_MINIMUM_PARALLELISM,
    outputLength: KEY_BYTES,
  });
  validatePassphraseDerivation(derivation);
  return derivation;
}

export function createDeviceKeyDerivation(
  provider: string,
  salt = generateKdfSalt(),
): DeviceKeyDerivation {
  requireByteLength(salt, KEY_BYTES, 'HKDF salt');
  return deviceKeyDerivationSchema.parse({
    algorithm: 'hkdf-sha256',
    version: 1,
    salt: encodeBase64Url(salt),
    context: DEVICE_HKDF_INFO,
    outputLength: KEY_BYTES,
    provider,
  });
}

export function derivePortableKek(
  key: Uint8Array,
  derivation: PortableKeyDerivation,
): KeyEncryptionKey {
  requireByteLength(key, KEY_BYTES, 'portable key');
  const parsed = portableKeyDerivationSchema.parse(derivation);
  const salt = decodeBase64Url(parsed.salt, { exactBytes: KEY_BYTES });
  try {
    return deriveHkdf(key, salt, PORTABLE_HKDF_INFO);
  } finally {
    zeroize(salt);
  }
}

export function deriveRecoveryKek(
  key: Uint8Array,
  derivation: RecoveryKeyDerivation,
): KeyEncryptionKey {
  requireByteLength(key, KEY_BYTES, 'recovery key');
  const parsed = recoveryKeyDerivationSchema.parse(derivation);
  const salt = decodeBase64Url(parsed.salt, { exactBytes: KEY_BYTES });
  try {
    return deriveHkdf(key, salt, RECOVERY_HKDF_INFO);
  } finally {
    zeroize(salt);
  }
}

export function deriveDeviceKek(
  key: Uint8Array,
  derivation: DeviceKeyDerivation,
): KeyEncryptionKey {
  requireByteLength(key, KEY_BYTES, 'device key');
  const parsed = deviceKeyDerivationSchema.parse(derivation);
  const salt = decodeBase64Url(parsed.salt, { exactBytes: KEY_BYTES });
  try {
    return deriveHkdf(key, salt, DEVICE_HKDF_INFO);
  } finally {
    zeroize(salt);
  }
}

export async function derivePassphraseKek(
  passphrase: Uint8Array,
  derivation: PassphraseDerivation,
): Promise<KeyEncryptionKey> {
  if (
    passphrase.byteLength < MIN_PASSPHRASE_BYTES ||
    passphrase.byteLength > 1_048_576
  ) {
    throw new CryptoInputError('Passphrase byte length is outside the supported range');
  }
  const parsed = passphraseDerivationSchema.parse(derivation);
  validatePassphraseDerivation(parsed);
  const salt = decodeBase64Url(parsed.salt, { exactBytes: 16 });
  try {
    const result = await deriveArgon2id({
      message: passphrase,
      nonce: salt,
      parallelism: parsed.parallelism,
      tagLength: parsed.outputLength,
      memoryKiB: parsed.memoryKiB,
      passes: parsed.passes,
    });
    try {
      return copyBytes(result) as KeyEncryptionKey;
    } finally {
      zeroize(result);
    }
  } catch {
    throw new CryptoInputError('Key derivation failed');
  } finally {
    zeroize(salt);
  }
}

export function cloneSecretKey<Kind extends string>(
  key: SecretKey<Kind>,
): SecretKey<Kind> {
  return copyBytes(key) as SecretKey<Kind>;
}

function randomSecret<Kind extends string>(): SecretKey<Kind> {
  return randomFillSync(new Uint8Array(KEY_BYTES)) as SecretKey<Kind>;
}

function formatCopyKey(
  key: Uint8Array,
  prefix: string,
  checksumDomain: Uint8Array,
): string {
  requireByteLength(key, KEY_BYTES);
  const checksum = checksumKey(key, checksumDomain);
  const payload = new Uint8Array(ENCODED_KEY_BYTES);
  payload.set(key);
  payload.set(checksum, KEY_BYTES);
  try {
    return `${prefix}${encodeBase64Url(payload)}`;
  } finally {
    zeroize(checksum);
    zeroize(payload);
  }
}

function parseCopyKey<Kind extends string>(
  value: string,
  prefix: string,
  checksumDomain: Uint8Array,
): SecretKey<Kind> {
  const expectedLength = prefix.length + Math.ceil((ENCODED_KEY_BYTES * 4) / 3);
  if (value.length !== expectedLength || !value.startsWith(prefix)) {
    throw new CryptoInputError('Invalid key format');
  }
  const payload = decodeBase64Url(value.slice(prefix.length), {
    exactBytes: ENCODED_KEY_BYTES,
  });
  const key = payload.slice(0, KEY_BYTES);
  const suppliedChecksum = payload.slice(KEY_BYTES);
  const expectedChecksum = checksumKey(key, checksumDomain);
  const valid = constantTimeEqual(suppliedChecksum, expectedChecksum);
  zeroize(payload);
  zeroize(suppliedChecksum);
  zeroize(expectedChecksum);
  if (!valid) {
    zeroize(key);
    throw new CryptoInputError('Invalid key format');
  }
  return key as SecretKey<Kind>;
}

function checksumKey(key: Uint8Array, domain: Uint8Array): Uint8Array {
  const digest = createHash('sha256').update(domain).update(key).digest();
  try {
    return Uint8Array.from(digest.subarray(0, CHECKSUM_BYTES));
  } finally {
    zeroize(digest);
  }
}

function deriveHkdf(key: Uint8Array, salt: Uint8Array, info: string): KeyEncryptionKey {
  const result = hkdfSync('sha256', key, salt, Buffer.from(info, 'ascii'), KEY_BYTES);
  const resultBytes = new Uint8Array(result);
  try {
    return copyBytes(resultBytes) as KeyEncryptionKey;
  } finally {
    zeroize(resultBytes);
  }
}

function validatePassphraseDerivation(derivation: PassphraseDerivation): void {
  if (
    derivation.memoryKiB < ARGON2ID_MINIMUM_MEMORY_KIB ||
    derivation.memoryKiB > ARGON2ID_MAXIMUM_MEMORY_KIB ||
    derivation.passes < ARGON2ID_MINIMUM_PASSES ||
    derivation.passes > ARGON2ID_MAXIMUM_PASSES ||
    derivation.parallelism < ARGON2ID_MINIMUM_PARALLELISM ||
    derivation.parallelism > ARGON2ID_MAXIMUM_PARALLELISM
  ) {
    throw new CryptoInputError('Argon2id parameters are outside the supported range');
  }
}
