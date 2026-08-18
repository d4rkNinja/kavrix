import { randomBytes } from 'node:crypto';

import {
  decodeBase64Url,
  createPassphraseDerivation,
  derivePassphraseKek,
  encodeBase64Url,
  requireByteLength,
  zeroize,
  type RecoveryKey,
} from '@kavrix/crypto';
import {
  keySlotIdSchema,
  passphraseDerivationSchema,
  vaultIdSchema,
  type KeySlotId,
  type VaultId,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import { PortableKeyFileError } from './errors.js';
import { readSecureFile, writeSecureFile } from './filesystem.js';

const FORMAT = 'kavrix-recovery-kit';
const VERSION = 1;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;
const KEY_BYTES = 32;
const MAX_FILE_BYTES = 16_384;
const AAD_DOMAIN = 'kavrix/recovery-kit/v1';

export type RecoveryKitBinding = Readonly<{
  vaultId: VaultId;
  recoverySlotId: KeySlotId;
}>;

export type ParsedRecoveryKit = RecoveryKitBinding &
  Readonly<{
    recoveryKey: RecoveryKey;
  }>;

type RecoveryKitEnvelope = Readonly<{
  format: typeof FORMAT;
  version: typeof VERSION;
  vaultId: VaultId;
  recoverySlotId: KeySlotId;
  derivation: ReturnType<typeof passphraseDerivationSchema.parse>;
  nonce: string;
  ciphertext: string;
  authenticationTag: string;
}>;

export async function writeRecoveryKitFile(
  path: string,
  recoveryKey: Uint8Array,
  passphrase: Uint8Array,
  binding: RecoveryKitBinding,
  mode: 'create' | 'replace' = 'create',
): Promise<void> {
  requireByteLength(recoveryKey, KEY_BYTES, 'recovery key');
  validateBinding(binding);
  const ownedKey = Uint8Array.from(recoveryKey);
  const ownedPassphrase = Uint8Array.from(passphrase);
  let serialized: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let kek: Uint8Array | undefined;
  try {
    const derivation = createPassphraseDerivation();
    kek = await derivePassphraseKek(ownedPassphrase, derivation);
    nonce = randomBytes(NONCE_BYTES);
    aad = associatedData(binding, derivation);
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      ownedKey,
      aad,
      null,
      nonce,
      kek,
    );
    const envelope: RecoveryKitEnvelope = {
      format: FORMAT,
      version: VERSION,
      vaultId: binding.vaultId,
      recoverySlotId: binding.recoverySlotId,
      derivation,
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(encrypted.ciphertext),
      authenticationTag: encodeBase64Url(encrypted.mac),
    };
    serialized = Buffer.from(JSON.stringify(envelope) + '\n', 'ascii');
    await writeSecureFile(path, serialized, mode);
  } finally {
    zeroize(serialized);
    zeroize(kek);
    zeroize(aad);
    zeroize(nonce);
    zeroize(ownedPassphrase);
    zeroize(ownedKey);
  }
}

export async function readRecoveryKitFile(
  path: string,
  passphrase: Uint8Array,
  expectedBinding?: RecoveryKitBinding,
): Promise<ParsedRecoveryKit> {
  const ownedPassphrase = Uint8Array.from(passphrase);
  let file: Buffer | undefined;
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let authenticationTag: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let kek: Uint8Array | undefined;
  let recoveryKey: Uint8Array | undefined;
  try {
    file = await readSecureFile(path, MAX_FILE_BYTES);
    const envelope = parseEnvelope(JSON.parse(file.toString('utf8')) as unknown);
    const binding = {
      vaultId: envelope.vaultId,
      recoverySlotId: envelope.recoverySlotId,
    };
    if (
      expectedBinding !== undefined &&
      (expectedBinding.vaultId !== binding.vaultId ||
        expectedBinding.recoverySlotId !== binding.recoverySlotId)
    ) {
      throw invalidKit();
    }
    nonce = decodeBase64Url(envelope.nonce, { exactBytes: NONCE_BYTES });
    ciphertext = decodeBase64Url(envelope.ciphertext, { exactBytes: KEY_BYTES });
    authenticationTag = decodeBase64Url(envelope.authenticationTag, {
      exactBytes: TAG_BYTES,
    });
    kek = await derivePassphraseKek(ownedPassphrase, envelope.derivation);
    aad = associatedData(binding, envelope.derivation);
    await sodium.ready;
    recoveryKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
      null,
      ciphertext,
      authenticationTag,
      aad,
      nonce,
      kek,
    );
    requireByteLength(recoveryKey, KEY_BYTES, 'recovery key');
    const result = { ...binding, recoveryKey: recoveryKey as RecoveryKey };
    recoveryKey = undefined;
    return result;
  } catch {
    throw invalidKit();
  } finally {
    zeroize(recoveryKey);
    zeroize(file);
    zeroize(kek);
    zeroize(aad);
    zeroize(nonce);
    zeroize(ciphertext);
    zeroize(authenticationTag);
    zeroize(ownedPassphrase);
  }
}

function associatedData(
  binding: RecoveryKitBinding,
  derivation: ReturnType<typeof passphraseDerivationSchema.parse>,
): Uint8Array {
  return Buffer.from(
    JSON.stringify({
      domain: AAD_DOMAIN,
      format: FORMAT,
      version: VERSION,
      vaultId: binding.vaultId,
      recoverySlotId: binding.recoverySlotId,
      derivation,
    }),
    'utf8',
  );
}

function parseEnvelope(value: unknown): RecoveryKitEnvelope {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalidKit();
  }
  const record = value as Record<string, unknown>;
  const expectedKeys = [
    'format',
    'version',
    'vaultId',
    'recoverySlotId',
    'derivation',
    'nonce',
    'ciphertext',
    'authenticationTag',
  ];
  if (
    Object.keys(record).length !== expectedKeys.length ||
    expectedKeys.some((key) => !Object.hasOwn(record, key))
  ) {
    throw invalidKit();
  }
  try {
    if (record['format'] !== FORMAT || record['version'] !== VERSION) {
      throw invalidKit();
    }
    const vaultId = vaultIdSchema.parse(record['vaultId']);
    const recoverySlotId = keySlotIdSchema.parse(record['recoverySlotId']);
    const derivation = passphraseDerivationSchema.parse(record['derivation']);
    if (
      typeof record['nonce'] !== 'string' ||
      typeof record['ciphertext'] !== 'string' ||
      typeof record['authenticationTag'] !== 'string'
    ) {
      throw invalidKit();
    }
    return {
      format: FORMAT,
      version: VERSION,
      vaultId,
      recoverySlotId,
      derivation,
      nonce: record['nonce'],
      ciphertext: record['ciphertext'],
      authenticationTag: record['authenticationTag'],
    };
  } catch {
    throw invalidKit();
  }
}

function validateBinding(binding: RecoveryKitBinding): void {
  vaultIdSchema.parse(binding.vaultId);
  keySlotIdSchema.parse(binding.recoverySlotId);
}

function invalidKit(): PortableKeyFileError {
  return new PortableKeyFileError('KEY_FILE_UNSAFE');
}
