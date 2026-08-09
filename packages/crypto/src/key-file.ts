import { randomBytes } from 'node:crypto';

import {
  keySlotIdSchema,
  passphraseDerivationSchema,
  vaultIdSchema,
  type KeySlot,
  type KeySlotId,
  type VaultId,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import {
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from './bytes.js';
import { AuthenticationError, CryptoInputError } from './errors.js';
import {
  createPassphraseDerivation,
  derivePassphraseKek,
  formatPortableKey,
  parsePortableKey,
  type PortableKey,
} from './keys.js';

const BEGIN_LABEL = '-----BEGIN CREDVAULT PORTABLE KEY-----';
const END_LABEL = '-----END CREDVAULT PORTABLE KEY-----';
const PROTECTION_ALGORITHM = 'argon2id+xchacha20-poly1305-ietf';
const KEY_FILE_AAD_DOMAIN = 'credvault/portable-key-file/v1';
const MAX_KEY_FILE_BYTES = 16_384;
const ASCII_FILE_BYTE = /[\x20-\x7E\n]/;

type PassphraseDerivation = Extract<
  KeySlot,
  { readonly type: 'passphrase' }
>['derivation'];

export type PortableKeyFileBinding =
  | { readonly kind: 'unbound' }
  | {
      readonly kind: 'bound';
      readonly vaultId: VaultId;
      readonly keySlotId: KeySlotId;
    };

export type ParsedPortableKeyFile = PortableKeyFileBinding & {
  readonly key: PortableKey;
  readonly protected: boolean;
};

export function serializePortableKeyFile(
  key: Uint8Array,
  binding: PortableKeyFileBinding,
): Uint8Array {
  validateBinding(binding);
  const text = [
    BEGIN_LABEL,
    'Version: 1',
    ...bindingHeaders(binding),
    `Key: ${formatPortableKey(key)}`,
    END_LABEL,
    '',
  ].join('\n');
  return Buffer.from(text, 'ascii');
}

export function parsePortableKeyFile(
  fileBytes: Uint8Array,
  expectedBinding?: PortableKeyFileBinding,
): ParsedPortableKeyFile {
  const lines = strictLines(fileBytes);
  if (
    lines.length !== 7 ||
    lines[0] !== BEGIN_LABEL ||
    lines[1] !== 'Version: 1' ||
    lines[6] !== END_LABEL
  ) {
    throw invalidKeyFile();
  }
  const binding = parseBinding(lines[2], lines[3], lines[4]);
  verifyExpectedBinding(binding, expectedBinding);
  const keyLine = lines[5];
  if (keyLine?.startsWith('Key: ') !== true) {
    throw invalidKeyFile();
  }
  let key: PortableKey;
  try {
    key = parsePortableKey(keyLine.slice('Key: '.length));
  } catch {
    throw invalidKeyFile();
  }
  return { ...binding, key, protected: false };
}

export async function serializeProtectedPortableKeyFile(
  key: Uint8Array,
  passphrase: Uint8Array,
  binding: PortableKeyFileBinding,
): Promise<Uint8Array> {
  requireByteLength(key, 32, 'portable key');
  validateBinding(binding);
  const derivation = createPassphraseDerivation();
  const kek = await derivePassphraseKek(passphrase, derivation);
  const nonce = randomBytes(24);
  const aad = protectedFileAad(binding, derivation);
  try {
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      key,
      aad,
      null,
      nonce,
      kek,
    );
    const text = [
      BEGIN_LABEL,
      'Version: 1',
      ...bindingHeaders(binding),
      `Protection: ${PROTECTION_ALGORITHM}`,
      `KDF-Version: ${String(derivation.version)}`,
      `KDF-Salt: ${derivation.salt}`,
      `KDF-Memory-KiB: ${String(derivation.memoryKiB)}`,
      `KDF-Passes: ${String(derivation.passes)}`,
      `KDF-Parallelism: ${String(derivation.parallelism)}`,
      `KDF-Output-Length: ${String(derivation.outputLength)}`,
      `Nonce: ${encodeBase64Url(nonce)}`,
      'AAD-Version: 1',
      `Ciphertext: ${encodeBase64Url(encrypted.ciphertext)}`,
      `Authentication-Tag: ${encodeBase64Url(encrypted.mac)}`,
      END_LABEL,
      '',
    ].join('\n');
    return Buffer.from(text, 'ascii');
  } finally {
    zeroize(kek);
    zeroize(nonce);
    zeroize(aad);
  }
}

export async function parseProtectedPortableKeyFile(
  fileBytes: Uint8Array,
  passphrase: Uint8Array,
  expectedBinding?: PortableKeyFileBinding,
): Promise<ParsedPortableKeyFile> {
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let authenticationTag: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let kek: Uint8Array | undefined;
  try {
    const lines = strictLines(fileBytes);
    if (
      lines.length !== 17 ||
      lines[0] !== BEGIN_LABEL ||
      lines[1] !== 'Version: 1' ||
      lines[5] !== `Protection: ${PROTECTION_ALGORITHM}` ||
      lines[13] !== 'AAD-Version: 1' ||
      lines[16] !== END_LABEL
    ) {
      throw invalidKeyFile();
    }
    const binding = parseBinding(lines[2], lines[3], lines[4]);
    verifyExpectedBinding(binding, expectedBinding);
    const derivation = passphraseDerivationSchema.parse({
      algorithm: 'argon2id',
      version: parseIntegerHeader(lines[6], 'KDF-Version'),
      salt: parseStringHeader(lines[7], 'KDF-Salt'),
      memoryKiB: parseIntegerHeader(lines[8], 'KDF-Memory-KiB'),
      passes: parseIntegerHeader(lines[9], 'KDF-Passes'),
      parallelism: parseIntegerHeader(lines[10], 'KDF-Parallelism'),
      outputLength: parseIntegerHeader(lines[11], 'KDF-Output-Length'),
    });
    nonce = decodeBase64Url(parseStringHeader(lines[12], 'Nonce'), {
      exactBytes: 24,
    });
    ciphertext = decodeBase64Url(parseStringHeader(lines[14], 'Ciphertext'), {
      exactBytes: 32,
    });
    authenticationTag = decodeBase64Url(
      parseStringHeader(lines[15], 'Authentication-Tag'),
      { exactBytes: 16 },
    );
    aad = protectedFileAad(binding, derivation);
    kek = await derivePassphraseKek(passphrase, derivation);
    await sodium.ready;
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
      null,
      ciphertext,
      authenticationTag,
      aad,
      nonce,
      kek,
    );
    requireByteLength(plaintext, 32, 'portable key');
    return { ...binding, key: plaintext as PortableKey, protected: true };
  } catch (error) {
    if (
      error instanceof CryptoInputError &&
      error.message === 'Invalid portable key file'
    ) {
      throw error;
    }
    throw new AuthenticationError();
  } finally {
    zeroize(nonce);
    zeroize(ciphertext);
    zeroize(authenticationTag);
    zeroize(aad);
    zeroize(kek);
  }
}

function protectedFileAad(
  binding: PortableKeyFileBinding,
  derivation: PassphraseDerivation,
): Uint8Array {
  return Buffer.from(
    [
      KEY_FILE_AAD_DOMAIN,
      BEGIN_LABEL,
      'Version: 1',
      ...bindingHeaders(binding),
      `Protection: ${PROTECTION_ALGORITHM}`,
      `KDF-Version: ${String(derivation.version)}`,
      `KDF-Salt: ${derivation.salt}`,
      `KDF-Memory-KiB: ${String(derivation.memoryKiB)}`,
      `KDF-Passes: ${String(derivation.passes)}`,
      `KDF-Parallelism: ${String(derivation.parallelism)}`,
      `KDF-Output-Length: ${String(derivation.outputLength)}`,
      'AAD-Version: 1',
      END_LABEL,
      '',
    ].join('\n'),
    'ascii',
  );
}

function strictLines(fileBytes: Uint8Array): string[] {
  if (fileBytes.byteLength === 0 || fileBytes.byteLength > MAX_KEY_FILE_BYTES) {
    throw invalidKeyFile();
  }
  for (const byte of fileBytes) {
    if (!ASCII_FILE_BYTE.test(String.fromCharCode(byte))) {
      throw invalidKeyFile();
    }
  }
  const text = Buffer.from(
    fileBytes.buffer,
    fileBytes.byteOffset,
    fileBytes.byteLength,
  ).toString('ascii');
  if (!text.endsWith('\n') || text.endsWith('\n\n')) {
    throw invalidKeyFile();
  }
  return text.slice(0, -1).split('\n');
}

function parseBinding(
  bindingLine: string | undefined,
  vaultLine: string | undefined,
  keyLine: string | undefined,
): PortableKeyFileBinding {
  const kind = parseStringHeader(bindingLine, 'Binding');
  const vaultValue = parseStringHeader(vaultLine, 'Vault-ID');
  const keyValue = parseStringHeader(keyLine, 'Key-ID');
  if (kind === 'unbound') {
    if (vaultValue !== '-' || keyValue !== '-') {
      throw invalidKeyFile();
    }
    return { kind: 'unbound' };
  }
  if (kind !== 'bound') {
    throw invalidKeyFile();
  }
  try {
    return {
      kind: 'bound',
      vaultId: vaultIdSchema.parse(vaultValue),
      keySlotId: keySlotIdSchema.parse(keyValue),
    };
  } catch {
    throw invalidKeyFile();
  }
}

function validateBinding(binding: PortableKeyFileBinding): void {
  if (binding.kind === 'bound') {
    vaultIdSchema.parse(binding.vaultId);
    keySlotIdSchema.parse(binding.keySlotId);
  }
}

function bindingHeaders(binding: PortableKeyFileBinding): readonly string[] {
  return binding.kind === 'unbound'
    ? ['Binding: unbound', 'Vault-ID: -', 'Key-ID: -']
    : [
        'Binding: bound',
        `Vault-ID: ${binding.vaultId}`,
        `Key-ID: ${binding.keySlotId}`,
      ];
}

function verifyExpectedBinding(
  actual: PortableKeyFileBinding,
  expected: PortableKeyFileBinding | undefined,
): void {
  if (
    expected !== undefined &&
    (expected.kind !== actual.kind ||
      (expected.kind === 'bound' &&
        (actual.kind !== 'bound' ||
          expected.vaultId !== actual.vaultId ||
          expected.keySlotId !== actual.keySlotId)))
  ) {
    throw invalidKeyFile();
  }
}

function parseStringHeader(line: string | undefined, name: string): string {
  const prefix = `${name}: `;
  if (line?.startsWith(prefix) !== true) {
    throw invalidKeyFile();
  }
  const value = line.slice(prefix.length);
  if (value.length === 0) {
    throw invalidKeyFile();
  }
  return value;
}

function parseIntegerHeader(line: string | undefined, name: string): number {
  const value = parseStringHeader(line, name);
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw invalidKeyFile();
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw invalidKeyFile();
  }
  return parsed;
}

function invalidKeyFile(): CryptoInputError {
  return new CryptoInputError('Invalid portable key file');
}
