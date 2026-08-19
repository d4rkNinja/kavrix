import { randomBytes } from 'node:crypto';

import {
  createPassphraseDerivation,
  decodeBase64Url,
  derivePassphraseKek,
  encodeBase64Url,
  requireByteLength,
  zeroize,
  type PortableKey,
} from '@kavrix/crypto';
import {
  canonicalJson,
  databaseIdSchema,
  keySlotIdSchema,
  passphraseDerivationSchema,
  type DatabaseId,
  type KeySlotId,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import { PortableKeyFileError } from './errors.js';
import { readSecureFile, writeSecureFile } from './filesystem.js';

const BEGIN = '-----BEGIN KAVRIX DATABASE KEY-----';
const END = '-----END KAVRIX DATABASE KEY-----';
const FORMAT_VERSION = 1;
const PROTECTION = 'argon2id+xchacha20-poly1305';
const AAD_DOMAIN = 'kavrix/database-key-file/v1';
const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;
const MAX_FILE_BYTES = 16_384;
const ASCII_FILE_BYTE = /[\x20-\x7E\n]/;

export type DatabaseKeyBinding = Readonly<{
  databaseId: DatabaseId;
  keySlotId: KeySlotId;
}>;

export type DatabaseKeyFileWriteOptions = Readonly<{
  mode?: 'create' | 'replace';
  protection: Readonly<{ kind: 'passphrase'; passphrase: Uint8Array }>;
}>;

export type ParsedDatabaseKeyFile = Readonly<{
  binding: DatabaseKeyBinding;
  portableKey: PortableKey;
}>;

/**
 * Reads only the protected envelope's untrusted public routing binding. The
 * file still passes path, ownership, link, size, and canonical-format checks;
 * callers must compare the binding with the outer database before requesting
 * a passphrase and pass it back to the full authenticated reader afterward.
 */
export async function readDatabaseKeyFileBinding(
  path: string,
): Promise<DatabaseKeyBinding> {
  let file: Uint8Array | undefined;
  try {
    file = await readSecureFile(path, MAX_FILE_BYTES);
    const binding = parseFile(file).binding;
    return { databaseId: binding.databaseId, keySlotId: binding.keySlotId };
  } catch {
    throw invalid();
  } finally {
    zeroize(file);
  }
}

export async function writeDatabaseKeyFile(
  path: string,
  portableKey: Uint8Array,
  binding: DatabaseKeyBinding,
  options: DatabaseKeyFileWriteOptions,
): Promise<void> {
  requireByteLength(portableKey, KEY_BYTES, 'portable key');
  validateBinding(binding);
  const ownedKey = Uint8Array.from(portableKey);
  const ownedPassphrase = Uint8Array.from(options.protection.passphrase);
  let nonce: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let kek: Uint8Array | undefined;
  let serialized: Uint8Array | undefined;
  try {
    const derivation = createPassphraseDerivation();
    const encodedDerivation = encodeDerivation(derivation);
    kek = await derivePassphraseKek(ownedPassphrase, derivation);
    nonce = randomBytes(NONCE_BYTES);
    aad = associatedData(binding, encodedDerivation);
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      ownedKey,
      aad,
      null,
      nonce,
      kek,
    );
    serialized = Buffer.from(
      [
        BEGIN,
        'Version: 1',
        `Database-ID: ${binding.databaseId}`,
        `Key-ID: ${binding.keySlotId}`,
        `Protection: ${PROTECTION}`,
        `Derivation: ${encodedDerivation}`,
        `Nonce: ${encodeBase64Url(nonce)}`,
        `Ciphertext: ${encodeBase64Url(encrypted.ciphertext)}`,
        `Tag: ${encodeBase64Url(encrypted.mac)}`,
        END,
        '',
      ].join('\n'),
      'ascii',
    );
    await writeSecureFile(path, serialized, options.mode ?? 'create');
  } finally {
    zeroize(serialized);
    zeroize(kek);
    zeroize(aad);
    zeroize(nonce);
    zeroize(ownedPassphrase);
    zeroize(ownedKey);
  }
}

export async function readDatabaseKeyFile(
  path: string,
  passphrase: Uint8Array,
  expectedBinding?: DatabaseKeyBinding,
): Promise<ParsedDatabaseKeyFile> {
  const ownedPassphrase = Uint8Array.from(passphrase);
  let file: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let kek: Uint8Array | undefined;
  let portableKey: Uint8Array | undefined;
  try {
    file = await readSecureFile(path, MAX_FILE_BYTES);
    const parsed = parseFile(file);
    if (
      expectedBinding !== undefined &&
      (expectedBinding.databaseId !== parsed.binding.databaseId ||
        expectedBinding.keySlotId !== parsed.binding.keySlotId)
    ) {
      throw invalid();
    }
    nonce = decodeBase64Url(parsed.nonce, { exactBytes: NONCE_BYTES });
    ciphertext = decodeBase64Url(parsed.ciphertext, { exactBytes: KEY_BYTES });
    tag = decodeBase64Url(parsed.tag, { exactBytes: TAG_BYTES });
    aad = associatedData(parsed.binding, parsed.encodedDerivation);
    kek = await derivePassphraseKek(ownedPassphrase, parsed.derivation);
    await sodium.ready;
    portableKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
      null,
      ciphertext,
      tag,
      aad,
      nonce,
      kek,
    );
    requireByteLength(portableKey, KEY_BYTES, 'portable key');
    const result: ParsedDatabaseKeyFile = {
      binding: parsed.binding,
      portableKey: portableKey as PortableKey,
    };
    portableKey = undefined;
    return result;
  } catch {
    throw invalid();
  } finally {
    zeroize(portableKey);
    zeroize(kek);
    zeroize(aad);
    zeroize(tag);
    zeroize(ciphertext);
    zeroize(nonce);
    zeroize(file);
    zeroize(ownedPassphrase);
  }
}

type ParsedFile = Readonly<{
  binding: DatabaseKeyBinding;
  derivation: ReturnType<typeof passphraseDerivationSchema.parse>;
  encodedDerivation: string;
  nonce: string;
  ciphertext: string;
  tag: string;
}>;

function parseFile(file: Uint8Array): ParsedFile {
  const lines = strictLines(file);
  if (
    lines.length !== 10 ||
    lines[0] !== BEGIN ||
    lines[1] !== 'Version: 1' ||
    lines[9] !== END
  ) {
    throw invalid();
  }
  try {
    const binding: DatabaseKeyBinding = {
      databaseId: databaseIdSchema.parse(header(lines[2], 'Database-ID')),
      keySlotId: keySlotIdSchema.parse(header(lines[3], 'Key-ID')),
    };
    if (lines[4] !== `Protection: ${PROTECTION}`) throw invalid();
    const encodedDerivation = header(lines[5], 'Derivation');
    const derivationBytes = decodeBase64Url(encodedDerivation, { maximumBytes: 1024 });
    let derivationText: string | undefined;
    try {
      derivationText = Buffer.from(derivationBytes).toString('utf8');
      const derivation = passphraseDerivationSchema.parse(JSON.parse(derivationText));
      if (
        canonicalJson(derivation) !== derivationText ||
        encodeDerivation(derivation) !== encodedDerivation
      ) {
        throw invalid();
      }
      return {
        binding,
        derivation,
        encodedDerivation,
        nonce: header(lines[6], 'Nonce'),
        ciphertext: header(lines[7], 'Ciphertext'),
        tag: header(lines[8], 'Tag'),
      };
    } finally {
      zeroize(derivationBytes);
      if (derivationText !== undefined) derivationText = undefined;
    }
  } catch {
    throw invalid();
  }
}

function strictLines(file: Uint8Array): string[] {
  if (file.byteLength === 0 || file.byteLength > MAX_FILE_BYTES) throw invalid();
  for (const byte of file) {
    if (!ASCII_FILE_BYTE.test(String.fromCharCode(byte))) throw invalid();
  }
  const text = Buffer.from(file).toString('ascii');
  if (!text.endsWith('\n') || text.endsWith('\n\n')) throw invalid();
  return text.slice(0, -1).split('\n');
}

function header(line: string | undefined, name: string): string {
  const prefix = `${name}: `;
  if (line?.startsWith(prefix) !== true || line.length === prefix.length)
    throw invalid();
  return line.slice(prefix.length);
}

function encodeDerivation(
  derivation: ReturnType<typeof passphraseDerivationSchema.parse>,
): string {
  return encodeBase64Url(Buffer.from(canonicalJson(derivation), 'utf8'));
}

function associatedData(
  binding: DatabaseKeyBinding,
  encodedDerivation: string,
): Uint8Array {
  return Buffer.from(
    canonicalJson({
      domain: AAD_DOMAIN,
      format: BEGIN,
      version: FORMAT_VERSION,
      databaseId: binding.databaseId,
      keySlotId: binding.keySlotId,
      protection: PROTECTION,
      derivation: encodedDerivation,
    }),
    'utf8',
  );
}

function validateBinding(binding: DatabaseKeyBinding): void {
  databaseIdSchema.parse(binding.databaseId);
  keySlotIdSchema.parse(binding.keySlotId);
}

function invalid(): PortableKeyFileError {
  return new PortableKeyFileError('KEY_FILE_UNSAFE');
}
