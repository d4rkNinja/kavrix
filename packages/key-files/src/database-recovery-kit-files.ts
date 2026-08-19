import { randomBytes } from 'node:crypto';

import {
  createPassphraseDerivation,
  decodeBase64Url,
  derivePassphraseKek,
  encodeBase64Url,
  requireByteLength,
  zeroize,
  type RecoveryKey,
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
import {
  cleanupOwnedSecureFilePublication,
  createOwnedSecureFile,
  readSecureFile,
  writeSecureFile,
  type OwnedSecureFilePublication,
} from './filesystem.js';

const FORMAT = 'kavrix-database-recovery-kit';
const VERSION = 1;
const AAD_DOMAIN = 'kavrix/database-recovery-kit/v1';
const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;
const MAX_FILE_BYTES = 16_384;

export type DatabaseRecoveryBinding = Readonly<{
  databaseId: DatabaseId;
  recoverySlotId: KeySlotId;
}>;

export type DatabaseRecoveryKitWriteOptions = Readonly<{
  mode?: 'create' | 'replace';
  passphrase: Uint8Array;
}>;

export type DatabaseRecoveryKitCreateOptions = Readonly<{
  passphrase: Uint8Array;
}>;

declare const databaseRecoveryKitFilePublicationBrand: unique symbol;
export type DatabaseRecoveryKitFilePublication = OwnedSecureFilePublication &
  Readonly<{ [databaseRecoveryKitFilePublicationBrand]: true }>;

export type DatabaseRecoveryKitFileCreateResult =
  | Readonly<{
      status: 'not-published';
      error: PortableKeyFileError;
    }>
  | Readonly<{
      status: 'published';
      publication: DatabaseRecoveryKitFilePublication;
    }>
  | Readonly<{
      status: 'publication-uncertain';
      publication: DatabaseRecoveryKitFilePublication;
      error: PortableKeyFileError;
    }>;

export type ParsedDatabaseRecoveryKit = Readonly<{
  binding: DatabaseRecoveryBinding;
  recoveryKey: RecoveryKey;
}>;

type Envelope = Readonly<{
  format: typeof FORMAT;
  version: typeof VERSION;
  databaseId: DatabaseId;
  recoverySlotId: KeySlotId;
  derivation: ReturnType<typeof passphraseDerivationSchema.parse>;
  nonce: string;
  ciphertext: string;
  authenticationTag: string;
}>;

export async function writeDatabaseRecoveryKitFile(
  path: string,
  recoveryKey: Uint8Array,
  binding: DatabaseRecoveryBinding,
  options: DatabaseRecoveryKitWriteOptions,
): Promise<void> {
  let serialized: Uint8Array | undefined;
  try {
    serialized = await serializeDatabaseRecoveryKitFile(recoveryKey, binding, options);
    await writeSecureFile(path, serialized, options.mode ?? 'create');
  } finally {
    zeroize(serialized);
  }
}

export async function createOwnedDatabaseRecoveryKitFile(
  path: string,
  recoveryKey: Uint8Array,
  binding: DatabaseRecoveryBinding,
  options: DatabaseRecoveryKitCreateOptions,
): Promise<DatabaseRecoveryKitFileCreateResult> {
  let serialized: Uint8Array | undefined;
  try {
    serialized = await serializeDatabaseRecoveryKitFile(recoveryKey, binding, options);
    const result = await createOwnedSecureFile(
      path,
      serialized,
      'database-recovery-kit-file',
      MAX_FILE_BYTES,
    );
    if (result.status === 'not-published') return result;
    return {
      ...result,
      publication: result.publication as DatabaseRecoveryKitFilePublication,
    };
  } finally {
    zeroize(serialized);
  }
}

export async function cleanupOwnedDatabaseRecoveryKitFile(
  publication: DatabaseRecoveryKitFilePublication,
): Promise<void> {
  await cleanupOwnedSecureFilePublication(publication, 'database-recovery-kit-file');
}

async function serializeDatabaseRecoveryKitFile(
  recoveryKey: Uint8Array,
  binding: DatabaseRecoveryBinding,
  options: DatabaseRecoveryKitCreateOptions,
): Promise<Uint8Array> {
  requireByteLength(recoveryKey, KEY_BYTES, 'recovery key');
  validateBinding(binding);
  const ownedKey = Uint8Array.from(recoveryKey);
  const ownedPassphrase = Uint8Array.from(options.passphrase);
  let nonce: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let kek: Uint8Array | undefined;
  let serialized: Uint8Array | undefined;
  try {
    const derivation = createPassphraseDerivation();
    nonce = randomBytes(NONCE_BYTES);
    aad = associatedData(binding, derivation, nonce);
    kek = await derivePassphraseKek(ownedPassphrase, derivation);
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      ownedKey,
      aad,
      null,
      nonce,
      kek,
    );
    const envelope: Envelope = {
      format: FORMAT,
      version: VERSION,
      databaseId: binding.databaseId,
      recoverySlotId: binding.recoverySlotId,
      derivation,
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(encrypted.ciphertext),
      authenticationTag: encodeBase64Url(encrypted.mac),
    };
    serialized = Buffer.from(`${canonicalJson(envelope)}\n`, 'utf8');
    const result = serialized;
    serialized = undefined;
    return result;
  } finally {
    zeroize(serialized);
    zeroize(kek);
    zeroize(aad);
    zeroize(nonce);
    zeroize(ownedPassphrase);
    zeroize(ownedKey);
  }
}

export async function readDatabaseRecoveryKitFile(
  path: string,
  passphrase: Uint8Array,
  expectedBinding?: DatabaseRecoveryBinding,
): Promise<ParsedDatabaseRecoveryKit> {
  const ownedPassphrase = Uint8Array.from(passphrase);
  let file: Uint8Array | undefined;
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let tag: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let kek: Uint8Array | undefined;
  let recoveryKey: Uint8Array | undefined;
  try {
    file = await readSecureFile(path, MAX_FILE_BYTES);
    const envelope = parseEnvelope(file);
    const binding: DatabaseRecoveryBinding = {
      databaseId: envelope.databaseId,
      recoverySlotId: envelope.recoverySlotId,
    };
    if (
      expectedBinding !== undefined &&
      (binding.databaseId !== expectedBinding.databaseId ||
        binding.recoverySlotId !== expectedBinding.recoverySlotId)
    )
      throw invalid();
    nonce = decodeBase64Url(envelope.nonce, { exactBytes: NONCE_BYTES });
    ciphertext = decodeBase64Url(envelope.ciphertext, { exactBytes: KEY_BYTES });
    tag = decodeBase64Url(envelope.authenticationTag, { exactBytes: TAG_BYTES });
    aad = associatedData(binding, envelope.derivation, nonce);
    kek = await derivePassphraseKek(ownedPassphrase, envelope.derivation);
    await sodium.ready;
    recoveryKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
      null,
      ciphertext,
      tag,
      aad,
      nonce,
      kek,
    );
    requireByteLength(recoveryKey, KEY_BYTES, 'recovery key');
    const result: ParsedDatabaseRecoveryKit = {
      binding,
      recoveryKey: recoveryKey as RecoveryKey,
    };
    recoveryKey = undefined;
    return result;
  } catch {
    throw invalid();
  } finally {
    zeroize(recoveryKey);
    zeroize(kek);
    zeroize(aad);
    zeroize(tag);
    zeroize(ciphertext);
    zeroize(nonce);
    zeroize(file);
    zeroize(ownedPassphrase);
  }
}

/**
 * Reads only the protected envelope's untrusted public routing fields needed
 * to select an opaque database document. This does not decrypt or request
 * recovery material; callers must compare the binding with that document and
 * pass it back to the full authenticated reader afterward.
 */
export async function readDatabaseRecoveryKitFileBinding(
  path: string,
): Promise<DatabaseRecoveryBinding> {
  let file: Uint8Array | undefined;
  try {
    file = await readSecureFile(path, MAX_FILE_BYTES);
    const envelope = parseEnvelope(file);
    return {
      databaseId: envelope.databaseId,
      recoverySlotId: envelope.recoverySlotId,
    };
  } catch {
    throw invalid();
  } finally {
    zeroize(file);
  }
}

function parseEnvelope(file: Uint8Array): Envelope {
  try {
    const text = Buffer.from(file).toString('utf8');
    if (!text.endsWith('\n') || text.endsWith('\n\n')) throw invalid();
    const value: unknown = JSON.parse(text);
    if (
      canonicalJson(value) + '\n' !== text ||
      typeof value !== 'object' ||
      value === null ||
      Array.isArray(value)
    )
      throw invalid();
    const record = value as Record<string, unknown>;
    const keys = [
      'format',
      'version',
      'databaseId',
      'recoverySlotId',
      'derivation',
      'nonce',
      'ciphertext',
      'authenticationTag',
    ];
    if (
      Object.keys(record).length !== keys.length ||
      keys.some((key) => !Object.hasOwn(record, key))
    )
      throw invalid();
    if (record['format'] !== FORMAT || record['version'] !== VERSION) throw invalid();
    const envelope: Envelope = {
      format: FORMAT,
      version: VERSION,
      databaseId: databaseIdSchema.parse(record['databaseId']),
      recoverySlotId: keySlotIdSchema.parse(record['recoverySlotId']),
      derivation: passphraseDerivationSchema.parse(record['derivation']),
      nonce: requireString(record['nonce']),
      ciphertext: requireString(record['ciphertext']),
      authenticationTag: requireString(record['authenticationTag']),
    };
    return envelope;
  } catch {
    throw invalid();
  }
}

function associatedData(
  binding: DatabaseRecoveryBinding,
  derivation: ReturnType<typeof passphraseDerivationSchema.parse>,
  nonce: Uint8Array,
): Uint8Array {
  return Buffer.from(
    canonicalJson({
      domain: AAD_DOMAIN,
      format: FORMAT,
      version: VERSION,
      databaseId: binding.databaseId,
      recoverySlotId: binding.recoverySlotId,
      derivation,
      nonce: encodeBase64Url(nonce),
    }),
    'utf8',
  );
}

function requireString(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) throw invalid();
  return value;
}

function validateBinding(binding: DatabaseRecoveryBinding): void {
  databaseIdSchema.parse(binding.databaseId);
  keySlotIdSchema.parse(binding.recoverySlotId);
}

function invalid(): PortableKeyFileError {
  return new PortableKeyFileError('KEY_FILE_UNSAFE');
}
