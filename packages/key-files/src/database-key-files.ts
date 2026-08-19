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
  databaseRevisionSchema,
  keySlotIdSchema,
  passphraseDerivationSchema,
  sha256DigestSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type DatabaseId,
  type KeySlotId,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';
import { z } from 'zod';

import { PortableKeyFileError } from './errors.js';
import {
  cleanupOwnedSecureFilePublication,
  createOwnedSecureFile,
  releaseOwnedSecureFilePublication,
  readSecureFile,
  writeSecureFile,
  type OwnedSecureFilePublication,
} from './filesystem.js';
import {
  verifyDatabaseRevisionAnchor,
  type DatabaseRevisionAnchor,
} from './database-revision-anchor.js';

const BEGIN = '-----BEGIN KAVRIX DATABASE KEY-----';
const END = '-----END KAVRIX DATABASE KEY-----';
const OWNER_FORMAT_VERSION = 1;
const LOCAL_SHARE_FORMAT_VERSION = 2;
const PROTECTION = 'argon2id+xchacha20-poly1305';
const AAD_DOMAIN = 'kavrix/database-key-file/v1';
const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;
const MAX_FILE_BYTES = 256 * 1024;
const ASCII_FILE_BYTE = /[\x20-\x7E\n]/;

export type DatabaseKeyBinding = Readonly<{
  databaseId: DatabaseId;
  keySlotId: KeySlotId;
}>;

export type DatabaseKeyFileWriteOptions = Readonly<{
  mode?: 'create' | 'replace';
  protection: Readonly<{ kind: 'passphrase'; passphrase: Uint8Array }>;
}>;

export type DatabaseKeyFileCreateOptions = Readonly<{
  protection: Readonly<{ kind: 'passphrase'; passphrase: Uint8Array }>;
}>;

declare const databaseKeyFilePublicationBrand: unique symbol;
export type DatabaseKeyFilePublication = OwnedSecureFilePublication &
  Readonly<{ [databaseKeyFilePublicationBrand]: true }>;

export type DatabaseKeyFileCreateResult =
  | Readonly<{
      status: 'not-published';
      error: PortableKeyFileError;
    }>
  | Readonly<{
      status: 'published';
      publication: DatabaseKeyFilePublication;
    }>
  | Readonly<{
      status: 'publication-uncertain';
      publication: DatabaseKeyFilePublication;
      error: PortableKeyFileError;
    }>;

export type ParsedDatabaseKeyFile = Readonly<{
  binding: DatabaseKeyBinding;
  portableKey: PortableKey;
  localShareBootstrap?: DatabaseRevisionAnchor | null;
}>;

const localShareAnchorSchema = z
  .object({
    databaseId: databaseIdSchema,
    databaseRevision: databaseRevisionSchema,
    catalogMetadataDigest: sha256DigestSchema,
    vaultHeads: z.record(
      vaultIdSchema,
      z
        .object({
          revision: vaultRevisionSchema,
          metadataDigest: sha256DigestSchema,
        })
        .strict(),
    ),
  })
  .strict();

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
  let serialized: Uint8Array | undefined;
  try {
    serialized = await serializeDatabaseKeyFile(portableKey, binding, options);
    await writeSecureFile(path, serialized, options.mode ?? 'create');
  } finally {
    zeroize(serialized);
  }
}

export async function createOwnedDatabaseKeyFile(
  path: string,
  portableKey: Uint8Array,
  binding: DatabaseKeyBinding,
  options: DatabaseKeyFileCreateOptions,
): Promise<DatabaseKeyFileCreateResult> {
  let serialized: Uint8Array | undefined;
  try {
    serialized = await serializeDatabaseKeyFile(portableKey, binding, options);
    const result = await createOwnedSecureFile(
      path,
      serialized,
      'database-key-file',
      MAX_FILE_BYTES,
    );
    if (result.status === 'not-published') return result;
    return {
      ...result,
      publication: result.publication as DatabaseKeyFilePublication,
    };
  } finally {
    zeroize(serialized);
  }
}

/**
 * Creates a local-share key that may bootstrap exactly one trusted companion
 * anchor from the authenticated snapshot captured at share time.
 */
export async function createOwnedDatabaseLocalShareKeyFile(
  path: string,
  portableKey: Uint8Array,
  binding: DatabaseKeyBinding,
  bootstrapAnchor: DatabaseRevisionAnchor,
  options: DatabaseKeyFileCreateOptions,
): Promise<DatabaseKeyFileCreateResult> {
  let serialized: Uint8Array | undefined;
  try {
    serialized = await serializeDatabaseKeyFile(portableKey, binding, options, {
      formatVersion: LOCAL_SHARE_FORMAT_VERSION,
      bootstrapAnchor,
    });
    const result = await createOwnedSecureFile(
      path,
      serialized,
      'database-key-file',
      MAX_FILE_BYTES,
    );
    if (result.status === 'not-published') return result;
    return {
      ...result,
      publication: result.publication as DatabaseKeyFilePublication,
    };
  } finally {
    zeroize(serialized);
  }
}

/** Removes local-share bootstrap authority after a companion anchor exists. */
export async function consumeDatabaseLocalShareBootstrap(
  path: string,
  portableKey: Uint8Array,
  binding: DatabaseKeyBinding,
  passphrase: Uint8Array,
): Promise<void> {
  let serialized: Uint8Array | undefined;
  try {
    serialized = await serializeDatabaseKeyFile(
      portableKey,
      binding,
      { protection: { kind: 'passphrase', passphrase } },
      { formatVersion: LOCAL_SHARE_FORMAT_VERSION, bootstrapAnchor: null },
    );
    await writeSecureFile(path, serialized, 'replace');
  } finally {
    zeroize(serialized);
  }
}

export async function cleanupOwnedDatabaseKeyFile(
  publication: DatabaseKeyFilePublication,
): Promise<void> {
  await cleanupOwnedSecureFilePublication(publication, 'database-key-file');
}

export async function releaseOwnedDatabaseKeyFile(
  publication: DatabaseKeyFilePublication,
): Promise<void> {
  await releaseOwnedSecureFilePublication(publication, 'database-key-file');
}

async function serializeDatabaseKeyFile(
  portableKey: Uint8Array,
  binding: DatabaseKeyBinding,
  options: DatabaseKeyFileCreateOptions,
  payloadOptions?: Readonly<{
    formatVersion: typeof LOCAL_SHARE_FORMAT_VERSION;
    bootstrapAnchor: DatabaseRevisionAnchor | null;
  }>,
): Promise<Uint8Array> {
  requireByteLength(portableKey, KEY_BYTES, 'portable key');
  validateBinding(binding);
  const ownedKey = Uint8Array.from(portableKey);
  const ownedPassphrase = Uint8Array.from(options.protection.passphrase);
  let nonce: Uint8Array | undefined;
  let aad: Uint8Array | undefined;
  let kek: Uint8Array | undefined;
  let serialized: Uint8Array | undefined;
  let ownedPayload: Uint8Array | undefined;
  try {
    const derivation = createPassphraseDerivation();
    const encodedDerivation = encodeDerivation(derivation);
    kek = await derivePassphraseKek(ownedPassphrase, derivation);
    nonce = randomBytes(NONCE_BYTES);
    const formatVersion = payloadOptions?.formatVersion ?? OWNER_FORMAT_VERSION;
    aad = associatedData(binding, encodedDerivation, formatVersion);
    await sodium.ready;
    let plaintext: Uint8Array = ownedKey;
    if (formatVersion === LOCAL_SHARE_FORMAT_VERSION) {
      const bootstrapAnchor = payloadOptions?.bootstrapAnchor ?? null;
      if (bootstrapAnchor !== null) {
        verifyDatabaseRevisionAnchor(bootstrapAnchor, bootstrapAnchor, {
          requireExactVaultSet: true,
        });
        if (bootstrapAnchor.databaseId !== binding.databaseId) throw invalid();
      }
      const anchorBytes = Buffer.from(
        bootstrapAnchor === null ? '' : canonicalJson(bootstrapAnchor),
        'utf8',
      );
      ownedPayload = Buffer.alloc(5 + KEY_BYTES + anchorBytes.byteLength);
      ownedPayload[0] = bootstrapAnchor === null ? 0 : 1;
      Buffer.from(
        ownedPayload.buffer,
        ownedPayload.byteOffset,
        ownedPayload.byteLength,
      ).writeUInt32BE(anchorBytes.byteLength, 1);
      ownedPayload.set(ownedKey, 5);
      ownedPayload.set(anchorBytes, 5 + KEY_BYTES);
      zeroize(anchorBytes);
      plaintext = ownedPayload;
    }
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      plaintext,
      aad,
      null,
      nonce,
      kek,
    );
    serialized = Buffer.from(
      [
        BEGIN,
        `Version: ${String(formatVersion)}`,
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
    const result = serialized;
    serialized = undefined;
    return result;
  } finally {
    zeroize(ownedPayload);
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
    ciphertext = decodeBase64Url(
      parsed.ciphertext,
      parsed.formatVersion === OWNER_FORMAT_VERSION
        ? { exactBytes: KEY_BYTES }
        : { maximumBytes: MAX_FILE_BYTES },
    );
    tag = decodeBase64Url(parsed.tag, { exactBytes: TAG_BYTES });
    aad = associatedData(
      parsed.binding,
      parsed.encodedDerivation,
      parsed.formatVersion,
    );
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
    let localShareBootstrap: DatabaseRevisionAnchor | null | undefined;
    if (parsed.formatVersion === LOCAL_SHARE_FORMAT_VERSION) {
      if (portableKey.byteLength < 5 + KEY_BYTES) throw invalid();
      const view = Buffer.from(
        portableKey.buffer,
        portableKey.byteOffset,
        portableKey.byteLength,
      );
      const hasBootstrap = portableKey[0];
      if (hasBootstrap !== 0 && hasBootstrap !== 1) throw invalid();
      const anchorLength = view.readUInt32BE(1);
      if (portableKey.byteLength !== 5 + KEY_BYTES + anchorLength) throw invalid();
      const decodedPortableKey = Uint8Array.from(
        portableKey.subarray(5, 5 + KEY_BYTES),
      );
      const anchorBytes = portableKey.subarray(5 + KEY_BYTES);
      let payloadText: string | undefined;
      if (hasBootstrap === 0) {
        if (anchorLength !== 0) throw invalid();
        localShareBootstrap = null;
      } else {
        if (anchorLength === 0) throw invalid();
        payloadText = Buffer.from(anchorBytes).toString('utf8');
        const value: unknown = JSON.parse(payloadText);
        if (canonicalJson(value) !== payloadText) throw invalid();
        localShareBootstrap = localShareAnchorSchema.parse(value);
      }
      zeroize(portableKey);
      portableKey = decodedPortableKey;
      if (localShareBootstrap !== null) {
        verifyDatabaseRevisionAnchor(localShareBootstrap, localShareBootstrap, {
          requireExactVaultSet: true,
        });
        if (localShareBootstrap.databaseId !== parsed.binding.databaseId)
          throw invalid();
      }
    }
    requireByteLength(portableKey, KEY_BYTES, 'portable key');
    const result: ParsedDatabaseKeyFile = {
      binding: parsed.binding,
      portableKey: portableKey as PortableKey,
      ...(localShareBootstrap === undefined ? {} : { localShareBootstrap }),
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
  formatVersion: typeof OWNER_FORMAT_VERSION | typeof LOCAL_SHARE_FORMAT_VERSION;
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
    (lines[1] !== 'Version: 1' && lines[1] !== 'Version: 2') ||
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
      const formatVersion =
        lines[1] === 'Version: 1' ? OWNER_FORMAT_VERSION : LOCAL_SHARE_FORMAT_VERSION;
      const nonce = header(lines[6], 'Nonce');
      const ciphertext = header(lines[7], 'Ciphertext');
      const tag = header(lines[8], 'Tag');
      let nonceBytes: Uint8Array | undefined;
      let ciphertextBytes: Uint8Array | undefined;
      let tagBytes: Uint8Array | undefined;
      try {
        nonceBytes = decodeBase64Url(nonce, { exactBytes: NONCE_BYTES });
        ciphertextBytes = decodeBase64Url(
          ciphertext,
          formatVersion === OWNER_FORMAT_VERSION
            ? { exactBytes: KEY_BYTES }
            : { maximumBytes: MAX_FILE_BYTES },
        );
        if (
          formatVersion === LOCAL_SHARE_FORMAT_VERSION &&
          ciphertextBytes.byteLength < 5 + KEY_BYTES
        )
          throw invalid();
        tagBytes = decodeBase64Url(tag, { exactBytes: TAG_BYTES });
      } finally {
        zeroize(tagBytes);
        zeroize(ciphertextBytes);
        zeroize(nonceBytes);
      }
      return {
        formatVersion,
        binding,
        derivation,
        encodedDerivation,
        nonce,
        ciphertext,
        tag,
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
  formatVersion: typeof OWNER_FORMAT_VERSION | typeof LOCAL_SHARE_FORMAT_VERSION,
): Uint8Array {
  return Buffer.from(
    canonicalJson({
      domain: AAD_DOMAIN,
      format: BEGIN,
      version: formatVersion,
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
