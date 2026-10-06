import { createHmac, hkdfSync, randomBytes } from 'node:crypto';

import {
  MAX_CIPHERTEXT_CHARS,
  canonicalJson,
  databaseAeadEnvelopeSchema,
  databaseAssociatedDataSchema,
  databasePortableKeySlotSchema,
  databaseRecoverySlotSchema,
  sha256DigestSchema,
  type DatabaseAeadEnvelope,
  type DatabaseAssociatedData,
  type DatabasePortableKeySlot,
  type DatabaseRecoverySlot,
  type KeySlotId,
  type Sha256Digest,
  type Timestamp,
  type DatabaseId,
  type DatabaseVaultDocument,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import {
  constantTimeEqual,
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from './bytes.js';
import { AuthenticationError, CryptoInputError } from './errors.js';
import {
  generateKdfSalt,
  generateRecoveryKey,
  type DatabaseRootKey,
  type KeyEncryptionKey,
  type RecoveryKey,
  type VaultRootKey,
} from './keys.js';

const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;
const MAX_CIPHERTEXT_BYTES = Math.floor((MAX_CIPHERTEXT_CHARS * 3) / 4);
const DATABASE_AAD_DOMAIN = Buffer.from('kavrix/database-aad/v1', 'ascii');
const DATABASE_ROOT_WRAP_DOMAIN = 'kavrix/database-root-wrap/v1';
const DATABASE_RECOVERY_WRAP_DOMAIN = 'kavrix/database-recovery-wrap/v1';
const DATABASE_VAULT_PAYLOAD_DIGEST_DOMAIN = 'kavrix/database-vault-payload-digest/v1';
const ASCII_FIELD = /^[\x21-\x7E]+$/;

export type DatabaseVaultPayloadDigestMetadata = Pick<
  DatabaseVaultDocument,
  | 'databaseId'
  | 'id'
  | 'schemaVersion'
  | 'cryptographicVersion'
  | 'currentKeyVersion'
  | 'databaseRevision'
  | 'revision'
  | 'createdAt'
  | 'updatedAt'
>;

export interface DatabaseSlotBinding {
  readonly databaseId: DatabaseId;
  readonly slotId: KeySlotId;
  readonly schemaVersion: number;
  readonly keyVersion: number;
  readonly revision: number;
  readonly metadataDigest: Sha256Digest;
}

export interface DatabaseSlotIdentity extends DatabaseSlotBinding {
  readonly createdAt: Timestamp;
}

export interface CreatedDatabaseRecoverySlot {
  readonly slot: DatabaseRecoverySlot;
  readonly recoveryKey: RecoveryKey;
}

/**
 * Compute the released VRK-keyed digest that binds a database-vault payload to
 * its exact legacy metadata projection. This deliberately remains separate
 * from AEAD v1 encoding so historical envelopes retain byte compatibility.
 */
export function computeDatabaseVaultPayloadMetadataDigest(
  metadata: DatabaseVaultPayloadDigestMetadata,
  vaultRootKey: Uint8Array,
  plaintext: Uint8Array,
): Sha256Digest {
  requireByteLength(vaultRootKey, KEY_BYTES, 'vault root key');
  const digestKey = new Uint8Array(
    hkdfSync(
      'sha256',
      vaultRootKey,
      new Uint8Array(KEY_BYTES),
      Buffer.from(`${DATABASE_VAULT_PAYLOAD_DIGEST_DOMAIN}/key`, 'ascii'),
      KEY_BYTES,
    ),
  );
  try {
    return sha256DigestSchema.parse(
      createHmac('sha256', digestKey)
        .update(DATABASE_VAULT_PAYLOAD_DIGEST_DOMAIN, 'utf8')
        .update('\0')
        .update(
          canonicalJson({
            databaseId: metadata.databaseId,
            id: metadata.id,
            schemaVersion: metadata.schemaVersion,
            cryptographicVersion: metadata.cryptographicVersion,
            currentKeyVersion: metadata.currentKeyVersion,
            databaseRevision: metadata.databaseRevision,
            revision: metadata.revision,
            createdAt: metadata.createdAt,
            updatedAt: metadata.updatedAt,
          }),
          'utf8',
        )
        .update('\0')
        .update(plaintext)
        .digest('base64url'),
    );
  } finally {
    zeroize(digestKey);
  }
}

export function canonicalDatabaseAssociatedData(
  associatedData: DatabaseAssociatedData,
): Uint8Array {
  return canonicalDatabaseAssociatedDataChecked(
    databaseAssociatedDataSchema.parse(associatedData),
  );
}

/**
 * Serializes an already-validated `DatabaseAssociatedData` to its canonical
 * bytes in one right-sized buffer.
 *
 * Only `databaseAssociatedDataSchema.parse` produces the branded parameter
 * type, and every public entry point runs that parse before calling this, so
 * skipping the second parse inside is sound. The byte layout is identical to
 * the fragment-concatenation form this replaces.
 */
function canonicalDatabaseAssociatedDataChecked(
  aad: DatabaseAssociatedData,
): Uint8Array {
  const databaseId = asciiBytes(aad.databaseId);
  const vaultId = aad.vaultId === undefined ? undefined : asciiBytes(aad.vaultId);
  const entityType = asciiBytes(aad.entityType);
  const entityId = asciiBytes(aad.entityId);
  const purpose = asciiBytes(aad.purpose);
  const metadataDigest = asciiBytes(aad.metadataDigest);
  const totalLength =
    4 +
    DATABASE_AAD_DOMAIN.byteLength +
    4 +
    4 +
    4 +
    databaseId.byteLength +
    4 +
    1 +
    (vaultId === undefined ? 0 : 4 + vaultId.byteLength) +
    4 +
    entityType.byteLength +
    4 +
    entityId.byteLength +
    4 +
    purpose.byteLength +
    4 +
    4 +
    4 +
    4 +
    4 +
    8 +
    4 +
    metadataDigest.byteLength;
  const output = Buffer.allocUnsafe(totalLength);
  let offset = 0;
  offset = writeLengthPrefixed(output, offset, DATABASE_AAD_DOMAIN);
  offset = writeUint32(output, offset, 4);
  offset = writeUint32(output, offset, aad.version);
  offset = writeLengthPrefixedAscii(output, offset, databaseId);
  // Presence marker is itself length-prefixed: [len=1][0|1], then the vault id
  // field when present.
  offset = writeUint32(output, offset, 1);
  if (vaultId === undefined) {
    output[offset] = 0;
    offset += 1;
  } else {
    output[offset] = 1;
    offset = writeLengthPrefixedAscii(output, offset + 1, vaultId);
  }
  offset = writeLengthPrefixedAscii(output, offset, entityType);
  offset = writeLengthPrefixedAscii(output, offset, entityId);
  offset = writeLengthPrefixedAscii(output, offset, purpose);
  offset = writeUint32(output, offset, 4);
  offset = writeUint32(output, offset, aad.schemaVersion);
  offset = writeUint32(output, offset, 4);
  offset = writeUint32(output, offset, aad.keyVersion);
  offset = writeUint32(output, offset, 8);
  offset = writeBigUint64(output, offset, aad.revision);
  writeLengthPrefixedAscii(output, offset, metadataDigest);
  return output;
}

export async function encryptDatabaseAead(
  plaintext: Uint8Array,
  key: Uint8Array,
  associatedData: DatabaseAssociatedData,
): Promise<DatabaseAeadEnvelope> {
  requireByteLength(key, KEY_BYTES);
  if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_CIPHERTEXT_BYTES) {
    throw new CryptoInputError('Plaintext byte length is outside the supported range');
  }
  const aad = databaseAssociatedDataSchema.parse(associatedData);
  const aadBytes = canonicalDatabaseAssociatedDataChecked(aad);
  const nonce = randomBytes(NONCE_BYTES);
  let ciphertext: Uint8Array | undefined;
  let authenticationTag: Uint8Array | undefined;
  try {
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      plaintext,
      aadBytes,
      null,
      nonce,
      key,
    );
    ciphertext = encrypted.ciphertext;
    authenticationTag = encrypted.mac;
    return databaseAeadEnvelopeSchema.parse({
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ciphertext),
      authenticationTag: encodeBase64Url(authenticationTag),
      aad,
      keyVersion: aad.keyVersion,
    });
  } finally {
    zeroize(aadBytes);
    zeroize(nonce);
    zeroize(ciphertext);
    zeroize(authenticationTag);
  }
}

export async function decryptDatabaseAead(
  envelope: DatabaseAeadEnvelope,
  key: Uint8Array,
  expectedAssociatedData: DatabaseAssociatedData,
): Promise<Uint8Array> {
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let authenticationTag: Uint8Array | undefined;
  let storedAadBytes: Uint8Array | undefined;
  let expectedAadBytes: Uint8Array | undefined;
  try {
    requireByteLength(key, KEY_BYTES);
    const parsed = databaseAeadEnvelopeSchema.parse(envelope);
    const expected = databaseAssociatedDataSchema.parse(expectedAssociatedData);
    storedAadBytes = canonicalDatabaseAssociatedDataChecked(parsed.aad);
    expectedAadBytes = canonicalDatabaseAssociatedDataChecked(expected);
    if (!constantTimeEqual(storedAadBytes, expectedAadBytes)) {
      throw new AuthenticationError();
    }
    nonce = decodeBase64Url(parsed.nonce, { exactBytes: NONCE_BYTES });
    ciphertext = decodeBase64Url(parsed.ciphertext, {
      maximumBytes: MAX_CIPHERTEXT_BYTES,
    });
    authenticationTag = decodeBase64Url(parsed.authenticationTag, {
      exactBytes: TAG_BYTES,
    });
    await sodium.ready;
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
      null,
      ciphertext,
      authenticationTag,
      expectedAadBytes,
      nonce,
      key,
    );
  } catch {
    throw new AuthenticationError();
  } finally {
    zeroize(nonce);
    zeroize(ciphertext);
    zeroize(authenticationTag);
    zeroize(storedAadBytes);
    zeroize(expectedAadBytes);
  }
}

export async function createDatabaseKeySlot(
  identity: DatabaseSlotIdentity,
  portableKey: Uint8Array,
  databaseRootKey: DatabaseRootKey,
): Promise<DatabasePortableKeySlot> {
  const context = databaseRootSlotContext(identity);
  const derivation = createDatabaseDerivation(DATABASE_ROOT_WRAP_DOMAIN);
  const kek = deriveDatabaseKek(portableKey, derivation, DATABASE_ROOT_WRAP_DOMAIN);
  try {
    const wrappedDatabaseRoot = await encryptDatabaseAead(
      databaseRootKey,
      kek,
      context,
    );
    await verifyDatabaseRootKey(databaseRootKey, wrappedDatabaseRoot, kek, context);
    return databasePortableKeySlotSchema.parse({
      slotVersion: 1,
      id: identity.slotId,
      type: 'portable-key',
      state: 'active',
      keyVersion: identity.keyVersion,
      derivation,
      wrappedDatabaseRoot,
      createdAt: identity.createdAt,
    });
  } finally {
    zeroize(kek);
  }
}

export async function unlockDatabaseKeySlot(
  slot: DatabasePortableKeySlot,
  portableKey: Uint8Array,
  expectedBinding: DatabaseSlotBinding,
): Promise<DatabaseRootKey> {
  let kek: KeyEncryptionKey | undefined;
  try {
    const parsed = requireDatabasePortableSlot(slot, expectedBinding);
    kek = deriveDatabaseKek(portableKey, parsed.derivation, DATABASE_ROOT_WRAP_DOMAIN);
    return await unwrapDatabaseRoot(
      parsed.wrappedDatabaseRoot,
      kek,
      databaseRootSlotContext(expectedBinding),
    );
  } catch {
    throw new AuthenticationError();
  } finally {
    zeroize(kek);
  }
}

export async function createDatabaseRecoverySlot(
  identity: DatabaseSlotIdentity,
  databaseRootKey: DatabaseRootKey,
): Promise<CreatedDatabaseRecoverySlot> {
  const recoveryKey = generateRecoveryKey();
  let completed = false;
  let kek: KeyEncryptionKey | undefined;
  try {
    const context = databaseRootSlotContext(identity);
    const derivation = createDatabaseDerivation(DATABASE_RECOVERY_WRAP_DOMAIN);
    kek = deriveDatabaseKek(recoveryKey, derivation, DATABASE_RECOVERY_WRAP_DOMAIN);
    const wrappedDatabaseRoot = await encryptDatabaseAead(
      databaseRootKey,
      kek,
      context,
    );
    await verifyDatabaseRootKey(databaseRootKey, wrappedDatabaseRoot, kek, context);
    const slot = databaseRecoverySlotSchema.parse({
      slotVersion: 1,
      id: identity.slotId,
      type: 'recovery-key',
      state: 'active',
      keyVersion: identity.keyVersion,
      derivation,
      wrappedDatabaseRoot,
      createdAt: identity.createdAt,
    });
    completed = true;
    return { slot, recoveryKey };
  } finally {
    zeroize(kek);
    if (!completed) {
      zeroize(recoveryKey);
    }
  }
}

export async function unlockDatabaseRecoverySlot(
  slot: DatabaseRecoverySlot,
  recoveryKey: Uint8Array,
  expectedBinding: DatabaseSlotBinding,
): Promise<DatabaseRootKey> {
  let kek: KeyEncryptionKey | undefined;
  try {
    const parsed = requireDatabaseRecoverySlot(slot, expectedBinding);
    kek = deriveDatabaseKek(
      recoveryKey,
      parsed.derivation,
      DATABASE_RECOVERY_WRAP_DOMAIN,
    );
    return await unwrapDatabaseRoot(
      parsed.wrappedDatabaseRoot,
      kek,
      databaseRootSlotContext(expectedBinding),
    );
  } catch {
    throw new AuthenticationError();
  } finally {
    zeroize(kek);
  }
}

export async function encryptDatabaseCatalog(
  plaintext: Uint8Array,
  databaseRootKey: DatabaseRootKey,
  context: DatabaseAssociatedData,
): Promise<DatabaseAeadEnvelope> {
  assertDatabaseCatalogContext(context);
  return encryptDatabaseAead(plaintext, databaseRootKey, context);
}

export async function decryptDatabaseCatalog(
  envelope: DatabaseAeadEnvelope,
  databaseRootKey: DatabaseRootKey,
  context: DatabaseAssociatedData,
): Promise<Uint8Array> {
  try {
    assertDatabaseCatalogContext(context);
    return await decryptDatabaseAead(envelope, databaseRootKey, context);
  } catch {
    throw new AuthenticationError();
  }
}

export async function wrapVaultRootForDatabase(
  vaultRootKey: VaultRootKey,
  databaseRootKey: DatabaseRootKey,
  context: DatabaseAssociatedData,
): Promise<DatabaseAeadEnvelope> {
  assertWrappedVaultRootContext(context);
  requireByteLength(vaultRootKey, KEY_BYTES, 'vault root key');
  return encryptDatabaseAead(vaultRootKey, databaseRootKey, context);
}

export async function unwrapVaultRootForDatabase(
  envelope: DatabaseAeadEnvelope,
  databaseRootKey: DatabaseRootKey,
  context: DatabaseAssociatedData,
): Promise<VaultRootKey> {
  try {
    assertWrappedVaultRootContext(context);
    const vaultRootKey = await decryptDatabaseAead(envelope, databaseRootKey, context);
    try {
      requireByteLength(vaultRootKey, KEY_BYTES, 'vault root key');
      return vaultRootKey as VaultRootKey;
    } catch {
      zeroize(vaultRootKey);
      throw new AuthenticationError();
    }
  } catch (error) {
    if (error instanceof AuthenticationError) {
      throw error;
    }
    throw new AuthenticationError();
  }
}

function databaseRootSlotContext(
  identity: DatabaseSlotBinding,
): DatabaseAssociatedData {
  return databaseAssociatedDataSchema.parse({
    version: 1,
    databaseId: identity.databaseId,
    entityType: 'wrapped-database-root',
    entityId: identity.slotId,
    purpose: 'database-root',
    schemaVersion: identity.schemaVersion,
    keyVersion: identity.keyVersion,
    revision: identity.revision,
    metadataDigest: identity.metadataDigest,
  });
}

function createDatabaseDerivation(context: string): {
  readonly algorithm: 'hkdf-sha256';
  readonly version: 1;
  readonly salt: string;
  readonly context: string;
  readonly outputLength: 32;
} {
  const salt = generateKdfSalt();
  try {
    return {
      algorithm: 'hkdf-sha256',
      version: 1,
      salt: encodeBase64Url(salt),
      context,
      outputLength: 32,
    };
  } finally {
    zeroize(salt);
  }
}

function deriveDatabaseKek(
  key: Uint8Array,
  derivation: {
    readonly salt: string;
    readonly context: string;
    readonly outputLength: number;
  },
  expectedContext: string,
): KeyEncryptionKey {
  requireByteLength(key, KEY_BYTES, 'database wrapping key');
  if (derivation.context !== expectedContext || derivation.outputLength !== KEY_BYTES) {
    throw new CryptoInputError('Invalid database key derivation');
  }
  const salt = decodeBase64Url(derivation.salt, { exactBytes: KEY_BYTES });
  try {
    // `hkdfSync` returns a fresh ArrayBuffer for this call, so the view over it
    // is exclusively owned; copying it again would add an allocation and wipe
    // per unwrap.
    return new Uint8Array(
      hkdfSync('sha256', key, salt, Buffer.from(expectedContext, 'ascii'), KEY_BYTES),
    ) as KeyEncryptionKey;
  } finally {
    zeroize(salt);
  }
}

function requireDatabasePortableSlot(
  slot: DatabasePortableKeySlot,
  expectedBinding: DatabaseSlotBinding,
): DatabasePortableKeySlot {
  try {
    const parsed = databasePortableKeySlotSchema.parse(slot);
    if (
      parsed.id !== expectedBinding.slotId ||
      parsed.keyVersion !== expectedBinding.keyVersion ||
      !sameDatabaseRootContext(parsed.wrappedDatabaseRoot.aad, expectedBinding)
    ) {
      throw new AuthenticationError();
    }
    return parsed;
  } catch {
    throw new AuthenticationError();
  }
}

function requireDatabaseRecoverySlot(
  slot: DatabaseRecoverySlot,
  expectedBinding: DatabaseSlotBinding,
): DatabaseRecoverySlot {
  try {
    const parsed = databaseRecoverySlotSchema.parse(slot);
    if (
      parsed.state !== 'active' ||
      parsed.id !== expectedBinding.slotId ||
      parsed.keyVersion !== expectedBinding.keyVersion ||
      !sameDatabaseRootContext(parsed.wrappedDatabaseRoot.aad, expectedBinding)
    ) {
      throw new AuthenticationError();
    }
    return parsed;
  } catch {
    throw new AuthenticationError();
  }
}

function sameDatabaseRootContext(
  context: DatabaseAssociatedData,
  binding: DatabaseSlotBinding,
): boolean {
  return (
    context.databaseId === binding.databaseId &&
    context.entityType === 'wrapped-database-root' &&
    context.entityId === binding.slotId &&
    context.purpose === 'database-root' &&
    context.schemaVersion === binding.schemaVersion &&
    context.keyVersion === binding.keyVersion &&
    context.revision === binding.revision &&
    context.metadataDigest === binding.metadataDigest &&
    context.vaultId === undefined
  );
}

async function unwrapDatabaseRoot(
  envelope: DatabaseAeadEnvelope,
  key: Uint8Array,
  context: DatabaseAssociatedData,
): Promise<DatabaseRootKey> {
  const root = await decryptDatabaseAead(envelope, key, context);
  try {
    requireByteLength(root, KEY_BYTES, 'database root key');
    return root as DatabaseRootKey;
  } catch {
    zeroize(root);
    throw new AuthenticationError();
  }
}

async function verifyDatabaseRootKey(
  expected: DatabaseRootKey,
  envelope: DatabaseAeadEnvelope,
  key: Uint8Array,
  context: DatabaseAssociatedData,
): Promise<void> {
  const candidate = await unwrapDatabaseRoot(envelope, key, context);
  try {
    if (!constantTimeEqual(expected, candidate)) {
      throw new CryptoInputError('Database root key verification failed');
    }
  } finally {
    zeroize(candidate);
  }
}

function assertDatabaseCatalogContext(context: DatabaseAssociatedData): void {
  const parsed = databaseAssociatedDataSchema.parse(context);
  if (
    parsed.entityType !== 'database-catalog' ||
    parsed.entityId !== parsed.databaseId ||
    parsed.purpose !== 'catalog' ||
    parsed.vaultId !== undefined
  ) {
    throw new CryptoInputError('Expected database catalog associated data');
  }
}

function assertWrappedVaultRootContext(context: DatabaseAssociatedData): void {
  const parsed = databaseAssociatedDataSchema.parse(context);
  if (
    parsed.entityType !== 'wrapped-vault-root' ||
    parsed.purpose !== 'vault-root' ||
    parsed.vaultId === undefined ||
    parsed.entityId !== parsed.vaultId
  ) {
    throw new CryptoInputError('Expected wrapped vault root associated data');
  }
}

function asciiBytes(value: string): Uint8Array {
  if (!ASCII_FIELD.test(value)) {
    throw new CryptoInputError('Associated-data fields must be printable ASCII');
  }
  return Buffer.from(value, 'ascii');
}

function writeLengthPrefixedAscii(
  output: Buffer,
  offset: number,
  value: Uint8Array,
): number {
  return writeLengthPrefixed(output, offset, value);
}

function writeLengthPrefixed(
  output: Buffer,
  offset: number,
  value: Uint8Array,
): number {
  const next = writeUint32(output, offset, value.byteLength);
  output.set(value, next);
  return next + value.byteLength;
}

function writeUint32(output: Buffer, offset: number, value: number): number {
  output.writeUInt32BE(value, offset);
  return offset + 4;
}

function writeBigUint64(output: Buffer, offset: number, value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new CryptoInputError('Invalid database revision');
  }
  output.writeBigUInt64BE(BigInt(value), offset);
  return offset + 8;
}
