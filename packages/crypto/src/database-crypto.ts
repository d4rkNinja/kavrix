import { hkdfSync, randomBytes } from 'node:crypto';

import {
  MAX_CIPHERTEXT_CHARS,
  databaseAeadEnvelopeSchema,
  databaseAssociatedDataSchema,
  databasePortableKeySlotSchema,
  databaseRecoverySlotSchema,
  type DatabaseAeadEnvelope,
  type DatabaseAssociatedData,
  type DatabasePortableKeySlot,
  type DatabaseRecoverySlot,
  type KeySlotId,
  type Sha256Digest,
  type Timestamp,
  type DatabaseId,
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
const ASCII_FIELD = /^[\x21-\x7E]+$/;

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

export function canonicalDatabaseAssociatedData(
  associatedData: DatabaseAssociatedData,
): Uint8Array {
  const aad = databaseAssociatedDataSchema.parse(associatedData);
  const vault =
    aad.vaultId === undefined
      ? lengthPrefixed(Uint8Array.of(0))
      : concat(lengthPrefixed(Uint8Array.of(1)), encodedAscii(aad.vaultId));

  return concat(
    lengthPrefixed(DATABASE_AAD_DOMAIN),
    lengthPrefixed(uint32(aad.version)),
    encodedAscii(aad.databaseId),
    vault,
    encodedAscii(aad.entityType),
    encodedAscii(aad.entityId),
    encodedAscii(aad.purpose),
    lengthPrefixed(uint32(aad.schemaVersion)),
    lengthPrefixed(uint32(aad.keyVersion)),
    lengthPrefixed(uint64(aad.revision)),
    encodedAscii(aad.metadataDigest),
  );
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
  const aadBytes = canonicalDatabaseAssociatedData(aad);
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
    storedAadBytes = canonicalDatabaseAssociatedData(parsed.aad);
    expectedAadBytes = canonicalDatabaseAssociatedData(expected);
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
    const result = new Uint8Array(
      hkdfSync('sha256', key, salt, Buffer.from(expectedContext, 'ascii'), KEY_BYTES),
    );
    try {
      return Uint8Array.from(result) as KeyEncryptionKey;
    } finally {
      zeroize(result);
    }
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

function encodedAscii(value: string): Uint8Array {
  if (!ASCII_FIELD.test(value)) {
    throw new CryptoInputError('Associated-data fields must be printable ASCII');
  }
  return lengthPrefixed(Buffer.from(value, 'ascii'));
}

function lengthPrefixed(value: Uint8Array): Uint8Array {
  return concat(uint32(value.byteLength), value);
}

function uint32(value: number): Uint8Array {
  const output = Buffer.allocUnsafe(4);
  output.writeUInt32BE(value);
  return output;
}

function uint64(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new CryptoInputError('Invalid database revision');
  }
  const output = Buffer.allocUnsafe(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

function concat(...values: readonly Uint8Array[]): Uint8Array {
  return Buffer.concat(values.map((value) => Buffer.from(value)));
}
