import { randomBytes } from 'node:crypto';

import {
  MAX_CIPHERTEXT_CHARS,
  aeadEnvelopeSchema,
  associatedDataSchema,
  type AeadEnvelope,
  type AssociatedData,
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

const AEAD_KEY_BYTES = 32;
const AEAD_NONCE_BYTES = 24;
const AEAD_TAG_BYTES = 16;
const MAX_CIPHERTEXT_BYTES = Math.floor((MAX_CIPHERTEXT_CHARS * 3) / 4);
const AAD_DOMAIN = Buffer.from('credvault/aad/v1', 'ascii');
const ATTACHMENT_CHUNK_AAD_DOMAIN = Buffer.from(
  'credvault/attachment-secretstream/v1',
  'ascii',
);
const ASCII_FIELD = /^[\x21-\x7E]+$/;

export async function encryptAead(
  plaintext: Uint8Array,
  key: Uint8Array,
  associatedData: AssociatedData,
): Promise<AeadEnvelope> {
  requireByteLength(key, AEAD_KEY_BYTES);
  if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_CIPHERTEXT_BYTES) {
    throw new CryptoInputError('Plaintext byte length is outside the supported range');
  }
  const aad = associatedDataSchema.parse(associatedData);
  const aadBytes = canonicalAssociatedDataChecked(aad);
  const nonce = randomBytes(AEAD_NONCE_BYTES);
  try {
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      plaintext,
      aadBytes,
      null,
      nonce,
      key,
    );
    return aeadEnvelopeSchema.parse({
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(encrypted.ciphertext),
      authenticationTag: encodeBase64Url(encrypted.mac),
      aad,
      keyVersion: aad.keyVersion,
    });
  } finally {
    zeroize(aadBytes);
    zeroize(nonce);
  }
}

export async function decryptAead(
  envelope: AeadEnvelope,
  key: Uint8Array,
  expectedAssociatedData: AssociatedData,
): Promise<Uint8Array> {
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let authenticationTag: Uint8Array | undefined;
  let storedAadBytes: Uint8Array | undefined;
  let expectedAadBytes: Uint8Array | undefined;
  try {
    requireByteLength(key, AEAD_KEY_BYTES);
    const parsed = aeadEnvelopeSchema.parse(envelope);
    const expected = associatedDataSchema.parse(expectedAssociatedData);
    storedAadBytes = canonicalAssociatedDataChecked(parsed.aad);
    expectedAadBytes = canonicalAssociatedDataChecked(expected);
    if (!constantTimeEqual(storedAadBytes, expectedAadBytes)) {
      throw new AuthenticationError();
    }
    nonce = decodeBase64Url(parsed.nonce, { exactBytes: AEAD_NONCE_BYTES });
    ciphertext = decodeBase64Url(parsed.ciphertext, {
      maximumBytes: MAX_CIPHERTEXT_BYTES,
    });
    authenticationTag = decodeBase64Url(parsed.authenticationTag, {
      exactBytes: AEAD_TAG_BYTES,
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

export function canonicalAssociatedData(associatedData: AssociatedData): Uint8Array {
  return canonicalAssociatedDataChecked(associatedDataSchema.parse(associatedData));
}

/**
 * Serializes an already-validated `AssociatedData` to its canonical bytes.
 *
 * The parameter type is what makes skipping the schema parse sound: only
 * `associatedDataSchema.parse` produces that branded type, and both public
 * entry points above run that parse before calling this. The wire format is
 * identical to building each field as its own buffer and concatenating; the
 * difference is that the whole AAD is written into one right-sized buffer
 * instead of allocating and copying a dozen fragments twice.
 */
function canonicalAssociatedDataChecked(aad: AssociatedData): Uint8Array {
  const domain = AAD_DOMAIN;
  const vaultId = asciiBytes(aad.vaultId);
  const entityType = asciiBytes(aad.entityType);
  const entityId = asciiBytes(aad.entityId);
  const groupId = aad.groupId === undefined ? undefined : asciiBytes(aad.groupId);
  const parentId = aad.parentId === undefined ? undefined : asciiBytes(aad.parentId);
  const purpose = asciiBytes(aad.purpose);
  // 17 = 4 length bytes + 17-byte domain string, written twice below.
  const totalLength =
    4 +
    domain.byteLength +
    4 +
    4 +
    vaultId.byteLength +
    4 +
    entityType.byteLength +
    4 +
    entityId.byteLength +
    1 +
    (groupId === undefined ? 0 : 4 + groupId.byteLength) +
    1 +
    (parentId === undefined ? 0 : 4 + parentId.byteLength) +
    4 +
    purpose.byteLength +
    4 +
    4;
  const output = Buffer.allocUnsafe(totalLength);
  let offset = 0;
  offset = writeLengthPrefixed(output, offset, domain);
  offset = writeUint32(output, offset, aad.version);
  offset = writeLengthPrefixedAscii(output, offset, vaultId);
  offset = writeLengthPrefixedAscii(output, offset, entityType);
  offset = writeLengthPrefixedAscii(output, offset, entityId);
  if (groupId === undefined) {
    output[offset] = 0;
    offset += 1;
  } else {
    output[offset] = 1;
    offset = writeLengthPrefixedAscii(output, offset + 1, groupId);
  }
  if (parentId === undefined) {
    output[offset] = 0;
    offset += 1;
  } else {
    output[offset] = 1;
    offset = writeLengthPrefixedAscii(output, offset + 1, parentId);
  }
  offset = writeLengthPrefixedAscii(output, offset, purpose);
  offset = writeUint32(output, offset, aad.schemaVersion);
  writeUint32(output, offset, aad.keyVersion);
  return output;
}

export function canonicalAttachmentChunkData(
  associatedData: AssociatedData,
  chunkIndex: number,
): Uint8Array {
  const base = canonicalAssociatedData(associatedData);
  requireUint32(chunkIndex, 'chunk index', true);
  try {
    return appendChunkIndexToBase(base, chunkIndex);
  } finally {
    zeroize(base);
  }
}

/**
 * Prepares a per-stream chunk-AAD factory.
 *
 * The canonical base AAD is constant for a whole attachment stream, so a
 * stream parses and canonicalizes it once instead of rebuilding it for every
 * chunk. Each returned buffer is exactly the bytes
 * `canonicalAttachmentChunkData` would produce for the same context and
 * index; callers own and zeroize each returned buffer.
 */
export function createAttachmentChunkAadFactory(
  associatedData: AssociatedData,
): (chunkIndex: number) => Uint8Array {
  const base = canonicalAssociatedData(associatedData);
  return (chunkIndex: number): Uint8Array => {
    requireUint32(chunkIndex, 'chunk index', true);
    return appendChunkIndexToBase(base, chunkIndex);
  };
}

/** [len][domain][base][version=1][chunkIndex]. */
function appendChunkIndexToBase(base: Uint8Array, chunkIndex: number): Uint8Array {
  const domain = ATTACHMENT_CHUNK_AAD_DOMAIN;
  // 17 = 4 length bytes + 17-byte attachment-chunk domain string.
  const totalLength = 4 + domain.byteLength + base.byteLength + 4 + 4;
  const output = Buffer.allocUnsafe(totalLength);
  let offset = 0;
  offset = writeLengthPrefixed(output, offset, domain);
  output.set(base, offset);
  offset += base.byteLength;
  offset = writeUint32(output, offset, 1);
  writeUint32(output, offset, chunkIndex);
  return output;
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

function requireUint32(value: number, label: string, allowZero: boolean): void {
  if (
    !Number.isSafeInteger(value) ||
    value < (allowZero ? 0 : 1) ||
    value > 0xff_ff_ff_ff
  ) {
    throw new CryptoInputError(`Invalid ${label}`);
  }
}
