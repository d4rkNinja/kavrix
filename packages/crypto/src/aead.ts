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
  const aadBytes = canonicalAssociatedData(aad);
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
    storedAadBytes = canonicalAssociatedData(parsed.aad);
    expectedAadBytes = canonicalAssociatedData(expected);
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
  const aad = associatedDataSchema.parse(associatedData);

  const fields = [
    lengthPrefixed(AAD_DOMAIN),
    uint32(aad.version),
    encodedAscii(aad.vaultId),
    encodedAscii(aad.entityType),
    encodedAscii(aad.entityId),
    aad.groupId === undefined
      ? Uint8Array.of(0)
      : concat(Uint8Array.of(1), encodedAscii(aad.groupId)),
    aad.parentId === undefined
      ? Uint8Array.of(0)
      : concat(Uint8Array.of(1), encodedAscii(aad.parentId)),
    encodedAscii(aad.purpose),
    uint32(aad.schemaVersion),
    uint32(aad.keyVersion),
  ];
  return concat(...fields);
}

export function canonicalAttachmentChunkData(
  associatedData: AssociatedData,
  chunkIndex: number,
): Uint8Array {
  const base = canonicalAssociatedData(associatedData);
  requireUint32(chunkIndex, 'chunk index', true);
  try {
    return concat(
      lengthPrefixed(ATTACHMENT_CHUNK_AAD_DOMAIN),
      base,
      uint32(1),
      uint32(chunkIndex),
    );
  } finally {
    zeroize(base);
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

function requireUint32(value: number, label: string, allowZero: boolean): void {
  if (
    !Number.isSafeInteger(value) ||
    value < (allowZero ? 0 : 1) ||
    value > 0xff_ff_ff_ff
  ) {
    throw new CryptoInputError(`Invalid ${label}`);
  }
}

function concat(...values: readonly Uint8Array[]): Uint8Array {
  return Buffer.concat(values.map((value) => Buffer.from(value)));
}
