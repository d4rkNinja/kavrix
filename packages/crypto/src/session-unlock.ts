import { randomBytes } from 'node:crypto';

import {
  sessionUnlockAssociatedDataSchema,
  sessionUnlockEnvelopeSchema,
  type SessionUnlockAssociatedData,
  type SessionUnlockEnvelope,
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

const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const TAG_BYTES = 16;
const MAX_PLAINTEXT_BYTES = 4096;
const SESSION_UNLOCK_AAD_DOMAIN = Buffer.from('kavrix/session-unlock-aad/v1', 'ascii');

function canonicalSessionUnlockAssociatedData(
  associatedData: SessionUnlockAssociatedData,
): Uint8Array {
  const fields: string[] = [
    SESSION_UNLOCK_AAD_DOMAIN.toString('ascii'),
    String(associatedData.version),
    associatedData.kind,
    associatedData.profileId,
    associatedData.createdAt,
  ];
  if (associatedData.databaseId !== undefined) {
    fields.push(associatedData.databaseId);
  }
  if (associatedData.ttlHours !== undefined) {
    fields.push(String(associatedData.ttlHours));
  }
  return Buffer.from(fields.join('\u0000'), 'utf8');
}

/**
 * Seals one local session-unlock payload (the passphrase-equivalent unlock
 * material) with a 32-byte key held by the OS keychain. The associated data
 * binds the envelope to one profile/database, one creation time, and one
 * TTL so a session file cannot be transplanted or replayed across targets.
 */
export async function sealSessionUnlock(
  plaintext: Uint8Array,
  key: Uint8Array,
  associatedData: SessionUnlockAssociatedData,
): Promise<SessionUnlockEnvelope> {
  requireByteLength(key, KEY_BYTES);
  const parsedAad = sessionUnlockAssociatedDataSchema.parse(associatedData);
  if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    throw new CryptoInputError(
      'Session unlock plaintext byte length is outside the supported range',
    );
  }
  const aadBytes = canonicalSessionUnlockAssociatedData(parsedAad);
  const nonce = randomBytes(NONCE_BYTES);
  let ciphertext: Uint8Array | undefined;
  let authenticationTag: Uint8Array | undefined;
  try {
    await sodium.ready;
    const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      plaintext,
      aadBytes,
      null,
      nonce,
      key,
    );
    ciphertext = sealed.ciphertext;
    authenticationTag = sealed.mac;
    return sessionUnlockEnvelopeSchema.parse({
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ciphertext),
      authenticationTag: encodeBase64Url(authenticationTag),
      aad: parsedAad,
    });
  } finally {
    zeroize(aadBytes);
    zeroize(nonce);
    zeroize(ciphertext);
    zeroize(authenticationTag);
  }
}

/**
 * Opens one session-unlock envelope. Any transplanted, truncated, or
 * tampered envelope fails authentication without revealing which part of
 * the input was close.
 */
export async function openSessionUnlock(
  envelope: SessionUnlockEnvelope,
  key: Uint8Array,
  expectedAssociatedData: SessionUnlockAssociatedData,
): Promise<Uint8Array> {
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let authenticationTag: Uint8Array | undefined;
  let storedAadBytes: Uint8Array | undefined;
  let expectedAadBytes: Uint8Array | undefined;
  try {
    requireByteLength(key, KEY_BYTES);
    const parsed = sessionUnlockEnvelopeSchema.parse(envelope);
    const expected = sessionUnlockAssociatedDataSchema.parse(expectedAssociatedData);
    storedAadBytes = canonicalSessionUnlockAssociatedData(parsed.aad);
    expectedAadBytes = canonicalSessionUnlockAssociatedData(expected);
    if (!constantTimeEqual(storedAadBytes, expectedAadBytes)) {
      throw new AuthenticationError();
    }
    nonce = decodeBase64Url(parsed.nonce, { exactBytes: NONCE_BYTES });
    ciphertext = decodeBase64Url(parsed.ciphertext, {
      maximumBytes: MAX_PLAINTEXT_BYTES * 2,
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
