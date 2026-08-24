import { hkdfSync, randomBytes } from 'node:crypto';

import {
  authorizationEnvelopeContextSchema,
  authorizationStateDomainSchema,
  authorizationStateEnvelopeSchema,
  canonicalJson,
  type AuthorizationEnvelopeContext,
  type AuthorizationStateEnvelope,
  type AuthorizationScopeKind,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import { constantTimeEqual, decodeBase64Url, encodeBase64Url } from './bytes.js';
import { AuthenticationError, CryptoInputError } from './errors.js';

const STATE_ENVELOPE_KEY_BYTES = 32;
const STATE_ENVELOPE_NONCE_BYTES = 24;
const STATE_ENVELOPE_TAG_BYTES = 16;
const STATE_AAD_DOMAIN = Buffer.from('kavrix/authorization-state-aad/v1', 'ascii');
const MAX_STATE_PLAINTEXT_BYTES = 512 * 1024;

/** Crypto material of a sealed state document; callers persist it beside the authenticated scope fields. */
export type StateEnvelopeCryptoFields = Readonly<{
  nonce: string;
  ciphertext: string;
  authenticationTag: string;
}>;

function canonicalContextBytes(context: AuthorizationEnvelopeContext): Uint8Array {
  const parsed = authorizationEnvelopeContextSchema.parse(context);
  const encoded = Buffer.from(canonicalJson(parsed), 'utf8');
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(encoded.byteLength);
  return Buffer.concat([STATE_AAD_DOMAIN, length, encoded]);
}

/**
 * Encrypts one bounded plaintext into authenticated state-envelope fields.
 * The exact scope kind, scope identity, and monotonic sequence are
 * authenticated as associated data, so sealed bytes can never be transplanted
 * to another database or vault, or to another position in the state sequence,
 * without failing decryption.
 */
export async function encryptStateEnvelope(
  plaintext: Uint8Array,
  key: Uint8Array,
  context: AuthorizationEnvelopeContext,
): Promise<StateEnvelopeCryptoFields> {
  assertKey(key);
  if (
    !(plaintext instanceof Uint8Array) ||
    plaintext.byteLength === 0 ||
    plaintext.byteLength > MAX_STATE_PLAINTEXT_BYTES
  ) {
    throw new CryptoInputError(
      'State-envelope plaintext is empty or outside the supported range',
    );
  }
  const aadBytes = canonicalContextBytes(context);
  const nonce = randomBytes(STATE_ENVELOPE_NONCE_BYTES);
  try {
    await sodium.ready;
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
      plaintext,
      aadBytes,
      null,
      nonce,
      key,
    );
    return {
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(encrypted.ciphertext),
      authenticationTag: encodeBase64Url(encrypted.mac),
    };
  } finally {
    zeroFill(aadBytes);
    zeroFill(nonce);
  }
}

/**
 * Decrypts one sealed state document against the expected context. The scope
 * fields carried by the document are compared with the caller-expected
 * context in constant time before decryption, and every authenticated byte is
 * verified by the AEAD; any mismatch fails closed with a generic error.
 */
export async function decryptStateEnvelope(
  envelope: AuthorizationStateEnvelope,
  key: Uint8Array,
  expectedContext: AuthorizationEnvelopeContext,
): Promise<Uint8Array> {
  let nonce: Uint8Array | undefined;
  let ciphertext: Uint8Array | undefined;
  let authenticationTag: Uint8Array | undefined;
  let storedBytes: Uint8Array | undefined;
  let expectedBytes: Uint8Array | undefined;
  try {
    assertKey(key);
    const parsed = authorizationStateEnvelopeSchema.parse(envelope);
    const declaredContext = authorizationEnvelopeContextSchema.parse({
      domain: authorizationStateDomainSchema.value,
      scopeKind: parsed.scopeKind,
      scopeId: parsed.scopeId,
      sequence: parsed.sequence,
    });
    storedBytes = canonicalContextBytes(declaredContext);
    expectedBytes = canonicalContextBytes(expectedContext);
    if (!constantTimeEqual(storedBytes, expectedBytes)) {
      throw new AuthenticationError();
    }
    nonce = decodeBase64Url(parsed.nonce, { exactBytes: STATE_ENVELOPE_NONCE_BYTES });
    authenticationTag = decodeBase64Url(parsed.authenticationTag, {
      exactBytes: STATE_ENVELOPE_TAG_BYTES,
    });
    ciphertext = decodeBase64Url(parsed.ciphertext, {
      maximumBytes: MAX_STATE_PLAINTEXT_BYTES + 64,
    });
    await sodium.ready;
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
      null,
      ciphertext,
      authenticationTag,
      expectedBytes,
      nonce,
      key,
    );
  } catch (error) {
    if (error instanceof CryptoInputError) throw error;
    throw new AuthenticationError();
  } finally {
    zeroFill(nonce);
    zeroFill(ciphertext);
    zeroFill(authenticationTag);
    zeroFill(storedBytes);
    zeroFill(expectedBytes);
  }
}

function assertKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.byteLength !== STATE_ENVELOPE_KEY_BYTES) {
    throw new CryptoInputError('State-envelope keys must encode exactly 32 bytes');
  }
}

const STATE_KEY_SALT = Buffer.from('kavrix/authorization-state-key-salt/v1', 'ascii');

/**
 * Derives the purpose-bound 32-byte key that seals one scope's authorization
 * state. The root key (database root or vault root) never seals state bytes
 * directly: derivation is domain-separated and additionally binds the exact
 * scope identity.
 */
export function deriveAuthorizationStateKey(
  rootKey: Uint8Array,
  scope: Readonly<{ scopeKind: AuthorizationScopeKind; scopeId: string }>,
): Uint8Array {
  if (
    !(rootKey instanceof Uint8Array) ||
    rootKey.byteLength !== STATE_ENVELOPE_KEY_BYTES
  ) {
    throw new CryptoInputError(
      'Authorization state root keys must encode exactly 32 bytes',
    );
  }
  const parsedScope = authorizationEnvelopeContextSchema
    .pick({
      scopeKind: true,
      scopeId: true,
    })
    .parse(scope);
  const info = Buffer.from(canonicalJson(parsedScope), 'utf8');
  const derived = hkdfSync(
    'sha256',
    rootKey,
    STATE_KEY_SALT,
    info,
    STATE_ENVELOPE_KEY_BYTES,
  );
  return new Uint8Array(derived);
}

function zeroFill(value: Uint8Array | undefined): void {
  value?.fill(0);
}
