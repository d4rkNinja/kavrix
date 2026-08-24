import { decryptStateEnvelope, encryptStateEnvelope } from '@kavrix/crypto';
import {
  authorizationStateDocumentSchema,
  authorizationStateEnvelopeSchema,
  canonicalJson,
  timestampSchema,
  MAX_AUTHORIZATION_STATE_BYTES,
  type AuthorizationEnvelopeContext,
  type AuthorizationScopeKind,
  type AuthorizationStateDocument,
  type AuthorizationStateEnvelope,
} from '@kavrix/schemas';

import {
  ProtectedJsonDocumentError,
  readProtectedJsonDocument,
  transitionProtectedJsonDocument,
  writeProtectedJsonDocument,
  type CanonicalJsonDocumentSchema,
} from './canonical-json-document.js';
import { PortableKeyFileError } from './errors.js';

export const AUTHORIZATION_STATE_SUFFIX = '.authorization';
const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

export type AuthorizationScope = Readonly<{
  scopeKind: AuthorizationScopeKind;
  scopeId: string;
}>;

export type AuthorizationStateErrorCode =
  | 'INTEGRITY_FAILURE'
  | 'INVALID_FORMAT'
  | 'KEY_INVALID'
  | 'OPERATION_FAILED'
  | 'SCOPE_MISMATCH';

const messages = {
  INTEGRITY_FAILURE:
    'The protected authorization state failed authentication; it may be corrupted or tampered with.',
  INVALID_FORMAT: 'The protected authorization state is malformed.',
  KEY_INVALID: 'The authorization state key is invalid.',
  OPERATION_FAILED: 'The authorization state operation failed.',
  SCOPE_MISMATCH: 'The authorization state belongs to a different database or vault.',
} as const satisfies Readonly<Record<AuthorizationStateErrorCode, string>>;

export class AuthorizationStateFileError extends Error {
  public override readonly name = 'AuthorizationStateFileError';

  public constructor(public readonly code: AuthorizationStateErrorCode) {
    super(messages[code]);
  }
}

/** Sidecar path convention beside the owning key file. */
export function authorizationStatePath(keyFile: string): string {
  return `${keyFile}${AUTHORIZATION_STATE_SUFFIX}`;
}

function envelopeDocumentSchema(): CanonicalJsonDocumentSchema<AuthorizationStateEnvelope> {
  return { parse: parseEnvelope };
}

const envelopeOptions = {
  schema: envelopeDocumentSchema(),
  maximumBytes: MAX_AUTHORIZATION_STATE_BYTES,
};

function parseEnvelope(value: unknown): AuthorizationStateEnvelope {
  return JSON.parse(
    canonicalJson(authorizationStateEnvelopeSchema.parse(value)),
  ) as AuthorizationStateEnvelope;
}

function contextFor(
  scope: AuthorizationScope,
  sequence: number,
): AuthorizationEnvelopeContext {
  return {
    domain: 'kavrix/authorization-state/v1',
    scopeKind: scope.scopeKind,
    scopeId: scope.scopeId,
    sequence,
  };
}

async function sealState(
  key: Uint8Array,
  scope: AuthorizationScope,
  previous: Readonly<{ createdAt: string; sequence: number }>,
  nextState: AuthorizationStateDocument,
): Promise<AuthorizationStateEnvelope> {
  const updatedAt = timestampSchema.parse(new Date().toISOString());
  const validated = authorizationStateDocumentSchema.parse(nextState);
  const plaintext = UTF8_ENCODER.encode(canonicalJson(validated));
  try {
    const fields = await encryptStateEnvelope(
      plaintext,
      key,
      contextFor(scope, previous.sequence),
    );
    return authorizationStateEnvelopeSchema.parse({
      format: 'kavrix-authorization-state',
      version: 1,
      scopeKind: scope.scopeKind,
      scopeId: scope.scopeId,
      sequence: previous.sequence,
      createdAt: previous.createdAt,
      updatedAt,
      nonce: fields.nonce,
      ciphertext: fields.ciphertext,
      authenticationTag: fields.authenticationTag,
    });
  } finally {
    plaintext.fill(0);
  }
}

function unsealEnvelope(
  document: AuthorizationStateEnvelope,
  key: Uint8Array,
  scope: AuthorizationScope,
): Promise<AuthorizationStateDocument> {
  if (document.scopeKind !== scope.scopeKind || document.scopeId !== scope.scopeId) {
    throw new AuthorizationStateFileError('SCOPE_MISMATCH');
  }
  return decryptStateEnvelope(document, key, contextFor(scope, document.sequence))
    .then((plaintext) => {
      try {
        return authorizationStateDocumentSchema.parse(
          JSON.parse(UTF8_DECODER.decode(plaintext)) as unknown,
        );
      } finally {
        plaintext.fill(0);
      }
    })
    .catch((error: unknown) => {
      throw mapUnsealError(error);
    });
}

function mapUnsealError(error: unknown): unknown {
  if (error instanceof AuthorizationStateFileError) return error;
  if (error instanceof SyntaxError) {
    return new AuthorizationStateFileError('INVALID_FORMAT');
  }
  if (error instanceof Error && error.name === 'ZodError') {
    return new AuthorizationStateFileError('INVALID_FORMAT');
  }
  if (error instanceof Error && error.message.includes('Authentication failed')) {
    return new AuthorizationStateFileError('INTEGRITY_FAILURE');
  }
  if (error instanceof Error && error.message.includes('32 bytes')) {
    return new AuthorizationStateFileError('KEY_INVALID');
  }
  if (error instanceof ProtectedJsonDocumentError) {
    return new AuthorizationStateFileError('INVALID_FORMAT');
  }
  if (error instanceof RangeError || error instanceof TypeError) {
    return new AuthorizationStateFileError('INVALID_FORMAT');
  }
  return error;
}

/**
 * Reads one sealed authorization state, returning null only when the sidecar
 * does not exist. Every other failure — malformed format, foreign scope,
 * broken authentication — fails closed.
 */
export async function readAuthorizationStateFile(
  path: string,
  key: Uint8Array,
  scope: AuthorizationScope,
): Promise<Readonly<{
  envelope: AuthorizationStateEnvelope;
  state: AuthorizationStateDocument;
}> | null> {
  let document: AuthorizationStateEnvelope;
  try {
    document = await readProtectedJsonDocument(path, envelopeOptions);
  } catch (error) {
    if (error instanceof PortableKeyFileError && error.code === 'KEY_FILE_NOT_FOUND') {
      return null;
    }
    if (error instanceof ProtectedJsonDocumentError) {
      throw new AuthorizationStateFileError('INVALID_FORMAT');
    }
    throw mapReadError(error);
  }
  const state = await unsealEnvelope(document, key, scope);
  return { envelope: document, state };
}

function mapReadError(error: unknown): unknown {
  if (error instanceof PortableKeyFileError) {
    return new AuthorizationStateFileError('OPERATION_FAILED');
  }
  return error;
}

/**
 * Creates the sealed sidecar at sequence zero. Creation is exclusive; a
 * concurrent creator wins and the loser must re-read before mutating.
 */
export async function initializeAuthorizationStateFile(
  path: string,
  key: Uint8Array,
  scope: AuthorizationScope,
  initialState: AuthorizationStateDocument,
): Promise<void> {
  const sealed = await sealState(
    key,
    scope,
    { createdAt: now(), sequence: 0 },
    initialState,
  );
  try {
    await writeProtectedJsonDocument(path, sealed, 'create', envelopeOptions);
  } catch (error) {
    if (
      error instanceof PortableKeyFileError &&
      error.code === 'KEY_FILE_ALREADY_EXISTS'
    ) {
      throw error;
    }
    if (error instanceof ProtectedJsonDocumentError) {
      throw new AuthorizationStateFileError('INVALID_FORMAT');
    }
    throw error instanceof AuthorizationStateFileError
      ? error
      : new AuthorizationStateFileError('OPERATION_FAILED');
  }
}

export type AuthorizationStateTransition<T> = Readonly<{
  nextState: AuthorizationStateDocument;
  result: T;
}>;

/**
 * Runs one authenticated state mutation under the protected-file lock. The
 * callback receives the decrypted current state and its sequence and returns
 * the complete next state; publication bumps the authenticated sequence by
 * exactly one so stale writers can never interleave.
 */
export async function transitionAuthorizationStateFile<T>(
  path: string,
  key: Uint8Array,
  scope: AuthorizationScope,
  callback: (
    currentState: AuthorizationStateDocument,
    currentSequence: number,
  ) => AuthorizationStateTransition<T> | Promise<AuthorizationStateTransition<T>>,
): Promise<T> {
  try {
    return await transitionProtectedJsonDocument(
      path,
      envelopeOptions,
      async (currentEnvelope) => {
        const currentState = await unsealEnvelope(currentEnvelope, key, scope);
        const transition = await callback(currentState, currentEnvelope.sequence);
        const nextEnvelope = await sealState(
          key,
          scope,
          {
            createdAt: currentEnvelope.createdAt,
            sequence: currentEnvelope.sequence + 1,
          },
          transition.nextState,
        );
        return { document: nextEnvelope, result: transition.result };
      },
    );
  } catch (error) {
    if (error instanceof ProtectedJsonDocumentError) {
      throw new AuthorizationStateFileError('INVALID_FORMAT');
    }
    if (error instanceof AuthorizationStateFileError) throw error;
    if (error instanceof Error && error.message.includes('Authentication failed')) {
      throw new AuthorizationStateFileError('INTEGRITY_FAILURE');
    }
    throw mapReadError(error);
  }
}

function now(): string {
  return timestampSchema.parse(new Date().toISOString());
}
