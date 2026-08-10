import type { FastifyRequest } from 'fastify';

import { apiBearerTokenSchema, type ApiBearerToken } from '@kavrix/schemas';

import { ApiAuthenticationError, ApiValidationError } from './errors.js';

interface RuntimeSchema<Output> {
  parse(value: unknown): Output;
}

const FORBIDDEN_FIELDS = new Set([
  'key',
  'passphrase',
  'plaintext',
  'portablekey',
  'recoverykey',
  'rootkey',
  'rootkeybytes',
  'secret',
  'secretkey',
  'unwrappedrootkey',
  'unwrappedvrk',
  'vaultrootkey',
  'vrk',
]);
const NON_SECRET_SIZE_FIELDS = new Set(['plaintextbytes']);
const MAX_INSPECTED_VALUES = 100_000;

export function parseRequest<Output>(
  schema: RuntimeSchema<Output>,
  value: unknown,
): Output {
  try {
    return schema.parse(value);
  } catch {
    throw new ApiValidationError();
  }
}

export function bearerToken(request: FastifyRequest): ApiBearerToken {
  const authorization = request.headers.authorization;
  if (
    typeof authorization !== 'string' ||
    !authorization.startsWith('Bearer ') ||
    authorization.includes(' ', 7)
  ) {
    throw new ApiAuthenticationError();
  }
  try {
    return apiBearerTokenSchema.parse(authorization.slice(7));
  } catch {
    throw new ApiAuthenticationError();
  }
}

/**
 * Parses an independently generated successor credential supplied by the
 * caller. Reusing this header makes an interrupted exchange idempotent without
 * making the successor derivable from the one-time bearer credential.
 */
export function successorToken(request: FastifyRequest): ApiBearerToken {
  const value = request.headers['x-kavrix-successor-token'];
  if (typeof value !== 'string') {
    throw new ApiAuthenticationError();
  }
  try {
    return apiBearerTokenSchema.parse(value);
  } catch {
    throw new ApiAuthenticationError();
  }
}

export function rejectSecretFields(value: unknown): void {
  const pending: unknown[] = [value];
  let inspected = 0;
  while (pending.length > 0) {
    inspected += 1;
    if (inspected > MAX_INSPECTED_VALUES) {
      throw new ApiValidationError();
    }
    const current = pending.pop();
    if (Array.isArray(current)) {
      const values = current as readonly unknown[];
      if (pending.length + values.length > MAX_INSPECTED_VALUES) {
        throw new ApiValidationError();
      }
      for (const nested of values) pending.push(nested);
      continue;
    }
    if (typeof current !== 'object' || current === null) {
      continue;
    }
    for (const [key, nested] of Object.entries(current)) {
      const normalized = key.replaceAll(/[^A-Za-z0-9]/g, '').toLowerCase();
      if (NON_SECRET_SIZE_FIELDS.has(normalized)) {
        pending.push(nested);
        continue;
      }
      if (
        FORBIDDEN_FIELDS.has(normalized) ||
        normalized.startsWith('plaintext') ||
        normalized.startsWith('unwrapped') ||
        normalized.includes('passphrase') ||
        normalized.includes('portablekey') ||
        normalized.includes('recoverykey')
      ) {
        throw new ApiValidationError();
      }
      pending.push(nested);
    }
  }
}
