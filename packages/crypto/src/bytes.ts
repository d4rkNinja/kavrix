import { timingSafeEqual } from 'node:crypto';

import { CryptoInputError } from './errors.js';

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export function encodeBase64Url(value: Uint8Array): string {
  return bufferView(value).toString('base64url');
}

export function decodeBase64Url(
  value: string,
  options: { readonly exactBytes?: number; readonly maximumBytes?: number } = {},
): Uint8Array {
  if (value.length === 0 || !BASE64URL_PATTERN.test(value) || value.includes('=')) {
    throw new CryptoInputError();
  }

  const maximumEncodedLength =
    options.maximumBytes === undefined
      ? undefined
      : Math.ceil((options.maximumBytes * 4) / 3);
  if (maximumEncodedLength !== undefined && value.length > maximumEncodedLength) {
    throw new CryptoInputError();
  }

  const decoded = Buffer.from(value, 'base64url');
  if (
    encodeBase64Url(decoded) !== value ||
    (options.exactBytes !== undefined && decoded.byteLength !== options.exactBytes) ||
    (options.maximumBytes !== undefined && decoded.byteLength > options.maximumBytes)
  ) {
    zeroize(decoded);
    throw new CryptoInputError();
  }
  return new Uint8Array(decoded.buffer, decoded.byteOffset, decoded.byteLength);
}

export function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    const maximumLength = Math.max(left.byteLength, right.byteLength, 1);
    const paddedLeft = Buffer.alloc(maximumLength);
    const paddedRight = Buffer.alloc(maximumLength);
    bufferView(left).copy(paddedLeft);
    bufferView(right).copy(paddedRight);
    timingSafeEqual(paddedLeft, paddedRight);
    zeroize(paddedLeft);
    zeroize(paddedRight);
    return false;
  }
  return timingSafeEqual(bufferView(left), bufferView(right));
}

export function zeroize(value: Uint8Array | undefined): void {
  value?.fill(0);
}

export function requireByteLength(
  value: Uint8Array,
  expected: number,
  label = 'key',
): void {
  if (value.byteLength !== expected) {
    throw new CryptoInputError(`${label} must be ${String(expected)} bytes`);
  }
}

export function copyBytes(value: Uint8Array): Uint8Array {
  return Uint8Array.from(value);
}

function bufferView(value: Uint8Array): Buffer {
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}
