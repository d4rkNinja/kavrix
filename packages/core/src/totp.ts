import { createHmac, timingSafeEqual } from 'node:crypto';
import { inspect } from 'node:util';

import type { SecretValue } from '@kavrix/schemas';

import { ValidationError } from './errors.js';

export const MIN_TOTP_SECRET_BYTES = 16;
export const MAX_TOTP_SECRET_BYTES = 128;
export const MIN_TOTP_PERIOD_SECONDS = 5;
export const MAX_TOTP_PERIOD_SECONDS = 3_600;
export const MAX_TOTP_UNIX_TIME_SECONDS = 253_402_300_799;
export const MAX_TOTP_VERIFICATION_WINDOW = 10;

export type TotpAlgorithm = 'sha1' | 'sha256' | 'sha512';
export type TotpDigits = 6 | 7 | 8;

export type TotpConfiguration = Readonly<{
  algorithm: TotpAlgorithm;
  digits: TotpDigits;
  periodSeconds: number;
}>;

export type TotpVerificationWindow = Readonly<{
  pastSteps: number;
  futureSteps: number;
}>;

declare const totpCodeBrand: unique symbol;
export type TotpCode = string & { readonly [totpCodeBrand]: true };

export type TotpGenerationResult = Readonly<{
  code: TotpCode;
  remainingSeconds: number;
}>;

const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const base32Values = new Map(
  Array.from(base32Alphabet).map((character, index) => [character, index] as const),
);

function invalidTotp(message = 'The TOTP parameters are invalid.'): never {
  throw new ValidationError(message);
}

function decodeCanonicalBase32(encoded: SecretValue): Buffer {
  if (!/^[A-Z2-7]+$/.test(encoded)) {
    invalidTotp('The TOTP seed must use canonical unpadded uppercase base32.');
  }
  if ([1, 3, 6].includes(encoded.length % 8)) {
    invalidTotp('The TOTP seed has a non-canonical base32 length.');
  }
  const decodedLength = Math.floor((encoded.length * 5) / 8);
  if (decodedLength < MIN_TOTP_SECRET_BYTES || decodedLength > MAX_TOTP_SECRET_BYTES) {
    invalidTotp('The decoded TOTP seed length is outside the supported range.');
  }

  const output = Buffer.alloc(decodedLength);
  let accumulator = 0;
  let availableBits = 0;
  let outputIndex = 0;

  try {
    for (const character of encoded) {
      const value = base32Values.get(character);
      if (value === undefined) {
        invalidTotp('The TOTP seed must use canonical unpadded uppercase base32.');
      }
      accumulator = (accumulator << 5) | value;
      availableBits += 5;
      if (availableBits >= 8) {
        availableBits -= 8;
        output[outputIndex] = (accumulator >>> availableBits) & 0xff;
        outputIndex += 1;
        accumulator &= (1 << availableBits) - 1;
      }
    }
    if (availableBits > 0 && accumulator !== 0) {
      invalidTotp('The TOTP seed has non-canonical trailing bits.');
    }
    if (outputIndex !== output.length) {
      invalidTotp();
    }
    return output;
  } catch (error) {
    output.fill(0);
    throw error;
  }
}

function validateConfiguration(configuration: TotpConfiguration): void {
  if (!['sha1', 'sha256', 'sha512'].includes(configuration.algorithm)) {
    invalidTotp('The TOTP digest algorithm is unsupported.');
  }
  if (![6, 7, 8].includes(configuration.digits)) {
    invalidTotp('TOTP codes must contain between 6 and 8 digits.');
  }
  if (
    !Number.isSafeInteger(configuration.periodSeconds) ||
    configuration.periodSeconds < MIN_TOTP_PERIOD_SECONDS ||
    configuration.periodSeconds > MAX_TOTP_PERIOD_SECONDS
  ) {
    invalidTotp(
      `The TOTP period must be an integer from ${String(MIN_TOTP_PERIOD_SECONDS)} to ${String(MAX_TOTP_PERIOD_SECONDS)} seconds.`,
    );
  }
}

function validateUnixTime(unixTimeSeconds: number): void {
  if (
    !Number.isSafeInteger(unixTimeSeconds) ||
    unixTimeSeconds < 0 ||
    unixTimeSeconds > MAX_TOTP_UNIX_TIME_SECONDS
  ) {
    invalidTotp('The TOTP Unix time is outside the supported range.');
  }
}

function validateWindow(window: TotpVerificationWindow): void {
  for (const value of [window.pastSteps, window.futureSteps]) {
    if (
      !Number.isSafeInteger(value) ||
      value < 0 ||
      value > MAX_TOTP_VERIFICATION_WINDOW
    ) {
      invalidTotp(
        `Each TOTP verification window direction must be from 0 to ${String(MAX_TOTP_VERIFICATION_WINDOW)} steps.`,
      );
    }
  }
}

function hotp(
  secret: Buffer,
  counter: number,
  configuration: TotpConfiguration,
): TotpCode {
  const counterBytes = Buffer.alloc(8);
  let digest: Buffer | undefined;
  try {
    counterBytes.writeBigUInt64BE(BigInt(counter));
    digest = createHmac(configuration.algorithm, secret).update(counterBytes).digest();
    const offsetByte = digest[digest.length - 1];
    if (offsetByte === undefined) {
      throw new Error('TOTP digest generation failed.');
    }
    const offset = offsetByte & 0x0f;
    const binary = digest.readUInt32BE(offset) & 0x7f_ff_ff_ff;
    return String(binary % 10 ** configuration.digits).padStart(
      configuration.digits,
      '0',
    ) as TotpCode;
  } finally {
    counterBytes.fill(0);
    digest?.fill(0);
  }
}

function counterAt(unixTimeSeconds: number, periodSeconds: number): number {
  return Math.floor(unixTimeSeconds / periodSeconds);
}

export class TotpSecret {
  readonly #bytes: Buffer;
  #destroyed = false;

  private constructor(bytes: Buffer) {
    this.#bytes = bytes;
    Object.freeze(this);
  }

  static fromBase32(encoded: SecretValue): TotpSecret {
    return new TotpSecret(decodeCanonicalBase32(encoded));
  }

  get destroyed(): boolean {
    return this.#destroyed;
  }

  destroy(): void {
    if (!this.#destroyed) {
      this.#bytes.fill(0);
      this.#destroyed = true;
    }
  }

  generate(
    configuration: TotpConfiguration,
    unixTimeSeconds: number,
  ): TotpGenerationResult {
    this.#assertAvailable();
    validateConfiguration(configuration);
    validateUnixTime(unixTimeSeconds);
    const counter = counterAt(unixTimeSeconds, configuration.periodSeconds);
    return Object.freeze({
      code: hotp(this.#bytes, counter, configuration),
      remainingSeconds:
        configuration.periodSeconds - (unixTimeSeconds % configuration.periodSeconds),
    });
  }

  verify(
    code: SecretValue,
    configuration: TotpConfiguration,
    unixTimeSeconds: number,
    window: TotpVerificationWindow = { pastSteps: 1, futureSteps: 1 },
  ): boolean {
    this.#assertAvailable();
    validateConfiguration(configuration);
    validateUnixTime(unixTimeSeconds);
    validateWindow(window);
    if (!new RegExp(`^[0-9]{${String(configuration.digits)}}$`).test(code)) {
      invalidTotp('The TOTP code has an invalid format.');
    }

    const supplied = Buffer.from(code, 'ascii');
    const currentCounter = counterAt(unixTimeSeconds, configuration.periodSeconds);
    let matched = 0;
    try {
      for (let step = -window.pastSteps; step <= window.futureSteps; step += 1) {
        const candidateCounter = currentCounter + step;
        const validCounter = candidateCounter >= 0;
        const expected = Buffer.from(
          hotp(this.#bytes, validCounter ? candidateCounter : 0, configuration),
          'ascii',
        );
        try {
          matched |= Number(validCounter) & Number(timingSafeEqual(supplied, expected));
        } finally {
          expected.fill(0);
        }
      }
      return matched !== 0;
    } finally {
      supplied.fill(0);
    }
  }

  toString(): string {
    return 'TotpSecret(<redacted>)';
  }

  toJSON(): string {
    return '[REDACTED]';
  }

  [inspect.custom](): string {
    return this.toString();
  }

  #assertAvailable(): void {
    if (this.#destroyed) {
      throw new ValidationError('The TOTP seed is no longer available.');
    }
  }
}

export function parseTotpSecret(encoded: SecretValue): TotpSecret {
  return TotpSecret.fromBase32(encoded);
}

export function generateTotpCode(
  secret: TotpSecret,
  configuration: TotpConfiguration,
  unixTimeSeconds: number,
): TotpGenerationResult {
  return secret.generate(configuration, unixTimeSeconds);
}

export function verifyTotpCode(
  secret: TotpSecret,
  code: SecretValue,
  configuration: TotpConfiguration,
  unixTimeSeconds: number,
  window?: TotpVerificationWindow,
): boolean {
  return window === undefined
    ? secret.verify(code, configuration, unixTimeSeconds)
    : secret.verify(code, configuration, unixTimeSeconds, window);
}
