import { inspect } from 'node:util';

import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';

import { secretValueSchema } from '@kavrix/schemas';

import {
  MAX_TOTP_UNIX_TIME_SECONDS,
  ValidationError,
  generateTotpCode,
  parseTotpSecret,
  verifyTotpCode,
  type TotpAlgorithm,
  type TotpConfiguration,
} from '../src/index.js';

const seeds: Readonly<Record<TotpAlgorithm, string>> = {
  sha1: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  sha256: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
  sha512:
    'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA',
};

const rfc6238Vectors = [
  [59, '94287082', '46119246', '90693936'],
  [1_111_111_109, '07081804', '68084774', '25091201'],
  [1_111_111_111, '14050471', '67062674', '99943326'],
  [1_234_567_890, '89005924', '91819424', '93441116'],
  [2_000_000_000, '69279037', '90698825', '38618901'],
  [20_000_000_000, '65353130', '77737706', '47863826'],
] as const;

function configuration(algorithm: TotpAlgorithm, digits = 8): TotpConfiguration {
  return { algorithm, digits: digits as 6 | 7 | 8, periodSeconds: 30 };
}

describe('RFC 6238 TOTP', () => {
  it.each(rfc6238Vectors)(
    'matches the official vectors at Unix time %i',
    (unixTimeSeconds, sha1, sha256, sha512) => {
      const expected = { sha1, sha256, sha512 } as const;
      for (const algorithm of ['sha1', 'sha256', 'sha512'] as const) {
        const secret = parseTotpSecret(secretValueSchema.parse(seeds[algorithm]));
        try {
          expect(
            generateTotpCode(secret, configuration(algorithm), unixTimeSeconds).code,
          ).toBe(expected[algorithm]);
        } finally {
          secret.destroy();
        }
      }
    },
  );

  it('returns the exact lifetime remaining in the current period', () => {
    const secret = parseTotpSecret(secretValueSchema.parse(seeds.sha1));
    try {
      expect(generateTotpCode(secret, configuration('sha1'), 59)).toEqual({
        code: '94287082',
        remainingSeconds: 1,
      });
      expect(generateTotpCode(secret, configuration('sha1'), 60).remainingSeconds).toBe(
        30,
      );
    } finally {
      secret.destroy();
    }
  });

  it('verifies every configured step without short-circuiting the public result', () => {
    const secret = parseTotpSecret(secretValueSchema.parse(seeds.sha1));
    const config = configuration('sha1', 6);
    try {
      const previous = generateTotpCode(secret, config, 30).code;
      const current = generateTotpCode(secret, config, 60).code;
      const future = generateTotpCode(secret, config, 90).code;
      const window = { pastSteps: 1, futureSteps: 1 };

      expect(
        verifyTotpCode(secret, secretValueSchema.parse(previous), config, 60, window),
      ).toBe(true);
      expect(
        verifyTotpCode(secret, secretValueSchema.parse(current), config, 60, window),
      ).toBe(true);
      expect(
        verifyTotpCode(secret, secretValueSchema.parse(future), config, 60, window),
      ).toBe(true);
      expect(
        verifyTotpCode(secret, secretValueSchema.parse(previous), config, 90, {
          pastSteps: 1,
          futureSteps: 0,
        }),
      ).toBe(false);
    } finally {
      secret.destroy();
    }
  });

  it('round-trips property-generated times, algorithms, and code widths', () => {
    const secret = parseTotpSecret(secretValueSchema.parse(seeds.sha512));
    try {
      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: MAX_TOTP_UNIX_TIME_SECONDS }),
          fc.constantFrom<TotpAlgorithm>('sha1', 'sha256', 'sha512'),
          fc.constantFrom<6 | 7 | 8>(6, 7, 8),
          fc.integer({ min: 5, max: 3_600 }),
          (unixTimeSeconds, algorithm, digits, periodSeconds) => {
            const config = { algorithm, digits, periodSeconds };
            const result = generateTotpCode(secret, config, unixTimeSeconds);
            expect(result.code).toMatch(new RegExp(`^[0-9]{${String(digits)}}$`));
            expect(result.remainingSeconds).toBeGreaterThanOrEqual(1);
            expect(result.remainingSeconds).toBeLessThanOrEqual(periodSeconds);
            expect(
              verifyTotpCode(
                secret,
                secretValueSchema.parse(result.code),
                config,
                unixTimeSeconds,
                { pastSteps: 0, futureSteps: 0 },
              ),
            ).toBe(true);
          },
        ),
        { numRuns: 200 },
      );
    } finally {
      secret.destroy();
    }
  });
});

describe('TOTP input hardening', () => {
  it.each([
    seeds.sha1.toLowerCase(),
    `${seeds.sha1}=`,
    ` ${seeds.sha1}`,
    'AAAAAAAAAAAAAAAAAAAAAAAA',
    'A'.repeat(207),
    'GEZDGNBVGY3TQOJQGEZDGNBVGZ',
    'GEZDGNBVGY3TQOJQGEZDGNBVGYA',
  ])('rejects non-canonical or out-of-bounds seed %#', (encoded) => {
    expect(() => parseTotpSecret(secretValueSchema.parse(encoded))).toThrow(
      ValidationError,
    );
  });

  it.each([
    [{ algorithm: 'md5', digits: 6, periodSeconds: 30 }, 0],
    [{ algorithm: 'sha1', digits: 5, periodSeconds: 30 }, 0],
    [{ algorithm: 'sha1', digits: 9, periodSeconds: 30 }, 0],
    [{ algorithm: 'sha1', digits: 6, periodSeconds: 4 }, 0],
    [{ algorithm: 'sha1', digits: 6, periodSeconds: 3_601 }, 0],
    [{ algorithm: 'sha1', digits: 6, periodSeconds: 30 }, -1],
    [
      { algorithm: 'sha1', digits: 6, periodSeconds: 30 },
      MAX_TOTP_UNIX_TIME_SECONDS + 1,
    ],
  ])('rejects invalid generation parameters %#', (config, unixTimeSeconds) => {
    const secret = parseTotpSecret(secretValueSchema.parse(seeds.sha1));
    try {
      expect(() =>
        generateTotpCode(secret, config as TotpConfiguration, unixTimeSeconds),
      ).toThrow(ValidationError);
    } finally {
      secret.destroy();
    }
  });

  it('rejects malformed codes and unbounded verification windows', () => {
    const secret = parseTotpSecret(secretValueSchema.parse(seeds.sha1));
    const config = configuration('sha1', 6);
    try {
      expect(() =>
        verifyTotpCode(secret, secretValueSchema.parse('12345'), config, 60),
      ).toThrow(ValidationError);
      expect(() =>
        verifyTotpCode(secret, secretValueSchema.parse('123456'), config, 60, {
          pastSteps: 11,
          futureSteps: 0,
        }),
      ).toThrow(ValidationError);
      expect(() =>
        verifyTotpCode(secret, secretValueSchema.parse('123456'), config, 60, {
          pastSteps: 0,
          futureSteps: -1,
        }),
      ).toThrow(ValidationError);
    } finally {
      secret.destroy();
    }
  });

  it('redacts inspection and JSON and fails closed after best-effort destruction', () => {
    const secret = parseTotpSecret(secretValueSchema.parse(seeds.sha1));
    expect(String(secret)).toBe('TotpSecret(<redacted>)');
    expect(inspect(secret)).toBe('TotpSecret(<redacted>)');
    expect(JSON.stringify(secret)).toBe('"[REDACTED]"');
    expect(inspect(secret)).not.toContain(seeds.sha1);
    secret.destroy();
    secret.destroy();
    expect(secret.destroyed).toBe(true);
    expect(() => generateTotpCode(secret, configuration('sha1'), 59)).toThrow(
      ValidationError,
    );
    expect(() =>
      verifyTotpCode(
        secret,
        secretValueSchema.parse('12345678'),
        configuration('sha1'),
        59,
      ),
    ).toThrow(ValidationError);
  });
});
