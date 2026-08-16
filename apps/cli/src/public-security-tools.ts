import type { Writable } from 'node:stream';

import type {
  PassphraseGeneratorPolicy,
  PasswordGeneratorPolicy,
  SafePassphraseSeparator,
  TotpAlgorithm,
  TotpConfiguration,
} from '@kavrix/core';
import type * as CoreSecurityToolsNamespace from '@kavrix/core';
import { secretValueSchema } from '@kavrix/schemas';
import { z } from 'zod';

import { CliUsageError } from './errors.js';
import { SECRET_INPUT_OPTIONS, type SecretInputPort } from './secret-input.js';

type CoreSecurityTools = typeof CoreSecurityToolsNamespace;

type SecretOutputBoundary = Readonly<{
  stdout: Writable;
  stdoutIsTty: boolean;
}>;

const PASSWORD_ALPHABETS = Object.freeze({
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}:,.?',
});

export async function executePasswordGeneration(
  boundary: SecretOutputBoundary,
  options: Readonly<Record<string, unknown>>,
): Promise<void> {
  requireSecretOutputAuthorization(boundary, options);
  const core = await import('@kavrix/core');
  const parsed = parsePasswordOptions(options, core);
  const classes = (
    [
      ['lowercase', PASSWORD_ALPHABETS.lowercase, parsed.lowercaseMin],
      ['uppercase', PASSWORD_ALPHABETS.uppercase, parsed.uppercaseMin],
      ['digits', PASSWORD_ALPHABETS.digits, parsed.digitsMin],
      ['symbols', PASSWORD_ALPHABETS.symbols, parsed.symbolsMin],
    ] as const
  )
    .filter((entry) => entry[2] > 0)
    .map(([name, alphabet, minimum]) => ({ name, alphabet, minimum }));
  const policy: PasswordGeneratorPolicy = {
    length: parsed.length,
    classes,
    ...(parsed.exclude === undefined ? {} : { excludedCharacters: parsed.exclude }),
  };
  try {
    boundary.stdout.write(`${core.generatePassword(policy)}\n`);
  } catch (error) {
    if (error instanceof core.ValidationError) {
      throw new CliUsageError('The password generation policy is invalid.');
    }
    throw error;
  }
}

export async function executePassphraseGeneration(
  boundary: SecretOutputBoundary,
  options: Readonly<Record<string, unknown>>,
): Promise<void> {
  requireSecretOutputAuthorization(boundary, options);
  const core = await import('@kavrix/core');
  const parsed = parsePassphraseOptions(options, core);
  const policy: PassphraseGeneratorPolicy = {
    wordCount: parsed.words,
    separator: parsed.separator,
    capitalize: parsed.capitalize,
    includeNumber: parsed.digit,
    excludedWords: parsed.excludeWord,
  };
  try {
    boundary.stdout.write(`${core.generatePassphrase(policy)}\n`);
  } catch (error) {
    if (error instanceof core.ValidationError) {
      throw new CliUsageError('The passphrase generation policy is invalid.');
    }
    throw error;
  }
}

export async function executeTotpGeneration(
  boundary: SecretOutputBoundary,
  secrets: SecretInputPort,
  options: Readonly<Record<string, unknown>>,
): Promise<void> {
  requireSecretOutputAuthorization(boundary, options);
  const core = await import('@kavrix/core');
  const parsed = parseTotpOptions(options, core);
  const acquired = await secrets.read({
    kind: SECRET_INPUT_OPTIONS.totpSeed.kind,
    fromStdin: parsed.secretStdin,
  });
  let secret: ReturnType<CoreSecurityTools['parseTotpSecret']> | undefined;
  try {
    const seed = secretValueSchema.safeParse(acquired);
    if (!seed.success) throw new CliUsageError('The TOTP request is invalid.');
    secret = core.parseTotpSecret(seed.data);
    const configuration: TotpConfiguration = {
      algorithm: parsed.algorithm,
      digits: parsed.digits,
      periodSeconds: parsed.period,
    };
    const unixTimeSeconds = parsed.time ?? Math.floor(Date.now() / 1_000);
    const result = core.generateTotpCode(secret, configuration, unixTimeSeconds);
    boundary.stdout.write(`${result.code}\n`);
  } catch (error) {
    if (error instanceof CliUsageError) throw error;
    if (error instanceof core.ValidationError) {
      throw new CliUsageError('The TOTP request is invalid.');
    }
    throw error;
  } finally {
    secret?.destroy();
  }
}

function requireSecretOutputAuthorization(
  boundary: SecretOutputBoundary,
  options: Readonly<Record<string, unknown>>,
): void {
  if (boundary.stdoutIsTty || options['stdout'] === true) return;
  throw new CliUsageError(
    'Secret output requires an interactive terminal or explicit --stdout acknowledgement.',
  );
}

function parsePasswordOptions(
  options: Readonly<Record<string, unknown>>,
  core: CoreSecurityTools,
): Readonly<{
  length: number;
  lowercaseMin: number;
  uppercaseMin: number;
  digitsMin: number;
  symbolsMin: number;
  exclude: string | undefined;
}> {
  const count = boundedIntegerString(0, core.MAX_GENERATED_PASSWORD_LENGTH);
  const parsed = z
    .object({
      length: boundedIntegerString(
        core.MIN_GENERATED_PASSWORD_LENGTH,
        core.MAX_GENERATED_PASSWORD_LENGTH,
      ),
      lowercaseMin: count,
      uppercaseMin: count,
      digitsMin: count,
      symbolsMin: count,
      exclude: z
        .string()
        .max(94)
        .regex(/^[!-~]+$/u)
        .refine((value) => new Set(value).size === value.length)
        .optional(),
      stdout: z.boolean().optional(),
    })
    .strict()
    .safeParse(options);
  if (!parsed.success) {
    throw new CliUsageError('The password generation policy is invalid.');
  }
  return {
    length: parsed.data.length,
    lowercaseMin: parsed.data.lowercaseMin,
    uppercaseMin: parsed.data.uppercaseMin,
    digitsMin: parsed.data.digitsMin,
    symbolsMin: parsed.data.symbolsMin,
    exclude: parsed.data.exclude,
  };
}

function parsePassphraseOptions(
  options: Readonly<Record<string, unknown>>,
  core: CoreSecurityTools,
): Readonly<{
  words: number;
  separator: SafePassphraseSeparator;
  capitalize: boolean;
  digit: boolean;
  excludeWord: readonly string[];
}> {
  const parsed = z
    .object({
      words: boundedIntegerString(
        core.MIN_PASSPHRASE_WORD_COUNT,
        core.MAX_PASSPHRASE_WORD_COUNT,
      ),
      separator: z.enum(core.SAFE_PASSPHRASE_SEPARATORS),
      capitalize: z.boolean().optional().default(false),
      digit: z.boolean().optional().default(false),
      excludeWord: z.array(z.string().min(1).max(64)).max(256).optional().default([]),
      stdout: z.boolean().optional(),
    })
    .strict()
    .safeParse(options);
  if (!parsed.success) {
    throw new CliUsageError('The passphrase generation policy is invalid.');
  }
  return parsed.data;
}

function parseTotpOptions(
  options: Readonly<Record<string, unknown>>,
  core: CoreSecurityTools,
): Readonly<{
  secretStdin: boolean;
  algorithm: TotpAlgorithm;
  digits: 6 | 7 | 8;
  period: number;
  time: number | undefined;
}> {
  const parsed = z
    .object({
      secretStdin: z.boolean().optional().default(false),
      ...totpConfigurationShape(core),
      stdout: z.boolean().optional(),
    })
    .strict()
    .safeParse(options);
  if (!parsed.success) throw new CliUsageError('The TOTP request is invalid.');
  return {
    secretStdin: parsed.data.secretStdin,
    algorithm: parsed.data.algorithm,
    digits: parsed.data.digits,
    period: parsed.data.period,
    time: parsed.data.time,
  };
}

/**
 * The raw option strings that select a TOTP algorithm, width, period, and
 * explicit generation time.
 *
 * Shared by the local-seed command and the stored-credential command so both
 * enforce one set of bounds. Duplicating the bounds would let the two paths drift
 * and would make an out-of-range period a usage error on one and an unchecked
 * value on the other.
 */
function totpConfigurationShape(core: CoreSecurityTools): Readonly<{
  algorithm: z.ZodType<TotpAlgorithm>;
  digits: z.ZodType<6 | 7 | 8, string>;
  period: z.ZodType<number>;
  time: z.ZodOptional<z.ZodType<number>>;
}> {
  return {
    algorithm: z.enum(['sha1', 'sha256', 'sha512']),
    digits: z.enum(['6', '7', '8']).transform((value) => Number(value) as 6 | 7 | 8),
    period: boundedIntegerString(
      core.MIN_TOTP_PERIOD_SECONDS,
      core.MAX_TOTP_PERIOD_SECONDS,
    ),
    time: boundedIntegerString(0, core.MAX_TOTP_UNIX_TIME_SECONDS).optional(),
  };
}

/**
 * Parse only the TOTP policy options, ignoring every unrelated option the
 * invoking command carries.
 *
 * The stored-credential command also accepts backend selection and passphrase
 * options, so this deliberately does not reject unknown keys; the parser that
 * rejects an unknown flag is Commander, which refuses it before any option value
 * reaches here. Every value that is present is still bounds-checked, and a
 * failure is reported as the same opaque usage error the local-seed path uses so
 * neither path becomes an oracle for which option was wrong.
 */
export async function parseTotpConfigurationOptions(
  options: Readonly<Record<string, unknown>>,
): Promise<
  Readonly<{ configuration: TotpConfiguration; unixTimeSeconds: number | undefined }>
> {
  const core = await import('@kavrix/core');
  const parsed = z.object(totpConfigurationShape(core)).safeParse(options);
  if (!parsed.success) throw new CliUsageError('The TOTP request is invalid.');
  return {
    configuration: {
      algorithm: parsed.data.algorithm,
      digits: parsed.data.digits,
      periodSeconds: parsed.data.period,
    },
    unixTimeSeconds: parsed.data.time,
  };
}

function boundedIntegerString(minimum: number, maximum: number): z.ZodType<number> {
  return z
    .string()
    .regex(/^(?:0|[1-9][0-9]*)$/u)
    .max(15)
    .transform(Number)
    .pipe(z.number().int().min(minimum).max(maximum));
}
