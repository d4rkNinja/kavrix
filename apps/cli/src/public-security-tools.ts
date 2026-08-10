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
      algorithm: z.enum(['sha1', 'sha256', 'sha512']),
      digits: z.enum(['6', '7', '8']).transform((value) => Number(value) as 6 | 7 | 8),
      period: boundedIntegerString(
        core.MIN_TOTP_PERIOD_SECONDS,
        core.MAX_TOTP_PERIOD_SECONDS,
      ),
      time: boundedIntegerString(0, core.MAX_TOTP_UNIX_TIME_SECONDS).optional(),
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

function boundedIntegerString(minimum: number, maximum: number): z.ZodType<number> {
  return z
    .string()
    .regex(/^(?:0|[1-9][0-9]*)$/u)
    .max(15)
    .transform(Number)
    .pipe(z.number().int().min(minimum).max(maximum));
}
