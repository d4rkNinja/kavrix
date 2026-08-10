import { randomFillSync } from 'node:crypto';

import { secretValueSchema, type SecretValue } from '@kavrix/schemas';

import { ValidationError } from './errors.js';
import { PASSPHRASE_WORD_LIST } from './passphrase-word-list.js';

export const MIN_PASSPHRASE_WORD_COUNT = 6;
export const MAX_PASSPHRASE_WORD_COUNT = 24;
export const MIN_PASSPHRASE_ENTROPY_BITS = 64;
export const PASSPHRASE_WORD_LIST_SIZE = 1_296;
export const SAFE_PASSPHRASE_SEPARATORS = ['-', '_', '.', ':', '+', '='] as const;

export type SafePassphraseSeparator = (typeof SAFE_PASSPHRASE_SEPARATORS)[number];

export type PassphraseGeneratorPolicy = Readonly<{
  /** Six or more independently selected words; defaults to eight. */
  wordCount?: number;
  /** A visible ASCII separator from the fixed safe set; defaults to `-`. */
  separator?: SafePassphraseSeparator;
  /** Capitalize exactly one uniformly selected word, adding positional entropy. */
  capitalize?: boolean;
  /** Append one uniformly selected decimal digit as a separate token. */
  includeNumber?: boolean;
  /** Exact, case-sensitive EFF-list words to remove before selection. */
  excludedWords?: readonly string[];
}>;

type ValidatedPassphrasePolicy = Readonly<{
  wordCount: number;
  separator: SafePassphraseSeparator;
  capitalize: boolean;
  includeNumber: boolean;
  words: readonly string[];
  searchSpace: bigint;
}>;

/** @internal Test seam; production generation always uses Node crypto. */
export type PassphraseRandomFill = (target: Uint8Array) => void;

export const DEFAULT_PASSPHRASE_POLICY = Object.freeze({
  wordCount: 8,
  separator: '-',
  capitalize: false,
  includeNumber: false,
  excludedWords: Object.freeze([]),
}) satisfies Required<PassphraseGeneratorPolicy>;

const UINT32_SPACE = 0x1_0000_0000;
const UINT32_BYTES = 4;
const MAX_RANDOM_REJECTIONS = 128;
const DECIMAL_DIGITS = 10;
const MIN_SEARCH_SPACE = 1n << BigInt(MIN_PASSPHRASE_ENTROPY_BITS);
const POLICY_KEYS = [
  'wordCount',
  'separator',
  'capitalize',
  'includeNumber',
  'excludedWords',
] as const;
const WORD_SET = new Set(PASSPHRASE_WORD_LIST);

function failPolicy(message: string): never {
  throw new ValidationError(message);
}

function validatePolicy(policyInput: unknown): ValidatedPassphrasePolicy {
  let policy: unknown = policyInput;
  if (policy === undefined) policy = DEFAULT_PASSPHRASE_POLICY;
  if (
    typeof policy !== 'object' ||
    policy === null ||
    Array.isArray(policy) ||
    Object.keys(policy).some((key) => !POLICY_KEYS.some((expected) => expected === key))
  ) {
    failPolicy('The passphrase policy is invalid.');
  }
  const candidate = policy as Record<string, unknown>;

  const wordCount = candidate['wordCount'] ?? DEFAULT_PASSPHRASE_POLICY.wordCount;
  if (
    typeof wordCount !== 'number' ||
    !Number.isSafeInteger(wordCount) ||
    wordCount < MIN_PASSPHRASE_WORD_COUNT ||
    wordCount > MAX_PASSPHRASE_WORD_COUNT
  ) {
    failPolicy(
      `Passphrases require ${String(MIN_PASSPHRASE_WORD_COUNT)} to ${String(MAX_PASSPHRASE_WORD_COUNT)} words.`,
    );
  }

  const separator = candidate['separator'] ?? DEFAULT_PASSPHRASE_POLICY.separator;
  if (!isSafeSeparator(separator)) {
    failPolicy('The passphrase separator is not supported.');
  }

  const capitalize = candidate['capitalize'] ?? DEFAULT_PASSPHRASE_POLICY.capitalize;
  const includeNumber =
    candidate['includeNumber'] ?? DEFAULT_PASSPHRASE_POLICY.includeNumber;
  if (typeof capitalize !== 'boolean' || typeof includeNumber !== 'boolean') {
    failPolicy('Passphrase decoration options must be boolean values.');
  }

  const excludedWords = candidate['excludedWords'] ?? [];
  if (
    !Array.isArray(excludedWords) ||
    excludedWords.length >= PASSPHRASE_WORD_LIST_SIZE
  ) {
    failPolicy('The passphrase exclusion list is invalid.');
  }
  const excluded = new Set<string>();
  for (const word of excludedWords) {
    if (typeof word !== 'string' || !WORD_SET.has(word) || excluded.has(word)) {
      failPolicy('Passphrase exclusions must be unique canonical word-list entries.');
    }
    excluded.add(word);
  }
  const words = Object.freeze(
    PASSPHRASE_WORD_LIST.filter((word) => !excluded.has(word)),
  );
  if (words.length === 0) failPolicy('The passphrase policy has no available words.');

  let searchSpace = BigInt(words.length) ** BigInt(wordCount);
  if (capitalize) searchSpace *= BigInt(wordCount);
  if (includeNumber) searchSpace *= BigInt(DECIMAL_DIGITS);
  if (searchSpace < MIN_SEARCH_SPACE) {
    failPolicy(
      `Passphrase policies must provide at least ${String(MIN_PASSPHRASE_ENTROPY_BITS)} bits of search space.`,
    );
  }

  return Object.freeze({
    wordCount,
    separator,
    capitalize,
    includeNumber,
    words,
    searchSpace,
  });
}

function isSafeSeparator(value: unknown): value is SafePassphraseSeparator {
  return SAFE_PASSPHRASE_SEPARATORS.some((separator) => separator === value);
}

function cryptoRandomFill(target: Uint8Array): void {
  randomFillSync(target);
}

function uniformRandomIndex(
  upperExclusive: number,
  randomFill: PassphraseRandomFill,
): number {
  if (!Number.isSafeInteger(upperExclusive) || upperExclusive < 1) {
    throw new Error('Cryptographic random selection failed.');
  }
  const limit = UINT32_SPACE - (UINT32_SPACE % upperExclusive);
  const bytes = new Uint8Array(UINT32_BYTES);
  try {
    for (let attempt = 0; attempt < MAX_RANDOM_REJECTIONS; attempt += 1) {
      try {
        randomFill(bytes);
      } catch {
        throw new Error('Cryptographic random selection failed.');
      }
      const value = new DataView(
        bytes.buffer,
        bytes.byteOffset,
        bytes.byteLength,
      ).getUint32(0, false);
      if (value < limit) return value % upperExclusive;
    }
    throw new Error('Cryptographic random selection failed.');
  } finally {
    bytes.fill(0);
  }
}

function capitalizeAsciiWord(word: string): string {
  const first = word[0];
  if (first === undefined) throw new Error('Passphrase generation failed.');
  return `${first.toUpperCase()}${word.slice(1)}`;
}

/**
 * Computes the exact number of outputs reachable under a policy. Selections
 * use replacement; capitalization chooses one position and a number adds ten
 * possible final tokens.
 */
export function calculatePassphraseSearchSpace(
  policy?: PassphraseGeneratorPolicy,
): bigint {
  return validatePolicy(policy).searchSpace;
}

export function calculatePassphraseEntropyBits(
  policy?: PassphraseGeneratorPolicy,
): number {
  const validated = validatePolicy(policy);
  return (
    Math.log2(validated.words.length) * validated.wordCount +
    (validated.capitalize ? Math.log2(validated.wordCount) : 0) +
    (validated.includeNumber ? Math.log2(DECIMAL_DIGITS) : 0)
  );
}

/**
 * Generates a branded secret using Node's cryptographic RNG. Index selection
 * uses rejection sampling over unsigned 32-bit values and therefore has no
 * modulo bias.
 */
export function generatePassphrase(policy?: PassphraseGeneratorPolicy): SecretValue {
  return generatePassphraseWithRandomFill(policy, cryptoRandomFill);
}

/** @internal Deterministic injection boundary used only by unit tests. */
export function generatePassphraseWithRandomFill(
  policy: PassphraseGeneratorPolicy | undefined,
  randomFill: PassphraseRandomFill,
): SecretValue {
  if (typeof randomFill !== 'function') {
    throw new Error('Cryptographic random selection failed.');
  }
  const validated = validatePolicy(policy);
  const words: string[] = [];
  for (let index = 0; index < validated.wordCount; index += 1) {
    const word =
      validated.words[uniformRandomIndex(validated.words.length, randomFill)];
    if (word === undefined) throw new Error('Passphrase generation failed.');
    words.push(word);
  }
  if (validated.capitalize) {
    const index = uniformRandomIndex(words.length, randomFill);
    const word = words[index];
    if (word === undefined) throw new Error('Passphrase generation failed.');
    words[index] = capitalizeAsciiWord(word);
  }
  if (validated.includeNumber) {
    words.push(String(uniformRandomIndex(DECIMAL_DIGITS, randomFill)));
  }
  return secretValueSchema.parse(words.join(validated.separator));
}
