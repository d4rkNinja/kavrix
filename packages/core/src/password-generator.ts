import { randomInt } from 'node:crypto';

import { secretValueSchema } from '@kavrix/schemas';
import type { SecretValue } from '@kavrix/schemas';

import { ValidationError } from './errors.js';

export const MIN_GENERATED_PASSWORD_LENGTH = 8;
export const MAX_GENERATED_PASSWORD_LENGTH = 1_024;
export const MAX_PASSWORD_CHARACTER_CLASSES = 16;

export type PasswordCharacterClass = Readonly<{
  name: string;
  alphabet: string;
  minimum: number;
}>;

export type PasswordGeneratorPolicy = Readonly<{
  length: number;
  classes: readonly PasswordCharacterClass[];
  excludedCharacters?: string;
}>;

type ValidatedCharacterClass = Readonly<{
  alphabet: readonly string[];
  minimum: number;
}>;

type ValidatedPasswordPolicy = Readonly<{
  length: number;
  classes: readonly ValidatedCharacterClass[];
  combinedAlphabet: readonly string[];
}>;

const classNamePattern = /^[a-z][a-z0-9-]{0,63}$/;

function failPolicy(message: string): never {
  throw new ValidationError(message);
}

function toUniquePrintableAscii(value: string, label: string): readonly string[] {
  const characters = Array.from(value);
  if (characters.length === 0) {
    failPolicy(`${label} must not be empty.`);
  }
  if (
    characters.some((character) => {
      const codePoint = character.codePointAt(0);
      return codePoint === undefined || codePoint < 0x21 || codePoint > 0x7e;
    })
  ) {
    failPolicy(`${label} must contain only visible ASCII characters.`);
  }
  if (new Set(characters).size !== characters.length) {
    failPolicy(`${label} must not contain duplicate characters.`);
  }
  return characters;
}

function validatePasswordPolicy(
  policy: PasswordGeneratorPolicy,
): ValidatedPasswordPolicy {
  if (
    !Number.isSafeInteger(policy.length) ||
    policy.length < MIN_GENERATED_PASSWORD_LENGTH ||
    policy.length > MAX_GENERATED_PASSWORD_LENGTH
  ) {
    failPolicy(
      `Password length must be an integer from ${String(MIN_GENERATED_PASSWORD_LENGTH)} to ${String(MAX_GENERATED_PASSWORD_LENGTH)}.`,
    );
  }
  if (
    policy.classes.length === 0 ||
    policy.classes.length > MAX_PASSWORD_CHARACTER_CLASSES
  ) {
    failPolicy(
      `Password policies require between 1 and ${String(MAX_PASSWORD_CHARACTER_CLASSES)} character classes.`,
    );
  }

  const excluded = new Set(
    policy.excludedCharacters === undefined
      ? []
      : toUniquePrintableAscii(policy.excludedCharacters, 'Excluded characters'),
  );
  const names = new Set<string>();
  const assignedCharacters = new Set<string>();
  let requiredCharacters = 0;

  const classes = policy.classes.map((characterClass) => {
    if (!classNamePattern.test(characterClass.name) || names.has(characterClass.name)) {
      failPolicy('Character class names must be unique lowercase identifiers.');
    }
    names.add(characterClass.name);
    if (
      !Number.isSafeInteger(characterClass.minimum) ||
      characterClass.minimum < 1 ||
      characterClass.minimum > MAX_GENERATED_PASSWORD_LENGTH
    ) {
      failPolicy('Every character class minimum must be a positive bounded integer.');
    }

    const alphabet = toUniquePrintableAscii(
      characterClass.alphabet,
      'Character class alphabet',
    ).filter((character) => !excluded.has(character));
    if (alphabet.length === 0) {
      failPolicy('Exclusions must not remove every character from a required class.');
    }
    for (const character of alphabet) {
      if (assignedCharacters.has(character)) {
        failPolicy('Character class alphabets must not overlap.');
      }
      assignedCharacters.add(character);
    }
    requiredCharacters += characterClass.minimum;
    return Object.freeze({
      alphabet: Object.freeze(alphabet),
      minimum: characterClass.minimum,
    });
  });

  if (requiredCharacters > policy.length) {
    failPolicy('The required character counts exceed the requested password length.');
  }

  return Object.freeze({
    length: policy.length,
    classes: Object.freeze(classes),
    combinedAlphabet: Object.freeze([...assignedCharacters]),
  });
}

function randomCharacter(alphabet: readonly string[]): string {
  const character = alphabet[randomInt(alphabet.length)];
  if (character === undefined) {
    throw new Error('Cryptographic random selection failed.');
  }
  return character;
}

/**
 * Generates a password from explicit character classes. Node's `randomInt`
 * performs rejection sampling, so selections and the Fisher-Yates shuffle do
 * not introduce modulo bias.
 */
export function generatePassword(policy: PasswordGeneratorPolicy): SecretValue {
  const validated = validatePasswordPolicy(policy);
  const password: string[] = [];

  for (const characterClass of validated.classes) {
    for (let index = 0; index < characterClass.minimum; index += 1) {
      password.push(randomCharacter(characterClass.alphabet));
    }
  }
  while (password.length < validated.length) {
    password.push(randomCharacter(validated.combinedAlphabet));
  }
  for (let index = password.length - 1; index > 0; index -= 1) {
    const swapIndex = randomInt(index + 1);
    const current = password[index];
    const replacement = password[swapIndex];
    if (current === undefined || replacement === undefined) {
      throw new Error('Cryptographic shuffle failed.');
    }
    password[index] = replacement;
    password[swapIndex] = current;
  }

  return secretValueSchema.parse(password.join(''));
}
