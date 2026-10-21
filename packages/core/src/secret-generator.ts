import {
  secretGenerationRequestSchema,
  type SecretGenerationRequest,
} from '@kavrix/schemas';

/**
 * Fills the target with cryptographically secure random bytes. The caller
 * supplies the platform CSPRNG so core stays free of platform imports.
 */
export type RandomFill = (target: Uint8Array) => void;

export type GeneratedSecret = Readonly<{
  value: string;
  alphabetSize: number;
  /**
   * Conservative lower bound: guaranteed class characters count only their
   * class size and the final shuffle contributes nothing.
   */
  entropyBits: number;
}>;

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
// Quotes, backslash, backtick, dollar, and space are excluded so a generated
// password survives shells, .env files, and connection strings unescaped.
const SYMBOLS = '!#%&()*+,-./:;<=>?@[]^_{|}~';
const AMBIGUOUS = new Set(['I', 'l', '1', 'O', '0', 'o', '|']);
const HEX = '0123456789abcdef';
const BASE64URL = `${UPPERCASE}${LOWERCASE}${DIGITS}-_`;

const UINT32_RANGE = 2 ** 32;

function withoutAmbiguous(alphabet: string, exclude: boolean): string {
  if (!exclude) return alphabet;
  return Array.from(alphabet)
    .filter((character) => !AMBIGUOUS.has(character))
    .join('');
}

/** Returns the non-empty character classes a request draws from. */
export function secretCharacterClasses(
  request: SecretGenerationRequest,
): readonly string[] {
  const parsed = secretGenerationRequestSchema.parse(request);
  if (parsed.format === 'hex') return [HEX];
  if (parsed.format === 'base64url') return [BASE64URL];
  const exclude = parsed.excludeAmbiguous;
  return [
    parsed.lowercase ? withoutAmbiguous(LOWERCASE, exclude) : '',
    parsed.uppercase ? withoutAmbiguous(UPPERCASE, exclude) : '',
    parsed.digits ? withoutAmbiguous(DIGITS, exclude) : '',
    parsed.symbols ? withoutAmbiguous(SYMBOLS, exclude) : '',
  ].filter((alphabet) => alphabet.length > 0);
}

/** Uniform index in [0, size) by rejection sampling, so no residue is favoured. */
function uniformIndex(size: number, fill: RandomFill, scratch: Uint8Array): number {
  if (!Number.isSafeInteger(size) || size < 1 || size > UINT32_RANGE) {
    throw new RangeError('Alphabet size is outside the supported range');
  }
  const limit = UINT32_RANGE - (UINT32_RANGE % size);
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    fill(scratch);
    const sample =
      ((scratch[0] ?? 0) * 0x1000000 +
        ((scratch[1] ?? 0) << 16) +
        ((scratch[2] ?? 0) << 8) +
        (scratch[3] ?? 0)) >>>
      0;
    if (sample < limit) return sample % size;
  }
  // A CSPRNG rejects at most half its samples per draw; 1024 consecutive
  // rejections means the random source is broken, so fail closed.
  throw new Error('The random source did not produce a usable sample');
}

function pick(alphabet: string, fill: RandomFill, scratch: Uint8Array): string {
  const characters = Array.from(alphabet);
  const character = characters[uniformIndex(characters.length, fill, scratch)];
  if (character === undefined) throw new RangeError('Alphabet is empty');
  return character;
}

/**
 * Generates one secret from a validated request. Password requests contain at
 * least one character from every selected class, then a Fisher-Yates shuffle
 * removes the positional bias of placing those characters first.
 */
export function generateSecret(
  request: SecretGenerationRequest,
  fill: RandomFill,
): GeneratedSecret {
  const parsed = secretGenerationRequestSchema.parse(request);
  const classes = secretCharacterClasses(parsed);
  const alphabet = classes.join('');
  const alphabetSize = Array.from(alphabet).length;
  if (classes.length > parsed.length) {
    throw new RangeError('The length is shorter than the selected character classes');
  }
  const scratch = new Uint8Array(4);
  const characters: string[] = [];
  try {
    const guaranteed = parsed.format === 'password' ? classes : [];
    for (const characterClass of guaranteed) {
      characters.push(pick(characterClass, fill, scratch));
    }
    while (characters.length < parsed.length) {
      characters.push(pick(alphabet, fill, scratch));
    }
    for (let index = characters.length - 1; index > 0; index -= 1) {
      const swap = uniformIndex(index + 1, fill, scratch);
      const current = characters[index];
      const other = characters[swap];
      if (current === undefined || other === undefined) {
        throw new RangeError('Shuffle index is out of range');
      }
      characters[index] = other;
      characters[swap] = current;
    }
    const guaranteedBits = guaranteed.reduce(
      (total, characterClass) => total + Math.log2(Array.from(characterClass).length),
      0,
    );
    const entropyBits = Math.floor(
      guaranteedBits + (parsed.length - guaranteed.length) * Math.log2(alphabetSize),
    );
    return Object.freeze({ value: characters.join(''), alphabetSize, entropyBits });
  } finally {
    scratch.fill(0);
    characters.fill('');
  }
}
