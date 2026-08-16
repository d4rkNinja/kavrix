import type { FieldDefinition, FieldValue, SecretValue } from '@kavrix/schemas';

import {
  AmbiguousNameError,
  NotFoundError,
  PermissionError,
  ValidationError,
} from '../errors.js';
import { parseTotpSecret, type TotpCode, type TotpConfiguration } from '../totp.js';

/**
 * The only field type whose stored value may be treated as a TOTP seed. Every
 * decision here is gated on it, so a seed can never be read out of a field whose
 * definition says it holds something else.
 */
export const TOTP_SECRET_FIELD_TYPE = 'totp-secret';

/**
 * The minimum a caller must expose for a field to take part in automatic seed
 * selection. `id` is what an ambiguity refusal names, because a label is mutable
 * and a label is what made the request ambiguous in the first place.
 */
export interface TotpSecretFieldCandidate {
  readonly id: string;
  readonly definition: FieldDefinition;
}

/**
 * One generated code plus the policy it was generated under.
 *
 * The seed is deliberately absent. Nothing in this result can be walked back to
 * seed material, so it stays safe to render, and the caller has no API here that
 * would hand it the seed instead.
 */
export interface StoredTotpGeneration {
  readonly code: TotpCode;
  readonly remainingSeconds: number;
  readonly configuration: TotpConfiguration;
}

export function assertTotpSecretField(field: FieldDefinition): void {
  if (field.type !== TOTP_SECRET_FIELD_TYPE) {
    throw new ValidationError('That field does not hold a TOTP secret.');
  }
}

/**
 * Refuse a field its own definition says must never be revealed.
 *
 * A generated code is short-lived rather than permanent, but it is still derived
 * from the seed and still authenticates, so a `never` reveal policy is honoured
 * here exactly as it is for a recovery code.
 */
export function assertTotpRevealPermitted(field: FieldDefinition): void {
  if (field.revealPolicy === 'never') {
    throw new PermissionError();
  }
}

/**
 * Select the one TOTP-secret field a credential holds.
 *
 * Automatic selection exists so the common case needs no field argument, and it
 * is unambiguous by construction: exactly one candidate is required. A
 * credential with no seed is `NOT_FOUND`, and one with several is refused with
 * their identifiers so the caller can name the intended field rather than have
 * one guessed. Guessing here would silently generate a code for the wrong
 * account, which is indistinguishable from a wrong code at the relying party.
 */
export function selectTotpSecretField<T extends TotpSecretFieldCandidate>(
  candidates: readonly T[],
): T {
  const matches = candidates.filter(
    ({ definition }) => definition.type === TOTP_SECRET_FIELD_TYPE,
  );
  if (matches.length > 1) {
    throw new AmbiguousNameError(matches.map(({ id }) => id));
  }
  const [only] = matches;
  if (only === undefined) throw new NotFoundError();
  return only;
}

/**
 * Generate one code from a stored seed and wipe the seed bytes before returning.
 *
 * The seed never leaves this function: it is decoded into an owned buffer, used
 * once, and zeroed in `finally`, so an exception on the generation path cleans up
 * exactly as a success does. The decoded buffer is the only copy this layer owns;
 * the caller's stored value is an immutable JavaScript string that cannot be
 * zeroed, which is a limitation of the runtime rather than of this policy.
 *
 * The configuration is supplied rather than read from the field, because the
 * canonical field definition stores no algorithm, digit count, or period. Adding
 * one would change the stored shape of every existing vault, so the caller owns
 * that policy and this function owns the seed.
 */
export function generateStoredTotpCode(
  field: FieldDefinition,
  value: FieldValue | undefined,
  configuration: TotpConfiguration,
  unixTimeSeconds: number,
): StoredTotpGeneration {
  const seed = readStoredTotpSeed(field, value);
  const secret = parseTotpSecret(seed);
  try {
    const generated = secret.generate(configuration, unixTimeSeconds);
    return Object.freeze<StoredTotpGeneration>({
      code: generated.code,
      remainingSeconds: generated.remainingSeconds,
      configuration,
    });
  } finally {
    secret.destroy();
  }
}

/**
 * Read the stored seed, refusing every state and shape that is not exactly one
 * secret scalar.
 *
 * Each non-present state gets its own refusal so an operator learns what to do
 * next, and none of them is treated as an absent seed: reporting "no seed" for a
 * value that failed to decrypt would invite a caller to overwrite a seed that is
 * still stored. This is not exported, so no caller above this layer has an API
 * that returns seed material at all.
 */
function readStoredTotpSeed(
  field: FieldDefinition,
  value: FieldValue | undefined,
): SecretValue {
  assertTotpSecretField(field);
  if (value === undefined) {
    throw new ValidationError('That field holds no TOTP secret yet.');
  }
  switch (value.state) {
    case 'missing':
      throw new ValidationError('That field holds no TOTP secret yet.');
    case 'empty':
      throw new ValidationError('That TOTP secret field is empty.');
    case 'orphaned':
      throw new ValidationError(
        'That TOTP secret field is archived, so restore it before generating a code.',
      );
    case 'inapplicable':
      throw new ValidationError('That TOTP secret field is marked inapplicable.');
    case 'unreadable':
      throw new ValidationError(
        'That TOTP secret field cannot be read, so no code may be generated.',
      );
    case 'present':
      break;
  }
  if (value.content.cardinality !== 'single') {
    throw new ValidationError(
      'That TOTP secret field stores a list rather than one seed.',
    );
  }
  const scalar = value.content.value;
  if (scalar.kind !== 'secret') {
    throw new ValidationError('That TOTP secret field holds no readable seed.');
  }
  return scalar.value;
}
