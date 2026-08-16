import {
  fieldValueMatchesDefinition,
  type FieldDefinition,
  type FieldValue,
  type FieldValueElement,
  type FieldValueElementId,
  type PresentFieldValue,
  type Timestamp,
} from '@kavrix/schemas';

import { AmbiguousNameError, NotFoundError, ValidationError } from '../errors.js';

/**
 * The only field type whose elements may carry a `used` lifecycle. Every
 * decision here is gated on it so a `used` state can never be written onto a
 * field the canonical value schema would reject.
 */
export const RECOVERY_CODE_FIELD_TYPE = 'recovery-code-list';

/**
 * One recovery code as it may be shown.
 *
 * The value is deliberately absent rather than truncated: a hint or a partial
 * code is still code material, and the stable element ID is what a caller needs
 * in order to act on a specific entry.
 */
export interface RecoveryCodeEntry {
  readonly id: FieldValueElementId;
  readonly status: 'available' | 'used';
  readonly usedAt: Timestamp | undefined;
}

export interface RecoveryCodeInventory {
  readonly total: number;
  readonly available: number;
  readonly used: number;
}

/** The element to consume plus the complete replacement value that consumes it. */
export interface RecoveryCodeUsePlan {
  readonly element: FieldValueElement;
  readonly value: PresentFieldValue;
  readonly inventory: RecoveryCodeInventory;
}

export function assertRecoveryCodeField(field: FieldDefinition): void {
  if (field.type !== RECOVERY_CODE_FIELD_TYPE) {
    throw new ValidationError('That field does not hold recovery codes.');
  }
}

/**
 * Read the stored element list, refusing every state that is not a readable
 * list of elements.
 *
 * Each non-present state gets its own refusal so an operator learns what to do
 * next, and none of them is treated as an empty list: silently reporting "no
 * codes" for an unreadable value would invite a caller to overwrite codes that
 * are still stored.
 */
export function readRecoveryCodeElements(
  field: FieldDefinition,
  value: FieldValue | undefined,
): readonly FieldValueElement[] {
  assertRecoveryCodeField(field);
  if (value === undefined) {
    throw new ValidationError('That field holds no recovery codes yet.');
  }
  switch (value.state) {
    case 'missing':
      throw new ValidationError('That field holds no recovery codes yet.');
    case 'empty':
      throw new ValidationError('That recovery code field is empty.');
    case 'orphaned':
      throw new ValidationError(
        'That recovery code field is archived, so restore it before using a code.',
      );
    case 'inapplicable':
      throw new ValidationError('That recovery code field is marked inapplicable.');
    case 'unreadable':
      throw new ValidationError(
        'That recovery code field cannot be read, so no code may be consumed.',
      );
    case 'present':
      break;
  }
  if (value.content.cardinality !== 'multiple') {
    throw new ValidationError(
      'That recovery code field stores a single value rather than a list of codes.',
    );
  }
  return value.content.elements;
}

/** Project the element list to identity and lifecycle only. */
export function listRecoveryCodes(
  elements: readonly FieldValueElement[],
): readonly RecoveryCodeEntry[] {
  return Object.freeze(
    elements.map((element) =>
      Object.freeze<RecoveryCodeEntry>({
        id: element.id,
        status: element.lifecycle.status,
        usedAt:
          element.lifecycle.status === 'used' ? element.lifecycle.usedAt : undefined,
      }),
    ),
  );
}

export function summarizeRecoveryCodes(
  elements: readonly FieldValueElement[],
): RecoveryCodeInventory {
  const used = elements.filter(({ lifecycle }) => lifecycle.status === 'used').length;
  return Object.freeze<RecoveryCodeInventory>({
    total: elements.length,
    available: elements.length - used,
    used,
  });
}

/**
 * Resolve one element by its stable identifier.
 *
 * Selection is never positional: an index shifts whenever codes are added,
 * consumed, or merged from another device, so the same index can name a
 * different code on a different replica. The stable element ID survives all of
 * those, which is what makes a consume request unambiguous.
 *
 * A code's own value is never accepted as a query, because matching on the
 * value would require comparing the query against decrypted code material and
 * would turn a mistyped argument into an oracle. Matching is case-sensitive and
 * exact first, then an unambiguous prefix as a typing convenience; anything
 * ambiguous is refused rather than guessed. This deliberately does not reuse
 * `resolveNamedEntity`, whose case-insensitive name and alias phases do not
 * apply to opaque identifiers.
 */
export function selectRecoveryCode(
  elements: readonly FieldValueElement[],
  query: string,
): FieldValueElement {
  const trimmed = query.trim();
  if (trimmed.length === 0) {
    throw new ValidationError('A recovery code identifier is required.');
  }
  const exact = elements.find(({ id }) => id === trimmed);
  if (exact !== undefined) return exact;

  const prefixed = elements.filter(({ id }) => id.startsWith(trimmed));
  if (prefixed.length > 1) {
    throw new AmbiguousNameError(prefixed.map(({ id }) => id));
  }
  const [only] = prefixed;
  if (only === undefined) throw new NotFoundError();
  return only;
}

/**
 * Plan the `available` to `used` transition for exactly one code.
 *
 * The plan is a complete replacement value rather than a patch, so the write
 * that applies it carries every other element unchanged and keeps every element
 * ID byte for byte. Stable identity is what lets a concurrent replica recognise
 * this as the same code rather than as an insertion, so preserving it is a
 * correctness requirement of the transition and not a detail of rendering.
 *
 * An already-used code is refused. That refusal is what makes a retry safe: the
 * durable write either committed, in which case the retry is told the code is
 * spent instead of silently overwriting the original `usedAt`, or it did not,
 * in which case the retry proceeds normally.
 */
export function planRecoveryCodeUse(
  field: FieldDefinition,
  value: FieldValue | undefined,
  query: string,
  usedAt: Timestamp,
): RecoveryCodeUsePlan {
  const elements = readRecoveryCodeElements(field, value);
  const element = selectRecoveryCode(elements, query);
  if (element.lifecycle.status === 'used') {
    throw new ValidationError('That recovery code has already been used.');
  }

  const consumed: FieldValueElement = {
    ...element,
    lifecycle: { version: 1, status: 'used', usedAt },
  };
  const next = elements.map((candidate) =>
    candidate.id === element.id ? consumed : candidate,
  );

  const replacement: PresentFieldValue = {
    version: 1,
    state: 'present',
    content: { cardinality: 'multiple', elements: next },
  };
  assertPreservedIdentity(elements, next);
  if (!fieldValueMatchesDefinition(field, replacement)) {
    throw new ValidationError(
      'Consuming that recovery code would produce a value its field rejects.',
    );
  }

  return Object.freeze<RecoveryCodeUsePlan>({
    element: consumed,
    value: replacement,
    inventory: summarizeRecoveryCodes(next),
  });
}

/**
 * Guard the invariant the transition exists to protect: consuming a code
 * rewrites one lifecycle and nothing else. A refactor that dropped, reordered,
 * or re-minted an element would be caught here rather than by a sync merge that
 * has already duplicated a code across devices.
 */
function assertPreservedIdentity(
  before: readonly FieldValueElement[],
  after: readonly FieldValueElement[],
): void {
  const identical =
    before.length === after.length &&
    before.every((element, index) => after[index]?.id === element.id);
  if (!identical) {
    throw new ValidationError('Consuming a recovery code must preserve every code.');
  }
}
