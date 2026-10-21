import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { associatedDataSchema } from '@kavrix/schemas';

import { canonicalAssociatedData } from '../src/index.js';

const identifier = fc.stringMatching(/^[a-z0-9]{1,12}$/u);

function itemContext(
  vaultId: string,
  entityId: string,
  groupId: string,
): ReturnType<typeof associatedDataSchema.safeParse> {
  return associatedDataSchema.safeParse({
    version: 1,
    schemaVersion: 2,
    keyVersion: 3,
    vaultId,
    entityType: 'item',
    entityId,
    groupId,
    purpose: 'item-payload',
  });
}

describe('canonical AAD properties', () => {
  it('is injective: distinct item contexts never share canonical bytes', () => {
    fc.assert(
      fc.property(
        fc.tuple(identifier, identifier, identifier),
        fc.tuple(identifier, identifier, identifier),
        (left, right) => {
          const a = itemContext(...left);
          const b = itemContext(...right);
          fc.pre(a.success && b.success);
          const same = Buffer.from(canonicalAssociatedData(a.data)).equals(
            Buffer.from(canonicalAssociatedData(b.data)),
          );
          expect(same).toBe(left.join('\u0000') === right.join('\u0000'));
        },
      ),
      { numRuns: 500 },
    );
  });

  it('separates every split of the same concatenated identifier text', () => {
    fc.assert(
      fc.property(
        fc.stringMatching(/^[a-z0-9]{2,16}$/u),
        fc.nat(),
        fc.nat(),
        (joined, first, second) => {
          const leftSplit = 1 + (first % (joined.length - 1));
          const rightSplit = 1 + (second % (joined.length - 1));
          fc.pre(leftSplit !== rightSplit);
          const a = itemContext(
            'v',
            joined.slice(0, leftSplit),
            joined.slice(leftSplit),
          );
          const b = itemContext(
            'v',
            joined.slice(0, rightSplit),
            joined.slice(rightSplit),
          );
          fc.pre(a.success && b.success);
          expect(
            Buffer.from(canonicalAssociatedData(a.data)).equals(
              Buffer.from(canonicalAssociatedData(b.data)),
            ),
          ).toBe(false);
        },
      ),
      { numRuns: 300 },
    );
  });
});
