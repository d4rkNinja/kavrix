import { keySlotSchema, type KeySlot, type KeySlotId } from '@kavrix/schemas';

import { LastUnlockSlotError, NotFoundError } from '../errors.js';

export function revokeKeySlot(
  slots: readonly KeySlot[],
  slotId: KeySlotId,
  revokedAt: string,
): readonly KeySlot[] {
  const target = slots.find((slot) => slot.id === slotId);
  if (!target) throw new NotFoundError();
  if (target.state === 'revoked') return slots;

  if (
    target.state === 'active' &&
    !slots.some(
      (slot) =>
        slot.id !== slotId &&
        slot.state === 'active' &&
        slot.keyVersion === target.keyVersion,
    )
  ) {
    throw new LastUnlockSlotError();
  }

  return slots.map((slot) => {
    if (slot.id !== slotId) return slot;
    const revoked = { ...slot, state: 'revoked' as const, revokedAt };
    delete revoked.supersededAt;
    return keySlotSchema.parse(revoked);
  });
}
