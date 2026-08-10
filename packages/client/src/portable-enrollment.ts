import {
  AuthenticationError,
  CryptoInputError,
  unlockPortableKeySlot,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  inviteRedeemResponseSchema,
  type InviteRedeemResponse,
  type KeySlot,
} from '@kavrix/schemas';

import { PortableKeyValidationError } from './errors.js';

type PortableSlot = Extract<KeySlot, { readonly type: 'portable-key' }>;

/**
 * Authenticates a redeemed vault locally with an active current portable slot.
 * The caller owns the returned VRK and must zeroize it after use.
 */
export async function unlockRedeemedVaultWithPortableKey(
  response: InviteRedeemResponse,
  formattedPortableKey: string,
): Promise<VaultRootKey> {
  let parsed: ReturnType<typeof inviteRedeemResponseSchema.safeParse>;
  try {
    parsed = inviteRedeemResponseSchema.safeParse(response);
  } catch {
    throw new PortableKeyValidationError();
  }
  if (!parsed.success) throw new PortableKeyValidationError();
  const { vault } = parsed.data;
  const candidates = vault.keySlots.filter(
    (slot): slot is PortableSlot =>
      slot.type === 'portable-key' &&
      slot.state === 'active' &&
      slot.keyVersion === vault.currentKeyVersion,
  );
  for (const slot of candidates) {
    try {
      return await unlockPortableKeySlot(slot, formattedPortableKey, {
        vaultId: vault.id,
        slotId: slot.id,
        schemaVersion: vault.schemaVersion,
        keyVersion: slot.keyVersion,
      });
    } catch (error) {
      if (
        !(error instanceof AuthenticationError) &&
        !(error instanceof CryptoInputError)
      ) {
        throw new PortableKeyValidationError();
      }
    }
  }
  throw new PortableKeyValidationError();
}
