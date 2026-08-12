import { CryptoAuthenticationError } from '@kavrix/core';
import {
  unlockPassphraseKeySlot,
  unlockPortableKeySlot,
  unlockRecoveryKeySlot,
  zeroize,
  type SlotBinding,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  keySlotIdSchema,
  vaultRecordSchema,
  type KeySlot,
  type KeySlotId,
  type RestoreKnownRecordsVerificationV1,
  type VaultRecord,
} from '@kavrix/schemas';
import { z } from 'zod';

export const MAX_PASSPHRASE_BYTES = 1024 * 1024;

const restoreSlotCredentialSchema = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('portable-key'),
      slotId: keySlotIdSchema,
      formattedKey: z.string(),
    })
    .strict(),
  z
    .object({
      type: z.literal('passphrase'),
      slotId: keySlotIdSchema,
      passphrase: z
        .instanceof(Uint8Array)
        .refine(
          (value) => value.byteLength > 0 && value.byteLength <= MAX_PASSPHRASE_BYTES,
        ),
    })
    .strict(),
  z
    .object({
      type: z.literal('recovery-key'),
      slotId: keySlotIdSchema,
      formattedKey: z.string(),
    })
    .strict(),
]);

export type RestoreSlotCredential =
  | Readonly<{ type: 'portable-key'; slotId: KeySlotId; formattedKey: string }>
  | Readonly<{ type: 'passphrase'; slotId: KeySlotId; passphrase: Uint8Array }>
  | Readonly<{ type: 'recovery-key'; slotId: KeySlotId; formattedKey: string }>;

export type SelectedRestoreSlot = Readonly<
  RestoreKnownRecordsVerificationV1['selectedSlot']
>;

type SlotType = KeySlot['type'];

export async function unwrapRestoreVaultRootKey(
  candidate: VaultRecord,
  credentialCandidate: RestoreSlotCredential,
): Promise<
  Readonly<{
    vaultRootKey: VaultRootKey;
    selectedSlot: SelectedRestoreSlot;
  }>
> {
  let rootKey: VaultRootKey | undefined;
  let ownedPassphrase: Uint8Array | undefined;
  try {
    const vault = vaultRecordSchema.parse(candidate);
    const credential = restoreSlotCredentialSchema.parse(credentialCandidate);
    const slotId = keySlotIdSchema.parse(credential.slotId);
    let selectedSlot: SelectedRestoreSlot;
    if (credential.type === 'portable-key') {
      const slot = selectCurrentSlot(vault, credential.type, slotId);
      rootKey = await unlockPortableKeySlot(
        slot,
        credential.formattedKey,
        slotBinding(vault, slot),
      );
      selectedSlot = selectedSlotEvidence(slot);
    } else if (credential.type === 'passphrase') {
      const slot = selectCurrentSlot(vault, credential.type, slotId);
      ownedPassphrase = Uint8Array.from(credential.passphrase);
      rootKey = await unlockPassphraseKeySlot(
        slot,
        ownedPassphrase,
        slotBinding(vault, slot),
      );
      selectedSlot = selectedSlotEvidence(slot);
    } else {
      const slot = selectCurrentSlot(vault, credential.type, slotId);
      rootKey = await unlockRecoveryKeySlot(
        slot,
        credential.formattedKey,
        slotBinding(vault, slot),
      );
      selectedSlot = selectedSlotEvidence(slot);
    }
    const result = { vaultRootKey: rootKey, selectedSlot } as const;
    rootKey = undefined;
    return result;
  } catch {
    zeroize(rootKey);
    throw new CryptoAuthenticationError();
  } finally {
    zeroize(ownedPassphrase);
  }
}

export function selectCurrentSlot<Type extends SlotType>(
  vault: VaultRecord,
  type: Type,
  slotId: KeySlotId | undefined,
): Extract<KeySlot, { readonly type: Type }> {
  const candidates = vault.keySlots.filter(
    (slot): slot is Extract<KeySlot, { readonly type: Type }> =>
      slot.type === type &&
      slot.state === 'active' &&
      slot.keyVersion === vault.currentKeyVersion &&
      (slotId === undefined || slot.id === slotId),
  );
  if (candidates.length !== 1) throw new CryptoAuthenticationError();
  return candidates[0] as Extract<KeySlot, { readonly type: Type }>;
}

export function slotBinding(vault: VaultRecord, slot: KeySlot): SlotBinding {
  return {
    vaultId: vault.id,
    slotId: slot.id,
    schemaVersion: vault.schemaVersion,
    keyVersion: slot.keyVersion,
  };
}

function selectedSlotEvidence(
  slot: Exclude<KeySlot, { readonly type: 'device-key' }>,
): SelectedRestoreSlot {
  return {
    id: slot.id,
    type: slot.type,
    keyVersion: slot.keyVersion,
  };
}
