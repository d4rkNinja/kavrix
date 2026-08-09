import {
  associatedDataSchema,
  keySlotSchema,
  vaultRecordSchema,
  type KeySlot,
  type KeySlotId,
  type DeviceId,
  type Timestamp,
  type VaultId,
  type VaultRecord,
  type AssociatedData,
} from '@kavrix/schemas';

import { constantTimeEqual, requireByteLength, zeroize } from './bytes.js';
import { AuthenticationError, CryptoInputError, LastValidSlotError } from './errors.js';
import { unwrapRootKey, wrapRootKey } from './hierarchy.js';
import {
  createPassphraseDerivation,
  createDeviceKeyDerivation,
  createPortableKeyDerivation,
  createRecoveryKeyDerivation,
  derivePassphraseKek,
  deriveDeviceKek,
  derivePortableKek,
  deriveRecoveryKek,
  parsePortableKey,
  parseRecoveryKey,
  type VaultRootKey,
} from './keys.js';

type PortableSlot = Extract<KeySlot, { readonly type: 'portable-key' }>;
type PassphraseSlot = Extract<KeySlot, { readonly type: 'passphrase' }>;
type RecoverySlot = Extract<KeySlot, { readonly type: 'recovery-key' }>;
type DeviceSlot = Extract<KeySlot, { readonly type: 'device-key' }>;

export interface SlotBinding {
  readonly vaultId: VaultId;
  readonly slotId: KeySlotId;
  readonly schemaVersion: number;
  readonly keyVersion: number;
}

export interface SlotIdentity extends SlotBinding {
  readonly createdAt: Timestamp;
}

export interface DeviceSlotIdentity extends SlotIdentity {
  readonly deviceId: DeviceId;
  readonly provider: string;
}

export async function createPortableKeySlot(
  identity: SlotIdentity,
  portableKey: Uint8Array,
  rootKey: VaultRootKey,
): Promise<PortableSlot> {
  const derivation = createPortableKeyDerivation();
  const kek = derivePortableKek(portableKey, derivation);
  const context = rootSlotContext(identity);
  try {
    const wrappedRootKey = await wrapRootKey(rootKey, kek, context);
    await verifyRootKeyReplacement(rootKey, wrappedRootKey, kek, context);
    return keySlotSchema.parse({
      slotVersion: 1,
      id: identity.slotId,
      type: 'portable-key',
      state: 'active',
      keyVersion: identity.keyVersion,
      derivation,
      wrappedRootKey,
      createdAt: identity.createdAt,
    }) as PortableSlot;
  } finally {
    zeroize(kek);
  }
}

export async function createPassphraseKeySlot(
  identity: SlotIdentity,
  passphrase: Uint8Array,
  rootKey: VaultRootKey,
): Promise<PassphraseSlot> {
  const derivation = createPassphraseDerivation();
  const kek = await derivePassphraseKek(passphrase, derivation);
  const context = rootSlotContext(identity);
  try {
    const wrappedRootKey = await wrapRootKey(rootKey, kek, context);
    await verifyRootKeyReplacement(rootKey, wrappedRootKey, kek, context);
    return keySlotSchema.parse({
      slotVersion: 1,
      id: identity.slotId,
      type: 'passphrase',
      state: 'active',
      keyVersion: identity.keyVersion,
      derivation,
      wrappedRootKey,
      createdAt: identity.createdAt,
    }) as PassphraseSlot;
  } finally {
    zeroize(kek);
  }
}

export async function createRecoveryKeySlot(
  identity: SlotIdentity,
  recoveryKey: Uint8Array,
  rootKey: VaultRootKey,
): Promise<RecoverySlot> {
  const derivation = createRecoveryKeyDerivation();
  const kek = deriveRecoveryKek(recoveryKey, derivation);
  const context = rootSlotContext(identity);
  try {
    const wrappedRootKey = await wrapRootKey(rootKey, kek, context);
    await verifyRootKeyReplacement(rootKey, wrappedRootKey, kek, context);
    return keySlotSchema.parse({
      slotVersion: 1,
      id: identity.slotId,
      type: 'recovery-key',
      state: 'active',
      keyVersion: identity.keyVersion,
      derivation,
      wrappedRootKey,
      createdAt: identity.createdAt,
    }) as RecoverySlot;
  } finally {
    zeroize(kek);
  }
}

export async function createDeviceKeySlot(
  identity: DeviceSlotIdentity,
  deviceKey: Uint8Array,
  rootKey: VaultRootKey,
): Promise<DeviceSlot> {
  const derivation = createDeviceKeyDerivation(identity.provider);
  const kek = deriveDeviceKek(deviceKey, derivation);
  const context = rootSlotContext(identity);
  try {
    const wrappedRootKey = await wrapRootKey(rootKey, kek, context);
    await verifyRootKeyReplacement(rootKey, wrappedRootKey, kek, context);
    return keySlotSchema.parse({
      slotVersion: 1,
      id: identity.slotId,
      type: 'device-key',
      state: 'active',
      keyVersion: identity.keyVersion,
      derivation,
      wrappedRootKey,
      createdAt: identity.createdAt,
      deviceId: identity.deviceId,
    }) as DeviceSlot;
  } finally {
    zeroize(kek);
  }
}

export async function unlockPortableKeySlot(
  slot: PortableSlot,
  formattedPortableKey: string,
  expectedBinding: SlotBinding,
): Promise<VaultRootKey> {
  const key = parsePortableKey(formattedPortableKey);
  const parsedSlot = requireSlotType(slot, 'portable-key', expectedBinding);
  const kek = derivePortableKek(key, parsedSlot.derivation);
  try {
    return await unwrapRootKey(
      parsedSlot.wrappedRootKey,
      kek,
      rootSlotContext(expectedBinding),
    );
  } finally {
    zeroize(key);
    zeroize(kek);
  }
}

export async function unlockPassphraseKeySlot(
  slot: PassphraseSlot,
  passphrase: Uint8Array,
  expectedBinding: SlotBinding,
): Promise<VaultRootKey> {
  const parsedSlot = requireSlotType(slot, 'passphrase', expectedBinding);
  const kek = await derivePassphraseKek(passphrase, parsedSlot.derivation);
  try {
    return await unwrapRootKey(
      parsedSlot.wrappedRootKey,
      kek,
      rootSlotContext(expectedBinding),
    );
  } finally {
    zeroize(kek);
  }
}

export async function unlockRecoveryKeySlot(
  slot: RecoverySlot,
  formattedRecoveryKey: string,
  expectedBinding: SlotBinding,
): Promise<VaultRootKey> {
  const key = parseRecoveryKey(formattedRecoveryKey);
  const parsedSlot = requireSlotType(slot, 'recovery-key', expectedBinding);
  const kek = deriveRecoveryKek(key, parsedSlot.derivation);
  try {
    return await unwrapRootKey(
      parsedSlot.wrappedRootKey,
      kek,
      rootSlotContext(expectedBinding),
    );
  } finally {
    zeroize(key);
    zeroize(kek);
  }
}

export async function unlockDeviceKeySlot(
  slot: DeviceSlot,
  deviceKey: Uint8Array,
  expectedBinding: SlotBinding,
): Promise<VaultRootKey> {
  const parsedSlot = requireSlotType(slot, 'device-key', expectedBinding);
  const kek = deriveDeviceKek(deviceKey, parsedSlot.derivation);
  try {
    return await unwrapRootKey(
      parsedSlot.wrappedRootKey,
      kek,
      rootSlotContext(expectedBinding),
    );
  } finally {
    zeroize(kek);
  }
}

export async function verifyRootKeyReplacement(
  expectedRootKey: VaultRootKey,
  candidateEnvelope: KeySlot['wrappedRootKey'],
  candidateKek: Uint8Array,
  expectedContext: AssociatedData,
): Promise<void> {
  const candidate = await unwrapRootKey(
    candidateEnvelope,
    candidateKek,
    expectedContext,
  );
  try {
    requireByteLength(expectedRootKey, 32, 'vault root key');
    if (!constantTimeEqual(expectedRootKey, candidate)) {
      throw new CryptoInputError('Replacement key verification failed');
    }
  } finally {
    zeroize(candidate);
  }
}

export function assertCanRevokeKeySlot(
  vault: VaultRecord,
  targetSlotId: KeySlotId,
): void {
  let parsedVault: VaultRecord;
  try {
    parsedVault = vaultRecordSchema.parse(vault);
  } catch {
    throw new CryptoInputError('Invalid vault record');
  }
  const target = parsedVault.keySlots.find((slot) => slot.id === targetSlotId);
  if (target?.state !== 'active') {
    throw new CryptoInputError('Unknown key slot');
  }
  const otherActiveSlotExists = parsedVault.keySlots.some(
    (slot) =>
      slot.id !== targetSlotId &&
      slot.state === 'active' &&
      slot.keyVersion === parsedVault.currentKeyVersion,
  );
  if (!otherActiveSlotExists) {
    throw new LastValidSlotError();
  }
}

function rootSlotContext(identity: SlotBinding): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: identity.schemaVersion,
    keyVersion: identity.keyVersion,
    vaultId: identity.vaultId,
    entityType: 'wrapped-root-key',
    entityId: identity.slotId,
    purpose: 'vrk-slot',
  });
}

function requireSlotType<Type extends KeySlot['type']>(
  slot: KeySlot,
  expected: Type,
  expectedBinding: SlotBinding,
): Extract<KeySlot, { readonly type: Type }> {
  let parsed: KeySlot;
  try {
    parsed = keySlotSchema.parse(slot);
  } catch {
    throw new AuthenticationError();
  }
  if (
    parsed.type !== expected ||
    parsed.state !== 'active' ||
    parsed.id !== expectedBinding.slotId ||
    parsed.keyVersion !== expectedBinding.keyVersion
  ) {
    throw new CryptoInputError('Unlock slot is unavailable');
  }
  return parsed as Extract<KeySlot, { readonly type: Type }>;
}
