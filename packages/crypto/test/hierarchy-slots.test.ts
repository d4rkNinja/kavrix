import { describe, expect, it } from 'vitest';

import {
  associatedDataSchema,
  deviceIdSchema,
  keySlotIdSchema,
  timestampSchema,
  vaultRecordSchema,
  type AeadEnvelope,
  type KeySlot,
  type VaultRecord,
} from '@kavrix/schemas';

import {
  AuthenticationError,
  CryptoInputError,
  LastValidSlotError,
  assertCanRevokeKeySlot,
  createDeviceKeySlot,
  createPassphraseKeySlot,
  createPortableKeySlot,
  createRecoveryKeySlot,
  decryptPayload,
  encryptPayload,
  formatPortableKey,
  formatRecoveryKey,
  generateAttachmentKey,
  generateDeviceKey,
  generateGroupKey,
  generateItemKey,
  generatePortableKey,
  generateRecoveryKey,
  generateVaultRootKey,
  rewrapKey,
  unlockDeviceKeySlot,
  unlockPassphraseKeySlot,
  unlockPortableKeySlot,
  unlockRecoveryKeySlot,
  unwrapAttachmentKey,
  unwrapGroupKey,
  unwrapItemKey,
  wrapAttachmentKey,
  wrapGroupKey,
  wrapItemKey,
} from '../src/index.js';
import {
  attachmentChunkAad,
  groupKeyAad,
  itemKeyAad,
  itemPayloadAad,
  otherGroupId,
  otherItemId,
  otherSlotId,
  otherVaultId,
  slotId,
  vaultId,
} from './helpers.js';

const createdAt = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const firstIdentity = {
  vaultId,
  slotId,
  schemaVersion: 1,
  keyVersion: 1,
  createdAt,
} as const;
const secondIdentity = { ...firstIdentity, slotId: otherSlotId } as const;
const firstBinding = {
  vaultId,
  slotId,
  schemaVersion: 1,
  keyVersion: 1,
} as const;
const secondBinding = { ...firstBinding, slotId: otherSlotId } as const;

describe('key hierarchy and independent unlock slots', () => {
  it('unlocks the same VRK from independent slots on two devices', async () => {
    const portableKey = generatePortableKey();
    const rootKey = generateVaultRootKey();
    const first = await createPortableKeySlot(firstIdentity, portableKey, rootKey);
    const second = await createPortableKeySlot(secondIdentity, portableKey, rootKey);

    expect(first.derivation.salt).not.toBe(second.derivation.salt);
    expect(first.wrappedRootKey.nonce).not.toBe(second.wrappedRootKey.nonce);
    await expect(
      unlockPortableKeySlot(first, formatPortableKey(portableKey), firstBinding),
    ).resolves.toEqual(rootKey);
    await expect(
      unlockPortableKeySlot(second, formatPortableKey(portableKey), secondBinding),
    ).resolves.toEqual(rootKey);
    await expect(
      unlockPortableKeySlot(
        { ...second, wrappedRootKey: first.wrappedRootKey },
        formatPortableKey(portableKey),
        secondBinding,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      unlockPortableKeySlot(
        first,
        formatPortableKey(generatePortableKey()),
        firstBinding,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('keeps recovery, passphrase, and device unlock paths independent', async () => {
    const rootKey = generateVaultRootKey();
    const recoveryKey = generateRecoveryKey();
    const recoverySlot = await createRecoveryKeySlot(
      firstIdentity,
      recoveryKey,
      rootKey,
    );
    await expect(
      unlockRecoveryKeySlot(recoverySlot, formatRecoveryKey(recoveryKey), firstBinding),
    ).resolves.toEqual(rootKey);
    await expect(
      unlockRecoveryKeySlot(
        recoverySlot,
        formatRecoveryKey(generateRecoveryKey()),
        firstBinding,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);

    const passphrase = Buffer.from('slot passphrase!', 'utf8');
    const passphraseSlot = await createPassphraseKeySlot(
      secondIdentity,
      passphrase,
      rootKey,
    );
    await expect(
      unlockPassphraseKeySlot(
        passphraseSlot,
        Buffer.from('wrong passphrase!'),
        secondBinding,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);

    const deviceSlotId = keySlotIdSchema.parse('device-slot');
    const deviceIdentity = {
      ...firstIdentity,
      slotId: deviceSlotId,
      deviceId: deviceIdSchema.parse('device-1'),
      provider: 'test-keychain',
    } as const;
    const deviceKey = generateDeviceKey();
    const deviceSlot = await createDeviceKeySlot(deviceIdentity, deviceKey, rootKey);
    await expect(
      unlockDeviceKeySlot(deviceSlot, deviceKey, {
        ...firstBinding,
        slotId: deviceSlotId,
      }),
    ).resolves.toEqual(rootKey);
  });

  it('requires another active slot for the aggregate current key version', async () => {
    const rootKey = generateVaultRootKey();
    const first = await createPortableKeySlot(
      firstIdentity,
      generatePortableKey(),
      rootKey,
    );
    expect(() => {
      assertCanRevokeKeySlot(vaultWithSlots([first]), slotId);
    }).toThrow(LastValidSlotError);

    const second = await createRecoveryKeySlot(
      secondIdentity,
      generateRecoveryKey(),
      rootKey,
    );
    expect(() => {
      assertCanRevokeKeySlot(vaultWithSlots([first, second]), slotId);
    }).not.toThrow();

    const oldSlot = {
      ...second,
      keyVersion: 2,
      wrappedRootKey: {
        ...second.wrappedRootKey,
        keyVersion: 2,
        aad: { ...second.wrappedRootKey.aad, keyVersion: 2 },
      },
    } as unknown as KeySlot;
    expect(() => {
      assertCanRevokeKeySlot(vaultWithSlots([first, oldSlot]), slotId);
    }).toThrow(LastValidSlotError);
    expect(() => {
      assertCanRevokeKeySlot(
        { ...vaultWithSlots([first]), keySlots: [{}] } as never,
        slotId,
      );
    }).toThrow(CryptoInputError);
    const unrelated = {
      ...second,
      wrappedRootKey: {
        ...second.wrappedRootKey,
        aad: { ...second.wrappedRootKey.aad, vaultId: otherVaultId },
      },
    } as unknown as KeySlot;
    expect(() => {
      assertCanRevokeKeySlot(
        {
          ...vaultWithSlots([first, second]),
          keySlots: [first, unrelated],
        },
        slotId,
      );
    }).toThrow(CryptoInputError);
  });

  it('rewraps hierarchy keys without re-encrypting item payloads', async () => {
    const oldRootKey = generateVaultRootKey();
    const newRootKey = generateVaultRootKey();
    const groupKey = generateGroupKey();
    const oldGroupContext = groupKeyAad();
    const newGroupContext = groupKeyAad({ keyVersion: 2 });
    const wrappedGroup = await wrapGroupKey(groupKey, oldRootKey, oldGroupContext);
    const rewrappedGroup = await rewrapKey(
      wrappedGroup,
      oldRootKey,
      newRootKey,
      oldGroupContext,
      newGroupContext,
    );
    await expect(
      unwrapGroupKey(rewrappedGroup, newRootKey, newGroupContext),
    ).resolves.toEqual(groupKey);

    const oldGroupKey = generateGroupKey();
    const newGroupKey = generateGroupKey();
    const itemKey = generateItemKey();
    const oldItemContext = itemKeyAad();
    const newItemContext = itemKeyAad({ keyVersion: 2 });
    const wrappedItem = await wrapItemKey(itemKey, oldGroupKey, oldItemContext);
    const plaintext = new TextEncoder().encode('payload remains unchanged');
    const payloadContext = itemPayloadAad();
    const payload = await encryptPayload(plaintext, itemKey, payloadContext);
    const payloadSnapshot = JSON.stringify(payload);
    const rewrappedItem = await rewrapKey(
      wrappedItem,
      oldGroupKey,
      newGroupKey,
      oldItemContext,
      newItemContext,
    );
    const unwrappedItem = await unwrapItemKey(
      rewrappedItem,
      newGroupKey,
      newItemContext,
    );
    await expect(
      decryptPayload(payload, unwrappedItem, payloadContext),
    ).resolves.toEqual(plaintext);
    expect(JSON.stringify(payload)).toBe(payloadSnapshot);
  });

  it('rejects transplanting whole valid group and item envelopes', async () => {
    const root = generateVaultRootKey();
    const firstGroupContext = groupKeyAad();
    const otherGroupContext = groupKeyAad({ entityId: otherGroupId });
    const firstGroupEnvelope = await wrapGroupKey(
      generateGroupKey(),
      root,
      firstGroupContext,
    );
    await wrapGroupKey(generateGroupKey(), root, otherGroupContext);
    await expect(
      unwrapGroupKey(firstGroupEnvelope, root, otherGroupContext),
    ).rejects.toBeInstanceOf(AuthenticationError);

    const groupKey = generateGroupKey();
    const firstItemContext = itemKeyAad();
    const otherItemContext = itemKeyAad({ entityId: otherItemId });
    const firstItemEnvelope = await wrapItemKey(
      generateItemKey(),
      groupKey,
      firstItemContext,
    );
    await wrapItemKey(generateItemKey(), groupKey, otherItemContext);
    await expect(
      unwrapItemKey(firstItemEnvelope, groupKey, otherItemContext),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('wraps attachment keys only under their owning item context', async () => {
    const itemKey = generateItemKey();
    const attachmentKey = generateAttachmentKey();
    const context = attachmentChunkAad({
      entityType: 'wrapped-attachment-key',
      purpose: 'attachment-key',
    });
    const envelope = await wrapAttachmentKey(attachmentKey, itemKey, context);
    await expect(unwrapAttachmentKey(envelope, itemKey, context)).resolves.toEqual(
      attachmentKey,
    );
    await expect(
      unwrapAttachmentKey(envelope, itemKey, {
        ...context,
        parentId: otherItemId,
      } as never),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });
});

function vaultWithSlots(keySlots: readonly KeySlot[]): VaultRecord {
  const sourceEnvelope = keySlots[0]?.wrappedRootKey;
  if (sourceEnvelope === undefined) {
    throw new Error('A test slot is required');
  }
  const preferencesAad = associatedDataSchema.parse({
    version: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId,
    entityType: 'vault-preferences',
    entityId: vaultId,
    purpose: 'vault-preferences',
  });
  return vaultRecordSchema.parse({
    id: vaultId,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots,
    currentKeyVersion: 1,
    revision: 0,
    encryptedPreferences: {
      ...sourceEnvelope,
      keyVersion: 1,
      aad: preferencesAad,
    } as AeadEnvelope,
    createdAt,
    updatedAt: createdAt,
  });
}
