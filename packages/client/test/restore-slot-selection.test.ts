import { describe, expect, it, vi } from 'vitest';
import type * as CryptoModule from '@kavrix/crypto';

const observed = vi.hoisted(() => ({ passphrases: [] as Uint8Array[] }));
vi.mock('@kavrix/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof CryptoModule>();
  return {
    ...actual,
    unlockPassphraseKeySlot: async (
      ...args: Parameters<typeof actual.unlockPassphraseKeySlot>
    ) => {
      observed.passphrases.push(args[1]);
      return actual.unlockPassphraseKeySlot(...args);
    },
  };
});

import {
  constantTimeEqual,
  createDeviceKeySlot,
  createPassphraseKeySlot,
  createPortableKeySlot,
  createRecoveryKeySlot,
  formatPortableKey,
  formatRecoveryKey,
  generateDeviceKey,
  generatePortableKey,
  generateRecoveryKey,
  zeroize,
} from '@kavrix/crypto';
import {
  deviceIdSchema,
  keySlotIdSchema,
  timestampSchema,
  vaultRecordSchema,
  type KeySlot,
  type VaultRecord,
} from '@kavrix/schemas';

import {
  unwrapRestoreVaultRootKey,
  type RestoreSlotCredential,
} from '../src/restore-slot-selection.js';
import { encryptedFixture } from './fixtures.js';

const now = timestampSchema.parse('2026-08-12T00:00:00.000Z');
const portableId = keySlotIdSchema.parse('slot.restore.portable');
const passphraseId = keySlotIdSchema.parse('slot.restore.passphrase');
const recoveryId = keySlotIdSchema.parse('slot.restore.recovery');
const deviceId = keySlotIdSchema.parse('slot.restore.device');

describe('restore slot selection', () => {
  it('unwraps portable, passphrase, and recovery slots with exact evidence', async () => {
    const material = await slotFixture();
    try {
      const credentials: readonly RestoreSlotCredential[] = [
        { type: 'portable-key', slotId: portableId, formattedKey: material.portable },
        { type: 'passphrase', slotId: passphraseId, passphrase: material.passphrase },
        { type: 'recovery-key', slotId: recoveryId, formattedKey: material.recovery },
      ];
      for (const credential of credentials) {
        const result = await unwrapRestoreVaultRootKey(material.vault, credential);
        try {
          expect(constantTimeEqual(result.vaultRootKey, material.rootKey)).toBe(true);
          expect(result.selectedSlot).toEqual({
            id: credential.slotId,
            type: credential.type,
            keyVersion: material.vault.currentKeyVersion,
          });
        } finally {
          zeroize(result.vaultRootKey);
        }
      }
      expect(material.passphrase).toEqual(
        new TextEncoder().encode('restore passphrase'),
      );
      expect(observed.passphrases.at(-1)?.every((byte) => byte === 0)).toBe(true);
    } finally {
      material.dispose();
    }
  });

  it('wipes its owned passphrase copy on authentication failure without mutating caller input', async () => {
    const material = await slotFixture();
    const wrong = new TextEncoder().encode('wrong restore passphrase');
    try {
      await expect(
        unwrapRestoreVaultRootKey(material.vault, {
          type: 'passphrase',
          slotId: passphraseId,
          passphrase: wrong,
        }),
      ).rejects.toMatchObject(genericError());
      expect(wrong).toEqual(new TextEncoder().encode('wrong restore passphrase'));
      expect(observed.passphrases.at(-1)?.every((byte) => byte === 0)).toBe(true);
    } finally {
      zeroize(wrong);
      material.dispose();
    }
  });

  it.each([
    [
      'wrong slot ID',
      (material: SlotMaterial) => ({
        type: 'portable-key',
        slotId: keySlotIdSchema.parse('slot.missing'),
        formattedKey: material.portable,
      }),
    ],
    [
      'wrong credential',
      () => ({
        type: 'portable-key',
        slotId: portableId,
        formattedKey: 'cvr1_invalid',
      }),
    ],
    [
      'omitted slot ID',
      (material: SlotMaterial) => ({
        type: 'portable-key',
        formattedKey: material.portable,
      }),
    ],
    [
      'device credential',
      () => ({
        type: 'device-key',
        slotId: deviceId,
        formattedKey: 'forbidden',
      }),
    ],
    [
      'unknown field',
      (material: SlotMaterial) => ({
        type: 'portable-key',
        slotId: portableId,
        formattedKey: material.portable,
        vaultRootKey: material.rootKey,
      }),
    ],
  ])('normalizes %s', async (_name, credential) => {
    const material = await slotFixture();
    try {
      await expect(
        unwrapRestoreVaultRootKey(material.vault, credential(material) as never),
      ).rejects.toMatchObject(genericError());
    } finally {
      material.dispose();
    }
  });

  it.each(['pending', 'revoked', 'superseded'] as const)(
    'rejects an otherwise valid %s slot',
    async (state) => {
      const material = await slotFixture();
      try {
        const vault = replaceSlot(material.vault, portableId, (slot) => ({
          ...slot,
          state,
          ...(state === 'revoked' ? { revokedAt: now } : {}),
          ...(state === 'superseded' ? { supersededAt: now } : {}),
        }));
        await expect(
          unwrapRestoreVaultRootKey(vault, {
            type: 'portable-key',
            slotId: portableId,
            formattedKey: material.portable,
          }),
        ).rejects.toMatchObject(genericError());
      } finally {
        material.dispose();
      }
    },
  );

  it('rejects a valid non-current slot, device slot, and runtime-invalid/ambiguous vaults', async () => {
    const material = await slotFixture();
    const alternate = generatePortableKey();
    try {
      const nonCurrent = await createPortableKeySlot(
        {
          vaultId: material.vault.id,
          slotId: keySlotIdSchema.parse('slot.old'),
          schemaVersion: material.vault.schemaVersion,
          keyVersion: 2,
          createdAt: now,
        },
        alternate,
        material.rootKey,
      );
      const vaultWithOld = vaultRecordSchema.parse({
        ...material.vault,
        keySlots: [...material.vault.keySlots, nonCurrent],
      });
      await expect(
        unwrapRestoreVaultRootKey(vaultWithOld, {
          type: 'portable-key',
          slotId: nonCurrent.id,
          formattedKey: formatPortableKey(alternate),
        }),
      ).rejects.toMatchObject(genericError());
      await expect(
        unwrapRestoreVaultRootKey(material.vault, {
          type: 'portable-key',
          slotId: deviceId,
          formattedKey: material.portable,
        }),
      ).rejects.toMatchObject(genericError());
      await expect(
        unwrapRestoreVaultRootKey(
          {
            ...material.vault,
            keySlots: [
              ...material.vault.keySlots,
              required(material.vault.keySlots[0]),
            ],
          },
          {
            type: 'portable-key',
            slotId: portableId,
            formattedKey: material.portable,
          },
        ),
      ).rejects.toMatchObject(genericError());
      await expect(
        unwrapRestoreVaultRootKey({ ...material.vault, keySlots: [{}] } as never, {
          type: 'portable-key',
          slotId: portableId,
          formattedKey: material.portable,
        }),
      ).rejects.toMatchObject(genericError());
    } finally {
      zeroize(alternate);
      material.dispose();
    }
  });
});

type SlotMaterial = Awaited<ReturnType<typeof slotFixture>>;

async function slotFixture(): Promise<
  Readonly<{
    vault: VaultRecord;
    rootKey: Awaited<ReturnType<typeof encryptedFixture>>['rootKey'];
    portable: string;
    recovery: string;
    passphrase: Uint8Array;
    dispose: () => void;
  }>
> {
  const fixture = await encryptedFixture();
  const portableKey = generatePortableKey();
  const recoveryKey = generateRecoveryKey();
  const deviceKey = generateDeviceKey();
  const passphrase = new TextEncoder().encode('restore passphrase');
  const identity = (
    slotId: typeof portableId,
  ): Readonly<{
    vaultId: typeof fixture.vaultId;
    slotId: typeof portableId;
    schemaVersion: typeof fixture.vault.schemaVersion;
    keyVersion: typeof fixture.vault.currentKeyVersion;
    createdAt: typeof now;
  }> => ({
    vaultId: fixture.vaultId,
    slotId,
    schemaVersion: fixture.vault.schemaVersion,
    keyVersion: fixture.vault.currentKeyVersion,
    createdAt: now,
  });
  try {
    const slots = [
      await createPortableKeySlot(identity(portableId), portableKey, fixture.rootKey),
      await createPassphraseKeySlot(
        identity(passphraseId),
        passphrase,
        fixture.rootKey,
      ),
      await createRecoveryKeySlot(identity(recoveryId), recoveryKey, fixture.rootKey),
      await createDeviceKeySlot(
        {
          ...identity(deviceId),
          deviceId: deviceIdSchema.parse('device.restore'),
          provider: 'test-native',
        },
        deviceKey,
        fixture.rootKey,
      ),
    ];
    const vault = vaultRecordSchema.parse({ ...fixture.vault, keySlots: slots });
    return {
      vault,
      rootKey: fixture.rootKey,
      portable: formatPortableKey(portableKey),
      recovery: formatRecoveryKey(recoveryKey),
      passphrase,
      dispose: () => {
        zeroize(passphrase);
        zeroize(fixture.rootKey);
      },
    };
  } finally {
    zeroize(portableKey);
    zeroize(recoveryKey);
    zeroize(deviceKey);
  }
}

function replaceSlot(
  vault: VaultRecord,
  id: typeof portableId,
  transform: (slot: KeySlot) => unknown,
): VaultRecord {
  return vaultRecordSchema.parse({
    ...vault,
    keySlots: vault.keySlots.map((slot) => (slot.id === id ? transform(slot) : slot)),
  });
}

function genericError(): Readonly<{ name: string; message: string }> {
  return {
    name: 'CryptoAuthenticationError',
    message: 'Encrypted data could not be authenticated.',
  };
}

function required<T>(value: T | null | undefined): T {
  if (value === null || value === undefined) throw new Error('Missing fixture value');
  return value;
}
