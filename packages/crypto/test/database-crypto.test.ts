import { describe, expect, it } from 'vitest';

import {
  databaseAssociatedDataSchema,
  databaseIdSchema,
  databaseRevisionSchema,
  keyVersionSchema,
  keySlotIdSchema,
  sha256DigestSchema,
  supportedCryptographicVersionSchema,
  supportedSchemaVersionSchema,
  timestampSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type DatabaseAeadEnvelope,
  type DatabaseAssociatedData,
} from '@kavrix/schemas';

import {
  AuthenticationError,
  computeDatabaseVaultPayloadMetadataDigest,
  createRecoveryKeySlot,
  createDatabaseKeySlot,
  createDatabaseRecoverySlot,
  decryptDatabaseAead,
  decryptDatabaseCatalog,
  encodeBase64Url,
  encryptDatabaseAead,
  encryptDatabaseCatalog,
  generateDatabaseRootKey,
  generatePortableKey,
  generateRecoveryKey,
  generateVaultRootKey,
  unlockDatabaseKeySlot,
  unlockDatabaseRecoverySlot,
  unwrapVaultRootForDatabase,
  wrapVaultRootForDatabase,
  zeroize,
} from '../src/index.js';
import type { DatabaseRootKey, VaultRootKey } from '../src/keys.js';

const databaseId = databaseIdSchema.parse('db-1');
const otherDatabaseId = databaseIdSchema.parse('db-2');
const vaultId = vaultIdSchema.parse('vault-1');
const otherVaultId = vaultIdSchema.parse('vault-2');
const slotId = keySlotIdSchema.parse('slot-1');
const createdAt = timestampSchema.parse('2026-08-19T00:00:00.000Z');
const canary = new TextEncoder().encode('database-plaintext-canary-9f7706a4');
const deterministicDatabaseRoot = Uint8Array.from(
  { length: 32 },
  (_, index) => index + 1,
) as DatabaseRootKey;
const deterministicVaultRoot = Uint8Array.from(
  { length: 32 },
  (_, index) => 255 - index,
) as VaultRootKey;

const databaseSlotIdentity = {
  databaseId,
  slotId,
  schemaVersion: 1,
  keyVersion: 1,
  revision: 1,
  metadataDigest: sha256DigestSchema.parse(encodeBase64Url(new Uint8Array(32).fill(7))),
  createdAt,
} as const;

const databaseSlotBinding = {
  databaseId,
  slotId,
  schemaVersion: 1,
  keyVersion: 1,
  revision: 1,
  metadataDigest: sha256DigestSchema.parse(encodeBase64Url(new Uint8Array(32).fill(7))),
} as const;

function catalogContext(
  overrides: Readonly<Record<string, unknown>> = {},
): DatabaseAssociatedData {
  return databaseAssociatedDataSchema.parse({
    version: 1,
    databaseId,
    entityType: 'database-catalog',
    entityId: databaseId,
    purpose: 'catalog',
    schemaVersion: 1,
    keyVersion: 1,
    revision: 1,
    metadataDigest: encodeBase64Url(new Uint8Array(32).fill(1)),
    ...overrides,
  });
}

function vaultRootContext(
  overrides: Readonly<Record<string, unknown>> = {},
): DatabaseAssociatedData {
  return databaseAssociatedDataSchema.parse({
    version: 1,
    databaseId,
    vaultId,
    entityType: 'wrapped-vault-root',
    entityId: vaultId,
    purpose: 'vault-root',
    schemaVersion: 1,
    keyVersion: 1,
    revision: 1,
    metadataDigest: encodeBase64Url(new Uint8Array(32).fill(2)),
    ...overrides,
  });
}

function mutateBase64Url(value: string): string {
  const bytes = Buffer.from(value, 'base64url');
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  return encodeBase64Url(bytes);
}

describe('database-domain authenticated encryption', () => {
  it('reproduces the released VRK-keyed database-vault payload digest vector', () => {
    const vaultRootKey = Uint8Array.from(
      { length: 32 },
      (_, index) => index + 1,
    ) as VaultRootKey;
    const plaintext = Buffer.from(
      JSON.stringify({
        records: {
          alpha: {
            updatedAt: '2026-08-29T00:00:00.000Z',
            value: 'canary',
          },
        },
      }),
      'utf8',
    );
    const keyBefore = Uint8Array.from(vaultRootKey);
    const plaintextBefore = Uint8Array.from(plaintext);
    try {
      expect(
        computeDatabaseVaultPayloadMetadataDigest(
          {
            databaseId,
            id: vaultId,
            schemaVersion: supportedSchemaVersionSchema.parse(1),
            cryptographicVersion: supportedCryptographicVersionSchema.parse(1),
            currentKeyVersion: keyVersionSchema.parse(1),
            databaseRevision: databaseRevisionSchema.parse(9),
            revision: vaultRevisionSchema.parse(4),
            createdAt,
            updatedAt: createdAt,
          },
          vaultRootKey,
          plaintext,
        ),
      ).toBe('z5C9HrO8X4KSx16fNQS4gw9bHIf6ZCOJ8Z9zGG_6k_A');
      expect(vaultRootKey).toEqual(keyBefore);
      expect(plaintext).toEqual(Buffer.from(plaintextBefore));
    } finally {
      zeroize(vaultRootKey);
      zeroize(plaintext);
      zeroize(keyBefore);
      zeroize(plaintextBefore);
    }
  });

  it('round-trips a database catalog without serializing plaintext', async () => {
    const databaseRootKey = Uint8Array.from(
      deterministicDatabaseRoot,
    ) as DatabaseRootKey;
    const context = catalogContext();
    const envelope = await encryptDatabaseCatalog(canary, databaseRootKey, context);

    await expect(
      decryptDatabaseCatalog(envelope, databaseRootKey, context),
    ).resolves.toEqual(canary);
    expect(JSON.stringify(envelope)).not.toContain(
      'database-plaintext-canary-9f7706a4',
    );
    zeroize(databaseRootKey);
  });

  it.each([
    ['database ID', { databaseId: otherDatabaseId }],
    ['purpose', { purpose: 'vault-root' }],
    ['entity ID', { entityId: vaultId }],
    ['revision', { revision: 2 }],
    [
      'metadata digest',
      { metadataDigest: encodeBase64Url(new Uint8Array(32).fill(9)) },
    ],
  ] as const)('rejects tampered %s context', async (_name, changes) => {
    const databaseRootKey = Uint8Array.from(
      deterministicDatabaseRoot,
    ) as DatabaseRootKey;
    const context = catalogContext();
    const envelope = await encryptDatabaseAead(canary, databaseRootKey, context);
    const tamperedContext = {
      ...context,
      ...changes,
    } as DatabaseAssociatedData;
    const tamperedEnvelope = {
      ...envelope,
      aad: tamperedContext,
    } as DatabaseAeadEnvelope;

    await expect(
      decryptDatabaseAead(tamperedEnvelope, databaseRootKey, context),
    ).rejects.toBeInstanceOf(AuthenticationError);
    zeroize(databaseRootKey);
  });

  it('rejects a vault ID swap and malformed context relationship', async () => {
    const databaseRootKey = Uint8Array.from(
      deterministicDatabaseRoot,
    ) as DatabaseRootKey;
    const context = vaultRootContext();
    const envelope = await encryptDatabaseAead(canary, databaseRootKey, context);

    await expect(
      decryptDatabaseAead(
        {
          ...envelope,
          aad: { ...context, vaultId: otherVaultId, entityId: otherVaultId },
        },
        databaseRootKey,
        context,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      decryptDatabaseAead(envelope, databaseRootKey, {
        ...context,
        entityId: databaseId,
      }),
    ).rejects.toBeInstanceOf(AuthenticationError);
    zeroize(databaseRootKey);
  });

  it.each(['nonce', 'ciphertext', 'authenticationTag'] as const)(
    'rejects a tampered %s',
    async (field) => {
      const databaseRootKey = Uint8Array.from(
        deterministicDatabaseRoot,
      ) as DatabaseRootKey;
      const context = catalogContext();
      const envelope = await encryptDatabaseAead(canary, databaseRootKey, context);
      const tampered = {
        ...envelope,
        [field]: mutateBase64Url(envelope[field]),
      };

      await expect(
        decryptDatabaseAead(tampered, databaseRootKey, context),
      ).rejects.toBeInstanceOf(AuthenticationError);
      zeroize(databaseRootKey);
    },
  );

  it('authenticates both key-version copies', async () => {
    const databaseRootKey = Uint8Array.from(
      deterministicDatabaseRoot,
    ) as DatabaseRootKey;
    const context = catalogContext();
    const envelope = await encryptDatabaseAead(canary, databaseRootKey, context);

    await expect(
      decryptDatabaseAead(
        { ...envelope, keyVersion: 2 } as DatabaseAeadEnvelope,
        databaseRootKey,
        context,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    zeroize(databaseRootKey);
  });

  it('maps a distinct valid database root key failure to AuthenticationError', async () => {
    const databaseRootKey = generateDatabaseRootKey();
    const wrongDatabaseRootKey = generateDatabaseRootKey();
    const context = catalogContext();
    try {
      const envelope = await encryptDatabaseAead(canary, databaseRootKey, context);

      await expect(
        decryptDatabaseAead(envelope, wrongDatabaseRootKey, context),
      ).rejects.toEqual(new AuthenticationError());
    } finally {
      zeroize(databaseRootKey);
      zeroize(wrongDatabaseRootKey);
    }
  });
});

describe('database root and vault root hierarchy', () => {
  it('maps distinct valid portable and recovery key failures to AuthenticationError', async () => {
    const portableKey = generatePortableKey();
    const wrongPortableKey = generatePortableKey();
    const databaseRootKey = generateDatabaseRootKey();
    const wrongRecoveryKey = generateRecoveryKey();
    let recoveryKey: Uint8Array | undefined;
    try {
      const portableSlot = await createDatabaseKeySlot(
        databaseSlotIdentity,
        portableKey,
        databaseRootKey,
      );
      await expect(
        unlockDatabaseKeySlot(portableSlot, wrongPortableKey, databaseSlotBinding),
      ).rejects.toEqual(new AuthenticationError());

      const recovery = await createDatabaseRecoverySlot(
        {
          ...databaseSlotIdentity,
          slotId: keySlotIdSchema.parse('wrong-key-recovery'),
        },
        databaseRootKey,
      );
      recoveryKey = recovery.recoveryKey;
      await expect(
        unlockDatabaseRecoverySlot(recovery.slot, wrongRecoveryKey, {
          ...databaseSlotBinding,
          slotId: recovery.slot.id,
        }),
      ).rejects.toEqual(new AuthenticationError());
    } finally {
      zeroize(portableKey);
      zeroize(wrongPortableKey);
      zeroize(databaseRootKey);
      zeroize(wrongRecoveryKey);
      zeroize(recoveryKey);
    }
  });

  it('uses dedicated portable and recovery database slots', async () => {
    const portableKey = generatePortableKey();
    const databaseRootKey = generateDatabaseRootKey();
    const portableSlot = await createDatabaseKeySlot(
      databaseSlotIdentity,
      portableKey,
      databaseRootKey,
    );
    expect(portableSlot.derivation.context).toBe('kavrix/database-root-wrap/v1');
    const recovered = await unlockDatabaseKeySlot(
      portableSlot,
      portableKey,
      databaseSlotBinding,
    );
    expect(recovered).toEqual(databaseRootKey);
    zeroize(recovered);

    const recovery = await createDatabaseRecoverySlot(
      { ...databaseSlotIdentity, slotId: keySlotIdSchema.parse('recovery-slot') },
      databaseRootKey,
    );
    const recoveredFromRecovery = await unlockDatabaseRecoverySlot(
      recovery.slot,
      recovery.recoveryKey,
      { ...databaseSlotBinding, slotId: recovery.slot.id },
    );
    expect(recoveredFromRecovery).toEqual(databaseRootKey);
    expect(recovery.slot.derivation.context).toBe('kavrix/database-recovery-wrap/v1');
    zeroize(recoveredFromRecovery);

    await expect(
      unlockDatabaseRecoverySlot(
        portableSlot as never,
        recovery.recoveryKey,
        databaseSlotBinding,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);

    const vaultRecoveryKey = generateRecoveryKey();
    const vaultRootKey = generateVaultRootKey();
    const vaultRecoverySlot = await createRecoveryKeySlot(
      {
        vaultId,
        slotId: keySlotIdSchema.parse('vault-recovery-slot'),
        schemaVersion: 1,
        keyVersion: 1,
        createdAt,
      },
      vaultRecoveryKey,
      vaultRootKey,
    );
    await expect(
      unlockDatabaseRecoverySlot(
        vaultRecoverySlot as never,
        recovery.recoveryKey,
        databaseSlotBinding,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    zeroize(vaultRecoveryKey);
    zeroize(vaultRootKey);

    zeroize(portableKey);
    zeroize(databaseRootKey);
    zeroize(recovery.recoveryKey);
  });

  it('wraps a vault root only for its exact database and vault context', async () => {
    const databaseRootKey = Uint8Array.from(
      deterministicDatabaseRoot,
    ) as DatabaseRootKey;
    const vaultRootKey = Uint8Array.from(deterministicVaultRoot) as VaultRootKey;
    const context = vaultRootContext();
    const wrapped = await wrapVaultRootForDatabase(
      vaultRootKey,
      databaseRootKey,
      context,
    );
    const unwrapped = await unwrapVaultRootForDatabase(
      wrapped,
      databaseRootKey,
      context,
    );
    expect(unwrapped).toEqual(vaultRootKey);
    zeroize(unwrapped);

    await expect(
      unwrapVaultRootForDatabase(wrapped, databaseRootKey, {
        ...context,
        vaultId: otherVaultId,
        entityId: otherVaultId,
      }),
    ).rejects.toBeInstanceOf(AuthenticationError);
    zeroize(databaseRootKey);
    zeroize(vaultRootKey);
  });
});
