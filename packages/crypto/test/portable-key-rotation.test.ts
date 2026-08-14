import { describe, expect, it } from 'vitest';

import {
  AuthenticationError,
  advancePortableKeyRotationCheckpoint,
  createPortableKeyRotationCheckpoint,
  createPortableKeySlot,
  generatePortableKey,
  generateVaultRootKey,
  portableKeyRotationSlotDigest,
  verifyPortableKeyRotationCheckpoint,
} from '../src/index.js';
import {
  keySlotIdSchema,
  keySlotSchema,
  vaultIdSchema,
  vaultRevisionSchema,
} from '@kavrix/schemas';

const vaultId = vaultIdSchema.parse('vault.portable.rotation.crypto');
const sourceSlotId = keySlotIdSchema.parse('slot.rotation.crypto.source');
const replacementSlotId = keySlotIdSchema.parse('slot.rotation.crypto.replace');
const operationId = 'operation.rotation.crypto.0001';

describe('portable-key rotation checkpoints', () => {
  it('authenticates the ordered pending, active, and completed lifecycle', async () => {
    const rootKey = generateVaultRootKey();
    const sourceKey = generatePortableKey();
    const replacementKey = generatePortableKey();
    const source = await createPortableKeySlot(
      {
        vaultId,
        slotId: sourceSlotId,
        schemaVersion: 1,
        keyVersion: 1,
        createdAt: '2026-08-14T00:00:00.000Z',
      },
      sourceKey,
      rootKey,
    );
    const replacementActive = await createPortableKeySlot(
      {
        vaultId,
        slotId: replacementSlotId,
        schemaVersion: 1,
        keyVersion: 1,
        createdAt: '2026-08-14T00:00:00.000Z',
      },
      replacementKey,
      rootKey,
    );
    const replacement = keySlotSchema.parse({
      ...replacementActive,
      state: 'pending',
    });
    const expected = {
      vaultId,
      operationId,
      sourceSlotId,
      replacementSlotId,
      sourceRevision: vaultRevisionSchema.parse(4),
      sourceSlotDigest: portableKeyRotationSlotDigest(source),
      replacementSlotDigest: portableKeyRotationSlotDigest(replacement),
    } as const;

    const prepared = createPortableKeyRotationCheckpoint(expected, rootKey);
    const pending = advancePortableKeyRotationCheckpoint(
      prepared,
      rootKey,
      expected,
      'pending-published',
      vaultRevisionSchema.parse(5),
    );
    const active = advancePortableKeyRotationCheckpoint(
      pending,
      rootKey,
      expected,
      'active-published',
      vaultRevisionSchema.parse(6),
    );
    const completed = advancePortableKeyRotationCheckpoint(
      active,
      rootKey,
      expected,
      'completed',
      vaultRevisionSchema.parse(7),
    );

    expect(completed.payload.state).toBe('completed');
    expect(
      verifyPortableKeyRotationCheckpoint(completed, rootKey, expected),
    ).toMatchObject({ remoteRevision: 7, state: 'completed' });
  });

  it('rejects forged state, changed slot snapshots, and a different root key', async () => {
    const rootKey = generateVaultRootKey();
    const sourceKey = generatePortableKey();
    const replacementKey = generatePortableKey();
    const source = await createPortableKeySlot(
      {
        vaultId,
        slotId: sourceSlotId,
        schemaVersion: 1,
        keyVersion: 1,
        createdAt: '2026-08-14T00:00:00.000Z',
      },
      sourceKey,
      rootKey,
    );
    const replacement = await createPortableKeySlot(
      {
        vaultId,
        slotId: replacementSlotId,
        schemaVersion: 1,
        keyVersion: 1,
        createdAt: '2026-08-14T00:00:00.000Z',
      },
      replacementKey,
      rootKey,
    );
    const expected = {
      vaultId,
      operationId,
      sourceSlotId,
      replacementSlotId,
      sourceRevision: vaultRevisionSchema.parse(4),
      sourceSlotDigest: portableKeyRotationSlotDigest(source),
      replacementSlotDigest: portableKeyRotationSlotDigest(replacement),
    } as const;
    const checkpoint = createPortableKeyRotationCheckpoint(expected, rootKey);
    expect(() =>
      verifyPortableKeyRotationCheckpoint(
        {
          ...checkpoint,
          payload: { ...checkpoint.payload, state: 'completed', remoteRevision: 7 },
        },
        rootKey,
        expected,
      ),
    ).toThrow(AuthenticationError);
    expect(() =>
      verifyPortableKeyRotationCheckpoint(checkpoint, generateVaultRootKey(), expected),
    ).toThrow(AuthenticationError);
    expect(() =>
      verifyPortableKeyRotationCheckpoint(checkpoint, rootKey, {
        ...expected,
        replacementSlotDigest: portableKeyRotationSlotDigest(source),
      }),
    ).toThrow(AuthenticationError);
  });
});
