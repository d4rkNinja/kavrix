import { describe, expect, it } from 'vitest';

import type { AeadEnvelope } from '@kavrix/schemas';

import {
  AuthenticationError,
  canonicalAssociatedData,
  encryptAead,
  generateItemKey,
} from '../src/index.js';
import { decryptAead } from '../src/aead.js';
import {
  groupId,
  itemPayloadAad,
  mutateBase64Url,
  otherGroupId,
  otherItemId,
  otherVaultId,
} from './helpers.js';

const plaintext = new TextEncoder().encode('unique-plaintext-canary-7ac19783');

describe('authenticated envelopes', () => {
  it('round-trips and emits deterministic canonical AAD', async () => {
    const key = generateItemKey();
    const aad = itemPayloadAad();
    const envelope = await encryptAead(plaintext, key, aad);
    await expect(decryptAead(envelope, key, aad)).resolves.toEqual(plaintext);
    expect(canonicalAssociatedData(aad)).toEqual(canonicalAssociatedData(aad));
    expect(envelope).toMatchObject({
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      keyVersion: 1,
    });
    expect(JSON.stringify(envelope)).not.toContain('unique-plaintext-canary-7ac19783');
  });

  it.each(['nonce', 'ciphertext', 'authenticationTag'] as const)(
    'rejects modified %s without returning plaintext',
    async (field) => {
      const key = generateItemKey();
      const envelope = await encryptAead(plaintext, key, itemPayloadAad());
      const tampered = {
        ...envelope,
        [field]: mutateBase64Url(envelope[field]),
      };
      await expect(decryptAead(tampered, key, itemPayloadAad())).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    },
  );

  it('returns the same generic failure for a wrong key and malformed envelope', async () => {
    const envelope = await encryptAead(plaintext, generateItemKey(), itemPayloadAad());
    await expect(
      decryptAead(envelope, generateItemKey(), itemPayloadAad()),
    ).rejects.toEqual(new AuthenticationError());
    const malformed = { ...envelope, version: 2 } as unknown as AeadEnvelope;
    await expect(
      decryptAead(malformed, generateItemKey(), itemPayloadAad()),
    ).rejects.toEqual(new AuthenticationError());
  });

  it.each([
    ['vault', { vaultId: otherVaultId }],
    ['group', { groupId: otherGroupId }],
    ['item', { entityId: otherItemId }],
    ['purpose', { purpose: 'history-event' }],
    ['schema version', { schemaVersion: 2 }],
  ] as const)('rejects %s context swapping', async (_name, aadChange) => {
    const key = generateItemKey();
    const envelope = await encryptAead(plaintext, key, itemPayloadAad());
    const tampered = {
      ...envelope,
      aad: { ...envelope.aad, ...aadChange },
    };
    await expect(
      decryptAead(tampered as unknown as AeadEnvelope, key, itemPayloadAad()),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('authenticates both copies of key version', async () => {
    const key = generateItemKey();
    const envelope = await encryptAead(plaintext, key, itemPayloadAad());
    await expect(
      decryptAead(
        { ...envelope, keyVersion: 2 } as unknown as AeadEnvelope,
        key,
        itemPayloadAad(),
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      decryptAead(
        {
          ...envelope,
          keyVersion: 2,
          aad: { ...envelope.aad, keyVersion: 2 },
        } as unknown as AeadEnvelope,
        key,
        itemPayloadAad(),
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('does not accept a valid item ciphertext under another item or group', async () => {
    const key = generateItemKey();
    const envelope = await encryptAead(plaintext, key, itemPayloadAad());
    const movedItem = {
      ...envelope,
      aad: { ...envelope.aad, entityId: otherItemId },
    };
    const movedGroup = {
      ...envelope,
      aad: { ...envelope.aad, groupId: otherGroupId },
    };
    await expect(
      decryptAead(movedItem as unknown as AeadEnvelope, key, itemPayloadAad()),
    ).rejects.toBeInstanceOf(AuthenticationError);
    await expect(
      decryptAead(movedGroup as unknown as AeadEnvelope, key, itemPayloadAad()),
    ).rejects.toBeInstanceOf(AuthenticationError);
    expect(envelope.aad.groupId).toBe(groupId);
  });
});
