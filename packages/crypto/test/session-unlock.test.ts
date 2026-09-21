import { describe, expect, it } from 'vitest';

import { openSessionUnlock, sealSessionUnlock } from '../src/session-unlock.js';

const KEY = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const AAD = {
  version: 1 as const,
  kind: 'session-unlock' as const,
  profileId: 'default',
  databaseId: 'db_abc',
  createdAt: '2026-01-01T00:00:00.000Z',
  ttlHours: 12,
};

describe('session unlock seal/open', () => {
  it('round-trips the unlock material', async () => {
    const plaintext = new TextEncoder().encode('passphrase-canary-2231');
    const envelope = await sealSessionUnlock(plaintext, KEY, AAD);
    expect(envelope.algorithm).toBe('xchacha20-poly1305-ietf');
    expect(envelope.aad.createdAt).toBe(AAD.createdAt);
    const opened = await openSessionUnlock(envelope, KEY, AAD);
    expect(new TextDecoder().decode(opened)).toBe('passphrase-canary-2231');
  });

  it('fails authentication when the AAD is transplanted', async () => {
    const plaintext = new TextEncoder().encode('canary');
    const envelope = await sealSessionUnlock(plaintext, KEY, AAD);
    await expect(
      openSessionUnlock(envelope, KEY, { ...AAD, profileId: 'other-profile' }),
    ).rejects.toThrow();
    await expect(
      openSessionUnlock(envelope, KEY, { ...AAD, ttlHours: 1 }),
    ).rejects.toThrow();
    await expect(
      openSessionUnlock(envelope, KEY, { ...AAD, databaseId: 'db_other' }),
    ).rejects.toThrow();
  });

  it('fails when the wrapping key differs', async () => {
    const plaintext = new TextEncoder().encode('canary');
    const envelope = await sealSessionUnlock(plaintext, KEY, AAD);
    const other = new Uint8Array(32).fill(9);
    await expect(openSessionUnlock(envelope, other, AAD)).rejects.toThrow();
  });

  it('fails closed on tampered ciphertext bytes', async () => {
    const plaintext = new TextEncoder().encode('canary');
    const envelope = await sealSessionUnlock(plaintext, KEY, AAD);
    const bytes = Buffer.from(envelope.ciphertext, 'base64url');
    const first = bytes[0] ?? 0;
    bytes[0] = first ^ 0xff;
    await expect(
      openSessionUnlock(
        { ...envelope, ciphertext: bytes.toString('base64url') },
        KEY,
        AAD,
      ),
    ).rejects.toThrow();
  });

  it('rejects oversized and empty plaintext', async () => {
    await expect(sealSessionUnlock(new Uint8Array(0), KEY, AAD)).rejects.toThrow();
    await expect(sealSessionUnlock(new Uint8Array(8192), KEY, AAD)).rejects.toThrow();
  });
});
