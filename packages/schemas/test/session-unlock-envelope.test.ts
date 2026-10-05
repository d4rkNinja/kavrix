import { describe, expect, it } from 'vitest';
import { sessionUnlockEnvelopeSchema } from '../src/session-unlock.js';

const envelope = {
  version: 1,
  algorithm: 'xchacha20-poly1305-ietf',
  nonce: Buffer.alloc(24).toString('base64url'),
  ciphertext: Buffer.from([1, 2, 3]).toString('base64url'),
  authenticationTag: Buffer.alloc(16).toString('base64url'),
  aad: {
    version: 1,
    kind: 'session-unlock',
    profileId: 'profile-a',
    databaseId: 'database-a',
    createdAt: '2026-09-01T00:00:00.000Z',
    ttlHours: 1,
  },
};

describe('session unlock envelope contract', () => {
  it('accepts the versioned, scoped envelope and optional TTL', () => {
    expect(sessionUnlockEnvelopeSchema.safeParse(envelope).success).toBe(true);
    const aad = {
      version: envelope.aad.version,
      kind: envelope.aad.kind,
      profileId: envelope.aad.profileId,
      createdAt: envelope.aad.createdAt,
    };
    expect(sessionUnlockEnvelopeSchema.safeParse({ ...envelope, aad }).success).toBe(
      true,
    );
  });

  it.each([
    ['nonce', Buffer.alloc(23).toString('base64url')],
    ['authenticationTag', Buffer.alloc(15).toString('base64url')],
  ] as const)(
    'rejects an incorrectly sized %s before authentication',
    (field, value) => {
      const result = sessionUnlockEnvelopeSchema.safeParse({
        ...envelope,
        [field]: value,
      });
      expect(result.success).toBe(false);
      if (result.success) throw new Error('A malformed session envelope was accepted');
      expect(result.error.issues.some(({ path }) => path[0] === field)).toBe(true);
    },
  );

  it.each([0, -1, 1.5, 8761])(
    'rejects a TTL outside the bounded integer contract: %s',
    (ttlHours) => {
      expect(
        sessionUnlockEnvelopeSchema.safeParse({
          ...envelope,
          aad: { ...envelope.aad, ttlHours },
        }).success,
      ).toBe(false);
    },
  );

  it('rejects unknown envelope versions, algorithms, and unauthenticated extra fields', () => {
    for (const patch of [
      { version: 2 },
      { algorithm: 'aes-cbc' },
      { extra: 'ignored?' },
    ]) {
      expect(
        sessionUnlockEnvelopeSchema.safeParse({ ...envelope, ...patch }).success,
      ).toBe(false);
    }
    expect(
      sessionUnlockEnvelopeSchema.safeParse({
        ...envelope,
        aad: { ...envelope.aad, extra: 'ignored?' },
      }).success,
    ).toBe(false);
  });
});
