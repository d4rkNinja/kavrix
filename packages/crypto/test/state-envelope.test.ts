import { hkdfSync, randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  decryptStateEnvelope,
  encryptStateEnvelope,
  type StateEnvelopeCryptoFields,
} from '../src/index.js';

const CONTEXT = Object.freeze({
  domain: 'kavrix/authorization-state/v1',
  scopeKind: 'database' as const,
  scopeId: 'db_test',
  sequence: 7,
});

function key(): Uint8Array {
  return new Uint8Array(
    hkdfSync('sha256', randomBytes(32), randomBytes(32), 'test', 32),
  );
}

function sealedDocument(fields: StateEnvelopeCryptoFields): Record<string, unknown> {
  return {
    format: 'kavrix-authorization-state',
    version: 1,
    scopeKind: CONTEXT.scopeKind,
    scopeId: CONTEXT.scopeId,
    sequence: CONTEXT.sequence,
    createdAt: '2026-08-22T00:00:00.000Z',
    updatedAt: '2026-08-22T00:00:00.000Z',
    ...fields,
  };
}

describe('state envelope', () => {
  it('round-trips a bounded plaintext under the exact context', async () => {
    const encryptionKey = key();
    const plaintext = new TextEncoder().encode(
      '{"policies":{},"grants":{},"audit":[]}',
    );
    const fields = await encryptStateEnvelope(plaintext, encryptionKey, CONTEXT);
    const decrypted = await decryptStateEnvelope(
      sealedDocument(fields) as never,
      encryptionKey,
      CONTEXT,
    );
    expect(new TextDecoder().decode(decrypted)).toBe(
      '{"policies":{},"grants":{},"audit":[]}',
    );
  });

  it('fails closed when any ciphertext or tag byte changes', async () => {
    const encryptionKey = key();
    const plaintext = new TextEncoder().encode('state');
    const fields = await encryptStateEnvelope(plaintext, encryptionKey, CONTEXT);
    const raw = Buffer.from(fields.ciphertext, 'base64url');
    if (raw.length === 0) throw new Error('unexpected empty ciphertext');
    raw[0] = (raw[0] ?? 0) ^ 0x01;
    await expect(
      decryptStateEnvelope(
        sealedDocument({ ...fields, ciphertext: raw.toString('base64url') }) as never,
        encryptionKey,
        CONTEXT,
      ),
    ).rejects.toThrow(/Authentication failed/u);

    const tag = Buffer.from(fields.authenticationTag, 'base64url');
    if (tag.length === 0) throw new Error('unexpected empty tag');
    tag[0] = (tag[0] ?? 0) ^ 0x01;
    await expect(
      decryptStateEnvelope(
        sealedDocument({
          ...fields,
          authenticationTag: tag.toString('base64url'),
        }) as never,
        encryptionKey,
        CONTEXT,
      ),
    ).rejects.toThrow(/Authentication failed/u);
  });

  it.each([
    ['scope kind', { scopeKind: 'vault' as const }],
    ['scope id', { scopeId: 'db_other' }],
    ['sequence', { sequence: 8 }],
    ['sequence regression', { sequence: 6 }],
  ])(
    'refuses transplant to a different $label via the authenticated context',
    async (_label, override) => {
      const encryptionKey = key();
      const fields = await encryptStateEnvelope(
        new TextEncoder().encode('state'),
        encryptionKey,
        CONTEXT,
      );
      await expect(
        decryptStateEnvelope(sealedDocument(fields) as never, encryptionKey, {
          ...CONTEXT,
          ...override,
        }),
      ).rejects.toThrow(/Authentication failed/u);
    },
  );

  it('binds the domain so vault AEAD contexts can never be substituted', async () => {
    const encryptionKey = key();
    const plaintext = new TextEncoder().encode('state');
    const fields = await encryptStateEnvelope(plaintext, encryptionKey, {
      domain: 'kavrix/authorization-state/v1',
      scopeKind: 'database',
      scopeId: 'db_x',
      sequence: 1,
    });
    await expect(
      decryptStateEnvelope(sealedDocument(fields) as never, encryptionKey, {
        domain: 'kavrix/authorization-state/v1',
        scopeKind: 'database',
        scopeId: 'db_x',
        sequence: 2,
      }),
    ).rejects.toThrow(/Authentication failed/u);
  });

  it('requires exactly 32-byte keys and non-empty bounded plaintext', async () => {
    const plaintext = new TextEncoder().encode('state');
    await expect(
      encryptStateEnvelope(plaintext, new Uint8Array(31), CONTEXT),
    ).rejects.toThrow(/32 bytes/u);
    await expect(
      encryptStateEnvelope(new Uint8Array(0), key(), CONTEXT),
    ).rejects.toThrow(/plaintext/u);
    await expect(
      encryptStateEnvelope(new Uint8Array(512 * 1024 + 1), key(), CONTEXT),
    ).rejects.toThrow(/plaintext/u);
  });
});
