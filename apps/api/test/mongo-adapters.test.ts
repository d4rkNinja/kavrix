import { describe, expect, it } from 'vitest';

import {
  deviceIdSchema,
  inviteIdSchema,
  schemaVersionSchema,
  sha256DigestSchema,
  timestampSchema,
  vaultIdSchema,
  type Sha256Digest,
} from '@kavrix/schemas';

import {
  enrollmentCompletionHash,
  inviteGrantDocument,
  mongoApiCollectionOptions,
  mongoApiCredentialClaimDocumentSchema,
  mongoApiInviteDocumentSchema,
  publicInviteFromDocument,
} from '../src/mongo-documents.js';
import { fixedWindowIdentity } from '../src/mongo-rate-limit.js';
import { parseMongoApiServerConfig } from '../src/server.js';

const vaultId = vaultIdSchema.parse('vault.mongo-test');
const deviceId = deviceIdSchema.parse('device.mongo-test');
const createdAt = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const expiresAt = timestampSchema.parse('2026-08-10T00:10:00.000Z');
const hash = (fill: number): Sha256Digest =>
  sha256DigestSchema.parse(Buffer.alloc(32, fill).toString('base64url'));

describe('Mongo API persistence contracts', () => {
  it('projects invite state without exposing token hashes', () => {
    const active = inviteGrantDocument({
      id: inviteIdSchema.parse('invite.mongo-test'),
      tokenHash: hash(1),
      vaultId,
      scopes: ['sync:read'],
      issuedByDeviceId: deviceId,
      createdAt,
      expiresAt,
    });
    const publicActive = publicInviteFromDocument(
      active,
      new Date('2026-08-10T00:01:00.000Z'),
    );
    expect(publicActive.state).toBe('active');
    expect(JSON.stringify(publicActive)).not.toContain(active.tokenHash);
    expect(
      publicInviteFromDocument(active, new Date('2026-08-10T00:11:00.000Z')).state,
    ).toBe('expired');

    const redeemed = mongoApiInviteDocumentSchema.parse({
      ...active,
      state: 'redeemed',
      consumedAt: createdAt,
      enrollmentTokenHash: hash(2),
      enrollmentExpiresAt: expiresAt,
    });
    expect(
      publicInviteFromDocument(redeemed, new Date('2026-08-10T00:01:00.000Z')),
    ).toMatchObject({ state: 'redeemed', consumedAt: createdAt });
  });

  it('strictly rejects plaintext-bearing and inconsistent documents', () => {
    const active = inviteGrantDocument({
      id: inviteIdSchema.parse('invite.strict-test'),
      tokenHash: hash(3),
      vaultId,
      scopes: ['sync:read'],
      issuedByDeviceId: deviceId,
      createdAt,
      expiresAt,
    });
    expect(
      mongoApiInviteDocumentSchema.safeParse({
        ...active,
        passphrase: 'plaintext-canary',
      }).success,
    ).toBe(false);
    expect(
      mongoApiCredentialClaimDocumentSchema.safeParse({
        _id: hash(4),
        kind: 'invite',
        parentHash: hash(3),
        createdAt,
      }).success,
    ).toBe(false);
    expect(mongoApiCollectionOptions.api_sessions.validator).toMatchObject({
      $jsonSchema: { additionalProperties: false },
    });
  });

  it('hashes rate keys into aligned fixed windows', () => {
    const first = fixedWindowIdentity({
      key: 'source:/route:192.0.2.1',
      limit: 5,
      windowSeconds: 60,
      now: new Date('2026-08-10T00:00:59.999Z'),
    });
    const next = fixedWindowIdentity({
      key: 'source:/route:192.0.2.1',
      limit: 5,
      windowSeconds: 60,
      now: new Date('2026-08-10T00:01:00.000Z'),
    });
    expect(first.id).not.toContain('192.0.2.1');
    expect(first.windowStartedAt.toISOString()).toBe('2026-08-10T00:00:00.000Z');
    expect(first.expiresAt.toISOString()).toBe('2026-08-10T00:01:00.000Z');
    expect(next.id).not.toBe(first.id);
    expect(() =>
      fixedWindowIdentity({
        key: 'invalid',
        limit: 0,
        windowSeconds: 60,
        now: new Date(createdAt),
      }),
    ).toThrow('Invalid rate-limit attempt');
  });

  it('canonically binds enrollment replay receipts to all input', () => {
    const base = {
      vaultId,
      deviceId,
      schemaVersion: schemaVersionSchema.parse(1),
      sessionTokenHash: hash(5),
    };
    expect(enrollmentCompletionHash(base)).toBe(enrollmentCompletionHash(base));
    expect(enrollmentCompletionHash({ ...base, sessionTokenHash: hash(6) })).not.toBe(
      enrollmentCompletionHash(base),
    );
  });

  it('validates server configuration and rejects TLS-secret fields', () => {
    expect(
      parseMongoApiServerConfig({
        mongodbUri: 'mongodb://127.0.0.1:27017',
        databaseName: 'kavrix_api',
        environment: 'production',
      }),
    ).toMatchObject({ host: '127.0.0.1', port: 3000 });
    expect(
      parseMongoApiServerConfig({
        mongodbUri: 'mongodb://127.0.0.1:27017',
        databaseName: 'kavrix_api',
        environment: 'production',
        vaultBootstrapEnabled: true,
      }),
    ).toMatchObject({ vaultBootstrapEnabled: true });
    expect(() =>
      parseMongoApiServerConfig({
        mongodbUri: 'mongodb://127.0.0.1:27017',
        databaseName: 'kavrix_api',
        environment: 'production',
        vaultBootstrapEnabled: 'true',
      }),
    ).toThrow();
    expect(() =>
      parseMongoApiServerConfig({
        mongodbUri: 'mongodb://127.0.0.1:27017',
        databaseName: 'kavrix_api',
        environment: 'production',
        tlsPrivateKey: 'must-not-be-owned',
      }),
    ).toThrow();
  });
});
