import { Writable } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { SyncConflictError } from '@kavrix/core';
import {
  aeadEnvelopeSchema,
  associatedDataSchema,
  changeIdSchema,
  changeRecordSchema,
  deviceIdSchema,
  deviceRecordSchema,
  encryptedGroupRecordSchema,
  inviteRedeemResponseSchema,
  keySlotIdSchema,
  opaqueMutationSchema,
  templateMigrationPublicationRequestSchema,
  timestampSchema,
  vaultRecordSchema,
  type VaultRecord,
  type TemplateMigrationPublicationRequest,
} from '@kavrix/schemas';
import type { FastifyInstance } from 'fastify';

import { buildApi } from '../src/index.js';
import {
  authHeader,
  createTestPorts,
  digest,
  envelope,
  groupTombstone,
  nowIso,
  otherVaultId,
  vaultFixture,
  vaultId,
} from './helpers.js';

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

describe('zero-knowledge Fastify API', () => {
  it('serves health and requires HTTPS in production', async () => {
    const fixture = await createTestPorts();
    expect(() =>
      buildApi({
        ports: fixture.ports,
        environment: 'production',
        trustedProxy: true as never,
      }),
    ).toThrow('explicit IP');
    for (const trustedProxy of [
      (() => true) as never,
      '0.0.0.0/0',
      '::/0',
      'proxy.example.com',
    ]) {
      expect(() =>
        buildApi({
          ports: fixture.ports,
          environment: 'production',
          trustedProxy,
        }),
      ).toThrow('explicit IP');
    }
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'production' }));
    const insecure = await app.inject({ method: 'GET', url: '/health' });
    expect(insecure.statusCode).toBe(426);
    const spoofed = await app.inject({
      method: 'GET',
      url: '/health',
      headers: { 'x-forwarded-proto': 'https' },
    });
    expect(spoofed.statusCode).toBe(426);
    const trustedApp = tracked(
      buildApi({
        ports: fixture.ports,
        environment: 'production',
        trustedProxy: '127.0.0.1',
      }),
    );
    const secure = await trustedApp.inject({
      method: 'GET',
      url: '/health',
      headers: { 'x-forwarded-proto': 'https' },
    });
    expect(secure.statusCode).toBe(200);
    expect(secure.json()).toEqual({ status: 'ok' });
    expect(secure.headers['cache-control']).toBe('no-store');
  });

  it('returns one generic error for missing, malformed, and unknown sessions', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const missing = await app.inject({ method: 'GET', url: `/v1/vaults/${vaultId}` });
    const malformed = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}`,
      headers: { authorization: 'Bearer malformed' },
    });
    const unknown = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}`,
      headers: authHeader(Buffer.alloc(32, 99).toString('base64url')),
    });
    expect([missing.statusCode, malformed.statusCode, unknown.statusCode]).toEqual([
      401, 401, 401,
    ]);
    expect(missing.json()).toEqual(malformed.json());
    expect(malformed.json()).toEqual(unknown.json());
    expect(unknown.json()).toEqual({
      error: { code: 'AUTHENTICATION_FAILED', message: 'Authentication failed' },
    });
    const malformedJson = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: {
        ...authHeader(fixture.token),
        'content-type': 'application/json',
      },
      payload: '{',
    });
    expect(malformedJson.statusCode).toBe(400);
  });

  it('requires an independent canonical successor credential for exchanges', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const inviteToken = await issueInvite(app, fixture.token, 600);
    const responses = await Promise.all([
      app.inject({
        method: 'POST',
        url: '/v1/invites/redeem',
        headers: authHeader(inviteToken),
      }),
      app.inject({
        method: 'POST',
        url: '/v1/invites/redeem',
        headers: {
          ...authHeader(inviteToken),
          'x-kavrix-successor-token': 'malformed',
        },
      }),
      app.inject({
        method: 'POST',
        url: '/v1/invites/redeem',
        headers: exchangeHeaders(inviteToken, inviteToken),
      }),
    ]);
    expect(responses.map(({ statusCode }) => statusCode)).toEqual([401, 401, 401]);
    expect(responses[0].json()).toEqual(responses[1].json());
    expect(responses[1].json()).toEqual(responses[2].json());
    expect(fixture.authorization.enrollments.size).toBe(0);
  });

  it('rejects bearer-hash collisions without consuming exchange authorization', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const inviteToken = await issueInvite(app, fixture.token, 600);
    const collidedRedemption = await app.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(inviteToken, fixture.token),
    });
    expect(collidedRedemption.statusCode).toBe(401);
    expect(fixture.authorization.enrollments.size).toBe(0);

    const enrollmentToken = (await fixture.ports.tokens.issue()).token;
    const redemption = await app.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(inviteToken, enrollmentToken),
    });
    expect(redemption.statusCode).toBe(200);
    const payload = {
      vaultId,
      deviceId: 'device-credential-collision',
      schemaVersion: 1,
    };
    for (const collidedSuccessor of [inviteToken, fixture.token]) {
      const collidedCompletion = await app.inject({
        method: 'POST',
        url: '/v1/enrollments/complete',
        headers: exchangeHeaders(enrollmentToken, collidedSuccessor),
        payload,
      });
      expect(collidedCompletion.statusCode).toBe(401);
    }
    expect(fixture.authorization.enrollments.size).toBe(1);
    const sessionToken = (await fixture.ports.tokens.issue()).token;
    const completion = await app.inject({
      method: 'POST',
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload,
    });
    expect(completion.statusCode).toBe(201);
  });

  it('bounds exact exchange replay by the original authorization expiry', async () => {
    const fixture = await createTestPorts();
    const app = tracked(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        enrollmentLifetimeSeconds: 60,
      }),
    );
    const inviteToken = await issueInvite(app, fixture.token, 60);
    const enrollmentToken = (await fixture.ports.tokens.issue()).token;
    const redemptionRequest = {
      method: 'POST' as const,
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(inviteToken, enrollmentToken),
    };
    const firstRedemption = await app.inject(redemptionRequest);
    expect(firstRedemption.statusCode).toBe(200);
    const replayedRedemption = await app.inject(redemptionRequest);
    expect(replayedRedemption.statusCode).toBe(200);
    expect(replayedRedemption.json()).toEqual(firstRedemption.json());
    const sessionToken = (await fixture.ports.tokens.issue()).token;
    const completionRequest = {
      method: 'POST' as const,
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload: {
        vaultId,
        deviceId: 'device-bounded-replay',
        schemaVersion: 1,
      },
    };
    expect((await app.inject(completionRequest)).statusCode).toBe(201);
    fixture.clock.advanceSeconds(61);
    expect((await app.inject(redemptionRequest)).statusCode).toBe(401);
    expect((await app.inject(completionRequest)).statusCode).toBe(401);
    const session = await app.inject({
      method: 'GET',
      url: '/v1/session',
      headers: authHeader(sessionToken),
    });
    expect(session.statusCode).toBe(200);
  });

  it('returns the bound opaque vault on redemption and hides storage failures', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const inviteToken = await issueInvite(app, fixture.token, 600);
    const enrollmentToken = (await fixture.ports.tokens.issue()).token;
    const redemption = await app.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(inviteToken, enrollmentToken),
    });
    expect(redemption.statusCode).toBe(200);
    const redeemed = inviteRedeemResponseSchema.parse(redemption.json());
    expect(redeemed).toMatchObject({
      vaultId,
      vault: vaultFixture(vaultId),
    });

    const missingFixture = await createTestPorts();
    const missingApp = tracked(
      buildApi({ ports: missingFixture.ports, environment: 'test' }),
    );
    const missingInvite = await issueInvite(missingApp, missingFixture.token, 600);
    missingFixture.storage.vaults.delete(vaultId);
    const missing = await missingApp.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(
        missingInvite,
        (await missingFixture.ports.tokens.issue()).token,
      ),
    });

    const crossedFixture = await createTestPorts();
    const crossedApp = tracked(
      buildApi({ ports: crossedFixture.ports, environment: 'test' }),
    );
    const crossedInvite = await issueInvite(crossedApp, crossedFixture.token, 600);
    crossedFixture.storage.vaults.set(vaultId, vaultFixture(otherVaultId));
    const crossed = await crossedApp.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(
        crossedInvite,
        (await crossedFixture.ports.tokens.issue()).token,
      ),
    });
    expect([missing.statusCode, crossed.statusCode]).toEqual([401, 401]);
    expect(missing.json()).toEqual(crossed.json());
    expect(missingFixture.authorization.enrollments.size).toBe(1);
    expect(crossedFixture.authorization.enrollments.size).toBe(1);
  });

  it('source-rates rotating unknown bearer tokens before authorization lookup', async () => {
    const fixture = await createTestPorts();
    const app = tracked(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        anonymousRatePolicy: { limit: 2, windowSeconds: 60 },
        sourceRatePolicy: { limit: 2, windowSeconds: 60 },
      }),
    );
    const responses = await Promise.all(
      [90, 91, 92].map(async (fill) =>
        app.inject({
          method: 'GET',
          url: `/v1/vaults/${vaultId}`,
          headers: authHeader(Buffer.alloc(32, fill).toString('base64url')),
        }),
      ),
    );
    expect(responses.map(({ statusCode }) => statusCode)).toEqual([401, 401, 429]);
  });

  it('keeps legitimate authenticated traffic separate from strict anonymous limits', async () => {
    const fixture = await createTestPorts();
    const app = tracked(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        anonymousRatePolicy: { limit: 1, windowSeconds: 60 },
        sourceRatePolicy: { limit: 20, windowSeconds: 60 },
      }),
    );
    const responses = await Promise.all(
      Array.from({ length: 3 }, async () =>
        app.inject({
          method: 'GET',
          url: `/v1/vaults/${vaultId}`,
          headers: authHeader(fixture.token),
        }),
      ),
    );
    expect(responses.map(({ statusCode }) => statusCode)).toEqual([200, 200, 200]);
  });

  it('source-rates requests before body parsing and recursive boundary validation', async () => {
    const fixture = await createTestPorts();
    const app = tracked(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        sourceRatePolicy: { limit: 1, windowSeconds: 60 },
      }),
    );
    const request = {
      method: 'POST' as const,
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
      payload: { scopes: ['sync:read'], expiresInSeconds: 600, plaintext: 'x' },
    };
    const first = await app.inject(request);
    const second = await app.inject(request);
    expect([first.statusCode, second.statusCode]).toEqual([400, 429]);
    expect(fixture.authorization.invites.size).toBe(0);
  });

  it('enforces scopes and vault isolation before storage access', async () => {
    const fixture = await createTestPorts(['sync:read']);
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const forbiddenScope = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
      payload: { scopes: ['sync:read'], expiresInSeconds: 600 },
    });
    const otherVault = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${otherVaultId}`,
      headers: authHeader(fixture.token),
    });
    expect(forbiddenScope.statusCode).toBe(403);
    expect(otherVault.statusCode).toBe(403);
  });

  it('issues, redeems, enrolls, lists, and revokes hash-only device tokens', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const invite = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
      payload: {
        scopes: ['sync:read', 'sync:write'],
        expiresInSeconds: 600,
      },
    });
    expect(invite.statusCode).toBe(201);
    const issuedInvite = json<{ inviteId: string; inviteToken: string }>(invite);
    const inviteToken = issuedInvite.inviteToken;
    expect(JSON.stringify([...fixture.authorization.invites.values()])).not.toContain(
      inviteToken,
    );
    const activeInvites = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
    });
    expect(activeInvites.statusCode).toBe(200);
    expect(activeInvites.json()).toMatchObject({
      invites: [{ id: issuedInvite.inviteId, state: 'active' }],
    });
    expect(activeInvites.body).not.toContain('tokenHash');

    const enrollmentIssued = await fixture.ports.tokens.issue();
    const redemption = await app.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(inviteToken, enrollmentIssued.token),
    });
    expect(redemption.statusCode).toBe(200);
    const enrollmentToken = enrollmentIssued.token;
    expect(redemption.body).not.toContain(enrollmentToken);
    const replay = await app.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(inviteToken, enrollmentToken),
    });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toEqual(redemption.json());
    const redeemedInvites = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
    });
    expect(redeemedInvites.json()).toMatchObject({
      invites: [{ id: issuedInvite.inviteId, state: 'redeemed' }],
    });

    const newDeviceId = deviceIdSchema.parse('device-2');
    const sessionIssued = await fixture.ports.tokens.issue();
    const sessionToken = sessionIssued.token;
    const collidedCompletion = await app.inject({
      method: 'POST',
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload: { vaultId, deviceId: 'device-1', schemaVersion: 1 },
    });
    expect(collidedCompletion.statusCode).toBe(401);
    const crossedCompletion = await app.inject({
      method: 'POST',
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload: { vaultId: otherVaultId, deviceId: newDeviceId, schemaVersion: 1 },
    });
    expect(crossedCompletion.statusCode).toBe(401);
    const completion = await app.inject({
      method: 'POST',
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload: { vaultId, deviceId: newDeviceId, schemaVersion: 1 },
    });
    expect(completion.statusCode).toBe(201);
    expect(completion.body).not.toContain(sessionToken);
    const completionReplay = await app.inject({
      method: 'POST',
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload: { vaultId, deviceId: newDeviceId, schemaVersion: 1 },
    });
    expect(completionReplay.statusCode).toBe(201);
    expect(completionReplay.json()).toEqual(completion.json());
    expect(JSON.stringify([...fixture.authorization.devices.values()])).not.toContain(
      sessionToken,
    );

    const session = await app.inject({
      method: 'GET',
      url: '/v1/session',
      headers: authHeader(sessionToken),
    });
    expect(session.statusCode).toBe(200);
    expect(session.json()).toMatchObject({ vaultId, deviceId: newDeviceId });
    for (const oldToken of [inviteToken, enrollmentToken]) {
      const oldCredential = await app.inject({
        method: 'GET',
        url: '/v1/session',
        headers: authHeader(oldToken),
      });
      expect(oldCredential.statusCode).toBe(401);
    }

    const devices = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/devices`,
      headers: authHeader(fixture.token),
    });
    expect(devices.statusCode).toBe(200);
    expect(devices.body).not.toContain('tokenHash');
    expect(devices.body).not.toContain(sessionToken);

    const revoked = await app.inject({
      method: 'DELETE',
      url: `/v1/vaults/${vaultId}/devices/${newDeviceId}`,
      headers: authHeader(fixture.token),
    });
    expect(revoked.statusCode).toBe(204);
    const afterRevocation = await app.inject({
      method: 'GET',
      url: '/v1/session',
      headers: authHeader(sessionToken),
    });
    expect(afterRevocation.statusCode).toBe(401);
  });

  it('lists and revokes an unused invite by opaque ID', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const issued = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
      payload: { scopes: ['sync:read'], expiresInSeconds: 600 },
    });
    const invite = json<{ inviteId: string; inviteToken: string }>(issued);

    const revoked = await app.inject({
      method: 'DELETE',
      url: `/v1/vaults/${vaultId}/invites/${invite.inviteId}`,
      headers: authHeader(fixture.token),
    });
    expect(revoked.statusCode).toBe(204);
    const redemption = await app.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(
        invite.inviteToken,
        (await fixture.ports.tokens.issue()).token,
      ),
    });
    expect(redemption.statusCode).toBe(401);
    const secondRevocation = await app.inject({
      method: 'DELETE',
      url: `/v1/vaults/${vaultId}/invites/${invite.inviteId}`,
      headers: authHeader(fixture.token),
    });
    expect(secondRevocation.statusCode).toBe(204);
    const listed = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
    });
    expect(listed.json()).toMatchObject({
      invites: [{ id: invite.inviteId, state: 'revoked' }],
    });
  });

  it('allows exactly one concurrent invite redemption or revocation to win', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const issued = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
      payload: { scopes: ['sync:read'], expiresInSeconds: 600 },
    });
    const invite = json<{ inviteId: string; inviteToken: string }>(issued);
    const enrollmentToken = (await fixture.ports.tokens.issue()).token;

    const [redemption, revocation] = await Promise.all([
      app.inject({
        method: 'POST',
        url: '/v1/invites/redeem',
        headers: exchangeHeaders(invite.inviteToken, enrollmentToken),
      }),
      app.inject({
        method: 'DELETE',
        url: `/v1/vaults/${vaultId}/invites/${invite.inviteId}`,
        headers: authHeader(fixture.token),
      }),
    ]);
    expect([
      [200, 404],
      [401, 204],
    ]).toContainEqual([redemption.statusCode, revocation.statusCode]);
  });

  it('fails closed on missing resources and cross-vault authorization records', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const missingVault = await app.inject({
      method: 'GET',
      url: '/v1/vaults/vault-missing',
      headers: authHeader(fixture.token),
    });
    expect(missingVault.statusCode).toBe(403);

    const missingDevice = await app.inject({
      method: 'DELETE',
      url: `/v1/vaults/${vaultId}/devices/device-missing`,
      headers: authHeader(fixture.token),
    });
    expect(missingDevice.statusCode).toBe(404);

    const seeded = [...fixture.authorization.devices.values()][0];
    if (seeded === undefined) throw new Error('Missing seeded device');
    const crossed = deviceRecordSchema.parse({
      ...seeded,
      vaultId: otherVaultId,
    });
    const list = vi
      .spyOn(fixture.authorization, 'listDevices')
      .mockResolvedValueOnce([crossed]);
    const crossedList = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/devices`,
      headers: authHeader(fixture.token),
    });
    expect(crossedList.statusCode).toBe(500);
    list.mockRestore();

    fixture.storage.vaults.delete(vaultId);
    const absentVault = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}`,
      headers: authHeader(fixture.token),
    });
    expect(absentVault.statusCode).toBe(404);
  });

  it('rejects expired invite and enrollment tokens generically', async () => {
    const fixture = await createTestPorts();
    const app = tracked(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        enrollmentLifetimeSeconds: 60,
      }),
    );
    const expiredInvite = await issueInvite(app, fixture.token, 60);
    const expiredEnrollmentSuccessor = (await fixture.ports.tokens.issue()).token;
    fixture.clock.advanceSeconds(61);
    const inviteResponse = await app.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(expiredInvite, expiredEnrollmentSuccessor),
    });
    expect(inviteResponse.statusCode).toBe(401);

    const freshFixture = await createTestPorts();
    const freshApp = tracked(
      buildApi({
        ports: freshFixture.ports,
        environment: 'test',
        enrollmentLifetimeSeconds: 60,
      }),
    );
    const inviteToken = await issueInvite(freshApp, freshFixture.token, 600);
    const enrollmentToken = (await freshFixture.ports.tokens.issue()).token;
    const redeemed = await freshApp.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(inviteToken, enrollmentToken),
    });
    expect(redeemed.statusCode).toBe(200);
    freshFixture.clock.advanceSeconds(61);
    const sessionToken = (await freshFixture.ports.tokens.issue()).token;
    const completion = await freshApp.inject({
      method: 'POST',
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload: { vaultId, deviceId: 'device-expired', schemaVersion: 1 },
    });
    expect(completion.statusCode).toBe(401);
  });

  it('fetches opaque vaults and reports structured stale revision conflicts', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const fetched = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}`,
      headers: authHeader(fixture.token),
    });
    expect(fetched.statusCode).toBe(200);
    expect(fetched.body).toContain('ciphertext');

    const maliciousRecord = vaultRecordSchema.parse({
      ...vaultFixture(vaultId, 2),
      keySlots: vaultFixture(vaultId, 2).keySlots.map((slot) => ({
        ...slot,
        wrappedRootKey: { ...slot.wrappedRootKey, ciphertext: 'BAUG' },
      })),
    });
    const bypass = await app.inject({
      method: 'PUT',
      url: `/v1/vaults/${vaultId}/records`,
      headers: authHeader(fixture.token),
      payload: {
        entityType: 'vault',
        expectedVaultRevision: 1,
        idempotencyKey: 'opaque-slot-bypass-01',
        record: maliciousRecord,
      },
    });
    expect(bypass.statusCode).toBe(400);
    expect(fixture.storage.vaults.get(vaultId)?.revision).toBe(1);

    const revisionTwo = vaultFixture(vaultId, 2);
    const written = await app.inject({
      method: 'PUT',
      url: `/v1/vaults/${vaultId}/records`,
      headers: authHeader(fixture.token),
      payload: {
        entityType: 'vault',
        expectedVaultRevision: 1,
        idempotencyKey: 'opaque-write-0001',
        record: revisionTwo,
      },
    });
    expect(written.statusCode).toBe(204);

    const stale = await app.inject({
      method: 'PUT',
      url: `/v1/vaults/${vaultId}/records`,
      headers: authHeader(fixture.token),
      payload: {
        entityType: 'vault',
        expectedVaultRevision: 1,
        idempotencyKey: 'opaque-write-0002',
        record: vaultFixture(vaultId, 2),
      },
    });
    expect(stale.statusCode).toBe(409);
    expect(stale.json()).toEqual({
      error: {
        code: 'SYNC_CONFLICT',
        message: 'The opaque record has a revision conflict',
        conflict: {
          entityType: 'vault',
          entityId: vaultId,
          expectedRevision: 1,
          currentRevision: 2,
        },
      },
    });
  });

  it('publishes and revokes only the addressed canonical key slot', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const slotId = keySlotIdSchema.parse('slot-2');
    const publishedRecord = addSlot(vaultFixture(vaultId), slotId, 'active', 2);
    const maliciousPublish = vaultRecordSchema.parse({
      ...publishedRecord,
      keySlots: publishedRecord.keySlots.map((slot) =>
        slot.id === 'slot-1'
          ? {
              ...slot,
              wrappedRootKey: { ...slot.wrappedRootKey, ciphertext: 'BAUG' },
            }
          : slot,
      ),
    });
    const rejectedPublish = await app.inject({
      method: 'PUT',
      url: `/v1/vaults/${vaultId}/key-slots/${slotId}`,
      headers: authHeader(fixture.token),
      payload: {
        expectedVaultRevision: 1,
        idempotencyKey: 'slot-malicious-0001',
        record: maliciousPublish,
      },
    });
    expect(rejectedPublish.statusCode).toBe(400);
    expect(fixture.storage.vaults.get(vaultId)?.revision).toBe(1);

    const published = await app.inject({
      method: 'PUT',
      url: `/v1/vaults/${vaultId}/key-slots/${slotId}`,
      headers: authHeader(fixture.token),
      payload: {
        expectedVaultRevision: 1,
        idempotencyKey: 'slot-publish-0001',
        record: publishedRecord,
      },
    });
    expect(published.statusCode).toBe(204);

    const revokedRecord = addSlot(
      fixture.storage.vaults.get(vaultId) ?? publishedRecord,
      slotId,
      'revoked',
      3,
    );
    const maliciousRevoke = vaultRecordSchema.parse({
      ...revokedRecord,
      keySlots: revokedRecord.keySlots.map((slot) =>
        slot.id === 'slot-1'
          ? {
              ...slot,
              wrappedRootKey: { ...slot.wrappedRootKey, ciphertext: 'BwgJ' },
            }
          : slot,
      ),
    });
    const rejectedRevoke = await app.inject({
      method: 'DELETE',
      url: `/v1/vaults/${vaultId}/key-slots/${slotId}`,
      headers: authHeader(fixture.token),
      payload: {
        expectedVaultRevision: 2,
        idempotencyKey: 'slot-malicious-0002',
        record: maliciousRevoke,
      },
    });
    expect(rejectedRevoke.statusCode).toBe(400);
    expect(fixture.storage.vaults.get(vaultId)?.revision).toBe(2);

    const revoked = await app.inject({
      method: 'DELETE',
      url: `/v1/vaults/${vaultId}/key-slots/${slotId}`,
      headers: authHeader(fixture.token),
      payload: {
        expectedVaultRevision: 2,
        idempotencyKey: 'slot-revoke-00001',
        record: revokedRecord,
      },
    });
    expect(revoked.statusCode).toBe(204);

    const current = fixture.storage.vaults.get(vaultId);
    const onlySlot = current?.keySlots.find((slot) => slot.id === 'slot-1');
    expect(onlySlot).toBeDefined();
    const lastSlotRevocation = await app.inject({
      method: 'DELETE',
      url: `/v1/vaults/${vaultId}/key-slots/${String(onlySlot?.id)}`,
      headers: authHeader(fixture.token),
      payload: {
        expectedVaultRevision: 3,
        idempotencyKey: 'slot-last-current-01',
        record: {
          ...current,
          revision: 4,
          keySlots: current?.keySlots.map((slot) =>
            slot.id === onlySlot?.id
              ? { ...slot, state: 'revoked', revokedAt: nowIso }
              : slot,
          ),
        },
      },
    });
    expect(lastSlotRevocation.statusCode).toBe(400);

    const restricted = await createTestPorts(['sync:read', 'sync:write']);
    const restrictedApp = tracked(
      buildApi({ ports: restricted.ports, environment: 'test' }),
    );
    const unauthorizedSlot = await restrictedApp.inject({
      method: 'PUT',
      url: `/v1/vaults/${vaultId}/key-slots/${slotId}`,
      headers: authHeader(restricted.token),
      payload: {
        expectedVaultRevision: 1,
        idempotencyKey: 'slot-scope-denied-01',
        record: publishedRecord,
      },
    });
    expect(unauthorizedSlot.statusCode).toBe(403);
  });

  it('paginates opaque records and tombstones with bound cursors', async () => {
    const fixture = await createTestPorts();
    const tombstone = groupTombstone('group-1', 1);
    fixture.storage.changes.push(
      {
        change: changeRecordSchema.parse({
          id: changeIdSchema.parse('change-1'),
          vaultId,
          serverSequence: 1,
          recordRevision: 1,
          operation: 'tombstone',
          ciphertextHash: digest('tombstone'),
          createdAt: nowIso,
          entityType: 'group',
          entityId: tombstone.entityId,
        }),
        record: tombstone,
      },
      {
        change: changeRecordSchema.parse({
          id: changeIdSchema.parse('change-2'),
          vaultId,
          serverSequence: 2,
          recordRevision: 2,
          operation: 'purge',
          createdAt: nowIso,
          entityType: 'group',
          entityId: 'group-2',
        }),
        record: null,
      },
    );
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const firstPage = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/sync?highestSeenVaultRevision=1&limit=1`,
      headers: authHeader(fixture.token),
    });
    expect(firstPage.statusCode).toBe(200);
    expect(firstPage.json()).toMatchObject({
      vaultId,
      serverVaultRevision: 1,
      changes: [{ record: { state: 'deleted', entityId: 'group-1' } }],
      nextCursor: { serverSequence: 1, highestSeenVaultRevision: 1 },
      hasMore: true,
    });
    const secondPage = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/sync?serverSequence=1&highestSeenVaultRevision=1&limit=1`,
      headers: authHeader(fixture.token),
    });
    expect(secondPage.statusCode).toBe(200);
    expect(secondPage.json()).toMatchObject({
      changes: [{ record: null, change: { operation: 'purge' } }],
      nextCursor: { serverSequence: 2 },
      hasMore: false,
    });
  });

  it('returns ordered committed, duplicate, and conflict sync outcomes', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const committedBatch = {
      vaultId,
      batchIdempotencyKey: 'batch-committed-0001',
      mutations: [
        {
          entityType: 'vault',
          expectedVaultRevision: 1,
          idempotencyKey: 'mutation-committed-01',
          record: vaultFixture(vaultId, 2),
        },
      ],
    };
    const committed = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/sync`,
      headers: authHeader(fixture.token),
      payload: committedBatch,
    });
    expect(committed.statusCode).toBe(200);
    expect(committed.json()).toMatchObject({
      vaultId,
      serverVaultRevision: 2,
      results: [{ status: 'accepted', disposition: 'committed' }],
    });

    const duplicate = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/sync`,
      headers: authHeader(fixture.token),
      payload: committedBatch,
    });
    expect(duplicate.statusCode).toBe(200);
    expect(duplicate.json()).toMatchObject({
      results: [{ status: 'accepted', disposition: 'duplicate' }],
    });

    const conflict = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/sync`,
      headers: authHeader(fixture.token),
      payload: {
        vaultId,
        batchIdempotencyKey: 'batch-conflict-00001',
        mutations: [
          {
            entityType: 'vault',
            expectedVaultRevision: 1,
            idempotencyKey: 'mutation-conflict-001',
            record: vaultFixture(vaultId, 2),
          },
        ],
      },
    });
    expect(conflict.statusCode).toBe(200);
    expect(conflict.json()).toMatchObject({
      serverVaultRevision: 2,
      results: [
        {
          status: 'conflict',
          currentRevision: 2,
          current: { id: vaultId, revision: 2 },
        },
      ],
    });
  });

  it('rejects cross-vault sync batches before invoking storage', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));

    const crossVault = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/sync`,
      headers: authHeader(fixture.token),
      payload: {
        vaultId: otherVaultId,
        batchIdempotencyKey: 'batch-cross-vault01',
        mutations: [
          {
            entityType: 'vault',
            expectedVaultRevision: 1,
            idempotencyKey: 'cross-vault-00001',
            record: vaultFixture(otherVaultId, 2),
          },
        ],
      },
    });
    expect(crossVault.statusCode).toBe(400);
    expect(fixture.storage.batches.size).toBe(0);

    const protectedRecord = vaultFixture(vaultId, 2);
    const slotBypass = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/sync`,
      headers: authHeader(fixture.token),
      payload: {
        vaultId,
        batchIdempotencyKey: 'batch-slot-bypass01',
        mutations: [
          {
            entityType: 'vault',
            expectedVaultRevision: 1,
            idempotencyKey: 'mutation-slot-bypass',
            record: {
              ...protectedRecord,
              keySlots: protectedRecord.keySlots.map((slot) => ({
                ...slot,
                wrappedRootKey: { ...slot.wrappedRootKey, ciphertext: 'BAUG' },
              })),
            },
          },
        ],
      },
    });
    expect(slotBypass.statusCode).toBe(400);
    expect(fixture.storage.batches.size).toBe(0);
  });

  it('publishes template migrations only after auth, scope, body, and rate checks', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const batch = apiTemplateMigrationBatch();
    const published = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/template-migrations`,
      headers: authHeader(fixture.token),
      payload: batch,
    });
    expect(published.statusCode).toBe(200);
    expect(published.json()).toMatchObject({
      vaultId,
      batchIdempotencyKey: batch.batchIdempotencyKey,
      results: [{ change: { entityType: 'group', operation: 'upsert' } }],
    });

    const missingAuth = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/template-migrations`,
      payload: batch,
    });
    expect(missingAuth.statusCode).toBe(401);
    const malformed = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/template-migrations`,
      headers: authHeader(fixture.token),
      payload: { ...batch, mutations: [] },
    });
    expect(malformed.statusCode).toBe(400);

    const restricted = await createTestPorts(['sync:read']);
    const restrictedApp = tracked(
      buildApi({ ports: restricted.ports, environment: 'test' }),
    );
    const denied = await restrictedApp.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/template-migrations`,
      headers: authHeader(restricted.token),
      payload: batch,
    });
    expect(denied.statusCode).toBe(403);

    const rateLimited = await createTestPorts();
    rateLimited.rateLimits.denied = true;
    const rateApp = tracked(
      buildApi({ ports: rateLimited.ports, environment: 'test' }),
    );
    const rateResponse = await rateApp.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/template-migrations`,
      headers: authHeader(rateLimited.token),
      payload: batch,
    });
    expect(rateResponse.statusCode).toBe(429);

    const failed = await createTestPorts();
    vi.spyOn(failed.storage, 'publishTemplateMigration').mockRejectedValueOnce(
      new Error('internal migration canary'),
    );
    const failedApp = tracked(buildApi({ ports: failed.ports, environment: 'test' }));
    const generic = await failedApp.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/template-migrations`,
      headers: authHeader(failed.token),
      payload: batch,
    });
    expect(generic.statusCode).toBe(500);
    expect(generic.body).not.toContain('internal migration canary');

    const conflicted = await createTestPorts();
    vi.spyOn(conflicted.storage, 'publishTemplateMigration').mockRejectedValueOnce(
      new SyncConflictError(),
    );
    const conflictedApp = tracked(
      buildApi({ ports: conflicted.ports, environment: 'test' }),
    );
    const conflict = await conflictedApp.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/template-migrations`,
      headers: authHeader(conflicted.token),
      payload: batch,
    });
    expect(conflict.statusCode).toBe(409);
    expect(conflict.json()).toEqual({
      error: {
        code: 'SYNC_CONFLICT',
        message: 'The opaque migration publication has a revision conflict',
      },
    });
  });

  it('bounds bodies and rates, rejects secret fields, and never logs bodies or tokens', async () => {
    const fixture = await createTestPorts();
    const logs: string[] = [];
    const stream = new Writable({
      write(chunk, _encoding, callback) {
        logs.push(String(chunk));
        callback();
      },
    });
    const app = tracked(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        bodyLimit: 512,
        authenticatedRatePolicy: { limit: 1, windowSeconds: 60 },
        logStream: stream,
      }),
    );
    const canary = 'plaintext-log-canary-47af';
    for (const field of ['passphrase', 'recovery_key', 'portableKey', 'unwrappedVrk']) {
      const forbidden = await app.inject({
        method: 'POST',
        url: `/v1/vaults/${vaultId}/invites`,
        headers: authHeader(fixture.token),
        payload: {
          scopes: ['sync:read'],
          expiresInSeconds: 600,
          [field]: canary,
        },
      });
      expect(forbidden.statusCode).toBe(400);
    }

    const first = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}`,
      headers: authHeader(fixture.token),
    });
    const rateLimited = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}`,
      headers: authHeader(fixture.token),
    });
    expect(first.statusCode).toBe(200);
    expect(rateLimited.statusCode).toBe(429);

    const oversized = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
      payload: { padding: 'x'.repeat(1_000) },
    });
    expect(oversized.statusCode).toBe(413);
    const successorCanary = Buffer.alloc(32, 61).toString('base64url');
    const exchange = await app.inject({
      method: 'POST',
      url: '/v1/invites/redeem',
      headers: exchangeHeaders(successorCanary, successorCanary),
    });
    expect(exchange.statusCode).toBe(401);
    expect(logs.join('')).not.toContain(canary);
    expect(logs.join('')).not.toContain(fixture.token);
    expect(logs.join('')).not.toContain(successorCanary);
  });
});

function apiTemplateMigrationBatch(): TemplateMigrationPublicationRequest {
  const groupId = 'group-api-template';
  const envelopeFor = (
    entityType: 'group' | 'wrapped-group-key',
    purpose: 'group-payload' | 'group-key',
  ): ReturnType<typeof aeadEnvelopeSchema.parse> =>
    aeadEnvelopeSchema.parse({
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: Buffer.alloc(24).toString('base64url'),
      ciphertext: Buffer.from('api-template-migration-plaintext').toString('base64url'),
      authenticationTag: Buffer.alloc(16).toString('base64url'),
      aad: associatedDataSchema.parse({
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId,
        entityType,
        entityId: groupId,
        purpose,
      }),
      keyVersion: 1,
    });
  const record = encryptedGroupRecordSchema.parse({
    id: groupId,
    vaultId,
    schemaVersion: 1,
    wrappedGroupKey: envelopeFor('wrapped-group-key', 'group-key'),
    encryptedPayload: envelopeFor('group', 'group-payload'),
    templateVersion: 2,
    recordRevision: 1,
    createdAt: nowIso,
    updatedAt: nowIso,
  });
  return templateMigrationPublicationRequestSchema.parse({
    vaultId,
    batchIdempotencyKey: 'api-template-batch-0001',
    mutations: [
      opaqueMutationSchema.parse({
        entityType: 'group',
        expectedRecordRevision: 0,
        idempotencyKey: 'api-template-group-0001',
        record,
      }),
    ],
  });
}

async function issueInvite(
  app: FastifyInstance,
  token: string,
  expiresInSeconds: number,
): Promise<string> {
  const response = await app.inject({
    method: 'POST',
    url: `/v1/vaults/${vaultId}/invites`,
    headers: authHeader(token),
    payload: { scopes: ['sync:read'], expiresInSeconds },
  });
  expect(response.statusCode).toBe(201);
  return json<{ inviteToken: string }>(response).inviteToken;
}

function addSlot(
  source: VaultRecord,
  slotId: ReturnType<typeof keySlotIdSchema.parse>,
  state: 'active' | 'revoked',
  revision: number,
): VaultRecord {
  const base = source.keySlots.find((slot) => slot.id === slotId) ?? source.keySlots[0];
  if (base?.type !== 'portable-key') {
    throw new Error('Expected portable fixture slot');
  }
  const updated = {
    ...base,
    id: slotId,
    state,
    wrappedRootKey: envelope(vaultId, 'wrapped-root-key', slotId, 'vrk-slot'),
    ...(state === 'revoked' ? { revokedAt: timestampSchema.parse(nowIso) } : {}),
  } as const;
  return vaultRecordSchema.parse({
    ...source,
    revision,
    keySlots: [...source.keySlots.filter((slot) => slot.id !== slotId), updated],
  });
}

function tracked(app: FastifyInstance): FastifyInstance {
  apps.push(app);
  return app;
}

function json<Output>(response: { json(): Output }): Output {
  return response.json();
}

function exchangeHeaders(
  parentToken: string,
  successorToken: string,
): Record<string, string> {
  return {
    ...authHeader(parentToken),
    'x-kavrix-successor-token': successorToken,
  };
}
