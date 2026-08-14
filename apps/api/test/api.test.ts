import { Writable } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { SyncConflictError } from '@kavrix/core';
import {
  aeadEnvelopeSchema,
  associatedDataSchema,
  changeIdSchema,
  changeRecordSchema,
  decodeControlListCursor,
  deviceIdSchema,
  deviceRecordSchema,
  encryptedGroupRecordSchema,
  encodeControlListCursor,
  inviteIdSchema,
  inviteRedeemResponseSchema,
  keySlotIdSchema,
  opaqueMutationSchema,
  templateMigrationPublicationRequestSchema,
  timestampSchema,
  vaultRecordSchema,
  type VaultRecord,
  type Sha256Digest,
  type TemplateMigrationPublicationRequest,
} from '@kavrix/schemas';
import type { FastifyInstance } from 'fastify';

import { buildApi } from '../src/index.js';
import {
  authHeader,
  createTestPorts,
  deviceId,
  deviceLabelEnvelope,
  digest,
  envelope,
  groupTombstone,
  MemoryAuthorization,
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

  it('serves dependency readiness without exposing the dependency error', async () => {
    const readyFixture = await createTestPorts();
    const readyApp = tracked(
      buildApi({
        ports: readyFixture.ports,
        environment: 'test',
        readiness: () => Promise.resolve(true),
      }),
    );
    const ready = await readyApp.inject({ method: 'GET', url: '/ready' });
    expect(ready.statusCode).toBe(200);
    expect(ready.json()).toEqual({ status: 'ready' });

    const unavailableFixture = await createTestPorts();
    const unavailableApp = tracked(
      buildApi({
        ports: unavailableFixture.ports,
        environment: 'test',
        readiness: () => Promise.resolve(false),
      }),
    );
    const unavailable = await unavailableApp.inject({
      method: 'GET',
      url: '/ready',
    });
    expect(unavailable.statusCode).toBe(503);
    expect(unavailable.json()).toEqual({ status: 'not_ready' });

    const failedFixture = await createTestPorts();
    const failedApp = tracked(
      buildApi({
        ports: failedFixture.ports,
        environment: 'test',
        readiness: () => Promise.reject(new Error('readiness plaintext-canary')),
      }),
    );
    const failed = await failedApp.inject({ method: 'GET', url: '/ready' });
    expect(failed.statusCode).toBe(503);
    expect(failed.body).not.toContain('readiness plaintext-canary');

    const productionFixture = await createTestPorts();
    const productionApp = tracked(
      buildApi({
        ports: productionFixture.ports,
        environment: 'production',
        readiness: () => Promise.resolve(true),
      }),
    );
    const insecure = await productionApp.inject({ method: 'GET', url: '/ready' });
    expect(insecure.statusCode).toBe(426);
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

  it('fails closed before storage when a session diverges from its canonical device', async () => {
    const mutations: readonly ((
      fixture: Awaited<ReturnType<typeof createTestPorts>>,
      tokenHash: Sha256Digest,
    ) => void)[] = [
      (fixture) => {
        const device = fixture.authorization.devices.get(deviceId);
        if (device === undefined) throw new Error('Missing canonical device fixture');
        fixture.authorization.devices.set(
          deviceId,
          deviceRecordSchema.parse({
            ...device,
            tokenHash: digest('other-device-token'),
          }),
        );
      },
      (fixture) => {
        const device = fixture.authorization.devices.get(deviceId);
        if (device === undefined) throw new Error('Missing canonical device fixture');
        fixture.authorization.devices.set(
          deviceId,
          deviceRecordSchema.parse({ ...device, scopes: ['sync:read'] }),
        );
      },
      (fixture, tokenHash) => {
        const session = fixture.authorization.sessions.get(tokenHash);
        if (session === undefined) throw new Error('Missing session fixture');
        fixture.authorization.sessions.set(tokenHash, {
          ...session,
          scopes: ['sync:read'],
        });
      },
      (fixture) => {
        const device = fixture.authorization.devices.get(deviceId);
        if (device === undefined) throw new Error('Missing canonical device fixture');
        fixture.authorization.devices.set(deviceId, {
          ...device,
          tokenVersion: 2,
        } as never);
      },
    ];

    for (const mutate of mutations) {
      const fixture = await createTestPorts();
      const canonicalDevice = fixture.authorization.devices.get(deviceId);
      if (canonicalDevice === undefined) throw new Error('Missing canonical device');
      const tokenHash = canonicalDevice.tokenHash;
      const storageCanary = 'session-device-storage-canary';
      const getVault = vi
        .spyOn(fixture.storage, 'getVault')
        .mockRejectedValue(new Error(storageCanary));
      mutate(fixture, tokenHash);
      const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));

      const response = await app.inject({
        method: 'GET',
        url: `/v1/vaults/${vaultId}`,
        headers: authHeader(fixture.token),
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual({
        error: { code: 'AUTHENTICATION_FAILED', message: 'Authentication failed' },
      });
      expect(response.body).not.toContain(storageCanary);
      expect(response.body).not.toContain(tokenHash);
      expect(getVault).not.toHaveBeenCalled();
    }

    const control = await createTestPorts();
    const controlDevice = control.authorization.devices.get(deviceId);
    if (controlDevice === undefined) throw new Error('Missing control device');
    control.authorization.devices.set(
      deviceId,
      deviceRecordSchema.parse({
        ...controlDevice,
        scopes: [...controlDevice.scopes].reverse(),
      }),
    );
    const controlStorage = vi.spyOn(control.storage, 'getVault');
    const app = tracked(buildApi({ ports: control.ports, environment: 'test' }));
    const response = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}`,
      headers: authHeader(control.token),
    });
    expect(response.statusCode).toBe(200);
    expect(controlStorage).toHaveBeenCalledOnce();
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

  it('rejects unbound enrollment device-label AAD without consuming the grant', async () => {
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

    const deviceId = 'device.label-binding';
    const sessionToken = (await fixture.ports.tokens.issue()).token;
    const labels = [
      deviceLabelEnvelope(otherVaultId, deviceId),
      deviceLabelEnvelope(vaultId, 'device.label-other'),
      deviceLabelEnvelope(vaultId, deviceId, 2),
    ];
    const responses = [];
    for (const encryptedLabel of labels) {
      responses.push(
        await app.inject({
          method: 'POST',
          url: '/v1/enrollments/complete',
          headers: exchangeHeaders(enrollmentToken, sessionToken),
          payload: {
            vaultId,
            deviceId,
            schemaVersion: 1,
            encryptedLabel,
          },
        }),
      );
    }

    expect(responses.map(({ statusCode }) => statusCode)).toEqual([400, 400, 400]);
    for (const response of responses) {
      expect(response.json()).toEqual({
        error: {
          code: 'VALIDATION_FAILED',
          message: 'Request validation failed',
        },
      });
    }
    expect(fixture.authorization.enrollments.size).toBe(1);
    expect(fixture.authorization.completions.size).toBe(0);
    expect(fixture.authorization.devices.size).toBe(1);
    expect(fixture.authorization.sessions.size).toBe(1);

    const valid = await app.inject({
      method: 'POST',
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload: {
        vaultId,
        deviceId,
        schemaVersion: 1,
        encryptedLabel: deviceLabelEnvelope(vaultId, deviceId),
      },
    });
    expect(valid.statusCode).toBe(201);
    expect(fixture.authorization.enrollments.size).toBe(0);
    expect(fixture.authorization.completions.size).toBe(1);
    expect(fixture.authorization.devices.has(deviceId)).toBe(true);
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
      nextCursor: null,
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

    const activePrincipal = fixture.authorization.sessions.get(sessionIssued.hash);
    const activeDevice = fixture.authorization.devices.get(newDeviceId);
    if (activePrincipal === undefined || activeDevice === undefined) {
      throw new Error('Enrollment did not persist its authorization records');
    }
    fixture.authorization.sessions.delete(sessionIssued.hash);
    const replayWithoutSession = await app.inject({
      method: 'POST',
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload: { vaultId, deviceId: newDeviceId, schemaVersion: 1 },
    });
    expect(replayWithoutSession.statusCode).toBe(401);
    expect(replayWithoutSession.json()).toEqual(crossedCompletion.json());

    fixture.authorization.sessions.set(sessionIssued.hash, activePrincipal);
    fixture.authorization.devices.set(
      newDeviceId,
      deviceRecordSchema.parse({ ...activeDevice, revokedAt: nowIso }),
    );
    const replayWithRevokedDevice = await app.inject({
      method: 'POST',
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload: { vaultId, deviceId: newDeviceId, schemaVersion: 1 },
    });
    expect(replayWithRevokedDevice.statusCode).toBe(401);
    expect(replayWithRevokedDevice.json()).toEqual(crossedCompletion.json());
    fixture.authorization.devices.set(newDeviceId, activeDevice);

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
    expect(devices.json()).toMatchObject({ nextCursor: null });
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

    const revokedCompletionReplay = await app.inject({
      method: 'POST',
      url: '/v1/enrollments/complete',
      headers: exchangeHeaders(enrollmentToken, sessionToken),
      payload: { vaultId, deviceId: newDeviceId, schemaVersion: 1 },
    });
    expect(revokedCompletionReplay.statusCode).toBe(401);
    expect(revokedCompletionReplay.json()).toEqual(crossedCompletion.json());
    expect(fixture.authorization.sessions.has(sessionIssued.hash)).toBe(false);
    expect(fixture.authorization.devices.get(newDeviceId)).toMatchObject({
      revokedAt: nowIso,
    });
  });

  it('authenticates before parsing control-list queries and enforces page limits', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const list = vi.spyOn(fixture.authorization, 'listInvitePage');
    const listDevices = vi.spyOn(fixture.authorization, 'listDevicePage');

    const unauthenticated = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/invites?cursor=${'x'.repeat(513)}`,
    });
    expect(unauthenticated.statusCode).toBe(401);
    expect(list).not.toHaveBeenCalled();
    const unauthenticatedDevices = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/devices?cursor=${'x'.repeat(513)}`,
    });
    expect(unauthenticatedDevices.statusCode).toBe(401);
    expect(listDevices).not.toHaveBeenCalled();

    for (const limit of ['0', '201', '1.5']) {
      for (const resource of ['invites', 'devices'] as const) {
        const invalid = await app.inject({
          method: 'GET',
          url: `/v1/vaults/${vaultId}/${resource}?limit=${limit}`,
          headers: authHeader(fixture.token),
        });
        expect(invalid.statusCode).toBe(400);
      }
    }
    expect(list).not.toHaveBeenCalled();
    expect(listDevices).not.toHaveBeenCalled();

    for (const [query, expectedLimit] of [
      ['', 50],
      ['?limit=1', 1],
      ['?limit=200', 200],
    ] as const) {
      const response = await app.inject({
        method: 'GET',
        url: `/v1/vaults/${vaultId}/invites${query}`,
        headers: authHeader(fixture.token),
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ invites: [], nextCursor: null });
      expect(list).toHaveBeenLastCalledWith(
        vaultId,
        { limit: expectedLimit },
        expect.any(Date),
      );
      const deviceResponse = await app.inject({
        method: 'GET',
        url: `/v1/vaults/${vaultId}/devices${query}`,
        headers: authHeader(fixture.token),
      });
      expect(deviceResponse.statusCode).toBe(200);
      expect(deviceResponse.json()).toMatchObject({
        devices: [{ id: 'device-1' }],
        nextCursor: null,
      });
      expect(listDevices).toHaveBeenLastCalledWith(vaultId, {
        limit: expectedLimit,
      });
    }
  });

  it('allows self-revocation only while another device remains and denies last-device revocation', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const otherDevice = deviceIdSchema.parse('device-2');
    const otherIssued = await fixture.ports.tokens.issue();
    fixture.authorization.seedSession(otherIssued.hash, {
      vaultId,
      deviceId: otherDevice,
      scopes: ['sync:read', 'sync:write', 'device:manage'],
    });

    const selfRevoked = await app.inject({
      method: 'DELETE',
      url: `/v1/vaults/${vaultId}/devices/${deviceId}`,
      headers: authHeader(fixture.token),
    });
    expect(selfRevoked.statusCode).toBe(204);
    await expect(
      app.inject({
        method: 'GET',
        url: '/v1/session',
        headers: authHeader(fixture.token),
      }),
    ).resolves.toMatchObject({ statusCode: 401 });
    await expect(
      app.inject({
        method: 'GET',
        url: '/v1/session',
        headers: authHeader(otherIssued.token),
      }),
    ).resolves.toMatchObject({ statusCode: 200 });

    const lastDenied = await app.inject({
      method: 'DELETE',
      url: `/v1/vaults/${vaultId}/devices/${otherDevice}`,
      headers: authHeader(otherIssued.token),
    });
    expect(lastDenied.statusCode).toBe(403);
    await expect(
      app.inject({
        method: 'GET',
        url: '/v1/session',
        headers: authHeader(otherIssued.token),
      }),
    ).resolves.toMatchObject({ statusCode: 200 });
  });

  it('rejects malformed or misbound request cursors and accepts an arbitrary same-vault position', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const list = vi.spyOn(fixture.authorization, 'listInvitePage');
    const listDevices = vi.spyOn(fixture.authorization, 'listDevicePage');
    const createdAt = timestampSchema.parse(nowIso);
    const encodeRaw = (value: string): string =>
      Buffer.from(value, 'utf8').toString('base64url');
    const invalidCursors = [
      'not*base64url',
      encodeRaw(
        `{"version":1, "vaultId":"${vaultId}","createdAt":"${createdAt}","resource":"invites","id":"invite-arbitrary"}`,
      ),
      'x'.repeat(513),
      encodeRaw(
        `{"createdAt":"${createdAt}","id":"invite-arbitrary","resource":"invites","vaultId":"${vaultId}","version":2}`,
      ),
      encodeControlListCursor({
        version: 1,
        resource: 'devices',
        vaultId,
        createdAt,
        id: deviceIdSchema.parse('device-arbitrary'),
      }),
      encodeControlListCursor({
        version: 1,
        resource: 'invites',
        vaultId: otherVaultId,
        createdAt,
        id: 'invite-arbitrary',
      }),
    ];

    for (const cursor of invalidCursors) {
      const response = await app.inject({
        method: 'GET',
        url: `/v1/vaults/${vaultId}/invites?cursor=${encodeURIComponent(cursor)}`,
        headers: authHeader(fixture.token),
      });
      expect(response.statusCode).toBe(400);
    }
    expect(list).not.toHaveBeenCalled();

    const deviceInvalidCursors = [
      'not*base64url',
      encodeRaw(
        `{"version":1, "vaultId":"${vaultId}","createdAt":"${createdAt}","resource":"devices","id":"device-arbitrary"}`,
      ),
      'x'.repeat(513),
      encodeRaw(
        `{"createdAt":"${createdAt}","id":"device-arbitrary","resource":"devices","vaultId":"${vaultId}","version":2}`,
      ),
      encodeControlListCursor({
        version: 1,
        resource: 'devices',
        vaultId: otherVaultId,
        createdAt,
        id: deviceIdSchema.parse('device-arbitrary'),
      }),
      encodeControlListCursor({
        version: 1,
        resource: 'invites',
        vaultId,
        createdAt,
        id: inviteIdSchema.parse('invite-arbitrary'),
      }),
    ];
    for (const cursor of deviceInvalidCursors) {
      const response = await app.inject({
        method: 'GET',
        url: `/v1/vaults/${vaultId}/devices?cursor=${encodeURIComponent(cursor)}`,
        headers: authHeader(fixture.token),
      });
      expect(response.statusCode).toBe(400);
    }

    const inviteCursorForDeviceRoute = encodeControlListCursor({
      version: 1,
      resource: 'invites',
      vaultId,
      createdAt,
      id: inviteIdSchema.parse('invite-arbitrary'),
    });
    for (const cursor of [inviteCursorForDeviceRoute]) {
      const response = await app.inject({
        method: 'GET',
        url: `/v1/vaults/${vaultId}/devices?cursor=${encodeURIComponent(cursor)}`,
        headers: authHeader(fixture.token),
      });
      expect(response.statusCode).toBe(400);
    }
    expect(listDevices).not.toHaveBeenCalled();

    const arbitrary = encodeControlListCursor({
      version: 1,
      resource: 'invites',
      vaultId,
      createdAt,
      id: 'invite-arbitrary',
    });
    const accepted = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/invites?limit=1&cursor=${arbitrary}`,
      headers: authHeader(fixture.token),
    });
    expect(accepted.statusCode).toBe(200);
    expect(accepted.json()).toEqual({ invites: [], nextCursor: null });
    expect(list).toHaveBeenCalledWith(
      vaultId,
      { limit: 1, cursor: arbitrary },
      expect.any(Date),
    );
  });

  it('matches binary keyset pagination in memory at empty, full, and lookahead boundaries', async () => {
    for (const rowCount of [0, 1, 200, 201]) {
      const authorization = new MemoryAuthorization();
      for (let index = 0; index < rowCount; index += 1) {
        const suffix = String(index).padStart(3, '0');
        const inviteCreatedAt = timestampSchema.parse(
          index === 200 ? '2026-08-09T23:59:59.000Z' : '2026-08-10T00:00:01.000Z',
        );
        const deviceCreatedAt = timestampSchema.parse(
          index === 200 ? '2026-08-10T00:00:02.000Z' : '2026-08-10T00:00:01.000Z',
        );
        await authorization.createInvite({
          id: inviteIdSchema.parse(`invite-${suffix}`),
          tokenHash: digest(`invite-page-${suffix}`),
          vaultId,
          scopes: ['sync:read'],
          issuedByDeviceId: deviceIdSchema.parse('device-page-issuer'),
          createdAt: inviteCreatedAt,
          expiresAt: timestampSchema.parse('2026-08-10T00:10:00.000Z'),
        });
        const pageDeviceId = deviceIdSchema.parse(`device-${suffix}`);
        authorization.devices.set(
          pageDeviceId,
          deviceRecordSchema.parse({
            id: pageDeviceId,
            vaultId,
            schemaVersion: 1,
            tokenHash: digest(`device-page-${suffix}`),
            tokenVersion: 1,
            scopes: ['sync:read'],
            createdAt: deviceCreatedAt,
          }),
        );
      }

      const first = await authorization.listInvitePage(
        vaultId,
        { limit: 200 },
        new Date(nowIso),
      );
      expect(first.invites).toHaveLength(Math.min(rowCount, 200));
      expect(first.nextCursor === null).toBe(rowCount <= 200);
      if (rowCount === 201 && first.nextCursor !== null) {
        expect(decodeControlListCursor(first.nextCursor)).toEqual({
          version: 1,
          resource: 'invites',
          vaultId,
          createdAt: '2026-08-10T00:00:01.000Z',
          id: 'invite-199',
        });
        const terminal = await authorization.listInvitePage(
          vaultId,
          { limit: 200, cursor: first.nextCursor },
          new Date(nowIso),
        );
        expect(terminal.invites.map(({ id }) => id)).toEqual(['invite-200']);
        expect(terminal.nextCursor).toBeNull();
      }

      const firstDevices = await authorization.listDevicePage(vaultId, {
        limit: 200,
      });
      expect(firstDevices.devices).toHaveLength(Math.min(rowCount, 200));
      expect(firstDevices.nextCursor === null).toBe(rowCount <= 200);
      if (rowCount === 201 && firstDevices.nextCursor !== null) {
        expect(decodeControlListCursor(firstDevices.nextCursor)).toEqual({
          version: 1,
          resource: 'devices',
          vaultId,
          createdAt: '2026-08-10T00:00:01.000Z',
          id: 'device-199',
        });
        const terminal = await authorization.listDevicePage(vaultId, {
          limit: 200,
          cursor: firstDevices.nextCursor,
        });
        expect(terminal.devices.map(({ id }) => id)).toEqual(['device-200']);
        expect(terminal.nextCursor).toBeNull();
      }
    }
  });

  it('reparses memory page options and binds cursors independently of routes', async () => {
    const authorization = new MemoryAuthorization();
    const createdAt = timestampSchema.parse(nowIso);
    const wrongResource = encodeControlListCursor({
      version: 1,
      resource: 'devices',
      vaultId,
      createdAt,
      id: deviceIdSchema.parse('device-memory-cursor'),
    });
    const wrongVault = encodeControlListCursor({
      version: 1,
      resource: 'invites',
      vaultId: otherVaultId,
      createdAt,
      id: inviteIdSchema.parse('invite-memory-cursor'),
    });
    for (const options of [
      { limit: 0 },
      { limit: 201 },
      { limit: 1.5 },
      { limit: 1, cursor: 'malformed' },
      { limit: 1, cursor: wrongResource },
      { limit: 1, cursor: wrongVault },
    ]) {
      await expect(
        authorization.listInvitePage(vaultId, options as never, new Date(nowIso)),
      ).rejects.toThrow();
    }
    await expect(
      authorization.listInvitePage(
        'invalid vault' as never,
        { limit: 1 },
        new Date(nowIso),
      ),
    ).rejects.toThrow();

    const wrongDeviceResource = encodeControlListCursor({
      version: 1,
      resource: 'invites',
      vaultId,
      createdAt,
      id: inviteIdSchema.parse('invite-device-swap'),
    });
    const wrongDeviceVault = encodeControlListCursor({
      version: 1,
      resource: 'devices',
      vaultId: otherVaultId,
      createdAt,
      id: deviceIdSchema.parse('device-memory-cursor'),
    });
    for (const options of [
      { limit: 0 },
      { limit: 201 },
      { limit: 1.5 },
      { limit: 1, cursor: 'malformed' },
      { limit: 1, cursor: wrongDeviceResource },
      { limit: 1, cursor: wrongDeviceVault },
    ]) {
      await expect(
        authorization.listDevicePage(vaultId, options as never),
      ).rejects.toThrow();
    }
    await expect(
      authorization.listDevicePage('invalid vault' as never, { limit: 1 }),
    ).rejects.toThrow();

    const arbitrary = encodeControlListCursor({
      version: 1,
      resource: 'invites',
      vaultId,
      createdAt,
      id: inviteIdSchema.parse('invite-memory-arbitrary'),
    });
    await expect(
      authorization.listInvitePage(
        vaultId,
        { limit: 1, cursor: arbitrary },
        new Date(nowIso),
      ),
    ).resolves.toEqual({ invites: [], nextCursor: null });

    const arbitraryDevice = encodeControlListCursor({
      version: 1,
      resource: 'devices',
      vaultId,
      createdAt,
      id: deviceIdSchema.parse('device-memory-arbitrary'),
    });
    await expect(
      authorization.listDevicePage(vaultId, {
        limit: 1,
        cursor: arbitraryDevice,
      }),
    ).resolves.toEqual({ devices: [], nextCursor: null });
  });

  it('uses timestamp direction and binary ID ties identically for memory invite and device pages', async () => {
    const authorization = new MemoryAuthorization();
    const issuer = deviceIdSchema.parse('device-page-issuer');
    const inviteRows = [
      ['invite-newest', '2026-08-10T00:00:02.000Z'],
      ['invite-~', '2026-08-10T00:00:01.000Z'],
      ['invite-a', '2026-08-10T00:00:01.000Z'],
      ['invite-_', '2026-08-10T00:00:01.000Z'],
      ['invite-A', '2026-08-10T00:00:01.000Z'],
      ['invite-0', '2026-08-10T00:00:01.000Z'],
      ['invite-oldest', '2026-08-10T00:00:00.000Z'],
    ] as const;
    for (const [id, createdAt] of inviteRows) {
      await authorization.createInvite({
        id: inviteIdSchema.parse(id),
        tokenHash: digest(`hash-${id}`),
        vaultId,
        scopes: ['sync:read'],
        issuedByDeviceId: issuer,
        createdAt: timestampSchema.parse(createdAt),
        expiresAt: timestampSchema.parse('2026-08-10T00:10:00.000Z'),
      });
    }
    const firstInvites = await authorization.listInvitePage(
      vaultId,
      { limit: 4 },
      new Date(nowIso),
    );
    expect(firstInvites.invites.map(({ id }) => id)).toEqual([
      'invite-newest',
      'invite-0',
      'invite-A',
      'invite-_',
    ]);
    if (firstInvites.nextCursor === null) throw new Error('Missing invite cursor');
    const secondInvites = await authorization.listInvitePage(
      vaultId,
      { limit: 4, cursor: firstInvites.nextCursor },
      new Date(nowIso),
    );
    expect(secondInvites.invites.map(({ id }) => id)).toEqual([
      'invite-a',
      'invite-~',
      'invite-oldest',
    ]);

    const deviceRows = [
      ['device-newest', '2026-08-10T00:00:02.000Z'],
      ['device-~', '2026-08-10T00:00:01.000Z'],
      ['device-a', '2026-08-10T00:00:01.000Z'],
      ['device-_', '2026-08-10T00:00:01.000Z'],
      ['device-A', '2026-08-10T00:00:01.000Z'],
      ['device-0', '2026-08-10T00:00:01.000Z'],
      ['device-oldest', '2026-08-10T00:00:00.000Z'],
    ] as const;
    for (const [id, createdAt] of deviceRows) {
      const parsedId = deviceIdSchema.parse(id);
      authorization.devices.set(
        parsedId,
        deviceRecordSchema.parse({
          id: parsedId,
          vaultId,
          schemaVersion: 1,
          tokenHash: digest(`hash-${id}`),
          tokenVersion: 1,
          scopes: ['sync:read'],
          createdAt,
        }),
      );
    }
    const firstDevices = await authorization.listDevicePage(vaultId, { limit: 4 });
    expect(firstDevices.devices.map(({ id }) => id)).toEqual([
      'device-oldest',
      'device-0',
      'device-A',
      'device-_',
    ]);
    if (firstDevices.nextCursor === null) throw new Error('Missing device cursor');
    const secondDevices = await authorization.listDevicePage(vaultId, {
      limit: 4,
      cursor: firstDevices.nextCursor,
    });
    expect(secondDevices.devices.map(({ id }) => id)).toEqual([
      'device-a',
      'device-~',
      'device-newest',
    ]);
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
      .spyOn(fixture.authorization, 'listDevicePage')
      .mockResolvedValueOnce({ devices: [crossed], nextCursor: null });
    const crossedList = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/devices`,
      headers: authHeader(fixture.token),
    });
    expect(crossedList.statusCode).toBe(500);

    list.mockResolvedValueOnce({
      devices: [seeded],
      nextCursor: encodeControlListCursor({
        version: 1,
        resource: 'devices',
        vaultId: otherVaultId,
        createdAt: seeded.createdAt,
        id: seeded.id,
      }),
    });
    const crossedCursor = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/devices`,
      headers: authHeader(fixture.token),
    });
    expect(crossedCursor.statusCode).toBe(500);

    list.mockResolvedValueOnce({
      devices: [seeded],
      nextCursor: encodeControlListCursor({
        version: 1,
        resource: 'devices',
        vaultId,
        createdAt: seeded.createdAt,
        id: deviceIdSchema.parse('device-not-final-row'),
      }),
    });
    const nonfinalCursor = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/devices`,
      headers: authHeader(fixture.token),
    });
    expect(nonfinalCursor.statusCode).toBe(500);
    list.mockRestore();

    const inviteList = vi
      .spyOn(fixture.authorization, 'listInvitePage')
      .mockResolvedValueOnce({
        invites: [],
        nextCursor: encodeControlListCursor({
          version: 1,
          resource: 'devices',
          vaultId,
          createdAt: timestampSchema.parse(nowIso),
          id: deviceIdSchema.parse('device-backend-cursor'),
        }),
      });
    const wrongInviteResource = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
    });
    expect(wrongInviteResource.statusCode).toBe(500);
    await fixture.authorization.createInvite({
      id: inviteIdSchema.parse('invite-backend-row'),
      tokenHash: digest('invite-backend-row'),
      vaultId,
      scopes: ['sync:read'],
      issuedByDeviceId: deviceIdSchema.parse('device-1'),
      createdAt: timestampSchema.parse(nowIso),
      expiresAt: timestampSchema.parse('2026-08-10T00:10:00.000Z'),
    });
    const seededInvite = (
      await fixture.authorization.listInvitePage(
        vaultId,
        { limit: 1 },
        new Date(nowIso),
      )
    ).invites[0];
    if (seededInvite === undefined) throw new Error('Missing seeded invite');
    inviteList.mockResolvedValueOnce({
      invites: [{ ...seededInvite, vaultId: otherVaultId }],
      nextCursor: null,
    });
    const crossedInviteRow = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
    });
    expect(crossedInviteRow.statusCode).toBe(500);

    inviteList.mockResolvedValueOnce({
      invites: [seededInvite],
      nextCursor: encodeControlListCursor({
        version: 1,
        resource: 'invites',
        vaultId: otherVaultId,
        createdAt: seededInvite.createdAt,
        id: seededInvite.id,
      }),
    });
    const crossedInviteCursor = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
    });
    expect(crossedInviteCursor.statusCode).toBe(500);

    inviteList.mockResolvedValueOnce({
      invites: [seededInvite],
      nextCursor: encodeControlListCursor({
        version: 1,
        resource: 'invites',
        vaultId,
        createdAt: seededInvite.createdAt,
        id: inviteIdSchema.parse('invite-not-final-row'),
      }),
    });
    const nonfinalInviteCursor = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
    });
    expect(nonfinalInviteCursor.statusCode).toBe(500);

    inviteList.mockResolvedValueOnce({
      invites: [seededInvite],
      nextCursor: 'malformed' as never,
    });
    const malformedInviteCursor = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/invites`,
      headers: authHeader(fixture.token),
    });
    expect(malformedInviteCursor.statusCode).toBe(500);
    inviteList.mockRestore();

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
