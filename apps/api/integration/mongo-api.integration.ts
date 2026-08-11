import { randomUUID } from 'node:crypto';

import {
  deviceIdSchema,
  inviteIdSchema,
  schemaVersionSchema,
  timestampSchema,
  vaultIdSchema,
  type ApiScope,
  type Sha256Digest,
  type Timestamp,
} from '@kavrix/schemas';
import { MongoClient, type Db } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { mongoApiCollectionNames } from '../src/mongo-documents.js';
import {
  initializeMongoApiPersistence,
  MongoAuthorizationPort,
} from '../src/mongo-persistence.js';
import { MongoRateLimitPort } from '../src/mongo-rate-limit.js';
import { createMongoApiServer } from '../src/server.js';
import { NodeTokenPort } from '../src/token.js';
import type { InviteGrant } from '../src/ports.js';

const mongodbUri = process.env['KAVRIX_MONGODB_URI'];
const describeMongo =
  mongodbUri === undefined || mongodbUri.length === 0 ? describe.skip : describe;

describeMongo('Mongo API adapters against a transaction-capable replica set', () => {
  const uri = requireMongoUri();
  const client = new MongoClient(uri, { appName: 'kavrix-api-integration' });
  const databaseName = `kavrix_api_test_${randomUUID().replaceAll('-', '')}`;
  const vaultId = vaultIdSchema.parse('vault.mongo-integration');
  const issuerDeviceId = deviceIdSchema.parse('device.mongo-issuer');
  const tokenPort = new NodeTokenPort();
  const baseTime = new Date('2026-08-10T00:00:00.000Z');
  let database: Db;
  let authorization: MongoAuthorizationPort;

  type RawMongoDocument = { _id: string } & Record<string, unknown>;

  beforeAll(async () => {
    await client.connect();
    database = client.db(databaseName);
    await initializeMongoApiPersistence(database);
    authorization = new MongoAuthorizationPort(client, database);
  });

  afterAll(async () => {
    await client.db(databaseName).dropDatabase();
    await client.close();
  });

  it('durably replays exact exchanges only before expiry and revokes sessions', async () => {
    const invite = await tokenPort.issue();
    const enrollment = await tokenPort.issue();
    const session = await tokenPort.issue();
    await authorization.createInvite(grant('invite.mongo-flow', invite.hash));
    const enrollmentExpiry = timestampSchema.parse(
      new Date(baseTime.getTime() + 300_000).toISOString(),
    );
    const redemption = await authorization.redeemInvite(
      invite.hash,
      enrollment.hash,
      enrollmentExpiry,
      baseTime,
    );
    expect(redemption).toMatchObject({
      vaultId,
      enrollmentExpiresAt: enrollmentExpiry,
    });
    await expect(
      authorization.redeemInvite(
        invite.hash,
        enrollment.hash,
        timestampSchema.parse(new Date(baseTime.getTime() + 600_000).toISOString()),
        new Date(baseTime.getTime() + 1_000),
      ),
    ).resolves.toEqual(redemption);

    const completion = {
      vaultId,
      deviceId: deviceIdSchema.parse('device.mongo-primary'),
      schemaVersion: schemaVersionSchema.parse(1),
      sessionTokenHash: session.hash,
    };
    const device = await authorization.completeEnrollment(
      enrollment.hash,
      completion,
      baseTime,
    );
    expect(device).toMatchObject({ id: completion.deviceId, tokenHash: session.hash });
    await expect(
      authorization.completeEnrollment(
        enrollment.hash,
        completion,
        new Date(baseTime.getTime() + 1_000),
      ),
    ).resolves.toEqual(device);
    await expect(authorization.findSession(session.hash, baseTime)).resolves.toEqual({
      vaultId,
      deviceId: completion.deviceId,
      scopes: ['sync:read', 'sync:write', 'device:manage'],
    });

    const afterExpiry = new Date(Date.parse(enrollmentExpiry) + 1);
    await expect(
      authorization.redeemInvite(
        invite.hash,
        enrollment.hash,
        enrollmentExpiry,
        afterExpiry,
      ),
    ).resolves.toBeNull();
    await expect(
      authorization.completeEnrollment(enrollment.hash, completion, afterExpiry),
    ).resolves.toBeNull();

    await expect(
      authorization.revokeDevice(
        vaultId,
        completion.deviceId,
        timestampSchema.parse(afterExpiry.toISOString()),
      ),
    ).resolves.toBe(true);
    await expect(
      authorization.findSession(session.hash, afterExpiry),
    ).resolves.toBeNull();

    const publicInvitePage = await authorization.listInvitePage(
      vaultId,
      { limit: 50 },
      baseTime,
    );
    expect(publicInvitePage.invites).toHaveLength(1);
    expect(publicInvitePage.nextCursor).toBeNull();
    expect(JSON.stringify(publicInvitePage)).not.toContain(invite.hash);
    const raw = JSON.stringify(
      await database.collection(mongoApiCollectionNames.invites).find({}).toArray(),
    );
    expect(raw).not.toContain(invite.token);
    expect(raw).not.toContain(enrollment.token);
    expect(raw).not.toContain(session.token);
  });

  it('enforces one global credential-hash namespace without consuming parents', async () => {
    const activeSession = await enrolledSession('credential-namespace-seed');

    const invite = await tokenPort.issue();
    await authorization.createInvite(
      grant('invite.mongo-cross-enrollment', invite.hash),
    );
    await expect(
      authorization.redeemInvite(
        invite.hash,
        activeSession.sessionHash,
        plusMinutes(5),
        baseTime,
      ),
    ).resolves.toBeNull();
    const validEnrollment = await tokenPort.issue();
    await expect(
      authorization.redeemInvite(
        invite.hash,
        validEnrollment.hash,
        plusMinutes(5),
        baseTime,
      ),
    ).resolves.not.toBeNull();

    const freshSession = await tokenPort.issue();
    const collidingCompletion = {
      vaultId,
      deviceId: deviceIdSchema.parse('device.mongo-cross-session'),
      schemaVersion: schemaVersionSchema.parse(1),
      sessionTokenHash: activeSession.sessionHash,
    };
    await expect(
      authorization.completeEnrollment(
        validEnrollment.hash,
        collidingCompletion,
        baseTime,
      ),
    ).resolves.toBeNull();
    await expect(
      authorization.completeEnrollment(
        validEnrollment.hash,
        { ...collidingCompletion, sessionTokenHash: freshSession.hash },
        baseTime,
      ),
    ).resolves.toMatchObject({ tokenHash: freshSession.hash });
    await expect(
      authorization.findSession(activeSession.sessionHash, baseTime),
    ).resolves.toMatchObject({ deviceId: activeSession.deviceId });
  });

  it('serializes two active parents claiming the same successor hash', async () => {
    const firstInvite = await tokenPort.issue();
    const secondInvite = await tokenPort.issue();
    const sharedSuccessor = await tokenPort.issue();
    await Promise.all([
      authorization.createInvite(
        grant('invite.mongo-shared-successor-a', firstInvite.hash),
      ),
      authorization.createInvite(
        grant('invite.mongo-shared-successor-b', secondInvite.hash),
      ),
    ]);
    const results = await Promise.all([
      authorization.redeemInvite(
        firstInvite.hash,
        sharedSuccessor.hash,
        plusMinutes(5),
        baseTime,
      ),
      authorization.redeemInvite(
        secondInvite.hash,
        sharedSuccessor.hash,
        plusMinutes(5),
        baseTime,
      ),
    ]);
    expect(results.filter((result) => result !== null)).toHaveLength(1);
    const losingParent = results[0] === null ? firstInvite : secondInvite;
    const freshSuccessor = await tokenPort.issue();
    await expect(
      authorization.redeemInvite(
        losingParent.hash,
        freshSuccessor.hash,
        plusMinutes(5),
        baseTime,
      ),
    ).resolves.not.toBeNull();
  });

  it('does not consume enrollment on a global device-ID collision', async () => {
    const existing = await enrolledSession('device-collision-seed');
    const invite = await tokenPort.issue();
    const enrollment = await tokenPort.issue();
    const session = await tokenPort.issue();
    await authorization.createInvite(
      grant('invite.mongo-device-collision', invite.hash),
    );
    await authorization.redeemInvite(
      invite.hash,
      enrollment.hash,
      plusMinutes(5),
      baseTime,
    );
    const collided = {
      vaultId,
      deviceId: existing.deviceId,
      schemaVersion: schemaVersionSchema.parse(1),
      sessionTokenHash: session.hash,
    };
    await expect(
      authorization.completeEnrollment(enrollment.hash, collided, baseTime),
    ).resolves.toBeNull();
    await expect(
      authorization.completeEnrollment(
        enrollment.hash,
        { ...collided, deviceId: deviceIdSchema.parse('device.mongo-after-collision') },
        baseTime,
      ),
    ).resolves.toMatchObject({ tokenHash: session.hash });
  });

  it('serializes invite redemption against revocation', async () => {
    const invite = await tokenPort.issue();
    const enrollment = await tokenPort.issue();
    const inviteId = inviteIdSchema.parse('invite.mongo-race');
    await authorization.createInvite(grant(inviteId, invite.hash));
    const [redemption, revoked] = await Promise.all([
      authorization.redeemInvite(
        invite.hash,
        enrollment.hash,
        plusMinutes(5),
        baseTime,
      ),
      authorization.revokeInvite(
        vaultId,
        inviteId,
        timestampSchema.parse(baseTime.toISOString()),
      ),
    ]);
    expect((redemption !== null ? 1 : 0) + (revoked ? 1 : 0)).toBe(1);
  });

  it('atomically shares fixed-window counters and installs strict validation', async () => {
    const rateLimits = new MongoRateLimitPort(database);
    const decisions = await Promise.all(
      Array.from({ length: 20 }, async () =>
        rateLimits.consume({
          key: 'integration-rate-key',
          limit: 7,
          windowSeconds: 60,
          now: baseTime,
        }),
      ),
    );
    expect(decisions.filter(Boolean)).toHaveLength(7);

    await expect(
      database
        .collection<RawMongoDocument>(mongoApiCollectionNames.sessions)
        .insertOne({
          _id: Buffer.alloc(32, 99).toString('base64url'),
          vaultId,
          deviceId: issuerDeviceId,
          scopes: ['sync:read'],
          createdAt: timestampSchema.parse(baseTime.toISOString()),
          passphrase: 'plaintext-canary',
        }),
    ).rejects.toThrow();
    const indexes = await database
      .collection(mongoApiCollectionNames.rateLimits)
      .indexes();
    expect(indexes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'rate_limit_expiry', expireAfterSeconds: 0 }),
      ]),
    );
  });

  it('composes and closes a Mongo-backed Fastify server without TLS secrets', async () => {
    const composedDatabase = `${databaseName}_server`;
    const server = await createMongoApiServer({
      mongodbUri: uri,
      databaseName: composedDatabase,
      environment: 'test',
      host: '127.0.0.1',
      port: 30_000,
    });
    const response = await server.app.inject({ method: 'GET', url: '/health' });
    expect(response.statusCode).toBe(200);
    await server.close();
    await client.db(composedDatabase).dropDatabase();
  });

  async function enrolledSession(label: string): Promise<{
    readonly sessionHash: Sha256Digest;
    readonly deviceId: ReturnType<typeof deviceIdSchema.parse>;
  }> {
    const invite = await tokenPort.issue();
    const enrollment = await tokenPort.issue();
    const session = await tokenPort.issue();
    const suffix = randomUUID().replaceAll('-', '');
    await authorization.createInvite(grant(`invite.${label}.${suffix}`, invite.hash));
    await authorization.redeemInvite(
      invite.hash,
      enrollment.hash,
      plusMinutes(5),
      baseTime,
    );
    const enrolledDeviceId = deviceIdSchema.parse(`device.${label}.${suffix}`);
    const device = await authorization.completeEnrollment(
      enrollment.hash,
      {
        vaultId,
        deviceId: enrolledDeviceId,
        schemaVersion: schemaVersionSchema.parse(1),
        sessionTokenHash: session.hash,
      },
      baseTime,
    );
    if (device === null) throw new Error('Enrollment fixture failed');
    return { sessionHash: session.hash, deviceId: enrolledDeviceId };
  }

  function grant(id: string, tokenHash: Sha256Digest): InviteGrant {
    return {
      id: inviteIdSchema.parse(id),
      tokenHash,
      vaultId,
      scopes: allScopes,
      issuedByDeviceId: issuerDeviceId,
      createdAt: timestampSchema.parse(baseTime.toISOString()),
      expiresAt: plusMinutes(10),
    };
  }

  function plusMinutes(minutes: number): Timestamp {
    return timestampSchema.parse(
      new Date(baseTime.getTime() + minutes * 60_000).toISOString(),
    );
  }
});

const allScopes: readonly ApiScope[] = ['sync:read', 'sync:write', 'device:manage'];

function requireMongoUri(): string {
  if (mongodbUri === undefined || mongodbUri.length === 0) {
    return 'mongodb://integration-test-is-skipped.invalid';
  }
  return mongodbUri;
}
