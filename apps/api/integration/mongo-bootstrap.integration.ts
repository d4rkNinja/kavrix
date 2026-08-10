import { randomUUID } from 'node:crypto';

import {
  deviceIdSchema,
  vaultIdSchema,
  type ApiBearerToken,
  type VaultBootstrapRequest,
} from '@kavrix/schemas';
import { mongoStorageCollectionNames } from '@kavrix/storage';
import type { LightMyRequestResponse } from 'fastify';
import { MongoClient } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  mongoApiCollectionNames,
  type MongoApiCredentialClaimDocument,
} from '../src/mongo-documents.js';
import { createMongoApiServer, type MongoApiServer } from '../src/server.js';
import { NodeTokenPort } from '../src/token.js';
import { authHeader, vaultFixture } from '../test/helpers.js';

const mongodbUri = process.env['KAVRIX_MONGODB_URI'];
const describeMongo =
  mongodbUri === undefined || mongodbUri.length === 0 ? describe.skip : describe;

describeMongo('Mongo initial-vault bootstrap', () => {
  const uri = requireMongoUri();
  const databaseName = `kavrix_bootstrap_${randomUUID().replaceAll('-', '')}`;
  const inspectionClient = new MongoClient(uri, {
    appName: 'kavrix-bootstrap-integration-inspection',
  });
  const tokens = new NodeTokenPort();
  let server: MongoApiServer;

  beforeAll(async () => {
    await inspectionClient.connect();
    server = await createMongoApiServer({
      mongodbUri: uri,
      databaseName,
      environment: 'test',
      host: '127.0.0.1',
      port: 30_001,
      vaultBootstrapEnabled: true,
    });
  });

  afterAll(async () => {
    await server.close();
    await inspectionClient.db(databaseName).dropDatabase();
    await inspectionClient.close();
  });

  it('atomically persists only the bearer hash and an initial sync anchor', async () => {
    const issued = await tokens.issue();
    const body = bootstrapBody('vault.mongo-bootstrap', 'device.mongo-bootstrap');

    const created = await bootstrap(issued.token, body);
    expect(created.statusCode).toBe(201);
    expect(created.json()).toEqual({
      vaultId: body.vault.id,
      deviceId: body.device.id,
    });
    expect(created.body).not.toContain(issued.token);

    const database = inspectionClient.db(databaseName);
    const counts = await Promise.all([
      database.collection(mongoStorageCollectionNames.vaults).countDocuments(),
      database.collection(mongoStorageCollectionNames.counters).countDocuments(),
      database.collection(mongoStorageCollectionNames.changes).countDocuments(),
      database.collection(mongoApiCollectionNames.devices).countDocuments(),
      database.collection(mongoApiCollectionNames.sessions).countDocuments(),
      database.collection(mongoApiCollectionNames.credentialClaims).countDocuments(),
    ]);
    expect(counts).toEqual([1, 1, 1, 1, 1, 1]);

    const documents = await Promise.all([
      database.collection(mongoStorageCollectionNames.vaults).find({}).toArray(),
      database.collection(mongoStorageCollectionNames.counters).find({}).toArray(),
      database.collection(mongoStorageCollectionNames.changes).find({}).toArray(),
      database.collection(mongoApiCollectionNames.devices).find({}).toArray(),
      database.collection(mongoApiCollectionNames.sessions).find({}).toArray(),
      database.collection(mongoApiCollectionNames.credentialClaims).find({}).toArray(),
    ]);
    expect(JSON.stringify(documents)).not.toContain(issued.token);
    const claim = await database
      .collection<MongoApiCredentialClaimDocument>(
        mongoApiCollectionNames.credentialClaims,
      )
      .findOne({ _id: issued.hash });
    expect(claim).toMatchObject({ _id: issued.hash, kind: 'session' });
    expect(claim?.bootstrapHash).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(documents[1]).toEqual([
      expect.objectContaining({ changeSequence: 1, vaultRevision: 0 }),
    ]);

    const retry = await bootstrap(issued.token, body);
    expect(retry.statusCode).toBe(201);
    const session = await server.app.inject({
      method: 'GET',
      url: '/v1/session',
      headers: authHeader(issued.token),
    });
    expect(session.statusCode).toBe(200);
    const initialSync = await server.app.inject({
      method: 'GET',
      url: `/v1/vaults/${body.vault.id}/sync?serverSequence=0&highestSeenVaultRevision=0&limit=10`,
      headers: authHeader(issued.token),
    });
    expect(initialSync.statusCode).toBe(200);
    expect(initialSync.json()).toMatchObject({
      vaultId: body.vault.id,
      serverVaultRevision: 0,
      changes: [
        {
          change: {
            serverSequence: 1,
            entityType: 'vault',
            entityId: body.vault.id,
            recordRevision: 0,
            operation: 'upsert',
          },
          record: body.vault,
        },
      ],
      hasMore: false,
    });
  });

  it('serializes vault collisions and leaves the losing bearer reusable', async () => {
    const first = await tokens.issue();
    const second = await tokens.issue();
    const sharedVault = 'vault.mongo-bootstrap-race';
    const firstBody = bootstrapBody(sharedVault, 'device.mongo-bootstrap-race-a');
    const secondBody = bootstrapBody(sharedVault, 'device.mongo-bootstrap-race-b');

    const responses = await Promise.all([
      bootstrap(first.token, firstBody),
      bootstrap(second.token, secondBody),
    ]);
    expect(responses.map(({ statusCode }) => statusCode).sort()).toEqual([201, 401]);

    const loser = responses[0].statusCode === 401 ? first : second;
    const recovery = await bootstrap(
      loser.token,
      bootstrapBody(
        'vault.mongo-bootstrap-after-race',
        'device.mongo-bootstrap-after-race',
      ),
    );
    expect(recovery.statusCode).toBe(201);
  });

  it('rejects incompatible credential and cross-vault device reuse without partial state', async () => {
    const original = await tokens.issue();
    const originalBody = bootstrapBody(
      'vault.mongo-bootstrap-original',
      'device.mongo-bootstrap-original',
    );
    await expect(bootstrap(original.token, originalBody)).resolves.toMatchObject({
      statusCode: 201,
    });

    const credentialReuseVault = vaultIdSchema.parse(
      'vault.mongo-bootstrap-credential-reuse',
    );
    const incompatible = await bootstrap(
      original.token,
      bootstrapBody(credentialReuseVault, 'device.mongo-bootstrap-credential-reuse'),
    );
    const newToken = await tokens.issue();
    const deviceReuseVault = vaultIdSchema.parse('vault.mongo-bootstrap-device-reuse');
    const deviceCollision = await bootstrap(
      newToken.token,
      bootstrapBody(deviceReuseVault, originalBody.device.id),
    );

    expect(incompatible.statusCode).toBe(401);
    expect(deviceCollision.statusCode).toBe(401);
    const database = inspectionClient.db(databaseName);
    await expect(
      database
        .collection<{ _id: string }>(mongoStorageCollectionNames.vaults)
        .countDocuments({ _id: { $in: [credentialReuseVault, deviceReuseVault] } }),
    ).resolves.toBe(0);
    await expect(
      database
        .collection(mongoApiCollectionNames.credentialClaims)
        .countDocuments({ _id: newToken.hash }),
    ).resolves.toBe(0);
  });

  function bootstrap(
    token: ApiBearerToken,
    body: VaultBootstrapRequest,
  ): Promise<LightMyRequestResponse> {
    return server.app.inject({
      method: 'POST',
      url: '/v1/vaults',
      headers: authHeader(token),
      payload: body,
    });
  }
});

function bootstrapBody(vaultValue: string, deviceValue: string): VaultBootstrapRequest {
  const vaultId = vaultIdSchema.parse(vaultValue);
  const vault = vaultFixture(vaultId, 0);
  return {
    vault,
    device: {
      id: deviceIdSchema.parse(deviceValue),
      schemaVersion: vault.schemaVersion,
    },
  } as const;
}

function requireMongoUri(): string {
  if (mongodbUri === undefined || mongodbUri.length === 0) {
    return 'mongodb://integration-test-is-skipped.invalid';
  }
  return mongodbUri;
}
