import { randomUUID } from 'node:crypto';

import { apiBearerTokenSchema, vaultIdSchema } from '@kavrix/schemas';
import { MongoVaultStorage } from '@kavrix/storage';
import { MongoClient } from 'mongodb';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { buildApi } from '../src/index.js';
import { authHeader, createTestPorts } from '../test/helpers.js';
import { mutation, vaultRecord } from '../../../packages/storage/test/fixtures.js';

const mongodbUri = process.env['KAVRIX_MONGODB_URI'];
const describeMongo =
  mongodbUri === undefined || mongodbUri.length === 0 ? describe.skip : describe;

describeMongo('sync rollback HTTP outcome against MongoDB rs0', () => {
  const uri = requireMongoUri();
  const client = new MongoClient(uri, { appName: 'kavrix-api-sync-rollback' });
  const databaseName = `kavrix_api_sync_rollback_${randomUUID().replaceAll('-', '')}`;

  beforeAll(async () => client.connect());

  afterAll(async () => {
    await client.db(databaseName).dropDatabase();
    await client.close();
  });

  it('maps a real counter rollback to the exact safe response and logs', async () => {
    const storage = new MongoVaultStorage(client, client.db(databaseName));
    await storage.initialize();
    await storage.commit(mutation('vault', vaultRecord(), null));
    const fixture = await createTestPorts();
    const tokenHash = await fixture.ports.tokens.hash(
      apiBearerTokenSchema.parse(fixture.token),
    );
    const principal = fixture.authorization.sessions.get(tokenHash);
    if (principal === undefined) throw new Error('Missing authorization fixture');
    fixture.authorization.sessions.set(tokenHash, {
      ...principal,
      vaultId: vaultIdSchema.parse('vault.1'),
    });
    const logs: string[] = [];
    const hostCanary = 'rollback-host-canary.invalid';
    const app = buildApi({
      ports: { ...fixture.ports, storage },
      environment: 'test',
      logStream: { write: (message) => logs.push(message) },
    });

    try {
      const response = await app.inject({
        method: 'GET',
        url: '/v1/vaults/vault.1/sync?serverSequence=1&highestSeenVaultRevision=999999&limit=1',
        headers: { ...authHeader(fixture.token), host: hostCanary },
      });

      expect(response.statusCode).toBe(409);
      expect(response.json()).toEqual({
        error: {
          code: 'SYNC_ROLLBACK_DETECTED',
          message: 'The sync cursor is not accepted',
        },
      });
      const completeLogs = logs.join('');
      expect(completeLogs).toContain('SYNC_ROLLBACK_DETECTED');
      expect(completeLogs).toContain('"statusCode":409');
      expect(completeLogs).not.toContain('vault.1');
      expect(completeLogs).not.toContain('999999');
      expect(completeLogs).not.toContain('/sync?');
      expect(completeLogs).not.toContain('SyncConflictError');
      expect(completeLogs).not.toContain(hostCanary);
    } finally {
      await app.close();
    }
  });
});

function requireMongoUri(): string {
  if (mongodbUri === undefined || mongodbUri.length === 0) {
    return 'mongodb://integration-test-is-skipped.invalid';
  }
  return mongodbUri;
}
