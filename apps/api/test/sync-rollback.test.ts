import { SyncConflictError } from '@kavrix/core';
import {
  apiBearerTokenSchema,
  templateMigrationPublicationRequestSchema,
  vaultIdSchema,
} from '@kavrix/schemas';
import { groupRecord, mutation } from '../../../packages/storage/test/fixtures.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';

import { buildApi } from '../src/index.js';
import { authHeader, createTestPorts, vaultFixture, vaultId } from './helpers.js';

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

describe('sync rollback HTTP outcome', () => {
  it('returns an exact cause-free rollback response and logs no cursor detail', async () => {
    const fixture = await createTestPorts();
    const logs: string[] = [];
    const causeCanary = 'rollback-cause-canary-93d7';
    const deviceCanary = 'rollback-device-canary-24a1';
    const conflict = new SyncConflictError();
    Object.defineProperties(conflict, {
      cause: { value: new Error(causeCanary), enumerable: true },
      deviceId: { value: deviceCanary, enumerable: true },
      vaultId: { value: vaultId, enumerable: true },
      revision: { value: 777_777, enumerable: true },
    });
    vi.spyOn(fixture.storage, 'pullSyncPage').mockRejectedValueOnce(conflict);
    const app = tracked(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        logStream: { write: (message) => logs.push(message) },
      }),
    );

    const response = await app.inject({
      method: 'GET',
      url: `/v1/vaults/${vaultId}/sync?serverSequence=654321&highestSeenVaultRevision=777777&limit=1`,
      headers: authHeader(fixture.token),
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toEqual({
      error: {
        code: 'SYNC_ROLLBACK_DETECTED',
        message: 'The sync cursor is not accepted',
      },
    });
    expect(response.body).not.toContain('cause');
    expect(response.body).not.toContain('revision');
    expect(response.body).not.toContain(vaultId);
    expect(response.body).not.toContain(deviceCanary);
    expect(response.body).not.toContain(causeCanary);

    const completeLogs = logs.join('');
    expect(completeLogs).toContain('SYNC_ROLLBACK_DETECTED');
    expect(completeLogs).toContain('"statusCode":409');
    expect(completeLogs).not.toContain('/sync?');
    expect(completeLogs).not.toContain(vaultId);
    expect(completeLogs).not.toContain('654321');
    expect(completeLogs).not.toContain('777777');
    expect(completeLogs).not.toContain(deviceCanary);
    expect(completeLogs).not.toContain(causeCanary);
  });

  it('keeps generic push conflicts as successful per-mutation outcomes', async () => {
    const fixture = await createTestPorts();
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const committed = {
      vaultId,
      batchIdempotencyKey: 'rollback-push-committed-0001',
      mutations: [
        {
          entityType: 'vault',
          expectedVaultRevision: 1,
          idempotencyKey: 'rollback-push-mutation-0001',
          record: vaultFixture(vaultId, 2),
        },
      ],
    } as const;
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `/v1/vaults/${vaultId}/sync`,
          headers: authHeader(fixture.token),
          payload: committed,
        })
      ).statusCode,
    ).toBe(200);

    const conflict = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${vaultId}/sync`,
      headers: authHeader(fixture.token),
      payload: {
        ...committed,
        batchIdempotencyKey: 'rollback-push-conflict-0001',
        mutations: [
          {
            ...committed.mutations[0],
            idempotencyKey: 'rollback-push-mutation-0002',
          },
        ],
      },
    });
    expect(conflict.statusCode).toBe(200);
    expect(conflict.json()).toMatchObject({
      results: [{ status: 'conflict', currentRevision: 2 }],
    });
  });

  it('keeps template publication conflicts on the existing SYNC_CONFLICT outcome', async () => {
    const fixture = await createTestPorts();
    const templateVaultId = vaultIdSchema.parse('vault.1');
    const tokenHash = await fixture.ports.tokens.hash(
      apiBearerTokenSchema.parse(fixture.token),
    );
    const principal = fixture.authorization.sessions.get(tokenHash);
    if (principal === undefined) throw new Error('Missing authorization fixture');
    fixture.authorization.sessions.set(tokenHash, {
      ...principal,
      vaultId: templateVaultId,
    });
    vi.spyOn(fixture.storage, 'publishTemplateMigration').mockRejectedValueOnce(
      new SyncConflictError(),
    );
    const app = tracked(buildApi({ ports: fixture.ports, environment: 'test' }));
    const batch = templateMigrationPublicationRequestSchema.parse({
      vaultId: templateVaultId,
      batchIdempotencyKey: 'rollback-template-batch-0001',
      mutations: [
        mutation('group', groupRecord(1), 0, 'rollback-template-mutation-0001'),
      ],
    });

    const response = await app.inject({
      method: 'POST',
      url: `/v1/vaults/${templateVaultId}/template-migrations`,
      headers: authHeader(fixture.token),
      payload: batch,
    });

    expect(response.statusCode).toBe(409);
    expect(response.json()).toEqual({
      error: {
        code: 'SYNC_CONFLICT',
        message: 'The opaque migration publication has a revision conflict',
      },
    });
  });
});

function tracked(app: FastifyInstance): FastifyInstance {
  apps.push(app);
  return app;
}
