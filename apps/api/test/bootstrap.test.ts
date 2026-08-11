import {
  deviceIdSchema,
  vaultIdSchema,
  type VaultBootstrapRequest,
} from '@kavrix/schemas';
import { afterEach, describe, expect, it } from 'vitest';

import { buildApi, NodeTokenPort } from '../src/index.js';
import {
  authHeader,
  createTestPorts,
  deviceId,
  deviceLabelEnvelope,
  vaultFixture,
} from './helpers.js';

const openApps: ReturnType<typeof buildApi>[] = [];

afterEach(async () => {
  await Promise.all(openApps.splice(0).map(async (app) => app.close()));
});

describe('initial vault bootstrap', () => {
  it('is absent unless explicitly enabled', async () => {
    const fixture = await createTestPorts();
    const app = track(buildApi({ ports: fixture.ports, environment: 'test' }));
    const token = await new NodeTokenPort().issue();
    const response = await app.inject({
      method: 'POST',
      url: '/v1/vaults',
      headers: authHeader(token.token),
      payload: bootstrapBody('vault.bootstrap-disabled', 'device.bootstrap-disabled'),
    });

    expect(response.statusCode).toBe(404);
    expect(fixture.bootstrap.receipts.size).toBe(0);
  });

  it('creates one opaque vault and first session without returning the bearer', async () => {
    const fixture = await createTestPorts();
    const app = track(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        vaultBootstrapEnabled: true,
      }),
    );
    const issued = await new NodeTokenPort().issue();
    const body = bootstrapBody('vault.bootstrap-new', 'device.bootstrap-new');

    const created = await app.inject({
      method: 'POST',
      url: '/v1/vaults',
      headers: authHeader(issued.token),
      payload: body,
    });
    expect(created.statusCode).toBe(201);
    expect(created.json()).toEqual({
      vaultId: body.vault.id,
      deviceId: body.device.id,
    });
    expect(created.body).not.toContain(issued.token);
    expect(JSON.stringify(fixture.storage.vaults)).not.toContain(issued.token);

    const session = await app.inject({
      method: 'GET',
      url: '/v1/session',
      headers: authHeader(issued.token),
    });
    expect(session.statusCode).toBe(200);
    expect(session.json()).toEqual({
      vaultId: body.vault.id,
      deviceId: body.device.id,
      scopes: ['sync:read', 'sync:write', 'device:manage'],
    });
  });

  it('replays exact input and fails closed on incompatible bearer reuse', async () => {
    const fixture = await createTestPorts();
    const app = track(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        vaultBootstrapEnabled: true,
      }),
    );
    const issued = await new NodeTokenPort().issue();
    const body = bootstrapBody('vault.bootstrap-retry', 'device.bootstrap-retry');
    const request = {
      method: 'POST' as const,
      url: '/v1/vaults',
      headers: authHeader(issued.token),
      payload: body,
    };

    await expect(app.inject(request)).resolves.toMatchObject({ statusCode: 201 });
    await expect(app.inject(request)).resolves.toMatchObject({ statusCode: 201 });
    const incompatible = await app.inject({
      ...request,
      payload: bootstrapBody(
        'vault.bootstrap-incompatible',
        'device.bootstrap-incompatible',
      ),
    });
    expect(incompatible.statusCode).toBe(401);
    expect(fixture.storage.vaults.has('vault.bootstrap-incompatible')).toBe(false);
  });

  it('does not partially create state on vault, device, or credential collisions', async () => {
    const fixture = await createTestPorts();
    const app = track(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        vaultBootstrapEnabled: true,
      }),
    );
    const tokens = new NodeTokenPort();
    const vaultCollisionToken = await tokens.issue();
    const deviceCollisionToken = await tokens.issue();
    const freshVaultId = 'vault.bootstrap-device-collision';

    const vaultCollision = await app.inject({
      method: 'POST',
      url: '/v1/vaults',
      headers: authHeader(vaultCollisionToken.token),
      payload: bootstrapBody('vault-1', 'device.bootstrap-unused'),
    });
    const deviceCollision = await app.inject({
      method: 'POST',
      url: '/v1/vaults',
      headers: authHeader(deviceCollisionToken.token),
      payload: bootstrapBody(freshVaultId, deviceId),
    });

    expect(vaultCollision.statusCode).toBe(401);
    expect(deviceCollision.statusCode).toBe(401);
    expect(fixture.storage.vaults.has(freshVaultId)).toBe(false);
    expect(fixture.authorization.sessions.size).toBe(1);
  });

  it('rejects unbound bootstrap device-label AAD without persisting state', async () => {
    const fixture = await createTestPorts();
    const app = track(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        vaultBootstrapEnabled: true,
      }),
    );
    const issued = await new NodeTokenPort().issue();
    const targetVaultId = 'vault.bootstrap-label-binding';
    const targetDeviceId = 'device.bootstrap-label-binding';
    const body = bootstrapBody(targetVaultId, targetDeviceId);
    const labels = [
      deviceLabelEnvelope('vault.bootstrap-label-other', targetDeviceId),
      deviceLabelEnvelope(targetVaultId, 'device.bootstrap-label-other'),
      deviceLabelEnvelope(targetVaultId, targetDeviceId, 2),
    ];
    const responses = [];
    for (const encryptedLabel of labels) {
      responses.push(
        await app.inject({
          method: 'POST',
          url: '/v1/vaults',
          headers: authHeader(issued.token),
          payload: {
            ...body,
            device: { ...body.device, encryptedLabel },
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
    expect(fixture.storage.vaults.has(targetVaultId)).toBe(false);
    expect(fixture.authorization.devices.has(targetDeviceId)).toBe(false);
    expect(fixture.authorization.sessions.size).toBe(1);
    expect(fixture.bootstrap.receipts.size).toBe(0);

    const valid = await app.inject({
      method: 'POST',
      url: '/v1/vaults',
      headers: authHeader(issued.token),
      payload: {
        ...body,
        device: {
          ...body.device,
          encryptedLabel: deviceLabelEnvelope(targetVaultId, targetDeviceId),
        },
      },
    });
    expect(valid.statusCode).toBe(201);
    expect(fixture.storage.vaults.has(targetVaultId)).toBe(true);
    expect(fixture.authorization.devices.has(targetDeviceId)).toBe(true);
    expect(fixture.bootstrap.receipts.size).toBe(1);
  });

  it('validates revision-zero input before claiming a session and rate limits by source', async () => {
    const fixture = await createTestPorts();
    const app = track(
      buildApi({
        ports: fixture.ports,
        environment: 'test',
        vaultBootstrapEnabled: true,
        sourceRatePolicy: { limit: 1, windowSeconds: 60 },
      }),
    );
    const issued = await new NodeTokenPort().issue();
    const body = bootstrapBody('vault.bootstrap-invalid', 'device.bootstrap-invalid');

    const invalid = await app.inject({
      method: 'POST',
      url: '/v1/vaults',
      headers: authHeader(issued.token),
      payload: { ...body, vault: { ...body.vault, revision: 1 } },
    });
    const limited = await app.inject({
      method: 'POST',
      url: '/v1/vaults',
      headers: authHeader(issued.token),
      payload: body,
    });

    expect(invalid.statusCode).toBe(400);
    expect(limited.statusCode).toBe(429);
    expect(fixture.bootstrap.receipts.size).toBe(0);
  });
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

function track(app: ReturnType<typeof buildApi>): ReturnType<typeof buildApi> {
  openApps.push(app);
  return app;
}
