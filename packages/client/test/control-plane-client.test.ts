import type { IncomingMessage, ServerResponse } from 'node:http';

import { afterEach, describe, expect, it } from 'vitest';

import { createPortableKeySlot, generatePortableKey } from '@kavrix/crypto';
import {
  apiBearerTokenSchema,
  deviceIdSchema,
  enrollmentCompleteRequestSchema,
  inviteIdSchema,
  inviteIssueRequestSchema,
  keySlotIdSchema,
  publicDeviceRecordSchema,
  publicInviteRecordSchema,
  timestampSchema,
  vaultBootstrapRequestSchema,
  vaultIdSchema,
  vaultKeySlotUpdateRequestSchema,
  vaultRecordSchema,
  type ApiBearerToken,
  type PublicDeviceRecord,
  type PublicInviteRecord,
  type VaultBootstrapRequest,
  type VaultId,
  type VaultKeySlotUpdateRequest,
  type VaultRecord,
} from '@kavrix/schemas';

import { ControlPlaneClient, ControlPlaneFailure } from '../src/index.js';
import { encryptedFixture } from './fixtures.js';
import {
  readRequest,
  startLoopbackServer,
  type LoopbackServer,
} from './loopback-server.js';

const timestamp = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const later = timestampSchema.parse('2026-08-10T00:01:00.000Z');
const sessionToken = bearer(10);
const inviteToken = bearer(11);
const enrollmentToken = bearer(12);
const successorSessionToken = bearer(13);
const deviceId = deviceIdSchema.parse('device.control');
const inviteId = inviteIdSchema.parse('invite.control');
const servers: LoopbackServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe('ControlPlaneClient', () => {
  it('covers every canonical control-plane route with header-only credentials', async () => {
    const fixture = await controlPlaneFixture();
    const seen: SeenRequest[] = [];
    const server = await trackedServer(async (request, response) => {
      const pathname = new URL(request.url ?? '/', 'http://loopback').pathname;
      seen.push({
        method: request.method ?? '',
        url: request.url ?? '',
        authorization: request.headers.authorization,
        successor: headerValue(request, 'x-kavrix-successor-token'),
        body: await readRequest(request),
      });
      if (pathname === '/health') {
        json(response, 200, { status: 'ok' });
        return;
      }
      if (pathname === '/v1/session') {
        json(response, 200, {
          vaultId: fixture.vaultId,
          deviceId,
          scopes: ['sync:read', 'sync:write', 'device:manage'],
        });
        return;
      }
      if (pathname === '/v1/vaults' && request.method === 'POST') {
        json(response, 201, { vaultId: fixture.vaultId, deviceId });
        return;
      }
      if (pathname === `/v1/vaults/${fixture.vaultId}`) {
        json(response, 200, fixture.vault);
        return;
      }
      if (pathname.endsWith('/invites') && request.method === 'POST') {
        json(response, 201, { inviteId, inviteToken, expiresAt: later });
        return;
      }
      if (pathname.endsWith('/invites') && request.method === 'GET') {
        json(response, 200, { invites: [fixture.invite] });
        return;
      }
      if (pathname.endsWith(`/invites/${inviteId}`)) {
        empty(response);
        return;
      }
      if (pathname === '/v1/invites/redeem') {
        json(response, 200, {
          vaultId: fixture.vaultId,
          expiresAt: later,
          vault: fixture.vault,
        });
        return;
      }
      if (pathname === '/v1/enrollments/complete') {
        json(response, 201, { vaultId: fixture.vaultId, deviceId });
        return;
      }
      if (pathname.endsWith('/devices') && request.method === 'GET') {
        json(response, 200, { devices: [fixture.device] });
        return;
      }
      if (pathname.endsWith(`/devices/${deviceId}`)) {
        empty(response);
        return;
      }
      if (pathname.includes('/key-slots/')) {
        empty(response);
        return;
      }
      json(response, 404, { error: { code: 'NOT_FOUND', message: 'missing' } });
    });
    const client = developmentClient(server.url);

    await expect(client.health()).resolves.toEqual({ status: 'ok' });
    await expect(
      client.getSession(sessionToken, fixture.vaultId, deviceId),
    ).resolves.toMatchObject({ vaultId: fixture.vaultId, deviceId });
    await expect(
      client.bootstrap(sessionToken, fixture.bootstrapRequest),
    ).resolves.toEqual({ vaultId: fixture.vaultId, deviceId });
    await expect(client.fetchVault(sessionToken, fixture.vaultId)).resolves.toEqual(
      fixture.vault,
    );
    await expect(
      client.issueInvite(sessionToken, fixture.vaultId, fixture.inviteRequest),
    ).resolves.toMatchObject({ inviteId, inviteToken });
    await expect(client.listInvites(sessionToken, fixture.vaultId)).resolves.toEqual([
      fixture.invite,
    ]);
    await expect(
      client.revokeInvite(sessionToken, fixture.vaultId, inviteId),
    ).resolves.toBeUndefined();

    const enrollmentSuccessor = Uint8Array.from(Buffer.alloc(32, 12));
    await expect(
      client.redeemInvite(inviteToken, enrollmentSuccessor, fixture.vaultId),
    ).resolves.toEqual({
      vaultId: fixture.vaultId,
      expiresAt: later,
      vault: fixture.vault,
    });
    expect(enrollmentSuccessor).toEqual(Uint8Array.from(Buffer.alloc(32, 12)));

    const sessionSuccessor = Uint8Array.from(Buffer.alloc(32, 13));
    await expect(
      client.completeEnrollment(
        enrollmentToken,
        sessionSuccessor,
        fixture.enrollmentRequest,
      ),
    ).resolves.toEqual({ vaultId: fixture.vaultId, deviceId });
    expect(sessionSuccessor).toEqual(Uint8Array.from(Buffer.alloc(32, 13)));
    await expect(client.listDevices(sessionToken, fixture.vaultId)).resolves.toEqual([
      fixture.device,
    ]);
    await expect(
      client.revokeDevice(sessionToken, fixture.vaultId, deviceId),
    ).resolves.toBeUndefined();
    await expect(
      client.publishKeySlot(
        sessionToken,
        fixture.vaultId,
        fixture.slotId,
        fixture.publishRequest,
      ),
    ).resolves.toBeUndefined();
    await expect(
      client.revokeKeySlot(
        sessionToken,
        fixture.vaultId,
        fixture.slotId,
        fixture.revokeRequest,
      ),
    ).resolves.toBeUndefined();

    expect(seen[0]).toMatchObject({ url: '/health', authorization: undefined });
    const redemption = required(
      seen.find((request) => request.url === '/v1/invites/redeem'),
    );
    expect(redemption).toMatchObject({
      authorization: `Bearer ${inviteToken}`,
      successor: enrollmentToken,
      body: '',
    });
    const completion = required(
      seen.find((request) => request.url === '/v1/enrollments/complete'),
    );
    expect(completion).toMatchObject({
      authorization: `Bearer ${enrollmentToken}`,
      successor: successorSessionToken,
    });
    const bootstrap = required(seen.find((request) => request.url === '/v1/vaults'));
    expect(bootstrap.authorization).toBe(`Bearer ${sessionToken}`);
    for (const request of seen) {
      expect(request.url).not.toContain(sessionToken);
      expect(request.url).not.toContain(inviteToken);
      expect(request.url).not.toContain(enrollmentToken);
      expect(request.url).not.toContain(successorSessionToken);
      expect(request.body).not.toContain(sessionToken);
      expect(request.body).not.toContain(inviteToken);
      expect(request.body).not.toContain(enrollmentToken);
      expect(request.body).not.toContain(successorSessionToken);
    }
  });

  it('requires HTTPS except explicit loopback development and hides invalid input', async () => {
    expect(() => new ControlPlaneClient({ baseUrl: 'not a URL' })).toThrow(TypeError);
    expect(() => new ControlPlaneClient({ baseUrl: 'http://127.0.0.1:8080' })).toThrow(
      TypeError,
    );
    expect(
      () =>
        new ControlPlaneClient({
          baseUrl: 'http://example.com',
          allowInsecureLoopbackDevelopment: true,
        }),
    ).toThrow(TypeError);
    expect(
      () =>
        new ControlPlaneClient({
          baseUrl: `https://user:${sessionToken}@example.com/?token=${sessionToken}`,
        }),
    ).toThrow(TypeError);
    expect(
      () =>
        new ControlPlaneClient({
          baseUrl: 'https://example.com',
          timeoutMs: 0,
        }),
    ).toThrow(TypeError);

    const canary = 'invalid-bearer-PLAINTEXT-CANARY';
    const error = await new ControlPlaneClient({
      baseUrl: 'https://127.0.0.1:1',
    })
      .getSession(canary as never, vaultIdSchema.parse('vault.invalid'), deviceId)
      .catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(ControlPlaneFailure);
    expect(String(error)).not.toContain(canary);
    expect(JSON.stringify(error)).not.toContain(canary);
  });

  it('refuses redirects without forwarding credentials', async () => {
    let targetHits = 0;
    const target = await trackedServer((_request, response) => {
      targetHits += 1;
      json(response, 200, { status: 'ok' });
    });
    const redirect = await trackedServer((_request, response) => {
      response.statusCode = 302;
      response.setHeader('location', `${target.url}/capture`);
      response.end();
    });
    await expect(developmentClient(redirect.url).health()).rejects.toMatchObject({
      kind: 'protocol',
    });
    expect(targetHits).toBe(0);
  });

  it('rejects malformed, wrongly typed, and oversized responses before DTO use', async () => {
    const cases: readonly (readonly [
      (response: ServerResponse) => void,
      Readonly<{ maximumResponseBytes?: number }>?,
    ])[] = [
      [
        (response) => {
          json(response, 200, { status: 'ok', extra: true });
        },
      ],
      [
        (response) => {
          response.setHeader('content-type', 'text/plain');
          response.end('{"status":"ok"}');
        },
      ],
      [
        (response) => {
          response.setHeader('content-type', 'application/json');
          response.end('{');
        },
      ],
      [
        (response) => {
          json(response, 201, { status: 'ok' });
        },
      ],
      [
        (response) => {
          response.setHeader('content-type', 'application/json');
          response.end(JSON.stringify({ status: 'ok', padding: 'x'.repeat(256) }));
        },
        { maximumResponseBytes: 64 },
      ],
      [
        (response) => {
          response.setHeader('content-type', 'application/json');
          response.setHeader('content-length', '1000');
          response.end('{}');
        },
        { maximumResponseBytes: 64 },
      ],
    ];
    for (const [handler, options] of cases) {
      const server = await trackedServer((_request, response) => {
        handler(response);
      });
      await expect(
        developmentClient(server.url, options).health(),
      ).rejects.toMatchObject({ kind: 'protocol' });
    }
  });

  it('classifies HTTP, timeout, abort, and response-body failures generically', async () => {
    const vaultId = vaultIdSchema.parse('vault.failures');
    for (const [status, kind] of [
      [400, 'client'],
      [401, 'unauthorized'],
      [403, 'forbidden'],
      [404, 'not-found'],
      [409, 'conflict'],
      [503, 'server'],
    ] as const) {
      const server = await trackedServer((_request, response) => {
        response.statusCode = status;
        response.end(`server-private-${sessionToken}`);
      });
      const error = await developmentClient(server.url)
        .getSession(sessionToken, vaultId, deviceId)
        .catch((failure: unknown) => failure);
      expect(error).toMatchObject({ kind });
      expect(String(error)).not.toContain(sessionToken);
      expect(JSON.stringify(error)).not.toContain(sessionToken);
    }

    const rateLimited = await trackedServer((_request, response) => {
      response.statusCode = 429;
      response.setHeader('retry-after', '2');
      response.end(`server-private-${sessionToken}`);
    });
    await expect(
      developmentClient(rateLimited.url).getSession(sessionToken, vaultId, deviceId),
    ).rejects.toMatchObject({ kind: 'rate-limited', retryAfterMs: 2_000 });

    const timeout = await trackedServer(async (_request, response) => {
      response.setHeader('content-type', 'application/json');
      response.write('{"status":');
      await new Promise((resolve) => setTimeout(resolve, 80));
      response.end('"ok"}');
    });
    await expect(
      developmentClient(timeout.url, { timeoutMs: 10 }).health(),
    ).rejects.toMatchObject({ kind: 'timeout' });

    const controller = new AbortController();
    controller.abort();
    const aborted = await trackedServer((_request, response) => {
      json(response, 200, { status: 'ok' });
    });
    await expect(
      developmentClient(aborted.url, { signal: controller.signal }).health(),
    ).rejects.toMatchObject({ kind: 'aborted' });
  });

  it('rejects cross-vault and cross-device responses at the client boundary', async () => {
    const fixture = await controlPlaneFixture();
    const otherVaultId = vaultIdSchema.parse('vault.other');
    const otherDeviceId = deviceIdSchema.parse('device.other');
    const otherDevice = publicDevice(otherVaultId, otherDeviceId);
    const server = await trackedServer((request, response) => {
      const pathname = new URL(request.url ?? '/', 'http://loopback').pathname;
      if (pathname === '/v1/session') {
        json(response, 200, {
          vaultId: otherVaultId,
          deviceId: otherDeviceId,
          scopes: ['sync:read'],
        });
        return;
      }
      if (pathname === '/v1/vaults' && request.method === 'POST') {
        json(response, 201, {
          vaultId: fixture.vaultId,
          deviceId: otherDeviceId,
        });
        return;
      }
      if (pathname.endsWith('/invites') && request.method === 'GET') {
        json(response, 200, {
          invites: [{ ...fixture.invite, vaultId: otherVaultId }],
        });
        return;
      }
      if (pathname === '/v1/invites/redeem') {
        json(response, 200, {
          vaultId: otherVaultId,
          expiresAt: later,
          vault: fixture.vault,
        });
        return;
      }
      if (pathname === '/v1/enrollments/complete') {
        json(response, 201, {
          vaultId: fixture.vaultId,
          deviceId: otherDeviceId,
        });
        return;
      }
      if (pathname.endsWith('/devices')) {
        json(response, 200, { devices: [otherDevice] });
        return;
      }
      json(response, 200, fixture.vault);
    });
    const client = developmentClient(server.url);
    await expect(
      client.getSession(sessionToken, fixture.vaultId, deviceId),
    ).rejects.toMatchObject({ kind: 'protocol' });
    await expect(
      client.bootstrap(sessionToken, fixture.bootstrapRequest),
    ).rejects.toMatchObject({ kind: 'protocol' });
    await expect(client.fetchVault(sessionToken, otherVaultId)).rejects.toMatchObject({
      kind: 'protocol',
    });
    await expect(
      client.listInvites(sessionToken, fixture.vaultId),
    ).rejects.toMatchObject({ kind: 'protocol' });
    await expect(
      client.redeemInvite(
        inviteToken,
        Uint8Array.from(Buffer.alloc(32, 12)),
        fixture.vaultId,
      ),
    ).rejects.toMatchObject({ kind: 'protocol' });
    await expect(
      client.completeEnrollment(
        enrollmentToken,
        Uint8Array.from(Buffer.alloc(32, 13)),
        fixture.enrollmentRequest,
      ),
    ).rejects.toMatchObject({ kind: 'protocol' });
    await expect(
      client.listDevices(sessionToken, fixture.vaultId),
    ).rejects.toMatchObject({ kind: 'protocol' });
  });

  it('rejects malformed public-device output and unsafe successor inputs', async () => {
    const fixture = await controlPlaneFixture();
    let hits = 0;
    const server = await trackedServer((request, response) => {
      hits += 1;
      const pathname = new URL(request.url ?? '/', 'http://loopback').pathname;
      if (pathname.endsWith('/devices')) {
        json(response, 200, {
          devices: [
            { ...fixture.device, tokenHash: Buffer.alloc(32).toString('base64url') },
          ],
        });
        return;
      }
      json(response, 200, {
        vaultId: fixture.vaultId,
        expiresAt: later,
        vault: fixture.vault,
      });
    });
    const client = developmentClient(server.url);
    await expect(
      client.listDevices(sessionToken, fixture.vaultId),
    ).rejects.toMatchObject({ kind: 'protocol' });
    const hitsAfterDeviceList = hits;
    await expect(
      client.redeemInvite(
        inviteToken,
        Uint8Array.from(Buffer.alloc(31, 12)),
        fixture.vaultId,
      ),
    ).rejects.toMatchObject({ kind: 'protocol' });
    await expect(
      client.redeemInvite(
        inviteToken,
        Uint8Array.from(Buffer.alloc(32, 11)),
        fixture.vaultId,
      ),
    ).rejects.toMatchObject({ kind: 'protocol' });
    expect(hits).toBe(hitsAfterDeviceList);
  });

  it('rejects cross-bound key-slot requests before network access', async () => {
    const fixture = await controlPlaneFixture();
    let hits = 0;
    const server = await trackedServer((_request, response) => {
      hits += 1;
      empty(response);
    });
    const client = developmentClient(server.url);
    const otherVaultId = vaultIdSchema.parse('vault.other-input');
    await expect(
      client.publishKeySlot(
        sessionToken,
        otherVaultId,
        fixture.slotId,
        fixture.publishRequest,
      ),
    ).rejects.toMatchObject({ kind: 'protocol' });
    await expect(
      client.revokeKeySlot(
        sessionToken,
        fixture.vaultId,
        fixture.slotId,
        fixture.publishRequest,
      ),
    ).rejects.toMatchObject({ kind: 'protocol' });
    expect(hits).toBe(0);
  });
});

type SeenRequest = Readonly<{
  method: string;
  url: string;
  authorization: string | undefined;
  successor: string | undefined;
  body: string;
}>;

type ControlPlaneFixture = Readonly<{
  vaultId: VaultId;
  vault: VaultRecord;
  bootstrapRequest: VaultBootstrapRequest;
  inviteRequest: ReturnType<typeof inviteIssueRequestSchema.parse>;
  enrollmentRequest: ReturnType<typeof enrollmentCompleteRequestSchema.parse>;
  invite: PublicInviteRecord;
  device: PublicDeviceRecord;
  slotId: ReturnType<typeof keySlotIdSchema.parse>;
  publishRequest: VaultKeySlotUpdateRequest;
  revokeRequest: VaultKeySlotUpdateRequest;
}>;

async function controlPlaneFixture(): Promise<ControlPlaneFixture> {
  const encrypted = await encryptedFixture();
  const secondarySlotId = keySlotIdSchema.parse('slot.control-secondary');
  const portableKey = generatePortableKey();
  const secondarySlot = await createPortableKeySlot(
    {
      vaultId: encrypted.vaultId,
      slotId: secondarySlotId,
      schemaVersion: encrypted.vault.schemaVersion,
      keyVersion: encrypted.vault.currentKeyVersion,
      createdAt: timestamp,
    },
    portableKey,
    encrypted.rootKey,
  );
  portableKey.fill(0);
  encrypted.rootKey.fill(0);
  const vault = vaultRecordSchema.parse({
    ...encrypted.vault,
    keySlots: [...encrypted.vault.keySlots, secondarySlot],
    revision: 1,
  });
  const slotId = required(vault.keySlots[0]).id;
  const bootstrapVault = vaultRecordSchema.parse({ ...vault, revision: 0 });
  const bootstrapRequest = vaultBootstrapRequestSchema.parse({
    vault: bootstrapVault,
    device: { id: deviceId, schemaVersion: vault.schemaVersion },
  });
  const publishRequest = vaultKeySlotUpdateRequestSchema.parse({
    expectedVaultRevision: 1,
    idempotencyKey: 'publish-slot-idempotency',
    record: { ...vault, revision: 2, updatedAt: later },
  });
  const revokeRequest = vaultKeySlotUpdateRequestSchema.parse({
    expectedVaultRevision: 1,
    idempotencyKey: 'revoke-slot-idempotency',
    record: {
      ...vault,
      revision: 2,
      updatedAt: later,
      keySlots: vault.keySlots.map((slot) =>
        slot.id === slotId ? { ...slot, state: 'revoked', revokedAt: later } : slot,
      ),
    },
  });
  return {
    vaultId: encrypted.vaultId,
    vault,
    bootstrapRequest,
    inviteRequest: inviteIssueRequestSchema.parse({
      scopes: ['sync:read'],
      expiresInSeconds: 600,
    }),
    enrollmentRequest: enrollmentCompleteRequestSchema.parse({
      vaultId: encrypted.vaultId,
      deviceId,
      schemaVersion: vault.schemaVersion,
    }),
    invite: publicInviteRecordSchema.parse({
      id: inviteId,
      vaultId: encrypted.vaultId,
      issuedByDeviceId: deviceId,
      scopes: ['sync:read'],
      state: 'active',
      createdAt: timestamp,
      expiresAt: later,
    }),
    device: publicDevice(encrypted.vaultId, deviceId),
    slotId,
    publishRequest,
    revokeRequest,
  };
}

function publicDevice(
  vaultId: VaultId,
  id: ReturnType<typeof deviceIdSchema.parse>,
): PublicDeviceRecord {
  return publicDeviceRecordSchema.parse({
    id,
    vaultId,
    schemaVersion: 1,
    tokenVersion: 1,
    scopes: ['sync:read'],
    createdAt: timestamp,
  });
}

function developmentClient(
  baseUrl: string,
  options: Readonly<{
    timeoutMs?: number;
    maximumResponseBytes?: number;
    signal?: AbortSignal;
  }> = {},
): ControlPlaneClient {
  return new ControlPlaneClient({
    baseUrl,
    allowInsecureLoopbackDevelopment: true,
    ...options,
  });
}

async function trackedServer(
  handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>,
): Promise<LoopbackServer> {
  const server = await startLoopbackServer(handler);
  servers.push(server);
  return server;
}

function json(response: ServerResponse, status: number, value: unknown): void {
  response.statusCode = status;
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.end(JSON.stringify(value));
}

function empty(response: ServerResponse): void {
  response.statusCode = 204;
  response.end();
}

function bearer(byte: number): ApiBearerToken {
  return apiBearerTokenSchema.parse(Buffer.alloc(32, byte).toString('base64url'));
}

function headerValue(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return typeof value === 'string' ? value : undefined;
}

function required<TValue>(value: TValue | undefined): TValue {
  if (value === undefined) throw new Error('The test fixture is incomplete.');
  return value;
}
