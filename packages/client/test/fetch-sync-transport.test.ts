import type { IncomingMessage, ServerResponse } from 'node:http';

import { afterEach, describe, expect, it } from 'vitest';

import {
  apiBearerTokenSchema,
  changeRecordSchema,
  contentHashForRecord,
  syncCursorSchema,
  syncPushRequestSchema,
  templateMigrationPublicationRequestSchema,
  templateMigrationPublicationResponseSchema,
  type TemplateMigrationPublicationRequest,
  type TemplateMigrationPublicationResponse,
} from '@kavrix/schemas';
import {
  SyncProtocolError,
  SyncRollbackError,
  SyncTransportFailure,
  classifySyncFailure,
} from '@kavrix/sync';

import { FetchSyncTransport } from '../src/index.js';
import { encryptedFixture } from './fixtures.js';
import {
  readRequest,
  startLoopbackServer,
  type LoopbackServer,
} from './loopback-server.js';

const token = apiBearerTokenSchema.parse(Buffer.alloc(32, 7).toString('base64url'));
const servers: LoopbackServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe('FetchSyncTransport', () => {
  it('sends auth only in headers and parses bounded canonical pull/push DTOs', async () => {
    const seen: { urls: string[]; authorization: string[]; bodies: string[] } = {
      urls: [],
      authorization: [],
      bodies: [],
    };
    const fixture = await encryptedFixture();
    const record = required(fixture.groups[0]);
    const server = await trackedServer(async (request, response) => {
      seen.urls.push(request.url ?? '');
      seen.authorization.push(request.headers.authorization ?? '');
      const body = await readRequest(request);
      seen.bodies.push(body);
      response.setHeader('content-type', 'application/json; charset=utf-8');
      if (request.method === 'GET') {
        response.end(
          JSON.stringify({
            vaultId: fixture.vaultId,
            serverVaultRevision: 0,
            changes: [],
            nextCursor: {
              vaultId: fixture.vaultId,
              serverSequence: 0,
              highestSeenVaultRevision: 0,
            },
            hasMore: false,
          }),
        );
        return;
      }
      const batch = syncPushRequestSchema.parse(JSON.parse(body));
      response.end(
        JSON.stringify({
          vaultId: fixture.vaultId,
          serverVaultRevision: 0,
          batchIdempotencyKey: batch.batchIdempotencyKey,
          results: batch.mutations.map((mutation) => ({
            status: 'conflict',
            idempotencyKey: mutation.idempotencyKey,
            currentRevision: 0,
            current: null,
          })),
        }),
      );
    });
    const transport = developmentTransport(server.url);
    const cursor = syncCursorSchema.parse({
      vaultId: fixture.vaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 0,
    });
    await expect(
      transport.pull({ vaultId: fixture.vaultId, cursor, limit: 25 }),
    ).resolves.toMatchObject({ vaultId: fixture.vaultId, changes: [] });
    const pushRequest = syncPushRequestSchema.parse({
      vaultId: fixture.vaultId,
      batchIdempotencyKey: 'batch-idempotency-key',
      mutations: [
        {
          entityType: 'group',
          expectedRecordRevision: 0,
          idempotencyKey: 'mutation-idempotency-key',
          record,
        },
      ],
    });
    await expect(transport.push(pushRequest)).resolves.toMatchObject({
      vaultId: fixture.vaultId,
      batchIdempotencyKey: 'batch-idempotency-key',
    });

    expect(seen.authorization).toEqual([`Bearer ${token}`, `Bearer ${token}`]);
    expect(seen.urls.every((url) => !url.includes(token))).toBe(true);
    expect(seen.bodies.every((body) => !body.includes(token))).toBe(true);
    expect(seen.urls[0]).toContain('serverSequence=0');
  });

  it('requires HTTPS except an explicit loopback-development opt-in', () => {
    const invalidTokenCanary = 'invalid-token-PLAINTEXT-CANARY';
    const invalidTokenError = catchSync(() => {
      new FetchSyncTransport({
        baseUrl: 'https://example.com',
        bearerToken: invalidTokenCanary as never,
      });
    });
    expect(invalidTokenError).toBeInstanceOf(TypeError);
    expect(JSON.stringify(invalidTokenError)).not.toContain(invalidTokenCanary);
    expect(String(invalidTokenError)).not.toContain(invalidTokenCanary);
    expect(
      () => new FetchSyncTransport({ baseUrl: 'not a URL', bearerToken: token }),
    ).toThrow(TypeError);
    expect(
      () =>
        new FetchSyncTransport({
          baseUrl: 'http://127.0.0.1:8080',
          bearerToken: token,
        }),
    ).toThrow(TypeError);
    expect(
      () =>
        new FetchSyncTransport({
          baseUrl: 'http://example.com',
          bearerToken: token,
          allowInsecureLoopbackDevelopment: true,
        }),
    ).toThrow(TypeError);
    expect(
      () =>
        new FetchSyncTransport({
          baseUrl: `https://user:${token}@example.com/?token=${token}#secret`,
          bearerToken: token,
        }),
    ).toThrow(TypeError);
    expect(
      () =>
        new FetchSyncTransport({
          baseUrl: 'http://127.0.0.1:8080',
          bearerToken: token,
          allowInsecureLoopbackDevelopment: true,
        }),
    ).not.toThrow();
    expect(
      () =>
        new FetchSyncTransport({
          baseUrl: 'https://example.com/api',
          bearerToken: token,
          timeoutMs: 0,
        }),
    ).toThrow(TypeError);
    expect(
      () =>
        new FetchSyncTransport({
          baseUrl: 'https://example.com/api',
          bearerToken: token,
          maximumResponseBytes: 300 * 1024 * 1024,
        }),
    ).toThrow(TypeError);
  });

  it('refuses redirects without forwarding authorization cross-origin', async () => {
    let targetHits = 0;
    const target = await trackedServer((_request, response) => {
      targetHits += 1;
      response.end('{}');
    });
    const redirect = await trackedServer((_request, response) => {
      response.statusCode = 302;
      response.setHeader('location', `${target.url}/capture`);
      response.end();
    });
    const fixture = await encryptedFixture();
    await expect(
      developmentTransport(redirect.url).pull({
        vaultId: fixture.vaultId,
        cursor: syncCursorSchema.parse({
          vaultId: fixture.vaultId,
          serverSequence: 0,
          highestSeenVaultRevision: 0,
        }),
        limit: 1,
      }),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    expect(targetHits).toBe(0);
  });

  it('bounds streamed responses before JSON parsing', async () => {
    const oversized = await trackedServer((_request, response) => {
      response.setHeader('content-type', 'application/json');
      response.write('{"padding":"');
      response.end('x'.repeat(256).concat('"}'));
    });
    const fixture = await encryptedFixture();
    const transport = developmentTransport(oversized.url, { maximumResponseBytes: 64 });
    await expect(
      transport.pull({
        vaultId: fixture.vaultId,
        cursor: syncCursorSchema.parse({
          vaultId: fixture.vaultId,
          serverSequence: 0,
          highestSeenVaultRevision: 0,
        }),
        limit: 1,
      }),
    ).rejects.toBeInstanceOf(SyncProtocolError);

    const declaredOversized = await trackedServer((_request, response) => {
      response.setHeader('content-type', 'application/json');
      response.setHeader('content-length', '1000');
      response.end('{}');
    });
    await expect(
      developmentTransport(declaredOversized.url, {
        maximumResponseBytes: 64,
      }).pull({
        vaultId: fixture.vaultId,
        cursor: syncCursorSchema.parse({
          vaultId: fixture.vaultId,
          serverSequence: 0,
          highestSeenVaultRevision: 0,
        }),
        limit: 1,
      }),
    ).rejects.toBeInstanceOf(SyncProtocolError);
  });

  it('classifies retry-after, authorization, timeout, and malformed responses generically', async () => {
    const fixture = await encryptedFixture();
    const cursor = syncCursorSchema.parse({
      vaultId: fixture.vaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 0,
    });
    const rateLimited = await trackedServer((_request, response) => {
      response.statusCode = 429;
      response.setHeader('retry-after', '2');
      response.end(`do-not-reflect-${token}`);
    });
    const rateError = await developmentTransport(rateLimited.url)
      .pull({ vaultId: fixture.vaultId, cursor, limit: 1 })
      .catch((error: unknown) => error);
    expect(rateError).toBeInstanceOf(SyncTransportFailure);
    expect(classifySyncFailure(rateError)).toEqual({
      state: 'error',
      code: 'rate-limited',
      retryable: true,
      retryAfterMs: 2_000,
    });
    expect(JSON.stringify(rateError)).not.toContain(token);
    expect(String(rateError)).not.toContain(token);

    const unauthorized = await trackedServer((_request, response) => {
      response.statusCode = 401;
      response.end();
    });
    await expect(
      developmentTransport(unauthorized.url).pull({
        vaultId: fixture.vaultId,
        cursor,
        limit: 1,
      }),
    ).rejects.toMatchObject({ kind: 'unauthorized' });

    const timeout = await trackedServer(async (_request, response) => {
      await new Promise((resolve) => setTimeout(resolve, 80));
      response.end('{}');
    });
    await expect(
      developmentTransport(timeout.url, { timeoutMs: 10 }).pull({
        vaultId: fixture.vaultId,
        cursor,
        limit: 1,
      }),
    ).rejects.toMatchObject({ kind: 'timeout' });

    const malformed = await trackedServer((_request, response) => {
      response.setHeader('content-type', 'text/plain');
      response.end('{"not":"accepted"}');
    });
    await expect(
      developmentTransport(malformed.url).pull({
        vaultId: fixture.vaultId,
        cursor,
        limit: 1,
      }),
    ).rejects.toBeInstanceOf(SyncProtocolError);

    const invalidJson = await trackedServer((_request, response) => {
      response.setHeader('content-type', 'application/json');
      response.end('{');
    });
    await expect(
      developmentTransport(invalidJson.url).pull({
        vaultId: fixture.vaultId,
        cursor,
        limit: 1,
      }),
    ).rejects.toBeInstanceOf(SyncProtocolError);
  });

  it('maps HTTP and network failures without parsing or reflecting response bodies', async () => {
    const fixture = await encryptedFixture();
    const cursor = syncCursorSchema.parse({
      vaultId: fixture.vaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 0,
    });
    for (const [status, kind] of [
      [403, 'device-revoked'],
      [408, 'timeout'],
      [503, 'server'],
    ] as const) {
      const server = await trackedServer((_request, response) => {
        response.statusCode = status;
        response.end(`private-${token}`);
      });
      await expect(
        developmentTransport(server.url).pull({
          vaultId: fixture.vaultId,
          cursor,
          limit: 1,
        }),
      ).rejects.toMatchObject({ kind });
    }

    const aborted = new AbortController();
    aborted.abort();
    await expect(
      new FetchSyncTransport({
        baseUrl: 'https://127.0.0.1:1',
        bearerToken: token,
        signal: aborted.signal,
      }).pull({ vaultId: fixture.vaultId, cursor, limit: 1 }),
    ).rejects.toMatchObject({ kind: 'client' });

    await expect(
      new FetchSyncTransport({
        baseUrl: 'https://127.0.0.1:1',
        bearerToken: token,
        timeoutMs: 1_000,
      }).pull({ vaultId: fixture.vaultId, cursor, limit: 1 }),
    ).rejects.toMatchObject({ kind: 'offline' });
  });

  it('maps only pull conflicts to rollback without retaining the response body', async () => {
    const fixture = await encryptedFixture();
    const bodyCanary = 'rollback-response-body-canary-5f4c';
    const server = await trackedServer((_request, response) => {
      response.statusCode = 409;
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ error: bodyCanary }));
    });
    const transport = developmentTransport(server.url);
    const cursor = syncCursorSchema.parse({
      vaultId: fixture.vaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 0,
    });

    const pullError = await transport
      .pull({ vaultId: fixture.vaultId, cursor, limit: 1 })
      .catch((error: unknown) => error);
    expect(pullError).toBeInstanceOf(SyncRollbackError);
    expect(pullError).not.toHaveProperty('cause');
    expect(String(pullError)).not.toContain(bodyCanary);
    expect(JSON.stringify(pullError)).not.toContain(bodyCanary);

    const pushRequest = syncPushRequestSchema.parse({
      vaultId: fixture.vaultId,
      batchIdempotencyKey: 'rollback-push-client-0001',
      mutations: [
        {
          entityType: 'group',
          expectedRecordRevision: 0,
          idempotencyKey: 'rollback-push-client-mutation-0001',
          record: required(fixture.groups[0]),
        },
      ],
    });
    const pushError = await transport
      .push(pushRequest)
      .catch((error: unknown) => error);
    expect(pushError).toBeInstanceOf(SyncTransportFailure);
    expect(pushError).toMatchObject({ kind: 'conflict' });
    expect(pushError).not.toBeInstanceOf(SyncRollbackError);

    const templateError = await transport
      .publishTemplateMigration(atomicPublication(fixture))
      .catch((error: unknown) => error);
    expect(templateError).toBeInstanceOf(SyncTransportFailure);
    expect(templateError).toMatchObject({ kind: 'conflict' });
    expect(templateError).not.toBeInstanceOf(SyncRollbackError);
  });

  it('rejects well-formed JSON that violates canonical response schemas', async () => {
    const fixture = await encryptedFixture();
    const invalid = await trackedServer((_request, response) => {
      response.setHeader('content-type', 'application/json');
      response.end('{}');
    });
    const transport = developmentTransport(invalid.url);
    const cursor = syncCursorSchema.parse({
      vaultId: fixture.vaultId,
      serverSequence: 0,
      highestSeenVaultRevision: 0,
    });
    await expect(
      transport.pull({ vaultId: fixture.vaultId, cursor, limit: 1 }),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    const pushRequest = syncPushRequestSchema.parse({
      vaultId: fixture.vaultId,
      batchIdempotencyKey: 'batch-idempotency-key',
      mutations: [
        {
          entityType: 'group',
          expectedRecordRevision: 0,
          idempotencyKey: 'mutation-idempotency-key',
          record: required(fixture.groups[0]),
        },
      ],
    });
    await expect(transport.push(pushRequest)).rejects.toBeInstanceOf(SyncProtocolError);
  });

  it('rejects malformed requests before connecting', async () => {
    const fixture = await encryptedFixture();
    const transport = new FetchSyncTransport({
      baseUrl: 'https://127.0.0.1:1',
      bearerToken: token,
    });
    await expect(
      transport.pull({
        vaultId: fixture.vaultId,
        cursor: syncCursorSchema.parse({
          vaultId: fixture.vaultId,
          serverSequence: 0,
          highestSeenVaultRevision: 0,
        }),
        limit: 501,
      }),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    await expect(
      transport.push({ vaultId: fixture.vaultId, mutations: [] } as never),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    await expect(
      transport.publishTemplateMigration({
        vaultId: fixture.vaultId,
        mutations: [],
      } as never),
    ).rejects.toBeInstanceOf(SyncProtocolError);
  });

  it('publishes the exact atomic request on the bound path after a lost response', async () => {
    const fixture = await encryptedFixture();
    const publication = atomicPublication(fixture);
    const expected = atomicPublicationResponse(publication);
    const bodies: string[] = [];
    const urls: string[] = [];
    let requests = 0;
    const server = await trackedServer(async (request, response) => {
      requests += 1;
      urls.push(request.url ?? '');
      bodies.push(await readRequest(request));
      if (requests === 1) {
        await new Promise((resolve) => setTimeout(resolve, 60));
      }
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify(expected));
    });

    await expect(
      developmentTransport(server.url, { timeoutMs: 10 }).publishTemplateMigration(
        publication,
      ),
    ).rejects.toMatchObject({ kind: 'timeout' });
    await expect(
      developmentTransport(server.url, { timeoutMs: 500 }).publishTemplateMigration(
        publication,
      ),
    ).resolves.toEqual(expected);

    expect(urls).toEqual([
      `/v1/vaults/${fixture.vaultId}/template-migrations`,
      `/v1/vaults/${fixture.vaultId}/template-migrations`,
    ]);
    expect(bodies).toEqual([JSON.stringify(publication), JSON.stringify(publication)]);
    expect(urls.every((url) => !url.endsWith('/sync'))).toBe(true);
  });

  it('rejects malformed or cross-vault atomic responses and classifies terminal failures', async () => {
    const fixture = await encryptedFixture();
    const publication = atomicPublication(fixture);
    const valid = atomicPublicationResponse(publication);
    for (const payload of [{}, { ...valid, vaultId: 'vault.other' }]) {
      const server = await trackedServer((_request, response) => {
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify(payload));
      });
      await expect(
        developmentTransport(server.url).publishTemplateMigration(publication),
      ).rejects.toBeInstanceOf(SyncProtocolError);
    }

    for (const [status, kind, code] of [
      [409, 'conflict', 'atomic-publication-conflict'],
      [401, 'unauthorized', 'authorization-failed'],
      [403, 'device-revoked', 'device-revoked'],
    ] as const) {
      const server = await trackedServer((_request, response) => {
        response.statusCode = status;
        response.end();
      });
      const error = await developmentTransport(server.url)
        .publishTemplateMigration(publication)
        .catch((caught: unknown) => caught);
      expect(error).toMatchObject({ kind });
      expect(classifySyncFailure(error)).toMatchObject({
        state: 'error',
        code,
        retryable: false,
      });
    }
  });
});

function atomicPublication(
  fixture: Awaited<ReturnType<typeof encryptedFixture>>,
): TemplateMigrationPublicationRequest {
  const record = required(fixture.groups[0]);
  return templateMigrationPublicationRequestSchema.parse({
    vaultId: fixture.vaultId,
    batchIdempotencyKey: 'template-batch-loopback-0001',
    mutations: [
      {
        entityType: 'group',
        expectedRecordRevision: 0,
        idempotencyKey: 'template-group-loopback-0001',
        record,
      },
    ],
  });
}

function atomicPublicationResponse(
  publication: TemplateMigrationPublicationRequest,
): TemplateMigrationPublicationResponse {
  const mutation = required(publication.mutations[0]);
  return templateMigrationPublicationResponseSchema.parse({
    vaultId: publication.vaultId,
    batchIdempotencyKey: publication.batchIdempotencyKey,
    serverVaultRevision: 2,
    results: [
      {
        idempotencyKey: mutation.idempotencyKey,
        change: changeRecordSchema.parse({
          id: 'change.template.loopback.1',
          vaultId: publication.vaultId,
          serverSequence: 2,
          entityType: mutation.entityType,
          entityId: mutation.record.id,
          recordRevision:
            'revision' in mutation.record
              ? mutation.record.revision
              : mutation.record.recordRevision,
          operation: 'upsert',
          ciphertextHash: contentHashForRecord(mutation.record),
          createdAt: mutation.record.updatedAt,
        }),
      },
    ],
  });
}

function developmentTransport(
  baseUrl: string,
  options: Readonly<{ timeoutMs?: number; maximumResponseBytes?: number }> = {},
): FetchSyncTransport {
  return new FetchSyncTransport({
    baseUrl,
    bearerToken: token,
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

function required<TValue>(value: TValue | undefined): TValue {
  if (value === undefined) throw new Error('The test fixture is incomplete.');
  return value;
}

function catchSync(operation: () => void): unknown {
  try {
    operation();
  } catch (error) {
    return error;
  }
  throw new Error('The operation was expected to throw.');
}
