import { afterEach, describe, expect, it } from 'vitest';

import {
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  encryptedAttachmentRecordSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
} from '@kavrix/schemas';
import type { FastifyInstance } from 'fastify';

import { buildApi } from '../src/index.js';
import {
  attachmentFixture,
  ciphertextAttachmentCanary,
  plaintextAttachmentCanary,
} from './attachment-fixtures.js';
import { authHeader, createTestPorts, otherVaultId } from './helpers.js';

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map(async (app) => app.close()));
});

describe('opaque attachment routes', () => {
  it('keeps staging hidden, resumes exact writes, and publishes ordered reads', async () => {
    const ports = await createTestPorts();
    const app = tracked(buildApi({ ports: ports.ports, environment: 'test' }));
    const fixture = attachmentFixture();
    seedParents(ports.storage, fixture);
    const base = attachmentUrl(fixture.path);

    const opened = await app.inject({
      method: 'POST',
      url: `${base}/stream/open`,
      headers: authHeader(ports.token),
      payload: fixture.start,
    });
    expect(opened.statusCode).toBe(200);
    expect(opened.json()).toMatchObject({ state: 'empty', nextChunkIndex: 0 });
    expect(
      (
        await app.inject({
          method: 'GET',
          url: base,
          headers: authHeader(ports.token),
        })
      ).statusCode,
    ).toBe(404);

    for (const chunk of fixture.chunks) {
      const staged = await app.inject({
        method: 'PUT',
        url: `${base}/stream/chunks/${String(chunk.record.index)}`,
        headers: authHeader(ports.token),
        payload: { start: fixture.start, chunk },
      });
      expect(staged.statusCode).toBe(200);
    }
    const duplicate = await app.inject({
      method: 'PUT',
      url: `${base}/stream/chunks/1`,
      headers: authHeader(ports.token),
      payload: { start: fixture.start, chunk: fixture.chunks[1] },
    });
    expect(duplicate.statusCode).toBe(200);
    expect(duplicate.json()).toMatchObject({
      state: 'ready-to-finalize',
      nextChunkIndex: 2,
    });

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const finalized = await app.inject({
        method: 'POST',
        url: `${base}/stream/finalize`,
        headers: authHeader(ports.token),
        payload: { start: fixture.start, finalize: fixture.finalize },
      });
      expect(finalized.statusCode).toBe(204);
    }
    const metadata = await app.inject({
      method: 'GET',
      url: base,
      headers: authHeader(ports.token),
    });
    const header = await app.inject({
      method: 'GET',
      url: `${base}/header`,
      headers: authHeader(ports.token),
    });
    const chunks = await Promise.all(
      [0, 1].map(async (index) =>
        app.inject({
          method: 'GET',
          url: `${base}/chunks/${String(index)}`,
          headers: authHeader(ports.token),
        }),
      ),
    );
    expect(metadata.statusCode).toBe(200);
    expect(encryptedAttachmentRecordSchema.parse(metadata.json())).toEqual(
      fixture.finalize.record,
    );
    expect(persistedAttachmentHeaderRecordSchema.parse(header.json())).toEqual(
      fixture.start.header,
    );
    const parsedChunks = chunks.map((response) =>
      persistedAttachmentChunkRecordSchema.parse(response.json()),
    );
    expect(parsedChunks).toEqual(fixture.chunks);
    expect(parsedChunks.map(({ record }) => record.index)).toEqual([0, 1]);
    expect(
      Buffer.from(parsedChunks[0]?.record.ciphertext ?? '', 'base64url')
        .subarray(0, Buffer.byteLength(ciphertextAttachmentCanary))
        .toString('utf8'),
    ).toBe(ciphertextAttachmentCanary);
    expect(JSON.stringify([...ports.storage.attachmentStaging.values()])).not.toContain(
      plaintextAttachmentCanary,
    );

    ports.storage.items.set(parentKey(fixture.item.vaultId, fixture.item.id), {
      ...fixture.item,
      tombstonedAt: fixture.item.updatedAt,
    });
    await expectParentHidden(app, ports.token, base);
    ports.storage.items.set(
      parentKey(fixture.item.vaultId, fixture.item.id),
      fixture.item,
    );
    ports.storage.groups.set(parentKey(fixture.group.vaultId, fixture.group.id), {
      ...fixture.group,
      tombstonedAt: fixture.group.updatedAt,
    });
    await expectParentHidden(app, ports.token, base);
  });

  it('rejects split attachment key versions without publishing metadata or a change', async () => {
    const ports = await createTestPorts();
    const app = tracked(buildApi({ ports: ports.ports, environment: 'test' }));
    const fixture = attachmentFixture();
    seedParents(ports.storage, fixture);
    const base = attachmentUrl(fixture.path);

    for (const chunk of fixture.chunks) {
      expect(
        (
          await app.inject({
            method: 'PUT',
            url: `${base}/stream/chunks/${String(chunk.record.index)}`,
            headers: authHeader(ports.token),
            payload: { start: fixture.start, chunk },
          })
        ).statusCode,
      ).toBe(200);
    }

    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${base}/stream/finalize`,
          headers: authHeader(ports.token),
          payload: {
            start: fixture.start,
            finalize: {
              ...fixture.finalize,
              record: {
                ...fixture.finalize.record,
                wrappedAttachmentKey: {
                  ...fixture.finalize.record.wrappedAttachmentKey,
                  aad: {
                    ...fixture.finalize.record.wrappedAttachmentKey.aad,
                    keyVersion: 2,
                  },
                  keyVersion: 2,
                },
              },
            },
          },
        })
      ).statusCode,
    ).toBe(400);
    expect(ports.storage.attachments).toHaveLength(0);
    expect(ports.storage.changes).toHaveLength(0);
  });

  it('fails closed on gaps, replacements, path swaps, bad hashes, and aborts', async () => {
    const ports = await createTestPorts();
    const app = tracked(buildApi({ ports: ports.ports, environment: 'test' }));
    const fixture = attachmentFixture();
    seedParents(ports.storage, fixture);
    const base = attachmentUrl(fixture.path);
    const request = (
      index: number,
      chunk: unknown,
      start: unknown = fixture.start,
    ): Promise<{ readonly statusCode: number; json(): unknown }> =>
      app.inject({
        method: 'PUT',
        url: `${base}/stream/chunks/${String(index)}`,
        headers: authHeader(ports.token),
        payload: { start, chunk },
      });

    expect((await request(1, fixture.chunks[1])).statusCode).toBe(409);
    expect((await request(0, fixture.chunks[0])).statusCode).toBe(200);
    const replacementBase = persistedAttachmentChunkRecordSchema.parse({
      ...fixture.chunks[0],
      record: {
        ...fixture.chunks[0].record,
        ciphertext: Buffer.alloc(fixture.chunks[0].plaintextBytes + 17, 11).toString(
          'base64url',
        ),
      },
    });
    const replacement = persistedAttachmentChunkRecordSchema.parse({
      ...replacementBase,
      ciphertextHash: attachmentChunkCiphertextHash(replacementBase),
    });
    expect((await request(0, replacement)).statusCode).toBe(409);
    expect(
      (
        await request(0, {
          ...fixture.chunks[0],
          ciphertextHash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        })
      ).statusCode,
    ).toBe(400);
    expect(
      (
        await request(0, fixture.chunks[0], {
          ...fixture.start,
          header: {
            ...fixture.start.header,
            record: { ...fixture.start.header.record, vaultId: otherVaultId },
          },
        })
      ).statusCode,
    ).toBe(400);

    const abortedFixture = attachmentFixture();
    const abortedStart = {
      ...abortedFixture.start,
      idempotencyKey: 'attachment-transfer-idempotency-abort',
    };
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${base}/stream/abort`,
          headers: authHeader(ports.token),
          payload: abortedStart,
        })
      ).statusCode,
    ).toBe(204);
    const replacementHeader = persistedAttachmentHeaderRecordSchema.parse({
      ...abortedStart.header,
      recordRevision: 1,
      contentHash: abortedStart.header.contentHash,
    });
    const incompatibleAbort = {
      ...abortedStart,
      expectedAttachmentRevision: 0,
      header: {
        ...replacementHeader,
        contentHash: attachmentHeaderContentHash(replacementHeader),
      },
    };
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${base}/stream/abort`,
          headers: authHeader(ports.token),
          payload: incompatibleAbort,
        })
      ).statusCode,
    ).toBe(409);
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${base}/stream/abort`,
          headers: authHeader(ports.token),
          payload: abortedStart,
        })
      ).statusCode,
    ).toBe(204);
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${base}/stream/open`,
          headers: authHeader(ports.token),
          payload: abortedStart,
        })
      ).statusCode,
    ).toBe(409);
    expect(
      (
        await app.inject({
          method: 'GET',
          url: base,
          headers: authHeader(ports.token),
        })
      ).statusCode,
    ).toBe(404);
  });

  it('enforces scopes, JSON/body bounds, source rate protection, and generic logs', async () => {
    const fixture = attachmentFixture();
    const readOnly = await createTestPorts(['sync:read']);
    const app = tracked(buildApi({ ports: readOnly.ports, environment: 'test' }));
    const base = attachmentUrl(fixture.path);
    expect(
      (
        await app.inject({
          method: 'POST',
          url: `${base}/stream/open`,
          headers: authHeader(readOnly.token),
          payload: fixture.start,
        })
      ).statusCode,
    ).toBe(403);
    const writePorts = await createTestPorts();
    const writeApp = tracked(
      buildApi({ ports: writePorts.ports, environment: 'test' }),
    );
    expect(
      (
        await writeApp.inject({
          method: 'POST',
          url: `${base}/stream/open`,
          headers: {
            ...authHeader(writePorts.token),
            'content-type': 'text/plain',
          },
          payload: JSON.stringify(fixture.start),
        })
      ).statusCode,
    ).toBe(415);

    const limited = await createTestPorts();
    limited.rateLimits.denied = true;
    const limitedApp = tracked(buildApi({ ports: limited.ports, environment: 'test' }));
    expect(
      (
        await limitedApp.inject({
          method: 'GET',
          url: base,
          headers: authHeader(limited.token),
        })
      ).statusCode,
    ).toBe(429);

    const logs: string[] = [];
    const logging = await createTestPorts();
    const loggingApp = tracked(
      buildApi({
        ports: logging.ports,
        environment: 'test',
        logStream: { write: (message) => logs.push(message) },
        bodyLimit: 128,
      }),
    );
    const oversized = await loggingApp.inject({
      method: 'POST',
      url: `${base}/stream/open`,
      headers: authHeader(logging.token),
      payload: fixture.start,
    });
    expect(oversized.statusCode).toBe(413);
    expect(logs.join('')).not.toContain(ciphertextAttachmentCanary);
    expect(logs.join('')).not.toContain(plaintextAttachmentCanary);
    expect(logs.join('')).not.toContain(logging.token);
  });
});

function attachmentUrl(path: ReturnType<typeof attachmentFixture>['path']): string {
  return `/v1/vaults/${path.vaultId}/groups/${path.groupId}/items/${path.itemId}/attachments/${path.attachmentId}`;
}

function tracked(app: FastifyInstance): FastifyInstance {
  apps.push(app);
  return app;
}

function seedParents(
  storage: Awaited<ReturnType<typeof createTestPorts>>['storage'],
  fixture: ReturnType<typeof attachmentFixture>,
): void {
  storage.groups.set(parentKey(fixture.group.vaultId, fixture.group.id), fixture.group);
  storage.items.set(parentKey(fixture.item.vaultId, fixture.item.id), fixture.item);
}

function parentKey(vault: string, entityId: string): string {
  return `${vault}:${entityId}`;
}

async function expectParentHidden(
  app: FastifyInstance,
  token: string,
  base: string,
): Promise<void> {
  const responses = await Promise.all(
    [base, `${base}/header`, `${base}/chunks/0`].map(async (url) =>
      app.inject({ method: 'GET', url, headers: authHeader(token) }),
    ),
  );
  expect(responses.map(({ statusCode }) => statusCode)).toEqual([404, 404, 404]);
}
