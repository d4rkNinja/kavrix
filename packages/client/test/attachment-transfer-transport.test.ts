import type { IncomingMessage, ServerResponse } from 'node:http';

import { afterEach, describe, expect, it } from 'vitest';

import {
  MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES,
  MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES,
  MAX_ATTACHMENT_CHUNKS,
  attachmentChunkCiphertextHash,
  persistedAttachmentChunkRecordSchema,
  type AttachmentStreamProgress,
} from '@kavrix/schemas';
import { SyncProtocolError } from '@kavrix/sync';

import {
  advanceAttachmentDownloadTotals,
  AttachmentTransferTransport,
} from '../src/attachment-transfer-transport.js';
import {
  attachmentBearerToken,
  attachmentTransportFixture,
} from './attachment-fixtures.js';
import {
  readRequest,
  startLoopbackServer,
  type LoopbackServer,
} from './loopback-server.js';

const servers: LoopbackServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

describe('AttachmentTransferTransport', () => {
  it('sends canonical auth/path/bodies and supports exact retry, finalize, and abort', async () => {
    const fixture = attachmentTransportFixture();
    const requests: { url: string; auth: string; body: string }[] = [];
    const server = await trackedServer(async (request, response) => {
      const body = await readRequest(request);
      requests.push({
        url: request.url ?? '',
        auth: request.headers.authorization ?? '',
        body,
      });
      if (request.url?.endsWith('/stream/open') === true) {
        sendJson(response, emptyProgress());
        return;
      }
      if (request.url?.includes('/stream/chunks/0') === true) {
        sendJson(response, stagedProgress(fixture.chunks[0]));
        return;
      }
      response.statusCode = 204;
      response.end();
    });
    const transport = developmentTransport(server.url);

    await expect(transport.open(fixture.start)).resolves.toEqual(emptyProgress());
    await expect(
      transport.stageChunk(fixture.start, fixture.chunks[0]),
    ).resolves.toEqual(stagedProgress(fixture.chunks[0]));
    await expect(
      transport.stageChunk(fixture.start, fixture.chunks[0]),
    ).resolves.toEqual(stagedProgress(fixture.chunks[0]));
    await expect(
      transport.finalize(fixture.start, fixture.finalize),
    ).resolves.toBeUndefined();
    await expect(transport.abort(fixture.start)).resolves.toBeUndefined();

    expect(requests.map(({ auth }) => auth)).toEqual(
      Array.from({ length: 5 }, () => `Bearer ${attachmentBearerToken}`),
    );
    expect(requests[1]?.body).toBe(requests[2]?.body);
    expect(requests.every(({ url }) => !url.includes(attachmentBearerToken))).toBe(
      true,
    );
    expect(requests[0]?.url).toContain(
      `/vaults/${fixture.path.vaultId}/groups/${fixture.path.groupId}/items/${fixture.path.itemId}/attachments/${fixture.path.attachmentId}`,
    );
  });

  it('retries a lost response with the exact same staged request', async () => {
    const fixture = attachmentTransportFixture();
    const bodies: string[] = [];
    let attempts = 0;
    const server = await trackedServer(async (request, response) => {
      bodies.push(await readRequest(request));
      attempts += 1;
      if (attempts === 1) {
        request.socket.destroy();
        return;
      }
      sendJson(response, stagedProgress(fixture.chunks[0]));
    });
    const transport = developmentTransport(server.url);
    await expect(
      transport.stageChunk(fixture.start, fixture.chunks[0]),
    ).rejects.toMatchObject({ kind: 'offline' });
    await expect(
      transport.stageChunk(fixture.start, fixture.chunks[0]),
    ).resolves.toMatchObject({ nextChunkIndex: 1 });
    expect(bodies).toHaveLength(2);
    expect(bodies[0]).toBe(bodies[1]);
  });

  it('downloads header then chunks in exact ascending order', async () => {
    const fixture = attachmentTransportFixture();
    const urls: string[] = [];
    const server = await trackedServer((request, response) => {
      urls.push(request.url ?? '');
      if (request.url?.endsWith('/header') === true) {
        sendJson(response, fixture.start.header);
        return;
      }
      const chunkMatch = request.url?.match(/\/chunks\/(\d+)$/u);
      if (chunkMatch !== undefined && chunkMatch !== null) {
        sendJson(response, fixture.chunks[Number(chunkMatch[1])]);
        return;
      }
      sendJson(response, fixture.finalize.record);
    });
    const records = [];
    for await (const record of developmentTransport(server.url).download(
      fixture.path,
    )) {
      records.push(record);
    }
    expect(records).toEqual([
      fixture.start.header,
      fixture.chunks[0],
      fixture.chunks[1],
    ]);
    expect(urls.map((url) => url.slice(url.lastIndexOf('/') + 1))).toEqual([
      fixture.path.attachmentId,
      'header',
      '0',
      '1',
    ]);
  });

  it('rejects split metadata before requesting an attachment header or chunk', async () => {
    const fixture = attachmentTransportFixture();
    const urls: string[] = [];
    const server = await trackedServer((request, response) => {
      urls.push(request.url ?? '');
      sendJson(response, {
        ...fixture.finalize.record,
        wrappedAttachmentKey: {
          ...fixture.finalize.record.wrappedAttachmentKey,
          aad: {
            ...fixture.finalize.record.wrappedAttachmentKey.aad,
            keyVersion: 2,
          },
          keyVersion: 2,
        },
      });
    });

    await expect(
      collect(developmentTransport(server.url).download(fixture.path)),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    expect(urls).toHaveLength(1);
    expect(urls[0]?.endsWith(`/${fixture.path.attachmentId}`)).toBe(true);
  });

  it('rejects mismatched progress, identities, hashes, indexes, and final tags', async () => {
    const fixture = attachmentTransportFixture();
    const wrongProgress = await trackedServer((_request, response) => {
      sendJson(response, {
        ...stagedProgress(fixture.chunks[0]),
        lastChunkCiphertextHash: fixture.chunks[1].ciphertextHash,
      });
    });
    await expect(
      developmentTransport(wrongProgress.url).stageChunk(
        fixture.start,
        fixture.chunks[0],
      ),
    ).rejects.toBeInstanceOf(SyncProtocolError);

    const wrongMetadata = await trackedServer((_request, response) => {
      sendJson(response, { ...fixture.finalize.record, vaultId: 'vault-cross-origin' });
    });
    await expect(
      developmentTransport(wrongMetadata.url).getMetadata(fixture.path),
    ).rejects.toBeInstanceOf(SyncProtocolError);

    const tombstonedMetadata = await trackedServer((_request, response) => {
      sendJson(response, {
        ...fixture.finalize.record,
        tombstonedAt: fixture.finalize.record.updatedAt,
      });
    });
    await expect(
      developmentTransport(tombstonedMetadata.url).getMetadata(fixture.path),
    ).rejects.toBeInstanceOf(SyncProtocolError);

    const wrongHashChunk = persistedAttachmentChunkRecordSchema.parse({
      ...fixture.chunks[0],
      ciphertextHash: fixture.chunks[1].ciphertextHash,
    });
    const wrongHash = await trackedServer((_request, response) => {
      sendJson(response, wrongHashChunk);
    });
    await expect(
      developmentTransport(wrongHash.url).getChunk(fixture.path, 0),
    ).rejects.toBeInstanceOf(SyncProtocolError);

    const wrongIndex = await trackedServer((_request, response) => {
      sendJson(response, fixture.chunks[1]);
    });
    await expect(
      developmentTransport(wrongIndex.url).getChunk(fixture.path, 0),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    await expect(
      developmentTransport(wrongIndex.url).getChunk(
        fixture.path,
        MAX_ATTACHMENT_CHUNKS,
      ),
    ).rejects.toBeInstanceOf(SyncProtocolError);

    const earlyFinalBase = persistedAttachmentChunkRecordSchema.parse({
      ...fixture.chunks[0],
      record: { ...fixture.chunks[0].record, tag: 'final' },
    });
    const earlyFinal = persistedAttachmentChunkRecordSchema.parse({
      ...earlyFinalBase,
      ciphertextHash: attachmentChunkCiphertextHash(earlyFinalBase),
    });
    const wrongTag = await trackedServer((request, response) => {
      if (request.url?.endsWith('/header') === true) {
        sendJson(response, fixture.start.header);
      } else if (request.url?.endsWith('/chunks/0') === true) {
        sendJson(response, earlyFinal);
      } else {
        sendJson(response, fixture.finalize.record);
      }
    });
    const download = developmentTransport(wrongTag.url).download(fixture.path);
    await expect(collect(download)).rejects.toBeInstanceOf(SyncProtocolError);
  });

  it('refuses redirects without forwarding authorization to another origin', async () => {
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
    const fixture = attachmentTransportFixture();
    await expect(
      developmentTransport(redirect.url).getMetadata(fixture.path),
    ).rejects.toBeInstanceOf(SyncProtocolError);
    expect(targetHits).toBe(0);
  });

  it('bounds aggregate downloads without allocating a maximum-size stream', () => {
    const chunk = attachmentTransportFixture().chunks[0];
    expect(() =>
      advanceAttachmentDownloadTotals(
        MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES - chunk.plaintextBytes + 1,
        0,
        chunk,
      ),
    ).toThrow(SyncProtocolError);
    expect(() =>
      advanceAttachmentDownloadTotals(
        0,
        MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES -
          Buffer.from(chunk.record.ciphertext, 'base64url').byteLength +
          1,
        chunk,
      ),
    ).toThrow(SyncProtocolError);
    expect(advanceAttachmentDownloadTotals(0, 0, chunk)).toEqual({
      totalPlaintextBytes: chunk.plaintextBytes,
      totalCiphertextBytes: Buffer.from(chunk.record.ciphertext, 'base64url')
        .byteLength,
    });
  });
});

function developmentTransport(baseUrl: string): AttachmentTransferTransport {
  return new AttachmentTransferTransport({
    baseUrl,
    bearerToken: attachmentBearerToken,
    allowInsecureLoopbackDevelopment: true,
  });
}

function emptyProgress(): AttachmentStreamProgress {
  return {
    version: 1,
    state: 'empty',
    nextChunkIndex: 0,
    totalPlaintextBytes: 0,
    totalCiphertextBytes: 0,
  } as const;
}

function stagedProgress(
  chunk: ReturnType<typeof attachmentTransportFixture>['chunks'][number],
): AttachmentStreamProgress {
  return {
    version: 1,
    state: chunk.record.tag === 'final' ? 'ready-to-finalize' : 'writing',
    nextChunkIndex: chunk.record.index + 1,
    totalPlaintextBytes: chunk.plaintextBytes,
    totalCiphertextBytes: chunk.plaintextBytes + 17,
    lastChunkIndex: chunk.record.index,
    lastChunkCiphertextHash: chunk.ciphertextHash,
    lastChunkPlaintextBytes: chunk.plaintextBytes,
  } as const;
}

function sendJson(response: ServerResponse, value: unknown): void {
  response.setHeader('content-type', 'application/json');
  response.end(JSON.stringify(value));
}

async function trackedServer(
  handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>,
): Promise<LoopbackServer> {
  const server = await startLoopbackServer(handler);
  servers.push(server);
  return server;
}

async function collect<T>(input: AsyncIterable<T>): Promise<T[]> {
  const output: T[] = [];
  for await (const value of input) output.push(value);
  return output;
}
