import {
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  attachmentChunkPathSchema,
  attachmentChunkStageRequestSchema,
  attachmentFinalizeRequestSchema,
  attachmentStreamFinalizeInputSchema,
  attachmentStreamProgressSchema,
  attachmentStreamStartInputSchema,
  attachmentTransferPathSchema,
  encryptedAttachmentRecordSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  type AttachmentStreamStartInput,
  type EncryptedAttachmentRecord,
} from '@kavrix/schemas';
import { SyncConflictError, ValidationError } from '@kavrix/core';

import { parseRequest } from '../boundary.js';
import {
  ApiAttachmentConflictError,
  ApiNotFoundError,
  ApiValidationError,
} from '../errors.js';
import type { ApiRoutePlugin } from '../route-context.js';
import type { ApiStoragePort } from '../ports.js';

export const attachmentRoutes: ApiRoutePlugin = (app, context) => {
  app.post(attachmentPath('/stream/open'), async (request, reply) => {
    const path = parseRequest(attachmentTransferPathSchema, request.params);
    await context.security.authenticate(request, 'sync:write', path.vaultId);
    const start = parseRequest(attachmentStreamStartInputSchema, request.body);
    requireStartPath(start, path);
    const session = await attachmentMutation(() =>
      context.ports.storage.beginAttachmentStream(start),
    );
    return reply
      .status(200)
      .send(attachmentStreamProgressSchema.parse(session.progress));
  });

  app.put(attachmentPath('/stream/chunks/:chunkIndex'), async (request, reply) => {
    const path = parseRequest(attachmentChunkPathSchema, request.params);
    await context.security.authenticate(request, 'sync:write', path.vaultId);
    const body = parseRequest(attachmentChunkStageRequestSchema, request.body);
    requireStartPath(body.start, path);
    if (
      body.chunk.record.index !== path.chunkIndex ||
      attachmentChunkCiphertextHash(body.chunk) !== body.chunk.ciphertextHash
    ) {
      throw new ApiValidationError();
    }
    const progress = await attachmentMutation(async () => {
      const session = await context.ports.storage.beginAttachmentStream(body.start);
      return session.writeChunk(body.chunk);
    });
    return reply.status(200).send(attachmentStreamProgressSchema.parse(progress));
  });

  app.post(attachmentPath('/stream/finalize'), async (request, reply) => {
    const path = parseRequest(attachmentTransferPathSchema, request.params);
    await context.security.authenticate(request, 'sync:write', path.vaultId);
    const body = parseRequest(attachmentFinalizeRequestSchema, request.body);
    requireStartPath(body.start, path);
    await attachmentMutation(async () => {
      const session = await context.ports.storage.beginAttachmentStream(body.start);
      await session.finalize(attachmentStreamFinalizeInputSchema.parse(body.finalize));
    });
    return reply.status(204).send();
  });

  app.post(attachmentPath('/stream/abort'), async (request, reply) => {
    const path = parseRequest(attachmentTransferPathSchema, request.params);
    await context.security.authenticate(request, 'sync:write', path.vaultId);
    const start = parseRequest(attachmentStreamStartInputSchema, request.body);
    requireStartPath(start, path);
    await attachmentMutation(() => context.ports.storage.abortAttachmentStream(start));
    return reply.status(204).send();
  });

  app.get(attachmentPath(''), async (request, reply) => {
    const path = parseRequest(attachmentTransferPathSchema, request.params);
    await context.security.authenticate(request, 'sync:read', path.vaultId);
    const record = await requireVisibleAttachment(context.ports.storage, path);
    return reply.status(200).send(record);
  });

  app.get(attachmentPath('/header'), async (request, reply) => {
    const path = parseRequest(attachmentTransferPathSchema, request.params);
    await context.security.authenticate(request, 'sync:read', path.vaultId);
    await requireVisibleAttachment(context.ports.storage, path);
    const header = await context.ports.storage.getAttachmentStreamHeader(
      path.vaultId,
      path.attachmentId,
    );
    if (header === null || !matchesPath(header.record, path)) {
      throw new ApiNotFoundError();
    }
    const parsed = persistedAttachmentHeaderRecordSchema.parse(header);
    if (attachmentHeaderContentHash(parsed) !== parsed.contentHash) {
      throw new ApiNotFoundError();
    }
    return reply.status(200).send(parsed);
  });

  app.get(attachmentPath('/chunks/:chunkIndex'), async (request, reply) => {
    const path = parseRequest(attachmentChunkPathSchema, request.params);
    await context.security.authenticate(request, 'sync:read', path.vaultId);
    const attachment = await requireVisibleAttachment(context.ports.storage, path);
    if (path.chunkIndex >= attachment.chunkCount) throw new ApiNotFoundError();
    const chunk = await context.ports.storage.getAttachmentChunk(
      path.vaultId,
      path.attachmentId,
      path.chunkIndex,
    );
    if (chunk === null) throw new ApiNotFoundError();
    if (
      chunk.record.index !== path.chunkIndex ||
      !matchesPath(chunk.record, path) ||
      attachmentChunkCiphertextHash(chunk) !== chunk.ciphertextHash
    ) {
      throw new ApiNotFoundError();
    }
    return reply.status(200).send(persistedAttachmentChunkRecordSchema.parse(chunk));
  });

  return Promise.resolve();
};

function attachmentPath(suffix: string): string {
  return `/v1/vaults/:vaultId/groups/:groupId/items/:itemId/attachments/:attachmentId${suffix}`;
}

function requireStartPath(
  start: AttachmentStreamStartInput,
  path: ReturnType<typeof attachmentTransferPathSchema.parse>,
): void {
  if (
    !matchesPath(start.header.record, path) ||
    attachmentHeaderContentHash(start.header) !== start.header.contentHash
  ) {
    throw new ApiValidationError();
  }
}

function matchesPath(
  record: Readonly<{
    vaultId: string;
    groupId: string;
    itemId: string;
    attachmentId: string;
  }>,
  path: ReturnType<typeof attachmentTransferPathSchema.parse>,
): boolean {
  return (
    record.vaultId === path.vaultId &&
    record.groupId === path.groupId &&
    record.itemId === path.itemId &&
    record.attachmentId === path.attachmentId
  );
}

async function requireVisibleAttachment(
  storage: ApiStoragePort,
  path: ReturnType<typeof attachmentTransferPathSchema.parse>,
): Promise<EncryptedAttachmentRecord> {
  const record = await storage.getAttachment(path.vaultId, path.attachmentId);
  const group = await storage.getGroup(path.vaultId, path.groupId);
  const item = await storage.getItem(path.vaultId, path.itemId);
  if (
    record === null ||
    group === null ||
    item === null ||
    record.groupId !== path.groupId ||
    record.itemId !== path.itemId ||
    item.groupId !== path.groupId
  ) {
    throw new ApiNotFoundError();
  }
  return encryptedAttachmentRecordSchema.parse(record);
}

async function attachmentMutation<Result>(
  operation: () => Promise<Result>,
): Promise<Result> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ValidationError || error instanceof SyncConflictError) {
      throw new ApiAttachmentConflictError();
    }
    throw error;
  }
}
